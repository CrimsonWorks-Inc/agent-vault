// Built-in connector profiles.
//
// A profile is a ceiling, not a default: its deny lists apply even under a
// grant of /**, and its host list is the outer bound of anything a policy can
// allow. The deny lists are chosen to block the paths that turn a read grant
// into persistence: deploy keys, webhooks, OAuth authorizations, secrets.

const PROFILES = {
  github: {
    kind: 'github',
    hosts: ['api.github.com', 'uploads.github.com', 'github.com'],
    fields: { token: { sites: ['header:authorization:Bearer', 'header:authorization:token', 'basic:pass'] } },
    probe: { method: 'GET', path: '/user' },
    // Headers the provider documents. A name that is only a guess would record
    // some other field as this credential's expiry, so every other profile
    // leaves `health` null. There are no built-in SPKI pins (Q7).
    health: {
      expiry_header: 'github-authentication-token-expiration',
      scopes_header: 'x-oauth-scopes',
      ratelimit_remaining_header: 'x-ratelimit-remaining',
    },
    deny_paths: [
      '/user/keys', '/user/keys/**', '/user/gpg_keys', '/user/gpg_keys/**',
      '/authorizations/**', '/applications/**',
      '/repos/*/*/hooks', '/repos/*/*/hooks/**',
      '/orgs/*/hooks', '/orgs/*/hooks/**',
      '/repos/*/*/keys', '/repos/*/*/keys/**',
      '/repos/*/*/actions/secrets/**', '/orgs/*/actions/secrets/**',
      '/repos/*/*/collaborators/**', '/settings/**',
    ],
    scrub: ['gh[pousr]_[A-Za-z0-9]{20,}', 'github_pat_[A-Za-z0-9_]{40,}'],
    defaultBudget: { unit: 'requests', limit: 500 },
  },

  slack: {
    kind: 'slack',
    hosts: ['slack.com', 'files.slack.com', 'www.slack.com'],
    fields: { token: { sites: ['header:authorization:Bearer', 'form:token'] } },
    probe: { method: 'POST', path: '/api/auth.test' },
    health: null,
    deny_paths: ['/api/admin.*', '/api/oauth.*', '/api/apps.connections.open', '/api/apps.manifest.*', '/api/users.profile.set'],
    scrub: ['xox[abpors]-[0-9A-Za-z-]{10,}'],
    defaultBudget: { unit: 'requests', limit: 500 },
  },

  anthropic: {
    kind: 'anthropic',
    hosts: ['api.anthropic.com'],
    fields: { key: { sites: ['header:x-api-key'] } },
    probe: { method: 'GET', path: '/v1/models' },
    health: null,
    deny_paths: ['/v1/organizations/**', '/v1/admin/**', '/v1/api_keys/**'],
    scrub: ['sk-ant-[A-Za-z0-9_-]{20,}'],
    defaultBudget: { unit: 'requests', limit: 20000 },
    env: { base: 'ANTHROPIC_BASE_URL', key: 'ANTHROPIC_API_KEY' },
  },

  openai: {
    kind: 'openai',
    hosts: ['api.openai.com'],
    fields: { key: { sites: ['header:authorization:Bearer'] } },
    probe: { method: 'GET', path: '/v1/models' },
    health: null,
    deny_paths: ['/v1/organization/**', '/v1/admin/**'],
    scrub: ['sk-(?:proj-)?[A-Za-z0-9_-]{20,}'],
    defaultBudget: { unit: 'requests', limit: 20000 },
    env: { base: 'OPENAI_BASE_URL', key: 'OPENAI_API_KEY' },
  },

  'google-genai': {
    kind: 'google-genai',
    hosts: ['generativelanguage.googleapis.com'],
    fields: { key: { sites: ['header:x-goog-api-key'] } },
    probe: { method: 'GET', path: '/v1beta/models' },
    health: null,
    deny_paths: [],
    scrub: ['AIza[0-9A-Za-z_-]{35}'],
    defaultBudget: { unit: 'requests', limit: 20000 },
    env: { base: 'GOOGLE_GEMINI_BASE_URL', key: 'GEMINI_API_KEY' },
  },

  http: {
    kind: 'http',
    hosts: [], // a generic credential must name its own exact host
    fields: { token: { sites: ['header:authorization:Bearer'] } },
    health: null,
    deny_paths: [],
    scrub: [],
    defaultBudget: { unit: 'requests', limit: 500 },
  },

  // The profile is the design; the L4 proxy that would carry it is not built.
  // Marked so a credential of this kind is refused at creation rather than
  // stored and handed a placeholder that can only ever misfire — the HTTP path
  // would try to send a database password as URL userinfo to a Postgres port.
  postgres: {
    kind: 'postgres',
    implemented: false,
    hosts: [],
    fields: { password: { sites: ['url:userinfo'] } },
    health: null,
    deny_paths: [],
    scrub: [],
    defaultBudget: { unit: 'sessions', limit: 20 },
    l4: true,
  },
}

/** Fetch a profile, with its policy ceiling precomputed. */
export function getProfile(kind) {
  const p = PROFILES[kind]
  if (!p) throw new Error(`unknown connector kind: ${kind}. Known: ${Object.keys(PROFILES).join(', ')}`)
  return {
    ...p,
    policyCeiling: {
      kind: p.kind,
      hosts: p.hosts.length ? p.hosts : null,
      deny_paths: p.deny_paths,
    },
  }
}

export function listProfiles() {
  return Object.keys(PROFILES).map((k) => {
    const p = PROFILES[k]
    return {
      kind: k, hosts: p.hosts, fields: Object.keys(p.fields), l4: !!p.l4,
      implemented: p.implemented !== false,
    }
  })
}

/** Default sites for a field, used when `cred add` does not override them. */
export function defaultSites(kind, field) {
  const p = PROFILES[kind]
  return p?.fields?.[field]?.sites || ['header:authorization:Bearer']
}

export function defaultField(kind) {
  const p = PROFILES[kind]
  return p ? Object.keys(p.fields)[0] : 'token'
}

const MONTHS = {
  jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6,
  jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12,
}

/**
 * Read the profile's documented health headers.
 * Pure: an unparseable expiry is omitted, and a header the profile did not
 * name is never consulted. Returns null when the profile has no health block
 * or none of its headers yielded a value.
 * @returns {{ observed_expires_at?: string, scopes?: string[], ratelimit_remaining?: number } | null}
 */
export function extractHealth(profile, headers) {
  const health = profile?.health
  if (!health) return null
  const out = {}
  if (health.expiry_header) {
    const rawExpiry = headerValue(headers, health.expiry_header)
    const iso = rawExpiry == null ? null : parseExpiry(rawExpiry)
    if (iso) out.observed_expires_at = iso
  }
  if (health.scopes_header) {
    const rawScopes = headerValue(headers, health.scopes_header)
    const scopes = rawScopes == null ? null : parseScopes(rawScopes)
    if (scopes) out.scopes = scopes
  }
  if (health.ratelimit_remaining_header) {
    const rawRemaining = headerValue(headers, health.ratelimit_remaining_header)
    const remaining = rawRemaining == null ? null : parseCount(rawRemaining)
    if (remaining != null) out.ratelimit_remaining = remaining
  }
  return Object.keys(out).length ? out : null
}

function headerValue(headers, name) {
  if (headers == null || name == null) return undefined
  const want = String(name).toLowerCase()
  if (typeof headers.get === 'function') {
    const got = headers.get(name)
    if (got == null) return undefined
    return Array.isArray(got) ? got.map(String).join(', ') : String(got)
  }
  if (typeof Map !== 'undefined' && headers instanceof Map) {
    for (const [key, value] of headers) {
      if (String(key).toLowerCase() === want) return joinHeader(value)
    }
    return undefined
  }
  if (Array.isArray(headers)) {
    const found = []
    for (const pair of headers) {
      if (!pair || String(pair[0]).toLowerCase() !== want) continue
      found.push(pair[1])
    }
    return found.length ? found.map((v) => (Array.isArray(v) ? v.map(String).join(', ') : String(v))).join(', ') : undefined
  }
  if (typeof headers !== 'object') return undefined
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === want) return joinHeader(value)
  }
  return undefined
}

function joinHeader(value) {
  if (value == null) return undefined
  if (Array.isArray(value)) return value.map(String).join(', ')
  return String(value)
}

/** Calendar date that survives a round trip through Date.UTC, or null. */
function utcIso(year, month, day, hour, minute, second) {
  if (![year, month, day, hour, minute, second].every(Number.isInteger)) return null
  if (month < 1 || month > 12 || day < 1 || day > 31) return null
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) return null
  const ms = Date.UTC(year, month - 1, day, hour, minute, second)
  if (!Number.isFinite(ms)) return null
  const date = new Date(ms)
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null
  if (date.getUTCHours() !== hour || date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second) return null
  return date.toISOString()
}

/**
 * GitHub's "2027-01-31 00:00:00 UTC", an ISO 8601 date, or an RFC 1123 date.
 * Anything else is unparseable and ignored.
 */
function parseExpiry(raw) {
  const s = String(raw).trim()
  let m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) UTC$/.exec(s)
  if (m) return utcIso(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6])
  m = /^(?:[A-Za-z]{3}, )?(\d{1,2}) ([A-Za-z]{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/.exec(s)
  if (m) {
    const month = MONTHS[m[2].toLowerCase()]
    if (month == null) return null
    return utcIso(+m[3], month, +m[1], +m[4], +m[5], +m[6])
  }
  m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2}))?$/.exec(s)
  if (!m) return null
  if (!m[4]) return utcIso(+m[1], +m[2], +m[3], 0, 0, 0)
  const offset = m[8]
  if (!offset || offset === 'Z' || offset === '+00:00' || offset === '+0000') {
    return utcIso(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6])
  }
  const ms = Date.parse(s)
  if (!Number.isFinite(ms)) return null
  return new Date(ms).toISOString()
}

function parseScopes(raw) {
  const scopes = String(raw).split(',').map((s) => s.trim()).filter(Boolean)
  return scopes.length ? scopes : null
}

function parseCount(raw) {
  const s = String(raw).trim()
  if (!/^(?:0|[1-9]\d{0,15})$/.test(s)) return null
  const n = Number(s)
  return Number.isSafeInteger(n) ? n : null
}

export { PROFILES }
