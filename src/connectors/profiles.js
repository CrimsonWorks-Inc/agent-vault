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
    deny_paths: ['/api/admin.*', '/api/oauth.*', '/api/apps.connections.open', '/api/apps.manifest.*', '/api/users.profile.set'],
    scrub: ['xox[abpors]-[0-9A-Za-z-]{10,}'],
    defaultBudget: { unit: 'requests', limit: 500 },
  },

  anthropic: {
    kind: 'anthropic',
    hosts: ['api.anthropic.com'],
    fields: { key: { sites: ['header:x-api-key'] } },
    probe: { method: 'GET', path: '/v1/models' },
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
    deny_paths: [],
    scrub: ['AIza[0-9A-Za-z_-]{35}'],
    defaultBudget: { unit: 'requests', limit: 20000 },
    env: { base: 'GOOGLE_GEMINI_BASE_URL', key: 'GEMINI_API_KEY' },
  },

  http: {
    kind: 'http',
    hosts: [], // a generic credential must name its own exact host
    fields: { token: { sites: ['header:authorization:Bearer'] } },
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

export { PROFILES }
