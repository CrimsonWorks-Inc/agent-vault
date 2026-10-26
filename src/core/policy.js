// The policy engine.
//
// Effective policy = profile ceiling n workspace n session n grant, where n
// intersects lists, takes the minimum of numeric limits, the stricter approval
// mode and the narrower enum. A child can never widen: that single rule is what
// makes `session fork` safe to hand to an agent without a presence prompt.

import { deny } from './errors.js'
import { validatePayload } from './payload.js'
import { METERED_KINDS } from './model-usage.js'

export const APPROVAL_ORDER = ['auto', 'first-use', 'on-write', 'each']
export const SQL_ORDER = ['read-only', 'read-write', 'raw']
export const SSH_MODE_ORDER = ['run', 'agent']

export const PER_MS = Object.freeze({ second: 1_000, minute: 60_000, hour: 3_600_000 })
export const WINDOW_MS = Object.freeze({ hour: 3_600_000, day: 86_400_000 })
const METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/** Suffixes where a wildcard host would span unrelated tenants. */
export const MULTI_TENANT_SUFFIXES = [
  's3.amazonaws.com', 'cloudfront.net', 'github.io', 'herokuapp.com',
  'ngrok.io', 'azurewebsites.net', 'vercel.app', 'pages.dev', 'workers.dev',
  'blob.core.windows.net', 'storage.googleapis.com', 'firebaseapp.com',
]

/** Intersect two lists; an absent list means "no constraint at this level". */
function intersectList(a, b) {
  if (a == null) return b == null ? null : [...b]
  if (b == null) return [...a]
  const bs = new Set(b)
  return a.filter((x) => bs.has(x))
}

function minNum(a, b) {
  if (a == null) return b
  if (b == null) return a
  return Math.min(a, b)
}

function stricter(a, b, order) {
  if (a == null) return b
  if (b == null) return a
  if (!order.includes(a)) return a
  if (!order.includes(b)) return b
  return order.indexOf(a) >= order.indexOf(b) ? a : b
}

function narrower(a, b, order) {
  if (a == null) return b
  if (b == null) return a
  return order.indexOf(a) <= order.indexOf(b) ? a : b
}

/**
 * Intersect a chain of policy layers, outermost (ceiling) first.
 * @param {object[]} layers
 */
export function intersect(layers) {
  let out = {}
  const invalid = new Map()
  for (const original of layers) {
    if (original == null) continue
    const layer = { ...original }
    for (const problem of validate(original)) {
      const field = problem.field
      if (field === 'redirects') { layer.redirects = { max: 0 }; continue }
      if (field === 'policy') { invalid.set('methods', false); continue }
      if (field === 'budget' || field === 'spend') { invalid.set(field, { invalid: true }); delete layer[field]; continue }
      if (field === 'routes' || field === 'payload') {
        const effective = field === 'routes' ? 'route_sets' : 'payload_sets'
        invalid.set(effective, [null]); delete layer[field]; delete layer[effective]; continue
      }
      invalid.set(field, original[field]); delete layer[field]
    }
    out = {
      kind: out.kind || layer.kind,
      hosts: intersectHosts(out.hosts, layer.hosts),
      methods: intersectList(out.methods ?? null, layer.methods ?? null),
      paths: intersectPaths(out.paths, layer.paths),
      deny_paths: [...(out.deny_paths || []), ...(layer.deny_paths || [])],
      approval: stricter(out.approval, layer.approval, APPROVAL_ORDER),
      sql_profile: narrower(out.sql_profile, layer.sql_profile, SQL_ORDER),
      mode: narrower(out.mode, layer.mode, SSH_MODE_ORDER),
      rate: intersectRate(out.rate, layer.rate),
      budget: intersectBudget(out.budget, layer.budget),
      placeholder_policy: intersectPh(out.placeholder_policy, layer.placeholder_policy),
      max_concurrent: intersectLimit(out.max_concurrent, layer.max_concurrent),
      quota: intersectWindow(out.quota, layer.quota, WINDOW_MS, 'window', 100_000_000),
      spend: intersectSpend(out.spend, layer.spend),
      redirects: intersectRedirects(out.redirects, layer.redirects),
      route_sets: [...(out.route_sets ?? []), ...(layer.route_sets ?? []), ...(layer.routes ? [layer.routes] : [])],
      payload_sets: [...(out.payload_sets ?? []), ...(layer.payload_sets ?? []), ...(layer.payload ? [layer.payload] : [])],
      databases: intersectList(out.databases ?? null, layer.databases ?? null),
      rcpt: intersectList(out.rcpt ?? null, layer.rcpt ?? null),
      // A child overriding these is the same widening the paths above used to
      // allow. Narrow, or keep the outer value.
      commands: intersectList(out.commands ?? null, layer.commands ?? null),
      graphql: out.graphql ?? layer.graphql,
      // Carried through the intersection for the spec's shape, but nothing
      // reads it: request-body streaming is not implemented, so a body over
      // the buffered limit is refused rather than streamed. It stays here
      // because the semantics are the interesting part (every layer must
      // agree before it is on) and because removing it would make a future
      // implementation quietly default to open. A field that looks like a
      // control and is not is worth a sentence.
      stream_bodies: (out.stream_bodies ?? false) && (layer.stream_bodies ?? false),
    }
  }
  for (const [field, value] of invalid) out[field] = value
  return out
}

// Hosts and paths intersect by "is this entry allowed by the outer layer",
// so an inner layer naming api.github.com under an outer *.github.com keeps the
// narrower entry rather than producing an empty set.
function intersectHosts(a, b) {
  if (a == null) return b == null ? null : [...b]
  if (b == null) return [...a]
  const keep = []
  for (const hb of b) if (a.some((ha) => hostAllows(ha, hb))) keep.push(hb)
  for (const ha of a) if (b.some((hb) => hostAllows(hb, ha)) && !keep.includes(ha)) keep.push(ha)
  return [...new Set(keep)]
}

function intersectPaths(a, b) {
  if (a == null) return b == null ? null : [...b]
  if (b == null) return [...a]
  const keep = []
  for (const pb of b) if (a.some((pa) => globAllows(pa, pb))) keep.push(pb)
  for (const pa of a) if (b.some((pb) => globAllows(pb, pa)) && !keep.includes(pa)) keep.push(pa)
  return [...new Set(keep)]
}

/**
 * True when `outer` permits everything `inner` permits.
 *
 * This used to compare only the text before `**`, so a ceiling of
 * `/repos/**\/pulls` admitted a child's `/repos/anything-at-all` — the child
 * widened past its own ceiling, which is the one thing the layering exists to
 * prevent. It is now real containment over segments, and deliberately
 * conservative: where containment cannot be shown it answers false, which
 * drops the entry and narrows. Erring toward narrower is the safe direction.
 */
function globAllows(outer, inner) {
  if (outer === inner) return true
  const o = String(outer).split('/').filter((x) => x !== '')
  const i = String(inner).split('/').filter((x) => x !== '')

  const segAllows = (op, ip) => {
    if (op === ip) return true
    if (op === '*' || op === '**') return true      // covers any single segment
    if (ip.includes('*')) return false              // inner is open where outer is not
    return matchSegment(op, ip)
  }

  const seen = new Set()
  const go = (oi, ii) => {
    const key = `${oi}:${ii}`
    if (seen.has(key)) return false
    seen.add(key)
    if (oi === o.length) return ii === i.length
    if (o[oi] === '**') {
      // Absorb nothing, or absorb one more inner segment.
      if (go(oi + 1, ii)) return true
      return ii < i.length && go(oi, ii + 1)
    }
    if (ii === i.length) return false
    // A single outer segment cannot cover the arbitrarily many an inner `**`
    // can produce.
    if (i[ii] === '**') return false
    if (!segAllows(o[oi], i[ii])) return false
    return go(oi + 1, ii + 1)
  }
  return go(0, 0)
}

function hostAllows(outer, inner) {
  if (outer === inner) return true
  if (outer.startsWith('*.')) {
    const suffix = outer.slice(1)
    return inner === outer || inner.endsWith(suffix)
  }
  return false
}

/** Select the stricter sustained rate, retaining its original capacity/window. */
function intersectRate(a, b) {
  return intersectWindow(a, b, PER_MS, 'per', 1_000_000)
}

const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const integer = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isInteger(v) && v >= min && v <= max
const keys = (v, allowed) => object(v) && Object.keys(v).every((k) => allowed.includes(k))
function validWindow(v, units, key, max) {
  return keys(v, ['count', key]) && integer(v.count, 1, max) && Object.hasOwn(units, v[key])
}
function intersectWindow(a, b, units, key, max) {
  if (a != null && !validWindow(a, units, key, max)) return a
  if (b != null && !validWindow(b, units, key, max)) return b
  if (a == null) return b
  if (b == null) return a
  const ar = a.count / units[a[key]], br = b.count / units[b[key]]
  return ar < br || (ar === br && a.count <= b.count) ? a : b
}
function intersectLimit(a, b) {
  if (a != null && !integer(a, 1, 1024)) return a
  if (b != null && !integer(b, 1, 1024)) return b
  return minNum(a, b)
}
export function budgetInteger(value) {
  if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) value = Number(value)
  return integer(value) ? value : null
}
function validBudget(v) {
  // Legacy layers may state only the unit; they add no numerical limit.
  return keys(v, ['unit', 'limit']) && (v.unit === undefined || v.unit === 'requests') && (v.limit === undefined || budgetInteger(v.limit) !== null)
}
function intersectBudget(a, b) {
  for (const v of [a, b]) if (v != null && !validBudget(v)) return { unit: v.unit, invalid: true }
  const limits = [a?.limit, b?.limit].filter((value) => value !== undefined).map(budgetInteger)
  if (a == null && b == null) return undefined
  return limits.length ? { unit: 'requests', limit: Math.min(...limits) } : { unit: 'requests' }
}
function validSpend(v) {
  return keys(v, ['tokens', 'usd_micros']) && Object.values(v).every((n) => integer(n))
}
function intersectSpend(a, b) {
  if ([a, b].some((v) => v != null && !validSpend(v))) return { invalid: true }
  if (a == null) return b
  if (b == null) return a
  return Object.fromEntries(['tokens', 'usd_micros'].filter((k) => a[k] != null || b[k] != null).map((k) => [k, minNum(a[k], b[k])]))
}
function validRedirects(v) { return keys(v, ['max']) && integer(v.max, 0, 5) }
function intersectRedirects(a, b) {
  if ([a, b].some((v) => v != null && !validRedirects(v))) return { max: 0 }
  if (a == null) return b
  if (b == null) return a
  return { max: Math.min(a.max, b.max) }
}

function intersectPh(a, b) {
  if (!a) return b
  if (!b) return a
  return {
    max_uses: minNum(a.max_uses, b.max_uses),
    ttl: minNum(a.ttl, b.ttl),
    max_active: minNum(a.max_active ?? 8, b.max_active ?? 8),
  }
}

/**
 * Normalize a destination before any grant match. Anything that cannot be
 * normalized unambiguously is refused rather than guessed at.
 */
export function normalizeHost(host) {
  if (!host) throw deny('AV_POLICY_DENIED', 'no destination host')
  let h = String(host).trim().toLowerCase()
  if (h.includes('@')) throw deny('AV_POLICY_DENIED', 'destination contains userinfo')
  if (h.includes('\\') || h.includes('\0')) throw deny('AV_POLICY_DENIED', 'destination contains an illegal character')
  h = h.replace(/\.$/, '')
  try { h = new URL(`https://${h}`).hostname } catch { throw deny('AV_POLICY_DENIED', `unparseable host: ${host}`) }
  return h
}

/**
 * Normalize a path: percent-decode, collapse traversal, reject what cannot be
 * resolved. Matching happens on the normalized form so %2e%2e and /../ cannot
 * walk outside an allowed prefix.
 */
/**
 * Encode one decided path for the wire, so a URL parser reads back exactly the
 * path the policy approved.
 *
 * Not encodeURIComponent, which was what this used to be. That encodes
 * everything outside `A-Za-z0-9-_.!~*'()` — including `:` `@` `$` `&` `+` `,`
 * `;` `=`, all of which RFC 3986 allows in a path segment and several of which
 * carry meaning:
 *
 *   /v1beta/models/gemini-pro:generateContent   the Gemini endpoint, in this
 *                                               project's own README
 *   /@scope/package                             every scoped npm package
 *   /Products(1)/Name                           OData
 *
 * All three were approved by the policy and then sent somewhere else. The
 * point of encoding here is that the two readings agree, not that the path be
 * unreadable, so this encodes exactly what is not a legal path character:
 * `/`, `?` and `#` (which would re-split or truncate it), `%` (so a literal
 * one round-trips), and anything else outside pchar.
 */
const PCHAR_SAFE = /[A-Za-z0-9\-._~!$&'()*+,;=:@]/

export function encodePathSegment(segment) {
  let out = ''
  for (const ch of String(segment)) {
    if (PCHAR_SAFE.test(ch)) { out += ch; continue }
    for (const byte of Buffer.from(ch, 'utf8')) {
      out += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`
    }
  }
  return out
}

/** A whole path, segment by segment. The separators are the only bare slashes. */
export function encodePathForWire(path) {
  return String(path).split('/').map(encodePathSegment).join('/')
}

/**
 * The path a request names, decoded once — which is what goes on the wire,
 * re-encoded — or a refusal.
 *
 * A path is decoded exactly once, and refused if decoding it again would
 * change it. This used to decode to a fixed point and check two readings,
 * once and fully decoded, but an upstream may decode any number of times in
 * between: `/a/b%252520c` was allowed on both readings and an upstream that
 * decodes twice served `/a/b%20c`, which neither reading was. No count of
 * readings closes that, so an escape that is itself encoded is refused.
 */
export function normalizePath(path) {
  const raw = String(path || '/')

  // The request itself must be well-formed.
  let p
  try { p = decodeURIComponent(raw) } catch {
    throw deny('AV_POLICY_DENIED', 'path contains an invalid percent-escape')
  }

  // Everything below decides what resource this names. A URL parser answers
  // the same question differently, and where the two disagree the request
  // goes somewhere the policy did not authorise.
  //
  //   An encoded slash is genuinely ambiguous: to this function it is a
  //   separator, to some upstreams a literal character in one segment. Two
  //   readings means two different resources, so it is refused rather than
  //   guessed. The same goes for a backslash, which several servers fold to
  //   a separator.
  //
  //   Both are looked for in the decoded path as well, so a backslash encoded
  //   twice (`%255c`) is named for what it is rather than only as the double
  //   encoding below.
  if (/%2f|%5c|\\/i.test(raw) || /%2f|%5c|\\/i.test(p)) {
    throw deny('AV_POLICY_DENIED', 'path contains an encoded slash or a backslash', {
      rule: 'path_ambiguous_separator',
      hint: 'Whether that names one segment or two depends on the upstream, so the path checked here may not be the path served.',
    })
  }

  //   Decoded once, nothing may still decode. `%25` followed by hex is an
  //   escape that was itself encoded, and an upstream that decodes again
  //   serves another path. A `%` that starts no escape is a literal percent
  //   sign, as in `/files/100%25`, and is sent as one. `%u` and four hex
  //   digits counts as an escape too: IIS decodes it.
  if (/%(?:[0-9a-f]{2}|u[0-9a-f]{4})/i.test(p)) {
    throw deny('AV_POLICY_DENIED', 'path is percent-encoded too many times: decoding it again would change it', {
      rule: 'path_ambiguous_encoding',
      hint: 'An upstream that decodes the path twice would serve a different path from the one checked here. Encode the path once.',
    })
  }

  //   `?` and `#` end the path. They survived decoding, so `/user/keys%23`
  //   was matched as "/user/keys#" (no deny glob hits) and then sent as
  //   "/user/keys".
  const cut = p.search(/[?#]/)
  if (cut !== -1) p = p.slice(0, cut)

  //   TAB, LF and CR are deleted outright by the WHATWG URL parser, so
  //   "/repos/o/r/hooks\t" matched no deny glob and arrived as
  //   "/repos/o/r/hooks". Every C0 control and DEL is refused: none of them
  //   belongs in a path, and each is a chance for two parsers to disagree.
  const control = /[\u0000-\u001f\u007f]/.exec(p)
  if (control) {
    const code = control[0].charCodeAt(0).toString(16).padStart(2, '0')
    throw deny('AV_POLICY_DENIED', `path contains a control character (0x${code})`, {
      rule: 'path_control_char',
      hint: 'A URL parser strips or reinterprets these, so the path checked here would not be the path requested.',
    })
  }

  const segments = []
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (segments.length === 0) throw deny('AV_POLICY_DENIED', 'path traverses above its root')
      segments.pop()
      continue
    }
    segments.push(seg)
  }
  return `/${segments.join('/')}`
}

/**
 * Glob matching, done segment by segment rather than by compiling to a regex.
 *
 * The regex version turned `**` into `.*`, so a pattern like `/**\/**\/**...`
 * built `^\/.*\/.*\/...$` and backtracked exponentially: fourteen groups took
 * 37 seconds, and the daemon is single-threaded, so that is 37 seconds where
 * nothing else in the vault answers. Anyone who can supply a grant or deny
 * path could do it.
 *
 * Making the quantifiers atomic would kill the backtracking and the matching
 * with it — `/**\/pulls` needs to backtrack to be correct. So the regex is
 * gone. This is the usual two-dimensional glob match: linear in
 * segments × pattern segments, with no backtracking to exploit.
 */
function matchSegment(pat, seg) {
  // `*` inside one segment, e.g. `admin.*`. Same shape, one dimension.
  const dp = new Array(seg.length + 1).fill(false)
  dp[0] = true
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i]
    if (c === '*') {
      // Once a prefix matches, every longer prefix does too.
      let seen = false
      for (let j = 0; j <= seg.length; j++) {
        seen = seen || dp[j]
        dp[j] = seen
      }
    } else {
      for (let j = seg.length; j >= 0; j--) {
        dp[j] = j > 0 && dp[j - 1] && seg[j - 1] === c
      }
    }
  }
  return dp[seg.length]
}

export function matchPath(pattern, path) {
  const pats = String(pattern).split('/').filter((x) => x !== '')
  const segs = String(path).split('/').filter((x) => x !== '')

  // reachable[j] === "the first j path segments can be consumed by the
  // pattern segments seen so far".
  let reachable = new Array(segs.length + 1).fill(false)
  reachable[0] = true
  for (const pat of pats) {
    const next = new Array(segs.length + 1).fill(false)
    if (pat === '**') {
      // Matches zero or more segments, so anything at or past a reachable
      // point stays reachable.
      let seen = false
      for (let j = 0; j <= segs.length; j++) {
        seen = seen || reachable[j]
        next[j] = seen
      }
    } else {
      for (let j = 1; j <= segs.length; j++) {
        next[j] = reachable[j - 1] && matchSegment(pat, segs[j - 1])
      }
    }
    reachable = next
  }
  return reachable[segs.length]
}


export function matchHost(pattern, host) {
  if (pattern === host) return true
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1)
    return host.endsWith(suffix) && host.length > suffix.length
  }
  return false
}

/**
 * The hosts a credential may ever reach: its own connector host, plus the
 * built-in profile's host list. A grant is confined to this set, so an agent
 * that mints its own grant still cannot point the credential anywhere else.
 */
export function credentialHostCeiling(cred, profileHosts = []) {
  const set = []
  const add = (h) => {
    if (!h) return
    // Compare on the hostname; the port travels with the connection, not the
    // allowlist, so a smuggled port cannot widen the set.
    let host = String(h).toLowerCase()
    if (host.startsWith('[')) host = host.slice(0, host.indexOf(']') + 1)
    else host = host.split(':')[0]
    host = host.replace(/\.$/, '')
    if (host && !set.includes(host)) set.push(host)
  }
  add(cred?.connector?.host)
  for (const h of profileHosts || []) add(h)
  return set
}

/** Hostname only, lowercased, port and trailing dot removed. */
export function hostOnly(authority) {
  let h = String(authority || '').toLowerCase().trim()
  if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1)
  return h.split(':')[0].replace(/\.$/, '')
}

/**
 * Confine a set of requested hosts to a credential's ceiling. Returns the
 * confined list; throws AV_POLICY_DENIED naming the offending host if any
 * requested host is outside the ceiling. An empty request defaults to the
 * whole ceiling.
 */
export function confineHosts(requested, ceiling) {
  if (!ceiling.length) {
    throw deny('AV_POLICY_DENIED', 'this credential declares no host it may reach', { rule: 'credential_host' })
  }
  if (requested == null || !requested.length) return [...ceiling]
  const out = []
  for (const req of requested) {
    const h = hostOnly(req)
    const allowed = ceiling.some((c) => matchHost(c, h))
    if (!allowed) {
      throw deny('AV_POLICY_DENIED', `host ${h} is outside what credential permits (${ceiling.join(', ')})`, {
        rule: 'credential_host',
        hint: 'A grant can only reach the hosts the credential itself declares.',
      })
    }
    if (!out.includes(h)) out.push(h)
  }
  return out
}

/** Is a wildcard host pattern spanning a shared, multi-tenant suffix? */
export function isMultiTenantWildcard(pattern) {
  if (!pattern.startsWith('*.')) return false
  const suffix = pattern.slice(2)
  return MULTI_TENANT_SUFFIXES.some((s) => suffix === s || suffix.endsWith(`.${s}`))
}

/**
 * Evaluate an HTTP request against an effective policy.
 * Throws a VaultError on denial; returns the matched rule name on success.
 */
export function evaluateHttp(policy, { method, host, path }) {
  for (const problem of validate(policy)) {
    if (problem.field === 'redirects') continue
    throw deny('AV_POLICY_DENIED', problem.field === 'budget' ? 'budget limit is not a number in the accepted integer format' : `invalid policy field ${problem.field}`, { rule: `${problem.field}_invalid` })
  }
  const m = String(method || 'GET').toUpperCase()
  const h = normalizeHost(host)
  const p = normalizePath(path)

  if (policy.hosts && !policy.hosts.some((pat) => matchHost(pat, h))) {
    throw deny('AV_NO_GRANT', `no grant allows host ${h}`, {
      rule: 'hosts',
      hint: policy.hosts.length
        ? `This session may reach: ${policy.hosts.join(', ')}.`
        : 'This session has no host grants at all.',
    })
  }
  if (policy.methods && !policy.methods.includes(m)) {
    throw deny('AV_POLICY_DENIED', `method ${m} is not allowed`, {
      rule: 'methods',
      hint: `Allowed methods: ${(policy.methods || []).join(', ') || 'none'}.`,
    })
  }
  for (const dp of policy.deny_paths || []) {
    if (matchPath(dp, p)) {
      throw deny('AV_POLICY_DENIED', `path ${p} is on a deny list`, {
        rule: `deny_paths:${dp}`,
        hint: 'This path is denied by the connector profile and cannot be granted.',
      })
    }
  }
  // Which pattern let it through, not merely that something did. The audit
  // log records this as `path_glob_matched`, and it was the literal string
  // "allow" on every record ever written — a field named for the glob that
  // never once held a glob.
  let matched = null
  if (policy.paths) {
    matched = policy.paths.find((pat) => matchPath(pat, p)) ?? null
    if (matched === null) {
      throw deny('AV_POLICY_DENIED', `path ${p} is outside the grant`, {
        rule: 'paths',
        hint: `Allowed paths: ${(policy.paths || []).join(', ') || 'none'}.`,
      })
    }
  }
  let route_matched = null
  for (const set of policy.route_sets ?? (policy.routes ? [policy.routes] : [])) {
    const pair = set.find((pair) => pair.methods.includes(m) && pair.paths.some((glob) => matchPath(glob, p)))
    if (!pair) throw deny('AV_POLICY_DENIED', 'request is outside the allowed routes', {
      rule: 'routes', hint: `Allowed here: ${set.flatMap((pair) => pair.methods.flatMap((method) => pair.paths.map((glob) => `${method} ${glob}`))).join(' | ')}`,
    })
    route_matched = `${m} ${pair.paths.find((glob) => matchPath(glob, p))}`
  }
  return { host: h, path: p, method: m, rule: matched ?? 'allow', matched, route_matched }
}

/** Does this request need a human approval under the effective policy? */
export function needsApproval(policy, { method, firstUse }) {
  const mode = policy.approval === undefined ? 'auto' : policy.approval
  const m = String(method || 'GET').toUpperCase()
  switch (mode) {
    case 'auto': return false
    case 'first-use': return !!firstUse
    case 'on-write': return !SAFE_METHODS.has(m)
    case 'each': return true
    default: return true
  }
}

/** Static checks that run before a policy is stored, surfaced by `policy lint`. */
export function lint(policy, { kind } = {}) {
  if (!object(policy)) return validate(policy).map((p) => ({ level: 'error', rule: p.field, message: p.message }))
  const problems = []
  if (!policy.budget || policy.budget.limit == null) {
    problems.push({ level: 'error', rule: 'budget', message: 'every grant must set a budget; add budget: { requests: N }' })
  }
  for (const host of Array.isArray(policy.hosts) ? policy.hosts : []) {
    if (typeof host === 'string' && isMultiTenantWildcard(host)) {
      problems.push({ level: 'error', rule: 'hosts', message: `${host} spans a shared multi-tenant suffix; name exact hosts` })
    }
  }
  for (const p of Array.isArray(policy.paths) ? policy.paths : []) {
    if (p === '/**' || p === '**') {
      problems.push({ level: 'warn', rule: 'paths', message: 'a root ** grant allows every path this connector permits' })
    }
  }
  const ph = policy.placeholder_policy
  if (ph && ph.max_uses != null && ph.max_uses < 100 && (kind === 'http' || kind === 'github' || kind === 'slack')) {
    problems.push({
      level: 'warn', rule: 'placeholder_policy',
      message: 'a low max_uses breaks SDK pagination and retries; session-lifetime is the default for a reason',
    })
  }
  if ((Array.isArray(policy.methods) ? policy.methods : []).some((m) => !SAFE_METHODS.has(m)) && (policy.approval || 'auto') === 'auto') {
    problems.push({ level: 'warn', rule: 'approval', message: 'write methods with approval: auto; on-write is the default for a reason' })
  }
  for (const problem of validate(policy, { kind })) problems.push({ level: 'error', rule: problem.field, message: problem.message })
  for (const set of Array.isArray(policy.route_sets) ? policy.route_sets : (Array.isArray(policy.routes) ? [policy.routes] : [])) {
    if (Array.isArray(set) && set.some((pair) => Array.isArray(pair.methods) && pair.methods.some((m) => !SAFE_METHODS.has(m)) && pair.paths?.some((p) => p === '/**' || p === '**'))) {
      problems.push({ level: 'warn', rule: 'routes', message: 'write route permits every path' })
    }
  }
  return problems
}

function stringList(v, predicate = () => true) {
  return Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0 && predicate(s))
}
function validRoutes(v) {
  return Array.isArray(v) && v.length <= 64 && v.every((pair) => keys(pair, ['methods', 'paths']) &&
    stringList(pair.methods, (m) => METHODS.includes(m)) && pair.methods.length >= 1 && pair.methods.length <= 7 &&
    stringList(pair.paths) && pair.paths.length >= 1 && pair.paths.length <= 64)
}
function validPayload(v) { return validatePayload(v).length === 0 }

/** Pure validation of both writable layers and stored effective policies. */
export function validate(layer, { kind } = {}) {
  if (!object(layer)) return [{ field: 'policy', message: 'policy must be an object' }]
  const problems = []
  const check = (field, ok) => { if (!ok) problems.push({ field, message: `invalid ${field}` }) }
  for (const [field, value] of Object.entries(layer)) {
    // Undefined fields are emitted by intersection for unconstrained values.
    if (value === undefined) continue
    if (['hosts', 'methods', 'paths', 'databases', 'rcpt', 'commands'].includes(field) && value === null) continue
    switch (field) {
      case 'kind': check(field, typeof value === 'string' && value.length > 0); break
      case 'hosts': case 'paths': case 'deny_paths': case 'databases': case 'rcpt': case 'commands': check(field, stringList(value)); break
      case 'methods': check(field, stringList(value, (m) => METHODS.includes(m))); break
      case 'approval': check(field, APPROVAL_ORDER.includes(value)); break
      case 'sql_profile': check(field, SQL_ORDER.includes(value)); break
      case 'mode': check(field, SSH_MODE_ORDER.includes(value)); break
      case 'budget': check(field, validBudget(value)); break
      case 'spend': check(field, validSpend(value)); break
      case 'rate': check(field, validWindow(value, PER_MS, 'per', 1_000_000)); break
      case 'quota': check(field, validWindow(value, WINDOW_MS, 'window', 100_000_000)); break
      case 'max_concurrent': check(field, integer(value, 1, 1024)); break
      case 'redirects': check(field, validRedirects(value)); break
      case 'routes': check(field, validRoutes(value)); break
      case 'route_sets': check('routes', Array.isArray(value) && value.every(validRoutes)); break
      case 'payload': check(field, validPayload(value)); break
      case 'payload_sets': check('payload', Array.isArray(value) && value.every(validPayload)); break
      case 'stream_bodies': check(field, typeof value === 'boolean'); break
      case 'graphql': check(field, object(value)); break
      case 'placeholder_policy': check(field, keys(value, ['max_uses', 'ttl', 'max_active']) && Object.values(value).every((n) => n === undefined || integer(n, 1))); break
      default: check(field, false)
    }
  }
  if (layer.spend !== undefined && kind !== undefined && !METERED_KINDS.includes(kind)) problems.push({ field: 'spend', message: 'spend applies only to anthropic, openai and google-genai' })
  return problems
}

/** Convert the public grant input to a policy layer without mutating input. */
export function grantPolicyFromInput(spec, { profile = {}, ceiling = [], defaults = true } = {}) {
  const out = {}
  const has = (k) => Object.hasOwn(spec, k)
  const hostCeiling = Array.isArray(ceiling) ? ceiling : (ceiling.hosts ?? profile.policyCeiling?.hosts ?? [])
  if (defaults || has('hosts')) out.hosts = confineHosts(spec.hosts, hostCeiling)
  for (const [k, fallback] of [['methods', ['GET', 'HEAD']], ['paths', ['/**']], ['approval', 'on-write']]) {
    if (defaults || has(k)) out[k] = has(k) ? structuredClone(spec[k]) : fallback
  }
  if (defaults || has('budget')) out.budget = { unit: profile.defaultBudget?.unit ?? 'requests', limit: has('budget') ? (budgetInteger(spec.budget) ?? spec.budget) : (profile.defaultBudget?.limit ?? 500) }
  for (const k of ['deny_paths', 'max_concurrent', 'routes', 'payload', 'sql_profile', 'mode', 'databases', 'rcpt', 'commands', 'graphql', 'stream_bodies', 'placeholder_policy']) {
    if (has(k)) out[k] = structuredClone(spec[k])
  }
  const aliases = { s: 'second', sec: 'second', second: 'second', m: 'minute', min: 'minute', minute: 'minute', h: 'hour', hour: 'hour', d: 'day', day: 'day' }
  for (const [k, key, allowed] of [['rate', 'per', PER_MS], ['quota', 'window', WINDOW_MS]]) {
    if (!has(k)) continue
    let v = structuredClone(spec[k])
    if (typeof v === 'string') {
      const match = /^(\d+)\/(s|sec|second|m|min|minute|h|hour|d|day)$/.exec(v)
      if (match && Object.hasOwn(allowed, aliases[match[2]])) v = { count: Number(match[1]), [key]: aliases[match[2]] }
    }
    out[k] = v
  }
  if (defaults || has('redirects')) out.redirects = { max: has('redirects') ? spec.redirects : 0 }
  if (has('spend_tokens') || has('spend_usd')) {
    out.spend = {}
    if (has('spend_tokens')) out.spend.tokens = spec.spend_tokens
    if (has('spend_usd')) {
      const usd = spec.spend_usd
      if (typeof usd !== 'number' || !Number.isFinite(usd) || usd < 0 || Math.abs(usd * 1e6 - Math.round(usd * 1e6)) > 1e-7) {
        throw deny('AV_POLICY_DENIED', 'invalid spend_usd', { rule: 'policy_invalid' })
      }
      out.spend.usd_micros = Math.round(usd * 1e6)
    }
  }
  const problems = validate(out, { kind: profile.kind })
  if (problems.length) throw deny('AV_POLICY_DENIED', `invalid policy field ${problems[0].field}`, { rule: 'policy_invalid' })
  return out
}

/** A detached, public description containing no runtime counters or secrets. */
export function describeEffective(effective) {
  const out = {}
  for (const k of ['hosts', 'methods', 'paths', 'deny_paths', 'approval', 'spend', 'rate', 'max_concurrent', 'quota']) out[k] = effective[k] ?? null
  out.routes = effective.route_sets ?? (effective.routes ? [effective.routes] : [])
  out.payload = effective.payload_sets ?? (effective.payload ? [effective.payload] : [])
  // A limit that is not a canonical integer is described as one, not as an
  // unlimited budget: the gateway refuses every request on it.
  out.budget = effective.budget ? (effective.budget.invalid ? { limit: null, invalid: true } : { limit: effective.budget.limit ?? null }) : null
  out.redirects = validRedirects(effective.redirects) ? effective.redirects : { max: 0 }
  return structuredClone(out)
}
