// The policy engine.
//
// Effective policy = profile ceiling n workspace n session n grant, where n
// intersects lists, takes the minimum of numeric limits, the stricter approval
// mode and the narrower enum. A child can never widen: that single rule is what
// makes `session fork` safe to hand to an agent without a presence prompt.

import { deny } from './errors.js'

export const APPROVAL_ORDER = ['auto', 'first-use', 'on-write', 'each']
export const SQL_ORDER = ['read-only', 'read-write', 'raw']
export const SSH_MODE_ORDER = ['run', 'agent']

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
  for (const layer of layers) {
    if (!layer) continue
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
      max_concurrent: minNum(out.max_concurrent, layer.max_concurrent),
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

function intersectRate(a, b) {
  if (!a) return b
  if (!b) return a
  return { count: Math.min(a.count, b.count), per: a.per }
}

function intersectBudget(a, b) {
  if (!a) return b
  if (!b) return a
  // A layer that names a unit but no limit constrains nothing, and Math.min
  // with an absent limit is NaN. Every budget check is `used >= limit`, and
  // `anything >= NaN` is false — so one layer written `{unit:'requests'}`
  // turned a counted grant into an uncounted one, silently, in the counter
  // itself. Take the tightest limit anyone actually stated, or none.
  // Coerced, because a limit can arrive as "50" from a config file, an MCP
  // tool or a hand-written policy, and refusing that would be fail-closed on
  // something that plainly means fifty. Number('') is 0, so the empty string
  // is excluded explicitly rather than read as a budget of nothing.
  const unit = b.unit || a.unit
  const limits = [a.limit, b.limit]
    .filter((n) => n !== null && n !== undefined && n !== '')
    .map(Number)
    .filter((n) => Number.isFinite(n))
  return limits.length ? { unit, limit: Math.min(...limits) } : { unit }
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

export function normalizePath(path) {
  let p = String(path || '/')

  // Decode to a fixed point, not a fixed number of rounds. Two rounds left a
  // live escape in the output at three levels of encoding, and the forwarded
  // path was the un-normalized original, so the upstream resolved something
  // the policy never saw.
  let decoded = p
  for (let i = 0; i < MAX_DECODE_ROUNDS; i++) {
    let next
    try { next = decodeURIComponent(decoded) } catch {
      throw deny('AV_POLICY_DENIED', 'path contains an invalid percent-escape')
    }
    if (next === decoded) break
    decoded = next
    if (i === MAX_DECODE_ROUNDS - 1) {
      throw deny('AV_POLICY_DENIED', 'path is percent-encoded too many times to resolve')
    }
  }

  // Everything below decides what resource this names. A URL parser answers
  // the same question differently, and where the two disagree the request
  // goes somewhere the policy did not authorise.
  //
  //   `?` and `#` end the path. They survived decoding, so `/user/keys%23`
  //   was matched as "/user/keys#" (no deny glob hits) and then sent as
  //   "/user/keys".
  const cut = decoded.search(/[?#]/)
  if (cut !== -1) decoded = decoded.slice(0, cut)

  //   An encoded slash is genuinely ambiguous: to this function it is a
  //   separator, to some upstreams a literal character in one segment. Two
  //   readings means two different resources, so it is refused rather than
  //   guessed. The same goes for a backslash, which several servers fold to
  //   a separator.
  if (/%2f|%5c|\\/i.test(String(path || ''))) {
    throw deny('AV_POLICY_DENIED', 'path contains an encoded slash or a backslash', {
      rule: 'path_ambiguous_separator',
      hint: 'Whether that names one segment or two depends on the upstream, so the path checked here may not be the path served.',
    })
  }

  //   TAB, LF and CR are deleted outright by the WHATWG URL parser, so
  //   "/repos/o/r/hooks\t" matched no deny glob and arrived as
  //   "/repos/o/r/hooks". Every C0 control and DEL is refused: none of them
  //   belongs in a path, and each is a chance for two parsers to disagree.
  const control = /[\u0000-\u001f\u007f]/.exec(decoded)
  if (control) {
    const code = control[0].charCodeAt(0).toString(16).padStart(2, '0')
    throw deny('AV_POLICY_DENIED', `path contains a control character (0x${code})`, {
      rule: 'path_control_char',
      hint: 'A URL parser strips or reinterprets these, so the path checked here would not be the path requested.',
    })
  }

  const segments = []
  for (const seg of decoded.split('/')) {
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

// Enough for any legitimate double-encoding, far short of a decode bomb.
const MAX_DECODE_ROUNDS = 5

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
  if (policy.paths && !policy.paths.some((pat) => matchPath(pat, p))) {
    throw deny('AV_POLICY_DENIED', `path ${p} is outside the grant`, {
      rule: 'paths',
      hint: `Allowed paths: ${(policy.paths || []).join(', ') || 'none'}.`,
    })
  }
  return { host: h, path: p, method: m, rule: 'allow' }
}

/** Does this request need a human approval under the effective policy? */
export function needsApproval(policy, { method, firstUse }) {
  const mode = policy.approval || 'auto'
  const m = String(method || 'GET').toUpperCase()
  switch (mode) {
    case 'auto': return false
    case 'first-use': return !!firstUse
    case 'on-write': return !SAFE_METHODS.has(m)
    case 'each': return true
    default: return false
  }
}

/** Static checks that run before a policy is stored, surfaced by `policy lint`. */
export function lint(policy, { kind } = {}) {
  const problems = []
  if (!policy.budget || policy.budget.limit == null) {
    problems.push({ level: 'error', rule: 'budget', message: 'every grant must set a budget; add budget: { requests: N }' })
  }
  for (const host of policy.hosts || []) {
    if (isMultiTenantWildcard(host)) {
      problems.push({ level: 'error', rule: 'hosts', message: `${host} spans a shared multi-tenant suffix; name exact hosts` })
    }
  }
  for (const p of policy.paths || []) {
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
  if ((policy.methods || []).some((m) => !SAFE_METHODS.has(m)) && (policy.approval || 'auto') === 'auto') {
    problems.push({ level: 'warn', rule: 'approval', message: 'write methods with approval: auto; on-write is the default for a reason' })
  }
  return problems
}
