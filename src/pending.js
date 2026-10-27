// Everything waiting for a human, and how to describe it.
//
// The CLI and the web UI are two interfaces to one API. They each used to fetch
// their own idea of what was waiting and write their own labels for it, which is
// how session requests came to appear in one and not the other: not a forgotten
// line, but two implementations of one concept, drifting the moment either
// changed. Adding a third kind of decision would have meant remembering three
// places.
//
// So the shape and the words live here, once. A surface decides how to paint
// them and how it proves a human is present — ANSI and a passphrase window, or
// HTML and a WebAuthn assertion — and nothing else.

/**
 * Where to look. Each source is a control route and how to read what it
 * returns; a new kind of decision is one entry here and both interfaces show
 * it.
 */
export const SOURCES = [
  { kind: 'request', path: '/v1/approvals' },
  { kind: 'session', path: '/v1/session-requests' },
]

/** One decision, in the terms a human needs to make it. */
function describe(kind, raw) {
  if (kind === 'session') {
    return {
      id: raw.id,
      kind: 'session',
      headline: raw.summary,
      // Whatever the agent typed. Shown, never believed.
      claim: raw.agent_reason_untrusted || null,
      created_at: raw.created_at,
      // A session is hours and a budget; a held request is one call. Saying so
      // is the difference between an informed yes and a reflex one.
      caution: 'This grants hours of access, not one call.',
      // One list, read by the CLI's hint, the CLI's validation and the UI's
      // inputs — so a dimension missing here is missing from every interface.
      // `ttl_minutes` was: `summarize()` renders it and `#createSession`
      // honours it, but no interface could set it and no human could narrow it.
      // The one dimension a session request states in plain minutes could only
      // be reached by hand-writing the HTTP body.
      narrowable: [
        'methods', 'paths', 'budget', 'uses', 'ttl_minutes',
        // Wave 3: the grant limits an agent may also ask for. Each only
        // narrows, and each is a dimension a human can tighten when answering.
        'rate', 'max_concurrent', 'quota', 'routes', 'payload', 'redirects',
        'spend_tokens', 'spend_usd', 'grant_ttl_minutes',
      ],
      // What only the owner can add, never narrow: an agent cannot propose
      // either one, so they are offered here as the human's own choices.
      owner_settable: ['approval', 'infinite'],
      proposal: raw.proposal || {},
      decide: { path: '/v1/session-requests/decide', idField: 'id' },
    }
  }
  return {
    id: raw.id,
    kind: 'request',
    headline: raw.summary,
    claim: raw.reason || null,
    created_at: raw.created_at,
    caution: null,
    narrowable: [],
    owner_settable: [],
    grant_id: raw.grant_id || null,
    // What the held request would send, scrubbed by the gateway (F13). The
    // agent wrote it: it is shown as untrusted text, never acted on.
    preview: raw.preview ?? null,
    decide: { path: '/v1/approvals', idField: 'id' },
  }
}

/**
 * Everything waiting, from every source.
 *
 * `get(path)` is the caller's transport: the CLI's control socket, or the UI
 * server's proxy to it. A source that a daemon does not have yet is absent
 * rather than fatal, so a new interface talking to an old daemon degrades to
 * showing less rather than showing nothing.
 */
export async function fetchPending(get) {
  const out = []
  for (const source of SOURCES) {
    const rows = await get(source.path).catch(() => [])
    for (const raw of Array.isArray(rows) ? rows : []) out.push(describe(source.kind, raw))
  }
  // Oldest first: the thing that has been waiting longest is the thing to
  // answer, and it is the one most likely to expire.
  return out.sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)))
}

/**
 * The call that answers one decision. Overrides are the human narrowing the
 * proposal; the daemon binds its presence check to exactly what is sent here.
 */
export function decision(item, { granted, overrides = null }) {
  // Not coerced: `!!"false"` is true, and a verdict that is not a boolean is a
  // caller's bug to surface, never an approval.
  if (typeof granted !== 'boolean') throw new TypeError('the verdict must be true or false')
  const body = { [item.decide.idField]: item.id, granted }
  if (overrides && Object.keys(overrides).length) body.overrides = overrides
  return { path: item.decide.path, body }
}

/** Narrowing flags, parsed the same way wherever they are typed. */
export function parseOverrides(args = {}) {
  const out = {}
  // Split on commas and upper-cased, the way `session create`, the wizard and
  // the UI's new-session form all read them. A narrowing of "/a/**,/b/**" was
  // one glob with a comma in it, and "get" a method nothing sends: both
  // approved a session that matched nothing, with nothing saying why.
  const list = (v) => (Array.isArray(v) ? v : String(v).split(',')).map((x) => String(x).trim()).filter(Boolean)
  const given = (v) => v !== undefined && v !== null && v !== ''
  if (args.methods) out.methods = list(args.methods).map((m) => m.toUpperCase())
  if (args.paths) out.paths = list(args.paths)
  // A number as typed is a number; anything else is passed on as typed, so the
  // daemon refuses it. Number('abc') is NaN, which JSON sends as null, and a
  // null narrowing is dropped: the human's "--budget abc" approved the
  // agent's own budget with nothing saying so.
  const num = (v) => (typeof v === 'number' ? v : (/^(0|[1-9][0-9]*)$/.test(String(v)) ? Number(v) : String(v)))
  const dec = (v) => (typeof v === 'number' ? v : (/^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/.test(String(v)) ? Number(v) : String(v)))
  if (given(args.budget)) out.budget = num(args.budget)
  if (given(args.uses)) out.uses = num(args.uses)
  // The generated hint spells this `--ttl_minutes`, because it is generated
  // from the field name and there is only one list. `--ttl-minutes` is the
  // spelling a hand would reach for, so accept both.
  const ttl = args.ttl_minutes ?? args['ttl-minutes']
  if (given(ttl)) out.ttl_minutes = num(ttl)
  // The wave-3 limits, by field name or by the CLI's flag. Shapes the daemon
  // understands (`60/min`, `1000/day`) are passed through for it to check.
  const pick = (...names) => names.map((n) => args[n]).find(given)
  const grantTtl = pick('grant_ttl_minutes', 'grant-ttl', 'grant_ttl')
  if (given(grantTtl)) out.grant_ttl_minutes = num(grantTtl)
  const concurrent = pick('max_concurrent', 'concurrency')
  if (given(concurrent)) out.max_concurrent = num(concurrent)
  if (given(args.redirects)) out.redirects = num(args.redirects)
  const tokens = pick('spend_tokens', 'spend-tokens')
  if (given(tokens)) out.spend_tokens = num(tokens)
  const usd = pick('spend_usd', 'spend-usd')
  if (given(usd)) out.spend_usd = dec(usd)
  if (given(args.rate)) out.rate = typeof args.rate === 'object' ? args.rate : String(args.rate)
  if (given(args.quota)) out.quota = typeof args.quota === 'object' ? args.quota : String(args.quota)
  if (Array.isArray(args.routes)) out.routes = args.routes
  else if (given(args.route)) out.routes = (Array.isArray(args.route) ? args.route : [args.route]).map(routeOf)
  if (given(args.payload) && typeof args.payload === 'object') out.payload = args.payload
  // Owner fields. The mode is passed through as typed and validated by the
  // daemon, so a typo is refused there rather than quietly meaning something.
  if (typeof args.approval === 'string' && args.approval !== '') out.approval = args.approval
  if (args.infinite === true || args.infinite === 'true') out.infinite = true
  return out
}

/**
 * `GET,HEAD:/repos/**` as a route pair. Split on the first colon; the
 * methods are comma-separated and upper-cased. Something that is not that
 * shape is passed on as typed, for the daemon to refuse.
 */
function routeOf(text) {
  const s = String(text)
  const at = s.indexOf(':')
  if (at <= 0) return s
  return {
    methods: s.slice(0, at).split(',').map((m) => m.trim().toUpperCase()).filter(Boolean),
    paths: [s.slice(at + 1).trim()],
  }
}

/**
 * Recording an approved session where local clients look.
 *
 * The daemon cannot do this. It runs as its own uid and the state file belongs
 * to the human — that is the boundary the whole design rests on. So whichever
 * client the human approved with records it: the CLI and the web UI both run
 * as them.
 *
 * That is better than the agent collecting it anyway. The MCP bridge re-reads
 * the state file on every request, so a session recorded here reaches a RUNNING
 * agent on its next call, with no restart and nothing copied by hand.
 *
 * The session comes from the gated decision itself (`answered.session`), which
 * the daemon counts as the one collection. It used to be fetched from the
 * collect route by request id, which is what let any agent that read the id
 * off the pending list take a session meant for another; that route now wants
 * the asker's secret, which the human's client never had. `remember` is the
 * caller's writer, already bound to the right path.
 */
export function collectApproved(item, { answered, remember }) {
  if (item.kind !== 'session') return null
  const got = answered?.session
  if (!got?.token) return null
  remember(got)
  return got
}

/** What a human actually granted, in the words they would use themselves. */
export function describeGranted(g = {}) {
  const bits = [`session for ${g.cred}`]
  if (g.methods) bits.push(g.methods.join(','))
  if (g.paths) bits.push(g.paths.join(' '))
  if (g.budget) bits.push(`${g.budget} requests`)
  if (g.uses) bits.push(`${g.uses}-use placeholder`)
  if (g.approval) bits.push(`approval ${g.approval}`)
  if (g.infinite === true) bits.push('never expires')
  return bits.join(' · ')
}

/**
 * A batch of decisions a human is about to make in one act of presence.
 *
 * Bulk approval is where consent quietly becomes a formality, so the shape is
 * deliberately narrow. The signature binds this list VERBATIM, which means the
 * set is fixed at the moment it is signed: "approve everything pending" would
 * have let an agent queue one more request between the signature and the
 * execution and have it approved by a human who never saw it. That is the same
 * hole as headers outside the request hash, and this codebase has paid for it
 * twice already.
 *
 * So every item is named, every verdict is explicit, and anything the list does
 * not mention is not touched.
 */
export const MAX_BULK_DECISIONS = 25

const DECISION_KEYS = new Set(['id', 'kind', 'granted', 'overrides'])
const KINDS = new Set(SOURCES.map((s) => s.kind))

/**
 * @returns {string|null} why the list is not usable, or null if it is.
 *
 * Validation is separate from binding on purpose. The signature covers exactly
 * the bytes that were sent; this decides whether to act on them. Normalising
 * first would mean the human signed one thing and the daemon executed another.
 */
export function checkDecisions(raw) {
  if (!Array.isArray(raw)) return 'decisions must be a list'
  if (!raw.length) return 'nothing was selected'
  if (raw.length > MAX_BULK_DECISIONS) {
    return `too many at once (${raw.length}); ${MAX_BULK_DECISIONS} is the most a person can actually read`
  }
  const seen = new Set()
  for (const d of raw) {
    if (!d || typeof d !== 'object' || Array.isArray(d)) return 'each decision must be an object'
    for (const k of Object.keys(d)) {
      if (!DECISION_KEYS.has(k)) return `a decision cannot carry ${JSON.stringify(k)}`
    }
    if (typeof d.id !== 'string' || !d.id) return 'each decision needs an id'
    if (!KINDS.has(d.kind)) return `unknown kind ${JSON.stringify(d.kind)}`
    // Not truthiness. `granted: "false"` is a string and would have approved.
    if (typeof d.granted !== 'boolean') return `the verdict for ${d.id} must be true or false`
    if (d.overrides !== undefined && (typeof d.overrides !== 'object' || d.overrides === null || Array.isArray(d.overrides))) {
      return `the narrowing for ${d.id} must be an object`
    }
    if (seen.has(d.id)) return `${d.id} appears twice, with no way to say which verdict wins`
    seen.add(d.id)
  }
  return null
}
