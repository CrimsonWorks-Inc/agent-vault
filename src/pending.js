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
      narrowable: ['methods', 'paths', 'budget', 'uses', 'ttl_minutes'],
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
    grant_id: raw.grant_id || null,
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
  const body = { [item.decide.idField]: item.id, granted: !!granted }
  if (overrides && Object.keys(overrides).length) body.overrides = overrides
  return { path: item.decide.path, body }
}

/** Narrowing flags, parsed the same way wherever they are typed. */
export function parseOverrides(args = {}) {
  const out = {}
  if (args.methods) out.methods = String(args.methods).split(',').map((m) => m.trim()).filter(Boolean)
  if (args.paths) out.paths = Array.isArray(args.paths) ? args.paths : [String(args.paths)]
  if (args.budget !== undefined && args.budget !== null && args.budget !== '') out.budget = Number(args.budget)
  if (args.uses !== undefined && args.uses !== null && args.uses !== '') out.uses = Number(args.uses)
  // The generated hint spells this `--ttl_minutes`, because it is generated
  // from the field name and there is only one list. `--ttl-minutes` is the
  // spelling a hand would reach for, so accept both.
  const ttl = args.ttl_minutes ?? args['ttl-minutes']
  if (ttl !== undefined && ttl !== null && ttl !== '') out.ttl_minutes = Number(ttl)
  return out
}

/**
 * Collecting an approved session, and recording it where local clients look.
 *
 * The daemon cannot do this. It runs as its own uid and the state file belongs
 * to the human — that is the boundary the whole design rests on. So whichever
 * client the human approved with collects the token and records it: the CLI and
 * the web UI both run as them.
 *
 * That is better than the agent collecting it anyway. The MCP bridge re-reads
 * the state file on every request, so a session recorded here reaches a RUNNING
 * agent on its next call, with no restart and nothing copied by hand.
 *
 * The token is handed out once, so this is the one collection. `remember` is the
 * caller's writer, already bound to the right path.
 */
export async function collectApproved(item, { get, remember }) {
  if (item.kind !== 'session') return null
  const got = await get(`/v1/session-requests/collect?id=${encodeURIComponent(item.id)}`).catch(() => null)
  if (!got || got.state !== 'approved' || !got.token) return null
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
  return bits.join(' · ')
}
