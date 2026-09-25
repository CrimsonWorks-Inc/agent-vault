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
      narrowable: ['methods', 'paths', 'budget', 'uses'],
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
  return out
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
