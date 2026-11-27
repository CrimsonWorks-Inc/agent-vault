// How one waiting decision, or several, becomes a signed request. Plain JS so
// the rules can be read (and tested) apart from the cards that call them.
//
// Everything here carries what GET pending gave it: the kind, the id, which
// fields can be narrowed. It decides none of that (src/pending.js does, for
// the CLI and this page alike).
//
// The narrowing is read by the CLI's own parser, parseOverrides from
// src/pending.js, bundled into the page at build time (contract C21, U2). A
// copy kept here would be a second reader, and the server rebuilds the signed
// operation with the first.

import { checkDecisions, parseOverrides } from '../../../../legacy/js/src/pending.js'

/** The approval modes an owner can choose for a session request, in the old page's order. */
export const OWNER_APPROVALS = [
  { value: '', label: 'unchanged' },
  { value: 'on-write', label: 'on-write' },
  { value: 'each', label: 'each' },
  { value: 'first-use', label: 'first-use' },
  { value: 'auto', label: 'auto: never ask' },
]

/**
 * What the human typed on one card, as the parser's input. Only when
 * approving: a denial carries no narrowing. The owner's approval is sent as
 * chosen, '' included (the parser reads '' as unchanged), and `infinite` only
 * when ticked, exactly as the old page read its inputs.
 *
 * `draft` is `{ fields: { [name]: text }, approval: string, infinite: boolean }`.
 */
export function typedNarrowing(item, draft = {}, granted = true) {
  const typed = {}
  if (!granted) return typed
  for (const f of item?.narrowable || []) {
    const v = String(draft.fields?.[f] ?? '').trim()
    if (v) typed[f] = v
  }
  if ((item?.owner_settable || []).length) {
    typed.approval = draft.approval ?? ''
    if (draft.infinite === true) typed.infinite = true
  }
  return typed
}

/**
 * The narrowing typed for a decision, as the one parser reads it, or why it
 * does not parse. The parser throws on a number that is not finite and on
 * routes or payload that are not JSON (C23); the caller then sends nothing,
 * so a decision never goes through without the narrowing typed for it.
 */
export function readNarrowing(typed) {
  try {
    return { overrides: parseOverrides(typed) }
  } catch (e) {
    return { error: `That narrowing does not parse, so nothing was sent: ${e?.message ?? e}` }
  }
}

/**
 * The signed operation and the request for one decision, byte for byte what
 * The old page sent. The signature covers the verdict AND any narrowing, so an
 * approval of "GET /user only" cannot be replayed to grant the wide original.
 *
 * Throws (before any signature is asked for) when the narrowing does not parse.
 */
export async function decisionCall(item, granted, draft, { operationFor, api }) {
  if (item.kind === 'credential') return credentialCall(item, granted, draft, { operationFor, api })
  const narrowing = readNarrowing(typedNarrowing(item, draft, granted))
  if (narrowing.error) throw new Error(narrowing.error)
  const { overrides } = narrowing
  const id = item.id
  if (item.kind === 'session') {
    return {
      operation: await operationFor('session_request.decide', { id, granted, ...overrides }),
      send: (proof) => api.post('session-requests/decide', {
        id, granted, overrides: granted ? overrides : undefined, presence: proof,
      }),
    }
  }
  return {
    operation: await operationFor(granted ? 'approval.approve' : 'approval.deny', { id, granted }),
    send: (proof) => api.post('approvals', { id, granted, presence: proof }),
  }
}

/**
 * A credential an agent proposed. Approving takes two things from the human,
 * in order: that they confirmed the hosts the key would be sent to, and the
 * key they typed. The signature binds the hosts exactly as shown and the key
 * by its digest (cred_proposal.approve, value_sha256); a denial carries
 * neither.
 *
 * `draft` is `{ hostsConfirmed: boolean, value: string }`.
 */
export async function credentialCall(item, granted, draft = {}, { operationFor, api }) {
  const id = item.id
  if (!granted) {
    return {
      operation: await operationFor('cred_proposal.deny', { id, granted }),
      send: (proof) => api.post('cred-proposals/decide', { id, granted, presence: proof }),
    }
  }
  const hosts = [...(item.hosts || [])]
  if (!hosts.length) throw new Error('This proposal names no host, so there is nothing to confirm.')
  if (draft.hostsConfirmed !== true) throw new Error('Confirm the host first.')
  // Trimmed, as the CLI reads it: a pasted key often carries a newline.
  const value = String(draft.value ?? '').trim()
  if (!value) throw new Error('Type the key first.')
  const body = { id, granted, hosts, value }
  return {
    operation: await operationFor('cred_proposal.approve', body),
    send: (proof) => api.post('cred-proposals/decide', { ...body, presence: proof }),
  }
}

/** Whether an item can be ticked for a bulk decision: a proposed key needs its own. */
export function bulkable(item) {
  return item?.kind === 'request' || item?.kind === 'session'
}

/**
 * Several decisions, one signature. The list is what is TICKED, never
 * "everything pending": the signature binds this exact set, so a request that
 * arrives between signing and executing is not covered by it and is not
 * touched. Per-item narrowing is deliberately not carried (a screen where you
 * tick twelve boxes is not where that attention exists).
 *
 * `picked` is the ticked items in the order they are shown.
 */
export function bulkDecisions(picked, granted) {
  const decisions = picked.map((item) => ({ id: item.id, kind: item.kind, granted }))
  if (!decisions.length) throw new Error('Nothing selected')
  const problem = checkDecisions(decisions)
  if (problem) throw new Error(`Nothing was sent: ${problem}`)
  return decisions
}

/** What happened to each one: an item can stop being pending before the signature lands. */
export function bulkOutcome(decisions, answered, granted) {
  const skipped = (answered?.decided || []).filter((r) => r.outcome === 'skipped')
  const verb = granted ? 'approved' : 'denied'
  return skipped.length
    ? `${decisions.length - skipped.length} ${verb}, ${skipped.length} no longer pending`
    : `${decisions.length} ${verb}`
}
