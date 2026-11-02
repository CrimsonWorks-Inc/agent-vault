// The pure parts of paging (contract U3, U4): the query a page sends, the
// envelope it reads back, the cursor stack behind Prev and Next, and the
// "Showing 26-50 of 312" line. Cursors are opaque: the page stores them and
// sends them back, and never looks inside a server's cursor.

export const PAGE_SIZES = [25, 50, 100]
export const DEFAULT_LIMIT = 25
/** The most a list route accepts in one page (U3: limit 1..200). */
export const MAX_LIMIT = 200

/** A page size the server will accept, from whatever was remembered. */
export function clampLimit(n) {
  const v = Number(n)
  return PAGE_SIZES.includes(v) ? v : DEFAULT_LIMIT
}

/**
 * The query for one page: `paged=1` and limit always, cursor and q when set,
 * then the filters. The envelope is opt-in with paged=1 (U3, amended); a
 * route asked without it answers in its old shape, which the CLI relies on.
 */
export function pageQuery({ limit = DEFAULT_LIMIT, cursor = null, q = '', filters = {} } = {}) {
  const out = { ...filters, paged: 1, limit }
  if (cursor) out.cursor = cursor
  const term = String(q ?? '').trim()
  if (term) out.q = term
  return out
}

/**
 * `{items, next_cursor, prev_cursor, total}` from a list route asked with
 * `paged=1`. The UI server and this page ship together, so any other shape
 * is a server that does not match this page, and it is said, not guessed at.
 */
export function readEnvelope(data) {
  if (!Array.isArray(data?.items)) throw new EnvelopeError()
  return {
    items: data.items,
    next_cursor: typeof data.next_cursor === 'string' && data.next_cursor ? data.next_cursor : null,
    prev_cursor: typeof data.prev_cursor === 'string' && data.prev_cursor ? data.prev_cursor : null,
    total: Number.isInteger(data.total) ? data.total : null,
  }
}

/** A list answer that is not a page: the UI server is older than this page. */
export class EnvelopeError extends Error {
  constructor() {
    super('The UI server answered a list without paging it. Close this tab and start the UI again with agent-vault ui.')
    this.name = 'EnvelopeError'
  }
}

/**
 * The cursor stack. `page` is 1-based. Next pushes the cursor that got us
 * here; Prev pops it. A server's prev_cursor is not needed, so a list whose
 * order shifted under us still walks back to exactly the pages we saw.
 */
export const firstPage = () => ({ cursor: null, stack: [], page: 1 })

export function nextPage(state, nextCursor) {
  if (!nextCursor) return state
  return { cursor: nextCursor, stack: [...state.stack, state.cursor], page: state.page + 1 }
}

export function prevPage(state) {
  if (!state.stack.length) return state
  const stack = state.stack.slice(0, -1)
  return { cursor: state.stack[state.stack.length - 1], stack, page: Math.max(1, state.page - 1) }
}

/**
 * The numbers for "Showing 26–50 of 312": from and to are 1-based, total is
 * null when the server did not say (audit).
 */
export function showing({ page, limit, count, total = null }) {
  if (!count) return { from: 0, to: 0, total: total ?? 0, text: total ? `Nothing on this page of ${total}` : 'Nothing to show' }
  const from = (page - 1) * limit + 1
  const to = from + count - 1
  const text = total === null || total === undefined
    ? `Showing ${from}–${to}`
    : `Showing ${from}–${to} of ${total}`
  return { from, to, total, text }
}

/** The remembered page size, read in a try/catch: storage can be refused. */
export function recallLimit(storage, key) {
  try { return clampLimit(storage?.getItem(key)) } catch { return DEFAULT_LIMIT }
}

export function rememberLimit(storage, key, n) {
  try { storage?.setItem(key, String(clampLimit(n))) } catch { /* nothing to remember it in */ }
}

/**
 * The list routes (U3). Every request the page makes to one of these sends
 * `paged=1`; the overview test holds the page to it.
 */
export const LIST_ROUTES = ['credentials', 'sessions', 'pending', 'templates', 'listeners', 'tripwires', 'audit', 'report/access', 'sessions/detail']

const ENVELOPE_KEYS = new Set(['items', 'next_cursor', 'prev_cursor', 'total'])

/**
 * Every page of a list, asked with `paged=1` and the largest page, following
 * the cursors until the server says there are no more. There is no page cap:
 * a reader that says it has the whole list has all of it, as the old page's
 * did (it read each list in one answer). Returns `{ items, beside }`:
 *
 *   items   every row, in the server's order;
 *   beside  the fields an object answer keeps beside its page (tripwires'
 *           `enabled` and `defaults`, report/access's `complete`), from the
 *           first page.
 *
 * A walk that cannot end (a cursor the server already gave, or a page with no
 * rows that still points onward) throws an IncompleteListError instead of
 * looping or handing back part of the list as if it were all of it.
 */
export async function fetchPages(get, path, { filters = {} } = {}) {
  const out = []
  let beside = null
  let cursor = null
  const seen = new Set()
  for (;;) {
    const data = await get(path, pageQuery({ limit: MAX_LIMIT, cursor, filters }))
    const page = readEnvelope(data)
    if (beside === null) beside = Object.fromEntries(Object.entries(data).filter(([k]) => !ENVELOPE_KEYS.has(k)))
    out.push(...page.items)
    if (!page.next_cursor) return { items: out, beside }
    if (seen.has(page.next_cursor) || !page.items.length) throw new IncompleteListError(path, out.length)
    seen.add(page.next_cursor)
    cursor = page.next_cursor
  }
}

/** A list whose pages never end: said, never shown as complete. */
export class IncompleteListError extends Error {
  constructor(path, read) {
    super(`The ${path} list did not come to an end: the UI server kept pointing to more after ${read} rows. Nothing was counted from it; reload the page, and if this keeps happening restart the UI with agent-vault ui.`)
    this.name = 'IncompleteListError'
    this.code = 'AV_LIST_INCOMPLETE'
  }
}

/**
 * Every item of a list, for a view that needs the whole set rather than a
 * page (the overview's counts, the pickers, the waiting badge).
 */
export async function fetchAll(get, path, opts = {}) {
  return (await fetchPages(get, path, opts)).items
}
