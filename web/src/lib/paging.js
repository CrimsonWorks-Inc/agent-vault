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
 * `{items, next_cursor, prev_cursor, total}` from a list route.
 *
 * A route that predates paging answers with a bare array (wave 1, before the
 * api piece lands). That is paged here instead, over the already-scrubbed
 * items the server sent, so the controls behave the same either way.
 */
export function readEnvelope(data, { limit = DEFAULT_LIMIT, cursor = null, q = '', searchFields = null } = {}) {
  if (Array.isArray(data)) return localPage(data, { limit, cursor, q, searchFields })
  const items = Array.isArray(data?.items) ? data.items : []
  return {
    items,
    next_cursor: typeof data?.next_cursor === 'string' && data.next_cursor ? data.next_cursor : null,
    prev_cursor: typeof data?.prev_cursor === 'string' && data.prev_cursor ? data.prev_cursor : null,
    total: Number.isInteger(data?.total) ? data.total : null,
  }
}

// Local cursors are the page's own ("@<offset>"), so reading them is fine;
// a server cursor never reaches this function's parser.
const LOCAL = /^@(\d+)$/

/** Page an array the server returned whole: q filters, then a slice. */
export function localPage(all, { limit = DEFAULT_LIMIT, cursor = null, q = '', searchFields = null } = {}) {
  const term = String(q ?? '').trim().toLowerCase()
  const matching = term ? all.filter((item) => matches(item, term, searchFields)) : all
  const m = LOCAL.exec(cursor ?? '')
  const offset = m ? Math.min(Number(m[1]), Math.max(0, matching.length - 1)) : 0
  const items = matching.slice(offset, offset + limit)
  return {
    items,
    next_cursor: offset + limit < matching.length ? `@${offset + limit}` : null,
    prev_cursor: offset > 0 ? `@${Math.max(0, offset - limit)}` : null,
    total: matching.length,
  }
}

/**
 * A case-insensitive substring match over the item's visible fields, which
 * is what U3 says the server's `q` does. Only strings and numbers are read,
 * at the top level or in the named fields.
 */
export function matches(item, term, fields = null) {
  const t = String(term).toLowerCase()
  const keys = fields || Object.keys(item || {})
  return keys.some((k) => {
    const v = item?.[k]
    return (typeof v === 'string' || typeof v === 'number') && String(v).toLowerCase().includes(t)
  })
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
 * the cursors. Returns `{ items, beside, legacy }`:
 *
 *   items   every row, in the server's order;
 *   beside  the fields an object answer keeps beside its page (tripwires'
 *           `enabled` and `defaults`, report/access's `complete`), from the
 *           first page;
 *   legacy  the answer itself when the server did not page it (a route from
 *           before U3): a bare array, or an object with no `items`. Then
 *           `items` is the array, or null for an object.
 */
export async function fetchPages(get, path, { filters = {}, maxPages = 50 } = {}) {
  const out = []
  let beside = null
  let cursor = null
  for (let i = 0; i < maxPages; i++) {
    const data = await get(path, pageQuery({ limit: MAX_LIMIT, cursor, filters }))
    if (Array.isArray(data)) return { items: data, beside: {}, legacy: data }
    if (!Array.isArray(data?.items)) return { items: null, beside: {}, legacy: data ?? null }
    if (beside === null) beside = Object.fromEntries(Object.entries(data).filter(([k]) => !ENVELOPE_KEYS.has(k)))
    out.push(...data.items)
    if (typeof data.next_cursor !== 'string' || !data.next_cursor) break
    cursor = data.next_cursor
  }
  return { items: out, beside: beside ?? {}, legacy: null }
}

/**
 * Every item of a list, for a view that needs counts rather than a page (the
 * overview's "active sessions"). A route that answers with a bare array is
 * used as it is.
 */
export async function fetchAll(get, path, opts = {}) {
  const r = await fetchPages(get, path, opts)
  return r.items ?? itemsOf(r.legacy)
}

/** The rows of a list answer, whether it came back paged or as a bare array. */
export function itemsOf(data) {
  if (Array.isArray(data)) return data
  return Array.isArray(data?.items) ? data.items : []
}
