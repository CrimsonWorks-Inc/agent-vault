// Paging for the UI server's list routes (UI contract U3, as amended: the
// envelope is opt-in with `paged=1`).
//
//   GET /api/<list>?paged=1&limit=<1..200>&cursor=<opaque>&q=<text>
//   → { items, next_cursor, prev_cursor, total }
//
// Three things here are protections, not conveniences:
//
//   - A cursor is sealed with a key that exists only in this process's
//     memory. The page cannot forge one, edit one, or carry one from one
//     list or filter to another: anything that does not open is a 400
//     AV_BAD_CURSOR, never a crash and never a guess. A restart makes every
//     outstanding cursor stale, and the page starts the list again.
//   - `limit` is a whole number from 1 to 200, written plainly. Nothing is
//     coerced: `1e2`, `-1`, `010` and `200.0` are all a 400 AV_BAD_LIMIT.
//   - `q` is matched against items the caller has ALREADY passed through
//     towardPage, over a fixed list of fields per list. A search therefore
//     cannot test a withheld value (a token, a placeholder, a credential
//     value), because those are gone before the match runs.

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export const LIMIT_DEFAULT = 25
export const LIMIT_MAX = 200
const MAC_BYTES = 16
const CURSOR_MAX_CHARS = 2048

/** A refusal the server answers with 400 and `code`. */
export class PagingError extends Error {
  constructor(code, message) {
    super(message)
    this.code = code
    this.status = 400
    this.problem = { code, detail: message }
  }
}

const badLimit = (why) => new PagingError('AV_BAD_LIMIT', `limit ${why}; give a whole number from 1 to ${LIMIT_MAX}`)
const badCursor = (why) => new PagingError('AV_BAD_CURSOR', `that cursor ${why}; start the list again from the first page`)

/**
 * The paging request in a query string, or null when the caller did not ask
 * for a page (the route then answers exactly as it always has). A cursor
 * without `paged=1` is refused: it can only have come from a paged answer, so
 * dropping it silently would answer a different question.
 */
export function pagingOf(params) {
  const paged = params.getAll('paged')
  if (paged.length === 0) {
    if (params.has('cursor')) throw badCursor('was sent without paged=1')
    return null
  }
  if (paged.length !== 1 || paged[0] !== '1') {
    throw new PagingError('AV_BAD_LIMIT', 'paged is 1 or absent')
  }
  const limits = params.getAll('limit')
  if (limits.length > 1) throw badLimit('was given more than once')
  let limit = LIMIT_DEFAULT
  if (limits.length === 1) {
    if (!/^[1-9][0-9]{0,2}$/.test(limits[0])) throw badLimit('is not a whole number written plainly')
    limit = Number(limits[0])
    if (limit > LIMIT_MAX) throw badLimit(`is more than ${LIMIT_MAX}`)
  }
  const cursors = params.getAll('cursor')
  if (cursors.length > 1) throw badCursor('was given more than once')
  const qs = params.getAll('q')
  if (qs.length > 1) throw new PagingError('AV_BAD_LIMIT', 'q was given more than once')
  return { limit, cursor: cursors[0] ?? null, q: (qs[0] ?? '').trim().toLowerCase() }
}

/**
 * Seals and opens cursors. The key is random per process and never leaves
 * it. A cursor names the list and the filters it was made under (as a
 * digest), the direction, and the sort key of the item it continues from.
 */
export class Cursors {
  #key
  constructor(key = randomBytes(32)) { this.#key = key }

  seal(list, filters, dir, key) {
    const body = Buffer.from(JSON.stringify({ v: 1, l: list, f: digestOf(filters), d: dir, k: key }))
    return Buffer.concat([this.#mac(body), body]).toString('base64url')
  }

  /** The cursor's direction and key, or a PagingError. Never throws anything else. */
  open(text, list, filters) {
    if (typeof text !== 'string' || text.length > CURSOR_MAX_CHARS || !/^[A-Za-z0-9_-]+$/.test(text)) throw badCursor('is not one this server made')
    const raw = Buffer.from(text, 'base64url')
    if (raw.length <= MAC_BYTES) throw badCursor('is not one this server made')
    const mac = raw.subarray(0, MAC_BYTES)
    const body = raw.subarray(MAC_BYTES)
    if (!timingSafeEqual(mac, this.#mac(body))) throw badCursor('is not one this server made, or has expired')
    let c
    try { c = JSON.parse(body.toString('utf8')) } catch { throw badCursor('is not one this server made') }
    if (!c || typeof c !== 'object' || c.v !== 1) throw badCursor('is not one this server made')
    if (c.l !== list) throw badCursor('belongs to a different list')
    if (c.f !== digestOf(filters)) throw badCursor('was made for a different search or filter')
    if (c.d !== 'next' && c.d !== 'prev') throw badCursor('is not one this server made')
    if (!Array.isArray(c.k) || c.k.length < 1 || c.k.length > 4 || !c.k.every(isKeyPart)) throw badCursor('is not one this server made')
    return { dir: c.d, key: c.k }
  }

  #mac(body) {
    return createHmac('sha256', this.#key).update('agent-vault ui cursor\n').update(body).digest().subarray(0, MAC_BYTES)
  }
}

const isKeyPart = (v) => v === null || (typeof v === 'string' && v.length <= 512) || Number.isFinite(v)

function digestOf(filters) {
  const flat = Object.keys(filters).sort().map((k) => [k, filters[k] ?? null])
  return createHash('sha256').update(JSON.stringify(flat)).digest('base64url').slice(0, 22)
}

/**
 * Does an item (already through towardPage) match `q`? `fields(item)` names
 * what may be searched; strings and numbers count, lists are searched one
 * element at a time, and nothing else does.
 */
export function matches(item, fields, q) {
  if (!q) return true
  const values = fields(item ?? {})
  for (const v of values) {
    for (const x of Array.isArray(v) ? v : [v]) {
      if ((typeof x === 'string' || typeof x === 'number') && String(x).toLowerCase().includes(q)) return true
    }
  }
  return false
}

/** Compare two sort keys, one direction per position (1 ascending, -1 descending). */
export function compareKeys(a, b, dirs) {
  for (let i = 0; i < dirs.length; i++) {
    const x = a[i] ?? ''
    const y = b[i] ?? ''
    let c = 0
    if (typeof x === 'number' && typeof y === 'number') c = x - y
    else {
      const sx = String(x)
      const sy = String(y)
      c = sx < sy ? -1 : sx > sy ? 1 : 0
    }
    if (c !== 0) return c * dirs[i]
  }
  return 0
}

/**
 * One page of an in-memory list. `items` must already be through
 * towardPage. `spec` is { name, key(item, index) → [...], dirs, fields(item) → [...] };
 * the key must end in something unique so the order is total and stable.
 */
export function pageList(items, spec, paging, filters, cursors) {
  const { limit, q } = paging
  // The key may use the item's place in the list as given (tripwire rules
  // keep the order they were saved in), so it is taken before filtering.
  const keyOf = (it, i) => spec.key(it ?? {}, i).map((p) => (isKeyPart(p) ? p : null))
  const cmp = (a, b) => compareKeys(a, b, spec.dirs)
  const sorted = (Array.isArray(items) ? items : [])
    .map((it, i) => ({ it, k: keyOf(it, i) }))
    .filter((e) => matches(e.it, spec.fields, q))
    .sort((a, b) => cmp(a.k, b.k))
  const f = { ...filters, q }
  let start = 0
  if (paging.cursor !== null) {
    const c = cursors.open(paging.cursor, spec.name, f)
    if (c.dir === 'next') {
      start = sorted.findIndex((e) => cmp(e.k, c.key) > 0)
      if (start < 0) start = sorted.length
    } else {
      let end = sorted.findIndex((e) => cmp(e.k, c.key) >= 0)
      if (end < 0) end = sorted.length
      start = Math.max(0, end - limit)
    }
  }
  const page = sorted.slice(start, start + limit)
  return {
    items: page.map((e) => e.it),
    next_cursor: page.length && start + limit < sorted.length ? cursors.seal(spec.name, f, 'next', page.at(-1).k) : null,
    prev_cursor: page.length && start > 0 ? cursors.seal(spec.name, f, 'prev', page[0].k) : null,
    total: sorted.length,
  }
}
