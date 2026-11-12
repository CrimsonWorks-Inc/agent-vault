import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  pageQuery, readEnvelope, firstPage, nextPage, prevPage, showing, recallLimit, rememberLimit,
  clampLimit, fetchAll, fetchPages, PAGE_SIZES, DEFAULT_LIMIT, EnvelopeError, IncompleteListError,
} from '../src/lib/paging.js'
import { Cursors, LISTS, pageAnswer, pagingOf } from '../../legacy/js/src/ui/list-paging.js'

test('every page asks for the envelope with paged=1 and a limit', () => {
  assert.deepEqual(pageQuery({}), { paged: 1, limit: 25 })
  assert.deepEqual(pageQuery({ limit: 50, cursor: 'abc', q: '  gh ', filters: { kind: 'x' } }), { kind: 'x', paged: 1, limit: 50, cursor: 'abc', q: 'gh' })
})

test('page sizes are 25, 50 and 100; anything else is the default', () => {
  assert.deepEqual(PAGE_SIZES, [25, 50, 100])
  assert.equal(clampLimit('50'), 50)
  assert.equal(clampLimit(7), DEFAULT_LIMIT)
  assert.equal(clampLimit(undefined), DEFAULT_LIMIT)
})

test('the envelope is read as given; cursors are passed through untouched', () => {
  const env = readEnvelope({ items: [{ id: 1 }], next_cursor: 'eyJvIjoyNX0', prev_cursor: null, total: 312 })
  assert.deepEqual(env, { items: [{ id: 1 }], next_cursor: 'eyJvIjoyNX0', prev_cursor: null, total: 312 })
  assert.deepEqual(readEnvelope({ items: [] }), { items: [], next_cursor: null, prev_cursor: null, total: null })
})

test('a list answer that is not a page is refused, never paged or guessed at here', () => {
  for (const notAPage of [[{ slug: 'a' }], {}, { rules: [] }, null, 'x']) {
    assert.throws(() => readEnvelope(notAPage), EnvelopeError)
  }
})

// The UI server's own paging (src/ui/list-paging.js), as src/ui/server.js
// #listed runs it, behind a `get` with the client's query.
function realServer(answers) {
  const cursors = new Cursors()
  const asked = []
  const get = async (path, query) => {
    asked.push(query)
    const params = new URLSearchParams(Object.entries(query).map(([k, v]) => [k, String(v)]))
    const { spec, within = null, drop = [], filters = {} } = answers[path](params)
    return pageAnswer(answers[`${path} data`], spec, pagingOf(params), { within, drop, filters }, cursors)
  }
  return { get, asked }
}

test('fetchAll walks the real server sealed cursors to the end, in the server order', async () => {
  const creds = Array.from({ length: 450 }, (_, i) => ({ slug: `c${String(i).padStart(3, '0')}` })).reverse()
  const { get, asked } = realServer({ credentials: () => ({ spec: LISTS.credentials }), 'credentials data': creds })
  const all = await fetchAll(get, 'credentials')
  assert.equal(all.length, 450)
  assert.deepEqual(all.map((c) => c.slug), [...creds].map((c) => c.slug).sort())
  assert.equal(asked.length, 3)
  assert.ok(asked.every((q) => q.paged === 1 && q.limit === 200))
  assert.equal(asked[0].cursor, undefined)
  assert.match(asked[1].cursor, /^[A-Za-z0-9_-]+$/)
})

test('fetchPages keeps what the real server puts beside a page (tripwires)', async () => {
  const rules = Array.from({ length: 205 }, (_, i) => ({ id: `r${i}`, codes: ['AV_X'], threshold: 1, window_s: 60, action: 'revoke_session' }))
  const { get } = realServer({
    tripwires: () => ({ spec: LISTS.tripwireRules, within: 'rules' }),
    'tripwires data': { enabled: true, rules_saved: true, rules, defaults: [{ id: 'd' }] },
  })
  const r = await fetchPages(get, 'tripwires')
  assert.deepEqual(r.items.map((x) => x.id), rules.map((x) => x.id), 'saved order, every page')
  assert.deepEqual(r.beside, { enabled: true, rules_saved: true, defaults: [{ id: 'd' }] })
})

test('Next pushes and Prev pops the cursor stack', () => {
  let s = firstPage()
  s = nextPage(s, 'c2')
  s = nextPage(s, 'c3')
  assert.deepEqual(s, { cursor: 'c3', stack: [null, 'c2'], page: 3 })
  s = prevPage(s)
  assert.deepEqual(s, { cursor: 'c2', stack: [null], page: 2 })
  s = prevPage(prevPage(s))
  assert.deepEqual(s, { cursor: null, stack: [], page: 1 })
  assert.equal(nextPage(s, null), s, 'no next cursor, no move')
})

test('"Showing 26–50 of 312"', () => {
  assert.equal(showing({ page: 2, limit: 25, count: 25, total: 312 }).text, 'Showing 26–50 of 312')
  assert.equal(showing({ page: 1, limit: 25, count: 7, total: null }).text, 'Showing 1–7')
  assert.equal(showing({ page: 1, limit: 25, count: 0, total: 0 }).text, 'Nothing to show')
})

test('the page size is remembered, and storage that throws is survived', () => {
  const store = new Map()
  const storage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) }
  rememberLimit(storage, 'k', 100)
  assert.equal(recallLimit(storage, 'k'), 100)
  const hostile = { getItem() { throw new Error('denied') }, setItem() { throw new Error('denied') } }
  assert.equal(recallLimit(hostile, 'k'), DEFAULT_LIMIT)
  assert.doesNotThrow(() => rememberLimit(hostile, 'k', 50))
})

test('fetchAll follows cursors with the largest page', async () => {
  const asked = []
  const pages = { '': { items: [1, 2], next_cursor: 'b' }, b: { items: [3], next_cursor: null } }
  const all = await fetchAll(async (path, q) => { asked.push(q); return pages[q.cursor ?? ''] }, 'sessions')
  assert.deepEqual(all, [1, 2, 3])
  assert.equal(asked[0].limit, 200)
  assert.equal(asked[0].paged, 1)
  assert.equal(asked[1].cursor, 'b')
  await assert.rejects(fetchAll(async () => [9, 8], 'x'), EnvelopeError)
})

test('fetchAll has no page cap: 60 pages of 200 come back whole', async () => {
  // The old helper stopped after 50 pages (10,000 rows) and returned what it
  // had as if it were the whole list.
  let calls = 0
  const get = async (path, q) => {
    const n = q.cursor ? Number(q.cursor.slice(1)) : 0
    calls++
    return { items: Array.from({ length: 200 }, (_, i) => n * 200 + i), next_cursor: n < 59 ? `p${n + 1}` : null, total: 12_000 }
  }
  const all = await fetchAll(get, 'sessions')
  assert.equal(all.length, 12_000)
  assert.equal(all.at(-1), 11_999)
  assert.equal(calls, 60)
})

test('a list that never ends is an error, never a partial list or a loop', async () => {
  // Each stub gives up after 20 calls, so a reader that would loop forever
  // fails here quickly instead of hanging the suite.
  const bounded = (answer) => { let n = 0; return async (path, q) => { if (++n > 20) throw new Error('looped'); return answer(path, q, n) } }
  // The server hands back a cursor it already gave.
  const loop = bounded((path, q) => ({ items: [q.cursor ?? 'first'], next_cursor: q.cursor === 'b' ? 'a' : (q.cursor === 'a' ? 'b' : 'a') }))
  await assert.rejects(fetchAll(loop, 'sessions'), (e) => e instanceof IncompleteListError && e.code === 'AV_LIST_INCOMPLETE' && /sessions/.test(e.message))
  // A page with nothing on it that still points onward, with a new cursor each time.
  let calls = 0
  const empty = bounded((path, q, n) => { calls = n; return q.cursor ? { items: [], next_cursor: `n${n}` } : { items: [1], next_cursor: 'n0' } })
  await assert.rejects(fetchPages(empty, 'credentials'), IncompleteListError)
  assert.equal(calls, 2, 'it stops at the first empty page')
  // An empty list is still an empty list.
  assert.deepEqual(await fetchAll(async () => ({ items: [], next_cursor: null }), 'pending'), [])
})

test('fetchPages refuses an object answer with no page in it', async () => {
  const { LIST_ROUTES } = await import('../src/lib/paging.js')
  await assert.rejects(fetchPages(async () => ({ enabled: false, rules: [], defaults: [] }), 'tripwires'), EnvelopeError)
  assert.ok(['tripwires', 'audit', 'report/access'].every((r) => LIST_ROUTES.includes(r)))
})
