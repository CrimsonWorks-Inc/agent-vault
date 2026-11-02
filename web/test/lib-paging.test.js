import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  pageQuery, readEnvelope, localPage, firstPage, nextPage, prevPage, showing, recallLimit, rememberLimit,
  clampLimit, fetchAll, itemsOf, matches, PAGE_SIZES, DEFAULT_LIMIT,
} from '../src/lib/paging.js'

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
  assert.deepEqual(readEnvelope({}), { items: [], next_cursor: null, prev_cursor: null, total: null })
})

test('a bare array is paged locally, with q over visible fields', () => {
  const all = Array.from({ length: 60 }, (_, i) => ({ slug: `cred-${i}`, kind: i % 2 ? 'github' : 'http' }))
  const p1 = readEnvelope(all, { limit: 25 })
  assert.equal(p1.items.length, 25)
  assert.equal(p1.total, 60)
  assert.equal(p1.next_cursor, '@25')
  const p3 = localPage(all, { limit: 25, cursor: '@50' })
  assert.equal(p3.items.length, 10)
  assert.equal(p3.next_cursor, null)
  const gh = localPage(all, { limit: 25, q: 'GITHUB' })
  assert.equal(gh.total, 30)
  assert.ok(gh.items.every((x) => x.kind === 'github'))
  assert.equal(matches({ secret: { value: 'x' }, slug: 'a' }, 'x'), false, 'nested objects are not searched')
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

test('fetchAll follows cursors with the largest page, and takes a bare array as it is', async () => {
  const asked = []
  const pages = { '': { items: [1, 2], next_cursor: 'b' }, b: { items: [3], next_cursor: null } }
  const all = await fetchAll(async (path, q) => { asked.push(q); return pages[q.cursor ?? ''] }, 'sessions')
  assert.deepEqual(all, [1, 2, 3])
  assert.equal(asked[0].limit, 200)
  assert.equal(asked[0].paged, 1)
  assert.equal(asked[1].cursor, 'b')
  assert.deepEqual(await fetchAll(async () => [9, 8], 'x'), [9, 8])
  assert.deepEqual(itemsOf([1]), [1])
  assert.deepEqual(itemsOf({ items: [2] }), [2])
  assert.deepEqual(itemsOf(null), [])
})
