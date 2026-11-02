// Audit paging while the log grows (UI contract U3, fix round 1). The audit
// log is appended to all the time, so a reader walking it a page at a time
// must never be shown a row twice or have one skipped from under them:
// Prev keeps its cursor's boundary and returns only the rows newer than it,
// even when that is less than a page, and never starts again from whatever
// the newest row is now.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { startStub, startUi } from './control-ui-helpers.js'
import { startUi as startUiOver } from './fix-control-helpers.js'

/** A stub daemon whose audit log is `rows` (oldest first), paged as the daemon pages it. */
async function stubAudit(rows) {
  const stub = await startStub((_key, _body, url) => {
    const limit = Number(url.searchParams.get('limit'))
    const before = url.searchParams.get('before')
    const after = url.searchParams.get('after')
    if (after !== null) return rows.filter((r) => r.seq > Number(after)).slice(0, limit)
    return rows.filter((r) => before === null || r.seq < Number(before)).slice(-limit)
  })
  const u = await startUi(stub)
  return { stub, u }
}

const seqs = (p) => p.items.map((r) => r.seq)
const strictlyNewestFirst = (list) => list.every((s, i) => i === 0 || s < list[i - 1])

test('Prev from the old first page holds only the rows appended since, and then there is no Prev', async () => {
  const rows = Array.from({ length: 10 }, (_, i) => ({ seq: i + 1, kind: 'test.review' }))
  const { stub, u } = await stubAudit(rows)
  const page = async (cursor) => (await u.api('GET', `audit?paged=1&limit=3${cursor ? `&cursor=${cursor}` : ''}`)).json()
  try {
    const first = await page()
    assert.deepEqual(seqs(first), [10, 9, 8])
    const second = await page(first.next_cursor)
    assert.deepEqual(seqs(second), [7, 6, 5])
    rows.push({ seq: 11, kind: 'test.review' })
    const oldFirst = await page(second.prev_cursor)
    assert.deepEqual(seqs(oldFirst), [10, 9, 8], 'Prev keeps its boundary: the page above [7,6,5]')
    assert.ok(oldFirst.prev_cursor, 'one row is newer than this page')
    const newest = await page(oldFirst.prev_cursor)
    assert.deepEqual(seqs(newest), [11], 'only the appended row, not [11,10,9] again')
    assert.equal(newest.prev_cursor, null, 'nothing is newer than the newest')
    // Next from the short page goes back down with nothing repeated or skipped.
    assert.deepEqual(seqs(await page(newest.next_cursor)), [10, 9, 8])
  } finally {
    await u.stop()
    await stub.stop()
  }
})

test('a log with gaps that grows while it is walked: Next sees the first snapshot once, Prev reaches every new row once', async () => {
  const rows = Array.from({ length: 61 }, (_, i) => ({ seq: i * 3, kind: 'test.review', session_id: `s_${i}` }))
  const { stub, u } = await stubAudit(rows)
  const page = async (cursor) => (await u.api('GET', `audit?paged=1&limit=7${cursor ? `&cursor=${cursor}` : ''}`)).json()
  try {
    const initial = rows.map((r) => r.seq).reverse()
    let p = await page()
    const seen = [...seqs(p)]
    while (p.next_cursor) {
      rows.push({ seq: rows.at(-1).seq + 3, kind: 'test.review' })
      p = await page(p.next_cursor)
      seen.push(...seqs(p))
    }
    assert.deepEqual(seen, initial, 'Next walks the log as it was, newest first, each row once')
    const bottom = seqs(p)
    // Back up to the top, with more rows still arriving.
    const back = []
    for (let i = 0; p.prev_cursor && i < 40; i++) {
      rows.push({ seq: rows.at(-1).seq + 3, kind: 'test.review' })
      p = await page(p.prev_cursor)
      back.unshift(...seqs(p))
    }
    assert.equal(p.prev_cursor, null)
    assert.ok(strictlyNewestFirst(back), 'Prev never repeats a row')
    const want = rows.map((r) => r.seq).filter((s) => s > bottom[0] && s <= back[0]).reverse()
    assert.deepEqual(back, want, 'Prev skips nothing between the bottom page and the top')
    assert.equal(back[0], rows.at(-1).seq, 'the walk back reaches the newest row')
  } finally {
    await u.stop()
    await stub.stop()
  }
})

test('a real daemon, a kind and a search, rows arriving all the time: both directions, no row twice, none skipped', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-auditgrow-'))
  const vault = Vault.create(dir, { factor: 'none' })
  let n = 0
  // A third of the alpha rows match q=s_1; beta rows and the other alpha rows
  // are there to be skipped.
  const add = () => {
    const i = n++
    vault.audit.write(i % 4 === 3 ? 'test.beta' : 'test.alpha', { session_id: i % 3 === 0 ? `s_1${i}` : `s_2${i}` })
  }
  for (let i = 0; i < 400; i++) add()
  const sock = join(dir, 'control.sock')
  const daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
  const u = await startUiOver({ sock, daemon })
  const matching = () => vault.audit.read({ limit: Infinity })
    .filter((r) => r.kind === 'test.alpha' && String(r.session_id).includes('s_1'))
    .map((r) => r.seq).reverse()
  const page = async (cursor) => {
    const res = await u.api('GET', `audit?paged=1&kind=test.alpha&q=S_1&limit=6${cursor ? `&cursor=${cursor}` : ''}`)
    assert.equal(res.status, 200)
    return res.json()
  }
  try {
    const initial = matching()
    assert.ok(initial.length > 60)
    let p = await page()
    const seen = [...seqs(p)]
    while (p.next_cursor) {
      for (let k = 0; k < 5; k++) add()
      p = await page(p.next_cursor)
      seen.push(...seqs(p))
    }
    assert.deepEqual(seen, initial, 'Next walks the matching rows as they were, each once')
    const bottom = seqs(p)
    const back = []
    for (let i = 0; p.prev_cursor && i < 100; i++) {
      for (let k = 0; k < 5; k++) add()
      p = await page(p.prev_cursor)
      back.unshift(...seqs(p))
    }
    assert.equal(p.prev_cursor, null)
    assert.ok(strictlyNewestFirst(back), 'Prev never repeats a row')
    const all = matching()
    assert.deepEqual(back, all.filter((s) => s > bottom[0] && s <= back[0]), 'Prev skips nothing')
    // And the rows that arrived during the walk back are reachable from the top.
    const top = await page()
    assert.equal(top.items[0].seq, all[0])
  } finally {
    await u.stop()
    await daemon.stop()
    rmSync(dir, { recursive: true, force: true })
  }
})
