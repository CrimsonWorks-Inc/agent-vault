// Audit paging, end to end (UI contract U3): the daemon's GET /v1/audit walks
// the whole log with before/after and filters kind BEFORE its limit, and the
// UI server's paged audit list walks a log of thousands of rows a page at a
// time in both directions. The old reads (`audit tail`, a bare limit) are
// unchanged.
//
// A real vault and daemon, with the rows written straight into the audit log
// so the counts and kinds are known exactly.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { towardPage } from '../../src/ui/server.js'
import { mint, newSid } from '../../src/core/placeholder.js'
import { controlAt, startUi, cli } from './fix-control-helpers.js'

const ROWS = 2400
const TOKEN = 'avs1.AuditOracleSid.AuditOracleSecret99'
const PLACEHOLDER = mint({ kPh: randomBytes(32), sid: newSid(), slug: 'gh', field: 'token' }).text

let dir, vault, daemon, sock, u

const control = async (path) => controlAt(sock, 'GET', path)
const all = () => vault.audit.read({ limit: Infinity })
const ofKind = (kind) => all().filter((r) => r.kind === kind || r.kind.startsWith(`${kind}.`))

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-auditpage-'))
  vault = Vault.create(dir, { factor: 'none' })
  for (let i = 0; i < ROWS; i++) {
    const kind = i % 2 === 0 ? 'test.alpha' : (i % 3 === 0 ? 'test.beta' : 'other.gamma')
    vault.audit.write(kind, { session_id: `s_${i % 37}`, n: i })
  }
  // Token- and placeholder-shaped text in searchable fields: what a search
  // that ran before towardPage would find.
  vault.audit.write('test.alpha', { session_id: TOKEN, credential_slug: PLACEHOLDER, n: -1 })
  // The newest rows are not alpha, so "the alpha rows among the newest N"
  // and "the newest N alpha rows" are different answers.
  for (let i = 0; i < 40; i++) vault.audit.write('other.gamma', { session_id: 's_tail', n: ROWS + i })
  sock = join(dir, 'control.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
  u = await startUi({ sock, daemon })
})

after(async () => {
  await u?.stop()
  await daemon?.stop()
  rmSync(dir, { recursive: true, force: true })
})

test('the fixture wrote the log it claims to', () => {
  assert.ok(all().length > ROWS + 40)
  assert.ok(ofKind('test.alpha').length > 1000, 'the kind filter must walk more than 1000 rows')
  assert.ok(all().slice(-30).every((r) => r.kind !== 'test.alpha'))
})

test('the daemon: a bare limit is the tail it always was', async () => {
  const r = await control('/v1/audit?limit=20')
  assert.equal(r.status, 200)
  assert.deepEqual(r.body, vault.audit.read({ limit: 20 }))
  assert.deepEqual((await control('/v1/audit')).body, vault.audit.read({ limit: 30 }))
})

test('the daemon: kind filters before the limit', async () => {
  const r = await control('/v1/audit?kind=test.alpha&limit=25')
  assert.equal(r.status, 200)
  assert.equal(r.body.length, 25)
  assert.ok(r.body.every((x) => x.kind === 'test.alpha'))
  assert.deepEqual(r.body.map((x) => x.seq), ofKind('test.alpha').slice(-25).map((x) => x.seq))
  // A family: test.* is alpha and beta.
  const fam = await control('/v1/audit?kind=test&limit=500&before=999999')
  assert.ok(fam.body.length === 500 && fam.body.every((x) => x.kind.startsWith('test.')))
})

test('the daemon: before and after walk the whole log, each row once', async () => {
  const want = all().map((r) => r.seq)
  // Newest to oldest with before=.
  const seen = []
  let at = Number.MAX_SAFE_INTEGER
  for (let guard = 0; guard < 100; guard++) {
    const r = await control(`/v1/audit?before=${at}&limit=500`)
    assert.equal(r.status, 200)
    assert.ok(r.body.length <= 500)
    if (!r.body.length) break
    assert.ok(r.body.every((x, i) => i === 0 || x.seq > r.body[i - 1].seq), 'oldest first within a page')
    assert.ok(r.body.every((x) => x.seq < at))
    seen.unshift(...r.body.map((x) => x.seq))
    at = r.body[0].seq
  }
  assert.deepEqual(seen, want)
  // Oldest to newest with after=.
  const forward = []
  at = 0
  for (let guard = 0; guard < 100; guard++) {
    const r = await control(`/v1/audit?after=${at}&limit=500`)
    if (!r.body.length) break
    assert.ok(r.body.every((x) => x.seq > at))
    forward.push(...r.body.map((x) => x.seq))
    at = r.body.at(-1).seq
  }
  assert.deepEqual(forward, want)
  // With a kind, the same.
  const alpha = []
  at = Number.MAX_SAFE_INTEGER
  for (let guard = 0; guard < 100; guard++) {
    const r = await control(`/v1/audit?kind=test.alpha&before=${at}&limit=137`)
    if (!r.body.length) break
    alpha.unshift(...r.body.map((x) => x.seq))
    at = r.body[0].seq
  }
  assert.deepEqual(alpha, ofKind('test.alpha').map((r) => r.seq))
})

test('the daemon: paging parameters are whole numbers in range or refused', async () => {
  for (const q of [
    'before=10&limit=0', 'before=10&limit=501', 'before=10&limit=1.5', 'before=10&limit=1e2', 'before=10&limit=',
    'before=-1', 'before=abc', 'before=1.5', 'before=', 'after=x', 'before=5&after=1',
    'kind=../../v1/credentials', 'kind=Test.Alpha', 'kind=',
  ]) {
    const r = await control(`/v1/audit?${q}`)
    // AV_POLICY_DENIED answers with its own status, as the export's range check does.
    assert.equal(r.status, 403, q)
    assert.equal(r.body.code, 'AV_POLICY_DENIED', q)
    assert.equal(r.body.rule, 'audit_range', q)
  }
  assert.equal((await control('/v1/audit?before=10&limit=500')).status, 200)
})

test('the CLI: audit tail reads the same tail as before', async () => {
  const r = await cli(dir, ['audit', 'tail', '--limit', '7', '--json'])
  assert.equal(r.code, 0, r.stderr)
  const rows = JSON.parse(r.stdout).data
  assert.deepEqual(rows.map((x) => x.seq), vault.audit.read({ limit: 7 }).map((x) => x.seq))
  const human = await cli(dir, ['audit', 'tail', '--limit', '5'])
  assert.equal(human.code, 0, human.stderr)
  assert.equal(human.stdout.trim().split('\n').length, 5)
})

const page = async (path) => {
  const res = await u.api('GET', path)
  return { status: res.status, body: await res.json() }
}

/** Walk the UI's paged audit list forward and back. */
async function walkUi(query, limit) {
  const pages = []
  let cursor = null
  for (let guard = 0; guard < 400; guard++) {
    const r = await page(`audit?paged=1&limit=${limit}${query}${cursor ? `&cursor=${cursor}` : ''}`)
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.total, null)
    pages.push(r.body)
    if (!r.body.next_cursor) break
    cursor = r.body.next_cursor
  }
  assert.equal(pages[0].prev_cursor, null)
  for (let i = pages.length - 1; i > 0; i--) {
    const back = await page(`audit?paged=1&limit=${limit}${query}&cursor=${pages[i].prev_cursor}`)
    assert.equal(back.status, 200)
    assert.deepEqual(back.body.items.map((x) => x.seq), pages[i - 1].items.map((x) => x.seq), `prev from page ${i}`)
  }
  return pages.flatMap((p) => p.items.map((x) => x.seq))
}

test('the page: a kind walks every row of that kind, newest first, across the whole log', async () => {
  const seqs = await walkUi('&kind=test.alpha', 200)
  const want = ofKind('test.alpha').map((r) => r.seq).reverse()
  assert.ok(want.length > 1000)
  assert.deepEqual(seqs, want)
  const first = await page('audit?paged=1&kind=test.alpha&limit=25')
  assert.equal(first.body.items.length, 25, 'kind=X&limit=25 is 25 rows of X')
  assert.ok(first.body.items.every((x) => x.kind === 'test.alpha'))
})

test('the page: with no kind the whole log is walkable', async () => {
  const seqs = await walkUi('', 200)
  assert.deepEqual(seqs, all().map((r) => r.seq).reverse())
})

test('the page: q searches visible fields across the whole log, a page at a time', async () => {
  const seqs = await walkUi('&kind=test.alpha&q=S_5', 7)
  const want = ofKind('test.alpha').map((r) => towardPage(r)).filter((r) => String(r.session_id).toLowerCase().includes('s_5')).map((r) => r.seq).reverse()
  assert.ok(want.length > 14, 'enough matches for several pages')
  assert.deepEqual(seqs, want)
})

test('the page: q never matches token or placeholder text in a row', async () => {
  for (const needle of [TOKEN, 'AuditOracleSecret99', 'avs1.', PLACEHOLDER, PLACEHOLDER.split('.')[3], 'av1.']) {
    const r = await page(`audit?paged=1&q=${encodeURIComponent(needle)}`)
    assert.equal(r.status, 200, needle)
    assert.deepEqual(r.body.items, [], `q=${needle} matched text the page is never shown`)
  }
  // The row is there, scrubbed, and findable by what the page does see.
  const r = await page('audit?paged=1&limit=200&kind=test.alpha')
  const shown = JSON.stringify(r.body)
  assert.ok(!shown.includes(TOKEN) && !shown.includes(PLACEHOLDER))
})

test('the page: audit cursors and limits are checked like every other list', async () => {
  const alpha = (await page('audit?paged=1&kind=test.alpha&limit=5')).body.next_cursor
  for (const path of [
    `audit?paged=1&kind=test.beta&limit=5&cursor=${alpha}`,
    `audit?paged=1&limit=5&cursor=${alpha}`,
    `audit?paged=1&kind=test.alpha&q=s_1&limit=5&cursor=${alpha}`,
    `credentials?paged=1&limit=5&cursor=${alpha}`,
    `audit?paged=1&kind=test.alpha&limit=5&cursor=${alpha.slice(0, -2)}`,
    `audit?kind=test.alpha&limit=5&cursor=${alpha}`,
  ]) {
    const r = await page(path)
    assert.equal(r.status, 400, path)
    assert.equal(r.body.code, 'AV_BAD_CURSOR', path)
  }
  for (const bad of ['0', '201', 'x']) assert.equal((await page(`audit?paged=1&limit=${bad}`)).body.code, 'AV_BAD_LIMIT')
})

test('the page: without paged=1 the audit route is unchanged', async () => {
  const r = await page('audit?limit=5')
  assert.deepEqual(r.body, towardPage(vault.audit.read({ limit: 5 })))
  const k = await page('audit?kind=test.beta&limit=4')
  assert.deepEqual(k.body.map((x) => x.seq), ofKind('test.beta').slice(-4).map((x) => x.seq))
})
