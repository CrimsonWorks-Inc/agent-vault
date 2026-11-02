// Paged list routes on the UI server (UI contract U3, as amended: the
// envelope is opt-in with paged=1).
//
// Run against a stand-in daemon that answers the list routes with fixed
// data, so every order, filter and edge is known exactly. Three protections
// are tested here beside the paging itself:
//
//   - a cursor is sealed: an edited, forged, truncated or borrowed cursor is
//     a 400 AV_BAD_CURSOR, never a page and never a crash;
//   - limit is a whole number from 1 to 200, written plainly (AV_BAD_LIMIT);
//   - q runs AFTER towardPage, so searching for a session token, a
//     placeholder or a credential value the daemon slipped into a list
//     finds nothing, while an ordinary search still works.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { UiServer, towardPage } from '../../src/ui/server.js'
import { fetchPending } from '../../src/pending.js'
import { mint, newSid } from '../../src/core/placeholder.js'
import { startStub, startUi } from './control-ui-helpers.js'

// What a careless daemon route might leak into a list. Each one is placed in
// a field that q is allowed to search, so a search that ran before
// towardPage would find it.
const TOKEN = 'avs1.QoracleSid01.QoracleSecretTokenPart02'
const PLACEHOLDER = mint({ kPh: randomBytes(32), sid: newSid(), slug: 'gh', field: 'token' }).text
const PH_NONCE = PLACEHOLDER.split('.')[3]
const VALUE = 'sk-test-QORACLEVALUE00112233'

const pad = (n) => String(n).padStart(3, '0')
const shuffle = (xs) => xs.map((x) => [Math.sin(xs.indexOf(x) * 7.3), x]).sort((a, b) => a[0] - b[0]).map(([, x]) => x)

const CREDENTIALS = shuffle(Array.from({ length: 61 }, (_, i) => ({
  id: `cred_${pad(i)}`, slug: `svc-${pad(i)}`, kind: i % 2 ? 'http' : 'github', connector: { host: `h${i}.test` },
  expires_at: null, health: null, expiry_warning: null,
})))
// The leaky one: a token in its label, a value and a placeholder under
// withheld keys, and the placeholder again in a searchable field.
CREDENTIALS.push({
  id: 'cred_leaky', slug: 'zz-leaky', kind: 'http', label: `uses ${TOKEN} and ${PLACEHOLDER}`,
  value: VALUE, token: TOKEN, placeholder: PLACEHOLDER, secret: VALUE,
})

const SESSIONS = shuffle(Array.from({ length: 75 }, (_, i) => ({
  id: `s_${pad(i)}`, label: i === 7 ? `agent ${TOKEN}` : `agent-${i % 9}`, state: i % 5 ? 'active' : 'revoked',
  // Repeated and missing creation times, so the id tie-break is exercised.
  created_at: i % 11 === 0 ? null : `2026-10-${String(1 + (i % 20)).padStart(2, '0')}T00:00:00.000Z`,
  expires_at: null, remote: false, grants: 1, creds: [{ slug: `svc-${pad(i % 61)}`, grant_id: `g_${i}` }], infinite: false, elevated: [],
})))

const APPROVALS = Array.from({ length: 30 }, (_, i) => ({
  id: `ap_${pad(i)}`, summary: i === 3 ? `GET /repos?key=${PLACEHOLDER}` : `GET /repos/${i}`,
  reason: null, created_at: `2026-10-${String(1 + (i % 28)).padStart(2, '0')}T01:00:00.000Z`, grant_id: `g_${i}`, preview: null,
}))
const SESSION_REQUESTS = Array.from({ length: 30 }, (_, i) => ({
  id: `sr_${pad(i)}`, summary: i === 4 ? `wants ${TOKEN}` : `wants svc-${pad(i)}`,
  agent_reason_untrusted: 'please', created_at: `2026-10-${String(1 + (i % 28)).padStart(2, '0')}T01:00:00.000Z`, proposal: {},
}))

const TEMPLATES = shuffle(Array.from({ length: 40 }, (_, i) => ({
  name: `tpl-${pad(i)}`, version: 1, hash: `h${i}`, summary: 'GET only', creds: [`svc-${pad(i)}`], elevated: [], updated_at: null,
})))
const LISTENERS = shuffle(Array.from({ length: 12 }, (_, i) => ({ id: `l-${pad(i)}`, address: `127.0.0.1:${7400 + i}`, surfaces: ['gateway'], state: 'configured' })))
const RULES = Array.from({ length: 9 }, (_, i) => ({ id: `rule-${i}`, codes: ['AV_PH_REPLAY'], threshold: 1 + i, window_s: 600, action: 'revoke_session' }))
const TRIPWIRES = { enabled: true, rules: RULES, rules_saved: true, defaults: RULES.slice(0, 2) }
const REPORT = {
  generated_at: '2026-11-01T00:00:00.000Z', since: '2026-10-25T00:00:00.000Z', complete: true,
  credentials: shuffle(Array.from({ length: 33 }, (_, i) => ({ slug: `svc-${pad(i)}`, requests: i, denials: 0 }))),
  sessions: shuffle(Array.from({ length: 52 }, (_, i) => ({
    id: `s_${pad(i)}`, label: `agent-${i}`, state: 'active', creds: [`svc-${pad(i)}`], requests: i, denials: 0,
    last_seen_at: i % 6 === 0 ? null : `2026-10-${String(1 + (i % 25)).padStart(2, '0')}T02:00:00.000Z`,
  }))),
}
const DETAIL = {
  session: { id: 's_001', label: 'agent', state: 'active' },
  grants: shuffle(Array.from({ length: 45 }, (_, i) => ({ grant_id: `g_${pad(i)}`, cred: `svc-${pad(i % 15)}`, state: 'active' }))),
  activity: { complete: true, requests: { allowed: 1, denied: 0, held: 0 } },
}

let stub, u

before(async () => {
  stub = await startStub((key, _body, url) => {
    switch (key) {
      case 'GET /v1/credentials': return CREDENTIALS
      case 'GET /v1/sessions': return SESSIONS
      case 'GET /v1/approvals': return APPROVALS
      case 'GET /v1/session-requests': return SESSION_REQUESTS
      case 'GET /v1/templates': return url.searchParams.get('name') ? TEMPLATES[0] : TEMPLATES
      case 'GET /v1/listeners': return LISTENERS
      case 'GET /v1/tripwires': return TRIPWIRES
      case 'GET /v1/report/access': return REPORT
      case 'GET /v1/sessions/detail': return DETAIL
      default: return { status: 404, body: { code: 'AV_NOT_FOUND', detail: 'no route' } }
    }
  })
  u = await startUi(stub)
})

after(async () => {
  await u?.stop()
  await stub?.stop()
})

const get = async (path) => {
  const res = await u.api('GET', path)
  return { status: res.status, body: await res.json() }
}
const withQuery = (path, extra) => `${path}${path.includes('?') ? '&' : '?'}${extra}`

/** Walk a list forward by next_cursor, then back by prev_cursor, checking every page. */
async function walk(path, limit, idOf) {
  const pages = []
  let cursor = null
  for (let guard = 0; guard < 500; guard++) {
    const r = await get(withQuery(path, `paged=1&limit=${limit}${cursor ? `&cursor=${cursor}` : ''}`))
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.ok(r.body.items.length <= limit)
    pages.push(r.body)
    if (!r.body.next_cursor) break
    cursor = r.body.next_cursor
  }
  assert.equal(pages[0].prev_cursor, null, 'the first page has no previous page')
  // And back again: each prev page is exactly the page before it.
  for (let i = pages.length - 1; i > 0; i--) {
    const back = await get(withQuery(path, `paged=1&limit=${limit}&cursor=${pages[i].prev_cursor}`))
    assert.equal(back.status, 200)
    assert.deepEqual(back.body.items.map(idOf), pages[i - 1].items.map(idOf), `prev from page ${i}`)
  }
  return { pages, ids: pages.flatMap((p) => p.items.map(idOf)) }
}

// The documented orders, written out independently of the server's.
const asc = (f) => (a, b) => (f(a) < f(b) ? -1 : f(a) > f(b) ? 1 : 0)
const desc = (f) => (a, b) => -asc(f)(a, b)
const by = (...cmps) => (a, b) => { for (const c of cmps) { const r = c(a, b); if (r) return r } return 0 }
const s = (v) => v ?? ''

test('without paged=1 every list route answers exactly as it always has', async () => {
  const plain = [
    ['sessions', SESSIONS], ['templates', TEMPLATES], ['listeners', LISTENERS],
    ['tripwires', TRIPWIRES], ['report/access', REPORT], ['sessions/detail?sid=s_001', DETAIL],
    // limit alone is not a page request: it changes nothing on these.
    ['sessions?limit=5', SESSIONS], ['templates?limit=5&q=tpl-001', TEMPLATES],
  ]
  for (const [path, expected] of plain) {
    const r = await get(path)
    assert.equal(r.status, 200, path)
    // As always, every answer passes towardPage on its way to the page.
    assert.deepEqual(r.body, towardPage(expected), path)
  }
  const pending = await get('pending')
  assert.deepEqual(pending.body.map((p) => p.id), (await fetchPending(async (p) => (p === '/v1/approvals' ? APPROVALS : SESSION_REQUESTS))).map((p) => p.id))
  const creds = await get('credentials')
  assert.equal(creds.body.length, CREDENTIALS.length)
  assert.ok(Array.isArray(creds.body))
  const one = await get('templates?name=tpl-001&paged=1')
  assert.deepEqual(one.body, TEMPLATES[0], 'one template by name is never a page')
})

test('each list pages through every item once, in its documented order, and back', async () => {
  const cases = [
    ['credentials', CREDENTIALS, (c) => c.slug, by(asc((c) => c.slug), asc((c) => c.id)), 9],
    ['sessions', SESSIONS, (x) => x.id, by(desc((x) => s(x.created_at)), desc((x) => x.id)), 8],
    ['templates', TEMPLATES, (t) => t.name, asc((t) => t.name), 7],
    ['listeners', LISTENERS, (l) => l.id, asc((l) => l.id), 5],
    ['tripwires', RULES, (r) => r.id, () => 0, 4],
    ['report/access', REPORT.sessions, (x) => x.id, by(desc((x) => s(x.last_seen_at)), asc((x) => x.id)), 10],
    ['report/access?list=credentials', REPORT.credentials, (c) => c.slug, asc((c) => c.slug), 10],
    ['sessions/detail?sid=s_001', DETAIL.grants, (g) => g.grant_id, by(asc((g) => g.cred), asc((g) => g.grant_id)), 6],
  ]
  for (const [path, items, idOf, order, limit] of cases) {
    const { pages, ids } = await walk(path, limit, idOf)
    assert.deepEqual(ids, [...items].sort(order).map(idOf), path)
    assert.equal(new Set(ids).size, items.length, `${path}: an item was repeated or lost`)
    for (const p of pages) assert.equal(p.total, items.length, path)
  }
})

test('pending pages newest first, with both kinds of decision', async () => {
  const all = await fetchPending(async (p) => (p === '/v1/approvals' ? APPROVALS : SESSION_REQUESTS))
  const order = by(desc((p) => p.created_at), asc((p) => p.kind), desc((p) => p.id))
  const { ids } = await walk('pending', 11, (p) => `${p.kind}:${p.id}`)
  assert.deepEqual(ids, [...all].sort(order).map((p) => `${p.kind}:${p.id}`))
})

test('an object answer keeps its other fields beside the page', async () => {
  const t = await get('tripwires?paged=1&limit=2')
  assert.equal(t.body.enabled, true)
  assert.equal(t.body.rules_saved, true)
  assert.deepEqual(t.body.defaults, TRIPWIRES.defaults)
  assert.ok(!('rules' in t.body), 'the full list rode along beside its page')
  const r = await get('report/access?paged=1&limit=3&list=credentials')
  assert.equal(r.body.generated_at, REPORT.generated_at)
  assert.equal(r.body.complete, true)
  assert.ok(!('sessions' in r.body) && !('credentials' in r.body))
  const d = await get('sessions/detail?sid=s_001&paged=1&limit=3')
  assert.deepEqual(d.body.session, DETAIL.session)
  assert.deepEqual(d.body.activity, DETAIL.activity)
  assert.equal(d.body.total, DETAIL.grants.length)
  assert.equal((await get('report/access?paged=1&list=everything')).status, 400)
})

test('limit is a whole number from 1 to 200; anything else is AV_BAD_LIMIT', async () => {
  for (const bad of ['0', '201', '-1', '1e2', '010', '2.5', '', 'abc', '20%30', '1000', '+5', ' 5']) {
    const r = await get(`credentials?paged=1&limit=${encodeURIComponent(bad)}`)
    assert.equal(r.status, 400, `limit=${bad}`)
    assert.equal(r.body.code, 'AV_BAD_LIMIT', `limit=${bad}`)
  }
  assert.equal((await get('credentials?paged=1&limit=5&limit=6')).body.code, 'AV_BAD_LIMIT')
  assert.equal((await get('credentials?paged=yes')).status, 400)
  assert.equal((await get('credentials?paged=1&limit=1')).body.items.length, 1)
  assert.equal((await get('credentials?paged=1&limit=200')).body.items.length, CREDENTIALS.length)
  assert.equal((await get('credentials?paged=1')).body.items.length, 25, 'the default page is 25')
})

test('a cursor that was not made by this server for this list and filter is AV_BAD_CURSOR', async () => {
  const first = (await get('credentials?paged=1&limit=5')).body
  const good = first.next_cursor
  assert.match(good, /^[A-Za-z0-9_-]+$/, 'cursors are opaque base64url')
  assert.equal((await get(`credentials?paged=1&limit=5&cursor=${good}`)).status, 200)

  // Edit what the cursor says and keep its seal: the seal no longer fits.
  const bytes = Buffer.from(good, 'base64url')
  const body = JSON.parse(bytes.subarray(16).toString())
  const edited = Buffer.concat([bytes.subarray(0, 16), Buffer.from(JSON.stringify({ ...body, k: ['svc-040', 'cred_040'] }))]).toString('base64url')
  const relisted = Buffer.concat([bytes.subarray(0, 16), Buffer.from(JSON.stringify({ ...body, l: 'templates' }))]).toString('base64url')
  const flipped = `${good.slice(0, 10)}${good[10] === 'A' ? 'B' : 'A'}${good.slice(11)}`
  const otherServer = new UiServer(stub.sock, { port: 0 }).cursors.seal('credentials', { q: '' }, 'next', ['svc-010', 'cred_010'])

  const bad = [
    edited, relisted, flipped, good.slice(0, -3), good.slice(0, 20), 'AAAA', 'not*base64', '%00',
    Buffer.from('{"v":1,"l":"credentials","d":"next","k":["a"]}').toString('base64url'),
    'A'.repeat(3000), otherServer,
  ]
  for (const c of bad) {
    const r = await get(`credentials?paged=1&limit=5&cursor=${encodeURIComponent(c)}`)
    assert.equal(r.status, 400, c.slice(0, 40))
    assert.equal(r.body.code, 'AV_BAD_CURSOR', c.slice(0, 40))
  }
  // A good cursor carried to another list, another search or another filter.
  for (const path of [
    `templates?paged=1&limit=5&cursor=${good}`,
    `credentials?paged=1&limit=5&q=svc&cursor=${good}`,
    `report/access?paged=1&limit=5&list=credentials&cursor=${good}`,
  ]) {
    const r = await get(path)
    assert.equal(r.status, 400, path)
    assert.equal(r.body.code, 'AV_BAD_CURSOR', path)
  }
  const detail = (await get('sessions/detail?sid=s_001&paged=1&limit=5')).body.next_cursor
  assert.equal((await get(`sessions/detail?sid=s_002&paged=1&limit=5&cursor=${detail}`)).body.code, 'AV_BAD_CURSOR')
  const report = (await get('report/access?paged=1&limit=5&since=7d')).body.next_cursor
  assert.equal((await get(`report/access?paged=1&limit=5&since=24h&cursor=${report}`)).body.code, 'AV_BAD_CURSOR')
  // And a cursor with no paged=1 is refused, not ignored.
  const lone = await get(`credentials?cursor=${good}`)
  assert.equal(lone.status, 400)
  assert.equal(lone.body.code, 'AV_BAD_CURSOR')
  assert.equal((await get(`credentials?paged=1&cursor=${good}&cursor=${good}`)).body.code, 'AV_BAD_CURSOR')
})

test('q is a case-insensitive match over visible fields, and filters before paging', async () => {
  const r = await get('credentials?paged=1&limit=3&q=SVC-01')
  assert.deepEqual(r.body.items.map((c) => c.slug), ['svc-010', 'svc-011', 'svc-012'])
  assert.equal(r.body.total, 10)
  const { ids } = await walk('credentials?q=svc-01', 3, (c) => c.slug)
  assert.deepEqual(ids, Array.from({ length: 10 }, (_, i) => `svc-01${i}`))
  assert.equal((await get('sessions?paged=1&q=svc-060')).body.total, 1, 'a session is found by the credential it maps')
  assert.equal((await get('pending?paged=1&q=GET%20/repos/1')).body.items.length > 0, true)
  assert.equal((await get('templates?paged=1&q=nothing-like-this')).body.total, 0)
})

test('q never matches a token, a placeholder or a value, even one the daemon leaked', async () => {
  const needles = [
    TOKEN, 'QoracleSecretTokenPart02', 'avs1.', PLACEHOLDER, PH_NONCE, 'av1.', VALUE, 'QORACLEVALUE',
  ]
  for (const list of ['credentials', 'sessions', 'pending', 'templates', 'listeners', 'report/access']) {
    for (const needle of needles) {
      const r = await get(`${list}?paged=1&q=${encodeURIComponent(needle)}`)
      assert.equal(r.status, 200, `${list} q=${needle}`)
      assert.deepEqual(r.body.items, [], `${list}: q=${needle} matched a withheld value`)
      assert.equal(r.body.total, 0, `${list}: q=${needle}`)
    }
  }
  // The leaky items are still there and still findable by what is visible,
  // and what the page is shown of them is scrubbed.
  const leaky = await get('credentials?paged=1&q=zz-leaky')
  assert.equal(leaky.body.total, 1)
  const shown = JSON.stringify(leaky.body)
  for (const needle of [TOKEN, PLACEHOLDER, VALUE]) assert.ok(!shown.includes(needle), `${needle} reached the page`)
  assert.ok(!('value' in leaky.body.items[0]) && !('token' in leaky.body.items[0]))
  assert.equal((await get('sessions?paged=1&q=s_007')).body.total, 1)
  assert.equal((await get('pending?paged=1&q=ap_003')).body.total, 1)
})

test('the cursors in an answer survive the scrub that every answer passes', async () => {
  const r = await get('sessions?paged=1&limit=10')
  assert.match(r.body.next_cursor, /^[A-Za-z0-9_-]{40,}$/)
  const next = await get(`sessions?paged=1&limit=10&cursor=${r.body.next_cursor}`)
  assert.equal(next.status, 200)
  assert.equal(next.body.items.length, 10)
})
