// Integrate-3, fix round 4.
//
// F1 / C27: `request.allowed` filed the glob that let a request through, as
// text. A glob can be one an agent proposed, so it can be a stored secret,
// and it went to audit.jsonl, GET /v1/audit and the export unscrubbed. It
// still did after the value was rotated out. The row now names the rule by
// its place in the grant. A deny-list denial named its pattern the same way,
// and a narrowing, which anyone on the socket may send, can add one.
//
// F2: `pending.decided_many` copied every id in the client's list into the
// log, whether or not anything had that id. Now only ids the daemon minted
// are written; the rest are counted.
//
// S1 / C26: `first-use` with a write method asks once and then never again,
// so it is elevated like `auto`: creating one, approving a request into one,
// or narrowing a request into one at approval needs a fresh proof.
//
// Coordinator items 5 and 6, at the end: CLI flags read loosely.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { startApi, PASSPHRASE } from './control-api-helpers.js'
import { startDaemon, cli } from './fix-control-helpers.js'
import { elevationOf } from '../../src/daemon/session-requests.js'

const VALUE = 'ghp/PLUS+slash/001122334455667788'
const PIN = '12345678'
const NEEDLES = [VALUE, 'PLUS+slash', '001122334455667788', encodeURIComponent(VALUE)]

/** A vault whose `demo` credential holds VALUE. */
async function start() {
  const a = await startApi({ passphrase: PASSPHRASE })
  a.vault.rotateCredential('demo', { value: VALUE, mode: 'revoke', retireMs: 0 })
  return a
}

/** The rows of audit.jsonl, GET /v1/audit and the export. */
async function surfaces(a) {
  const file = readFileSync(a.vault.audit.path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
  const read = await a.control('GET', '/v1/audit?limit=100000')
  assert.equal(read.status, 200)
  const exported = await a.control('GET', '/v1/audit/export')
  assert.equal(exported.status, 200)
  return [['audit.jsonl', file], ['GET /v1/audit', read.body], ['the export', exported.body.rows]]
}

async function assertAbsent(a, needles = NEEDLES) {
  for (const [where, rows] of await surfaces(a)) {
    assert.ok(Array.isArray(rows) && rows.length > 0, `${where} is not a list of records`)
    const text = JSON.stringify(rows)
    for (const n of needles) assert.ok(!text.includes(n), `${where} holds ${JSON.stringify(n)}`)
  }
}

/** Ask as an agent, approve as a human in the window, and return the grant and a placeholder for it. */
async function approved(a, proposal) {
  const asked = await a.control('POST', '/v1/session-requests', proposal)
  assert.equal(asked.status, 200, JSON.stringify(asked.body))
  a.openWindow()
  try {
    const r = await a.control('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const grant = a.vault.db.grants[r.body.session.grant_id]
    const { placeholder } = a.vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
    return { grant, placeholder }
  } finally { a.closeWindow() }
}

const call = (a, placeholder, path) => a.gateway(`/p/demo${path}`, { headers: { authorization: `Bearer ${placeholder}` } })

// --- F1 / C27 -----------------------------------------------------------------------

test('C27: a secret as the path glob and the route glob is in no gateway row, before or after rotation; the grant still allows the path', async () => {
  const a = await start()
  try {
    const { grant, placeholder } = await approved(a, {
      cred: 'demo', methods: ['GET'], paths: ['/elsewhere/**', `/${VALUE}`],
      routes: [{ methods: ['GET'], paths: ['/elsewhere/**'] }, { methods: ['GET'], paths: [`/${VALUE}`] }], reason: 'job',
    })
    assert.deepEqual(grant.policy.paths, ['/elsewhere/**', `/${VALUE}`], 'the grant keeps the glob text')

    const ok = await call(a, placeholder, `/${VALUE}`)
    assert.equal(ok.status, 200, ok.text)
    assert.equal(a.seen.at(-1).url, `/${VALUE}`)
    const [row] = a.audit('request.allowed')
    assert.equal(row.req.path_rule, 1, 'the second path rule let it through')
    assert.equal(row.req.route_rule, 1, 'and the second route')
    assert.equal(row.req.method, 'GET')
    assert.ok(!('path_glob_matched' in row.req) && !('route_matched' in row.req), JSON.stringify(row.req))
    assert.equal((await call(a, placeholder, '/not-the-path')).status, 403)
    await assertAbsent(a)

    // Rotated out with no grace: the old value is no longer a stored secret,
    // so nothing would scrub it. The row never held it to begin with.
    a.vault.rotateCredential('demo', { value: 'ghp_NEWVALUE99887766554433221100ff', mode: 'keep', retireMs: 0 })
    assert.ok(!a.vault.allSecrets().some((s) => s.secret === VALUE), 'the old value is still stored; the test proves nothing')
    const { placeholder: fresh } = a.vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
    assert.equal((await call(a, fresh, `/${VALUE}`)).status, 200)
    assert.equal((await call(a, fresh, '/not-the-path')).status, 403)
    const rows = a.audit('request.allowed')
    assert.equal(rows.length, 2)
    assert.equal(rows[1].req.path_rule, 1)
    assert.equal(rows[1].req.route_rule, 1)
    // The request's own path is the one thing C27 leaves as it was: scrubbed
    // while the value is stored. Once it is not, the path is just a path, so
    // only the first row is held to the full needle list.
    for (const [where, all] of await surfaces(a)) {
      const text = JSON.stringify(all.map((r) => (r.kind?.startsWith('request.') && r.req ? { ...r, req: { ...r.req, path: null } } : r)))
      for (const n of NEEDLES) assert.ok(!text.includes(n), `${where} holds ${JSON.stringify(n)} outside req.path`)
    }
  } finally { await a.stop() }
})

test('C27: a path-only grant records path_rule and a null route_rule, never the glob', async () => {
  const a = await start()
  try {
    const { placeholder } = await approved(a, { cred: 'demo', methods: ['GET'], paths: [`/${VALUE}`], reason: 'job' })
    assert.equal((await call(a, placeholder, `/${VALUE}`)).status, 200)
    const [row] = a.audit('request.allowed')
    assert.equal(row.req.path_rule, 0)
    assert.equal(row.req.route_rule, null)
    await assertAbsent(a)
  } finally { await a.stop() }
})

test('C27: a deny pattern added by an open narrowing is named by index in the denial, never by its text', async () => {
  const a = await start()
  try {
    const { grant, placeholder } = await approved(a, { cred: 'demo', methods: ['GET'], paths: ['/**'], reason: 'job' })
    // Narrowing needs no presence: it only takes capability away.
    const narrowed = await a.control('POST', '/v1/sessions/narrow', { sid: grant.session_id, narrow: { deny_paths: [`/${VALUE}`] } })
    assert.equal(narrowed.status, 200, JSON.stringify(narrowed.body))
    const r = await call(a, placeholder, `/${VALUE}`)
    assert.equal(r.status, 403, r.text)
    const denial = a.audit('request.denied').at(-1)
    assert.match(denial.rule, /^deny_paths:\d+$/)
    assert.equal(a.vault.db.grants[grant.id].policy.deny_paths[Number(denial.rule.split(':')[1])], `/${VALUE}`, 'the index names the pattern in the grant')
    await assertAbsent(a)
  } finally { await a.stop() }
})

// --- F2 -----------------------------------------------------------------------------

test('F2: decide-many writes only ids the daemon minted, and counts the rest', async () => {
  const a = await start()
  try {
    const asked = await a.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET'], paths: ['/x'], reason: 'job' })
    const real = asked.body.id
    a.openWindow()
    const r = await a.control('POST', '/v1/pending/decide-many', {
      decisions: [{ id: real, kind: 'session', granted: true }, { id: VALUE, kind: 'session', granted: true }],
    })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.deepEqual(r.body.decided.map((d) => [d.id, d.outcome]), [[real, 'decided'], [VALUE, 'skipped']],
      'the caller is still told about the id it sent')
    // A PIN as a denied id, and a made-up held-request id.
    const r2 = await a.control('POST', '/v1/pending/decide-many', {
      decisions: [{ id: PIN, kind: 'session', granted: false }, { id: `apr_${PIN}`, kind: 'request', granted: false }],
    })
    assert.equal(r2.status, 200, JSON.stringify(r2.body))
    // A real id that is no longer pending is still the daemon's own: it is
    // recorded, as skipped.
    const r3 = await a.control('POST', '/v1/pending/decide-many', { decisions: [{ id: real, kind: 'session', granted: false }] })
    assert.equal(r3.status, 200, JSON.stringify(r3.body))
    a.closeWindow()

    const rows = a.audit('pending.decided_many')
    assert.equal(rows.length, 3)
    const shape = (row) => ({ granted: row.granted, denied: row.denied, skipped: row.skipped, unknown: row.unknown })
    assert.deepEqual(shape(rows[0]), { granted: [real], denied: [], skipped: [], unknown: 1 })
    assert.deepEqual(shape(rows[1]), { granted: [], denied: [], skipped: [], unknown: 2 })
    assert.deepEqual(shape(rows[2]), { granted: [], denied: [real], skipped: [real], unknown: 0 })
    for (const row of rows) {
      assert.deepEqual(Object.keys(row).filter((k) => !['seq', 'ts', 'kind', 'prev_hash', 'hash'].includes(k)).sort(), ['denied', 'granted', 'skipped', 'unknown'])
    }
    assert.equal(Object.keys(a.vault.db.sessions).length, 1, 'nothing was made for a made-up id')
    await assertAbsent(a, [...NEEDLES, PIN])
  } finally { await a.stop() }
})

// --- S1 / C26 -----------------------------------------------------------------------

const FIRST_USE_WRITES = { cred: 'demo', methods: ['GET', 'POST', 'DELETE'], approval: 'first-use' }
const openWindow = (d) => { d.daemon.presenceGraceUntil = Date.now() + 60_000 }

async function requestFor(d, body = { methods: ['GET', 'POST'] }) {
  const r = await d.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'job', ...body })
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body.id
}

test('C26: elevationOf names first-use with a write method, and not read-only first-use', () => {
  assert.deepEqual(elevationOf(FIRST_USE_WRITES), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'first-use', methods: ['get', 'patch'] }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'first-use', routes: [{ methods: ['DELETE'], paths: ['/x'] }] }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ grants: [{ cred: 'a' }, { ...FIRST_USE_WRITES, cred: 'b' }] }), ['approval_auto_writes'])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'first-use' }), [], 'the default methods are GET and HEAD')
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'first-use', methods: ['GET', 'HEAD', 'OPTIONS'] }), [])
  assert.deepEqual(elevationOf({ cred: 'demo', approval: 'on-write', methods: ['POST'] }), [])
})

test('C26: creating first-use with writes needs a fresh proof; read-only first-use rides the window', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    openWindow(d)
    const refused = await d.control('POST', '/v1/sessions', FIRST_USE_WRITES)
    assert.equal(refused.status, 401, JSON.stringify(refused.body))
    assert.equal(refused.body.rule, 'fresh_presence')
    const made = await d.control('POST', '/v1/sessions', { ...FIRST_USE_WRITES, presence: { passphrase: PASSPHRASE } })
    assert.equal(made.status, 200, JSON.stringify(made.body))
    assert.equal(d.vault.db.grants[made.body.grant_id].policy.approval, 'first-use')
    const listed = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === made.body.session_id)
    assert.deepEqual(listed.elevated, ['approval_auto_writes'])

    openWindow(d)
    const plain = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET', 'HEAD'], approval: 'first-use' })
    assert.equal(plain.status, 200, JSON.stringify(plain.body))
    const listedPlain = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === plain.body.session_id)
    assert.deepEqual(listedPlain.elevated, [])
  } finally { await d.stop() }
})

test('C26: approving a request into first-use with writes needs a fresh proof, not the window', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const id = await requestFor(d)
    openWindow(d)
    const overrides = { approval: 'first-use' }
    const refused = await d.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides })
    assert.equal(refused.status, 401, JSON.stringify(refused.body))
    assert.equal(refused.body.rule, 'fresh_presence')
    assert.equal(d.daemon.sessionRequests.get(id).state, 'pending', 'still waiting')
    const ok = await d.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides, presence: { passphrase: PASSPHRASE } })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(d.vault.db.grants[ok.body.session.grant_id].policy.approval, 'first-use')
  } finally { await d.stop() }
})

test('C26: narrowing a request into first-use with a write left needs a fresh proof; narrowing it to read-only does not', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    const wide = await requestFor(d, { methods: ['GET', 'POST', 'DELETE'] })
    openWindow(d)
    const refused = await d.control('POST', '/v1/session-requests/decide', {
      id: wide, granted: true, overrides: { approval: 'first-use', methods: ['GET', 'POST'] },
    })
    assert.equal(refused.status, 401, JSON.stringify(refused.body))
    assert.equal(refused.body.rule, 'fresh_presence')

    const ok = await d.control('POST', '/v1/session-requests/decide', {
      id: wide, granted: true, overrides: { approval: 'first-use', methods: ['GET'] },
    })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    const grant = d.vault.db.grants[ok.body.session.grant_id]
    assert.equal(grant.policy.approval, 'first-use')
    assert.deepEqual(grant.policy.methods, ['GET'])

    // In a bulk decision, one such item makes the whole list fresh.
    const a = await requestFor(d, { methods: ['GET'] })
    const b = await requestFor(d)
    openWindow(d)
    const decisions = [{ id: a, kind: 'session', granted: true }, { id: b, kind: 'session', granted: true, overrides: { approval: 'first-use' } }]
    const bulk = await d.control('POST', '/v1/pending/decide-many', { decisions })
    assert.equal(bulk.status, 401, JSON.stringify(bulk.body))
    assert.equal(bulk.body.rule, 'fresh_presence')
    const fresh = await d.control('POST', '/v1/pending/decide-many', { decisions, presence: { passphrase: PASSPHRASE } })
    assert.equal(fresh.status, 200, JSON.stringify(fresh.body))
  } finally { await d.stop() }
})

test('C26: a live narrowing cannot loosen a write grant into first-use', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    openWindow(d)
    const made = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET', 'POST'], approval: 'on-write' })
    assert.equal(made.status, 200, JSON.stringify(made.body))
    d.daemon.presenceGraceUntil = 0
    const r = await d.control('POST', '/v1/sessions/narrow', { sid: made.body.session_id, narrow: { approval: 'first-use' } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(d.vault.db.grants[made.body.grant_id].policy.approval, 'on-write', 'the stricter mode stays')
    const listed = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === made.body.session_id)
    assert.deepEqual(listed.elevated, [])
  } finally { await d.stop() }
})

// --- CLI flags (coordinator items 5 and 6) -------------------------------------------
//
// `--force=false` was the string "false", which is truthy, so `env` replaced
// the file and exited 0. `--uses` with no value was `true`, and Number(true)
// is 1, so `env` minted a one-use placeholder and exited 0. A flag that is
// there-or-not takes no value, and a numeric flag needs one.

test('a boolean flag given a value, even "false", is refused with exit 2 naming the flag', async () => {
  const d = await startDaemon({ socketName: 'control.sock' })
  try {
    const made = await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])
    assert.equal(made.code, 0, made.stderr)
    const f = join(d.dir, 'mapped.env')
    writeFileSync(f, 'MINE=1\n')
    const before = d.vault.audit.read({ limit: 1000 }).filter((x) => x.kind.startsWith('placeholder.issued')).length
    for (const args of [
      ['env', '--out', f, '--map', 'X=demo', '--force=false'],
      ['env', '--out', f, '--map', 'X=demo', '--force=true'],
      ['env', '--out', f, '--map', 'X=demo', '--force=no'],
      ['env', '--map', 'X=demo', '--profile-vars=false'],
      ['tls', 'setup', '--force=false'],
    ]) {
      const r = await cli(d.dir, args)
      const flag = args.at(-1).split('=')[0]
      assert.equal(r.code, 2, `${args.join(' ')}: ${r.stderr}`)
      assert.ok(r.stderr.includes(`${flag} takes no value`), `${args.join(' ')}: ${r.stderr}`)
    }
    assert.equal(readFileSync(f, 'utf8'), 'MINE=1\n', 'the file was replaced')
    const after = d.vault.audit.read({ limit: 1000 }).filter((x) => x.kind.startsWith('placeholder.issued')).length
    assert.equal(after, before, 'a refused command minted a placeholder')
    // The flag itself still works.
    const forced = await cli(d.dir, ['env', '--out', f, '--map', 'X=demo', '--force'])
    assert.equal(forced.code, 0, forced.stderr)
    assert.notEqual(readFileSync(f, 'utf8'), 'MINE=1\n')
  } finally { await d.stop() }
})

test('a numeric flag with no value is refused with exit 2 naming the flag, not read as 1', async () => {
  const d = await startDaemon({ socketName: 'control.sock' })
  try {
    const made = await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])
    assert.equal(made.code, 0, made.stderr)
    const issued = () => d.vault.audit.read({ limit: 1000 }).filter((x) => x.kind.startsWith('placeholder.issued')).length
    const before = issued()
    for (const args of [
      ['env', '--map', 'X=demo', '--uses'],
      ['env', '--map', 'X=demo', '--uses=0'],
      ['env', '--map', 'X=demo', '--uses=lots'],
      ['exec', '--map', 'X=demo', '--uses', '--', process.execPath, '-e', '0'],
      ['ph', 'next', 'demo', '--uses'],
      ['ph', 'next', 'demo', '--uses=0'],
      ['audit', 'tail', '--limit'],
      ['tls', 'setup', '--port'],
      // --print, and HOME here, so nothing is written even if the port were read.
      ['mcp', 'install', '--agent', 'claude-code', '--transport', 'http', '--port', '--print'],
    ]) {
      const r = await cli(d.dir, args, { env: { HOME: d.dir } })
      const flag = args.find((a) => /^--(uses|limit|port)/.test(a)).split('=')[0]
      assert.equal(r.code, 2, `${args.join(' ')}: ${r.stderr}`)
      assert.ok(r.stderr.includes(flag), `${args.join(' ')}: ${r.stderr}`)
    }
    assert.equal(issued(), before, 'a refused command minted a placeholder')
    const ok = await cli(d.dir, ['env', '--map', 'X=demo', '--uses', '3', '--json'])
    assert.equal(ok.code, 0, ok.stderr)
    assert.ok(issued() > before, 'a valid --uses mints')
  } finally { await d.stop() }
})
