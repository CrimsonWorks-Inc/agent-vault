// Integrate-3, fix round 5.
//
// F1: a refused Touch ID confirmation recorded `presence.denied { reason:
// e.message }`. The message quotes the client's own clientDataJSON (its type
// and origin, or a JSON.parse snippet), none of it signed, so a caller with
// no valid signature could put any 8 KiB of text into audit.jsonl, GET
// /v1/audit and the export. The reason is now one of a closed set of codes.
//
// C28, the sweep: every audit row carries codes, not free text. A denial
// keeps its code and rule and loses the sentence, which quotes the request;
// vault_explain_denial serves the sentence from memory, to the session that
// was denied. Payload rules name a key by its index. Faults record a class,
// a failed bind its system code, a session whether it has a label. Text an
// agent wrote stays only in `*_untrusted`, always scrubbed and bounded.
//
// Item 3: `mcp install --tls=false` picked the https URL.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { startApi, PASSPHRASE } from './control-api-helpers.js'
import { startDaemon, cli, makeAuthenticator, enrol, signed } from './fix-control-helpers.js'
import { operationFor } from '../../src/ui/webauthn.js'
import { errorClass } from '../../src/daemon/server.js'
import { deny } from '../../src/core/errors.js'
import * as crypt from '../../src/store/crypto.js'
import { restoreBackup, BACKUP_FORMAT, BACKUP_VERSION, BACKUP_KDF } from '../../src/store/backup.js'
import { fresh } from './store-helpers.js'

const VALUE = 'ghp/PLUS+slash/001122334455667788'
const NEEDLES = [VALUE, 'PLUS+slash', '001122334455667788', encodeURIComponent(VALUE)]

/** A vault with a passphrase whose `demo` credential holds VALUE. */
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

const b64 = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url')
const CHAIN = ['seq', 'ts', 'kind', 'prev_hash', 'hash']
const own = (row) => Object.keys(row).filter((k) => !CHAIN.includes(k)).sort()

// --- F1 ---------------------------------------------------------------------------

test('F1: a refused Touch ID assertion records a closed code, never the client data it quotes, on all three surfaces', async () => {
  const a = await start()
  try {
    const human = makeAuthenticator()
    enrol(a.vault, human)
    const body = { cred: 'demo', approval: 'auto', methods: ['GET', 'POST', 'DELETE'] }
    const op = operationFor('session.create', body)
    // Each a real challenge for the real operation, with one thing wrong.
    // None of them needs a valid signature to reach the log.
    const variants = [
      ['client_data_type', (ch, p) => ({ ...p, clientDataJSON: b64({ type: VALUE, challenge: ch, origin: human.origin }) })],
      ['origin', (ch, p) => ({ ...p, clientDataJSON: b64({ type: 'webauthn.get', challenge: ch, origin: VALUE }) })],
      ['malformed', (ch, p) => ({ ...p, clientDataJSON: b64(`{"type":"${VALUE}`) })],
      ['malformed', (ch, p) => ({ ...p, clientDataJSON: b64('null') })],
      ['malformed', (ch, p) => ({ ...p, clientDataJSON: b64({ type: 'webauthn.get', challenge: 7, origin: human.origin }) })],
      ['malformed', (ch, p) => ({ ...p, authenticatorData: b64(VALUE.slice(0, 20)) })],
      ['malformed', (ch, p) => ({ ...p, signature: { value: VALUE } })],
      ['size', (ch, p) => ({ ...p, clientDataJSON: b64({ type: VALUE.repeat(300), challenge: ch, origin: human.origin }) })],
      ['credential', (ch, p) => ({ ...p, credentialId: VALUE })],
      ['challenge', (ch, p) => ({ ...p, clientDataJSON: b64({ type: 'webauthn.get', challenge: b64(VALUE), origin: human.origin }) })],
      ['signature', (ch, p) => ({ ...p, signature: b64(VALUE) })],
    ]
    for (const [, make] of variants) {
      const ch = await a.control('POST', '/v1/presence/challenge', { operation: op, origins: [human.origin] })
      assert.equal(ch.status, 200, JSON.stringify(ch.body))
      const presence = { challengeId: ch.body.challengeId, ...make(ch.body.challenge, human.assert(ch.body.challenge)) }
      const res = await a.control('POST', '/v1/sessions', { ...body, presence })
      assert.equal(res.status, 401, JSON.stringify(res.body))
    }
    assert.equal(Object.keys(a.vault.db.sessions).length, 0, 'a refused assertion created a session')
    const denied = a.audit('presence.denied')
    assert.deepEqual(denied.map((r) => r.reason), variants.map(([code]) => code))
    for (const r of denied) assert.deepEqual(own(r), ['reason'], JSON.stringify(r))
    await assertAbsent(a)

    // And a good one still works.
    const ok = await a.control('POST', '/v1/sessions', { ...body, presence: await signed(a.control, human, op) })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
  } finally { await a.stop() }
})

// --- C28: gateway denials --------------------------------------------------------

test('C28: a denial row has the code, rule, method and path, and no sentence; explain-denial gives the sentence to its own session only', async () => {
  const a = await start()
  try {
    const mine = a.session({ policy: { methods: ['GET'], deny_paths: ['/admin/**'] } })
    const other = a.session()
    // A method no policy names, chosen by the agent: the sentence quotes it.
    const MARK = 'SECRETMETHODMARKER'
    const r = await a.tool('vault_http', { cred: 'demo', method: MARK, path: '/x' }, { token: mine.token })
    assert.equal(r.body.status, 403, JSON.stringify(r.body))
    const said = JSON.parse(r.body.body)
    assert.ok(said.detail.includes(MARK), `the caller is told why: ${said.detail}`)

    const [row] = a.audit('request.denied')
    assert.equal(row.request_id, r.body.request_id)
    assert.equal(row.reason_code, 'AV_POLICY_DENIED')
    assert.equal(row.req.method, 'OTHER', 'a method no policy names is recorded as OTHER')
    assert.ok(!('detail' in row) && !('hint' in row), JSON.stringify(row))
    await assertAbsent(a, [...NEEDLES, MARK])

    // The session that was denied gets the sentence back.
    const explained = await a.tool('vault_explain_denial', { request_id: r.body.request_id }, { token: mine.token })
    assert.equal(explained.body.code, 'AV_POLICY_DENIED')
    assert.equal(explained.body.rule, row.rule)
    assert.equal(explained.body.detail, said.detail)
    // Another session, and a caller with none, get no record at all.
    for (const token of [other.token, null]) {
      const theirs = await a.tool('vault_explain_denial', { request_id: r.body.request_id }, { token })
      assert.match(theirs.body.error, /no record/, JSON.stringify(theirs.body))
      assert.ok(!JSON.stringify(theirs.body).includes(MARK))
    }

    // After an hour the sentence is forgotten: code and rule only.
    const real = Date.now
    Date.now = () => real() + 61 * 60_000
    try {
      const late = await a.tool('vault_explain_denial', { request_id: r.body.request_id }, { token: mine.token })
      assert.equal(late.body.code, 'AV_POLICY_DENIED')
      assert.equal(late.body.rule, row.rule)
      assert.equal(late.body.detail, null)
    } finally { Date.now = real }

    // And after a thousand later denials, the oldest goes first.
    const denyPath = await a.tool('vault_http', { cred: 'demo', method: 'GET', path: '/admin/x' }, { token: mine.token })
    assert.equal(denyPath.body.status, 403)
    assert.match(a.daemon.pipeline.explainDenial(denyPath.body.request_id, mine.session.id).detail, /deny list/)
    for (let i = 0; i < 1000; i++) await a.gateway('/p/demo/x')
    assert.equal(a.daemon.pipeline.explainDenial(denyPath.body.request_id, mine.session.id), null, 'the oldest sentence was kept past the bound')
    const evicted = await a.tool('vault_explain_denial', { request_id: denyPath.body.request_id }, { token: mine.token })
    assert.ok(!JSON.stringify(evicted.body).includes('deny list'), JSON.stringify(evicted.body))
  } finally { await a.stop() }
})

test('C28: a payload rule names its key by index, and a strict query names the parameter by position, on all three surfaces', async () => {
  const a = await start()
  try {
    const json = a.session({ policy: { payload: { json: { '/ok': {}, [`/${VALUE}`]: { absent: true } } } } })
    const nested = { ghp: { 'PLUS+slash': { '001122334455667788': 1 } } }
    const r = await a.gateway('/p/demo/x', {
      method: 'POST', body: JSON.stringify(nested),
      headers: { authorization: `Bearer ${json.placeholder}`, 'content-type': 'application/json' },
    })
    assert.equal(r.status, 403, r.text)
    assert.equal(r.json.rule, 'payload:json:1:absent')
    assert.equal(a.audit('request.denied').at(-1).rule, 'payload:json:1:absent')

    const strict = a.session({ policy: { payload: { query: { a: {} }, query_strict: true } } })
    const q = await a.gateway(`/p/demo/x?a=1&${encodeURIComponent(VALUE)}=v`, { headers: { authorization: `Bearer ${strict.placeholder}` } })
    assert.equal(q.status, 403, q.text)
    assert.equal(q.json.rule, 'payload:query:1:strict')
    assert.equal(a.audit('request.denied').at(-1).rule, 'payload:query:1:strict')
    assert.equal(a.seen.length, 0, 'a refused request reached the upstream')
    await assertAbsent(a)
  } finally { await a.stop() }
})

test('C28: a redirect refused for its host records no host it was not allowed to reach', async () => {
  const HOST = 'secretmarker99887766.evil.test'
  const a = await startApi({
    upstreamReply: (req, res) => { res.writeHead(302, { location: `http://${HOST}/x` }); res.end() },
  })
  try {
    const s = a.session({ policy: { methods: ['GET'], redirects: { max: 2 } } })
    const r = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(r.status, 302, r.text)
    const [row] = a.audit('request.redirect_returned')
    assert.equal(row.reason, 'host')
    assert.equal(row.to_host, null)
    await assertAbsent(a, [HOST, 'secretmarker'])
  } finally { await a.stop() }
})

// --- C28: daemon rows ------------------------------------------------------------

test('C28: a fault is recorded by class, never by message', () => {
  assert.equal(errorClass(new TypeError(VALUE)), 'TypeError')
  assert.equal(errorClass(new SyntaxError(VALUE)), 'SyntaxError')
  assert.equal(errorClass(deny('AV_LOCKED', VALUE)), 'AV_LOCKED')
  assert.equal(errorClass(Object.assign(new Error(VALUE), { name: VALUE })), 'other')
  assert.equal(errorClass({ name: VALUE, message: VALUE }), 'other')
  assert.equal(errorClass(VALUE), 'other')
  assert.equal(errorClass(undefined), 'other')
})

test('C28: a listener that cannot bind records its system code, not the message', async () => {
  const busy = createServer()
  await new Promise((resolve) => busy.listen(0, '127.0.0.1', resolve))
  const port = busy.address().port
  const d = await startDaemon({ listeners: [{ id: 'busy', address: `127.0.0.1:${port}`, surfaces: ['gateway'] }] })
  try {
    const [row] = d.vault.audit.read({ limit: 1000 }).filter((r) => r.kind === 'listen.bind_failed')
    assert.deepEqual(own(row), ['listener_id', 'reason'])
    assert.equal(row.reason, 'EADDRINUSE')
    assert.ok(!JSON.stringify(row).includes(String(port)), JSON.stringify(row))
  } finally {
    await d.stop()
    await new Promise((resolve) => busy.close(resolve))
  }
})

test('C28: session.created says whether a session has a label, not what it says', async () => {
  const a = await start()
  try {
    a.openWindow()
    const r = await a.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], label: `job ${VALUE}` })
    a.closeWindow()
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const [row] = a.audit('session.created')
    assert.equal(row.has_label, true)
    assert.ok(!('label' in row))
    assert.equal(a.vault.db.sessions[row.session_id].label, `job ${VALUE}`, 'the session keeps its label')
    await assertAbsent(a)
  } finally { await a.stop() }
})

test('C28: a failed webhook records a system code or `error`, never other text from the error', async () => {
  let thrown = null
  const a = await startApi({ notifyFetch: async () => { throw thrown } })
  try {
    a.vault.setNotifyWebhook({ url: 'https://hooks.example/x', detail: 'minimal' })
    thrown = Object.assign(new Error(VALUE), { code: 'secret-in-a-code ghp' })
    assert.deepEqual((await a.control('POST', '/v1/notify/test')).body, { sent: false, error: 'error' })
    a.daemon.notifier.lastTest = 0
    a.daemon.notifier.lastFailureRecorded = 0
    thrown = Object.assign(new Error(VALUE), { code: 'ECONNREFUSED' })
    assert.deepEqual((await a.control('POST', '/v1/notify/test')).body, { sent: false, error: 'ECONNREFUSED' })
    assert.deepEqual(a.audit('notify.failed').map((r) => r.reason), ['error', 'ECONNREFUSED'])
    await assertAbsent(a, [VALUE, 'secret-in-a-code'])
  } finally { await a.stop() }
})

// --- C28: *_untrusted fields -----------------------------------------------------

test('C28: every *_untrusted field is scrubbed whole, cleaned of placeholders, and cut to 200', async () => {
  const a = await start()
  try {
    // vault_get_placeholder: the agent's reason went to the log as sent.
    const s = a.session()
    const reason = `${'r'.repeat(150)} ${s.placeholder} ${VALUE} ${'z'.repeat(300)}`
    const got = await a.tool('vault_get_placeholder', { cred: 'demo', reason }, { token: s.token })
    assert.equal(got.isError, false, JSON.stringify(got.body))
    const [issued] = a.audit('placeholder.issued_via_mcp')
    assert.ok(issued.agent_reason_untrusted.length <= 200, issued.agent_reason_untrusted.length)
    assert.match(issued.agent_reason_untrusted, /«placeholder»/)
    assert.ok(!issued.agent_reason_untrusted.includes(s.placeholder.slice(0, 12)))

    // A held request's reason (the av-reason header) had no bound.
    const held = a.session({ policy: { approval: 'each' } })
    const r = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${held.placeholder}`, 'av-reason': `${'h'.repeat(190)}${VALUE}${'t'.repeat(500)}` } })
    assert.equal(r.status, 202, r.text)
    const [asked] = a.audit('approval.requested')
    assert.ok(asked.agent_reason_untrusted.length <= 200, asked.agent_reason_untrusted.length)
    assert.ok(asked.agent_reason_untrusted.startsWith('h'.repeat(190)))

    // A panic reason, through the same cleaning as the rest.
    const p = await a.control('POST', '/v1/panic', { reason: `${'p'.repeat(160)}${VALUE}` })
    assert.equal(p.status, 200, JSON.stringify(p.body))
    const [panic] = a.audit('panic.triggered')
    assert.equal(panic.reason_untrusted, `${'p'.repeat(160)}[[av:redacted:demo]]`)
    await assertAbsent(a, [...NEEDLES, 'ghp/PLU'])
  } finally { await a.stop() }
})

test('C28: a quarantine reason restored from a bundle is cleaned before it is recorded', async () => {
  const RECOVERY = 'correct horse battery staple'
  const KDF = { ...BACKUP_KDF, keylen: 32, maxmem: 256 * 1024 * 1024 }
  const salt = crypt.randomKey().subarray(0, 16)
  const head = { format: BACKUP_FORMAT, version: BACKUP_VERSION, created_at: new Date().toISOString() }
  const key = await crypt.scryptAsync(RECOVERY, salt, KDF)
  const since = new Date().toISOString()
  const entry = {
    slug: 'third', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' }, created_at: since,
    fields: [{ name: 'token', value: VALUE, sites: ['header:authorization:Bearer'] }], scrub_patterns: [], pins: {}, expires_at: null,
    quarantine: { since, by: 'control', rule_id: null, reason_untrusted: `leaked ${VALUE} here` },
  }
  const sealed = crypt.seal(key, JSON.stringify({ credentials: [entry], templates: [] }), `${head.format}|${head.version}|${head.created_at}`)
  const bundle = { ...head, kdf: { ...BACKUP_KDF, salt: salt.toString('base64') }, cipher: 'chacha20-poly1305', nonce: sealed.nonce, ct: sealed.ct }
  const t = fresh('av-r5-restore-')
  try {
    const out = await restoreBackup(t.vault, bundle, { recoveryPassphrase: RECOVERY })
    assert.ok(out.restored.includes('third'), JSON.stringify(out))
    const [row] = t.vault.audit.read({ limit: 1000 }).filter((r) => r.kind === 'cred.quarantined')
    assert.equal(row.reason_untrusted, 'leaked [[av:redacted:third]] here')
    const text = readFileSync(t.vault.audit.path, 'utf8')
    for (const n of NEEDLES) assert.ok(!text.includes(n), `audit.jsonl holds ${n}`)
  } finally { t.done() }
})

// --- item 3 ----------------------------------------------------------------------

test('item 3: mcp install --tls takes no value; bare --tls is the https URL and its absence the plain one', async () => {
  const d = await startDaemon()
  try {
    for (const v of ['--tls=false', '--tls=0', '--tls=no', '--tls=true']) {
      const r = await cli(d.dir, ['mcp', 'install', '--agent', 'claude-code', '--transport', 'http', v, '--print'], { env: { HOME: d.dir } })
      assert.equal(r.code, 2, `${v}: ${r.stdout} ${r.stderr}`)
      assert.match(r.stderr, /--tls takes no value/)
      assert.ok(!r.stdout.includes('https://'), `${v} still printed a URL`)
    }
    const tls = await cli(d.dir, ['mcp', 'install', '--agent', 'claude-code', '--transport', 'http', '--tls', '--print'], { env: { HOME: d.dir } })
    assert.equal(tls.code, 0, tls.stderr)
    assert.ok(tls.stdout.includes('https://localhost:7443/mcp'), tls.stdout)
    const plain = await cli(d.dir, ['mcp', 'install', '--agent', 'claude-code', '--transport', 'http', '--print'], { env: { HOME: d.dir } })
    assert.equal(plain.code, 0, plain.stderr)
    assert.ok(!plain.stdout.includes('https://') && plain.stdout.includes('http://127.0.0.1:'), plain.stdout)
  } finally { await d.stop() }
})
