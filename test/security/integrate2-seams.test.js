// The seams wave 2 left stubbed, now that the branches meet (integrate-2).
// Each batch called the others by contract name, with optional chaining or a
// stub in its tests. These run the real modules against each other: the
// gateway with the connectors' pinnedRequest and extractHealth, the gateway
// with the store's grant, budget, health, quarantine and settings methods, the
// store's scrub patterns under the gateway's grammar, the held-request record
// as the store's report reads it, and the panic hook that stays unwired until
// wave 3. Upstreams are real local servers, so "nothing sent" is counted.

import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import https from 'node:https'
import { execFile, execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { Pipeline } from '../../src/daemon/pipeline.js'
import { pinnedRequest, spkiOf } from '../../src/connectors/pinning.js'
import { summarizeSession } from '../../src/store/activity.js'
import { startDaemon } from './fix-control-helpers.js'

const SECRET = 'ghp_INTEGRATE2SEAMS0011223344556677889900'
const WRONG = `sha256/${'A'.repeat(43)}=`
const HOUR = 3_600_000
const problem = (r) => JSON.parse(Buffer.from(r.body).toString('utf8'))

// --------------------------------------------------------------- fixtures

const certDir = mkdtempSync(join(tmpdir(), 'av-int2-tls-'))
after(() => rmSync(certDir, { recursive: true, force: true }))

/** A private root, an intermediate, a leaf it signs, and a self-signed leaf; all for 127.0.0.1. */
function makeCerts() {
  const run = (args) => execFileSync('openssl', args, { cwd: certDir, stdio: ['ignore', 'pipe', 'pipe'] })
  run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.crt', '-days', '2', '-subj', '/CN=Int2Root', '-addext', 'basicConstraints=critical,CA:TRUE'])
  run(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'int.key', '-out', 'int.csr', '-subj', '/CN=Int2Intermediate'])
  writeFileSync(join(certDir, 'int.ext'), 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
  run(['x509', '-req', '-in', 'int.csr', '-CA', 'root.crt', '-CAkey', 'root.key', '-out', 'int.crt', '-days', '2', '-CAcreateserial', '-extfile', 'int.ext'])
  writeFileSync(join(certDir, 'leaf.ext'), 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
  run(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=127.0.0.1'])
  run(['x509', '-req', '-in', 'leaf.csr', '-CA', 'int.crt', '-CAkey', 'int.key', '-out', 'leaf.crt', '-days', '2', '-CAcreateserial', '-extfile', 'leaf.ext'])
  run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.crt', '-days', '2', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'])
  const read = (name) => readFileSync(join(certDir, name), 'utf8')
  const pin = (name) => spkiOf(new X509Certificate(read(name)))
  return {
    root: join(certDir, 'root.crt'),
    self: { key: read('self.key'), cert: read('self.crt'), pin: pin('self.crt') },
    chain: { key: read('leaf.key'), cert: read('leaf.crt') + read('int.crt'), leafPin: pin('leaf.crt'), intPin: pin('int.crt') },
  }
}
const certs = makeCerts()

/** A local upstream that records every request it is sent. */
async function upstream(t, { tls = null, respond } = {}) {
  const seen = []
  const handler = (req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, raw: req.rawHeaders, body })
      if (respond) return respond(req, res, seen.length)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end('{"ok":true}')
    })
  }
  const server = tls ? https.createServer(tls, handler) : createServer(handler)
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve) }))
  return { port: server.address().port, seen }
}

/** A real vault and pipeline, no injected upstream: the request goes out through pinnedRequest. */
function gateway(t, port, { scheme = 'https', kind = 'http', host = `127.0.0.1:${port}`, policy = {}, session = {}, fetchImpl } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-int2-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({ slug: 'up', kind, connector: { host, scheme }, fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] } })
  const cred = vault.findCredential('up')
  const made = vault.createSession({ label: 'int2', ttlMs: 8 * HOUR, ...session })
  const grant = vault.createGrant({
    sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
    policy: { hosts: [host.split(':')[0]], methods: ['GET', 'POST'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'auto', ...policy },
  })
  const { placeholder } = vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
  const pipeline = new Pipeline(vault, { allowedHosts: new Set(['127.0.0.1', 'localhost']), ...(fetchImpl ? { fetchImpl } : {}) })
  const req = (over = {}) => ({
    method: 'GET', path: '/p/up/x', query: '',
    headers: [['host', 'localhost'], ['av-session', made.token], ['authorization', `Bearer ${placeholder}`]],
    body: null, ...over,
  })
  const row = () => Object.values(vault.db.placeholders).find((p) => p.grant_id === grant.id && p.placeholder_text !== undefined) ??
    Object.values(vault.db.placeholders).find((p) => p.grant_id === grant.id)
  return { dir, vault, cred, session: made.session, token: made.token, grant, placeholder, pipeline, req, row }
}

// ------------------------------------------- gateway + connectors (F11, C9)

test('a correct leaf pin goes out through the real pinnedRequest, with the secret and the URL host', async (t) => {
  const up = await upstream(t, { tls: { key: certs.self.key, cert: certs.self.cert } })
  const g = gateway(t, up.port)
  g.vault.setPins('up', '127.0.0.1', [certs.self.pin])
  const res = await g.pipeline.handle(g.req())
  assert.equal(res.status, 200, Buffer.from(res.body ?? '').toString())
  assert.equal(up.seen.length, 1)
  assert.equal(up.seen[0].headers.authorization, `Bearer ${SECRET}`)
  assert.equal(up.seen[0].headers.host, `127.0.0.1:${up.port}`)
})

test('a wrong pin on an untrusted self-signed upstream sends nothing and is refunded; its own leaf pin is reached', async (t) => {
  // C7/C8: only an exact leaf pin stands in for CA trust. A pin that does not
  // match an untrusted leaf leaves Node's own refusal, before any byte.
  const up = await upstream(t, { tls: { key: certs.self.key, cert: certs.self.cert } })
  const g = gateway(t, up.port)
  g.vault.setPins('up', '127.0.0.1', [WRONG])
  const p = problem(await g.pipeline.handle(g.req()))
  assert.equal(p.code, 'AV_UPSTREAM_UNREACHABLE')
  assert.equal(p.refunded, true)
  assert.equal(up.seen.length, 0, 'the upstream received a request')
  assert.equal(g.row().uses, 0)
  g.vault.setPins('up', '127.0.0.1', [certs.self.pin])
  assert.equal((await g.pipeline.handle(g.req())).status, 200)
  assert.equal(up.seen.length, 1)
})

test('on a chain the daemon trusts, an intermediate or leaf pin is honoured, and a pin that matches nothing is AV_PIN_MISMATCH, refunded and unsent', async (t) => {
  // NODE_EXTRA_CA_CERTS is read once at start-up, so the gateway runs in a
  // child that trusts the private root, as a daemon would. The server, and
  // its request count, stay in this process.
  const up = await upstream(t, { tls: { key: certs.chain.key, cert: certs.chain.cert } })
  const script = join(certDir, 'child.mjs')
  writeFileSync(script, `
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from ${JSON.stringify(new URL('../../src/store/vault.js', import.meta.url).href)}
import { Pipeline } from ${JSON.stringify(new URL('../../src/daemon/pipeline.js', import.meta.url).href)}
const [port, ...pins] = process.argv.slice(2)
const out = []
for (const pin of pins) {
  const dir = mkdtempSync(join(tmpdir(), 'av-int2-child-'))
  try {
    const vault = Vault.create(dir, { factor: 'none' })
    vault.addCredential({ slug: 'up', kind: 'http', connector: { host: '127.0.0.1:' + port, scheme: 'https' }, fields: { token: ${JSON.stringify(SECRET)} }, sites: { token: ['header:authorization:Bearer'] } })
    const cred = vault.findCredential('up')
    if (pin !== 'none') vault.setPins('up', '127.0.0.1', [pin])
    const { session, token } = vault.createSession({ label: 'child' })
    const grant = vault.createGrant({ sessionId: session.id, credentialId: cred.id, fields: ['token'], policy: { hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 10 }, approval: 'auto' } })
    const { placeholder } = vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
    const r = await new Pipeline(vault, { allowedHosts: new Set(['localhost']) }).handle({ method: 'GET', path: '/p/up/x', query: '', headers: [['host', 'localhost'], ['av-session', token], ['authorization', 'Bearer ' + placeholder]], body: null })
    const record = vault.audit.read({ limit: 1000 }).find((x) => x.kind === 'request.pin_mismatch') ?? null
    const uses = Object.values(vault.db.placeholders).find((x) => x.grant_id === grant.id).uses
    out.push({ pin, status: r.status, body: Buffer.from(r.body ?? '').toString(), presented: record?.presented_spki ?? null, uses })
  } finally { rmSync(dir, { recursive: true, force: true }) }
}
console.log(JSON.stringify(out))
`)
  const stdout = await new Promise((resolve, reject) => execFile(process.execPath, [script, String(up.port), certs.chain.intPin, WRONG, certs.chain.leafPin, 'none'], {
    env: { ...process.env, NODE_EXTRA_CA_CERTS: certs.root }, timeout: 30_000,
  }, (err, out, errText) => (err ? reject(new Error(`${err.message}\n${errText}`)) : resolve(out))))
  const [intermediate, wrong, leaf, none] = JSON.parse(stdout.trim().split('\n').at(-1))
  assert.equal(intermediate.status, 200, intermediate.body)
  const p = JSON.parse(wrong.body)
  assert.equal(p.code, 'AV_PIN_MISMATCH')
  assert.equal(p.rule, 'spki_pin')
  assert.equal(p.refunded, true)
  assert.equal(wrong.uses, 0)
  // Recorded with the keys the upstream presented: the leaf, then the intermediate.
  assert.deepEqual(wrong.presented?.slice(0, 2), [certs.chain.leafPin, certs.chain.intPin])
  assert.equal(intermediate.presented, null)
  assert.equal(leaf.status, 200, leaf.body)
  assert.equal(none.status, 200, none.body)
  // Three delivered (intermediate, leaf, no pins); the wrong pin sent nothing.
  assert.equal(up.seen.length, 3)
  for (const s of up.seen) assert.equal(s.headers.authorization, `Bearer ${SECRET}`)
})

test('the same chain with an intermediate pin is refused, unsent, when the daemon does not trust its root', async (t) => {
  // C7: a pin on a non-leaf adds to CA verification, never replaces it.
  const up = await upstream(t, { tls: { key: certs.chain.key, cert: certs.chain.cert } })
  const g = gateway(t, up.port)
  g.vault.setPins('up', '127.0.0.1', [certs.chain.intPin])
  const res = await g.pipeline.handle(g.req())
  assert.notEqual(res.status, 200)
  assert.equal(up.seen.length, 0)
})

test("the agent's Host header never reaches the connector; a Host that did would be refused unsent (C9)", async (t) => {
  const up = await upstream(t)
  const g = gateway(t, up.port, { scheme: 'http' })
  // Any spelling, any number of them: the upstream sees the URL host only.
  const res = await g.pipeline.handle(g.req({ headers: [...g.req().headers, ['HOST', '127.0.0.1'], ['Host', 'localhost']] }))
  assert.equal(res.status, 200, Buffer.from(res.body ?? '').toString())
  assert.equal(up.seen.length, 1)
  assert.equal(up.seen[0].headers.host, `127.0.0.1:${up.port}`)
  assert.equal(up.seen[0].raw.filter((v, i) => i % 2 === 0 && v.toLowerCase() === 'host').length, 1)
  // A pipeline that let another Host through would meet pinnedRequest's own
  // check: refused before a connection, reported as what it is, refunded.
  const uses = g.row().uses
  g.pipeline.upstream = (r) => pinnedRequest({ ...r, headers: { ...r.headers, Host: 'evil.example' } })
  const refused = await g.pipeline.handle(g.req())
  const p = problem(refused)
  assert.equal(refused.status, 403)
  assert.equal(p.code, 'AV_POLICY_DENIED')
  assert.equal(p.rule, 'host_mismatch')
  assert.equal(p.refunded, true)
  assert.equal(up.seen.length, 1, 'the evil Host reached the upstream')
  assert.equal(g.row().uses, uses)
})

test('a repeated list header goes out folded into one line, not refused as header_format', async (t) => {
  const up = await upstream(t)
  const g = gateway(t, up.port, { scheme: 'http' })
  const res = await g.pipeline.handle(g.req({ headers: [...g.req().headers, ['x-list', 'a'], ['x-list', 'b']] }))
  assert.equal(res.status, 200, Buffer.from(res.body ?? '').toString())
  assert.equal(up.seen[0].headers['x-list'], 'a, b')
})

test('a malformed pin table on a credential is pinned, not unpinned: refused before a connection', async (t) => {
  const up = await upstream(t, { tls: { key: certs.self.key, cert: certs.self.cert } })
  const g = gateway(t, up.port)
  for (const pins of ['x', ['a'], { '127.0.0.1': 'x' }, { '127.0.0.1': ['nope'] }]) {
    g.cred.pins = pins
    const res = await g.pipeline.handle(g.req())
    assert.equal(problem(res).code, 'AV_PIN_MISMATCH', JSON.stringify(pins))
  }
  assert.equal(up.seen.length, 0)
})

test('the connectors health reader and the store record what a response says (F10)', async (t) => {
  // A github credential can only reach GitHub's hosts, so the response is a
  // stand-in; the header reader and the store are the real ones.
  const g = gateway(t, 0, {
    kind: 'github', host: 'api.github.com',
    fetchImpl: async () => ({ status: 401, headers: { 'content-type': 'application/json', 'github-authentication-token-expiration': '2027-01-31 00:00:00 UTC' }, body: Buffer.from('{}') }),
  })
  const res = await g.pipeline.handle(g.req())
  assert.equal(res.status, 401)
  const health = g.vault.findCredential('up').health
  assert.equal(health.status, 'unauthorized')
  assert.equal(health.http_status, 401)
  assert.equal(health.observed_expires_at, '2027-01-31T00:00:00.000Z')
  assert.equal(health.source, 'response')
  assert.equal(g.vault.listCredentials()[0].health.status, 'unauthorized')
})

// ----------------------------------------------- gateway + store (slice A)

test('an expired grant is refused before anything is sent, and stays expired, not missing (F18)', async (t) => {
  const up = await upstream(t)
  const g = gateway(t, up.port, { scheme: 'http' })
  // A short-lived grant beside the fixture's, through the store's own ttl.
  const short = g.vault.createGrant({ sessionId: g.session.id, credentialId: g.cred.id, fields: ['token'], ttlMs: 60_000, policy: { hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 10 }, approval: 'auto' } })
  g.vault.revokeGrant(g.grant.id)
  const { placeholder } = g.vault.issuePlaceholder({ grantId: short.id, field: 'token' })
  const req = g.req({ headers: [['host', 'localhost'], ['av-session', g.token], ['authorization', `Bearer ${placeholder}`]] })
  const real = Date.now
  Date.now = () => real() + 2 * 60_000
  try {
    for (let i = 0; i < 2; i++) {
      const res = await g.pipeline.handle(req)
      assert.equal(problem(res).code, 'AV_GRANT_EXPIRED', `attempt ${i + 1}`)
    }
  } finally { Date.now = real }
  assert.equal(up.seen.length, 0)
  assert.equal(g.vault.db.grants[short.id].state, 'expired')
})

test('each redirect hop is charged to the grant by the store, and the hop past the budget is not followed (F6)', async (t) => {
  const up = await upstream(t, { respond: (req, res) => { res.writeHead(302, { location: '/next' }); res.end() } })
  const g = gateway(t, up.port, { scheme: 'http', policy: { budget: { unit: 'requests', limit: 2 }, redirects: { max: 5 } } })
  const res = await g.pipeline.handle(g.req())
  assert.equal(res.status, 302)
  assert.equal(res.headers['av-redirect-stopped'], 'budget')
  assert.equal(up.seen.length, 2, 'one request and one charged hop')
  assert.equal(g.grant.budget_used, 2)
})

test('a grant layer with no limit is bounded by the session layer, and its hops are charged (C4, one reader)', async (t) => {
  const up = await upstream(t, { respond: (req, res) => { res.writeHead(302, { location: '/next' }); res.end() } })
  const g = gateway(t, up.port, { scheme: 'http', policy: { budget: { unit: 'requests' }, redirects: { max: 5 } }, session: { policy: { budget: { unit: 'requests', limit: 3 } } } })
  const res = await g.pipeline.handle(g.req())
  assert.equal(res.headers['av-redirect-stopped'], 'budget')
  // Before the shared reader, chargeGrant called this budget unreadable and
  // the first hop stopped: one request reached the upstream, not three.
  assert.equal(up.seen.length, 3)
  assert.equal(g.grant.budget_used, 3)
})

test('a credential the store quarantined is refused before any send, and a tripwire quarantines through the store (F16)', async (t) => {
  const up = await upstream(t)
  const g = gateway(t, up.port, { scheme: 'http' })
  g.vault.setQuarantine('up', { by: 'control', reason: 'leaked' })
  const refused = await g.pipeline.handle(g.req())
  assert.equal(problem(refused).code, 'AV_QUARANTINED')
  assert.equal(problem(refused).rule, 'quarantine')
  assert.equal(up.seen.length, 0)
  assert.equal(g.row().uses, 0)
  g.vault.clearQuarantine('up')
  assert.equal((await g.pipeline.handle(g.req())).status, 200)

  // The store's settings switch the tripwire on; its action is the store's setQuarantine.
  g.vault.updateSettings({ tripwires: { enabled: true, rules: [{ id: 'methods', codes: ['AV_POLICY_DENIED'], threshold: 2, window_s: 60, action: 'quarantine_credential' }] } })
  for (let i = 0; i < 2; i++) assert.equal(problem(await g.pipeline.handle(g.req({ method: 'DELETE' }))).code, 'AV_POLICY_DENIED')
  const q = g.vault.findCredential('up').quarantine
  assert.equal(q.by, 'tripwire')
  assert.equal(q.rule_id, 'methods')
  assert.equal(problem(await g.pipeline.handle(g.req())).code, 'AV_QUARANTINED')
  assert.equal(up.seen.length, 1)
})

test('preflight and the real route agree, read with the store itself, on finite, expired, infinite and legacy sessions', async (t) => {
  const up = await upstream(t)
  for (const [name, setup, expected] of [
    ['finite', () => ({}), 'allow'],
    ['infinite', () => ({ session: { infinite: true, ttlMs: null } }), 'allow'],
    ['expired', () => ({ session: { ttlMs: 60_000 } }), 'AV_SESSION_EXPIRED'],
    ['legacy', () => ({}), 'AV_SESSION_EXPIRED'],
  ]) {
    const g = gateway(t, up.port, { scheme: 'http', ...setup() })
    if (name === 'infinite') assert.equal(g.session.infinite, true)
    if (name === 'legacy') { delete g.session.infinite; g.session.expires_at = null }
    const shift = name === 'expired' ? 2 * 60_000 : 0
    const real = Date.now
    Date.now = () => real() + shift
    try {
      let pre
      try { pre = (await g.pipeline.preflight(g.req())).would } catch (e) { pre = e.code }
      const res = await g.pipeline.handle(g.req())
      assert.equal(pre, expected, `${name}: preflight`)
      assert.equal(res.status === 200 ? 'allow' : problem(res).code, expected, `${name}: the real route`)
    } finally { Date.now = real }
  }
})

// ------------------------------------------------- gateway + store (F4, C5)

test('a scrub pattern the store saves is applied by the gateway, and one the grammar refuses is never saved', async (t) => {
  const up = await upstream(t, { respond: (req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('before acme_QWERTYUI after') } })
  const g = gateway(t, up.port, { scheme: 'http' })
  for (const source of ['acme_[A-Z]+', 'acme_.*', 'acme_[A-Z]{1,}', 'abc[^Q]{0,250}[^Q]{250}Q']) {
    assert.throws(() => g.vault.addScrubPattern('up', source), (e) => e.rule === 'scrub_pattern', source)
  }
  assert.equal(g.vault.findCredential('up').scrub_patterns, undefined)
  // With nothing stored, the token goes back unscrubbed: the pattern is the protection.
  assert.ok(Buffer.from((await g.pipeline.handle(g.req())).body).toString().includes('acme_QWERTYUI'))
  g.vault.addScrubPattern('up', 'acme_[A-Z]{8}')
  const res = await g.pipeline.handle(g.req())
  assert.equal(res.status, 200)
  const text = Buffer.from(res.body).toString()
  assert.ok(!text.includes('acme_QWERTYUI'), text)
  assert.ok(text.startsWith('before ') && text.endsWith(' after'), text)
})

// ------------------------------------------------ C11, C1, C12

test('a held request is recorded as held, and the store report counts it as held, not as a use (C11)', async (t) => {
  const up = await upstream(t)
  const g = gateway(t, up.port, { scheme: 'http', policy: { approval: 'each' } })
  const held = await g.pipeline.handle(g.req())
  assert.equal(held.status, 202)
  assert.equal(up.seen.length, 0)
  const rows = g.vault.audit.read({ limit: 1000 })
  assert.deepEqual(rows.filter((r) => r.kind === 'request.allowed').map((r) => r.decision), ['held'])
  const summary = summarizeSession(rows, { session: g.session, grants: Object.values(g.vault.db.grants) })
  assert.equal(summary.requests.held, 1)
  assert.equal(summary.requests.allowed, 0)
})

test('panic with the hook unwired reports session_requests_denied: null and leaves session requests pending (C1)', async () => {
  const d = await startDaemon()
  try {
    const asked = await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET'], reason: 'integrate-2 seam' })
    assert.equal(asked.status, 200, JSON.stringify(asked.body))
    assert.equal(d.daemon.pipeline.onPanic, null)
    // The hook answers { session_requests_denied }; the panic reports it as
    // denied_session_requests (F16's route shape), null while unwired.
    const result = await d.daemon.pipeline.panic({ reason: null, lock: false })
    assert.equal(result.denied_session_requests, null)
    assert.equal(d.vault.audit.read({ limit: 1000 }).find((r) => r.kind === 'panic.triggered').denied_session_requests, null)
    const pending = await d.control('GET', '/v1/session-requests')
    assert.ok(JSON.stringify(pending.body).includes('integrate-2 seam'), JSON.stringify(pending.body))
  } finally { await d.stop() }
})

const LOOPBACK = { id: 'local', kind: 'tcp', remote: false, advertise: [] }
const REMOTE = { id: 'lan', kind: 'tls', remote: true, advertise: [] }

test('an infinite session is refused on a network listener, with nothing sent and the refusal recorded (C12)', async (t) => {
  const up = await upstream(t)
  const g = gateway(t, up.port, { scheme: 'http', session: { infinite: true, ttlMs: null } })
  assert.equal(g.session.infinite, true)
  const touched = g.session.last_used_at
  for (const headers of [
    [['host', 'localhost'], ['av-session', g.token], ['authorization', `Bearer ${g.placeholder}`]],
    [['host', 'localhost'], ['authorization', `Bearer ${g.token}`]],
  ]) {
    const res = await g.pipeline.handle(g.req({ headers, listener: REMOTE }))
    assert.equal(res.status, 403)
    assert.equal(problem(res).code, 'AV_REMOTE_FORBIDDEN')
    assert.equal(problem(res).rule, 'infinite_remote')
  }
  assert.equal(up.seen.length, 0)
  assert.equal(g.row().uses, 0)
  assert.equal(g.session.last_used_at, touched, 'a refused remote use kept the session alive')
  const records = g.vault.audit.read({ limit: 1000 }).filter((r) => r.rule === 'infinite_remote' || r.reason_code === 'infinite_remote' || JSON.stringify(r).includes('infinite_remote'))
  assert.equal(records.length, 2, 'each refusal is audited')
  // Its placeholder alone is not a remote carrier either.
  const bare = await g.pipeline.handle(g.req({ headers: [['host', 'localhost'], ['authorization', `Bearer ${g.placeholder}`]], listener: REMOTE }))
  assert.equal(bare.status, 401)
  assert.equal(up.seen.length, 0)
  // Preflight answers the same.
  await assert.rejects(g.pipeline.preflight(g.req({ listener: REMOTE })), (e) => e.rule === 'infinite_remote')
  // On loopback the same session works.
  assert.equal((await g.pipeline.handle(g.req({ listener: LOOPBACK }))).status, 200)
  assert.equal((await g.pipeline.handle(g.req())).status, 200)
  assert.equal(up.seen.length, 2)
})

test('a finite session on a network listener is unchanged by C12', async (t) => {
  const up = await upstream(t)
  const g = gateway(t, up.port, { scheme: 'http' })
  const res = await g.pipeline.handle(g.req({ listener: REMOTE }))
  assert.equal(res.status, 200, Buffer.from(res.body ?? '').toString())
  assert.equal(up.seen.length, 1)
  assert.equal(up.seen[0].headers.authorization, `Bearer ${SECRET}`)
})
