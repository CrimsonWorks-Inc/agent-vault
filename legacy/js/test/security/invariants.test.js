// The whole system, driven randomly, checked against the promises on the tin.
//
// Every other file in test/security/ checks one thing someone thought of. This
// one checks the four claims the README actually makes, against sequences
// nobody chose: a real daemon, a real gateway, a real upstream that echoes
// whatever it is given, and a few thousand requests assembled at random from
// the shapes an agent can produce — right ones, wrong ones, encoded ones,
// misdirected ones, expired ones.
//
// The claims:
//   1. A credential value never reaches the agent, in any response, in any
//      encoding.
//   2. A credential value never reaches the audit log.
//   3. A credential only ever reaches a host the grant allows.
//   4. A placeholder is never spent more times than it has uses.
//   5. The audit chain verifies afterwards.
//
// Nothing here is a scenario. If a sequence breaks one of these, the seed
// reproduces it exactly, and the failure is a real one by construction: these
// five are what the product is.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as httpRequest, createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

// Distinct shapes, so a leak names which credential leaked rather than just
// "something did". The first is the one the grant covers; the others are
// bystanders that must never appear either — an upstream echoing one of those
// is how a vault leaks a credential the request never involved.
const SECRETS = {
  granted: 'ghp_INVARIANTGRANTED00112233445566778899',
  bystander: 'xoxb-9999-INVARIANTBYSTANDERVALUE00',
  accented: 'contraseña-INVARIANT-über-0123456789',
}

let dir, vault, daemon, upstream, upPort, session, token, placeholder, oneShot
/** Everything the fake upstream was ever sent, and where. */
let wire

function rng(seed) {
  let s = seed
  return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
}

const gw = (path, headers, method = 'GET', body = null) => new Promise((resolve) => {
  const req = httpRequest({ host: '127.0.0.1', port: daemon.gatewayPort, path, method, headers }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(c).toString('latin1') }))
  })
  req.on('error', (e) => resolve({ status: 0, text: String(e.message) }))
  req.end(body)
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-inv-'))

  // An upstream that echoes the entire request back. This is the hostile
  // upstream from the threat model: whatever reached it, it hands straight
  // back, so anything the proxy sent is offered to the agent on the way out.
  upstream = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('latin1')
      wire.push({ url: req.url, headers: { ...req.headers }, body })
      const echo = JSON.stringify({ url: req.url, headers: req.headers, body })
      res.writeHead(200, { 'content-type': 'application/json' })
      // Echoed several ways at once, because one of them is usually the one
      // that slips: raw, base64, and percent-encoded.
      res.end(`${echo}\n${Buffer.from(echo, 'latin1').toString('base64')}\n${encodeURIComponent(echo)}`)
    })
  })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  upPort = upstream.address().port

  vault = Vault.create(dir, { factor: 'none' })
  const cred = vault.addCredential({
    slug: 'prod', kind: 'http',
    connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
    fields: { token: SECRETS.granted },
    sites: { token: ['header:authorization:Bearer'] },
  })
  vault.addCredential({
    slug: 'other', kind: 'http', connector: { host: 'slack.test', scheme: 'https' },
    fields: { token: SECRETS.bystander }, sites: { token: ['header:authorization:Bearer'] },
  })
  vault.addCredential({
    slug: 'accented', kind: 'http', connector: { host: 'example.test', scheme: 'https' },
    fields: { password: SECRETS.accented }, sites: { password: ['basic:pass'] },
  })

  const made = vault.createSession({ label: 'agent' })
  session = made.session
  token = made.token
  const grant = vault.createGrant({
    sessionId: session.id, credentialId: cred.id, fields: ['token'],
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/allowed/**'],
      budget: { unit: 'requests', limit: 100000 }, approval: 'auto',
    },
  })
  placeholder = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder
  oneShot = vault.issuePlaceholder({ grantId: grant.id, field: 'token', uses: 3 })

  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'c.sock') }).start()
  wire = []
})

after(async () => {
  if (daemon) await daemon.stop()
  if (upstream) await new Promise((r) => upstream.close(r))
  rmSync(dir, { recursive: true, force: true })
})

/** Every way an agent might carry, mangle or misplace a placeholder. */
function requestFor(rnd, p) {
  const pick = (a) => a[Math.floor(rnd() * a.length)]
  // Single-line encodings only for anything that goes in a header, a query or
  // a path: Node's HTTP client refuses a header value containing a newline, so
  // a wrapped form there never reaches the daemon at all and would only be
  // testing the client.
  const INLINE = [
    (t) => t,
    (t) => encodeURIComponent(t),
    (t) => Buffer.from(t, 'utf8').toString('base64'),
    (t) => [...t].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
  ]
  // Bodies can carry anything, including the wrapped base64 that hid a
  // placeholder from the detector entirely.
  const WRAPPED = [
    ...INLINE,
    (t) => Buffer.from(t, 'utf8').toString('base64').replace(/(.{64})/g, '$1\n'),
    (t) => Buffer.from(t, 'utf8').toString('base64').replace(/(.{76})/g, '$1\r\n'),
  ]
  const carried = pick(INLINE)(p)
  const inBody = pick(WRAPPED)(p)
  const auth = { authorization: `Bearer ${p}`, 'av-session': token }

  return pick([
    // The legitimate shape.
    () => [pick(['/p/prod/allowed/a', '/p/prod/allowed/b/c', '/p/prod/allowed/deep/er/still']), auth, 'GET', null],
    // Placeholder somewhere that is not a site.
    () => [`/p/prod/allowed/${carried}`, auth, 'GET', null],
    () => ['/p/prod/allowed/a', { ...auth, 'x-note': carried }, 'GET', null],
    () => ['/p/prod/allowed/a', { ...auth, [`x-${p.replace(/[^A-Za-z0-9-]/g, '-')}`]: '1' }, 'GET', null],
    () => [`/p/prod/allowed/a?${carried}=1`, auth, 'GET', null],
    () => [`/p/prod/allowed/a?note=${carried}`, auth, 'GET', null],
    () => ['/p/prod/allowed/a', { ...auth, 'content-type': 'application/json' }, 'POST',
      JSON.stringify({ note: inBody })],
    () => ['/p/prod/allowed/a', { ...auth, 'content-type': 'application/json' }, 'POST',
      `{"k":${JSON.stringify(inBody)},"k":"harmless"}`],
    () => ['/p/prod/allowed/a', { ...auth, 'content-type': 'application/json' }, 'POST',
      JSON.stringify({ [inBody]: 'v' })],
    () => ['/p/prod/allowed/a', { ...auth, 'content-type': 'application/x-www-form-urlencoded' }, 'POST',
      `f=${encodeURIComponent(inBody)}`],
    () => ['/p/prod/allowed/a', { ...auth, 'content-type': 'text/plain' }, 'POST', `here: ${inBody}`],
    // Wrong destination, wrong method, wrong path, no session.
    () => ['/p/prod/forbidden/a', auth, 'GET', null],
    () => ['/p/prod/allowed/a', auth, 'DELETE', null],
    () => [`/t/http/127.0.0.1:${upPort}/allowed/a`, auth, 'GET', null],
    () => ['/p/other/allowed/a', auth, 'GET', null],
    () => ['/p/prod/allowed/a', { authorization: `Bearer ${p}` }, 'GET', null],
    () => ['/p/prod/allowed/a', { ...auth, authorization: 'Bearer av1.notreal.x_y.aaaaaaaaaaaaaaaaaaaaaaaaaa.zzzzzz' }, 'GET', null],
  ])()
}

test('across thousands of random requests, no credential ever reaches the agent', async () => {
  // Several seeds, because one sequence passing is one sequence. A failure
  // names its seed and case, and both are deterministic.
  let allowed = 0
  for (const seed of [20260921, 7, 31337, 999983]) {
  const rnd = rng(seed)
  for (let i = 0; i < 600; i++) {
    const p = rnd() < 0.15 ? oneShot.placeholder : placeholder
    const [path, headers, method, body] = requestFor(rnd, p)
    const res = await gw(path, headers, method, body)
    if (res.status === 200) allowed++

    // The response, as the agent reads it, in the two ways it might read it.
    const asLatin1 = res.text
    const asUtf8 = Buffer.from(res.text, 'latin1').toString('utf8')
    for (const [name, secret] of Object.entries(SECRETS)) {
      assert.ok(!asLatin1.includes(secret), `seed ${seed} case ${i} (${method} ${path.slice(0, 60)}): ${name} reached the agent`)
      assert.ok(!asUtf8.includes(secret), `seed ${seed} case ${i}: ${name} reached the agent as UTF-8`)
    }
    // And the placeholder must never be forwarded: it is a bearer capability.
    // Whatever reached the upstream is in `wire`, checked below in full.
  }
  }
  assert.ok(allowed > 50, `only ${allowed} of 2400 requests were allowed; the fixture is not exercising the happy path`)
})

test('the granted credential reached only the host its grant allows, and nothing else did', () => {
  assert.ok(wire.length > 0, 'nothing reached the upstream at all')
  for (const [n, sent] of wire.entries()) {
    const all = `${sent.url}\n${JSON.stringify(sent.headers)}\n${sent.body}`
    // The one credential this grant covers is the only one that may appear,
    // and only in its declared site.
    assert.ok(!all.includes(SECRETS.bystander), `request ${n}: a bystander credential was sent upstream`)
    assert.ok(!all.includes(SECRETS.accented), `request ${n}: a bystander credential was sent upstream`)
    if (all.includes(SECRETS.granted)) {
      assert.equal(sent.headers.authorization, `Bearer ${SECRETS.granted}`,
        `request ${n}: the secret was sent somewhere other than its declared site`)
    }
  }
})

test('no placeholder and no session token was ever forwarded upstream', () => {
  // Both are capabilities for THIS daemon and mean nothing to an upstream, so
  // sending either hands a third party something it can spend.
  for (const [n, sent] of wire.entries()) {
    const all = `${sent.url}\n${JSON.stringify(sent.headers)}\n${sent.body}`
    assert.ok(!all.includes(placeholder), `request ${n}: a placeholder was forwarded upstream`)
    assert.ok(!all.includes(oneShot.placeholder), `request ${n}: a placeholder was forwarded upstream`)
    assert.ok(!all.includes(token), `request ${n}: the session token was forwarded upstream`)
  }
})

test('a placeholder was never spent more times than it had uses', () => {
  // The ledger is the only thing that authorises an injection, so a
  // three-use placeholder must produce at most three upstream requests
  // however many times, and in whatever shapes, it was presented.
  const row = vault.db.placeholders[oneShot.row.id]
  assert.ok(row, 'the limited placeholder is gone from the ledger')
  assert.ok(row.uses <= row.max_uses, `spent ${row.uses} of ${row.max_uses}`)
  assert.equal(row.max_uses, 3)
  if (row.uses >= row.max_uses) {
    assert.equal(row.state, 'dead', 'an exhausted placeholder must not stay active')
  }
})

test('nothing sensitive reached the audit log, and its chain still verifies', () => {
  const raw = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
  for (const [name, secret] of Object.entries(SECRETS)) {
    assert.ok(!raw.includes(secret), `${name} is in the audit log`)
  }
  assert.ok(!raw.includes(placeholder), 'a full placeholder is in the audit log')
  assert.ok(!raw.includes(oneShot.placeholder), 'a full placeholder is in the audit log')
  assert.ok(!raw.includes(token), 'a session token is in the audit log')

  const v = vault.audit.verify()
  assert.equal(v.ok, true, `the chain did not verify after ${v.count} records: ${v.reason}`)
  assert.ok(v.count > 1000, `expected a busy log, got ${v.count}`)
})
