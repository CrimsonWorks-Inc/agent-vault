// What reaches the upstream, and what must not.
//
// The session token is a capability for this daemon and nothing else. It was
// being forwarded verbatim whenever the agent carried it the documented way —
// `Authorization: Bearer avs1...` — so every API the vault proxied for received
// a live vault capability and logged it. Found while making a real call to the
// Gemini API, which refused the request outright for carrying two credentials;
// a less strict upstream would simply have kept it.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

const SECRET = 'ghp_CARRIERTEST00112233445566778899aa'
let dir, vault, daemon, gatewayPort, upstream, upstreamPort, seen, token, placeholder

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-carrier-'))
  vault = Vault.create(dir, { factor: 'none' })

  seen = []
  upstream = createServer((req, res) => {
    seen.push(req.headers)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end('{"ok":true}')
  })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  upstreamPort = upstream.address().port

  const cred = vault.addCredential({
    slug: 'demo', kind: 'http',
    connector: { host: `127.0.0.1:${upstreamPort}`, scheme: 'http' },
    fields: { token: SECRET },
    // Deliberately not the Authorization header: that is where the session
    // token rides, and the two must not be confused for each other.
    sites: { token: ['header:x-api-key'] },
  })
  const made = vault.createSession({ label: 'carrier', policy: {} })
  token = made.token
  const grant = vault.createGrant({
    sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/**'],
      budget: { unit: 'requests', limit: 50 }, approval: 'auto',
    },
  })
  placeholder = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder

  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'c.sock') }).start()
  gatewayPort = daemon.gatewayPort
})

after(async () => {
  if (daemon) await daemon.stop()
  if (upstream) await new Promise((r) => upstream.close(r))
  rmSync(dir, { recursive: true, force: true })
})

const call = (headers) => fetch(`http://127.0.0.1:${gatewayPort}/p/demo/thing`, { headers })

test('the session token in Authorization never reaches the upstream', async () => {
  seen.length = 0
  const res = await call({ authorization: `Bearer ${token}`, 'x-api-key': placeholder })
  assert.equal(res.status, 200)
  assert.equal(seen.length, 1, 'the request should have been forwarded')

  const sent = JSON.stringify(seen[0])
  assert.ok(!sent.includes(token), 'the session token was forwarded upstream')
  assert.ok(!sent.includes('avs1.'), 'no session token in any shape')
  assert.equal(seen[0].authorization, undefined, 'the carrier header is consumed, like AV-Session')
})

test('the credential still arrives, at its own declared site', async () => {
  seen.length = 0
  await call({ authorization: `Bearer ${token}`, 'x-api-key': placeholder })
  assert.equal(seen[0]['x-api-key'], SECRET, 'substitution must still happen')
})

test('the AV-Session carrier behaves the same way', async () => {
  seen.length = 0
  const res = await call({ 'av-session': token, 'x-api-key': placeholder })
  assert.equal(res.status, 200)
  const sent = JSON.stringify(seen[0])
  assert.ok(!sent.includes(token))
  assert.equal(seen[0]['av-session'], undefined)
})

test('a session token smuggled into an unrelated header is dropped too', async () => {
  // Not an escalation on its own — the agent already holds its own token — but
  // there is no legitimate reason for one to leave the machine, and an agent
  // parking it in a side header is how it would reach a host it controls.
  seen.length = 0
  await call({ 'av-session': token, 'x-api-key': placeholder, 'x-note': `fyi ${token}` })
  const sent = JSON.stringify(seen[0])
  assert.ok(!sent.includes(token), 'a token in any header must not be forwarded')
  assert.equal(seen[0]['x-note'], undefined)
})

test('headers that carry no token are forwarded untouched', async () => {
  // The fix must not become a blunt instrument: ordinary headers still pass.
  seen.length = 0
  await call({ 'av-session': token, 'x-api-key': placeholder, 'x-trace': 'abc123', accept: 'application/json' })
  assert.equal(seen[0]['x-trace'], 'abc123')
  assert.equal(seen[0].accept, 'application/json')
})
