// Network listeners, and the TLS one the MCP connector needs.
//
// Until now listeners were recorded and validated but never bound, which also
// meant `req.listener` was always undefined and every remote rule in the
// pipeline was unreachable. These tests bind real ones.
//
// The certificate exists for an unglamorous reason: Claude Desktop and Claude
// Code refuse an MCP connector URL that is not https, with no exemption for
// loopback. So a vault that only ever talks to its own machine still needs
// one, and it has to be a certificate the client will actually accept.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, existsSync, statSync, chmodSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest } from 'node:http'
import { request as tlsRequest } from 'node:https'
import { execFileSync } from 'node:child_process'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { parseAddress, isLoopbackHost } from '../../src/daemon/server.js'
import { ensureCertificate, tlsPaths } from '../../src/daemon/tls.js'

let dir, vault, sock

let nextSock = 0
/** A daemon on its own socket, so tests cannot race on a stale one. */
async function daemonOnFreshSocket() {
  sock = join(dir, `c${nextSock++}.sock`)
  return new Daemon(vault, { port: 0, socketPath: sock }).start()
}

const control = (method, path, body) => new Promise((resolve, reject) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const chunks = []
    res.on('data', (c) => chunks.push(c))
    res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') }))
  })
  req.on('error', reject)
  req.end(body ? JSON.stringify(body) : undefined)
})

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'av-listen-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'ghp_LISTENTEST00112233445566778899' }, sites: { token: ['header:authorization:Bearer'] },
  })
})

after(() => rmSync(dir, { recursive: true, force: true }))

// ------------------------------------------------------------------ parsing

test('addresses parse, and nonsense is refused rather than half-bound', () => {
  assert.deepEqual(parseAddress('127.0.0.1:7443'), { host: '127.0.0.1', port: 7443 })
  assert.deepEqual(parseAddress('[::1]:7443'), { host: '::1', port: 7443 })
  assert.deepEqual(parseAddress('0.0.0.0:0'), { host: '0.0.0.0', port: 0 })
  assert.throws(() => parseAddress('127.0.0.1'), /<host>:<port>/)
  assert.throws(() => parseAddress('127.0.0.1:99999'), /bad port/)
})

test('loopback is recognised in every form it arrives in', () => {
  for (const h of ['127.0.0.1', '127.0.0.53', '::1', 'localhost']) {
    assert.equal(isLoopbackHost(h), true, h)
  }
  for (const h of ['0.0.0.0', '10.0.0.5', 'example.com']) {
    assert.equal(isLoopbackHost(h), false, h)
  }
})

// ------------------------------------------------------------- certificate

test('the certificate covers both names a client may use to reach loopback', () => {
  const info = ensureCertificate(dir)
  assert.equal(info.created, true)
  assert.ok(info.pem.startsWith('-----BEGIN CERTIFICATE-----'))
  assert.match(info.fingerprint, /^[0-9A-F]{2}(:[0-9A-F]{2})+$/)

  const text = execFileSync('openssl', ['x509', '-in', info.cert, '-noout', '-text'], { encoding: 'utf8' })
  assert.match(text, /DNS:localhost/)
  assert.match(text, /IP Address:127\.0\.0\.1/)
  // Its own CA, so the same file works as the client's trust anchor.
  assert.match(text, /CA:TRUE/)
})

test('the private key is not readable by anyone else', () => {
  // The whole design rests on the agent's account not reaching key material.
  // A world-readable TLS key would let anything on the box impersonate the vault.
  const p = tlsPaths(dir)
  assert.equal(statSync(p.key).mode & 0o077, 0)
})

test('generating twice reuses the certificate rather than churning it', () => {
  const first = ensureCertificate(dir)
  const second = ensureCertificate(dir)
  assert.equal(second.created, false)
  assert.equal(second.fingerprint, first.fingerprint)
})

test('a key that became readable is refused, not loaded anyway', async () => {
  const p = tlsPaths(dir)
  const before = statSync(p.key).mode & 0o777
  chmodSync(p.key, 0o644)
  try {
    const d = new Daemon(vault, { port: 0, socketPath: join(dir, 'x.sock') })
    await assert.rejects(
      () => d.bindListener({ id: 'bad', address: '127.0.0.1:0', surfaces: ['mcp'], tls: { managed: true } }),
      /must not be readable/,
    )
  } finally { chmodSync(p.key, before) }
})

// ---------------------------------------------------------------- binding

test('a TLS listener binds and serves only the surface it declares', async () => {
  const daemon = await daemonOnFreshSocket()
  try {
    const added = await control('POST', '/v1/listeners', {
      id: 'mcp-tls', address: '127.0.0.1:0', surfaces: ['mcp'], tls: { managed: true },
    })
    assert.equal(added.status, 200)

    // Restart so the new listener is bound.
    await daemon.stop()
    const d2 = await daemonOnFreshSocket()
    try {
      const bound = d2.listeners.find((l) => l.id === 'mcp-tls')
      assert.ok(bound, 'the listener should have bound')
      assert.equal(bound.tls, true)

      const ca = readFileSync(tlsPaths(dir).cert)
      const get = (path, opts) => https(bound.port, path, ca, opts)

      // The declared surface answers, over TLS, with the certificate trusted
      // only because we handed the client this exact PEM.
      const mcp = await get('/mcp', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      })
      assert.ok(mcp.status < 500, `mcp answered ${mcp.status}: ${mcp.text.slice(0, 120)}`)

      // The one it does not declare is not reachable here, whatever the URL says.
      const proxy = await get('/p/demo/user')
      assert.equal(proxy.status, 404)
      assert.match(JSON.parse(proxy.text).detail, /does not serve the gateway surface/)

      // And an untrusting client refuses it, which is what proves the trust
      // above came from the CA rather than from nothing being checked.
      await assert.rejects(() => https(bound.port, '/mcp', undefined, { method: 'POST' }),
        /self.signed|DEPTH_ZERO/i)
    } finally { await d2.stop() }
  } finally {
    await control('DELETE', '/v1/listeners?id=mcp-tls').catch(() => {})
  }
})

test('an address with no port is refused when it is added, not at the next restart', async () => {
  // This one was found the hard way: `listen add mcp-tls --address 127.0.0.1`
  // was accepted and reported success, and the only symptom was a surface that
  // silently never appeared after the next restart.
  const daemon = await daemonOnFreshSocket()
  try {
    const res = await control('POST', '/v1/listeners', { id: 'noport', address: '127.0.0.1', surfaces: ['mcp'] })
    assert.ok(res.status >= 400, `answered ${res.status}`)
    assert.match(res.body.detail, /<host>:<port>/)
    assert.match(res.body.hint, /127\.0\.0\.1:7443/)

    const listed = await control('GET', '/v1/listeners')
    assert.ok(!listed.body.some((l) => l.id === 'noport'), 'nothing should have been stored')
  } finally { await daemon.stop() }
})

test('a network listener with no TLS is refused at add time too', async () => {
  const daemon = await daemonOnFreshSocket()
  try {
    const res = await control('POST', '/v1/listeners', { id: 'lan', address: '10.0.0.5:7443', surfaces: ['mcp'] })
    assert.equal(res.status, 403)
    assert.equal(res.body.code, 'AV_REMOTE_FORBIDDEN')
    assert.match(res.body.hint, /--tls managed/)
  } finally { await daemon.stop() }
})

test('a listener on a network address without TLS is refused', async () => {
  // Plaintext off loopback would put session tokens and substituted
  // credentials on the wire.
  const d = new Daemon(vault, { port: 0, socketPath: join(dir, 'y.sock') })
  await assert.rejects(
    () => d.bindListener({ id: 'lan', address: '0.0.0.0:0', surfaces: ['mcp'] }),
    /must configure TLS/,
  )
})

/** One TLS request, trusting only the CA passed in. */
function https(port, path, ca, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = tlsRequest(
      { host: 'localhost', port, path, method, headers, ...(ca ? { ca } : {}) },
      (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }))
      },
    )
    req.on('error', reject)
    req.end(body)
  })
}

test('the listener a request arrived on reaches the pipeline at all', async () => {
  // #bindListener set `req.listener` on the Node request; #onGateway then
  // built a fresh object for pipeline.handle() without it, so the field was
  // dropped one call later and was `undefined` for the pipeline's whole life.
  //
  // Three things depended on it and none of them had ever run: the rule
  // refusing a bare placeholder as a carrier on a network listener, a
  // listener's `advertise` host list, and the peer recorded in the audit log
  // — which said `loopback`/`local` for every request ever made, including any
  // that crossed a network.
  //
  // A loopback TLS listener is enough to see it: `peer.kind` must name the
  // listener the request actually came in on.
  const daemon = await daemonOnFreshSocket()
  try {
    const added = await control('POST', '/v1/listeners', {
      id: 'peer-test', address: '127.0.0.1:0', surfaces: ['gateway'], tls: { managed: true },
    })
    assert.equal(added.status, 200)
    await daemon.stop()

    const d2 = await daemonOnFreshSocket()
    try {
      const bound = d2.listeners.find((l) => l.id === 'peer-test')
      assert.ok(bound, 'the listener should have bound')
      const before = vault.audit.read({ limit: 500 }).length

      const ca = readFileSync(tlsPaths(dir).cert)
      await https(bound.port, '/p/nope/whatever', ca, { headers: { host: '127.0.0.1' } })

      const fresh = vault.audit.read({ limit: 500 }).slice(before)
      const record = fresh.find((r) => r.peer)
      assert.ok(record, 'the request produced no audited record at all')
      assert.equal(record.peer.listener_id, 'peer-test',
        'the audit log did not record which listener the request arrived on')
      assert.equal(record.peer.kind, 'tls',
        `peer.kind was "${record.peer.kind}": the listener never reached the pipeline`)
    } finally { await d2.stop() }
  } finally {
    await control('DELETE', '/v1/listeners?id=peer-test').catch(() => {})
  }
})
