// The serving rules. The whole security argument for binding a network
// address is that some surfaces can never cross the machine boundary, so these
// tests assert the refusals rather than the happy path.

import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault, isLoopbackSpec } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

let dir, vault

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'av-serving-'))
  vault = Vault.create(dir, { factor: 'none' })
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

test('a listener naming the control surface on a network address is refused outright', () => {
  assert.throws(
    () => vault.addListener({ id: 'bad', address: 'eth0:7411', surfaces: ['gateway', 'control'] }),
    (e) => e.code === 'AV_REMOTE_FORBIDDEN' && /control/.test(e.detail),
  )
  assert.equal(vault.listListeners().length, 0, 'the entry is not partially applied')
})

test('a listener naming the database surface on a network address is refused', () => {
  assert.throws(
    () => vault.addListener({ id: 'bad', address: '10.0.0.5:7411', surfaces: ['l4'] }),
    (e) => e.code === 'AV_REMOTE_FORBIDDEN',
  )
})

test('the refusal is audited so a misconfiguration is loud, not silent', () => {
  try { vault.addListener({ id: 'bad', address: 'tailscale0:7411', surfaces: ['control'] }) } catch { /* expected */ }
  const kinds = vault.audit.read({ limit: 20 }).map((r) => r.kind)
  assert.ok(kinds.includes('listen.refused'))
})

test('the same surfaces are allowed on a loopback or unix address', () => {
  const l = vault.addListener({ id: 'local-extra', address: 'unix:/tmp/av-extra.sock', surfaces: ['control', 'l4'] })
  assert.equal(l.id, 'local-extra')
})

test('gateway and mcp surfaces may be bound to a network address', () => {
  const l = vault.addListener({
    id: 'tailnet', address: 'tailscale0:7411', surfaces: ['gateway', 'mcp'],
    client_auth: 'bearer', allow_cidr: ['100.64.0.0/10'],
  })
  assert.deepEqual(l.surfaces, ['gateway', 'mcp'])
  // Says what it does. Mutual TLS is not implemented, and a listener that
  // recorded 'mtls-required' while accepting a bearer token was claiming a
  // protection it did not have.
  assert.equal(l.client_auth, 'bearer')
})

test('loopback detection covers the forms an operator actually types', () => {
  for (const ok of ['unix:/run/av.sock', '127.0.0.1:7411', '[::1]:7411', 'localhost:7411']) {
    assert.ok(isLoopbackSpec(ok), ok)
  }
  for (const notOk of ['0.0.0.0:7411', 'eth0:7411', '10.0.0.5:7411', 'tailscale0:7411']) {
    assert.ok(!isLoopbackSpec(notOk), notOk)
  }
})

test('removing a listener is allowed without ceremony: reducing reach is always safe', () => {
  vault.addListener({ id: 'tailnet', address: 'tailscale0:7411', surfaces: ['gateway'] })
  vault.removeListener('tailnet')
  assert.equal(vault.listListeners().length, 0)
  assert.ok(vault.audit.read({ limit: 10 }).some((r) => r.kind === 'listen.removed'))
})

test('the control socket is created with mode 0600 and no network address', async () => {
  const socketPath = join(dir, 'control.sock')
  const daemon = await new Daemon(vault, { port: 0, socketPath }).start()
  try {
    const mode = statSync(socketPath).mode & 0o777
    assert.equal(mode, 0o600, `control socket mode is 0${mode.toString(8)}`)
    // The gateway binds loopback only; the control API has no TCP listener at all.
    assert.equal(daemon.servers.length, 2)
    const gateway = daemon.servers[0].address()
    assert.equal(gateway.address, '127.0.0.1')
  } finally {
    await daemon.stop()
  }
})

test('the vault directory is 0700 so another local user cannot read it', () => {
  const mode = statSync(dir).mode & 0o777
  assert.equal(mode, 0o700)
})
