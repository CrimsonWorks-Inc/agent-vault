// The stdio bridge, and what it does when the session underneath it ends.
//
// A session lasts hours; an agent outlives it. The bridge used to read the
// token once at launch, so the moment the session expired it was dead until
// the whole client restarted — and the way you found out was a tool call
// failing with no useful explanation, hours after the fact.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

const CLI = new URL('../../bin/agent-vault.js', import.meta.url).pathname
let dir, vault, daemon, cred

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-br-'))
  vault = Vault.create(dir, { factor: 'none' })
  cred = vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'ghp_BRIDGETEST00112233445566778899' }, sites: { token: ['header:authorization:Bearer'] },
  })
  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'control.sock') }).start()
})

after(async () => {
  if (daemon) await daemon.stop()
  rmSync(dir, { recursive: true, force: true })
})

/** A session with a grant, plus the token written where the bridge looks. */
function newSession(label) {
  const { session, token } = vault.createSession({ label, policy: {} })
  vault.createGrant({
    sessionId: session.id, credentialId: cred.id, fields: ['token'],
    policy: { hosts: ['api.example.com'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 10 } },
  })
  writeFileSync(join(dir, 'cli-state.json'), JSON.stringify({ token, session_id: session.id }), { mode: 0o600 })
  return { session, token }
}

/** Drive the bridge over stdio and collect one response per request. */
function bridge() {
  const proc = spawn(process.execPath, [CLI, 'mcp'], {
    env: { ...process.env, AGENT_VAULT_DIR: dir, AGENT_VAULT_SESSION: '' },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const lines = []
  const waiters = []
  let buf = ''
  proc.stdout.setEncoding('utf8')
  proc.stdout.on('data', (c) => {
    buf += c
    let nl
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim()
      buf = buf.slice(nl + 1)
      if (!line) continue
      if (waiters.length) waiters.shift()(JSON.parse(line))
      else lines.push(JSON.parse(line))
    }
  })
  return {
    proc,
    send(obj) { proc.stdin.write(`${JSON.stringify(obj)}\n`) },
    next(ms = 5000) {
      if (lines.length) return Promise.resolve(lines.shift())
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('bridge did not answer')), ms)
        waiters.push((v) => { clearTimeout(t); resolve(v) })
      })
    },
  }
}

test('the bridge answers over stdio with the session on disk', async () => {
  newSession('first')
  const b = bridge()
  try {
    b.send({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    const res = await b.next()
    assert.ok(res.result?.tools?.length, JSON.stringify(res).slice(0, 200))
    assert.ok(res.result.tools.some((t) => t.name === 'vault_http'))
  } finally { b.proc.kill() }
})

test('a session that ends mid-flight is replaced without restarting the client', async () => {
  // The case that actually happens: you come back the next morning, the
  // session has expired, and the agent is still running. Creating a new one
  // in another terminal should be enough.
  const first = newSession('will-expire')
  const b = bridge()
  try {
    b.send({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    assert.ok((await b.next()).result?.tools?.length, 'the first call should work')

    // End it the way time would, then issue a replacement.
    vault.revokeSession(first.session.id, 'test')
    newSession('replacement')

    b.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })
    const res = await b.next()
    assert.ok(res.result?.tools?.length, `the bridge should have picked up the new session: ${JSON.stringify(res).slice(0, 200)}`)
  } finally { b.proc.kill() }
})

test('with no replacement to find, the failure is still reported', async () => {
  // Recovery must not turn a dead session into silence. If there is nothing
  // new on disk, the client gets the daemon's answer.
  const only = newSession('no-successor')
  const b = bridge()
  try {
    b.send({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    await b.next()

    vault.revokeSession(only.session.id, 'test')
    // State still names the revoked token, so there is nothing to swap to.
    b.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })
    const res = await b.next()
    const text = JSON.stringify(res)
    assert.ok(!res.result?.tools, 'a revoked session must not still list tools')
    assert.match(text, /AV_SESSION_REVOKED|AV_SESSION_REQUIRED|error/i)
  } finally { b.proc.kill() }
})

test('the bridge refuses to start with no session at all', async () => {
  writeFileSync(join(dir, 'cli-state.json'), JSON.stringify({}), { mode: 0o600 })
  const proc = spawn(process.execPath, [CLI, 'mcp'], {
    env: { ...process.env, AGENT_VAULT_DIR: dir, AGENT_VAULT_SESSION: '' },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  let err = ''
  proc.stderr.on('data', (c) => { err += c })
  const code = await new Promise((r) => proc.on('exit', r))
  assert.notEqual(code, 0)
  assert.match(err, /no session/)
  assert.match(err, /session create/)
})
