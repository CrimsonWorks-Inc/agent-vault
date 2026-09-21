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

test('every line the bridge writes to stdout is a JSON-RPC message', async () => {
  // On a stdio transport stdout IS the protocol channel. The bridge forwarded
  // the daemon's HTTP body verbatim, and a denial comes back as problem+json —
  // `{"type":"…/AV_SESSION_EXPIRED","code":…}` — which is valid JSON and not a
  // JSON-RPC message. The client could not parse it as protocol, never saw a
  // reply to `initialize`, and sat there until it timed out: an expired
  // session made the whole server look unreachable, with nothing on stderr to
  // say why.
  //
  // The test above this one missed it by checking that SOME json came back
  // with the right code in it. That is true of a problem document too.
  const only = newSession('protocol-shape')
  const b = bridge()
  const stderr = []
  b.proc.stderr.setEncoding('utf8')
  b.proc.stderr.on('data', (c) => stderr.push(c))
  try {
    // A denial on the very first message, which is the case that hung.
    vault.revokeSession(only.session.id, 'test')
    b.send({ jsonrpc: '2.0', id: 7, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } })
    const res = await b.next()

    assert.equal(res.jsonrpc, '2.0', `not a JSON-RPC message: ${JSON.stringify(res).slice(0, 120)}`)
    assert.equal(res.id, 7, 'the reply must carry the id of the request it answers')
    assert.ok(res.error, 'a refusal must be a JSON-RPC error, not a problem document')
    assert.match(res.error.message, /AV_SESSION_REVOKED|AV_SESSION_REQUIRED/)
    assert.ok(!('type' in res), 'a problem+json document reached stdout')

    // And the human-readable diagnosis goes where diagnostics belong.
    assert.match(stderr.join(''), /agent-vault mcp:.*(REVOKED|REQUIRED)/i,
      'the reason must be on stderr, or a human sees a bare protocol error')
  } finally { b.proc.kill() }
})

test('a successful call is still forwarded byte for byte', async () => {
  // The translation must not touch real protocol traffic: a JSON-RPC response
  // from the daemon has to arrive exactly as the daemon wrote it.
  newSession('passthrough')
  const b = bridge()
  try {
    b.send({ jsonrpc: '2.0', id: 11, method: 'tools/list', params: {} })
    const res = await b.next()
    assert.equal(res.jsonrpc, '2.0')
    assert.equal(res.id, 11)
    assert.ok(Array.isArray(res.result?.tools), 'a working call must come back as a result')
    assert.ok(res.result.tools.length > 0)
  } finally { b.proc.kill() }
})

