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
    //
    // Asserted on a tool that SPENDS capability rather than on `tools/list`.
    // Listing tool names is not capability and no longer requires a session -
    // binding the protocol to one made a client whose session died report the
    // whole server as unreachable. What must not survive a revocation is the
    // ability to reach a credential.
    b.send({
      jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'vault_list_creds', arguments: {} },
    })
    const res = await b.next()
    assert.equal(res.id, 2, 'the reply must answer the request that was sent')
    assert.equal(res.result?.isError, true, 'a revoked session still reached a credential')
    const said = res.result.content[0].text
    assert.match(said, /needs a live session/i, said.slice(0, 160))
    assert.match(said, /revoked/i, `the agent is not told why: ${said.slice(0, 160)}`)
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
    // The original trigger was `initialize` under a dead session, because the
    // endpoint answered 401 problem+json before parsing anything. It no longer
    // does: the handshake does not depend on capability, which is the point.
    // So the shape is asserted over the handshake AND the refusal that
    // replaced it - every line on this channel is still a JSON-RPC message
    // carrying the id of the request it answers.
    vault.revokeSession(only.session.id, 'test')
    b.send({ jsonrpc: '2.0', id: 7, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } })
    const hello = await b.next()
    assert.equal(hello.jsonrpc, '2.0', `not a JSON-RPC message: ${JSON.stringify(hello).slice(0, 120)}`)
    assert.equal(hello.id, 7, 'the reply must carry the id of the request it answers')
    assert.ok(hello.result?.serverInfo, 'a dead session must not stop the handshake')

    b.send({
      jsonrpc: '2.0', id: 8, method: 'tools/call',
      params: { name: 'vault_http', arguments: { cred: 'gh', method: 'GET', path: '/x', reason: 'r' } },
    })
    const res = await b.next()
    assert.equal(res.jsonrpc, '2.0', `not a JSON-RPC message: ${JSON.stringify(res).slice(0, 120)}`)
    assert.equal(res.id, 8, 'the reply must carry the id of the request it answers')
    assert.equal(res.result?.isError, true, 'a refusal must be marked as one, not returned as an answer')
    assert.ok(!('type' in res), 'a problem+json document reached stdout')

    // And the reason reaches the caller IN BAND. It used to go to stderr,
    // because the daemon's answer was a problem document the bridge had to
    // translate and the translation was all there was to report. Now the
    // refusal is a tool result, which is strictly better: a client that never
    // shows stderr still shows this.
    const why = res.result.content[0].text
    assert.match(why, /revoked/i, `the agent is not told why: ${why.slice(0, 160)}`)
    assert.match(why, /vault_request_session/, 'the refusal does not say how to recover')
    assert.equal(stderr.join('').includes('problem'), false, 'a problem document was logged as protocol noise')
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


test('a daemon restart does not leave the bridge permanently broken', async () => {
  // The daemon keeps MCP sessions in memory, so a restart invalidates every
  // one of them at once. The bridge cached its Mcp-Session-Id and never
  // cleared it, so from then on every call came back
  // AV_MCP_SESSION_UNKNOWN — for the life of the client. The bridge already
  // recovers from a dead VAULT session by re-reading the token; this is the
  // same papercut one layer up, and it needed the same treatment.
  newSession('survives-restart')
  const b = bridge()
  try {
    b.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } })
    const init = await b.next()
    assert.ok(init.result, `initialize failed: ${JSON.stringify(init).slice(0, 160)}`)

    // Everything the daemon knew about MCP sessions, gone — exactly what a
    // restart does.
    daemon.mcp.sessions.clear()

    b.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })
    const res = await b.next()
    assert.equal(res.id, 2)
    assert.ok(!res.error, `the bridge did not recover: ${JSON.stringify(res.error)}`)
    assert.ok(Array.isArray(res.result?.tools), 'the tools should be listable again')

    // And it keeps working afterwards, rather than recovering exactly once.
    b.send({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} })
    const again = await b.next()
    assert.ok(Array.isArray(again.result?.tools), 'the recovery must be durable')
  } finally { b.proc.kill() }
})

// Whatever the daemon says, stdout stays protocol.
//
// On a stdio transport stdout IS the protocol channel, and the bridge used to
// forward the daemon's HTTP body verbatim. A problem+json document is valid
// JSON and not a JSON-RPC message, so the client never saw a reply and sat
// there until it timed out.
//
// That used to be reachable through the real daemon, because a dead session
// made `initialize` answer 401 problem+json. It no longer does - the handshake
// is not bound to a session any more - and rewriting those tests quietly left
// this protection untested, which the mutation check caught and I had not.
//
// So it is driven against a stub that answers the way the daemon still can:
// a browser Origin, a wrong method, a 5xx, anything not written as protocol.
test('a non-protocol answer from the daemon still reaches the client as JSON-RPC', async () => {
  const { createServer } = await import('node:http')
  const stubDir = mkdtempSync(join(tmpdir(), 'av-stub-'))
  const sock = join(stubDir, 'control.sock')

  // The gateway the bridge will be told to talk to, answering /mcp with a
  // problem document rather than a JSON-RPC message.
  const gateway = createServer((req, res) => {
    res.writeHead(503, { 'content-type': 'application/problem+json' })
    res.end(JSON.stringify({
      type: 'https://agent-vault.dev/errors/AV_UPSTREAM', code: 'AV_UPSTREAM',
      detail: 'the vault is having a bad day', hint: 'try later',
    }))
  })
  await new Promise((r) => gateway.listen(0, '127.0.0.1', r))

  // The control socket the bridge reads its endpoint from.
  const control = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ gateway_port: gateway.address().port }))
  })
  await new Promise((r) => control.listen(sock, r))

  writeFileSync(join(stubDir, 'cli-state.json'), JSON.stringify({ token: 'avs1.stub.notreal' }), { mode: 0o600 })

  const proc = spawn(process.execPath, [CLI, 'mcp'], {
    env: { ...process.env, AGENT_VAULT_DIR: stubDir, AGENT_VAULT_SESSION: '' },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const out = []
  const stderr = []
  proc.stdout.setEncoding('utf8')
  proc.stderr.setEncoding('utf8')
  proc.stdout.on('data', (c) => out.push(c))
  proc.stderr.on('data', (c) => stderr.push(c))

  try {
    proc.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'initialize', params: {} })}\n`)
    const deadline = Date.now() + 5000
    while (!out.join('').includes('\n') && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50))
    }
    const lines = out.join('').split('\n').filter((l) => l.trim())
    assert.ok(lines.length, 'the bridge answered nothing at all, which is the hang this prevents')

    for (const line of lines) {
      const msg = JSON.parse(line)
      assert.equal(msg.jsonrpc, '2.0', `not a JSON-RPC message: ${line.slice(0, 140)}`)
      assert.equal(msg.id, 42, 'the reply must carry the id of the request it answers')
      assert.ok(msg.error, 'a refusal must be a JSON-RPC error, not a problem document')
      assert.match(msg.error.message, /AV_UPSTREAM|bad day/, msg.error.message)
      assert.ok(!('type' in msg), 'a problem+json document reached stdout')
    }

    // And the diagnosis goes where diagnostics belong, since there is no tool
    // result to carry it on this path.
    assert.match(stderr.join(''), /agent-vault mcp:/, 'nothing on stderr to say what happened')
  } finally {
    proc.kill()
    gateway.close()
    control.close()
    rmSync(stubDir, { recursive: true, force: true })
  }
})
