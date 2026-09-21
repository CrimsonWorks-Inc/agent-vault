// MCP over both transports. The point of these tests is parity: the stdio
// bridge and the Streamable HTTP endpoint must reach the same handler and
// produce the same results, because if they diverge the divergence will be in
// policy or scrubbing rather than in framing.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { McpServer } from '../../src/daemon/mcp.js'
import { Pipeline } from '../../src/daemon/pipeline.js'
import { startFakeGitHub, REAL_TOKEN } from '../../demo/fake-github.js'

let dir, vault, daemon, base, token, upstream, ghPort, session

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-mcp-'))
  const fake = await startFakeGitHub()
  upstream = fake.server
  ghPort = fake.port
  vault = Vault.create(dir, { factor: 'none' })
  const cred = vault.addCredential({
    slug: 'demo-gh', kind: 'http',
    connector: { host: `127.0.0.1:${ghPort}`, scheme: 'http' },
    fields: { token: REAL_TOKEN },
    sites: { token: ['header:authorization:Bearer'] },
  })
  const created = vault.createSession({ label: 'mcp test', policy: {} })
  session = created.session
  token = created.token
  vault.createGrant({
    sessionId: session.id, credentialId: cred.id, fields: ['token'],
    policy: { hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'auto' },
  })
  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'control.sock') }).start()
  base = `http://127.0.0.1:${daemon.gatewayPort}`
})

after(async () => {
  if (daemon) await daemon.stop()
  if (upstream) await new Promise((r) => upstream.close(r))
  rmSync(dir, { recursive: true, force: true })
})

/** One Streamable HTTP call. */
async function mcpPost(message, { headers = {}, auth = true } = {}) {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(auth ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: JSON.stringify(message),
  })
  const text = await res.text()
  return { status: res.status, headers: Object.fromEntries(res.headers), body: text ? JSON.parse(text) : null }
}

test('initialize returns a protocol version, server info and a session id', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } })
  assert.equal(res.status, 200)
  assert.equal(res.body.result.serverInfo.name, 'agent-vault')
  assert.equal(res.body.result.protocolVersion, '2025-06-18')
  assert.ok(res.headers['mcp-session-id'], 'a transport session id is issued')
  assert.match(res.body.result.instructions, /placeholders/i)
})

test('the endpoint refuses a request with no bearer token', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, { auth: false })
  assert.equal(res.status, 401)
  assert.equal(res.body.code, 'AV_SESSION_REQUIRED')
})

test('the MCP session id alone never authenticates', async () => {
  const init = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })
  const sid = init.headers['mcp-session-id']
  const res = await mcpPost({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, {
    auth: false, headers: { 'mcp-session-id': sid },
  })
  assert.equal(res.status, 401, 'a routing key is not a credential')
})

test('an unknown MCP session id is rejected rather than silently accepted', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, {
    headers: { 'mcp-session-id': 'not-a-real-session' },
  })
  assert.equal(res.status, 404)
  assert.equal(res.body.code, 'AV_MCP_SESSION_UNKNOWN')
})

test('an unsupported protocol version is refused with the supported list', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, {
    headers: { 'mcp-protocol-version': '1999-01-01' },
  })
  assert.equal(res.status, 400)
  assert.equal(res.body.code, 'AV_MCP_PROTOCOL')
  assert.ok(Array.isArray(res.body.supported))
})

test('a browser cannot drive the MCP endpoint', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, {
    headers: { origin: 'https://evil.test' },
  })
  assert.equal(res.status, 403)
  assert.equal(res.body.code, 'AV_BROWSER_ORIGIN')
})

test('tools/list advertises the tools an agent needs and no secret-bearing tool', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  const names = res.body.result.tools.map((t) => t.name)
  assert.ok(names.includes('vault_http'))
  assert.ok(names.includes('vault_get_placeholder'))
  assert.ok(names.includes('vault_explain_denial'))
  assert.ok(!names.some((n) => /reveal|secret|export/i.test(n)), 'no tool exposes a value')
})

test('vault_list_creds tells the agent exactly where a placeholder goes', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'vault_list_creds', arguments: {} } })
  const data = JSON.parse(res.body.result.content[0].text)
  assert.equal(data[0].slug, 'demo-gh')
  assert.match(data[0].usage[0].put_placeholder_at[0], /Authorization: Bearer/)
})

test('vault_http runs the full pipeline and never returns the secret', async () => {
  const res = await mcpPost({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'vault_http', arguments: { cred: 'demo-gh', method: 'GET', path: '/user', reason: 'testing' } },
  })
  const data = JSON.parse(res.body.result.content[0].text)
  assert.equal(data.status, 200)
  assert.equal(data.decision, 'allow')
  assert.ok(!JSON.stringify(res.body).includes(REAL_TOKEN), 'the secret must not come back through MCP')
  assert.ok(data.body.includes('frozencrow'))
})

test('vault_http is bound by the same policy as the gateway', async () => {
  const res = await mcpPost({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'vault_http', arguments: { cred: 'demo-gh', method: 'DELETE', path: '/user', reason: 'testing' } },
  })
  const data = JSON.parse(res.body.result.content[0].text)
  assert.equal(data.status, 403)
  assert.equal(data.decision, 'deny')
})

test('DELETE ends the transport session but not the vault session', async () => {
  const init = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })
  const sid = init.headers['mcp-session-id']
  const res = await fetch(`${base}/mcp`, { method: 'DELETE', headers: { authorization: `Bearer ${token}`, 'mcp-session-id': sid } })
  assert.equal(res.status, 204)
  const after = await mcpPost({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  assert.equal(after.status, 200, 'the vault session is untouched')
})

test('transport parity: stdio and HTTP produce identical tool results', async () => {
  const pipeline = new Pipeline(vault)
  const stdio = new McpServer(vault, pipeline, () => session)
  stdio.sessionToken = token

  for (const call of [
    { name: 'vault_status', arguments: {} },
    { name: 'vault_list_creds', arguments: {} },
  ]) {
    const viaStdio = await stdio.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: call })
    const viaHttp = await mcpPost({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: call })
    assert.deepEqual(
      JSON.parse(viaStdio.result.content[0].text),
      JSON.parse(viaHttp.body.result.content[0].text),
      `${call.name} differs between transports`,
    )
  }
})

test('batched JSON-RPC messages are answered as a batch', async () => {
  const res = await mcpPost([
    { jsonrpc: '2.0', id: 1, method: 'ping' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ])
  assert.equal(res.status, 200)
  assert.equal(res.body.length, 2)
  assert.equal(res.body[0].id, 1)
})

test('a notification gets 202 with no body, per the transport spec', async () => {
  const res = await mcpPost({ jsonrpc: '2.0', method: 'notifications/initialized' })
  assert.equal(res.status, 202)
})
