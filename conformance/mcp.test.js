// MCP over Streamable HTTP and the stdio bridge. Schemas and one call per tool.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { rustSkipReason, implName, openWorld, seed, runCli, leaksSecret, ROOT } from './lib/harness.js'

const PKG_VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version
const TOOLS = {
  vault_status: [],
  vault_list_creds: [],
  vault_get_placeholder: ['cred', 'reason'],
  vault_request_session: ['reason'],
  vault_approval_status: ['approval_id'],
  vault_http: ['cred', 'method', 'path', 'reason'],
  vault_explain_denial: ['request_id'],
  vault_describe_access: [],
  vault_preflight: ['cred', 'method', 'path'],
}

const skip = rustSkipReason()
if (skip) {
  test('mcp', { skip }, () => {})
} else {
  describe('mcp', { concurrency: false, timeout: 120_000 }, () => {
    let w
    let mcpSession
    before(async () => {
      w = await openWorld()
      await seed(w, { approval: 'auto', methods: ['GET'] })
    })
    after(async () => { await w?.close() })

    async function post(message, headers = {}) {
      const res = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          authorization: `Bearer ${w.session.token}`,
          ...(mcpSession ? { 'mcp-session-id': mcpSession } : {}),
          ...headers,
        },
        body: JSON.stringify(message),
      })
      const text = await res.text()
      let json = null
      try { json = text ? JSON.parse(text) : null } catch { json = null }
      if (res.headers.get('mcp-session-id')) mcpSession = res.headers.get('mcp-session-id')
      return { status: res.status, headers: Object.fromEntries(res.headers), json, text }
    }

    function toolBody(rpc) {
      assert.equal(rpc.jsonrpc, '2.0')
      const text = rpc.result?.content?.[0]?.text
      assert.equal(typeof text, 'string')
      let json = null
      try { json = JSON.parse(text) } catch { json = null }
      return { isError: rpc.result.isError === true, text, json }
    }

    test('handshake, tool schemas, and one call of every tool', async () => {
      const init = await post({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'conformance', version: '0' } },
      })
      assert.equal(init.status, 200)
      assert.equal(init.json.result.protocolVersion, '2025-06-18')
      assert.equal(typeof init.json.result.serverInfo.version, 'string')
      assert.ok(init.json.result.serverInfo.version.length > 0)
      if (implName() === 'js') assert.equal(init.json.result.serverInfo.version, PKG_VERSION)
      assert.equal(typeof init.json.result.instructions, 'string')
      assert.ok(mcpSession)

      const older = await post({
        jsonrpc: '2.0', id: 2, method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'conformance', version: '0' } },
      })
      assert.equal(older.json.result.protocolVersion, '2025-03-26')

      const unknown = await post({
        jsonrpc: '2.0', id: 3, method: 'initialize',
        params: { protocolVersion: '1999-01-01', capabilities: {}, clientInfo: { name: 'conformance', version: '0' } },
      })
      assert.equal(unknown.json.result.protocolVersion, '2025-06-18')

      const listed = await post({ jsonrpc: '2.0', id: 4, method: 'tools/list' })
      const tools = listed.json.result.tools
      assert.deepEqual(tools.map((t) => t.name).sort(), Object.keys(TOOLS).sort())
      for (const tool of tools) {
        assert.equal(tool.inputSchema.type, 'object')
        assert.deepEqual(tool.inputSchema.required || [], TOOLS[tool.name])
      }

      const status = toolBody((await post({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'vault_status', arguments: {} } })).json)
      assert.equal(status.isError, false)
      assert.equal(leaksSecret(status.text), null)

      const creds = toolBody((await post({
        jsonrpc: '2.0', id: 6, method: 'tools/call',
        params: { name: 'vault_list_creds', arguments: { available_only: true } },
      })).json)
      assert.equal(creds.isError, false)
      assert.ok(creds.json.some((c) => c.slug === w.slug))
      assert.equal(leaksSecret(creds.text), null)

      const ph = toolBody((await post({
        jsonrpc: '2.0', id: 7, method: 'tools/call',
        params: { name: 'vault_get_placeholder', arguments: { cred: w.slug, reason: 'conformance drill' } },
      })).json)
      assert.equal(ph.isError, false)
      assert.match(ph.json.placeholder, /^av1\./)
      assert.equal(leaksSecret(ph.text), null)

      const asked = toolBody((await post({
        jsonrpc: '2.0', id: 8, method: 'tools/call',
        params: { name: 'vault_request_session', arguments: { cred: w.slug, reason: 'conformance drill', methods: ['GET'] } },
      })).json)
      assert.equal(asked.json.state, 'pending')
      assert.equal(typeof asked.json.request_id, 'string')
      assert.equal(typeof asked.json.poll_secret, 'string')
      assert.equal(leaksSecret(asked.text), null)

      const access = toolBody((await post({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'vault_describe_access', arguments: {} } })).json)
      assert.equal(access.isError, false)
      assert.equal(leaksSecret(access.text), null)

      const pre = toolBody((await post({
        jsonrpc: '2.0', id: 10, method: 'tools/call',
        params: { name: 'vault_preflight', arguments: { cred: w.slug, method: 'GET', path: '/user' } },
      })).json)
      assert.equal(pre.isError, false)
      assert.equal(pre.json.would, 'allow')

      const http = toolBody((await post({
        jsonrpc: '2.0', id: 11, method: 'tools/call',
        params: { name: 'vault_http', arguments: { cred: w.slug, method: 'GET', path: '/echo', reason: 'conformance drill' } },
      })).json)
      assert.equal(http.isError, false)
      assert.equal(http.json.status, 200)
      assert.equal(typeof http.json.body, 'string')
      assert.ok(http.json.body.includes('ordinary-traffic-control'))
      assert.equal(leaksSecret(http.json.body), null)
      assert.equal(w.upstream.hits.at(-1).seen, 'test-secret-conform-0123456789abcdef')

      const missingApproval = toolBody((await post({
        jsonrpc: '2.0', id: 12, method: 'tools/call',
        params: { name: 'vault_approval_status', arguments: { approval_id: 'no-such-approval' } },
      })).json)
      assert.equal(typeof missingApproval.text, 'string')
      assert.ok(missingApproval.text.includes('no approval'))
      assert.equal(leaksSecret(missingApproval.text), null)

      const missingDenial = toolBody((await post({
        jsonrpc: '2.0', id: 13, method: 'tools/call',
        params: { name: 'vault_explain_denial', arguments: { request_id: http.json.request_id || 'no-such-request' } },
      })).json)
      assert.equal(typeof missingDenial.text, 'string')
      assert.equal(leaksSecret(missingDenial.text), null)

      const badVersion = await post(
        { jsonrpc: '2.0', id: 14, method: 'tools/list' },
        { 'mcp-protocol-version': '1999-01-01' },
      )
      assert.equal(badVersion.status, 400)
      assert.equal(badVersion.json.code, 'AV_MCP_PROTOCOL')
    })

    test('a dead token still initializes and says the session is invalid', async () => {
      const res = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          authorization: 'Bearer avs1.dead.not-a-real-token',
        },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1, method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'conformance', version: '0' } },
        }),
      })
      const json = await res.json()
      assert.equal(res.status, 200)
      assert.equal(json.result.protocolVersion, '2025-06-18')
      assert.equal(res.headers.get('av-session-invalid'), '1')
      const sid = res.headers.get('mcp-session-id')
      const gone = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'DELETE',
        headers: { 'mcp-session-id': sid, authorization: 'Bearer avs1.dead.not-a-real-token' },
      })
      assert.equal(gone.status, 204)
    })

    test('the notification stream opens for a live MCP session and closes with it', async () => {
      const opened = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          authorization: `Bearer ${w.session.token}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1, method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'conformance', version: '0' } },
        }),
      })
      const sid = opened.headers.get('mcp-session-id')
      await opened.text()
      const stream = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        headers: { 'mcp-session-id': sid, authorization: `Bearer ${w.session.token}` },
      })
      assert.equal(stream.status, 200)
      assert.match(stream.headers.get('content-type'), /text\/event-stream/)
      const reader = stream.body.getReader()
      const chunk = await reader.read()
      await reader.cancel()
      assert.ok(Buffer.from(chunk.value).toString('utf8').includes('agent-vault'))
      const del = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'DELETE',
        headers: { 'mcp-session-id': sid, authorization: `Bearer ${w.session.token}` },
      })
      assert.equal(del.status, 204)
      const after = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        headers: { 'mcp-session-id': sid, authorization: `Bearer ${w.session.token}` },
      })
      const body = await after.json()
      assert.equal(after.status, 404)
      assert.equal(body.code, 'AV_MCP_SESSION_UNKNOWN')
    })

    test('stdio bridge proxies a session and refuses to start without one', async () => {
      const none = await runCli(w, ['mcp'], { timeout: 5000 })
      assert.equal(none.code, 9)
      assert.match(none.stderr, /no session/)
      assert.equal(leaksSecret(none.stdout + none.stderr), null)

      const init = JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'conformance', version: '0' } },
      })
      const list = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
      const bridged = await runCli(w, ['mcp'], {
        env: { ...w.env, AGENT_VAULT_SESSION: w.session.token },
        input: `${init}\n${list}\n`,
        timeout: 10_000,
        until: (out) => out.trim().split('\n').filter((line) => line.startsWith('{')).length >= 2,
      })
      const lines = bridged.stdout.trim().split('\n').filter((line) => line.startsWith('{')).map((line) => JSON.parse(line))
      assert.equal(lines[0].result.protocolVersion, '2025-06-18')
      assert.equal(lines[1].result.tools.length, Object.keys(TOOLS).length)
      assert.equal(leaksSecret(bridged.stdout + bridged.stderr), null)
      assert.equal(ROOT.includes('agent-vault'), true)
    })
  })
}
