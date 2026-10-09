// The MCP tool surface, from the agent's side of it.
//
// These five tools are what an agent actually drives, so they are the surface
// most likely to be probed in anger. Everything here is a thing an agent can
// ask for directly: a path outside its grant, a traversal out of its
// credential's route, a header it should not be able to set, a credential it
// was never granted.
//
// vault_http builds `/p/<slug><path>` from the agent's own `path` argument and
// forwards its own `headers` object, so both are attacker-controlled by
// construction.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { McpServer } from '../../src/daemon/mcp.js'
import { SessionRequests } from '../../src/daemon/session-requests.js'
import { Pipeline } from '../../src/daemon/pipeline.js'

let dir, vault, mcp, upstream, upPort, received, session

const call = (name, args) => mcp.handle({
  jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args },
})
const result = (r) => {
  try { return JSON.parse(r?.result?.content?.[0]?.text || '{}') } catch { return {} }
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-mcpt-'))
  received = []
  upstream = createServer((req, res) => {
    // rawHeaders, because Node keeps only the first of a repeated
    // content-type in `headers` and would hide a duplicate.
    received.push({ url: req.url, headers: req.headers, rawHeaders: req.rawHeaders })
    req.resume()
    res.end('{}')
  })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  upPort = upstream.address().port

  vault = Vault.create(dir, { factor: 'none' })
  const allowed = vault.addCredential({
    slug: 'allowed', kind: 'http', connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
    fields: { token: 'ALLOWED-SECRET-0011223' }, sites: { token: ['header:authorization:Bearer'] },
  })
  // A second credential this session is never granted. It must stay unreachable.
  vault.addCredential({
    slug: 'ungranted', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'UNGRANTED-SECRET-0044556' }, sites: { token: ['header:authorization:Bearer'] },
  })
  const made = vault.createSession({ label: 'agent' })
  session = made.session
  vault.createGrant({
    sessionId: session.id, credentialId: allowed.id, fields: ['token'],
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/safe/**'],
      budget: { unit: 'requests', limit: 100 }, approval: 'auto',
    },
  })
  // The session-request store lives on the daemon, because a request outlives
  // any one MCP connection — the human answers in their own time.
  mcp = new McpServer(vault, new Pipeline(vault), () => session, {
    sessionRequests: new SessionRequests(vault),
  })
})

after(() => {
  if (upstream) upstream.close()
  rmSync(dir, { recursive: true, force: true })
})

test('a request inside the grant works, so the refusals below mean something', async () => {
  received.length = 0
  const r = result(await call('vault_http', { cred: 'allowed', method: 'GET', path: '/safe/x' }))
  assert.equal(r.status, 200)
  assert.equal(received.length, 1)
  assert.equal(received[0].url, '/safe/x')
  assert.equal(received[0].headers.authorization, 'Bearer ALLOWED-SECRET-0011223')
})

test('a path outside the grant never reaches the upstream', async () => {
  received.length = 0
  const r = result(await call('vault_http', { cred: 'allowed', method: 'GET', path: '/forbidden/x' }))
  assert.equal(r.status, 403)
  assert.deepEqual(received, [], 'nothing should have been sent')
})

test('traversal cannot climb out of the granted path', async () => {
  // `/p/<slug>` is built by string concatenation around an argument the agent
  // controls, so `..` is the first thing anyone would try.
  for (const path of ['/safe/../forbidden/x', '/../../etc/passwd', '/safe/%2e%2e/forbidden/x', '/safe/./../forbidden']) {
    received.length = 0
    const r = result(await call('vault_http', { cred: 'allowed', method: 'GET', path }))
    assert.ok(r.status === 403 || r.status === 400, `${path} answered ${r.status}`)
    assert.deepEqual(received, [], `${path} reached the upstream`)
  }
})

test('a credential this session was never granted is unreachable', async () => {
  received.length = 0
  const r = result(await call('vault_http', { cred: 'ungranted', method: 'GET', path: '/safe/x' }))
  assert.match(String(r.error), /no grant/)
  assert.deepEqual(received, [])
})

test('CRLF in a path or a header cannot smuggle anything upstream', async () => {
  received.length = 0
  const viaPath = result(await call('vault_http', {
    cred: 'allowed', method: 'GET', path: '/safe/x\r\nX-Injected: 1',
  }))
  assert.notEqual(viaPath.status, 200)
  const viaHeader = result(await call('vault_http', {
    cred: 'allowed', method: 'GET', path: '/safe/x', headers: { 'X-A': 'v\r\nX-Injected: 1' },
  }))
  assert.notEqual(viaHeader.status, 200)
  for (const r of received) {
    assert.ok(!Object.keys(r.headers).some((h) => /injected/i.test(h)), 'a header was smuggled through')
  }
})

test('the agent cannot set the daemon’s own headers through a tool argument', async () => {
  // These used to be pushed before the daemon's, so the agent's value won and
  // the request failed as unauthenticated. Not an escalation, but a tool
  // argument should not be able to reach the daemon's own plumbing at all.
  received.length = 0
  const r = result(await call('vault_http', {
    cred: 'allowed', method: 'GET', path: '/safe/x',
    headers: { 'av-session': 'forged', 'AV-Reason': 'spoofed', host: 'evil.test' },
  }))
  assert.equal(r.status, 200, 'the request should simply proceed')
  assert.equal(received.length, 1)
  assert.ok(!Object.keys(received[0].headers).some((h) => h.toLowerCase().startsWith('av-')),
    'no av-* header may reach the upstream')
  assert.ok(!String(received[0].headers.host).includes('evil'), 'the host must be the credential’s')
})

test('a body goes upstream with exactly one content-type', async () => {
  // A caller's `Content-Type` was forwarded as written, and then a default
  // `content-type: application/json` was added beside it, because the lookup
  // only checked the lowercase key. A form-encoded Graph API batch went out
  // with both and was parsed as JSON.
  const contentTypes = (r) => {
    const out = []
    for (let i = 0; i < r.rawHeaders.length; i += 2) {
      if (r.rawHeaders[i].toLowerCase() === 'content-type') out.push(r.rawHeaders[i + 1])
    }
    return out
  }

  received.length = 0
  const form = result(await call('vault_http', {
    cred: 'allowed', method: 'POST', path: '/safe/x', body: 'batch=%5B%5D',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  }))
  assert.equal(form.status, 200)
  assert.equal(received.length, 1)
  assert.deepEqual(contentTypes(received[0]), ['application/x-www-form-urlencoded'])

  received.length = 0
  const json = result(await call('vault_http', {
    cred: 'allowed', method: 'POST', path: '/safe/x', body: '{"a":1}',
  }))
  assert.equal(json.status, 200)
  assert.equal(received.length, 1)
  assert.deepEqual(contentTypes(received[0]), ['application/json'])
})

test('vault_get_placeholder is bound to the session’s own grants', async () => {
  const ok = result(await call('vault_get_placeholder', { cred: 'allowed', reason: 'testing' }))
  assert.match(ok.placeholder, /^av1\./)
  const no = result(await call('vault_get_placeholder', { cred: 'ungranted', reason: 'testing' }))
  assert.match(String(no.error), /no grant/)
  assert.equal(no.placeholder, undefined)
})

test('no tool returns a credential value, whatever it is asked', async () => {
  // The one invariant the whole design rests on.
  const outputs = []
  outputs.push(await call('vault_status', {}))
  outputs.push(await call('vault_list_creds', {}))
  outputs.push(await call('vault_get_placeholder', { cred: 'allowed', reason: 'x' }))
  outputs.push(await call('vault_http', { cred: 'allowed', method: 'GET', path: '/safe/x' }))
  outputs.push(await call('vault_explain_denial', { request_id: 'nope' }))
  const all = JSON.stringify(outputs)
  assert.ok(!all.includes('ALLOWED-SECRET-0011223'), 'a credential value came back through a tool')
  assert.ok(!all.includes('UNGRANTED-SECRET-0044556'), 'an ungranted credential value came back')
})

test('the tool list is exactly the documented tools', async () => {
  // A new tool is a new surface. This fails when one is added, which is the
  // point: it should be a decision, not a drive-by. It did its job when
  // vault_request_session arrived — a tool two error paths had been telling
  // agents to call for months while it did not exist.
  const listed = await mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
  assert.deepEqual(listed.result.tools.map((t) => t.name).sort(), [
    'vault_approval_status', 'vault_explain_denial', 'vault_get_placeholder', 'vault_http',
    'vault_list_creds', 'vault_request_session', 'vault_status',
  ])
})

test('the one capability-shaped tool cannot create capability', async () => {
  // vault_request_session is the only tool that touches session creation, so
  // it is the one to be sure about: asking must create nothing. A human
  // answers it through the control socket, gated, or it never resolves.
  const before = Object.keys(vault.db.sessions).length
  const res = await mcp.handle({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'vault_request_session', arguments: { cred: 'gh-frozencrow', reason: 'testing' } },
  })
  const payload = JSON.parse(res.result.content[0].text)
  assert.equal(payload.state, 'pending')
  assert.ok(payload.request_id.startsWith('sr_'))
  assert.equal(Object.keys(vault.db.sessions).length, before, 'asking created a session')
  assert.equal(JSON.stringify(payload).includes('avs1.'), false, 'a token came back from asking')

  // Polling before a human answers hands out nothing either.
  const polled = await mcp.handle({
    jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'vault_request_session', arguments: { poll_id: payload.request_id, reason: 'checking' } },
  })
  const poll = JSON.parse(polled.result.content[0].text)
  assert.equal(poll.state, 'pending')
  assert.equal(poll.token, undefined)
})

test('a concurrent request cannot hijack a batch mid-flight', async () => {
  // Found by an independent audit. The bearer session lived in one field on
  // the Daemon and was read back across the `await` in the batch loop, so any
  // other /mcp request landing in that window replaced it — and the rest of
  // the batch ran as that other session, against credentials it was never
  // granted. Deterministic, not a narrow race: the attacker picks the window
  // by making its first call slow.
  const { Daemon } = await import('../../src/daemon/server.js')

  const dir2 = mkdtempSync(join(tmpdir(), 'av-race-'))
  let slowUpstream
  try {
    // An upstream that holds the first request open, widening the window.
    let held
    slowUpstream = createServer((req, res) => {
      if (req.url.startsWith('/slow')) {
        held = res
        setTimeout(() => { res.end('{}') }, 120)
        return
      }
      res.end('{}')
    })
    await new Promise((r) => slowUpstream.listen(0, '127.0.0.1', r))
    const port = slowUpstream.address().port
    void held

    const v = Vault.create(dir2, { factor: 'none' })
    const mk = (slug, secret) => v.addCredential({
      slug, kind: 'http', connector: { host: `127.0.0.1:${port}`, scheme: 'http' },
      fields: { token: secret }, sites: { token: ['header:authorization:Bearer'] },
    })
    const low = mk('low', 'LOW-SECRET-000000')
    const high = mk('high', 'HIGH-SECRET-PRODUCTION-99999')

    const grantTo = (session, cred) => v.createGrant({
      sessionId: session.id, credentialId: cred.id, fields: ['token'],
      policy: {
        hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'],
        budget: { unit: 'requests', limit: 50 }, approval: 'auto',
      },
    })
    const a = v.createSession({ label: 'privileged' })
    const b = v.createSession({ label: 'unprivileged' })
    grantTo(a.session, high)
    grantTo(b.session, low)

    const daemon = await new Daemon(v, { port: 0, socketPath: join(dir2, 'c.sock') }).start()
    try {
      const rpc = (token, body) => fetch(`http://127.0.0.1:${daemon.gatewayPort}/mcp`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify(body),
      }).then((r) => r.json())

      // B sends a batch: a slow call it may make, then one it may not.
      const batch = rpc(b.token, [
        { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'vault_http', arguments: { cred: 'low', method: 'GET', path: '/slow' } } },
        { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'vault_http', arguments: { cred: 'high', method: 'GET', path: '/STOLEN' } } },
      ])
      // A merely touches /mcp during the window.
      await new Promise((r) => setTimeout(r, 25))
      await rpc(a.token, { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'vault_status', arguments: {} } })

      const out = JSON.stringify(await batch)
      assert.ok(!out.includes('HIGH-SECRET-PRODUCTION-99999'),
        'the unprivileged batch obtained the privileged credential')
      assert.match(out, /no grant/, 'the second call should still be refused on its own merits')
    } finally { await daemon.stop() }
  } finally {
    if (slowUpstream) slowUpstream.close()
    rmSync(dir2, { recursive: true, force: true })
  }
})

// An agent has to be able to ask for a SHORT session.
//
// `vault_request_session` took cred, methods, paths and budget — but not a
// lifetime, although `ttl_minutes` is one of the six fields a proposal may
// name, `summarize()` renders it, and the daemon honours it. So every request
// an agent could actually make took the eight-hour default, and the human
// approving it was shown no lifetime at all. The tool's own description says
// "ask for the least you need"; on the one dimension measured in minutes, it
// could not.
test('an agent can ask for the least lifetime it needs, not just the least scope', async () => {
  const listed = await mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
  const ask = listed.result.tools.find((t) => t.name === 'vault_request_session')
  const props = ask.inputSchema.properties

  assert.ok(props.ttl_minutes, 'an agent cannot ask for a short session')
  assert.equal(props.ttl_minutes.type, 'number')

  // Every other dimension a proposal carries is already askable; the point is
  // that the set is complete, not that one field exists.
  for (const field of ['cred', 'methods', 'paths', 'budget']) {
    assert.ok(props[field], `vault_request_session cannot name ${field}`)
  }
})

// Every tool an error path tells an agent to call has to exist.
//
// The 202 from a held write has always named `vault_approval_status`, and it
// was never built — the THIRD instance of this in the codebase, after the two
// error paths that named `vault_request_session` before it existed. It sits on
// the busiest path in the system: every held write reaches it, and an agent
// that follows the instruction gets a tool-not-found with no other way to learn
// the human answered.
//
// This morning's sweep checked `agent-vault <cmd>` hints against the CLI's
// commands and walked straight past this, because a tool name is not a command.
test('no error path names an MCP tool that does not exist', async () => {
  const listed = await mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
  const names = new Set(listed.result.tools.map((t) => t.name))

  const files = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules') continue
      const p = join(dir, entry.name)
      if (entry.isDirectory()) walk(p)
      else if (/\.(js|html|md)$/.test(entry.name)) files.push(p)
    }
  }
  walk(new URL('../../src', import.meta.url).pathname)

  const bad = []
  for (const file of files) {
    readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
      const t = line.trim()
      if (t.startsWith('*') || t.startsWith('//')) return
      for (const m of line.matchAll(/\bvault_[a-z_]+/g)) {
        if (names.has(m[0])) continue
        bad.push(`${file.replace(/^.*\/src\//, 'src/')}:${i + 1} → ${m[0]}`)
      }
    })
  }
  assert.deepEqual(bad, [], `error paths naming tools that do not exist:\n${bad.join('\n')}`)
})

// And the tool the 202 names actually answers the question it was named for.
test('an agent can find out whether the human answered', async () => {
  const held = await mcp.handle({
    jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'vault_approval_status', arguments: { approval_id: 'ap_doesnotexist' } },
  })
  const missing = JSON.parse(held.result.content[0].text)
  assert.match(missing.error, /no approval/, 'an unknown id should say so, not crash')
})
