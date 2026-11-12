// C12 on every surface, not just /p/ (integrate-2, round 2).
//
// A session with no expiry is never usable from a network listener. The rule
// ran only inside the pipeline, so /p/ refused an infinite session's token on
// a TLS listener bound to 0.0.0.0 while the same token, on the same listener,
// drove MCP vault_http (the upstream got the real secret), read /v1/session
// and /v1/credentials, and minted live placeholders through POST
// /v1/placeholders and vault_get_placeholder. Every surface now asks the vault
// one question, assertSessionUsable(session, listener).
//
// These run a real daemon with real listeners: managed TLS on 0.0.0.0 and
// [::] (remote by their bind address, so a client on 127.0.0.1 still arrives
// on a network listener), managed TLS and plain TCP on 127.0.0.1, and the
// built-in gateway. The upstream is a local server, so "nothing sent" is
// counted, and placeholder rows are counted so "nothing minted" is too.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import https from 'node:https'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { tlsPaths } from '../../src/daemon/tls.js'

const SECRET = 'ghp_C12SURFACES00112233445566778899aabb'
const MARKER = 'C12_UPSTREAM_MARKER'
const HOUR = 3_600_000

let dir, vault, daemon, ca, upstream
const seen = []
const L = {} // listener id -> { port, tls, host } or { skip: reason }
let inf, fin

function session(label, infinite) {
  const cred = vault.findCredential('up')
  const made = vault.createSession({ label, infinite, ttlMs: infinite ? null : 8 * HOUR })
  const grant = vault.createGrant({
    sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
    policy: { hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/**'], budget: { unit: 'requests', limit: 1000 }, approval: 'auto' },
  })
  const { placeholder } = vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
  return { ...made, grant, placeholder }
}

before(async () => {
  upstream = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seen.push({ url: req.url, headers: req.headers })
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(MARKER)
    })
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))

  dir = mkdtempSync(join(tmpdir(), 'av-c12s-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'up', kind: 'http', connector: { host: `127.0.0.1:${upstream.address().port}`, scheme: 'http' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  inf = session('infinite', true)
  fin = session('finite', false)
  assert.equal(inf.session.infinite, true)

  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'c.sock') }).start()
  for (const [id, address, tls, host] of [
    ['wild-v4', '0.0.0.0:0', true, '127.0.0.1'],
    ['wild-v6', '[::]:0', true, '::1'],
    ['loop-tls', '127.0.0.1:0', true, '127.0.0.1'],
    ['loop-tcp', '127.0.0.1:0', false, '127.0.0.1'],
  ]) {
    try {
      const bound = await daemon.bindListener({ id, address, surfaces: ['gateway', 'mcp'], ...(tls ? { tls: { managed: true } } : {}) })
      L[id] = { port: bound.port, tls, host }
    } catch (e) {
      L[id] = { skip: `${address} did not bind here: ${e.message}` }
    }
  }
  L.builtin = { port: daemon.gatewayPort, tls: false, host: '127.0.0.1' }
  // Written by the first managed-TLS bind.
  ca = readFileSync(tlsPaths(dir).cert, 'utf8')
  // [::] binds on a machine with IPv6 but a client may still not reach ::1.
  if (!L['wild-v6'].skip) {
    try { await request('wild-v6', { path: '/v1/status' }) } catch (e) { L['wild-v6'] = { skip: `::1 is not reachable here: ${e.message}` } }
  }
})

after(async () => {
  await daemon?.stop()
  await new Promise((resolve) => upstream.close(resolve))
  rmSync(dir, { recursive: true, force: true })
})

/** One request to a listener. A fresh connection each time, so stop() never waits on a kept-alive socket. */
function request(id, { path, method = 'GET', headers = {}, body = null }) {
  const { port, tls, host } = L[id]
  return new Promise((resolve, reject) => {
    const lib = tls ? https : http
    const req = lib.request({
      host, port, path, method, agent: false,
      headers: { host: 'localhost', ...headers },
      ...(tls ? { ca, servername: 'localhost' } : {}),
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() }))
    })
    req.on('error', reject)
    req.end(body)
  })
}

const rpc = (method, params = {}) => JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
const call = (name, args) => rpc('tools/call', { name, arguments: args })
function mcp(id, headers, body) {
  return request(id, { path: '/mcp', method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body })
}
/** The JSON a tool result carries in its text. */
function toolResult(res) {
  const result = JSON.parse(res.text).result
  return { isError: result.isError === true, body: JSON.parse(result.content[0].text) }
}
const placeholderRows = () => Object.keys(vault.db.placeholders).length
const refusals = () => vault.audit.read({ limit: 5000 }).filter((r) => r.rule === 'infinite_remote')

/** Run fn and report what it cost: upstream hits, placeholder rows, C12 audit records. */
async function counted(fn) {
  const hits = seen.length
  const rows = placeholderRows()
  const audited = refusals().length
  const res = await fn()
  return { res, hits: seen.length - hits, minted: placeholderRows() - rows, audited: refusals().length - audited }
}

const REMOTE = ['wild-v4', 'wild-v6']
const LOOPBACK = ['builtin', 'loop-tcp', 'loop-tls']
function each(ids, t, fn) {
  return (async () => {
    for (const id of ids) {
      if (L[id].skip) { t.diagnostic(`skipped ${id}: ${L[id].skip}`); continue }
      await fn(id)
    }
  })()
}

// ------------------------------------------------- /p/ (the control surface)

test('/p/ on a network listener: the infinite token is refused before anything is sent, a finite one works', async (t) => {
  await each(REMOTE, t, async (id) => {
    for (const [name, headers] of [
      ['av-session', { 'av-session': inf.token, authorization: `Bearer ${inf.placeholder}` }],
      ['bearer token', { authorization: `Bearer ${inf.token}` }],
    ]) {
      const { res, hits } = await counted(() => request(id, { path: '/p/up/x', headers }))
      assert.equal(res.status, 403, `${id} ${name}: ${res.text}`)
      assert.equal(JSON.parse(res.text).rule, 'infinite_remote')
      assert.equal(hits, 0)
    }
    for (const [name, headers] of [
      ['placeholder as Bearer', { authorization: `Bearer ${inf.placeholder}` }],
      ['placeholder as Basic', { authorization: `Basic ${Buffer.from(`x:${inf.placeholder}`).toString('base64')}` }],
    ]) {
      const { res, hits } = await counted(() => request(id, { path: '/p/up/x', headers }))
      assert.equal(res.status, 401, `${id} ${name}: ${res.text}`)
      assert.equal(JSON.parse(res.text).rule, 'remote_carrier')
      assert.equal(hits, 0)
    }
    for (const [name, opts] of [
      ['cookie', { path: '/p/up/x', headers: { cookie: `av-session=${inf.token}` } }],
      ['query', { path: `/p/up/x?access_token=${inf.token}` }],
      ['x-api-key', { path: '/p/up/x', headers: { 'x-api-key': inf.token } }],
      ['mcp-session-id', { path: '/p/up/x', headers: { 'mcp-session-id': inf.token } }],
    ]) {
      const { res, hits } = await counted(() => request(id, opts))
      assert.equal(res.status, 401, `${id} ${name}: ${res.text}`)
      assert.equal(hits, 0)
    }
    const { res, hits } = await counted(() => request(id, { path: '/p/up/x', headers: { 'av-session': fin.token, authorization: `Bearer ${fin.placeholder}` } }))
    assert.equal(res.status, 200, `${id} finite: ${res.text}`)
    assert.equal(hits, 1)
    assert.equal(seen.at(-1).headers.authorization, `Bearer ${SECRET}`)
  })
})

// ------------------------------------------------------------------- /mcp

test('/mcp on a network listener: every tool that needs a session refuses the infinite token as AV_REMOTE_FORBIDDEN, sends nothing, mints nothing, and records it', async (t) => {
  await each(REMOTE, t, async (id) => {
    for (const [name, headers] of [
      ['av-session', { 'av-session': inf.token }],
      ['bearer token', { authorization: `Bearer ${inf.token}` }],
      ['both', { 'av-session': inf.token, authorization: `Bearer ${inf.token}` }],
    ]) {
      for (const [tool, args] of [
        ['vault_http', { cred: 'up', method: 'GET', path: '/x' }],
        ['vault_get_placeholder', { cred: 'up', reason: 'c12' }],
        ['vault_list_creds', {}],
        ['vault_approval_status', { approval_id: 'apr_none' }],
      ]) {
        const { res, hits, minted, audited } = await counted(() => mcp(id, headers, call(tool, args)))
        assert.equal(res.status, 200, `${id} ${name} ${tool}: ${res.text}`)
        const r = toolResult(res)
        assert.equal(r.isError, true, `${id} ${name} ${tool} was not an error: ${res.text}`)
        assert.equal(r.body.code, 'AV_REMOTE_FORBIDDEN', `${id} ${name} ${tool}: ${res.text}`)
        assert.equal(r.body.rule, 'infinite_remote')
        assert.ok(!res.text.includes(MARKER) && !res.text.includes(SECRET) && !/av1\./.test(res.text))
        assert.equal(hits, 0, `${id} ${name} ${tool} reached the upstream`)
        assert.equal(minted, 0, `${id} ${name} ${tool} minted a placeholder`)
        assert.equal(audited, 1, `${id} ${name} ${tool}: the refusal was not recorded once`)
      }
    }
    // A placeholder is not a session token, and no token is no session.
    for (const headers of [{ authorization: `Bearer ${inf.placeholder}` }, {}]) {
      const { res, hits, minted } = await counted(() => mcp(id, headers, call('vault_http', { cred: 'up', method: 'GET', path: '/x' })))
      const r = toolResult(res)
      assert.equal(r.isError, true)
      assert.equal(r.body.error, 'this tool needs a live session')
      assert.equal(hits, 0)
      assert.equal(minted, 0)
    }
  })
})

test('/mcp on a network listener: the handshake and the ungated tools treat the infinite token as a dead one', async (t) => {
  await each(REMOTE, t, async (id) => {
    const { res: init, audited } = await counted(() => mcp(id, { authorization: `Bearer ${inf.token}` }, rpc('initialize', { protocolVersion: '2025-06-18' })))
    assert.equal(init.status, 200, init.text)
    assert.equal(init.headers['av-session-invalid'], '1')
    assert.equal(JSON.parse(init.text).result.serverInfo.name, 'agent-vault')
    assert.equal(audited, 0, 'a handshake is not a use and records nothing')
    const { res: asked, audited: statusAudited } = await counted(() => mcp(id, { authorization: `Bearer ${inf.token}` }, call('vault_status', {})))
    assert.equal(statusAudited, 0, 'asking why is not a use and records nothing')
    const status = toolResult(asked)
    assert.equal(status.body.session, null)
    assert.match(status.body.session_problem, /network listener/)
    assert.equal(status.body.credentials_available, 0)
    const explained = toolResult(await mcp(id, { authorization: `Bearer ${inf.token}` }, call('vault_explain_denial', { request_id: 'req_none' })))
    assert.ok(!JSON.stringify(explained.body).includes(inf.session.id))
  })
})

test('/mcp on a network listener: a finite token is unchanged', async (t) => {
  await each(REMOTE, t, async (id) => {
    const headers = { authorization: `Bearer ${fin.token}` }
    const init = await mcp(id, headers, rpc('initialize', { protocolVersion: '2025-06-18' }))
    assert.equal(init.headers['av-session-invalid'], undefined)
    const { res, hits } = await counted(() => mcp(id, headers, call('vault_http', { cred: 'up', method: 'GET', path: '/x' })))
    const r = toolResult(res)
    assert.equal(r.isError, false, res.text)
    assert.equal(r.body.status, 200, res.text)
    assert.equal(r.body.body, MARKER)
    assert.equal(hits, 1)
    assert.equal(seen.at(-1).headers.authorization, `Bearer ${SECRET}`)
    // And the pipeline under it saw the listener it arrived on.
    const row = vault.audit.read({ limit: 5000 }).filter((x) => x.request_id === r.body.request_id && x.peer).at(-1)
    assert.equal(row.peer.listener_id, id)
    const { res: got, minted } = await counted(() => mcp(id, headers, call('vault_get_placeholder', { cred: 'up', reason: 'c12' })))
    assert.match(toolResult(got).body.placeholder, /^av1\./)
    assert.equal(minted, 1)
  })
})

// --------------------------------------------------------------- /v1 discovery

test('/v1 on a network listener: every session route refuses the infinite token with 403 infinite_remote; /v1/status stays open', async (t) => {
  await each(REMOTE, t, async (id) => {
    for (const [name, opts] of [
      ['GET /v1/session', { path: '/v1/session', headers: { 'av-session': inf.token } }],
      ['GET /v1/session (Bearer)', { path: '/v1/session', headers: { authorization: `Bearer ${inf.token}` } }],
      ['GET /v1/credentials', { path: '/v1/credentials', headers: { authorization: `Bearer ${inf.token}` } }],
      ['POST /v1/placeholders', { path: '/v1/placeholders?cred=up', method: 'POST', headers: { 'av-session': inf.token, 'content-type': 'application/json' }, body: '{}' }],
      ['GET /v1/anything-else', { path: '/v1/nope', headers: { 'av-session': inf.token } }],
    ]) {
      const { res, hits, minted, audited } = await counted(() => request(id, opts))
      assert.equal(res.status, 403, `${id} ${name}: ${res.text}`)
      const p = JSON.parse(res.text)
      assert.equal(p.code, 'AV_REMOTE_FORBIDDEN')
      assert.equal(p.rule, 'infinite_remote')
      assert.ok(!res.text.includes(inf.session.id), `${id} ${name} described the session`)
      assert.ok(!/av1\./.test(res.text))
      assert.equal(hits, 0)
      assert.equal(minted, 0, `${id} ${name} minted a placeholder`)
      assert.equal(audited, 1, `${id} ${name}: the refusal was not recorded once`)
    }
    const status = await request(id, { path: '/v1/status', headers: { 'av-session': inf.token } })
    assert.equal(status.status, 200)
  })
})

test('/v1 on a network listener: a finite token is unchanged', async (t) => {
  await each(REMOTE, t, async (id) => {
    const s = await request(id, { path: '/v1/session', headers: { 'av-session': fin.token } })
    assert.equal(s.status, 200, s.text)
    assert.equal(JSON.parse(s.text).id, fin.session.id)
    const c = await request(id, { path: '/v1/credentials', headers: { authorization: `Bearer ${fin.token}` } })
    assert.equal(c.status, 200, c.text)
    assert.equal(JSON.parse(c.text)[0].slug, 'up')
    const { res, minted } = await counted(() => request(id, { path: '/v1/placeholders?cred=up', method: 'POST', headers: { 'av-session': fin.token, 'content-type': 'application/json' }, body: '{}' }))
    assert.equal(res.status, 200, res.text)
    assert.match(JSON.parse(res.text).placeholder, /^av1\./)
    assert.equal(minted, 1)
  })
})

// --------------------------------------------------------------- loopback

test('on loopback (built-in gateway, TCP and TLS listeners) the infinite token works on every surface', async (t) => {
  await each(LOOPBACK, t, async (id) => {
    const p = await counted(() => request(id, { path: '/p/up/x', headers: { 'av-session': inf.token, authorization: `Bearer ${inf.placeholder}` } }))
    assert.equal(p.res.status, 200, `${id} /p/: ${p.res.text}`)
    assert.equal(p.hits, 1)

    const viaMcp = await counted(() => mcp(id, { authorization: `Bearer ${inf.token}` }, call('vault_http', { cred: 'up', method: 'GET', path: '/x' })))
    const r = toolResult(viaMcp.res)
    assert.equal(r.isError, false, `${id} vault_http: ${viaMcp.res.text}`)
    assert.equal(r.body.body, MARKER)
    assert.equal(viaMcp.hits, 1)

    const got = await counted(() => mcp(id, { 'av-session': inf.token }, call('vault_get_placeholder', { cred: 'up', reason: 'c12' })))
    assert.match(toolResult(got.res).body.placeholder, /^av1\./)
    assert.equal(got.minted, 1)

    const s = await request(id, { path: '/v1/session', headers: { 'av-session': inf.token } })
    assert.equal(s.status, 200, `${id} /v1/session: ${s.text}`)
    assert.equal(JSON.parse(s.text).infinite, true)
    const c = await request(id, { path: '/v1/credentials', headers: { authorization: `Bearer ${inf.token}` } })
    assert.equal(c.status, 200)
    const ph = await counted(() => request(id, { path: '/v1/placeholders?cred=up', method: 'POST', headers: { 'av-session': inf.token, 'content-type': 'application/json' }, body: '{}' }))
    assert.equal(ph.res.status, 200, `${id} POST /v1/placeholders: ${ph.res.text}`)
    assert.equal(ph.minted, 1)
    assert.equal(p.audited + viaMcp.audited + got.audited + ph.audited, 0)
  })
})

test('stdio MCP has no network listener and stays loopback for an infinite session', async () => {
  // serveStdio calls handle(message) with no listener: the machine itself.
  const { hits, res } = await counted(() => daemon.mcp.handle(JSON.parse(call('vault_http', { cred: 'up', method: 'GET', path: '/x' })), inf.session, inf.token))
  const body = JSON.parse(res.result.content[0].text)
  assert.equal(res.result.isError, undefined, JSON.stringify(res))
  assert.equal(body.body, MARKER)
  assert.equal(hits, 1)
})

// --------------------------------------------------------- defence in depth

test('vault_http hands its listener to the pipeline, which refuses an infinite session there by itself', async () => {
  // As if a transport resolved the session without asking about the listener:
  // the pipeline under vault_http still asks, because the listener travels
  // with the message to the tool and on into pipeline.handle.
  const listener = { id: 'wild-v4', kind: 'tls', remote: true, advertise: [] }
  const { hits, res } = await counted(() => daemon.mcp.handle(JSON.parse(call('vault_http', { cred: 'up', method: 'GET', path: '/x' })), inf.session, inf.token, listener))
  const body = JSON.parse(res.result.content[0].text)
  assert.equal(body.status, 403, JSON.stringify(body))
  assert.equal(JSON.parse(body.body).rule, 'infinite_remote')
  assert.equal(hits, 0)
  const row = vault.audit.read({ limit: 5000 }).filter((x) => x.request_id === body.request_id).at(-1)
  assert.equal(row.rule, 'infinite_remote')
  assert.equal(row.peer.listener_id, 'wild-v4')
})

test('the vault answers C12 for a peek and for a use alike, and records only the use', () => {
  const remote = { id: 'lan', kind: 'tls', remote: true }
  const before = refusals().length
  assert.throws(() => vault.assertSessionUsable(inf.session, remote, { peek: true }), (e) => e.code === 'AV_REMOTE_FORBIDDEN' && e.rule === 'infinite_remote')
  assert.equal(refusals().length, before)
  assert.throws(() => vault.assertSessionUsable(inf.session, remote), (e) => e.rule === 'infinite_remote')
  assert.equal(refusals().length, before + 1)
  assert.equal(vault.assertSessionUsable(inf.session, null), inf.session)
  assert.equal(vault.assertSessionUsable(inf.session, { id: 'local', kind: 'tcp', remote: false }), inf.session)
  assert.equal(vault.assertSessionUsable(fin.session, remote), fin.session)
  assert.equal(vault.assertSessionUsable(fin.session, remote, { peek: true }), fin.session)
})
