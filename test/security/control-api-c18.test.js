// C18 on every wave-3 surface that resolves a session. Each asks the vault
// one question, assertSessionUsable(session, listener), with the listener the
// request really arrived on: the gateway's POST /v1/preflight, and the MCP
// tools vault_describe_access and vault_preflight. An infinite session's
// token on a TLS listener bound to 0.0.0.0 is refused on each, and a finite
// one works. The approval stream on the control socket resolves no session
// at all (C20); control-api-notify.test.js shows a token sent to it is
// ignored.
//
// A real daemon with real listeners, as in integrate2-c12-surfaces.test.js,
// plus the tools called in process with a remote listener, so each tool's own
// check is tested and not only the HTTP endpoint's in front of it.

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

const SECRET = 'ghp_C18SURFACES00112233445566778899aabb'
const HOUR = 3_600_000
let dir, vault, daemon, ca, upstream, hits = 0
const L = {}
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
  upstream = http.createServer((req, res) => { hits++; res.end('{}') })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  dir = mkdtempSync(join(tmpdir(), 'av-c18-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'up', kind: 'http', connector: { host: `127.0.0.1:${upstream.address().port}`, scheme: 'http' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  inf = session('infinite', true)
  fin = session('finite', false)
  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'c.sock') }).start()
  for (const [id, address, tls] of [['wild', '0.0.0.0:0', true], ['loop', '127.0.0.1:0', true]]) {
    const bound = await daemon.bindListener({ id, address, surfaces: ['gateway', 'mcp'], tls: { managed: true } })
    L[id] = { port: bound.port, tls }
  }
  ca = readFileSync(tlsPaths(dir).cert, 'utf8')
})

after(async () => {
  await daemon?.stop()
  await new Promise((resolve) => upstream.close(resolve))
  rmSync(dir, { recursive: true, force: true })
})

function request(id, { path, method = 'GET', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: '127.0.0.1', port: L[id].port, path, method, agent: false, ca, servername: 'localhost',
      headers: { host: 'localhost', ...headers },
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString()
        let json = null
        try { json = JSON.parse(text) } catch { /* not JSON */ }
        resolve({ status: res.statusCode, text, json })
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

const preflight = (id, s) => request(id, {
  path: '/v1/preflight', method: 'POST',
  headers: { authorization: `Bearer ${s.token}`, 'content-type': 'application/json' },
  body: JSON.stringify({ method: 'GET', path: '/p/up/x', headers: [['authorization', `Bearer ${s.placeholder}`]] }),
})

function toolOver(id, s, name, args) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })
  return request(id, { path: '/mcp', method: 'POST', headers: { authorization: `Bearer ${s.token}`, 'content-type': 'application/json' }, body })
    .then((r) => JSON.parse(JSON.parse(r.text).result.content[0].text))
}

/** The tool called in process, as a message that arrived on `listener`. */
async function toolIn(s, name, args, listener) {
  const r = await daemon.mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }, s.session, s.token, listener)
  return JSON.parse(r.result.content[0].text)
}
const REMOTE = { id: 'wild', kind: 'tls', remote: true, advertise: [] }

test('gateway POST /v1/preflight: an infinite token on a network listener is refused, a finite one works (C18)', async () => {
  const before = hits
  const refused = await preflight('wild', inf)
  assert.equal(refused.status, 403, refused.text)
  assert.equal(refused.json.code, 'AV_REMOTE_FORBIDDEN')
  assert.equal(refused.json.rule, 'infinite_remote')
  const finite = await preflight('wild', fin)
  assert.equal(finite.status, 200, finite.text)
  assert.equal(finite.json.would, 'allow')
  // On loopback the infinite session is the machine's own.
  const local = await preflight('loop', inf)
  assert.equal(local.status, 200, local.text)
  assert.equal(hits, before, 'a preflight reached the upstream')
})

test('MCP vault_describe_access: refused for an infinite session on a network listener, over HTTP and in the tool itself (C18)', async () => {
  const over = await toolOver('wild', inf, 'vault_describe_access', {})
  assert.equal(over.code, 'AV_REMOTE_FORBIDDEN', JSON.stringify(over))
  const inTool = await toolIn(inf, 'vault_describe_access', {}, REMOTE)
  assert.equal(inTool.code, 'AV_REMOTE_FORBIDDEN', JSON.stringify(inTool))
  assert.equal(inTool.rule, 'infinite_remote')
  const finite = await toolOver('wild', fin, 'vault_describe_access', {})
  assert.equal(finite.session.id, fin.session.id, JSON.stringify(finite))
  assert.equal((await toolIn(fin, 'vault_describe_access', {}, REMOTE)).session.id, fin.session.id)
  assert.equal((await toolIn(inf, 'vault_describe_access', {}, null)).session.infinite, true)
})

test('MCP vault_preflight: refused for an infinite session on a network listener, over HTTP and in the tool itself (C18)', async () => {
  const args = { cred: 'up', method: 'GET', path: '/x' }
  const over = await toolOver('wild', inf, 'vault_preflight', args)
  assert.equal(over.code, 'AV_REMOTE_FORBIDDEN', JSON.stringify(over))
  const inTool = await toolIn(inf, 'vault_preflight', args, REMOTE)
  assert.equal(inTool.code, 'AV_REMOTE_FORBIDDEN', JSON.stringify(inTool))
  const finite = await toolOver('wild', fin, 'vault_preflight', args)
  assert.equal(finite.would, 'allow', JSON.stringify(finite))
  assert.equal((await toolIn(fin, 'vault_preflight', args, REMOTE)).would, 'allow')
  assert.equal((await toolIn(inf, 'vault_preflight', args, null)).would, 'allow')
})

test('a refused peek records nothing and changes nothing', async () => {
  const records = vault.audit.read({ limit: 100_000 }).length
  const seenAt = vault.db.sessions[inf.session.id].last_seen_at
  await toolIn(inf, 'vault_describe_access', {}, REMOTE)
  await toolIn(inf, 'vault_preflight', { cred: 'up', method: 'GET', path: '/x' }, REMOTE)
  assert.equal(vault.audit.read({ limit: 100_000 }).length, records)
  assert.equal(vault.db.sessions[inf.session.id].last_seen_at, seenAt)
  assert.equal(vault.db.sessions[inf.session.id].state, 'active')
})
