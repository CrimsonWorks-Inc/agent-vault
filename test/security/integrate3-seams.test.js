// Where the three wave-3 branches meet (integrate-3).
//
// control-api, control-ui and control-cli were built at the same time against
// the contract, each with the others' half stood in. These are the places
// where one branch's output is another's input, run on the merged code: the
// MCP tools the docs name, the preview a held request carries to the page,
// C18 on the surfaces control-api added, and what the audit log keeps of an
// agent's session request.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import https from 'node:https'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { McpServer } from '../../src/daemon/mcp.js'
import { tlsPaths } from '../../src/daemon/tls.js'
import { fetchPending } from '../../src/pending.js'
import { startUi } from './fix-control-helpers.js'
import { startApi, SECRET } from './control-api-helpers.js'
import { servedSource, servedConst } from './integrate3-helpers.js'

const README = readFileSync(new URL('../../README.md', import.meta.url), 'utf8')
const PAGE = readFileSync(new URL('../../src/ui/app.html', import.meta.url), 'utf8')
const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve']

test('the README and the docs page say how many MCP tools there are, and it is how many mcp.js has', () => {
  const tools = new McpServer({}, null, () => null).tools.map((t) => t.name)
  const word = WORDS[tools.length]
  assert.ok(word, `${tools.length} tools`)
  // Every sentence that counts the tools, in either document.
  const counts = (text) => [...text.matchAll(/\b(\w+) (?:MCP )?tools\b/gi)].map((m) => m[1].toLowerCase()).filter((w) => WORDS.includes(w))
  assert.deepEqual(counts(README), [word], 'the README counts the tools differently')
  assert.deepEqual(counts(PAGE), [word], 'the docs page counts the tools differently')
  for (const name of tools) {
    assert.ok(README.includes(`\`${name}\``), `the README does not name ${name}`)
    assert.ok(PAGE.includes(`<code>${name}</code>`), `the docs page does not name ${name}`)
  }
})

// --- F13: the preview of a held request ---------------------------------------

/** One gateway request on the daemon's own loopback listener. */
function gateway(port, path, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, agent: false, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }))
    })
    req.on('error', reject)
    req.end(body)
  })
}

test('F13: a held request carries its preview from the gateway through pending.js and the UI server, and the page escapes it', async () => {
  const a = await startApi()
  const u = await startUi(a)
  try {
    const s = a.session({ policy: { approval: 'each' } })
    const hostile = '<img src=x onerror=alert(1)><script>steal()</script>'
    const held = await gateway(a.daemon.gatewayPort, '/p/demo/issues?q=1', {
      method: 'POST',
      headers: { 'av-session': s.token, authorization: `Bearer ${s.placeholder}`, 'content-type': 'application/json' },
      body: JSON.stringify({ title: hostile }),
    })
    assert.equal(held.status, 202, held.text)
    assert.equal(a.seen.length, 0, 'a held request reached the upstream')

    // pending.js, over the real control socket: the item carries the preview.
    const items = await fetchPending(async (path) => (await a.control('GET', path)).body)
    const item = items.find((i) => i.kind === 'request')
    assert.ok(item?.preview, `describe() dropped the preview: ${JSON.stringify(item)}`)
    assert.equal(item.preview.method, 'POST')
    assert.match(item.preview.body.text, /onerror/, 'the preview is not the request that was held')
    // The placeholder rode in the authorization header; the preview does not show it.
    assert.ok(!JSON.stringify(item.preview).includes(s.placeholder), 'the preview shows the placeholder')

    // The same through the UI server, which is what the page paints.
    const viaUi = (await (await u.api('GET', 'pending')).json()).find((i) => i.kind === 'request')
    assert.deepEqual(viaUi.preview.body.text, item.preview.body.text)

    // The served page's own renderer, with its own esc.
    const render = new Function(`${servedConst('esc')}\n${servedConst('UNTRUSTED')}\n${servedSource('function previewBlock(')}\nreturn previewBlock`)()
    const html = render(viaUi.preview, viaUi.id)
    assert.ok(!/<img|<script/i.test(html), 'the page renders the agent\'s markup as markup')
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/)
    assert.match(html, /What it sends/)
  } finally { await u.stop(); await a.stop() }
})

// --- C18 on the surfaces wave 3 added ----------------------------------------------

test('C18: an infinite token is refused on a 0.0.0.0 and a [::] TLS listener by every wave-3 surface, and a finite one works', async (t) => {
  let hits = 0
  const upstream = http.createServer((req, res) => { hits++; req.resume(); res.end('{}') })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const dir = mkdtempSync(join(tmpdir(), 'av-i3c18-'))
  const vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'up', kind: 'http', connector: { host: `127.0.0.1:${upstream.address().port}`, scheme: 'http' },
    fields: { token: 'ghp_I3C18SURFACES0011223344556677' }, sites: { token: ['header:authorization:Bearer'] },
  })
  const session = (infinite) => {
    const made = vault.createSession({ label: infinite ? 'inf' : 'fin', infinite, ttlMs: infinite ? null : 3_600_000 })
    const grant = vault.createGrant({
      sessionId: made.session.id, credentialId: vault.findCredential('up').id, fields: ['token'],
      policy: { hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'auto' },
    })
    return { ...made, placeholder: vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder }
  }
  const inf = session(true)
  const fin = session(false)
  const daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'c.sock') }).start()
  t.after(async () => { await daemon.stop(); await new Promise((resolve) => upstream.close(resolve)); rmSync(dir, { recursive: true, force: true }) })

  const L = {}
  for (const [id, address, host] of [['v4', '0.0.0.0:0', '127.0.0.1'], ['v6', '[::]:0', '::1']]) {
    try {
      L[id] = { port: (await daemon.bindListener({ id, address, surfaces: ['gateway', 'mcp'], tls: { managed: true } })).port, host }
    } catch (e) { L[id] = { skip: e.message } }
  }
  const ca = readFileSync(tlsPaths(dir).cert, 'utf8')
  const request = (id, path, token, body) => new Promise((resolve, reject) => {
    const req = https.request({
      host: L[id].host, port: L[id].port, path, method: 'POST', agent: false, ca, servername: 'localhost',
      headers: { host: 'localhost', authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }))
    })
    req.on('error', reject)
    req.end(JSON.stringify(body))
  })
  if (!L.v6.skip) {
    try { await request('v6', '/v1/preflight', fin.token, {}) } catch (e) { L.v6 = { skip: `::1 is not reachable here: ${e.message}` } }
  }
  assert.ok(!L.v4.skip, `0.0.0.0 must bind: ${L.v4.skip}`)

  const preflight = (id, s) => request(id, '/v1/preflight', s.token, { method: 'GET', path: '/p/up/x', headers: [['authorization', `Bearer ${s.placeholder}`]] })
  const tool = async (id, s, name, args) => {
    const r = await request(id, '/mcp', s.token, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })
    return JSON.parse(JSON.parse(r.text).result.content[0].text)
  }
  for (const id of ['v4', 'v6']) {
    if (L[id].skip) { t.diagnostic(`[${id}] skipped: ${L[id].skip}`); continue }
    const refused = await preflight(id, inf)
    assert.equal(refused.status, 403, `${id} preflight: ${refused.text}`)
    assert.equal(JSON.parse(refused.text).rule, 'infinite_remote')
    assert.equal((await preflight(id, fin)).status, 200, `${id}: a finite session's preflight was refused`)
    for (const [name, args] of [['vault_describe_access', {}], ['vault_preflight', { cred: 'up', method: 'GET', path: '/x' }]]) {
      const r = await tool(id, inf, name, args)
      assert.equal(r.rule, 'infinite_remote', `${id} ${name}: ${JSON.stringify(r)}`)
      const ok = await tool(id, fin, name, args)
      assert.ok(!ok.code, `${id} ${name}: a finite session was refused: ${JSON.stringify(ok)}`)
    }
  }
  assert.equal(hits, 0, 'a preflight or a description reached the upstream')
})

// --- what the audit log keeps of a session request -------------------------------

/** Every audit record, as text. */
const auditText = (a) => JSON.stringify(a.vault.audit.read({ limit: 100_000 }))

test('a stored secret an agent puts in a session request path or reason does not reach the audit log', async () => {
  const a = await startApi()
  try {
    const asked = await a.control('POST', '/v1/session-requests', {
      cred: 'demo', paths: [`/${SECRET}`, '/plain/path'], reason: `please, my token is ${SECRET}`,
    })
    assert.equal(asked.status, 200, JSON.stringify(asked.body))
    const [opened] = a.audit('session_request.opened')
    assert.ok(opened, 'nothing was recorded')
    assert.ok(!auditText(a).includes(SECRET), 'the stored secret is in the audit log')
    assert.ok(!auditText(a).includes(SECRET.slice(0, 12)), 'part of the stored secret is in the audit log')
    assert.match(opened.summary, /\[\[av:redacted:demo\]\]/, 'the summary no longer says something was there')
    assert.match(opened.summary, /\/plain\/path/, 'the summary lost the ordinary path')
    assert.match(opened.agent_reason_untrusted, /^please, my token is \[\[av:redacted:demo\]\]$/)
    // The human still sees the request as asked: only the log is scrubbed.
    assert.ok(a.daemon.sessionRequests.pending()[0].summary.includes(SECRET))
  } finally { await a.stop() }
})

test('an ordinary session request is recorded in the audit log as asked', async () => {
  const a = await startApi()
  try {
    const asked = await a.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET'], paths: ['/repos/**'], reason: 'read the repo list' })
    assert.equal(asked.status, 200, JSON.stringify(asked.body))
    const [opened] = a.audit('session_request.opened')
    assert.equal(opened.summary, a.daemon.sessionRequests.pending()[0].summary)
    assert.match(opened.summary, /\/repos\/\*\*/)
    assert.equal(opened.agent_reason_untrusted, 'read the repo list')
  } finally { await a.stop() }
})

test('with no secrets to scrub against, an agent-written summary is not recorded at all', async () => {
  const a = await startApi()
  try {
    const sr = a.daemon.sessionRequests
    // The store cannot give its secrets (as when it is locked): nothing it
    // could not check is written.
    const allSecrets = a.vault.allSecrets
    a.vault.allSecrets = () => { throw new Error('locked') }
    try { sr.propose({ proposal: { cred: 'demo', paths: [`/${SECRET}`] }, reason: SECRET }) } finally { a.vault.allSecrets = allSecrets }
    const [opened] = a.audit('session_request.opened')
    assert.equal(opened.summary, null)
    assert.equal(opened.agent_reason_untrusted, null)
    assert.ok(!auditText(a).includes(SECRET))
  } finally { await a.stop() }
})
