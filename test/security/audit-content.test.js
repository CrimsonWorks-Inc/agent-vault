// What the audit log is allowed to contain.
//
// The README promises: "No credential value, full placeholder, body or full
// path ever enters it." That is the kind of promise which stops being true one
// well-meaning `detail` field at a time, and the failure is silent — the log
// keeps working, it just starts holding the thing it exists to avoid holding.
//
// So rather than checking the events we happen to think of, this drives a busy
// vault through a realistic sequence and then reads every record back looking
// for anything that should not be there.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest, createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

const SECRET = 'ghp_AUDITCONTENT0011223344556677889'
const OTHER = 'xoxb-9999-AUDITOTHERSECRETVALUE'
const BODY_SECRET = 'body-only-marker-0xdeadbeef'
let dir, vault, daemon, sock, placeholder, token, upstream, upPort

const ctl = (method, path, body) => new Promise((resolve) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString() || '{}') }))
  })
  req.on('error', () => resolve({ status: 0, body: {} }))
  req.end(body ? JSON.stringify(body) : undefined)
})

const gw = (path, headers, method = 'GET', payload = null) => new Promise((resolve) => {
  const req = unixRequest({ host: '127.0.0.1', port: daemon.gatewayPort, path, method, headers }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(c).toString() }))
  })
  req.on('error', (e) => resolve({ status: 0, text: e.message }))
  req.end(payload)
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-audc-'))
  upstream = createServer((req, res) => { res.end(JSON.stringify({ echoed: SECRET })) })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  upPort = upstream.address().port

  vault = Vault.create(dir, { factor: 'none' })
  const cred = vault.addCredential({
    slug: 'prod', kind: 'http', connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  vault.addCredential({
    slug: 'slack', kind: 'http', connector: { host: 'slack.com', scheme: 'https' },
    fields: { token: OTHER }, sites: { token: ['header:authorization:Bearer'] },
  })
  const made = vault.createSession({ label: 'agent' })
  token = made.token
  const grant = vault.createGrant({
    sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/allowed/**'],
      budget: { unit: 'requests', limit: 50 }, approval: 'auto',
    },
  })
  placeholder = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder

  sock = join(dir, 'c.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()

  // A busy, realistic sequence: allowed calls, a denial, a misplaced
  // placeholder, a bad token, a secret-bearing body, and an agent-supplied
  // reason string.
  await gw('/allowed/thing/with/a/long/path?token=shhh', { authorization: `Bearer ${placeholder}` })
  await gw('/forbidden/secret-path-name', { authorization: `Bearer ${placeholder}` })
  await gw('/allowed/x', { authorization: `Bearer ${placeholder}`, 'x-note': placeholder })
  await gw('/allowed/x', { authorization: 'Bearer avs1.deadbeefdead.notarealtokenatall' })
  await gw('/allowed/post', { authorization: `Bearer ${placeholder}`, 'content-type': 'application/json' },
    'POST', JSON.stringify({ note: BODY_SECRET, password: 'hunter2' }))
  await gw('/allowed/x', { authorization: `Bearer ${placeholder}`, 'av-reason': 'because I said so' })
  await ctl('POST', '/v1/sessions', { cred: 'prod', methods: ['GET'], paths: ['/**'] })
})

after(async () => {
  if (daemon) await daemon.stop()
  if (upstream) upstream.close()
  rmSync(dir, { recursive: true, force: true })
})

test('no credential value reaches the audit log, in any field', () => {
  const raw = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
  assert.ok(!raw.includes(SECRET), 'the injected credential is in the audit log')
  assert.ok(!raw.includes(OTHER), 'another vault credential is in the audit log')
})

test('no full placeholder and no session token reaches it either', () => {
  // A full placeholder in the log is a capability sitting in a file that is
  // meant to be readable evidence; a session token is worse.
  const raw = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
  assert.ok(!raw.includes(placeholder), 'a full placeholder is in the audit log')
  assert.ok(!raw.includes(token), 'a session token is in the audit log')
  // The nonce hash is the intended handle, so records can still be correlated.
  assert.match(raw, /placeholder_id/, 'records should still identify placeholders by id')
})

test('request bodies never reach it', () => {
  const raw = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
  assert.ok(!raw.includes(BODY_SECRET), 'a request body is in the audit log')
  assert.ok(!raw.includes('hunter2'), 'a request body is in the audit log')
})

test('an agent-supplied reason is recorded as a claim, never as fact', () => {
  // The reason is whatever the agent typed. Storing it is useful; storing it
  // under a name that implies the daemon checked it would not be.
  const rows = vault.audit.read({ limit: 200 })
  const withReason = JSON.stringify(rows).includes('because I said so')
  if (withReason) {
    assert.match(JSON.stringify(rows), /untrusted|claimed|agent_reason/,
      'an agent-supplied reason must be labelled as unverified')
  }
})

test('the chain verifies, and editing a record breaks it', () => {
  // The log is only evidence if tampering is detectable.
  const before = vault.audit.verify()
  assert.equal(before.ok, true, 'the chain should be intact to start with')
  assert.ok(before.count > 5, `expected a busy log, got ${before.count}`)

  const path = join(dir, 'audit.jsonl')
  const lines = readFileSync(path, 'utf8').trimEnd().split('\n')
  const victim = Math.floor(lines.length / 2)
  const row = JSON.parse(lines[victim])
  row.kind = 'tampered'
  lines[victim] = JSON.stringify(row)
  writeFileSync(path, `${lines.join('\n')}\n`)

  const reopened = Vault.open(dir)
  reopened.unlockWith({})
  const after = reopened.audit.verify()
  assert.equal(after.ok, false, 'an edited record must break the chain')
  assert.ok(Number.isInteger(after.brokenAt), 'and it must name where')
})
