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
  //
  // These used to be written without the /p/<slug> prefix, so every one of
  // them was an unknown route: the "realistic sequence" was nine 404s, and the
  // tests below passed because a request that never happened cannot leak
  // anything. A test fixture that does not exercise the code it guards is
  // worse than no fixture, because it reads like coverage.
  const P = '/p/prod'
  await gw(`${P}/allowed/thing/with/a/long/path?token=shhh`, { authorization: `Bearer ${placeholder}` })
  await gw(`${P}/forbidden/secret-path-name`, { authorization: `Bearer ${placeholder}` })
  await gw(`${P}/allowed/x`, { authorization: `Bearer ${placeholder}`, 'x-note': placeholder })
  await gw(`${P}/allowed/x`, { authorization: 'Bearer avs1.deadbeefdead.notarealtokenatall' })
  await gw(`${P}/allowed/post`, { authorization: `Bearer ${placeholder}`, 'content-type': 'application/json' },
    'POST', JSON.stringify({ note: BODY_SECRET, password: 'hunter2' }))
  await gw(`${P}/allowed/x`, { authorization: `Bearer ${placeholder}`, 'av-reason': 'because I said so' })
  // A placeholder in the PATH. The path is never a site, so this is denied —
  // and the denial record is the one that carries the path, which makes this
  // the single case guaranteed to offer the log a live placeholder.
  await gw(`${P}/allowed/${placeholder}/x`, { authorization: `Bearer ${placeholder}` })
  await gw(`${P}/allowed/x?key=${encodeURIComponent(SECRET)}`, { authorization: `Bearer ${placeholder}` })
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

test('the log says which resource was reached, not just which rule matched', () => {
  // Under a grant of /allowed/** every record used to carry the same glob, so
  // the log could say a credential had been used forty times and not which
  // forty things it had been used on — the first question anyone asks it.
  const rows = vault.audit.read({ limit: 200 })
  const allowed = rows.filter((r) => r.kind === 'request.allowed')
  assert.ok(allowed.length > 0, 'expected some allowed requests')
  assert.ok(
    allowed.some((r) => r.req?.path?.includes('/allowed/thing/with/a/long/path')),
    'an allowed request did not record the path it reached',
  )
  // And a denial says what was denied, not just that something was.
  const denied = rows.filter((r) => r.decision === 'deny')
  assert.ok(denied.length > 0, 'expected some denials')
  assert.ok(
    denied.some((r) => r.req?.path?.includes('/forbidden/secret-path-name')),
    'a denial did not record what was denied',
  )
  // The query string stays out: that is where credentials appear in a URL.
  const raw = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
  assert.ok(!raw.includes('token=shhh'), 'a query string reached the audit log')
  assert.ok(!raw.includes('key='), 'a query string reached the audit log')
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

test('cutting the end off the log is detected, and cannot be quietly continued', () => {
  // The chain proves no record was edited or removed from the MIDDLE, because
  // every later hash stops matching. It proves nothing about the end: delete
  // the last fifty lines and what remains verifies perfectly, first record to
  // last. The records anyone would want gone are always the most recent ones,
  // so that is the whole attack, and it needs no key and no cleverness.
  //
  // Worse, the daemon used to resume from whatever the file ended with — so
  // the next write continued the chain from the truncated point and the log
  // became permanently self-consistent at its shorter length.
  const fresh = mkdtempSync(join(tmpdir(), 'av-trunc-'))
  try {
    const v = Vault.create(fresh, { factor: 'none' })
    for (let i = 0; i < 12; i++) v.audit.write('test.event', { n: i })
    assert.equal(v.audit.verify().ok, true)
    const full = v.audit.verify().count

    const path = join(fresh, 'audit.jsonl')
    const lines = readFileSync(path, 'utf8').trimEnd().split('\n')
    writeFileSync(path, `${lines.slice(0, -5).join('\n')}\n`)

    // The chain alone still walks cleanly. That is the point.
    const reopened = Vault.open(fresh)
    reopened.unlockWith({})
    const v2 = reopened.audit.verify()
    assert.equal(v2.ok, false, 'a truncated log must not verify')
    assert.match(v2.reason, /removed from the end/)

    // And the evidence survives the daemon continuing to write, rather than
    // being overwritten by the next record.
    const kinds = reopened.audit.read({ limit: 50 }).map((r) => r.kind)
    assert.ok(kinds.includes('audit.truncation_detected'), 'the gap must be recorded in the log itself')
    const noted = reopened.audit.read({ limit: 50 }).find((r) => r.kind === 'audit.truncation_detected')
    assert.equal(noted.expected_seq, full)
    assert.equal(noted.found_seq, full - 5)
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('emptying the log entirely is detected too', () => {
  // The loudest version of the same attack, and the one a chain walk can say
  // nothing at all about: there is nothing left to walk.
  const fresh = mkdtempSync(join(tmpdir(), 'av-empty-'))
  try {
    const v = Vault.create(fresh, { factor: 'none' })
    for (let i = 0; i < 6; i++) v.audit.write('test.event', { n: i })
    writeFileSync(join(fresh, 'audit.jsonl'), '')

    const reopened = Vault.open(fresh)
    reopened.unlockWith({})
    assert.equal(reopened.audit.verify().ok, false, 'an emptied log must not verify')
    assert.ok(
      reopened.audit.read({ limit: 10 }).some((r) => r.kind === 'audit.truncation_detected'),
      'and the daemon must say so in the log it starts over with',
    )
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('losing the anchor is reported rather than assumed harmless', () => {
  // Removing the anchor is the natural next move once truncation is caught, so
  // its absence has to be a finding in itself. It cannot be forged: the head
  // is authenticated under K_audit, which lives behind the uid boundary.
  const fresh = mkdtempSync(join(tmpdir(), 'av-anchor-'))
  try {
    const v = Vault.create(fresh, { factor: 'none' })
    v.audit.write('test.event', {})
    rmSync(join(fresh, 'audit.jsonl.head'))
    const reopened = Vault.open(fresh)
    reopened.unlockWith({})
    const res = reopened.audit.verify()
    assert.equal(res.ok, false)
    assert.match(res.reason, /anchor/)
    assert.ok(
      reopened.audit.read({ limit: 10 }).some((r) => r.kind === 'audit.anchor_missing'),
      'and it must be recorded, so deleting the anchor again does not clear it',
    )
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('a normal restart is not mistaken for tampering', () => {
  // The fail-closed direction is worthless if it fires on ordinary use. Stop
  // and start a vault repeatedly and the log must stay clean.
  const fresh = mkdtempSync(join(tmpdir(), 'av-restart-'))
  try {
    let v = Vault.create(fresh, { factor: 'none' })
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 5; i++) v.audit.write('test.event', { round, i })
      v = Vault.open(fresh)
      v.unlockWith({})
      const res = v.audit.verify()
      assert.equal(res.ok, true, `restart ${round}: ${res.reason}`)
    }
    assert.equal(
      v.audit.read({ limit: 100 }).some((r) => r.kind === 'audit.truncation_detected'), false,
      'a clean restart must not be recorded as a truncation',
    )
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})
