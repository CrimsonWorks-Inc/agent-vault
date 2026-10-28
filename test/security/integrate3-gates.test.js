// What the page signs is what the daemon checks (contract 0.5, C19, C22(4)).
//
// Every change the page can make is signed over an operation the page builds
// itself, in the browser, with WebCrypto. The UI server rebuilds it from the
// request and compares; for the routes in DAEMON_VERIFIED the daemon rebuilds
// it again from what reaches it and verifies the same signature. Three
// builders, one operation. The wave-3 branches each tested their side against
// a stand-in, so here every gated UI route runs end to end: the served page's
// own operationFor, the real UI server, the real daemon.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { operationFor, canonicalOperation, DIGESTED } from '../../src/ui/webauthn.js'
import { UiServer } from '../../src/ui/server.js'
import { signed, PASSPHRASE } from './fix-control-helpers.js'
import { servedPageSigning, startSigned } from './integrate3-helpers.js'

const page = servedPageSigning()

/**
 * A control call with an explicit length. The shared helper lets Node chunk
 * the body, and the daemon answers a chunked DELETE with a bare 400.
 */
function del(sock, path, body) {
  const method = 'DELETE'
  const payload = Buffer.from(JSON.stringify(body ?? {}))
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath: sock, path, method, headers: { 'content-type': 'application/json', 'content-length': payload.length } }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') }))
    })
    req.on('error', reject)
    req.end(payload)
  })
}

/** Refused for want of a valid signature: the daemon's answer to a swapped operation. */
const refusedUnsigned = (r) => r.status === 401 && r.body.code === 'AV_PRESENCE_REQUIRED'
const PIN_A = `sha256/${'A'.repeat(43)}=`
const PIN_B = `sha256/${'B'.repeat(43)}=`

test('C19: the page, webauthn.js and so the daemon digest every secret-bearing key the same way', async () => {
  const bundle = { version: 1, kdf: { n: 16384, salt: 'c2FsdA' }, sealed: 'Zm9v', credentials: [{ slug: 'demo', n: 1 }] }
  const reordered = { credentials: [{ n: 1, slug: 'demo' }], sealed: 'Zm9v', kdf: { salt: 'c2FsdA', n: 16384 }, version: 1 }
  const values = ['ghp_STRINGVALUE001122', '', 'true', 42, true, null, ['a', { b: 1 }], bundle]
  for (const key of DIGESTED) {
    for (const v of values) {
      const params = { slug: 'demo', [key]: v }
      assert.equal(canonicalOperation(await page.operationFor('cred.test_op', params)), canonicalOperation(operationFor('cred.test_op', params)),
        `${key} = ${JSON.stringify(v)}`)
    }
  }
  // The page's list is the servers' list.
  const pageKeys = Object.keys(await page.operationFor('x', Object.fromEntries([...DIGESTED].map((k) => [k, 's']))))
  assert.deepEqual(pageKeys.filter((k) => k.endsWith('_sha256')).sort(), [...DIGESTED].map((k) => `${k}_sha256`).sort())
  // Two bundles differ; one bundle with its keys reordered does not.
  const a = await page.operationFor('backup.restore', { bundle })
  assert.equal(a.bundle_sha256, (await page.operationFor('backup.restore', { bundle: reordered })).bundle_sha256)
  assert.notEqual(a.bundle_sha256, (await page.operationFor('backup.restore', { bundle: { ...bundle, sealed: 'YmFy' } })).bundle_sha256)
  assert.notEqual(a.bundle_sha256, (await page.operationFor('backup.restore', { bundle: '[object Object]' })).bundle_sha256)
})

/** A local upstream that counts what reaches it, so an approved request goes nowhere real. */
async function upstream() {
  const seen = []
  const server = http.createServer((req, res) => {
    req.resume()
    req.on('end', () => { seen.push(`${req.method} ${req.url}`); res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}') })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { seen, port: server.address().port, stop: () => new Promise((resolve) => server.close(resolve)) }
}

/**
 * One gated change through the UI, as the page makes it: build the operation
 * with the served page's builder over what is sent (the body, or the query of
 * a DELETE), sign it through the UI, send it.
 */
async function change(t, { method, path, op, bind, body = {} }) {
  const operation = await page.operationFor(op, bind ?? body)
  const presence = await t.u.presence(t.auth, operation)
  // A locked vault has no audit log open, so after `lock` there is nothing to count.
  const count = () => (t.d.vault.audit?.read({ limit: 100_000 }) ?? []).filter((r) => r.kind === 'presence.verified').length
  const verifiedBefore = count()
  const res = await t.u.api(method, path, { ...body, presence })
  const answer = await res.json()
  const verified = count() - verifiedBefore
  return { status: res.status, answer, verified, operation }
}

test('every gated UI route: the operation the page signs is the one the UI server and the real daemon rebuild', async () => {
  const up = await upstream()
  const t = await startSigned({ passphrase: PASSPHRASE, host: `127.0.0.1:${up.port}`, scheme: 'http' })
  try {
    const { vault, daemon, control } = t.d
    vault.addCredential({ slug: 'spare', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' }, fields: { token: 'ghp_SPARE0011223344556677889900aa' }, sites: { token: ['header:authorization:Bearer'] } })
    vault.addCredential({ slug: 'pinned', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' }, fields: { token: 'ghp_PINNED0011223344556677889900a' }, sites: { token: ['header:authorization:Bearer'] } })
    vault.setPins('pinned', 'api.example.com', [PIN_A, PIN_B])

    const seen = new Set()
    const daemonChecked = []
    const expect = async (c, check = () => {}) => {
      const key = `${c.method} ${c.path.split('?')[0]}`
      seen.add(key)
      const r = await change(t, c)
      // 409: the UI server rebuilt another operation. 403: the daemon did.
      assert.equal(r.status, 200, `${key}: ${JSON.stringify(r.answer)}`)
      if (UiServer.DAEMON_VERIFIED.has(key)) assert.ok(r.verified >= 1, `${key}: the daemon did not verify the signature itself`)
      else daemonChecked.push(...(r.verified ? [key] : []))
      check(r.answer)
      return r.answer
    }

    // Credentials.
    await expect({ method: 'POST', path: 'credentials', op: 'cred.add', body: { slug: 'added', kind: 'http', value: 'ghp_ADDED00112233445566778899aabb', host: 'api.example.com' } })
    assert.ok(vault.findCredential('added'))
    await expect({ method: 'POST', path: 'credentials/rotate', op: 'cred.rotate', body: { slug: 'spare', value: 'ghp_ROTATED0011223344556677889900', mode: 'keep', retire_hours: 1 } })
    const scrub = await expect({ method: 'POST', path: 'credentials/scrub', op: 'cred.scrub_add', body: { slug: 'spare', pattern: 'acme_[A-Za-z0-9]{20}', sample: 'token acme_abcdefghijklmnopqrst' } })
    const sid = scrub.id ?? scrub.pattern?.id
    assert.ok(sid, JSON.stringify(scrub))
    await expect({ method: 'DELETE', path: `credentials/scrub?slug=spare&id=${encodeURIComponent(sid)}`, op: 'cred.scrub_remove', bind: { slug: 'spare', id: sid } })
    await expect({ method: 'POST', path: 'credentials/expiry', op: 'cred.expiry_set', body: { slug: 'spare', expires_at: '2031-01-31T00:00:00.000Z' } })
    assert.equal((await control('POST', '/v1/credentials/quarantine', { slug: 'spare' })).status, 200)
    await expect({ method: 'POST', path: 'credentials/release', op: 'cred.release', body: { slug: 'spare' } })
    assert.ok(!vault.findCredential('spare').quarantine)

    // C22(4): one pin, then every pin for the host. spki is bound as null when absent.
    await expect({ method: 'DELETE', path: `credentials/pins?slug=pinned&host=api.example.com&spki=${encodeURIComponent(PIN_A)}`, op: 'cred.pins_remove', bind: { slug: 'pinned', host: 'api.example.com', spki: PIN_A } })
    assert.deepEqual(vault.findCredential('pinned').pins['api.example.com'], [PIN_B])
    await expect({ method: 'DELETE', path: 'credentials/pins?slug=pinned&host=api.example.com', op: 'cred.pins_remove', bind: { slug: 'pinned', host: 'api.example.com', spki: null } })
    assert.ok(!(vault.findCredential('pinned').pins?.['api.example.com']?.length), 'the pins are still there')

    // Templates and tripwires.
    await expect({ method: 'POST', path: 'templates', op: 'template.save', body: { name: 'gh-read', spec: { cred: 'demo', methods: ['GET'], paths: ['/repos/**'] } } })
    await expect({ method: 'DELETE', path: 'templates?name=gh-read', op: 'template.delete', bind: { name: 'gh-read' } })
    await expect({ method: 'POST', path: 'tripwires', op: 'tripwires.set', body: { enabled: false } })

    // Sessions: create, narrow, revoke.
    const made = await expect({ method: 'POST', path: 'sessions', op: 'session.create', body: { cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], approval: 'each', ttl_hours: 1 } })
    await expect({ method: 'POST', path: 'sessions/narrow', op: 'session.narrow', body: { sid: made.session_id, narrow: { methods: ['POST'] } } })

    // A held write, answered from the page; the replay reaches only the local upstream.
    const held = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: daemon.gatewayPort, path: '/p/demo/things', method: 'POST', headers: { 'av-session': made.token, authorization: `Bearer ${made.placeholder}`, 'content-type': 'application/json' } }, (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') }))
      })
      req.on('error', reject)
      req.end('{"a":1}')
    })
    assert.equal(held.status, 202, JSON.stringify(held.body))
    const approvalId = (await control('GET', '/v1/approvals')).body[0]?.id
    assert.ok(approvalId)
    await expect({ method: 'POST', path: 'approvals', op: 'approval.approve', body: { id: approvalId, granted: true } })

    // Session requests: one decision, and several in one act of presence.
    const ask = async () => (await control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET'], paths: ['/**'], reason: 'x' })).body
    const one = await ask()
    await expect({ method: 'POST', path: 'session-requests/decide', op: 'session_request.decide', body: { id: one.request_id ?? one.id, granted: false } })
    const two = await ask()
    await expect({ method: 'POST', path: 'pending/decide-many', op: 'pending.decide_many', body: { decisions: [{ kind: 'session', id: two.request_id ?? two.id, granted: false }] } })

    await expect({ method: 'DELETE', path: `sessions?sid=${encodeURIComponent(made.session_id)}`, op: 'session.revoke', bind: { sid: made.session_id } })
    await expect({ method: 'DELETE', path: 'credentials?slug=added', op: 'cred.remove', bind: { slug: 'added' } })

    // Touch ID unlock (prf_secret is digested), then its removal.
    await expect({ method: 'POST', path: 'touchid/enroll', op: 'touchid.enroll', body: { credential_id: t.auth.record.credentialId, prf_secret: Buffer.alloc(32, 7).toString('base64') } })
    await expect({ method: 'POST', path: 'touchid/remove', op: 'touchid.remove', body: {} })

    // Last, because nothing works after it.
    await expect({ method: 'POST', path: 'lock', op: 'vault.lock', body: {} })
    assert.ok(vault.locked)

    // Every gated route was driven here, except the presence-key rotation,
    // which control-ui-rotate.test.js runs against the real daemon.
    const missed = [...UiServer.GATED].filter((k) => !seen.has(k) && k !== 'POST presence/rotate')
    assert.deepEqual(missed, [], 'a gated UI route is not covered end to end')
    // A route the daemon verifies for itself belongs in DAEMON_VERIFIED. These
    // four predate wave 3 and are verified by the daemon all the same (noted in
    // the control-ui review); no wave-3 route may join them.
    assert.deepEqual(daemonChecked.sort(), ['POST approvals', 'POST lock', 'POST touchid/enroll', 'POST touchid/remove'])
  } finally { await t.stop(); await up.stop() }
})

test('C22(4): a pin removal signed without spki, or for another spki, is refused by the UI and by the daemon', async () => {
  const t = await startSigned()
  try {
    const { vault, control } = t.d
    vault.addCredential({ slug: 'pinned', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' }, fields: { token: 'ghp_PINNED0011223344556677889900a' }, sites: { token: ['header:authorization:Bearer'] } })
    vault.setPins('pinned', 'api.example.com', [PIN_A, PIN_B])
    const all = 'credentials/pins?slug=pinned&host=api.example.com'
    // Signed with spki omitted, which is not what the daemon binds.
    let presence = await t.u.presence(t.auth, operationFor('cred.pins_remove', { slug: 'pinned', host: 'api.example.com' }))
    assert.equal((await t.u.api('DELETE', all, { presence })).status, 409)
    // Signed for one pin, sent for all of them.
    presence = await t.u.presence(t.auth, await page.operationFor('cred.pins_remove', { slug: 'pinned', host: 'api.example.com', spki: PIN_A }))
    assert.equal((await t.u.api('DELETE', all, { presence })).status, 409)
    // The daemon refuses the same swap on its own socket.
    presence = await signed(control, t.auth, operationFor('cred.pins_remove', { slug: 'pinned', host: 'api.example.com', spki: PIN_A }))
    let r = await del(t.d.sock, '/v1/credentials/pins?slug=pinned&host=api.example.com', { presence })
    assert.ok(refusedUnsigned(r), JSON.stringify(r))
    presence = await signed(control, t.auth, operationFor('cred.pins_remove', { slug: 'pinned', host: 'api.example.com' }))
    r = await del(t.d.sock, '/v1/credentials/pins?slug=pinned&host=api.example.com', { presence })
    assert.ok(refusedUnsigned(r), JSON.stringify(r))
    assert.deepEqual(vault.findCredential('pinned').pins['api.example.com'], [PIN_A, PIN_B], 'a pin was removed')
  } finally { await t.stop() }
})

test('C19 end to end: a backup bundle is bound by its canonical digest when the daemon restores it', async () => {
  const t = await startSigned({ passphrase: PASSPHRASE })
  try {
    const { control, auth } = { control: t.d.control, auth: t.auth }
    const recovery = 'integrate three recovery words'
    let presence = await signed(control, auth, await page.operationFor('backup.export', { recovery_passphrase: recovery }))
    const exported = await control('POST', '/v1/backup/export', { recovery_passphrase: recovery, presence })
    assert.equal(exported.status, 200, JSON.stringify(exported.body))
    const bundle = exported.body.bundle ?? exported.body
    assert.equal(typeof bundle, 'object')

    // Signed over another bundle: refused.
    const other = { ...bundle, integrate3: 'not this one' }
    presence = await signed(control, auth, await page.operationFor('backup.restore', { bundle: other, recovery_passphrase: recovery, on_conflict: 'rename' }))
    let r = await control('POST', '/v1/backup/restore', { bundle, recovery_passphrase: recovery, on_conflict: 'rename', presence })
    assert.ok(refusedUnsigned(r), JSON.stringify(r))

    // Signed by the page over this bundle with its keys in another order: the same operation, accepted.
    const reordered = Object.fromEntries(Object.entries(bundle).reverse())
    presence = await signed(control, auth, await page.operationFor('backup.restore', { bundle: reordered, recovery_passphrase: recovery, on_conflict: 'rename' }))
    r = await control('POST', '/v1/backup/restore', { bundle, recovery_passphrase: recovery, on_conflict: 'rename', presence })
    assert.equal(r.status, 200, JSON.stringify(r.body))
  } finally { await t.stop() }
})

test('C19 end to end: a webhook URL is bound by digest, and the page signs what the daemon checks', async () => {
  const t = await startSigned()
  try {
    const url = 'https://hooks.example.com/services/T000/B000/integrate3secret'
    let presence = await signed(t.d.control, t.auth, await page.operationFor('notify.set', { webhook_url: 'https://hooks.example.com/other', detail: 'minimal' }))
    let r = await t.d.control('POST', '/v1/notify', { webhook_url: url, detail: 'minimal', presence })
    assert.ok(refusedUnsigned(r), JSON.stringify(r))
    const op = await page.operationFor('notify.set', { webhook_url: url, detail: 'minimal' })
    assert.ok(!JSON.stringify(op).includes('integrate3secret'), 'the webhook URL is in the signed operation in clear')
    presence = await signed(t.d.control, t.auth, op)
    r = await t.d.control('POST', '/v1/notify', { webhook_url: url, detail: 'minimal', presence })
    assert.equal(r.status, 200, JSON.stringify(r.body))
  } finally { await t.stop() }
})
