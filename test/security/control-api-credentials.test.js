// Credential-record routes after wave 3. Every write to a credential record
// needs a human (0.3): rotation (F7), scrub patterns (F4), expiry (F10), pins
// (F11) and releasing a quarantine (F16). Two are open on purpose: the
// throttled read-only probe (F12), and quarantine (F16), which only stops
// things and has to work in an emergency.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { startApi, PASSPHRASE, SECRET } from './control-api-helpers.js'

const PIN = `sha256/${'A'.repeat(43)}=`
const NEW_VALUE = 'ghp_ROTATEDVALUE99887766554433221100aa'

const refusedForPresence = (r, what) => {
  assert.equal(r.status, 401, `${what}: ${JSON.stringify(r.body)}`)
  assert.equal(r.body.code, 'AV_PRESENCE_REQUIRED', what)
}

// ------------------------------------------------------------ F7 rotate

test('rotating needs a human; once rotated, the next request carries the new value', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const s = a.session()
    refusedForPresence(await a.control('POST', '/v1/credentials/rotate', { slug: 'demo', value: NEW_VALUE }), 'rotate')
    assert.equal(a.vault.revealField(a.vault.findCredential('demo').id, 'token'), SECRET, 'refused, yet rotated')
    a.openWindow()
    const r = await a.control('POST', '/v1/credentials/rotate', { slug: 'demo', value: NEW_VALUE, retire_hours: 2 })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.rotated.version, 2)
    assert.equal(r.body.rotated.mode, 'keep')
    assert.equal(r.body.invalidated_approvals, 0)
    assert.ok(!JSON.stringify(r.body).includes(NEW_VALUE), 'the value came back')
    assert.ok(!JSON.stringify(a.audit()).includes(NEW_VALUE), 'the value is in the audit log')
    a.seen.length = 0
    const res = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(res.status, 200, res.text)
    assert.equal(a.seen[0].headers.authorization, `Bearer ${NEW_VALUE}`)
  } finally { await a.stop() }
})

test('rotating denies the held requests a human approved against the old key', async () => {
  const a = await startApi()
  try {
    const s = a.session({ policy: { approval: 'each' } })
    const held = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(held.status, 202, held.text)
    const r = await a.control('POST', '/v1/credentials/rotate', { slug: 'demo', value: NEW_VALUE })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.invalidated_approvals, 1)
    assert.equal(a.daemon.pipeline.pendingApprovals().length, 0)
    assert.ok(a.audit('approval.denied').some((x) => x.reason === 'credential_rotated'))
  } finally { await a.stop() }
})

test('a rotation it cannot read is refused, and changes nothing', async () => {
  const a = await startApi()
  try {
    for (const [body, rule] of [
      [{ slug: 'demo', value: NEW_VALUE, retire_hours: 169 }, 'retire_window'],
      [{ slug: 'demo', value: NEW_VALUE, retire_hours: 1.5 }, 'retire_window'],
      [{ slug: 'demo', value: NEW_VALUE, retire_hours: '2' }, 'retire_window'],
      [{ slug: 'demo', value: NEW_VALUE, mode: 'later' }, 'rotate_mode'],
      [{ slug: 'demo', value: SECRET }, 'rotate_same_value'],
    ]) {
      const r = await a.control('POST', '/v1/credentials/rotate', body)
      assert.equal(r.status, 403, JSON.stringify(body))
      assert.equal(r.body.rule, rule, JSON.stringify(r.body))
    }
    assert.equal((await a.control('POST', '/v1/credentials/rotate', { slug: 'missing', value: NEW_VALUE })).status, 404)
    assert.equal(a.vault.revealField(a.vault.findCredential('demo').id, 'token'), SECRET)
  } finally { await a.stop() }
})

// ------------------------------------------------------ F4 scrub patterns

test('adding and removing a scrub pattern need a human; the sample is the human\'s own text', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const pattern = 'acme_[A-Za-z0-9]{20,40}'
    refusedForPresence(await a.control('POST', '/v1/credentials/scrub', { slug: 'demo', pattern }), 'scrub add')
    assert.equal(a.vault.findCredential('demo').scrub_patterns?.length ?? 0, 0)
    a.openWindow()
    const sample = 'before acme_abcdefghijklmnopqrstuvwx after, and acme_short'
    const r = await a.control('POST', '/v1/credentials/scrub', { slug: 'demo', pattern, sample })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.match(r.body.id, /^sp_/)
    assert.equal(r.body.sample.matches, 1)
    assert.equal(r.body.sample.redacted, 'before [[av:derived]] after, and acme_short')
    const listed = (await a.control('GET', '/v1/credentials')).body.find((c) => c.slug === 'demo')
    assert.equal(listed.scrub_patterns[0].source, pattern)
    const added = a.audit('cred.scrub_pattern_added').at(-1)
    assert.equal(added.length, pattern.length)
    assert.ok(!JSON.stringify(added).includes(pattern), 'the source is in the log')
    a.closeWindow()
    refusedForPresence(await a.control('DELETE', `/v1/credentials/scrub?slug=demo&id=${r.body.id}`), 'scrub remove')
    a.openWindow()
    assert.deepEqual((await a.control('DELETE', `/v1/credentials/scrub?slug=demo&id=${r.body.id}`)).body, { ok: true, removed: true })
    assert.deepEqual((await a.control('DELETE', `/v1/credentials/scrub?slug=demo&id=${r.body.id}`)).body, { ok: true, removed: false })
  } finally { await a.stop() }
})

test('a pattern that could backtrack, match everything, or carry a secret is refused, before the gate', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    for (const pattern of ['(a+)+b', '.*', 'a', '[a-z]+', 42]) {
      // Refused for what it is, with no passphrase asked for.
      const r = await a.control('POST', '/v1/credentials/scrub', { slug: 'demo', pattern })
      assert.equal(r.status, 403, String(pattern))
      assert.equal(r.body.rule, 'scrub_pattern')
    }
    a.openWindow()
    const secret = await a.control('POST', '/v1/credentials/scrub', { slug: 'demo', pattern: SECRET })
    assert.equal(secret.body.rule, 'scrub_pattern')
    assert.ok(!JSON.stringify(secret.body).includes(SECRET))
    const bigSample = await a.control('POST', '/v1/credentials/scrub', { slug: 'demo', pattern: 'acme_[a-z]{4}', sample: 5 })
    assert.equal(bigSample.body.rule, 'policy_invalid')
  } finally { await a.stop() }
})

// --------------------------------------------------------- F10 expiry

test('setting an expiry needs a human, and is metadata the gateway does not enforce', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const s = a.session()
    refusedForPresence(await a.control('POST', '/v1/credentials/expiry', { slug: 'demo', expires_at: '2020-01-01' }), 'expiry')
    a.openWindow()
    for (const expires_at of ['not a date', 20200101, undefined]) {
      const bad = await a.control('POST', '/v1/credentials/expiry', { slug: 'demo', expires_at })
      assert.equal(bad.body.rule, 'expires_at', JSON.stringify(expires_at))
    }
    const r = await a.control('POST', '/v1/credentials/expiry', { slug: 'demo', expires_at: '2020-01-01T00:00:00Z' })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.expiry_warning, 'expired')
    const res = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(res.status, 200, 'an expired credential is still usable: expiry is not enforcement')
    const listed = await a.tool('vault_list_creds', {}, { token: s.token })
    assert.equal(listed.body[0].expiry_warning, 'expired')
    assert.equal((await a.control('GET', '/v1/status')).body.credentials_expiring, 1)
    const cleared = await a.control('POST', '/v1/credentials/expiry', { slug: 'demo', expires_at: null })
    assert.equal(cleared.body.expires_at, null)
  } finally { await a.stop() }
})

test('a credential can be added with its expiry; a bad one leaves nothing stored', async () => {
  const a = await startApi()
  try {
    const bad = await a.control('POST', '/v1/credentials', { slug: 'later', kind: 'http', host: 'api.example.com', value: 'LATER-SECRET-00112233', expires_at: 'soonish' })
    assert.equal(bad.body.rule, 'expires_at')
    assert.equal(a.vault.findCredential('later'), null)
    const ok = await a.control('POST', '/v1/credentials', { slug: 'later', kind: 'http', host: 'api.example.com', value: 'LATER-SECRET-00112233', expires_at: '2099-01-01' })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(ok.body.expires_at, '2099-01-01T00:00:00.000Z')
  } finally { await a.stop() }
})

// ----------------------------------------------------------- F11 pins

test('setting and removing pins need a human, and only for a host the credential reaches', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    refusedForPresence(await a.control('POST', '/v1/credentials/pins', { slug: 'demo', host: '127.0.0.1', pins: [PIN] }), 'pins set')
    a.openWindow()
    const elsewhere = await a.control('POST', '/v1/credentials/pins', { slug: 'demo', host: 'evil.example', pins: [PIN] })
    assert.equal(elsewhere.body.rule, 'pin_host')
    for (const pins of [['sha256/short'], 'sha256/x', null]) {
      const r = await a.control('POST', '/v1/credentials/pins', { slug: 'demo', host: '127.0.0.1', pins })
      assert.equal(r.body.rule, 'pin_format', JSON.stringify(pins))
    }
    const r = await a.control('POST', '/v1/credentials/pins', { slug: 'demo', host: '127.0.0.1', pins: [PIN] })
    assert.deepEqual(r.body, { slug: 'demo', host: '127.0.0.1', pins: 1 })
    a.closeWindow()
    refusedForPresence(await a.control('DELETE', '/v1/credentials/pins?slug=demo&host=127.0.0.1'), 'pins remove')
    a.openWindow()
    assert.deepEqual((await a.control('DELETE', '/v1/credentials/pins?slug=demo&host=127.0.0.1')).body, { ok: true, remaining: 0 })
  } finally { await a.stop() }
})

// ----------------------------------------------------------- F12 probe

/** A github credential aimed at a local upstream, which answers with the secret in its body. */
async function probeTarget(a) {
  const hits = []
  const up = http.createServer((req, res) => {
    hits.push({ method: req.method, url: req.url, auth: req.headers.authorization })
    res.writeHead(200, { 'content-type': 'application/json', 'x-oauth-scopes': 'repo, read:org' })
    res.end(JSON.stringify({ login: 'octo', echoed: req.headers.authorization }))
  })
  await new Promise((resolve) => up.listen(0, '127.0.0.1', resolve))
  for (const slug of ['gh', 'gh2']) {
    a.vault.addCredential({
      slug, kind: 'github', connector: { host: `127.0.0.1:${up.address().port}`, scheme: 'http' },
      fields: { token: `ghp_PROBE${slug.toUpperCase()}SECRET0011223344556677` }, sites: { token: ['header:authorization:Bearer'] },
    })
  }
  return { hits, close: () => new Promise((resolve) => up.close(resolve)) }
}

test('cred test is open, hits only the profile\'s probe, and never returns the body', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  const t = await probeTarget(a)
  try {
    const r = await a.control('POST', '/v1/credentials/test', { slug: 'gh', path: '/repos/x/y/keys', method: 'DELETE', body: 'x' })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.ok, true)
    assert.equal(r.body.status, 'ok')
    assert.equal(r.body.http_status, 200)
    assert.deepEqual(t.hits.map((h) => `${h.method} ${h.url}`), ['GET /user'])
    assert.ok(!JSON.stringify(r.body).includes('PROBEGH'), 'the upstream body came back')
    const tested = a.audit('cred.tested').at(-1)
    assert.equal(tested.credential_slug, 'gh')
    assert.equal(tested.http_status, 200)
    // Pins apply to the probe. Pinned over plain http, nothing is sent, and
    // the refusal is the pin's, not an internal error.
    a.vault.setPins('gh2', '127.0.0.1', [`sha256/${'B'.repeat(43)}=`])
    const pinned = await a.control('POST', '/v1/credentials/test', { slug: 'gh2' })
    assert.equal(pinned.status, 502, JSON.stringify(pinned.body))
    assert.equal(pinned.body.code, 'AV_PIN_MISMATCH')
    assert.equal(pinned.body.rule, 'pin_plaintext')
    assert.equal(t.hits.length, 1, 'a pinned probe reached the upstream over plain http')
    assert.ok(!JSON.stringify(pinned.body).includes('PROBEGH2'))
    // http has no fixed probe.
    const none = await a.control('POST', '/v1/credentials/test', { slug: 'demo' })
    assert.equal(none.body.rule, 'no_probe')
    assert.equal((await a.control('POST', '/v1/credentials/test', { slug: 'missing' })).status, 404)
    assert.equal((await a.control('POST', '/v1/credentials/test', { all: 'yes' })).body.rule, 'policy_invalid')
  } finally { await t.close(); await a.stop() }
})

test('a second test within a minute is throttled through the route; another credential is not (C20)', async () => {
  const a = await startApi()
  const t = await probeTarget(a)
  try {
    assert.equal((await a.control('POST', '/v1/credentials/test', { slug: 'gh' })).status, 200)
    const again = await a.control('POST', '/v1/credentials/test', { slug: 'gh' })
    assert.equal(again.status, 429, JSON.stringify(again.body))
    assert.equal(again.body.code, 'AV_QUOTA_EXCEEDED')
    assert.equal(again.body.rule, 'probe_throttle')
    assert.ok(Number.isInteger(again.body.retry_after) && again.body.retry_after > 0)
    assert.equal(t.hits.length, 1, 'the throttled call reached the upstream')
    const other = await a.control('POST', '/v1/credentials/test', { slug: 'gh2' })
    assert.equal(other.status, 200, JSON.stringify(other.body))
    // All at once: the throttled ones say so, the rest run.
    const all = await a.control('POST', '/v1/credentials/test', { all: true })
    const by = Object.fromEntries(all.body.results.map((x) => [x.slug, x]))
    assert.equal(by.gh.error, 'AV_QUOTA_EXCEEDED')
    assert.ok(by.gh.retry_after > 0)
    assert.equal(by.demo.error, 'AV_NOT_FOUND')
  } finally { await t.close(); await a.stop() }
})

// ------------------------------------------------- F16 quarantine, release

test('quarantine is open, stops every use at once, and denies held requests', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const s = a.session({ policy: { approval: 'each' } })
    const held = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(held.status, 202)
    // No presence: an agent can do this, and gains nothing by it.
    const r = await a.control('POST', '/v1/credentials/quarantine', { slug: 'demo', reason: `because ${s.placeholder} and ${SECRET}` })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.denied_approvals, 1)
    assert.equal(r.body.quarantine.by, 'control')
    // Agent-written, so stored as untrusted, with nothing that works in it.
    const recorded = a.audit('cred.quarantined').at(-1)
    for (const text of [JSON.stringify(r.body), JSON.stringify(recorded)]) {
      assert.ok(!text.includes(s.placeholder), 'a placeholder is in the quarantine record')
      assert.ok(!text.includes(SECRET), 'the secret is in the quarantine record')
    }
    assert.match(recorded.reason_untrusted, /«placeholder»/)
    const p = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(p.json?.code, 'AV_QUARANTINED', p.text)
    assert.equal((await a.tool('vault_http', { cred: 'demo', method: 'GET', path: '/x', reason: 'x' }, { token: s.token })).body.code, 'AV_QUARANTINED')
    assert.equal((await a.tool('vault_get_placeholder', { cred: 'demo', reason: 'x' }, { token: s.token })).body.code, 'AV_QUARANTINED')
    a.openWindow()
    assert.equal((await a.control('POST', '/v1/sessions', { cred: 'demo' })).body.code, 'AV_QUARANTINED')
    assert.equal((await a.tool('vault_list_creds', {}, { token: s.token })).body[0].quarantined, true)
  } finally { await a.stop() }
})

test('an agent cannot ask for a session on a quarantined credential, over either door (C12 note)', async () => {
  const a = await startApi()
  try {
    await a.control('POST', '/v1/credentials/quarantine', { slug: 'demo' })
    const asked = await a.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'please' })
    assert.equal(asked.status, 403, JSON.stringify(asked.body))
    assert.equal(asked.body.code, 'AV_QUARANTINED')
    assert.equal(asked.body.rule, 'quarantine')
    const viaMcp = await a.tool('vault_request_session', { cred: 'demo', reason: 'please' })
    assert.equal(viaMcp.body.code, 'AV_QUARANTINED')
    assert.equal(a.daemon.sessionRequests.pending().length, 0, 'a request was opened')
    // Released, the same request is an ordinary one.
    await a.control('POST', '/v1/credentials/release', { slug: 'demo' })
    assert.equal((await a.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'please' })).status, 200)
  } finally { await a.stop() }
})

test('releasing a quarantine needs a human, and a still-live session works again', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const s = a.session()
    await a.control('POST', '/v1/credentials/quarantine', { slug: 'demo' })
    refusedForPresence(await a.control('POST', '/v1/credentials/release', { slug: 'demo' }), 'release')
    assert.ok(a.vault.findCredential('demo').quarantine, 'released without a human')
    a.openWindow()
    assert.deepEqual((await a.control('POST', '/v1/credentials/release', { slug: 'demo' })).body, { slug: 'demo', released: true })
    assert.equal((await a.control('POST', '/v1/credentials/release', { slug: 'missing' })).status, 404)
    const res = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(res.status, 200, res.text)
    assert.equal((await a.control('POST', '/v1/credentials/quarantine', { slug: 'demo', reason: 7 })).body.rule, 'policy_invalid')
  } finally { await a.stop() }
})
