// F12. The probe uses the profile's method and path, never a path the caller
// supplies. It records health, throttles a second call inside a minute, and
// the result holds neither the secret, a placeholder, nor the response body.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import https from 'node:https'
import { Readable } from 'node:stream'
import { execFile, execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate } from 'node:crypto'
import { getProfile } from '../../src/connectors/profiles.js'
import * as probe from '../../src/connectors/probe.js'
import { spkiOf } from '../../src/connectors/pinning.js'

const { runProbe } = probe

const SECRET = 'ghp_REALSECRET0000111122223333444455556666'
const PLACEHOLDER = 'av1.abcdefghjkmn.gh_token.abcdefghjkmnpqrstvwxyz2345.abcdef'
const BODY = 'BODY_SENTINEL_do_not_return'

function cred(over = {}) {
  return {
    id: over.id || 'cred_test',
    slug: 'gh',
    connector: { host: 'api.github.com', scheme: 'https', ...(over.connector || {}) },
    fields: over.fields || [{ name: 'token', sites: ['header:authorization:Bearer'] }],
    pins: over.pins,
  }
}

function vault(over = {}) {
  const health = []
  const revealed = []
  return {
    health,
    revealed,
    revealField(id, field) {
      revealed.push({ id, field })
      if (over.revealField) return over.revealField(id, field)
      return SECRET
    },
    recordHealth(id, patch) {
      health.push({ id, patch })
      return patch
    },
    setCredentialExpiry() { throw new Error('a probe must not set credential expiry') },
  }
}

function upstreamOf(sent, response) {
  return async (req) => {
    sent.push(req)
    if (response) return response(req)
    return { status: 200, headers: { 'x-oauth-scopes': 'repo, user', 'x-ratelimit-remaining': '7' } }
  }
}

function leaks(value, needles, seen = new Set()) {
  if (value == null || seen.has(value)) return false
  if (typeof value === 'string') return needles.some((n) => n && value.includes(n))
  if (typeof value === 'number' || typeof value === 'boolean') return false
  if (Buffer.isBuffer(value)) return needles.some((n) => value.includes(Buffer.from(n)))
  if (typeof value !== 'object') return false
  seen.add(value)
  if (typeof value.read === 'function' && typeof value.pipe === 'function') return true
  for (const inner of Object.values(value)) {
    if (leaks(inner, needles, seen)) return true
  }
  return false
}

test('the probe hits only the profile method and path, and ignores a caller path, method and body', async () => {
  const sent = []
  const v = vault()
  const result = await runProbe({
    vault: v,
    cred: cred({ id: 'cred_path' }),
    profile: getProfile('github'),
    upstream: upstreamOf(sent),
    path: '/user/keys',
    method: 'DELETE',
    body: 'pwned',
  })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].method, 'GET')
  assert.equal(sent[0].url, 'https://api.github.com/user')
  assert.ok(sent[0].body == null || sent[0].body === '')
  assert.equal(sent[0].headers.authorization, `Bearer ${SECRET}`)
  assert.equal(sent[0].url.includes(SECRET), false)
  assert.equal(result.ok, true)
  assert.equal(result.status, 'ok')
  assert.equal(result.http_status, 200)
  assert.equal(Number.isInteger(result.latency_ms), true)
  assert.ok(result.latency_ms >= 0)
  assert.deepEqual(result.scopes, ['repo', 'user'])
  assert.equal(result.ratelimit_remaining, 7)
  assert.equal(v.health.length, 1)
  assert.equal(v.health[0].id, 'cred_path')
  assert.equal(v.health[0].patch.source, 'probe')
  assert.equal(v.health[0].patch.status, 'ok')
  assert.equal(v.health[0].patch.http_status, 200)
  assert.deepEqual(v.revealed, [{ id: 'cred_path', field: 'token' }])
})

test('slack is a POST to the profile path with an empty form body, not the caller body', async () => {
  const sent = []
  await runProbe({
    vault: vault(),
    cred: cred({ id: 'cred_slack', connector: { host: 'slack.com', scheme: 'https' } }),
    profile: getProfile('slack'),
    upstream: upstreamOf(sent, () => ({ status: 200, headers: {} })),
    path: '/api/admin.users.session.reset',
    method: 'GET',
    body: 'token=stolen',
  })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].method, 'POST')
  assert.equal(sent[0].url, 'https://slack.com/api/auth.test')
  assert.equal(sent[0].headers['content-type'], 'application/x-www-form-urlencoded')
  assert.equal(sent[0].headers.authorization, `Bearer ${SECRET}`)
  assert.ok(sent[0].body == null || sent[0].body === '')
  assert.notEqual(sent[0].body, 'token=stolen')
})

test('a header site with no scheme sends the raw secret, and the first header site wins', async () => {
  const sent = []
  const v = vault()
  await runProbe({
    vault: v,
    cred: cred({
      id: 'cred_key',
      connector: { host: 'api.anthropic.com', scheme: 'https' },
      fields: [
        { name: 'password', sites: ['basic:pass'] },
        { name: 'key', sites: ['header:x-api-key', 'header:authorization:Bearer'] },
      ],
    }),
    profile: getProfile('anthropic'),
    upstream: upstreamOf(sent, () => ({ status: 204, headers: {} })),
  })
  assert.equal(sent[0].url, 'https://api.anthropic.com/v1/models')
  assert.equal(sent[0].method, 'GET')
  assert.equal(sent[0].headers['x-api-key'], SECRET)
  assert.equal(sent[0].headers.authorization, undefined)
  assert.deepEqual(v.revealed, [{ id: 'cred_key', field: 'key' }])
  assert.equal(v.health[0].patch.status, 'ok')
  assert.equal(v.health[0].patch.http_status, 204)
})

test('the result and the health record never contain the secret, a placeholder, or the body', async () => {
  const sent = []
  const v = vault()
  const logs = []
  const methods = ['log', 'info', 'warn', 'error', 'debug']
  const saved = {}
  for (const name of methods) {
    saved[name] = console[name]
    console[name] = (...args) => logs.push(args.map(String).join(' '))
  }
  try {
    const stream = Readable.from([`body ${SECRET} ${PLACEHOLDER} ${BODY}`])
    const result = await runProbe({
      vault: v,
      cred: cred({ id: 'cred_body' }),
      profile: getProfile('github'),
      upstream: upstreamOf(sent, () => ({
        status: 200,
        headers: {
          'x-oauth-scopes': `repo, ${SECRET}, ${PLACEHOLDER}`,
          'github-authentication-token-expiration': '2027-01-31 00:00:00 UTC',
        },
        body: Buffer.from(`${SECRET} ${PLACEHOLDER} ${BODY}`),
        res: stream,
      })),
    })
    const needles = [SECRET, PLACEHOLDER, BODY]
    assert.equal(leaks(result, needles), false)
    assert.equal(leaks(v.health, needles), false)
    assert.equal(logs.some((line) => needles.some((n) => line.includes(n))), false)
    assert.equal(stream.readableEnded, true)
    assert.equal(result.observed_expires_at, '2027-01-31T00:00:00.000Z')
    assert.ok(result.scopes.some((s) => s.includes('repo')))
    assert.equal(result.scopes.some((s) => s.includes(SECRET)), false)
    assert.equal(result.scopes.some((s) => s.includes(PLACEHOLDER)), false)
  } finally {
    for (const name of methods) console[name] = saved[name]
  }
})

test('status classes: 401, 403, other codes, and a network error', async () => {
  const cases = [
    [401, 'unauthorized', false],
    [403, 'forbidden', false],
    [404, 'error', false],
    [500, 'error', false],
    [302, 'error', false],
  ]
  let n = 0
  for (const [code, status, ok] of cases) {
    const v = vault()
    const result = await runProbe({
      vault: v,
      cred: cred({ id: `cred_status_${code}` }),
      profile: getProfile('github'),
      upstream: async () => ({ status: code, headers: {} }),
    })
    assert.equal(result.status, status, String(code))
    assert.equal(result.ok, ok, String(code))
    assert.equal(result.http_status, code)
    assert.equal(v.health[0].patch.status, status)
    assert.equal(v.health[0].patch.source, 'probe')
  }

  const v = vault()
  const result = await runProbe({
    vault: v,
    cred: cred({ id: 'cred_down' }),
    profile: getProfile('github'),
    upstream: async () => { throw new Error(`connect failed for ${SECRET} and ${PLACEHOLDER} ${BODY}`) },
  })
  assert.equal(result.status, 'unreachable')
  assert.equal(result.ok, false)
  assert.equal(result.http_status, null)
  assert.equal(leaks(result, [SECRET, PLACEHOLDER, BODY]), false)
  assert.equal(v.health[0].patch.status, 'unreachable')
  assert.equal(v.health[0].patch.http_status, null)
})

test('http and postgres have no probe, and a credential with no header site is refused before any request', async () => {
  const sent = []
  const up = upstreamOf(sent)
  for (const kind of ['http', 'postgres']) {
    await assert.rejects(
      () => runProbe({ vault: vault(), cred: cred({ id: `cred_${kind}` }), profile: getProfile(kind), upstream: up }),
      (err) => err.code === 'AV_NOT_FOUND' && err.rule === 'no_probe'
        && err.hint === 'This kind has no fixed read-only probe. Use vault_http on a path you know.',
    )
  }
  const v = vault()
  await assert.rejects(
    () => runProbe({
      vault: v,
      cred: cred({ id: 'cred_basic', fields: [{ name: 'password', sites: ['basic:pass'] }] }),
      profile: getProfile('github'),
      upstream: up,
    }),
    (err) => err.code === 'AV_NOT_FOUND' && err.rule === 'no_probe',
  )
  assert.equal(v.revealed.length, 0)
  assert.equal(sent.length, 0)
  assert.equal(v.health.length, 0)
})

test('a host that is not a hostname is refused and nothing is sent', async () => {
  const sent = []
  const up = upstreamOf(sent)
  const bad = [
    'api.github.com/steal',
    'https://evil.test',
    'api.github.com@evil.test',
    'api.github.com\nevil.test',
    'api.github.com?x=1',
    '*.github.com',
    'file://api.github.com',
  ]
  let n = 0
  for (const host of bad) {
    await assert.rejects(
      () => runProbe({
        vault: vault(),
        cred: cred({ id: `cred_bad_${n++}`, connector: { host, scheme: 'https' } }),
        profile: getProfile('github'),
        upstream: up,
      }),
      (err) => err.code === 'AV_POLICY_DENIED' && err.rule === 'credential_host',
    )
  }
  await assert.rejects(
    () => runProbe({
      vault: vault(),
      cred: cred({ id: 'cred_file', connector: { host: 'api.github.com', scheme: 'file' } }),
      profile: getProfile('github'),
      upstream: up,
    }),
    (err) => err.code === 'AV_POLICY_DENIED' && err.rule === 'credential_host',
  )
  assert.equal(sent.length, 0)
})

test('an ordinary host, port and http scheme are used as declared', async () => {
  const sent = []
  await runProbe({
    vault: vault(),
    cred: cred({ id: 'cred_port', connector: { host: '127.0.0.1:8443', scheme: 'HTTP' } }),
    profile: getProfile('github'),
    upstream: upstreamOf(sent, () => ({ status: 200, headers: {} })),
  })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].url, 'http://127.0.0.1:8443/user')
  assert.equal(sent[0].method, 'GET')
  assert.equal(sent[0].pins, null)
})

test('pins for the host are forwarded, and a missing recordHealth still returns the result', async () => {
  const sent = []
  const pin = `sha256/${'C'.repeat(43)}=`
  const v = vault()
  delete v.recordHealth
  const result = await runProbe({
    vault: v,
    cred: cred({ id: 'cred_pins', pins: { 'API.GitHub.com': [pin] } }),
    profile: getProfile('github'),
    upstream: upstreamOf(sent),
  })
  assert.deepEqual(sent[0].pins, [pin])
  assert.equal(result.status, 'ok')
})

/** Run `fn` with the probe throttle's clock reading `clock.at`. */
async function withClock(fn) {
  const { probeClock } = probe
  assert.equal(typeof probeClock?.now, 'function', 'the throttle has its own clock')
  const saved = probeClock.now
  const clock = { at: 1_000_000 }
  probeClock.now = () => clock.at
  try {
    return await fn(clock)
  } finally {
    probeClock.now = saved
  }
}

test('the second probe inside 60 seconds is throttled, and one after the window is not', () => withClock(async (clock) => {
  const sent = []
  const v = vault()
  const base = {
    vault: v,
    cred: cred({ id: 'cred_throttle' }),
    profile: getProfile('github'),
    upstream: upstreamOf(sent),
  }
  const first = await runProbe(base)
  assert.equal(first.status, 'ok')
  assert.equal(sent.length, 1)
  clock.at += 1_000
  await assert.rejects(
    () => runProbe(base),
    (err) => {
      assert.equal(err.code, 'AV_QUOTA_EXCEEDED')
      assert.equal(err.rule, 'probe_throttle')
      assert.equal(err.http, 429)
      assert.equal(err.retryAfter, 59)
      return true
    },
  )
  clock.at += 58_999
  await assert.rejects(() => runProbe(base), (err) => err.code === 'AV_QUOTA_EXCEEDED' && err.retryAfter === 1)
  assert.equal(sent.length, 1, 'a throttled probe does not touch the upstream')
  assert.equal(v.revealed.length, 1, 'a throttled probe does not read the secret')
  clock.at += 1
  const again = await runProbe(base)
  assert.equal(again.status, 'ok')
  assert.equal(sent.length, 2)
}))

test('V-Q5: a now on the call does not skip the throttle', async () => {
  const sent = []
  const base = { cred: cred({ id: 'cred_now' }), profile: getProfile('github'), upstream: upstreamOf(sent) }
  await runProbe({ ...base, vault: vault() })
  let bypassed = 0
  for (let i = 1; i <= 3; i++) {
    try {
      await runProbe({ ...base, vault: vault(), now: Date.now() + i * 61_000 })
      bypassed++
    } catch (err) {
      assert.equal(err.code, 'AV_QUOTA_EXCEEDED')
    }
  }
  assert.equal(bypassed, 0, 'a caller-supplied now skipped the 60 s throttle')
  assert.equal(sent.length, 1)
})

test('V-Q5: a far-future now on the call does not lock the credential out', () => withClock(async (clock) => {
  const sent = []
  const base = { cred: cred({ id: 'cred_now_future' }), profile: getProfile('github'), upstream: upstreamOf(sent) }
  await runProbe({ ...base, vault: vault(), now: Number.MAX_SAFE_INTEGER })
  clock.at += 60_000
  const later = await runProbe({ ...base, vault: vault() })
  assert.equal(later.status, 'ok')
  assert.equal(sent.length, 2)
}))

test('V-Q7: a body that never ends is cut off and destroyed, and the probe returns', async () => {
  // A fast endless body hits the byte bound; a trickle hits the time bound.
  const fast = new Readable({ read() { setImmediate(() => { if (!this.destroyed) this.push(Buffer.alloc(16 * 1024)) }) } })
  const slow = new Readable({ read() { setTimeout(() => { if (!this.destroyed) this.push(Buffer.alloc(1)) }, 50) } })
  for (const [name, stream, within] of [['fast', fast, 1_500], ['trickle', slow, 4_000]]) {
    const started = Date.now()
    const pending = runProbe({
      vault: vault(),
      cred: cred({ id: `cred_endless_${name}` }),
      profile: getProfile('github'),
      upstream: async () => ({ status: 200, headers: {}, res: stream }),
    })
    const winner = await Promise.race([
      pending.then(() => 'done'),
      new Promise((r) => setTimeout(() => r('timeout'), within).unref()),
    ])
    const destroyedByProbe = stream.destroyed
    stream.destroy()
    await pending.catch(() => {})
    assert.equal(winner, 'done', `${name}: the probe was still waiting after ${Date.now() - started} ms`)
    assert.equal(destroyedByProbe, true, `${name}: the probe left the body stream open`)
  }
})

test('V-Q7: an ordinary short body is drained to its end and not cut', async () => {
  const stream = Readable.from([Buffer.alloc(1024), Buffer.alloc(1024)])
  const result = await runProbe({
    vault: vault(),
    cred: cred({ id: 'cred_short_body' }),
    profile: getProfile('github'),
    upstream: async () => ({ status: 200, headers: {}, res: stream }),
  })
  assert.equal(result.status, 'ok')
  assert.equal(stream.readableEnded, true)
})

test('V-Q8: a recordHealth failure after a 200 is a store error, not unreachable', async () => {
  const calls = []
  const storeError = Object.assign(new Error(`vault is locked ${SECRET}`), { code: 'AV_LOCKED' })
  const v = vault()
  v.recordHealth = (id, patch) => {
    calls.push(patch.status)
    throw storeError
  }
  await assert.rejects(
    () => runProbe({
      vault: v,
      cred: cred({ id: 'cred_store_busy' }),
      profile: getProfile('github'),
      upstream: async () => ({ status: 200, headers: {} }),
    }),
    (err) => {
      assert.equal(err.code, 'AV_LOCKED')
      assert.equal(String(err.message).includes(SECRET), false)
      return true
    },
  )
  assert.deepEqual(calls, ['ok'], 'the upstream answer was re-recorded after the store failed')

  // The same for a network failure: one record, and the store error surfaces.
  const down = []
  const v2 = vault()
  v2.recordHealth = (id, patch) => {
    down.push(patch.status)
    throw storeError
  }
  await assert.rejects(
    () => runProbe({
      vault: v2,
      cred: cred({ id: 'cred_store_busy_down' }),
      profile: getProfile('github'),
      upstream: async () => { throw new Error('ECONNREFUSED') },
    }),
    (err) => err.code === 'AV_LOCKED',
  )
  assert.deepEqual(down, ['unreachable'])
})

test('V-Q9: pins of the wrong shape refuse the probe before the secret is read', async () => {
  const pin = `sha256/${'C'.repeat(43)}=`
  const shapes = [
    { 'api.github.com': pin },
    { 'api.github.com': { 0: pin } },
    { 'api.github.com': [pin, 'garbage'] },
    { 'api.github.com': 42 },
    pin,
    [pin],
    true,
  ]
  let n = 0
  for (const pins of shapes) {
    const sent = []
    const v = vault()
    await assert.rejects(
      () => runProbe({ vault: v, cred: cred({ id: `cred_pin_shape_${n++}`, pins }), profile: getProfile('github'), upstream: upstreamOf(sent) }),
      (err) => err.code === 'AV_PIN_MISMATCH' && err.reason === 'pin_format',
      JSON.stringify(pins),
    )
    assert.equal(sent.length, 0, `${JSON.stringify(pins)} was sent unpinned`)
    assert.equal(v.revealed.length, 0)
  }
})

test('pins under two spellings of the same host are joined, and an empty one does not hide the other', async () => {
  const sent = []
  const pin = `sha256/${'C'.repeat(43)}=`
  await runProbe({
    vault: vault(),
    cred: cred({ id: 'cred_pin_dupe', pins: { 'api.github.com': [], 'API.GitHub.com': [pin], 'other.test': [`sha256/${'E'.repeat(43)}=`] } }),
    profile: getProfile('github'),
    upstream: upstreamOf(sent),
  })
  assert.deepEqual(sent[0].pins, [pin])
  let n2 = 0
  for (const pins of [undefined, null, {}, { 'api.github.com': null }, { 'api.github.com': [] }]) {
    const none = []
    await runProbe({ vault: vault(), cred: cred({ id: `cred_pin_none_${n2++}`, pins }), profile: getProfile('github'), upstream: upstreamOf(none) })
    assert.equal(none[0].pins, null, JSON.stringify(pins))
  }
})
let n2 = 0

test('F-1: pins are looked up by the host of the URL the probe sends to, however the key or the declared host spells it', async () => {
  const pin = `sha256/${'C'.repeat(43)}=`
  const cases = [
    ['[0:0::1]:8443', { '[::1]': [pin] }],
    ['[::1]:8443', { '[0:0::1]': [pin] }],
    ['[::1]:8443', { '[0:0:0:0:0:0:0:1]:8443': [pin] }],
    ['api.github.com', { 'API.GitHub.com.': [pin] }],
  ]
  let n = 0
  for (const [host, pins] of cases) {
    const sent = []
    await runProbe({
      vault: vault(),
      cred: cred({ id: `cred_pin_url_${n++}`, connector: { host, scheme: 'https' }, pins }),
      profile: getProfile('github'),
      upstream: upstreamOf(sent),
    })
    assert.equal(sent.length, 1, host)
    assert.deepEqual(sent[0].pins, [pin], `${host} ${JSON.stringify(pins)}`)
  }
  // A key for another host is not this URL's, and the probe sends no Host.
  const other = []
  await runProbe({
    vault: vault(),
    cred: cred({ id: 'cred_pin_url_other', connector: { host: '[::1]:8443', scheme: 'https' }, pins: { '[::2]': [pin] } }),
    profile: getProfile('github'),
    upstream: upstreamOf(other),
  })
  assert.equal(other[0].pins, null)
  assert.equal(Object.keys(other[0].headers).some((k) => k.toLowerCase() === 'host'), false)
})

const PROBE_CHILD = `
const { runProbe } = await import(process.env.AV_PROBE_URL)
const { getProfile } = await import(process.env.AV_PROFILES_URL)
const health = []
const vault = {
  revealField: () => process.env.AV_SECRET,
  recordHealth: (id, patch) => { health.push(patch); return patch },
}
const out = { health }
try {
  out.result = await runProbe({
    vault,
    cred: JSON.parse(process.env.AV_CRED),
    profile: getProfile('github'),
    path: '/user/keys',
    method: 'POST',
    body: 'pwned',
  })
} catch (e) {
  out.error = { code: e.code, reason: e.reason, message: e.message }
}
process.stdout.write(JSON.stringify(out))
`

/** runProbe with the real pinnedRequest, in a child that trusts `trust`. */
function probeIn(trust, credential) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['--input-type=module', '-e', PROBE_CHILD], {
      env: {
        ...process.env,
        NODE_EXTRA_CA_CERTS: trust,
        AV_PROBE_URL: new URL('../../src/connectors/probe.js', import.meta.url).href,
        AV_PROFILES_URL: new URL('../../src/connectors/profiles.js', import.meta.url).href,
        AV_SECRET: SECRET,
        AV_CRED: JSON.stringify(credential),
      },
      timeout: 30_000,
    }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`probe child failed: ${err.message}\n${stderr}`))
      resolve(JSON.parse(stdout))
    })
  })
}

test('with the real upstream: a root pin adds to CA verification, a mismatch sends nothing, and a match probes only /user', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-probe-'))
  const ossl = (args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] })
  try {
    ossl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.crt', '-days', '2', '-subj', '/CN=ProbeRoot', '-addext', 'basicConstraints=critical,CA:TRUE'])
    writeFileSync(join(dir, 'leaf.ext'), 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
    ossl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'key.pem', '-out', 'leaf.csr', '-subj', '/CN=localhost'])
    ossl(['x509', '-req', '-in', 'leaf.csr', '-CA', 'root.crt', '-CAkey', 'root.key', '-out', 'cert.pem', '-days', '2', '-CAcreateserial', '-extfile', 'leaf.ext'])
    const cert = readFileSync(join(dir, 'cert.pem'))
    const key = readFileSync(join(dir, 'key.pem'))
    const root = readFileSync(join(dir, 'root.crt'))
    const rootPin = spkiOf(new X509Certificate(root))
    let bytes = 0
    let requests = 0
    let seen = null
    // The root rides along, so a check that skipped CA verification would see it.
    const server = https.createServer({ cert: Buffer.concat([cert, root]), key }, (req, res) => {
      requests++
      const chunks = []
      req.on('data', (c) => chunks.push(c))
      req.on('end', () => {
        seen = { method: req.method, url: req.url, authorization: req.headers.authorization, body: Buffer.concat(chunks).toString('utf8') }
        res.end(`${SECRET} ${PLACEHOLDER} ${BODY}`)
      })
    })
    server.on('secureConnection', (socket) => {
      socket.on('data', (c) => { bytes += c.length })
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    const host = `127.0.0.1:${server.address().port}`
    const at = (id, pins) => cred({ id, connector: { host, scheme: 'https' }, pins })
    try {
      // Trusted chain, wrong pin: nothing is sent.
      const bad = await probeIn(join(dir, 'root.crt'), at('cred_pin_bad', { '127.0.0.1': [`sha256/${'D'.repeat(43)}=`] }))
      assert.equal(bad.error?.code, 'AV_PIN_MISMATCH')
      assert.equal(String(bad.error.message).includes(SECRET), false)
      assert.equal(bad.health[0].status, 'error')
      assert.equal(bad.health[0].source, 'probe')

      // The root pin matches, but nothing trusts the chain: a non-leaf pin
      // never stands in for CA trust.
      const untrusted = await runProbe({ vault: vault(), cred: at('cred_pin_untrusted', { '127.0.0.1': [rootPin] }), profile: getProfile('github') })
      assert.equal(untrusted.status, 'unreachable')
      await new Promise((r) => setTimeout(r, 200))
      assert.equal(bytes, 0)
      assert.equal(requests, 0)

      const good = await probeIn(join(dir, 'root.crt'), at('cred_pin_ok', { '127.0.0.1': [rootPin] }))
      assert.equal(good.error, undefined)
      assert.equal(good.result.status, 'ok')
      assert.equal(leaks(good, [SECRET, PLACEHOLDER, BODY]), false)
      assert.equal(requests, 1)
      assert.equal(seen.method, 'GET')
      assert.equal(seen.url, '/user')
      assert.equal(seen.authorization, `Bearer ${SECRET}`)
      assert.notEqual(seen.body, 'pwned')
    } finally {
      server.close()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
