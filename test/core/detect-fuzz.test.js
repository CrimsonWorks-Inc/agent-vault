// Property tests for the detector and the policy engine.
//
// The detector is the thing AV_BAD_LOCATION rests on: if a placeholder is
// smuggled somewhere it does not belong and the detector misses it, the request
// is forwarded as though nothing happened. The policy engine's deny lists are
// what keep a read grant from reaching the paths that turn into persistence.
//
// Both survived their first fuzzing unchanged, which is worth recording as
// plainly as a failure would be.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import * as ph from '../../src/core/placeholder.js'
import { detectAll } from '../../src/core/detect.js'
import { locate } from '../../src/core/substitute.js'
import { intersect, evaluateHttp, normalizePath, matchPath } from '../../src/core/policy.js'

function rng(seed) {
  let s = seed
  return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
}

const K = randomBytes(32)
const LETTERS = 'abcdefghijklmnopqrstuvwxyz0123456789'
// Characters that can neither extend a placeholder nor join a base64 run, so
// these exercise the encodings rather than the grammar's boundary rule.
const DELIM = [...' \n\t{}"\',;()[]|!?#*^~`']
const WORDS = ['hello', 'value', 'token', 'data', '{"k":', '"}', '<p>', '&amp;', '%20', '...']

function mintOne(rnd) {
  const pick = (a) => a[Math.floor(rnd() * a.length)]
  return ph.mint({
    kPh: K,
    sid: ph.newSid(),
    slug: `ab${Array.from({ length: Math.floor(rnd() * 8) }, () => pick([...LETTERS])).join('')}`,
    field: pick(['token', 'key', 'password', 'secret']),
  })
}

/** Every way a tool might mangle a placeholder between the agent and here. */
const ENCODERS = {
  raw: (t) => t,
  percent: (t) => encodeURIComponent(t),
  'percent-double': (t) => encodeURIComponent(encodeURIComponent(t)),
  'json-unicode': (t) => [...t].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
  'json-slash': (t) => t.replace(/\//g, '\\/'),
  base64: (t) => Buffer.from(t, 'utf8').toString('base64'),
  base64url: (t) => Buffer.from(t, 'utf8').toString('base64url'),
  // Offset so the placeholder does not begin on a 3-byte boundary, which is
  // the case the three-alignment decoder exists for.
  'base64-offset-1': (t) => Buffer.from(`x${t}`, 'utf8').toString('base64'),
  'base64-offset-2': (t) => Buffer.from(`xy${t}`, 'utf8').toString('base64'),
  'base64-embedded': (t) => Buffer.from(`prefix-${t}-suffix`, 'utf8').toString('base64'),
}

test('every encoding of a placeholder is detected, wherever it sits', () => {
  for (const seed of [1, 7, 42, 99]) {
    const rnd = rng(seed)
    const pick = (a) => a[Math.floor(rnd() * a.length)]
    const noise = (n) => Array.from({ length: n }, () => pick([...WORDS, ...DELIM])).join('')
    for (const [name, encode] of Object.entries(ENCODERS)) {
      for (let i = 0; i < 300; i++) {
        const p = mintOne(rnd)
        const body = noise(Math.floor(rnd() * 20)) + pick(DELIM)
          + encode(p.text) + pick(DELIM) + noise(Math.floor(rnd() * 20))
        const hits = detectAll(body)
        assert.ok(hits.some((h) => h.nonce === p.nonce), `seed ${seed}: ${name} was not detected`)
      }
    }
  }
})

test('wrapped base64 is still base64', () => {
  // A minimal placeholder encodes to 80 base64 characters and the shortest run
  // the decoder looks at is 72, so a single line break in the middle left two
  // runs that were both too short and the placeholder was not seen at all.
  //
  // Every one of these is what a normal tool produces, not an evasion someone
  // had to invent: `base64` the command wraps at 76 columns, MIME parts wrap
  // at 76, PEM wraps at 64, and inside a JSON string those breaks are written
  // `\n`, whose backslash ends the run just as surely.
  const rnd = rng(8891)
  for (let i = 0; i < 200; i++) {
    const p = mintOne(rnd)
    const b = Buffer.from(p.text, 'utf8').toString('base64')
    const wrapped = {
      unwrapped: b,
      'PEM, 64 columns': b.replace(/(.{64})/g, '$1\n'),
      'MIME, 76 columns with CRLF': b.replace(/(.{76})/g, '$1\r\n'),
      'a single space': `${b.slice(0, 40)} ${b.slice(40)}`,
      'a tab': `${b.slice(0, 33)}\t${b.slice(33)}`,
      'JSON-escaped newlines': b.replace(/(.{64})/g, '$1\\n'),
      'indented, as a pretty-printer would': b.replace(/(.{60})/g, '$1\n      '),
    }
    for (const [how, blob] of Object.entries(wrapped)) {
      const hits = detectAll(`{"attachment":"${blob.replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"}`)
      assert.ok(hits.some((h) => h.nonce === p.nonce), `${how} was not detected`)
    }
  }
})

test('the detector stays linear on a large body', () => {
  // The detector runs over every request body up to the 16 MiB buffered limit,
  // on a single-threaded daemon, on input an agent chooses. Linear is the
  // requirement; the ReDoS in the policy globs was the same shape and cost 37
  // seconds of the daemon per request.
  const timeFor = (mb) => {
    const body = Buffer.alloc(mb << 20, 7).toString('base64').replace(/(.{76})/g, '$1\n')
    const started = Date.now()
    detectAll(body)
    return Date.now() - started
  }
  const one = Math.max(timeFor(1), 1)
  const four = timeFor(4)
  assert.ok(four < one * 12, `4 MiB took ${four}ms against ${one}ms for 1 MiB; that is not linear`)
})

test('the detector is a superset of the substituter, structurally', () => {
  // locate() routes every region through detectAll, so the two cannot drift
  // apart. This asserts the wiring rather than sampling it: a placeholder in a
  // header the substituter would read is a placeholder detectAll found.
  const rnd = rng(2024)
  for (let i = 0; i < 500; i++) {
    const p = mintOne(rnd)
    const occ = locate({
      method: 'GET',
      path: '/thing',
      query: '',
      headers: [['authorization', `Bearer ${p.text}`]],
      body: null,
    })
    assert.ok(occ.occurrences.some((o) => o.parsed.nonce === p.nonce), 'locate missed a header placeholder')
    assert.ok(detectAll(`Bearer ${p.text}`).some((h) => h.nonce === p.nonce), 'detectAll missed the same text')
  }
})

test('a placeholder needs a boundary, and both sides agree about that', () => {
  // A trailing alphanumeric means the text is not a placeholder by the grammar,
  // so the detector does not report one. That is only safe because the
  // substituter reads through the same function and will not substitute it
  // either — the two cannot disagree. Recorded because it looks like a miss.
  const rnd = rng(5)
  const p = mintOne(rnd)
  assert.equal(detectAll(p.text).length, 1)
  assert.equal(detectAll(`${p.text}x`).length, 0, 'a trailing letter makes it not a placeholder')
  assert.equal(detectAll(`x${p.text}`).length, 1, 'a leading letter does not')
  for (const after of [' ', '"', '/', '.', '\n', '}', ',']) {
    assert.equal(detectAll(p.text + after).length, 1, `a trailing ${JSON.stringify(after)} must still parse`)
  }
})

// ------------------------------------------------------------------- policy

const HOSTS = ['api.github.com', '*.github.com', 'github.com', 'api.example.com', '*.example.com', '*']
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH']
const PATHS = ['/**', '/repos/**', '/repos/*/*/issues', '/user', '/user/**', '/v1/**', '/*']

test('intersecting policies can only narrow, never widen', () => {
  // The whole policy model is profile ∩ workspace ∩ session ∩ grant. If any
  // combination allowed something a single layer refused, every ceiling in the
  // system would be advisory.
  for (const seed of [1, 7, 42]) {
    const rnd = rng(seed)
    const pick = (a) => a[Math.floor(rnd() * a.length)]
    const some = (a, n) => Array.from({ length: n }, () => pick(a))
    const layer = () => {
      const o = {}
      if (rnd() < 0.85) o.hosts = some(HOSTS, 1 + Math.floor(rnd() * 3))
      if (rnd() < 0.85) o.methods = some(METHODS, 1 + Math.floor(rnd() * 3))
      if (rnd() < 0.85) o.paths = some(PATHS, 1 + Math.floor(rnd() * 3))
      if (rnd() < 0.4) o.deny_paths = some(['/user/keys', '/settings/**'], 1)
      return o
    }
    const allows = (pol, req) => { try { evaluateHttp(pol, req); return true } catch { return false } }

    for (let i = 0; i < 4000; i++) {
      const layers = Array.from({ length: 2 + Math.floor(rnd() * 2) }, layer)
      const req = {
        method: pick(METHODS),
        host: pick(['api.github.com', 'github.com', 'api.example.com', 'evil.test']),
        path: pick(['/user', '/user/keys', '/repos/a/b/issues', '/v1/models', '/settings/x', '/']),
      }
      const combined = intersect(layers)
      if (allows(combined, req)) {
        for (const [n, l] of layers.entries()) {
          assert.ok(allows(l, req), `seed ${seed} case ${i}: layer ${n} refused what the intersection allowed`)
        }
      }
      // And the result must not depend on the order the layers are applied in.
      assert.equal(
        allows(intersect([...layers].reverse()), req), allows(combined, req),
        `seed ${seed} case ${i}: intersection depends on layer order`,
      )
    }
  }
})

test('a denied path stays denied however it is spelled', () => {
  // Deny lists are what stop a read grant reaching deploy keys and webhooks.
  // A path that normalizes onto one must not slip through by being written
  // with dot segments, doubled slashes, a query string or percent-escapes.
  const policy = {
    hosts: ['api.github.com'], methods: ['GET', 'POST', 'DELETE'], paths: ['/**'],
    deny_paths: ['/user/keys', '/user/keys/**', '/user/gpg_keys', '/repos/*/*/hooks', '/settings/**'],
  }
  const denied = ['/user/keys', '/user/gpg_keys', '/repos/a/b/hooks', '/settings/x']
  const rnd = rng(31337)
  const pick = (a) => a[Math.floor(rnd() * a.length)]
  const pct = (s) => [...s].map((c) => (rnd() < 0.3 && /[a-zA-Z_]/.test(c) ? `%${c.charCodeAt(0).toString(16)}` : c)).join('')
  const mutators = [
    (p) => p, (p) => `${p}/`, (p) => p.replace('/', '//'),
    (p) => p.replace(/\/([^/]+)/, '/./$1'), (p) => p.replace(/\/([^/]+)/, '/zzz/../$1'),
    (p) => `${p}?a=1`, (p) => pct(p), (p) => pct(pct(p)),
    (p) => p.replace(/\//g, '//'), (p) => `/a/b/../../${p.slice(1)}`,
  ]
  const allows = (p) => {
    try { evaluateHttp(policy, { method: 'GET', host: 'api.github.com', path: p }); return true } catch { return false }
  }

  for (let i = 0; i < 20000; i++) {
    let p = pick(denied)
    for (let k = 0, rounds = 1 + Math.floor(rnd() * 3); k < rounds; k++) p = pick(mutators)(p)
    let norm
    try { norm = normalizePath(p) } catch { continue } // refused outright is fine
    const shouldDeny = denied.some((d) => norm === d || norm.startsWith(`${d}/`))
    if (shouldDeny) assert.ok(!allows(p), `deny list escaped: ${p} normalized to ${norm}`)
  }
})

test('a child cannot widen past a ceiling with a mid-pattern **', () => {
  // globAllows compared only the text before `**`, so a ceiling of
  // /repos/**/pulls admitted /repos/anything-at-all. The child widened past
  // its own ceiling, which is the single thing layering exists to prevent.
  const ceiling = { hosts: ['api.github.com'], methods: ['GET'], paths: ['/repos/**/pulls'] }
  const child = { hosts: ['api.github.com'], methods: ['GET'], paths: ['/repos/anything-at-all'] }
  const effective = intersect([ceiling, child])
  const allows = (pol, path) => {
    try { evaluateHttp(pol, { method: 'GET', host: 'api.github.com', path }); return true } catch { return false }
  }
  assert.equal(allows(ceiling, '/repos/anything-at-all'), false, 'the ceiling does not allow this')
  assert.equal(allows(effective, '/repos/anything-at-all'), false, 'so the intersection must not either')
  // And the legitimate case still works.
  assert.equal(allows(intersect([ceiling, { paths: ['/repos/a/pulls'] }]), '/repos/a/pulls'), true)
})

test('glob matching is linear, not exponential', () => {
  // `**` compiled to `.*`, so a nested pattern backtracked exponentially:
  // fourteen groups took 37 seconds of a single-threaded daemon. Reachable by
  // anyone who can supply a grant or deny path.
  const evil = `/${'**/'.repeat(16)}x`
  const path = `/${'a/'.repeat(48)}b`
  // Two seconds, against a bug that took thirty-seven. A tight threshold here
  // turns a busy CI machine into a red build, and the failure this guards
  // against is three orders of magnitude away, not two.
  const started = Date.now()
  assert.equal(matchPath(evil, path), false)
  const ms = Date.now() - started
  assert.ok(ms < 2000, `matching took ${ms}ms; it should be linear`)
})
