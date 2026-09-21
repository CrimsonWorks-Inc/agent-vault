// Where the policy engine and the URL parser must agree about a path.
//
// Every bug in this file was the same shape: two pieces of code read the same
// bytes and named different resources. The policy saw one path and allowed it;
// the wire carried another and the upstream served it. The deny lists exist to
// stop a read grant reaching deploy keys, webhooks, OAuth grants and admin
// endpoints — the paths that turn access into persistence — and each of these
// walked straight past them.
//
// Found by an independent audit, reproduced here so they stay found.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluateHttp, normalizePath } from '../../src/core/policy.js'

const POLICY = {
  hosts: ['api.github.com'],
  methods: ['GET', 'POST', 'DELETE'],
  paths: ['/**'],
  deny_paths: [
    '/user/keys', '/user/keys/**', '/user/gpg_keys',
    '/repos/*/*/hooks', '/repos/*/*/keys', '/settings/**', '/api/admin.*',
  ],
}

const allows = (path) => {
  try { evaluateHttp(POLICY, { method: 'POST', host: 'api.github.com', path }); return true } catch { return false }
}

/** What a URL parser makes of the same path, which is what the server sees. */
const asUrlWouldRead = (path) => {
  try { return new URL(`https://api.github.com${path}`).pathname } catch { return null }
}

test('the paths the deny list is for are denied', () => {
  for (const p of ['/user/keys', '/user/gpg_keys', '/repos/o/r/hooks', '/repos/o/r/keys', '/settings/x', '/api/admin.users']) {
    assert.equal(allows(p), false, `${p} should be denied outright`)
  }
  // And something legitimate still passes, so the above means something.
  assert.equal(allows('/repos/o/r/issues'), true)
})

test('a tab, newline or carriage return cannot smuggle a path past the deny list', () => {
  // The WHATWG URL parser deletes U+0009, U+000A and U+000D outright.
  // normalizePath kept them as ordinary bytes, so `/user/keys%09` matched no
  // deny glob here and arrived as `/user/keys` there. One character.
  for (const enc of ['%09', '%0a', '%0d']) {
    for (const base of ['/user/keys', '/repos/o/r/hooks', '/settings/x']) {
      const spelled = `${base}${enc}`
      assert.equal(allows(spelled), false, `${spelled} slipped past the deny list`)
    }
    // Also mid-path, which is how a literal deny entry like /api/admin.* is beaten.
    assert.equal(allows(`/api/a${enc}dmin.users`), false, `/api/a${enc}dmin.users slipped past`)
  }
})

test('an encoded fragment or query cannot truncate the path after the check', () => {
  // `#` and `?` end a path for a URL parser. They survived decoding here, so
  // `/user/keys%23` was matched as the literal "/user/keys#" — which no glob
  // covers — and then sent as "/user/keys".
  for (const spelled of ['/user/keys%23', '/user/keys%3Fz=1', '/repos/o/r/hooks%23x', '/settings/x%3f']) {
    assert.equal(allows(spelled), false, `${spelled} slipped past the deny list`)
  }
})

test('percent-encoding is resolved however many layers deep it goes', () => {
  // Decoding ran a fixed two rounds, so a third layer left a live escape in
  // the output and the upstream resolved it to something else again.
  assert.equal(normalizePath('/repos/%252e%252e/admin'), '/admin')
  assert.equal(normalizePath('/repos/%25252e%25252e/admin'), '/admin')
  assert.equal(allows('/user/%25256beys'), false, 'a thrice-encoded deny path slipped past')
  // A decode bomb is refused rather than followed forever.
  const deep = `/user/${'%25'.repeat(12)}6beys`
  assert.throws(() => normalizePath(deep), /too many times|invalid percent-escape/)
})

test('an encoded slash is refused rather than guessed', () => {
  // To this code it is a separator; to some upstreams it is a literal in one
  // segment. Two readings is two different resources, and guessing which is
  // exactly how the bugs above happened.
  for (const spelled of ['/repos/o%2fr/hooks', '/user%2Fkeys', '/a%5Cb']) {
    assert.throws(
      () => normalizePath(spelled),
      /encoded slash|backslash/,
      `${spelled} should be refused`,
    )
  }
})

test('whatever the spelling, the policy reads what the wire will carry', () => {
  // The property behind all of the above: if a spelling is allowed here, a URL
  // parser must resolve it to the same path this decided on. Anything else is
  // the same class of bug wearing a different hat.
  const spellings = [
    '/repos/o/r/issues', '/repos/o/r/issues/', '/repos/./o/r/issues',
    '/repos/o/x/../r/issues', '/repos//o//r//issues', '/repos/%6f/r/issues',
  ]
  for (const spelled of spellings) {
    if (!allows(spelled)) continue
    const decided = normalizePath(spelled)
    const onTheWire = asUrlWouldRead(decided.split('/').map(encodeURIComponent).join('/'))
    assert.equal(decodeURIComponent(onTheWire), decided,
      `${spelled}: policy decided ${decided} but the wire would carry ${onTheWire}`)
  }
})

test('a path that is only control characters does not become the root', () => {
  // Stripping rather than refusing would turn junk into "/", which on many
  // APIs is a listing endpoint.
  assert.throws(() => normalizePath('/%09%09%09'), /control character/)
})
