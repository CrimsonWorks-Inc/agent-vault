// F10. Health is metadata read from the headers a profile names.
// An unparseable expiry is dropped. A header the profile did not name —
// including an ordinary Date header — is not an expiry.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PROFILES, getProfile, extractHealth } from '../../src/connectors/profiles.js'

const github = () => getProfile('github')

test('a GitHub expiry header becomes observed_expires_at', () => {
  const h = extractHealth(github(), {
    'github-authentication-token-expiration': '2027-01-31 00:00:00 UTC',
    'x-oauth-scopes': 'repo, user',
    'x-ratelimit-remaining': '42',
  })
  assert.deepEqual(h, {
    observed_expires_at: '2027-01-31T00:00:00.000Z',
    scopes: ['repo', 'user'],
    ratelimit_remaining: 42,
  })
})

test('ISO 8601 and RFC 1123 expiries parse, and the header name is case-insensitive', () => {
  const iso = extractHealth(github(), { 'GitHub-Authentication-Token-Expiration': '2027-06-15T13:45:30Z' })
  assert.equal(iso.observed_expires_at, '2027-06-15T13:45:30.000Z')
  const rfc = extractHealth(github(), { 'github-authentication-token-expiration': 'Sun, 31 Jan 2027 00:00:00 GMT' })
  assert.equal(rfc.observed_expires_at, '2027-01-31T00:00:00.000Z')
  const dateOnly = extractHealth(github(), { 'github-authentication-token-expiration': '2027-03-01' })
  assert.equal(dateOnly.observed_expires_at, '2027-03-01T00:00:00.000Z')
})

test('an unparseable expiry is ignored, and so is a calendar date that is not a date', () => {
  assert.equal(extractHealth(github(), { 'github-authentication-token-expiration': 'not-a-date' }), null)
  assert.equal(extractHealth(github(), { 'github-authentication-token-expiration': '2027-02-31 00:00:00 UTC' }), null)
  assert.equal(extractHealth(github(), { 'github-authentication-token-expiration': 'yesterday' }), null)
  const scopesOnly = extractHealth(github(), {
    'github-authentication-token-expiration': 'nope',
    'x-oauth-scopes': 'gist',
  })
  assert.deepEqual(scopesOnly, { scopes: ['gist'] })
  assert.equal(scopesOnly.observed_expires_at, undefined)
})

test('a rate-limit header that is not a non-negative integer is ignored', () => {
  assert.equal(extractHealth(github(), { 'x-ratelimit-remaining': '0' }).ratelimit_remaining, 0)
  assert.equal(extractHealth(github(), { 'x-ratelimit-remaining': 'nope' }), null)
  assert.equal(extractHealth(github(), { 'x-ratelimit-remaining': '-1' }), null)
  assert.equal(extractHealth(github(), { 'x-ratelimit-remaining': '1.5' }), null)
  assert.equal(extractHealth(github(), { 'x-ratelimit-remaining': '1e2' }), null)
})

test('an ordinary Date header is not treated as an expiry', () => {
  const h = extractHealth(github(), { date: 'Sun, 31 Jan 2027 00:00:00 GMT', server: 'GitHub.com' })
  assert.equal(h, null)
})

test('a profile with no health block yields nothing, even when GitHub headers are present', () => {
  const headers = {
    'github-authentication-token-expiration': '2027-01-31 00:00:00 UTC',
    'x-oauth-scopes': 'repo',
    'x-ratelimit-remaining': '7',
  }
  for (const kind of Object.keys(PROFILES)) {
    if (kind === 'github') continue
    assert.equal(PROFILES[kind].health, null, kind)
    assert.equal(extractHealth(getProfile(kind), headers), null, kind)
  }
  assert.deepEqual(Object.keys(PROFILES.github.health).sort(), [
    'expiry_header', 'ratelimit_remaining_header', 'scopes_header',
  ])
})

test('no profile carries a built-in SPKI pin', () => {
  for (const [kind, profile] of Object.entries(PROFILES)) {
    assert.equal(Object.hasOwn(profile, 'pins'), false, kind)
  }
})

test('header arrays and a Headers-like get() are read the same way', () => {
  const fromArray = extractHealth(github(), { 'x-oauth-scopes': ['repo', 'read:org'] })
  assert.deepEqual(fromArray.scopes, ['repo', 'read:org'])
  const fromGet = extractHealth(github(), { get: (n) => (n.toLowerCase() === 'x-ratelimit-remaining' ? '9' : null) })
  assert.equal(fromGet.ratelimit_remaining, 9)
})
