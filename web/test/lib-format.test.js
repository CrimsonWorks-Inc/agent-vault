import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ago, until, expiresIn, soonestExpiry, plural, count, span, tripwireRuleText, policyValue } from '../src/lib/format.js'

const NOW = Date.parse('2026-11-01T12:00:00Z')

test('an infinite session says "never expires", never a date', () => {
  assert.equal(until(null, {}, NOW), 'never expires')
  assert.equal(until('2099-01-01T00:00:00Z', { infinite: true }, NOW), 'never expires')
})

test('until counts down in minutes, hours, then days', () => {
  assert.equal(until('2026-11-01T12:30:00Z', {}, NOW), '30m left')
  assert.equal(until('2026-11-01T17:00:00Z', {}, NOW), '5h left')
  assert.equal(until('2026-11-05T12:00:00Z', {}, NOW), '4d left')
  assert.equal(until('2026-11-01T11:00:00Z', {}, NOW), 'expired')
  assert.equal(until('not a date', {}, NOW), 'expired')
})

test('ago', () => {
  assert.equal(ago('2026-11-01T11:59:30Z', NOW), '30s ago')
  assert.equal(ago('2026-11-01T11:00:00Z', NOW), '1h ago')
  assert.equal(ago('2026-10-30T12:00:00Z', NOW), '2d ago')
})

test('credential expiry: the sooner of the set and the observed', () => {
  const c = { expires_at: '2026-11-10T00:00:00Z', health: { observed_expires_at: '2026-11-05T00:00:00Z' } }
  assert.equal(soonestExpiry(c), Date.parse('2026-11-05T00:00:00Z'))
  assert.equal(soonestExpiry({}), null)
  assert.equal(expiresIn(Date.parse('2026-11-05T00:00:00Z'), NOW), 'expires in 4d')
  assert.equal(expiresIn(null, NOW), 'expires soon')
  assert.equal(expiresIn(NOW - 1, NOW), 'expired')
})

test('tripwire rules read as app.html printed them', () => {
  assert.equal(tripwireRuleText({ id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' }),
    'replay  AV_PH_REPLAY  1 in 10m  → revoke_session')
  assert.equal(tripwireRuleText({ id: 'x', rule_prefix: 'host_', threshold: 3, window_s: 7200, action: 'panic' }), 'x  host_*  3 in 2h  → panic')
  assert.equal(span(45), '45s')
})

test('small words', () => {
  assert.equal(plural(1, 'credential'), '1 credential')
  assert.equal(plural(3, 'credential'), '3 credentials')
  assert.equal(count(12480), '12,480')
  assert.equal(count(undefined), '—')
  assert.equal(policyValue(null), 'none')
  assert.equal(policyValue(['GET', 'HEAD']), 'GET, HEAD')
})
