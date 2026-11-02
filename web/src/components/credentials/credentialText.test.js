import { describe, expect, it } from 'vitest'
import { credentialBadges, credentialFacts, expiryIso, expiryLine, heldDenied, pinsText, quarantineLine, testParts } from './credentialText.js'

describe('credential text (the old page parity)', () => {
  it('badges say what to notice, in words', () => {
    expect(credentialBadges({ quarantine: {}, expiry_warning: 'expired', health: { status: 'ok' } }))
      .toEqual([{ tone: 'crit', text: 'quarantined' }, { tone: 'crit', text: 'expired' }, { tone: 'ok', text: 'healthy' }])
    const soon = new Date(Date.now() + 2.5 * 86400e3).toISOString()
    expect(credentialBadges({ expiry_warning: 'soon', expires_at: soon, health: { status: 'unauthorized' } }))
      .toEqual([{ tone: 'warn', text: 'expires in 3d' }, { tone: 'warn', text: 'unauthorized' }])
    expect(credentialBadges({ health: { status: 'unknown' } })).toEqual([])
  })
  it('pins read-only, hosts with a count', () => {
    expect(pinsText({ 'api.github.com': 2, 'x.com': 0, bad: 'n' })).toBe('pinned: api.github.com (2)')
    expect(pinsText(null)).toBe('')
  })
  it('the row facts', () => {
    expect(credentialFacts({ fields: [{ fp8: 'ab', sites: ['a', 'b'] }] }))
      .toEqual([['host', 'no host set'], ['fingerprint', 'ab'], ['injected at', 'a, b'], ['version', '1']])
  })
  it('expiry, quarantine and test lines', () => {
    const at = '2030-01-02T00:00:00.000Z'
    expect(expiryLine({ expires_at: at })).toMatch(/^expires in \d+d \(2030-01-02\)$/)
    expect(expiryLine({ health: { observed_expires_at: at } })).toMatch(/as the upstream reports it\)$/)
    expect(expiryLine({})).toBe('')
    expect(quarantineLine({ by: 'tripwire', rule_id: 'replay' })).toBe('quarantined by tripwire (tripwire replay)')
    expect(testParts({ status: 'ok', http_status: 200, latency_ms: 41, scopes: ['repo'] })).toEqual({ ok: true, status: 'ok', rest: ' · 200 · 41ms · scopes: repo' })
    expect(testParts({ status: 'fail', latency_ms: 3 }).rest).toBe(' · no answer · 3ms')
    expect(testParts({ error: 'boom' })).toEqual({ error: 'boom' })
  })
  it('an expiry day is midnight UTC; held requests are counted', () => {
    expect(expiryIso('2026-12-01')).toBe('2026-12-01T00:00:00.000Z')
    expect(heldDenied(0)).toBe('')
    expect(heldDenied(1)).toBe('; 1 held request denied')
    expect(heldDenied(3)).toBe('; 3 held requests denied')
  })
})
