import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import * as ph from '../../src/core/placeholder.js'
import * as b32 from '../../src/core/base32.js'

const K = randomBytes(32)
const mk = (slug = 'gh-frozencrow', field = 'token', sid = ph.newSid()) =>
  ph.mint({ kPh: K, sid, slug, field })

test('constants are derived from the grammar, not hard-coded independently', () => {
  // If the grammar changes and these drift, every scanner window is wrong.
  assert.equal(ph.PH_MIN_LEN, 3 + 1 + 12 + 1 + 3 + 1 + 26 + 1 + 6)
  assert.equal(ph.PH_MIN_LEN, 54)
  assert.equal(ph.PH_MAX_LEN, 92)
  assert.equal(ph.B64_MIN_RUN, Math.ceil((ph.PH_MIN_LEN * 4) / 3))
  assert.equal(ph.B64_MIN_RUN, 72)
  assert.equal(ph.SCAN_OVERLAP, 3 * ph.PH_MAX_LEN + 2)
  assert.equal(ph.SCAN_OVERLAP, 278)
})

test('a minted placeholder is within the length bounds and round-trips', () => {
  const p = mk()
  assert.ok(p.text.length >= ph.PH_MIN_LEN && p.text.length <= ph.PH_MAX_LEN, p.text.length)
  const parsed = ph.parseAt(p.text)
  assert.ok(parsed)
  assert.equal(parsed.slug, 'gh-frozencrow')
  assert.equal(parsed.field, 'token')
  assert.equal(parsed.sid, p.sid)
  assert.ok(ph.verify(K, parsed))
})

test('the longest legal label still fits inside PH_MAX_LEN', () => {
  const p = mk('a'.repeat(24), 'b'.repeat(16))
  assert.equal(p.text.length, ph.PH_MAX_LEN)
  assert.ok(ph.verify(K, ph.parseAt(p.text)))
})

test('every character survives a URL, JSON, a shell word and a SCRAM username', () => {
  for (let i = 0; i < 50; i++) {
    const { text } = mk()
    assert.equal(encodeURIComponent(text), text, 'must be RFC 3986 unreserved')
    assert.equal(JSON.parse(JSON.stringify(text)), text)
    assert.equal(text, text.toLowerCase())
    // The base32 groups exclude the ambiguous letters; the label carries the
    // human-chosen credential slug, which may legitimately contain any of them.
    const parsed = ph.parseAt(text)
    for (const group of [parsed.sid, parsed.nonce, parsed.chk]) {
      assert.ok(!/[ilou]/.test(group), `ambiguous letter in ${group}`)
    }
  }
})

test('the check characters are keyed: another vault cannot forge one', () => {
  const other = randomBytes(32)
  const parsed = ph.parseAt(mk().text)
  assert.ok(ph.verify(K, parsed))
  assert.ok(!ph.verify(other, parsed))
})

test('mutating any character breaks verification', () => {
  const { text } = mk()
  for (const i of [4, 10, 20, 40, text.length - 1]) {
    const c = text[i] === '0' ? '1' : '0'
    const mutated = text.slice(0, i) + c + text.slice(i + 1)
    const parsed = ph.parseAt(mutated)
    if (parsed) assert.ok(!ph.verify(K, parsed), `mutation at ${i} should not verify`)
  }
})

test('nonce entropy is 128 bits and never repeats across mints', () => {
  const seen = new Set()
  for (let i = 0; i < 2000; i++) {
    const p = mk()
    assert.equal(p.nonce.length, 26)
    assert.ok(!seen.has(p.nonce))
    seen.add(p.nonce)
  }
})

test('diagnose names the actual corruption so an agent can self-correct', () => {
  const { text } = mk()
  assert.match(ph.diagnose(text.replace('av1.', 'av2.')), /does not start/)
  assert.match(ph.diagnose(text + 'zz'), /expected groups of 12\/26\/6/)
  assert.match(ph.diagnose(text.split('.').slice(0, 4).join('.')), /expected 5 dot-separated groups/)
})

test('findAll locates placeholders in surrounding text and skips near-misses', () => {
  const a = mk().text
  const b = mk('pg-prod', 'password').text
  const hay = `Authorization: Bearer ${a}\nX-Other: av1.notreal\npg=${b};`
  const found = ph.findAll(hay)
  assert.equal(found.length, 2)
  assert.deepEqual(found.map((f) => f.text), [a, b])
})

test('a placeholder immediately followed by base32 text is not a placeholder', () => {
  // Otherwise a longer opaque token beginning with our prefix would be parsed
  // as a placeholder plus trailing data.
  const { text } = mk()
  assert.equal(ph.findAll(text + 'abcd').length, 0)
  assert.equal(ph.findAll(text + '-abcd').length, 1)
})

test('the scanner pattern published for gitleaks matches real placeholders', () => {
  const re = new RegExp(ph.SCANNER_PATTERN)
  for (let i = 0; i < 20; i++) assert.match(mk().text, re)
})

test('base32 encodes and decodes round-trip', () => {
  for (let i = 0; i < 100; i++) {
    const bytes = randomBytes(16)
    const enc = b32.encode(bytes, 26)
    assert.equal(enc.length, 26)
    assert.ok(b32.isBase32(enc))
    assert.deepEqual(b32.decode(enc, 16), bytes)
  }
})
