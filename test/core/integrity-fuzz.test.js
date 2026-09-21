// Property tests for the two integrity primitives the gates rest on.
//
// The placeholder checksum is what makes a forged or mangled placeholder
// unusable: it is a keyed MAC truncated to six characters, and the whole ledger
// lookup happens behind it. The operation canonicaliser is what binds a
// WebAuthn signature to one specific action — if two different operations
// canonicalise the same, a signature for the harmless one authorises the other.
//
// Neither is the kind of thing example-based tests probe deeply, because the
// interesting inputs are the ones nobody would think to write down.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import * as ph from '../../src/core/placeholder.js'
import { canonicalOperation } from '../../src/ui/webauthn.js'
import { matchesSite } from '../../src/core/substitute.js'

function rng(seed) {
  let s = seed
  return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
}

const K = randomBytes(32)
const LETTERS = 'abcdefghijklmnopqrstuvwxyz0123456789'

const mintOne = (rnd) => ph.mint({
  kPh: K,
  sid: ph.newSid(),
  slug: `ab${Array.from({ length: Math.floor(rnd() * 8) }, () => LETTERS[Math.floor(rnd() * LETTERS.length)]).join('')}`,
  field: 'token',
})

// ------------------------------------------------------------- the checksum

test('a minted placeholder always verifies under its own key', () => {
  const rnd = rng(1)
  for (let i = 0; i < 3000; i++) {
    const p = mintOne(rnd)
    const parsed = ph.parseAt(p.text, 0)
    assert.ok(parsed, `minted placeholder did not parse: ${p.text}`)
    assert.ok(ph.verify(K, parsed), `minted placeholder did not verify: ${p.text}`)
  }
})

test('changing any single character makes a placeholder unusable', () => {
  // Either it stops parsing or it fails the checksum. What must never happen
  // is that a mutated placeholder parses AND verifies, because everything
  // downstream trusts that pair.
  const rnd = rng(7)
  const alphabet = [...'0123456789abcdefghjkmnpqrstvwxyz._-']
  let mutations = 0
  for (let i = 0; i < 1200; i++) {
    const p = mintOne(rnd)
    for (let k = 0; k < 6; k++) {
      const at = Math.floor(rnd() * p.text.length)
      const repl = alphabet[Math.floor(rnd() * alphabet.length)]
      if (repl === p.text[at]) continue
      const mutated = p.text.slice(0, at) + repl + p.text.slice(at + 1)
      mutations++
      const parsed = ph.parseAt(mutated, 0)
      if (parsed) {
        assert.ok(!ph.verify(K, parsed),
          `a one-character change still verified:\n  from ${p.text}\n  to   ${mutated}`)
      }
    }
  }
  assert.ok(mutations > 5000, `expected plenty of mutations, got ${mutations}`)
})

test('a placeholder never verifies under a different key', () => {
  // The check is keyed, so a placeholder minted by one vault is meaningless to
  // another. Six characters is 30 bits; this asserts the key actually matters
  // rather than the format merely being self-consistent.
  const rnd = rng(42)
  const other = randomBytes(32)
  for (let i = 0; i < 3000; i++) {
    const parsed = ph.parseAt(mintOne(rnd).text, 0)
    assert.ok(!ph.verify(other, parsed), 'a placeholder verified under the wrong key')
  }
})

test('random text is never mistaken for a placeholder', () => {
  const rnd = rng(99)
  const chars = [...'av1.0123456789abcdefghjkmnpqrstvwxyz_-']
  for (let i = 0; i < 20000; i++) {
    const len = 40 + Math.floor(rnd() * 60)
    const junk = `av1.${Array.from({ length: len }, () => chars[Math.floor(rnd() * chars.length)]).join('')}`
    const parsed = ph.parseAt(junk, 0)
    if (parsed) assert.ok(!ph.verify(K, parsed), `random text verified as a placeholder: ${junk}`)
  }
})

// ------------------------------------------------- the operation canonicaliser

test('operations that differ in any way canonicalise differently', () => {
  // A collision here means a signature collected for one action authorises
  // another. The daemon compares canonicalOperation(signed) against
  // canonicalOperation(received), so this is the whole binding.
  const rnd = rng(2024)
  const pick = (a) => a[Math.floor(rnd() * a.length)]
  const OPS = ['session.create', 'cred.add', 'cred.remove', 'approval.approve', 'listener.add']
  const CREDS = ['prod', 'prod2', 'staging', 'prod-key', '']
  const METHODS = [['GET'], ['GET', 'POST'], ['POST'], ['GET', 'POST', 'DELETE'], []]
  const PATHS = [['/**'], ['/v1/**'], ['/user'], ['/**', '/user'], []]

  const seen = new Map()
  let pairs = 0
  for (let i = 0; i < 40000; i++) {
    const op = {
      op: pick(OPS),
      cred: pick(CREDS),
      methods: pick(METHODS),
      paths: pick(PATHS),
    }
    const text = canonicalOperation(op)
    const key = JSON.stringify([op.op, op.cred, op.methods, op.paths])
    if (seen.has(text)) {
      pairs++
      assert.equal(seen.get(text), key,
        `two different operations canonicalised identically:\n  ${seen.get(text)}\n  ${key}\n  -> ${text}`)
    } else seen.set(text, key)
  }
  assert.ok(pairs > 100, 'the generator should be producing repeats to compare against')
})

test('key order and absent fields do not change the canonical form', () => {
  // The UI builds the operation in one order and the daemon rebuilds it in
  // another. If those disagreed, every legitimate signature would be rejected
  // — or worse, a mismatch would be papered over somewhere.
  assert.equal(
    canonicalOperation({ op: 'session.create', cred: 'prod', methods: ['GET'] }),
    canonicalOperation({ methods: ['GET'], cred: 'prod', op: 'session.create' }),
  )
  // An explicitly undefined field is the same as not naming it at all.
  assert.equal(
    canonicalOperation({ op: 'cred.add', slug: 'x' }),
    canonicalOperation({ op: 'cred.add', slug: 'x', kind: undefined }),
  )
  // But null is a value, and arrays keep their order because order is meaning.
  assert.notEqual(
    canonicalOperation({ op: 'cred.add', kind: null }),
    canonicalOperation({ op: 'cred.add' }),
  )
  assert.notEqual(
    canonicalOperation({ op: 'x', methods: ['GET', 'POST'] }),
    canonicalOperation({ op: 'x', methods: ['POST', 'GET'] }),
  )
})

// ------------------------------------------------------------ site matching

test('an encoded occurrence is never treated as an injection site', () => {
  // The detector deliberately sees more than the substituter. Everything it
  // finds in a non-raw encoding must be reported and refused, never
  // substituted, or an agent could smuggle a placeholder past the site check
  // by base64-ing it.
  const rnd = rng(31337)
  const encodings = ['percent', 'percent-double', 'json-escape', 'base64']
  const sites = [
    { kind: 'header', name: 'authorization', scheme: 'Bearer' },
    { kind: 'header', name: 'x-api-key' },
    { kind: 'query', key: 'key' },
    { kind: 'json', pointer: '/auth/key' },
  ]
  for (let i = 0; i < 5000; i++) {
    const site = sites[Math.floor(rnd() * sites.length)]
    const location = {
      region: site.kind === 'header' ? 'header' : site.kind,
      name: site.name,
      scheme: site.scheme,
      key: site.key,
      pointer: site.pointer,
      encoding: encodings[Math.floor(rnd() * encodings.length)],
    }
    assert.equal(matchesSite(location, site), false,
      `an occurrence encoded as ${location.encoding} matched a site`)
  }
  // The same location in raw text is a site, so the check above is meaningful.
  assert.equal(
    matchesSite({ region: 'header', name: 'x-api-key', encoding: 'raw' }, { kind: 'header', name: 'x-api-key' }),
    true,
  )
})
