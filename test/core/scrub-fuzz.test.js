// Property tests for the scrubber.
//
// Written after a throwaway fuzzer found a real leak in about thirty cases, on
// every seed: the streaming scrubber scrubbed the emitted prefix and held the
// tail separately, so any match straddling that split was torn in two and
// neither half matched. A secret longer than the emitted prefix passed through
// in full — and the \u-escaped encoding is six times the secret's length, so
// it was reachable on any streamed response.
//
// The hand-written tests all passed throughout. They checked the cases someone
// thought of; this checks the ones nobody did.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Scrubber, encodings } from '../../src/core/scrub.js'

/** Seeded, so a failure is reproducible from its seed alone. */
function rng(seed) {
  let s = seed
  return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
}
const ALPHA = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/+='
const NOISE = [...'abc XYZ {}":,\n\t<>&%\\']

function makeCase(rnd) {
  const pick = (a) => a[Math.floor(rnd() * a.length)]
  const len = 8 + Math.floor(rnd() * 30)
  const secret = Array.from({ length: len }, () => pick([...ALPHA])).join('')
  const forms = encodings(secret, 1)
  const hidden = forms[Math.floor(rnd() * forms.length)]
  const noise = (n) => Array.from({ length: n }, () => pick(NOISE)).join('')
  return {
    secret,
    hidden,
    body: noise(Math.floor(rnd() * 40)) + hidden + noise(Math.floor(rnd() * 40)),
  }
}

/** Feed a body through the stream in chunks of random size. */
function streamed(scrubber, body, rnd) {
  const st = scrubber.stream()
  let out = ''
  let pos = 0
  while (pos < body.length) {
    const take = 1 + Math.floor(rnd() * 12)
    out += st.push(body.slice(pos, pos + take))
    pos += take
  }
  return out + st.flush()
}

test('a secret never survives the stream, in any encoding at any chunk size', () => {
  // The property that matters: however the bytes arrive, the secret does not
  // come out the other side.
  for (const seed of [1, 7, 42, 99, 12345]) {
    const rnd = rng(seed)
    for (let i = 0; i < 2000; i++) {
      const { secret, hidden, body } = makeCase(rnd)
      if (!hidden) continue
      const s = new Scrubber([{ secret, label: 'k', replacement: '[R]', always: true }])
      const out = streamed(s, body, rnd)
      assert.ok(!out.includes(secret), `seed ${seed} case ${i}: raw secret survived`)
      assert.ok(!out.includes(hidden), `seed ${seed} case ${i}: encoded secret survived`)
    }
  }
})

test('streaming and whole-body scrubbing agree', () => {
  // A response split into chunks must not come out different from the same
  // response handled in one piece. Divergence here is how a leak hides.
  for (const seed of [3, 77, 4242]) {
    const rnd = rng(seed)
    for (let i = 0; i < 1500; i++) {
      const { secret, body } = makeCase(rnd)
      const s = new Scrubber([{ secret, label: 'k', replacement: '[R]', always: true }])
      assert.equal(streamed(s, body, rnd), s.scrub(body).text, `seed ${seed} case ${i}`)
    }
  }
})

test('text with no secret in it is passed through byte for byte', () => {
  // The scrubber must not become a blunt instrument: a response that contains
  // nothing sensitive has to arrive unchanged.
  const rnd = rng(2024)
  const pick = (a) => a[Math.floor(rnd() * a.length)]
  for (let i = 0; i < 2000; i++) {
    const body = Array.from({ length: Math.floor(rnd() * 200) }, () => pick(NOISE)).join('')
    const s = new Scrubber([{ secret: 'SECRET-NOT-PRESENT-0011223344', label: 'k', replacement: '[R]', always: true }])
    assert.equal(streamed(s, body, rnd), body, `case ${i}`)
  }
})

test('every declared encoding of a secret is actually caught', () => {
  // scrub.js claims seven encodings. This asserts the claim rather than
  // trusting the comment.
  const rnd = rng(31337)
  for (let i = 0; i < 400; i++) {
    const { secret } = makeCase(rnd)
    const s = new Scrubber([{ secret, label: 'k', replacement: '[R]', always: true }])
    for (const [n, form] of encodings(secret, 1).entries()) {
      const out = s.scrub(`before ${form} after`).text
      assert.ok(!out.includes(form), `encoding ${n} of ${secret} was not redacted`)
    }
  }
})
