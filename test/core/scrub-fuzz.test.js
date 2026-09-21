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

test('a secret inside a base64 blob does not come back with its tail intact', () => {
  // The base64 needle trimmed a blunt four characters off the end to clear the
  // padding. Padding is at most two characters, so that also removed up to
  // three bytes of the SECRET — and those bytes are its last three. An
  // upstream that echoed a token inside a base64 blob returned it to the agent
  // missing everything but its tail, which is not redaction.
  //
  // The offsets matter: a secret embedded in a larger blob does not begin on a
  // 3-byte boundary, which is what the three alignments exist for.
  for (const len of [24, 32, 40, 41, 42, 43, 64]) {
    const secret = `ghp_${'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.repeat(3).slice(0, len - 4)}`
    assert.equal(secret.length, len)
    const s = new Scrubber([{ secret, label: 'k', replacement: '[R]', always: true }])
    for (let offset = 0; offset < 6; offset++) {
      const blob = Buffer.concat([
        Buffer.alloc(offset, 0x41), Buffer.from(secret, 'utf8'), Buffer.from('TRAILING', 'utf8'),
      ]).toString('base64')
      const { text } = s.scrub(`{"blob":"${blob}"}`)

      // Whatever survived, read at every alignment. The leak was specifically
      // the END of the secret — the four trimmed characters are its last
      // three bytes — so that is what to look for, and three characters of a
      // credential's tail is three more than zero. The trailing data is chosen
      // not to contain them, so a hit here is the secret and not a collision.
      const tail = secret.slice(-3)
      assert.ok(!'TRAILING'.includes(tail), 'the test fixture would collide')
      const surviving = text.replace(/\[R\]/g, ' ')
      for (const piece of surviving.split(/[^A-Za-z0-9+/=_-]+/)) {
        for (let skip = 0; skip < 4; skip++) {
          let t = piece.slice(skip).replace(/=+$/, '')
          if (t.length < 8) continue
          if (t.length % 4 === 1) t = t.slice(0, -1)
          const decoded = Buffer.from(t + '='.repeat((4 - (t.length % 4)) % 4), 'base64').toString('latin1')
          assert.ok(
            !decoded.includes(tail),
            `len ${len} offset ${offset}: the secret's last ${tail.length} characters survived the scrub`,
          )
        }
      }
    }
  }
})

test('a secret is scrubbed as the response actually carries it, not as a JS string', () => {
  // Bodies are read byte-for-byte as latin1 so a binary response survives
  // intact. The needles were JS strings, so a secret with any character
  // outside ASCII never matched: "café" on the wire is five bytes that read
  // back as "cafÃ©". Any credential with an accent in it was published to the
  // agent the moment an upstream echoed it — and non-ASCII passwords are
  // ordinary, not exotic.
  const secrets = [
    'ghp_plainASCIIsecret12345',
    'pa55w0rd-café-über-secret',
    'Sécrèt-Key-0123456789',
    'пароль-секретный-123',
    '密码-0123456789abcdef',
    '🔑-emoji-key-0123456',
  ]
  for (const secret of secrets) {
    const s = new Scrubber([{ secret, label: 'k', replacement: '[R]', always: true }])
    // Exactly how the pipeline sees a UTF-8 body.
    const wire = Buffer.from(JSON.stringify({ echo: secret }), 'utf8').toString('latin1')
    const { text, redactions } = s.scrub(wire)
    assert.ok(redactions > 0, `${secret} was not redacted at all`)
    const asClientReads = Buffer.from(text, 'latin1').toString('utf8')
    assert.ok(!asClientReads.includes(secret), `${secret} survived to the agent`)
  }
})

test('the same holds through the streaming path, at any chunk size', () => {
  const secret = 'contraseña-secreta-0123456789'
  const wire = Buffer.from(`{"echo":"${secret}"}`, 'utf8').toString('latin1')
  for (const size of [1, 3, 7, 32, 4096]) {
    const s = new Scrubber([{ secret, label: 'k', replacement: '[R]', always: true }])
    const st = s.stream()
    let out = ''
    for (let p = 0; p < wire.length; p += size) out += st.push(wire.slice(p, p + size))
    out += st.flush()
    const asClientReads = Buffer.from(out, 'latin1').toString('utf8')
    assert.ok(!asClientReads.includes(secret), `chunk size ${size} leaked the secret`)
  }
})
