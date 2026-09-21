import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Scrubber, encodings } from '../../src/core/scrub.js'

const SECRET = 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
const PLACEHOLDER = 'av1.7f2x0k9m3qzr.gh-frozencrow_token.5a8e1n0t2rc7q9x4wz6vhb3pdk.c4d9tz'

const scrubber = () => new Scrubber([{ secret: SECRET, label: 'gh-frozencrow', replacement: PLACEHOLDER }])

test('a raw echo of the injected secret is replaced by the placeholder the agent used', () => {
  const { text, redactions } = scrubber().scrub(`{"error":"bad credentials: ${SECRET}"}`)
  assert.ok(!text.includes(SECRET))
  assert.ok(text.includes(PLACEHOLDER))
  assert.ok(redactions > 0)
})

test('every encoding of the secret is covered', () => {
  const s = scrubber()
  const variants = {
    raw: SECRET,
    percent: encodeURIComponent(SECRET),
    hex: Buffer.from(SECRET).toString('hex'),
    base64: Buffer.from(SECRET).toString('base64'),
    base64url: Buffer.from(SECRET).toString('base64url'),
    jsonEscaped: [...SECRET].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
  }
  for (const [name, v] of Object.entries(variants)) {
    const { text } = s.scrub(`prefix ${v} suffix`)
    assert.ok(!text.includes(v), `${name} encoding survived the scrubber`)
  }
})

test('base64 at all three alignments is covered', () => {
  const s = scrubber()
  for (const pad of ['', 'a', 'bb']) {
    const blob = Buffer.from(pad + SECRET).toString('base64')
    const { text } = s.scrub(`{"blob":"${blob}"}`)
    assert.ok(!text.includes(blob), `alignment ${pad.length} survived`)
  }
})

test('a secret split across streaming chunks is still caught', () => {
  const s = scrubber()
  const body = `leading text ${SECRET} trailing text`
  for (const cut of [5, 15, 20, 30, 40, 50]) {
    const st = s.stream()
    let out = st.push(body.slice(0, cut))
    out += st.push(body.slice(cut))
    out += st.flush()
    assert.ok(!out.includes(SECRET), `split at ${cut} leaked`)
    assert.equal(out.replace(PLACEHOLDER, SECRET), body, `split at ${cut} corrupted the body`)
  }
})

test('a different vault credential echoed back is redacted, not revealed', () => {
  const other = 'xoxb-9999-8888-SECRETSLACKVALUE'
  const s = new Scrubber([
    { secret: SECRET, label: 'gh-frozencrow', replacement: PLACEHOLDER },
    { secret: other, label: 'slack-team' },
  ])
  const { text } = s.scrub(`{"a":"${SECRET}","b":"${other}"}`)
  assert.ok(!text.includes(other))
  assert.ok(text.includes('[[av:redacted:slack-team]]'))
})

test('derived tokens the vault never stored are redacted by shape', () => {
  const s = new Scrubber([])
  const minted = 'ghs_MINTEDINSTALLATIONTOKEN1234567890ab'
  const { text } = s.scrub(`{"token":"${minted}"}`)
  assert.ok(!text.includes(minted))
  assert.ok(text.includes('[[av:derived]]'))
  assert.ok(s.derivedSeen.has('github'))
})

test('short values are never treated as secrets, so responses are not shredded', () => {
  const s = new Scrubber([{ secret: 'abc', label: 'tiny' }])
  const { text } = s.scrub('abc appears in ordinary prose abc abc')
  assert.equal(text, 'abc appears in ordinary prose abc abc')
})

test('a response with no secret passes through byte-identical', () => {
  const body = JSON.stringify({ items: [{ id: 1, title: 'an ordinary issue' }] })
  assert.equal(scrubber().scrub(body).text, body)
})

test('encodings() are distinct and deduplicated', () => {
  // An alphanumeric secret collapses several encodings onto the raw form
  // (percent, HTML and JSON escaping are all no-ops on it), and the set
  // deduplicates rather than carrying redundant needles.
  const plain = encodings(SECRET)
  assert.ok(plain.length >= 5, `only ${plain.length} encodings`)
  assert.equal(new Set(plain).size, plain.length)
  assert.ok(plain.every((e) => e.length >= 8))

  // A secret with characters that actually re-encode yields strictly more.
  const spicy = encodings('pa/ss+wo<rd>"with/specials-1234567890')
  assert.ok(spicy.length > plain.length)
  assert.equal(new Set(spicy).size, spicy.length)
})

test('a secret this request injected is redacted even below the length floor', () => {
  // The pen test noted 4-char values slipped past the 8-char floor. The floor
  // exists to avoid false positives on the bulk set of other vault secrets;
  // the value we actually injected is known exactly and always scrubbed.
  const shortSecret = 'test'
  const placeholder = 'av1.7f2x0k9m3qzr.gh_token.5a8e1n0t2rc7q9x4wz6vhb3pdk.c4d9tz'
  const s = new Scrubber([{ secret: shortSecret, label: 'gh', replacement: placeholder, always: true }])
  const { text } = s.scrub(`{"echo":"${shortSecret}"}`)
  assert.ok(!text.includes(`"${shortSecret}"`), 'the injected short secret leaked')
  assert.ok(text.includes(placeholder))
})

test('a short OTHER vault secret keeps the length floor, to avoid shredding prose', () => {
  const s = new Scrubber([{ secret: 'test', label: 'other' }]) // no always flag
  const { text } = s.scrub('this is a test of ordinary prose that says test twice')
  assert.equal(text, 'this is a test of ordinary prose that says test twice')
})
