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

test('the derived-token shapes do not match ordinary English', () => {
  // Every shape used to match mid-word, because none of them required a token
  // boundary. `disk-usage_by_repository_over_time` came back as
  // `di[[av:derived]]`, and on a streamed response the same match cut the
  // stream with AV_UNSCANNABLE. A scrubber that corrupts ordinary prose is not
  // a cautious scrubber, it is a broken proxy — and these shapes are a
  // heuristic for tokens the vault never stored, so a miss costs a heuristic
  // while a false hit costs every response that mentions a repository.
  const s = new Scrubber([])
  const innocent = [
    'a disk-usage_by_repository_over_time report',
    'we took a task-oriented_approach_to_the_whole_thing',
    'see also: brisk-and_efficient_processing_of_requests',
    'the file lives at src/disk-cache_manager_implementation.ts',
    'highp_precision_floating_point_values_only please',
    'the boxox-abcdefghijklmnop identifier',
  ]
  for (const text of innocent) {
    const r = s.scrub(text)
    assert.equal(r.redactions, 0, `ordinary text was redacted: ${JSON.stringify(r.text)}`)
    assert.equal(r.text, text, 'ordinary text must pass through byte for byte')
  }
})

test('the derived-token shapes still catch real tokens the vault never stored', () => {
  // The other half: a boundary that stops false hits must not stop true ones.
  // These are the minted credentials the vault has no stored copy of — an
  // installation token, a key an upstream just issued — so shape is the only
  // thing there is to go on.
  const s = new Scrubber([])
  const real = {
    github: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'github-pat': `github_pat_${'A'.repeat(44)}`,
    slack: 'xoxb-1234567890-0987654321-abcdefghijkl',
    aws: 'AKIAIOSFODNN7EXAMPLE',
    'google-oauth': `ya29.${'a'.repeat(30)}`,
    'google-api': `AIza${'B'.repeat(35)}`,
    anthropic: `sk-ant-api03-${'c'.repeat(30)}`,
    openai: `sk-proj-${'d'.repeat(30)}`,
    'private-key': '-----BEGIN RSA PRIVATE KEY-----',
  }
  for (const [name, token] of Object.entries(real)) {
    for (const context of [`${token}`, `value: ${token}`, `{"key":"${token}"}`, `\n${token}\n`]) {
      const r = s.scrub(context)
      assert.ok(r.redactions > 0, `${name} was not caught in ${JSON.stringify(context.slice(0, 30))}`)
      assert.ok(!r.text.includes(token), `${name} survived: ${r.text.slice(0, 60)}`)
    }
  }
})
