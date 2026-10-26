// The pure core under the gateway: the scrubber, path normalisation, policy
// intersection and substitution, plus how a placeholder authenticates. Each
// test is an input that two readers used to read differently, or a protection
// a comment claimed and the code did not have.

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { Scrubber } from '../../src/core/scrub.js'
import * as policy from '../../src/core/policy.js'
import * as sub from '../../src/core/substitute.js'
import { setup, cleanup, SECRET } from './gateway-helpers.js'

afterEach(cleanup)

// ------------------------------------------------------------ the scrubber

const S = 'rSECRETVALUE-0123456789abcdef'
const scrubber = () => new Scrubber([{ secret: S, label: 'a', replacement: '[x]', always: true }])
const pct = (s, hex = (b) => b.toString(16).toUpperCase()) => [...Buffer.from(s)].map((b) => `%${hex(b).padStart(2, '0')}`).join('')

test('the scrubber catches the encodings it used to miss', () => {
  const b64 = Buffer.from(S).toString('base64')
  const cases = {
    partialJsonEscape: `{"t":"\\u0072${S.slice(1)}"}`,
    mixedJsonEscape: `{"t":"${[...S].map((c, i) => (i % 2 ? `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}` : c)).join('')}"}`,
    fullPercentUpper: pct(S),
    fullPercentLower: pct(S, (b) => b.toString(16)),
    upperHex: Buffer.from(S).toString('hex').toUpperCase(),
    wrappedB64: `-----BEGIN-----\n${b64.replace(/(.{16})/g, '$1\n')}\n-----END-----`,
    wrappedB64Crlf: b64.replace(/(.{16})/g, '$1\r\n'),
    wrappedB64JsonEscaped: `{"blob":"${b64.replace(/(.{16})/g, '$1\\n')}"}`,
  }
  for (const [name, text] of Object.entries(cases)) {
    const { text: out, redactions } = scrubber().scrub(text)
    assert.ok(redactions > 0, `${name}: not redacted`)
    assert.ok(out.includes('[x]'), `${name}: ${out}`)
    // Whatever is left must not decode back to the secret.
    const decoded = decodeURIComponent(out.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/%(?![0-9a-fA-F]{2})/g, '%25'))
    assert.ok(!decoded.includes(S), `${name}: ${out}`)
    assert.ok(!Buffer.from(out.replace(/\\n|\s/g, ''), 'base64').toString('latin1').includes(S), `${name}: base64 survives`)
  }
})

test('the scrubber leaves ordinary escaped and wrapped text alone', () => {
  const texts = [
    '{"html":"\\u003cb\\u003ebold\\u003c/b\\u003e","path":"/a%20b/c%2Fd"}',
    'line one\nline two\r\nline three\n',
    Buffer.from('a perfectly ordinary blob of bytes that is not a secret at all').toString('base64').replace(/(.{16})/g, '$1\n'),
    `${S.slice(0, 10)}\n${S.slice(10, 20)}`, // part of a secret is not the secret
  ]
  for (const t of texts) assert.deepEqual(scrubber().scrub(t), { text: t, redactions: 0 })
})

test('a percent-encoded secret split across stream chunks is still caught', () => {
  const s = scrubber().stream()
  const enc = pct(S)
  const hold = scrubber().overlap
  // The second push brings the total to exactly the hold-back plus 47, so the
  // cut lands 40 characters into the encoded secret.
  let out = s.push(`before ${enc.slice(0, 40)}`)
  const second = `${enc.slice(40)} after `
  out += s.push(second + '.'.repeat(hold + 47 - 47 - second.length))
  out += s.push('.'.repeat(400))
  out += s.flush()
  assert.ok(!decodeURIComponent(out).includes(S), out)
  assert.match(out, /before \[x\] after/)
})

test('a derived token straddling the stream hold-back is not emitted in halves', () => {
  const token = `ghp_${'A1b2C3d4E5'.repeat(4)}`
  const s = new Scrubber([]).stream()
  // The hold-back is 63 characters. The second push makes 75, so the cut
  // lands ten characters into the token: too few for the pattern to match in
  // the head, and the tail alone no longer starts with ghp_.
  let out = s.push(`: ${token.slice(0, 10)}`)
  out += s.push(token.slice(10) + ' '.repeat(29))
  out += s.push(` and then the stream goes on ${'.'.repeat(200)}`)
  out += s.flush()
  assert.ok(!(out.includes(token.slice(0, 10)) && out.includes(token.slice(10))), `the token reached the agent in halves: ${out}`)
  assert.ok(!out.includes(token))
  assert.match(out, /\[\[av:derived\]\]/)
})

test('the stream scrubber still emits ordinary text unchanged', () => {
  const s = new Scrubber([]).stream()
  const text = `the sk- prefix and gh tokens, ghp_ alone, a disk-usage_by_repository_over_time report ${'.'.repeat(300)}`
  let out = ''
  for (let i = 0; i < text.length; i += 37) out += s.push(text.slice(i, i + 37))
  out += s.flush()
  assert.equal(out, text)
})

// ----------------------------------------------------------- path decoding

test('a backslash encoded more than once is still refused', () => {
  for (const p of ['/allowed/x%255c..%255c..%255cadmin', '/a/%255cb', '/a/%252fb']) {
    assert.throws(() => policy.normalizePath(p), (e) => e.rule === 'path_ambiguous_separator', p)
  }
  // Three times, it is refused as an escape that was itself encoded.
  assert.throws(() => policy.normalizePath('/a/%25255cb'), (e) => e.rule === 'path_ambiguous_encoding')
})

test('ordinary encoded paths still normalise', () => {
  assert.equal(policy.normalizePath('/a/b%20c'), '/a/b c')
  assert.equal(policy.encodePathForWire(policy.normalizePath('/a/b%20c')), '/a/b%20c')
  assert.equal(policy.normalizePath('/v1beta/models/gemini-pro:generateContent'), '/v1beta/models/gemini-pro:generateContent')
  assert.equal(policy.normalizePath('/repos/o/r/%2e%2e/x'), '/repos/o/x')
})

test('a literal percent sign can be sent, and still cannot hide an escape', () => {
  assert.equal(policy.normalizePath('/files/100%25'), '/files/100%')
  assert.equal(policy.encodePathForWire(policy.normalizePath('/files/100%25')), '/files/100%25')
  assert.equal(policy.normalizePath('/q/50%25%20off'), '/q/50% off')
  // A literal % beside it does not hide an escape that is still live.
  for (const p of ['/%2561dmin%25', '/caf%25C3%25A9%25', `/user/${'%25'.repeat(12)}6beys`]) {
    assert.throws(() => policy.normalizePath(p), (e) => e.code === 'AV_POLICY_DENIED' && e.rule === 'path_ambiguous_encoding', p)
  }
  // The raw request is still held to a well-formed URL.
  assert.throws(() => policy.normalizePath('/a%zz'), /invalid percent-escape/)
})

// --------------------------------------------------------- policy intersect

test('intersecting two rates never allows more than either', () => {
  const MINUTE = 60_000
  const HOUR = 60 * MINUTE
  const allows = (r, windowMs) => {
    const per = { minute: MINUTE, hour: HOUR }[r.per] ?? r.per
    return r.count * (windowMs / per)
  }
  const a = { count: 10, per: 'minute' }
  const b = { count: 100, per: 'hour' }
  for (const [x, y] of [[a, b], [b, a]]) {
    const { rate } = policy.intersect([{ rate: x }, { rate: y }])
    assert.ok(allows(rate, HOUR) <= 100, `${JSON.stringify(rate)} allows ${allows(rate, HOUR)} an hour`)
    assert.ok(allows(rate, MINUTE) <= 10, `${JSON.stringify(rate)} allows ${allows(rate, MINUTE)} a minute`)
  }
})

test('intersecting rates in the same unit is the smaller count', () => {
  assert.deepEqual(policy.intersect([{ rate: { count: 10, per: 'minute' } }, { rate: { count: 5, per: 'minute' } }]).rate, { count: 5, per: 'minute' })
  assert.deepEqual(policy.intersect([{ rate: { count: 10, per: 'minute' } }, {}]).rate, { count: 10, per: 'minute' })
})

test('lint accepts valid enforced limits', () => {
  const base = { hosts: ['h'], budget: { unit: 'requests', limit: 5 } }
  assert.ok(!policy.lint({ ...base, max_concurrent: 2 }).some((p) => p.rule === 'max_concurrent'))
  assert.ok(!policy.lint({ ...base, rate: { count: 1, per: 'minute' } }).some((p) => p.rule === 'rate'))
  assert.ok(!policy.lint(base).some((p) => p.rule === 'max_concurrent' || p.rule === 'rate'))
})

// ------------------------------------------------------------- substitution

test('JSON substitution changes the one string and nothing else in the body', async () => {
  const s = setup({ sites: { key: ['json:/auth/token'] } })
  const ph = s.ph()
  const raw = `{ "id": 12345678901234567891, "ratio": 1.0, "auth": {"token": "${ph}", "n": [1e3, -0.50]}, "z": "\\u00e9" }`
  await s.pipeline.handle(s.request({ method: 'POST', headers: [...s.request().headers, ['content-type', 'application/json']], body: Buffer.from(raw) }))
  assert.equal(s.sent.length, 1)
  assert.equal(s.sent[0].body, raw.replace(ph, SECRET))
})

test('JSON substitution follows the same duplicate key and pointer escaping as the parser', () => {
  const ph = 'av1.PLACEHOLDER'
  const body = `{"a/b":{"t":"x"},"k":"first","k":"${ph}","arr":["${ph}"]}`
  const req = { method: 'POST', path: '/', query: '', headers: [['content-type', 'application/json']], body: Buffer.from(body) }
  const out1 = sub.apply(req, { region: 'json', pointer: '/k', encoding: 'raw' }, ph, 'S"1')
  assert.equal(out1.body.toString(), body.replace(`"k":"${ph}"`, '"k":"S\\"1"'))
  const out2 = sub.apply(req, { region: 'json', pointer: '/arr/0', encoding: 'raw' }, ph, 'S2')
  assert.equal(out2.body.toString(), body.replace(`["${ph}"]`, '["S2"]'))
})

test('form substitution leaves the rest of the field and the body as written', async () => {
  const s = setup({ sites: { key: ['form:token'] } })
  const ph = s.ph()
  const raw = `token=Bearer+${ph}+x%C3%A9&text=a+b%21&flag=&bare`
  await s.pipeline.handle(s.request({ method: 'POST', headers: [...s.request().headers, ['content-type', 'application/x-www-form-urlencoded']], body: Buffer.from(raw) }))
  assert.equal(s.sent[0].body, raw.replace(ph, encodeURIComponent(SECRET)))
})

test('Basic substitution writes the Authorization header the placeholder was found in', () => {
  const ph = 'av1.PLACEHOLDER'
  const basic = `Basic ${Buffer.from(`user:${ph}`).toString('base64')}`
  const req = { method: 'GET', path: '/', query: '', headers: [['Authorization', 'Bearer x'], ['authorization', basic]], body: null }
  const out = sub.apply(req, { region: 'basic', part: 'pass', index: 1, encoding: 'raw' }, ph, 'SECRET')
  assert.equal(out.headers[0][1], 'Bearer x')
  assert.equal(out.headers[1][1], `Basic ${Buffer.from('user:SECRET').toString('base64')}`)
})

// Two Authorization headers are two readings of one credential slot: which
// one the upstream acts on is its choice. Refused before anything is sent;
// the unit test above keeps the substitution itself honest.
test('Basic substitution through the pipeline, with a second Authorization header present', async () => {
  const s = setup({ sites: { key: ['basic:pass'] } })
  const ph = s.ph()
  const res = await s.pipeline.handle(s.request({
    headers: [...s.request().headers, ['Authorization', 'Bearer x'], ['authorization', `Basic ${Buffer.from(`user:${ph}`).toString('base64')}`]],
  }))
  assert.equal(res.status, 403); assert.equal(JSON.parse(res.body).rule, 'header_duplicate')
  assert.equal(s.sent.length, 0, 'a request went upstream')
})

test('an ordinary single Basic header is substituted as before', async () => {
  const s = setup({ sites: { key: ['basic:pass'] } })
  const ph = s.ph()
  await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['authorization', `Basic ${Buffer.from(`user:${ph}`).toString('base64')}`]] }))
  assert.equal(s.sent[0].headers.authorization, `Basic ${Buffer.from(`user:${SECRET}`).toString('base64')}`)
})

test('rate layers preserve canonical windows and refuse unknown units at evaluation', () => {
  const r = (x, y) => policy.intersect([{ rate: x }, { rate: y }]).rate
  assert.deepEqual(r({ count: 60, per: 'second' }, { count: 100, per: 'minute' }), { count: 100, per: 'minute' })
  const invalid = { count: 9, per: 'fortnight' }
  assert.deepEqual(r({ count: 5, per: 'minute' }, invalid), invalid)
  assert.throws(() => policy.evaluateHttp({ rate: invalid }, { method: 'GET', host: 'example.test', path: '/' }), (e) => e.rule === 'rate_invalid')
  const profile = { defaultBudget: { unit: 'requests', limit: 5 } }
  assert.deepEqual(policy.grantPolicyFromInput({ rate: '5/sec' }, { profile, ceiling: ['example.test'] }).rate, { count: 5, per: 'second' })
})

// ---------------------------------------------------------------- round 2

test('base64 wrapped at any width, and hex in mixed case, are redacted', () => {
  const b64 = Buffer.from(S).toString('base64')
  const hex = Buffer.from(S).toString('hex')
  // Every other letter upper case, so there is always one of each.
  let n = 0
  const mixed = hex.replace(/[a-f]/g, (c) => (n++ % 2 ? c.toUpperCase() : c))
  assert.ok(/[a-f]/.test(mixed) && /[A-F]/.test(mixed))
  const wrap = (t, w, br = '\n') => t.match(new RegExp(`.{1,${w}}`, 'g')).join(br)
  const cases = {
    b64At4: wrap(b64, 4), b64At8: wrap(b64, 8), b64At12: `body:\n${wrap(b64, 12)}\nend`,
    b64At8Crlf: wrap(b64, 8, '\r\n'), b64Indented: `  ${wrap(b64, 8, '\n  ')}`,
    b64TrailingSpace: wrap(b64, 8, ' \n'), b64At8JsonEscaped: `{"blob":"${wrap(b64, 8, '\\n')}"}`,
    mixedHex: `id=${mixed};`, mixedHexWrapped: wrap(mixed, 10), mixedHexWrapped8Crlf: wrap(mixed, 8, '\r\n'),
  }
  for (const [name, text] of Object.entries(cases)) {
    const { text: out, redactions } = scrubber().scrub(text)
    assert.ok(redactions > 0 && out.includes('[x]'), `${name}: ${out}`)
    const joined = out.replace(/\\n|\s/g, '')
    assert.ok(!Buffer.from(joined, 'base64').toString('latin1').includes(S), `${name}: base64 survives`)
    assert.ok(!Buffer.from(joined.replace(/[^0-9a-fA-F]/g, ''), 'hex').toString('latin1').includes(S), `${name}: hex survives`)
  }
})

test('several wrapped blobs in one body are each searched, and the search ends', () => {
  const wrap8 = (t) => Buffer.from(t).toString('base64').replace(/(.{8})/g, '$1\n')
  const ordinary = wrap8('an ordinary blob that is long enough to search')
  const text = `first:\n${ordinary}\n\nsecond:\n${wrap8(S)}\n\nthird:\n${ordinary}\n`
  const { text: out, redactions } = scrubber().scrub(text)
  assert.equal(redactions, 1)
  assert.ok(out.startsWith(`first:\n${ordinary}\n\nsecond:\n`) && out.endsWith(`third:\n${ordinary}\n`), out)
})

test('wrapped prose, short lines, ordinary blobs and ordinary mixed-case hex are left alone', () => {
  const texts = [
    'The quick brown fox\njumps over the lazy dog.\nconfiguration\nmanagement\n',
    'a\nb\nc\nde\nfg\n',
    Buffer.from('a perfectly ordinary blob of bytes that is not a secret at all').toString('base64').replace(/(.{8})/g, '$1\n'),
    'sha: 9F86d081884C7d659A2feaa0C55aD015a3BF4f1B2b0B822cd15D6c15B0F00A08',
    'DeadBeef CafeBabe 0xDEADbeef\nFACEfeed\n',
    Buffer.from(S.slice(0, 12)).toString('hex').toUpperCase().replace(/(.{4})/g, '$1\n'), // part of a secret is not the secret
  ]
  for (const t of texts) assert.deepEqual(scrubber().scrub(t), { text: t, redactions: 0 })
})

test('the wrapped and mixed-case views stay linear on large bodies', () => {
  const sc = scrubber()
  const bodies = ['ab\n'.repeat(1e6), 'aB'.repeat(2e6), 'The quick brown fox\n'.repeat(2e5), `ghp ${'x\n'.repeat(1e6)}`]
  for (const body of bodies) {
    const started = Date.now()
    assert.equal(sc.scrub(body).redactions, 0)
    assert.ok(Date.now() - started < 3000, `${body.slice(0, 8)}... took ${Date.now() - started} ms`)
  }
})

test('a path whose escape was itself encoded is refused, however many times it was', async () => {
  // Round 2 sent `/a/b%2520c` as written and checked two readings of it. An
  // upstream that decodes twice reads `/a/b%252520c` as `/a/b%20c`, which
  // neither reading was, and a deny on that resource did not hold.
  const twice = { hosts: ['up.test'], methods: ['GET'], paths: ['/**'], deny_paths: ['/a/b%20c'] }
  assert.throws(() => policy.evaluateHttp(twice, { method: 'GET', host: 'up.test', path: '/a/b%252520c' }),
    (e) => e.code === 'AV_POLICY_DENIED', 'a triply encoded path reached what an upstream decoding twice serves')
  const deny = { hosts: ['up.test'], methods: ['GET'], paths: ['/**'], deny_paths: ['/a/b%20c', '/a/b c', '/admin', '/user/keys'] }
  const spellings = [
    '/a/b%252520c', '/a/b%2520c', '/a/b%25252520c', '/%2561dmin', '/%252561dmin',
    '/user/%2525256beys', '/repos/%252e%252e/admin', '/repos/%25252e%25252e/admin', '/%25u0061dmin',
    '/a/b%25%32%30c',
  ]
  for (const p of spellings) {
    assert.throws(() => policy.evaluateHttp(deny, { method: 'GET', host: 'up.test', path: p }),
      (e) => e.code === 'AV_POLICY_DENIED' && e.rule === 'path_ambiguous_encoding', p)
  }
  // And through the pipeline: nothing reaches the upstream.
  const s = setup()
  for (const p of ['/p/a/b%252520c', '/p/a/b%2520c']) {
    const res = await s.pipeline.handle(s.request({ path: p, headers: [...s.request().headers, ['x-key', s.ph()]] }))
    assert.equal(res.status, 403, p)
    assert.match(res.body.toString(), /path_ambiguous_encoding/, p)
  }
  assert.equal(s.sent.length, 0)
})

test('a path encoded once is sent and checked as before', async () => {
  const s = setup()
  const cases = {
    '/p/a/b%20c/100%25': '/b%20c/100%25',
    '/p/a/caf%C3%A9/na%C3%AFve': '/caf%C3%A9/na%C3%AFve',
    '/p/a/q/50%25off/%25': '/q/50%25off/%25',
    '/p/a/x/%2e%2e/models/gemini-pro:generateContent': '/models/gemini-pro:generateContent',
    '/p/a/%E2%9C%93/%7Euser': '/%E2%9C%93/~user',
  }
  for (const [path, wire] of Object.entries(cases)) {
    await s.pipeline.handle(s.request({ path, headers: [...s.request().headers, ['x-key', s.ph()]] }))
    assert.equal(new URL(s.sent.at(-1).url).pathname, wire, path)
  }
  assert.equal(s.sent.length, Object.keys(cases).length)
  // An encoded slash is refused as it was, by its own rule.
  assert.throws(() => policy.normalizePath('/a%2Fb'), (e) => e.rule === 'path_ambiguous_separator')
  const allow = { hosts: ['up.test'], methods: ['GET'], paths: ['/a/**'] }
  assert.equal(policy.evaluateHttp(allow, { method: 'GET', host: 'up.test', path: '/a/b%20c' }).path, '/a/b c')
  assert.equal(policy.evaluateHttp(allow, { method: 'GET', host: 'up.test', path: '/a/caf%C3%A9' }).path, '/a/caf\u00e9')
})

test('a form placeholder with a percent-encoded character leaves the rest of the body as written', async () => {
  const s = setup({ sites: { key: ['form:token'] } })
  const ph = s.ph()
  const spelled = `%61${ph.slice(1)}`
  const raw = `token=Bearer+${spelled}+x%C3%A9&text=a+b%21&flag=&bare`
  const res = await s.pipeline.handle(s.request({ method: 'POST', headers: [...s.request().headers, ['content-type', 'application/x-www-form-urlencoded']], body: Buffer.from(raw) }))
  assert.equal(res.status, 200)
  assert.equal(s.sent[0].body, raw.replace(spelled, encodeURIComponent(SECRET)))
  assert.equal(new URLSearchParams(s.sent[0].body).get('token'), `Bearer ${SECRET} xé`)
})

const jsonPost = (s, body) => s.pipeline.handle(s.request({ method: 'POST', headers: [...s.request().headers, ['content-type', 'application/json']], body: Buffer.from(body) }))

test('a placeholder hidden by a duplicate JSON key is refused, however it is hidden', async () => {
  for (const shape of [
    (ph) => `{"token":"${ph}","token":"${ph}"}`,
    (ph) => `{"token":"${ph}","\\u0074oken":"${ph}"}`,
    (ph) => `{"auth":{"token":"${ph}"},"auth":{"token":"${ph}"}}`,
    (ph) => `{"auth":{"token":"${ph}"},"auth":"x","auth":{"token":"${ph}"}}`,
    (ph) => `{"${ph}":1,"token":"${ph}"}`,
  ]) {
    const s = setup({ sites: { key: ['json:/token', 'json:/auth/token'] } })
    const body = shape(s.ph('key', 5))
    const res = await jsonPost(s, body)
    assert.equal(res.status, 403, body)
    assert.equal(JSON.parse(res.body).code, 'AV_BAD_LOCATION', body)
    assert.equal(s.sent.length, 0, body)
  }
})

test('locate() reports a placeholder in a shadowed duplicate by position', () => {
  const ph = 'av1.aaaaaaaaaaaa.a_key.aaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaa'
  const req = { method: 'POST', path: '/', query: '', headers: [['content-type', 'application/json']], body: Buffer.from(`{"token":"${ph}","token":"${ph}"}`) }
  const regions = sub.locate(req).occurrences.map((o) => o.location.region)
  assert.deepEqual(regions.sort(), ['body', 'json'])
})

test('a substituted placeholder left anywhere in the outgoing request is found', () => {
  const ph = 'av1.aaaaaaaaaaaa.a_key.aaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaa'
  const nonce = 'aaaaaaaaaaaaaaaaaaaaaaaaaa'
  const req = (body) => ({ method: 'POST', path: '/', query: '', headers: [['content-type', 'application/json']], body: Buffer.from(body) })
  assert.equal(sub.unsubstituted(req(`{"token":"${ph}","token":"SECRET"}`), [nonce])?.location.region, 'body')
  assert.equal(sub.unsubstituted(req(`{"token":"SECRET","n":12345678901234567891}`), [nonce]), null)
})

test('ordinary JSON, duplicates without a placeholder in the shadowed copy included, is substituted as before', async () => {
  const s = setup({ sites: { key: ['json:/token'] } })
  const ph = s.ph()
  const raw = `{"token":"first","token":"${ph}","n":12345678901234567891,"keys":{"a":"${'x'.repeat(80)}","a":"y"}}`
  const res = await jsonPost(s, raw)
  assert.equal(res.status, 200)
  assert.equal(s.sent[0].body, raw.replace(ph, SECRET))
})

