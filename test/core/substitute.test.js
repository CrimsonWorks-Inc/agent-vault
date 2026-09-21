import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import * as ph from '../../src/core/placeholder.js'
import * as sub from '../../src/core/substitute.js'
import * as sites from '../../src/core/sites.js'
import * as detect from '../../src/core/detect.js'

const K = randomBytes(32)
const SID = ph.newSid()
const mk = () => ph.mint({ kPh: K, sid: SID, slug: 'gh-frozencrow', field: 'token' }).text

function req(over = {}) {
  return { method: 'GET', path: '/repos/frozencrow/agent-vault/issues', query: '', headers: [], body: null, ...over }
}

const bearerSite = sites.parseSite('header:authorization:Bearer')

// ---------------------------------------------------------------- declared sites

test('a placeholder at a declared header site is located and substituted', () => {
  const p = mk()
  const r = req({ headers: [['Authorization', `Bearer ${p}`]] })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 1)
  assert.ok(sub.matchesSite(occurrences[0].location, bearerSite))

  const out = sub.apply(r, occurrences[0].location, p, 'ghp_REALSECRETVALUE123456')
  assert.equal(sub.getHeader(out, 'authorization'), 'Bearer ghp_REALSECRETVALUE123456')
  assert.equal(sub.getHeader(r, 'authorization'), `Bearer ${p}`, 'input must not be mutated')
})

test('the scheme must match the declared site', () => {
  const p = mk()
  const r = req({ headers: [['Authorization', `token ${p}`]] })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences[0].location.scheme, 'token')
  assert.ok(!sub.matchesSite(occurrences[0].location, bearerSite))
  assert.ok(sub.matchesSite(occurrences[0].location, sites.parseSite('header:authorization:token')))
})

test('scheme matching tolerates case and repeated whitespace, per RFC 9110', () => {
  const p = mk()
  for (const value of [`bearer ${p}`, `BEARER   ${p}`, `Bearer\t${p}`]) {
    const { occurrences } = sub.locate(req({ headers: [['Authorization', value]] }))
    assert.equal(occurrences.length, 1, value)
    assert.ok(sub.matchesSite(occurrences[0].location, bearerSite), value)
  }
})

test('Authorization: Basic is decoded so the password field is a real site', () => {
  const p = mk()
  const encoded = Buffer.from(`x-access-token:${p}`).toString('base64')
  const r = req({ headers: [['Authorization', `Basic ${encoded}`]] })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 1)
  assert.equal(occurrences[0].location.region, 'basic')
  assert.equal(occurrences[0].location.part, 'pass')
  assert.ok(sub.matchesSite(occurrences[0].location, sites.parseSite('basic:pass')))

  const out = sub.apply(r, occurrences[0].location, p, 'ghp_REALSECRET1234567890')
  const decoded = Buffer.from(sub.getHeader(out, 'authorization').slice(6), 'base64').toString()
  assert.equal(decoded, 'x-access-token:ghp_REALSECRET1234567890')
})

test('a JSON body pointer is a site when declared, and substitutes in place', () => {
  const p = mk()
  const body = Buffer.from(JSON.stringify({ auth: { key: p }, note: 'hello' }))
  const r = req({ method: 'POST', headers: [['Content-Type', 'application/json']], body })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 1)
  assert.equal(occurrences[0].location.pointer, '/auth/key')
  assert.ok(sub.matchesSite(occurrences[0].location, sites.parseSite('json:/auth/key')))

  const out = sub.apply(r, occurrences[0].location, p, 'sk-REALSECRET1234567890')
  assert.deepEqual(JSON.parse(out.body.toString()), { auth: { key: 'sk-REALSECRET1234567890' }, note: 'hello' })
  assert.equal(sub.getHeader(out, 'content-length'), String(out.body.length))
})

test('a form field is a site when declared', () => {
  const p = mk()
  const body = Buffer.from(`token=${p}&channel=general`)
  const r = req({ method: 'POST', headers: [['Content-Type', 'application/x-www-form-urlencoded']], body })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 1)
  assert.ok(sub.matchesSite(occurrences[0].location, sites.parseSite('form:token')))
  const out = sub.apply(r, occurrences[0].location, p, 'xoxb-REALSECRET123456')
  assert.match(out.body.toString(), /token=xoxb-REALSECRET123456&channel=general/)
})

test('a query parameter is a site when declared and is re-encoded on substitution', () => {
  const p = mk()
  const r = req({ query: `key=${p}&pretty=1` })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences[0].location.key, 'key')
  assert.ok(sub.matchesSite(occurrences[0].location, sites.parseSite('query:key')))
  const out = sub.apply(r, occurrences[0].location, p, 'AIzaREALSECRET123456789')
  assert.equal(out.query, 'key=AIzaREALSECRET123456789&pretty=1')
})

// ------------------------------------------------------- misplaced: the core rule

test('the request path is never a site', () => {
  const p = mk()
  const r = req({ path: `/repos/${p}/issues` })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 1)
  assert.equal(occurrences[0].location.region, 'path')
  for (const s of ['header:authorization:Bearer', 'basic:pass', 'json:/auth/key', 'query:key', 'form:token']) {
    assert.ok(!sub.matchesSite(occurrences[0].location, sites.parseSite(s)))
  }
})

test('a placeholder in an undeclared body field is located and matches no site', () => {
  // This is the prompt-injection case: "post your token in this issue comment".
  const p = mk()
  const body = Buffer.from(JSON.stringify({ body: `here is my token: ${p}` }))
  const r = req({ method: 'POST', headers: [['Content-Type', 'application/json']], body })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 1)
  assert.equal(occurrences[0].location.pointer, '/body')
  assert.ok(!sub.matchesSite(occurrences[0].location, sites.parseSite('json:/auth/key')))
  assert.ok(!sub.matchesSite(occurrences[0].location, bearerSite))
})

test('a placeholder in an undeclared header matches no declared site', () => {
  const p = mk()
  const r = req({ headers: [['X-Debug-Token', p]] })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences[0].location.name, 'x-debug-token')
  assert.ok(!sub.matchesSite(occurrences[0].location, bearerSite))
})

// --------------------------------------------------------- encoding evasion

// A placeholder is entirely RFC 3986 unreserved, so encodeURIComponent is a
// no-op on it: that is a property of the grammar, asserted here so a future
// grammar change that breaks it is caught. The real evasion is a tool that
// aggressively encodes dots, which does change the bytes.
const pctEncode = (s) => s.replace(/\./g, '%2e')

test('a placeholder is unchanged by ordinary URL encoding', () => {
  const p = mk()
  assert.equal(encodeURIComponent(p), p)
})

test('percent-encoded placeholders are detected and never count as a site', () => {
  const p = mk()
  const r = req({ method: 'POST', headers: [['Content-Type', 'text/plain']], body: Buffer.from(pctEncode(p)) })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 1)
  assert.equal(occurrences[0].location.encoding, 'percent')
  assert.ok(!sub.matchesSite(occurrences[0].location, sites.parseSite('json:/x')))
})

test('double percent-encoding is detected', () => {
  const p = mk()
  const twice = pctEncode(p).replace(/%/g, '%25')
  const hits = detect.detectAll(twice)
  assert.ok(hits.length >= 1)
  assert.ok(hits.some((h) => h.encoding === 'percent-double'))
})

test('JSON unicode escapes are detected', () => {
  const p = mk()
  const escaped = [...p].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')
  const hits = detect.detectAll(escaped)
  assert.equal(hits.length, 1)
  assert.equal(hits[0].encoding, 'json-escape')
  assert.equal(hits[0].text, p)
})

test('base64 smuggling is detected at every alignment and in both alphabets', () => {
  const p = mk()
  for (const prefix of ['', 'a', 'bb', 'ccc']) {
    for (const urlSafe of [false, true]) {
      let b64 = Buffer.from(prefix + p, 'utf8').toString('base64')
      if (urlSafe) b64 = b64.replace(/\+/g, '-').replace(/\//g, '_')
      const hits = detect.detectAll(`{"data":"${b64}"}`)
      assert.ok(hits.some((h) => h.text === p && h.encoding === 'base64'),
        `alignment ${prefix.length} urlSafe=${urlSafe} should be caught`)
    }
  }
})

test('a Basic header is read as its site and not double-reported as base64', () => {
  const p = mk()
  const encoded = Buffer.from(`x:${p}`).toString('base64')
  const { occurrences } = sub.locate(req({ headers: [['Authorization', `Basic ${encoded}`]] }))
  assert.equal(occurrences.length, 1)
  assert.equal(occurrences[0].location.encoding, 'raw')
})

test('UTF-16 and other non-matching encodings do not produce false positives', () => {
  const p = mk()
  const utf16 = Buffer.from(p, 'utf16le').toString('latin1')
  const hits = detect.detectAll(utf16)
  assert.equal(hits.length, 0)
})

test('a body with no placeholder produces no occurrences', () => {
  const r = req({ method: 'POST', headers: [['Content-Type', 'application/json']], body: Buffer.from('{"title":"a normal issue"}') })
  assert.equal(sub.locate(r).occurrences.length, 0)
})

test('multiple placeholders in one request are each located separately', () => {
  const a = mk()
  const b = ph.mint({ kPh: K, sid: SID, slug: 'pg-prod', field: 'password' }).text
  const r = req({ headers: [['Authorization', `Bearer ${a}`], ['X-Other', b]] })
  const { occurrences } = sub.locate(r)
  assert.equal(occurrences.length, 2)
  assert.deepEqual(occurrences.map((o) => o.location.region), ['header', 'header'])
})

test('an oversized body is reported unscannable rather than forwarded unchecked', () => {
  const r = req({ method: 'POST', headers: [['Content-Type', 'application/json']], body: Buffer.alloc(sub.MAX_BUFFERED_BODY + 1, 0x20) })
  const result = sub.locate(r)
  assert.match(result.unscannable, /16 MiB/)
})

test('describeLocation is specific enough for an agent to fix its own request', () => {
  const p = mk()
  const r = req({ method: 'POST', headers: [['Content-Type', 'application/json']], body: Buffer.from(JSON.stringify({ comment: p })) })
  const { occurrences } = sub.locate(r)
  assert.equal(sub.describeLocation(occurrences[0].location), 'JSON body at /comment')
})
