// queryBound builds the five gated DELETEs whose operation the server binds
// from the query string. Checked against src/ui/server.js itself, not a copy
// of it: a real UiServer over a fake control socket mints a challenge for the
// operation the page would sign, and the DELETE goes in with that challenge
// and a dummy proof. The server compares the two operations BEFORE it checks
// the signature, so a mismatch is 409 "signed for a different operation",
// and a match gets as far as the signature check and fails there instead.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { UiServer } from '../../src/ui/server.js'
import { queryBound, QUERY_BOUND, operationFor, canonicalJson } from '../src/lib/presence.js'
import { withQuery, UI_HEADER } from '../src/lib/api.js'
import * as webauthn from '../../src/ui/webauthn.js'

let dir, daemon, ui, cookie
let minted = 0

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-qb-'))
  const sock = join(dir, 'control.sock')
  // Just enough of a daemon: an enrolled key, and a challenge minter.
  daemon = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => {
      res.setHeader('content-type', 'application/json')
      if (req.method === 'GET' && req.url === '/v1/presence') return res.end(JSON.stringify({ credentialId: randomBytes(16).toString('base64url'), publicKeySpki: 'AAAA', signCount: 0 }))
      if (req.method === 'POST' && req.url === '/v1/presence/challenge') {
        return res.end(JSON.stringify({ challengeId: `ch${++minted}`, challenge: randomBytes(32).toString('base64url'), allowCredentials: [{ id: 'AAAA' }] }))
      }
      res.statusCode = 404
      res.end('{"error":"not in this fake"}')
    })
  })
  await new Promise((r) => daemon.listen(sock, r))
  ui = await new UiServer(sock, { port: 0, statePath: join(dir, 'cli-state.json') }).start()
  const claim = await fetch(ui.url, { redirect: 'manual' })
  cookie = /av_ui=([^;]+)/.exec(claim.headers.get('set-cookie') || '')[1]
})

after(async () => {
  await ui?.stop()
  await new Promise((r) => daemon?.close(r))
  rmSync(dir, { recursive: true, force: true })
})

async function call(method, path, body) {
  const res = await fetch(`${ui.origin}/api/${path}`, {
    method,
    headers: { [UI_HEADER]: '1', cookie: `av_ui=${cookie}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  return { status: res.status, body: await res.json().catch(() => ({})) }
}

/** Sign `operation` (as far as the challenge), then send `path?query` with it. */
async function submit(operation, path, query) {
  const ch = await call('POST', 'presence/challenge', { operation })
  assert.equal(ch.status, 200, JSON.stringify(ch.body))
  const proof = { challengeId: ch.body.challengeId, credentialId: 'AAAA', authenticatorData: 'AAAA', clientDataJSON: 'AAAA', signature: 'AAAA' }
  return call('DELETE', withQuery(path, query), { presence: proof })
}
const MISMATCH = /different operation/

const CASES = [
  ['DELETE credentials', { slug: 'gh-work' }],
  ['DELETE sessions', { sid: 's_123' }],
  ['DELETE credentials/scrub', { slug: 'gh-work', id: 3 }],
  ['DELETE credentials/pins', { slug: 'gh-work', host: 'api.github.com', spki: 'sha256/abc=' }],
  ['DELETE credentials/pins', { slug: 'gh-work', host: 'api.github.com' }],          // every pin: spki absent
  ['DELETE credentials/pins', { slug: 'gh-work', host: 'api.github.com', spki: '' }], // the same
  ['DELETE templates', { name: 'read-only' }],
]

test('every query-bound route has a case here', () => {
  assert.deepEqual(new Set(CASES.map(([r]) => r)), new Set(Object.keys(QUERY_BOUND)))
})

for (const [route, params] of CASES) {
  test(`${route} ${JSON.stringify(params)}: the server binds what the page signs`, async () => {
    const r = queryBound(route, params)
    const res = await submit(r.operation, r.path, r.query)
    assert.ok(!MISMATCH.test(res.body.error || ''), `server.js bound a different operation: ${res.status} ${res.body.error}`)
    // It got as far as the signature, which the dummy proof fails.
    assert.notEqual(res.status, 200)
  })
}

test('the check can tell: an operation that leaves spki out is refused as a different operation', async () => {
  const r = queryBound('DELETE credentials/pins', { slug: 'gh', host: 'api.github.com' })
  const { spki: _gone, ...wrong } = r.operation
  const res = await submit(wrong, r.path, r.query)
  assert.equal(res.status, 409)
  assert.match(res.body.error, MISMATCH)
  // And so does a number where the server reads a string.
  const n = queryBound('DELETE credentials/scrub', { slug: 'gh', id: 3 })
  const res2 = await submit({ ...n.operation, id: 3 }, n.path, n.query)
  assert.equal(res2.status, 409)
})

test('queryBound reads fields as the server does, and refuses what it does not bind', () => {
  assert.deepEqual(queryBound('DELETE credentials/pins', { slug: 'gh', host: 'h' }), {
    method: 'DELETE', path: 'credentials/pins', query: { slug: 'gh', host: 'h' },
    operation: { op: 'cred.pins_remove', slug: 'gh', host: 'h', spki: null },
  })
  assert.deepEqual(queryBound('DELETE credentials/scrub', { slug: 'gh', id: 7 }).operation, { op: 'cred.scrub_remove', slug: 'gh', id: '7' })
  assert.throws(() => queryBound('DELETE sessions', { sid: 's', all: true }), /does not bind all/)
  assert.throws(() => queryBound('POST sessions', {}), /not a query-bound/)
  // The same canonical form webauthn.js builds for the server's own reading.
  const url = new URL(`http://x/${withQuery('credentials/pins', queryBound('DELETE credentials/pins', { slug: 'gh', host: 'h' }).query)}`)
  const server = webauthn.operationFor('cred.pins_remove', { slug: url.searchParams.get('slug'), host: url.searchParams.get('host'), spki: url.searchParams.get('spki') })
  assert.equal(canonicalJson(queryBound('DELETE credentials/pins', { slug: 'gh', host: 'h' }).operation), webauthn.canonicalOperation(server))
})

test('operationFor refuses the reserved fields as webauthn.js does, before any digest', async () => {
  const cases = [
    ['cred.add', { slug: 'gh', op: 'session.create' }],
    ['cred.add', { slug: 'gh', value: 'sk-test-real', value_sha256: '00'.repeat(32) }],
    ['session.create', { label: 'x', anything_sha256: 'ab' }],
  ]
  for (const [op, params] of cases) {
    let serverError = null
    try { webauthn.operationFor(op, params) } catch (e) { serverError = e }
    assert.ok(serverError, `the server accepts ${JSON.stringify(params)}?`)
    await assert.rejects(operationFor(op, params), (e) => {
      assert.ok(serverError.message.endsWith(e.message), `${e.message} vs ${serverError.message}`)
      assert.equal(e.code, serverError.code)
      assert.equal(e.rule, 'reserved_operation_field')
      return true
    })
  }
  // The route's own op repeated in the body is allowed, by both.
  const same = await operationFor('cred.add', { slug: 'gh', op: 'cred.add' })
  assert.equal(canonicalJson(same), webauthn.canonicalOperation(webauthn.operationFor('cred.add', { slug: 'gh', op: 'cred.add' })))
})
