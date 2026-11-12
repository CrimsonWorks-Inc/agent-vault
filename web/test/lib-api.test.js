// lib/api.js: the only request path. Same origin, the custom header the
// server requires, and errors read into ApiError with the right kind.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createApi, ApiError, errorFrom, withQuery, UI_HEADER } from '../src/lib/api.js'

const reply = (status, body) => ({ ok: status < 400, status, json: async () => body })

function client(answer) {
  const seen = []
  const fatal = []
  const api = createApi({
    fetch: async (url, init) => { seen.push({ url, init }); return typeof answer === 'function' ? answer(url, init) : answer },
    onFatal: (e) => fatal.push(e),
  })
  return { api, seen, fatal }
}

test('the header name is the one the UI server checks', () => {
  const server = readFileSync(new URL('../../legacy/js/src/ui/server.js', import.meta.url), 'utf8')
  assert.match(server, new RegExp(`req\\.headers\\['${UI_HEADER}'\\] !== '1'`))
})

test('every request is same-origin, carries the header, and sends JSON only with a body', async () => {
  const { api, seen } = client(reply(200, { ok: true }))
  await api.get('status')
  await api.post('lock', { presence: { challengeId: 'c' } })
  await api.del('sessions', { sid: 's 1' }, { presence: {} })
  await api.post('presence/enroll/begin')
  assert.equal(seen[0].url, '/api/status')
  for (const { init } of seen) {
    assert.equal(init.credentials, 'same-origin')
    assert.equal(init.headers[UI_HEADER], '1')
  }
  assert.equal(seen[0].init.body, undefined)
  assert.equal(seen[0].init.headers['content-type'], undefined)
  assert.equal(seen[1].init.headers['content-type'], 'application/json')
  assert.deepEqual(JSON.parse(seen[1].init.body), { presence: { challengeId: 'c' } })
  assert.equal(seen[2].url, '/api/sessions?sid=s+1')
  assert.equal(seen[2].init.method, 'DELETE')
  assert.equal(seen[3].init.body, undefined, 'a POST with no body sends none, as the old page did')
})

test('a refusal becomes an ApiError with status, code and detail', async () => {
  const { api, fatal } = client(reply(403, { error: 'the verdict must be true or false', detail: { code: 'AV_POLICY_DENIED', rule: 'bulk_decision' } }))
  const e = await api.post('approvals', { granted: 'false' }).catch((x) => x)
  assert.ok(e instanceof ApiError)
  assert.equal(e.status, 403)
  assert.equal(e.code, 'AV_POLICY_DENIED')
  assert.equal(e.message, 'the verdict must be true or false')
  assert.equal(e.detail.rule, 'bulk_decision')
  assert.equal(e.kind, 'http')
  assert.equal(fatal.length, 0, 'an ordinary refusal is shown beside the button, not as a full page')
})

test('the flat {code, detail} shape reads too', () => {
  const e = errorFrom(400, { code: 'AV_BAD_CURSOR', detail: 'that cursor is not one this server issued' })
  assert.equal(e.code, 'AV_BAD_CURSOR')
  assert.equal(e.message, 'that cursor is not one this server issued')
})

test('only the cookie check is a lost session; a presence 401 is not', async () => {
  const lost = client(reply(401, { error: 'not authenticated' }))
  const e1 = await lost.api.get('status').catch((x) => x)
  assert.equal(e1.kind, 'session')
  assert.equal(lost.fatal.length, 1)

  const sig = client(reply(401, { error: 'this action needs a fresh authenticator signature' }))
  const e2 = await sig.api.post('lock', {}).catch((x) => x)
  assert.equal(e2.kind, 'http')
  assert.equal(sig.fatal.length, 0)
})

test('503 is the daemon, a network failure is the UI server', async () => {
  const down = client(reply(503, { error: 'connect ENOENT /tmp/av.sock' }))
  assert.equal((await down.api.get('status').catch((x) => x)).kind, 'daemon')
  assert.equal(down.fatal.length, 1)

  const gone = client(() => { throw new TypeError('Failed to fetch') })
  const e = await gone.api.get('status').catch((x) => x)
  assert.equal(e.kind, 'server')
  assert.equal(e.status, 0)
  assert.equal(gone.fatal.length, 1)
})

test('a body that is not JSON still gives a useful error', async () => {
  const { api } = client({ ok: false, status: 500, json: async () => { throw new SyntaxError('x') } })
  const e = await api.get('status').catch((x) => x)
  assert.equal(e.message, 'request failed (500)')
})

test('withQuery leaves out empty values and appends to an existing query', () => {
  assert.equal(withQuery('audit', { kind: 'tripwire.fired', limit: 5, cursor: null, q: '' }), 'audit?kind=tripwire.fired&limit=5')
  assert.equal(withQuery('a?x=1', { y: 2 }), 'a?x=1&y=2')
  assert.equal(withQuery('a', {}), 'a')
})
