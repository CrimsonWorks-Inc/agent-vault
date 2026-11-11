// Gateway, from outside: substitution, scrubbing, confinement, budgets, approvals.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { rustSkipReason, openWorld, seed, gateway, leaksSecret, LOOKALIKE } from './lib/harness.js'

const skip = rustSkipReason()
if (skip) {
  test('gateway', { skip }, () => {})
} else {
  describe('gateway', { concurrency: false, timeout: 120_000 }, () => {
    let w
    before(async () => {
      w = await openWorld()
      await seed(w)
    })
    after(async () => { await w?.close() })

    const token = () => w.session.token
    const placeholder = () => w.session.placeholder

    test('substitution only at the declared authorization site', async () => {
      const before = w.upstream.hits.length
      const res = await gateway(w, `/p/${w.slug}/echo`, { token: token(), placeholder: placeholder() })
      assert.equal(res.status, 200)
      assert.equal(res.json.ordinary, 'ordinary-traffic-control')
      assert.equal(res.json.lookalike, LOOKALIKE)
      assert.equal(leaksSecret(res.text), null)
      assert.equal(w.upstream.hits.length, before + 1)
      assert.equal(w.upstream.hits.at(-1).seen, 'test-secret-conform-0123456789abcdef')
      assert.equal(leaksSecret(w.log()), null)
    })

    test('a placeholder anywhere else is refused and not forwarded', async () => {
      const before = w.upstream.hits.length
      const res = await gateway(w, `/p/${w.slug}/user?q=${encodeURIComponent(placeholder())}`, {
        token: token(),
        placeholder: placeholder(),
      })
      assert.equal(res.status, 403)
      assert.equal(res.json.code, 'AV_BAD_LOCATION')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(res.text), null)

      const inBody = await gateway(w, `/p/${w.slug}/user`, {
        method: 'POST',
        token: token(),
        placeholder: placeholder(),
        headers: { 'content-type': 'text/plain' },
        body: `note ${placeholder()}`,
      })
      assert.equal(inBody.status, 403)
      assert.equal(inBody.json.code, 'AV_BAD_LOCATION')
      assert.equal(w.upstream.hits.length, before)
    })

    test('host confinement refuses an undeclared host before connecting', async () => {
      const before = w.upstream.hits.length
      const res = await gateway(w, '/t/http/evil.example/user', { token: token(), placeholder: placeholder() })
      assert.equal(res.status, 403)
      assert.equal(res.json.code, 'AV_NO_GRANT')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(res.text), null)
    })

    test('a spent budget is refused', async () => {
      const made = await w.control('POST', '/v1/sessions', {
        cred: w.slug, label: 'budget', methods: ['GET'], paths: ['/**'], budget: 1, approval: 'on-write', ttl_hours: 1,
      })
      assert.equal(made.status, 200, made.text)
      const limited = { token: made.json.token, placeholder: made.json.placeholder }
      const first = await gateway(w, `/p/${w.slug}/user`, limited)
      assert.equal(first.status, 200)
      assert.equal(leaksSecret(first.text), null)
      const second = await gateway(w, `/p/${w.slug}/user`, limited)
      assert.equal(second.status, 403)
      assert.equal(second.json.code, 'AV_POLICY_DENIED')
      assert.equal(second.json.rule, 'budget')
    })

    test('preflight predicts and does not spend a budget or create an approval', async () => {
      const sid = w.session.session_id
      const before = await w.control('GET', `/v1/sessions/detail?sid=${sid}`)
      const used = before.json.grants[0].budget.used
      const waiting = await w.control('GET', '/v1/approvals')
      const pre = await gateway(w, '/v1/preflight', {
        method: 'POST',
        token: token(),
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          method: 'POST',
          path: `/p/${w.slug}/echo`,
          headers: [['content-type', 'application/json']],
          body: '{"n":1}',
          assume_placeholder: true,
        }),
      })
      assert.equal(pre.status, 200)
      assert.equal(pre.json.would, 'hold')
      assert.equal(typeof pre.json.advisory, 'string')
      const after = await w.control('GET', `/v1/sessions/detail?sid=${sid}`)
      assert.equal(after.json.grants[0].budget.used, used)
      const still = await w.control('GET', '/v1/approvals')
      assert.equal(still.json.length, waiting.json.length)

      const get = await gateway(w, '/v1/preflight', {
        method: 'POST',
        token: token(),
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method: 'GET', path: `/p/${w.slug}/user`, assume_placeholder: true }),
      })
      assert.equal(get.status, 200)
      assert.equal(get.json.would, 'allow')
      const spent = await w.control('GET', `/v1/sessions/detail?sid=${sid}`)
      assert.equal(spent.json.grants[0].budget.used, used)
    })

    test('an on-write request is held, then runs once when granted and stays refused when denied', async () => {
      const send = (body) => gateway(w, `/p/${w.slug}/echo`, {
        method: 'POST',
        token: token(),
        placeholder: placeholder(),
        headers: { 'content-type': 'application/json' },
        body,
      })
      const held = await send('{"n":1}')
      assert.equal(held.status, 202)
      assert.equal(held.json.code, 'AV_APPROVAL_PENDING')
      const id = held.json.approval_id
      assert.equal(typeof id, 'string')
      assert.equal(held.headers['av-approval-id'], id)
      const hits = w.upstream.hits.length

      const granted = await w.control('POST', '/v1/approvals', { id, granted: true })
      assert.equal(granted.status, 200, granted.text)
      const ran = await send('{"n":1}')
      assert.equal(ran.status, 200)
      assert.equal(leaksSecret(ran.text), null)
      assert.equal(ran.json.ordinary, 'ordinary-traffic-control')
      assert.equal(w.upstream.hits.length, hits + 1)

      const again = await send('{"n":1}')
      assert.equal(again.headers['av-replayed'], 'true')
      assert.equal(w.upstream.hits.length, hits + 1)
      assert.equal(leaksSecret(again.text), null)

      const other = await send('{"n":2}')
      assert.equal(other.status, 202)
      const denied = await w.control('POST', '/v1/approvals', { id: other.json.approval_id, granted: false })
      assert.equal(denied.status, 200, denied.text)
      const replay = await send('{"n":2}')
      assert.equal(replay.status, 403)
      assert.equal(replay.json.code, 'AV_POLICY_DENIED')
      assert.equal(replay.json.rule, 'approval')
      assert.equal(w.upstream.hits.length, hits + 1)
    })

    test('discovery routes and a browser Origin', async () => {
      const status = await gateway(w, '/v1/status')
      assert.equal(status.status, 200)
      assert.equal(typeof status.json.daemon_version, 'string')
      assert.equal(leaksSecret(status.text), null)

      const missing = await gateway(w, '/v1/session')
      assert.equal(missing.status, 401)
      assert.equal(missing.json.code, 'AV_SESSION_REQUIRED')

      const session = await gateway(w, '/v1/session', { token: token() })
      assert.equal(session.status, 200)
      assert.equal(session.json.id, w.session.session_id)
      assert.equal(session.text.includes(token()), false)

      const creds = await gateway(w, '/v1/credentials', { token: token() })
      assert.equal(creds.status, 200)
      assert.equal(creds.json[0].slug, w.slug)
      assert.equal(leaksSecret(creds.text), null)

      const minted = await gateway(w, `/v1/placeholders?cred=${w.slug}`, { method: 'POST', token: token() })
      assert.equal(minted.status, 200)
      assert.match(minted.json.placeholder, /^av1\./)
      assert.equal(leaksSecret(minted.text), null)

      const browser = await gateway(w, '/v1/preflight', {
        method: 'POST',
        token: token(),
        headers: { origin: 'http://evil.test', 'content-type': 'application/json' },
        body: '{}',
      })
      assert.equal(browser.status, 403)
      assert.equal(browser.json.code, 'AV_BROWSER_ORIGIN')

      const mcp = await gateway(w, '/mcp', {
        method: 'POST',
        token: token(),
        headers: { origin: 'http://evil.test', 'content-type': 'application/json' },
        body: '{}',
      })
      assert.equal(mcp.status, 403)
      assert.equal(mcp.json.code, 'AV_BROWSER_ORIGIN')
    })
  })
}
