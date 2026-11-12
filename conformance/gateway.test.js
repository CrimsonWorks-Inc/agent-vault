// Gateway, from outside: substitution, scrubbing, confinement, budgets, approvals.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { connect } from 'node:net'
import { createServer as createTlsServer } from 'node:https'
import { mkdtemp, rm } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { rustSkipReason, openWorld, seed, gateway, leaksSecret, LOOKALIKE, SECRET, pinValue } from './lib/harness.js'

function rawGateway(port, path, { method = 'GET', headers = [], body = '' } = {}) {
  const payload = Buffer.from(body)
  const lines = [
    `${method} ${path} HTTP/1.1`,
    `Host: 127.0.0.1:${port}`,
    `Content-Length: ${payload.length}`,
    'Connection: close',
    ...headers.map(([name, value]) => `${name}: ${value}`),
    '',
    '',
  ]
  return new Promise((resolve, reject) => {
    const sock = connect(port, '127.0.0.1', () => sock.end(Buffer.concat([Buffer.from(lines.join('\r\n')), payload])))
    const chunks = []
    sock.on('data', (c) => chunks.push(c))
    sock.on('error', reject)
    sock.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      const split = raw.indexOf('\r\n\r\n')
      const head = split === -1 ? raw : raw.slice(0, split)
      const text = split === -1 ? '' : raw.slice(split + 4)
      const status = Number(head.split('\r\n')[0].split(' ')[1])
      const headersOut = {}
      for (const line of head.split('\r\n').slice(1)) {
        const i = line.indexOf(':')
        if (i === -1) continue
        headersOut[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim()
      }
      let bodyText = text
      if (/chunked/i.test(headersOut['transfer-encoding'] || '')) {
        const parts = []
        let rest = text
        while (rest.length) {
          const nl = rest.indexOf('\r\n')
          if (nl === -1) break
          const size = Number.parseInt(rest.slice(0, nl), 16)
          if (!Number.isFinite(size) || size === 0) break
          const start = nl + 2
          parts.push(rest.slice(start, start + size))
          rest = rest.slice(start + size + 2)
        }
        bodyText = parts.join('')
      }
      let json = null
      try { json = bodyText.trim() ? JSON.parse(bodyText) : null } catch { json = null }
      resolve({ status, headers: headersOut, text: bodyText, json })
    })
  })
}

function startCatcher(host = '127.0.0.1') {
  const hits = []
  const server = createServer((req, res) => {
    hits.push({ method: req.method, url: req.url })
    res.end('{}')
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, host, () => resolve({
      port: server.address().port,
      hits,
      close: () => new Promise((r) => server.close(r)),
    }))
  })
}

const skip = rustSkipReason()
if (skip) {
  test('gateway', { skip }, () => {})
} else {
  describe('gateway', { concurrency: false, timeout: 180_000 }, () => {
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
      // The credential's host is 127.0.0.1, and the port is not part of the
      // match, so another port on that address is still this credential.
      // `localhost` is a different name. The catcher listens on 127.0.0.1,
      // which is where that name connects, so a request that was sent anyway
      // would land here. 127.0.0.2 is not assigned on this machine.
      const catcher = await startCatcher()
      try {
        const before = w.upstream.hits.length
        const res = await gateway(w, `/t/http/localhost:${catcher.port}/x`, { token: token(), placeholder: placeholder() })
        assert.equal(res.status, 403, res.text)
        assert.equal(res.json.code, 'AV_NO_GRANT')
        assert.equal(w.upstream.hits.length, before)
        assert.equal(catcher.hits.length, 0)
        assert.equal(leaksSecret(res.text), null)
        const ok = await gateway(w, `/p/${w.slug}/user`, { token: token(), placeholder: placeholder() })
        assert.equal(ok.status, 200, ok.text)
        assert.equal(ok.json.ordinary, 'ordinary-traffic-control')
      } finally {
        await catcher.close()
      }
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

    test('a method-override cannot name a method the grant did not allow', async () => {
      const before = w.upstream.hits.length
      const header = await gateway(w, `/p/${w.slug}/user`, {
        token: token(),
        placeholder: placeholder(),
        headers: { 'x-http-method-override': 'DELETE' },
      })
      assert.equal(header.status, 403, header.text)
      assert.equal(header.json.code, 'AV_POLICY_DENIED')
      assert.equal(header.json.rule, 'methods')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(header.text), null)

      const field = await gateway(w, `/p/${w.slug}/user?_method=DELETE`, {
        token: token(),
        placeholder: placeholder(),
      })
      assert.equal(field.status, 403, field.text)
      assert.equal(field.json.code, 'AV_POLICY_DENIED')
      assert.equal(field.json.rule, 'method_override')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(field.text), null)

      const ok = await gateway(w, `/p/${w.slug}/user`, {
        token: token(),
        placeholder: placeholder(),
        headers: { 'x-http-method-override': 'GET' },
      })
      assert.equal(ok.status, 200, ok.text)
      assert.equal(ok.json.ordinary, 'ordinary-traffic-control')
      assert.equal(w.upstream.hits.at(-1).seen, 'test-secret-conform-0123456789abcdef')
      assert.equal(leaksSecret(ok.text), null)
    })

    test('a placeholder rotated off the live ledger is stale, and the newest still works', async () => {
      const made = await w.control('POST', '/v1/sessions', {
        cred: w.slug, label: 'ledger', methods: ['GET'], paths: ['/**'], budget: 20, approval: 'on-write', ttl_hours: 1,
      })
      assert.equal(made.status, 200, made.text)
      const mint = () => w.control('POST', '/v1/placeholders', { cred: w.slug, sid: made.json.session_id })
      const use = (ph) => gateway(w, `/p/${w.slug}/user`, { token: made.json.token, placeholder: ph })
      const first = await mint()
      assert.equal(first.status, 200, first.text)
      const used = await use(first.json.placeholder)
      assert.equal(used.status, 200, used.text)
      assert.equal(used.json.ordinary, 'ordinary-traffic-control')
      let newest = first
      for (let i = 0; i < 8; i++) {
        newest = await mint()
        assert.equal(newest.status, 200, newest.text)
        const res = await use(newest.json.placeholder)
        assert.equal(res.status, 200, `${i} ${res.text}`)
        assert.equal(res.json.ordinary, 'ordinary-traffic-control')
        assert.equal(leaksSecret(res.text), null)
      }
      const stale = await use(first.json.placeholder)
      assert.notEqual(stale.status, 200)
      assert.equal(stale.json.code, 'AV_PH_STALE')
      assert.equal(leaksSecret(stale.text), null)
      const again = await use(newest.json.placeholder)
      assert.equal(again.status, 200, again.text)
      assert.equal(again.json.ordinary, 'ordinary-traffic-control')
      assert.equal(leaksSecret(again.text), null)
    })

    test('a placeholder in an undeclared header, an encoding, or a second Authorization is refused', async () => {
      const ph = placeholder()
      const tok = token()
      const encodings = {
        base64: Buffer.from(ph).toString('base64'),
        'base64-offset': Buffer.from(`xy${ph}`).toString('base64'),
        percent: ph.replace(/\./g, '%2e'),
        'percent-bytes': [...ph].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''),
        'json-escape': [...ph].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
      }
      const cases = [
        ['an undeclared header', { path: `/p/${w.slug}/user`, headers: [['av-session', tok], ['authorization', `Bearer ${ph}`], ['x-debug', ph]] }],
        ...Object.entries(encodings).flatMap(([name, encoded]) => [
          [`${name} in the query`, { path: `/p/${w.slug}/user?q=${encoded}`, headers: [['av-session', tok], ['authorization', `Bearer ${ph}`]] }],
          [`${name} in the body`, {
            path: `/p/${w.slug}/user`,
            method: 'POST',
            headers: [['av-session', tok], ['authorization', `Bearer ${ph}`], ['content-type', 'application/json']],
            body: JSON.stringify({ note: encoded }),
          }],
        ]),
        // Node's req.headers keeps the first Authorization and drops the
        // second (headersDistinct still lists both). The gateway copies
        // req.headers, so the pipeline never sees the pair and cannot return
        // header_duplicate. The placeholder in the dropped header is absent,
        // and nothing is forwarded.
        ['a second Authorization header', {
          path: `/p/${w.slug}/user`,
          headers: [['av-session', tok], ['authorization', 'Bearer something-else'], ['authorization', `Bearer ${ph}`]],
        }],
        ['a malformed percent-escape in a query key', {
          path: `/p/${w.slug}/user?bad%=${encodeURIComponent(ph)}`,
          headers: [['av-session', tok]],
        }],
      ]
      for (const [name, spec] of cases) {
        const before = w.upstream.hits.length
        const res = await rawGateway(w.port, spec.path, spec)
        if (name.startsWith('a second')) {
          assert.equal(res.status, 401, `${name} ${res.status} ${res.text}`)
          assert.equal(res.json?.code, 'AV_SESSION_REQUIRED', `${name} ${res.text}`)
          assert.equal(res.json?.rule, 'no_placeholder', `${name} ${res.text}`)
        } else {
          assert.equal(res.status, 403, `${name} ${res.status} ${res.text}`)
          assert.equal(res.json?.code, 'AV_BAD_LOCATION', `${name} ${res.text}`)
        }
        assert.equal(w.upstream.hits.length, before, name)
        assert.equal(leaksSecret(res.text), null, name)
      }
      const ok = await gateway(w, `/p/${w.slug}/user`, { token: tok, placeholder: ph })
      assert.equal(ok.status, 200, ok.text)
      assert.equal(ok.json.ordinary, 'ordinary-traffic-control')
      assert.equal(w.upstream.hits.at(-1).seen, SECRET)
    })

    test('a one-time placeholder is exhausted, races once, and hands back a one-time successor', async () => {
      const made = await w.control('POST', '/v1/sessions', {
        cred: w.slug, label: 'once', methods: ['GET'], paths: ['/**'], budget: 30, approval: 'auto', ttl_hours: 1,
      })
      assert.equal(made.status, 200, made.text)
      const issue = () => w.control('POST', '/v1/placeholders', { cred: w.slug, sid: made.json.session_id, uses: 1 })
      const call = (ph) => gateway(w, `/p/${w.slug}/user`, { token: made.json.token, placeholder: ph })

      const once = await issue()
      assert.match(once.json.placeholder, /^av1\./)
      const before = w.upstream.hits.length
      const first = await call(once.json.placeholder)
      assert.equal(first.status, 200, first.text)
      assert.equal(first.json.ordinary, 'ordinary-traffic-control')
      assert.equal(leaksSecret(first.text), null)
      const next = first.headers['av-placeholder-next']
      assert.match(next, /^av1\./)
      const second = await call(once.json.placeholder)
      assert.equal(second.status, 401, second.text)
      assert.equal(second.json.code, 'AV_PH_EXHAUSTED')
      assert.equal(w.upstream.hits.length, before + 1)

      const successor = await call(next)
      assert.equal(successor.status, 200, successor.text)
      assert.equal(successor.json.ordinary, 'ordinary-traffic-control')
      const successorAgain = await call(next)
      assert.equal(successorAgain.status, 401, successorAgain.text)
      assert.equal(successorAgain.json.code, 'AV_PH_EXHAUSTED')
      assert.equal(w.upstream.hits.length, before + 2)

      const raced = await issue()
      const racedBefore = w.upstream.hits.length
      const results = await Promise.all(Array.from({ length: 20 }, () => call(raced.json.placeholder)))
      assert.equal(results.filter((r) => r.status === 200).length, 1)
      assert.equal(results.filter((r) => r.status === 200 && r.json.ordinary === 'ordinary-traffic-control').length, 1)
      assert.ok(results.filter((r) => r.status !== 200).every((r) => r.json.code === 'AV_PH_EXHAUSTED'))
      assert.equal(w.upstream.hits.length, racedBefore + 1)
      assert.equal(leaksSecret(results.map((r) => r.text).join('\n')), null)

      const other = await w.control('POST', '/v1/sessions', {
        cred: w.slug, label: 'other', methods: ['GET'], paths: ['/**'], budget: 5, approval: 'auto', ttl_hours: 1,
      })
      assert.equal(other.status, 200, other.text)
      const crossBefore = w.upstream.hits.length
      const cross = await gateway(w, `/p/${w.slug}/user`, { token: made.json.token, placeholder: other.json.placeholder })
      assert.equal(cross.status, 403, cross.text)
      assert.equal(cross.json.code, 'AV_PH_CROSS_SESSION')
      assert.equal(w.upstream.hits.length, crossBefore)
      assert.equal(leaksSecret(cross.text), null)

      const bad = `${once.json.placeholder.slice(0, -1)}${once.json.placeholder.at(-1) === 'a' ? 'b' : 'a'}`
      const malformed = await gateway(w, `/p/${w.slug}/user`, { placeholder: bad })
      assert.equal(malformed.status, 400, malformed.text)
      assert.equal(malformed.json.code, 'AV_PH_MALFORMED')
      assert.equal(malformed.json.rule, 'checksum')
      assert.equal(w.upstream.hits.length, crossBefore)
      assert.equal(leaksSecret(malformed.text), null)

      const side = await w.control('POST', '/v1/credentials', {
        slug: 'other-cred', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      assert.equal(side.status, 200, side.text)
      const grant = { methods: ['GET'], paths: ['/**'], budget: 5, approval: 'auto' }
      const both = await w.control('POST', '/v1/sessions', {
        label: 'two', ttl_hours: 1,
        grants: [{ cred: w.slug, ...grant }, { cred: 'other-cred', ...grant }],
      })
      assert.equal(both.status, 200, both.text)
      const wrongBefore = w.upstream.hits.length
      const wrong = await gateway(w, '/p/other-cred/user', { token: both.json.token, placeholder: both.json.placeholder })
      assert.equal(wrong.status, 403, wrong.text)
      assert.equal(wrong.json.code, 'AV_PH_WRONG_CONNECTOR')
      assert.equal(w.upstream.hits.length, wrongBefore)
      assert.equal(leaksSecret(wrong.text), null)

      const ordinary = await call((await w.control('POST', '/v1/placeholders', { cred: w.slug, sid: made.json.session_id })).json.placeholder)
      assert.equal(ordinary.status, 200, ordinary.text)
      assert.equal(ordinary.json.ordinary, 'ordinary-traffic-control')
      assert.equal(leaksSecret(ordinary.text), null)
    })

    test('a failure before connect refunds the budget, and a different Basic spelling is a new approval', async () => {
      const closed = await w.control('POST', '/v1/credentials', {
        slug: 'closed', kind: 'http', host: '127.0.0.1:1', scheme: 'http',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      assert.equal(closed.status, 200, closed.text)
      const dead = await w.control('POST', '/v1/sessions', {
        cred: 'closed', label: 'refund', methods: ['GET'], paths: ['/**'], budget: 3, approval: 'auto', ttl_hours: 1,
      })
      assert.equal(dead.status, 200, dead.text)
      const missed = await gateway(w, '/p/closed/user', { token: dead.json.token, placeholder: dead.json.placeholder })
      assert.equal(missed.status, 502, missed.text)
      assert.equal(missed.json.code, 'AV_UPSTREAM_UNREACHABLE')
      assert.equal(missed.json.refunded, true)
      const detail = await w.control('GET', `/v1/sessions/detail?sid=${dead.json.session_id}`)
      assert.equal(detail.json.grants[0].budget.used, 0)
      assert.equal(leaksSecret(missed.text), null)

      const added = await w.control('POST', '/v1/credentials', {
        slug: 'basic', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http',
        value: SECRET, sites: ['basic:pass'],
      })
      assert.equal(added.status, 200, added.text)
      const session = await w.control('POST', '/v1/sessions', {
        cred: 'basic', label: 'basic', methods: ['POST'], paths: ['/**'], budget: 5, approval: 'each', ttl_hours: 1,
      })
      assert.equal(session.status, 200, session.text)
      const basic = (user, ph) => `Basic ${Buffer.from(`${user}:${ph}`).toString('base64')}`
      const send = (user, ph = session.json.placeholder) => gateway(w, '/p/basic/echo', {
        method: 'POST',
        token: session.json.token,
        headers: { authorization: basic(user, ph), 'content-type': 'application/json' },
        body: '{}',
      })
      const held = await send('user')
      assert.equal(held.status, 202, held.text)
      assert.equal(held.json.code, 'AV_APPROVAL_PENDING')
      const heldBudget = await w.control('GET', `/v1/sessions/detail?sid=${session.json.session_id}`)
      assert.equal(heldBudget.json.grants[0].budget.used, 0)
      const granted = await w.control('POST', '/v1/approvals', { id: held.json.approval_id, granted: true })
      assert.equal(granted.status, 200, granted.text)
      const before = w.upstream.hits.length
      const ran = await send('user')
      assert.equal(ran.status, 200, ran.text)
      assert.equal(leaksSecret(ran.text), null)
      assert.equal(w.upstream.hits.length, before + 1)
      assert.equal(w.upstream.hits.at(-1).seen, basic('user', SECRET))
      const spent = await w.control('GET', `/v1/sessions/detail?sid=${session.json.session_id}`)
      assert.equal(spent.json.grants[0].budget.used, 1)
      const other = await send('admin')
      assert.equal(other.status, 202, other.text)
      assert.notEqual(other.json.approval_id, held.json.approval_id)
      const still = await w.control('GET', `/v1/sessions/detail?sid=${session.json.session_id}`)
      assert.equal(still.json.grants[0].budget.used, 1)
      assert.equal(w.upstream.hits.length, before + 1)
    })

    test('a pinned self-signed upstream that presents the wrong key sends nothing', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'av-pin-'))
      const hits = []
      let server
      try {
        execFileSync('openssl', [
          'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.crt',
          '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
        ], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] })
        server = createTlsServer({
          key: readFileSync(join(dir, 'self.key')),
          cert: readFileSync(join(dir, 'self.crt')),
        }, (req, res) => { hits.push(req.url); res.end('{}') })
        await new Promise((resolve, reject) => {
          server.once('error', reject)
          server.listen(0, '127.0.0.1', resolve)
        })
        const port = server.address().port
        // Trust this leaf so the handshake is authorized. A wrong pin is then
        // the refusal. Without that, Node's CA check fails first and the
        // daemon reports the connection as unreachable.
        w.env.NODE_EXTRA_CA_CERTS = join(dir, 'self.crt')
        await w.restart()
        const added = await w.control('POST', '/v1/credentials', {
          slug: 'pinned', kind: 'http', host: `127.0.0.1:${port}`, scheme: 'https',
          value: SECRET, sites: ['header:authorization:Bearer'],
        })
        assert.equal(added.status, 200, added.text)
        const pins = await w.control('POST', '/v1/credentials/pins', { slug: 'pinned', host: '127.0.0.1', pins: [pinValue()] })
        assert.equal(pins.status, 200, pins.text)
        const session = await w.control('POST', '/v1/sessions', {
          cred: 'pinned', label: 'pin', methods: ['GET'], paths: ['/**'], budget: 3, approval: 'auto', ttl_hours: 1,
        })
        assert.equal(session.status, 200, session.text)
        const res = await gateway(w, '/p/pinned/user', { token: session.json.token, placeholder: session.json.placeholder })
        assert.equal(res.status, 502, res.text)
        assert.equal(res.json.code, 'AV_PIN_MISMATCH')
        assert.equal(res.json.rule, 'spki_pin')
        assert.equal(hits.length, 0)
        assert.equal(leaksSecret(res.text), null)
        const detail = await w.control('GET', `/v1/sessions/detail?sid=${session.json.session_id}`)
        assert.equal(detail.json.grants[0].budget.used, 0)
      } finally {
        if (server) await new Promise((r) => server.close(r))
        await rm(dir, { recursive: true, force: true })
      }
    })
  })
}
