// Sessions on the control API after wave 3: what a create body may carry
// (every GrantSpec field, through grantPolicyFromInput), a budget of 0
// refused before anyone is asked for presence (C17), grant lifetimes (F18),
// live narrowing (F15), and the activity and access review routes (F19).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi, PASSPHRASE, SECRET, HOUR } from './control-api-helpers.js'
import { parseOverrides } from '../../src/pending.js'

const sessions = (a) => Object.values(a.vault.db.sessions).length

// ------------------------------------------------------------------ create

test('a budget of 0 is refused before the presence gate, and nothing is made (C17)', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const before = sessions(a)
    for (const budget of [0, '0']) {
      const r = await a.control('POST', '/v1/sessions', { cred: 'demo', budget })
      // A policy refusal, not a request for a passphrase it would refuse anyway.
      assert.equal(r.status, 403, JSON.stringify(r.body))
      assert.equal(r.body.rule, 'budget')
    }
    const many = await a.control('POST', '/v1/sessions', { grants: [{ cred: 'demo', budget: 0 }] })
    assert.equal(many.body.rule, 'budget')
    assert.equal(sessions(a), before, 'a session was made and torn down')
    assert.ok(!a.audit('session.created').length)
    // An ordinary budget reaches the gate, which is what it should do.
    const gated = await a.control('POST', '/v1/sessions', { cred: 'demo', budget: 1 })
    assert.equal(gated.status, 401)
    assert.equal(gated.body.code, 'AV_PRESENCE_REQUIRED')
    a.openWindow()
    const ok = await a.control('POST', '/v1/sessions', { cred: 'demo', budget: 1 })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
  } finally { await a.stop() }
})

test('a create body carries every grant limit, converted by the one converter', async () => {
  const a = await startApi()
  try {
    const r = await a.control('POST', '/v1/sessions', {
      cred: 'demo', methods: ['GET', 'POST'], rate: '2/s', quota: '100/day', max_concurrent: 2,
      routes: [{ methods: ['GET'], paths: ['/repos/**'] }], redirects: 1, deny_paths: ['/admin/**'], budget: '7',
    })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const policy = a.vault.db.grants[r.body.grant_id].policy
    assert.deepEqual(policy.rate, { count: 2, per: 'second' })
    assert.deepEqual(policy.quota, { count: 100, window: 'day' })
    assert.equal(policy.max_concurrent, 2)
    assert.deepEqual(policy.routes, [{ methods: ['GET'], paths: ['/repos/**'] }])
    assert.deepEqual(policy.redirects, { max: 1 })
    assert.equal(policy.budget.limit, 7)
    // An ordinary body still gets the defaults, including redirects off.
    const plain = await a.control('POST', '/v1/sessions', { cred: 'demo' })
    assert.deepEqual(a.vault.db.grants[plain.body.grant_id].policy.redirects, { max: 0 })
    assert.deepEqual(a.vault.db.grants[plain.body.grant_id].policy.methods, ['GET', 'HEAD'])
  } finally { await a.stop() }
})

test('a grant limit that cannot be read is refused and leaves nothing behind', async () => {
  const a = await startApi()
  try {
    const before = sessions(a)
    for (const body of [
      { cred: 'demo', rate: '5/fortnight' }, { cred: 'demo', rate: { count: 'NaN', per: 'second' } },
      { cred: 'demo', max_concurrent: 1.5 }, { cred: 'demo', quota: '10/s' },
      { cred: 'demo', routes: [{ methods: ['FETCH'], paths: ['/x'] }] }, { cred: 'demo', redirects: 9 },
      // Spend applies only to the model-provider kinds.
      { cred: 'demo', spend_tokens: 100 },
      { cred: 'demo', remote: 'yes' },
    ]) {
      const r = await a.control('POST', '/v1/sessions', body)
      assert.equal(r.status, 403, JSON.stringify(body))
      assert.equal(r.body.rule, 'policy_invalid', JSON.stringify(r.body))
    }
    assert.equal(sessions(a), before)
  } finally { await a.stop() }
})

// ---------------------------------------------------------- F18 lifetimes

test('a grant lifetime is set, clamped to the session, and refused when it is not a whole number (F18)', async () => {
  const a = await startApi()
  try {
    for (const grant_ttl_minutes of [0, -5, 'x', 1.5]) {
      const r = await a.control('POST', '/v1/sessions', { cred: 'demo', grant_ttl_minutes })
      assert.equal(r.status, 403, String(grant_ttl_minutes))
      assert.equal(r.body.rule, 'grant_ttl')
    }
    const short = await a.control('POST', '/v1/sessions', { cred: 'demo', grant_ttl_minutes: 5 })
    assert.equal(short.status, 200, JSON.stringify(short.body))
    const ends = Date.parse(short.body.grants[0].expires_at)
    assert.ok(Math.abs(ends - (Date.now() + 5 * 60_000)) < 5_000, short.body.grants[0].expires_at)
    // Longer than the session: the session's end wins.
    const long = await a.control('POST', '/v1/sessions', { cred: 'demo', ttl_hours: 1, grant_ttl_minutes: 600 })
    assert.ok(Date.parse(long.body.grants[0].expires_at) <= Date.parse(long.body.expires_at) + 1000)
    // None: no lifetime of its own.
    const none = await a.control('POST', '/v1/sessions', { cred: 'demo' })
    assert.equal(none.body.grants[0].expires_at, null)
  } finally { await a.stop() }
})

test('an expired grant is refused with its own code while the session\'s other grant works (F18)', async () => {
  const a = await startApi()
  try {
    a.vault.addCredential({
      slug: 'other', kind: 'http', connector: { host: `127.0.0.1:${a.upPort}`, scheme: 'http' },
      fields: { token: 'OTHER-SECRET-0099887766' }, sites: { token: ['header:authorization:Bearer'] },
    })
    const r = await a.control('POST', '/v1/sessions', {
      grants: [{ cred: 'demo', grant_ttl_minutes: 1 }, { cred: 'other' }],
    })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const [first, second] = r.body.grants
    // The clock moves past the grant's end.
    a.vault.db.grants[first.grant_id].expires_at = new Date(Date.now() - 1000).toISOString()
    const expired = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${first.placeholder}` } })
    assert.equal(expired.json?.code, 'AV_GRANT_EXPIRED', expired.text)
    const works = await a.gateway('/p/other/x', { headers: { authorization: `Bearer ${second.placeholder}` } })
    assert.equal(works.status, 200, works.text)
    // Over MCP, with its own code.
    const asked = await a.tool('vault_get_placeholder', { cred: 'demo', reason: 'x' }, { token: r.body.token })
    assert.equal(asked.body.code, 'AV_GRANT_EXPIRED', JSON.stringify(asked.body))
    const sent = await a.tool('vault_http', { cred: 'demo', method: 'GET', path: '/x', reason: 'x' }, { token: r.body.token })
    assert.equal(sent.body.code, 'AV_GRANT_EXPIRED', JSON.stringify(sent.body))
  } finally { await a.stop() }
})

// --------------------------------------------------------- F15 narrowing

test('narrowing intersects: auto plus DELETE on an on-write GET grant leaves on-write and no methods (F15)', async () => {
  const a = await startApi()
  try {
    const s = a.session({ policy: { methods: ['GET'], approval: 'on-write' } })
    const r = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, narrow: { approval: 'auto', methods: ['DELETE'] } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const [g] = r.body.grants
    assert.equal(g.before.approval, 'on-write')
    assert.equal(g.after.approval, 'on-write')
    assert.deepEqual(g.after.methods, [])
    assert.equal(a.vault.db.grants[s.grant.id].policy.approval, 'on-write')
    assert.deepEqual(a.vault.db.grants[s.grant.id].policy.methods, [])
    // And the gateway reads it: GET is now refused too.
    const res = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(res.status, 403, res.text)
    assert.ok(a.audit('grant.narrowed').some((x) => x.grant_id === s.grant.id && x.fields.includes('methods')))
  } finally { await a.stop() }
})

test('narrowing never widens, over random narrows (F15)', async () => {
  const a = await startApi()
  try {
    const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']
    const MODES = ['each', 'on-write', 'first-use', 'auto']
    const ORDER = ['auto', 'first-use', 'on-write', 'each']
    let seed = 7
    const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n }
    for (let i = 0; i < 40; i++) {
      const start = METHODS.filter(() => rnd(2))
      const s = a.session({ policy: { methods: start, approval: MODES[rnd(4)], budget: { unit: 'requests', limit: 50 } } })
      const narrow = { methods: METHODS.filter(() => rnd(2)), approval: MODES[rnd(4)], budget: rnd(100) }
      const r = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, narrow })
      assert.equal(r.status, 200, JSON.stringify(r.body))
      const { before, after } = r.body.grants[0]
      assert.ok(after.methods.every((m) => before.methods.includes(m)), `${JSON.stringify(narrow)}: ${after.methods} ⊄ ${before.methods}`)
      assert.ok(ORDER.indexOf(after.approval) >= ORDER.indexOf(before.approval), `${after.approval} is laxer than ${before.approval}`)
      assert.ok(after.budget.limit <= before.budget.limit)
    }
  } finally { await a.stop() }
})

test('a narrowing that turns redirects on is refused; turning them off is not (F15)', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    const on = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, narrow: { redirects: 5 } })
    assert.equal(on.status, 403)
    assert.equal(on.body.rule, 'narrow_widens')
    // Refused before anything changes, the lifetime beside it included.
    const expires = a.vault.db.sessions[s.session.id].expires_at
    const both = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, narrow: { redirects: 3 }, session_ttl_minutes: 5 })
    assert.equal(both.body.rule, 'narrow_widens')
    assert.equal(a.vault.db.sessions[s.session.id].expires_at, expires, 'a refused narrowing shortened the session')
    assert.ok(!a.audit('session.shortened').length)
    const off = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, narrow: { redirects: 0 } })
    assert.equal(off.status, 200, JSON.stringify(off.body))
    assert.deepEqual(off.body.grants[0].after.redirects, { max: 0 })
  } finally { await a.stop() }
})

test('an agent can narrow its own session with no presence, and only ever loses capability (F15)', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const s = a.session({ policy: { methods: ['GET', 'POST'] } })
    const before = await a.gateway('/p/demo/x', { method: 'POST', headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(before.status, 200, before.text)
    const r = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, narrow: { methods: ['GET'] } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const after = await a.gateway('/p/demo/x', { method: 'POST', headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(after.status, 403, after.text)
    const get = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(get.status, 200, get.text)
  } finally { await a.stop() }
})

test('a session lifetime in a narrowing makes an infinite session finite, and a grant lifetime shortens the grant (F15)', async () => {
  const a = await startApi()
  try {
    const s = a.session({ infinite: true })
    assert.equal(s.session.infinite, true)
    const r = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, session_ttl_minutes: 30, narrow: { grant_ttl_minutes: 10 } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.infinite, false)
    assert.ok(Date.parse(r.body.expires_at) <= Date.now() + 30 * 60_000 + 1000)
    assert.ok(Date.parse(r.body.grants[0].expires_at) <= Date.now() + 10 * 60_000 + 1000)
    assert.equal(a.vault.db.sessions[s.session.id].infinite, false)
    assert.ok(a.audit('session.shortened').some((x) => x.session_id === s.session.id && x.was_infinite === true))
    assert.ok(a.audit('grant.shortened').some((x) => x.grant_id === s.grant.id))
  } finally { await a.stop() }
})

test('a narrowing that does nothing, or names what cannot be narrowed, is refused (F15)', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    const policy = JSON.stringify(a.vault.db.grants[s.grant.id].policy)
    for (const [body, rule] of [
      [{ sid: s.session.id }, 'narrow_empty'],
      [{ sid: s.session.id, narrow: {} }, 'narrow_empty'],
      [{ sid: s.session.id, narrow: { uses: 1 } }, 'policy_invalid'],
      [{ sid: s.session.id, narrow: { cred: 'demo' } }, 'policy_invalid'],
      [{ sid: s.session.id, narrow: 'GET' }, 'policy_invalid'],
      [{ sid: s.session.id, narrow: { approval: 'sometimes' } }, 'approval'],
      [{ sid: s.session.id, narrow: { budget: 'lots' } }, 'policy_invalid'],
      [{ sid: s.session.id, narrow: { rate: '5/fortnight' } }, 'policy_invalid'],
      [{ sid: s.session.id, session_ttl_minutes: 0 }, 'ttl'],
      [{ sid: s.session.id, grant_ttl_minutes: '5' }, 'grant_ttl'],
      [{ sid: s.session.id, narrow: { grant_ttl_minutes: 0 } }, 'grant_ttl'],
      // One value, one place (C22): both at once is refused, whichever is shorter.
      [{ sid: s.session.id, grant_ttl_minutes: 5, narrow: { grant_ttl_minutes: 10 } }, 'policy_invalid'],
    ]) {
      const r = await a.control('POST', '/v1/sessions/narrow', body)
      assert.equal(r.status, 403, JSON.stringify(body))
      assert.equal(r.body.rule, rule, JSON.stringify(r.body))
    }
    assert.equal(JSON.stringify(a.vault.db.grants[s.grant.id].policy), policy, 'a refused narrowing changed the grant')
    assert.equal((await a.control('POST', '/v1/sessions/narrow', { sid: 'nope', narrow: { methods: ['GET'] } })).status, 404)
    const other = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, cred: 'missing', narrow: { methods: ['GET'] } })
    assert.equal(other.status, 404)
    a.vault.revokeSession(s.session.id)
    const revoked = await a.control('POST', '/v1/sessions/narrow', { sid: s.session.id, narrow: { methods: ['GET'] } })
    assert.equal(revoked.body.code, 'AV_SESSION_REVOKED')
  } finally { await a.stop() }
})

test('narrowing one credential leaves the session\'s other grant alone (F15)', async () => {
  const a = await startApi()
  try {
    a.vault.addCredential({
      slug: 'other', kind: 'http', connector: { host: `127.0.0.1:${a.upPort}`, scheme: 'http' },
      fields: { token: 'OTHER-SECRET-0099887766' }, sites: { token: ['header:authorization:Bearer'] },
    })
    const r = await a.control('POST', '/v1/sessions', { grants: [{ cred: 'demo', methods: ['GET', 'POST'] }, { cred: 'other', methods: ['GET', 'POST'] }] })
    const n = await a.control('POST', '/v1/sessions/narrow', { sid: r.body.session_id, cred: 'other', narrow: { methods: ['GET'] } })
    assert.equal(n.status, 200, JSON.stringify(n.body))
    assert.deepEqual(n.body.grants.map((g) => g.cred), ['other'])
    assert.deepEqual(a.vault.db.grants[r.body.grants[0].grant_id].policy.methods, ['GET', 'POST'])
    assert.deepEqual(a.vault.db.grants[r.body.grants[1].grant_id].policy.methods, ['GET'])
  } finally { await a.stop() }
})

// ------------------------------------------------------ F19 detail, report

test('the session detail holds metadata only: no placeholder text, query or secret (F19)', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    await a.gateway('/p/demo/repos/x?token=QUERYSECRET123', { headers: { authorization: `Bearer ${s.placeholder}` } })
    await a.gateway('/p/demo/repos/y', { headers: { authorization: `Bearer ${s.placeholder}` } })
    // A placeholder in the path, where it does not belong.
    await a.gateway(`/p/demo/items/${s.placeholder}`, { headers: { authorization: `Bearer ${s.placeholder}` } })
    const r = await a.control('GET', `/v1/sessions/detail?sid=${s.session.id}`)
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const text = JSON.stringify(r.body)
    assert.ok(!text.includes(s.placeholder), 'the placeholder text is in the detail')
    assert.ok(!text.includes('QUERYSECRET123'), 'a query is in the detail')
    assert.ok(!text.includes(SECRET), 'the secret is in the detail')
    assert.ok(!text.includes(s.token), 'the token is in the detail')
    const [grant] = r.body.grants
    assert.ok(grant.placeholders.length >= 1)
    for (const p of grant.placeholders) {
      assert.ok(p.id.startsWith('ph_'), JSON.stringify(p))
      assert.equal('placeholder' in p, false)
    }
    assert.equal(r.body.activity.complete, true, JSON.stringify(r.body.activity))
    assert.equal(r.body.activity.requests.allowed, 2)
    assert.ok(r.body.activity.requests.denied >= 1)
    assert.equal(grant.budget.limit, 100)
    assert.equal(grant.budget.used, 2)
    assert.equal(grant.budget.remaining, 98)
    assert.equal(r.body.session.infinite, false)
  } finally { await a.stop() }
})

test('the detail says when history is incomplete, and is refused while locked (F19)', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    // A session the log never saw created: history that cannot be complete.
    const ghost = { ...structuredClone(s.session), id: 'ghostsession1' }
    a.vault.db.sessions[ghost.id] = ghost
    const r = await a.control('GET', `/v1/sessions/detail?sid=${ghost.id}`)
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.activity.complete, false)
    assert.equal((await a.control('GET', '/v1/sessions/detail?sid=nope')).status, 404)
    a.vault.lock()
    const locked = await a.control('GET', `/v1/sessions/detail?sid=${s.session.id}`)
    assert.equal(locked.body.code, 'AV_LOCKED')
    assert.equal((await a.control('GET', '/v1/report/access')).body.code, 'AV_LOCKED')
    a.vault.unlockWith({})
  } finally { await a.stop() }
})

test('the access report covers every session and credential, and refuses a since it cannot read (F19)', async () => {
  const a = await startApi()
  try {
    const s = a.session({ policy: { methods: ['GET', 'POST'] } })
    await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
    for (const since of [undefined, '7d', '24h', new Date(Date.now() - HOUR).toISOString()]) {
      const r = await a.control('GET', `/v1/report/access${since ? `?since=${encodeURIComponent(since)}` : ''}`)
      assert.equal(r.status, 200, JSON.stringify(r.body))
      const mine = r.body.sessions.find((x) => x.id === s.session.id)
      assert.ok(mine, JSON.stringify(r.body.sessions))
      assert.deepEqual(mine.unused_methods, ['POST'])
      assert.equal(r.body.credentials.find((c) => c.slug === 'demo').requests, 1)
    }
    for (const since of ['yesterday', '7', '-1d', '0d', '1e3h']) {
      const r = await a.control('GET', `/v1/report/access?since=${since}`)
      assert.equal(r.status, 403, since)
      assert.equal(r.body.rule, 'report_since')
    }
  } finally { await a.stop() }
})

// ------------------------------------------------- the human's overrides

test('a typo in a narrowing is refused, by the parser and by the daemon, never dropped as null', async () => {
  // Number('abc') is NaN, which JSON sends as null, and a null override is
  // dropped: the human's "--budget abc" used to approve the agent's own budget.
  // The parser throws (C23); a caller that sends the string anyway is refused.
  assert.deepEqual(parseOverrides({ uses: '2', concurrency: '4', 'spend-usd': '1.25' }), { uses: 2, max_concurrent: 4, spend_usd: 1.25 })
  for (const [flag, field] of [['budget', 'budget'], ['grant-ttl', 'grant_ttl_minutes']]) {
    assert.throws(() => parseOverrides({ [flag]: 'abc' }), (e) => e.field === field)
  }
  assert.deepEqual(parseOverrides({ route: ['get,head:/repos/**'] }).routes, [{ methods: ['GET', 'HEAD'], paths: ['/repos/**'] }])
  const a = await startApi()
  try {
    const asked = await a.control('POST', '/v1/session-requests', { cred: 'demo', budget: 50, reason: 'x' })
    const typo = await a.control('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true, overrides: { budget: 'abc' } })
    assert.equal(typo.status, 403, JSON.stringify(typo.body))
    assert.equal(typo.body.rule, 'policy_invalid')
    assert.equal(a.daemon.sessionRequests.get(asked.body.id).state, 'pending', 'a refused decision settled the request')
    const ok = await a.control('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true, overrides: parseOverrides({ budget: '5' }) })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(a.vault.db.grants[ok.body.session.grant_id].policy.budget.limit, 5)
  } finally { await a.stop() }
})
