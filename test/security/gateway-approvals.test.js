// The approval state machine and the request hash it is keyed by. Each test
// is a way a held request could run more than once, run as something the
// human did not see, or stay stuck after it ran.

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import * as canon from '../../src/core/canon.js'
import { setup, cleanup, drain, SECRET } from './gateway-helpers.js'

afterEach(cleanup)

const held = (res) => JSON.parse(res.body).approval_id

// ------------------------------------------------------ deciding an approval

test('an approval that already ran cannot be denied, and the deny hands back nothing', async () => {
  const s = setup({ approval: 'on-write' })
  const ph = s.ph('key', 1)
  const write = s.request({ method: 'POST', headers: [...s.request().headers, ['x-key', ph]], body: Buffer.from('x') })
  const id = held(await s.pipeline.handle(write))
  s.pipeline.decideApproval(id, true)
  const ran = await s.pipeline.handle(write)
  assert.equal(ran.status, 200)
  assert.ok(ran.headers['av-placeholder-next'], 'the one-use placeholder was spent and has a successor')

  // The deny route is open to anything on the control socket. It returned the
  // whole approval, cached response included, and the response carried the
  // successor placeholder: a bearer capability for anyone who asked.
  let returned = null
  assert.throws(() => { returned = s.pipeline.decideApproval(id, false) }, (e) => e.code === 'AV_POLICY_DENIED')
  assert.equal(returned, null)
  const approval = [...s.pipeline.approvals.values()].find((a) => a.id === id)
  assert.equal(approval.state, 'consumed', 'a decision on a spent approval must not change it')
})

test('granting an approval that already ran does not arm it again', async () => {
  const s = setup({ approval: 'on-write' })
  const write = s.request({ method: 'POST', headers: [...s.request().headers, ['x-key', s.ph()]], body: Buffer.from('x') })
  const id = held(await s.pipeline.handle(write))
  s.pipeline.decideApproval(id, true)
  assert.equal((await s.pipeline.handle(write)).status, 200)
  assert.equal(s.sent.length, 1)

  assert.throws(() => s.pipeline.decideApproval(id, true), (e) => e.code === 'AV_POLICY_DENIED')
  const again = await s.pipeline.handle(write)
  assert.equal(again.headers['av-replayed'], 'true', 'the resend replays; it does not run')
  assert.equal(s.sent.length, 1, 'one human decision executed the write twice')
})

test('a granted approval cannot be flipped to denied before it is sent', async () => {
  const s = setup({ approval: 'on-write' })
  const write = s.request({ method: 'POST', headers: [...s.request().headers, ['x-key', s.ph()]], body: Buffer.from('x') })
  const id = held(await s.pipeline.handle(write))
  s.pipeline.decideApproval(id, true)
  assert.throws(() => s.pipeline.decideApproval(id, false), (e) => e.code === 'AV_POLICY_DENIED')
  assert.equal((await s.pipeline.handle(write)).status, 200, 'the human grant stands')
})

test('deciding a pending approval still works, both ways, and returns no response body', async () => {
  const s = setup({ approval: 'on-write' })
  const write = (body) => s.request({ method: 'POST', headers: [...s.request().headers, ['x-key', s.ph()]], body: Buffer.from(body) })
  const yes = held(await s.pipeline.handle(write('yes')))
  const no = held(await s.pipeline.handle(write('no')))
  const granted = s.pipeline.decideApproval(yes, true)
  const denied = s.pipeline.decideApproval(no, false)
  assert.equal(granted.state, 'granted')
  assert.equal(denied.state, 'denied')
  assert.ok(!('result' in granted) && !('result' in denied))
  assert.equal((await s.pipeline.handle(write('yes'))).status, 200)
  assert.equal((await s.pipeline.handle(write('no'))).status, 403)
  assert.equal(s.sent.length, 1)
})

// ----------------------------------------------------------- the request hash

test('literal marker text cannot make two different requests hash alike', async () => {
  const s = setup({ approval: 'each', sites: { key: ['header:x-key', 'json:/token'] } })
  const marker = `<av:${s.grant.id}:key>`
  const ph = s.ph()
  const mk = (header, token) => s.request({
    method: 'POST',
    headers: [...s.request().headers, ['content-type', 'application/json'], ['x-key', header]],
    body: Buffer.from(JSON.stringify({ token })),
  })
  // A: the placeholder in the header, the marker text in the body.
  const id = held(await s.pipeline.handle(mk(ph, marker)))
  s.pipeline.decideApproval(id, true)
  // B: swapped. The secret would go into the body, which the human never saw.
  const b = await s.pipeline.handle(mk(marker, ph))
  assert.equal(b.status, 202, 'B ran under the approval given to A')
  assert.equal(s.sent.length, 0)

  // The same within one header value.
  const c = held(await s.pipeline.handle(mk(`${ph} ${marker}`, 'x')))
  s.pipeline.decideApproval(c, true)
  assert.equal((await s.pipeline.handle(mk(`${marker} ${ph}`, 'x'))).status, 202)
  assert.equal(s.sent.length, 0)

  // A itself, resent, is the request the human approved.
  assert.equal((await s.pipeline.handle(mk(ph, marker))).status, 200)
  assert.equal(s.sent.length, 1)
  assert.equal(s.sent[0].headers['x-key'], SECRET)
})

test('reordering the values of a repeated header changes the request hash', () => {
  const base = { method: 'POST', host: 'h', path: '/x', query: '', bodySha256: '', credentials: ['g:f'] }
  const one = canon.requestHash({ ...base, headers: [['X-HTTP-Method-Override', 'POST'], ['X-HTTP-Method-Override', 'DELETE']] })
  const two = canon.requestHash({ ...base, headers: [['X-HTTP-Method-Override', 'DELETE'], ['X-HTTP-Method-Override', 'POST']] })
  assert.notEqual(one, two, 'an upstream reading the last value sees a different method')
  // Header NAME order and case are still not significant.
  const a = canon.requestHash({ ...base, headers: [['A', '1'], ['b', '2']] })
  const b = canon.requestHash({ ...base, headers: [['B', '2'], ['a', '1']] })
  assert.equal(a, b)
})

// ------------------------------------------------------------ method override

const override = (s, method, value) => s.request({
  method, headers: [...s.request().headers, ['x-key', s.ph()], ['X-HTTP-Method-Override', value]],
  body: method === 'GET' ? null : Buffer.from('x'),
})

test('a method-override header is held to the methods allowlist', async () => {
  const s = setup({ methods: ['GET', 'POST'] })
  const res = await s.pipeline.handle(override(s, 'POST', 'DELETE'))
  assert.equal(res.status, 403)
  assert.equal(JSON.parse(res.body).rule, 'methods')
  assert.equal(s.sent.length, 0, 'a DELETE went out under a grant that allows only GET and POST')
  // Several values in one header, as Node joins repeats.
  assert.equal((await s.pipeline.handle(override(s, 'POST', 'POST, DELETE'))).status, 403)
  assert.equal(s.sent.length, 0)
})

test('a method-override header counts for approval, and the human is shown it', async () => {
  const s = setup({ methods: ['GET', 'DELETE'], approval: 'on-write' })
  const res = await s.pipeline.handle(override(s, 'GET', 'DELETE'))
  assert.equal(res.status, 202, 'a GET that the upstream runs as DELETE skipped on-write approval')
  const [approval] = s.pipeline.pendingApprovals()
  assert.match(approval.summary, /DELETE/)
  assert.equal(s.sent.length, 0)
})

test('ordinary requests are not affected by the override checks', async () => {
  const s = setup({ methods: ['GET', 'POST'], approval: 'on-write' })
  const get = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.equal(get.status, 200)
  // An override naming an allowed safe method is allowed and not held.
  assert.equal((await s.pipeline.handle(override(s, 'GET', 'GET'))).status, 200)
  const post = await s.pipeline.handle(s.request({ method: 'POST', headers: [...s.request().headers, ['x-key', s.ph()]], body: Buffer.from('x') }))
  assert.equal(post.status, 202)
  assert.equal(s.pipeline.pendingApprovals()[0].summary, 'POST up.test/x')
})

// ------------------------------------------------------------- refunds

test('a failure before connecting refunds every placeholder the request spent', async () => {
  const s = setup({
    fields: { key: SECRET, second: 'OTHERSECRET-0123456789' },
    sites: { key: ['header:x-key'], second: ['header:x-second'] },
    fetchImpl: async () => { throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) },
  })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph('key')], ['x-second', s.ph('second')]] }))
  assert.equal(res.status, 502)
  assert.deepEqual(Object.values(s.vault.db.placeholders).map((r) => r.uses), [0, 0])
  assert.equal(s.vault.db.grants[s.grant.id].budget_used, 0)
})

test('a failure that may have reached the server refunds nothing', async () => {
  const s = setup({
    fields: { key: SECRET, second: 'OTHERSECRET-0123456789' },
    sites: { key: ['header:x-key'], second: ['header:x-second'] },
    fetchImpl: async () => { throw Object.assign(new Error('reset'), { code: 'ECONNRESET' }) },
  })
  await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph('key')], ['x-second', s.ph('second')]] }))
  assert.deepEqual(Object.values(s.vault.db.placeholders).map((r) => r.uses), [1, 1])
  assert.equal(s.vault.db.grants[s.grant.id].budget_used, 2)
})

// ------------------------------------------- an approval with nothing to replay

const sse = () => async () => ({ status: 200, headers: { 'content-type': 'text/event-stream' }, res: Readable.from([Buffer.from('data: hi\n\n')]) })

test('a streamed approval that ran does not leave its resend waiting forever', async () => {
  const s = setup({ approval: 'each', fetchImpl: sse() })
  const req = s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] })
  const first = held(await s.pipeline.handle(req))
  s.pipeline.decideApproval(first, true)
  const ran = await s.pipeline.handle(req)
  assert.equal(ran.status, 200)
  await drain(ran.stream)

  // It used to answer 202 under the spent approval, which is not pending, so
  // no human could ever approve it again.
  const retry = await s.pipeline.handle(req)
  assert.equal(retry.status, 202)
  const second = held(retry)
  assert.notEqual(second, first, 'the resend is held under the spent approval')
  assert.ok(s.pipeline.pendingApprovals().some((a) => a.id === second), 'the human cannot see what is being waited on')
  assert.equal(s.pipeline.approvalStatus(first).state, 'consumed', 'the spent approval is still on record')

  s.pipeline.decideApproval(second, true)
  const reran = await s.pipeline.handle(req)
  assert.equal(reran.status, 200)
  await drain(reran.stream)
})

test('a buffered approval whose replay window closed is asked for again, not stuck', async () => {
  const s = setup({ approval: 'each' })
  const req = (path) => s.request({ path, headers: [...s.request().headers, ['x-key', s.ph()]] })
  const first = held(await s.pipeline.handle(req('/p/a/x')))
  s.pipeline.decideApproval(first, true)
  assert.equal((await s.pipeline.handle(req('/p/a/x'))).status, 200)
  assert.equal((await s.pipeline.handle(req('/p/a/x'))).headers['av-replayed'], 'true')

  // Age the replay out, then let the sweep run (it runs when a new approval opens).
  for (const a of s.pipeline.approvals.values()) a.decided_at = new Date(Date.now() - 10 * 60_000).toISOString()
  await s.pipeline.handle(req('/p/a/other'))

  const retry = await s.pipeline.handle(req('/p/a/x'))
  assert.equal(retry.status, 202)
  assert.notEqual(held(retry), first)
  assert.ok(s.pipeline.pendingApprovals().some((a) => a.id === held(retry)))
  assert.equal(s.sent.length, 1)
})

test('a request that failed after reaching the upstream is asked for again, not stuck', async () => {
  let fail = true
  const s = setup({
    approval: 'each',
    fetchImpl: async () => {
      if (fail) throw Object.assign(new Error('reset'), { code: 'ECONNRESET' })
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') }
    },
  })
  const req = s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] })
  const first = held(await s.pipeline.handle(req))
  s.pipeline.decideApproval(first, true)
  assert.equal((await s.pipeline.handle(req)).status, 502)
  fail = false
  const retry = await s.pipeline.handle(req)
  assert.equal(retry.status, 202, 'the request may have run, so it must not run again unasked')
  assert.notEqual(held(retry), first)
  assert.ok(s.pipeline.pendingApprovals().some((a) => a.id === held(retry)))
})

test('a resend while the approved request is still in flight keeps waiting on it', async () => {
  let release
  const gate = new Promise((r) => { release = r })
  const s = setup({
    approval: 'each',
    fetchImpl: async () => { await gate; return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') } },
  })
  const req = s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] })
  const first = held(await s.pipeline.handle(req))
  s.pipeline.decideApproval(first, true)
  const running = s.pipeline.handle(req)
  const meanwhile = await s.pipeline.handle(req)
  assert.equal(meanwhile.status, 202)
  assert.equal(held(meanwhile), first, 'an in-flight approval must not open a second one')
  release()
  assert.equal((await running).status, 200)
  assert.equal((await s.pipeline.handle(req)).headers['av-replayed'], 'true')
})
