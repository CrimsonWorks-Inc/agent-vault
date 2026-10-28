// Integrate-3, fix round 1.
//
// F1 (what an approved record quoted) is now C25, tested in
// integrate3-c25.test.js: the record holds no value at all. D1:
// a decision's override keys the daemon does not apply were dropped and the
// approval went through. D2: `passphrase` reached the page under its own name.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi, PASSPHRASE } from './control-api-helpers.js'
import { overridesProblem } from '../../src/daemon/session-requests.js'
import { parseOverrides, fetchPending } from '../../src/pending.js'
import { towardPage } from '../../src/ui/server.js'

test('D1: the daemon refuses a decision whose overrides name a key it will not apply, naming the key, and decides nothing', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const ask = async () => {
      const r = await a.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET'], paths: ['/**'] })
      assert.equal(r.status, 200, JSON.stringify(r.body))
      return r.body.request_id ?? r.body.id
    }
    const grantsNow = () => Object.keys(a.vault.db.grants).length
    for (const [overrides, named] of [
      [{ hosts: ['127.0.0.1'] }, 'hosts'],
      [{ deny_paths: ['/admin/**'] }, 'deny_paths'],
      [{ methods: ['GET'], not_a_field: 1 }, 'not_a_field'],
      ['budget=5', 'object'],
      [['budget'], 'object'],
    ]) {
      const id = await ask()
      const grants = grantsNow()
      a.openWindow()
      const r = await a.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides })
      assert.ok(r.status >= 400 && r.status < 500, `${JSON.stringify(overrides)}: ${r.status} ${JSON.stringify(r.body)}`)
      assert.match(JSON.stringify(r.body), new RegExp(named), `${JSON.stringify(overrides)}: the refusal does not name it`)
      assert.equal(a.daemon.sessionRequests.get(id).state, 'pending', `${JSON.stringify(overrides)}: it was decided`)
      assert.equal(grantsNow(), grants, `${JSON.stringify(overrides)}: a grant was made`)

      // The bulk route reads overrides the same way.
      const many = await a.control('POST', '/v1/pending/decide-many', { decisions: [{ id, kind: 'session', granted: true, overrides }] })
      if (typeof overrides === 'object' && !Array.isArray(overrides)) {
        assert.ok(many.status >= 400 && many.status < 500, `bulk ${JSON.stringify(overrides)}: ${many.status} ${JSON.stringify(many.body)}`)
        assert.match(JSON.stringify(many.body), new RegExp(named))
      } else {
        assert.equal(many.status, 403, 'checkDecisions refuses a narrowing that is not an object')
      }
      assert.equal(a.daemon.sessionRequests.get(id).state, 'pending', `bulk ${JSON.stringify(overrides)}: it was decided`)
      assert.equal(grantsNow(), grants)
    }
    // A held request takes no narrowing at all.
    const held = await a.control('POST', '/v1/pending/decide-many', { decisions: [{ id: 'apr_x', kind: 'request', granted: true, overrides: { budget: 1 } }] })
    assert.ok(held.status >= 400 && held.status < 500)
    assert.match(JSON.stringify(held.body), /held request/)

    // Every field the daemon applies still goes through, so the refusals are the keys'.
    const id = await ask()
    a.openWindow()
    const ok = await a.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides: { methods: ['GET'], budget: 5, approval: 'each' } })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    const bulkId = await ask()
    const bulk = await a.control('POST', '/v1/pending/decide-many', { decisions: [{ id: bulkId, kind: 'session', granted: true, overrides: { budget: 3 } }] })
    assert.equal(bulk.status, 200, JSON.stringify(bulk.body))
    assert.ok(['approved', 'collected'].includes(a.daemon.sessionRequests.get(bulkId).state))
  } finally { await a.stop() }
})

test('D1: nothing the CLI or the page can send on a valid path names a key the daemon refuses', async () => {
  // Every field the shared parser can emit, by every spelling it reads.
  const page = parseOverrides({
    methods: 'GET', paths: '/a/**', budget: '5', uses: '2', ttl_minutes: '30', 'ttl-minutes': '30',
    grant_ttl_minutes: '5', max_concurrent: '1', redirects: '0', spend_tokens: '9', spend_usd: '1.5',
    rate: '60/min', quota: '1000/day', routes: '[{"methods":["GET"],"paths":["/x"]}]', payload: '{}',
    approval: 'each', infinite: true,
  })
  assert.equal(overridesProblem(page), null, `the page parser emits a key the daemon refuses: ${Object.keys(page)}`)
  // A key the parser does not read is refused there, naming it (fix round 2),
  // as the daemon refuses it.
  for (const k of ['hosts', 'deny_paths', 'not_a_field']) assert.throws(() => parseOverrides({ budget: '1', [k]: 'x' }), (e) => e.field === k)
  assert.equal(overridesProblem(parseOverrides({ route: ['GET:/x'] })), null)
  // The CLI refuses, before sending, any field outside the item's own list;
  // that list holds only fields the daemon applies.
  const [item] = await fetchPending(async (path) => (path === '/v1/session-requests'
    ? [{ id: 'sr_x', summary: 's', created_at: '2030-01-01T00:00:00Z', proposal: { cred: 'demo' } }]
    : []))
  assert.equal(item.kind, 'session')
  const settable = [...item.narrowable, ...item.owner_settable]
  assert.equal(overridesProblem(Object.fromEntries(settable.map((f) => [f, 1]))), null, `settable: ${settable}`)
  for (const k of ['hosts', 'deny_paths', 'cred_x']) assert.match(overridesProblem({ [k]: 1 }), new RegExp(k))
})

// --- D2 -------------------------------------------------------------------------

test('D2: towardPage withholds passphrase at any depth, in any case or hyphenation', () => {
  const got = towardPage({
    passphrase: 'p1', PassPhrase: 'p2', nested: [{ PASSPHRASE: 'p3', 'pass-phrase': 'p4', pass_phrase: 'p5', 'Pass-Phrase': 'p6', note: 'kept' }],
    has_passphrase: true, passphrase_set_at: '2030-01-01',
  })
  for (const p of ['p1', 'p2', 'p3', 'p4', 'p5', 'p6']) assert.ok(!JSON.stringify(got).includes(p), JSON.stringify(got))
  // Only the name itself is withheld: the flags around it still reach the page.
  assert.equal(got.has_passphrase, true)
  assert.equal(got.passphrase_set_at, '2030-01-01')
  assert.equal(got.nested[0].note, 'kept')
})

test('D2 (round 3): a run of hyphens, underscores or spaces is one separator, so pass--phrase, pass__phrase and "pass phrase" are withheld', () => {
  const got = towardPage({
    'pass--phrase': 'q1', pass__phrase: 'q2', 'pass phrase': 'q3', 'Pass -_ Phrase': 'q4',
    nested: { 'recovery pass phrase': 'q5', 'recovery--passphrase': 'q6', 'webhook--url': 'q7' },
    'pass phrase note': 'kept', has_passphrase: true,
  })
  for (const q of ['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7']) assert.ok(!JSON.stringify(got).includes(q), JSON.stringify(got))
  assert.equal(got['pass phrase note'], 'kept')
  assert.equal(got.has_passphrase, true)
})
