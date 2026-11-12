// C4, one budget reader (integrate-2). The gateway's budget stage and the
// store's chargeGrant, issue and consume used to read an unusual budget each
// their own way. Both failed closed, but they disagreed: a layer with no limit
// was "no limit" to the gateway and "unreadable" to chargeGrant, so a
// redirect hop on such a grant was refused; '1e3' or 5.5 were numbers to one
// reader and nonsense to the other. Now both call policy.budgetLimit, and
// these are the inputs w2-store-report.md listed, through both call sites.

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { budgetLimit } from '../../src/core/policy.js'
import { setup, cleanup } from './gateway-helpers.js'

afterEach(cleanup)

const ABSENT = Symbol('absent')
// [label, budget layer on the grant, what C4 reads it as]
const CASES = [
  ['absent', ABSENT, Infinity],
  ['null', null, null],
  ['unit only', { unit: 'requests' }, Infinity],
  ['limit undefined', { unit: 'requests', limit: undefined }, Infinity],
  ['limit null', { unit: 'requests', limit: null }, null],
  ["limit ''", { unit: 'requests', limit: '' }, null],
  ["'1e3'", { unit: 'requests', limit: '1e3' }, null],
  ['5.5', { unit: 'requests', limit: 5.5 }, null],
  ["'05'", { unit: 'requests', limit: '05' }, null],
  ["' 5'", { unit: 'requests', limit: ' 5' }, null],
  ['true', { unit: 'requests', limit: true }, null],
  ['[5]', { unit: 'requests', limit: [5] }, null],
  ['2 ** 53', { unit: 'requests', limit: 2 ** 53 }, null],
  ["unit 'usd'", { unit: 'usd', limit: 5 }, null],
  ['invalid: true', { unit: 'requests', limit: 5, invalid: true }, null],
  ['an extra key', { unit: 'requests', limit: 5, burst: 9 }, null],
  ['a number, not a layer', 5, null],
  ["'lots'", { unit: 'requests', limit: 'lots' }, null],
  ["'Infinity'", { unit: 'requests', limit: 'Infinity' }, null],
  ['-1', { unit: 'requests', limit: -1 }, null],
  ['NaN', { unit: 'requests', limit: NaN }, null],
  ['0', { unit: 'requests', limit: 0 }, 0],
  ["'0'", { unit: 'requests', limit: '0' }, 0],
  ['50', { unit: 'requests', limit: 50 }, 50],
  ["'50'", { unit: 'requests', limit: '50' }, 50],
]

test('the shared reader gives each listed budget its C4 meaning', () => {
  for (const [label, budget, expected] of CASES) {
    assert.equal(budgetLimit(budget === ABSENT ? undefined : budget), expected, label)
  }
})

/** The grant as a hand edit or an old vault might hold it, with `used` already spent. */
function withBudget(f, budget, used) {
  if (budget === ABSENT) delete f.grant.policy.budget
  else f.grant.policy.budget = budget
  f.grant.budget_used = used
}

/** What the gateway does: 'allow', or the rule it refused with. */
async function gateway(f, ph) {
  const res = await f.pipeline.handle(f.request({ headers: [['host', '127.0.0.1'], ['av-session', f.token], ['x-key', ph]] }))
  return res.status === 200 ? 'allow' : JSON.parse(res.body).rule
}

test('the gateway and chargeGrant agree on every listed budget, at the limit and under it', async () => {
  for (const [label, budget, limit] of CASES) {
    // The placeholder is issued under an ordinary budget first: issue refuses
    // a budget of 0 outright, and this is about reading, not issuing.
    const f = setup()
    const ph = f.ph('key', 1000)
    const probe = async (used) => {
      withBudget(f, budget, used)
      const before = f.grant.budget_used
      const charged = f.vault.chargeGrant(f.grant.id)
      if (charged) f.grant.budget_used = before
      withBudget(f, budget, used)
      return { gateway: await gateway(f, ph), charged }
    }
    if (limit === null) {
      // Unreadable: both refuse, whatever was spent.
      const { gateway: g, charged } = await probe(0)
      assert.ok(g === 'budget_invalid' || g === 'budget', `${label}: the gateway answered ${g}`)
      assert.equal(charged, false, `${label}: chargeGrant charged an unreadable budget`)
    } else if (limit === Infinity) {
      // No limit at this layer: both let a heavily used grant through.
      const { gateway: g, charged } = await probe(10_000)
      assert.equal(g, 'allow', `${label}: the gateway`)
      assert.equal(charged, true, `${label}: chargeGrant`)
    } else {
      // A number: both refuse at the limit, and both allow one under it.
      const at = await probe(limit)
      assert.equal(at.gateway, 'budget', `${label}: the gateway at the limit`)
      assert.equal(at.charged, false, `${label}: chargeGrant at the limit`)
      if (limit > 0) {
        const under = await probe(limit - 1)
        assert.equal(under.gateway, 'allow', `${label}: the gateway under the limit`)
        assert.equal(under.charged, true, `${label}: chargeGrant under the limit`)
      }
    }
    cleanup()
  }
})
