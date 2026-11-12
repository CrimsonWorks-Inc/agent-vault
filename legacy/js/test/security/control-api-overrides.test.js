// The one override parser (C21, as amended by C23). parseOverrides is
// injected into the approvals page as source, so it must not reach outside
// its own body; and a narrowing it cannot read throws, naming the field,
// rather than being dropped: a dropped narrowing approves the agent's own
// proposal with nothing telling the human their flag was ignored.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi } from './control-api-helpers.js'
import { parseOverrides } from '../../src/pending.js'

/** The function as the page gets it: its source, evaluated where no module scope exists. */
const injected = new Function(`return (${parseOverrides.toString()})`)()

/** The result of a call, or the error it threw, in a comparable shape. */
const outcome = (fn, args) => {
  try { return { ok: fn(args) } } catch (e) { return { threw: e.constructor.name, message: e.message, field: e.field } }
}

const ROUTES = [{ methods: ['GET'], paths: ['/only'] }]
const PAYLOAD = { query: { q: { max_length: 8 } } }

// Every field parseOverrides reads, typed as the CLI, the page or a caller
// might, including what must throw.
const INPUTS = [
  {}, { methods: 'get, post', paths: '/a/**,/b/**' }, { methods: ['GET'], paths: ['/x'] },
  { budget: '5' }, { budget: 5 }, { budget: '' }, { budget: 'abc' }, { budget: '   ' }, { budget: 'Infinity' }, { budget: true },
  { uses: '2' }, { ttl_minutes: '15' }, { 'ttl-minutes': '15' }, { ttl_minutes: 'soon' },
  { grant_ttl_minutes: '10' }, { 'grant-ttl': '10' }, { grant_ttl: 'x' },
  { max_concurrent: '4' }, { concurrency: 'four' }, { redirects: '0' }, { redirects: 'NaN' },
  { spend_tokens: '1000' }, { 'spend-tokens': '1e3' }, { spend_usd: '1.25' }, { 'spend-usd': '$1' },
  { rate: '  60/min  ' }, { rate: 60 }, { rate: { n: 1 } }, { quota: ' 1000/day' }, { quota: ['x'] },
  { routes: JSON.stringify(ROUTES) }, { routes: ROUTES }, { routes: '[{"methods":' }, { routes: '5' }, { routes: 'null' },
  { route: 'get,head:/repos/**' }, { route: ['GET:/a', 'POST:/b'] }, { route: 'no-colon' },
  { payload: JSON.stringify(PAYLOAD) }, { payload: PAYLOAD }, { payload: '{oops' }, { payload: '"text"' },
  { approval: 'auto' }, { approval: '' }, { infinite: true }, { infinite: 'true' }, { infinite: 'yes' },
]

test('parseOverrides is self-contained: built from its source in a fresh scope, it agrees on every field (C21, C23)', () => {
  for (const args of INPUTS) {
    assert.deepEqual(outcome(injected, args), outcome(parseOverrides, args), JSON.stringify(args))
  }
  // The shorthand is the one the review caught: it used a module-scope helper.
  assert.deepEqual(injected({ route: 'get,head:/repos/**' }).routes, [{ methods: ['GET', 'HEAD'], paths: ['/repos/**'] }])
})

test('routes and payload as JSON strings are parsed; a value passes through; bad JSON throws (C23)', () => {
  assert.deepEqual(parseOverrides({ routes: JSON.stringify(ROUTES) }), { routes: ROUTES })
  assert.deepEqual(parseOverrides({ routes: ROUTES }), { routes: ROUTES })
  assert.deepEqual(parseOverrides({ payload: JSON.stringify(PAYLOAD) }), { payload: PAYLOAD })
  assert.deepEqual(parseOverrides({ payload: PAYLOAD }), { payload: PAYLOAD })
  for (const [field, bad] of [['routes', '[{"methods":'], ['payload', '{oops'], ['routes', 'null'], ['payload', '"text"'], ['routes', '5']]) {
    assert.throws(() => parseOverrides({ [field]: bad }), (e) => e.field === field && e instanceof TypeError, `${field} ${bad}`)
  }
  // A full list wins over the shorthand, as before.
  assert.deepEqual(parseOverrides({ routes: JSON.stringify(ROUTES), route: 'POST:/wide' }), { routes: ROUTES })
})

test('a numeric narrowing is Number(v), and anything not finite throws, naming the field (C23)', () => {
  assert.deepEqual(parseOverrides({ budget: '5', uses: 2, ttl_minutes: '15', grant_ttl_minutes: '10', max_concurrent: '4', redirects: '0', spend_tokens: '1000', spend_usd: '1.25' }), {
    budget: 5, uses: 2, ttl_minutes: 15, grant_ttl_minutes: 10, max_concurrent: 4, redirects: 0, spend_tokens: 1000, spend_usd: 1.25,
  })
  const fields = {
    budget: 'budget', uses: 'uses', ttl_minutes: 'ttl_minutes', 'ttl-minutes': 'ttl_minutes',
    grant_ttl_minutes: 'grant_ttl_minutes', 'grant-ttl': 'grant_ttl_minutes', max_concurrent: 'max_concurrent', concurrency: 'max_concurrent',
    redirects: 'redirects', spend_tokens: 'spend_tokens', 'spend-tokens': 'spend_tokens', spend_usd: 'spend_usd', 'spend-usd': 'spend_usd',
  }
  for (const [flag, field] of Object.entries(fields)) {
    for (const typo of ['abc', '5x', '   ', 'Infinity', true, {}, Number.NaN]) {
      assert.throws(() => parseOverrides({ [flag]: typo }), (e) => e.field === field, `${flag}=${JSON.stringify(typo)} was not refused`)
    }
  }
  // An empty box is still absent, not zero, and not an error.
  assert.deepEqual(parseOverrides({ budget: '', uses: null, redirects: undefined }), {})
})

test('rate and quota: a string is trimmed, anything else passes through for the daemon (C23)', () => {
  assert.deepEqual(parseOverrides({ rate: '  60/min  ', quota: ' 1000/day ' }), { rate: '60/min', quota: '1000/day' })
  const obj = { n: 1 }
  assert.deepEqual(parseOverrides({ rate: 60, quota: obj }), { rate: 60, quota: obj })
})

test('an approval narrowed with --routes or --payload as JSON creates a grant with the parsed value, not the proposal', async () => {
  const a = await startApi()
  try {
    const decide = async (overrides) => {
      const asked = await a.control('POST', '/v1/session-requests', {
        cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], routes: [{ methods: ['GET', 'POST'], paths: ['/**'] }], reason: 'x',
      })
      assert.equal(asked.status, 200, JSON.stringify(asked.body))
      const r = await a.control('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true, overrides })
      assert.equal(r.status, 200, JSON.stringify(r.body))
      return a.vault.db.grants[r.body.session.grant_id].policy
    }
    // Exactly as the CLI reads `--routes '…'` and `--payload '…'`.
    const routed = await decide(parseOverrides({ routes: JSON.stringify(ROUTES) }))
    assert.deepEqual(routed.routes, ROUTES, 'the agent\'s wider routes were approved')
    const shaped = await decide(parseOverrides({ payload: JSON.stringify(PAYLOAD) }))
    assert.deepEqual(shaped.payload, PAYLOAD, 'the payload narrowing was dropped')
    // A proposal decided with a value the parser refused never gets that far.
    assert.throws(() => parseOverrides({ routes: '[{"methods":' }), /routes/)
  } finally { await a.stop() }
})
