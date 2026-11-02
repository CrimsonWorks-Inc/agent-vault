// A narrowing that does not parse (C23). parseOverrides throws on a number
// that is not finite, on routes/payload that are not JSON, and on a key no
// approval applies. The page reads the narrowing with that parser (C21) and
// must then say why and send nothing: a decision that went through without
// the narrowing typed for it would grant more than the human chose.
//
// Run against the page's own decision builder (web/src/components/approvals/
// decide.js decisionCall, which Approvals calls inside the gated button's
// operation, before any challenge is asked for), with recorders for what it
// would sign and send.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { decisionCall, readNarrowing } from '../../web/src/components/approvals/decide.js'
import { parseOverrides } from '../../src/pending.js'

const ITEM = { id: 'sr_1', kind: 'session', narrowable: ['methods', 'budget', 'routes'], owner_settable: ['approval', 'infinite'] }

/** decisionCall, with recorders for everything it calls. */
async function decide(granted, fields, extra = {}) {
  const calls = { operationFor: [], api: [], error: null, call: null }
  const deps = {
    operationFor: async (op, params) => { calls.operationFor.push({ op, params }); return { op, ...params } },
    api: { post: async (path, body) => { calls.api.push({ path, body }); return {} } },
  }
  try {
    calls.call = await decisionCall(ITEM, granted, { fields, ...extra }, deps)
  } catch (e) { calls.error = String(e?.message ?? e) }
  return calls
}

test('a narrowing the parser refuses is said, and nothing is signed or sent (C23)', async () => {
  for (const [fields, why] of [[{ budget: 'lots', methods: 'GET' }, /budget/], [{ routes: '[{not json' }, /routes/]]) {
    const calls = await decide(true, fields)
    assert.equal(calls.operationFor.length, 0, 'an operation was built for a narrowing that did not parse')
    assert.equal(calls.api.length, 0, 'a decision was sent without its narrowing')
    assert.equal(calls.call, null, 'nothing was handed to the gate to sign')
    assert.match(calls.error ?? '', /^That narrowing does not parse, so nothing was sent: /)
    assert.match(calls.error, why)
  }
})

test('a narrowing that parses is signed and sent as parsed', async () => {
  const calls = await decide(true, { methods: 'get', budget: '7' })
  assert.equal(calls.error, null)
  // The owner's approval box goes as chosen, '' included, and the parser reads '' as unchanged.
  const parsed = parseOverrides({ methods: 'get', budget: '7', approval: '' })
  assert.deepEqual(calls.operationFor, [{ op: 'session_request.decide', params: { id: 'sr_1', granted: true, ...parsed } }])
  await calls.call.send({ challengeId: 'c' })
  assert.deepEqual(calls.api[0].body.overrides, parsed)
  assert.deepEqual(calls.api[0].body.overrides.methods, ['GET'])
  assert.equal(calls.api[0].body.overrides.budget, 7)
})

test('a denial reads no narrowing, so text the parser refuses cannot block it', async () => {
  const calls = await decide(false, { budget: 'lots' })
  assert.equal(calls.error, null)
  assert.deepEqual(calls.operationFor, [{ op: 'session_request.decide', params: { id: 'sr_1', granted: false } }])
  await calls.call.send({ challengeId: 'c' })
  assert.equal(calls.api[0].body.granted, false)
  assert.equal(calls.api[0].body.overrides, undefined)
})

test('the narrowing is read by the shared parser, and a refusal is never read as no narrowing', () => {
  assert.deepEqual(readNarrowing({ methods: 'get,head', budget: '3' }), { overrides: parseOverrides({ methods: 'get,head', budget: '3' }) })
  const bad = readNarrowing({ budget: 'Infinity' })
  assert.equal(bad.overrides, undefined, 'a narrowing that does not parse came back as overrides')
  assert.match(bad.error, /nothing was sent/)
  // decisionCall reads the narrowing before it builds the operation.
  const src = readFileSync(new URL('../../web/src/components/approvals/decide.js', import.meta.url), 'utf8')
  const body = src.slice(src.indexOf('export async function decisionCall('))
  assert.ok(body.indexOf('readNarrowing(') < body.indexOf('operationFor('), 'the narrowing is not read before the operation is built')
})
