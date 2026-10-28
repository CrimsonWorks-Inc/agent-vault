// A narrowing that does not parse (C23). parseOverrides throws on a number
// that is not finite or on routes/payload that are not JSON. The page runs
// that parser (C21) and must then show why and send nothing: a decision that
// went through without the narrowing typed for it would grant more than the
// human chose.
//
// Run against the page's own decide action and readNarrowing, with a stand-in
// parser, so the test does not depend on which field the real one refuses.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PAGE, pageSource } from './control-ui-helpers.js'

/** The page's `async decide(btn) { … }` action, braces balanced. */
function decideSource() {
  const start = PAGE.indexOf('async decide(btn) {')
  assert.ok(start >= 0, 'the page has no decide action')
  let depth = 0
  let i = PAGE.indexOf('{', start)
  for (; i < PAGE.length; i++) {
    if (PAGE[i] === '{') depth++
    else if (PAGE[i] === '}' && --depth === 0) break
  }
  return PAGE.slice(start, i + 1)
}

/** decide, wired to a stand-in parser and recorders for everything it calls. */
function harness(parseOverrides) {
  const calls = { toast: [], gated: [], api: [], operationFor: [], render: 0 }
  const input = (field, value) => ({ dataset: { field }, value })
  const document = {
    querySelectorAll: () => [input('budget', 'lots'), input('methods', 'GET')],
    querySelector: () => null,
  }
  const deps = {
    document,
    parseOverrides,
    drafts: new Map(),
    toast: (m) => { calls.toast.push(String(m)) },
    render: () => { calls.render++ },
    operationFor: async (op, params) => { calls.operationFor.push({ op, params }); return { op, ...params } },
    gated: async (op, send) => { calls.gated.push(op); return send({ challengeId: 'c' }) },
    api: async (method, path, body) => { calls.api.push({ method, path, body }); return {} },
  }
  const make = new Function('deps', `
    const { document, parseOverrides, drafts, toast, render, operationFor, gated, api } = deps
    ${pageSource('readNarrowing')}
    return { ${decideSource()} }`)
  return { actions: make(deps), calls }
}

const approveBtn = { dataset: { id: 'sr_1', granted: '1', kind: 'session' } }

test('a narrowing the parser refuses is shown, and nothing is signed or sent (C23)', async () => {
  const { actions, calls } = harness(() => { throw new Error('budget must be a finite number') })
  await actions.decide(approveBtn)
  assert.equal(calls.operationFor.length, 0, 'an operation was built for a narrowing that did not parse')
  assert.equal(calls.gated.length, 0, 'a signature was asked for')
  assert.equal(calls.api.length, 0, 'a decision was sent without its narrowing')
  assert.equal(calls.toast.length, 1)
  assert.match(calls.toast[0], /budget must be a finite number/)
  assert.doesNotMatch(calls.toast[0], /Approved/)
})

test('a narrowing that parses is signed and sent as parsed', async () => {
  const { actions, calls } = harness((typed) => ({ methods: [typed.methods], budget: 7 }))
  await actions.decide(approveBtn)
  assert.equal(calls.gated.length, 1)
  assert.deepEqual(calls.operationFor[0], { op: 'session_request.decide', params: { id: 'sr_1', granted: true, methods: ['GET'], budget: 7 } })
  assert.deepEqual(calls.api[0].body.overrides, { methods: ['GET'], budget: 7 })
  assert.deepEqual(calls.toast, ['Approved'])
})

test('a denial reads no narrowing, so a refusing parser cannot block it', async () => {
  let asked = 0
  const { actions, calls } = harness((typed) => {
    asked++
    if (Object.keys(typed).length) throw new Error('unexpected')
    return {}
  })
  await actions.decide({ dataset: { id: 'sr_1', granted: '0', kind: 'session' } })
  assert.equal(asked, 1)
  assert.equal(calls.api.length, 1)
  assert.equal(calls.api[0].body.granted, false)
  assert.equal(calls.api[0].body.overrides, undefined)
})

test('decide reads the narrowing through readNarrowing before it signs anything', () => {
  const decide = decideSource()
  const read = decide.indexOf('readNarrowing(typed)')
  assert.ok(read > 0 && read < decide.indexOf('gated('), 'the narrowing is not read before the signature')
  assert.match(pageSource('readNarrowing'), /const overrides = parseOverrides\(typed\)/)
})
