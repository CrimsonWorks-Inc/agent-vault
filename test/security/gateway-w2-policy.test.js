import { test } from 'node:test'
import assert from 'node:assert/strict'
import { intersect, evaluateHttp, needsApproval, validate, lint, grantPolicyFromInput } from '../../src/core/policy.js'

const request = (method, path) => ({ host: 'api.example.test', method, path })
const pair = (methods, paths) => ({ methods, paths })
const allowed = (policy, method, path) => assert.doesNotThrow(() => evaluateHttp(policy, request(method, path)))
const denied = (policy, method, path, rule = 'routes') => assert.throws(() => evaluateHttp(policy, request(method, path)), (e) => e.code === 'AV_POLICY_DENIED' && e.rule === rule)

test('route pairs bind methods to their own paths and every inherited set applies', () => {
  const parent = { routes: [pair(['GET'], ['/repos/**']), pair(['POST'], ['/repos/*/issues'])] }
  const effective = intersect([parent])
  allowed(effective, 'GET', '/repos/o/pulls')
  allowed(effective, 'POST', '/repos/o/issues')
  denied(effective, 'POST', '/repos/o/pulls')
  // Which route allowed it, by index (C27): never the glob text.
  assert.equal(evaluateHttp(effective, request('POST', '/repos/o/issues')).route_rule, 1)
  assert.equal(evaluateHttp(effective, request('GET', '/repos/o/pulls')).route_rule, 0)
  const child = intersect([parent, { routes: [pair(['POST'], ['/repos/**'])] }])
  denied(child, 'POST', '/repos/o/pulls')
  denied(child, 'GET', '/repos/o/pulls')
  allowed(child, 'POST', '/repos/o/issues')
  denied(intersect([{ routes: [] }]), 'GET', '/')
  allowed(intersect([{}]), 'POST', '/')
  denied(intersect([parent, { deny_paths: ['/repos/o/issues'] }]), 'POST', '/repos/o/issues', 'deny_paths:0')
})

test('stored effective route and payload policies retain all ancestor constraints', () => {
  const first = intersect([
    { routes: [pair(['GET'], ['/a/**'])], payload: { query: { first: { required: true } } } },
    { routes: [pair(['GET'], ['/a/b'])], payload: { query: { second: { absent: true } } } },
  ])
  const reused = intersect([first, { methods: ['GET', 'POST'], paths: ['/**'] }])
  assert.equal(Object.hasOwn(reused, 'routes'), false)
  assert.equal(Object.hasOwn(reused, 'payload'), false)
  assert.deepEqual(reused.payload_sets, first.payload_sets)
  assert.deepEqual(reused.route_sets, first.route_sets)
  assert.equal(reused.payload_sets.length, 2)
  allowed(reused, 'GET', '/a/b')
  denied(reused, 'GET', '/a/c')
})

test('malformed stored route and payload constraints refuse before reaching upstream', () => {
  for (const layer of [{ route_sets: [null] }, { payload_sets: [{ json: { '/x': { min: NaN } } }] }]) {
    assert.ok(validate(layer).length)
    assert.throws(() => evaluateHttp(layer, request('GET', '/')), (e) => e.code === 'AV_POLICY_DENIED' && /_invalid$/.test(e.rule))
  }
  assert.equal(needsApproval(intersect([{ approval: 'unknown' }, { approval: 'auto' }]), { method: 'GET' }), true)
  assert.equal(needsApproval(intersect([{ approval: 'auto' }, { approval: 'unknown' }]), { method: 'GET' }), true)
})

test('creation refuses coercion, supports zero limits, and cannot escape credential hosts', () => {
  const options = { ceiling: ['api.example.test'] }
  for (const spec of [{ budget: '5.5' }, { max_concurrent: 1.5 }, { quota: { count: 1, window: 'week' } }, { spend_tokens: NaN }]) {
    assert.throws(() => grantPolicyFromInput(spec, options), (e) => e.rule === 'policy_invalid')
  }
  assert.throws(() => grantPolicyFromInput({ hosts: ['evil.test'] }, options), (e) => e.rule === 'credential_host')
  const valid = grantPolicyFromInput({ budget: 0, spend_tokens: 0, spend_usd: 0, redirects: 0 }, options)
  assert.equal(valid.budget.limit, 0)
  assert.deepEqual(valid.spend, { tokens: 0, usd_micros: 0 })
  assert.deepEqual(validate(valid), [])
  assert.ok(lint({ routes: [pair(['POST'], ['/**'])], budget: { limit: 1 } }).some((p) => p.level === 'warn' && p.rule === 'routes'))
})
