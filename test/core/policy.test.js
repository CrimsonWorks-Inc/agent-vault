import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as policy from '../../src/core/policy.js'

const GH = { kind: 'github', hosts: ['api.github.com'], deny_paths: ['/repos/*/*/hooks', '/user/keys'] }
const WS = { hosts: ['api.github.com'], methods: ['GET', 'HEAD'], paths: ['/repos/frozencrow/*', '/user'], budget: { unit: 'requests', limit: 500 } }

test('intersection narrows and never widens', () => {
  const eff = policy.intersect([GH, WS, { methods: ['GET'] }])
  assert.deepEqual(eff.methods, ['GET'])
  const widened = policy.intersect([GH, WS, { methods: ['GET', 'POST', 'DELETE'] }])
  assert.deepEqual(widened.methods, ['GET'], 'a child must not add a method the parent lacks')
})

test('numeric limits take the minimum and approval takes the stricter mode', () => {
  const eff = policy.intersect([
    { budget: { unit: 'requests', limit: 500 }, approval: 'on-write', max_concurrent: 8 },
    { budget: { unit: 'requests', limit: 100 }, approval: 'each', max_concurrent: 20 },
  ])
  assert.equal(eff.budget.limit, 100)
  assert.equal(eff.approval, 'each')
  assert.equal(eff.max_concurrent, 8)
})

test('enums narrow: a child cannot upgrade read-only to raw', () => {
  assert.equal(policy.intersect([{ sql_profile: 'read-only' }, { sql_profile: 'raw' }]).sql_profile, 'read-only')
  assert.equal(policy.intersect([{ sql_profile: 'raw' }, { sql_profile: 'read-write' }]).sql_profile, 'read-write')
  assert.equal(policy.intersect([{ mode: 'run' }, { mode: 'agent' }]).mode, 'run')
})

test('an allowed request passes and returns its normalized destination', () => {
  const eff = policy.intersect([GH, WS])
  const r = policy.evaluateHttp(eff, { method: 'GET', host: 'api.github.com', path: '/repos/frozencrow/agent-vault' })
  assert.equal(r.host, 'api.github.com')
  assert.equal(r.path, '/repos/frozencrow/agent-vault')
})

test('a host outside the grant is denied with the reachable hosts named', () => {
  const eff = policy.intersect([GH, WS])
  try {
    policy.evaluateHttp(eff, { method: 'GET', host: 'evil.test', path: '/' })
    assert.fail('should have denied')
  } catch (e) {
    assert.equal(e.code, 'AV_NO_GRANT')
    assert.match(e.hint, /api\.github\.com/)
  }
})

test('a write method under a read-only grant is denied', () => {
  const eff = policy.intersect([GH, WS])
  assert.throws(
    () => policy.evaluateHttp(eff, { method: 'POST', host: 'api.github.com', path: '/repos/frozencrow/x/issues' }),
    (e) => e.code === 'AV_POLICY_DENIED' && e.rule === 'methods',
  )
})

test('a profile deny list outranks a permissive grant', () => {
  const eff = policy.intersect([GH, { hosts: ['api.github.com'], methods: ['GET'], paths: ['/**'] }])
  assert.throws(
    () => policy.evaluateHttp(eff, { method: 'GET', host: 'api.github.com', path: '/user/keys' }),
    (e) => e.code === 'AV_POLICY_DENIED' && e.rule.startsWith('deny_paths'),
  )
})

test('path traversal cannot escape an allowed prefix', () => {
  const eff = policy.intersect([GH, WS])
  for (const evil of [
    '/repos/frozencrow/../../user/keys',
    '/repos/frozencrow/%2e%2e/%2e%2e/user/keys',
    '/repos/frozencrow/..%2f..%2fuser%2fkeys',
  ]) {
    assert.throws(() => policy.evaluateHttp(eff, { method: 'GET', host: 'api.github.com', path: evil }), /AV_/, evil)
  }
})

test('normalization rejects userinfo, trailing dots and illegal characters', () => {
  assert.equal(policy.normalizeHost('API.GitHub.Com.'), 'api.github.com')
  assert.throws(() => policy.normalizeHost('user@evil.test'), /AV_POLICY_DENIED/)
  assert.throws(() => policy.normalizeHost('evil\\test'), /AV_POLICY_DENIED/)
})

test('glob semantics: * spans one segment, ** spans many', () => {
  assert.ok(policy.matchPath('/repos/*/issues', '/repos/frozencrow/issues'))
  assert.ok(!policy.matchPath('/repos/*/issues', '/repos/frozencrow/agent-vault/issues'))
  assert.ok(policy.matchPath('/repos/**', '/repos/frozencrow/agent-vault/issues/1'))
})

test('wildcard hosts over shared suffixes are refused by lint', () => {
  const problems = policy.lint({ hosts: ['*.s3.amazonaws.com'], budget: { limit: 1 } })
  assert.ok(problems.some((p) => p.level === 'error' && p.rule === 'hosts'))
  assert.equal(policy.lint({ hosts: ['*.internal.example.com'], budget: { limit: 1 } }).filter((p) => p.rule === 'hosts').length, 0)
})

test('lint requires a budget on every grant', () => {
  assert.ok(policy.lint({ hosts: ['api.github.com'] }).some((p) => p.level === 'error' && p.rule === 'budget'))
})

test('approval modes behave as documented', () => {
  assert.equal(policy.needsApproval({ approval: 'auto' }, { method: 'POST' }), false)
  assert.equal(policy.needsApproval({ approval: 'on-write' }, { method: 'GET' }), false)
  assert.equal(policy.needsApproval({ approval: 'on-write' }, { method: 'POST' }), true)
  assert.equal(policy.needsApproval({ approval: 'each' }, { method: 'GET' }), true)
  assert.equal(policy.needsApproval({ approval: 'first-use' }, { method: 'GET', firstUse: true }), true)
})
