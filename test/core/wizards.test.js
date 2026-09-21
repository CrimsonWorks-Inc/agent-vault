import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildPolicy, suggestSlug, pathsForScope, scopePresets, ACCESS_LEVELS, BUDGET_CHOICES } from '../../src/cli/wizards.js'

test('read-only access cannot write, and needs no approval because it cannot', () => {
  const p = buildPolicy({ kind: 'github', access: 'read', paths: ['/user'], budget: 100, ttlHours: 8 })
  assert.deepEqual(p.methods, ['GET', 'HEAD'])
  assert.equal(p.approval, 'auto')
  assert.ok(!p.methods.includes('POST'))
})

test('the write level asks before changing anything, and never deletes', () => {
  const p = buildPolicy({ kind: 'github', access: 'write', paths: ['/**'], budget: 500, ttlHours: 8 })
  assert.equal(p.approval, 'on-write')
  assert.ok(p.methods.includes('POST'))
  assert.ok(!p.methods.includes('DELETE'), 'delete needs the explicit full level')
})

test('the full level includes delete and says so by not asking', () => {
  const p = buildPolicy({ kind: 'github', access: 'full', paths: ['/**'], budget: 500, ttlHours: 1 })
  assert.ok(p.methods.includes('DELETE'))
  assert.equal(p.approval, 'auto')
})

test('an unknown access level is refused rather than defaulted', () => {
  // Defaulting here would silently grant something nobody chose.
  assert.throws(() => buildPolicy({ kind: 'github', access: 'admin' }), /unknown access level/)
})

test('the budget falls back to the profile default, not to unlimited', () => {
  const p = buildPolicy({ kind: 'anthropic', access: 'read' })
  assert.equal(p.budget, 20000)
  const generic = buildPolicy({ kind: 'http', access: 'read' })
  assert.equal(generic.budget, 500)
})

test('a suggested name avoids collisions with what is already stored', () => {
  assert.equal(suggestSlug('github', []), 'github')
  assert.equal(suggestSlug('github', ['github']), 'github-2')
  assert.equal(suggestSlug('github', ['github', 'github-2']), 'github-3')
})

test('a suggested name is always a valid slug', () => {
  for (const kind of ['github', 'google-genai', 'Weird Name!', '']) {
    assert.match(suggestSlug(kind, []), /^[a-z0-9-]{1,24}$/)
  }
})

test('the one-repository scope is genuinely narrow', () => {
  const paths = pathsForScope('github', 'repo', 'frozencrow/agent-vault')
  assert.ok(paths.includes('/repos/frozencrow/agent-vault'))
  assert.ok(paths.includes('/repos/frozencrow/agent-vault/**'))
  assert.ok(!paths.some((p) => p === '/**'), 'that would not be one repository')
  assert.ok(!paths.some((p) => p.includes('other-owner')))
})

test('the owner scope covers repos and orgs but not everything', () => {
  const paths = pathsForScope('github', 'owner', 'frozencrow')
  assert.ok(paths.includes('/repos/frozencrow/**'))
  assert.ok(paths.includes('/orgs/frozencrow/**'))
  assert.ok(!paths.includes('/**'))
})

test('custom paths are split and trimmed', () => {
  assert.deepEqual(pathsForScope('http', 'custom', '/a/** , /b'), ['/a/**', '/b'])
})

test('every connector offers a scope list with a custom escape hatch', () => {
  for (const kind of ['github', 'slack', 'anthropic', 'http', 'unknown-kind']) {
    const presets = scopePresets(kind)
    assert.ok(presets.length >= 2, kind)
    assert.ok(presets.some((c) => c.value === 'custom'), `${kind} needs a custom option`)
  }
})

test('model APIs are offered a larger budget than ordinary APIs', () => {
  assert.equal(BUDGET_CHOICES('anthropic')[0].value, 20000)
  assert.equal(BUDGET_CHOICES('github')[0].value, 500)
})

test('every access level has a label and a hint a person can act on', () => {
  for (const [name, level] of Object.entries(ACCESS_LEVELS)) {
    assert.ok(level.label.length > 3, name)
    assert.ok(level.hint.length > 10, name)
    assert.ok(Array.isArray(level.methods) && level.methods.length, name)
  }
})
