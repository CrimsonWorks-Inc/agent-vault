// The supply-chain promises of contract D2, checked where they are written.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))
const lock = JSON.parse(readFileSync(new URL('../../package-lock.json', import.meta.url), 'utf8'))

test('agent-vault has no runtime dependencies', () => {
  assert.deepEqual(pkg.dependencies, {})
  assert.equal(pkg.optionalDependencies, undefined)
  assert.equal(pkg.peerDependencies, undefined)
})

test('every devDependency is an exact version, and the lockfile agrees', () => {
  for (const [name, v] of Object.entries(pkg.devDependencies)) {
    assert.match(v, /^\d+\.\d+\.\d+$/, `${name} is ${v}, not an exact version`)
    assert.equal(lock.packages[`node_modules/${name}`]?.version, v, `${name} in the lockfile is not ${v}`)
  }
  assert.deepEqual(lock.packages[''].dependencies ?? {}, {}, 'the lockfile records a runtime dependency')
})

test('the package ships the built page and not its source', () => {
  assert.ok(pkg.files.includes('src'), 'src (with src/ui/dist) ships')
  assert.ok(!pkg.files.some((f) => f === 'web' || f.startsWith('web/')), 'web/ must not ship')
})

test('the UI scripts are wired: build, dev, tests, and the prepack drift check', () => {
  assert.equal(pkg.scripts['build:ui'], 'vite build --config web/vite.config.js')
  assert.match(pkg.scripts['dev:ui'], /vite --config web\/vite\.config\.js/)
  assert.match(pkg.scripts['test:ui'], /vitest run/)
  assert.match(pkg.scripts.test, /web\/test\/\*\.test\.js/)
  assert.match(pkg.scripts.test, /vitest run/)
  assert.equal(pkg.scripts.prepack, 'node web/scripts/check-dist.mjs')
})
