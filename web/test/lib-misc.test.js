import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readTheme, saveTheme, applyTheme, nextTheme, effectiveTheme, THEME_KEY } from '../src/lib/theme.js'
import { parseHash, formatHash, PAGES } from '../src/lib/router.js'
import { createWatcher, notificationText, batchText, notificationsOn, setNotifications } from '../src/lib/notify.js'
import { createCache } from '../src/lib/cache.js'

const memory = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m } }
const hostile = { getItem() { throw new Error('no') }, setItem() { throw new Error('no') }, removeItem() { throw new Error('no') } }

test('theme: system by default, a pick is remembered, storage failures are survived', () => {
  const s = memory()
  assert.equal(readTheme(s), 'system')
  saveTheme(s, 'dark')
  assert.equal(s.m.get(THEME_KEY), 'dark')
  assert.equal(readTheme(s), 'dark')
  saveTheme(s, 'system')
  assert.equal(s.m.has(THEME_KEY), false)
  s.setItem(THEME_KEY, '<script>')
  assert.equal(readTheme(s), 'system')
  assert.equal(readTheme(hostile), 'system')
  assert.doesNotThrow(() => saveTheme(hostile, 'light'))
  assert.equal(nextTheme('system'), 'light')
  assert.equal(nextTheme('dark'), 'system')
  assert.equal(effectiveTheme('system', true), 'dark')
})

test('theme goes on <html> only when picked', () => {
  const attrs = new Map()
  const root = { setAttribute: (k, v) => attrs.set(k, v), removeAttribute: (k) => attrs.delete(k) }
  applyTheme(root, 'dark')
  assert.equal(attrs.get('data-theme'), 'dark')
  applyTheme(root, 'system')
  assert.equal(attrs.has('data-theme'), false)
})

test('routes: the old page\'s fragments still open the same views', () => {
  assert.deepEqual(parseHash('#docs/connect'), { page: 'docs', rest: 'connect' })
  assert.deepEqual(parseHash('#approvals/req%2F1'), { page: 'approvals', rest: 'req/1' })
  assert.deepEqual(parseHash('#/sessions'), { page: 'sessions', rest: '' })
  assert.deepEqual(parseHash('#nope'), { page: 'overview', rest: '' })
  assert.deepEqual(parseHash(''), { page: 'overview', rest: '' })
  assert.deepEqual(parseHash('#audit/%E0%A4%A'), { page: 'audit', rest: '' })
  assert.equal(formatHash('approvals', 'req/1'), '#approvals/req%2F1')
  assert.deepEqual(PAGES.map((p) => p.id).sort(), ['approvals', 'audit', 'containment', 'credentials', 'docs', 'notifications', 'overview', 'sessions', 'settings', 'templates'])
})

test('notifications: the first look primes, later looks announce what is new', () => {
  const watch = createWatcher()
  assert.deepEqual(watch([{ id: 'a' }]), [])
  assert.deepEqual(watch([{ id: 'a' }, { id: 'b' }]).map((x) => x.id), ['b'])
  assert.deepEqual(watch([{ id: 'b' }]), [])
  assert.equal(notificationText({ kind: 'request', headline: 'POST /repos\u202e\nx' }), 'Held request: POST /repos x')
  assert.equal(notificationText({ kind: 'session', headline: 'y'.repeat(200) }).length, 120)
  assert.equal(batchText([{ kind: 'session', headline: 'a' }, { kind: 'session', headline: 'b' }]), 'Session requested: a (and 1 more)')
  const s = memory()
  assert.equal(notificationsOn(s), false)
  setNotifications(s, true)
  assert.equal(notificationsOn(s), true)
  assert.equal(notificationsOn(hostile), false)
})

test('the slow cache keeps a value for its window and forgets on clear', async () => {
  let t = 0
  let n = 0
  const c = createCache({ ms: 1000, now: () => t })
  const load = async () => ++n
  assert.equal(await c.get('k', load), 1)
  t = 500
  assert.equal(await c.get('k', load), 1)
  t = 1500
  assert.equal(await c.get('k', load), 2)
  c.clear()
  assert.equal(await c.get('k', load), 3)
})
