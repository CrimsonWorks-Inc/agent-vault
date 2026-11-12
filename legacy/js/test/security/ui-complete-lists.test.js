// The page's complete-list readers against the real daemon and UI server.
//
// The overview's counts, the access review, the credential and template
// pickers and the waiting badge read a whole list with fetchAll, page after
// page. They must get all of it: the old page read each list in one answer,
// and a reader that stops early would count, offer or badge a partial set as
// if it were the whole one. Nothing here is stubbed: a throwaway vault, the
// real Daemon, the real UiServer and the page's own paging module.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { fetchAll, fetchPages, pageQuery, readEnvelope } from '../../../../web/src/lib/paging.js'
import { startDaemon, startUi } from './fix-control-helpers.js'

const MANY = 10_001
// The daemon's most: 32 stored tripwire rules.
const RULES = Array.from({ length: 32 }, (_, i) => ({ id: `rule-${String(i).padStart(2, '0')}`, codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 60, action: 'revoke_session' }))

let d
let u
before(async () => {
  d = await startDaemon()
  const original = d.vault.createSession({ label: 'seed', ttlMs: 3_600_000 }).session
  for (let i = 0; i < MANY; i++) {
    const id = `s_many_${String(i).padStart(5, '0')}`
    d.vault.db.sessions[id] = { ...original, id, label: id }
  }
  delete d.vault.db.sessions[original.id]
  d.vault.updateSettings({ tripwires: { enabled: false, rules: RULES } })
  u = await startUi(d)
})
after(async () => { await u?.stop(); await d?.stop() })

/** The page's `api.get`, over the real UI server. */
function pageGet(calls) {
  return async (path, query) => {
    calls.push(query)
    const r = await u.api('GET', `${path}?${new URLSearchParams(query)}`)
    const body = await r.json()
    if (!r.ok) throw new Error(JSON.stringify(body))
    return body
  }
}

test('fetchAll reads every row of a list longer than 50 pages of 200', async () => {
  const calls = []
  const all = await fetchAll(pageGet(calls), 'sessions')
  assert.equal(all.length, MANY, 'the overview would count a partial list as the whole one')
  assert.equal(new Set(all.map((s) => s.id)).size, MANY, 'each row once')
  assert.equal(calls.length, Math.ceil(MANY / 200))
  assert.ok(calls.length > 50)
  assert.ok(calls.every((q) => q.paged === 1 && q.limit === 200))
})

test('32 tripwire rules: the list the page shows pages and searches; the snapshot has all 32', async () => {
  const get = pageGet([])
  // The displayed list: a page of 25, then the other 7, then a search.
  const first = readEnvelope(await get('tripwires', pageQuery({ limit: 25 })))
  assert.equal(first.total, 32)
  assert.deepEqual(first.items.map((r) => r.id), RULES.slice(0, 25).map((r) => r.id))
  const second = readEnvelope(await get('tripwires', pageQuery({ limit: 25, cursor: first.next_cursor })))
  assert.deepEqual(second.items.map((r) => r.id), RULES.slice(25).map((r) => r.id))
  assert.equal(second.next_cursor, null)
  const found = readEnvelope(await get('tripwires', pageQuery({ limit: 25, q: 'rule-07' })))
  assert.deepEqual(found.items.map((r) => r.id), ['rule-07'])
  // The snapshot the editor and the signed body use: every rule, and the settings beside them.
  const all = await fetchPages(get, 'tripwires')
  assert.deepEqual(all.items, RULES)
  assert.equal(all.beside.enabled, false)
  assert.equal(all.beside.rules_saved, true)
})
