// The placeholder ledger has a live-row bound per grant field (max_active),
// and two ways round it.
//
// - Only UNUSED rows were eligible for rotation, so once every live row had
//   been used once the bound stopped applying: ask, use, ask again, and the
//   live rows grew until the budget ran out. vault_get_placeholder plus an
//   ordinary native call is all it took.
// - An explicit ttlMs replaced the grant's placeholder ttl instead of being
//   bounded by it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startDaemon } from './fix-control-helpers.js'

async function sessionFor(d, policy = {}) {
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  const s = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'], budget: 100, ...policy })
  d.daemon.presenceGraceUntil = 0
  assert.equal(s.status, 200, JSON.stringify(s.body))
  return { token: s.body.token, session: d.vault.sessionByToken(s.body.token), grantId: s.body.grant_id }
}

async function getPlaceholder(d, s) {
  const r = await d.daemon.mcp.handle({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'vault_get_placeholder', arguments: { cred: 'demo', reason: 'native client' } },
  }, s.session, s.token)
  const body = JSON.parse(r.result.content[0].text)
  assert.match(String(body.placeholder), /^av1\./, JSON.stringify(body))
  return body.placeholder
}

/** One request through the gateway, the way a native client sends it. */
async function native(d, s, placeholder, path = '/user') {
  const res = await fetch(`http://127.0.0.1:${d.daemon.gatewayPort}/p/demo${path}`, {
    headers: { authorization: `Bearer ${placeholder}`, 'av-session': s.token },
  })
  return { status: res.status, body: await res.text() }
}

const live = (d, s) => d.vault.listPlaceholders(s.session.id).filter((p) => p.state === 'active' && p.grant_id === s.grantId)

test('asking for a placeholder and using it, over and over, stays within max_active', async () => {
  const d = await startDaemon()
  try {
    d.daemon.pipeline.upstream = async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') })
    const s = await sessionFor(d)
    for (let i = 0; i < 12; i++) {
      const p = await getPlaceholder(d, s)
      const r = await native(d, s, p, `/n/${i}`)
      assert.equal(r.status, 200, `call ${i}: ${r.body}`)
    }
    const rows = live(d, s)
    assert.ok(rows.length <= 8, `${rows.length} live placeholders on a grant with max_active 8`)
  } finally { await d.stop() }
})

test('a max_active that is not a number is not an unbounded ledger', async () => {
  const d = await startDaemon()
  try {
    const s = await sessionFor(d)
    d.vault.db.grants[s.grantId].policy.placeholder_policy = { max_active: 'lots' }
    for (let i = 0; i < 12; i++) d.vault.issuePlaceholder({ grantId: s.grantId })
    assert.ok(live(d, s).length <= 8, `${live(d, s).length} live`)
  } finally { await d.stop() }
})

test('a placeholder in use keeps working while fewer than max_active are live', async () => {
  const d = await startDaemon()
  try {
    d.daemon.pipeline.upstream = async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') })
    const s = await sessionFor(d)
    const kept = await getPlaceholder(d, s)
    assert.equal((await native(d, s, kept)).status, 200)
    // Others come and go, up to the bound, and the first one is untouched.
    for (let i = 0; i < 6; i++) await getPlaceholder(d, s)
    for (let i = 0; i < 5; i++) {
      const r = await native(d, s, kept, `/again/${i}`)
      assert.equal(r.status, 200, `reuse ${i}: ${r.body}`)
    }
  } finally { await d.stop() }
})

test('a rotated placeholder says to ask again, and the newest still works', async () => {
  const d = await startDaemon()
  try {
    d.daemon.pipeline.upstream = async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') })
    const s = await sessionFor(d)
    const first = await getPlaceholder(d, s)
    assert.equal((await native(d, s, first)).status, 200)
    let newest
    for (let i = 0; i < 8; i++) {
      newest = await getPlaceholder(d, s)
      assert.equal((await native(d, s, newest, `/n/${i}`)).status, 200)
    }
    const stale = await native(d, s, first)
    assert.notEqual(stale.status, 200)
    assert.match(stale.body, /AV_PH_STALE/)
    assert.equal((await native(d, s, newest)).status, 200)
  } finally { await d.stop() }
})

test('an explicit placeholder ttl cannot outlast the grant\'s', async () => {
  const d = await startDaemon()
  try {
    const s = await sessionFor(d)
    d.vault.db.grants[s.grantId].policy.placeholder_policy = { ttl: 1 }
    const before = Date.now()
    const { row } = d.vault.issuePlaceholder({ grantId: s.grantId, ttlMs: 3_600_000 })
    const lasts = Date.parse(row.expires_at) - before
    assert.ok(lasts <= 2000, `the row lives ${lasts} ms on a grant whose placeholders live one second`)
  } finally { await d.stop() }
})

test('an explicit placeholder ttl shorter than the grant\'s is kept', async () => {
  const d = await startDaemon()
  try {
    const s = await sessionFor(d)
    d.vault.db.grants[s.grantId].policy.placeholder_policy = { ttl: 3600 }
    const before = Date.now()
    const { row } = d.vault.issuePlaceholder({ grantId: s.grantId, ttlMs: 5000 })
    const lasts = Date.parse(row.expires_at) - before
    assert.ok(lasts >= 4000 && lasts <= 6000, `the row lives ${lasts} ms`)
    // And with no explicit ttl, the grant's applies.
    const plain = d.vault.issuePlaceholder({ grantId: s.grantId }).row
    const span = Date.parse(plain.expires_at) - before
    assert.ok(span > 3_500_000 && span <= 3_601_000, `the row lives ${span} ms`)
  } finally { await d.stop() }
})
