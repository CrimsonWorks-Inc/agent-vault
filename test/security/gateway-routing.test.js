// How a request is routed and authenticated before any policy runs: which
// scheme it goes out on, and what a placeholder carrying the session may
// touch before it has been verified.

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { setup, cleanup } from './gateway-helpers.js'

afterEach(cleanup)

// ---------------------------------------------------------------- routing

test('/t/https/ to an http credential goes out over https, not in the clear', async () => {
  const s = setup({ connector: { host: 'up.test', scheme: 'http' } })
  await s.pipeline.handle(s.request({ path: '/t/https/up.test/x', headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.match(s.sent[0].url, /^https:\/\/up\.test\/x/)
  await s.pipeline.handle(s.request({ path: '/t/http/up.test/x', headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.match(s.sent[1].url, /^http:\/\/up\.test\/x/, 'an http credential asked for over http stays http')
})

// ------------------------------------------------------- the carrier path

test('a placeholder with a forged checksum does not keep its session alive', async () => {
  const s = setup()
  const real = s.ph()
  const last = real.slice(-6)
  const forged = real.slice(0, -6) + (last === 'aaaaaa' ? 'bbbbbb' : 'aaaaaa')
  const soon = new Date(Date.now() + 60_000).toISOString()
  s.vault.db.sessions[s.session.id].expires_at = soon
  const res = await s.pipeline.handle(s.request({ headers: [['host', '127.0.0.1'], ['x-key', forged]] }))
  assert.equal(res.status, 400)
  assert.equal(JSON.parse(res.body).code, 'AV_PH_MALFORMED')
  assert.equal(s.vault.db.sessions[s.session.id].expires_at, soon, 'a forged placeholder extended the session')
})

test('a real placeholder as the only carrier still authenticates and keeps the session alive', async () => {
  const s = setup({ sites: { key: ['header:x-key'] } })
  const soon = new Date(Date.now() + 60_000).toISOString()
  s.vault.db.sessions[s.session.id].expires_at = soon
  const res = await s.pipeline.handle(s.request({ headers: [['host', '127.0.0.1'], ['x-key', s.ph()]] }))
  assert.equal(res.status, 200)
  assert.ok(Date.parse(s.vault.db.sessions[s.session.id].expires_at) > Date.parse(soon))
})
