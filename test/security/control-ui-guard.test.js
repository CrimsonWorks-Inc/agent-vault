// What reaches the page (0.10): no secret, no session token, no full
// placeholder, except the hand-off card for a session the human just made.
//
// The daemon's routes are not supposed to return any of these. The UI server
// holds that line itself as well, on every answer, so a daemon route that
// slips — or agent-written text in an approval preview that a scrub missed —
// still does not put a capability in a browser.
//
// And one parser of typed narrowing (C21): the page runs the function the
// server rebinds with, injected when the page is served.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { Script } from 'node:vm'
import * as ph from '../../src/core/placeholder.js'
import { operationFor } from '../../src/ui/webauthn.js'
import { parseOverrides } from '../../src/pending.js'
import { servedPage, towardPage, PARSER_MARKER } from '../../src/ui/server.js'
import { startStub, startUi, PAGE } from './control-ui-helpers.js'

const PLACEHOLDER = ph.mint({ kPh: randomBytes(32), sid: ph.newSid(), slug: 'demo', field: 'token' }).text
const TOKEN = `avs1.${ph.newSid()}.${randomBytes(24).toString('base64url')}`

let d
let u

before(async () => {
  d = await startStub((key) => {
    switch (key) {
      case 'GET /v1/sessions/detail':
        return {
          session: { id: 's_1', label: `pasted ${TOKEN} by mistake`, state: 'active' },
          token: TOKEN,
          grants: [{
            cred: 'demo',
            placeholders: [{ id: 'ph_01', field: 'token', uses: 1, placeholder: PLACEHOLDER }],
            note: `the agent sent ${PLACEHOLDER} to /repos`,
          }],
          activity: { complete: true, paths: [{ method: 'GET', path: '/repos/av1.example/x', count: 2 }] },
        }
      case 'GET /v1/approvals':
        return [{ id: 'ap_1', summary: `POST api.example.com/x?ph=${PLACEHOLDER}`, created_at: '2026-10-27T00:00:00Z' }]
      case 'GET /v1/notify':
        return { webhook: { host: 'hooks.example', detail: 'minimal', configured_at: 'x' }, webhook_url: 'https://hooks.example/T0/B0/secret' }
      case 'GET /v1/templates':
        return { status: 404, body: { code: 'AV_NOT_FOUND', detail: `no template; you sent ${PLACEHOLDER}` } }
      case 'POST /v1/sessions':
        return { session_id: 's_2', token: TOKEN, placeholder: PLACEHOLDER, grants: [{ cred: 'demo', placeholder: PLACEHOLDER }] }
      default:
        return { ok: true }
    }
  })
  u = await startUi(d)
})
after(async () => { await u.stop(); await d.stop() })

test('a token or placeholder a daemon route returns never reaches the page', async () => {
  const res = await u.api('GET', 'sessions/detail?sid=s_1')
  const text = await res.text()
  assert.equal(res.status, 200)
  assert.ok(!text.includes(PLACEHOLDER), 'a placeholder reached the page')
  assert.ok(!text.includes(TOKEN), 'a session token reached the page')
  assert.ok(!text.includes('avs1.'), 'a token-shaped string reached the page')
  const body = JSON.parse(text)
  assert.equal(body.grants[0].placeholders[0].id, 'ph_01', 'the ledger row id is what the page shows instead')
  assert.equal(body.grants[0].note, 'the agent sent «placeholder» to /repos')
  assert.equal(body.session.label, 'pasted «token» by mistake')
})

test('ordinary text is untouched', async () => {
  const body = await (await u.api('GET', 'sessions/detail?sid=s_1')).json()
  // Looks a little like a placeholder, is not one.
  assert.equal(body.activity.paths[0].path, '/repos/av1.example/x')
  assert.equal(body.session.state, 'active')
  assert.deepEqual(towardPage({ a: [1, true, null, 'x'], b: { c: 'GET /user' } }), { a: [1, true, null, 'x'], b: { c: 'GET /user' } })
})

test('the approvals list, a webhook URL and an error message are held to the same line', async () => {
  const pending = await (await u.api('GET', 'pending')).text()
  assert.ok(!pending.includes(PLACEHOLDER))
  assert.match(pending, /«placeholder»/)
  const notify = await (await u.api('GET', 'notify')).json()
  assert.deepEqual(notify, { webhook: { host: 'hooks.example', detail: 'minimal', configured_at: 'x' } })
  const refused = await u.api('GET', 'templates?name=x')
  assert.equal(refused.status, 404)
  assert.ok(!(await refused.text()).includes(PLACEHOLDER))
})

test('the hand-off for a session made here still carries what the agent needs', async () => {
  const body = { cred: 'demo', methods: ['GET'] }
  const presence = await u.presence(d.auth, operationFor('session.create', body))
  const created = await (await u.api('POST', 'sessions', { ...body, presence })).json()
  assert.equal(created.token, TOKEN)
  assert.equal(created.grants[0].placeholder, PLACEHOLDER)
})

test('the page runs the very parser the server rebinds a narrowing with (C21)', () => {
  const served = servedPage()
  assert.ok(served.includes(parseOverrides.toString()), 'the served page does not carry parseOverrides byte for byte')
  assert.ok(!served.includes(PARSER_MARKER), 'the marker was left in place of the parser')
  assert.ok(PAGE.includes(PARSER_MARKER), 'app.html lost its marker')
  // No second reader left in the page.
  assert.ok(!/function parseNarrowing\(/.test(PAGE))
  const decide = PAGE.slice(PAGE.indexOf('async decide(btn) {'))
  assert.match(decide.slice(0, decide.indexOf('gated(')), /const overrides = parseOverrides\(typed\)/)
  // The injected function stands alone: evaluated with nothing around it, it
  // reads every field as the module's own copy does.
  const alone = new Script(`(${parseOverrides.toString()})`).runInNewContext({})
  for (const raw of [{ methods: 'get, post', paths: '/a/**,/b', budget: '7', uses: '2', ttl_minutes: '30' }, { approval: 'auto', infinite: 'true' }]) {
    assert.deepEqual(JSON.parse(JSON.stringify(alone(raw))), parseOverrides(raw))
  }
})

