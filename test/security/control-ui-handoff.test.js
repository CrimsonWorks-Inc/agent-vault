// The hand-off is the one answer that may carry a capability to the page, and
// only the capability the card shows (0.10). Review of wave 3 found the whole
// POST sessions answer exempt from the guard, error bodies included, and the
// guard itself matching withheld keys in exact case only.
//
// Fix round 1: towardPage runs on every answer, the card's fields are copied
// back on a successful create only, and a key is withheld whatever its case
// or its '-'/'_' spelling, at any depth. Also: the parser the page is served
// with cannot end its own <script>, and a VaultError refusal keeps its status.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import * as ph from '../../src/core/placeholder.js'
import { operationFor } from '../../src/ui/webauthn.js'
import { servedPage, towardPage, handoffTowardPage, PARSER_MARKER } from '../../src/ui/server.js'
import { startStub, startUi } from './control-ui-helpers.js'

const PLACEHOLDER = ph.mint({ kPh: randomBytes(32), sid: ph.newSid(), slug: 'demo', field: 'token' }).text
const TOKEN = `avs1.${ph.newSid()}.${randomBytes(24).toString('base64url')}`
const HOOK = 'https://hooks.example/secret-path-XYZ'
const VALUE = 'super-secret-value-XYZ'
const PASSPHRASE = 'recovery-passphrase-XYZ'
const BUNDLE = 'bundle-secret-XYZ'
const SECRETS = [TOKEN, PLACEHOLDER, HOOK, VALUE, PASSPHRASE, BUNDLE]

const leaked = (text, allowed = []) => SECRETS.filter((s) => !allowed.includes(s) && text.includes(s))

// What the stand-in daemon answers POST /v1/sessions with, per test.
let sessionsAnswer = null

let d
let u

before(async () => {
  d = await startStub((key) => {
    switch (key) {
      case 'POST /v1/sessions': return sessionsAnswer
      case 'POST /v1/credentials': return { ok: true }
      case 'GET /v1/sessions/detail':
        return {
          session: { id: 's_1', state: 'active', Webhook_URL: HOOK, 'webhook-url': HOOK },
          VALUE,
          'Recovery-Passphrase': PASSPHRASE,
          Bundle: { sealed: BUNDLE },
          nested: { deeper: { Token: TOKEN, 'PLACE-HOLDER': 'not withheld', Placeholder: PLACEHOLDER } },
          items: [{ Value: VALUE, label: 'kept' }, [{ 'WEBHOOK-URL': HOOK, 'recovery_PASSPHRASE': PASSPHRASE }]],
          token_hash: 'kept, not a withheld name',
        }
      default: return { ok: true }
    }
  })
  u = await startUi(d)
})
after(async () => { await u.stop(); await d.stop() })

async function createSession() {
  const body = { cred: 'demo', methods: ['GET'] }
  const presence = await u.presence(d.auth, operationFor('session.create', body))
  return u.api('POST', 'sessions', { ...body, presence })
}

test('an error from POST sessions reaches the page with none of the withheld fields (F1)', async () => {
  sessionsAnswer = {
    status: 400,
    body: {
      code: 'AV_POLICY_DENIED', detail: 'no',
      token: TOKEN, placeholder: PLACEHOLDER, value: VALUE, webhook_url: HOOK,
      bundle: { sealed: BUNDLE }, recovery_passphrase: PASSPHRASE,
      grants: [{ cred: 'demo', placeholder: PLACEHOLDER, value: VALUE }],
    },
  }
  const res = await createSession()
  const text = await res.text()
  assert.equal(res.status, 400, 'the daemon status is what the page gets')
  assert.deepEqual(leaked(text), [], 'an error body is not a hand-off')
  const body = JSON.parse(text)
  assert.equal(body.detail.code, 'AV_POLICY_DENIED', 'the refusal itself still reaches the page')
  assert.equal(body.detail.grants[0].cred, 'demo')
})

test('a successful hand-off carries the token and placeholders, and nothing else withheld (F1)', async () => {
  sessionsAnswer = {
    session_id: 's_2', token: TOKEN, label: 'ci', expires_at: '2026-10-28T00:00:00Z', infinite: false,
    webhook_url: HOOK, value: VALUE, bundle: { sealed: BUNDLE }, recovery_passphrase: PASSPHRASE,
    grants: [{
      cred: 'demo', grant_id: 'g_1', placeholder: PLACEHOLDER,
      usage: [`header Authorization: Bearer ${PLACEHOLDER}`], base_url: 'http://127.0.0.1:7777/p/demo',
      probe_path: '/user', env: { key: 'DEMO_TOKEN' }, lint: [],
      value: VALUE, webhook_url: HOOK, Bundle: BUNDLE,
    }],
    placeholder: PLACEHOLDER, usage: [`header Authorization: Bearer ${PLACEHOLDER}`],
  }
  const res = await createSession()
  const text = await res.text()
  assert.equal(res.status, 200)
  assert.deepEqual(leaked(text, [TOKEN, PLACEHOLDER]), [], 'a secret rode along with the hand-off')
  const body = JSON.parse(text)
  assert.equal(body.token, TOKEN)
  assert.equal(body.session_id, 's_2')
  assert.equal(body.label, 'ci')
  assert.equal(body.expires_at, '2026-10-28T00:00:00Z')
  assert.equal(body.infinite, false)
  const [g] = body.grants
  assert.equal(g.placeholder, PLACEHOLDER)
  assert.deepEqual(g.usage, [`header Authorization: Bearer ${PLACEHOLDER}`])
  assert.equal(g.base_url, 'http://127.0.0.1:7777/p/demo')
  assert.equal(g.cred, 'demo')
  // The rest of the card's inputs pass through the guard as any answer does.
  assert.equal(g.env.key, 'DEMO_TOKEN')
  assert.equal(g.probe_path, '/user')
  // The daemon's copy of grants[0] at the top, for a one-grant client.
  assert.equal(body.placeholder, PLACEHOLDER)
  assert.deepEqual(body.usage, [`header Authorization: Bearer ${PLACEHOLDER}`])
  assert.ok(!('value' in g) && !('webhook_url' in g) && !('Bundle' in g))
})

test('a card field is copied back only as a scalar or a list of scalars (F1)', () => {
  const out = handoffTowardPage({
    token: { value: VALUE }, label: [HOOK, { webhook_url: HOOK }],
    grants: [{ cred: 'demo', placeholder: PLACEHOLDER, usage: [{ value: VALUE }], sites: ['header:Authorization:Bearer'] }],
  })
  assert.equal(out.token, undefined, 'a nested object under a card field is not copied back')
  assert.equal(out.grants[0].placeholder, PLACEHOLDER)
  assert.deepEqual(out.grants[0].usage, [{}])
  assert.deepEqual(out.grants[0].sites, ['header:Authorization:Bearer'])
  assert.deepEqual(out.label, [HOOK, {}], 'a list holding an object is filtered, not copied')
  // One grant, no list: the card reads `s.grants || [s]`, and so does this.
  const single = handoffTowardPage({ token: TOKEN, placeholder: PLACEHOLDER, value: VALUE })
  assert.deepEqual(single, { token: TOKEN, placeholder: PLACEHOLDER })
  // Not a record: no card, just the guard.
  assert.deepEqual(handoffTowardPage([TOKEN]), ['«token»'])
})

test('a withheld key is withheld in any case, hyphenated, nested, and inside arrays (F2)', async () => {
  const res = await u.api('GET', 'sessions/detail?sid=s_1')
  const text = await res.text()
  assert.equal(res.status, 200)
  assert.deepEqual(leaked(text), [])
  const body = JSON.parse(text)
  assert.deepEqual(body.session, { id: 's_1', state: 'active' })
  assert.equal(body.VALUE, undefined)
  assert.equal(body['Recovery-Passphrase'], undefined)
  assert.equal(body.Bundle, undefined)
  assert.deepEqual(body.nested, { deeper: { 'PLACE-HOLDER': 'not withheld' } }, 'only names that fold to a withheld one go')
  assert.deepEqual(body.items, [{ label: 'kept' }, [{}]])
  assert.equal(body.token_hash, 'kept, not a withheld name')
})

test('towardPage folds case and hyphens and leaves other keys alone (F2)', () => {
  assert.deepEqual(
    towardPage({ Webhook_URL: HOOK, 'webhook-url': HOOK, VALUE, 'Recovery-Passphrase': PASSPHRASE, 'PRF-Secret': 'x', keep: 1 }),
    { keep: 1 },
  )
  assert.deepEqual(towardPage([[{ a: { 'token-hash': 't', Tokens: 2, values: [1] } }]]), [[{ a: { 'token-hash': 't', Tokens: 2, values: [1] } }]])
})

test('the page will not be served with a parser that could end its own script', () => {
  assert.doesNotThrow(() => servedPage())
  for (const src of ["'</script>'", "'</SCRIPT '", "'<!--'", JSON.stringify(PARSER_MARKER)]) {
    // eslint-disable-next-line no-new-func
    const fn = new Function(`return ${src}`)
    assert.throws(() => servedPage(fn), /cannot be put in the page/, src)
  }
  // Ordinary source with a '<' in it is fine.
  assert.doesNotThrow(() => servedPage(function p(x) { return x < 2 && '<script' }))
})

test('a reserved operation field is a 403 refusal, not a 500, and is not forwarded', async () => {
  const body = { slug: 'demo', kind: 'github', value: VALUE }
  const presence = await u.presence(d.auth, operationFor('cred.add', body))
  const before = d.callsTo('POST', '/v1/credentials').length
  const res = await u.api('POST', 'credentials', { ...body, op: 'cred.remove', presence })
  const text = await res.text()
  assert.equal(res.status, 403)
  assert.equal(JSON.parse(text).detail.rule, 'reserved_operation_field')
  assert.ok(!text.includes(VALUE))
  assert.equal(d.callsTo('POST', '/v1/credentials').length, before, 'a refused request reached the daemon')
})
