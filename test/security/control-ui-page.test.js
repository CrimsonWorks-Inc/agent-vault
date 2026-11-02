// The page's wave-3 views, run from the modules the page is built from.
//
// - A desktop notification carries the daemon's headline, never the agent's
//   reason, and has no actions: it is a signal, not an approval channel.
// - A template's fields are a ceiling: the form refuses to send a value that
//   would widen it.
// - The advanced limits are parsed before anything is signed.
// - Credential badges, pins and a probe line say what is wrong as text.
//
// The rendered views (an approval preview, the session detail card, the
// access review, panic's dialog) are React components; their escaping and
// labelling are held by the vitest files named beside each test below.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { notificationText, showNotice, batchText } from '../../web/src/lib/notify.js'
import { tripwireRuleText } from '../../web/src/lib/format.js'
import {
  templateLimits, templateOverrides, advancedFields, buildSessionBody, detailMarkdown, narrowSummary, MODEL_KINDS,
} from '../../web/src/components/sessions/sessionLogic.js'
import { credentialBadges, pinsText, testParts } from '../../web/src/components/credentials/credentialText.js'
import { copyable, copyText } from '../../web/src/lib/clipboard.js'

const read = (rel) => readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8')
const HOSTILE = '<img src=x onerror=alert(1)>'

test('a notification says what the daemon saw, never what the agent claimed', () => {
  const item = { kind: 'request', headline: 'POST api.example.com/issues\u0007\n', claim: '<script>approve me</script>' }
  const text = notificationText(item)
  assert.equal(text, 'Held request: POST api.example.com/issues  ')
  assert.ok(!text.includes('approve me'))
  assert.match(notificationText({ kind: 'session', headline: 'session for demo' }), /^Session requested: /)
  assert.equal(notificationText({ kind: 'request', headline: 'x'.repeat(300) }).length, 120)
})

test('a notification has no actions; clicking it only opens the approvals view', () => {
  const made = []
  class FakeNotification {
    static permission = 'granted'
    constructor(title, opts) { made.push({ title, opts }); this.title = title }
  }
  const location = { hash: '' }
  let focused = 0
  const fresh = [{ id: 'sr_1', kind: 'session', headline: 'session for demo', claim: 'approve me please' }, { id: 'ap_2', kind: 'request', headline: 'x' }]
  const n = showNotice(fresh, { Notification: FakeNotification, location, focus: () => { focused++ } })
  assert.deepEqual(made, [{ title: 'agent-vault', opts: { body: batchText(fresh), tag: 'agent-vault-pending' } }])
  assert.ok(!('actions' in made[0].opts), 'a notification with actions is an approval channel')
  assert.doesNotMatch(made[0].opts.body, /approve me/)
  n.onclick()
  assert.equal(location.hash, '#approvals/sr_1')
  assert.equal(focused, 1)
  // Not granted: nothing is shown.
  FakeNotification.permission = 'default'
  assert.equal(showNotice(fresh, { Notification: FakeNotification, location }), null)
  assert.equal(made.length, 1)
  // The shell raises it through this one function.
  assert.match(read('web/src/App.jsx'), /showNotice\(fresh\)/)
})

test('panic is confirmed in a dialog the page draws, never window.confirm, and is not gated', () => {
  // Rendered and driven in web/src/pages/Containment.test.jsx and Overview.test.jsx.
  const card = read('web/src/components/overview/ContainmentCard.jsx')
  const panic = card.slice(card.indexOf('function PanicButton('))
  assert.doesNotMatch(panic, /\bconfirm\(/)
  assert.doesNotMatch(panic, /GatedButton|gated\(|operationFor/)
  assert.match(panic, /<ConfirmDialog/)
  assert.match(panic, /Lock the vault too/)
  assert.match(panic, /api\.post\('panic', \{ lock,/)
})

test('a credential’s badges and pins say what is wrong without echoing anything', () => {
  const soon = new Date(Date.now() + 3 * 86_400_000).toISOString()
  const badges = credentialBadges({ expiry_warning: 'soon', expires_at: soon, health: { status: HOSTILE }, quarantine: { since: soon } })
  assert.deepEqual(badges.map((b) => b.text), ['quarantined', 'expires in 3d', HOSTILE])
  // Text, rendered by React as text: web/src/pages/Credentials.test.jsx.
  assert.ok(badges.every((b) => typeof b.text === 'string' && typeof b.tone === 'string'))
  assert.equal(pinsText({ 'api.github.com': 2, 'x.example': 0 }), 'pinned: api.github.com (2)')
  assert.equal(pinsText(null), '')
  assert.deepEqual(credentialBadges({ health: { status: 'ok' } }), [{ tone: 'ok', text: 'healthy' }])
})

test('the session Markdown says when it never expires and when history is incomplete', () => {
  // The rendered card (labels and paths from the log as text): web/src/pages/Sessions.test.jsx.
  const detail = {
    session: { id: 's_1', label: HOSTILE, state: 'active', infinite: true, elevated: ['infinite'] },
    grants: [{ cred: 'demo', state: 'active', effective: { methods: ['GET'], payload: [{ json: { [HOSTILE]: { absent: true } } }] },
      placeholders: [{ id: 'ph_1', field: 'token', uses: 1, state: 'active' }] }],
    activity: { complete: false, note: 'log started later', requests: { allowed: 1 }, paths: [{ method: 'GET', path: `/a/${HOSTILE}`, count: 1 }] },
  }
  const md = detailMarkdown(detail)
  assert.match(md, /history incomplete/)
  assert.match(md, /- expires: never/)
})

test('Copy as Markdown carries no terminal controls from what the agent sent', async () => {
  // Grok's final security review, finding 1: a path with SOH, ESC and an
  // RTL override, pasted into a terminal, must not carry the ESC with it.
  const path = '/a\u0001b\u001b[31mc\u202ed'
  const detail = {
    session: { id: 's_1', label: 'lab\u001b]0;x\u0007el\u202e', state: 'active' },
    grants: [],
    activity: { complete: true, requests: { allowed: 1 }, paths: [{ method: 'G\u001bET', path, count: 2 }] },
  }
  const CONTROLS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u2028\u2029]/
  const md = detailMarkdown(detail)
  assert.doesNotMatch(md, CONTROLS, 'the Markdown itself is clean')
  assert.match(md, /- 2 × `G ET \/a b \[31mcd`/)
  assert.match(md, /^## Session `s_1` \(lab \]0;x el\)$/m)
  // What a copy writes: the same cleaning for any text, newlines and tabs kept.
  const raw = `line one\tA\nline\u0001 two\u001b[0m\r\n\u0085\u2028end & < > " '`
  const copied = copyable(raw)
  assert.doesNotMatch(copied, CONTROLS)
  assert.equal(copied, `line one\tA\nline two[0m\nend & < > " '`)
  const written = []
  await copyText(`x\u001by${path}`, { writeText: async (t) => { written.push(t) } })
  assert.deepEqual(written, ['xy/ab[31mcd'])
})

test('a narrow result lists only what changed', () => {
  const r = narrowSummary({
    session_id: 's_1', expires_at: '2026-10-27T12:00:00.000Z', infinite: false,
    grants: [{ cred: 'demo', before: { methods: ['GET', 'POST'], approval: 'on-write' }, after: { methods: ['GET'], approval: 'on-write' } }],
  })
  assert.deepEqual(r.grants[0].changes, [{ key: 'methods', before: 'GET, POST', after: 'GET' }])
  assert.equal(r.ends, 'expires 2026-10-27T12:00:00.000Z')
})

test('a tripwire rule reads the way the CLI prints it', () => {
  assert.equal(tripwireRuleText({ id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' }),
    'replay  AV_PH_REPLAY  1 in 10m  → revoke_session')
  assert.equal(tripwireRuleText({ id: 'd', rule_prefix: 'deny_paths:', threshold: 5, window_s: 3600, action: 'panic' }),
    'd  deny_paths:*  5 in 1h  → panic')
})

const TEMPLATE = { grants: [
  { cred: 'gh', methods: ['GET', 'HEAD', 'POST'], budget: 200, approval: 'on-write' },
  { cred: 'oai', methods: ['POST'], budget: 50, approval: 'each', grant_ttl_minutes: 30 },
], ttl_hours: 8 }

test('a template’s limits are read across every grant', () => {
  const L = templateLimits(TEMPLATE)
  assert.deepEqual(L.creds, ['gh', 'oai'])
  assert.deepEqual(L.methods, ['GET', 'HEAD', 'POST'])
  assert.equal(L.budget, 200)
  assert.equal(L.grantTtl, null, 'one grant has no lifetime of its own, so none is a ceiling')
  assert.equal(L.approvalFloor, 2)
  assert.equal(L.ttlHours, 8)
  assert.equal(templateLimits({ cred: 'gh', infinite: true }).infinite, true)
})

test('overrides on a template only ever narrow it', () => {
  const L = templateLimits(TEMPLATE)
  const base = { methods: ['GET', 'HEAD', 'POST'] }
  // Each of these would widen something, and is refused before signing.
  for (const chosen of [
    { ...base, approval: 'auto' }, { ...base, approval: 'first-use' }, { ...base, approval: 'sometimes' },
    { ...base, budget: '201' }, { ...base, budget: 'lots' }, { ...base, lifetime: '24' }, { ...base, lifetime: 'never' },
    { methods: ['DELETE'] }, { methods: [] },
  ]) {
    const r = templateOverrides(L, chosen)
    assert.ok(r.error, `${JSON.stringify(chosen)} was let through`)
    assert.equal(r.overrides, undefined)
  }
})

test('an untouched template form sends nothing, and a narrowing sends just that', () => {
  const L = templateLimits(TEMPLATE)
  assert.deepEqual(templateOverrides(L, { methods: ['GET', 'HEAD', 'POST'], approval: '', budget: '', lifetime: 'template', grantTtl: '' }),
    { overrides: {} })
  assert.deepEqual(templateOverrides(L, {
    label: 'triage', methods: ['GET', 'HEAD'], approval: 'each', budget: '20', lifetime: '1', grantTtl: '15',
  }), { overrides: { label: 'triage', methods: ['GET', 'HEAD'], approval: 'each', budget: 20, ttl_hours: 1, grant_ttl_minutes: 15 } })
  // An endless template can be given a lifetime: that only shortens it.
  const endless = templateLimits({ cred: 'gh', infinite: true })
  assert.deepEqual(templateOverrides(endless, { methods: ['GET', 'HEAD'], lifetime: '24' }).overrides, { ttl_hours: 24 })
})

test('advanced limits become GrantSpec fields, and a bad payload is said before signing', () => {
  assert.deepEqual(advancedFields({}), { fields: {} })
  assert.deepEqual(advancedFields({
    rate: ' 60/min ', quota: '1000/day', concurrency: '4', redirects: '2', grantTtl: '30', spendTokens: '5000', spendUsd: '1.25',
    payload: '{"json":{"/channel":{"one_of":["#bots"]}}}', graphqlQueriesOnly: true,
    routes: [{ methods: ['GET'], paths: '/repos/**, /user' }, { methods: [], paths: '' }],
  }).fields, {
    rate: '60/min', quota: '1000/day', max_concurrent: 4, redirects: 2, grant_ttl_minutes: 30, spend_tokens: 5000, spend_usd: 1.25,
    payload: { json: { '/channel': { one_of: ['#bots'] } }, graphql: { operations: ['query'] } },
    routes: [{ methods: ['GET'], paths: ['/repos/**', '/user'] }],
  })
  assert.match(advancedFields({ payload: '{not json' }).error, /not JSON/)
  assert.match(advancedFields({ payload: '[1]' }).error, /JSON object/)
  assert.match(advancedFields({ concurrency: 'four' }).error, /max_concurrent must be a number/)
  assert.match(advancedFields({ routes: [{ methods: ['GET'], paths: ' ' }] }).error, /at least one method and one path/)
  assert.match(advancedFields({ routes: Array.from({ length: 17 }, () => ({ methods: ['GET'], paths: '/a' })) }).error, /At most 16/)
})

test('the session form sends spend limits only for a model provider’s credential', () => {
  assert.deepEqual(MODEL_KINDS, ['anthropic', 'openai', 'google-genai'])
  const form = { picked: ['gh'], methods: 'GET', paths: '/**', budget: '5', approval: 'on-write', lifetime: '8', spendTokens: '100', spendUsd: '1' }
  const plain = buildSessionBody(form, new Map([['gh', 'github']]))
  assert.equal(plain.body.grants[0].spend_tokens, undefined)
  assert.equal(plain.body.grants[0].spend_usd, undefined)
  const model = buildSessionBody({ ...form, picked: ['oai'] }, new Map([['oai', 'openai']]))
  assert.equal(model.body.grants[0].spend_tokens, 100)
  assert.equal(model.body.grants[0].spend_usd, 1)
})

test('a probe result is text, never markup', () => {
  // Rendered as text in web/src/pages/Credentials.test.jsx.
  const parts = testParts({ status: 'ok', http_status: 200, latency_ms: 12, scopes: [HOSTILE] })
  assert.equal(parts.ok, true)
  assert.match(parts.rest, /scopes: <img/)
  assert.deepEqual(testParts({ error: 'probed in the last minute' }), { error: 'probed in the last minute' })
})
