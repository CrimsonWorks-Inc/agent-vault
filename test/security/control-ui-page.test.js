// The page's wave-3 views, run as the page defines them.
//
// - Agent-written text (an approval preview, a quarantine reason, a path in
//   the activity log) is escaped, set in monospace and labelled as unverified.
// - A desktop notification carries the daemon's headline, never the agent's
//   reason, and has no actions: it is a signal, not an approval channel.
// - A template's fields are a ceiling: the form refuses to send a value that
//   would widen it.
// - The advanced limits are parsed before anything is signed.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PAGE, pageFunctions, pageConst, pageSource } from './control-ui-helpers.js'

const PRELUDE = [
  pageConst('UNTRUSTED'), pageConst('APPROVAL_ORDER'), pageConst('MODEL_KINDS'),
  pageConst('ROUTE_METHODS'), pageConst('MAX_ROUTE_ROWS'),
  'const until = (iso) => (iso === null ? "never" : `until ${iso}`)',
  'const ago = (iso) => `since ${iso}`',
].join('\n')

const page = pageFunctions([
  'previewBlock', 'notificationText', 'credentialBadges', 'soonestExpiry', 'expiresIn', 'pinsText',
  'policyValue', 'describedTable', 'spendBar', 'narrowSummary', 'detailCard', 'detailMarkdown',
  'accessReview', 'tripwireRuleText', 'templateLimits', 'templateOverrides', 'advancedFields',
  'canonicalJson', 'testLine',
], PRELUDE)

const HOSTILE = '<img src=x onerror=alert(1)>'

test('a held request preview is escaped, monospace and labelled as the agent’s', () => {
  const html = page.previewBlock({
    method: 'POST', host: 'api.example.com', path: `/x/${HOSTILE}`,
    query: [['q', HOSTILE]], headers: [[HOSTILE, 'v']], content_type: 'application/json',
    body: { text: `{"title": "${HOSTILE}"}`, bytes: 40, shown_bytes: 40, truncated: false, kind: 'json' },
    placeholders: [{ label: 'demo.token', location: HOSTILE }], untrusted: true,
  }, 'ap_1')
  assert.ok(!html.includes('<img'), 'agent text reached the page as markup')
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/)
  assert.match(html, /What it sends \(written by the agent, not verified\)/)
  assert.match(html, /<pre class="untrusted">/)
  assert.match(html, /<span class="chip">demo\.token @ /)
})

test('an ordinary preview shows the body, and a binary one shows none', () => {
  const html = page.previewBlock({ method: 'POST', host: 'h', path: '/c', body: { text: '{"comment": "looks good"}', bytes: 25, kind: 'json' } })
  assert.match(html, /looks good/)
  assert.match(page.previewBlock({ body: { text: null, kind: 'binary', bytes: 9 } }), /binary body, not shown/)
  assert.equal(page.previewBlock(null), '')
})

test('a notification says what the daemon saw, never what the agent claimed', () => {
  const item = { kind: 'request', headline: 'POST api.example.com/issues\u0007\n', claim: '<script>approve me</script>' }
  const text = page.notificationText(item)
  assert.equal(text, 'Held request: POST api.example.com/issues  ')
  assert.ok(!text.includes('approve me'))
  assert.match(page.notificationText({ kind: 'session', headline: 'session for demo' }), /^Session requested: /)
  assert.equal(page.notificationText({ kind: 'request', headline: 'x'.repeat(300) }).length, 120)
})

test('a notification has no actions; clicking it only opens the approvals view', () => {
  const notify = pageSource('notifyNew')
  assert.match(notify, /new Notification\('agent-vault', \{ body, tag: 'agent-vault-pending' \}\)/)
  assert.doesNotMatch(notify, /actions\s*:/)
  assert.match(notify, /openApproval\(fresh\[0\]\.id\)/)
  assert.doesNotMatch(notify, /claim|reason/)
})

test('panic is confirmed in a dialog the page draws, never window.confirm, and is not gated', () => {
  const panic = PAGE.slice(PAGE.indexOf('async panic() {'), PAGE.indexOf("async 'tripwires-on'()"))
  assert.doesNotMatch(panic, /confirm\(/)
  assert.doesNotMatch(panic, /gated\(/)
  assert.match(panic, /await dialog\(/)
  assert.match(panic, /Lock the vault too/)
})

test('a credential’s badges and pins say what is wrong without echoing anything', () => {
  const soon = new Date(Date.now() + 3 * 86_400_000).toISOString()
  const html = page.credentialBadges({
    expiry_warning: 'soon', expires_at: soon, health: { status: HOSTILE }, quarantine: { since: soon },
  })
  assert.match(html, /quarantined/)
  assert.match(html, /expires in 3d/)
  assert.ok(!html.includes('<img'))
  assert.equal(page.pinsText({ 'api.github.com': 2, 'x.example': 0 }), 'pinned: api.github.com (2)')
  assert.equal(page.pinsText(null), '')
  assert.equal(page.credentialBadges({ health: { status: 'ok' } }), '<span class="pill ok">healthy</span>')
})

test('the session detail and its Markdown escape what the agent chose', () => {
  const detail = {
    session: { id: 's_1', label: HOSTILE, state: 'active', infinite: true, elevated: ['infinite'] },
    grants: [{ cred: 'demo', state: 'active', effective: { methods: ['GET'], payload: [{ json: { [HOSTILE]: { absent: true } } }] },
      placeholders: [{ id: 'ph_1', field: 'token', uses: 1, state: 'active' }] }],
    activity: { complete: false, note: 'log started later', requests: { allowed: 1 }, paths: [{ method: 'GET', path: `/a/${HOSTILE}`, count: 1 }] },
  }
  const html = page.detailCard(detail)
  assert.ok(!html.includes('<img'), 'a path or label from the log became markup')
  assert.match(html, /History is incomplete: log started later/)
  assert.match(html, /never/)
  const md = page.detailMarkdown(detail)
  assert.match(md, /history incomplete/)
  assert.match(md, /- expires: never/)
})

test('a narrow result lists only what changed', () => {
  const html = page.narrowSummary({
    session_id: 's_1', expires_at: '2026-10-27T12:00:00.000Z', infinite: false,
    grants: [{ cred: 'demo', before: { methods: ['GET', 'POST'], approval: 'on-write' }, after: { methods: ['GET'], approval: 'on-write' } }],
  })
  assert.match(html, /methods: GET, POST &rarr; GET/)
  assert.doesNotMatch(html, /approval:/)
})

test('the access review flags unused methods and expiring or quarantined credentials', () => {
  const html = page.accessReview({
    complete: true,
    sessions: [{ id: 's_1', label: 'triage', unused_methods: ['POST'] }, { id: 's_2', unused_methods: [] }],
    credentials: [{ slug: 'a', quarantined: true }, { slug: 'b', expiry_warning: 'expired' }, { slug: 'c' }],
  })
  assert.match(html, /never used: <span class="mono">POST/)
  assert.match(html, /quarantined/)
  assert.match(html, /expired/)
  assert.doesNotMatch(html, />c</)
  assert.match(page.accessReview({ complete: false, sessions: [], credentials: [] }), /incomplete/)
})

test('a tripwire rule reads the way the CLI prints it', () => {
  assert.equal(page.tripwireRuleText({ id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' }),
    'replay  AV_PH_REPLAY  1 in 10m  → revoke_session')
  assert.equal(page.tripwireRuleText({ id: 'd', rule_prefix: 'deny_paths:', threshold: 5, window_s: 3600, action: 'panic' }),
    'd  deny_paths:*  5 in 1h  → panic')
})

const TEMPLATE = { grants: [
  { cred: 'gh', methods: ['GET', 'HEAD', 'POST'], budget: 200, approval: 'on-write' },
  { cred: 'oai', methods: ['POST'], budget: 50, approval: 'each', grant_ttl_minutes: 30 },
], ttl_hours: 8 }

test('a template’s limits are read across every grant', () => {
  const L = page.templateLimits(TEMPLATE)
  assert.deepEqual(L.creds, ['gh', 'oai'])
  assert.deepEqual(L.methods, ['GET', 'HEAD', 'POST'])
  assert.equal(L.budget, 200)
  assert.equal(L.grantTtl, null, 'one grant has no lifetime of its own, so none is a ceiling')
  assert.equal(L.approvalFloor, 2)
  assert.equal(L.ttlHours, 8)
  assert.equal(page.templateLimits({ cred: 'gh', infinite: true }).infinite, true)
})

test('overrides on a template only ever narrow it', () => {
  const L = page.templateLimits(TEMPLATE)
  const base = { methods: ['GET', 'HEAD', 'POST'] }
  // Each of these would widen something, and is refused before signing.
  for (const chosen of [
    { ...base, approval: 'auto' }, { ...base, approval: 'first-use' }, { ...base, approval: 'sometimes' },
    { ...base, budget: '201' }, { ...base, budget: 'lots' }, { ...base, lifetime: '24' }, { ...base, lifetime: 'never' },
    { methods: ['DELETE'] }, { methods: [] },
  ]) {
    const r = page.templateOverrides(L, chosen)
    assert.ok(r.error, `${JSON.stringify(chosen)} was let through`)
    assert.equal(r.overrides, undefined)
  }
})

test('an untouched template form sends nothing, and a narrowing sends just that', () => {
  const L = page.templateLimits(TEMPLATE)
  assert.deepEqual(page.templateOverrides(L, { methods: ['GET', 'HEAD', 'POST'], approval: '', budget: '', lifetime: 'template', grantTtl: '' }),
    { overrides: {} })
  assert.deepEqual(page.templateOverrides(L, {
    label: 'triage', methods: ['GET', 'HEAD'], approval: 'each', budget: '20', lifetime: '1', grantTtl: '15',
  }), { overrides: { label: 'triage', methods: ['GET', 'HEAD'], approval: 'each', budget: 20, ttl_hours: 1, grant_ttl_minutes: 15 } })
  // An endless template can be given a lifetime: that only shortens it.
  const endless = page.templateLimits({ cred: 'gh', infinite: true })
  assert.deepEqual(page.templateOverrides(endless, { methods: ['GET', 'HEAD'], lifetime: '24' }).overrides, { ttl_hours: 24 })
})

test('advanced limits become GrantSpec fields, and a bad payload is said before signing', () => {
  assert.deepEqual(page.advancedFields({}), { fields: {} })
  assert.deepEqual(page.advancedFields({
    rate: ' 60/min ', quota: '1000/day', concurrency: '4', redirects: '2', grantTtl: '30', spendTokens: '5000', spendUsd: '1.25',
    payload: '{"json":{"/channel":{"one_of":["#bots"]}}}', graphqlQueriesOnly: true,
    routes: [{ methods: ['GET'], paths: '/repos/**, /user' }, { methods: [], paths: '' }],
  }).fields, {
    rate: '60/min', quota: '1000/day', max_concurrent: 4, redirects: 2, grant_ttl_minutes: 30, spend_tokens: 5000, spend_usd: 1.25,
    payload: { json: { '/channel': { one_of: ['#bots'] } }, graphql: { operations: ['query'] } },
    routes: [{ methods: ['GET'], paths: ['/repos/**', '/user'] }],
  })
  assert.match(page.advancedFields({ payload: '{not json' }).error, /not JSON/)
  assert.match(page.advancedFields({ payload: '[1]' }).error, /JSON object/)
  assert.match(page.advancedFields({ concurrency: 'four' }).error, /max_concurrent must be a number/)
  assert.match(page.advancedFields({ routes: [{ methods: ['GET'], paths: ' ' }] }).error, /at least one method and one path/)
  assert.match(page.advancedFields({ routes: Array.from({ length: 17 }, () => ({ methods: ['GET'], paths: '/a' })) }).error, /At most 16/)
})

test('the session form sends spend limits only for a model provider’s credential', () => {
  const read = pageSource('readSessionForm')
  assert.match(read, /const models = picked\.some\(\(slug\) => MODEL_KINDS\.includes\(credKinds\.get\(slug\)\)\)/)
  assert.match(read, /spendTokens: models \? value\('sSpendTokens'\) : ''/)
  assert.deepEqual(JSON.parse(pageConst('MODEL_KINDS').replace(/^const MODEL_KINDS = /, '').replace(/'/g, '"')),
    ['anthropic', 'openai', 'google-genai'])
})

test('a probe result is painted, never trusted as markup', () => {
  assert.ok(!page.testLine({ status: 'ok', http_status: 200, latency_ms: 12, scopes: [HOSTILE] }).includes('<img'))
  assert.match(page.testLine({ error: 'probed in the last minute' }), /probed in the last minute/)
})
