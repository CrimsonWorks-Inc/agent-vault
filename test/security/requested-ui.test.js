// The web UI for R1–R3: what the page signs is what the daemon re-checks.
//
// An elevated session made from the page needs no new mechanism: the page
// already signs every gated operation with a fresh assertion, and the daemon
// verifies it again itself. These tests drive the UI server the way the page
// does, and check the page's own parsing against the shared parser, so a
// session request approved with owner options is not refused as a different
// operation, and cannot be replayed into a wider one.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { operationFor, canonicalOperation } from '../../src/ui/webauthn.js'
import { parseOverrides } from '../../src/pending.js'
import { overridesOf } from '../../src/daemon/session-requests.js'
import { UiServer, servedPage } from '../../src/ui/server.js'
import { startDaemon, startUi, makeAuthenticator, enrol, PASSPHRASE } from './fix-control-helpers.js'

const PAGE = readFileSync(new URL('../../src/ui/app.html', import.meta.url), 'utf8')

/** A named function from the page's script, as a callable. */
function pageFunction(name, prelude = '', page = PAGE) {
  const PAGE = page
  const start = PAGE.indexOf(`function ${name}(`)
  assert.ok(start >= 0, `the page has no ${name}()`)
  let depth = 0
  // The body, not a default parameter's braces: `(args = {}) {`.
  let i = PAGE.indexOf(') {', start) + 2
  for (; i < PAGE.length; i++) {
    if (PAGE[i] === '{') depth++
    else if (PAGE[i] === '}' && --depth === 0) break
  }
  return new Function(`${prelude}\n${PAGE.slice(start, i + 1)}; return ${name}`)()
}

/** A `const name = (…) => …` arrow from the page, as a callable: up to the next statement. */
function pageArrow(name) {
  const start = PAGE.indexOf(`const ${name} = (`)
  assert.ok(start >= 0, `the page has no ${name}`)
  const ends = ['\n\n', '\n  /**', '\n  const ', '\n  let ', '\n  function ']
    .map((e) => PAGE.indexOf(e, start + 1)).filter((i) => i > 0)
  return new Function(`${PAGE.slice(start, Math.min(...ends))}; return ${name}`)()
}

test('the page reads owner options exactly as the CLI and the daemon do', () => {
  // The parser the page runs is the one the server puts in it (C21).
  const narrowing = pageFunction('parseOverrides', '', servedPage())
  for (const raw of [
    { approval: 'auto' }, { infinite: true }, { approval: 'each', methods: 'get,post', infinite: true },
    { approval: '' }, { infinite: false },
  ]) {
    const page = narrowing(raw)
    assert.deepEqual(page, parseOverrides(raw), JSON.stringify(raw))
    const signed = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...page }))
    const server = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...overridesOf(parseOverrides(page)) }))
    assert.equal(signed, server, `${JSON.stringify(raw)} would be refused as a different operation`)
  }
})

test('a session with no expiry renders as never, and garbage as expired', () => {
  const until = pageArrow('until')
  assert.equal(until(null), 'never')
  assert.equal(until('garbage'), 'expired')
  assert.equal(until(new Date(Date.now() + 2 * 3600_000 + 60_000).toISOString()), '2h left')
})

test('the decisions that can be elevated are re-verified by the daemon', () => {
  for (const key of ['POST sessions', 'POST session-requests/decide', 'POST pending/decide-many']) {
    assert.ok(UiServer.GATED.has(key), `${key} is not gated`)
    assert.ok(UiServer.DAEMON_VERIFIED.has(key), `${key} is not in DAEMON_VERIFIED`)
  }
})

test('the page warns before it signs an elevated session', () => {
  assert.ok(PAGE.includes('No approval prompts for writes, or only for the first request. Your authenticator is asked every time you create one.'))
  assert.ok(PAGE.includes('This session never expires. It lasts until you revoke it, and your authenticator is asked every time you create one.'))
  const autoWrites = pageArrow('autoWrites')
  // The arrow reads SAFE_METHODS from the page; give it the same list.
  globalThis.SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS']
  try {
    assert.equal(autoWrites('auto', ['GET', 'POST']), true)
    assert.equal(autoWrites('auto', ['get', 'head']), false)
    assert.equal(autoWrites('auto', undefined), false)
    assert.equal(autoWrites('on-write', ['POST']), false)
    // C26: first-use asks once, then never again, so it warns like auto.
    assert.equal(autoWrites('first-use', ['GET', 'DELETE']), true)
    assert.equal(autoWrites('first-use', ['GET', 'HEAD']), false)
    assert.equal(autoWrites('each', ['POST']), false)
  } finally { delete globalThis.SAFE_METHODS }
})

test('the hand-off card offers an env command with no session token in it', () => {
  const start = PAGE.indexOf('const envCmd = ')
  assert.ok(start > 0)
  const line = PAGE.slice(start, PAGE.indexOf('\n', start))
  assert.match(line, /env --session \$\{s\.session_id\} --out \.env/)
  assert.doesNotMatch(line, /token/, 'the command must not carry the session token')
  const suggested = pageArrow('suggestedName')
  assert.equal(suggested({ cred: 'oai', env: { key: 'OPENAI_API_KEY' } }), 'OPENAI_API_KEY')
  assert.equal(suggested({ cred: 'gh-work', env: null }), 'GH_WORK_TOKEN')
})

test('approving a request with owner options from the page creates the session they chose', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const auth = makeAuthenticator()
  enrol(d.vault, auth)
  const u = await startUi(d)
  try {
    const asked = await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET', 'POST'], reason: 'job' })
    const id = asked.body.id
    // The window is open: it must not be what lets this through.
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const overrides = { approval: 'auto' }
    const presence = await u.presence(auth, operationFor('session_request.decide', { id, granted: true, ...overrides }))
    const r = await u.api('POST', 'session-requests/decide', { id, granted: true, overrides, presence })
    const body = await r.json()
    assert.equal(r.status, 200, JSON.stringify(body))
    assert.ok(!JSON.stringify(body).includes('avs1.'), 'the page never sees the token')
    const record = d.daemon.sessionRequests.get(id)
    assert.equal(record.granted_proposal.approval, 'auto')
    const grant = Object.values(d.vault.db.grants).at(-1)
    assert.equal(grant.policy.approval, 'auto')
    const proof = d.vault.audit.read({ limit: 50 }).find((x) => x.kind === 'presence.verified' && x.fresh === true)
    assert.equal(proof?.op, 'session request approval')
  } finally {
    d.daemon.presenceGraceUntil = 0
    await u.stop(); await d.stop()
  }
})

test('a signature for one owner option cannot be spent on another', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const auth = makeAuthenticator()
  enrol(d.vault, auth)
  const u = await startUi(d)
  try {
    const asked = await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET', 'POST'], reason: 'job' })
    const id = asked.body.id
    const presence = await u.presence(auth, operationFor('session_request.decide', { id, granted: true, approval: 'each' }))
    const r = await u.api('POST', 'session-requests/decide', { id, granted: true, overrides: { approval: 'auto' }, presence })
    assert.equal(r.status, 409)
    assert.equal(d.daemon.sessionRequests.get(id).state, 'pending')
  } finally { await u.stop(); await d.stop() }
})

test('an auto-approving multi-credential session made from the page needs only its own signature', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const auth = makeAuthenticator()
  enrol(d.vault, auth)
  const u = await startUi(d)
  try {
    const body = { label: 'ui', grants: [{ cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], budget: 5, approval: 'auto' }], ttl_hours: 8 }
    const presence = await u.presence(auth, operationFor('session.create', body))
    const r = await u.api('POST', 'sessions', { ...body, presence })
    const s = await r.json()
    assert.equal(r.status, 200, JSON.stringify(s))
    assert.equal(s.grants.length, 1)
    const listed = await (await u.api('GET', 'sessions')).json()
    assert.deepEqual(listed.find((x) => x.id === s.session_id).elevated, ['approval_auto_writes'])
  } finally { await u.stop(); await d.stop() }
})

test('the docs say how to start an auto-approving session, and that read-only needs nothing', () => {
  assert.ok(PAGE.includes('3b. Let it write without asking'))
  assert.ok(PAGE.includes('session create --cred ${c.cred} --methods GET,POST --approval auto'))
  assert.ok(PAGE.includes('auto means no approval prompts at all, including for writes. Because that takes you out of the loop for the life of the session, creating one asks for your passphrase or fingerprint every time, even inside the five-minute window, and is refused on a vault with no passphrase. Read-only sessions are unaffected: GET and HEAD never ask under on-write either.'))
  assert.ok(PAGE.includes('Give a tool an env file'))
  assert.ok(PAGE.includes('env --out .env --map GH_TOKEN=${c.cred} --profile-vars'))
  assert.ok(PAGE.includes('The file holds placeholders, which only work through this vault, and is written readable by you alone. It is never overwritten unless you say so.'))
  assert.ok(PAGE.includes('Revoking: agent-vault session revoke &lt;sid&gt;, or Panic, ends an infinite session like any other.'))
})

test('what the human typed on an approval survives the five-second re-render', () => {
  // The approvals view re-renders on a timer. Narrowings and owner options
  // were inputs it rebuilt from scratch, so they vanished mid-edit.
  const render = PAGE.slice(PAGE.indexOf('async function render() {'), PAGE.indexOf('async function refreshChrome()'))
  assert.match(render, /restoreDrafts\(\)/)
  assert.match(PAGE, /const DRAFTED = '\.narrow-input, \.owner-approval, \.owner-infinite'/)
  const decide = PAGE.slice(PAGE.indexOf('async decide(btn) {'))
  assert.match(decide.slice(0, decide.indexOf("toast(granted ? 'Approved' : 'Denied')")), /drafts\.delete\(key\)/,
    'a decided item’s drafts are forgotten, so they cannot reappear on another')
})
