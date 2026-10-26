// R3: sessions with no expiry, for the owner only.
//
// A session that never ends is the longest-lived capability the vault can
// hand out, so it is elevated: a fresh proof every time it is created, refused
// on a vault with no factor, never remote, and never something an agent can
// propose. With no idle expiry (Q2) it ends when someone revokes it.
//
// Store slice A (vault.createSession({infinite}) and the expiry helpers) is
// built in parallel. Until it lands, `stubSliceA` gives the vault the shape
// slice A promises, so these tests exercise the daemon, CLI and UI side now and
// the real store once it is there. The tests of the store's own liveness rules
// skip until then.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startDaemon, startUi, cli, makeAuthenticator, enrol, PASSPHRASE } from './fix-control-helpers.js'
import * as vaultStore from '../../src/store/vault.js'
import * as webauthn from '../../src/ui/webauthn.js'

const SLICE_A = typeof vaultStore.sessionExpiryMs === 'function'

/** What slice A's createSession does for `infinite`, on a store that predates it. */
function stubSliceA(vault) {
  if (SLICE_A) return
  const original = vault.createSession.bind(vault)
  vault.createSession = ({ infinite, elevated, ...opts }) => {
    const made = original(opts)
    if (infinite) Object.assign(made.session, { infinite: true, expires_at: null, max_expires_at: null, idle_timeout_ms: null })
    else made.session.infinite = false
    return made
  }
  // Slice A's issuePlaceholder bounds a placeholder by a session expiry that
  // may be Infinity. The old one would compute new Date(NaN), so for these
  // tests an infinite session lends it a far-off date for the one call.
  const issue = vault.issuePlaceholder.bind(vault)
  vault.issuePlaceholder = (args) => {
    const s = vault.db.sessions[vault.db.grants[args.grantId]?.session_id]
    if (s?.infinite !== true) return issue(args)
    const far = new Date(Date.now() + 100 * 365 * 86_400_000).toISOString()
    Object.assign(s, { expires_at: far, max_expires_at: far })
    try { return issue(args) } finally { Object.assign(s, { expires_at: null, max_expires_at: null }) }
  }
}

async function daemon(opts = {}) {
  const d = await startDaemon({ socketName: 'control.sock', ...opts })
  stubSliceA(d.vault)
  return d
}

const INFINITE = { cred: 'demo', infinite: true }

test('a session with no expiry needs a fresh proof, and gets one from the passphrase', async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  try {
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const refused = await d.control('POST', '/v1/sessions', INFINITE)
    assert.equal(refused.status, 401, JSON.stringify(refused.body))
    assert.equal(refused.body.rule, 'fresh_presence')
    d.daemon.presenceGraceUntil = 0

    const r = await d.control('POST', '/v1/sessions', { ...INFINITE, presence: { passphrase: PASSPHRASE } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.infinite, true)
    assert.equal(r.body.expires_at, null)
    const listed = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === r.body.session_id)
    assert.equal(listed.infinite, true)
    assert.equal(listed.expires_at, null)
    assert.deepEqual(listed.elevated, ['infinite'])
    // The agent's own view of its session says so too.
    const own = await fetch(`http://127.0.0.1:${d.daemon.gatewayPort}/v1/session`, { headers: { authorization: `Bearer ${r.body.token}` } })
    const view = await own.json()
    assert.equal(own.status, 200, JSON.stringify(view))
    assert.equal(view.infinite, true)
    assert.equal(view.expires_at, null)
  } finally { await d.stop() }
})

test('a vault with no factor refuses a session with no expiry', async () => {
  const d = await daemon()
  try {
    const r = await d.control('POST', '/v1/sessions', INFINITE)
    assert.equal(r.status, 401)
    assert.equal(r.body.rule, 'factor_required')
    assert.equal(Object.keys(d.vault.db.sessions).length, 0)
  } finally { await d.stop() }
})

test('a session with no expiry is never remote, and says so before asking for anything', async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  try {
    for (const presence of [undefined, { passphrase: PASSPHRASE }]) {
      const r = await d.control('POST', '/v1/sessions', { ...INFINITE, remote: true, presence })
      assert.equal(r.status, 403, JSON.stringify(r.body))
      assert.equal(r.body.code, 'AV_REMOTE_FORBIDDEN')
      assert.equal(r.body.rule, 'infinite_remote')
    }
    assert.equal(Object.keys(d.vault.db.sessions).length, 0)
  } finally { await d.stop() }
})

test('a lifetime is a positive number, and infinite has none to set', async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  try {
    // Refused before the gate: nobody is asked for a passphrase for this.
    for (const body of [
      { cred: 'demo', ttl_hours: 'abc' }, { cred: 'demo', ttl_hours: 0 }, { cred: 'demo', ttl_hours: -1 },
      { cred: 'demo', ttl_hours: '8' }, { ...INFINITE, ttl_hours: 1 }, { cred: 'demo', infinite: 'yes' },
      { cred: 'demo', infinite: 1 },
    ]) {
      const r = await d.control('POST', '/v1/sessions', body)
      assert.equal(r.status, 403, `${JSON.stringify(body)}: ${JSON.stringify(r.body)}`)
      assert.equal(r.body.rule, 'ttl', JSON.stringify(body))
    }
    assert.equal(Object.keys(d.vault.db.sessions).length, 0)
  } finally { await d.stop() }
})

test('ordinary finite sessions are unchanged', async () => {
  const d = await daemon()
  try {
    const one = await d.control('POST', '/v1/sessions', { cred: 'demo', ttl_hours: 1 })
    assert.equal(one.status, 200, JSON.stringify(one.body))
    assert.equal(one.body.infinite, false)
    const s = d.vault.db.sessions[one.body.session_id]
    const left = Date.parse(s.expires_at) - Date.now()
    assert.ok(left > 59 * 60_000 && left <= 3600_000, `an hour, not ${left}ms`)
    assert.equal(s.max_expires_at, s.expires_at, 'a lifetime someone named is its own ceiling')
    d.vault.touchSession(s)
    assert.equal(Date.parse(s.expires_at) <= Date.parse(s.max_expires_at), true)

    // The default lifetime still idle-extends towards its cap.
    const dflt = await d.control('POST', '/v1/sessions', { cred: 'demo', ttl_hours: null })
    const ds = d.vault.db.sessions[dflt.body.session_id]
    const before = Date.parse(ds.expires_at)
    ds.expires_at = new Date(Date.now() + 60_000).toISOString()
    d.vault.touchSession(ds)
    assert.ok(Date.parse(ds.expires_at) > Date.now() + 60_000, 'idle activity extends it')
    assert.ok(Date.parse(ds.expires_at) <= Date.parse(ds.max_expires_at))
    void before
    // Fractional hours are fine.
    assert.equal((await d.control('POST', '/v1/sessions', { cred: 'demo', ttl_hours: 0.5 })).status, 200)
  } finally { await d.stop() }
})

test('revoking a session with no expiry kills its placeholders', async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  try {
    const r = await d.control('POST', '/v1/sessions', { ...INFINITE, presence: { passphrase: PASSPHRASE } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal((await d.control('DELETE', `/v1/sessions?sid=${r.body.session_id}`)).status, 200)
    const rows = Object.values(d.vault.db.placeholders).filter((p) => p.sid === r.body.session_id)
    assert.ok(rows.length)
    for (const p of rows) {
      assert.equal(p.state, 'dead')
      assert.equal(p.dead_reason, 'session_ended')
    }
    const listed = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === r.body.session_id)
    assert.equal(listed.state, 'revoked')
  } finally { await d.stop() }
})

test('the owner can add no expiry when approving, but not on top of a lifetime the agent asked for', async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  try {
    const ask = async (body) => (await d.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'long job', ...body })).body.id
    const timed = await ask({ ttl_minutes: 30 })
    const clash = await d.control('POST', '/v1/session-requests/decide', {
      id: timed, granted: true, overrides: { infinite: true }, presence: { passphrase: PASSPHRASE },
    })
    assert.equal(clash.status, 403, JSON.stringify(clash.body))
    assert.equal(clash.body.rule, 'ttl')

    const open = await ask({})
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const windowed = await d.control('POST', '/v1/session-requests/decide', { id: open, granted: true, overrides: { infinite: true } })
    assert.equal(windowed.status, 401)
    assert.equal(windowed.body.rule, 'fresh_presence')
    d.daemon.presenceGraceUntil = 0
    const ok = await d.control('POST', '/v1/session-requests/decide', {
      id: open, granted: true, overrides: { infinite: true }, presence: { passphrase: PASSPHRASE },
    })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(ok.body.session.infinite, true)
    assert.equal(ok.body.session.expires_at, null)
  } finally { await d.stop() }
})

test('an authenticator assertion creates one from the UI, which marks it everywhere', async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  const auth = makeAuthenticator()
  enrol(d.vault, auth)
  const u = await startUi(d)
  try {
    const body = { label: 'ui', grants: [{ cred: 'demo', methods: ['GET'], paths: ['/**'], budget: 5, approval: 'on-write' }], infinite: true }
    const presence = await u.presence(auth, webauthn.operationFor('session.create', body))
    const r = await u.api('POST', 'sessions', { ...body, presence })
    const s = await r.json()
    assert.equal(r.status, 200, JSON.stringify(s))
    assert.equal(s.infinite, true)
    const listed = await (await u.api('GET', 'sessions')).json()
    assert.equal(listed.find((x) => x.id === s.session_id).infinite, true)
  } finally { await u.stop(); await d.stop() }
})

test('the CLI refuses --ttl with --infinite, and lists an infinite session as never', async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  try {
    const both = await cli(d.dir, ['session', 'create', '--cred', 'demo', '--ttl', '2', '--infinite'])
    assert.equal(both.code, 2, both.stderr)
    assert.match(both.stderr, /--ttl and --infinite cannot be combined/)
    const noTty = await cli(d.dir, ['session', 'create', '--cred', 'demo', '--infinite'])
    assert.equal(noTty.code, 5, noTty.stderr)

    const r = await d.control('POST', '/v1/sessions', { ...INFINITE, presence: { passphrase: PASSPHRASE } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const list = await cli(d.dir, ['session', 'list'])
    assert.equal(list.code, 0, list.stderr)
    const line = list.stdout.split('\n').find((l) => l.startsWith(r.body.session_id))
    assert.match(line, /elevated infinite grants:1 approval:on-write expires:never$/)
  } finally { await d.stop() }
})

test('the CLI on a vault with no factor says to set a passphrase first', async () => {
  const d = await daemon()
  try {
    const r = await cli(d.dir, ['session', 'create', '--cred', 'demo', '--infinite'])
    assert.equal(r.code, 5, r.stderr)
    assert.match(r.stderr, /next: agent-vault passphrase set/)
  } finally { await d.stop() }
})

// ------------------------------------------------ the store's own rules (slice A)

test('a stored expiry that does not parse is never live', { skip: !SLICE_A && 'store slice A has not landed' }, async () => {
  const d = await daemon()
  try {
    for (const expires of ['garbage', null]) {
      const { session } = d.vault.createSession({ label: 'odd' })
      session.expires_at = expires
      assert.throws(() => d.vault.assertSessionLive(session), { code: 'AV_SESSION_EXPIRED' }, String(expires))
    }
  } finally { await d.stop() }
})

test('an infinite session is the default for an implicit placeholder when it is the only one', { skip: !SLICE_A && 'store slice A has not landed' }, async () => {
  const d = await daemon({ passphrase: PASSPHRASE })
  try {
    const r = await d.control('POST', '/v1/sessions', { ...INFINITE, presence: { passphrase: PASSPHRASE } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const issued = await d.control('POST', '/v1/placeholders', { cred: 'demo' })
    assert.equal(issued.status, 200, JSON.stringify(issued.body))
  } finally { await d.stop() }
})
