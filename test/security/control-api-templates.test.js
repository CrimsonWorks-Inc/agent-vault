// Session templates (F17): named shapes a human saved. A template is
// configuration, not standing approval: saving is gated, creating from one
// passes the normal gate (fresh when the result is elevated), the signed
// operation binds the template's hash so an edit after signing is refused,
// overrides only narrow, and a session request from a template is a snapshot.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi, PASSPHRASE } from './control-api-helpers.js'
import { makeAuthenticator, enrol, signed } from './fix-control-helpers.js'
import * as webauthn from '../../src/ui/webauthn.js'
import { resolveTemplate } from '../../src/daemon/session-requests.js'

const GET_ONLY = { cred: 'demo', methods: ['GET'], paths: ['/repos/**'], budget: 20 }

async function save(a, name, spec) {
  a.openWindow()
  const r = await a.control('POST', '/v1/templates', { name, spec })
  a.closeWindow()
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body
}

test('saving a template needs a human, and is checked like a create first', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const refused = await a.control('POST', '/v1/templates', { name: 'read', spec: GET_ONLY })
    assert.equal(refused.status, 401)
    assert.equal(refused.body.code, 'AV_PRESENCE_REQUIRED')
    assert.equal(a.vault.getTemplate('read'), null)
    // Checked before the gate, so nobody is asked to save what would fail.
    for (const [spec, code, rule] of [
      [{ cred: 'missing' }, 'AV_NOT_FOUND', undefined],
      [{ cred: 'demo', budget: 0 }, 'AV_POLICY_DENIED', 'budget'],
      [{ cred: 'demo', rate: '1/fortnight' }, 'AV_POLICY_DENIED', 'policy_invalid'],
      [{ cred: 'demo', template: 'other' }, 'AV_POLICY_DENIED', 'session_shape'],
      ['demo', 'AV_POLICY_DENIED', 'session_shape'],
    ]) {
      const r = await a.control('POST', '/v1/templates', { name: 'x', spec })
      assert.equal(r.body.code, code, JSON.stringify(spec))
      if (rule) assert.equal(r.body.rule, rule, JSON.stringify(r.body))
    }
    a.openWindow()
    const badName = await a.control('POST', '/v1/templates', { name: 'Not A Name', spec: GET_ONLY })
    assert.equal(badName.body.rule, 'template_name')
    const ok = await a.control('POST', '/v1/templates', { name: 'read', spec: GET_ONLY })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(ok.body.version, 1)
    assert.match(ok.body.hash, /^[0-9a-f]{64}$/)
    assert.deepEqual(ok.body.elevated, [])
    assert.ok(Array.isArray(ok.body.lint))
    const elevated = await a.control('POST', '/v1/templates', { name: 'writer', spec: { cred: 'demo', methods: ['GET', 'POST'], approval: 'auto' } })
    assert.deepEqual(elevated.body.elevated, ['approval_auto_writes'])
  } finally { await a.stop() }
})

test('templates are listed with summaries, read in full by name, and deleted without presence', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const t = await save(a, 'read', GET_ONLY)
    const list = await a.control('GET', '/v1/templates')
    assert.equal(list.status, 200)
    const [row] = list.body
    assert.equal(row.name, 'read')
    assert.equal(row.hash, t.hash)
    assert.deepEqual(row.creds, ['demo'])
    assert.match(row.summary, /session for demo · GET/)
    const full = await a.control('GET', '/v1/templates?name=read')
    assert.deepEqual(full.body.spec, GET_ONLY)
    assert.equal((await a.control('GET', '/v1/templates?name=nope')).status, 404)
    // Removing a shape grants nothing, so it needs no human.
    const gone = await a.control('DELETE', '/v1/templates?name=read')
    assert.deepEqual(gone.body, { ok: true, removed: true })
    assert.equal((await a.control('DELETE', '/v1/templates?name=read')).body.removed, false)
  } finally { await a.stop() }
})

test('creating from a template binds its hash: an edit after looking is refused, the current hash works', async () => {
  const a = await startApi()
  try {
    const t = await save(a, 'read', GET_ONLY)
    const missing = await a.control('POST', '/v1/sessions', { template: 'read' })
    assert.equal(missing.body.rule, 'template_changed')
    const ok = await a.control('POST', '/v1/sessions', { template: 'read', template_hash: t.hash, label: 'from template' })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(ok.body.label, 'from template')
    assert.deepEqual(a.vault.db.grants[ok.body.grant_id].policy.methods, ['GET'])
    const created = a.audit('session.created').find((r) => r.session_id === ok.body.session_id)
    assert.equal(created.template, 'read')
    assert.equal(created.template_version, 1)
    // The human looked at v1; the template is now v2.
    const edited = await save(a, 'read', { ...GET_ONLY, methods: ['GET', 'POST'] })
    const stale = await a.control('POST', '/v1/sessions', { template: 'read', template_hash: t.hash })
    assert.equal(stale.status, 403)
    assert.equal(stale.body.rule, 'template_changed')
    assert.match(stale.body.detail, /the template changed after you looked at it; review it again/)
    const fresh = await a.control('POST', '/v1/sessions', { template: 'read', template_hash: edited.hash })
    assert.equal(fresh.status, 200)
    assert.equal(a.vault.db.sessions[fresh.body.session_id].template_version, 2)
  } finally { await a.stop() }
})

test('a signature over one template hash cannot be spent on another', async () => {
  // The operation is the whole body, template_hash included. Built from the
  // name alone, an assertion the human made for v1 would create from v2.
  const a = await startApi()
  try {
    const auth = makeAuthenticator()
    enrol(a.vault, auth)
    const v1 = await (async () => { a.vault.saveTemplate('read', GET_ONLY); return a.vault.getTemplate('read') })()
    const looked = { template: 'read', template_hash: v1.hash }
    const presence = await signed(a.control, auth, webauthn.operationFor('session.create', looked))
    a.vault.saveTemplate('read', { ...GET_ONLY, methods: ['GET', 'DELETE'] })
    const v2 = a.vault.getTemplate('read')
    const swapped = await a.control('POST', '/v1/sessions', { template: 'read', template_hash: v2.hash, presence })
    assert.equal(swapped.status, 401, JSON.stringify(swapped.body))
    assert.equal(swapped.body.code, 'AV_PRESENCE_REQUIRED')
    // Signed for what is sent, it works.
    const body = { template: 'read', template_hash: v2.hash }
    const ok = await a.control('POST', '/v1/sessions', { ...body, presence: await signed(a.control, auth, webauthn.operationFor('session.create', body)) })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
  } finally { await a.stop() }
})

test('overrides only narrow: DELETE on a GET template still makes a GET-only session', async () => {
  const a = await startApi()
  try {
    const t = await save(a, 'read', { ...GET_ONLY, approval: 'on-write', ttl_hours: 2 })
    const r = await a.control('POST', '/v1/sessions', {
      template: 'read', template_hash: t.hash,
      methods: ['GET', 'DELETE'], paths: ['/repos/x/**', '/admin/**'], budget: 500, approval: 'auto', ttl_hours: 24,
    })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const policy = a.vault.db.grants[r.body.grant_id].policy
    assert.deepEqual(policy.methods, ['GET'])
    assert.deepEqual(policy.paths, ['/repos/x/**'])
    assert.equal(policy.budget.limit, 20)
    assert.equal(policy.approval, 'on-write')
    assert.ok(Date.parse(r.body.expires_at) <= Date.now() + 2 * 3_600_000 + 1000)
    // Narrower values do narrow.
    const n = await a.control('POST', '/v1/sessions', { template: 'read', template_hash: t.hash, budget: 3, approval: 'each' })
    assert.equal(a.vault.db.grants[n.body.grant_id].policy.budget.limit, 3)
    assert.equal(a.vault.db.grants[n.body.grant_id].policy.approval, 'each')
    // Anything that is not an override is refused, never ignored.
    for (const extra of [{ hosts: ['evil.example'] }, { remote: true }, { rate: '1/s' }, { grants: [] }]) {
      const bad = await a.control('POST', '/v1/sessions', { template: 'read', template_hash: t.hash, ...extra })
      assert.equal(bad.status, 403, JSON.stringify(extra))
      assert.ok(['template_override', 'session_shape'].includes(bad.body.rule), JSON.stringify(bad.body))
    }
  } finally { await a.stop() }
})

test('an infinite template can only be made finite, never the other way round', async () => {
  const t = { spec: { cred: 'demo', infinite: true } }
  assert.equal(resolveTemplate(t, { ttl_hours: 1 }).infinite, undefined)
  assert.equal(resolveTemplate(t, { ttl_hours: 1 }).ttl_hours, 1)
  assert.equal(resolveTemplate(t, { infinite: false }).infinite, undefined)
  assert.throws(() => resolveTemplate({ spec: { cred: 'demo' } }, { infinite: true }), (e) => e.rule === 'template_override')
  assert.throws(() => resolveTemplate({ spec: { cred: 'demo' } }, { infinite: 'false' }), (e) => e.rule === 'ttl')
  // A budget override where the template names none needs the default to compare with.
  assert.throws(() => resolveTemplate({ spec: { cred: 'demo' } }, { budget: 10 }), (e) => e.rule === 'policy_invalid')
  assert.equal(resolveTemplate({ spec: { cred: 'demo' } }, { budget: 10 }, { budgetDefault: () => 500 }).budget, 10)
  assert.equal(resolveTemplate({ spec: { cred: 'demo' } }, { budget: 900 }, { budgetDefault: () => 500 }).budget, 500)
})

test('an elevated template needs a fresh proof to create, and the window is not one', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const t = await save(a, 'writer', { cred: 'demo', methods: ['GET', 'POST'], approval: 'auto' })
    a.openWindow()
    const windowed = await a.control('POST', '/v1/sessions', { template: 'writer', template_hash: t.hash })
    assert.equal(windowed.status, 401, JSON.stringify(windowed.body))
    assert.equal(windowed.body.rule, 'fresh_presence')
    const ok = await a.control('POST', '/v1/sessions', { template: 'writer', template_hash: t.hash, presence: { passphrase: PASSPHRASE } })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    // Narrowed to reads, it is an ordinary session and the window does.
    const narrowed = await a.control('POST', '/v1/sessions', { template: 'writer', template_hash: t.hash, methods: ['GET'] })
    assert.equal(narrowed.status, 200, JSON.stringify(narrowed.body))
  } finally { await a.stop() }
})

test('a session request from a template is a snapshot: an edit afterwards does not reach the session', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    await save(a, 'read', GET_ONLY)
    const asked = await a.control('POST', '/v1/session-requests', { template: 'read', reason: 'reading repos', budget: 5 })
    assert.equal(asked.status, 200, JSON.stringify(asked.body))
    assert.match(asked.body.summary, /^template read v1 · session for demo · GET/)
    assert.equal(asked.body.proposal.budget, 5)
    assert.equal(asked.body.proposal.template_version, 1)
    // The owner edits the template after the agent asked.
    await save(a, 'read', { ...GET_ONLY, methods: ['GET', 'POST', 'DELETE'], budget: 999 })
    a.openWindow()
    const decided = await a.control('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true })
    assert.equal(decided.status, 200, JSON.stringify(decided.body))
    const policy = a.vault.db.grants[decided.body.session.grant_id].policy
    assert.deepEqual(policy.methods, ['GET'], 'the approved session took the edited template')
    assert.equal(policy.budget.limit, 5)
    const session = a.vault.db.sessions[decided.body.session.session_id]
    assert.equal(session.template, 'read')
    assert.equal(session.template_version, 1)
  } finally { await a.stop() }
})

test('a template request names one credential, and a template\'s owner fields come only from the template', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    a.vault.addCredential({
      slug: 'other', kind: 'http', connector: { host: `127.0.0.1:${a.upPort}`, scheme: 'http' },
      fields: { token: 'OTHER-SECRET-0099887766' }, sites: { token: ['header:authorization:Bearer'] },
    })
    await save(a, 'both', { grants: [{ cred: 'demo' }, { cred: 'other' }] })
    const multi = await a.control('POST', '/v1/session-requests', { template: 'both', reason: 'x' })
    assert.equal(multi.body.rule, 'template_multi_cred')
    assert.equal((await a.control('POST', '/v1/session-requests', { template: 'nope', reason: 'x' })).status, 404)
    const t = await save(a, 'writer', { cred: 'demo', methods: ['GET', 'POST'], approval: 'auto' })
    // The agent still cannot add an owner field itself.
    const own = await a.control('POST', '/v1/session-requests', { template: 'writer', approval: 'each', reason: 'x' })
    assert.equal(own.body.rule, 'owner_only_field')
    const wrong = await a.control('POST', '/v1/session-requests', { template: 'writer', cred: 'other', reason: 'x' })
    assert.equal(wrong.body.rule, 'session_shape')
    const asked = await a.control('POST', '/v1/session-requests', { template: 'writer', reason: 'x' })
    assert.equal(asked.status, 200, JSON.stringify(asked.body))
    assert.equal(asked.body.proposal.approval, 'auto')
    assert.equal(asked.body.proposal.template_hash, t.hash)
    // Elevated, so approving it needs a fresh proof; the window is not one.
    a.openWindow()
    const windowed = await a.control('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true })
    assert.equal(windowed.body.rule, 'fresh_presence')
    const ok = await a.control('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true, presence: { passphrase: PASSPHRASE } })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    assert.equal(a.vault.db.grants[ok.body.session.grant_id].policy.approval, 'auto')
  } finally { await a.stop() }
})

test('MCP asks by template name, with no credential named, and lists single-credential templates', async () => {
  const a = await startApi()
  try {
    await save(a, 'read', GET_ONLY)
    a.vault.addCredential({
      slug: 'other', kind: 'http', connector: { host: `127.0.0.1:${a.upPort}`, scheme: 'http' },
      fields: { token: 'OTHER-SECRET-0099887766' }, sites: { token: ['header:authorization:Bearer'] },
    })
    await save(a, 'both', { grants: [{ cred: 'demo' }, { cred: 'other' }] })
    const status = await a.tool('vault_status')
    assert.deepEqual(status.body.templates.map((t) => t.name), ['read'])
    assert.equal(status.body.templates[0].cred, 'demo')
    const asked = await a.tool('vault_request_session', { template: 'read', reason: 'x', grant_ttl_minutes: 15 })
    assert.equal(asked.body.state, 'pending', JSON.stringify(asked.body))
    assert.match(asked.body.asked_for, /^template read v1/)
    const record = a.daemon.sessionRequests.get(asked.body.request_id)
    assert.equal(record.proposal.grant_ttl_minutes, 15)
    assert.equal((await a.tool('vault_request_session', { template: 'nope', reason: 'x' })).body.code, 'AV_NOT_FOUND')
    assert.equal((await a.tool('vault_request_session', { template: 'both', reason: 'x' })).body.rule, 'template_multi_cred')
  } finally { await a.stop() }
})
