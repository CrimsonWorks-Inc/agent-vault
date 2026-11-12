// A.7 items 8–9, end to end. Item 8: an agent asks for a session by template
// name over MCP, the human edits the template while the request waits, and
// what they approve is the version the agent was shown. Item 9: a grant with
// its own one-minute lifetime ends on a fake clock while the session's other
// grant keeps working.

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { startE2E, SECRETS } from './integrate3-e2e-helpers.js'

test('A.7 8 (F17): a session requested by template matches the snapshot it was asked from, not the edited template', async () => {
  const e = await startE2E()
  try {
    const v1 = await e.cli(['template', 'save', 'reader', '--cred', 'gh', '--methods', 'GET', '--paths', '/repos/**'], { json: true })
    assert.equal(v1.code, 0, v1.stdout + v1.stderr)
    assert.equal(v1.data.version, 1)

    // The agent has no session yet; it asks by name.
    const asked = await e.mcp(null, 'vault_request_session', { template: 'reader', reason: 'read the repo' })
    assert.equal(asked.body.state, 'pending', asked.text)
    const id = asked.body.request_id

    // The human widens the template while the request waits.
    const v2 = await e.cli(['template', 'save', 'reader', '--cred', 'gh', '--methods', 'GET,POST', '--paths', '/**'], { json: true })
    assert.equal(v2.code, 0, v2.stdout + v2.stderr)
    assert.equal(v2.data.version, 2)

    const approved = await e.cli(['approve', id], { json: true })
    assert.equal(approved.code, 0, approved.stdout + approved.stderr)
    const created = e.audit('session.created').at(-1)
    assert.equal(created.template, 'reader')
    assert.equal(created.template_version, 1, JSON.stringify(created))
    const grant = Object.values(e.vault.db.grants).find((g) => g.session_id === created.session_id)
    assert.deepEqual(grant.policy.methods, ['GET'])
    assert.deepEqual(grant.policy.paths, ['/repos/**'])

    // The CLI recorded the session where the bridge reads it; the agent uses it.
    const token = JSON.parse(readFileSync(join(e.dir, 'cli-state.json'), 'utf8')).token
    const polled = await e.mcp(null, 'vault_request_session', { poll_id: id, poll_secret: asked.body.poll_secret })
    assert.equal(polled.body.state, 'approved', polled.text)
    const read = await e.mcp(token, 'vault_http', { cred: 'gh', method: 'GET', path: '/repos/a', reason: 'e2e' })
    assert.equal(read.body.status, 200, read.text)
    for (const [method, path] of [['POST', '/repos/a'], ['GET', '/user']]) {
      const r = await e.mcp(token, 'vault_http', { cred: 'gh', method, path, reason: 'e2e', ...(method === 'POST' ? { body: '{}' } : {}) })
      assert.equal(r.body.status, 403, `${method} ${path} is outside v1: ${r.text}`)
    }
    assert.equal(e.seen.length, 1)
  } finally { await e.stop() }
})

test('A.7 9 (F18): a grant with --grant-ttl 1 ends with AV_GRANT_EXPIRED on a fake clock; the other grant still works', async () => {
  const e = await startE2E()
  try {
    writeFileSync(join(e.dir, 'grants.json'), JSON.stringify([{ cred: 'gh', grant_ttl_minutes: 1 }, { cred: 'other' }]))
    const made = await e.cli(['session', 'create', '--grants-file', join(e.dir, 'grants.json')], { json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const s = made.data
    const get = (cred) => e.mcp(s.token, 'vault_http', { cred, method: 'GET', path: `/${cred}`, reason: 'e2e' })

    // Does not fire inside the minute.
    assert.equal((await get('gh')).body.status, 200)
    assert.equal((await get('other')).body.status, 200)
    assert.equal(e.seen.length, 2)

    mock.timers.enable({ apis: ['Date'], now: Date.now() + 2 * 60_000 })
    try {
      const expired = await get('gh')
      assert.equal(expired.isError, true, expired.text)
      assert.equal(expired.body.code, 'AV_GRANT_EXPIRED', expired.text)
      assert.equal(e.seen.length, 2, 'nothing was sent on the expired grant')
      // The same over the gateway with the grant's own placeholder.
      const gh = (s.grants || []).find((g) => g.cred === 'gh')
      const direct = await e.gateway('/p/gh/again', { headers: { 'av-session': s.token, authorization: `Bearer ${gh.placeholder}` } })
      assert.notEqual(direct.status, 200, direct.text)
      assert.equal(e.seen.length, 2)

      const still = await get('other')
      assert.equal(still.body.status, 200, still.text)
      assert.equal(e.seen.length, 3)
      assert.equal(e.seen.at(-1).headers.authorization, `Bearer ${SECRETS.other}`)
      assert.equal(e.vault.db.sessions[s.session_id].state, 'active', 'the session outlives its grant')
    } finally { mock.timers.reset() }
  } finally { await e.stop() }
})
