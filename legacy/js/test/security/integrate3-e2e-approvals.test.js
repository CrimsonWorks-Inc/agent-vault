// A.7 items 6–7, end to end. Item 6: a held write is printed by `watch`,
// previewed by `approvals` with its placeholder hidden, approved with the CLI,
// and then runs exactly once when the agent resends it. Item 7: F15 narrowing
// mid-run, and an F16 tripwire that revokes a replaying session before its
// answer comes back.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as ph from '../../src/core/placeholder.js'
import { startE2E, PASSPHRASE, SECRETS } from './integrate3-e2e-helpers.js'

test('A.7 6 (F13, F14): watch prints a held POST, the preview hides the placeholder, and the approved resend runs once', async () => {
  const e = await startE2E()
  const watch = e.cliStream(['watch', '--json', '--no-notify'])
  try {
    const made = await e.cli(['session', 'create', '--cred', 'gh', '--methods', 'GET,POST', '--approval', 'on-write'], { json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const s = made.data
    const request = { cred: 'gh', method: 'POST', path: '/repos/a/issues', body: '{"title":"<b>hello</b>"}', reason: 'file the bug' }
    const held = await e.mcp(s.token, 'vault_http', request)
    assert.equal(held.body.status, 202, held.text)
    const approvalId = JSON.parse(held.body.body).approval_id
    assert.ok(approvalId)
    assert.equal(e.seen.length, 0, 'nothing is sent while it is held')

    // watch tells the human, with the daemon's headline and nothing else.
    const line = await watch.wait((l) => l.includes(approvalId))
    // A pending frame, or the snapshot if it was filed before watch connected.
    const { data } = JSON.parse(line)
    const entry = data.event === 'snapshot' ? data.items.find((i) => i.id === approvalId) : data
    assert.equal(entry.id, approvalId)
    assert.equal(entry.kind, 'request')
    assert.ok(!/av1\./.test(line) && !line.includes(SECRETS.gh))

    // The preview shows what would be sent, with the placeholder hidden.
    const listed = await e.cli(['approvals'], { json: true })
    assert.equal(listed.code, 0, listed.stderr)
    const item = listed.data.find((p) => p.id === approvalId)
    assert.ok(item?.preview, listed.stdout)
    assert.equal(item.preview.method, 'POST')
    assert.equal(item.preview.path, '/repos/a/issues')
    assert.match(item.preview.body.text, /hello/)
    assert.ok(!item.preview.headers.some(([name]) => name.toLowerCase() === 'authorization'), 'the credential header is left out')
    assert.ok(item.preview.placeholders.some((p) => p.label === 'gh.token'), JSON.stringify(item.preview.placeholders))
    assert.ok(!/av1\./.test(listed.stdout), 'no placeholder text anywhere in the listing')
    assert.ok(!listed.stdout.includes(SECRETS.gh))
    // The agent's own status view carries no preview.
    const status = await e.mcp(s.token, 'vault_approval_status', { approval_id: approvalId })
    assert.ok(!('preview' in status.body), status.text)

    const approved = await e.cli(['approve', approvalId], { json: true })
    assert.equal(approved.code, 0, approved.stdout + approved.stderr)

    // The resend executes, once; another resend replays the stored answer.
    const ran = await e.mcp(s.token, 'vault_http', request)
    assert.equal(ran.body.status, 200, ran.text)
    assert.equal(e.seen.length, 1)
    assert.equal(e.seen[0].body, request.body)
    assert.equal(e.seen[0].headers.authorization, `Bearer ${SECRETS.gh}`)
    const again = await e.mcp(s.token, 'vault_http', request)
    assert.equal(again.body.status, 200, again.text)
    assert.equal(again.body.headers['av-replayed'], 'true')
    assert.equal(e.seen.length, 1, 'the replay did not reach the upstream')
    assert.equal(e.audit('approval.replayed').length, 1)
  } finally {
    await watch.stop()
    await e.stop()
  }
})

test('A.7 7 (F15): session narrow --methods GET mid-run refuses the next POST and keeps GET working', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE })
  try {
    const made = await e.cli(['session', 'create', '--cred', 'gh', '--methods', 'GET,POST', '--approval', 'auto'], { tty: true, input: `${PASSPHRASE}\n`, json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const s = made.data
    const post = () => e.mcp(s.token, 'vault_http', { cred: 'gh', method: 'POST', path: '/w', body: '{}', reason: 'e2e' })
    assert.equal((await post()).body.status, 200)
    assert.equal(e.seen.length, 1)

    const narrowed = await e.cli(['session', 'narrow', s.session_id, '--methods', 'GET'], { json: true })
    assert.equal(narrowed.code, 0, narrowed.stdout + narrowed.stderr)
    const refused = await post()
    assert.equal(refused.body.status, 403, refused.text)
    assert.equal(e.seen.length, 1, 'the refused POST reached nothing')
    const get = await e.mcp(s.token, 'vault_http', { cred: 'gh', method: 'GET', path: '/r', reason: 'e2e' })
    assert.equal(get.body.status, 200, get.text)
    assert.equal(e.seen.length, 2)
    assert.equal(e.vault.db.sessions[s.session_id].state, 'active', 'narrowing does not end the session')
  } finally { await e.stop() }
})

test('A.7 7 (F16): with the tripwire on, a replayed placeholder revokes its session before the answer returns', async () => {
  const e = await startE2E()
  try {
    const made = await e.cli(['session', 'create', '--cred', 'gh'], { json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const s = made.data
    // A placeholder of this session, used once and then spent.
    const next = await e.cli(['ph', 'next', 'gh'], { json: true })
    assert.equal(next.code, 0, next.stdout + next.stderr)
    const spent = next.data.placeholder
    const row = e.vault.resolvePlaceholder(ph.parseAt(spent))
    e.vault.burnPlaceholder(row.id, 'spent')

    // Off by default: the replay is refused and nothing else happens.
    const off = await e.gateway('/p/gh/user', { headers: { authorization: `Bearer ${spent}` } })
    assert.equal(off.json?.code, 'AV_PH_REPLAY', off.text)
    assert.equal(e.vault.db.sessions[s.session_id].state, 'active')
    assert.equal(e.audit('tripwire.fired').length, 0)

    const on = await e.cli(['tripwire', 'on'], { json: true })
    assert.equal(on.code, 0, on.stdout + on.stderr)
    const replayed = await e.gateway('/p/gh/user', { headers: { authorization: `Bearer ${spent}` } })
    assert.equal(replayed.json?.code, 'AV_PH_REPLAY', replayed.text)
    // Read the moment the answer is in: the revocation was not deferred.
    assert.equal(e.vault.db.sessions[s.session_id].state, 'revoked')
    const fired = e.audit('tripwire.fired')
    assert.equal(fired.length, 1)
    assert.equal(fired[0].rule_id, 'replay')
    assert.equal(e.seen.length, 0)
    // And the session's own token and placeholder are dead too.
    const after = await e.mcp(s.token, 'vault_http', { cred: 'gh', method: 'GET', path: '/user', reason: 'e2e' })
    assert.notEqual(after.body?.status, 200, after.text)
    assert.equal(e.seen.length, 0)
  } finally { await e.stop() }
})
