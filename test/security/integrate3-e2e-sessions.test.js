// A.7 items 1–3, end to end: R1 auto-approval with a passphrase prompt, R2
// env files and exec, R3 infinite sessions and panic. Each runs the real CLI
// against a throwaway daemon, then uses what it made through the gateway or
// MCP, and reads the result back over the control socket.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { statSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { startE2E, grantOf, PASSPHRASE, SECRETS } from './integrate3-e2e-helpers.js'

test('A.7 1 (R1): --approval auto asks for the passphrase on a terminal, and a POST is then not held', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE })
  try {
    const r = await e.cli(['session', 'create', '--cred', 'gh', '--approval', 'auto', '--methods', 'GET,POST'], { tty: true, input: `${PASSPHRASE}\n`, json: true })
    assert.equal(r.code, 0, r.stdout + r.stderr)
    const s = r.data
    assert.ok(s.token && s.placeholder, 'the hand-off came back')
    // The proof was fresh, for this one call: no window was opened.
    const verified = e.audit('presence.verified')
    assert.ok(verified.some((v) => v.fresh === true), JSON.stringify(verified))
    assert.equal(e.audit('presence.window_opened').length, 0)
    const created = e.audit('session.created').find((c) => c.session_id === s.session_id)
    assert.deepEqual(created.elevated, ['approval_auto_writes'])

    // A write through the gateway goes straight through: nothing is held.
    const post = await e.gateway('/p/gh/repos/x/issues', { method: 'POST', headers: { ...e.auth(s), 'content-type': 'application/json' }, body: '{"title":"t"}' })
    assert.equal(post.status, 200, post.text)
    assert.equal(e.seen.length, 1)
    assert.equal(e.seen[0].method, 'POST')
    assert.equal(e.seen[0].headers.authorization, `Bearer ${SECRETS.gh}`)
    assert.equal(e.daemon.pipeline.pendingApprovals().length, 0)
  } finally { await e.stop() }
})

test('A.7 1 (R1): the same command with the window open and no passphrase is refused, and nothing is made', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE })
  try {
    // A window is the CLI's ordinary proof. Elevation never accepts one.
    const opened = await e.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
    assert.equal(opened.status, 200, JSON.stringify(opened.body))
    const before = Object.keys(e.vault.db.sessions).length
    const r = await e.cli(['session', 'create', '--cred', 'gh', '--approval', 'auto', '--methods', 'GET,POST'], { json: true })
    assert.equal(r.code, 5, r.stdout + r.stderr)
    assert.equal(r.envelope.ok, false)
    assert.equal(Object.keys(e.vault.db.sessions).length, before, 'no session was created')
    // And the window does let an ordinary session through, so it was open.
    const plain = await e.cli(['session', 'create', '--cred', 'gh'], { json: true })
    assert.equal(plain.code, 0, plain.stdout + plain.stderr)
    assert.equal(Object.keys(e.vault.db.sessions).length, before + 1)
  } finally { await e.stop() }
})

test('A.7 2 (R2): env writes a 0600 file of placeholders, refuses to replace it, and exec sends the real value upstream', async () => {
  const e = await startE2E()
  try {
    const made = await e.cli(['session', 'create', '--cred', 'gh,openai'], { json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const sid = made.data.session_id

    const out = join(e.dir, '.env')
    const env = await e.cli(['env', '--out', '.env', '--map', 'GH_TOKEN=gh', '--profile-vars'], { json: true })
    assert.equal(env.code, 0, env.stdout + env.stderr)
    assert.equal(statSync(out).mode & 0o777, 0o600)
    const text = readFileSync(out, 'utf8')
    for (const secret of Object.values(SECRETS)) assert.ok(!text.includes(secret), 'no real value in the file')
    const vars = Object.fromEntries(text.split('\n').filter((l) => l && !l.startsWith('#')).map((l) => l.split(/=(.*)/s).slice(0, 2)))
    assert.deepEqual(Object.keys(vars).sort(), ['GH_TOKEN', 'OPENAI_API_KEY', 'OPENAI_BASE_URL'])
    assert.match(vars.GH_TOKEN, /^av1\./)
    assert.match(vars.OPENAI_API_KEY, /^av1\./)
    assert.equal(vars.OPENAI_BASE_URL, `http://127.0.0.1:${e.daemon.gatewayPort}/p/openai`)
    // Each placeholder belongs to this session and its own credential.
    const rows = Object.values(e.vault.db.placeholders).filter((p) => p.sid === sid)
    assert.ok(rows.length >= 2)

    // A second run does not replace it.
    const again = await e.cli(['env', '--out', '.env', '--map', 'GH_TOKEN=gh', '--profile-vars'], { json: true })
    assert.equal(again.code, 11, again.stdout + again.stderr)
    assert.equal(readFileSync(out, 'utf8'), text, 'the file is untouched')

    // exec hands the child a placeholder; the gateway puts the real value in.
    const script = [
      "const leaked = Object.values(process.env).some((v) => /ghp_E2E/.test(v))",
      "fetch(process.env.AGENT_VAULT_URL + '/p/gh/user', { headers: { 'av-session': process.env.AGENT_VAULT_SESSION, authorization: 'Bearer ' + process.env.GH_TOKEN } })",
      "  .then(async (r) => { console.log(JSON.stringify({ status: r.status, leaked, ph: /^av1\\./.test(process.env.GH_TOKEN) })); process.exit(r.status === 200 ? 0 : 1) })",
    ].join('\n')
    const ran = await e.cli(['exec', '--map', 'GH_TOKEN=gh', '--', process.execPath, '-e', script])
    assert.equal(ran.code, 0, ran.stdout + ran.stderr)
    assert.deepEqual(JSON.parse(ran.stdout.trim().split('\n').pop()), { status: 200, leaked: false, ph: true })
    const hit = e.seen.at(-1)
    assert.equal(hit.url, '/user')
    assert.equal(hit.headers.authorization, `Bearer ${SECRETS.gh}`, 'the upstream saw the real value')
  } finally { await e.stop() }
})

test('A.7 3 (R3): an infinite session lists as never, says infinite over MCP, and panic revokes it', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE })
  try {
    const r = await e.cli(['session', 'create', '--cred', 'gh', '--infinite'], { tty: true, input: `${PASSPHRASE}\n`, json: true })
    assert.equal(r.code, 0, r.stdout + r.stderr)
    const s = r.data
    assert.equal(s.infinite, true)

    const listed = await e.cli(['session', 'list'])
    assert.equal(listed.code, 0, listed.stderr)
    const line = listed.stdout.split('\n').find((l) => l.startsWith(s.session_id))
    assert.ok(line, listed.stdout)
    assert.match(line, /expires:never/)
    assert.match(line, /infinite/)

    const status = await e.mcp(s.token, 'vault_status')
    assert.equal(status.isError, false, status.text)
    assert.equal(status.body.session.id, s.session_id)
    assert.equal(status.body.session.infinite, true, status.text)

    // It works until the panic, and not after.
    assert.equal((await e.gateway('/p/gh/user', { headers: e.auth(s) })).status, 200)
    const panic = await e.cli(['panic'], { json: true })
    assert.equal(panic.code, 0, panic.stdout + panic.stderr)
    assert.ok(panic.data.revoked_sessions >= 1)
    assert.equal(e.vault.db.sessions[s.session_id].state, 'revoked')
    const hits = e.seen.length
    const after = await e.gateway('/p/gh/user', { headers: e.auth(s) })
    assert.notEqual(after.status, 200)
    assert.equal(e.seen.length, hits, 'nothing reached the upstream after the panic')
    assert.equal(e.audit('panic.triggered').length, 1)
  } finally { await e.stop() }
})
