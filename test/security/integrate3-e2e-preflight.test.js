// A.7 item 10, end to end: F20 preflight changes nothing but the audit log,
// over MCP vault_preflight and the CLI's gateway preflight, and F19 session
// show reports the real request without counting the preflight as one.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startE2E } from './integrate3-e2e-helpers.js'

const records = (text) => text.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))

test('A.7 10 (F19, F20): a preflight changes nothing but its audit record, and session show counts only the real request', async () => {
  const e = await startE2E()
  try {
    const made = await e.cli(['session', 'create', '--cred', 'gh', '--methods', 'GET,POST'], { json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const s = made.data
    const real = await e.mcp(s.token, 'vault_http', { cred: 'gh', method: 'GET', path: '/repos/a', reason: 'e2e' })
    assert.equal(real.body.status, 200, real.text)
    assert.equal(e.seen.length, 1)

    // Over MCP: a write that would be held.
    let before = e.files()
    const mcp = await e.mcp(s.token, 'vault_preflight', { cred: 'gh', method: 'POST', path: '/repos/a/issues', body: '{}' })
    assert.equal(mcp.isError, false, mcp.text)
    assert.equal(mcp.body.would, 'hold', mcp.text)
    let after = e.files()
    assert.equal(after.vault, before.vault, 'the vault itself is byte-for-byte unchanged')
    assert.ok(after.audit.startsWith(before.audit), 'the log only grew')
    let added = records(after.audit.slice(before.audit.length))
    assert.deepEqual(added.map((r) => r.kind), ['request.preflighted'])
    assert.equal(added[0].would, 'hold')
    assert.equal(added[0].session_id, s.session_id)

    // Through the CLI and the gateway's preflight route: a read that would pass.
    before = e.files()
    // The agent's request as it would send it: the placeholder at its site.
    const cli = await e.cli(['preflight', '--cred', 'gh', '--method', 'GET', '--path', '/user', '--header', `authorization: Bearer ${s.placeholder}`], { json: true })
    assert.equal(cli.code, 0, cli.stdout + cli.stderr)
    assert.equal(cli.data.would, 'allow')
    after = e.files()
    assert.equal(after.vault, before.vault)
    added = records(after.audit.slice(before.audit.length))
    assert.deepEqual(added.map((r) => r.kind), ['request.preflighted'])

    assert.equal(e.seen.length, 1, 'no preflight reached the upstream')
    assert.equal(e.daemon.pipeline.pendingApprovals().length, 0, 'and none was held')

    // session show: the real request, and the preflights kept apart from it.
    const shown = await e.cli(['session', 'show', s.session_id], { json: true })
    assert.equal(shown.code, 0, shown.stdout + shown.stderr)
    const { activity, grants } = shown.data
    assert.deepEqual(activity.requests, { allowed: 1, denied: 0, held: 0 })
    assert.deepEqual(activity.paths.map((p) => [p.method, p.path, p.count]), [['GET', '/repos/a', 1]])
    assert.equal(grants[0].budget.used, 1, 'a preflight spends no budget')
    const human = await e.cli(['session', 'show', s.session_id])
    assert.equal(human.code, 0, human.stderr)
    assert.match(human.stdout, /\/repos\/a/)
    assert.ok(!/\/repos\/a\/issues|\/user\b/.test(human.stdout), 'the preflighted paths are not reported as requests')
    const preflighted = await e.control('GET', '/v1/audit?kind=request.preflighted&limit=10')
    assert.equal(preflighted.status, 200)
    const rows = (preflighted.body.records || preflighted.body).filter((r) => r.kind === 'request.preflighted')
    assert.equal(rows.length, 2)
  } finally { await e.stop() }
})
