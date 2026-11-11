// Hardening regressions mined from test/security. Each shape has an ordinary-traffic control.
// These are the encodings the response scrubber and the detector already search for.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  rustSkipReason, openWorld, seed, gateway, runCli, leaksSecret, LOOKALIKE, SECRET,
} from './lib/harness.js'

const skip = rustSkipReason()
if (skip) {
  test('hardening', { skip }, () => {})
} else {
  describe('hardening', { concurrency: false, timeout: 120_000 }, () => {
    let w
    before(async () => {
      w = await openWorld()
      await seed(w)
    })
    after(async () => { await w?.close() })

    test('echoed encodings never come back, and ordinary traffic does', async () => {
      const echo = await gateway(w, `/p/${w.slug}/echo`, { token: w.session.token, placeholder: w.session.placeholder })
      assert.equal(echo.status, 200)
      assert.equal(echo.json.ordinary, 'ordinary-traffic-control')
      assert.equal(echo.json.lookalike, LOOKALIKE)
      assert.equal(leaksSecret(echo.text), null)
      assert.equal(w.upstream.hits.at(-1).seen, SECRET)

      const posted = await gateway(w, `/p/${w.slug}/echo`, {
        method: 'POST',
        token: w.session.token,
        placeholder: w.session.placeholder,
        headers: { 'content-type': 'text/plain' },
        body: SECRET,
      })
      assert.equal(posted.status, 202, posted.text)
      assert.equal(posted.json.code, 'AV_APPROVAL_PENDING')
      assert.equal(leaksSecret(posted.text), null)
    })

    test('the secret stays out of MCP results, CLI output, the audit log, and daemon logs', async () => {
      const mcp = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          authorization: `Bearer ${w.session.token}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1, method: 'tools/call',
          params: { name: 'vault_http', arguments: { cred: w.slug, method: 'GET', path: '/echo', reason: 'conformance drill' } },
        }),
      })
      const mcpText = await mcp.text()
      assert.equal(mcp.status, 200)
      assert.ok(mcpText.includes('ordinary-traffic-control'))
      assert.ok(mcpText.includes(LOOKALIKE))
      assert.equal(leaksSecret(mcpText), null)

      const listed = await runCli(w, ['cred', 'list', '--json'])
      assert.equal(listed.code, 0, listed.stdout)
      assert.equal(listed.json.ok, true)
      assert.ok(listed.json.data.some((c) => c.slug === w.slug))
      assert.equal(leaksSecret(listed.stdout + listed.stderr), null)

      const tail = await runCli(w, ['audit', 'tail', '--json', '--limit', '50'])
      assert.equal(tail.code, 0, tail.stderr + tail.stdout)
      assert.equal(tail.json.ok, true)
      assert.equal(leaksSecret(tail.stdout + tail.stderr), null)

      const status = await runCli(w, ['status', '--json'])
      assert.equal(status.code, 0, status.stdout)
      assert.equal(leaksSecret(status.stdout + status.stderr), null)

      const audit = await w.control('GET', '/v1/audit?limit=100')
      assert.equal(audit.status, 200)
      assert.equal(leaksSecret(audit.text), null)
      const chain = await w.control('GET', '/v1/audit/verify')
      assert.equal(chain.json.ok, true)
      assert.equal(leaksSecret(w.log()), null)
    })
  })
}
