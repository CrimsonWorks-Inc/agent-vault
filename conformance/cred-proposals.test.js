// Credential proposals, black-box: an agent describes a credential over MCP
// without the key; the human sees the hosts, then the key is typed and
// saved, or the proposal is denied. Rust only (new with credential
// proposals; the frozen JS reference has no such tool).

import { after, before, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { implName, leaksSecret, openWorld, runCli, rustSkipReason } from './lib/harness.js'

const SECRET = 'test-proposed-key-fake-0123456789'

const skip = rustSkipReason() || (implName() === 'js' ? 'credential proposals are Rust only' : null)
if (skip) {
  test('cred-proposals', { skip }, () => {})
} else {
  describe('cred-proposals', { concurrency: false, timeout: 120_000 }, () => {
    let w
    before(async () => { w = await openWorld() })
    after(async () => { await w?.close() })

    let rpcId = 0
    async function propose(args) {
      const res = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: { name: 'vault_propose_credential', arguments: args } }),
      })
      const rpc = await res.json()
      return JSON.parse(rpc.result.content[0].text)
    }

    test('an agent proposes without a session, a human sees the hosts and saves the key', async () => {
      const asked = await propose({ slug: 'linear', host: 'api.linear.app', sites: ['header:authorization'], reason: 'to read issues' })
      assert.equal(asked.state, 'pending', JSON.stringify(asked))
      assert.deepEqual(asked.hosts, ['api.linear.app'])
      assert.match(asked.request_id, /^cp_/)

      const listed = await runCli(w, ['approvals', '--json'])
      assert.equal(listed.code, 0, listed.stderr)
      const item = listed.json.data.find((i) => i.id === asked.request_id)
      assert.equal(item.kind, 'credential')
      assert.deepEqual(item.hosts, ['api.linear.app'])
      assert.equal(item.decide.path, '/v1/cred-proposals/decide')
      const shown = await runCli(w, ['approvals'])
      assert.match(shown.stdout, /key requested/)
      assert.match(shown.stdout, /the key will be sent only to: api\.linear\.app/)

      // Without a terminal there is no one to check the host or type the key.
      const piped = await runCli(w, ['approve', asked.request_id], { input: `${SECRET}\n` })
      assert.notEqual(piped.code, 0)
      assert.match(piped.stderr, /needs a terminal/)

      // A pending proposal survives a restart.
      await w.restart()
      const again = await propose({ poll_id: asked.request_id, poll_secret: asked.poll_secret })
      assert.equal(again.state, 'pending')

      const wrong = await w.control('POST', '/v1/cred-proposals/decide', { id: asked.request_id, granted: true, hosts: ['evil.example'], value: SECRET })
      assert.equal(wrong.status, 403)
      assert.equal(wrong.json.rule, 'proposal_hosts')
      const saved = await w.control('POST', '/v1/cred-proposals/decide', { id: asked.request_id, granted: true, hosts: ['api.linear.app'], value: SECRET })
      assert.equal(saved.status, 200, saved.text)
      assert.equal(saved.json.credential.slug, 'linear')
      assert.equal(leaksSecret(saved.text, SECRET), null)

      const creds = await runCli(w, ['cred', 'list', '--json'])
      const linear = creds.json.data.find((c) => c.slug === 'linear')
      assert.equal(linear.connector.host, 'api.linear.app')
      assert.deepEqual(linear.fields[0].sites, ['header:authorization'])
      const polled = await propose({ poll_id: asked.request_id, poll_secret: asked.poll_secret })
      assert.equal(polled.state, 'approved')
      assert.equal(polled.cred, 'linear')
    })

    test('a proposal never carries the key and never widens a fixed host', async () => {
      const keyed = await propose({ slug: 'gh', kind: 'github', value: SECRET })
      assert.equal(keyed.rule, 'proposal_secret')
      const widened = await propose({ slug: 'gh', kind: 'github', host: 'evil.example' })
      assert.equal(widened.rule, 'proposal_host')
      const audit = await runCli(w, ['audit', 'export'])
      assert.equal(leaksSecret(audit.stdout, SECRET), null)
    })

    test('an agent waiting in its tool call gets the answer the moment it is given', async () => {
      const started = Date.now()
      const call = propose({ slug: 'waited', host: 'api.waited.example', wait_seconds: 30 })
      let id
      while (!id) {
        const listed = await w.control('GET', '/v1/cred-proposals')
        id = listed.json.find((p) => p.proposal.slug === 'waited')?.id
        if (!id) await new Promise((r) => setTimeout(r, 50))
      }
      const saved = await w.control('POST', '/v1/cred-proposals/decide', { id, granted: true, hosts: ['api.waited.example'], value: SECRET })
      assert.equal(saved.status, 200, saved.text)
      const answer = await call
      assert.equal(answer.state, 'approved', JSON.stringify(answer))
      assert.equal(answer.cred, 'waited')
      assert.equal(answer.request_id, id)
      assert.ok(Date.now() - started < 15_000, 'woken by the answer, not the 30-second wait')
    })

    test('the CLI denies one with no key, and the agent is told', async () => {
      const asked = await propose({ slug: 'notion', host: 'api.notion.com' })
      const denied = await runCli(w, ['deny', asked.request_id])
      assert.equal(denied.code, 0, denied.stderr)
      assert.match(denied.stdout, /denied/)
      const polled = await propose({ poll_id: asked.request_id, poll_secret: asked.poll_secret })
      assert.equal(polled.state, 'denied')
      const creds = await runCli(w, ['cred', 'list', '--json'])
      assert.equal(creds.json.data.some((c) => c.slug === 'notion'), false)
    })
  })
}
