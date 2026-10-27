// Approval notifications (F14). A notification is a signal, never an approval
// channel, and never carries what an agent wrote: no reason, no body, no
// query, no placeholder. The stream is open (it shows what GET /v1/approvals
// already shows), resolves no session (C20), and holds at most 8 watchers.
// The webhook URL is a credential: setting it needs the owner, only its host
// is ever shown or recorded, and it is POSTed to at most once per 30 s.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi, stream, PASSPHRASE } from './control-api-helpers.js'
import { webhookPayload, cleanHeadline } from '../../src/daemon/notify.js'

const HOOK = 'https://hooks.example/services/T000/B000/SECRETPATH?token=QUERYSECRET'

/** A webhook endpoint stand-in that records each POST. */
function recorder(status = 200) {
  const calls = []
  const fetchImpl = async (req) => { calls.push({ ...req, body: JSON.parse(req.body) }); return { status: fetchImpl.status } }
  fetchImpl.status = status
  return { calls, fetchImpl }
}

test('the stream sends a snapshot, then each new item, without the agent\'s words', async () => {
  const a = await startApi()
  try {
    const s = a.session({ policy: { approval: 'each' } })
    const first = await a.gateway('/p/demo/before', { headers: { authorization: `Bearer ${s.placeholder}` } })
    assert.equal(first.status, 202)
    const watch = await stream(a.sock)
    try {
      assert.equal(watch.status, 200)
      await watch.wait(1)
      assert.equal(watch.events[0].event, 'snapshot')
      assert.equal(watch.events[0].data.items.length, 1)
      assert.equal(watch.events[0].data.items[0].kind, 'request')
      // A held request whose reason is hostile, and a session request whose
      // proposal carries a placeholder.
      await a.gateway('/p/demo/later', { headers: { authorization: `Bearer ${s.placeholder}`, 'av-reason': '<script>alert(1)</script>' } })
      const asked = await a.control('POST', '/v1/session-requests', {
        cred: 'demo', paths: [`/x/${s.placeholder}`], reason: '<script>steal()</script>',
      })
      assert.equal(asked.status, 200, JSON.stringify(asked.body))
      await watch.wait(3)
      const [, held, session] = watch.events
      assert.equal(held.event, 'pending')
      assert.equal(held.data.kind, 'request')
      assert.match(held.data.headline, /^GET /)
      assert.equal(session.data.kind, 'session')
      assert.equal(session.data.id, asked.body.id)
      const raw = watch.events.map((e) => e.raw).join('\n')
      assert.ok(!raw.includes('<script>'), 'an agent reason reached the stream')
      assert.ok(!raw.includes(s.placeholder), 'a placeholder reached the stream')
      assert.match(session.data.headline, /«placeholder»/)
      assert.deepEqual(Object.keys(session.data).sort(), ['created_at', 'headline', 'id', 'kind'])
    } finally { watch.close() }
  } finally { await a.stop() }
})

test('a ninth watcher is refused', async () => {
  const a = await startApi()
  const open = []
  try {
    for (let i = 0; i < 8; i++) {
      const w = await stream(a.sock)
      assert.equal(w.status, 200, `watcher ${i}`)
      open.push(w)
    }
    const ninth = await stream(a.sock)
    assert.equal(ninth.status, 429)
    ninth.close()
    open.pop().close()
    await new Promise((r) => setTimeout(r, 50))
    const again = await stream(a.sock)
    assert.equal(again.status, 200, 'a closed watcher did not free its place')
    open.push(again)
  } finally {
    for (const w of open) w.close()
    await a.stop()
  }
})

test('the stream resolves no session: a token sent to it is ignored and touches nothing (C20)', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    const seenAt = a.vault.db.sessions[s.session.id].last_seen_at
    const records = a.audit().length
    for (const headers of [{ authorization: `Bearer ${s.token}` }, { 'av-session': s.token }, { 'av-session': 'avs1.garbage.token' }, {}]) {
      const w = await stream(a.sock, '/v1/pending/stream', headers)
      assert.equal(w.status, 200, JSON.stringify(headers))
      await w.wait(1)
      w.close()
    }
    assert.equal(a.vault.db.sessions[s.session.id].last_seen_at, seenAt, 'the stream touched the session')
    assert.equal(a.audit().length, records, 'the stream wrote audit records')
  } finally { await a.stop() }
})

test('setting a webhook needs the owner; only its host is ever shown or recorded', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  try {
    const refused = await a.control('POST', '/v1/notify', { webhook_url: HOOK })
    assert.equal(refused.status, 401)
    assert.equal(refused.body.code, 'AV_PRESENCE_REQUIRED')
    assert.deepEqual((await a.control('GET', '/v1/notify')).body, { webhook: null })
    a.openWindow()
    for (const webhook_url of ['http://example.com/hook', 'https://user:pw@hooks.example/x', 'not a url', 5]) {
      const r = await a.control('POST', '/v1/notify', { webhook_url })
      assert.equal(r.body.rule, 'webhook_url', JSON.stringify(webhook_url))
    }
    const set = await a.control('POST', '/v1/notify', { webhook_url: HOOK })
    assert.equal(set.status, 200, JSON.stringify(set.body))
    assert.equal(set.body.webhook.host, 'hooks.example')
    assert.equal(set.body.webhook.detail, 'minimal')
    const shown = await a.control('GET', '/v1/notify')
    const everything = JSON.stringify([set.body, shown.body, a.audit(), a.vault.db.kv.notify])
    for (const part of ['SECRETPATH', 'QUERYSECRET', '/services/']) {
      assert.ok(!everything.includes(part), `${part} was shown, recorded or stored in clear`)
    }
    assert.deepEqual(a.audit('notify.configured').at(-1).host, 'hooks.example')
    // Removing it narrows what leaves the machine: open.
    a.closeWindow()
    assert.deepEqual((await a.control('DELETE', '/v1/notify')).body, { ok: true, removed: true })
    assert.equal(a.audit('notify.removed').length, 1)
  } finally { await a.stop() }
})

test('the minimal webhook is counts and ids only; one POST per interval', async () => {
  const hook = recorder()
  const a = await startApi({ notifyFetch: hook.fetchImpl })
  try {
    a.vault.setNotifyWebhook({ url: HOOK })
    const s = a.session({ policy: { approval: 'each' } })
    await a.gateway('/p/demo/a?q=QUERYTEXT', { headers: { authorization: `Bearer ${s.placeholder}`, 'av-reason': '<script>x</script>' } })
    await a.control('POST', '/v1/session-requests', { cred: 'demo', reason: '<script>y</script>', paths: [`/x/${s.placeholder}`] })
    await new Promise((r) => setTimeout(r, 50))
    assert.equal(hook.calls.length, 1, 'more than one POST inside the interval')
    assert.ok(a.daemon.notifier.timer, 'the second item is not waiting for the next slot')
    const [call] = hook.calls
    assert.equal(call.url, HOOK)
    assert.equal(call.method, 'POST')
    assert.deepEqual(Object.keys(call.body).sort(), ['event', 'ids', 'kinds', 'open', 'source', 'waiting'])
    assert.equal(call.body.event, 'pending')
    assert.equal(call.body.kinds.request, 1)
    const text = JSON.stringify(call.body)
    for (const part of ['<script>', s.placeholder, 'QUERYTEXT', 'headline', 'GET ']) assert.ok(!text.includes(part), `${part} is in the minimal payload`)
    assert.equal(a.audit('notify.sent').at(-1).host, 'hooks.example')
  } finally { await a.stop() }
})

test('the headline webhook adds the gateway\'s summary, never the agent\'s words', () => {
  const ph = 'av1.abcdefghijklmnopqrstuvwxyz.demo_token.ABCDEFGHIJKLMNOPQRSTUVWX.ABCD'
  const items = [
    { kind: 'request', id: 'ap_1', headline: 'POST api.example.com/repos/x', created_at: '2026-01-01T00:00:00Z' },
    { kind: 'session', id: 'sr_1', headline: cleanHeadline(`session for demo · GET · /x/${ph}\u001b[31m`), created_at: '2026-01-01T00:00:01Z' },
  ]
  const minimal = JSON.parse(webhookPayload(items, 'minimal'))
  assert.equal(minimal.items, undefined)
  assert.ok(!JSON.stringify(minimal).includes('api.example.com'))
  const headline = JSON.parse(webhookPayload(items, 'headline'))
  assert.equal(headline.items.length, 2)
  assert.equal(headline.items[1].headline, 'POST api.example.com/repos/x')
  assert.ok(!JSON.stringify(headline).includes('\u001b'))
  // Bounded at 2 KiB by dropping items, never by cutting JSON.
  const many = Array.from({ length: 50 }, (_, i) => ({ kind: 'request', id: `ap_${i}`, headline: 'x'.repeat(190), created_at: `2026-01-01T00:00:${String(i).padStart(2, '0')}Z` }))
  const big = webhookPayload(many, 'headline')
  assert.ok(Buffer.byteLength(big) <= 2048)
  assert.equal(JSON.parse(big).waiting, 50)
})

test('a test notification is throttled, a failure is recorded once, and no webhook is not found', async () => {
  const hook = recorder()
  const a = await startApi({ notifyFetch: hook.fetchImpl })
  try {
    assert.equal((await a.control('POST', '/v1/notify/test')).status, 404)
    a.vault.setNotifyWebhook({ url: HOOK, detail: 'headline' })
    const first = await a.control('POST', '/v1/notify/test')
    assert.deepEqual(first.body, { sent: true, status: 200 })
    assert.equal(hook.calls[0].body.event, 'test')
    const second = await a.control('POST', '/v1/notify/test')
    assert.equal(second.status, 429)
    assert.equal(second.body.code, 'AV_QUOTA_EXCEEDED')
    assert.equal(hook.calls.length, 1)
    // The endpoint starts failing: recorded by host, once.
    hook.fetchImpl.status = 500
    a.daemon.notifier.lastTest = 0
    assert.deepEqual((await a.control('POST', '/v1/notify/test')).body, { sent: false, status: 500 })
    a.daemon.notifier.lastTest = 0
    await a.control('POST', '/v1/notify/test')
    const failed = a.audit('notify.failed')
    assert.equal(failed.length, 1)
    assert.deepEqual({ host: failed[0].host, reason: failed[0].reason }, { host: 'hooks.example', reason: 'status_500' })
  } finally { await a.stop() }
})
