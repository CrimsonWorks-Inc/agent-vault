// Wave 1 landed on two branches with disjoint files, and two of its fixes
// only hold if both halves are present together. Each half was tested on its
// own branch; these tests run them as one daemon.
//
// 1. An approval that has run stays spent. fix-control gated the deny route
//    and stopped the control API returning an approval's cached result;
//    fix-gateway made the pipeline refuse to decide anything not pending.
//    Either alone left a path: an ungated deny on a re-decidable approval, or
//    a gated one that still rewrote a spent approval's state.
// 2. One bad upstream costs one request. fix-gateway ends a failing event
//    stream instead of letting it throw or hang; fix-control guards the
//    process against whatever still escapes.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { operationFor } from '../../src/ui/webauthn.js'
import { startDaemon, makeAuthenticator, enrol, signed, PASSPHRASE } from './fix-control-helpers.js'

let d, auth, token, placeholder, upstreamHits = 0, n = 0

const gateway = (method, path, body, ph = placeholder) => fetch(`http://127.0.0.1:${d.daemon.gatewayPort}${path}`, {
  method,
  headers: { 'av-session': token, authorization: `Bearer ${ph}` },
  body,
})

const approvalOf = (id) => [...d.daemon.pipeline.approvals.values()].find((a) => a.id === id)

/** Nothing a refusal sends back may carry the response the request got. */
function assertNoResult(body) {
  const text = JSON.stringify(body)
  assert.ok(!text.includes('"result"'), text)
  assert.ok(!text.includes('av-placeholder-next'), text)
  assert.ok(!text.includes('ran-ok'), text)
}

/** A write held for approval, granted by a signature, then run: a spent approval. */
async function spent() {
  const path = `/p/demo/things/${++n}`
  const first = await gateway('POST', path, 'x')
  assert.equal(first.status, 202, await first.text())
  const id = first.headers.get('av-approval-id')
  const presence = await signed(d.control, auth, operationFor('approval.approve', { id, granted: true }))
  const ok = await d.control('POST', '/v1/approvals', { id, granted: true, presence })
  assert.equal(ok.status, 200, JSON.stringify(ok.body))
  const ran = await gateway('POST', path, 'x')
  assert.equal(ran.status, 200, await ran.text())
  assert.ok(ran.headers.get('av-placeholder-next'), 'the one-use placeholder was spent and has a successor')
  placeholder = ran.headers.get('av-placeholder-next')
  assert.equal(approvalOf(id).state, 'consumed')
  assert.ok(approvalOf(id).result, 'the response is held for a replay')
  return { id, path }
}

/** Run `fn` with a passphrase window open, as the CLI would after a prompt. */
async function inWindow(fn) {
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  try { return await fn() } finally { d.daemon.presenceGraceUntil = 0 }
}

before(async () => {
  d = await startDaemon({ passphrase: PASSPHRASE })
  auth = makeAuthenticator()
  enrol(d.vault, auth)
  d.daemon.pipeline.upstream = async () => {
    upstreamHits++
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ran-ok') }
  }
  const s = await inWindow(() => d.control('POST', '/v1/sessions', {
    cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], approval: 'on-write', uses: 1,
  }))
  assert.equal(s.status, 200, JSON.stringify(s.body))
  token = s.body.token
  placeholder = s.body.placeholder
})
after(() => d?.stop())

// ------------------------------------------------- a spent approval stays spent

test('denying a spent approval still needs the human, and changes nothing without one', async () => {
  const { id } = await spent()
  const res = await d.control('POST', '/v1/approvals', { id, granted: false })
  assert.equal(res.status, 401, JSON.stringify(res.body))
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')
  assertNoResult(res.body)
  assert.equal(approvalOf(id).state, 'consumed')
})

test('a spent approval cannot be denied even with presence, and the refusal hands back nothing', async () => {
  const { id } = await spent()
  for (const attempt of [
    async () => d.control('POST', '/v1/approvals', {
      id, granted: false, presence: await signed(d.control, auth, operationFor('approval.deny', { id, granted: false })),
    }),
    () => inWindow(() => d.control('POST', '/v1/approvals', { id, granted: false })),
  ]) {
    const res = await attempt()
    assert.equal(res.status, 403, JSON.stringify(res.body))
    assert.equal(res.body.code, 'AV_POLICY_DENIED')
    assertNoResult(res.body)
    assert.equal(approvalOf(id).state, 'consumed')
  }
})

test('a spent approval cannot be granted again, so its write runs once', async () => {
  const { id, path } = await spent()
  const hits = upstreamHits
  const presence = await signed(d.control, auth, operationFor('approval.approve', { id, granted: true }))
  const res = await d.control('POST', '/v1/approvals', { id, granted: true, presence })
  assert.equal(res.status, 403, JSON.stringify(res.body))
  assertNoResult(res.body)
  assert.equal(approvalOf(id).state, 'consumed')
  const again = await gateway('POST', path, 'x')
  assert.equal(again.headers.get('av-replayed'), 'true', 'the resend replays; it does not run')
  assert.equal(upstreamHits, hits, 'one human decision executed the write twice')
})

test('a bulk decision skips a spent approval, both ways, and reports no result', async () => {
  const { id } = await spent()
  for (const granted of [false, true]) {
    const decisions = [{ id, kind: 'request', granted }]
    const presence = await signed(d.control, auth, operationFor('pending.decide_many', { decisions }))
    const res = await d.control('POST', '/v1/pending/decide-many', { decisions, presence })
    assert.equal(res.status, 200, JSON.stringify(res.body))
    assert.equal(res.body.decided[0].outcome, 'skipped')
    assertNoResult(res.body)
    assert.equal(approvalOf(id).state, 'consumed')
  }
})

test('internally, deciding a spent approval throws and leaves it spent', async () => {
  const { id } = await spent()
  for (const granted of [false, true]) {
    let returned = null
    assert.throws(() => { returned = d.daemon.pipeline.decideApproval(id, granted) }, (e) => e.code === 'AV_POLICY_DENIED')
    assert.equal(returned, null)
    assert.equal(approvalOf(id).state, 'consumed')
  }
})

test('a spent approval set aside for a new ask cannot be decided either', async () => {
  const { id, path } = await spent()
  // The replay window closed: the resend is a new request that asks again,
  // and the spent one is kept under a key no request hashes to.
  approvalOf(id).result = null
  const resend = await gateway('POST', path, 'x')
  assert.equal(resend.status, 202, await resend.text())
  assert.notEqual(resend.headers.get('av-approval-id'), id)
  const res = await inWindow(() => d.control('POST', '/v1/approvals', { id, granted: true }))
  assert.equal(res.status, 403, JSON.stringify(res.body))
  assertNoResult(res.body)
  assert.equal(approvalOf(id).state, 'consumed')
})

test('the control API strips a cached result even if the pipeline hands one back', async () => {
  // Two layers hold this: the pipeline returns only approvals that were
  // pending, which have no result yet, and the control API drops `result`
  // from whatever it is given. With the first in place the second is never
  // reached, so stand in for a pipeline that regressed and check it alone.
  const { id } = await spent()
  const leaked = { ...approvalOf(id), result: { status: 200, headers: { 'av-placeholder-next': 'avph_leak' }, body: 'ran-ok' } }
  const pipeline = d.daemon.pipeline
  const { decideApproval, pendingApprovals } = pipeline
  pipeline.decideApproval = () => leaked
  pipeline.pendingApprovals = () => [leaked]
  try {
    const single = await inWindow(() => d.control('POST', '/v1/approvals', { id, granted: false }))
    assert.equal(single.status, 200, JSON.stringify(single.body))
    assertNoResult(single.body)
    const decisions = [{ id, kind: 'request', granted: false }]
    const bulk = await inWindow(() => d.control('POST', '/v1/pending/decide-many', { decisions }))
    assert.equal(bulk.status, 200, JSON.stringify(bulk.body))
    assert.equal(bulk.body.decided[0].outcome, 'decided')
    assertNoResult(bulk.body.decided[0].result) // the item's `result` is the approval view itself
    const listed = await d.control('GET', '/v1/approvals')
    assert.equal(listed.status, 200, JSON.stringify(listed.body))
    assertNoResult(listed.body)
  } finally {
    Object.assign(pipeline, { decideApproval, pendingApprovals })
  }
})

// -------------------------------------- one bad upstream, one request, no more

// In a child process, because the test runner keeps its own handlers on this
// one, and the process guard is what is under test.
test('a failing event stream neither crashes nor hangs the daemon, and the guard stays the backstop', () => {
  const helpers = new URL('./fix-control-helpers.js', import.meta.url).href
  const script = `
    import { PassThrough } from 'node:stream'
    import { EventEmitter } from 'node:events'
    import { gzipSync } from 'node:zlib'
    const { startDaemon } = await import(${JSON.stringify(helpers)})
    const d = await startDaemon()
    const s = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'] })
    const ask = async (path) => {
      const res = await fetch('http://127.0.0.1:' + d.daemon.gatewayPort + '/p/demo' + path, {
        headers: { 'av-session': s.body.token, authorization: 'Bearer ' + s.body.placeholder },
      })
      const body = await Promise.race([res.text(), new Promise((r) => setTimeout(() => r('HUNG'), 5000))])
      return { status: res.status, body }
    }
    const reset = () => Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' })
    const sse = (src, headers = {}) => ({ status: 200, headers: { 'content-type': 'text/event-stream', ...headers }, res: src })
    const bad = {
      // A compressed stream whose source resets part way through a block.
      '/gzip-reset': () => {
        const src = new PassThrough()
        src.write(gzipSync(Buffer.from('data: one\\n\\n')).subarray(0, 15))
        setTimeout(() => src.destroy(reset()), 20)
        return sse(src, { 'content-encoding': 'gzip' })
      },
      // A plain stream that errors before anyone has read from it.
      '/plain-early': () => {
        const src = new PassThrough()
        src.destroy(reset())
        return sse(src)
      },
      // A plain stream that closes without ending or erroring.
      '/plain-close': () => {
        const src = new PassThrough()
        src.write('data: one\\n\\n')
        setTimeout(() => src.destroy(), 20)
        return sse(src)
      },
      '/ok': () => sse(new PassThrough().end('data: fine\\n\\n')),
    }
    d.daemon.pipeline.upstream = async ({ url }) => bad[new URL(url).pathname]()
    const faults = () => d.vault.audit.read({ limit: 500 }).filter((r) => r.kind === 'daemon.uncaught').length
    const out = { streams: {} }
    for (const path of ['/gzip-reset', '/plain-early', '/plain-close']) out.streams[path] = await ask(path)
    await new Promise((r) => setTimeout(r, 100))
    out.faultsAfterStreams = faults()
    // Something the stream handling does not cover still reaches the guard.
    setImmediate(() => new EventEmitter().emit('error', reset()))
    await new Promise((r) => setTimeout(r, 100))
    out.faultsAfterStray = faults()
    out.status = (await d.control('GET', '/v1/status')).status
    out.ok = await ask('/ok')
    await d.stop()
    console.log(JSON.stringify(out))
  `
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 30_000 })
  assert.equal(r.status, 0, `the daemon process died or hung: ${r.stderr.slice(0, 600)}`)
  const out = JSON.parse(r.stdout.trim().split('\n').pop())
  for (const [path, res] of Object.entries(out.streams)) {
    assert.notEqual(res.body, 'HUNG', `${path}: the agent waited forever on a stream the upstream had dropped`)
    assert.match(res.body, /AV_UNSCANNABLE/, `${path}: the stream ended without saying why`)
  }
  assert.equal(out.faultsAfterStreams, 0, 'a failing stream escaped the pipeline and only the guard caught it')
  assert.equal(out.faultsAfterStray, 1, 'the guard no longer records what escapes')
  assert.equal(out.status, 200, 'the control socket stopped answering')
  assert.equal(out.ok.status, 200)
  assert.match(out.ok.body, /data: fine/, 'the gateway stopped serving after a bad upstream')
})
