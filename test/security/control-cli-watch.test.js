import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { createServer } from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { watchApprovals } from '../../src/cli/watch.js'

function harness(options = {}) {
  const signals = new EventEmitter(), timers = new Map(), requests = [], calls = [], launches = []
  let stdout = '', stderr = '', nextTimer = 0
  const deps = {
    signals, platform: 'darwin',
    stdout: { write: (s) => { stdout += s } }, stderr: { write: (s) => { stderr += s } },
    setTimeout(fn, delay) { const id = ++nextTimer; timers.set(id, { fn, delay }); return id },
    clearTimeout(id) { timers.delete(id) },
    execFile(...args) { calls.push(args) },
    spawn(...args) { launches.push(args); return { on() {}, unref() {} } },
    request(config, callback) {
      const req = new EventEmitter()
      req.end = () => {}
      req.destroy = () => { req.destroyed = true }
      requests.push({ config, callback, req })
      return req
    },
  }
  const done = watchApprovals({ socketPath: '/test.sock', ...options, deps: { ...deps, ...options.deps } })
  const respond = (statusCode = 200) => {
    const res = new PassThrough()
    res.statusCode = statusCode
    requests.at(-1).callback(res)
    return res
  }
  const tick = (delay) => {
    const entry = [...timers].find(([, timer]) => timer.delay === delay)
    assert.ok(entry, `expected timer ${delay}`)
    timers.delete(entry[0]); entry[1].fn()
  }
  return { done, signals, timers, requests, calls, launches, respond, tick,
    output: () => stdout, errors: () => stderr, stop: () => signals.emit('SIGINT') }
}
const frame = (event, data) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`
const entry = (id, extra = {}) => ({ kind: 'request', id, headline: 'POST example.com/repos', created_at: 123, ...extra })

test('snapshot and pending deduplicate IDs across reconnects; SIGINT cleans resources', async () => {
  const h = harness({ notify: false, open: true })
  const res = h.respond()
  assert.equal(h.requests[0].config.path, '/v1/pending/stream')
  assert.equal(h.requests[0].config.socketPath, '/test.sock')
  assert.equal(h.requests[0].config.method, 'GET')
  res.write(frame('snapshot', { items: [entry('one')] }))
  res.write(frame('pending', entry('one')))
  res.emit('end')
  h.tick(1000)
  h.respond().write(frame('snapshot', { items: [entry('one'), entry('two', { kind: 'session' })] }))
  assert.equal(h.output(), 'held one  POST example.com/repos\nsession requested two  POST example.com/repos\n')
  assert.equal(h.launches.length, 1)
  assert.equal(h.launches[0][1].at(-1), 'ui')
  h.stop()
  assert.equal(await h.done, 0)
  assert.equal(h.signals.listenerCount('SIGINT'), 0)
  assert.equal(h.timers.size, 0)
  assert.ok(h.requests.at(-1).req.destroyed)
})

test('JSON emits one envelope per SSE event, including fragmented multiline CRLF frames, without desktop effects', async () => {
  const events = []
  const h = harness({ json: true, open: true, onEvent: (e) => events.push(e) })
  const res = h.respond()
  res.write(': ping\r\n\r\nevent: pending\r\ndata: {"id":"one",\r\n')
  res.write('data: "kind":"session","headline":"café"}\r\n\r\n')
  res.write('event: pending\ndata: invalid\n\n')
  res.write(frame('snapshot', { items: [] }))
  assert.deepEqual(h.output().trim().split('\n').map(JSON.parse), [
    { ok: true, data: { event: 'pending', id: 'one', kind: 'session', headline: 'café' } },
    { ok: true, data: { event: 'snapshot', items: [] } },
  ])
  assert.equal(events.length, 2)
  assert.equal(h.calls.length, 0)
  assert.equal(h.launches.length, 0)
  h.stop(); await h.done
})

test('notifications use argv, strip unsafe text, coalesce, and warn only once', async () => {
  const h = harness()
  const res = h.respond()
  res.write(frame('pending', entry('one', {
    headline: 'POST example.com/path?secret=bad\n\u001b av1.fake_token " & do shell script',
    reason: '<script>phish</script>', body: 'body-secret',
  })))
  res.write(frame('pending', entry('two')))
  res.write(frame('pending', entry('three')))
  assert.equal(h.calls.length, 1)
  const [binary, args, callback] = h.calls[0]
  assert.equal(binary, 'osascript')
  assert.equal(args.at(-2), '--')
  const text = args.at(-1)
  assert.ok(text.startsWith('Held request:'))
  assert.ok(text.length <= 120)
  assert.doesNotMatch(text, /secret|av1\.|script>phish|body-secret|[\n\x1b]/)
  assert.ok(args.filter((_, i) => args[i - 1] === '-e').every((script) => !script.includes(text)))
  callback(new Error('missing'))
  h.tick(10000)
  assert.equal(h.calls.length, 2)
  assert.match(h.calls[1][1].at(-1), /and 1 more/)
  h.calls[1][2](new Error('missing'))
  assert.equal(h.errors().trim().split('\n').length, 1)
  h.stop(); await h.done
})

test('quiet suppresses human output; Linux notifications and no-notify work', async () => {
  const h = harness({ quiet: true, deps: { platform: 'linux' } })
  h.respond().write(frame('pending', entry('one')))
  assert.equal(h.output(), '')
  assert.equal(h.calls[0][0], 'notify-send')
  assert.equal(h.calls[0][1][0], 'agent-vault')
  h.stop(); await h.done
  const off = harness({ notify: false })
  off.respond().write(frame('pending', entry('one')))
  assert.equal(off.calls.length, 0)
  off.stop(); await off.done
})

test('startup connection errors reject with exit 3 and leave no listeners or timers', async () => {
  const h = harness()
  h.requests[0].req.emit('error', new Error('ENOENT'))
  await assert.rejects(h.done, { exit: 3 })
  assert.equal(h.signals.listenerCount('SIGINT'), 0)
  assert.equal(h.timers.size, 0)
})

test('daemon refusals preserve the registered exit code', async () => {
  const h = harness()
  h.respond(429).end(JSON.stringify({ code: 'AV_QUOTA_EXCEEDED', detail: 'subscriber limit' }))
  await assert.rejects(h.done, { exit: 6, message: 'subscriber limit' })
})

test('an old daemon returns the version-skew exit and restart hint', async () => {
  const h = harness()
  h.respond(404).end(JSON.stringify({ code: 'AV_NOT_FOUND', detail: 'no control route GET /v1/pending/stream' }))
  await assert.rejects(h.done, { exit: 15, next: 'restart the daemon you started with: agent-vault daemon' })
})

test('reconnection backoff caps at 30 seconds and SIGINT cancels a pending retry', async () => {
  const h = harness()
  h.respond().emit('end')
  for (const delay of [1000, 2000, 4000, 8000, 16000, 30000, 30000]) {
    h.tick(delay)
    h.requests.at(-1).req.emit('error', new Error('offline'))
  }
  h.stop(); await h.done
  assert.equal(h.timers.size, 0)
})

test('real Unix socket SSE decodes UTF-8 split across chunks and closes on SIGINT', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'av-watch-'))
  const socketPath = join(dir, 'control.sock')
  const server = createServer((req, res) => {
    assert.equal(req.url, '/v1/pending/stream')
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    const bytes = Buffer.from(frame('pending', entry('real', { headline: 'POST café.test/path' })))
    const split = bytes.indexOf(Buffer.from('é')) + 1
    res.write(bytes.subarray(0, split))
    setImmediate(() => res.write(bytes.subarray(split)))
  })
  t.after(async () => { server.closeAllConnections(); await new Promise((r) => server.close(r)); await rm(dir, { recursive: true, force: true }) })
  await new Promise((r) => server.listen(socketPath, r))
  const signals = new EventEmitter()
  let output = ''
  await watchApprovals({ socketPath, notify: false,
    onEvent() { signals.emit('SIGINT') },
    deps: { signals, stdout: { write(s) { output += s } } },
  })
  assert.match(output, /café\.test/)
  assert.equal(signals.listenerCount('SIGINT'), 0)
})
