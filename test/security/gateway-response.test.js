// What comes back from an upstream, and what goes out to one. Each test is an
// upstream that leaks, hangs, crashes the daemon or floods it, or a request
// the proxy frames wrongly on the wire.

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { Readable, PassThrough } from 'node:stream'
import { gzipSync } from 'node:zlib'
import { Pipeline } from '../../src/daemon/pipeline.js'
import { setup, cleanup, drain, SECRET } from './gateway-helpers.js'

afterEach(cleanup)

const streaming = (source, extra = {}) => async () => ({
  status: 200, headers: { 'content-type': 'text/event-stream', ...extra }, res: source,
})

/** Fail the test if anything throws outside a promise while `fn` runs. */
async function noUncaught(fn) {
  const seen = []
  const record = (e) => seen.push(e)
  process.on('uncaughtException', record)
  try {
    const out = await fn()
    await new Promise((r) => setTimeout(r, 50))
    return { out, seen }
  } finally {
    process.off('uncaughtException', record)
  }
}

/** The first chunk a stream yields, or 'timeout'. */
async function first(stream, ms = 1000) {
  const it = stream[Symbol.asyncIterator]()
  return Promise.race([it.next().then((r) => r.value?.toString()), new Promise((r) => setTimeout(() => r('timeout'), ms))])
}

// -------------------------------------------------------- response headers

test('a secret in a response header NAME does not reach the agent', async () => {
  const hex = Buffer.from(SECRET).toString('hex')
  const s = setup({
    respond: () => ({
      status: 200,
      headers: {
        'content-type': 'text/plain', 'x-ratelimit-remaining': '41',
        [`x-leak-${hex}`]: '1',
        // Node lowercases names, so this is how a reflected secret arrives.
        [`x-echo-${SECRET.toLowerCase()}`]: '1',
      },
      body: Buffer.from('ok'),
    }),
  })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.equal(res.status, 200)
  for (const name of Object.keys(res.headers)) {
    assert.ok(!name.includes(hex), `${name} carries the secret in hex`)
    assert.ok(!name.includes(SECRET.toLowerCase()), `${name} carries the secret`)
  }
  assert.equal(res.headers['x-ratelimit-remaining'], '41', 'an ordinary header must survive')
  assert.ok(Number(res.headers['av-redacted']) >= 2)
})

// --------------------------------------------------------- event streams

const anthropic = (t) => `event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":${JSON.stringify(t)}}}\n\n`

test('a secret split across the text of two Anthropic-shaped events is cut', async () => {
  const s = setup({
    fetchImpl: streaming(Readable.from([anthropic(SECRET.slice(0, 14)), anthropic(SECRET.slice(14)), 'event: message_stop\ndata: {"type":"message_stop"}\n\n'].map((c) => Buffer.from(c)))),
  })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  const body = await drain(res.stream)
  const text = [...body.matchAll(/"text":"([^"]*)"/g)].map((m) => m[1]).join('')
  assert.ok(!text.includes(SECRET), 'the client reassembled the secret')
  assert.match(body, /AV_UNSCANNABLE/)
})

test('an ordinary Anthropic-shaped stream passes through untouched', async () => {
  const events = ['Hello', ', world. ', 'The disk-usage_by_repository report ', 'is ready.'].map(anthropic)
  events.push('event: message_stop\ndata: {"type":"message_stop"}\n\n')
  const s = setup({ fetchImpl: streaming(Readable.from(events.map((c) => Buffer.from(c)))) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.equal(await drain(res.stream), events.join(''))
})

test('a CRLF-framed stream is released event by event', async () => {
  const src = new PassThrough()
  const s = setup({ fetchImpl: streaming(src) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  // Followed by the start of an event that has not ended, so the scrubber's
  // usual hold-back is not what keeps the first one in.
  src.write(`data: one\r\n\r\ndata: ${'x'.repeat(1000)}`)
  const got = await first(res.stream)
  assert.notEqual(got, 'timeout', 'nothing reached the agent until the upstream closed')
  assert.match(got, /data: one/)
  src.end()
})

test('a bare-CR stream is released, and a CRLF split across chunks is one line end', async () => {
  const s = setup({ fetchImpl: streaming(Readable.from(['data: a\r\r', 'data: b\r', '\n\r', '\ndata: c\n\n'].map((c) => Buffer.from(c)))) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.equal(await drain(res.stream), 'data: a\n\ndata: b\n\ndata: c\n\n')
})

test('an event that never ends is cut instead of held without bound', async () => {
  async function* endless() {
    yield Buffer.from('data: ')
    for (let i = 0; i < 18; i++) yield Buffer.alloc(1024 * 1024, 'a')
  }
  const s = setup({ fetchImpl: streaming(Readable.from(endless())) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  const body = await drain(res.stream)
  assert.ok(/AV_UNSCANNABLE/.test(body), 'the stream was not cut')
  assert.ok(body.length < 1024 * 1024, `${body.length} bytes went out unscanned`)
})

test('a compressed stream is bounded by what it decodes to, not per chunk', async () => {
  const event = `data: ${'a'.repeat(1024 * 1024)}\n\n`
  const bomb = gzipSync(Buffer.from(event.repeat(66)))
  assert.ok(bomb.length < 1024 * 1024)
  // In small slices, so no single write to zlib decodes past its own
  // per-call limit: that limit is not what is under test.
  const slices = []
  for (let i = 0; i < bomb.length; i += 1024) slices.push(bomb.subarray(i, i + 1024))
  const s = setup({ fetchImpl: streaming(Readable.from(slices), { 'content-encoding': 'gzip' }) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  let total = 0
  let cut = false
  // Only a flag is kept: an assertion that printed a 1 MiB chunk would be
  // too large for the mutation check to read back.
  for await (const c of res.stream) { total += c.length; cut = /AV_UNSCANNABLE/.test(c.toString()) }
  assert.ok(cut, 'the stream was not cut')
  assert.ok(total <= 64 * 1024 * 1024 + 4096, `${total} bytes streamed out of a ${bomb.length}-byte body`)
})

test('an ordinary compressed stream still streams in full', async () => {
  const events = ['data: one\n\n', 'data: two\n\n']
  const s = setup({ fetchImpl: streaming(Readable.from([gzipSync(Buffer.from(events.join('')))]), { 'content-encoding': 'gzip' }) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.equal(await drain(res.stream), events.join(''))
})

test('a compressed stream whose source errors neither crashes the daemon nor throws at the writer', async () => {
  const src = new PassThrough()
  const s = setup({ fetchImpl: streaming(src, { 'content-encoding': 'gzip' }) })
  const { out, seen } = await noUncaught(async () => {
    const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
    src.write(gzipSync(Buffer.from('data: one\n\n')).subarray(0, 15))
    setTimeout(() => src.destroy(Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' })), 20)
    return drain(res.stream)
  })
  assert.deepEqual(seen.map((e) => e.message), [], 'the error escaped as an uncaught exception')
  assert.match(out, /AV_UNSCANNABLE/)
})

test('an uncompressed stream that errors before anyone reads it does not crash the daemon', async () => {
  const src = new PassThrough()
  const s = setup({ fetchImpl: streaming(src) })
  const { out, seen } = await noUncaught(async () => {
    const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
    src.destroy(Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }))
    await new Promise((r) => setTimeout(r, 20))
    return drain(res.stream)
  })
  assert.deepEqual(seen.map((e) => e.message), [])
  assert.match(out, /AV_UNSCANNABLE/)
})

test('a compressed stream from a real upstream that resets mid-body ends instead of hanging', async () => {
  const up = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'content-encoding': 'gzip' })
    res.write(gzipSync(Buffer.from('data: one\n\n')).subarray(0, 15))
    setTimeout(() => res.socket.destroy(), 50)
  })
  await new Promise((r) => up.listen(0, '127.0.0.1', r))
  try {
    const port = up.address().port
    const s = setup({ connector: { host: `127.0.0.1:${port}`, scheme: 'http' }, hosts: ['127.0.0.1'] })
    const real = new Pipeline(s.vault, { allowedHosts: new Set(['127.0.0.1']) })
    const res = await real.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
    assert.equal(res.status, 200)
    const out = await Promise.race([drain(res.stream), new Promise((r) => setTimeout(() => r('hung'), 5000))])
    assert.notEqual(out, 'hung', 'the agent waited forever on a stream the upstream had dropped')
    assert.match(out, /AV_UNSCANNABLE/)
  } finally {
    up.close()
  }
})

// A secret's second half with a long tail after it, as the event that ends it.
const split = [anthropic(SECRET.slice(0, 14)), anthropic(SECRET.slice(14) + 'x'.repeat(2000))]
const textOf = (body) => [...body.matchAll(/^data: (.*)$/gm)].map((m) => { try { return JSON.parse(m[1]).delta?.text ?? '' } catch { return '' } }).join('')

test('a split secret is caught when the event that finishes it is long', async () => {
  for (const compressed of [false, true]) {
    const bytes = Buffer.from(split.join(''))
    const s = setup({ fetchImpl: streaming(Readable.from([compressed ? gzipSync(bytes) : bytes]), compressed ? { 'content-encoding': 'gzip' } : {}) })
    const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
    const body = await drain(res.stream)
    assert.ok(!textOf(body).includes(SECRET), `the client reassembled the secret (gzip: ${compressed})`)
    assert.match(body, /AV_UNSCANNABLE/)
  }
})

test('a split secret is caught in plain-text events when the event that finishes it is long', async () => {
  const s = setup({ fetchImpl: streaming(Readable.from([`data: ${SECRET.slice(0, 14)}\n\n`, `data: ${SECRET.slice(14)}${'x'.repeat(2000)}\n\n`].map((c) => Buffer.from(c)))) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  const body = await drain(res.stream)
  assert.ok(!body.replace(/\n\ndata: |^data: /g, '').includes(SECRET), 'the client reassembled the secret')
  assert.match(body, /AV_UNSCANNABLE/)
})

test('an ordinary stream of long events passes through untouched, compressed or not', async () => {
  const events = Array.from({ length: 6 }, (_, i) => anthropic(`${'lorem ipsum dolor sit amet '.repeat(100)}${i}`))
  for (const compressed of [false, true]) {
    const bytes = Buffer.from(events.join(''))
    const s = setup({ fetchImpl: streaming(Readable.from([compressed ? gzipSync(bytes) : bytes]), compressed ? { 'content-encoding': 'gzip' } : {}) })
    const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
    assert.equal(await drain(res.stream), events.join(''))
  }
})

test('a stream with more key paths than are tracked is cut, not forgotten', async () => {
  const many = `data: ${JSON.stringify(Object.fromEntries(Array.from({ length: 1025 }, (_, i) => [`k${i}`, 'metadata'])))}\n\n`
  const s = setup({ fetchImpl: streaming(Readable.from([anthropic(SECRET.slice(0, 14)), many, anthropic(SECRET.slice(14))].map((c) => Buffer.from(c)))) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  const body = await drain(res.stream)
  assert.ok(!textOf(body).includes(SECRET), 'the client reassembled the secret')
  assert.match(body, /AV_UNSCANNABLE/)
  assert.match(body, /JSON key paths/)
})

test('an ordinary stream over many key paths, below the limit, passes through', async () => {
  const events = [
    anthropic('Hello'),
    ...Array.from({ length: 5 }, (_, n) => `data: ${JSON.stringify(Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`m${n}_${i}`, 'value'])))}\n\n`),
    anthropic(' world'),
  ]
  const s = setup({ fetchImpl: streaming(Readable.from(events.map((c) => Buffer.from(c)))) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.equal(await drain(res.stream), events.join(''))
})

// A key path built by joining keys with `.` named two places as one: `a.b` is
// both {"a":{"b":…}} and {"a.b":…}. A value at the other one was appended to
// the run between the halves of a secret, and no run held the secret whole.
const ev = (o) => `data: ${JSON.stringify(o)}\n\n`
const half = [SECRET.slice(0, 14), SECRET.slice(14)]
const collisions = [
  { name: 'a dotted key beside the nested path', read: (o) => o.a?.b, events: [ev({ a: { b: half[0] }, 'a.b': 'x' }), ev({ a: { b: half[1] } })] },
  { name: 'keys that are literally "."', read: (o) => o['.']?.['.'], events: [ev({ '.': { '.': half[0] }, '...': 'x' }), ev({ '.': { '.': half[1] } })] },
  { name: 'an empty key above a nested one', read: (o) => o['']?.x, events: [ev({ '': { x: half[0] }, x: 'y' }), ev({ '': { x: half[1] } })] },
  { name: 'a key ending in a dot', read: (o) => o.a?.[''], events: [ev({ a: { '': half[0] }, 'a.': 'x' }), ev({ a: { '': half[1] } })] },
  { name: 'an array index beside a "0" key', read: (o) => (Array.isArray(o.c) ? o.c[0] : undefined), events: [ev({ c: [half[0]] }), ev({ c: { 0: 'x' } }), ev({ c: [half[1]] })] },
]

test('a secret split across events is caught however the keys are spelled, compressed or not', async () => {
  for (const { name, read, events } of collisions) {
    for (const compressed of [false, true]) {
      const bytes = Buffer.from(events.join(''))
      const s = setup({ fetchImpl: streaming(Readable.from([compressed ? gzipSync(bytes) : bytes]), compressed ? { 'content-encoding': 'gzip' } : {}) })
      const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
      const body = await drain(res.stream)
      const text = [...body.matchAll(/^data: (.*)$/gm)].map((m) => { try { return read(JSON.parse(m[1])) ?? '' } catch { return '' } }).join('')
      assert.ok(!text.includes(SECRET), `${name}: the client reassembled the secret (gzip: ${compressed})`)
      assert.match(body, /AV_UNSCANNABLE/, `${name} (gzip: ${compressed})`)
    }
  }
})

test('an ordinary stream with dotted, empty and numeric keys passes through untouched, compressed or not', async () => {
  const events = [
    ev({ choices: [{ index: 0, delta: { content: 'Hello' } }], 'x.request.id': 'req_1', '.': 'dot', '': 'empty' }),
    ev({ choices: [{ index: 0, delta: { content: ' world' } }], meta: { 0: 'zero', 'a.b': 'c' } }),
    ev({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }),
  ]
  for (const compressed of [false, true]) {
    const bytes = Buffer.from(events.join(''))
    const s = setup({ fetchImpl: streaming(Readable.from([compressed ? gzipSync(bytes) : bytes]), compressed ? { 'content-encoding': 'gzip' } : {}) })
    const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
    assert.equal(await drain(res.stream), events.join(''))
  }
})

// A client does not put text back together by key path alone. The Anthropic
// SDK gathers `delta.text` by the event's `index`, OpenAI's by
// `choices[].index` and `tool_calls[].index`, the Responses API by
// `output_index` and `content_index`. An event at another index between the
// halves landed in the same run here, and the client never saw it there.
const ant = (i, t) => `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: i, delta: { type: 'text_delta', text: t } })}\n\n`
const oai = (i, t) => ev({ id: 'c1', choices: [{ index: i, delta: { content: t } }] })
const tool = (i, t) => ev({ id: 'c1', choices: [{ index: 0, delta: { tool_calls: [{ index: i, function: { arguments: t } }] } }] })
const resp = (o, c, t, extra = {}) => ev({ type: 'response.output_text.delta', output_index: o, content_index: c, delta: t, ...extra })
const regrouped = [
  { name: 'Anthropic blocks', group: (o) => [o.index, o.delta?.text], events: [ant(0, half[0]), ant(1, 'x'), ant(0, half[1])] },
  { name: 'OpenAI choices', group: (o) => [o.choices[0].index, o.choices[0].delta.content], events: [oai(0, half[0]), oai(1, 'x'), oai(0, half[1])] },
  { name: 'OpenAI tool calls', group: (o) => { const c = o.choices[0].delta.tool_calls[0]; return [c.index, c.function.arguments] }, events: [tool(0, half[0]), tool(1, 'x'), tool(0, half[1])] },
  { name: 'Responses content parts', group: (o) => [`${o.output_index}/${o.content_index}`, o.delta], events: [resp(0, 0, half[0]), resp(0, 1, 'x'), resp(0, 0, half[1])] },
  // The client ignores `retry_index`; the upstream varies it so that a run kept by every index never joins the halves.
  { name: 'a decoy index the client ignores', group: (o) => [o.output_index, o.delta], events: [resp(0, 0, half[0], { retry_index: 1 }), resp(1, 0, 'x', { retry_index: 2 }), resp(0, 0, half[1], { retry_index: 3 })] },
  // Python's json.loads takes NaN and Infinity, and the Python SDKs read events with it. JSON.parse refused the payload and the per-path view skipped it.
  { name: 'NaN beside the text', group: (o) => [0, o.delta?.text], parse: (t) => JSON.parse(t.replace(/-?\b(?:NaN|Infinity)\b/g, 'null')), events: [`data: {"index":0,"delta":{"type":"text_delta","text":"${half[0]}"},"p":NaN}\n\n`, `data: {"index":0,"delta":{"type":"x","text":"${half[1]}"},"p":-Infinity}\n\n`] },
]

test('a secret split across events is caught however the client regroups them, compressed or not', async () => {
  for (const { name, group, events, parse = JSON.parse } of regrouped) {
    for (const compressed of [false, true]) {
      const bytes = Buffer.from(events.join(''))
      const s = setup({ fetchImpl: streaming(Readable.from([compressed ? gzipSync(bytes) : bytes]), compressed ? { 'content-encoding': 'gzip' } : {}) })
      const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
      const body = await drain(res.stream)
      const groups = {}
      for (const m of body.matchAll(/^data: (.*)$/gm)) {
        try { const [k, t] = group(parse(m[1])); if (typeof t === 'string') groups[k] = (groups[k] ?? '') + t } catch { /* not an event the client reads */ }
      }
      assert.ok(!Object.values(groups).some((t) => t.includes(SECRET)), `${name}: the client reassembled the secret (gzip: ${compressed})`)
      assert.match(body, /AV_UNSCANNABLE/, `${name} (gzip: ${compressed})`)
    }
  }
})

test('a stream with more index fields over one value than can be combined is cut', async () => {
  const wide = ev({ a_index: 1, b_index: 2, c_index: 3, d_index: 4, e_index: 5, delta: 'hello' })
  const s = setup({ fetchImpl: streaming(Readable.from([Buffer.from(wide)])) })
  const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  const body = await drain(res.stream)
  assert.match(body, /AV_UNSCANNABLE/)
  assert.match(body, /index fields/)
})

test('ordinary multi-block, multi-choice and NaN-bearing streams pass through untouched, compressed or not', async () => {
  const blocks = Array.from({ length: 60 }, (_, i) => [
    `event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: i, content_block: i % 2 ? { type: 'tool_use', id: `toolu_${i}`, name: 'Read', input: {} } : { type: 'text', text: '' } })}\n\n`,
    i % 2
      ? `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: i, delta: { type: 'input_json_delta', partial_json: `{"path":"/tmp/f${i}"}` } })}\n\n`
      : ant(i, `Paragraph ${i}. `),
    `event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: i })}\n\n`,
  ]).flat()
  const choices = Array.from({ length: 40 }, (_, i) => [oai(0, `alpha ${i} `), oai(1, `beta ${i} `), tool(i % 3, `{"n":${i}}`)]).flat()
  const responses = Array.from({ length: 40 }, (_, i) => resp(i % 4, i % 2, `part ${i} `, { item_id: `msg_${i % 4}`, sequence_number: i }))
  const nan = ['data: {"index":0,"delta":{"text":"Hello"},"score":NaN}\n\n', 'data: {"index":0,"delta":{"text":" world"},"score":Infinity}\n\n']
  for (const events of [blocks, choices, responses, nan]) {
    for (const compressed of [false, true]) {
      const bytes = Buffer.from(events.join(''))
      const s = setup({ fetchImpl: streaming(Readable.from([compressed ? gzipSync(bytes) : bytes]), compressed ? { 'content-encoding': 'gzip' } : {}) })
      const res = await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
      assert.equal(await drain(res.stream), events.join(''))
    }
  }
})

/** A real upstream that sends `body`, and resets the socket part way if `reset`. */
async function bufferedUpstream(reset, fn) {
  const up = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': reset ? '1000' : '7' })
    res.write('partial')
    if (reset) setTimeout(() => res.socket.destroy(), 30)
    else res.end()
  })
  await new Promise((r) => up.listen(0, '127.0.0.1', r))
  try {
    const s = setup({ connector: { host: `127.0.0.1:${up.address().port}`, scheme: 'http' }, hosts: ['127.0.0.1'] })
    const real = new Pipeline(s.vault, { allowedHosts: new Set(['127.0.0.1']) })
    return await fn(s, await real.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] })))
  } finally {
    up.closeAllConnections()
    up.close()
  }
}

test('a buffered upstream that resets mid-body is an upstream failure, and the use is not refunded', async () => {
  await bufferedUpstream(true, (s, res) => {
    assert.equal(res.status, 502)
    assert.equal(JSON.parse(res.body).code, 'AV_UPSTREAM_UNREACHABLE')
    assert.ok(!res.body.toString().includes('partial'))
    assert.deepEqual(Object.values(s.vault.db.placeholders).map((r) => r.uses), [1])
  })
})

test('a buffered upstream that completes its body is answered as before', async () => {
  await bufferedUpstream(false, (s, res) => {
    assert.equal(res.status, 200)
    assert.equal(res.body.toString(), 'partial')
  })
})

// --------------------------------------------------------- request framing

test('a request body goes out with a Content-Length that matches it', async () => {
  const s = setup({ sites: { key: ['header:x-key', 'json:/token'] } })
  await s.pipeline.handle(s.request({ method: 'POST', headers: [...s.request().headers, ['x-key', s.ph()], ['content-length', '5']], body: Buffer.from('hello') }))
  assert.equal(s.sent[0].headers['content-length'], '5')
  // Substitution changes the length; the header follows it.
  const body = JSON.stringify({ token: s.ph() })
  await s.pipeline.handle(s.request({ method: 'POST', headers: [...s.request().headers, ['content-type', 'application/json'], ['content-length', String(body.length)]], body: Buffer.from(body) }))
  assert.equal(s.sent[1].headers['content-length'], String(Buffer.byteLength(s.sent[1].body)))
  assert.equal(s.sent[1].body, JSON.stringify({ token: SECRET }))
  // No body, no length.
  await s.pipeline.handle(s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] }))
  assert.equal(s.sent[2].headers['content-length'], undefined)
})

test('a DELETE with a body reaches a real upstream framed', async () => {
  const seen = []
  const up = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seen.push({ length: req.headers['content-length'], body: Buffer.concat(chunks).toString() })
      res.end('ok')
    })
  })
  await new Promise((r) => up.listen(0, '127.0.0.1', r))
  try {
    const s = setup({ connector: { host: `127.0.0.1:${up.address().port}`, scheme: 'http' }, hosts: ['127.0.0.1'], methods: ['DELETE'] })
    const real = new Pipeline(s.vault, { allowedHosts: new Set(['127.0.0.1']) })
    const res = await real.handle(s.request({ method: 'DELETE', headers: [...s.request().headers, ['x-key', s.ph()]], body: Buffer.from('hello') }))
    assert.equal(res.status, 200)
    assert.deepEqual(seen, [{ length: '5', body: 'hello' }])
  } finally {
    up.close()
  }
})
