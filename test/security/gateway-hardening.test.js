// Response forms that no other suite sent. Each test is an upstream that
// writes a stored secret in a form the agent's client can read back — JSON
// escapes, a content block's starting text, an index that does not match its
// array position or is missing, base64 inside a URL — and asserts the agent
// never gets it. The controls at the end are the ordinary traffic each of
// those checks must leave alone.

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import { gzipSync } from 'node:zlib'
import { setup, cleanup, drain, SECRET } from './gateway-helpers.js'

afterEach(cleanup)

// A base64-style secret: `/` and `+` in the secret itself, and `+` and `/` in
// its own base64 at more than one alignment, so that percent-encoding the
// base64 actually changes it.
const SLASHED = 'Zq7/Bv3+Kd9/Wm2?>Hx5~Lp8sTe'
const SECRETS = [SECRET, SLASHED]

const withKey = (s) => s.request({ headers: [...s.request().headers, ['x-key', s.ph()]] })

/** A pipeline whose upstream answers with `respond`, holding `secret`. */
const buffered = (secret, respond) => setup({ fields: { key: secret }, respond })

/** Every string anywhere in a parsed JSON value. */
const stringsIn = (v) => (typeof v === 'string' ? [v] : v && typeof v === 'object' ? Object.values(v).flatMap(stringsIn) : [])

// ------------------------------------------------------------ JSON escapes

/** `secret` with every `/` written `\/` and every `step`-th other character as `\uXXXX`. */
function escaped(secret, step, upper = false) {
  return [...secret].map((c, i) => {
    if (c === '/') return '\\/'
    if (i % step !== 0) return c === '"' || c === '\\' ? `\\${c}` : c
    const hex = c.charCodeAt(0).toString(16).padStart(4, '0')
    return `\\u${upper ? hex.toUpperCase() : hex}`
  }).join('')
}

test('a secret in a JSON body with `\\/` and `\\uXXXX` escapes does not reach the agent', async () => {
  for (const secret of SECRETS) {
    const forms = [
      // Only the slashes escaped, as PHP's json_encode and Go's encoder write them.
      secret.replace(/\//g, '\\/'),
      // Slashes and one character in three, in either case of hex.
      escaped(secret, 3),
      escaped(secret, 3, true),
      // Slashes and a single character.
      escaped(secret, 1000),
      // Slashes as \u002f and everything else plain.
      secret.replace(/\//g, '\\u002f'),
    ]
    for (const form of forms) {
      const body = `{"error":{"message":"bad key ${form}","echo":"${form}"}}`
      // The fixture checks itself: a JSON reader gets the secret back out of it.
      assert.ok(stringsIn(JSON.parse(body)).some((t) => t.includes(secret)), `fixture ${form} does not decode to the secret`)
      const s = buffered(secret, () => ({ status: 401, headers: { 'content-type': 'application/json' }, body: Buffer.from(body) }))
      const res = await s.pipeline.handle(withKey(s))
      const got = res.body.toString('latin1')
      const decoded = stringsIn(JSON.parse(got))
      assert.ok(!decoded.some((t) => t.includes(secret)), `${form}: the agent decoded the secret out of ${got}`)
      assert.ok(!got.includes(secret))
    }
  }
})

// --------------------------------------------- event streams, and a client

const streaming = (events, compressed) => async () => {
  const bytes = Buffer.from(events.join(''))
  return {
    status: 200,
    headers: { 'content-type': 'text/event-stream', ...(compressed ? { 'content-encoding': 'gzip' } : {}) },
    res: Readable.from([compressed ? gzipSync(bytes) : bytes]),
  }
}

/**
 * Run `events` through the gateway, identity and gzip, and hand each body to
 * `check`. The body is read byte for byte as latin1, so `sent` is what was
 * sent, read the same way.
 */
async function throughGateway(events, check, secret = SECRET) {
  for (const compressed of [false, true]) {
    const s = setup({ fields: { key: secret }, fetchImpl: streaming(events, compressed) })
    const res = await s.pipeline.handle(withKey(s))
    await check(await drain(res.stream), compressed)
  }
}
const sent = (events) => Buffer.from(events.join('')).toString('latin1')

/** The JSON payload of every event in `body` that parses. */
const payloads = (body) => [...body.matchAll(/^data: (.*)$/gm)].flatMap((m) => { try { return [JSON.parse(m[1])] } catch { return [] } })

/**
 * Text as a client puts it back together: `gather(payload, add)` calls
 * add(group, text) for each piece the client appends, and the result is every
 * group's text.
 */
function reassemble(body, gather) {
  const groups = new Map()
  for (const p of payloads(body)) {
    try { gather(p, (g, t) => { if (typeof t === 'string') groups.set(g, (groups.get(g) ?? '') + t) }) } catch { /* not an event this client reads */ }
  }
  return [...groups.values()]
}

/**
 * The secret is cut out of the stream, whatever the client does with it.
 * `holds(text)` says whether reassembled text gives the secret away.
 */
async function cutWhole(name, events, gather, secret = SECRET, holds = (t) => t.includes(secret)) {
  // A fixture that checks itself: without the gateway, the client does get the secret.
  assert.ok(reassemble(events.join(''), gather).some(holds), `${name}: the fixture does not hand the client the secret`)
  await throughGateway(events, (body, compressed) => {
    assert.ok(!reassemble(body, gather).some(holds), `${name}: the client reassembled the secret (gzip: ${compressed})`)
    assert.ok(!body.includes(secret), `${name}: the secret is in the bytes (gzip: ${compressed})`)
    assert.match(body, /AV_UNSCANNABLE/, `${name} (gzip: ${compressed})`)
  }, secret)
}

const sse = (type, o) => `event: ${type}\ndata: ${JSON.stringify({ type, ...o })}\n\n`
const data = (o) => `data: ${JSON.stringify(o)}\n\n`

// The Anthropic SDK's MessageStream: a block starts as `content_block`, and
// each delta is appended to the block at its `index`. The JS SDK indexes an
// array, so an index of "0" is the block at 0.
const anthropicClient = (p, add) => {
  if (p.type === 'content_block_start') for (const f of ['text', 'thinking']) add(`${Number(p.index)}.${f}`, p.content_block[f])
  if (p.type === 'content_block_delta') {
    if (p.delta.type === 'text_delta') add(`${Number(p.index)}.text`, p.delta.text)
    if (p.delta.type === 'thinking_delta') add(`${Number(p.index)}.thinking`, p.delta.thinking)
  }
}

const half = (secret, at = 11) => [secret.slice(0, at), secret.slice(at)]

test('a secret that starts in a content block and continues in its deltas is cut, identity and gzip', async () => {
  for (const secret of SECRETS) {
    const [a, b] = half(secret)
    const message = sse('message_start', { message: { id: 'msg_1', type: 'message', role: 'assistant', model: 'claude-x', content: [], usage: { input_tokens: 3, output_tokens: 1 } } })
    const delta = (i, t, kind = 'text') => sse('content_block_delta', { index: i, delta: kind === 'text' ? { type: 'text_delta', text: t } : { type: 'thinking_delta', thinking: t } })
    const cases = {
      'start then one delta': [message, sse('content_block_start', { index: 0, content_block: { type: 'text', text: a } }), delta(0, b)],
      'start then several deltas': [message, sse('content_block_start', { index: 0, content_block: { type: 'text', text: a } }), delta(0, b.slice(0, 3)), delta(0, b.slice(3, 7)), delta(0, b.slice(7))],
      'another block in between': [
        message, sse('content_block_start', { index: 1, content_block: { type: 'text', text: a } }),
        sse('content_block_start', { index: 0, content_block: { type: 'text', text: 'x' } }), delta(0, 'yz'), sse('ping', {}), delta(1, b),
      ],
      'a thinking block': [message, sse('content_block_start', { index: 0, content_block: { type: 'thinking', thinking: a, signature: '' } }), delta(0, 'x', 'text'), delta(0, b, 'thinking')],
      'an index written "0"': [message, sse('content_block_start', { index: '0', content_block: { type: 'text', text: a } }), sse('content_block_start', { index: 1, content_block: { type: 'text', text: 'x' } }), delta(0, b)],
    }
    for (const [name, events] of Object.entries(cases)) await cutWhole(`${name} (${secret})`, events, anthropicClient, secret)
  }
})

// ------------------------------------------- indexes that mislead or are missing

// OpenAI's chat SDKs gather `choices[]` by `index` and `tool_calls[]` by
// theirs, not by where the element sits in the array. A typed client in Go,
// Rust or C# reads an index that is missing as zero; a client that keys a map
// by it reads it as its own group.
const chatClient = (missing) => (p, add) => {
  for (const c of p.choices ?? []) {
    const i = c.index ?? missing
    add(`${i}`, c.delta?.content)
    for (const t of c.delta?.tool_calls ?? []) add(`${i}.tool.${t.index ?? missing}`, t.function?.arguments)
  }
}
const chunk = (...choices) => data({ id: 'chatcmpl-1', object: 'chat.completion.chunk', choices })
const content = (index, text) => ({ ...(index === undefined ? {} : { index }), delta: { content: text } })
const call = (index, args) => ({ ...(index === undefined ? {} : { index }), function: { arguments: args } })

// The Responses SDK: an item starts with its content, a part starts with its
// text, and each delta is appended at `output_index` / `content_index`.
const responsesClient = (missing) => (p, add) => {
  const o = p.output_index ?? missing
  if (p.type === 'response.output_item.added') (p.item.content ?? []).forEach((c, i) => add(`${o}/${i}`, c.text))
  if (p.type === 'response.content_part.added') add(`${o}/${p.content_index ?? missing}`, p.part.text)
  if (p.type === 'response.output_text.delta') add(`${o}/${p.content_index ?? missing}`, p.delta)
}
const text = (o, c, delta) => data({ type: 'response.output_text.delta', item_id: 'msg_1', ...(o === undefined ? {} : { output_index: o }), ...(c === undefined ? {} : { content_index: c }), delta })

test('a secret split across events whose index disagrees with its array position is cut', async () => {
  for (const secret of SECRETS) {
    const [a, b] = half(secret)
    await cutWhole('chat: the choice moves to another position', [chunk(content(0, a)), chunk(content(1, 'x'), content(0, b))], chatClient(0), secret)
    await cutWhole('chat: a tool call moves to another position', [
      chunk({ index: 0, delta: { tool_calls: [call(1, a)] } }),
      chunk({ index: 0, delta: { tool_calls: [call(0, 'x'), call(1, b)] } }),
    ], chatClient(0), secret)
    await cutWhole('responses: an item starts with its text, and the deltas follow at its output_index', [
      data({ type: 'response.output_item.added', output_index: 1, item: { id: 'msg_1', type: 'message', role: 'assistant', content: [{ type: 'output_text', text: a, annotations: [] }] } }),
      text(0, 0, 'x'), text(1, 0, b),
    ], responsesClient(0), secret)
    await cutWhole('responses: an item\'s content position is its content_index', [
      data({ type: 'response.output_item.added', output_index: 0, item: { id: 'msg_1', type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'x' }, { type: 'output_text', text: a }] } }),
      text(0, 0, 'y'), text(0, 1, b),
    ], responsesClient(0), secret)
    await cutWhole('responses: a part starts with its text', [
      data({ type: 'response.content_part.added', output_index: 0, content_index: 1, part: { type: 'output_text', text: a, annotations: [] } }),
      text(0, 0, 'x'), text(0, 1, b),
    ], responsesClient(0), secret)
  }
})

test('a secret split across events where the index is missing from some of them is cut', async () => {
  for (const secret of SECRETS) {
    const [a, b] = half(secret)
    for (const [missing, label] of [[0, 'read as zero'], ['none', 'read as its own group']]) {
      const chat = chatClient(missing)
      const responses = responsesClient(missing)
      // The other half sits beside the missing one, and something else sits
      // between them: at another index when a missing one is zero, and at
      // zero when it is a group of its own.
      const first = missing === 0 ? 0 : undefined
      const other = missing === 0 ? 1 : 0
      await cutWhole(`chat, missing index ${label}, after`, [chunk(content(first, a)), chunk(content(other, 'x')), chunk(content(undefined, b))], chat, secret)
      await cutWhole(`chat, missing index ${label}, before`, [chunk(content(undefined, a)), chunk(content(other, 'x')), chunk(content(first, b))], chat, secret)
      await cutWhole(`chat tool call, missing index ${label}`, [
        chunk({ index: 0, delta: { tool_calls: [call(undefined, a)] } }),
        chunk({ index: 0, delta: { tool_calls: [call(other, 'x')] } }),
        chunk({ index: 0, delta: { tool_calls: [call(first, b)] } }),
      ], chat, secret)
      await cutWhole(`responses, missing output_index ${label}, after`, [text(first, 0, a), text(other, 0, 'x'), text(undefined, 0, b)], responses, secret)
      await cutWhole(`responses, missing output_index ${label}, before`, [text(undefined, 0, a), text(other, 0, 'x'), text(first, 0, b)], responses, secret)
      await cutWhole(`responses, missing content_index ${label}`, [text(0, undefined, a), text(0, other, 'x'), text(0, first, b)], responses, secret)
    }
  }
})

// --------------------------------------------- base64, then percent-encoded

/** base64 of `secret` behind `pad` other bytes, percent-encoded as a URL or form value would be. */
const urlBase64 = (secret, pad) => encodeURIComponent(Buffer.concat([Buffer.from('abc'.slice(0, pad)), Buffer.from(secret)]).toString('base64'))

/** True when anything percent-decoded and base64-decoded out of `text` holds `secret`. */
function recovers(text, secret) {
  let plain = text
  try { plain = decodeURIComponent(text) } catch { /* a stray % */ }
  for (const run of plain.match(/[A-Za-z0-9+/]{8,}={0,2}/g) ?? []) {
    for (let skip = 0; skip < 4; skip++) {
      if (Buffer.from(run.slice(skip), 'base64').toString('latin1').includes(secret)) return true
    }
  }
  return plain.includes(secret)
}

test('a secret base64-encoded and then percent-encoded does not reach the agent in a body, a header or a redirect', async () => {
  for (const secret of SECRETS) {
    for (let pad = 0; pad < 3; pad++) {
      const enc = urlBase64(secret, pad)
      assert.ok(recovers(enc, secret), 'the fixture does not decode to the secret')
      const s = buffered(secret, () => ({
        status: 302,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          location: `https://up.test/callback?state=xyz&token=${enc}&next=%2Fhome`,
          'x-debug-token': `t=${enc}`,
        },
        body: Buffer.from(`grant=ok&token=${enc}&scope=read%20write`),
      }))
      const res = await s.pipeline.handle(withKey(s))
      assert.equal(res.status, 302)
      const label = `${secret} behind ${pad} bytes, as ${enc}`
      assert.ok(!recovers(res.body.toString('latin1'), secret), `body: ${label}`)
      assert.ok(!recovers(res.headers.location ?? '', secret), `location: ${label} -> ${res.headers.location}`)
      assert.ok(!recovers(res.headers['x-debug-token'] ?? '', secret), `header: ${label}`)
    }
  }
})

test('a secret base64-encoded and percent-encoded in a stream is cut', async () => {
  for (const secret of SECRETS) {
    const enc = urlBase64(secret, 0)
    const events = [data({ choices: [{ index: 0, delta: { content: `see https://up.test/x?t=${enc}` } }] })]
    await throughGateway(events, (body) => assert.ok(!recovers(body.replace(/^data: /gm, ''), secret), body), secret)
    // And split across two events.
    const split = [data({ choices: [{ index: 0, delta: { content: `t=${enc.slice(0, 12)}` } }] }), data({ choices: [{ index: 0, delta: { content: enc.slice(12) } }] })]
    await cutWhole(`percent-encoded base64 split (${secret})`, split, chatClient(0), secret, (t) => recovers(t, secret))
  }
})

// ---------------------------------------------------------------- controls

test('ordinary JSON with `\\/` in URLs and `\\u` escapes passes through unmodified', async () => {
  const body = JSON.stringify({
    html_url: 'https://github.com/o/r/pull/7', next: '/v1/items?page=2&q=%2Fdocs',
    note: 'caf\u00e9 \u2014 "quoted" <b>&amp;</b>', path: 'C:\\Users\\a', b64: 'aGVsbG8vd29ybGQ=',
  }).replace(/\//g, '\\/').replace(/é/g, '\\u00e9').replace(/—/g, '\\u2014').replace(/</g, '\\u003c')
  const s = setup({ respond: () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(body) }) })
  const res = await s.pipeline.handle(withKey(s))
  assert.equal(res.body.toString('latin1'), body)
  assert.equal(res.headers['av-redacted'], undefined)
})

test('ordinary percent-encoded query strings pass through unmodified in a body, a header and a redirect', async () => {
  const query = 'q=hello%20world&tag=%2Fdocs%2F&b64=aGVsbG8vd29ybGQ%3D&sig=dGhpcyBpcyBub3Qgc2VjcmV0%2B%2F&redirect_uri=https%3A%2F%2Fapp.test%2Fcb'
  const s = setup({
    respond: () => ({
      status: 302,
      headers: { 'content-type': 'application/x-www-form-urlencoded', location: `https://up.test/next?${query}`, 'x-next': query },
      body: Buffer.from(query),
    }),
  })
  const res = await s.pipeline.handle(withKey(s))
  assert.equal(res.body.toString('latin1'), query)
  assert.equal(res.headers.location, `https://up.test/next?${query}`)
  assert.equal(res.headers['x-next'], query)
  assert.equal(res.headers['av-redacted'], undefined)
})

const anthropicStream = [
  sse('message_start', { message: { id: 'msg_01', type: 'message', role: 'assistant', model: 'claude-x', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 25, output_tokens: 1 } } }),
  sse('content_block_start', { index: 0, content_block: { type: 'thinking', thinking: '', signature: '' } }),
  sse('content_block_delta', { index: 0, delta: { type: 'thinking_delta', thinking: 'The user wants the file. ' } }),
  sse('content_block_delta', { index: 0, delta: { type: 'thinking_delta', thinking: 'I should read it first.' } }),
  sse('content_block_delta', { index: 0, delta: { type: 'signature_delta', signature: 'EqQBCgIYAhIM1gbcDa9GJwZA2b3hGgxBdjrkzLoky3dl1pkiMOYds' } }),
  sse('content_block_stop', { index: 0 }),
  sse('ping', {}),
  sse('content_block_start', { index: 1, content_block: { type: 'text', text: '' } }),
  ...['Sure', ' — I\'ll read ', 'https://example.com/a/b?q=1 ', 'and the disk-usage_by_repository report.'].map((t) => sse('content_block_delta', { index: 1, delta: { type: 'text_delta', text: t } })),
  sse('content_block_stop', { index: 1 }),
  sse('content_block_start', { index: 2, content_block: { type: 'tool_use', id: 'toolu_01', name: 'read_file', input: {} } }),
  ...['', '{"path": "/tmp', '/report.txt",', ' "limit": 200}'].map((t) => sse('content_block_delta', { index: 2, delta: { type: 'input_json_delta', partial_json: t } })),
  sse('content_block_stop', { index: 2 }),
  sse('message_delta', { delta: { stop_reason: 'tool_use', stop_sequence: null }, usage: { output_tokens: 89 } }),
  sse('message_stop', {}),
]

const chatStream = [
  chunk({ index: 0, delta: { role: 'assistant', content: '', refusal: null }, logprobs: null, finish_reason: null }),
  ...['Let me', ' check', ' https://example.com/a/b', '.'].map((t) => chunk({ index: 0, delta: { content: t }, finish_reason: null })),
  chunk({ index: 0, delta: { tool_calls: [{ index: 0, id: 'call_abc', type: 'function', function: { name: 'get_weather', arguments: '' } }] } }),
  ...['{"loc', 'ation":', ' "Paris"}'].map((t) => chunk({ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: t } }] } })),
  chunk({ index: 0, delta: { tool_calls: [{ index: 1, id: 'call_def', type: 'function', function: { name: 'get_time', arguments: '' } }] } }),
  ...['{"tz":', ' "CET"}'].map((t) => chunk({ index: 0, delta: { tool_calls: [{ index: 1, function: { arguments: t } }] } })),
  chunk({ index: 0, delta: {}, finish_reason: 'tool_calls' }),
  data({ id: 'chatcmpl-1', object: 'chat.completion.chunk', choices: [], usage: { prompt_tokens: 9, completion_tokens: 12, total_tokens: 21 } }),
  'data: [DONE]\n\n',
]

const responsesStream = (() => {
  const r = (type, o) => `event: ${type}\ndata: ${JSON.stringify({ type, ...o })}\n\n`
  const response = (status, output) => ({ id: 'resp_1', object: 'response', created_at: 1700000000, status, model: 'gpt-x', output, tools: [{ type: 'web_search' }], text: { format: { type: 'text' } }, usage: null })
  const answer = 'Paris is the capital of France [1].'
  const annotation = { type: 'url_citation', start_index: 31, end_index: 34, url: 'https://en.wikipedia.org/wiki/Paris', title: 'Paris - Wikipedia' }
  const reasoning = { id: 'rs_1', type: 'reasoning', summary: [{ type: 'summary_text', text: 'Looked it up.' }] }
  const message = { id: 'msg_1', type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: answer, annotations: [annotation] }] }
  const fn = { id: 'fc_1', type: 'function_call', call_id: 'call_1', name: 'lookup', arguments: '{"city":"Paris"}', status: 'completed' }
  let n = 0
  const seq = () => ({ sequence_number: n++ })
  return [
    r('response.created', { response: response('in_progress', []), ...seq() }),
    r('response.output_item.added', { output_index: 0, item: { id: 'rs_1', type: 'reasoning', summary: [] }, ...seq() }),
    r('response.reasoning_summary_part.added', { item_id: 'rs_1', output_index: 0, summary_index: 0, part: { type: 'summary_text', text: '' }, ...seq() }),
    ...['Looked ', 'it up.'].map((delta) => r('response.reasoning_summary_text.delta', { item_id: 'rs_1', output_index: 0, summary_index: 0, delta, ...seq() })),
    r('response.output_item.done', { output_index: 0, item: reasoning, ...seq() }),
    r('response.output_item.added', { output_index: 1, item: { id: 'msg_1', type: 'message', status: 'in_progress', role: 'assistant', content: [] }, ...seq() }),
    r('response.content_part.added', { item_id: 'msg_1', output_index: 1, content_index: 0, part: { type: 'output_text', text: '', annotations: [] }, ...seq() }),
    ...['Paris is ', 'the capital ', 'of France [1].'].map((delta) => r('response.output_text.delta', { item_id: 'msg_1', output_index: 1, content_index: 0, delta, ...seq() })),
    r('response.output_text.annotation.added', { item_id: 'msg_1', output_index: 1, content_index: 0, annotation_index: 0, annotation, ...seq() }),
    r('response.output_text.done', { item_id: 'msg_1', output_index: 1, content_index: 0, text: answer, ...seq() }),
    r('response.content_part.done', { item_id: 'msg_1', output_index: 1, content_index: 0, part: message.content[0], ...seq() }),
    r('response.output_item.done', { output_index: 1, item: message, ...seq() }),
    r('response.output_item.added', { output_index: 2, item: { ...fn, arguments: '', status: 'in_progress' }, ...seq() }),
    ...['{"city":', '"Paris"}'].map((delta) => r('response.function_call_arguments.delta', { item_id: 'fc_1', output_index: 2, delta, ...seq() })),
    r('response.function_call_arguments.done', { item_id: 'fc_1', output_index: 2, arguments: fn.arguments, ...seq() }),
    r('response.output_item.done', { output_index: 2, item: fn, ...seq() }),
    r('response.completed', { response: { ...response('completed', [reasoning, message, fn]), usage: { input_tokens: 30, output_tokens: 40, total_tokens: 70 } }, ...seq() }),
  ]
})()

const geminiStream = [
  data({ candidates: [{ content: { parts: [{ text: 'The capital' }], role: 'model' }, index: 0 }], usageMetadata: { promptTokenCount: 8, totalTokenCount: 8 }, modelVersion: 'gemini-x', responseId: 'r1' }),
  // Gemini leaves `index` out of some chunks.
  data({ candidates: [{ content: { parts: [{ text: ' of France is Paris; see https://example.com/a/b.' }], role: 'model' } }], modelVersion: 'gemini-x', responseId: 'r1' }),
  data({ candidates: [{ content: { parts: [{ functionCall: { name: 'lookup', args: { city: 'Paris', fields: ['population', 'area'] } } }], role: 'model' }, index: 0 }], modelVersion: 'gemini-x', responseId: 'r1' }),
  data({ candidates: [{ content: { parts: [{ text: '' }], role: 'model' }, finishReason: 'STOP', index: 0 }], usageMetadata: { promptTokenCount: 8, candidatesTokenCount: 20, totalTokenCount: 28 }, modelVersion: 'gemini-x', responseId: 'r1' }),
]

test('ordinary Anthropic, OpenAI chat, Responses and Gemini streams pass through unmodified, identity and gzip', async () => {
  for (const [name, events] of Object.entries({ anthropic: anthropicStream, chat: chatStream, responses: responsesStream, gemini: geminiStream })) {
    await throughGateway(events, (body, compressed) => assert.equal(body, sent(events), `${name} (gzip: ${compressed})`))
  }
})

test('the ordinary streams are left whole when the vault holds a base64-style secret', async () => {
  for (const events of [anthropicStream, chatStream, responsesStream, geminiStream]) {
    await throughGateway(events, (body) => assert.equal(body, sent(events)), SLASHED)
  }
})
