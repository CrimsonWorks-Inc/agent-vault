import test from 'node:test'
import assert from 'node:assert/strict'
import { PRICES_VERSION, meterRequest, priceOf, usageFromBody, usageFromEvent, reservationFor, chargeFor } from '../../src/core/model-usage.js'

const request = (kind, path, json, extras = {}) => meterRequest(kind, {
  method: 'POST', path, contentType: 'application/json; charset=utf-8', body: Buffer.from(JSON.stringify(json)), ...extras,
})
const denied = rule => e => e.code === 'AV_POLICY_DENIED' && e.rule === rule && !e.detail.includes('secret-marker')

test('model meters classify only the contracted endpoints and methods', () => {
  for (const [kind, paths] of [
    ['anthropic', ['/v1/messages']],
    ['openai', ['/v1/chat/completions', '/v1/responses', '/v1/completions', '/v1/embeddings']],
    ['google-genai', ['/v1/models/gemini-2.5-flash:generateContent', '/v1beta/models/gemini-2.5-flash:streamGenerateContent']],
  ]) {
    for (const path of paths) {
      assert.equal(request(kind, path + '?alt=sse', {}).metered, true, path)
      for (const method of ['PUT', 'PATCH', 'DELETE']) {
        assert.equal(request(kind, path, {}, { method }).unmodeled, true, method)
      }
      // No body, no tokens: the safe methods are free, like GET.
      for (const method of ['HEAD', 'OPTIONS']) assert.equal(request(kind, path, {}, { method }).free, true, method)
    }
    assert.equal(request(kind, '/v1/unknown', {}).unmodeled, true)
    assert.equal(request(kind, '/v1/unknown', {}, { method: 'GET', body: 'invalid' }).free, true)
  }
  assert.equal(request('anthropic', '/v1/messages/count_tokens', {}, { body: 'invalid' }).free, true)
  assert.equal(request('google-genai', '/v1beta/models/x:countTokens', {}, { body: 'invalid' }).free, true)
  assert.equal(request('github', '/anything', {}).unmodeled, false)
})

test('metered JSON fails closed without echoing request contents', () => {
  for (const body of ['secret-marker', 'null', '[]', 'true', '', undefined]) {
    assert.throws(() => request('openai', '/v1/responses', {}, { body }), denied('spend_unparseable'))
  }
  assert.throws(() => request('anthropic', '/v1/messages', {}, { contentType: 'text/plain' }), denied('spend_unparseable'))
  assert.equal(request('openai', '/v1/responses', {}, { contentType: 'application/vendor+json' }).metered, true)
})

test('reservations use original UTF-8 byte length and provider output limits', () => {
  const json = { model: 'gpt-4.1-mini', input: '雪🌲', max_completion_tokens: 37, max_tokens: 99, max_output_tokens: 121 }
  const meter = request('openai', '/v1/responses', json)
  assert.equal(meter.input_estimate, Math.ceil(Buffer.byteLength(JSON.stringify(json)) / 3))
  assert.equal(meter.max_output, 37)
  assert.equal(meter.model, json.model)
  assert.equal(request('openai', '/v1/completions', { max_tokens: 51 }).max_output, 51)
  assert.equal(request('openai', '/v1/responses', { max_output_tokens: 53 }).max_output, 53)
  assert.equal(request('anthropic', '/v1/messages', { max_tokens: 57 }).max_output, 57)
  const google = request('google-genai', '/v1beta/models/gemini-2.5-flash:generateContent', { generationConfig: { maxOutputTokens: 61 } })
  assert.equal(google.model, 'gemini-2.5-flash')
  assert.equal(google.max_output, 61)
  assert.equal(request('openai', '/v1/embeddings', { max_tokens: 91 }).max_output, 0)
})

test('invalid or absent output limits use the binding profile defaults', () => {
  for (const value of [undefined, null, 0, -1, 1.5, '500', true, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(request('anthropic', '/v1/messages', { max_tokens: value }).max_output, 4096)
    assert.equal(request('openai', '/v1/chat/completions', { max_tokens: value }).max_output, 16384)
    assert.equal(request('google-genai', '/v1/models/x:generateContent', { generationConfig: { maxOutputTokens: value } }).max_output, 8192)
  }
})

test('checked prices use microdollars per million tokens and reject unknown USD models', () => {
  assert.match(PRICES_VERSION, /^\d{4}-\d{2}-\d{2}$/)
  assert.deepEqual(priceOf('openai', 'gpt-4.1-mini-2025-04-14'), { input_micros_per_mtok: 400000, output_micros_per_mtok: 1600000 })
  assert.deepEqual(priceOf('google-genai', 'gemini-2.5-flash-lite'), { input_micros_per_mtok: 100000, output_micros_per_mtok: 400000 })
  assert.equal(priceOf('anthropic', 'claude-sonnet-4-5-20250929').output_micros_per_mtok, 15000000)
  assert.equal(priceOf('anthropic', 'claude-sonnet-4-20250514').input_micros_per_mtok, 3000000)
  for (const model of [null, 'unknown', 'gpt-4.1-mini-expensive', 'gpt-4.1-mini-audio']) assert.equal(priceOf('openai', model), null)
  assert.equal(priceOf('google-genai', 'gemini-2.5-flash-image'), null)
  assert.equal(priceOf('github', 'gpt-4.1-mini'), null)
  assert.equal(priceOf('__proto__', 'gpt-4.1-mini'), null)
  const meter = request('openai', '/v1/responses', { model: 'secret-marker' })
  assert.throws(() => reservationFor('openai', meter, { usd: true }), denied('spend_unpriced'))
  assert.equal(reservationFor('openai', meter).usd_micros, 0)
  assert.ok(reservationFor('openai', meter).tokens > 0)
})

test('reservation prices round up exactly and reject integer overflow', () => {
  const meter = { metered: true, model: 'gpt-4.1-mini', input_estimate: 1, max_output: 1 }
  assert.deepEqual(reservationFor('openai', meter, { usd: true }), { tokens: 2, usd_micros: 2 })
  assert.deepEqual(reservationFor('openai', { ...meter, input_estimate: 1, max_output: 0 }), { tokens: 1, usd_micros: 1 })
  assert.throws(() => reservationFor('openai', { ...meter, input_estimate: Number.MAX_SAFE_INTEGER }), denied('spend_unparseable'))
  assert.deepEqual(reservationFor('openai', { metered: false }), { tokens: 0, usd_micros: 0 })
})

test('buffered usage includes Anthropic cache tokens and both OpenAI response shapes', () => {
  assert.deepEqual(usageFromBody('anthropic', { usage: { input_tokens: 10, cache_creation_input_tokens: 20, cache_read_input_tokens: 30, output_tokens: 4 } }), { input_tokens: 60, output_tokens: 4 })
  assert.deepEqual(usageFromBody('anthropic', { usage: { input_tokens: 10, output_tokens: 4 } }), { input_tokens: 10, output_tokens: 4 })
  for (const usage of [{ prompt_tokens: 31, completion_tokens: 7 }, { input_tokens: 31, output_tokens: 7 }]) {
    assert.deepEqual(usageFromBody('openai', { usage }), { input_tokens: 31, output_tokens: 7 })
  }
  assert.deepEqual(usageFromBody('openai', { usage: { prompt_tokens: 5, total_tokens: 5 } }), { input_tokens: 5, output_tokens: 0 })
  assert.deepEqual(usageFromBody('google-genai', { usageMetadata: { promptTokenCount: 9, candidatesTokenCount: 3 } }), { input_tokens: 9, output_tokens: 3 })
})

test('malformed, absent and partial usage cannot turn into a zero charge', () => {
  for (const json of [null, [], {}, { usage: {} }, { usage: { input_tokens: 4 } }, { usage: { input_tokens: -1, output_tokens: 1 } },
    { usage: { input_tokens: '4', output_tokens: 1 } }, { usage: { input_tokens: 0.5, output_tokens: 1 } },
    { usage: { input_tokens: Number.MAX_SAFE_INTEGER, cache_read_input_tokens: 1, output_tokens: 1 } }]) {
    assert.equal(usageFromBody('anthropic', json), null)
  }
  assert.equal(usageFromBody('openai', { usage: { prompt_tokens: 4 } }), null)
  assert.equal(usageFromBody('google-genai', { usageMetadata: { promptTokenCount: 4 } }), null)
  assert.equal(usageFromBody('github', { usage: { input_tokens: 4, output_tokens: 1 } }), null)
})

test('Anthropic SSE merges message_start cache usage and cumulative message_delta', () => {
  let acc = usageFromEvent('anthropic', JSON.stringify({ type: 'message_start', message: { usage: { input_tokens: 5, cache_creation_input_tokens: 7, cache_read_input_tokens: 11, output_tokens: 0 } } }))
  const before = { ...acc }
  acc = usageFromEvent('anthropic', { type: 'message_delta', usage: { output_tokens: 9 } }, acc)
  assert.deepEqual(before, { input_tokens: 23, output_tokens: 0 })
  assert.deepEqual(acc, { input_tokens: 23, output_tokens: 9 })
  assert.deepEqual(usageFromEvent('anthropic', { type: 'message_delta', usage: { output_tokens: 7 } }, acc), acc)
  assert.equal(usageFromEvent('anthropic', { type: 'message_delta', usage: { output_tokens: 9 } }), null)
})

test('OpenAI and Google SSE final usage survives chunks without usage and repeated totals', () => {
  for (const [kind, event] of [
    ['openai', { usage: { prompt_tokens: 17, completion_tokens: 6 } }],
    ['openai', { type: 'response.completed', response: { usage: { input_tokens: 17, output_tokens: 6 } } }],
    ['google-genai', { usageMetadata: { promptTokenCount: 17, candidatesTokenCount: 6 } }],
  ]) {
    assert.equal(usageFromEvent(kind, '{}'), null)
    const acc = usageFromEvent(kind, JSON.stringify(event))
    assert.deepEqual(acc, { input_tokens: 17, output_tokens: 6 })
    for (const next of ['[DONE]', 'broken', '{}', JSON.stringify(event)]) assert.deepEqual(usageFromEvent(kind, next, acc), acc)
  }
})

test('missing usage charges the full reservation; actual usage may exceed it', () => {
  const meter = { metered: true, model: 'gpt-4.1-mini', input_estimate: 10, max_output: 10 }
  const reservation = reservationFor('openai', meter, { usd: true })
  assert.deepEqual(chargeFor('openai', meter, reservation, null), reservation)
  assert.deepEqual(chargeFor('openai', meter, reservation, { input_tokens: NaN, output_tokens: 0 }), reservation)
  assert.deepEqual(chargeFor('openai', meter, reservation, { input_tokens: 100, output_tokens: 100 }), { tokens: 200, usd_micros: 200 })
  assert.deepEqual(chargeFor('openai', meter, reservation, { input_tokens: 0, output_tokens: 0 }), { tokens: 0, usd_micros: 0 })
})

test('Gemini thinking tokens are charged as output, and a thoughts-only reply still settles', () => {
  assert.deepEqual(usageFromBody('google-genai', { usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, thoughtsTokenCount: 20 } }), { input_tokens: 10, output_tokens: 25 })
  assert.deepEqual(usageFromBody('google-genai', { usageMetadata: { promptTokenCount: 10, thoughtsTokenCount: 20 } }), { input_tokens: 10, output_tokens: 20 })
  assert.deepEqual(usageFromBody('google-genai', { usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 } }), { input_tokens: 10, output_tokens: 5 })
  assert.equal(usageFromBody('google-genai', { usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, thoughtsTokenCount: -1 } }), null)
  assert.equal(usageFromBody('google-genai', { usageMetadata: { promptTokenCount: 10 } }), null)
})
