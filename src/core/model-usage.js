import { deny } from './errors.js'
import { parseStrictJson } from './payload.js'

// Standard first-party list prices, USD microdollars per million tokens.
// Estimates exclude provider-specific tool fees, caching discounts and tiers.
export const PRICES_VERSION = '2026-10-25'
const PRICES = {
  // https://developers.openai.com/api/docs/models/gpt-4.1-mini
  openai: [['gpt-4.1-mini', 400_000, 1_600_000]],
  // https://platform.claude.com/docs/en/about-claude/pricing
  anthropic: [['claude-sonnet-4-5', 3_000_000, 15_000_000], ['claude-sonnet-4-0', 3_000_000, 15_000_000], ['claude-sonnet-4', 3_000_000, 15_000_000]],
  // https://ai.google.dev/gemini-api/docs/pricing (standard text input/output)
  'google-genai': [['gemini-2.5-flash-lite', 100_000, 400_000], ['gemini-2.5-flash', 300_000, 2_500_000]],
}
const DEFAULT_OUTPUT = { anthropic: 4096, openai: 16384, 'google-genai': 8192 }
/** The connector kinds a spend limit applies to. Everything else ignores it. */
export const METERED_KINDS = Object.freeze(Object.keys(DEFAULT_OUTPUT))
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const count = value => Number.isSafeInteger(value) && value >= 0
const fail = (rule, detail) => { throw deny('AV_POLICY_DENIED', detail, { rule }) }

/** Unknown variants do not inherit a cheaper family's price. Dated snapshots
 * use the longest known model prefix; arbitrary suffixes remain unpriced. */
export function priceOf(kind, model) {
  if (!Object.hasOwn(PRICES, kind) || typeof model !== 'string') return null
  const rows = (PRICES[kind] ?? []).filter(([prefix]) => model === prefix ||
    (model.startsWith(prefix + '-') && /^(?:\d{8}|\d{4}-\d{2}-\d{2})$/.test(model.slice(prefix.length + 1))))
  rows.sort((a, b) => b[0].length - a[0].length)
  return rows.length ? { input_micros_per_mtok: rows[0][1], output_micros_per_mtok: rows[0][2] } : null
}

/** Inspect original request bytes, before credentials are injected. */
export function meterRequest(kind, { method, path, contentType, body } = {}) {
  const result = { metered: false, free: false, model: null, max_output: 0, input_estimate: 0, unmodeled: false }
  if (!Object.hasOwn(DEFAULT_OUTPUT, kind)) return result
  const verb = typeof method === 'string' ? method.toUpperCase() : ''
  const pathname = typeof path === 'string' ? path.split('?')[0] : ''
  const google = /^\/v1(?:beta)?\/models\/([^/:]+):(generateContent|streamGenerateContent|countTokens)$/.exec(pathname)
  // A request with no body cannot ask for tokens, so the safe methods are free.
  if (['GET', 'HEAD', 'OPTIONS'].includes(verb) || (verb === 'POST' && ((kind === 'anthropic' && pathname === '/v1/messages/count_tokens') ||
    (kind === 'google-genai' && google?.[2] === 'countTokens')))) return { ...result, free: true }
  const metered = verb === 'POST' && ((kind === 'anthropic' && pathname === '/v1/messages') ||
    (kind === 'openai' && ['/v1/chat/completions', '/v1/responses', '/v1/completions', '/v1/embeddings'].includes(pathname)) ||
    (kind === 'google-genai' && google && google[2] !== 'countTokens'))
  if (!metered) return { ...result, unmodeled: true }
  let bytes, json
  try {
    if (typeof contentType !== 'string' || !/^application\/(?:json|[\w.+-]+\+json)(?:\s*;|\s*$)/i.test(contentType)) throw Error()
    if (typeof body !== 'string' && !Buffer.isBuffer(body) && !(body instanceof Uint8Array)) throw Error()
    bytes = Buffer.from(body)
    json = parseStrictJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    if (!object(json)) throw Error()
  } catch { fail('spend_unparseable', 'A metered request needs a readable JSON object body.') }
  const model = kind === 'google-genai' ? google[1] : typeof json.model === 'string' ? json.model : null
  const proposed = kind === 'anthropic' ? json.max_tokens : kind === 'openai'
    ? json.max_completion_tokens ?? json.max_tokens ?? json.max_output_tokens : json.generationConfig?.maxOutputTokens
  const max_output = pathname === '/v1/embeddings' ? 0 : count(proposed) && proposed > 0 ? proposed : DEFAULT_OUTPUT[kind]
  return { ...result, metered: true, model, max_output, input_estimate: Math.ceil(bytes.length / 3) }
}

/** Return null for absent, partial or malformed usage so settlement charges
 * the reservation rather than silently turning a missing counter into zero. */
export function usageFromBody(kind, json) {
  if (!object(json)) return null
  let input, output
  if (kind === 'anthropic') {
    const u = json.usage
    if (!object(u) || !count(u.input_tokens) || !count(u.output_tokens)) return null
    const creation = u.cache_creation_input_tokens ?? 0, read = u.cache_read_input_tokens ?? 0
    if (!count(creation) || !count(read)) return null
    input = u.input_tokens + creation + read
    output = u.output_tokens
  } else if (kind === 'openai') {
    const u = json.usage
    if (!object(u)) return null
    input = u.prompt_tokens ?? u.input_tokens
    output = u.completion_tokens ?? u.output_tokens
    // Embeddings report prompt_tokens and total_tokens, with no output counter.
    if (output === undefined && count(input) && u.total_tokens === input) output = 0
  } else if (kind === 'google-genai') {
    const u = json.usageMetadata
    input = u?.promptTokenCount
    output = u?.candidatesTokenCount
    // Thinking tokens are billed as output and reported apart from the
    // candidates. A reply that is all thinking has no candidates count.
    const thoughts = u?.thoughtsTokenCount ?? 0
    if (output === undefined && count(input) && count(thoughts) && thoughts > 0) output = 0
    if (!count(thoughts)) return null
    if (count(output)) output += thoughts
  }
  return count(input) && count(output) ? { input_tokens: input, output_tokens: output } : null
}

/** eventData is an SSE data payload (JSON text or parsed object), not a
 * transport chunk. Providers' counters are cumulative, never added twice. */
export function usageFromEvent(kind, eventData, acc = null) {
  let event = eventData
  try { if (typeof event === 'string' || Buffer.isBuffer(event)) event = JSON.parse(event.toString()) } catch { return acc }
  if (!object(event)) return acc
  let usage = usageFromBody(kind, event)
  if (kind === 'openai' && event.response) usage = usageFromBody(kind, event.response)
  if (kind === 'anthropic') {
    if (event.type === 'message_start') usage = usageFromBody(kind, event.message)
    if (event.type === 'message_delta' && acc && count(event.usage?.output_tokens)) {
      usage = { input_tokens: acc.input_tokens, output_tokens: event.usage.output_tokens }
    }
  }
  if (!usage) return acc
  return { input_tokens: Math.max(acc?.input_tokens ?? 0, usage.input_tokens),
    output_tokens: Math.max(acc?.output_tokens ?? 0, usage.output_tokens) }
}

function amount(input, output, price) {
  if (!count(input) || !count(output) || !count(input + output)) fail('spend_unparseable', 'Model token counters exceed the supported integer range.')
  // BigInt keeps multiplication and upward rounding exact for large counters.
  const micros = price ? (BigInt(input) * BigInt(price.input_micros_per_mtok) +
    BigInt(output) * BigInt(price.output_micros_per_mtok) + 999_999n) / 1_000_000n : 0n
  if (micros > BigInt(Number.MAX_SAFE_INTEGER)) fail('spend_unparseable', 'Model price exceeds the supported integer range.')
  return { tokens: input + output, usd_micros: Number(micros) }
}

/** USD limits must opt in, so token-only budgets work for unknown models. */
export function reservationFor(kind, meter, { usd = false } = {}) {
  if (!meter.metered) return { tokens: 0, usd_micros: 0 }
  const price = priceOf(kind, meter.model)
  if (usd && !price) fail('spend_unpriced', 'This model has no checked USD price; use a token budget or a priced model.')
  return amount(meter.input_estimate, meter.max_output, price)
}

/** An aborted stream must pass null even if it yielded partial usage. */
export function chargeFor(kind, meter, reservation, usage) {
  if (!usage || !count(usage.input_tokens) || !count(usage.output_tokens)) return { ...reservation }
  return amount(usage.input_tokens, usage.output_tokens, priceOf(kind, meter.model))
}
