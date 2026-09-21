// Canonical serialization for anything that gets hashed: presence operation
// hashes, approval request hashes and the audit chain. Two structurally equal
// values must produce identical bytes on every run and every platform, or a
// presence proof stops binding to the operation the human actually saw.
//
// The spec pins deterministic CBOR (RFC 8949 4.2.1) for the Rust daemon. This
// implementation uses the same rules expressed in JSON: object keys sorted by
// their UTF-8 bytes, no floats, no undefined, arrays in order.

import { createHash, createHmac } from 'node:crypto'

export function canonicalize(value) {
  if (value === null) return 'null'
  const t = typeof value
  if (t === 'boolean') return value ? 'true' : 'false'
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('canon: non-finite number')
    if (!Number.isInteger(value)) throw new Error('canon: floats are not canonicalizable')
    return String(value)
  }
  if (t === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (t === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort(byUtf8)
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`
  }
  throw new Error(`canon: cannot canonicalize ${t}`)
}

function byUtf8(a, b) {
  const ba = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  return Buffer.compare(ba, bb)
}

export function hash(value) {
  return createHash('sha256').update(canonicalize(value)).digest('hex')
}

export function hmac(key, value) {
  return createHmac('sha256', key).update(canonicalize(value)).digest('hex')
}

/**
 * The approval and idempotency key for a proxied request. A granted approval is
 * bound to this, so an SDK that retries a request after a 202 attaches to the
 * same approval instead of prompting the human twice or sending twice.
 */
export function requestHash({ method, host, path, query, bodySha256, placeholderIds }) {
  return hash({
    method: String(method || '').toUpperCase(),
    host: String(host || '').toLowerCase(),
    path: path || '/',
    query: query || '',
    body: bodySha256 || '',
    placeholders: [...(placeholderIds || [])].sort(),
  })
}

export function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex')
}
