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
export function requestHash({ method, host, path, query, bodySha256, credentials, headers }) {
  return hash({
    method: String(method || '').toUpperCase(),
    host: String(host || '').toLowerCase(),
    path: path || '/',
    query: query || '',
    body: bodySha256 || '',
    // WHICH credential field gets injected, as `<grant>:<field>` — not which
    // placeholder carried it. A placeholder is a bearer token with a fresh
    // nonce every time one is minted, so hashing its identity made the hash
    // change on every call. `vault_http` mints one per request, so a held write
    // could never be resent: each retry hashed differently, opened ANOTHER
    // approval, and asked the human again. The feature that stops a write going
    // out unattended instead asked for consent in a loop and never spent it.
    //
    // Two placeholders from the same grant and field carry identical
    // capability, so nothing the human was shown can differ between them.
    credentials: [...(credentials || [])].sort(),
    // The headers that will actually be forwarded. Whatever is NOT in this
    // hash is what an agent can change under someone else's approval, and
    // headers were not in it: after a human approved `POST /x`, the same
    // method, host, path and body with different headers hashed identically
    // and executed as approved. `X-HTTP-Method-Override: DELETE` is the sharp
    // version — plenty of frameworks honour it, so the approved POST reaches
    // the upstream as a delete. The human was shown method, host and path,
    // and a header can change what all three mean.
    headers: [...(headers || [])]
      .map(([n, v]) => [String(n).toLowerCase(), String(v)])
      .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : (a[0] < b[0] ? -1 : 1))),
  })
}

export function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex')
}
