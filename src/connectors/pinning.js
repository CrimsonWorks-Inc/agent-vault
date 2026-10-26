// SPKI pins for one credential's hosts.
//
// Pins are set by the human, per credential. Nothing in here is a built-in
// pin: a hard-coded third-party key breaks every request the day that
// provider rotates its CA.
//
// A pin adds to Node's verification and never replaces it. The chain must
// still verify to a root Node trusts (its own store plus NODE_EXTRA_CA_CERTS,
// exactly as with no pins), and the certificate must still name the host.
// Only then is the pin compared, and only against certificates the peer has
// proven: the leaf, whose key the handshake proves, and each issuer whose key
// signed the certificate below it. A certificate the server merely appends
// proves nothing, so pinning an intermediate or root survives leaf rotation
// without letting a forged leaf borrow a real intermediate's name.
//
// Order is the whole protection. Node sends the headers — which carry the
// substituted secret — on the first write or end. When pins are set, neither
// happens until `secureConnect` has fired and the proven chain intersects the
// list. A mismatch destroys the socket and rejects with AV_PIN_MISMATCH. No
// byte of the request was written.
//
// `pins` is null, undefined or [] for no pins. Anything else that is not an
// array of well-formed pins is refused before a connection (reason
// 'pin_format'). A malformed value never means "no pins".

import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import tls from 'node:tls'
import { createHash, X509Certificate } from 'node:crypto'

const UPSTREAM_TIMEOUT_MS = 30_000
const CHAIN_HOPS = 16
const MAX_PINS = 4

/** The one pin format: 'sha256/' and the base64 of a 32-byte digest. */
export const PIN_RE = /^sha256\/[A-Za-z0-9+/]{43}=$/

/**
 * Whether `pins` is usable as a pin list. null, undefined and [] are no pins.
 * @returns {'none' | 'pinned' | 'invalid'}
 */
export function pinListState(pins) {
  if (pins == null) return 'none'
  if (!Array.isArray(pins)) return 'invalid'
  if (pins.length === 0) return 'none'
  if (pins.length > MAX_PINS) return 'invalid'
  return pins.every((p) => typeof p === 'string' && PIN_RE.test(p)) ? 'pinned' : 'invalid'
}

/** 'sha256/<base64>' of the certificate's SubjectPublicKeyInfo. */
export function spkiOf(x509Cert) {
  const der = x509Cert.publicKey.export({ type: 'spki', format: 'der' })
  return `sha256/${createHash('sha256').update(der).digest('base64')}`
}

/**
 * SPKI pin of every certificate Node presents, leaf first, de-duplicated.
 * The root's issuerCertificate points at itself; the walk stops there.
 */
export function chainPins(tlsSocket) {
  const out = []
  const seen = new Set()
  let cert = typeof tlsSocket?.getPeerCertificate === 'function'
    ? tlsSocket.getPeerCertificate(true)
    : null
  for (let hops = 0; cert && cert.raw && hops < CHAIN_HOPS; hops++) {
    const id = cert.fingerprint256 || cert.raw.toString('base64')
    if (seen.has(id)) break
    seen.add(id)
    try {
      const pin = spkiOf(new X509Certificate(cert.raw))
      if (!out.includes(pin)) out.push(pin)
    } catch { /* a cert we cannot read cannot satisfy a pin */ }
    const next = cert.issuerCertificate
    if (!next || next === cert) break
    if (next.raw && cert.raw.equals?.(next.raw)) break
    cert = next
  }
  return out
}

/**
 * SPKI pins of the certificates a peer has proven, leaf first. The leaf counts
 * because the handshake proved the server holds its key. Each issuer counts
 * only when the certificate below it names it and carries its signature.
 * Node links getPeerCertificate's issuers by name and key identifier alone,
 * so a certificate that is merely appended stops the walk here.
 */
export function verifiedChainPins(tlsSocket) {
  const out = []
  let cert = typeof tlsSocket?.getPeerCertificate === 'function'
    ? tlsSocket.getPeerCertificate(true)
    : null
  let child = null
  for (let hops = 0; cert && cert.raw && hops < CHAIN_HOPS; hops++) {
    let x509
    try { x509 = new X509Certificate(cert.raw) } catch { break }
    if (child) {
      let signed = false
      try { signed = child.checkIssued(x509) && child.verify(x509.publicKey) } catch { signed = false }
      if (!signed) break
    }
    const pin = spkiOf(x509)
    if (!out.includes(pin)) out.push(pin)
    const next = cert.issuerCertificate
    if (!next || next === cert) break
    if (next.raw && cert.raw.equals?.(next.raw)) break
    child = x509
    cert = next
  }
  return out
}

function pinError(presented, reason) {
  const err = Object.assign(new Error('certificate pin mismatch'), {
    code: 'AV_PIN_MISMATCH',
    presented: Array.isArray(presented) ? [...presented] : [],
  })
  if (reason) err.reason = reason
  return err
}

/**
 * Drop-in for the pipeline's defaultUpstream. Same resolve shape:
 * `{ status, headers, res }`. `pins` null, omitted, or empty leaves
 * verification exactly as Node's client does. A non-empty list keeps that
 * verification and is checked after it, before any application byte is
 * written. Any other value is refused with reason 'pin_format'.
 */
export function pinnedRequest({ url, method, headers, body, pins = null }) {
  return new Promise((resolve, reject) => {
    let settled = false
    const fail = (err) => {
      if (settled) return
      settled = true
      reject(err)
    }
    const succeed = (value) => {
      if (settled) return
      settled = true
      resolve(value)
    }

    let parsed
    try { parsed = new URL(url) } catch (e) { fail(e); return }

    const state = pinListState(pins)
    if (state === 'invalid') {
      fail(pinError([], 'pin_format'))
      return
    }
    const pinning = state === 'pinned'
    const pinList = pinning ? pins.slice() : null
    if (pinning && parsed.protocol !== 'https:') {
      fail(pinError([], 'plaintext'))
      return
    }

    const isHttp = parsed.protocol === 'http:'
    const open = isHttp ? httpRequest : httpsRequest
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttp ? 80 : 443),
      path: `${parsed.pathname}${parsed.search}`,
      method,
      headers,
    }
    const onResponse = (res) => succeed({ status: res.statusCode, headers: res.headers, res })
    const writeRequest = (req) => {
      if (body) req.write(body)
      req.end()
    }

    if (!pinning) {
      // No pins configured: the same request defaultUpstream makes.
      // Certificate verification stays at Node's default.
      const req = open(opts, onResponse)
      req.on('error', fail)
      req.setTimeout(UPSTREAM_TIMEOUT_MS, () => req.destroy(new Error('upstream timeout')))
      writeRequest(req)
      return
    }

    // Pins narrow Node's trust; they never stand in for it. A chain that does
    // not verify, or a certificate for another name, fails the handshake
    // exactly as it would with no pins, and `secureConnect` never fires. The
    // socket is not taken from a pool (`agent: false`), so the handshake we
    // check is the handshake this request uses, and no session is resumed.
    opts.agent = false
    opts.rejectUnauthorized = true
    const req = open(opts, onResponse)
    req.on('error', fail)
    req.setTimeout(UPSTREAM_TIMEOUT_MS, () => req.destroy(new Error('upstream timeout')))

    const release = () => {
      if (settled) return
      writeRequest(req)
    }
    req.on('socket', (socket) => {
      const check = () => {
        if (settled) return
        const proven = verifiedChainPins(socket)
        if (!proven.some((p) => pinList.includes(p))) {
          const presented = chainPins(socket)
          // Settle the pin error before destroy. destroy() emits 'error'
          // synchronously, and that must not replace AV_PIN_MISMATCH.
          fail(pinError(presented))
          try { socket.destroy() } catch { /* already gone */ }
          try { req.destroy() } catch { /* already gone */ }
          return
        }
        release()
      }
      // `encrypted` is already true while the handshake is still running.
      // Waiting on secureConnecting is what keeps the write after the check.
      if (socket.secureConnecting) socket.once('secureConnect', check)
      else if (socket.encrypted) check()
      else socket.once('secureConnect', check)
    })
  })
}

/**
 * The certificates a host presents, for the human to read before pinning.
 * Sends no credential and no HTTP request. `rejectUnauthorized` is off
 * because the point is to show a chain the trust store may not know yet.
 * @returns {Promise<Array<{ subject: string, issuer: string, spki: string, not_after: string | null }>>}
 */
export function fetchChainPins(host, port = 443) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (err, value) => {
      if (settled) return
      settled = true
      try { socket.destroy() } catch { /* already closed */ }
      if (err) reject(err)
      else resolve(value)
    }
    const opts = { host, port, rejectUnauthorized: false }
    if (typeof host === 'string' && /[a-z]/i.test(host) && !/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.startsWith('[')) {
      opts.servername = host
    }
    const socket = tls.connect(opts)
    socket.setTimeout(UPSTREAM_TIMEOUT_MS, () => finish(new Error('upstream timeout')))
    socket.once('error', (err) => finish(err))
    socket.once('secureConnect', () => {
      try {
        const described = []
        const pins = chainPins(socket)
        let cert = socket.getPeerCertificate(true)
        const seen = new Set()
        for (let hops = 0; cert && cert.raw && hops < CHAIN_HOPS && hops < pins.length + 1; hops++) {
          const id = cert.fingerprint256 || cert.raw.toString('base64')
          if (seen.has(id)) break
          seen.add(id)
          const x509 = new X509Certificate(cert.raw)
          const notAfter = new Date(x509.validTo)
          described.push({
            subject: x509.subject,
            issuer: x509.issuer,
            spki: spkiOf(x509),
            not_after: Number.isNaN(notAfter.getTime()) ? null : notAfter.toISOString(),
          })
          const next = cert.issuerCertificate
          if (!next || next === cert) break
          cert = next
        }
        finish(null, described)
      } catch (err) {
        finish(err)
      }
    })
  })
}
