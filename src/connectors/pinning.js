// SPKI pins for one credential's hosts.
//
// Pins are set by the human, per credential. Nothing in here is a built-in
// pin: a hard-coded third-party key breaks every request the day that
// provider rotates its CA.
//
// There are two ways a pinned connection is accepted, and only two.
//
// An exact leaf pin stands in for CA trust. When the SPKI of the end-entity
// certificate — the one at chain position 0, whose private key the handshake
// itself proves — is on the list, the chain need not verify to a trusted
// root. That is what lets a self-signed internal upstream be pinned. The
// certificate must still name the host, and must be inside its validity
// window: an expired pinned leaf is refused with reason 'leaf_expired'.
//
// Any other pin adds to Node's verification and never replaces it. The chain
// must verify to a root Node trusts (its own store plus NODE_EXTRA_CA_CERTS,
// exactly as with no pins), and the certificate must name the host. Only then
// is the pin compared, and only against certificates the peer has proven: the
// leaf, and each issuer whose key signed the certificate below it. A
// certificate the server merely appends proves nothing, so pinning an
// intermediate or root survives leaf rotation without letting a forged leaf
// borrow a real intermediate's name. A pin on a non-leaf certificate never
// stands in for CA trust.
//
// The host is the URL's, everywhere. The TLS server name, Node's certificate
// check and the one here all name the host the bytes are written to, never a
// Host header: Node copies a Host header into the server name when none is
// set, which let a certificate for the header's name pass for the URL host.
// A Host header that names anything other than the URL's host and port is
// refused before a connection (AV_POLICY_DENIED, rule 'host_mismatch'); it is
// not rewritten. An IPv6 URL host loses its brackets for the connection and
// the certificate check, and is never sent as a server name.
//
// The caller's headers are read once. Each own enumerable name and its value
// are copied, a value that is not a string refused (rule 'header_format'),
// and the Host check and the request both use that copy. Node reads a headers
// object again when it builds the request, so a getter or a Proxy that
// answered the check with the URL host could otherwise put another host on
// the wire.
//
// Order is the whole protection. Node sends the headers — which carry the
// substituted secret — on the first write or end. When pins are set, neither
// happens until `secureConnect` has fired and the decision above has been
// made. A refusal destroys the socket and rejects: AV_PIN_MISMATCH for a pin
// that matched nothing or a pinned leaf out of date, Node's own TLS error code
// for a chain or name that does not verify. No byte of the request was
// written.
//
// `pins` is null, undefined or [] for no pins. Anything else that is not an
// array of well-formed pins is refused before a connection (reason
// 'pin_format'). A malformed value never means "no pins".

import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import tls from 'node:tls'
import { isIP } from 'node:net'
import { createHash, X509Certificate } from 'node:crypto'
import { deny } from '../core/errors.js'

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

/**
 * One copy of the caller's headers: a null-prototype object of strings, the
 * only headers anything here reads or Node is given. An object's own
 * enumerable names, or a flat array of name, value pairs, are each read once.
 * null when a value is not a string, an array is not whole pairs or names a
 * header twice, or `headers` is neither an object nor null.
 */
function snapshotHeaders(headers) {
  const out = Object.create(null)
  if (headers == null) return out
  if (typeof headers !== 'object') return null
  if (Array.isArray(headers)) {
    const length = headers.length
    if (!Number.isSafeInteger(length) || length % 2 !== 0) return null
    for (let i = 0; i < length; i += 2) {
      const name = headers[i]
      const value = headers[i + 1]
      if (typeof name !== 'string' || typeof value !== 'string' || Object.hasOwn(out, name)) return null
      out[name] = value
    }
    return out
  }
  for (const name of Object.keys(headers)) {
    const value = headers[name]
    if (typeof value !== 'string') return null
    out[name] = value
  }
  return out
}

/** Every value the snapshot gives for a Host header, under any spelling. */
function hostHeaderValues(sent) {
  return Object.keys(sent).filter((name) => name.toLowerCase() === 'host').map((name) => sent[name])
}

/**
 * Whether a Host header value names the URL's host and port. Case does not
 * matter, and the scheme's default port may be written or left out. Anything
 * else, a list or a value that is not a string included, does not.
 */
export function hostHeaderMatches(value, parsed) {
  if (typeof value !== 'string') return false
  const given = value.toLowerCase()
  if (given === parsed.host) return true
  const defaultPort = { 'https:': '443', 'http:': '80' }[parsed.protocol]
  return parsed.port === '' && !!defaultPort && given === `${parsed.hostname}:${defaultPort}`
}

/** The URL's host as a certificate names it: no IPv6 brackets. */
export function urlIdentity(parsed) {
  const host = parsed.hostname
  return host.startsWith('[') ? host.slice(1, -1) : host
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
 * verification exactly as Node's client does. A non-empty list is checked
 * once the handshake is done and before any application byte is written: an
 * exact leaf pin stands in for CA trust, any other pin needs a verified chain
 * as well. Any other value is refused with reason 'pin_format'.
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

    // The caller's headers are read here and never again.
    let sent
    try { sent = snapshotHeaders(headers) } catch { sent = null }
    if (!sent) {
      fail(deny('AV_POLICY_DENIED', 'headers must be names with string values, each read once', { rule: 'header_format' }))
      return
    }

    // The one name every identity decision uses.
    const identity = urlIdentity(parsed)
    if (!hostHeaderValues(sent).every((v) => hostHeaderMatches(v, parsed))) {
      fail(deny('AV_POLICY_DENIED', 'the Host header names a different host than the URL', { rule: 'host_mismatch' }))
      return
    }

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
    // The connect address has no IPv6 brackets: Node resolves '[::1]' as a
    // name and fails. Node brackets it again in the Host header it writes.
    const opts = {
      hostname: identity,
      port: parsed.port || (isHttp ? 80 : 443),
      path: `${parsed.pathname}${parsed.search}`,
      method,
      headers: sent,
    }
    // Set, so Node does not take it from a Host header. An IP is never sent
    // as SNI; '' tells Node to check the certificate against the URL host.
    if (!isHttp) opts.servername = isIP(identity) ? '' : identity
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

    // Node's verification still runs on every handshake, but the decision is
    // ours: `rejectUnauthorized` off only stops Node destroying the socket
    // before an exact leaf pin can be looked at. `check` refuses anything that
    // neither verified nor has its leaf pinned, with the code Node would have
    // used. The socket is not taken from a pool (`agent: false`), so the
    // handshake we check is the handshake this request uses, and no session
    // is resumed.
    opts.agent = false
    opts.rejectUnauthorized = false
    const req = open(opts, onResponse)
    req.on('error', fail)
    req.setTimeout(UPSTREAM_TIMEOUT_MS, () => req.destroy(new Error('upstream timeout')))

    const release = () => {
      if (settled) return
      writeRequest(req)
    }
    req.on('socket', (socket) => {
      const refuse = (err) => {
        // Settle first. destroy() emits 'error' synchronously, and that must
        // not replace the refusal.
        fail(err)
        try { socket.destroy() } catch { /* already gone */ }
        try { req.destroy() } catch { /* already gone */ }
      }
      const check = () => {
        if (settled) return
        const verdict = pinVerdict(socket, identity, pinList)
        if (verdict) refuse(verdict)
        else release()
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
 * Whether a finished handshake may carry the request: null to send, or the
 * error to refuse with.
 *
 * The leaf is the handshake's own certificate, chain position 0, and its pin
 * is the only one that can stand in for CA trust. `socket.authorized` is
 * Node's verdict on the chain and on the server name it was given. That name
 * is the URL host, but the decision does not rest on it: the name is checked
 * here against `hostname`, the URL host without brackets, on both paths.
 */
function pinVerdict(socket, hostname, pinList) {
  const leaf = socket.getPeerCertificate(true)
  let leafX509 = null
  try { leafX509 = leaf?.raw ? new X509Certificate(leaf.raw) : null } catch { leafX509 = null }
  const leafPin = leafX509 ? spkiOf(leafX509) : null

  if (socket.authorized) {
    const wrongName = tls.checkServerIdentity(hostname, leaf)
    if (wrongName) return wrongName
    if (verifiedChainPins(socket).some((p) => pinList.includes(p))) return null
    return pinError(chainPins(socket))
  }

  const leafPinned = leafPin !== null && pinList.includes(leafPin)
  if (!leafPinned) return chainError(socket)

  const nameError = tls.checkServerIdentity(hostname, leaf)
  if (nameError) return nameError
  // Written so that a date that does not parse (NaN) refuses.
  const now = Date.now()
  if (!(now <= Date.parse(leafX509.validTo))) return pinError(chainPins(socket), 'leaf_expired')
  if (!(now >= Date.parse(leafX509.validFrom))) return pinError(chainPins(socket), 'leaf_not_yet_valid')
  return null
}

/** The error Node would have destroyed the socket with. */
function chainError(socket) {
  const code = typeof socket.authorizationError === 'string' && socket.authorizationError
    ? socket.authorizationError
    : (socket.authorizationError?.code || 'UNABLE_TO_VERIFY_LEAF_SIGNATURE')
  return Object.assign(new Error(`upstream certificate not trusted: ${code}`), { code })
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
