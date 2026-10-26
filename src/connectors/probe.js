// Pre-flight probe for `cred test`.
//
// The method and path are the profile's constant. A path, method or body on
// the call is ignored, so a caller cannot aim the credential at some other
// request. The secret is placed only at the credential's first header site,
// and only sent to a host inside the credential's ceiling. The response body
// is drained and dropped. Nothing returned or logged contains the secret, a
// placeholder, or that body.
//
// recordHealth is optional-chained until the store's slice A is merged. If it
// throws, that store error is what the caller gets: the upstream's answer is
// never re-recorded as `unreachable`. A second probe of the same credential
// inside 60 seconds is AV_QUOTA_EXCEEDED and does not touch the network. The
// throttle reads the daemon's own clock, never a time on the call.
//
// Pins that are not a list of pins refuse the probe before the secret is
// read (AV_PIN_MISMATCH, reason 'pin_format'). They never mean "no pins".

import { Scrubber } from '../core/scrub.js'
import { deny, VaultError } from '../core/errors.js'
import { credentialHostCeiling, hostOnly, matchHost } from '../core/policy.js'
import { parseSite } from '../core/sites.js'
import { SCANNER_PATTERN } from '../core/placeholder.js'
import { extractHealth } from './profiles.js'
import { isIP } from 'node:net'
import { pinnedRequest, pinListState, urlIdentity } from './pinning.js'

const PROBE_WINDOW_MS = 60_000
// The body is never read. A little is drained so an ordinary response can
// finish; past either bound the stream is destroyed.
const DRAIN_LIMIT_BYTES = 64 * 1024
const DRAIN_TIMEOUT_MS = 2_000
const probeAt = new Map()
const PLACEHOLDER_RE = new RegExp(SCANNER_PATTERN, 'g')
// The same session-token shape the pipeline refuses to forward.
const SESSION_RE = /avs1\.[0-9a-z]{12}\.[A-Za-z0-9_-]{20,}/g

/**
 * The throttle's clock: the daemon's monotonic milliseconds, so a wall-clock
 * step cannot lock a credential out or free it early. It is never read from
 * the call; tests replace `now` here.
 */
export const probeClock = { now: () => Math.floor(performance.now()) }

/**
 * @param {{ vault: object, cred: object, profile: object, upstream?: Function }} opts
 * `path`, `method`, `body` and `now`, if a caller passes them, are not read.
 * @returns {Promise<{ ok: boolean, status: string, http_status: number|null, latency_ms: number, scopes: string[]|null, ratelimit_remaining: number|null, observed_expires_at: string|null, checked_at: string }>}
 */
export async function runProbe({ vault, cred, profile, upstream, path, method, body } = {}) {
  // These three are the request a caller might try to supply. The probe does
  // not use them. Keeping the names is what makes that choice testable.
  void path
  void method
  void body

  const probe = profile?.probe
  if (!probe || typeof probe.method !== 'string' || !probe.method || typeof probe.path !== 'string' || !isProbePath(probe.path)) {
    throw deny('AV_NOT_FOUND', 'this connector has no probe', {
      rule: 'no_probe',
      hint: 'This kind has no fixed read-only probe. Use vault_http on a path you know.',
    })
  }
  const probeMethod = probe.method
  const probePath = probe.path

  const destination = probeDestination(cred, profile)
  const header = firstHeaderSite(cred)
  if (!header) {
    throw deny('AV_NOT_FOUND', 'this credential has no header site a probe can authenticate with', {
      rule: 'no_probe',
      hint: 'A probe sends the secret only in a header site declared on the credential.',
    })
  }

  const url = destination.urlFor(probePath)
  const pins = pinsFor(cred, urlIdentity(new URL(url)))
  if (pinListState(pins) === 'invalid') {
    throw Object.assign(new Error('certificate pin mismatch'), { code: 'AV_PIN_MISMATCH', presented: [], reason: 'pin_format' })
  }

  takeProbeSlot(cred.id, probeClock.now())

  const secret = await vault.revealField(cred.id, header.field)
  const scrubber = new Scrubber([{ secret, label: cred.slug || 'cred', always: true }])
  const headers = {
    [header.site.name]: header.site.scheme ? `${header.site.scheme} ${secret}` : String(secret),
  }
  // Slack's probe is POST /api/auth.test. The secret stays in the header.
  // The body is an empty form, never a body the caller supplied.
  let requestBody
  if (probeMethod === 'POST') {
    headers['content-type'] = 'application/x-www-form-urlencoded'
    requestBody = ''
  }
  const send = typeof upstream === 'function' ? upstream : pinnedRequest
  const started = Date.now()
  let answered = null

  const finish = async (status, httpStatus, extracted) => {
    const scopes = scrubList(extracted?.scopes, scrubber)
    const observed = scrubText(extracted?.observed_expires_at ?? null, scrubber)
    const ratelimit = Number.isInteger(extracted?.ratelimit_remaining) ? extracted.ratelimit_remaining : null
    const checked_at = new Date().toISOString()
    const elapsed = (answered ?? Date.now()) - started
    const latency_ms = Number.isInteger(elapsed) && elapsed >= 0 ? elapsed : 0
    const patch = {
      status,
      http_status: httpStatus,
      checked_at,
      source: 'probe',
      observed_expires_at: observed,
      scopes,
    }
    try {
      await vault.recordHealth?.(cred.id, patch)
    } catch (e) {
      // The store refused the write. That is its error to report; the
      // upstream already answered and is not "unreachable".
      throw scrubThrown(e, scrubber)
    }
    return {
      ok: status === 'ok',
      status,
      http_status: httpStatus,
      latency_ms,
      scopes,
      ratelimit_remaining: ratelimit,
      observed_expires_at: observed,
      checked_at,
    }
  }

  let response
  try {
    response = await send({
      url,
      method: probeMethod,
      headers,
      body: requestBody,
      pins,
    })
  } catch (e) {
    if (e?.code === 'AV_PIN_MISMATCH') {
      await finish('error', null, null)
      throw scrubThrown(e, scrubber)
    }
    if (e instanceof VaultError) throw scrubThrown(e, scrubber)
    return await finish('unreachable', null, null)
  }
  answered = Date.now()
  await discard(response?.res)
  const httpStatus = Number.isInteger(response?.status) ? response.status : null
  return await finish(classify(httpStatus), httpStatus, extractHealth(profile, response?.headers))
}

function isProbePath(path) {
  return path.startsWith('/') && !path.includes('://') && !/[\s?#\\]/.test(path)
}

function takeProbeSlot(credId, now) {
  if (credId == null) {
    throw deny('AV_NOT_FOUND', 'no such credential', { rule: 'no_probe' })
  }
  const key = String(credId)
  const prev = probeAt.get(key)
  if (Number.isInteger(prev) && now - prev < PROBE_WINDOW_MS) {
    const elapsed = now >= prev ? now - prev : 0
    const retryAfter = Math.ceil((PROBE_WINDOW_MS - elapsed) / 1000)
    throw deny('AV_QUOTA_EXCEEDED', 'this credential was already probed in the last minute', {
      rule: 'probe_throttle',
      retryAfter: Number.isInteger(retryAfter) && retryAfter > 0 ? retryAfter : 60,
    })
  }
  probeAt.set(key, now)
}

function classify(httpStatus) {
  if (!Number.isInteger(httpStatus)) return 'error'
  if (httpStatus >= 200 && httpStatus < 300) return 'ok'
  if (httpStatus === 401) return 'unauthorized'
  if (httpStatus === 403) return 'forbidden'
  return 'error'
}

function probeDestination(cred, profile) {
  const declared = cred?.connector?.host || profile?.hosts?.[0]
  if (typeof declared !== 'string' || !declared.trim()) {
    throw deny('AV_POLICY_DENIED', 'this credential declares no host it may reach', { rule: 'credential_host' })
  }
  const parts = splitHostPort(declared)
  if (!parts) {
    throw deny('AV_POLICY_DENIED', 'host is outside what this credential permits', { rule: 'credential_host' })
  }
  const host = hostOnly(parts.host)
  const ceiling = credentialHostCeiling(cred, profile?.hosts || [])
  const allowed = !!host && ceiling.some((entry) => matchHost(entry, host))
  if (!allowed) {
    throw deny('AV_POLICY_DENIED', 'host is outside what this credential permits', { rule: 'credential_host' })
  }
  const scheme = String(cred?.connector?.scheme || 'https').toLowerCase()
  if (scheme !== 'https' && scheme !== 'http') {
    throw deny('AV_POLICY_DENIED', 'host is outside what this credential permits', { rule: 'credential_host' })
  }
  const authority = parts.port == null ? host : `${host}:${parts.port}`
  return {
    host,
    urlFor(pathname) {
      return `${scheme}://${authority}${pathname}`
    },
  }
}

function splitHostPort(raw) {
  const s = String(raw).trim().toLowerCase()
  if (!s || /[\s/\\?#@]/.test(s)) return null
  if (s.startsWith('[')) {
    const end = s.indexOf(']')
    if (end < 2) return null
    const host = s.slice(0, end + 1)
    const rest = s.slice(end + 1)
    if (rest === '') return usable(host, null)
    const port = /^:(\d+)$/.exec(rest)
    if (!port) return null
    return usable(host, Number(port[1]))
  }
  const colon = s.lastIndexOf(':')
  if (colon === -1) return usable(s.replace(/\.$/, ''), null)
  const host = s.slice(0, colon).replace(/\.$/, '')
  const portStr = s.slice(colon + 1)
  if (!/^\d+$/.test(portStr)) return null
  return usable(host, Number(portStr))
}

function usable(host, port) {
  if (!isHost(host)) return null
  if (port != null && (!Number.isInteger(port) || port < 1 || port > 65535)) return null
  return { host, port }
}

function isHost(host) {
  if (host.startsWith('[')) {
    if (!host.endsWith(']')) return false
    const inner = host.slice(1, -1)
    return inner.includes(':') && /^[0-9a-f:]+$/.test(inner)
  }
  if (/^\d/.test(host)) return isIpv4(host)
  if (host.length === 0 || host.length > 253) return false
  return host.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
}

function isIpv4(host) {
  const parts = host.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
}

function firstHeaderSite(cred) {
  const fields = Array.isArray(cred?.fields) ? cred.fields : []
  for (const field of fields) {
    const sites = Array.isArray(field?.sites) ? field.sites : []
    for (const spec of sites) {
      let site
      try { site = parseSite(spec) } catch { continue }
      if (site.kind === 'header') return { field: field.name, site }
    }
  }
  return null
}

/**
 * The stored pin list for `host`, the URL host the probe sends to, without
 * IPv6 brackets. Each key is read the way the URL parser reads a host, so
 * '[0:0::1]', '[::1]' and '::1', or 'API.GitHub.com.' and 'api.github.com',
 * are the same host.
 * Keys that name the same host are joined, so an empty duplicate cannot hide
 * a real list. A table or entry of the wrong shape comes back as `false`,
 * which pinListState refuses; it is never null.
 */
function pinsFor(cred, host) {
  const table = cred?.pins
  if (table == null) return null
  if (typeof table !== 'object' || Array.isArray(table)) return false
  const found = []
  for (const [key, value] of Object.entries(table)) {
    if (urlHostOf(key) !== host || value == null) continue
    if (!Array.isArray(value)) return false
    found.push(...value)
  }
  return found.length > 0 ? found : null
}

/**
 * The host the URL parser gives `key`, without IPv6 brackets, or null if it
 * names no host. A bare IPv6 address is bracketed first.
 */
function urlHostOf(key) {
  const bare = String(key).trim()
  const host = isIP(bare) === 6 ? `[${bare}]` : hostOnly(key)
  if (!host) return null
  try { return urlIdentity(new URL(`https://${host}/`)) } catch { return null }
}

function scrubText(text, scrubber) {
  if (typeof text !== 'string') return text ?? null
  let out = scrubber ? scrubber.scrub(text).text : text
  PLACEHOLDER_RE.lastIndex = 0
  out = out.replace(PLACEHOLDER_RE, '[[av:redacted]]')
  out = out.replace(SESSION_RE, '[[av:redacted]]')
  return out
}

function scrubList(list, scrubber) {
  if (!Array.isArray(list) || list.length === 0) return null
  return list.map((item) => scrubText(String(item), scrubber))
}

function scrubThrown(err, scrubber) {
  const out = Object.assign(new Error(scrubText(String(err?.message ?? ''), scrubber)), { code: err?.code })
  if (err?.reason) out.reason = err.reason
  if (Array.isArray(err?.presented)) out.presented = [...err.presented]
  if (err?.rule) out.rule = err.rule
  if (err?.hint) out.hint = scrubText(String(err.hint), scrubber)
  if (err?.detail) out.detail = scrubText(String(err.detail), scrubber)
  if (Number.isInteger(err?.retryAfter)) out.retryAfter = err.retryAfter
  if (Number.isInteger(err?.http)) out.http = err.http
  return out
}

/**
 * Drain and drop a body nobody reads: at most DRAIN_LIMIT_BYTES, for at most
 * DRAIN_TIMEOUT_MS. Past either bound the stream is destroyed, so a body that
 * never ends neither holds the probe nor keeps a socket reading.
 */
function discard(stream) {
  if (!stream || typeof stream.on !== 'function') return Promise.resolve()
  if (stream.readableEnded || stream.destroyed) return Promise.resolve()
  return new Promise((resolve) => {
    let done = false
    let bytes = 0
    const timer = setTimeout(() => finish(true), DRAIN_TIMEOUT_MS)
    const onData = (chunk) => {
      // Drop every chunk. Do not concatenate: the body is not a result.
      bytes += chunk?.length ?? 0
      if (bytes > DRAIN_LIMIT_BYTES) finish(true)
    }
    const onEnd = () => finish(false)
    function finish(cut) {
      if (done) return
      done = true
      clearTimeout(timer)
      stream.off?.('data', onData)
      stream.off?.('end', onEnd)
      stream.off?.('close', onEnd)
      if (cut) {
        try { stream.destroy?.() } catch { /* already gone */ }
      }
      resolve()
    }
    // Stays attached: a destroyed response may still report its socket.
    stream.on('error', () => finish(true))
    stream.on('end', onEnd)
    stream.on('close', onEnd)
    stream.on('data', onData)
    if (typeof stream.resume === 'function') stream.resume()
  })
}
