// Telling a human that something is waiting for them (F14).
//
// A notification is a SIGNAL, never an approval channel: it carries no action,
// and whatever it links to is the normal view, where presence is still asked
// for. It never carries what an agent wrote. A reason is agent-written text put
// in front of the human, which is the phishing channel, so the words here are
// the gateway's own summary of a held request (`METHOD host/path`) or the
// daemon's summary of a session request, with any placeholder-shaped text
// replaced. A query, a body and a reason never get here at all.
//
// Two ways out:
//   - the stream on the control socket (`agent-vault watch`), at most
//     MAX_SUBSCRIBERS at once, because anything on the socket can open one;
//   - the owner's webhook, whose URL is a bearer credential (a Slack webhook
//     URL is one): the store keeps it sealed, it is decrypted here only to
//     send, and only its host is ever shown or recorded. One POST per
//     WEBHOOK_INTERVAL_MS at most, fire and forget, never following a
//     redirect.

import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { deny } from '../core/errors.js'
import * as ph from '../core/placeholder.js'
import { redactStored } from '../core/scrub.js'

export { redactStored }

export const MAX_SUBSCRIBERS = 8
const KEEPALIVE_MS = 15_000
const WEBHOOK_INTERVAL_MS = 30_000
const TEST_INTERVAL_MS = 30_000
const FAILURE_RECORD_MS = 5 * 60_000
const WEBHOOK_TIMEOUT_MS = 5_000
const MAX_PAYLOAD_BYTES = 2048
const MAX_IDS = 10
const MAX_HEADLINE = 200
const KINDS = new Set(['request', 'session'])

/**
 * A headline as it may leave the daemon: no control characters (a terminal
 * escape in a path is still an escape), no placeholder, and bounded.
 */
export function cleanHeadline(text) {
  let s = typeof text === 'string' ? text : ''
  // Replaced from the end, so earlier offsets stay right.
  for (const hit of ph.findAll(s).reverse()) s = `${s.slice(0, hit.offset)}«placeholder»${s.slice(hit.end)}`
  // eslint-disable-next-line no-control-regex
  s = s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ')
  return s.length > MAX_HEADLINE ? `${s.slice(0, MAX_HEADLINE - 1)}…` : s
}

/** Whether an event is one waiting item the notifier can describe. */
function isItem(event) {
  return !!event && typeof event === 'object' && KINDS.has(event.kind) && typeof event.id === 'string' && !!event.id
}

/**
 * One waiting item in the one shape every surface sends. Null when it cannot
 * be read. A headline is the daemon's summary, but the paths in it are the
 * agent's, and an agent that holds a stored secret can put it in one: so
 * stored secrets are redacted, and with `secrets` null (the vault cannot be
 * read) there is no headline at all.
 */
function itemOf(event, secrets) {
  if (!isItem(event)) return null
  return {
    kind: event.kind,
    id: event.id.slice(0, 64),
    headline: secrets ? cleanHeadline(redactStored(event.headline, secrets)) : '',
    created_at: typeof event.created_at === 'string' ? event.created_at.slice(0, 40) : null,
  }
}

/**
 * The body a webhook is sent. `minimal` is counts and ids; `headline` adds
 * each item's headline. Nothing else is ever in it, and it is held under
 * MAX_PAYLOAD_BYTES by dropping items, never by cutting JSON.
 */
export function webhookPayload(items, detail, { event = 'pending' } = {}) {
  const kinds = { request: 0, session: 0 }
  for (const i of items) kinds[i.kind]++
  const newest = [...items].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, MAX_IDS)
  const body = {
    source: 'agent-vault', event, waiting: items.length, kinds,
    ids: newest.map((i) => i.id),
    open: 'agent-vault approvals',
  }
  if (detail === 'headline') body.items = newest.map((i) => ({ kind: i.kind, id: i.id, headline: i.headline }))
  let text = JSON.stringify(body)
  while (Buffer.byteLength(text) > MAX_PAYLOAD_BYTES && (body.items?.length || body.ids.length)) {
    if (body.items?.length) body.items.pop()
    else body.ids.pop()
    text = JSON.stringify(body)
  }
  return text
}

/**
 * Send one webhook POST. No redirect is followed (Node's client follows none),
 * the answer's body is drained unread, and it gives up after
 * WEBHOOK_TIMEOUT_MS. Resolves `{ status }`; rejects with an error whose
 * `code` says why, never with the URL.
 */
function defaultSend({ url, method, headers, body }) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url)
    const send = parsed.protocol === 'https:' ? httpsRequest : httpRequest
    const req = send(parsed, { method, headers, agent: false, timeout: WEBHOOK_TIMEOUT_MS }, (res) => {
      res.resume()
      res.on('end', () => resolve({ status: res.statusCode }))
      res.on('error', () => resolve({ status: res.statusCode }))
    })
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'timeout' })))
    req.on('error', (e) => reject(Object.assign(new Error('send failed'), { code: typeof e?.code === 'string' ? e.code : 'error' })))
    req.end(body)
  })
}

export class Notifier {
  /**
   * @param {import('../store/vault.js').Vault} vault
   * @param {{ fetchImpl?: Function, snapshot?: () => object[] }} opts
   *   `snapshot` returns everything waiting now, as pending events.
   *   `fetchImpl({ url, method, headers, body }) → Promise<{ status }>`
   *   replaces the network, for tests.
   */
  constructor(vault, { fetchImpl = null, snapshot = () => [] } = {}) {
    this.vault = vault
    this.send = fetchImpl || defaultSend
    this.snapshot = snapshot
    this.subscribers = new Set()
    this.lastSent = 0
    this.lastTest = 0
    this.lastFailureRecorded = 0
    this.timer = null
    this.closed = false
  }

  /** Every stored secret, for redacting headlines; null when the vault cannot give them. */
  #secrets() {
    try { return this.vault.allSecrets() } catch { return null }
  }

  /** What is waiting now, cleaned. */
  #waiting() {
    let rows = []
    try { rows = this.snapshot() || [] } catch { rows = [] }
    const secrets = rows.length ? this.#secrets() : null
    return rows.map((r) => itemOf(r, secrets)).filter(Boolean)
  }

  /** Something new is waiting. Never throws: the caller is holding a request. */
  pending(event) {
    if (this.closed || !isItem(event)) return
    // allSecrets() decrypts the whole vault, and a held request is something
    // an agent can cause at will: only when someone is watching.
    if (this.subscribers.size) {
      const frame = `event: pending\ndata: ${JSON.stringify(itemOf(event, this.#secrets()))}\n\n`
      for (const res of this.subscribers) {
        try { res.write(frame) } catch { this.subscribers.delete(res) }
      }
    }
    this.#scheduleWebhook()
  }

  /**
   * Add a stream subscriber: the snapshot first, then each new item, with a
   * keep-alive comment so idle proxies do not cut it. Refused past
   * MAX_SUBSCRIBERS, before anything is written.
   */
  subscribe(res) {
    if (this.closed) throw deny('AV_NOT_FOUND', 'the daemon is stopping')
    if (this.subscribers.size >= MAX_SUBSCRIBERS) {
      throw deny('AV_QUOTA_EXCEEDED', `at most ${MAX_SUBSCRIBERS} watchers at once`, { rule: 'stream_limit', retryAfter: 30 })
    }
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' })
    res.write(`event: snapshot\ndata: ${JSON.stringify({ items: this.#waiting() })}\n\n`)
    this.subscribers.add(res)
    const keepAlive = setInterval(() => {
      try { res.write(': ping\n\n') } catch { /* closed below */ }
    }, KEEPALIVE_MS)
    keepAlive.unref?.()
    res.on('close', () => {
      clearInterval(keepAlive)
      this.subscribers.delete(res)
    })
  }

  /** The configured webhook, or null. Never thrown on: a locked vault has none to use. */
  #webhook() {
    try {
      if (this.vault.locked || !this.vault.notifyConfig?.()) return null
      return this.vault.getNotifyWebhook()
    } catch { return null }
  }

  /** At most one POST per interval: the first item sends now, the rest wait for the next slot. */
  #scheduleWebhook() {
    if (this.timer || !this.vault.notifyConfig?.()) return
    const wait = Math.max(0, this.lastSent + WEBHOOK_INTERVAL_MS - Date.now())
    if (wait === 0) {
      this.#sendWebhook()
      return
    }
    this.timer = setTimeout(() => { this.timer = null; this.#sendWebhook() }, wait)
    this.timer.unref?.()
  }

  #sendWebhook() {
    const hook = this.#webhook()
    if (!hook || this.closed) return
    const items = this.#waiting()
    if (!items.length) return
    this.lastSent = Date.now()
    this.#post(hook, webhookPayload(items, hook.detail), items.length).catch(() => {})
  }

  /** POST a payload; records the outcome by host. Resolves `{ sent, status?, error? }`. */
  async #post(hook, body, count) {
    try {
      const res = await this.send({
        url: hook.url, method: 'POST', body,
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'user-agent': 'agent-vault' },
      })
      const status = Number.isInteger(res?.status) ? res.status : 0
      if (status >= 200 && status < 300) {
        this.#record('notify.sent', { host: hook.host, items: count })
        return { sent: true, status }
      }
      this.#failed(hook.host, `status_${status}`)
      return { sent: false, status }
    } catch (e) {
      // A system error code (ECONNREFUSED) or `error`, never free text.
      const reason = typeof e?.code === 'string' && /^E[A-Z0-9_]{1,39}$/.test(e.code) ? e.code : 'error'
      this.#failed(hook.host, reason)
      return { sent: false, error: reason }
    }
  }

  /** A failure is recorded at most once per FAILURE_RECORD_MS, so a dead endpoint cannot flood the log. */
  #failed(host, reason) {
    const now = Date.now()
    if (now - this.lastFailureRecorded < FAILURE_RECORD_MS) return
    this.lastFailureRecorded = now
    this.#record('notify.failed', { host, reason })
  }

  #record(kind, fields) {
    try { if (!this.vault.locked) this.vault.audit?.write(kind, fields) } catch { /* the send already happened or did not */ }
  }

  /**
   * Send a test notification now (POST /v1/notify/test). Throttled to one per
   * TEST_INTERVAL_MS, because anything on the socket can call it and each one
   * lands on the owner's phone.
   */
  async test() {
    if (this.vault.locked) throw deny('AV_LOCKED', 'unlock the vault to use the webhook')
    const hook = this.#webhook()
    if (!hook) throw deny('AV_NOT_FOUND', 'no webhook is configured')
    const now = Date.now()
    if (now - this.lastTest < TEST_INTERVAL_MS) {
      const wait = Math.ceil((this.lastTest + TEST_INTERVAL_MS - now) / 1000)
      throw deny('AV_QUOTA_EXCEEDED', 'a test notification was sent less than 30 seconds ago', { retryAfter: Math.max(1, wait) })
    }
    this.lastTest = now
    const items = this.#waiting()
    return this.#post(hook, webhookPayload(items, hook.detail, { event: 'test' }), items.length)
  }

  /** End every stream and drop the timer, so the daemon can stop. */
  close() {
    this.closed = true
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
    for (const res of this.subscribers) {
      try { res.end() } catch { /* already gone */ }
    }
    this.subscribers.clear()
  }
}
