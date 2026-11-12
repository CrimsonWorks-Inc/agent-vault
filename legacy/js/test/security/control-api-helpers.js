// Shared scaffolding for the control-api (wave 3) tests: a temp vault whose
// credential points at a local upstream that counts what reaches it, an
// in-process daemon on a temp control socket, and clients for the control
// socket, the gateway and MCP. Not a test file itself: the glob only picks
// up *.test.js.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import http from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { controlAt } from './fix-control-helpers.js'

export const PASSPHRASE = 'correct horse battery staple'
export const SECRET = 'ghp_CONTROLAPI00112233445566778899aabb'
export const HOUR = 3_600_000

/**
 * A vault with credential `demo` (kind http) aimed at a local upstream, and
 * a daemon in front of it. `passphrase` turns the presence gate on.
 */
export async function startApi({ passphrase = null, notifyFetch = null, upstreamReply = null } = {}) {
  const seen = []
  const upstream = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() })
      if (upstreamReply) return upstreamReply(req, res)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end('{"ok":true}')
    })
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upPort = upstream.address().port

  const dir = mkdtempSync(join(tmpdir(), 'av-api-'))
  const vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  if (passphrase) vault.setPassphrase(passphrase)
  const sock = join(dir, 'c.sock')
  const daemon = await new Daemon(vault, { port: 0, socketPath: sock, notifyFetch }).start()
  const control = (method, path, body) => controlAt(sock, method, path, body)

  /** One gateway request on the built-in loopback listener. */
  const gateway = (path, { method = 'GET', headers = {}, body = null } = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: daemon.gatewayPort, path, method, agent: false, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString()
        let json = null
        try { json = JSON.parse(text) } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json })
      })
    })
    req.on('error', reject)
    req.end(body)
  })

  /** Call an MCP tool as an agent holding `token` (or none). */
  const tool = async (name, args = {}, { token = null, listener = null } = {}) => {
    const session = token ? vault.sessionByToken(token) : null
    const r = await daemon.mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }, session, token ?? '', listener)
    const result = r.result
    return { isError: result.isError === true, body: JSON.parse(result.content[0].text) }
  }

  /** A session made directly in the vault: one grant on `demo`, one placeholder. */
  const session = ({ policy = {}, infinite = false, ttlMs = null, grantTtlMs = null, label = 'agent' } = {}) => {
    const cred = vault.findCredential('demo')
    const made = vault.createSession({ label, infinite, ttlMs: infinite ? null : (ttlMs ?? 8 * HOUR) })
    const grant = vault.createGrant({
      sessionId: made.session.id, credentialId: cred.id, fields: ['token'], ttlMs: grantTtlMs,
      policy: {
        hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/**'],
        budget: { unit: 'requests', limit: 100 }, approval: 'auto', ...policy,
      },
    })
    const { placeholder } = vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
    return { ...made, grant, placeholder }
  }

  const openWindow = () => { daemon.presenceGraceUntil = Date.now() + 60_000 }
  const closeWindow = () => { daemon.presenceGraceUntil = 0 }
  const audit = (kind) => vault.audit.read({ limit: 100_000 }).filter((r) => !kind || r.kind === kind)

  const stop = async () => {
    await daemon.stop()
    await new Promise((resolve) => upstream.close(resolve))
    rmSync(dir, { recursive: true, force: true })
  }
  return { dir, vault, daemon, sock, control, gateway, tool, session, openWindow, closeWindow, audit, seen, upPort, stop }
}

/** Open a GET stream on the control socket and collect its SSE events. */
export function stream(sock, path = '/v1/pending/stream', headers = {}) {
  return new Promise((resolve, reject) => {
    const events = []
    let buffer = ''
    const req = http.request({ socketPath: sock, path, method: 'GET', headers }, (res) => {
      const handle = {
        status: res.statusCode, headers: res.headers, events,
        close: () => { req.destroy() },
        /** Resolves once `n` events have arrived. */
        wait: (n, ms = 2000) => new Promise((ok, fail) => {
          const started = Date.now()
          const tick = () => {
            if (events.length >= n) return ok(events)
            if (Date.now() - started > ms) return fail(new Error(`only ${events.length} events: ${JSON.stringify(events)}`))
            setTimeout(tick, 10)
          }
          tick()
        }),
      }
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        buffer += chunk
        let at
        while ((at = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, at)
          buffer = buffer.slice(at + 2)
          const event = /^event: (.*)$/m.exec(frame)?.[1]
          const data = /^data: (.*)$/m.exec(frame)?.[1]
          if (event) events.push({ event, data: data ? JSON.parse(data) : null, raw: frame })
          else if (!frame.startsWith(':')) events.push({ event: null, raw: frame })
        }
      })
      res.on('error', () => {})
      if (res.statusCode !== 200) {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => resolve({ ...handle, body: (() => { try { return JSON.parse(buffer) } catch { return null } })() }))
        return
      }
      resolve(handle)
    })
    req.on('error', reject)
    req.end()
  })
}
