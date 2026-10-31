// Scaffolding for the integrate-3 end-to-end tests (contract A.7): one
// throwaway vault and in-process daemon, a local upstream that records what
// reached it, the real CLI spawned against the daemon's control socket, MCP
// over the gateway's Streamable HTTP endpoint, and plain gateway requests.
// Not a test file itself: the glob only picks up *.test.js.
//
// No real network: every credential's upstream is the local server. The
// `http` credentials point at it directly. A profile credential (openai) has
// a fixed public host, so the pipeline's upstream is wrapped to send those
// requests to the same local server, over a real socket, path and headers
// unchanged.

import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import http from 'node:http'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { controlAt } from './fix-control-helpers.js'

export const PASSPHRASE = 'correct horse battery staple'
// Shaped like nothing real, and long enough to be scrubbed.
export const SECRETS = {
  gh: 'ghp_E2EINTEGRATE3aaaaaaaaaaaaaaaaaaaaaa',
  other: 'ghp_E2EOTHERCRED3bbbbbbbbbbbbbbbbbbbbbb',
  openai: 'sk-proj-E2EINTEGRATE3cccccccccccccccccccc',
}
export const ROTATED = 'ghp_E2EROTATEDVALUEdddddddddddddddddddddd'

const BIN = fileURLToPath(new URL('../../bin/agent-vault.js', import.meta.url))

// A terminal for readSecret: stdin claims to be a TTY and raw mode is a no-op,
// so the CLI takes its interactive passphrase path and reads the piped line.
const TTY_STUB = `data:text/javascript,${encodeURIComponent(
  'process.stdin.isTTY = true; process.stdin.isRaw = false; process.stdin.setRawMode = function (m) { this.isRaw = m; return this }',
)}`

/** The headers a pipeline hands its upstream, as a plain object. */
function headerObject(headers) {
  if (Array.isArray(headers)) return Object.fromEntries(headers.map(([k, v]) => [k, v]))
  if (headers && typeof headers.entries === 'function' && !(headers.constructor === Object)) return Object.fromEntries(headers.entries())
  return { ...(headers || {}) }
}

/**
 * A vault with credentials `gh` and `other` (kind http) and `openai`, a daemon
 * on `<dir>/control.sock`, and the local upstream. `reply(hit)` may
 * return (or resolve to) `{ status, headers, body }` to answer differently.
 */
export async function startE2E({ passphrase = null, reply = null } = {}) {
  const seen = []
  const upstream = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', async () => {
      const body = Buffer.concat(chunks).toString()
      const hit = { method: req.method, url: req.url, headers: req.headers, body, host: req.headers['x-e2e-host'] || req.headers.host }
      seen.push(hit)
      const out = (await reply?.(hit)) || { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
      res.writeHead(out.status ?? 200, out.headers ?? { 'content-type': 'application/json' })
      res.end(out.body ?? '')
    })
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upPort = upstream.address().port

  const dir = mkdtempSync(join(tmpdir(), 'av-e2e-'))
  const vault = Vault.create(dir, { factor: 'none' })
  for (const slug of ['gh', 'other']) {
    vault.addCredential({
      slug, kind: 'http', connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
      fields: { token: SECRETS[slug] }, sites: { token: ['header:authorization:Bearer'] },
    })
  }
  vault.addCredential({
    slug: 'openai', kind: 'openai', connector: { host: 'api.openai.com', scheme: 'https' },
    fields: { key: SECRETS.openai }, sites: { key: ['header:authorization:Bearer'] },
  })
  if (passphrase) vault.setPassphrase(passphrase)
  const sock = join(dir, 'control.sock')
  const daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()

  // Profile hosts are public names; send them to the local upstream instead.
  const original = daemon.pipeline.upstream
  daemon.pipeline.upstream = (req) => {
    const url = new URL(req.url)
    if (url.hostname === '127.0.0.1') return original(req)
    return new Promise((resolve, reject) => {
      const headers = { ...headerObject(req.headers), host: `127.0.0.1:${upPort}`, 'x-e2e-host': url.host }
      const out = http.request({ host: '127.0.0.1', port: upPort, path: url.pathname + url.search, method: req.method, headers, agent: false }, (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
      })
      out.on('error', reject)
      out.end(req.body ?? undefined)
    })
  }

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
    req.end(body ?? undefined)
  })

  /**
   * An MCP tool call as an agent holding `token` (null: an agent with no
   * session), over the gateway's Streamable HTTP endpoint. `body` is the
   * tool's JSON answer.
   */
  let rpc = 0
  const mcp = async (token, name, args = {}) => {
    const res = await fetch(`http://127.0.0.1:${daemon.gatewayPort}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpc, method: 'tools/call', params: { name, arguments: args } }),
    })
    const envelope = await res.json()
    const result = envelope.result
    if (!result) return { status: res.status, isError: true, body: envelope.error ?? envelope, text: JSON.stringify(envelope) }
    const text = result.content?.[0]?.text ?? ''
    let body = null
    try { body = JSON.parse(text) } catch { body = text }
    return { status: res.status, isError: result.isError === true, body, text }
  }

  /**
   * The real CLI. `tty: true` gives it a terminal (see TTY_STUB) whose typed
   * line is `input`. `json: true` adds --json and parses the envelope.
   */
  const cli = (args, { input, tty = false, json = false, timeout = 20_000 } = {}) => new Promise((resolve, reject) => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('AGENT_VAULT')))
    Object.assign(env, { AGENT_VAULT_DIR: dir, HOME: dir, NO_COLOR: '1' })
    const argv = [...(tty ? ['--import', TTY_STUB] : []), BIN, ...args, ...(json ? ['--json'] : [])]
    const child = spawn(process.execPath, argv, { cwd: dir, env, stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d })
    child.stderr.on('data', (d) => { stderr += d })
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`timeout: ${args.join(' ')}\n${stdout}\n${stderr}`)) }, timeout)
    child.on('close', (code) => {
      clearTimeout(timer)
      let envelope = null
      // On a terminal the passphrase prompt is written to stdout first.
      const start = stdout.search(/^\{/m)
      if (json && start >= 0) { try { envelope = JSON.parse(stdout.slice(start)) } catch { /* not an envelope */ } }
      resolve({ code, stdout, stderr, envelope, data: envelope?.data })
    })
    child.on('error', (e) => { clearTimeout(timer); reject(e) })
    if (input !== undefined) child.stdin.write(input)
    child.stdin.end()
  })

  /** A long-running CLI command, read line by line until `until(line)`. */
  const cliStream = (args) => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('AGENT_VAULT')))
    Object.assign(env, { AGENT_VAULT_DIR: dir, HOME: dir, NO_COLOR: '1' })
    const child = spawn(process.execPath, [BIN, ...args], { cwd: dir, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    child.stdout.on('data', (d) => { stdout += d })
    return {
      child,
      get stdout() { return stdout },
      wait: (until, ms = 10_000) => new Promise((resolve, reject) => {
        const started = Date.now()
        const tick = () => {
          const line = stdout.split('\n').find(until)
          if (line) return resolve(line)
          if (Date.now() - started > ms) return reject(new Error(`no matching line in: ${stdout}`))
          setTimeout(tick, 20)
        }
        tick()
      }),
      stop: () => new Promise((resolve) => {
        if (child.exitCode !== null) return resolve()
        child.once('close', resolve)
        child.kill('SIGINT')
      }),
    }
  }

  /** The gateway headers an agent sends for one session's grant. */
  const auth = (s) => ({ 'av-session': s.token, authorization: `Bearer ${s.placeholder}` })
  const audit = (kind) => vault.audit.read({ limit: 100_000 }).filter((r) => !kind || r.kind === kind)
  const files = () => ({ vault: readFileSync(join(dir, 'vault.json'), 'utf8'), audit: readFileSync(join(dir, 'audit.jsonl'), 'utf8') })
  const openWindow = () => { daemon.presenceGraceUntil = Date.now() + 60_000 }

  const stop = async () => {
    await daemon.stop()
    await new Promise((resolve) => upstream.close(resolve))
    rmSync(dir, { recursive: true, force: true })
  }
  return { dir, vault, daemon, sock, control, gateway, mcp, cli, cliStream, auth, audit, files, openWindow, seen, upPort, stop }
}

/** The grant for `slug` in a session-create answer (one or several grants). */
export function grantOf(created, slug) {
  return (created.grants || [created]).find((g) => g.cred === slug)
}
