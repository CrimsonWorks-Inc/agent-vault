#!/usr/bin/env node
// A throwaway vault to look at the built page against (contract U9).
// Development only: never shipped (web/ is not in "files").
//
//   node web/scripts/dev-vault.mjs [--port 5180] [--enrolled] [--locked] [--pending 3]
//                                  [--sessions 64] [--creds 6] [--templates 0]
//
// It builds nothing. It serves whatever is in src/ui/dist, so run
// `npm run build:ui` first. In one process it:
//
//   1. creates a vault in a fresh temp dir, never the real one, with fake
//      credentials (sk-test-..., ghp_test...), more than 60 sessions and more
//      than 200 audit records, so every list has pages;
//   2. starts a daemon on that vault (its own control socket, gateway port 0)
//      and an `agent-vault ui` server for it (src/ui/server.js, unchanged);
//   3. claims the UI server's launch token itself and forwards everything on
//      http://127.0.0.1:<port> to that UI server with its session cookie, so
//      the page, its assets and their CSP are exactly what the UI server
//      serves (U2), and the link can be opened by any number of browsers.
//
// --enrolled stores a generated P-256 key as the presence authenticator, so
// the page shows the enrolled state (no signature can be made with it from a
// browser; gated flows stop at the presence prompt, as U9 says they will).
// --locked locks the vault after seeding. --pending N leaves N session
// requests waiting in Approvals. --creds N stores N credentials (at least the
// six named ones) and --templates N saves N session templates, so those
// lists have pages too.
//
// Ctrl-C removes the temp dir.

import http from 'node:http'
import { mkdtempSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { parseArgs } from 'node:util'

const ROOT = fileURLToPath(new URL('../..', import.meta.url))
const DIST = join(ROOT, 'src/ui/dist')
const { Vault } = await import(join(ROOT, 'src/store/vault.js'))
const { Daemon } = await import(join(ROOT, 'src/daemon/server.js'))
const { UiServer } = await import(join(ROOT, 'src/ui/server.js'))

const { values: args } = parseArgs({
  options: {
    port: { type: 'string', default: '5180' },
    enrolled: { type: 'boolean', default: false },
    locked: { type: 'boolean', default: false },
    pending: { type: 'string', default: '3' },
    sessions: { type: 'string', default: '64' },
    creds: { type: 'string', default: '6' },
    templates: { type: 'string', default: '0' },
  },
})

if (!existsSync(join(DIST, 'index.html'))) {
  console.error('src/ui/dist/index.html is missing: run npm run build:ui first')
  process.exit(1)
}

// ---- 1. the vault ------------------------------------------------------------

const dir = mkdtempSync(join(tmpdir(), 'av-dev-vault-'))
const cleanup = () => { try { rmSync(dir, { recursive: true, force: true }) } catch { /* gone */ } }
process.on('exit', cleanup)
process.on('SIGINT', () => process.exit(0))
process.on('SIGTERM', () => process.exit(0))

// A local upstream, so gateway traffic (and the audit rows it writes) never
// leaves the machine.
const upstream = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}') })
await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
const upHost = `127.0.0.1:${upstream.address().port}`

const vault = Vault.create(dir, { factor: 'none' })
const CREDS = [
  ['gh-work', 'ghp_test', 'Aa'],
  ['gh-personal', 'ghp_test', 'Bb'],
  ['openai-dev', 'sk-test-', 'Cc'],
  ['anthropic-dev', 'sk-test-ant-', 'Dd'],
  ['stripe-test', 'sk_test_', 'Ee'],
  ['internal-api', 'tok_test_', 'Ff'],
]
for (let i = CREDS.length; i < Number(args.creds); i++) CREDS.push([`svc-${String(i).padStart(2, '0')}`, 'tok_test_', 'Zz'])
for (const [slug, prefix, fill] of CREDS) {
  vault.addCredential({
    slug, kind: 'http', connector: { host: upHost, scheme: 'http' },
    fields: { token: `${prefix}${fill.repeat(20)}` }, sites: { token: ['header:authorization:Bearer'] },
  })
}
// A passphrase, so widening calls can carry fresh presence the way the CLI's do.
const PASSPHRASE = 'dev vault passphrase, not a secret'
vault.setPassphrase(PASSPHRASE)
vault.setCredentialExpiry('openai-dev', new Date(Date.now() + 4 * 86400e3).toISOString())
vault.setQuarantine('internal-api', { by: 'control', reason: 'rotating after a test leak\u202e(written by a test)' })

const sock = join(dir, 'control.sock')
const daemon = await new Daemon(vault, { port: 0, socketPath: sock, uiPort: 0 }).start()

function control(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null
    const req = http.request({ socketPath: sock, path, method, headers: { 'content-type': 'application/json', ...(payload ? { 'content-length': payload.length } : {}) } }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(Buffer.concat(chunks).toString() || '{}') } catch { parsed = {} }
        if (res.statusCode >= 400) reject(Object.assign(new Error(parsed.detail || parsed.error || `HTTP ${res.statusCode}`), { body: parsed }))
        else resolve(parsed)
      })
    })
    req.on('error', reject)
    req.end(payload ?? undefined)
  })
}

const gateway = (path, token, method = 'GET') => new Promise((resolve) => {
  const req = http.request({ host: '127.0.0.1', port: daemon.gatewayPort, path, method, agent: false, headers: { authorization: `Bearer ${token}` } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)) })
  req.on('error', () => resolve(0))
  req.end()
})

// ---- seed: sessions, traffic, requests ----------------------------------------

const AGENTS = ['claude-code', 'cursor', 'codex', 'gemini-cli', 'ci-runner', 'deploy-bot']
const tokens = []
const nSessions = Number(args.sessions)
for (let i = 0; i < nSessions; i++) {
  const cred = CREDS[i % 5][0]
  const body = {
    label: `${AGENTS[i % AGENTS.length]} #${String(i + 1).padStart(2, '0')}`,
    grants: [{ cred, methods: i % 3 ? ['GET'] : ['GET', 'POST', 'DELETE'], paths: ['/**'], approval: i % 4 === 0 ? 'on-write' : 'auto' }],
    ...(i % 17 === 0 ? { infinite: true } : { ttl_hours: 1 + (i % 48) }),
    presence: { passphrase: PASSPHRASE },
  }
  try {
    // What the CLI does: a short presence window for an ordinary widening,
    // and the passphrase in the body for one that needs it fresh.
    await control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
    const s = await control('POST', '/v1/sessions', body)
    tokens.push({ sid: s.session_id, token: s.token, cred })
  } catch (e) { console.error(`session ${i}: ${e.message}`) }
}
// Traffic: allowed reads, and a few refusals (a write the grant does not allow).
let requests = 0
for (let round = 0; round < 3; round++) {
  for (const t of tokens) {
    await gateway(`/p/${t.cred}/repos/acme/app/issues?page=${round}`, t.token)
    requests++
    if (round === 0 && requests % 5 === 0) await gateway(`/p/${t.cred}/admin/keys`, t.token, 'PUT')
  }
}
// A few revoked, so the list has more than one state.
for (const t of tokens.slice(0, 6)) await control('DELETE', `/v1/sessions?sid=${encodeURIComponent(t.sid)}`).catch(() => {})

// Session requests waiting for a human: an agent with no session asking.
const nPending = Number(args.pending)
for (let i = 0; i < nPending; i++) {
  await control('POST', '/v1/session-requests', {
    cred: 'gh-work',
    methods: ['GET'],
    paths: ['/repos/acme/app/**'],
    reason: i === 0 ? 'Need to open a PR\u202e and nothing else. <b>Approve</b>' : `Read the CI logs for build ${4100 + i}`,
  }).catch((e) => console.error(`request ${i}: ${e.message}`))
}

for (let i = 0; i < Number(args.templates); i++) {
  await control('POST', '/v1/presence/window', { passphrase: PASSPHRASE }).catch(() => {})
  await control('POST', '/v1/templates', {
    name: `tpl-${String(i + 1).padStart(2, '0')}`,
    spec: { cred: CREDS[i % 5][0], methods: i % 2 ? ['GET'] : ['GET', 'POST'], paths: ['/repos/**'], ttl_hours: 1 + (i % 8) },
    presence: { passphrase: PASSPHRASE },
  }).catch((e) => console.error(`template ${i}: ${e.message}`))
}

if (args.enrolled) {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  vault.setPresenceKey({
    credentialId: randomBytes(32).toString('base64url'),
    publicKeySpki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  })
}

// ---- 2. the UI server, and its session ------------------------------------------

const ui = await new UiServer(sock, { port: 0, idleMs: 8 * 3600_000, statePath: join(dir, 'cli-state.json') }).start()
const claim = await fetch(ui.url, { redirect: 'manual' })
const cookie = /av_ui=([^;]+)/.exec(claim.headers.get('set-cookie') || '')?.[1]
if (!cookie) throw new Error('could not claim the UI server session')

if (args.locked) await control('POST', '/v1/lock', {}).catch((e) => console.error(`lock: ${e.message}`))

// ---- 3. the page, as the UI server serves it ---------------------------------

// Every path goes to the real UI server (src/ui/server.js), which serves the
// built page and its assets from memory under the strict CSP (U2) and answers
// /api. This only adds the session cookie, and the Host and Origin the UI
// server expects, so the link works for any browser and any number of loads.
const page = http.createServer((req, res) => {
  const headers = { ...req.headers, host: `localhost:${ui.boundPort}`, cookie: `av_ui=${cookie}` }
  if (headers.origin) headers.origin = ui.origin
  const up = http.request({ host: '127.0.0.1', port: ui.boundPort, path: req.url, method: req.method, headers }, (r) => {
    const h = { ...r.headers }
    delete h['set-cookie']
    res.writeHead(r.statusCode, h)
    r.pipe(res)
  })
  up.on('error', () => { res.writeHead(502); res.end('{"error":"ui server gone"}') })
  req.pipe(up)
})
await new Promise((r) => page.listen(Number(args.port), '127.0.0.1', r))

const audit = await control('GET', '/v1/audit?limit=500').catch(() => [])
console.log(JSON.stringify({
  page: `http://127.0.0.1:${page.address().port}/`,
  ui_server: ui.origin,
  vault_dir: dir,
  sessions: tokens.length,
  credentials: CREDS.length,
  templates: Number(args.templates),
  audit_records: Array.isArray(audit) ? audit.length : null,
  pending: nPending,
  enrolled: args.enrolled,
  locked: args.locked,
}))
