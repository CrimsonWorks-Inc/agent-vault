// Scaffolding for the integrate-3 seam tests: the page's own signing, a real
// daemon with an enrolled authenticator behind a real UI server, and a
// stand-in control socket that records what the CLI sends. Not a test file
// itself: the glob only picks up *.test.js.

import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { parseOverrides } from '../../src/pending.js'
import { operationFor, canonicalJson } from '../../../../web/src/lib/presence.js'
import { readNarrowing } from '../../../../web/src/components/approvals/decide.js'
import { startDaemon, startUi, makeAuthenticator, enrol, cli } from './fix-control-helpers.js'

/**
 * The page's own narrowing reader and operation builder, from the modules the
 * bundle is built from: parseOverrides is src/pending.js's (the bundle imports
 * it, C21; one-source-of-truth.test.js proves the built bundle does),
 * readNarrowing is web/src/components/approvals/decide.js's, and
 * operationFor / canonicalJson are web/src/lib/presence.js's (WebCrypto).
 */
export function pageSigning() {
  return { parseOverrides, readNarrowing, operationFor, canonicalJson }
}

/**
 * A real daemon with `demo`, an enrolled authenticator and no passphrase, so
 * every gated call needs a signature the daemon verifies itself, and a real
 * UI server in front of it with its launch link claimed.
 */
export async function startSigned(options = {}) {
  const d = await startDaemon(options)
  const u = await startUi(d)
  const auth = makeAuthenticator(u.ui.origin)
  enrol(d.vault, auth)
  return { d, u, auth, stop: async () => { await u.stop(); await d.stop() } }
}

/**
 * A control socket where the CLI looks for one (`control.sock` under
 * AGENT_VAULT_DIR) that lists one pending session request and records every
 * call. `run(argv)` runs the real CLI against it with --json.
 */
export async function startCliStub(item = { id: 'sr_x', summary: 'session for demo', created_at: '2030-01-01T00:00:00Z', proposal: { cred: 'demo' } }) {
  const dir = mkdtempSync(join('/tmp', 'av-i3-'))
  const calls = []
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString()
      calls.push({ method: req.method, path: req.url, body: text ? JSON.parse(text) : null })
      res.writeHead(200, { 'content-type': 'application/json' })
      if (req.url === '/v1/session-requests') return res.end(JSON.stringify([item]))
      if (req.url === '/v1/approvals') return res.end('[]')
      res.end(JSON.stringify({ id: item.id, state: 'approved' }))
    })
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(join(dir, 'control.sock'), resolve) })
  const run = async (argv) => {
    const r = await cli(dir, [...argv, '--json'], { env: { HOME: dir, AGENT_VAULT_SESSION: '' } })
    let envelope = null
    try { envelope = JSON.parse(r.stdout) } catch { /* not JSON */ }
    return { ...r, envelope }
  }
  const decisions = () => calls.filter((c) => c.method === 'POST' && c.path === '/v1/session-requests/decide')
  const stop = async () => {
    await new Promise((resolve) => server.close(resolve))
    rmSync(dir, { recursive: true, force: true })
  }
  return { dir, calls, run, decisions, stop }
}

/** CLI flags for a typed narrowing: `{ budget: '5' }` → `['--budget', '5']`. */
export const flagsOf = (typed) => Object.entries(typed).flatMap(([k, v]) => (v === true ? [`--${k}`] : [`--${k}`, v]))
