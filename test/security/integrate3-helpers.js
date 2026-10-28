// Scaffolding for the integrate-3 seam tests: the page as the UI server really
// serves it, a real daemon with an enrolled authenticator behind a real UI
// server, and a stand-in control socket that records what the CLI sends. Not a
// test file itself: the glob only picks up *.test.js.

import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { servedPage } from '../../src/ui/server.js'
import { startDaemon, startUi, makeAuthenticator, enrol, cli } from './fix-control-helpers.js'

/** app.html with parseOverrides injected, exactly as a browser receives it. */
export const SERVED = servedPage()

/** The source of a function or method in the served page, braces balanced. */
export function servedSource(head) {
  const start = SERVED.indexOf(head)
  if (start < 0) throw new Error(`the served page has no ${head}`)
  // The body starts at the first `{` after the signature's `)`, so a default
  // parameter's `{}` is not read as the body.
  const close = SERVED.indexOf(') {', start)
  let i = close > 0 ? close + 2 : SERVED.indexOf('{', start)
  let depth = 0
  for (; i < SERVED.length; i++) {
    if (SERVED[i] === '{') depth++
    else if (SERVED[i] === '}' && --depth === 0) break
  }
  return SERVED.slice(start, i + 1)
}

/** A `const NAME = …` line from the served page, verbatim. */
export function servedConst(name) {
  const start = SERVED.indexOf(`const ${name} = `)
  if (start < 0) throw new Error(`the served page has no const ${name}`)
  return SERVED.slice(start, SERVED.indexOf('\n', start))
}

/**
 * The page's own narrowing reader and operation builder, lifted out of the
 * served page into one scope: the injected parseOverrides, readNarrowing,
 * operationFor (WebCrypto digests), canonicalJson and DIGESTED.
 */
export function servedPageSigning() {
  return new Function(`
    ${servedSource('function parseOverrides(')}
    ${servedSource('function readNarrowing(')}
    ${servedSource('async function operationFor(')}
    ${servedConst('DIGESTED')}
    ${servedSource('function canonicalJson(')}
    return { parseOverrides, readNarrowing, operationFor, canonicalJson }`)()
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
