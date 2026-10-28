// Scaffolding for the control-ui tests: a stand-in daemon on a temp control
// socket, and the page's own functions lifted out of app.html. Not a test file
// itself — the glob only picks up *.test.js.
//
// The wave-3 control routes are built by another batch at the same time, so
// the UI side is tested against a daemon that answers the contract's shapes
// and records what it was sent. The presence routes behave like the real
// daemon's: an enrolled authenticator, and challenges minted per operation.

import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { makeAuthenticator } from './fix-control-helpers.js'

export { startUi, makeAuthenticator } from './fix-control-helpers.js'

/**
 * A control socket that answers presence like the daemon and everything else
 * with `answer(key, body, url)`: either a body, or `{ status, body }`.
 */
export async function startStub(answer = () => ({ ok: true }), { enrolled = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-cui-'))
  const sock = join(dir, 'c.sock')
  const auth = makeAuthenticator()
  const calls = []
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', async () => {
      const text = Buffer.concat(chunks).toString('utf8')
      let body = null
      try { body = text ? JSON.parse(text) : null } catch { body = { unparseable: text } }
      const url = new URL(req.url, 'http://control')
      const key = `${req.method} ${url.pathname}`
      const reply = (status, obj) => {
        res.writeHead(status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(obj))
      }
      if (key === 'GET /v1/presence') return reply(200, enrolled ? auth.record : null)
      if (key === 'POST /v1/presence/challenge') {
        return reply(200, {
          challengeId: randomBytes(12).toString('base64url'),
          challenge: randomBytes(32).toString('base64url'),
          allowCredentials: [{ id: auth.record.credentialId, type: 'public-key' }],
          rpId: 'localhost',
        })
      }
      calls.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), body })
      try {
        const out = await answer(key, body, url)
        if (out && typeof out === 'object' && 'status' in out && 'body' in out) return reply(out.status, out.body)
        return reply(200, out ?? {})
      } catch (e) {
        return reply(500, { code: 'AV_INTERNAL', detail: String(e?.message ?? e) })
      }
    })
  })
  await new Promise((resolve) => server.listen(sock, resolve))
  return {
    dir, sock, auth, calls,
    // startUi asks the daemon to trust the UI's origin; this one trusts all.
    daemon: {},
    callsTo: (method, path) => calls.filter((c) => c.method === method && c.path === path),
    stop: async () => {
      await new Promise((r) => server.close(r))
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

export const PAGE = readFileSync(new URL('../../src/ui/app.html', import.meta.url), 'utf8')

/** The source of a named function in the page's script, braces balanced. */
export function pageSource(name, { async = false } = {}) {
  const head = `${async ? 'async ' : ''}function ${name}(`
  const start = PAGE.indexOf(head)
  if (start < 0) throw new Error(`the page has no ${name}()`)
  let depth = 0
  let i = PAGE.indexOf('{', start)
  // Skip the parameter list's default-object braces by starting at the body:
  // the first `{` after the closing parenthesis of the signature.
  const close = PAGE.indexOf(') {', start)
  if (close > 0) i = close + 2
  for (; i < PAGE.length; i++) {
    if (PAGE[i] === '{') depth++
    else if (PAGE[i] === '}' && --depth === 0) break
  }
  return PAGE.slice(start, i + 1)
}

/** Named page functions as callables, sharing one scope and a prelude. */
export function pageFunctions(names, prelude = '') {
  const sources = names.map((n) => (typeof n === 'string' ? pageSource(n) : pageSource(n.name, n)))
  const plain = names.map((n) => (typeof n === 'string' ? n : n.name))
  return new Function(`${PAGE_PRELUDE}\n${prelude}\n${sources.join('\n')}\nreturn { ${plain.join(', ')} }`)()
}

/** The page's small shared helpers, as the page defines them. */
const PAGE_PRELUDE = pageConst('esc')

/** A `const NAME = …` statement from the page, verbatim. */
export function pageConst(name) {
  const start = PAGE.indexOf(`const ${name} = `)
  if (start < 0) throw new Error(`the page has no const ${name}`)
  const end = PAGE.indexOf('\n', start)
  return PAGE.slice(start, end)
}
