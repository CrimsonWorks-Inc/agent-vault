// The CLI and the web UI are two interfaces to one API.
//
// They each used to fetch their own idea of what was waiting for a human and
// write their own labels for it. So when session requests were added, they
// appeared in the CLI and not in the UI — and the UI's badge stayed at zero, so
// there was nothing to suggest anything was missing. That is not a forgotten
// line: it is two implementations of one concept, which drift the moment either
// one changes.
//
// These tests hold the two interfaces to the same answer. They are deliberately
// about equality rather than content: whatever the list is, both must show it.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { fetchPending, SOURCES, parseOverrides } from '../../src/pending.js'

const ROOT = new URL('../..', import.meta.url).pathname
let dir, vault, daemon, sock

const ctl = (method, path, body) => new Promise((resolve) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString() || '{}')))
  })
  req.on('error', () => resolve({}))
  req.end(body ? JSON.stringify(body) : undefined)
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-one-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
    fields: { token: 'ghp_ONESOURCE00112233445566778' },
    sites: { token: ['header:authorization:Bearer'] },
  })
  sock = join(dir, 'c.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
})

after(async () => {
  if (daemon) await daemon.stop()
  rmSync(dir, { recursive: true, force: true })
})

test('both interfaces read the same list from the same module', async () => {
  // Two session requests and nothing else, so the list has content the old
  // UI would have missed entirely.
  await ctl('POST', '/v1/session-requests', { cred: 'gh', methods: ['GET'], paths: ['/user'], reason: 'first' })
  await ctl('POST', '/v1/session-requests', { cred: 'gh', methods: ['GET'], paths: ['/repos'], reason: 'second' })

  const shared = await fetchPending((path) => ctl('GET', path))
  assert.equal(shared.length, 2, 'the shared list should hold both requests')
  for (const item of shared) {
    assert.equal(item.kind, 'session')
    assert.ok(item.headline, 'every item must carry a headline a human can read')
    assert.ok(item.caution, 'a session grants hours; that has to be said')
    assert.ok(item.narrowable.includes('paths'), 'a session must be narrowable')
    assert.ok(item.decide?.path, 'every item must say which route settles it')
  }

  // The CLI renders this list; the UI serves it. Neither may hold its own idea
  // of where to look.
  const cli = readFileSync(join(ROOT, 'src/cli/index.js'), 'utf8')
  const ui = readFileSync(join(ROOT, 'src/ui/server.js'), 'utf8')
  for (const [name, src] of Object.entries({ cli, ui })) {
    assert.match(src, /fetchPending\(/, `${name} must use the shared list`)
    for (const source of SOURCES) {
      const own = new RegExp(`GET'\\s*,\\s*'${source.path.replace(/\//g, '\\/')}'`)
      assert.ok(!own.test(src), `${name} fetches ${source.path} itself instead of using the shared list`)
    }
  }
})

test('the page paints the list and decides nothing about it', async () => {
  // The browser cannot import a module, so the UI server hands it the already
  // normalised list. If the page went back to fetching the raw routes it would
  // be free to disagree with the CLI again.
  const page = readFileSync(join(ROOT, 'src/ui/app.html'), 'utf8')
  assert.match(page, /api\('GET', 'pending'\)/, 'the page must read the normalised list')
  assert.ok(!/api\('GET', 'session-requests'\)/.test(page),
    'the page must not fetch a source directly')
  assert.ok(!/api\('GET', 'approvals'\)/.test(page),
    'the page must not fetch a source directly — the badge missing session requests is exactly this bug')

  // And the count a human sees covers every kind, because a decision that
  // raises no badge is one nobody knows to make.
  const badge = /approvalCount[\s\S]{0,400}/.exec(page)?.[0] || ''
  assert.ok(!badge.includes("'approvals'"), 'the badge must count everything waiting')
})

test('narrowing flags are parsed identically wherever they are typed', () => {
  // The CLI takes --paths and the UI takes a text box. Both go through one
  // parser, so "GET,POST" cannot mean two different things in two interfaces.
  assert.deepEqual(parseOverrides({ methods: 'GET, POST', paths: '/user', budget: '5' }),
    { methods: ['GET', 'POST'], paths: ['/user'], budget: 5 })
  assert.deepEqual(parseOverrides({}), {}, 'nothing typed means nothing narrowed')
  assert.deepEqual(parseOverrides({ budget: '' }), {}, 'an empty box is not a budget of zero')
})

test('a new kind of decision reaches both interfaces by construction', () => {
  // The real test of the refactor: adding a source is one entry in one array.
  // If either interface enumerated kinds itself, this would be the place that
  // caught it.
  const pending = readFileSync(join(ROOT, 'src/pending.js'), 'utf8')
  assert.match(pending, /export const SOURCES/)
  const cli = readFileSync(join(ROOT, 'src/cli/index.js'), 'utf8')
  const ui = readFileSync(join(ROOT, 'src/ui/server.js'), 'utf8')
  const page = readFileSync(join(ROOT, 'src/ui/app.html'), 'utf8')
  for (const [name, src] of Object.entries({ cli, ui, page })) {
    assert.ok(!/kind === 'session'[\s\S]{0,80}kind === 'request'/.test(src),
      `${name} enumerates the kinds itself; that list belongs in pending.js`)
  }
})
