// The web page and the docs it carries.
//
// - Narrowing a session request before approving always failed with 409: the
//   page signed the raw text it read from the inputs ("GET", "100"), and the
//   UI server rebuilt the operation from parsed values (["GET"], 100).
// - The hand-off card's example sent two Authorization headers, so the
//   placeholder was dropped for every Bearer-site credential.
// - The docs told readers to put a placeholder in X-Agent-Vault-Cred (refused
//   as AV_BAD_LOCATION), listed five of seven MCP tools, and gave a passphrase
//   backoff twice the real one.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { operationFor, canonicalOperation } from '../../src/ui/webauthn.js'
import { parseOverrides } from '../../src/pending.js'
import { McpServer } from '../../src/daemon/mcp.js'
import { servedPage } from '../../src/ui/server.js'
import { startDaemon, startUi, makeAuthenticator, enrol, PASSPHRASE } from './fix-control-helpers.js'

const PAGE = readFileSync(new URL('../../src/ui/app.html', import.meta.url), 'utf8')
const README = readFileSync(new URL('../../README.md', import.meta.url), 'utf8')

/** A named function from the page's script, as a callable. */
function pageFunction(name, page = PAGE) {
  const PAGE = page
  const start = PAGE.indexOf(`function ${name}(`)
  assert.ok(start >= 0, `the page has no ${name}()`)
  let depth = 0
  // The body, not a default parameter's braces: `(args = {}) {`.
  let i = PAGE.indexOf(') {', start) + 2
  for (; i < PAGE.length; i++) {
    if (PAGE[i] === '{') depth++
    else if (PAGE[i] === '}' && --depth === 0) break
  }
  const async = PAGE.slice(start - 6, start) === 'async ' ? 'async ' : ''
  return new Function(`${async}${PAGE.slice(start, i + 1)}; return ${name}`)()
}

const RAW = [
  { methods: 'GET' },
  { methods: 'get, post', paths: '/repos/a/**,/repos/b/**', budget: '100' },
  { uses: '3', ttl_minutes: '15' },
  { paths: '/user' },
]

test('what the page signs for a narrowing is what the server rebuilds', () => {
  // The parser the page runs is the one the server puts in it (C21).
  const narrowing = pageFunction('parseOverrides', servedPage())
  for (const raw of RAW) {
    const page = narrowing(raw)
    const signed = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...page }))
    // The UI server parses what the page sends; the daemon binds the result.
    const rebuilt = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...parseOverrides(page) }))
    assert.equal(signed, rebuilt, `${JSON.stringify(raw)} would be refused as a different operation`)
    assert.deepEqual(page, parseOverrides(raw), 'and it reads the inputs the way the CLI flags are read')
  }
  assert.match(PAGE, /const overrides = parseOverrides\(typed\)/, 'the decide action must sign the parsed narrowing')
})

test('a narrowed approval made the way the page makes it goes through', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const u = await startUi(d)
  try {
    const auth = makeAuthenticator(u.ui.origin)
    enrol(d.vault, auth)
    const asked = (await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], budget: 500 })).body
    const overrides = pageFunction('parseOverrides', servedPage())({ methods: 'get', paths: '/user,/user/repos', budget: '10' })
    const presence = await u.presence(auth, operationFor('session_request.decide', { id: asked.id, granted: true, ...overrides }))
    const res = await u.api('POST', 'session-requests/decide', { id: asked.id, granted: true, overrides, presence })
    const body = await res.json()
    assert.equal(res.status, 200, JSON.stringify(body))
    const grant = d.vault.grantsForSession(body.recorded.session_id)[0]
    assert.deepEqual(grant.policy.methods, ['GET'])
    assert.deepEqual(grant.policy.paths, ['/user', '/user/repos'])
    assert.equal(grant.policy.budget.limit, 10)
  } finally { await u.stop(); await d.stop() }
})

test('the hand-off example sends the token where it cannot displace the placeholder', () => {
  const example = pageFunction('exampleCall')({
    sites: ['header:authorization:Bearer'], token: 'avs1.abc.def', placeholder: 'av1.ph', base_url: 'http://127.0.0.1:7411/p/demo', probe: '/user',
  })
  assert.equal((example.match(/authorization:/gi) || []).length, 1, example)
  assert.match(example, /-H "AV-Session: avs1\.abc\.def"/)
  assert.match(example, /-H "authorization: Bearer av1\.ph"/i)
})

test('the docs name every MCP tool, and only injection sites that exist', () => {
  const names = new McpServer({}, null, () => null).tools.map((t) => t.name)
  for (const name of names) {
    assert.ok(PAGE.includes(`<code>${name}</code>`), `the docs page does not list ${name}`)
    assert.ok(README.includes(`\`${name}\``), `the README does not list ${name}`)
  }
  assert.ok(!/X-Agent-Vault-Cred/i.test(PAGE), 'no profile declares that header as a site')
  assert.ok(!/up to a minute/.test(PAGE + README), 'the backoff caps at thirty seconds')
  assert.ok(!/is this one still valid/.test(PAGE), 'ph check is an offline grammar check')
})

// Round 3, review finding 5, option C. Without a passphrase the page does not
// offer Touch ID unlock and does not ask for a tap: it says what the daemon
// says, in the daemon's words, and names the command that fixes it.
test('without a passphrase the page gives the daemon\'s guidance instead of a tap', async () => {
  const guidance = PAGE.match(/const TOUCHID_NEEDS_PASSPHRASE = '([^']+)'/)?.[1]
  assert.ok(guidance, 'the page names its guidance once')
  const STORE = readFileSync(new URL('../../src/store/vault.js', import.meta.url), 'utf8')
  assert.ok(STORE.includes(`hint: '${guidance}'`), 'the page and the daemon say the same thing')
  assert.match(guidance, /agent-vault passphrase set/)

  const enable = pageFunction('enableTouchId')
  const saved = { api: globalThis.api, navigator: Object.getOwnPropertyDescriptor(globalThis, 'navigator') }
  try {
    globalThis.TOUCHID_NEEDS_PASSPHRASE = guidance
    globalThis.b64ToBuf = () => new Uint8Array(4)
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true, value: { credentials: { create: async () => { throw new Error('reached the authenticator') } } },
    })
    globalThis.api = async () => ({ has_passphrase: false, rp_id: 'localhost', prf_salt: 'AAAA' })
    await assert.rejects(enable(), (e) => e.message === guidance)
    // With a passphrase, it goes on to the authenticator.
    globalThis.api = async () => ({ has_passphrase: true, rp_id: 'localhost', prf_salt: 'AAAA' })
    await assert.rejects(enable(), /reached the authenticator/)
  } finally {
    globalThis.api = saved.api
    delete globalThis.b64ToBuf
    delete globalThis.TOUCHID_NEEDS_PASSPHRASE
    if (saved.navigator) Object.defineProperty(globalThis, 'navigator', saved.navigator)
    else delete globalThis.navigator
  }

  // The Unlocking card shows the guidance, with no Enable button, on a vault
  // with no passphrase.
  const row = PAGE.match(/if \(!ls\.has_passphrase && prfSupported\(\)\) \{([\s\S]*?)\} else if/)?.[1]
  assert.ok(row, 'a vault with no passphrase gets a Touch ID row')
  assert.match(row, /esc\(TOUCHID_NEEDS_PASSPHRASE\)/)
  assert.ok(!/touchid-enable/.test(row), 'no Enable button without a passphrase')
  // Option A's warning and its no-recovery text are gone.
  assert.ok(!/Turn on Touch ID unlock anyway|nothing else opens the vault|recovery: false/.test(PAGE + README))
})
