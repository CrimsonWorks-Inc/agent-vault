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
import { startDaemon, startUi, makeAuthenticator, enrol, PASSPHRASE } from './fix-control-helpers.js'

const PAGE = readFileSync(new URL('../../src/ui/app.html', import.meta.url), 'utf8')
const README = readFileSync(new URL('../../README.md', import.meta.url), 'utf8')

/** A named function from the page's script, as a callable. */
function pageFunction(name) {
  const start = PAGE.indexOf(`function ${name}(`)
  assert.ok(start >= 0, `the page has no ${name}()`)
  let depth = 0
  let i = PAGE.indexOf('{', start)
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
  const narrowing = pageFunction('parseNarrowing')
  for (const raw of RAW) {
    const page = narrowing(raw)
    const signed = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...page }))
    // The UI server parses what the page sends; the daemon binds the result.
    const rebuilt = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...parseOverrides(page) }))
    assert.equal(signed, rebuilt, `${JSON.stringify(raw)} would be refused as a different operation`)
    assert.deepEqual(page, parseOverrides(raw), 'and it reads the inputs the way the CLI flags are read')
  }
  assert.match(PAGE, /const overrides = parseNarrowing\(typed\)/, 'the decide action must sign the parsed narrowing')
})

test('a narrowed approval made the way the page makes it goes through', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const u = await startUi(d)
  try {
    const auth = makeAuthenticator(u.ui.origin)
    enrol(d.vault, auth)
    const asked = (await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], budget: 500 })).body
    const overrides = pageFunction('parseNarrowing')({ methods: 'get', paths: '/user,/user/repos', budget: '10' })
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

// Round 2. The page refused to start Touch ID unlock on a vault with no
// passphrase, whatever the daemon allowed, and hid the button there too.
test('the page offers Touch ID unlock without a passphrase, after saying what that costs', async () => {
  const enable = pageFunction('enableTouchId')
  const saved = { api: globalThis.api, confirm: globalThis.confirm, navigator: Object.getOwnPropertyDescriptor(globalThis, 'navigator') }
  const asked = []
  try {
    globalThis.api = async () => ({ has_passphrase: false, rp_id: 'localhost', prf_salt: 'AAAA' })
    globalThis.b64ToBuf = () => new Uint8Array(4)
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true, value: { credentials: { create: async () => { throw new Error('reached the authenticator') } } },
    })
    // Declined: nothing happens, and nothing is thrown at the owner.
    globalThis.confirm = (text) => { asked.push(text); return false }
    assert.equal(await enable(), false)
    assert.match(asked[0], /no passphrase/i)
    assert.match(asked[0], /lose the authenticator/i)
    // Accepted: it goes on to the authenticator.
    globalThis.confirm = () => true
    await assert.rejects(enable(), /reached the authenticator/)
    // With a passphrase, nobody is asked.
    asked.length = 0
    globalThis.confirm = (text) => { asked.push(text); return true }
    globalThis.api = async () => ({ has_passphrase: true, rp_id: 'localhost', prf_salt: 'AAAA' })
    await assert.rejects(enable(), /reached the authenticator/)
    assert.equal(asked.length, 0)
  } finally {
    globalThis.api = saved.api
    globalThis.confirm = saved.confirm
    delete globalThis.b64ToBuf
    if (saved.navigator) Object.defineProperty(globalThis, 'navigator', saved.navigator)
    else delete globalThis.navigator
  }
  assert.match(PAGE, /\(ls\.has_passphrase \|\| presenceState\.enrolled\) && prfSupported\(\)/, 'the Enable row shows on an authenticator-only vault')
})
