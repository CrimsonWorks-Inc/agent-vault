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
import { readNarrowing } from '../../web/src/components/approvals/decide.js'
import { exampleCall } from '../../web/src/components/sessions/sessionLogic.js'
import { createPresence, TOUCHID_NEEDS_PASSPHRASE } from '../../web/src/lib/presence.js'
import { startDaemon, startUi, makeAuthenticator, enrol, PASSPHRASE } from './fix-control-helpers.js'

const README = readFileSync(new URL('../../README.md', import.meta.url), 'utf8')

const read = (rel) => readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8')

/** The page's narrowing, read as the approvals page reads it (decide.js, which imports src/pending.js, C21). */
const pageNarrowing = (typed) => {
  const r = readNarrowing(typed)
  assert.ok(!r.error, r.error)
  return r.overrides
}

const RAW = [
  { methods: 'GET' },
  { methods: 'get, post', paths: '/repos/a/**,/repos/b/**', budget: '100' },
  { uses: '3', ttl_minutes: '15' },
  { paths: '/user' },
]

test('what the page signs for a narrowing is what the server rebuilds', () => {
  // The parser the page runs is src/pending.js's, imported into the bundle (C21).
  for (const raw of RAW) {
    const page = pageNarrowing(raw)
    const signed = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...page }))
    // The UI server parses what the page sends; the daemon binds the result.
    const rebuilt = canonicalOperation(operationFor('session_request.decide', { id: 'sr_x', granted: true, ...parseOverrides(page) }))
    assert.equal(signed, rebuilt, `${JSON.stringify(raw)} would be refused as a different operation`)
    assert.deepEqual(page, parseOverrides(raw), 'and it reads the inputs the way the CLI flags are read')
  }
  assert.match(read('web/src/components/approvals/decide.js'), /return \{ overrides: parseOverrides\(typed\) \}/, 'the decide action must sign the parsed narrowing')
})

test('a narrowed approval made the way the page makes it goes through', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const u = await startUi(d)
  try {
    const auth = makeAuthenticator(u.ui.origin)
    enrol(d.vault, auth)
    const asked = (await d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], budget: 500 })).body
    const overrides = pageNarrowing({ methods: 'get', paths: '/user,/user/repos', budget: '10' })
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
  const example = exampleCall({
    sites: ['header:authorization:Bearer'], token: 'avs1.abc.def', placeholder: 'av1.ph', base_url: 'http://127.0.0.1:7411/p/demo', probe: '/user',
  })
  assert.equal((example.match(/authorization:/gi) || []).length, 1, example)
  assert.match(example, /-H "AV-Session: avs1\.abc\.def"/)
  assert.match(example, /-H "authorization: Bearer av1\.ph"/i)
})

/**
 * The page's words: the React docs sources, and the built bundle the server
 * actually serves (found through dist/index.html), so text anywhere on the
 * page is covered, not only in the Docs section.
 */
function docsSource() {
  const read = (rel) => readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8')
  const bundle = /src="\/assets\/([^"]+\.js)"/.exec(read('src/ui/dist/index.html'))?.[1]
  assert.ok(bundle, 'the built page names its script')
  return ['web/src/components/docs/sections.jsx', 'web/src/components/docs/RefusedTable.jsx',
    'web/src/components/docs/Prose.jsx', 'web/src/pages/Docs.jsx', `src/ui/dist/assets/${bundle}`].map(read).join('\n')
}

test('the docs name every MCP tool, and only injection sites that exist', () => {
  const names = new McpServer({}, null, () => null).tools.map((t) => t.name)
  const docs = docsSource()
  for (const name of names) {
    // MCP_TOOLS in sections.jsx: one [name, what] row per tool, shown as code.
    assert.ok(docs.includes(`['${name}', `), `the docs page does not list ${name}`)
    assert.ok(README.includes(`\`${name}\``), `the README does not list ${name}`)
  }
  assert.ok(!/X-Agent-Vault-Cred/i.test(docs), 'no profile declares that header as a site')
  assert.ok(!/up to a minute/.test(docs + README), 'the backoff caps at thirty seconds')
  assert.ok(!/is this one still valid/.test(docs), 'ph check is an offline grammar check')
})

// Round 3, review finding 5, option C. Without a passphrase the page does not
// offer Touch ID unlock and does not ask for a tap: it says what the daemon
// says, in the daemon's words, and names the command that fixes it.
test('without a passphrase the page gives the daemon\'s guidance instead of a tap', async () => {
  const guidance = TOUCHID_NEEDS_PASSPHRASE
  assert.equal(read('web/src/lib/presence.js').split('Touch ID unlock needs a passphrase to fall back on').length, 2, 'the page names its guidance once')
  const STORE = readFileSync(new URL('../../src/store/vault.js', import.meta.url), 'utf8')
  assert.ok(STORE.includes(`hint: '${guidance}'`), 'the page and the daemon say the same thing')
  assert.match(guidance, /agent-vault passphrase set/)

  // The page's own flow (web/src/lib/presence.js), over a stand-in UI server
  // and an authenticator that records whether it was reached.
  let params
  let reached = 0
  const presence = createPresence({
    call: async (method, path) => (path === 'touchid/enroll-params' ? params : {}),
    credentials: () => ({ create: async () => { reached++; throw new Error('reached the authenticator') } }),
    random: (n) => new Uint8Array(n),
  })
  params = { has_passphrase: false, rp_id: 'localhost', prf_salt: 'AAAA' }
  await assert.rejects(presence.enableTouchId(), (e) => e.message === guidance)
  assert.equal(reached, 0, 'a tap was asked for on a vault with no passphrase')
  // With a passphrase, it goes on to the authenticator.
  params = { has_passphrase: true, rp_id: 'localhost', prf_salt: 'AAAA' }
  await assert.rejects(presence.enableTouchId(), /reached the authenticator/)
  assert.equal(reached, 1)

  // The Unlocking card shows the guidance, with no Enable button, on a vault
  // with no passphrase (rendered in web/src/pages/Overview.test.jsx / Settings.test.jsx).
  const card = read('web/src/components/overview/SecurityCards.jsx')
  const row = card.match(/if \(!ls\.has_passphrase\) \{([\s\S]*?)\} else if/)?.[1]
  assert.ok(row, 'a vault with no passphrase gets a Touch ID row')
  assert.match(row, /meta=\{TOUCHID_NEEDS_PASSPHRASE\}/)
  assert.ok(!/enableTouchId|Enable/.test(row), 'no Enable button without a passphrase')
  // Option A's warning and its no-recovery text are gone.
  assert.ok(!/Turn on Touch ID unlock anyway|nothing else opens the vault|recovery: false/.test(docsSource() + README))
})
