// One narrowing, one operation, on every surface (contract C21, C23).
//
// A human narrows a session request in one of three places: `agent-vault
// approve` with flags, the approvals page, or anything that posts to the UI
// server. All three read the typed text with src/pending.js parseOverrides
// (the page runs the copy the UI server injects), and the daemon rebinds the
// signed operation from what reaches it. If any two read the same text
// differently, either the signature fails (409 from the UI server, 403 from
// the daemon) or, worse, one of them drops a field and the agent's own
// proposal is what gets approved.
//
// So, for every C21/C23 field, the same typed narrowing must give the same
// operation from the CLI, from the served page and through the UI server to the
// real daemon, and the session made must carry it. And a narrowing that cannot
// be read must be refused everywhere, with nothing approved.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { operationFor, canonicalOperation } from '../../src/ui/webauthn.js'
import { overridesOf } from '../../src/daemon/session-requests.js'
import { parseOverrides, OVERRIDE_KEYS } from '../../src/pending.js'
import { startDaemon, cli, PASSPHRASE } from './fix-control-helpers.js'
import { servedPageSigning, servedSource, startSigned, startCliStub, flagsOf } from './integrate3-helpers.js'

const page = servedPageSigning()

/** What an agent asks for: wide enough that every narrowing below narrows it. */
const PROPOSAL = { cred: 'demo', methods: ['GET', 'HEAD', 'POST'], paths: ['/**'], budget: 50, ttl_minutes: 120, reason: 'integrate-3' }

/** Every field the page offers, plus the CLI's route shorthand and the owner's approval mode. */
const NARROWINGS = [
  ['methods', { methods: 'get,head' }],
  ['paths', { paths: '/repos/**,/user' }],
  ['budget', { budget: '5' }],
  ['uses', { uses: '2' }],
  ['ttl_minutes', { ttl_minutes: '30' }],
  ['grant_ttl_minutes', { grant_ttl_minutes: '10' }],
  ['max_concurrent', { max_concurrent: '2' }],
  ['redirects', { redirects: '1' }],
  // Spend limits are for model-provider credentials (F5).
  ['spend_tokens', { spend_tokens: '1000' }, 'openai'],
  ['spend_usd', { spend_usd: '0.5' }, 'openai'],
  ['rate', { rate: '60/min' }],
  ['quota', { quota: '1000/day' }],
  ['routes as JSON text', { routes: '[{"methods":["GET"],"paths":["/repos/**"]}]' }],
  ['payload as JSON text', { payload: '{"json":{"/amount":{"max":100}}}' }],
  ['route shorthand', { route: 'get,head:/repos/**' }],
  ['approval (owner)', { approval: 'on-write' }],
  ['several at once', { methods: 'GET', budget: '3', rate: '10/min', max_concurrent: '1', ttl_minutes: '15' }],
]

/** The operation the daemon rebuilds from a decision body (server.js, session-requests/decide). */
const daemonOperation = (body) => operationFor('session_request.decide', {
  id: body.id, granted: body.granted, ...overridesOf(body.overrides || {}),
})

/** The operation the page signs for `typed`, after reading it as the page does. */
async function pageOperation(id, typed) {
  const read = page.readNarrowing(typed)
  assert.ok(!read.error, `the page could not read ${JSON.stringify(typed)}: ${read.error}`)
  return { overrides: read.overrides, op: await page.operationFor('session_request.decide', { id, granted: true, ...read.overrides }) }
}

test('the page runs the injected parser, and it reads every narrowing as the module does', () => {
  for (const [name, typed] of NARROWINGS) {
    assert.deepEqual(page.parseOverrides(typed), parseOverrides(typed), name)
  }
  assert.ok(!servedSource('function readNarrowing(').includes('parseNarrowing'), 'the page keeps a second parser')
})

test('the CLI and the page sign the same operation for the same narrowing, field by field', async () => {
  const stub = await startCliStub()
  try {
    for (const [name, typed] of NARROWINGS) {
      const before = stub.decisions().length
      const r = await stub.run(['approve', 'sr_x', ...flagsOf(typed)])
      assert.equal(r.code, 0, `${name}: ${r.stdout}${r.stderr}`)
      const sent = stub.decisions()
      assert.equal(sent.length, before + 1, `${name}: the CLI sent no decision`)
      const { op } = await pageOperation('sr_x', typed)
      assert.equal(canonicalOperation(daemonOperation(sent.at(-1).body)), canonicalOperation(op),
        `${name}: the CLI's decision rebinds to another operation than the page signs`)
    }
  } finally { await stub.stop() }
})

/** Both daemons get a model-provider credential beside `demo`. */
function addModel(vault) {
  vault.addCredential({
    slug: 'openai', kind: 'openai', connector: { host: 'api.openai.com', scheme: 'https' },
    fields: { key: 'sk-proj-INTEGRATE3NARROW00112233445566' }, sites: { key: ['header:authorization:Bearer'] },
  })
}

/** Open a request for PROPOSAL on `cred` and return its id. */
async function ask(control, cred = 'demo') {
  const r = await control('POST', '/v1/session-requests', { ...PROPOSAL, cred })
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body.request_id ?? r.body.id
}

/** The grant a decision made, as stored. */
const newestGrant = (vault) => Object.values(vault.db.grants).at(-1)

test('through the UI server, each narrowing signed by the page is approved by the real daemon, and kept', async () => {
  const t = await startSigned()
  const c = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  addModel(t.d.vault)
  addModel(c.vault)
  try {
    for (const [name, typed, cred] of NARROWINGS) {
      const id = await ask(t.d.control, cred)
      const { overrides, op } = await pageOperation(id, typed)
      const presence = await t.u.presence(t.auth, op)
      const grantsBefore = Object.keys(t.d.vault.db.grants).length
      const res = await t.u.api('POST', 'session-requests/decide', { id, granted: true, overrides, presence })
      const body = await res.json()
      // 409 is the UI server rebuilding another operation; 403 is the daemon.
      assert.equal(res.status, 200, `${name}: ${JSON.stringify(body)}`)
      assert.equal(Object.keys(t.d.vault.db.grants).length, grantsBefore + 1, `${name}: no grant was made`)
      // Nothing typed was dropped on the way: the daemon granted exactly it.
      for (const [field, value] of Object.entries(overrides)) {
        assert.deepEqual(body.granted?.[field], value, `${name}: ${field} was not what was approved`)
      }

      // The CLI, on its own daemon with the passphrase window open, makes the
      // same grant from the same typed text.
      c.daemon.presenceGraceUntil = Date.now() + 60_000
      const cid = await ask(c.control, cred)
      const r = await cli(c.dir, ['approve', cid, ...flagsOf(typed), '--json'], { env: { HOME: c.dir, AGENT_VAULT_SESSION: '' } })
      assert.equal(r.code, 0, `${name}: ${r.stdout}${r.stderr}`)
      const { id: _a, created_at: _b, ...ui } = newestGrant(t.d.vault)
      const { id: _c, created_at: _d, ...viaCli } = newestGrant(c.vault)
      assert.deepEqual(stripIds(viaCli), stripIds(ui), `${name}: the CLI and the page made different grants`)
    }
  } finally { await t.stop(); await c.stop() }
})

/** A stored grant without what differs between two vaults by construction. */
function stripIds(g) {
  const out = {}
  for (const [k, v] of Object.entries(g)) {
    if (/(^|_)(id|at)$/.test(k) || k === 'expires') continue
    out[k] = v
  }
  return out
}

/** Typed text no surface can read, and the field each one must be refused for. */
const UNREADABLE = [
  ['budget', { budget: 'abc' }],
  ['max_concurrent', { max_concurrent: '5x' }],
  ['spend_usd', { spend_usd: 'Infinity' }],
  ['ttl_minutes', { ttl_minutes: 'NaN' }],
  ['grant_ttl_minutes', { grant_ttl_minutes: '10 min' }],
  ['routes', { routes: '[not json' }],
  ['routes', { routes: '"GET /repos/**"' }],
  ['payload', { payload: '{' }],
]

test('a narrowing that cannot be read: the CLI exits 2 naming the field, and sends nothing', async () => {
  const stub = await startCliStub()
  try {
    for (const [field, typed] of UNREADABLE) {
      const callsBefore = stub.calls.length
      const r = await stub.run(['approve', 'sr_x', ...flagsOf(typed)])
      assert.equal(r.code, 2, `${JSON.stringify(typed)}: ${r.stdout}`)
      assert.equal(r.envelope?.ok, false)
      assert.match(r.envelope.error.message, new RegExp(`^--${field}: .*nothing was sent`), JSON.stringify(typed))
      assert.equal(stub.calls.length, callsBefore, `${JSON.stringify(typed)}: the CLI talked to the daemon`)
    }
  } finally { await stub.stop() }
})

/** The page's decide action wired to the served parser, an input box per typed field, and recorders. */
function pageDecide(typed) {
  const calls = { toast: [], gated: 0, api: 0, operationFor: 0 }
  const inputs = Object.entries(typed).map(([field, value]) => ({ dataset: { field }, value }))
  const deps = {
    document: { querySelectorAll: () => inputs, querySelector: () => null },
    drafts: new Map(),
    toast: (m) => { calls.toast.push(String(m)) },
    render: () => {},
    operationFor: async () => { calls.operationFor++; return {} },
    gated: async () => { calls.gated++ },
    api: async () => { calls.api++ },
  }
  const start = servedSource('async decide(btn) {')
  const actions = new Function('deps', `
    const { document, drafts, toast, render, operationFor, gated, api } = deps
    ${servedSource('function parseOverrides(')}
    ${servedSource('function readNarrowing(')}
    return { ${start} }`)(deps)
  return { decide: () => actions.decide({ dataset: { id: 'sr_1', granted: '1', kind: 'session' } }), calls }
}

test('a narrowing that cannot be read: the page shows why and builds, signs and sends nothing', async () => {
  for (const [field, typed] of UNREADABLE) {
    const { decide, calls } = pageDecide(typed)
    await decide()
    assert.equal(calls.operationFor + calls.gated + calls.api, 0, `${JSON.stringify(typed)}: the page went ahead`)
    assert.equal(calls.toast.length, 1)
    assert.match(calls.toast[0], new RegExp(`nothing was sent: ${field}:`), JSON.stringify(typed))
  }
  // The same harness approves an ordinary narrowing, so the refusal above is the parser's.
  const { decide, calls } = pageDecide({ budget: '5' })
  await decide()
  assert.equal(calls.api, 0, 'gated is a recorder, so nothing is sent from here')
  assert.equal(calls.operationFor, 1)
  assert.equal(calls.gated, 1)
})

test('a narrowing that cannot be read: the UI server answers 400 and the daemon 4xx, and nothing is approved', async () => {
  const t = await startSigned()
  const c = await startDaemon({ passphrase: PASSPHRASE, socketName: 'control.sock' })
  try {
    for (const [field, typed] of UNREADABLE) {
      // A caller that skips the page and posts the raw text to the UI server.
      const id = await ask(t.d.control)
      const res = await t.u.api('POST', 'session-requests/decide', { id, granted: true, overrides: typed })
      const body = await res.json()
      assert.equal(res.status, 400, `${JSON.stringify(typed)}: ${JSON.stringify(body)}`)
      assert.match(JSON.stringify(body), new RegExp(field))
      assert.equal(t.d.daemon.sessionRequests.get(id).state, 'pending', `${JSON.stringify(typed)}: the UI server decided it`)

      // The daemon itself, with the human present (the window is open), so
      // the only thing that can refuse is the narrowing.
      c.daemon.presenceGraceUntil = Date.now() + 60_000
      const cid = await ask(c.control)
      const grants = Object.keys(c.vault.db.grants).length
      const r = await c.control('POST', '/v1/session-requests/decide', { id: cid, granted: true, overrides: typed })
      assert.ok(r.status >= 400 && r.status < 500, `${JSON.stringify(typed)}: the daemon answered ${r.status} ${JSON.stringify(r.body)}`)
      assert.equal(c.daemon.sessionRequests.get(cid).state, 'pending', `${JSON.stringify(typed)}: the daemon decided it`)
      assert.equal(Object.keys(c.vault.db.grants).length, grants, `${JSON.stringify(typed)}: a grant was made`)
    }
    // The same daemon approves an ordinary narrowing, so the refusals above are the narrowing's.
    c.daemon.presenceGraceUntil = Date.now() + 60_000
    const cid = await ask(c.control)
    const r = await c.control('POST', '/v1/session-requests/decide', { id: cid, granted: true, overrides: { budget: 5 } })
    assert.equal(r.status, 200, JSON.stringify(r.body))
  } finally { await t.stop(); await c.stop() }
})

// Fix round 2: a key no approval applies. The UI server copied known fields
// only, so `{ hosts, budget }` answered 200 with the budget applied and the
// host list gone, where the daemon refuses the same body outright.
const UNAPPLIED = [
  ['hosts', { hosts: 'evil.test', budget: '6' }],
  ['deny_paths', { deny_paths: '/admin/**' }],
  ['not_a_field', { not_a_field: 'x', budget: '6' }],
]

test('a key no approval applies is refused by the shared parser, the UI server (400), the page and the CLI, as the daemon refuses it', async () => {
  for (const [field, typed] of UNAPPLIED) {
    assert.throws(() => parseOverrides(typed), (e) => e instanceof TypeError && e.field === field, JSON.stringify(typed))
    assert.match(page.readNarrowing(typed).error ?? '', new RegExp(`nothing was sent: ${field}:`), `the page read ${JSON.stringify(typed)}`)
    const { decide, calls } = pageDecide(typed)
    await decide()
    assert.equal(calls.operationFor + calls.gated + calls.api, 0, `${JSON.stringify(typed)}: the page went ahead`)
  }
  // Not an object at all: every index is a key nobody reads.
  for (const bad of ['budget=5', ['budget']]) assert.throws(() => parseOverrides(bad), TypeError)

  const t = await startSigned()
  const stub = await startCliStub()
  try {
    for (const [field, typed] of UNAPPLIED) {
      const id = await ask(t.d.control)
      const res = await t.u.api('POST', 'session-requests/decide', { id, granted: true, overrides: typed })
      const body = await res.json()
      assert.equal(res.status, 400, `${JSON.stringify(typed)}: ${JSON.stringify(body)}`)
      assert.match(JSON.stringify(body), new RegExp(field))
      // A denial reads the narrowing too, so it is refused the same way.
      const denied = await t.u.api('POST', 'session-requests/decide', { id, granted: false, overrides: typed })
      assert.equal(denied.status, 400)
      assert.equal(t.d.daemon.sessionRequests.get(id).state, 'pending', `${JSON.stringify(typed)}: the UI server decided it`)
      const r = await t.d.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides: { ...typed, budget: 6 } })
      assert.equal(r.status, 403, `${JSON.stringify(typed)}: the daemon answered ${r.status}`)

      const before = stub.calls.filter((c) => c.method === 'POST').length
      const cli = await stub.run(['approve', 'sr_x', ...flagsOf(typed)])
      assert.equal(cli.code, 2, `${JSON.stringify(typed)}: ${cli.stdout}`)
      assert.match(cli.envelope.error.message, new RegExp(field.replace('_', '[_-]')))
      assert.equal(stub.calls.filter((c) => c.method === 'POST').length, before, `${JSON.stringify(typed)}: the CLI sent a decision`)
    }
    // An ordinary narrowing passes the check and goes on to the signature
    // the UI server asks for, so the refusals are the keys'.
    const id = await ask(t.d.control)
    const res = await t.u.api('POST', 'session-requests/decide', { id, granted: true, overrides: { budget: '6' } })
    assert.equal(res.status, 401, 'no signature was sent, so presence is what it asks for')
  } finally { await t.stop(); await stub.stop() }
})

test('OVERRIDE_KEYS is the list the self-contained parser reads, key for key', () => {
  const src = parseOverrides.toString()
  for (const k of OVERRIDE_KEYS) {
    assert.ok(src.includes(`'${k}'`), `parseOverrides does not list ${k}`)
    assert.doesNotThrow(() => parseOverrides({ [k]: undefined }), k)
  }
  const listed = [...src.slice(src.indexOf('const known = ['), src.indexOf(']', src.indexOf('const known = ['))).matchAll(/'([^']+)'/g)].map((m) => m[1])
  assert.deepEqual([...listed].sort(), [...OVERRIDE_KEYS].sort())
})
