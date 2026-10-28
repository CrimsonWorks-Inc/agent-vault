// Integrate-3, fix round 3: C25. A session request's audit records carry its
// structure, never a value the agent wrote.
//
// Rounds 1 and 2 scrubbed the agent's text against every stored secret, in
// every encoding the response scrubber knew. Each review found another one
// it did not: a partial `\/`, an uppercase `\u`, five layers of percent,
// wrapped base64, base64 of percent, HTML entities, mixed-case hex, a value
// rotated out before the approval, a former secret typed by the human, and a
// PIN that went to the log as a placeholder's max_uses during the approval.
// Listing encodings never closes that, so the records now hold no value at
// all: ids, the vault's own slug, who acted, the decision, field NAMES, list
// counts, and the names of the fields a human narrowed.
//
// Every test reads the three places a record is kept (audit.jsonl, GET
// /v1/audit and the export), checks each session_request record against an
// exact key allowlist with every value drawn from a known set, and checks
// that no form of the secret is anywhere in any of the three. And every test
// checks the grant still enforces the real values: the log is what changed,
// not the grant.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { startApi, PASSPHRASE } from './control-api-helpers.js'
import { shapeOf, narrowedOf } from '../../src/daemon/session-requests.js'

const VALUE = 'ghp/PLUS+slash/001122334455667788'
const AMP = 'abcd&efgh-ijkl-0099887766'
const PIN = '12345678'
const CHAIN = ['seq', 'ts', 'kind', 'prev_hash', 'hash']
const FIELD_NAMES = new Set([
  'cred', 'methods', 'paths', 'budget', 'uses', 'ttl_minutes', 'rate', 'max_concurrent', 'quota', 'routes',
  'payload', 'redirects', 'spend_tokens', 'spend_usd', 'grant_ttl_minutes', 'approval', 'infinite',
])

// The exact keys each record may carry (C25). Anything else is a value field.
const SHAPES = {
  'session_request.opened': ['request_id', 'actor', 'cred', 'template', 'proposed', 'counts'],
  'session_request.approved': ['request_id', 'decision', 'cred', 'proposed', 'actor', 'session_id', 'granted', 'counts', 'narrowed', 'edited'],
  'session_request.denied': ['request_id', 'decision', 'cred', 'proposed', 'actor'],
}

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')
const hex = (s) => Buffer.from(s, 'utf8').toString('hex')
const mixedHex = (s) => { let flip = false; return hex(s).replace(/[a-f]/g, (c) => ((flip = !flip) ? c.toUpperCase() : c)) }
const uEsc = (s, upper) => [...s].map((c) => { const h = c.charCodeAt(0).toString(16).padStart(4, '0'); return `\\u${upper ? h.toUpperCase() : h}` }).join('')
const pct = (s, n) => { let out = s; for (let i = 0; i < n; i++) out = encodeURIComponent(out); return out }
const htmlDec = (s) => [...s].map((c) => `&#${c.charCodeAt(0)};`).join('')
const htmlHex = (s) => [...s].map((c) => `&#x${c.charCodeAt(0).toString(16)};`).join('')

/**
 * Every form of `s` the r2 and r3 reviews wrote to the log, by name. A form
 * that holds a newline cannot be a path, so `inPath` is false for it; it
 * still goes in the reason and a payload rule.
 */
function variantsOf(s) {
  const wrapped = b64(s)
  const cut = Math.floor(wrapped.length / 2)
  return [
    { name: 'raw', text: s },
    ...[1, 2, 3, 4, 5].map((n) => ({ name: `percent x${n}`, text: pct(s, n) })),
    { name: '\\u lower', text: uEsc(s, false) },
    { name: '\\u upper', text: uEsc(s, true) },
    { name: '\\/ partial', text: s.replace('/', '\\/') },
    { name: '\\/ full', text: s.replaceAll('/', '\\/') },
    { name: 'base64', text: b64(s) },
    { name: 'base64 wrapped', text: `${wrapped.slice(0, cut)}\n${wrapped.slice(cut)}`, halves: [wrapped.slice(0, cut), wrapped.slice(cut)], inPath: false },
    { name: 'base64 of percent', text: b64(encodeURIComponent(s)) },
    { name: 'html decimal', text: htmlDec(s) },
    { name: 'html hex', text: htmlHex(s) },
    { name: 'hex lower', text: hex(s) },
    { name: 'hex upper', text: hex(s).toUpperCase() },
    { name: 'hex mixed case', text: mixedHex(s) },
  ].map((v) => ({ inPath: true, ...v }))
}

const VARIANTS = [...variantsOf(VALUE), { name: 'html named', text: AMP.replace('&', '&amp;'), inPath: true }]

/** Every needle that must not be anywhere in the log: each form, its halves, the raw values and the PIN. */
const NEEDLES = [
  VALUE, AMP, PIN, VALUE.slice(0, 12), 'PLUS+slash', '001122334455667788',
  ...VARIANTS.flatMap((v) => [v.text, ...(v.halves ?? [])]),
]

/** A vault whose `demo` holds VALUE, `amp` holds AMP, and `pin` holds the PIN. */
async function start() {
  const a = await startApi({ passphrase: PASSPHRASE })
  a.vault.rotateCredential('demo', { value: VALUE, mode: 'revoke', retireMs: 0 })
  for (const [slug, token] of [['amp', AMP], ['pin', PIN]]) {
    a.vault.addCredential({
      slug, kind: 'http', connector: { host: `127.0.0.1:${a.upPort}`, scheme: 'http' },
      fields: { token }, sites: { token: ['header:authorization:Bearer'] },
    })
  }
  return a
}

/** A proposal holding every form in its paths, routes, payload rules and reason, and the PIN in every number. */
function greedy({ numbers = true } = {}) {
  const pathForms = VARIANTS.filter((v) => v.inPath).map((v) => `/${v.text}`)
  return {
    cred: 'demo', methods: ['GET', 'POST'],
    paths: pathForms,
    routes: [{ methods: ['GET', 'POST'], paths: pathForms.slice(0, 3) }],
    payload: { json: { '/q': { one_of: [...VARIANTS.map((v) => v.text), ...(numbers ? [Number(PIN)] : [])] } } },
    ...(numbers ? {
      budget: Number(PIN), uses: Number(PIN), quota: { count: Number(PIN), window: 'day' },
      ttl_minutes: Number(PIN), grant_ttl_minutes: Number(PIN),
    } : {}),
    reason: `forms: ${VARIANTS.map((v) => v.text).join(' | ')} | ${PIN}`,
  }
}

async function ask(a, body) {
  const r = await a.control('POST', '/v1/session-requests', body)
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body.request_id ?? r.body.id
}

async function gated(a, fn) {
  a.openWindow()
  try { return await fn() } finally { a.closeWindow() }
}

async function decide(a, id, extra = {}) {
  const r = await gated(a, () => a.control('POST', '/v1/session-requests/decide', { id, granted: true, ...extra }))
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body
}

async function decideMany(a, decisions) {
  const r = await gated(a, () => a.control('POST', '/v1/pending/decide-many', { decisions }))
  assert.equal(r.status, 200, JSON.stringify(r.body))
  for (const d of r.body.decided) assert.equal(d.outcome, 'decided', JSON.stringify(r.body))
  return r.body
}

/** The rows of audit.jsonl, GET /v1/audit and the export, by where they came from. */
async function surfaces(a) {
  const file = readFileSync(a.vault.audit.path, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l) } catch { return { line: l } } })
  const read = await a.control('GET', '/v1/audit?limit=100000')
  assert.equal(read.status, 200)
  const exported = await a.control('GET', '/v1/audit/export')
  assert.equal(exported.status, 200)
  return [['audit.jsonl', file], ['GET /v1/audit', read.body], ['the export', exported.body.rows]]
}

/**
 * Each session_request record on every surface has exactly its allowlisted
 * keys, and every value is one this code chose: an id, the vault's slug, an
 * actor, a decision, field names, counts, a boolean. Then no needle is in
 * any record on any surface, of any kind.
 */
async function assertStructureOnly(a, { kinds, ids, slugs = ['demo'] }) {
  for (const [where, rows] of await surfaces(a)) {
    assert.ok(Array.isArray(rows), `${where} is not a list of records`)
    for (const kind of kinds) assert.ok(rows.some((r) => r.kind === kind), `${where} has no ${kind}`)
    for (const r of rows.filter((x) => /^session_request\.(opened|approved|denied)$/.test(x.kind))) {
      const allowed = [...CHAIN, ...SHAPES[r.kind], ...(r.actor === 'panic' ? ['reason'] : [])]
      assert.deepEqual(Object.keys(r).sort(), [...allowed].sort(), `${where} ${r.kind} keys: ${JSON.stringify(r)}`)
      assert.ok(ids.includes(r.request_id), `${where} ${r.kind} request_id ${r.request_id}`)
      assert.ok(r.cred === null || slugs.includes(r.cred), `${where} ${r.kind} cred ${r.cred}`)
      assert.ok(['agent', 'human', 'panic'].includes(r.actor), `${where} ${r.kind} actor ${r.actor}`)
      if (r.actor === 'panic') assert.equal(r.reason, 'panic')
      for (const list of ['proposed', 'granted', 'narrowed']) {
        if (r[list] === undefined) continue
        assert.ok(Array.isArray(r[list]) && r[list].every((f) => FIELD_NAMES.has(f)), `${where} ${r.kind} ${list}: ${JSON.stringify(r[list])}`)
      }
      if (r.counts !== undefined) {
        for (const [f, n] of Object.entries(r.counts)) {
          assert.ok(FIELD_NAMES.has(f) && Number.isSafeInteger(n) && n >= 0 && n < 1000, `${where} ${r.kind} counts ${f}: ${n}`)
        }
      }
      if (r.kind === 'session_request.opened') assert.ok(r.template === null || typeof r.template === 'string')
      if (r.kind !== 'session_request.opened') assert.equal(r.decision, r.kind.split('.')[1])
      if (r.kind === 'session_request.approved') {
        assert.ok(Object.hasOwn(a.vault.db.sessions, r.session_id), `${where} session_id ${r.session_id}`)
        assert.equal(typeof r.edited, 'boolean')
      }
    }
    const text = JSON.stringify(rows)
    for (const n of NEEDLES) assert.ok(!text.includes(n), `${where} holds ${JSON.stringify(n)}`)
  }
}

function grantFor(a, sessionId) {
  const grants = Object.values(a.vault.db.grants).filter((g) => g.session_id === sessionId)
  assert.equal(grants.length, 1)
  return grants[0]
}

/** The grant enforces every form the agent proposed, and the PIN in every number. */
function assertGrantKeeps(a, sessionId, { numbers = true } = {}) {
  const grant = grantFor(a, sessionId)
  for (const v of VARIANTS.filter((x) => x.inPath)) assert.ok(grant.policy.paths.includes(`/${v.text}`), `the grant lost the ${v.name} path`)
  assert.ok(JSON.stringify(grant.policy.payload).includes(JSON.stringify(VARIANTS[0].text)), 'the grant lost the payload rule')
  if (numbers) {
    assert.equal(grant.policy.budget.limit, Number(PIN))
    assert.equal(grant.policy.quota.count, Number(PIN))
  }
  return grant
}

// --- the records ------------------------------------------------------------------

test('C25: shapeOf names the fields a proposal sets and counts its lists; narrowedOf names what a human changed', () => {
  const p = { cred: 'demo', methods: ['GET'], paths: ['/a', '/b', '/c'], routes: [{}, {}], budget: Number(PIN), payload: { json: {} }, reason: 'x', template_hash: 'h' }
  assert.deepEqual(shapeOf(p), { fields: ['cred', 'methods', 'paths', 'budget', 'routes', 'payload'], counts: { methods: 1, paths: 3, routes: 2 } })
  // Names come from the list of fields, never from the proposal's own keys.
  assert.deepEqual(shapeOf({ [VALUE]: 1, cred: 'demo' }), { fields: ['cred'], counts: {} })
  assert.deepEqual(shapeOf(null), { fields: [], counts: {} })
  assert.deepEqual(narrowedOf(p, { ...p, paths: ['/a'], approval: 'each' }), ['paths', 'approval'])
  assert.deepEqual(narrowedOf(p, { ...p }), [])
})

test('C25: every r2 and r3 form, in paths, routes, payload, reason and every number, reaches no record; decide keeps the grant whole', async () => {
  const a = await start()
  try {
    const id = await ask(a, greedy())
    await decide(a, id)
    const [opened] = a.audit('session_request.opened')
    assert.deepEqual(opened.proposed, ['cred', 'methods', 'paths', 'budget', 'uses', 'ttl_minutes', 'quota', 'routes', 'payload', 'grant_ttl_minutes'])
    assert.deepEqual(opened.counts, { methods: 2, paths: VARIANTS.length - 1, routes: 1 })
    assert.equal(opened.actor, 'agent')
    assert.equal(opened.cred, 'demo')
    const [approved] = a.audit('session_request.approved')
    assert.deepEqual(approved.granted, opened.proposed)
    assert.deepEqual(approved.narrowed, [])
    assert.equal(approved.edited, false)
    await assertStructureOnly(a, { kinds: ['session_request.opened', 'session_request.approved'], ids: [id] })

    // F6 and the C25 addendum: nothing written during the approval carries a
    // number the agent chose.
    const sid = approved.session_id
    const [created] = a.audit('session.created').filter((r) => r.session_id === sid)
    assert.equal(created.expires_at, null)
    assert.equal(created.has_expiry, true)
    const [grantRow] = a.audit('grant.created').filter((r) => r.session_id === sid)
    assert.equal(grantRow.expires_at, null)
    assert.equal(grantRow.has_expiry, true)
    const [issued] = a.audit('placeholder.issued').filter((r) => r.session_id === sid)
    assert.ok(issued && !('max_uses' in issued), JSON.stringify(issued))

    // The live session, grant and placeholder keep the real values.
    const grant = assertGrantKeeps(a, sid)
    assert.ok(a.vault.db.sessions[sid].expires_at, 'the live session lost its end')
    assert.ok(grant.expires_at, 'the live grant lost its end')
    const row = Object.values(a.vault.db.placeholders).find((p) => p.grant_id === grant.id)
    assert.ok(row.max_uses > 0, 'the live placeholder lost its ceiling')
  } finally { await a.stop() }
})

test('C25: decide-many records the same structure, and pending.decided_many holds only ids', async () => {
  const a = await start()
  try {
    const one = await ask(a, greedy())
    const two = await ask(a, greedy({ numbers: false }))
    await decideMany(a, [{ id: one, kind: 'session', granted: true }, { id: two, kind: 'session', granted: false }])
    await assertStructureOnly(a, { kinds: ['session_request.opened', 'session_request.approved', 'session_request.denied', 'pending.decided_many'], ids: [one, two] })
    const [many] = a.audit('pending.decided_many')
    assert.deepEqual(many, { ...many, granted: [one], denied: [two], skipped: [] })
    const [denied] = a.audit('session_request.denied')
    assert.equal(denied.request_id, two)
    assert.equal(denied.actor, 'human')
    assert.deepEqual(denied.proposed, ['cred', 'methods', 'paths', 'routes', 'payload'])
    const [approved] = a.audit('session_request.approved')
    assertGrantKeeps(a, approved.session_id)
  } finally { await a.stop() }
})

test('C25: a denial, and a panic denial, record structure only', async () => {
  const a = await start()
  try {
    const one = await ask(a, greedy())
    const r = await gated(a, () => a.control('POST', '/v1/session-requests/decide', { id: one, granted: false }))
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const two = await ask(a, greedy({ numbers: false }))
    const panic = await a.control('POST', '/v1/panic', {})
    assert.equal(panic.status, 200, JSON.stringify(panic.body))
    assert.equal(panic.body.denied_session_requests, 1)
    const denied = a.audit('session_request.denied')
    assert.deepEqual(denied.map((d) => [d.request_id, d.actor, d.decision]), [[one, 'human', 'denied'], [two, 'panic', 'denied']])
    await assertStructureOnly(a, { kinds: ['session_request.opened', 'session_request.denied'], ids: [one, two] })
  } finally { await a.stop() }
})

// --- rotation and the human's own text ----------------------------------------------

test('C25: a value rotated out (retireMs 0) between the ask and decide is in no record, and the gateway enforces the grant', async () => {
  const a = await start()
  try {
    const id = await ask(a, greedy())
    a.vault.rotateCredential('demo', { value: 'ghp_NEWVALUE99887766554433221100ff', mode: 'keep', retireMs: 0 })
    assert.ok(!a.vault.allSecrets().some((s) => s.secret === VALUE), 'the old value is still stored; the test proves nothing')
    await decide(a, id)
    await assertStructureOnly(a, { kinds: ['session_request.opened', 'session_request.approved'], ids: [id] })
    const [approved] = a.audit('session_request.approved')
    const grant = assertGrantKeeps(a, approved.session_id)
    const { placeholder } = a.vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
    const allowed = await a.gateway(`/p/demo/${VALUE}`, { headers: { authorization: `Bearer ${placeholder}` } })
    assert.equal(allowed.status, 200, allowed.text)
    assert.equal(a.seen.at(-1).url, `/${VALUE}`)
    const outside = await a.gateway('/p/demo/not-the-path', { headers: { authorization: `Bearer ${placeholder}` } })
    assert.equal(outside.status, 403, outside.text)
  } finally { await a.stop() }
})

test('C25: a human override holding a former secret and a PIN is recorded as the names it narrowed, nothing more', async () => {
  const a = await start()
  try {
    const id = await ask(a, { cred: 'demo', methods: ['GET'], paths: ['/ok'], reason: 'ordinary' })
    a.vault.rotateCredential('demo', { value: 'ghp_NEWVALUE99887766554433221100ee', mode: 'keep', retireMs: 0 })
    await decide(a, id, { overrides: { paths: [`/${VALUE}`, `/${pct(VALUE, 5)}`], budget: Number(PIN) } })
    const [approved] = a.audit('session_request.approved')
    assert.deepEqual(approved.narrowed, ['paths', 'budget'])
    assert.deepEqual(approved.granted, ['cred', 'methods', 'paths', 'budget'])
    assert.deepEqual(approved.counts, { methods: 1, paths: 2 })
    assert.equal(approved.edited, true)
    await assertStructureOnly(a, { kinds: ['session_request.opened', 'session_request.approved'], ids: [id] })
    const grant = grantFor(a, approved.session_id)
    assert.deepEqual(grant.policy.paths, [`/${VALUE}`, `/${pct(VALUE, 5)}`])
    assert.equal(grant.policy.budget.limit, Number(PIN))
  } finally { await a.stop() }
})

// --- F6 and the addendum ------------------------------------------------------------

test('F6: placeholder.issued and placeholder.refunded carry no use ceiling; a human-made session keeps its expiry in the log', async () => {
  const a = await start()
  try {
    // A human-made session is unchanged (C25 addendum): its end is the owner's.
    const s = a.session({ policy: { budget: { unit: 'requests', limit: Number(PIN) } } })
    const [created] = a.audit('session.created').filter((r) => r.session_id === s.session.id)
    assert.equal(created.expires_at, s.session.expires_at)
    assert.ok(!('has_expiry' in created))
    const [grantRow] = a.audit('grant.created').filter((r) => r.session_id === s.session.id)
    assert.ok(!('has_expiry' in grantRow))

    const row = Object.values(a.vault.db.placeholders).find((p) => p.grant_id === s.grant.id)
    assert.equal(row.max_uses, Number(PIN))
    row.uses = 1
    a.vault.refundPlaceholder(row.id)
    const [refunded] = a.audit('placeholder.refunded')
    assert.ok(refunded && !('max_uses' in refunded), JSON.stringify(refunded))
    for (const kind of ['placeholder.issued', 'placeholder.refunded']) {
      for (const r of a.audit(kind)) assert.ok(!JSON.stringify(r).includes(PIN), JSON.stringify(r))
    }
    // An infinite request-made session says it has no end.
    const id = await ask(a, { cred: 'demo', methods: ['GET'], paths: ['/inf'] })
    a.openWindow()
    const r = await a.control('POST', '/v1/session-requests/decide', { id, granted: true, overrides: { infinite: true }, presence: { passphrase: PASSPHRASE } })
    a.closeWindow()
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const [approved] = a.audit('session_request.approved')
    const [inf] = a.audit('session.created').filter((x) => x.session_id === approved.session_id)
    assert.deepEqual([inf.expires_at, inf.has_expiry, inf.infinite], [null, false, true])
  } finally { await a.stop() }
})

test('C25: no request record is written with a value even when the secrets cannot be read', async () => {
  const a = await start()
  try {
    a.vault.allSecrets = () => { throw new Error('unreadable') }
    const id = await ask(a, greedy({ numbers: false }))
    await decide(a, id)
    await assertStructureOnly(a, { kinds: ['session_request.opened', 'session_request.approved'], ids: [id] })
  } finally { await a.stop() }
})
