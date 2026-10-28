// Integrate-3, fix round 2: the approved record (and the opened one) keep no
// stored secret, however it was written into the proposal.
//
// Round 1's scrub re-read the stored secrets at approval and replaced their
// exact text. Three ways through it, each reproduced by the review:
//   F1. A value rotated out (retireMs 0) between the ask and the approval was
//       no longer stored, so it was written raw; an empty or partial secret
//       list scrubbed nothing.
//   F2. A number was passed through: budget 12345678 is the secret "12345678".
//   F3. Only the exact text was matched, so a percent-encoded secret survived.
// Every test here reads the three places the record is kept: audit.jsonl,
// GET /v1/audit and the export. And every test checks the grant still holds
// the real values, because the scrub is the log's, not the grant's.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { startApi, PASSPHRASE, SECRET } from './control-api-helpers.js'
import { auditCopy, holdsSecret, needlesOf, redactDeep } from '../../src/daemon/session-requests.js'

const ROTATED = 'ghp_ROTATEME00112233445566778899aa'
const ENCODABLE = 'ghp/PLUS+slash/001122334455667788'
const PIN = '12345678'

/** A vault whose `demo` credential holds `value`, and a second one, `pin`, holding the number. */
async function start(value = SECRET) {
  const a = await startApi({ passphrase: PASSPHRASE })
  if (value !== SECRET) a.vault.rotateCredential('demo', { value, mode: 'revoke', retireMs: 0 })
  a.vault.addCredential({
    slug: 'pin', kind: 'http', connector: { host: `127.0.0.1:${a.upPort}`, scheme: 'http' },
    fields: { token: PIN }, sites: { token: ['header:authorization:Bearer'] },
  })
  return a
}

async function ask(a, body) {
  const r = await a.control('POST', '/v1/session-requests', body)
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body.request_id ?? r.body.id
}

async function decide(a, id, extra = {}) {
  a.openWindow()
  try {
    const r = await a.control('POST', '/v1/session-requests/decide', { id, granted: true, ...extra })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    return r.body
  } finally { a.closeWindow() }
}

/**
 * None of `needles` is in the log file, GET /v1/audit or the export; each
 * carries `kinds`. With `requestRecords`, only the session request records
 * and the bulk decision are read: a number is also a limit the vault writes
 * on its own records (a placeholder's max_uses is the budget), which is not
 * the agent's text quoted back.
 */
async function assertAbsent(a, needles, kinds = ['session_request.approved'], { requestRecords = false } = {}) {
  const file = readFileSync(a.vault.audit.path, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l) } catch { return { line: l } } })
  const read = await a.control('GET', '/v1/audit?limit=100000')
  assert.equal(read.status, 200)
  const exported = await a.control('GET', '/v1/audit/export')
  assert.equal(exported.status, 200)
  const scope = (rows) => (requestRecords ? rows.filter((r) => /^(session_request|pending)\./.test(r.kind ?? '')) : rows)
  for (const [where, rows] of [['audit.jsonl', file], ['GET /v1/audit', read.body], ['the export', exported.body.rows]]) {
    assert.ok(Array.isArray(rows), `${where} is not a list of records`)
    const text = JSON.stringify(scope(rows))
    for (const kind of kinds) assert.ok(text.includes(`"${kind}"`), `${where} has no ${kind}`)
    for (const n of needles) assert.ok(!text.includes(n), `${where} holds ${JSON.stringify(n)}`)
  }
}

/** The one grant the approval made. */
function grantOf(a, approved) {
  const grants = Object.values(a.vault.db.grants).filter((g) => g.session_id === approved.session_id)
  assert.equal(grants.length, 1)
  return grants[0]
}

// --- F1: rotation between the ask and the approval ---------------------------

test('F1: a value rotated out with retireMs 0 between the ask and decide is not written to the approved record, and the grant enforces it', async () => {
  const a = await start(ROTATED)
  try {
    const id = await ask(a, { cred: 'demo', methods: ['GET'], paths: [`/${ROTATED}`, '/ok'], reason: `mine is ${ROTATED}` })
    a.vault.rotateCredential('demo', { value: 'ghp_NEWVALUE99887766554433221100ff', mode: 'keep', retireMs: 0 })
    assert.ok(!a.vault.allSecrets().some((s) => s.secret === ROTATED), 'the old value is still in the scrub set; the test proves nothing')

    await decide(a, id)
    const [approved] = a.audit('session_request.approved')
    assert.deepEqual(approved.granted.paths, ['/[[av:redacted:demo]]', '/ok'])
    await assertAbsent(a, [ROTATED, ROTATED.slice(0, 16)], ['session_request.opened', 'session_request.approved'])

    // The grant holds the real path, and the gateway enforces it.
    const grant = grantOf(a, approved)
    assert.deepEqual(grant.policy.paths, [`/${ROTATED}`, '/ok'])
    const { placeholder } = a.vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
    const allowed = await a.gateway(`/p/demo/${ROTATED}`, { headers: { authorization: `Bearer ${placeholder}` } })
    assert.equal(allowed.status, 200, allowed.text)
    assert.equal(a.seen.at(-1).url, `/${ROTATED}`)
    const { placeholder: other } = a.vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
    const outside = await a.gateway('/p/demo/not-the-path', { headers: { authorization: `Bearer ${other}` } })
    assert.equal(outside.status, 403, outside.text)
  } finally { await a.stop() }
})

test('F1: the same rotation before decide-many keeps the path and a payload one_of string out of the record', async () => {
  const a = await start(ROTATED)
  try {
    const id = await ask(a, {
      cred: 'demo', methods: ['GET', 'POST'], paths: [`/many/${ROTATED}`],
      payload: { json: { '/q': { one_of: [ROTATED, 'plain'] } } },
    })
    a.vault.rotateCredential('demo', { value: 'ghp_NEWVALUE99887766554433221100ee', mode: 'keep', retireMs: 0 })
    a.openWindow()
    const r = await a.control('POST', '/v1/pending/decide-many', { decisions: [{ id, kind: 'session', granted: true }] })
    a.closeWindow()
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.decided[0].outcome, 'decided', JSON.stringify(r.body))

    const [approved] = a.audit('session_request.approved')
    assert.ok(approved.granted, 'the record was nulled where a scrub was enough')
    assert.deepEqual(approved.granted.paths, ['/many/[[av:redacted:demo]]'])
    await assertAbsent(a, [ROTATED, ROTATED.slice(0, 16)], ['session_request.opened', 'session_request.approved', 'pending.decided_many'])

    const grant = grantOf(a, approved)
    assert.deepEqual(grant.policy.paths, [`/many/${ROTATED}`])
    assert.ok(JSON.stringify(grant.policy.payload).includes(ROTATED), 'the grant lost the one_of value the human approved')
  } finally { await a.stop() }
})

// --- F2: numbers ------------------------------------------------------------------

test('F2: a stored secret as a number in quota, budget or a payload one_of is not in the approved record, and the grant keeps the numbers', async () => {
  const a = await start()
  try {
    const id = await ask(a, {
      cred: 'demo', methods: ['GET', 'POST'], paths: ['/n'],
      budget: Number(PIN), quota: { count: Number(PIN), window: 'day' },
      payload: { json: { '/q': { one_of: [Number(PIN), PIN] } } },
    })
    await decide(a, id)
    const [approved] = a.audit('session_request.approved')
    assert.ok(approved.granted, 'the record was nulled where a scrub was enough')
    assert.equal(approved.granted.budget, '[[av:redacted:pin]]')
    assert.equal(approved.granted.quota.count, '[[av:redacted:pin]]')
    await assertAbsent(a, [PIN], ['session_request.opened', 'session_request.approved'], { requestRecords: true })

    const grant = grantOf(a, approved)
    assert.equal(grant.policy.budget.limit, Number(PIN))
    assert.equal(grant.policy.quota.count, Number(PIN))
    assert.deepEqual(grant.policy.payload.json['/q'].one_of, [Number(PIN), PIN])
  } finally { await a.stop() }
})

test('F2: a number the human sets as a narrowing is scrubbed the same way', async () => {
  const a = await start()
  try {
    const id = await ask(a, { cred: 'demo', methods: ['GET'], paths: ['/n'], budget: 99999999 })
    await decide(a, id, { overrides: { budget: Number(PIN) } })
    const [approved] = a.audit('session_request.approved')
    assert.equal(approved.granted.budget, '[[av:redacted:pin]]')
    await assertAbsent(a, [PIN], ['session_request.opened', 'session_request.approved'], { requestRecords: true })
    assert.equal(grantOf(a, approved).policy.budget.limit, Number(PIN))
  } finally { await a.stop() }
})

// --- F3: encodings ----------------------------------------------------------------

test('F3: a percent-encoded secret in a path and the reason reaches neither record, and the grant keeps both paths', async () => {
  const a = await start(ENCODABLE)
  try {
    const encoded = encodeURIComponent(ENCODABLE)
    assert.notEqual(encoded, ENCODABLE)
    const id = await ask(a, {
      cred: 'demo', methods: ['GET'], paths: [`/${encoded}`, `/${ENCODABLE}`],
      reason: `the token, url-safe: ${encoded}`,
    })
    const [opened] = a.audit('session_request.opened')
    assert.ok(opened.summary && !opened.summary.includes(encoded), JSON.stringify(opened))
    assert.ok(opened.agent_reason_untrusted && !opened.agent_reason_untrusted.includes(encoded), JSON.stringify(opened))

    await decide(a, id)
    const [approved] = a.audit('session_request.approved')
    assert.deepEqual(approved.granted.paths, ['/[[av:redacted:demo]]', '/[[av:redacted:demo]]'])
    await assertAbsent(a, [ENCODABLE, encoded, encoded.slice(0, 14)], ['session_request.opened', 'session_request.approved'])
    assert.deepEqual(grantOf(a, approved).policy.paths, [`/${encoded}`, `/${ENCODABLE}`])
  } finally { await a.stop() }
})

test('F3: every encoding the response scrubber knows is scrubbed, and a form it cannot replace nulls the record', () => {
  const secrets = [{ secret: ENCODABLE, label: 'demo' }]
  const forms = needlesOf(secrets).map((n) => n.needle)
  assert.ok(forms.length >= 6, `${forms.length} forms`)
  for (const form of forms) {
    const out = auditCopy({ paths: [`/x${form}y`], reason: form }, secrets)
    assert.ok(out, `the record was nulled for ${form}`)
    assert.ok(!JSON.stringify(out).includes(form), `${form} survived: ${JSON.stringify(out)}`)
  }
  // Encoded in part, or twice over: not a form to replace, so not recorded.
  const partly = ENCODABLE.replace('/', '%2F')
  assert.equal(auditCopy({ paths: [`/${partly}`] }, secrets), null)
  assert.equal(auditCopy({ paths: [`/${encodeURIComponent(encodeURIComponent(ENCODABLE))}`] }, secrets), null)
  assert.equal(holdsSecret(`\\u${'g'.charCodeAt(0).toString(16).padStart(4, '0')}${ENCODABLE.slice(1)}`, needlesOf(secrets)), true)
  // Ordinary text is kept as it is.
  assert.deepEqual(auditCopy({ paths: ['/repos/**'], budget: 5 }, secrets), { paths: ['/repos/**'], budget: 5 })
  // redactDeep alone replaces a number's decimal form.
  assert.deepEqual(redactDeep({ n: 9_123_456_789 }, [{ secret: '12345678', label: 'pin' }]), { n: '9[[av:redacted:pin]]9' })
})

// --- fail closed --------------------------------------------------------------------

test('fail closed: an empty or partial secret list at approval stores granted null, and the grant keeps the real path', async () => {
  for (const [name, stub] of [
    ['empty', () => []],
    ['partial', (all) => all.filter((s) => s.label !== 'demo')],
  ]) {
    const a = await start()
    try {
      const id = await ask(a, { cred: 'demo', methods: ['GET'], paths: [`/${SECRET}`] })
      const real = a.vault.allSecrets.bind(a.vault)
      a.vault.allSecrets = () => stub(real())
      try { await decide(a, id) } finally { a.vault.allSecrets = real }
      const [approved] = a.audit('session_request.approved')
      assert.equal(approved.granted, null, `${name}: ${JSON.stringify(approved)}`)
      assert.ok(approved.session_id, `${name}: the record no longer says it was approved`)
      await assertAbsent(a, [SECRET])
      assert.deepEqual(grantOf(a, approved).policy.paths, [`/${SECRET}`])
    } finally { await a.stop() }
  }
})

test('fail closed: an empty or partial secret list when asked records no summary or reason, and the approval stores granted null', async () => {
  for (const [name, stub] of [
    ['empty', () => []],
    ['partial', (all) => all.filter((s) => s.label !== 'demo')],
  ]) {
    const a = await start()
    try {
      const real = a.vault.allSecrets.bind(a.vault)
      a.vault.allSecrets = () => stub(real())
      let id
      try { id = await ask(a, { cred: 'demo', methods: ['GET'], paths: [`/${SECRET}`], reason: SECRET }) } finally { a.vault.allSecrets = real }
      const [opened] = a.audit('session_request.opened')
      assert.equal(opened.summary, null, name)
      assert.equal(opened.agent_reason_untrusted, null, name)
      // Nothing was captured when it was asked, so the approval cannot be checked against it.
      await decide(a, id)
      const [approved] = a.audit('session_request.approved')
      assert.equal(approved.granted, null, `${name}: ${JSON.stringify(approved)}`)
      await assertAbsent(a, [SECRET], ['session_request.opened', 'session_request.approved'])
    } finally { await a.stop() }
  }
})

test('fail closed: a request with nothing captured (as after a restart) stores granted null; one with the capture keeps a scrubbed record', async () => {
  const a = await start()
  try {
    const lost = await ask(a, { cred: 'demo', methods: ['GET'], paths: ['/plain'] })
    const kept = await ask(a, { cred: 'demo', methods: ['GET'], paths: ['/plain'] })
    // What a restart loses: the capture is memory only, never in a record.
    assert.ok(!JSON.stringify(a.vault.db.kv.session_requests).includes('secret'), 'the capture was persisted')
    a.daemon.sessionRequests.asked.delete(lost)
    await decide(a, lost)
    await decide(a, kept)
    const records = a.audit('session_request.approved')
    assert.equal(records.find((r) => r.request_id === lost).granted, null)
    assert.deepEqual(records.find((r) => r.request_id === kept).granted.paths, ['/plain'])
  } finally { await a.stop() }
})

test('the capture holds only the secrets the request itself holds, and is dropped once it is decided', async () => {
  const a = await start()
  try {
    const plain = await ask(a, { cred: 'demo', methods: ['GET'], paths: ['/plain'] })
    const holding = await ask(a, { cred: 'demo', methods: ['GET'], paths: [`/${encodeURIComponent(SECRET)}`], budget: Number(PIN) })
    assert.deepEqual(a.daemon.sessionRequests.asked.get(plain), [])
    assert.deepEqual(a.daemon.sessionRequests.asked.get(holding).map((s) => s.label).sort(), ['demo', 'pin'])
    await decide(a, holding)
    assert.equal(a.daemon.sessionRequests.asked.has(holding), false)
  } finally { await a.stop() }
})
