// F9, store side: audit export and the external head witness, and C10: no
// caller can set a chain field. Neither may weaken what the chain and the
// head anchor already prove.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { createHmac } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { CHAIN_FIELDS } from '../../src/store/audit.js'
import { fresh, code, records, refusedCleanly, SECRET, POLICY } from './store-helpers.js'

const logLines = (v) => readFileSync(join(v.dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean)
const logRows = (v) => logLines(v).map((l) => JSON.parse(l))

/** Some ordinary traffic, so there is a chain worth exporting. */
function busy(v) {
  const { session } = v.vault.createSession({ label: 'busy' })
  const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY })
  const issued = v.vault.issuePlaceholder({ grantId: grant.id })
  v.vault.consumePlaceholder(issued.row.id)
  return issued.placeholder
}

test('export returns the records after since_seq exactly as they are on disk, and is recorded after reading', () => {
  const v = fresh()
  try {
    const placeholder = busy(v)
    const before = { seq: v.vault.audit.seq, hash: v.vault.audit.head }
    const out = v.vault.audit.export({ sinceSeq: 2 })
    assert.deepEqual(out.head, before)
    assert.deepEqual(out.rows, logRows(v).filter((r) => r.seq > 2 && r.seq <= before.seq))
    assert.equal(out.next_seq, before.seq)
    // Chained as exported: each row names the hash before it.
    for (let i = 1; i < out.rows.length; i++) assert.equal(out.rows[i].prev_hash, out.rows[i - 1].hash)
    const text = JSON.stringify(out)
    assert.ok(!text.includes(SECRET) && !text.includes(placeholder), 'an export carried a value or a placeholder')

    const [rec] = records(v, 'audit.exported')
    assert.deepEqual([rec.from_seq, rec.to_seq, rec.rows], [3, before.seq, before.seq - 2])
    assert.equal(rec.seq, before.seq + 1)
    assert.equal(v.vault.audit.verify().ok, true)

    // Nothing new past the head: an empty page that says where it stopped.
    const tail = v.vault.audit.export({ sinceSeq: v.vault.audit.seq })
    assert.deepEqual([tail.rows.length, tail.next_seq], [0, v.vault.audit.seq - 1])
    assert.deepEqual([records(v, 'audit.exported')[1].from_seq, records(v, 'audit.exported')[1].to_seq], [null, null])
  } finally { v.done() }
})

test('the export limit is clamped to 1..5000', () => {
  const v = fresh()
  try {
    busy(v)
    assert.equal(v.vault.audit.export({ limit: 0 }).rows.length, 1)
    assert.equal(v.vault.audit.export({ limit: -7 }).rows.length, 1)
    assert.equal(v.vault.audit.export({ limit: 2.7 }).rows.length, 2)
    const all = v.vault.audit.seq
    assert.equal(v.vault.audit.export({ limit: 1e9 }).rows.length, all)
    assert.equal(v.vault.audit.export({ limit: 3 }).next_seq, 3)
  } finally { v.done() }
})

test('an export range that is not a whole number is refused, and nothing is recorded', () => {
  const v = fresh()
  try {
    for (const opts of [{ sinceSeq: -1 }, { sinceSeq: 1.5 }, { sinceSeq: '3' }, { sinceSeq: NaN }, { limit: 'x' }, { limit: NaN }]) {
      refusedCleanly(v, () => v.vault.audit.export(opts), { code: 'AV_POLICY_DENIED', rule: 'audit_range' })
    }
  } finally { v.done() }
})

test('a checkpoint names a stable vault id, the head, and a MAC over both; it keeps the chain intact', () => {
  const v = fresh()
  try {
    busy(v)
    const seq = v.vault.audit.seq
    const head = v.vault.audit.head
    const c = v.vault.audit.checkpoint()
    assert.deepEqual([c.seq, c.head], [seq, head])
    assert.match(c.vault_id, /^vlt_[0-9A-Z]{26}$/)
    assert.equal(c.mac, createHmac('sha256', v.vault.audit.key).update(`witness|${c.vault_id}|${c.seq}|${c.head}|${c.ts}`).digest('hex'))
    const [rec] = records(v, 'audit.checkpoint_issued')
    assert.equal(rec.checkpoint_seq, seq)
    assert.equal(rec.seq, seq + 1, 'the checkpoint record took its own place in the chain')
    assert.equal(v.vault.audit.verify().ok, true)

    assert.equal(v.vault.audit.checkpoint().vault_id, c.vault_id)
    const again = Vault.open(v.dir)
    again.unlock()
    assert.equal(again.audit.checkpoint().vault_id, c.vault_id, 'the vault id survives a restart')
  } finally { v.done() }
})

test('an untouched log reports its witnesses ok, the genesis one included', () => {
  const v = fresh()
  try {
    const key = v.vault.audit.key
    const witnesses = [v.vault.audit.checkpoint()]
    busy(v)
    witnesses.push(v.vault.audit.checkpoint())
    busy(v)
    witnesses.push(v.vault.audit.checkpoint())
    const ts = new Date().toISOString()
    const id = witnesses[0].vault_id
    const genesis = '0'.repeat(64)
    witnesses.push({ vault_id: id, seq: 0, head: genesis, ts, mac: createHmac('sha256', key).update(`witness|${id}|0|${genesis}|${ts}`).digest('hex') })
    const out = v.vault.audit.verifyWitness(witnesses)
    assert.deepEqual(out, { ok: true, checked: 4, ahead: [], mismatched: [], forged: [], other_vault: [] })
    const [rec] = records(v, 'audit.witness_verified')
    assert.deepEqual([rec.ok, rec.checked, rec.ahead, rec.mismatched, rec.forged], [true, 4, 0, 0, 0])
  } finally { v.done() }
})

test('a log cut back after a witness reports it ahead', () => {
  const v = fresh()
  try {
    busy(v)
    const early = v.vault.audit.checkpoint()
    busy(v)
    const late = v.vault.audit.checkpoint()
    const lines = logLines(v)
    writeFileSync(join(v.dir, 'audit.jsonl'), `${lines.slice(0, late.seq - 3).join('\n')}\n`)
    const out = v.vault.audit.verifyWitness([early, late])
    assert.equal(out.ok, false)
    assert.deepEqual(out.ahead, [late.seq])
    assert.deepEqual(out.mismatched, [])
  } finally { v.done() }
})

test('a record whose hash was changed reports mismatched; a changed witness reports forged', () => {
  const v = fresh()
  try {
    busy(v)
    const c = v.vault.audit.checkpoint()
    const lines = logLines(v)
    const row = JSON.parse(lines[c.seq - 1])
    row.hash = 'f'.repeat(64)
    lines[c.seq - 1] = JSON.stringify(row)
    writeFileSync(join(v.dir, 'audit.jsonl'), `${lines.join('\n')}\n`)
    assert.deepEqual(v.vault.audit.verifyWitness([c]).mismatched, [c.seq])

    const forged = [
      { ...c, seq: c.seq - 1 }, { ...c, head: 'a'.repeat(64) }, { ...c, ts: new Date(0).toISOString() },
      { ...c, mac: 'zz' }, { ...c, mac: undefined }, null, 'checkpoint', [], { ...c, seq: '3' },
    ]
    const out = v.vault.audit.verifyWitness(forged)
    assert.deepEqual(out.forged, forged.map((_, i) => i))
    assert.equal(out.ok, false)
  } finally { v.done() }
})

test('a witness for another vault is reported, and does not by itself fail the check', () => {
  const v = fresh()
  try {
    const key = v.vault.audit.key
    const c = v.vault.audit.checkpoint()
    const other = { ...c, vault_id: 'vlt_SOMEWHEREELSE0000000000000' }
    other.mac = createHmac('sha256', key).update(`witness|${other.vault_id}|${other.seq}|${other.head}|${other.ts}`).digest('hex')
    const out = v.vault.audit.verifyWitness([c, other])
    assert.deepEqual([out.ok, out.other_vault, out.forged], [true, [1], []])
  } finally { v.done() }
})

test('a witness list that is not a list, or too long, is refused', () => {
  const v = fresh()
  try {
    for (const bad of [null, {}, 'x', Array.from({ length: 10_001 }, () => ({}))]) {
      refusedCleanly(v, () => v.vault.audit.verifyWitness(bad), { code: 'AV_POLICY_DENIED', rule: 'audit_range' })
    }
  } finally { v.done() }
})

// ------------------------------------------------------------------ C10

test('a caller cannot set a chain field: write refuses it, naming the field, and appends nothing', () => {
  const v = fresh()
  try {
    for (const k of CHAIN_FIELDS) {
      const before = readFileSync(join(v.dir, 'audit.jsonl'), 'utf8')
      const seq = v.vault.audit.seq
      const thrown = (() => { try { v.vault.audit.write('test.reserved', { [k]: 7, other: 1 }) } catch (e) { return e } })()
      assert.equal(thrown?.code, 'AV_INTERNAL', k)
      assert.match(thrown.detail ?? thrown.message, new RegExp(`\\b${k}\\b`))
      assert.equal(readFileSync(join(v.dir, 'audit.jsonl'), 'utf8'), before, `${k}: something was appended`)
      assert.equal(v.vault.audit.seq, seq)
    }
    assert.deepEqual([...CHAIN_FIELDS].sort(), ['hash', 'kind', 'prev_hash', 'seq', 'ts'])
    // Ordinary fields, including ones that merely contain the words, are fine.
    v.vault.audit.write('test.ordinary', { checkpoint_seq: 3, template_hash: 'ab', kinds: 1, from_seq: 2 })
    assert.equal(v.vault.audit.verify().ok, true)
  } finally { v.done() }
})

/** The object literal passed as `write`'s second argument, by brace matching. */
function fieldsLiterals(src) {
  const out = []
  const re = /\b(?:audit\??\.write|this\.write)\(\s*(?:'[^']*'|`[^`]*`|[A-Za-z_.?]+)\s*,\s*\{/g
  let m
  while ((m = re.exec(src))) {
    let depth = 0
    let i = m.index + m[0].length - 1
    const start = i
    for (; i < src.length; i++) {
      if (src[i] === '{') depth++
      else if (src[i] === '}' && --depth === 0) break
    }
    out.push(src.slice(start, i + 1))
  }
  return out
}

test('no audit.write call in src passes a chain field', () => {
  const files = []
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name)
      if (e.isDirectory()) walk(p)
      else if (e.name.endsWith('.js')) files.push(p)
    }
  }
  walk(new URL('../../src', import.meta.url).pathname)
  let calls = 0
  const bad = []
  for (const f of files) {
    for (const lit of fieldsLiterals(readFileSync(f, 'utf8'))) {
      calls++
      // Only keys at the top level of the literal: a nested `req: { … }` is its own object.
      let depth = 0
      let top = ''
      for (const ch of lit) {
        if (ch === '{' || ch === '[' || ch === '(') depth++
        if (depth === 1) top += ch
        if (ch === '}' || ch === ']' || ch === ')') depth--
      }
      const key = new RegExp(`(?:^|[{,])\\s*(${CHAIN_FIELDS.join('|')})\\s*(?::|,|\\})`)
      const hit = key.exec(top)
      if (hit) bad.push(`${f.replace(/^.*\/src\//, 'src/')}: ${hit[1]}`)
    }
  }
  assert.ok(calls > 80, `found only ${calls} write() calls; the scan has stopped reading the source`)
  assert.deepEqual(bad, [])
  // And the scan does see a reserved key when there is one.
  const probe = fieldsLiterals("this.audit.write('x', { a: 1, seq: n })")[0]
  assert.ok(probe.includes('seq'))
})
