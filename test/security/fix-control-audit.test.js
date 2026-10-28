// The audit log has to survive the things that happen to files, and must not
// be erasable by the things an adversary does to them.
//
// - Deleting audit.jsonl while the daemon was stopped re-created it empty and
//   wrote a fresh anchor over the old one: verify said "intact", one record.
//   Deleting the anchor too, or emptying the log, did the same.
// - One unreadable line in the middle threw out of the constructor, inside
//   unlock, where it looked like a wrong passphrase: no factor could open the
//   vault again. A last line that lost only its newline got there in two
//   restarts.
// - The anchor was rewritten in place, so a crash mid-write left it empty —
//   a permanent false finding of tampering.
// - A float in caller-supplied fields made write() throw after the change it
//   was recording had already been made.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, writeFileSync, unlinkSync, statSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import { startDaemon } from './fix-control-helpers.js'

function fresh() {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-audit-'))
  const vault = Vault.create(dir, { factor: 'none' })
  for (let i = 0; i < 5; i++) vault.audit.write('test.event', { n: i })
  vault.lock()
  const log = join(dir, 'audit.jsonl')
  const head = `${log}.head`
  const reopen = () => { const v = Vault.open(dir); v.unlockWith({}); return v }
  return { dir, log, head, reopen, done: () => rmSync(dir, { recursive: true, force: true }) }
}

test('an untouched log reopens and verifies clean', () => {
  const f = fresh()
  try {
    const v = f.reopen()
    assert.equal(v.audit.verify().ok, true, JSON.stringify(v.audit.verify()))
    v.lock()
    assert.equal(f.reopen().audit.verify().ok, true)
  } finally { f.done() }
})

test('a brand-new vault verifies clean', () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-audit-'))
  try {
    const v = Vault.create(dir, { factor: 'none' })
    assert.equal(v.audit.verify().ok, true, JSON.stringify(v.audit.verify()))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('deleting the log is not a fresh start', () => {
  const f = fresh()
  try {
    unlinkSync(f.log)
    const v = f.reopen()
    const r = v.audit.verify()
    assert.equal(r.ok, false, `a deleted log verified as ${JSON.stringify(r)}`)
  } finally { f.done() }
})

test('deleting the log and its anchor together is not a fresh start', () => {
  const f = fresh()
  try {
    unlinkSync(f.log)
    unlinkSync(f.head)
    const r = f.reopen().audit.verify()
    assert.equal(r.ok, false, `verified as ${JSON.stringify(r)}`)
  } finally { f.done() }
})

test('emptying the log and deleting its anchor is not a fresh start', () => {
  const f = fresh()
  try {
    writeFileSync(f.log, '')
    unlinkSync(f.head)
    const r = f.reopen().audit.verify()
    assert.equal(r.ok, false, `verified as ${JSON.stringify(r)}`)
  } finally { f.done() }
})

test('a log deleted while the daemon runs is reported, not passed', () => {
  const f = fresh()
  try {
    const v = f.reopen()
    unlinkSync(f.log)
    assert.equal(v.audit.verify().ok, false)
  } finally { f.done() }
})

test('a damaged line in the middle does not lock the owner out, and is reported', () => {
  const f = fresh()
  try {
    const lines = readFileSync(f.log, 'utf8').split('\n')
    lines[2] = '{"seq":3,"kind":"test.ev\u0000garbage'
    writeFileSync(f.log, lines.join('\n'))
    let v
    assert.doesNotThrow(() => { v = f.reopen() }, 'the right factor must still open the vault')
    assert.equal(v.locked, false)
    const r = v.audit.verify()
    assert.equal(r.ok, false)
    assert.equal(r.brokenAt, 3, JSON.stringify(r))
    assert.doesNotThrow(() => v.audit.read({ limit: 100 }))
    assert.ok(v.audit.read({ limit: 100 }).some((x) => x.kind === 'audit.corruption_detected'))
  } finally { f.done() }
})

test('a last line that lost only its newline survives two restarts', () => {
  const f = fresh()
  try {
    const text = readFileSync(f.log, 'utf8')
    writeFileSync(f.log, text.replace(/\n$/, ''))
    const v1 = f.reopen() // appends vault.unlock
    v1.lock()
    const v2 = f.reopen()
    assert.equal(v2.locked, false)
    assert.equal(v2.audit.verify().ok, true, JSON.stringify(v2.audit.verify()))
  } finally { f.done() }
})

test('a torn half-written last line is still dropped quietly', () => {
  const f = fresh()
  try {
    writeFileSync(f.log, `${readFileSync(f.log, 'utf8')}{"seq":99,"ts":"20`)
    const v = f.reopen()
    assert.equal(v.audit.verify().ok, true, JSON.stringify(v.audit.verify()))
  } finally { f.done() }
})

test('the anchor is replaced whole, never rewritten in place', () => {
  const f = fresh()
  try {
    const v = f.reopen()
    const before = statSync(f.head).ino
    v.audit.write('test.event', { n: 'after' })
    const after = statSync(f.head).ino
    // A rename installs a new file; an in-place write truncates the old one,
    // and a crash between the truncate and the write leaves it empty.
    assert.notEqual(after, before)
    assert.ok(!existsSync(`${f.head}.tmp`), 'no temp file is left behind')
    assert.equal(v.audit.verify().ok, true)
  } finally { f.done() }
})

test('a float in caller fields is recorded, not thrown after the fact', () => {
  const f = fresh()
  try {
    const v = f.reopen()
    let rec
    assert.doesNotThrow(() => { rec = v.audit.write('test.float', { reason: 1.5, nested: { x: 0.25, ok: 3 } }) })
    assert.equal(rec.reason, '1.5')
    assert.equal(rec.nested.ok, 3, 'integers are unchanged')
    assert.equal(v.audit.verify().ok, true)
  } finally { f.done() }
})

test('a session request with a non-string reason is stored and recorded', async () => {
  const d = await startDaemon()
  try {
    const res = await d.control('POST', '/v1/session-requests', { cred: 'demo', reason: 1.5 })
    assert.equal(res.status, 200, JSON.stringify(res.body))
    const opened = d.vault.audit.read({ limit: 50 }).filter((r) => r.kind === 'session_request.opened')
    assert.equal(opened.length, 1, 'the request exists, so its record must too')

    const ok = await d.control('POST', '/v1/session-requests', { cred: 'demo', reason: 'reading issues' })
    assert.equal(ok.status, 200)
    const last = d.vault.audit.read({ limit: 50 }).filter((r) => r.kind === 'session_request.opened').at(-1)
    // C25: the record says a request was opened and its shape, never the
    // agent's words.
    assert.equal(last.cred, 'demo')
    assert.ok(!('agent_reason_untrusted' in last) && !JSON.stringify(last).includes('reading issues'), JSON.stringify(last))
  } finally { await d.stop() }
})

// A line can parse and still not be a record. `{}` as the last line made
// recovery resume from `seq: undefined`, and the next write inside unlock
// threw: AV_LOCKED for the right factor, with no way back in.
for (const [name, bad] of [
  ['an empty object', '{}'],
  ['a record with a string seq', '{"seq":"6","ts":"x","kind":"k","hash":"00","prev_hash":"00"}'],
  ['a record with no hashes', '{"seq":6,"ts":"x","kind":"k"}'],
]) {
  test(`${name} as the last line does not lock the owner out, and is reported`, () => {
    const f = fresh()
    try {
      const before = readFileSync(f.log, 'utf8')
      const at = before.split('\n').filter(Boolean).length + 1
      writeFileSync(f.log, `${before}${bad}\n`)
      let v
      assert.doesNotThrow(() => { v = f.reopen() }, 'the right factor must still open the vault')
      assert.equal(v.locked, false)
      const r = v.audit.verify()
      assert.equal(r.ok, false, `a malformed record verified as ${JSON.stringify(r)}`)
      assert.equal(r.brokenAt, at, JSON.stringify(r))
      // Appending resumed from the last real record, not from the bad one.
      const rec = v.audit.write('test.after', {})
      assert.ok(Number.isSafeInteger(rec.seq) && rec.seq >= at, JSON.stringify(rec))
      assert.ok(v.audit.read({ limit: 100 }).some((x) => x.kind === 'audit.corruption_detected'))
      v.lock()
      assert.doesNotThrow(() => f.reopen(), 'and it opens again after that')
    } finally { f.done() }
  })
}

test('an empty object in the middle does not lock the owner out, and is reported', () => {
  const f = fresh()
  try {
    const lines = readFileSync(f.log, 'utf8').split('\n')
    lines[2] = '{}'
    writeFileSync(f.log, lines.join('\n'))
    let v
    assert.doesNotThrow(() => { v = f.reopen() })
    const r = v.audit.verify()
    assert.equal(r.ok, false)
    assert.equal(r.brokenAt, 3, JSON.stringify(r))
  } finally { f.done() }
})

test('ordinary records, checkpoints included, are all recognised as records', () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-audit-'))
  try {
    const v = Vault.create(dir, { factor: 'none' })
    // Past a checkpoint, so its different shape (a `mac`, no fields) is covered.
    for (let i = 0; i < 1005; i++) v.audit.write('test.event', { n: i })
    v.lock()
    const again = Vault.open(dir)
    again.unlockWith({})
    assert.equal(again.audit.corruption, null)
    assert.equal(again.audit.verify().ok, true, JSON.stringify(again.audit.verify()))
    assert.ok(again.audit.read({ limit: 2000 }).some((x) => x.kind === 'checkpoint'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
