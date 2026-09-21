// The audit log: append-only, hash-chained, keyed.
//
// Every allow, deny, presence outcome, placeholder event and connection
// termination lands here. The chain is what makes tampering detectable: each
// record's hash covers the previous hash, so removing or editing a record
// breaks every hash after it and `audit verify` says exactly where.
//
// Never written here: credential values in any encoding, full placeholders,
// request or response bodies, full paths, or Authorization header values. The
// log has to be safe to hand to someone debugging a failure.

import { appendFileSync, readFileSync, existsSync, writeFileSync } from 'node:fs'
import { createHmac } from 'node:crypto'
import * as canon from '../core/canon.js'

const CHECKPOINT_EVERY = 1000

export class AuditLog {
  /**
   * @param {string} path  JSONL file (the spec's production store is SQLite
   *                       with insert-only triggers; the chain is identical)
   * @param {Buffer} key   K_audit
   */
  constructor(path, key) {
    this.path = path
    this.key = key
    this.seq = 0
    this.prevHash = '0'.repeat(64)
    this.sinceCheckpoint = 0
    if (existsSync(path)) this.#recover()
    else writeFileSync(path, '', { mode: 0o600 })
  }

  #recover() {
    const lines = readFileSync(this.path, 'utf8').split('\n').filter(Boolean)
    if (!lines.length) return
    const last = JSON.parse(lines[lines.length - 1])
    this.seq = last.seq
    this.prevHash = last.hash
    this.sinceCheckpoint = this.seq % CHECKPOINT_EVERY
  }

  #hash(record) {
    const { hash, ...rest } = record
    return createHmac('sha256', this.key)
      .update(`${record.seq}|${record.ts}|${record.kind}|${canon.canonicalize(rest)}|${this.prevHash}`)
      .digest('hex')
  }

  /**
   * Append one record. `fields` is merged in as-is, so callers control the
   * shape; the chain fields are added here.
   */
  write(kind, fields = {}) {
    const record = { seq: this.seq + 1, ts: new Date().toISOString(), kind, ...fields, prev_hash: this.prevHash }
    record.hash = this.#hash(record)
    appendFileSync(this.path, `${JSON.stringify(record)}\n`, { mode: 0o600 })
    this.seq = record.seq
    this.prevHash = record.hash
    if (++this.sinceCheckpoint >= CHECKPOINT_EVERY) {
      this.sinceCheckpoint = 0
      this.#checkpoint()
    }
    return record
  }

  #checkpoint() {
    const record = {
      seq: this.seq + 1,
      ts: new Date().toISOString(),
      kind: 'checkpoint',
      mac: createHmac('sha256', this.key).update(this.prevHash).digest('hex'),
      prev_hash: this.prevHash,
    }
    record.hash = this.#hash(record)
    appendFileSync(this.path, `${JSON.stringify(record)}\n`, { mode: 0o600 })
    this.seq = record.seq
    this.prevHash = record.hash
  }

  /** Read records, newest last. */
  read({ limit = 100, kind, sessionId, since } = {}) {
    if (!existsSync(this.path)) return []
    let rows = readFileSync(this.path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    if (kind) rows = rows.filter((r) => r.kind === kind || r.kind.startsWith(`${kind}.`))
    if (sessionId) rows = rows.filter((r) => r.session_id === sessionId)
    if (since) rows = rows.filter((r) => r.ts >= since)
    return rows.slice(-limit)
  }

  /**
   * Recompute the whole chain. Returns { ok, count, brokenAt } so `audit verify`
   * can name the first record that does not match.
   */
  verify() {
    if (!existsSync(this.path)) return { ok: true, count: 0 }
    const rows = readFileSync(this.path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    let prev = '0'.repeat(64)
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i]
      if (row.prev_hash !== prev) return { ok: false, count: rows.length, brokenAt: row.seq, reason: 'prev_hash mismatch' }
      const { hash, ...rest } = row
      const expected = createHmac('sha256', this.key)
        .update(`${row.seq}|${row.ts}|${row.kind}|${canon.canonicalize(rest)}|${prev}`)
        .digest('hex')
      if (expected !== hash) return { ok: false, count: rows.length, brokenAt: row.seq, reason: 'hash mismatch' }
      if (row.seq !== i + 1) return { ok: false, count: rows.length, brokenAt: row.seq, reason: 'sequence gap' }
      prev = hash
    }
    return { ok: true, count: rows.length, head: prev }
  }

  get head() { return this.prevHash }
}
