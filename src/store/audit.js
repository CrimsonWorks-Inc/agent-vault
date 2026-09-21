// The audit log: append-only, hash-chained, keyed.
//
// Every allow, deny, presence outcome, placeholder event and connection
// termination lands here. The chain is what makes tampering detectable: each
// record's hash covers the previous hash, so removing or editing a record
// breaks every hash after it and `audit verify` says exactly where.
//
// The chain alone says nothing about the END of the log — truncate it and what
// remains still verifies — so the head (seq, hash) is also kept in a small
// authenticated file beside it, and `audit verify` compares the two.
//
// Never written here: credential values in any encoding, full placeholders,
// request or response bodies, query strings, or Authorization header values.
// The log has to be safe to hand to someone debugging a failure.
//
// The path IS written, scrubbed. Leaving it out meant a grant of
// /repos/frozencrow/** recorded the same glob for every request, so the log
// could say a credential had been used forty times and not which forty things
// it had been used on — the first question anyone asks it. The query string
// still stays out: that is where a credential actually appears in a URL.

import { appendFileSync, readFileSync, existsSync, writeFileSync } from 'node:fs'
import { createHmac } from 'node:crypto'
import * as canon from '../core/canon.js'

const CHECKPOINT_EVERY = 1000

export class AuditLog {
  /**
   * @param {string} path  JSONL file (the spec's production store is SQLite
   *                       with insert-only triggers; the chain is identical)
   * @param {Buffer} key   K_audit
   * @param {{anchored: boolean, markAnchored: () => void}} [stamp]
   *   Whether this vault is known to keep an anchor, held in the VAULT rather
   *   than beside the log. Without it, deleting the anchor file is
   *   indistinguishable from a vault written before anchors existed — so
   *   `rm audit.jsonl.head` alongside a truncation turned a detected
   *   tampering back into "chain intact", repeatably, erasing the previous
   *   round's evidence each time. The stamp lives in a different file, so
   *   removing the anchor no longer removes the knowledge that there was one.
   */
  constructor(path, key, stamp = null) {
    this.path = path
    this.key = key
    this.stamp = stamp
    // Where the chain had got to, kept outside the log. The chain proves no
    // record was edited or removed from the middle, because every later hash
    // would stop matching. It proves nothing about the END: delete the last
    // fifty lines and what remains verifies perfectly. The records anyone
    // would want gone are always the most recent ones, so that is the whole
    // attack, and it needed no key and no cleverness — just `truncate`.
    this.anchorPath = `${path}.head`
    this.seq = 0
    this.prevHash = '0'.repeat(64)
    this.sinceCheckpoint = 0
    /** Set when the log came back shorter than the anchor says it was. */
    this.truncation = null
    /** Set when a non-empty log had no authentic anchor beside it. */
    this.anchorMissing = null
    if (existsSync(path)) this.#recover()
    else writeFileSync(path, '', { mode: 0o600 })
    // Recorded into the chain itself, immediately, because the very next write
    // moves the anchor to the current length and would otherwise destroy the
    // only evidence that anything was missing.
    if (this.truncation) this.write('audit.truncation_detected', this.truncation)
    else if (this.anchorMissing) this.write('audit.anchor_missing', this.anchorMissing)
    else this.#anchor()
    // From here this vault is known to keep an anchor, so a later absence is
    // tampering rather than an upgrade. Written after the first anchor exists,
    // so a crash in between leaves the weaker claim rather than a false one.
    this.stamp?.markAnchored?.()
  }

  /** The (seq, hash) the log should end at, authenticated under K_audit. */
  #anchor() {
    const body = { seq: this.seq, hash: this.prevHash }
    body.mac = createHmac('sha256', this.key).update(`${body.seq}|${body.hash}`).digest('hex')
    writeFileSync(this.anchorPath, JSON.stringify(body), { mode: 0o600 })
  }

  /** Read the anchor, or null if it is absent or not authentic. */
  #readAnchor() {
    if (!existsSync(this.anchorPath)) return null
    try {
      const a = JSON.parse(readFileSync(this.anchorPath, 'utf8'))
      const want = createHmac('sha256', this.key).update(`${a.seq}|${a.hash}`).digest('hex')
      return a.mac === want ? a : null
    } catch { return null }
  }

  #recover() {
    const lines = readFileSync(this.path, 'utf8').split('\n').filter(Boolean)
    const anchor = this.#readAnchor()
    if (!lines.length) {
      // An emptied log with a live anchor is the loudest version of the same
      // attack, and the one a chain walk can say nothing about at all.
      if (anchor && anchor.seq > 0) this.truncation = { expected_seq: anchor.seq, found_seq: 0 }
      return
    }
    const last = JSON.parse(lines[lines.length - 1])
    this.seq = last.seq
    this.prevHash = last.hash
    this.sinceCheckpoint = this.seq % CHECKPOINT_EVERY
    // A crash between the append and the anchor write leaves the anchor one
    // record behind, which is why only a SHORTER log is a finding.
    if (anchor && anchor.seq > last.seq) {
      this.truncation = { expected_seq: anchor.seq, found_seq: last.seq, expected_head: anchor.hash }
    } else if (!anchor) {
      // Deleting the anchor is the obvious next move once truncation is
      // caught, and re-creating it at whatever length the log now has would
      // launder exactly the edit it exists to catch.
      //
      // Whether that absence is tampering or an upgrade is decided by the
      // stamp in the vault — a different file, which an adversary removing the
      // anchor has not necessarily touched. Known to be anchored and the
      // anchor is gone: someone took it. No stamp: this vault predates
      // anchoring, which is not evidence of anything.
      this.anchorMissing = { found_seq: last.seq, was_anchored: !!this.stamp?.anchored }
    }
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
    // After the append, never before: a crash in between then leaves the
    // anchor one record behind the log, which is benign. The other order
    // would report a truncation every time the machine lost power.
    this.#anchor()
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

    // The chain is self-consistent. That is not the same as complete: a walk
    // from the first record cannot tell a log of 200 records from the first
    // 200 of a log that had 250. Only something held outside the file can,
    // which is what the anchor is for.
    const anchor = this.#readAnchor()
    if (!anchor) {
      return {
        ok: false,
        count: rows.length,
        reason: rows.length
          ? 'the head anchor is missing or not authentic, so the end of the log cannot be trusted'
          : 'the head anchor is missing',
      }
    }
    if (anchor.seq > rows.length) {
      return {
        ok: false,
        count: rows.length,
        brokenAt: rows.length + 1,
        reason: `the log ends at record ${rows.length} but should end at ${anchor.seq}: ${anchor.seq - rows.length} record(s) were removed from the end`,
      }
    }
    if (anchor.seq === rows.length && anchor.hash !== prev) {
      return { ok: false, count: rows.length, brokenAt: anchor.seq, reason: 'the last record does not match the head anchor' }
    }

    // A gap found at startup is permanent evidence, not a one-off warning. The
    // daemon keeps running and keeps appending, so within a few records the
    // chain and the anchor agree again — and everything above would go quiet
    // about a log that is known to be missing its middle.
    const cut = rows.find((r) => r.kind === 'audit.truncation_detected')
    if (cut) {
      return {
        ok: false,
        count: rows.length,
        brokenAt: cut.seq,
        reason: `records were removed from the end: the log restarted at ${cut.found_seq} where it should have been at ${cut.expected_seq}`,
      }
    }

    // A missing anchor means one of two different things, and collapsing them
    // was a real bug in both directions.
    //
    // On a vault KNOWN to have kept one, the anchor's absence is somebody
    // having removed it, which is the same act as the truncation it exists to
    // catch — and reporting that as intact let an adversary truncate, delete
    // the anchor, and get a clean bill of health, repeatedly, erasing the
    // previous round's evidence each time.
    //
    // On a vault written before anchoring existed there is no evidence either
    // way: the chain is intact, nothing proves how far it once reached.
    // Reporting THAT as tampering would make the check permanently red on
    // every upgrade, and a check that always fails is a check nobody reads.
    // Any removal-after-anchoring anywhere in the log is the finding, not just
    // the first absence: a vault upgraded from a pre-anchor build carries a
    // permanent benign note at its start, and taking the first record would
    // let every later removal hide behind it forever.
    const absences = rows.filter((r) => r.kind === 'audit.anchor_missing')
    const removed = absences.find((r) => r.was_anchored)
    const noAnchor = removed || absences[0]
    if (noAnchor) {
      if (noAnchor.was_anchored) {
        return {
          ok: false,
          count: rows.length,
          brokenAt: noAnchor.seq,
          reason: `the head anchor was removed from a vault that kept one: at record ${noAnchor.seq} the log was found without it, so records may have been removed from the end`,
        }
      }
      return {
        ok: true,
        count: rows.length,
        head: prev,
        unanchored_before: noAnchor.seq,
        note: `the log had no head anchor when it was opened at record ${noAnchor.seq}, so nothing proves how many records preceded that point; everything from there on is anchored`,
      }
    }
    return { ok: true, count: rows.length, head: prev }
  }

  get head() { return this.prevHash }
}
