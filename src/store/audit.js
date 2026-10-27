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

import { readFileSync, existsSync, writeFileSync, openSync, writeSync, closeSync, renameSync, truncateSync } from 'node:fs'
import { createHmac, timingSafeEqual } from 'node:crypto'
import * as canon from '../core/canon.js'
import { deny } from '../core/errors.js'

const CHECKPOINT_EVERY = 1000
const HEX64 = /^[0-9a-f]{64}$/
const GENESIS = '0'.repeat(64)
// Set by write() itself; a caller's field may never carry one of these names.
export const CHAIN_FIELDS = Object.freeze(['seq', 'ts', 'kind', 'prev_hash', 'hash'])
// F9's bounds: one export page, and one witness file's worth of checkpoints.
const MAX_EXPORT_ROWS = 5000
const MAX_WITNESS_CHECKPOINTS = 10_000

/**
 * Whether a parsed line has the shape of a record. Parsing is not enough: a
 * line of `{}` parses, recovery then resumed from `seq: undefined`, and the
 * next write inside unlock threw — AV_LOCKED for the right factor, every
 * time. A line without the chain fields is as unreadable as one that does
 * not parse, and is reported the same way.
 */
function isRecord(row) {
  return !!row && typeof row === 'object' && !Array.isArray(row)
    && Number.isSafeInteger(row.seq) && row.seq >= 1
    && typeof row.ts === 'string' && typeof row.kind === 'string'
    && typeof row.hash === 'string' && HEX64.test(row.hash)
    && typeof row.prev_hash === 'string' && HEX64.test(row.prev_hash)
}

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
    /** Set when lines in the log could not be read at all. */
    this.corruption = null
    // A missing log goes through recovery like any other, rather than being
    // re-created and re-anchored on the spot. Skipping it meant `rm
    // audit.jsonl` while the daemon was stopped wrote a fresh anchor at seq 0
    // over the old one, and verify reported a one-record log as intact.
    if (!existsSync(path)) writeFileSync(path, '', { mode: 0o600 })
    this.#recover()
    // Recorded into the chain itself, immediately, because the very next write
    // moves the anchor to the current length and would otherwise destroy the
    // only evidence that anything was missing.
    if (this.corruption) this.write('audit.corruption_detected', this.corruption)
    if (this.truncation) this.write('audit.truncation_detected', this.truncation)
    else if (this.anchorMissing) this.write('audit.anchor_missing', this.anchorMissing)
    else if (!this.corruption) this.#anchor()
    // From here this vault is known to keep an anchor, so a later absence is
    // tampering rather than an upgrade. Written after the first anchor exists,
    // so a crash in between leaves the weaker claim rather than a false one.
    this.stamp?.markAnchored?.()
  }

  /**
   * The (seq, hash) the log should end at, authenticated under K_audit.
   *
   * Written to a temp file and renamed over the old one. It was rewritten in
   * place — truncate, then write — so a crash between the two left an empty
   * anchor, which an anchored vault reads as somebody having removed it: a
   * permanent, false finding of tampering. A rename is atomic, so a crashed
   * process leaves the old anchor or the new one.
   *
   * Not fsynced, and neither is the log line before it: this runs several
   * times per proxied request, and two flushes per record made every request
   * several times slower. The cost of that is a power cut, not a crash — the
   * OS may then persist the anchor ahead of the line it covers, which reads
   * as truncation. The README states it under the honest limits.
   */
  #anchor() {
    const body = { seq: this.seq, hash: this.prevHash }
    body.mac = createHmac('sha256', this.key).update(`${body.seq}|${body.hash}`).digest('hex')
    const tmp = `${this.anchorPath}.tmp`
    const fd = openSync(tmp, 'w', 0o600)
    try { writeSync(fd, JSON.stringify(body)) } finally { closeSync(fd) }
    renameSync(tmp, this.anchorPath)
  }

  /** Append one line. */
  #append(line) {
    const fd = openSync(this.path, 'a', 0o600)
    try { writeSync(fd, line) } finally { closeSync(fd) }
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

  /**
   * Every record in the file, as objects.
   *
   * A half-written final line is what an ordinary crash mid-append leaves — a
   * power cut, a SIGKILL — and JSON.parse threw on it. From inside unlockWith
   * that throw landed in a `catch` that moved on to the next factor, so every
   * factor failed identically and one interrupted write locked the owner out
   * of the vault for good. verify() and read() threw outright.
   *
   * Dropping a torn LAST line is also correct against the anchor: the anchor
   * is written AFTER the append, so a crash mid-append leaves it pointing at
   * the previous record, which is exactly where the log now ends. A torn line
   * reports no truncation; a record genuinely removed still does.
   *
   * Only the last line. A bad line anywhere else is corruption the chain
   * should report, not something to quietly skip past.
   */
  /**
   * Repair the end of the file: drop a half-written final line, and finish a
   * complete one that lost only its newline.
   *
   * The newline case used to pass as complete, so the next append joined onto
   * it and produced one corrupt line in the middle of the log. The repair is a
   * truncate at the last newline, never a rewrite of the whole file: a crash
   * during a rewrite could take the entire history with it.
   */
  #dropTornTail() {
    const text = readFileSync(this.path, 'utf8')
    if (!text || text.endsWith('\n')) return
    const cut = text.lastIndexOf('\n') + 1
    try {
      JSON.parse(text.slice(cut))
      this.#append('\n')
    } catch {
      truncateSync(this.path, Buffer.byteLength(text.slice(0, cut)))
    }
  }

  /**
   * Every line in the file, as records. A line that cannot be read comes back
   * as `{ unreadable: true, line }` rather than throwing: this runs inside
   * unlock, where a throw looked exactly like a wrong passphrase, so one bad
   * sector in the middle of the log locked the owner out of every credential.
   * The chain reports the break instead, which is what it exists to do.
   */
  #rows() {
    const lines = readFileSync(this.path, 'utf8').split('\n').filter(Boolean)
    if (lines.length) {
      try { JSON.parse(lines[lines.length - 1]) } catch { lines.pop() }
    }
    return lines.map((l, i) => {
      try {
        const row = JSON.parse(l)
        if (isRecord(row)) return row
      } catch { /* reported below */ }
      return { unreadable: true, line: i + 1 }
    })
  }

  #recover() {
    // Repair before reading, not just read around it. A torn fragment has no
    // trailing newline, so the NEXT append concatenates onto it and produces
    // one corrupt line holding both — turning a recoverable crash into a
    // genuinely broken chain, one record further in, every time.
    this.#dropTornTail()
    const rows = this.#rows()
    const unreadable = rows.filter((r) => r.unreadable).map((r) => r.line)
    if (unreadable.length) this.corruption = { lines: unreadable.slice(0, 20), count: unreadable.length }
    const lines = rows.filter((r) => !r.unreadable)
    const anchor = this.#readAnchor()
    if (!lines.length) {
      // An emptied log with a live anchor is the loudest version of the same
      // attack, and the one a chain walk can say nothing about at all.
      if (anchor && anchor.seq > 0) this.truncation = { expected_seq: anchor.seq, found_seq: 0 }
      // And with the anchor gone as well, the stamp is the only witness. An
      // empty or deleted log on a vault known to keep an anchor is the whole
      // history erased, not a vault that has never written anything.
      else if (!anchor && this.stamp?.anchored) this.anchorMissing = { found_seq: 0, was_anchored: true }
      return
    }
    const last = lines[lines.length - 1]
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
    // Made recordable first. The canonical form refuses floats, and fields
    // carry agent-written values (a `reason` of 1.5), so write() threw AFTER
    // the change it was recording had been made: a stored session request,
    // a minted placeholder, and no record of either.
    //
    //
    // And the chain fields come from the chain, never from the caller (C10).
    // They were spread in before `prev_hash` and after `seq`, `ts` and `kind`,
    // so a field named `seq` rewrote the record's own place in the chain
    // (verify then reports a sequence gap, and this.seq rewinds to it) and
    // one named `hash` was replaced by the chain hash without a word. Dropping
    // such a field would lose what the caller meant to record, so it is
    // refused, before anything is appended.
    const own = recordable(fields) ?? {}
    const reserved = CHAIN_FIELDS.find((k) => Object.hasOwn(own, k))
    if (reserved) throw deny('AV_INTERNAL', `audit record ${kind} sets the chain field ${reserved}; name it something else`)
    const record = { seq: this.seq + 1, ts: new Date().toISOString(), kind, ...own, prev_hash: this.prevHash }
    record.hash = this.#hash(record)
    this.#append(`${JSON.stringify(record)}\n`)
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
    this.#append(`${JSON.stringify(record)}\n`)
    this.seq = record.seq
    this.prevHash = record.hash
  }

  /** Read records, newest last. */
  read({ limit = 100, kind, sessionId, since } = {}) {
    if (!existsSync(this.path)) return []
    let rows = this.#rows().filter((r) => !r.unreadable)
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
    if (!existsSync(this.path)) {
      // Gone from under a running daemon. On a vault known to keep an anchor
      // that is the whole log removed, not an empty one.
      return this.stamp?.anchored
        ? { ok: false, count: 0, reason: 'the audit log is missing from a vault that keeps one' }
        : { ok: true, count: 0 }
    }
    const rows = this.#rows()
    let prev = '0'.repeat(64)
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i]
      if (row.unreadable) return { ok: false, count: rows.length, brokenAt: i + 1, reason: 'unreadable record' }
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

  // ------------------------------------------------- F9: export and witness

  /**
   * A page of the log as it is on disk, chain fields and all, so anyone who
   * holds the vault can re-verify it elsewhere (F9). Records with seq above
   * `sinceSeq`, in order, at most 5000. Reading it is recorded, after it is
   * read, so the head returned is the one the page was read against.
   */
  export({ sinceSeq = 0, limit = MAX_EXPORT_ROWS } = {}) {
    if (!Number.isSafeInteger(sinceSeq) || sinceSeq < 0) {
      throw deny('AV_POLICY_DENIED', 'since_seq must be a whole number, 0 or more', { rule: 'audit_range' })
    }
    if (typeof limit !== 'number' || Number.isNaN(limit)) {
      throw deny('AV_POLICY_DENIED', `limit must be a number, clamped to 1..${MAX_EXPORT_ROWS}`, { rule: 'audit_range' })
    }
    const take = Math.min(MAX_EXPORT_ROWS, Math.max(1, Math.floor(limit)))
    const rows = this.#rows().filter((r) => !r.unreadable && r.seq > sinceSeq).slice(0, take)
    const head = { seq: this.seq, hash: this.prevHash }
    const nextSeq = rows.length ? rows[rows.length - 1].seq : sinceSeq
    this.write('audit.exported', { from_seq: rows.length ? rows[0].seq : null, to_seq: rows.length ? nextSeq : null, rows: rows.length })
    return { rows, next_seq: nextSeq, head }
  }

  /**
   * Where the log has got to, MACed under K_audit, for keeping somewhere the
   * agent cannot rewrite (F9). The MAC message starts `witness|`, which no
   * record hash or anchor MAC does, so none can stand in for another.
   */
  checkpoint() {
    const vaultId = this.#vaultId()
    const seq = this.seq
    const head = this.prevHash
    const ts = new Date().toISOString()
    const mac = this.#witnessMac(vaultId, seq, head, ts)
    this.write('audit.checkpoint_issued', { checkpoint_seq: seq })
    return { vault_id: vaultId, seq, head, ts, mac }
  }

  /**
   * Check witness checkpoints against the log on disk (F9). A checkpoint
   * whose MAC does not verify is `forged`; one for another vault is
   * `other_vault`; one past the last record is `ahead` (the log was cut back);
   * one whose record now has a different hash is `mismatched`. A witness
   * behind the head is normal. Read from the file, not from memory: a log
   * truncated under a running daemon is still ahead of what the daemon
   * remembers writing.
   */
  verifyWitness(checkpoints) {
    if (!Array.isArray(checkpoints) || checkpoints.length > MAX_WITNESS_CHECKPOINTS) {
      throw deny('AV_POLICY_DENIED', `checkpoints must be a list of at most ${MAX_WITNESS_CHECKPOINTS}`, { rule: 'audit_range' })
    }
    const vaultId = this.#vaultId()
    const hashAt = new Map([[0, GENESIS]])
    let last = 0
    for (const r of this.#rows()) {
      if (r.unreadable) continue
      hashAt.set(r.seq, r.hash)
      if (r.seq > last) last = r.seq
    }
    const out = { ok: true, checked: checkpoints.length, ahead: [], mismatched: [], forged: [], other_vault: [] }
    checkpoints.forEach((c, i) => {
      const shaped = c && typeof c === 'object' && typeof c.vault_id === 'string' && Number.isSafeInteger(c.seq) && c.seq >= 0 &&
        typeof c.head === 'string' && HEX64.test(c.head) && typeof c.ts === 'string' && typeof c.mac === 'string' && HEX64.test(c.mac)
      if (!shaped || !timingSafeEqual(Buffer.from(c.mac, 'hex'), Buffer.from(this.#witnessMac(c.vault_id, c.seq, c.head, c.ts), 'hex'))) {
        out.forged.push(i)
      } else if (c.vault_id !== vaultId) {
        out.other_vault.push(i)
      } else if (c.seq > last) {
        out.ahead.push(c.seq)
      } else if (hashAt.get(c.seq) !== c.head) {
        out.mismatched.push(c.seq)
      }
    })
    out.ok = !out.forged.length && !out.ahead.length && !out.mismatched.length
    this.write('audit.witness_verified', {
      ok: out.ok, checked: out.checked, ahead: out.ahead.length, mismatched: out.mismatched.length, forged: out.forged.length,
    })
    return out
  }

  #witnessMac(vaultId, seq, head, ts) {
    return createHmac('sha256', this.key).update(`witness|${vaultId}|${seq}|${head}|${ts}`).digest('hex')
  }

  /** The vault's stable id, kept in the vault (kv.vault_id), created on first use. */
  #vaultId() {
    const vaultId = this.stamp?.vaultId?.()
    if (typeof vaultId !== 'string' || !vaultId) throw new Error('this audit log belongs to no vault id, so it cannot be witnessed')
    return vaultId
  }

  get head() { return this.prevHash }
}

/**
 * Fields as the chain can hold them. A number that is not an integer becomes
 * its decimal string; so does anything else the canonical form has no
 * encoding for. Integers, strings, booleans and null pass unchanged.
 */
function recordable(value) {
  if (value === null || value === undefined) return value
  if (typeof value === 'number') return Number.isInteger(value) ? value : String(value)
  if (typeof value === 'string' || typeof value === 'boolean') return value
  if (Array.isArray(value)) return value.map((v) => (v === undefined ? null : recordable(v)))
  if (typeof value === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(value)) if (v !== undefined) out[k] = recordable(v)
    return out
  }
  return String(value)
}
