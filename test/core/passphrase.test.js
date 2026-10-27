import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync, chmodSync, statSync, readFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import { randomBytes, generateKeyPairSync } from 'node:crypto'

/** A presence authenticator record, as the web UI hands the daemon one. */
const presenceKey = () => ({
  credentialId: randomBytes(16).toString('base64url'),
  publicKeySpki: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
  signCount: 0,
})

let dir
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'av-pp-')) })
afterEach(() => rmSync(dir, { recursive: true, force: true }))

test('a none-vault unlocks with no secret; a passphrase vault does not', () => {
  const v = Vault.create(dir, { factor: 'none' })
  assert.equal(v.hasPassphrase, false)
  v.setPassphrase('correct horse battery')
  assert.equal(v.hasPassphrase, true)

  // Reopen: it must not unlock without the passphrase.
  v.lock()
  const reopened = Vault.open(dir)
  assert.throws(() => reopened.unlock(null), /AV_LOCKED/)
  assert.throws(() => reopened.unlock('wrong'), /AV_LOCKED/)
  assert.equal(reopened.unlock('correct horse battery'), true)
})

test('locking a passphrase vault zeroizes a key that disk alone cannot recover', () => {
  const v = Vault.create(dir, { factor: 'none' })
  v.addCredential({ slug: 'x', kind: 'http', connector: { host: 'h' }, fields: { token: 'super-secret-value' }, sites: { token: ['header:authorization:Bearer'] } })
  v.setPassphrase('correct horse battery')
  v.lock()
  // A fresh open with the device key present still cannot read anything.
  const reopened = Vault.open(dir)
  assert.throws(() => reopened.revealField(reopened.findCredential('x')?.id, 'token'), /AV_LOCKED/)
})

test('changing a passphrase requires the current one', () => {
  const v = Vault.create(dir, { factor: 'none' })
  v.setPassphrase('first-passphrase')
  assert.throws(() => v.setPassphrase('second-passphrase', 'wrong'), /current passphrase is required/)
  v.setPassphrase('second-passphrase', 'first-passphrase') // succeeds
  v.lock()
  assert.equal(Vault.open(dir).unlock('second-passphrase'), true)
})

test('removing a passphrase requires the current one, then unlock needs no secret', () => {
  const v = Vault.create(dir, { factor: 'none' })
  v.setPassphrase('the-passphrase')
  // Removing it needs another human factor to take over: here a presence
  // authenticator, which keeps the control socket gated.
  v.setPresenceKey(presenceKey())
  assert.throws(() => v.removePassphrase('wrong'), /current passphrase is required/)
  v.removePassphrase('the-passphrase')
  assert.equal(v.hasPassphrase, false)
  v.lock()
  assert.equal(Vault.open(dir).unlock(null), true)
})

test('the passphrase cannot be removed while it is the last human factor', () => {
  const v = Vault.create(dir, { factor: 'none' })
  v.setPassphrase('the-passphrase')
  const before = readFileSync(join(dir, 'vault.json'), 'utf8')
  assert.throws(() => v.removePassphrase('the-passphrase'), (e) => e.code === 'AV_POLICY_DENIED' && e.rule === 'last_factor' && /agent-vault ui/.test(e.hint))
  assert.equal(v.hasPassphrase, true)
  assert.equal(readFileSync(join(dir, 'vault.json'), 'utf8'), before, 'a refusal must not write anything')
  v.lock()
  assert.throws(() => Vault.open(dir).unlock(null), /AV_LOCKED/)
})

test('a passphrase under 8 characters is refused', () => {
  const v = Vault.create(dir, { factor: 'none' })
  assert.throws(() => v.setPassphrase('short'), /at least 8/)
})


test('Touch ID (a PRF secret) unlocks the vault, alongside the passphrase', () => {
  const v = Vault.create(dir, { factor: 'none' })
  // A passphrase is required first, as the recovery factor.
  assert.throws(() => v.addWebauthnUnlock('cred-1', randomBytes(32).toString('base64')), /set a passphrase first/)
  v.setPassphrase('recovery-passphrase')

  const prf = randomBytes(32).toString('base64') // stands in for the authenticator's PRF output
  v.addWebauthnUnlock('cred-1', prf)
  assert.equal(v.hasWebauthnUnlock, true)
  assert.equal(v.webauthnUnlockCredentialId, 'cred-1')

  v.lock()
  const r = Vault.open(dir)
  // Wrong PRF secret fails.
  assert.throws(() => r.unlockWith({ prfSecret: randomBytes(32).toString('base64') }), /AV_LOCKED/)
  // The right PRF secret unlocks.
  assert.equal(r.unlockWith({ prfSecret: prf }), 'webauthn-prf')

  // And the passphrase still works as recovery.
  r.lock()
  const r2 = Vault.open(dir)
  assert.equal(r2.unlockWith({ passphrase: 'recovery-passphrase' }), 'passphrase')
})

test('the passphrase cannot be removed while Touch ID is the other factor', () => {
  const v = Vault.create(dir, { factor: 'none' })
  v.setPassphrase('recovery-passphrase')
  v.addWebauthnUnlock('cred-1', randomBytes(32).toString('base64'))
  assert.throws(() => v.removePassphrase('recovery-passphrase'), (e) => e.rule === 'last_factor' && /remove Touch ID unlock first/.test(e.message))
  // Removing Touch ID first is allowed. The passphrase then goes only if a
  // presence authenticator is left to gate the socket.
  v.removeWebauthnUnlock()
  assert.throws(() => v.removePassphrase('recovery-passphrase'), (e) => e.rule === 'last_factor')
  v.setPresenceKey(presenceKey())
  assert.equal(v.removePassphrase('recovery-passphrase'), true)
})

test('removing the last unlock factor leaves the vault openable, not destroyed', () => {
  // Every wrap is a way back to the master key. Remove the last one and the
  // vault is not locked, it is gone: no factor opens it, and no factor can be
  // added, because adding one needs the key that just became unreachable. Not
  // a lockout — a deletion of every credential in it, with no recovery.
  //
  // The two supported paths cannot reach this state (enrolling Touch ID needs
  // a passphrase, and the passphrase cannot be removed while Touch ID is
  // enrolled), so this reaches it directly, the way a half-written state or an
  // older build's vault would. removePassphrase has always had this guard.
  // removeWebauthnUnlock did not.
  const v = Vault.create(dir, { factor: 'none' })
  v.setPassphrase('recovery-passphrase')
  const prf = randomBytes(32).toString('base64')
  v.addWebauthnUnlock('cred-1', prf)

  // The state under test: the PRF wrap is the only one left.
  v.db.kv.vmk_wraps = v.db.kv.vmk_wraps.filter((w) => w.class === 'webauthn-prf')
  assert.equal(v.db.kv.vmk_wraps.length, 1)

  v.removeWebauthnUnlock()
  assert.ok(v.db.kv.vmk_wraps.length > 0, 'the vault was left with no way to open it')

  // And prove it by actually opening it again from disk. `lock()` wipes the
  // key in memory, so a successful unlock here came from a wrap, not from
  // state the process happened to be holding.
  v.lock()
  const r = Vault.open(dir)
  assert.equal(r.unlockWith({ passphrase: null }), 'none',
    'the vault should still open on the uid boundary alone')
})

test('setting a passphrase keeps an existing Touch ID factor', () => {
  const v = Vault.create(dir, { factor: 'none' })
  v.setPassphrase('first-passphrase')
  const prf = randomBytes(32).toString('base64')
  v.addWebauthnUnlock('cred-1', prf)
  v.setPassphrase('second-passphrase', 'first-passphrase') // change passphrase
  assert.equal(v.hasWebauthnUnlock, true, 'the Touch ID factor must survive a passphrase change')
  v.lock()
  const r = Vault.open(dir)
  assert.equal(r.unlockWith({ prfSecret: prf }), 'webauthn-prf')
})

test('a passphrase vault comes up locked after a restart, not crashed', () => {
  const v = Vault.create(dir, { factor: 'none' })
  v.setPassphrase('the-passphrase')
  // Simulate a normal (not explicitly locked) restart: the daemon cannot
  // auto-unlock without the secret, so it must come up locked, not throw.
  const r = Vault.open(dir)
  const unlocked = r.startInRecordedState(null)
  assert.equal(unlocked, false)
  assert.equal(r.locked, true)
})

test('a crash mid-append does not lock the owner out of their own vault', () => {
  // A half-written final line in audit.jsonl is what an interrupted append
  // leaves behind — a power cut, a SIGKILL. JSON.parse threw on it from inside
  // unlockWith, inside a `catch` that moved on to the next factor, so every
  // factor failed identically and the vault could never be opened again. One
  // interrupted write, every credential gone.
  const fresh = mkdtempSync(join(tmpdir(), 'av-torn-'))
  try {
    const v = Vault.create(fresh, { factor: 'none' })
    v.setPassphrase('the-owners-passphrase')
    v.audit.write('test.event', { n: 1 })
    v.lock()

    // Exactly what a crash mid-append leaves: a complete log plus a fragment.
    const path = join(fresh, 'audit.jsonl')
    writeFileSync(path, `${readFileSync(path, 'utf8')}{"seq":99,"ts":"2026`)

    const reopened = Vault.open(fresh)
    assert.equal(reopened.unlockWith({ passphrase: 'the-owners-passphrase' }), 'passphrase',
      'a torn final line must not cost the owner their vault')
    // And the torn line is not mistaken for someone removing a record.
    assert.equal(reopened.audit.verify().ok, true)
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('a failed unlock leaves nothing half-open', () => {
  // unlockWith set this.vmk and opened the audit log afterwards, so a failure
  // in between left the key installed while the caller was told AV_LOCKED. The
  // vault then reported locked === false, revealField worked, and this.audit
  // was null — open for reading and recording nothing, which is the worst of
  // both states.
  const fresh = mkdtempSync(join(tmpdir(), 'av-halfopen-'))
  try {
    const v = Vault.create(fresh, { factor: 'none' })
    v.addCredential({
      slug: 'x', kind: 'http', connector: { host: 'h' },
      fields: { token: 'a-secret-value-here' }, sites: { token: ['header:authorization:Bearer'] },
    })
    v.setPassphrase('the-owners-passphrase')
    v.lock()

    // The path that matters is the one where the passphrase is RIGHT and
    // something afterwards fails — opening the audit log. A wrong passphrase
    // fails before the key is ever assigned, so it never reached this state.
    // A log that cannot be read at all does. (A corrupt line in the middle
    // used to be the example, and was itself a bug: it locked the owner out
    // for good. The chain reports that now, and the vault still opens.)
    const path = join(fresh, 'audit.jsonl')
    rmSync(path)
    mkdirSync(path)

    const reopened = Vault.open(fresh)
    assert.throws(() => reopened.unlockWith({ passphrase: 'the-owners-passphrase' }),
      /AV_LOCKED/, 'a vault whose log cannot be opened must not report success')
    assert.equal(reopened.locked, true, 'a failed unlock must leave the vault locked')
    assert.equal(reopened.vmk, null, 'a failed unlock must leave no key behind')
    assert.throws(() => reopened.revealField(reopened.findCredential('x').id, 'token'), /AV_LOCKED/)
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('a leftover temp file cannot hand the vault a permissive mode', () => {
  // #persist writes a temp file and renames it over the vault, so vault.json
  // ends up with whatever mode the TEMP file had. writeFileSync's mode option
  // applies at creation only — write into a file that already exists and the
  // mode is ignored — so a temp file left behind by a crash, with a mode
  // somebody else set, became the mode of the vault itself. A world-readable
  // vault.json is every credential in it, to every account on the machine.
  const fresh = mkdtempSync(join(tmpdir(), 'av-mode-'))
  try {
    const v = Vault.create(fresh, { factor: 'none' })
    const tmp = join(fresh, 'vault.json.tmp')
    writeFileSync(tmp, 'left over from a crash', { mode: 0o666 })
    chmodSync(tmp, 0o666)

    // Anything that persists.
    v.addCredential({
      slug: 'x', kind: 'http', connector: { host: 'example.com' },
      fields: { token: 'value-long-enough' }, sites: { token: ['header:authorization:Bearer'] },
    })

    const mode = statSync(join(fresh, 'vault.json')).mode & 0o777
    assert.equal(mode, 0o600, `the vault ended up mode 0${mode.toString(8)}`)
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('the placeholder ledger does not grow without bound', () => {
  // `max_active` caps how many placeholders are ACTIVE by marking the excess
  // dead. Nothing ever removed a row, so the ledger grew forever and every
  // write rewrote all of it: 1400 mints produced 1400 rows and a 744 KiB
  // vault.json, at 13.5ms of blocked event loop per mint. An agent decides how
  // often to mint.
  const fresh = mkdtempSync(join(tmpdir(), 'av-ledger-'))
  try {
    const v = Vault.create(fresh, { factor: 'none' })
    const cred = v.addCredential({
      slug: 'x', kind: 'http', connector: { host: 'h' },
      fields: { token: 'a-secret-value-here' }, sites: { token: ['header:authorization:Bearer'] },
    })
    const s = v.createSession({ label: 'a' })
    const g = v.createGrant({
      sessionId: s.session.id, credentialId: cred.id, fields: ['token'],
      policy: { hosts: ['h'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 100000 } },
    })

    // The bound is what this is about. Timing it as well would make the test
    // fail whenever the machine is busy, which teaches people to ignore it.
    for (let i = 0; i < 900; i++) v.issuePlaceholder({ grantId: g.id, field: 'token' })

    const rows = Object.keys(v.db.placeholders).length
    assert.ok(rows <= 600, `900 mints left ${rows} rows in the ledger`)
    // The file is rewritten on every mint, so a bounded row count is what
    // keeps the cost of one mint from growing with the age of the vault.
    const bytes = statSync(join(fresh, 'vault.json')).size
    assert.ok(bytes < 512 * 1024, `vault.json reached ${(bytes / 1024).toFixed(0)} KiB after 900 mints`)

    // The most recent ones survive, because those are the ones a replay is
    // most likely to be about.
    const live = Object.values(v.db.placeholders).filter((p) => p.state === 'active')
    assert.ok(live.length > 0, 'the active placeholders must not be collected')
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

/**
 * Every method of the Vault class, by name, with its source. A method starts
 * at a two-space-indented header and ends at the first line that is exactly
 * two spaces and a closing brace. A method written on one line (`save(opts) {
 * this.#persist(opts) }`) is its own body: the scan used to skip those, so a
 * one-line writer was on no list and no check read it.
 */
function vaultMethods(src) {
  const methods = new Map()
  const lines = src.split('\n')
  const header = /^  (?:static |async |get |set )*(#?[A-Za-z_$][\w$]*)\s*\(.*\{\s*$/
  const oneLine = /^  (?:static |async |get |set )*(#?[A-Za-z_$][\w$]*)\s*\(.*\)\s*\{.*\}\s*$/
  const keyword = (name) => ['if', 'for', 'while', 'switch', 'catch'].includes(name)
  for (let i = 0; i < lines.length; i++) {
    const single = oneLine.exec(lines[i])
    if (single && !keyword(single[1])) { methods.set(single[1], lines[i]); continue }
    const m = header.exec(lines[i])
    if (!m || keyword(m[1])) continue
    let j = i + 1
    while (j < lines.length && lines[j] !== '  }') j++
    methods.set(m[1], lines.slice(i, j + 1).join('\n'))
    i = j
  }
  return methods
}

// The writes allowed to skip the fsync: ledger churn an agent can simply ask
// for again, a redirect hop's budget charge (F6) and a health observation
// (F10), both coordinator-approved. Nothing that records a security decision.
// `save` is the pipeline's write for its own counters (quota windows, approval
// state), which passes the option through; a one-line method, so the scan only
// sees it since it reads those too.
const NON_DURABLE_ALLOWED = new Set(['issuePlaceholder', 'consumePlaceholder', 'refundPlaceholder', 'chargeGrant', 'recordHealth', 'save'])

// Every other method that writes the vault, each of which must write durably.
// A method that writes and is on neither list fails the test below, so a new
// writer is classified when it is added, not when someone notices.
const DURABLE = new Set([
  // key material and the factors
  'create', '#anchorStamp', '#openWith', 'setPassphrase', '#commitFactors', 'addWebauthnUnlock', 'removeWebauthnUnlock',
  'setPresenceKey', 'prfSalt', 'removePassphrase', 'lock', 'startInRecordedState',
  // credentials and their settings
  'addCredential', 'deleteCredential', 'setCredentialExpiry', 'setQuarantine', 'clearQuarantine', 'updateSettings',
  // sessions, grants and the placeholders a human acts on
  'addWorkspace', 'createSession', 'assertSessionLive', 'shortenSession', 'revokeSession', 'forkSession',
  'createGrant', 'assertGrantLive', 'revokeGrant', 'shortenGrant', 'narrowGrant', 'burnPlaceholder', 'nextPlaceholder',
  'addListener', 'removeListener',
  // slice B: scrub patterns (F4), rotation (F7), the webhook (F14), templates (F17), restore (F8)
  'addScrubPattern', 'removeScrubPattern', 'rotateCredential', 'setNotifyWebhook', 'clearNotifyWebhook',
  'saveTemplate', 'deleteTemplate', 'restoreEntries',
  // F11: pins (integrate-2)
  'setPins', 'clearPins',
])

test('key material and security decisions are written durably, whatever the ledger does', () => {
  // The fsync split is only safe if the half that matters keeps it. A lost
  // placeholder is one the agent asks for again; a lost credential is gone,
  // and a lost revocation, shortening or quarantine is access a human took
  // away coming back after a power cut.
  const src = readFileSync(new URL('../../src/store/vault.js', import.meta.url).pathname, 'utf8')
  const methods = vaultMethods(src)
  assert.ok(methods.size > 40 && methods.has('createSession') && methods.has('consumePlaceholder'),
    `the method scan found ${methods.size} methods; it has stopped reading vault.js`)
  // One-line methods are read too.
  assert.ok(methods.has('save') && methods.has('listCredentials') && methods.get('save').includes('#persist('),
    'the method scan does not see one-line methods')

  // Every non-durable write sits in an allowed method, and only there. Any
  // spelling of the option counts, not just the one this file uses today.
  const nonDurable = /#persist\(\s*\{[^}]*durable[^}]*\}\s*\)/
  let found = 0
  for (const [name, body] of methods) {
    if (!nonDurable.test(body)) continue
    found++
    assert.ok(NON_DURABLE_ALLOWED.has(name), `${name} writes without an fsync; only ${[...NON_DURABLE_ALLOWED].join(', ')} may`)
  }
  assert.ok(found > 0, 'the ledger is expected to skip the fsync; finding none means this scan is broken')
  // And none outside a method, where the scan above would not see it.
  const inMethods = [...methods.values()].reduce((n, body) => n + (body.match(new RegExp(nonDurable, 'g'))?.length ?? 0), 0)
  assert.equal([...src.matchAll(new RegExp(nonDurable, 'g'))].length, inMethods, 'a non-durable write outside any method')

  // The credential and factor paths, and every write that records a security
  // decision, persist durably: they write, and never with the option.
  for (const fn of DURABLE) {
    const body = methods.get(fn)
    assert.ok(body, `${fn} is not in vault.js any more; update this list`)
    // The factor paths write through #commitFactors, which is on this list.
    assert.ok(body.includes('#persist(') || body.includes('#commitFactors('), `${fn} no longer writes through #persist`)
    assert.ok(!/durable/.test(body), `${fn} writes without an fsync`)
  }
})

test('every method that writes the vault is classified as durable or as allowed to skip the fsync', () => {
  // The list above used to name only the methods someone thought of. The
  // slice B writers (rotation, scrub patterns, the webhook, templates) were
  // durable, and on no list, so a `durable: false` planted in one of them was
  // caught only by the general scan. Now every write site is on a list.
  const src = readFileSync(new URL('../../src/store/vault.js', import.meta.url).pathname, 'utf8')
  const methods = vaultMethods(src)
  const writers = [...methods].filter(([name, body]) => name !== '#persist' && /#persist\(|#commitFactors\(/.test(body)).map(([name]) => name)
  assert.ok(writers.length > 40 && writers.includes('rotateCredential') && writers.includes('restoreEntries'),
    `the scan found ${writers.length} writers; it has stopped reading vault.js`)
  const unclassified = writers.filter((n) => !DURABLE.has(n) && !NON_DURABLE_ALLOWED.has(n))
  assert.deepEqual(unclassified, [], `these write the vault and are on no list: ${unclassified.join(', ')}`)
  for (const name of [...DURABLE, ...NON_DURABLE_ALLOWED]) {
    assert.ok(writers.includes(name), `${name} is listed but does not write the vault; update the list`)
    assert.ok(!(DURABLE.has(name) && NON_DURABLE_ALLOWED.has(name)), `${name} is on both lists`)
  }
  // A durable method writes only as `#persist()`: no option, in any spelling.
  for (const name of DURABLE) {
    const body = methods.get(name)
    const calls = body.match(/#persist\(/g)?.length ?? 0
    const plain = body.match(/#persist\(\)/g)?.length ?? 0
    assert.equal(calls, plain, `${name} passes an option to #persist`)
  }
})
