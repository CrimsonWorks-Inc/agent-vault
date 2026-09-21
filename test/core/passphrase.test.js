import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync, chmodSync, statSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'

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
  assert.throws(() => v.removePassphrase('wrong'), /current passphrase is required/)
  v.removePassphrase('the-passphrase')
  assert.equal(v.hasPassphrase, false)
  v.lock()
  assert.equal(Vault.open(dir).unlock(null), true)
})

test('a passphrase under 8 characters is refused', () => {
  const v = Vault.create(dir, { factor: 'none' })
  assert.throws(() => v.setPassphrase('short'), /at least 8/)
})

import { randomBytes } from 'node:crypto'

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
  assert.throws(() => v.removePassphrase('recovery-passphrase'), /remove Touch ID unlock first/)
  // Removing Touch ID first, then the passphrase, is allowed.
  v.removeWebauthnUnlock()
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
    // A corrupt line in the MIDDLE of the log does: that is real corruption,
    // not a torn tail, and it is not something to read past.
    const path = join(fresh, 'audit.jsonl')
    const lines = readFileSync(path, 'utf8').trimEnd().split('\n')
    lines[1] = '{"seq":2,"this is not'
    writeFileSync(path, `${lines.join('\n')}\n`)

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

    const started = Date.now()
    for (let i = 0; i < 900; i++) v.issuePlaceholder({ grantId: g.id, field: 'token' })
    const ms = Date.now() - started

    const rows = Object.keys(v.db.placeholders).length
    assert.ok(rows <= 600, `900 mints left ${rows} rows in the ledger`)
    assert.ok(ms < 5000, `900 mints took ${ms}ms, all of it on the event loop`)

    // The most recent ones survive, because those are the ones a replay is
    // most likely to be about.
    const live = Object.values(v.db.placeholders).filter((p) => p.state === 'active')
    assert.ok(live.length > 0, 'the active placeholders must not be collected')
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('key material is still written durably, whatever the ledger does', () => {
  // The fsync split is only safe if the half that matters keeps it. A lost
  // placeholder is one the agent asks for again; a lost credential is gone.
  const src = readFileSync(new URL('../../src/store/vault.js', import.meta.url).pathname, 'utf8')
  const nonDurable = [...src.matchAll(/#persist\(\{ durable: false \}\)/g)].length
  assert.ok(nonDurable > 0 && nonDurable <= 4,
    `${nonDurable} non-durable writes: this should be the placeholder ledger and nothing else`)

  // The credential and factor paths must not be among them.
  for (const fn of ['addCredential', 'setPassphrase', 'removePassphrase', 'addWebauthnUnlock', 'removeWebauthnUnlock']) {
    const body = new RegExp(`${fn}\\\\([^)]*\\\\) \\\\{[\\\\s\\\\S]*?\\\\n  \\\\}`).exec(src)?.[0] || ''
    assert.ok(!body.includes('durable: false'), `${fn} writes key material without an fsync`)
  }
})
