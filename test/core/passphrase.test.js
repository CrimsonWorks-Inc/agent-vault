import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
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
