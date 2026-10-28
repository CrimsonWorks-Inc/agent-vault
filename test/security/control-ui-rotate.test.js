// Replacing the confirmation authenticator from the page (deferred from wave 1).
//
// The first enrolment is passphrase-only: an assertion cannot vouch for the
// key that would produce it. A REPLACEMENT is the other way round. The key
// being replaced is the best witness there is, so the new key is registered
// first, its public record is shown to the page, and it is enrolled only with
// the CURRENT key's signature over exactly that record — checked here and then
// by the real daemon, which owns the key.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { operationFor } from '../../src/ui/webauthn.js'
import { startDaemon, startUi, makeAuthenticator, enrol, PASSPHRASE } from './fix-control-helpers.js'

async function setup() {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const u = await startUi(d)
  const current = makeAuthenticator(u.ui.origin)
  enrol(d.vault, current)
  const next = makeAuthenticator(u.ui.origin)
  /** Register `next` through the page's routes; returns its public record. */
  const register = async () => {
    const begin = await (await u.api('POST', 'presence/rotate/begin')).json()
    const res = await u.api('POST', 'presence/rotate/register', next.register(begin.challenge, u.ui.origin))
    assert.equal(res.status, 200)
    return (await res.json()).credential
  }
  return { d, u, current, next, register, stop: async () => { await u.stop(); await d.stop() } }
}

test('the current key can enrol its replacement, and only the replacement works afterwards', async () => {
  const t = await setup()
  try {
    const credential = await t.register()
    assert.equal(credential.credentialId, t.next.record.credentialId)
    assert.ok(!('privateKey' in credential))
    const presence = await t.u.presence(t.current, operationFor('presence.enroll', credential))
    const res = await t.u.api('POST', 'presence/rotate', { ...credential, presence })
    const body = await res.json()
    assert.equal(res.status, 200, JSON.stringify(body))
    assert.equal(body.replaced, true)
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, t.next.record.credentialId, 'the daemon still holds the old key')

    // The new key confirms changes; the old one no longer does.
    const old = await t.u.presence(t.current, { op: 'vault.lock' })
    assert.notEqual((await t.u.api('POST', 'lock', { presence: old })).status, 200)
    const fresh = await t.u.presence(t.next, { op: 'vault.lock' })
    assert.equal((await t.u.api('POST', 'lock', { presence: fresh })).status, 200)
  } finally { await t.stop() }
})

test('a replacement with no signature, or signed by the new key itself, is refused', async () => {
  const t = await setup()
  try {
    const credential = await t.register()
    let res = await t.u.api('POST', 'presence/rotate', { ...credential })
    assert.equal(res.status, 401)
    // The key being enrolled cannot vouch for itself.
    const self = await t.u.presence(t.next, operationFor('presence.enroll', credential))
    res = await t.u.api('POST', 'presence/rotate', { ...credential, presence: self })
    assert.notEqual(res.status, 200)
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, t.current.record.credentialId)
  } finally { await t.stop() }
})

test('the record enrolled is the one registered here, not one the request names', async () => {
  const t = await setup()
  try {
    const credential = await t.register()
    // Some other public key, signed for by the real key: the signature is
    // genuine, the record is not the one this page registered.
    const other = { ...credential, publicKeySpki: makeAuthenticator(t.u.ui.origin).record.publicKeySpki }
    const presence = await t.u.presence(t.current, operationFor('presence.enroll', other))
    const res = await t.u.api('POST', 'presence/rotate', { ...other, presence })
    assert.equal(res.status, 409)
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, t.current.record.credentialId)
  } finally { await t.stop() }
})

test('with nothing registered there is nothing to enrol', async () => {
  const t = await setup()
  try {
    const credential = { ...t.next.record, enrolledAt: new Date().toISOString() }
    const presence = await t.u.presence(t.current, operationFor('presence.enroll', credential))
    const res = await t.u.api('POST', 'presence/rotate', { ...credential, presence })
    assert.equal(res.status, 409)
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, t.current.record.credentialId)
  } finally { await t.stop() }
})

test('a signature for the replacement is refused when it covers a different record', async () => {
  const t = await setup()
  try {
    const credential = await t.register()
    const presence = await t.u.presence(t.current, operationFor('presence.enroll', { ...credential, signCount: 7 }))
    const res = await t.u.api('POST', 'presence/rotate', { ...credential, presence })
    assert.equal(res.status, 409)
    assert.equal(t.d.vault.db.kv.webauthn.credentialId, t.current.record.credentialId)
  } finally { await t.stop() }
})

test('a first enrolment still cannot be made this way', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  const u = await startUi(d)
  try {
    const res = await u.api('POST', 'presence/rotate/begin')
    assert.equal(res.status, 412)
  } finally { await u.stop(); await d.stop() }
})
