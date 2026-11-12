// Lock, throttle, revocation, panic, audit, and backup. Each world is its own.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  rustSkipReason, openWorld, seed, gateway, leaksSecret, PASSPHRASE, RECOVERY, SECRET, runCli,
} from './lib/harness.js'

const skip = rustSkipReason()
if (skip) {
  test('lifecycle', { skip }, () => {})
} else {
  describe('lifecycle', { concurrency: false, timeout: 180_000 }, () => {
    test('lock, unlock, revocation, panic, and audit', async () => {
      const w = await openWorld()
      try {
        await seed(w, { approval: 'auto', methods: ['GET'] })
        const ok = await gateway(w, `/p/${w.slug}/user`, { token: w.session.token, placeholder: w.session.placeholder })
        assert.equal(ok.status, 200)
        assert.equal(leaksSecret(ok.text), null)

        const verified = await w.control('GET', '/v1/audit/verify')
        assert.equal(verified.status, 200)
        assert.equal(verified.json.ok, true)
        assert.ok(verified.json.count > 0)
        const exported = await w.control('GET', '/v1/audit/export')
        assert.equal(exported.status, 200)
        assert.ok(Array.isArray(exported.json.rows))
        assert.equal(leaksSecret(exported.text), null)

        const revoked = await w.control('DELETE', `/v1/sessions?sid=${w.session.session_id}`)
        assert.equal(revoked.json.ok, true)
        const hitsAtRevoke = w.upstream.hits.length
        const afterRevoke = await gateway(w, `/p/${w.slug}/user`, { token: w.session.token, placeholder: w.session.placeholder })
        assert.equal(afterRevoke.status, 401, afterRevoke.text)
        assert.equal(afterRevoke.json.code, 'AV_SESSION_REVOKED')
        assert.equal(w.upstream.hits.length, hitsAtRevoke)

        const another = await w.control('POST', '/v1/sessions', {
          cred: w.slug, label: 'panic', methods: ['GET'], paths: ['/**'], budget: 5, approval: 'on-write', ttl_hours: 1,
        })
        assert.equal(another.status, 200, another.text)
        const panic = await w.control('POST', '/v1/panic', { reason: 'conformance drill' })
        assert.equal(panic.status, 200, panic.text)
        assert.equal(typeof panic.json.revoked_sessions, 'number')
        assert.ok(panic.json.revoked_sessions >= 1)
        const hitsAtPanic = w.upstream.hits.length
        const afterPanic = await gateway(w, `/p/${w.slug}/user`, { token: another.json.token, placeholder: another.json.placeholder })
        assert.equal(afterPanic.status, 401, afterPanic.text)
        assert.equal(afterPanic.json.code, 'AV_SESSION_REVOKED')
        assert.equal(w.upstream.hits.length, hitsAtPanic)

        const live = await w.control('POST', '/v1/sessions', {
          cred: w.slug, label: 'lock', methods: ['GET'], paths: ['/**'], budget: 5, approval: 'on-write', ttl_hours: 1,
        })
        assert.equal(live.status, 200, live.text)
        const locked = await w.control('POST', '/v1/lock', {})
        assert.equal(locked.json.locked, true)
        const gated = await gateway(w, `/p/${w.slug}/user`, { token: live.json.token, placeholder: live.json.placeholder })
        assert.equal(gated.status, 423)
        assert.equal(gated.json.code, 'AV_LOCKED')
        const audit = await w.control('GET', '/v1/audit')
        assert.equal(audit.status, 423)
        assert.equal(audit.json.code, 'AV_LOCKED')
        const verify = await w.control('GET', '/v1/audit/verify')
        assert.equal(verify.status, 423)
        assert.equal(verify.json.code, 'AV_LOCKED')
        const status = await w.control('GET', '/v1/status')
        assert.equal(status.status, 200)
        assert.equal(status.json.locked, true)
        assert.equal(status.json.audit_records, null)

        const unlocked = await w.control('POST', '/v1/unlock', {})
        assert.equal(unlocked.status, 200, unlocked.text)
        assert.equal(unlocked.json.locked, false)
        const state = await w.control('GET', '/v1/lockstate')
        assert.equal(state.json.locked, false)
      } finally {
        await w.close()
      }
    })

    test('five wrong passphrases are answered, and the next one waits', async () => {
      const w = await openWorld()
      try {
        const set = await w.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
        assert.equal(set.status, 200, set.text)
        assert.equal(set.json.has_passphrase, true)
        const locked = await w.control('POST', '/v1/lock', {})
        assert.equal(locked.json.locked, true)
        for (let i = 0; i < 5; i++) {
          const guess = await w.control('POST', '/v1/unlock', { passphrase: `wrong-guess-${i}` })
          assert.equal(guess.status, 423, guess.text)
          assert.equal(guess.json.code, 'AV_LOCKED')
        }
        const limited = await w.control('POST', '/v1/unlock', { passphrase: 'wrong-guess-again' })
        assert.equal(limited.status, 429, limited.text)
        assert.equal(limited.json.code, 'AV_RATE_LIMITED')
        assert.equal(limited.json.rule, 'passphrase_throttle')
        assert.equal(leaksSecret(limited.text), null)
      } finally {
        await w.close()
      }
    })

    test('backup export, inspect, and restore round trip', async () => {
      const w = await openWorld()
      try {
        await seed(w, { approval: 'auto', methods: ['GET'] })
        const set = await w.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
        assert.equal(set.status, 200, set.text)
        const quarantined = await w.control('POST', '/v1/credentials/quarantine', { slug: w.slug, reason: 'backup' })
        assert.equal(quarantined.status, 200, quarantined.text)
        const exported = await w.control('POST', '/v1/backup/export', {
          recovery_passphrase: RECOVERY,
          presence: { passphrase: PASSPHRASE },
        })
        assert.equal(exported.status, 200, exported.text)
        assert.equal(exported.json.summary.credentials >= 1, true)
        assert.equal(typeof exported.json.bundle_sha256, 'string')
        assert.equal(exported.json.bundle.format, 'agent-vault-backup')
        assert.equal(leaksSecret(exported.text), null)

        const seen = await w.control('POST', '/v1/backup/inspect', {
          bundle: exported.json.bundle, recovery_passphrase: RECOVERY,
        })
        assert.equal(seen.status, 200, seen.text)
        assert.equal(seen.json.credentials[0].slug, w.slug)
        assert.equal(seen.json.credentials[0].kind, 'http')
        assert.ok(seen.json.credentials[0].fields.includes('token'))
        assert.equal(leaksSecret(seen.text), null)

        const wrong = await w.control('POST', '/v1/backup/inspect', {
          bundle: exported.json.bundle, recovery_passphrase: 'not-the-recovery',
        })
        assert.equal(wrong.status, 403)
        assert.equal(wrong.json.code, 'AV_PRESENCE_DENIED')
        assert.equal(wrong.json.rule, 'backup_auth')

        const window = await w.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
        assert.equal(window.json.granted, true)
        const removed = await w.control('DELETE', `/v1/credentials?slug=${w.slug}`)
        assert.equal(removed.status, 200, removed.text)
        const restored = await w.control('POST', '/v1/backup/restore', {
          bundle: exported.json.bundle, recovery_passphrase: RECOVERY, on_conflict: 'skip',
        })
        assert.equal(restored.status, 200, restored.text)
        assert.ok(restored.json.restored.includes(w.slug), restored.text)
        const still = await w.control('POST', '/v1/sessions', {
          cred: w.slug, label: 'still-quarantined', methods: ['GET'], paths: ['/**'], budget: 2, ttl_hours: 1,
        })
        assert.equal(still.status, 403, still.text)
        assert.equal(still.json.code, 'AV_QUARANTINED')
        assert.equal(still.json.rule, 'quarantine')
        const reopen = await w.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
        assert.equal(reopen.json.granted, true)
        const released = await w.control('POST', '/v1/credentials/release', { slug: w.slug })
        assert.equal(released.status, 200, released.text)
        assert.equal(released.json.released, true)

        const list = await w.control('GET', '/v1/credentials')
        assert.ok(list.json.some((c) => c.slug === w.slug))
        assert.equal(leaksSecret(list.text), null)
        const session = await w.control('POST', '/v1/sessions', {
          cred: w.slug, label: 'restored', methods: ['GET'], paths: ['/**'], budget: 5, approval: 'on-write', ttl_hours: 1,
        })
        assert.equal(session.status, 200, session.text)
        const res = await gateway(w, `/p/${w.slug}/user`, { token: session.json.token, placeholder: session.json.placeholder })
        assert.equal(res.status, 200, res.text)
        assert.equal(leaksSecret(res.text), null)
        assert.equal(w.upstream.hits.at(-1).seen, SECRET)
        const chain = await w.control('GET', '/v1/audit/verify')
        assert.equal(chain.json.ok, true)
        assert.equal(leaksSecret(chain.text), null)
      } finally {
        await w.close()
      }
    })

    test('an elevated session needs the passphrase itself, and the audit records why', async () => {
      const w = await openWorld()
      try {
        await seed(w)
        const set = await w.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
        assert.equal(set.status, 200, set.text)
        const bare = await w.control('POST', '/v1/sessions', {
          cred: w.slug, methods: ['POST'], paths: ['/**'], approval: 'auto', budget: 3, ttl_hours: 1,
        })
        assert.equal(bare.status, 401, bare.text)
        assert.equal(bare.json.code, 'AV_PRESENCE_REQUIRED')
        assert.equal(bare.json.rule, 'fresh_presence')
        const window = await w.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
        assert.equal(window.json.granted, true)
        const riding = await w.control('POST', '/v1/sessions', {
          cred: w.slug, methods: ['POST'], paths: ['/**'], approval: 'auto', budget: 3, ttl_hours: 1,
        })
        assert.equal(riding.status, 401, riding.text)
        assert.equal(riding.json.code, 'AV_PRESENCE_REQUIRED')
        assert.equal(riding.json.rule, 'fresh_presence')
        const ordinary = await w.control('POST', '/v1/sessions', {
          cred: w.slug, label: 'ordinary', methods: ['GET'], paths: ['/**'], budget: 3, ttl_hours: 1,
        })
        assert.equal(ordinary.status, 200, ordinary.text)
        const made = await w.control('POST', '/v1/sessions', {
          cred: w.slug, methods: ['POST'], paths: ['/**'], approval: 'auto', budget: 3, ttl_hours: 1,
          presence: { passphrase: PASSPHRASE },
        })
        assert.equal(made.status, 200, made.text)
        const infinite = await w.control('POST', '/v1/sessions', {
          cred: w.slug, methods: ['GET'], paths: ['/**'], infinite: true,
          presence: { passphrase: PASSPHRASE },
        })
        assert.equal(infinite.status, 200, infinite.text)
        const audit = await w.control('GET', '/v1/audit?limit=200')
        assert.equal(audit.status, 200, audit.text)
        const created = audit.json.filter((r) => r.kind === 'session.created')
        assert.ok(created.some((r) => Array.isArray(r.elevated) && r.elevated.includes('approval_auto_writes')))
        assert.ok(created.some((r) => Array.isArray(r.elevated) && r.elevated.includes('infinite')))
        assert.equal(leaksSecret(audit.text), null)
      } finally {
        await w.close()
      }
    })

    test('passphrase set and remove print text, and lock and unlock use the envelope', async () => {
      const w = await openWorld()
      try {
        const set = await runCli(w, ['passphrase', 'set', '--json'], { input: `${PASSPHRASE}\n${PASSPHRASE}\n` })
        assert.equal(set.code, 0, set.stderr + set.stdout)
        assert.equal(set.json, null)
        assert.match(set.stdout, /passphrase set/)
        assert.equal(leaksSecret(set.stdout + set.stderr), null)

        const locked = await runCli(w, ['lock', '--json'])
        assert.equal(locked.code, 0, locked.stdout)
        assert.equal(locked.json.ok, true)
        assert.equal(locked.json.data.locked, true)

        const unlocked = await runCli(w, ['unlock', '--json'], { input: `${PASSPHRASE}\n` })
        assert.equal(unlocked.code, 0, unlocked.stderr + unlocked.stdout)
        assert.equal(unlocked.json.ok, true)
        assert.equal(unlocked.json.data.locked, false)

        const removed = await runCli(w, ['passphrase', 'remove', '--json'], { input: `${PASSPHRASE}\n` })
        assert.equal(removed.code, 6, removed.stderr + removed.stdout)
        assert.equal(removed.json.ok, false)
        assert.match(removed.json.error.message, /last human factor/)
      } finally {
        await w.close()
      }
    })
  })
}
