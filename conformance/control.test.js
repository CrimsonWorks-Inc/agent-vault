import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import {
  binaries, rustSkipReason, openWorld, seed, leaksSecret, SECRET, readStream, pinValue, presenceKey, PASSPHRASE, gateway, freePort,
} from './lib/harness.js'

const skip = rustSkipReason()
if (skip) {
  test('control api', { skip }, () => {})
} else {
  describe('control api', { concurrency: false, timeout: 180_000 }, () => {
    let w
    before(async () => {
      w = await openWorld()
      await seed(w)
    })
    after(async () => { await w?.close() })

    test('GET /v1/status and GET /v1/lockstate', async () => {
      const status = await w.control('GET', '/v1/status')
      assert.equal(status.status, 200)
      assert.equal(typeof status.json.daemon_version, 'string')
      assert.equal(status.json.gateway_port, w.port)
      assert.equal(typeof status.json.credentials, 'number')
      assert.equal(leaksSecret(status.text), null)
      const lock = await w.control('GET', '/v1/lockstate')
      assert.equal(lock.status, 200)
      assert.equal(lock.json.locked, false)
      assert.equal(lock.json.has_passphrase, false)
      assert.equal(lock.json.needs_secret, false)
    })

    test('credentials: success shape and the main refusals', async () => {
      const list = await w.control('GET', '/v1/credentials')
      assert.equal(list.status, 200)
      assert.ok(list.json.some((c) => c.slug === w.slug))
      const pub = list.json.find((c) => c.slug === w.slug)
      assert.equal(pub.kind, 'http')
      assert.ok(pub.fields[0].fp8)
      assert.equal(leaksSecret(list.text), null)

      const badDate = await w.control('POST', '/v1/credentials', {
        slug: 'baddate', kind: 'http', host: '127.0.0.1', value: SECRET, expires_at: 'tomorrow',
      })
      assert.equal(badDate.status, 403)
      assert.equal(badDate.json.code, 'AV_POLICY_DENIED')
      assert.equal(badDate.json.rule, 'expires_at')

      const postgres = await w.control('POST', '/v1/credentials', {
        slug: 'pg', kind: 'postgres', host: '127.0.0.1', value: SECRET,
      })
      assert.equal(postgres.status, 403)
      assert.equal(postgres.json.code, 'AV_POLICY_DENIED')
      assert.equal(postgres.json.rule, 'connector_implemented')

      const extra = await w.control('POST', '/v1/credentials', {
        slug: 'extra', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http', value: SECRET,
      })
      assert.equal(extra.status, 200)
      assert.equal(leaksSecret(extra.text), null)
      const removed = await w.control('DELETE', '/v1/credentials?slug=extra')
      assert.equal(removed.status, 200)
      assert.equal(removed.json.ok, true)
      const missing = await w.control('DELETE', '/v1/credentials?slug=missing-cred')
      assert.equal(missing.status, 404)
      assert.equal(missing.json.code, 'AV_NOT_FOUND')
    })

    test('credential record routes', async () => {
      const rotated = await w.control('POST', '/v1/credentials/rotate', {
        slug: w.slug, value: 'test-secret-conform-rotate-0123456789ab', mode: 'keep',
      })
      assert.equal(rotated.status, 200, rotated.text)
      assert.equal(typeof rotated.json.invalidated_approvals, 'number')
      assert.equal(leaksSecret(rotated.text), null)

      const badHours = await w.control('POST', '/v1/credentials/rotate', {
        slug: w.slug, value: 'test-secret-conform-rotate-fffffffffffffff0', retire_hours: 999,
      })
      assert.equal(badHours.status, 403)
      assert.equal(badHours.json.code, 'AV_POLICY_DENIED')
      assert.equal(badHours.json.rule, 'retire_window')

      const expiry = await w.control('POST', '/v1/credentials/expiry', {
        slug: w.slug, expires_at: '2099-01-01T00:00:00.000Z',
      })
      assert.equal(expiry.status, 200)
      assert.equal(expiry.json.expires_at, '2099-01-01T00:00:00.000Z')
      const cleared = await w.control('POST', '/v1/credentials/expiry', { slug: w.slug, expires_at: null })
      assert.equal(cleared.status, 200)

      const scrub = await w.control('POST', '/v1/credentials/scrub', {
        slug: w.slug, pattern: 'zzz[0-9]{8,16}', sample: 'zzz12345678',
      })
      assert.equal(scrub.status, 200)
      assert.equal(typeof scrub.json.id, 'string')
      assert.equal(scrub.json.sample.matches, 1)
      const badPattern = await w.control('POST', '/v1/credentials/scrub', { slug: w.slug, pattern: '.*' })
      assert.equal(badPattern.status, 403)
      assert.equal(badPattern.json.rule, 'scrub_pattern')
      const unscrub = await w.control('DELETE', `/v1/credentials/scrub?slug=${w.slug}&id=${scrub.json.id}`)
      assert.equal(unscrub.status, 200)
      assert.equal(unscrub.json.ok, true)

      const pin = pinValue()
      const pins = await w.control('POST', '/v1/credentials/pins', { slug: w.slug, host: '127.0.0.1', pins: [pin] })
      assert.equal(pins.status, 200)
      const listed = await w.control('GET', '/v1/credentials')
      const row = listed.json.find((c) => c.slug === w.slug)
      assert.equal(row.pins['127.0.0.1'], 1)
      assert.equal(leaksSecret(listed.text), null)
      const clearedPins = await w.control('DELETE', `/v1/credentials/pins?slug=${w.slug}&host=127.0.0.1&spki=${encodeURIComponent(pin)}`)
      assert.equal(clearedPins.status, 200)
      assert.equal(clearedPins.json.ok, true)

      const badPin = await w.control('POST', '/v1/credentials/pins', { slug: w.slug, host: '127.0.0.1', pins: ['nope'] })
      assert.equal(badPin.status, 403)
      assert.equal(badPin.json.rule, 'pin_format')

      const probe = await w.control('POST', '/v1/credentials/test', { slug: w.slug })
      assert.equal(probe.status, 404)
      assert.equal(probe.json.code, 'AV_NOT_FOUND')
      assert.equal(probe.json.rule, 'no_probe')
      const all = await w.control('POST', '/v1/credentials/test', { all: true })
      assert.equal(all.status, 200)
      assert.ok(all.json.results.some((r) => r.slug === w.slug && r.rule === 'no_probe'))
      const badAll = await w.control('POST', '/v1/credentials/test', { all: false })
      assert.equal(badAll.status, 403)
      assert.equal(badAll.json.code, 'AV_POLICY_DENIED')
      assert.equal(badAll.json.rule, 'policy_invalid')

      const side = await w.control('POST', '/v1/credentials', {
        slug: 'side', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      assert.equal(side.status, 200)
      const held = await w.control('POST', '/v1/sessions', {
        cred: 'side', label: 'held', methods: ['GET'], paths: ['/**'], budget: 8, approval: 'auto', ttl_hours: 1,
      })
      assert.equal(held.status, 200, held.text)
      const before = w.upstream.hits.length
      const live = await gateway(w, '/p/side/user', { token: held.json.token, placeholder: held.json.placeholder })
      assert.equal(live.status, 200, live.text)
      assert.equal(live.json.ordinary, 'ordinary-traffic-control')
      assert.equal(w.upstream.hits.length, before + 1)
      assert.equal(w.upstream.hits.at(-1).seen, SECRET)
      const ask = await w.control('POST', '/v1/session-requests', {
        cred: 'side', reason: 'approve me', methods: ['GET'], paths: ['/user'], budget: 2,
      })
      const bulkAsk = await w.control('POST', '/v1/session-requests', {
        cred: 'side', reason: 'bulk me', methods: ['GET'], paths: ['/user'], budget: 2,
      })
      assert.equal(ask.status, 200, ask.text)
      assert.equal(bulkAsk.status, 200, bulkAsk.text)
      const quarantined = await w.control('POST', '/v1/credentials/quarantine', { slug: 'side', reason: 'drill' })
      assert.equal(quarantined.status, 200)
      assert.equal(quarantined.json.slug, 'side')
      assert.ok(quarantined.json.quarantine)
      const stopped = w.upstream.hits.length
      const refused = await gateway(w, '/p/side/user', { token: held.json.token, placeholder: held.json.placeholder })
      assert.equal(refused.status, 403, refused.text)
      assert.equal(refused.json.code, 'AV_QUARANTINED')
      assert.equal(refused.json.rule, 'quarantine')
      assert.equal(w.upstream.hits.length, stopped)
      assert.equal(leaksSecret(refused.text), null)
      const noSession = await w.control('POST', '/v1/sessions', {
        cred: 'side', label: 'later', methods: ['GET'], paths: ['/**'], budget: 2, ttl_hours: 1,
      })
      assert.equal(noSession.status, 403, noSession.text)
      assert.equal(noSession.json.code, 'AV_QUARANTINED')
      assert.equal(noSession.json.rule, 'quarantine')
      const noBatch = await w.control('POST', '/v1/placeholders/batch', {
        sid: held.json.session_id, purpose: 'env', items: [{ cred: 'side' }],
      })
      assert.equal(noBatch.status, 403, noBatch.text)
      assert.equal(noBatch.json.code, 'AV_QUARANTINED')
      assert.equal(noBatch.json.items, undefined)
      const noAsk = await w.control('POST', '/v1/session-requests', {
        cred: 'side', reason: 'after', methods: ['GET'], paths: ['/user'], budget: 2,
      })
      assert.equal(noAsk.status, 403, noAsk.text)
      assert.equal(noAsk.json.code, 'AV_QUARANTINED')
      const noApprove = await w.control('POST', '/v1/session-requests/decide', { id: ask.json.id, granted: true })
      assert.equal(noApprove.status, 403, noApprove.text)
      assert.equal(noApprove.json.code, 'AV_QUARANTINED')
      const stillPending = await w.control('GET', '/v1/session-requests')
      assert.equal(stillPending.json.find((r) => r.id === ask.json.id).state, 'pending')
      const skipped = await w.control('POST', '/v1/pending/decide-many', {
        decisions: [{ id: bulkAsk.json.id, kind: 'session', granted: true }],
      })
      assert.equal(skipped.status, 200, skipped.text)
      assert.equal(skipped.json.decided[0].outcome, 'skipped')
      assert.match(skipped.json.decided[0].reason, /quarantined/)
      assert.equal((await w.control('GET', '/v1/session-requests')).json.find((r) => r.id === bulkAsk.json.id).state, 'pending')
      const released = await w.control('POST', '/v1/credentials/release', { slug: 'side' })
      assert.equal(released.status, 200)
      assert.equal(released.json.released, true)
      const again = await gateway(w, '/p/side/user', { token: held.json.token, placeholder: held.json.placeholder })
      assert.equal(again.status, 200, again.text)
      assert.equal(again.json.ordinary, 'ordinary-traffic-control')
      assert.equal(leaksSecret(again.text), null)
      assert.equal(w.upstream.hits.at(-1).seen, SECRET)
      await w.control('DELETE', '/v1/credentials?slug=side')
    })

    test('sessions, placeholders, narrowing and detail', async () => {
      const listed = await w.control('GET', '/v1/sessions')
      assert.equal(listed.status, 200)
      const row = listed.json.find((s) => s.id === w.session.session_id)
      assert.equal(row.state, 'active')
      assert.equal(row.grants, 1)
      assert.equal(leaksSecret(listed.text), null)
      assert.equal(listed.text.includes(w.session.token), false)

      const missing = await w.control('POST', '/v1/sessions', { cred: 'no-such', label: 'x' })
      assert.equal(missing.status, 404)
      assert.equal(missing.json.code, 'AV_NOT_FOUND')
      const bare = await w.control('POST', '/v1/sessions', {})
      assert.equal(bare.status, 404)
      assert.equal(bare.json.code, 'AV_NOT_FOUND')
      const shape = await w.control('POST', '/v1/sessions', { cred: w.slug, grants: [{ cred: w.slug }] })
      assert.equal(shape.status, 403)
      assert.equal(shape.json.rule, 'session_shape')
      const zero = await w.control('POST', '/v1/sessions', { cred: w.slug, budget: 0 })
      assert.equal(zero.status, 403)
      assert.equal(zero.json.rule, 'budget')

      const issued = await w.control('POST', '/v1/placeholders', { cred: w.slug, sid: w.session.session_id })
      assert.equal(issued.status, 200)
      assert.match(issued.json.placeholder, /^av1\./)
      assert.ok(issued.json.usage.length)
      const noGrant = await w.control('POST', '/v1/placeholders', { cred: 'missing', sid: w.session.session_id })
      assert.equal(noGrant.status, 404)
      assert.equal(noGrant.json.code, 'AV_NOT_FOUND')

      const batch = await w.control('POST', '/v1/placeholders/batch', {
        sid: w.session.session_id,
        purpose: 'env',
        items: [{ cred: w.slug }],
      })
      assert.equal(batch.status, 200)
      assert.equal(batch.json.items.length, 1)
      assert.match(batch.json.items[0].placeholder, /^av1\./)
      const badBatch = await w.control('POST', '/v1/placeholders/batch', { items: [] })
      assert.equal(badBatch.status, 403)
      assert.equal(badBatch.json.rule, 'batch_shape')

      const narrow = await w.control('POST', '/v1/sessions/narrow', {
        sid: w.session.session_id, narrow: { methods: ['GET'] },
      })
      assert.equal(narrow.status, 200)
      assert.deepEqual(narrow.json.grants[0].after.methods, ['GET'])
      const empty = await w.control('POST', '/v1/sessions/narrow', { sid: w.session.session_id, narrow: {} })
      assert.equal(empty.status, 403)
      assert.equal(empty.json.rule, 'narrow_empty')
      // Put POST back so later gateway-style calls in this file still have it.
      // Narrowing cannot widen, so a second session carries POST.
      const again = await w.control('POST', '/v1/sessions', {
        cred: w.slug, label: 'writes', methods: ['GET', 'POST'], paths: ['/**'], budget: 20, approval: 'on-write', ttl_hours: 1,
      })
      assert.equal(again.status, 200)
      w.writeSession = again.json

      const detail = await w.control('GET', `/v1/sessions/detail?sid=${w.session.session_id}`)
      assert.equal(detail.status, 200)
      assert.equal(detail.json.session.id, w.session.session_id)
      assert.equal(typeof detail.json.grants[0].budget.limit, 'number')
      assert.equal(typeof detail.json.activity, 'object')
      assert.equal(leaksSecret(detail.json.activity), null)
      assert.equal(JSON.stringify(detail.json.activity).includes(w.session.placeholder), false)
      assert.equal(JSON.stringify(detail.json.activity).includes(w.session.token), false)
      assert.equal(leaksSecret(detail.text), null)
      assert.equal(detail.text.includes(w.session.placeholder), false)
      const noSession = await w.control('GET', '/v1/sessions/detail?sid=missing')
      assert.equal(noSession.status, 404)

      const report = await w.control('GET', '/v1/report/access?since=7d')
      assert.equal(report.status, 200)
      assert.ok(Array.isArray(report.json.credentials))
      const badSince = await w.control('GET', '/v1/report/access?since=nope')
      assert.equal(badSince.status, 403)
      assert.equal(badSince.json.rule, 'report_since')
    })

    test('session requests, bulk decisions and approvals', async () => {
      const asked = await w.control('POST', '/v1/session-requests', {
        cred: w.slug, reason: 'conformance check', methods: ['GET'], paths: ['/user'], budget: 5, ttl_minutes: 30,
      })
      assert.equal(asked.status, 200)
      assert.equal(asked.json.state, 'pending')
      assert.equal(typeof asked.json.collect_secret, 'string')
      const owned = await w.control('POST', '/v1/session-requests', { cred: w.slug, reason: 'no', approval: 'auto' })
      assert.equal(owned.status, 403)
      assert.equal(owned.json.rule, 'owner_only_field')

      const pending = await w.control('GET', '/v1/session-requests')
      assert.equal(pending.status, 200)
      assert.ok(pending.json.some((r) => r.id === asked.json.id))
      assert.equal(JSON.stringify(pending.json).includes(asked.json.collect_secret), false)

      const waiting = await w.control('GET', `/v1/session-requests/collect?id=${asked.json.id}&secret=${asked.json.collect_secret}`)
      assert.equal(waiting.status, 200)
      assert.equal(waiting.json.state, 'pending')
      const wrong = await w.control('GET', `/v1/session-requests/collect?id=${asked.json.id}&secret=not-the-secret`)
      assert.equal(wrong.status, 403)
      assert.equal(wrong.json.rule, 'collect_secret')

      const second = await w.control('POST', '/v1/session-requests', {
        cred: w.slug, reason: 'second', methods: ['GET'], paths: ['/user'], budget: 2,
      })
      assert.equal(second.status, 200)
      const badVerdict = await w.control('POST', '/v1/session-requests/decide', { id: asked.json.id, granted: 'yes' })
      assert.equal(badVerdict.status, 403)
      assert.equal(badVerdict.json.rule, 'bulk_decision')
      const denied = await w.control('POST', '/v1/session-requests/decide', { id: second.json.id, granted: false })
      assert.equal(denied.status, 200)
      const approved = await w.control('POST', '/v1/session-requests/decide', { id: asked.json.id, granted: true })
      assert.equal(approved.status, 200)
      assert.equal(approved.json.state, 'approved')
      assert.equal(typeof approved.json.session.session_id, 'string')
      assert.equal(leaksSecret(approved.text), null)

      const third = await w.control('POST', '/v1/session-requests', {
        cred: w.slug, reason: 'bulk', methods: ['GET'], paths: ['/user'], budget: 2,
      })
      const fourth = await w.control('POST', '/v1/session-requests', {
        cred: w.slug, reason: 'bulk-2', methods: ['GET'], paths: ['/user'], budget: 2,
      })
      const bulk = await w.control('POST', '/v1/pending/decide-many', {
        decisions: [
          { id: third.json.id, kind: 'session', granted: false },
          { id: fourth.json.id, kind: 'session', granted: false },
        ],
      })
      assert.equal(bulk.status, 200)
      assert.equal(bulk.json.decided.length, 2)
      const badBulk = await w.control('POST', '/v1/pending/decide-many', { decisions: [] })
      assert.equal(badBulk.status, 403)
      assert.equal(badBulk.json.rule, 'bulk_decision')

      const approvals = await w.control('GET', '/v1/approvals')
      assert.equal(approvals.status, 200)
      assert.ok(Array.isArray(approvals.json))
      const noApproval = await w.control('POST', '/v1/approvals', { id: 'missing-approval', granted: false })
      assert.equal(noApproval.status, 404)
      assert.equal(noApproval.json.code, 'AV_NOT_FOUND')
      const badGrant = await w.control('POST', '/v1/approvals', { id: 'missing-approval', granted: 'no' })
      assert.equal(badGrant.status, 403)
      assert.equal(badGrant.json.rule, 'bulk_decision')
    })

    test('audit, templates, tripwires, listeners, tls, notify, ui, presence', async () => {
      const tail = await w.control('GET', '/v1/audit?limit=20')
      assert.equal(tail.status, 200)
      assert.ok(Array.isArray(tail.json))
      assert.ok(tail.json.length > 0)
      assert.equal(leaksSecret(tail.text), null)
      const verify = await w.control('GET', '/v1/audit/verify')
      assert.equal(verify.status, 200)
      assert.equal(verify.json.ok, true)
      assert.equal(typeof verify.json.count, 'number')
      const exported = await w.control('GET', '/v1/audit/export')
      assert.equal(exported.status, 200)
      assert.ok(Array.isArray(exported.json.rows))
      const badRange = await w.control('GET', '/v1/audit?before=nope')
      assert.equal(badRange.status, 403)
      assert.equal(badRange.json.rule, 'audit_range')
      const checkpoint = await w.control('GET', '/v1/audit/checkpoint')
      assert.equal(checkpoint.status, 200)
      assert.equal(typeof checkpoint.json.head, 'string')
      const witness = await w.control('POST', '/v1/audit/verify-witness', { checkpoints: [checkpoint.json] })
      assert.equal(witness.status, 200)
      assert.equal(witness.json.ok, true)
      const mac = checkpoint.json.mac
      const flipped = `${mac[0] === 'a' ? 'b' : 'a'}${mac.slice(1)}`
      const forged = await w.control('POST', '/v1/audit/verify-witness', {
        checkpoints: [{ ...checkpoint.json, mac: flipped }],
      })
      assert.equal(forged.status, 200, forged.text)
      assert.equal(forged.json.ok, false)
      assert.deepEqual(forged.json.forged, [0])
      const notAList = await w.control('POST', '/v1/audit/verify-witness', { checkpoints: 'all' })
      assert.equal(notAList.status, 403, notAList.text)
      assert.equal(notAList.json.code, 'AV_POLICY_DENIED')
      assert.equal(notAList.json.rule, 'audit_range')
      const clamped = await w.control('GET', '/v1/audit/export?limit=0')
      assert.equal(clamped.status, 200, clamped.text)
      assert.equal(clamped.json.rows.length, 1)
      const unbounded = await w.control('GET', '/v1/audit/export')
      assert.ok(unbounded.json.rows.length > 1, `rows ${unbounded.json.rows.length}`)
      const badLimit = await w.control('GET', '/v1/audit/export?limit=nope')
      assert.equal(badLimit.status, 403, badLimit.text)
      assert.equal(badLimit.json.code, 'AV_POLICY_DENIED')
      assert.equal(badLimit.json.rule, 'audit_range')

      const saved = await w.control('POST', '/v1/templates', {
        name: 'read-user',
        spec: { cred: w.slug, methods: ['GET'], paths: ['/user'], budget: 5, approval: 'on-write' },
      })
      assert.equal(saved.status, 200)
      assert.equal(saved.json.name, 'read-user')
      assert.equal(typeof saved.json.hash, 'string')
      const one = await w.control('GET', '/v1/templates?name=read-user')
      assert.equal(one.status, 200)
      assert.equal(one.json.name, 'read-user')
      const all = await w.control('GET', '/v1/templates')
      assert.equal(all.status, 200)
      assert.ok(all.json.some((t) => t.name === 'read-user'))
      const badSpec = await w.control('POST', '/v1/templates', { name: 'bad', spec: { template: 'read-user' } })
      assert.equal(badSpec.status, 403)
      assert.equal(badSpec.json.rule, 'session_shape')
      const removed = await w.control('DELETE', '/v1/templates?name=read-user')
      assert.equal(removed.status, 200)
      assert.equal(removed.json.ok, true)
      const gone = await w.control('GET', '/v1/templates?name=read-user')
      assert.equal(gone.status, 404)

      const wires = await w.control('GET', '/v1/tripwires')
      assert.equal(wires.status, 200)
      assert.equal(typeof wires.json.enabled, 'boolean')
      assert.ok(Array.isArray(wires.json.rules))
      const on = await w.control('POST', '/v1/tripwires', { enabled: true })
      assert.equal(on.status, 200)
      assert.equal(on.json.enabled, true)
      const off = await w.control('POST', '/v1/tripwires', { enabled: false })
      assert.equal(off.status, 200)
      assert.equal(off.json.enabled, false)
      const junk = await w.control('POST', '/v1/tripwires', { enabled: 'yes' })
      assert.equal(junk.status, 403)
      assert.equal(junk.json.rule, 'tripwire_rule')

      const listeners = await w.control('GET', '/v1/listeners')
      assert.equal(listeners.status, 200)
      assert.ok(Array.isArray(listeners.json))
      const plain = await w.control('POST', '/v1/listeners', {
        id: 'lan', address: '192.0.2.10:443', surfaces: ['gateway'],
      })
      assert.equal(plain.status, 403)
      assert.equal(plain.json.code, 'AV_REMOTE_FORBIDDEN')
      const badAddr = await w.control('POST', '/v1/listeners', { id: 'bad', address: 'not-an-address' })
      assert.equal(badAddr.status, 404)
      assert.equal(badAddr.json.rule, 'listener_address')
      const loopPort = await freePort()
      const added = await w.control('POST', '/v1/listeners', {
        id: 'loop', address: `127.0.0.1:${loopPort}`, surfaces: ['gateway'],
      })
      assert.equal(added.status, 200)
      assert.equal(added.json.id, 'loop')
      const unbound = await w.control('DELETE', '/v1/listeners?id=loop')
      assert.equal(unbound.status, 200)
      assert.equal(unbound.json.ok, true)

      const tls0 = await w.control('GET', '/v1/tls')
      assert.equal(tls0.status, 200)
      assert.equal(tls0.json.configured, false)
      const tls = await w.control('POST', '/v1/tls/ensure', {})
      assert.equal(tls.status, 200)
      assert.equal(typeof tls.json.fingerprint, 'string')
      assert.match(tls.json.certificate, /BEGIN CERTIFICATE/)
      assert.equal(leaksSecret(tls.text), null)
      const tls1 = await w.control('GET', '/v1/tls')
      assert.equal(tls1.status, 200)
      assert.equal(tls1.json.configured, true)

      const notify0 = await w.control('GET', '/v1/notify')
      assert.equal(notify0.status, 200)
      assert.equal(notify0.json.webhook, null)
      for (const webhook_url of [
        'http://user:pass@127.0.0.1/hook',
        'http://example.test/hook',
        'not a url',
      ]) {
        const refused = await w.control('POST', '/v1/notify', { webhook_url })
        assert.equal(refused.status, 403, `${webhook_url} ${refused.text}`)
        assert.equal(refused.json.code, 'AV_POLICY_DENIED')
        assert.equal(refused.json.rule, 'webhook_url')
        assert.equal(w.upstream.hits.some((h) => h.url.startsWith('/hook')), false)
      }
      const hook = await w.control('POST', '/v1/notify', {
        webhook_url: `http://127.0.0.1:${w.upstream.port}/hook`, detail: 'minimal',
      })
      assert.equal(hook.status, 200)
      assert.equal(hook.json.webhook.host, `127.0.0.1:${w.upstream.port}`)
      assert.equal(hook.text.includes('/hook'), false)
      const marked = w.upstream.hits.length
      const tested = await w.control('POST', '/v1/notify/test', {})
      assert.equal(tested.status, 200)
      assert.equal(tested.json.sent, true)
      const delivered = w.upstream.hits.slice(marked).filter((h) => h.method === 'POST' && h.url.startsWith('/hook'))
      assert.equal(delivered.length, 1)
      assert.equal(leaksSecret(delivered[0].body), null)
      assert.equal(delivered[0].body.includes('/hook'), false)
      assert.equal(delivered[0].body.includes(String(w.upstream.port)), false)
      assert.match(delivered[0].body, /"source":"agent-vault"/)
      const cleared = await w.control('DELETE', '/v1/notify')
      assert.equal(cleared.status, 200)
      assert.equal(cleared.json.removed, true)
      const noHook = await w.control('POST', '/v1/notify/test', {})
      assert.equal(noHook.status, 404)
      assert.equal(noHook.json.code, 'AV_NOT_FOUND')

      const ui = await w.control('GET', '/v1/ui')
      assert.equal(ui.status, 200)
      assert.equal(typeof ui.json.port, 'number')
      assert.ok(ui.json.origins.some((o) => o.startsWith('http://localhost:')))
      const badOrigin = await w.control('POST', '/v1/ui/origins', { origin: 'https://evil.test' })
      assert.equal(badOrigin.status, 403)
      assert.equal(badOrigin.json.rule, 'ui_origin')
      const freshOrigin = await w.control('POST', '/v1/ui/origins', { origin: 'http://localhost:9' })
      assert.equal(freshOrigin.status, 401)
      assert.equal(freshOrigin.json.code, 'AV_PRESENCE_REQUIRED')
      assert.equal(freshOrigin.json.rule, 'factor_required')

      const presence = await w.control('GET', '/v1/presence')
      assert.equal(presence.status, 200)
      assert.equal(presence.json, null)
      const counter = await w.control('PATCH', '/v1/presence', { signCount: 10 })
      assert.equal(counter.status, 403)
      assert.equal(counter.json.rule, 'counter_not_settable')
      const early = await w.control('POST', '/v1/presence', presenceKey())
      assert.equal(early.status, 403)
      assert.equal(early.json.rule, 'factor_order')
      const challenge = await w.control('POST', '/v1/presence/challenge', { operation: { op: 'cred.add' } })
      assert.equal(challenge.status, 401)
      assert.equal(challenge.json.code, 'AV_PRESENCE_REQUIRED')
      const enrollParams = await w.control('GET', '/v1/factors/webauthn-enroll-params')
      assert.equal(enrollParams.status, 200)
      assert.equal(enrollParams.json.has_passphrase, false)
      assert.equal(typeof enrollParams.json.prf_salt, 'string')
      const noTouch = await w.control('GET', '/v1/unlock/webauthn-params')
      assert.equal(noTouch.status, 404)
      const touch = await w.control('POST', '/v1/factors/webauthn', {
        action: 'enroll', credential_id: 'abc', prf_secret: randomBytes(32).toString('base64'),
      })
      assert.equal(touch.status, 403)
      assert.equal(touch.json.rule, 'factor_order')

      const window = await w.control('POST', '/v1/presence/window', {})
      assert.equal(window.status, 200)
      assert.equal(window.json.ungated, true)
      assert.equal(window.json.granted, false)

      const stream = await readStream(w.socketPath)
      assert.equal(stream.status, 200)
      assert.match(stream.headers['content-type'], /text\/event-stream/)
      assert.match(stream.text, /event: snapshot/)
      assert.equal(leaksSecret(stream.text), null)

      const backup = await w.control('POST', '/v1/backup/export', { recovery_passphrase: 'recovery-phrase-ok' })
      assert.equal(backup.status, 401)
      assert.equal(backup.json.rule, 'factor_required')
    })

    test('malformed JSON and an unknown route do not take the daemon down', async () => {
      const bad = await rawControl(w.socketPath, 'POST', '/v1/status', '{')
      assert.equal(bad.status, 400)
      assert.equal(bad.json.code, 'AV_MCP_PROTOCOL')
      const missing = await w.control('GET', '/v1/no-such-route')
      assert.equal(missing.status, 404)
      assert.equal(missing.json.code, 'AV_NOT_FOUND')
      assert.match(missing.json.detail, /no control route/)
      const still = await w.control('GET', '/v1/status')
      assert.equal(still.status, 200)
    })

    test('an elevated session is refused when no human factor is enrolled', async () => {
      const elevated = await w.control('POST', '/v1/sessions', {
        cred: w.slug, methods: ['POST'], paths: ['/**'], approval: 'auto', budget: 2, ttl_hours: 1,
      })
      assert.equal(elevated.status, 401, elevated.text)
      assert.equal(elevated.json.code, 'AV_PRESENCE_REQUIRED')
      assert.equal(elevated.json.rule, 'factor_required')
      const infinite = await w.control('POST', '/v1/sessions', {
        cred: w.slug, methods: ['GET'], paths: ['/**'], infinite: true,
      })
      assert.equal(infinite.status, 401, infinite.text)
      assert.equal(infinite.json.code, 'AV_PRESENCE_REQUIRED')
      assert.equal(infinite.json.rule, 'factor_required')
      const listed = await w.control('GET', '/v1/sessions')
      assert.equal(listed.json.some((s) => s.infinite === true), false)
    })

    test('a retire window scrubs the old value, and revoke mode stops the grant', async () => {
      // Its own vault: the shared one has already retired the fixture secret,
      // and the scrubber matches every retired value, not only this credential's.
      const own = await openWorld()
      try {
        const add = (slug) => own.control('POST', '/v1/credentials', {
          slug, kind: 'http', host: `127.0.0.1:${own.upstream.port}`, scheme: 'http',
          value: SECRET, sites: ['header:authorization:Bearer'],
        })
        const sessionFor = (slug, label) => own.control('POST', '/v1/sessions', {
          cred: slug, label, methods: ['GET'], paths: ['/**'], budget: 5, approval: 'auto', ttl_hours: 1,
        })
        assert.equal((await add('dropwin')).status, 200)
        const drop = await sessionFor('dropwin', 'drop')
        assert.equal(drop.status, 200, drop.text)
        const dropped = await own.control('POST', '/v1/credentials/rotate', {
          slug: 'dropwin', value: 'test-secret-conform-drop-0123456789abcd', retire_hours: 0,
        })
        assert.equal(dropped.status, 200, dropped.text)
        const visible = await gateway(own, '/p/dropwin/reflect', { token: drop.json.token, placeholder: drop.json.placeholder })
        assert.equal(visible.status, 200, visible.text)
        assert.equal(visible.json.ordinary, 'ordinary-traffic-control')
        assert.notEqual(leaksSecret(visible.text), null)
        assert.equal(own.upstream.hits.at(-1).seen, 'test-secret-conform-drop-0123456789abcd')
        assert.equal(visible.text.includes('test-secret-conform-drop-0123456789abcd'), false)

        assert.equal((await add('keepwin')).status, 200)
        const keep = await sessionFor('keepwin', 'keep')
        assert.equal(keep.status, 200, keep.text)
        const kept = await own.control('POST', '/v1/credentials/rotate', {
          slug: 'keepwin', value: 'test-secret-conform-kept-0123456789abcd', retire_hours: 1,
        })
        assert.equal(kept.status, 200, kept.text)
        const hidden = await gateway(own, '/p/keepwin/reflect', { token: keep.json.token, placeholder: keep.json.placeholder })
        assert.equal(hidden.status, 200, hidden.text)
        assert.equal(hidden.json.ordinary, 'ordinary-traffic-control')
        assert.equal(leaksSecret(hidden.text), null)
        assert.equal(hidden.text.includes('test-secret-conform-kept-0123456789abcd'), false)
        assert.equal(own.upstream.hits.at(-1).seen, 'test-secret-conform-kept-0123456789abcd')
        const same = await own.control('POST', '/v1/credentials/rotate', {
          slug: 'keepwin', value: 'test-secret-conform-kept-0123456789abcd',
        })
        assert.equal(same.status, 403, same.text)
        assert.equal(same.json.code, 'AV_POLICY_DENIED')
        assert.equal(same.json.rule, 'rotate_same_value')

        assert.equal((await add('revoked')).status, 200)
        const doomed = await sessionFor('revoked', 'revoke')
        assert.equal(doomed.status, 200, doomed.text)
        const once = await gateway(own, '/p/revoked/user', { token: doomed.json.token, placeholder: doomed.json.placeholder })
        assert.equal(once.status, 200, once.text)
        const hits = own.upstream.hits.length
        const revoked = await own.control('POST', '/v1/credentials/rotate', {
          slug: 'revoked', value: 'test-secret-conform-revoke-0123456789ab', mode: 'revoke', retire_hours: 0,
        })
        assert.equal(revoked.status, 200, revoked.text)
        const stopped = await gateway(own, '/p/revoked/user', { token: doomed.json.token, placeholder: doomed.json.placeholder })
        assert.equal(stopped.status, 403, stopped.text)
        assert.equal(stopped.json.code, 'AV_NO_GRANT')
        assert.equal(own.upstream.hits.length, hits)
        assert.equal(leaksSecret(stopped.text), null)
      } finally {
        await own.close()
      }
    })

    test('quarantine and a pending request survive a restart', async () => {
      const added = await w.control('POST', '/v1/credentials', {
        slug: 'sticky', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      assert.equal(added.status, 200, added.text)
      const session = await w.control('POST', '/v1/sessions', {
        cred: 'sticky', methods: ['GET'], paths: ['/**'], budget: 5, approval: 'auto', ttl_hours: 1,
      })
      assert.equal(session.status, 200, session.text)
      const asked = await w.control('POST', '/v1/session-requests', {
        cred: 'sticky', reason: 'survive', methods: ['GET'], paths: ['/user'], budget: 2,
      })
      assert.equal(asked.status, 200, asked.text)
      const quarantined = await w.control('POST', '/v1/credentials/quarantine', { slug: 'sticky', reason: 'restart' })
      assert.equal(quarantined.status, 200, quarantined.text)
      await w.restart()
      const pending = await w.control('GET', '/v1/session-requests')
      assert.equal(pending.status, 200, pending.text)
      assert.equal(pending.json.find((r) => r.id === asked.json.id)?.state, 'pending')
      const creds = await w.control('GET', '/v1/credentials')
      assert.ok(creds.json.find((c) => c.slug === 'sticky')?.quarantine)
      const before = w.upstream.hits.length
      const refused = await gateway(w, '/p/sticky/user', { token: session.json.token, placeholder: session.json.placeholder })
      assert.equal(refused.status, 403, refused.text)
      assert.equal(refused.json.code, 'AV_QUARANTINED')
      assert.equal(refused.json.rule, 'quarantine')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(refused.text), null)
    })

    test('revoking a session removes it', async () => {
      const created = await w.control('POST', '/v1/sessions', {
        cred: w.slug, label: 'doomed', methods: ['GET'], paths: ['/**'], budget: 2, ttl_hours: 1,
      })
      assert.equal(created.status, 200)
      const gone = await w.control('DELETE', `/v1/sessions?sid=${created.json.session_id}`)
      assert.equal(gone.status, 200)
      assert.equal(gone.json.ok, true)
      const listed = await w.control('GET', '/v1/sessions')
      const row = listed.json.find((s) => s.id === created.json.session_id)
      assert.notEqual(row?.state, 'active')
    })
  })

  describe('control api with a passphrase', { concurrency: false, timeout: 120_000 }, () => {
    let w
    before(async () => {
      w = await openWorld()
      await seed(w, { slug: 'gated' })
    })
    after(async () => { await w?.close() })

    test('a first passphrase is open, and later widening is refused without it', async () => {
      const set = await w.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
      assert.equal(set.status, 200)
      assert.equal(set.json.has_passphrase, true)
      const refused = await w.control('POST', '/v1/credentials', {
        slug: 'later', kind: 'http', host: '127.0.0.1', scheme: 'http', value: SECRET,
      })
      assert.equal(refused.status, 401)
      assert.equal(refused.json.code, 'AV_PRESENCE_REQUIRED')
      assert.equal(refused.json.rule, 'human_presence')
      assert.ok(refused.json.factors.includes('passphrase'))
      const wrong = await w.control('POST', '/v1/presence/window', { passphrase: 'not-the-phrase' })
      assert.equal(wrong.status, 403)
      assert.equal(wrong.json.code, 'AV_PRESENCE_DENIED')
      const opened = await w.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
      assert.equal(opened.status, 200)
      assert.equal(opened.json.granted, true)
      const added = await w.control('POST', '/v1/credentials', {
        slug: 'later', kind: 'http', host: '127.0.0.1', scheme: 'http', value: SECRET,
      })
      assert.equal(added.status, 200)
      assert.equal(leaksSecret(added.text), null)
    })

    test('presence enrollment and a touch-id wrap round-trip under a fresh passphrase', async () => {
      const key = presenceKey()
      const enrolled = await w.control('POST', '/v1/presence', { ...key, presence: { passphrase: PASSPHRASE } })
      assert.equal(enrolled.status, 200)
      assert.equal(enrolled.json.ok, true)
      assert.equal(enrolled.json.replaced, false)
      const stored = await w.control('GET', '/v1/presence')
      assert.equal(stored.json.credentialId, key.credentialId)
      const prf = randomBytes(32).toString('base64')
      const touch = await w.control('POST', '/v1/factors/webauthn', {
        credential_id: key.credentialId, prf_secret: prf, presence: { passphrase: PASSPHRASE },
      })
      assert.equal(touch.status, 200)
      assert.equal(touch.json.enrolled, true)
      const params = await w.control('GET', '/v1/unlock/webauthn-params')
      assert.equal(params.status, 200)
      assert.equal(params.json.credential_id, key.credentialId)
      const removed = await w.control('POST', '/v1/factors/webauthn', {
        action: 'remove', presence: { passphrase: PASSPHRASE },
      })
      assert.equal(removed.status, 200)
      assert.equal(removed.json.removed, true)
    })
  })
}

function rawControl(socketPath, method, path, body) {
  return import('node:http').then(({ request }) => new Promise((resolve, reject) => {
    const payload = Buffer.from(body)
    const req = request({
      socketPath, path, method,
      headers: { 'content-type': 'application/json', 'content-length': payload.length },
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        resolve({ status: res.statusCode, json: JSON.parse(text), text })
      })
    })
    req.on('error', reject)
    req.end(payload)
  }))
}

void binaries
