// F14, store side: the approval-notification webhook. Its URL is a bearer
// credential, so it is sealed at rest and only its host is ever shown or
// audited.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Vault } from '../../src/store/vault.js'
import { fresh, code, records, onDisk, auditText, refusedCleanly } from './store-helpers.js'

const URL_SECRET = 'https://hooks.example/services/T000/B000/XXXXSECRETPATHXXXX?token=QUERYSECRET'

test('a webhook is sealed at rest, and only its host is shown or audited', () => {
  const v = fresh()
  try {
    const view = v.vault.setNotifyWebhook({ url: URL_SECRET })
    assert.deepEqual(Object.keys(view).sort(), ['configured_at', 'detail', 'host'])
    assert.equal(view.host, 'hooks.example')
    assert.equal(view.detail, 'minimal')
    assert.deepEqual(v.vault.notifyConfig(), view)
    assert.deepEqual(v.vault.getNotifyWebhook(), { url: URL_SECRET, host: 'hooks.example', detail: 'minimal' })

    for (const where of [JSON.stringify(onDisk(v)), auditText(v), JSON.stringify(v.vault.notifyConfig())]) {
      for (const part of ['XXXXSECRETPATHXXXX', 'QUERYSECRET', '/services/']) assert.ok(!where.includes(part), `${part} leaked`)
    }
    assert.deepEqual(records(v, 'notify.configured').map((r) => [r.host, r.detail]), [['hooks.example', 'minimal']])

    // It opens again after a restart, under the same key.
    const again = Vault.open(v.dir)
    again.unlock()
    assert.equal(again.getNotifyWebhook().url, URL_SECRET)
    assert.equal(again.notifyConfig().host, 'hooks.example')
  } finally { v.done() }
})

test('loopback http and the headline detail are accepted', () => {
  const v = fresh()
  try {
    for (const url of ['http://127.0.0.1:9000/hook', 'http://localhost/hook', 'http://[::1]:8080/x', 'https://hooks.example:8443/a']) {
      assert.equal(v.vault.setNotifyWebhook({ url, detail: 'headline' }).detail, 'headline', url)
    }
  } finally { v.done() }
})

test('a webhook that is not https, has userinfo or is not a URL is refused, and nothing is kept', () => {
  const v = fresh()
  try {
    v.vault.setNotifyWebhook({ url: 'https://hooks.example/keep' })
    for (const url of [
      'http://example.com/hook', 'http://127.0.0.1.evil.example/hook', 'ftp://hooks.example/x', 'javascript:alert(1)',
      'not a url', '', 'https://user:pw@hooks.example/x', 'https://user@hooks.example/x',
      `https://hooks.example/${'a'.repeat(2048)}`, 42, null, undefined,
    ]) {
      refusedCleanly(v, () => v.vault.setNotifyWebhook({ url }), { code: 'AV_POLICY_DENIED', rule: 'webhook_url' })
    }
    refusedCleanly(v, () => v.vault.setNotifyWebhook({ url: 'https://hooks.example/x', detail: 'everything' }), { code: 'AV_POLICY_DENIED', rule: 'policy_invalid' })
    assert.equal(v.vault.getNotifyWebhook().url, 'https://hooks.example/keep')
  } finally { v.done() }
})

test('the sealed URL is bound to what it is: a credential\'s ciphertext does not open as one', () => {
  const v = fresh()
  try {
    v.vault.setNotifyWebhook({ url: URL_SECRET })
    const field = v.vault.db.credentials[v.cred.id].fields[0]
    v.vault.db.kv.notify.sealed = { ct: field.ct, nonce: field.nonce }
    assert.throws(() => v.vault.getNotifyWebhook())
  } finally { v.done() }
})

test('clearing the webhook removes it once, and a locked vault reveals nothing', () => {
  const v = fresh()
  try {
    v.vault.setNotifyWebhook({ url: URL_SECRET })
    assert.equal(v.vault.clearNotifyWebhook(), true)
    assert.equal(v.vault.clearNotifyWebhook(), false)
    assert.equal(records(v, 'notify.removed').length, 1)
    assert.equal(v.vault.getNotifyWebhook(), null)
    assert.equal(v.vault.notifyConfig(), null)
    assert.equal(onDisk(v).kv.notify, undefined)

    v.vault.setNotifyWebhook({ url: URL_SECRET })
    v.vault.lock()
    assert.equal(code(() => v.vault.getNotifyWebhook()).code, 'AV_LOCKED')
    assert.equal(code(() => v.vault.setNotifyWebhook({ url: 'https://hooks.example/y' })).code, 'AV_LOCKED')
    assert.equal(code(() => v.vault.clearNotifyWebhook()).code, 'AV_LOCKED')
    assert.equal(v.vault.notifyConfig().host, 'hooks.example')
  } finally { v.done() }
})
