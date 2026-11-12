// Builds a JS vault in a temp dir for the migrate tests, with the JS store
// itself (src/store/*), and writes what the tests need to check against.
// Fixture values only: every secret here is fake and the vault is a temp dir.
//
//   node make-js-vault.mjs <repo src dir> <vault dir> <none|passphrase> <out.json>

import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { writeFileSync } from 'node:fs'

const [, , src, dir, factor, out] = process.argv
const { Vault } = await import(`file://${src}/store/vault.js`)
const { exportBackup } = await import(`file://${src}/store/backup.js`)

const PASSPHRASE = 'test-passphrase-not-real'
const RECOVERY = 'test-recovery-passphrase-not-real'
const SECRETS = {
  demo: 'test-secret-demo-0011223344556677889900',
  gh_old: 'ghp_TESTSECRETOLD00112233445566778899aabb',
  gh: 'ghp_TESTSECRETNEW00112233445566778899aabb',
  other: 'test-secret-other-00112233445566778899',
}
const WEBHOOK = 'https://hooks.example/services/TEST/NOTREAL/test-webhook-path'
const PIN = `sha256/${'Q'.repeat(43)}=`
const POLICY = { hosts: ['api.example.com'], methods: ['GET', 'POST'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'on-write' }

const v = factor === 'passphrase'
  ? Vault.create(dir, { factor: 'passphrase', passphrase: PASSPHRASE })
  : Vault.create(dir, { factor: 'none' })

const demo = v.addCredential({
  slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
  fields: { token: SECRETS.demo }, sites: { token: ['header:authorization:Bearer'] },
})
const gh = v.addCredential({ slug: 'gh', kind: 'github', fields: { token: SECRETS.gh_old } })
v.addCredential({
  slug: 'other', kind: 'http', connector: { host: 'api.other.example', scheme: 'https' },
  fields: { token: SECRETS.other }, sites: { token: ['header:authorization:Bearer'] },
})
v.addScrubPattern('demo', 'acme_[A-Za-z0-9]{20,40}')
v.setCredentialExpiry('demo', '2031-01-01')
v.setPins('demo', 'api.example.com', [PIN])
v.rotateCredential('gh', { value: SECRETS.gh, retireMs: 3 * 86_400_000 })
v.recordHealth('demo', { status: 'ok', http_status: 200, source: 'probe' })
v.setQuarantine('other', { by: 'control', reason: 'fixture' })
v.updateSettings({
  tripwires: { enabled: true, rules: [{ id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' }] },
  retention_days: 30,
})
v.setNotifyWebhook({ url: WEBHOOK, detail: 'headline' })
v.saveTemplate('gh-read', { cred: 'gh', methods: ['GET'], spend_usd: 0.5 })
const ws = v.addWorkspace({ name: 'team', policy: { methods: ['GET'] } })
v.addListener({ id: 'lan', address: '127.0.0.1:9443', surfaces: ['gateway'], advertise: [], allow_cidr: [], tls: { managed: true } })
const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
const presence = { credentialId: randomBytes(32).toString('base64url'), publicKeySpki: spki, signCount: 7 }
v.setPresenceKey(presence)
v.prfSalt()
if (factor === 'passphrase') v.addWebauthnUnlock('fixture-prf-credential', randomBytes(32))

const { session, token } = v.createSession({ label: 'agent', workspaceId: ws.id })
const grant = v.createGrant({ sessionId: session.id, credentialId: demo.id, fields: ['token'], policy: POLICY })
const { placeholder, row } = v.issuePlaceholder({ grantId: grant.id, uses: 5 })
v.consumePlaceholder(row.id)
const ghGrant = v.createGrant({ sessionId: session.id, credentialId: gh.id, fields: ['token'], policy: { ...POLICY, hosts: ['api.github.com'] } })
const ghPh = v.issuePlaceholder({ grantId: ghGrant.id })
const ended = v.createSession({ label: 'ended' })
v.createGrant({ sessionId: ended.session.id, credentialId: demo.id, fields: ['token'], policy: POLICY })
v.revokeSession(ended.session.id)
v.db.kv.session_requests = [{
  id: 'sr_FIXTURE0000000000000000000', collect_hash: 'a'.repeat(64), proposal: { cred: 'demo', methods: ['GET'] },
  fingerprint: 'fp-fixture', summary: 'session for demo', reason_untrusted: 'fixture', state: 'pending',
  created_at: new Date().toISOString(), decided_at: null,
}]
v.db.kv.ui_origins = ['http://127.0.0.1:7777']
v.save()
const witness = v.audit.checkpoint()
const { bundle } = await exportBackup(v, { recoveryPassphrase: RECOVERY })

writeFileSync(out, JSON.stringify({
  factor, passphrase: PASSPHRASE, recovery: RECOVERY, secrets: SECRETS, webhook: WEBHOOK, pin: PIN,
  token, session_id: session.id, ended_session_id: ended.session.id, grant_id: grant.id,
  placeholder, row_id: row.id, gh_placeholder: ghPh.placeholder, presence,
  witness, bundle, head: v.audit.head, seq: v.audit.seq, workspace_id: ws.id,
}, null, 1))
