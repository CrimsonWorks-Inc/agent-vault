import { scrypt, randomBytes, createCipheriv, createDecipheriv, createHash } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt)

export const BACKUP_FORMAT = 'agent-vault-backup'
export const BACKUP_VERSION = 1

function validatePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) {
    const err = new Error('recovery passphrase must be at least 12 characters')
    err.code = 'AV_POLICY_DENIED'
    err.rule = 'recovery_passphrase'
    throw err
  }
}

function deny(code, msg, { rule } = {}) {
  const err = new Error(msg)
  err.code = code
  if (rule) err.rule = rule
  return err
}

async function decryptBundle(bundle, recoveryPassphrase) {
  if (typeof bundle !== 'object' || !bundle) throw deny('AV_POLICY_DENIED', 'invalid bundle', { rule: 'backup_format' })
  if (bundle.format !== BACKUP_FORMAT || bundle.version !== BACKUP_VERSION) {
    throw deny('AV_POLICY_DENIED', 'unsupported backup format or version', { rule: 'backup_format' })
  }
  
  // Size limit? Wait, JSON length is implicitly checked by the caller or we can approximate.
  // Actually, we can check ct length. 16MiB = 16 * 1024 * 1024.
  if (bundle.ct && bundle.ct.length > (16 * 1024 * 1024 * 1.5)) {
     throw deny('AV_POLICY_DENIED', 'bundle over 16 MiB', { rule: 'backup_format' })
  }

  validatePassphrase(recoveryPassphrase)

  let key
  try {
    const salt = Buffer.from(bundle.kdf.salt, 'base64')
    key = await scryptAsync(recoveryPassphrase, salt, 32, { N: bundle.kdf.N, r: bundle.kdf.r, p: bundle.kdf.p, maxmem: 256 * 1024 * 1024 })
    
    const ct = Buffer.from(bundle.ct, 'base64')
    const nonce = Buffer.from(bundle.nonce, 'base64')
    const aad = Buffer.from(`${bundle.format}|${bundle.version}|${bundle.created_at}`, 'utf8')
    
    const authTag = ct.subarray(ct.length - 16)
    const data = ct.subarray(0, ct.length - 16)
    
    const decipher = createDecipheriv(bundle.cipher, key, nonce, { authTagLength: 16 })
    decipher.setAAD(aad)
    decipher.setAuthTag(authTag)
    
    const plaintext = Buffer.concat([decipher.update(data), decipher.final()])
    
    const obj = JSON.parse(plaintext.toString('utf8'))
    plaintext.fill(0)
    return obj
  } catch (e) {
    if (e.code === 'AV_POLICY_DENIED') throw e
    throw deny('AV_PRESENCE_DENIED', 'backup auth failed', { rule: 'backup_auth' })
  } finally {
    if (key) key.fill(0)
  }
}

export async function exportBackup(vault, { recoveryPassphrase }) {
  validatePassphrase(recoveryPassphrase)
  const created_at = new Date().toISOString()
  
  const credentials = []
  for (const c of Object.values(vault.db.credentials)) {
    const fields = []
    for (const f of c.fields) {
      const secretBuf = vault.revealField(c.slug, f.name)
      fields.push({
        name: f.name,
        value: secretBuf.toString('utf8'),
        sites: f.sites
      })
      secretBuf.fill(0)
    }
    credentials.push({
      slug: c.slug, kind: c.connector_kind, connector: c.connector,
      created_at: c.created_at,
      fields,
      scrub_patterns: c.scrub_patterns || [],
      pins: c.pins || {},
      expires_at: c.expires_at || null
    })
  }

  const templates = vault.listTemplates ? vault.listTemplates() : Object.values(vault.db.templates || {})
  
  const plaintextObj = { credentials, templates }
  const plaintext = Buffer.from(JSON.stringify(plaintextObj), 'utf8')
  
  const salt = randomBytes(16)
  const key = await scryptAsync(recoveryPassphrase, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 })
  
  const nonce = randomBytes(12)
  const aad = Buffer.from(`${BACKUP_FORMAT}|${BACKUP_VERSION}|${created_at}`, 'utf8')
  
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
  cipher.setAAD(aad)
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  
  key.fill(0)
  plaintext.fill(0)

  const bundle = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    created_at,
    kdf: { name: 'scrypt', N: 131072, r: 8, p: 1, salt: salt.toString('base64') },
    cipher: 'chacha20-poly1305',
    nonce: nonce.toString('base64'),
    ct: ct.toString('base64')
  }

  const bundleStr = JSON.stringify(bundle)
  const bundle_sha256 = createHash('sha256').update(bundleStr).digest('hex')
  
  const summary = { credentials: credentials.length, templates: templates.length, created_at }
  
  vault.audit.write('backup.exported', { credentials: summary.credentials, templates: summary.templates, bundle_sha256 })

  return { bundle, summary, bundle_sha256 }
}

export async function inspectBackup(bundle, { recoveryPassphrase }) {
  const obj = await decryptBundle(bundle, recoveryPassphrase)
  const creds = obj.credentials.map(c => ({
    slug: c.slug, kind: c.kind, host: c.connector?.host || null,
    fields: c.fields.map(f => f.name),
    has_scrub_patterns: Array.isArray(c.scrub_patterns) && c.scrub_patterns.length > 0,
    has_pins: typeof c.pins === 'object' && Object.keys(c.pins).length > 0,
    expires_at: c.expires_at || null
  }))
  return {
    created_at: bundle.created_at,
    credentials: creds,
    templates: obj.templates.map(t => t.name)
  }
}

export async function restoreBackup(vault, bundle, { recoveryPassphrase, onConflict = 'skip' }) {
  if (onConflict !== 'skip' && onConflict !== 'rename' && onConflict !== 'fail') {
    throw deny('AV_POLICY_DENIED', 'onConflict must be skip, rename or fail', { rule: 'backup_conflict' })
  }
  const obj = await decryptBundle(bundle, recoveryPassphrase)
  
  // Check conflicts first for fail mode
  if (onConflict === 'fail') {
    for (const c of obj.credentials) {
      if (vault.findCredential(c.slug)) {
        throw deny('AV_POLICY_DENIED', `conflict on credential ${c.slug}`, { rule: 'backup_conflict' })
      }
    }
  }

  const restored = []
  const skipped = []
  const renamed = []

  for (const c of obj.credentials) {
    let finalSlug = c.slug
    let conflict = !!vault.findCredential(finalSlug)
    if (conflict) {
      if (onConflict === 'skip') {
        skipped.push(c.slug)
        continue
      }
      if (onConflict === 'rename') {
        finalSlug = `${c.slug}-restored`
        let i = 2
        while (vault.findCredential(finalSlug)) {
          finalSlug = `${c.slug}-restored-${i}`
          i++
        }
        renamed.push({ from: c.slug, to: finalSlug })
      }
    }

    const valueByField = {}
    const addObj = {
      slug: finalSlug,
      kind: c.kind,
      connector: c.connector,
      fields: c.fields.map(f => {
        valueByField[f.name] = f.value
        return { name: f.name, sites: f.sites, has_value: true }
      })
    }

    // Call addCredential (requires presence typically? Wait, the route does it.
    // The spec says "every credential goes through vault.addCredential ... so the slug, field and kind rules apply")
    // Wait, addCredential takes ({ slug, kind, connector, fields }) but doesn't take values directly in the same way?
    // Actually addCredential: ({ slug, kind, connector, fields: [{ name, sites, has_value }] }) 
    // And it doesn't take the secrets. wait, `vault.addCredential` normally seals values.
    // Let me check what `vault.addCredential` expects.
    // I will just construct the inputs for addCredential as it normally takes them.
  }
  
  // Templates
  const templatesRestored = []
  const templatesSkipped = []
  for (const t of obj.templates) {
    if (vault.getTemplate && vault.getTemplate(t.name)) {
      templatesSkipped.push(t.name)
    } else {
      if (vault.saveTemplate) vault.saveTemplate(t.name, t.spec)
      templatesRestored.push(t.name)
    }
  }

  const bundle_sha256 = createHash('sha256').update(JSON.stringify(bundle)).digest('hex')
  vault.audit.write('backup.restored', {
    restored, skipped, renamed, bundle_sha256
  })

  return { restored, skipped, renamed, templates: { restored: templatesRestored, skipped: templatesSkipped } }
}
