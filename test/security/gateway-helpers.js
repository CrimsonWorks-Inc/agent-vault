// Shared setup for the gateway-* suites: a throwaway vault with one http
// credential, one session and one grant, and a fake upstream that records
// exactly what reached the wire.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import { Pipeline } from '../../src/daemon/pipeline.js'

export const SECRET = 'SECRETVALUE-0123456789abcdef'

const dirs = []

/** Remove every vault made since the last call. */
export function cleanup() {
  while (dirs.length) rmSync(dirs.pop(), { recursive: true, force: true })
}

export function setup({
  fields = { key: SECRET },
  sites = { key: ['header:x-key'] },
  approval = 'auto',
  methods = ['GET', 'POST'],
  paths = ['/**'],
  connector = { host: 'up.test', scheme: 'https' },
  hosts = ['up.test'],
  respond,
  fetchImpl,
  scrubBudget,
} = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-gw-'))
  dirs.push(dir)
  const vault = Vault.create(dir, { factor: 'none' })
  const cred = vault.addCredential({ slug: 'a', kind: 'http', connector, fields, sites })
  const { session, token } = vault.createSession({ label: 'gw', policy: {} })
  const grant = vault.createGrant({
    sessionId: session.id, credentialId: cred.id, fields: Object.keys(fields),
    policy: { hosts, methods, paths, budget: { unit: 'requests', limit: 1000 }, approval },
  })
  const sent = []
  const pipeline = new Pipeline(vault, {
    allowedHosts: new Set(['127.0.0.1']),
    scrubBudget,
    fetchImpl: fetchImpl || (async (r) => {
      sent.push({ ...r, body: r.body ? Buffer.from(r.body).toString('utf8') : null })
      return respond ? respond(r) : { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') }
    }),
  })
  const ph = (field = 'key', uses = null) => vault.issuePlaceholder({ grantId: grant.id, field, uses }).placeholder
  const request = (over = {}) => ({
    method: 'GET', path: '/p/a/x', query: '',
    headers: [['host', '127.0.0.1'], ['av-session', token]],
    body: null, ...over,
  })
  return { dir, vault, cred, session, token, grant, pipeline, sent, ph, request }
}

/** Read a scrubbed event stream to the end. */
export async function drain(stream) {
  let out = ''
  for await (const c of stream) out += Buffer.from(c).toString('latin1')
  return out
}
