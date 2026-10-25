// Shared scaffolding for the fix-control regression tests: a temp vault, an
// in-process daemon on a temp socket, a control-socket client, and a software
// platform authenticator the daemon can verify. Not a test file itself — the
// glob only picks up *.test.js.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest } from 'node:http'
import { generateKeyPairSync, createHash, sign as cryptoSign, randomBytes } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

export const PASSPHRASE = 'correct horse battery staple'
export const SECRET = 'ghp_FIXCONTROL00112233445566778899aa'

/** A vault with one credential, and a daemon on a temp control socket. */
export async function startDaemon({ passphrase = null, sites = ['header:authorization:Bearer'], host = 'api.example.com', scheme = 'https', listeners = [] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-'))
  const vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host, scheme },
    fields: { token: SECRET }, sites: { token: sites },
  })
  if (passphrase) vault.setPassphrase(passphrase)
  // Configured before start, which is when listeners bind.
  for (const l of listeners) vault.addListener(l)
  const sock = join(dir, 'c.sock')
  const daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
  const control = (method, path, body) => controlAt(sock, method, path, body)
  const stop = async () => {
    await daemon.stop()
    rmSync(dir, { recursive: true, force: true })
  }
  return { dir, vault, daemon, sock, control, stop }
}

export function controlAt(sock, method, path, body) {
  return new Promise((resolve, reject) => {
    const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString()
        let parsed
        try { parsed = JSON.parse(text || '{}') } catch { parsed = { raw: text } }
        resolve({ status: res.statusCode, body: parsed })
      })
    })
    req.on('error', reject)
    req.end(body ? JSON.stringify(body) : undefined)
  })
}

// --- a synthetic platform authenticator ------------------------------------

export function makeAuthenticator(origin = 'http://localhost:7777') {
  const credentialId = randomBytes(16).toString('base64url')
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const rpIdHash = createHash('sha256').update('localhost').digest()
  return {
    origin,
    /** What the daemon stores for an enrolled presence authenticator. */
    record: {
      credentialId,
      publicKeySpki: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      signCount: 0,
    },
    assert(challenge, at = origin) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: at }))
      const ad = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.alloc(4)])
      const signature = cryptoSign('sha256', Buffer.concat([ad, createHash('sha256').update(clientDataJSON).digest()]), privateKey)
      return {
        credentialId,
        authenticatorData: ad.toString('base64url'),
        clientDataJSON: clientDataJSON.toString('base64url'),
        signature: signature.toString('base64url'),
      }
    },
  }
}

/** Enrol a presence authenticator directly in the vault, as the passphrase-gated route would. */
export function enrol(vault, auth) {
  vault.db.kv.webauthn = { ...auth.record }
  vault.save()
}

/** Ask the daemon for a challenge over `operation`, and sign it. */
export async function signed(control, auth, operation) {
  const ch = await control('POST', '/v1/presence/challenge', { operation, origins: [auth.origin] })
  if (ch.status !== 200) throw new Error(`challenge refused: ${JSON.stringify(ch.body)}`)
  return { challengeId: ch.body.challengeId, ...auth.assert(ch.body.challenge) }
}

/** The web UI in front of a daemon, with the launch link already claimed. */
export async function startUi(d) {
  const { UiServer } = await import('../../src/ui/server.js')
  const ui = await new UiServer(d.sock, { port: 0 }).start()
  const cookie = (await fetch(ui.url, { redirect: 'manual' })).headers.get('set-cookie').split(';')[0]
  const api = (method, path, body) => fetch(`${ui.origin}/api/${path}`, {
    method,
    headers: { 'x-av-ui': '1', cookie, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  /** Do what the page does: get a challenge through the UI, sign it there. */
  const presence = async (auth, operation) => {
    const ch = await (await api('POST', 'presence/challenge', { operation })).json()
    return { challengeId: ch.challengeId, ...auth.assert(ch.challenge, ui.origin) }
  }
  return { ui, api, presence, cookie, stop: () => ui.stop() }
}
