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
export async function startDaemon({ passphrase = null, sites = ['header:authorization:Bearer'], host = 'api.example.com', scheme = 'https', listeners = [], socketName = 'c.sock' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-'))
  const vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host, scheme },
    fields: { token: SECRET }, sites: { token: sites },
  })
  if (passphrase) vault.setPassphrase(passphrase)
  // Configured before start, which is when listeners bind.
  for (const l of listeners) vault.addListener(l)
  // `control.sock` is where the CLI looks under AGENT_VAULT_DIR.
  const sock = join(dir, socketName)
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

// The daemon's default web UI port. Written here rather than imported, so the
// helpers load against a build that predates it.
export const UI_ORIGIN = 'http://localhost:7412'

function cborUint(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b
}
function cbor(v) {
  if (typeof v === 'number') return v >= 0 ? cborUint(0, v) : cborUint(1, -1 - v)
  if (typeof v === 'string') return Buffer.concat([cborUint(3, Buffer.byteLength(v)), Buffer.from(v)])
  if (Buffer.isBuffer(v)) return Buffer.concat([cborUint(2, v.length), v])
  if (v instanceof Map) return Buffer.concat([cborUint(5, v.size), ...[...v].map(([k, x]) => Buffer.concat([cbor(k), cbor(x)]))])
  throw new Error('unsupported')
}

export function makeAuthenticator(origin = UI_ORIGIN) {
  const rawId = randomBytes(16)
  const credentialId = rawId.toString('base64url')
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const rpIdHash = createHash('sha256').update('localhost').digest()
  return {
    origin,
    /** A `none` attestation, as the page sends to finish enrolment. */
    register(challenge, at = origin) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: at }))
      const raw = publicKey.export({ format: 'der', type: 'spki' })
      const point = raw.subarray(raw.length - 65)
      const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, point.subarray(1, 33)], [-3, point.subarray(33, 65)]])
      const len = Buffer.alloc(2); len.writeUInt16BE(rawId.length)
      const authData = Buffer.concat([rpIdHash, Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), len, rawId, cbor(cose)])
      const att = new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]])
      return { attestationObject: cbor(att).toString('base64url'), clientDataJSON: clientDataJSON.toString('base64url') }
    },
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
  // A UI on a port of its own is trusted because the test configured the
  // daemon to trust it — in process, the way the daemon's owner would.
  d.daemon.allowUiOrigin?.(ui.origin)
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

const BIN = new URL('../../bin/agent-vault.js', import.meta.url).pathname

/**
 * Run the real CLI against `dir`. Resolves with { code, stdout, stderr }
 * whatever the exit code; `input` goes to stdin; `env` is merged in.
 */
export function cli(dir, args, { input, env = {}, timeout = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    import('node:child_process').then(({ spawn }) => {
      const child = spawn(process.execPath, [BIN, ...args], {
        env: { ...process.env, AGENT_VAULT_DIR: dir, NO_COLOR: '1', ...env },
        stdio: ['pipe', 'pipe', 'pipe'],
      })
      let stdout = ''
      let stderr = ''
      child.stdout.on('data', (d) => { stdout += d })
      child.stderr.on('data', (d) => { stderr += d })
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`timeout: ${args.join(' ')}\n${stdout}\n${stderr}`)) }, timeout)
      child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }) })
      child.on('error', (e) => { clearTimeout(timer); reject(e) })
      if (input !== undefined) child.stdin.write(input)
      child.stdin.end()
    })
  })
}

export { BIN }
