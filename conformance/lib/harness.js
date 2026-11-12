// Black-box harness. Talks to a daemon only through its socket, its gateway,
// and the CLI. Nothing here imports src/.
import { spawn } from 'node:child_process'
import { createServer, request as httpRequest } from 'node:http'
import { mkdtemp, rm, mkdir, chmod } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { once } from 'node:events'
import { randomBytes, createHash, generateKeyPairSync } from 'node:crypto'

export const ROOT = fileURLToPath(new URL('../..', import.meta.url))
export const SECRET = 'test-secret-conform-0123456789abcdef'
export const LOOKALIKE = 'test-secret-conform-fedcba9876543210'
export const PASSPHRASE = 'vault-pass-conform'
export const RECOVERY = 'recovery-phrase-ok'

const SKIP_RUST = 'AV_IMPL=rust but rust/target/debug/agent-vault and rust/target/debug/agent-vault-daemon are not built'

export function implName() {
  return process.env.AV_IMPL || 'js'
}

/** Argv for the daemon and the CLI, or null when the Rust binaries are absent. */
export function binaries() {
  const impl = implName()
  if (impl === 'js') {
    return {
      impl,
      daemon: [process.execPath, join(ROOT, 'bin/agent-vault-daemon.js')],
      cli: [process.execPath, join(ROOT, 'bin/agent-vault.js')],
    }
  }
  if (impl !== 'rust') {
    throw new Error(`AV_IMPL must be unset, "js", or "rust" (got ${JSON.stringify(impl)})`)
  }
  const daemon = join(ROOT, 'rust/target/debug/agent-vault-daemon')
  const cli = join(ROOT, 'rust/target/debug/agent-vault')
  if (!existsSync(daemon) || !existsSync(cli)) {
    // A missing binary is a skip unless a gate asked to be failed instead.
    // AV_REQUIRE_IMPL=1 is how the Rust acceptance run refuses to pass by skipping.
    if (process.env.AV_REQUIRE_IMPL === '1') {
      throw new Error(`${SKIP_RUST} (AV_REQUIRE_IMPL=1: a missing implementation is a failure, not a skip)`)
    }
    return null
  }
  return { impl, daemon: [daemon], cli: [cli] }
}

export function rustSkipReason() {
  return binaries() ? null : SKIP_RUST
}

function tempParent() {
  // macOS os.tmpdir() is a long /var/folders path. A Unix socket path has to
  // stay under ~104 bytes, and the CLI looks for <dir>/control.sock.
  return process.platform === 'win32' ? tmpdir() : '/tmp'
}

export function secretForms(secret) {
  const hex = Buffer.from(secret, 'utf8').toString('hex')
  const b64 = Buffer.from(secret, 'utf8').toString('base64')
  return [
    secret,
    encodeURIComponent(secret),
    b64,
    b64.replace(/\+/g, '-').replace(/\//g, '_'),
    hex,
    hex.toUpperCase(),
    [...secret].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
    secret.replace(/[<>&"']/g, (c) => `&#${c.charCodeAt(0)};`),
  ]
}

/** The first encoding of `secret` found in `text`, or null when none is present. */
export function leaksSecret(text, secret = SECRET) {
  const blob = typeof text === 'string' ? text : JSON.stringify(text)
  return secretForms(secret).find((form) => form && blob.includes(form)) || null
}

export function startUpstream() {
  const hits = []
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      const seen = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '')
      hits.push({ method: req.method, url: req.url, seen, body })
      const send = (status, obj) => {
        const payload = JSON.stringify(obj)
        res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) })
        res.end(payload)
      }
      if (req.url.startsWith('/reflect')) {
        // The stored secret, so a retire-window scrub can be seen from outside.
        return send(200, { echoed: SECRET, ordinary: 'ordinary-traffic-control', lookalike: LOOKALIKE })
      }
      if (req.url.startsWith('/echo')) {
        return send(200, {
          login: 'fixture-user',
          token_used: seen,
          token_b64: Buffer.from(seen, 'utf8').toString('base64'),
          token_pct: encodeURIComponent(seen),
          token_hex: Buffer.from(seen, 'utf8').toString('hex'),
          token_u: [...seen].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
          ordinary: 'ordinary-traffic-control',
          lookalike: LOOKALIKE,
        })
      }
      if (req.url.startsWith('/user')) {
        return send(200, { login: 'fixture-user', ordinary: 'ordinary-traffic-control', lookalike: LOOKALIKE })
      }
      if (req.method === 'POST') {
        return send(201, { created: true, ordinary: 'ordinary-traffic-control', echoed: body })
      }
      send(200, { ok: true, path: req.url, ordinary: 'ordinary-traffic-control' })
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        hits,
        close: () => new Promise((r) => server.close(r)),
      })
    })
  })
}

function baseEnv(dir) {
  const env = { ...process.env, NO_COLOR: '1' }
  for (const key of ['AGENT_VAULT_SESSION', 'AGENT_VAULT_URL', 'AGENT_VAULT_PLACEHOLDER', 'AGENT_VAULT_PORT']) {
    delete env[key]
  }
  env.AGENT_VAULT_DIR = dir
  env.AV_VAULT_DIR = dir
  env.AV_RUN_DIR = dir
  env.AV_PORT = '0'
  return env
}

function spawnDaemon(bins, env, dir) {
  const stderr = []
  const stdout = []
  const child = spawn(bins.daemon[0], bins.daemon.slice(1), {
    env,
    cwd: dir,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let settled = false
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      settled = true
      reject(new Error(`daemon did not become ready\nstdout:\n${stdout.join('')}\nstderr:\n${stderr.join('')}`))
    }, 15_000)
    const take = (buf, sink) => {
      sink.push(buf.toString('utf8'))
      const text = stdout.join('')
      const m = /gateway\s+http:\/\/127\.0\.0\.1:(\d+)/.exec(text)
      if (m && !settled) {
        settled = true
        clearTimeout(timer)
        resolve(Number(m[1]))
      }
    }
    child.stdout.on('data', (b) => take(b, stdout))
    child.stderr.on('data', (b) => stderr.push(b.toString('utf8')))
    child.once('exit', (code, signal) => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        reject(new Error(`daemon exited before ready (${code ?? signal})\n${stderr.join('')}${stdout.join('')}`))
      }
    })
  })
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode) return
    child.kill('SIGTERM')
    const exited = once(child, 'exit')
    const killer = setTimeout(() => child.kill('SIGKILL'), 3000)
    await exited
    clearTimeout(killer)
  }
  return ready.then((port) => ({
    port,
    stop,
    log: () => ({ stdout: stdout.join(''), stderr: stderr.join('') }),
  })).catch(async (e) => {
    await stop()
    throw e
  })
}

export async function openWorld() {
  const bins = binaries()
  if (!bins) throw new Error(SKIP_RUST)
  const dir = await mkdtemp(join(tempParent(), 'avc-'))
  // mkdtemp is already 0700. Loosen it so a daemon that never chmods the
  // vault directory cannot pass the mode check.
  await chmod(dir, 0o755)
  const upstream = await startUpstream()
  const env = baseEnv(dir)
  let daemon
  const attach = () => spawnDaemon(bins, env, dir)
  try {
    daemon = await attach()
    const world = {
      dir,
      env,
      port: daemon.port,
      upstream,
      bins,
      socketPath: join(dir, 'control.sock'),
      log() { return daemon.log() },
      control(method, path, body) { return control(world.socketPath, method, path, body) },
      async restart() {
        await daemon.stop()
        daemon = await attach()
        world.port = daemon.port
        return world
      },
      async close() {
        await daemon.stop()
        await upstream.close()
        await rm(dir, { recursive: true, force: true })
      },
    }
    return world
  } catch (e) {
    if (daemon) await daemon.stop()
    await upstream.close()
    await rm(dir, { recursive: true, force: true })
    throw e
  }
}

/** A loopback port that is free at the moment it is returned. */
export function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close((err) => (err ? reject(err) : resolve(port)))
    })
  })
}

export function control(socketPath, method, path, body, { timeout = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body))
    const req = httpRequest({
      socketPath,
      path,
      method,
      headers: {
        'content-type': 'application/json',
        ...(payload ? { 'content-length': payload.length } : {}),
      },
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        let json = null
        if (text) {
          try { json = JSON.parse(text) } catch { json = { raw: text } }
        }
        resolve({ status: res.statusCode, headers: res.headers, json, text })
      })
    })
    const timer = setTimeout(() => {
      req.destroy()
      reject(new Error(`control ${method} ${path} timed out`))
    }, timeout)
    req.on('error', (e) => { clearTimeout(timer); reject(e) })
    req.on('close', () => clearTimeout(timer))
    req.end(payload)
  })
}

/** Open the approval stream, read the snapshot, then close the connection. */
export function readStream(socketPath) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath, path: '/v1/pending/stream', method: 'GET' }, (res) => {
      let text = ''
      const finish = () => {
        req.destroy()
        resolve({ status: res.statusCode, headers: res.headers, text })
      }
      res.on('data', (c) => {
        text += c.toString('utf8')
        if (text.includes('event: snapshot')) finish()
      })
      res.on('end', finish)
    })
    const timer = setTimeout(() => { req.destroy(); reject(new Error('pending stream produced no snapshot')) }, 15_000)
    req.on('error', (e) => { clearTimeout(timer); reject(e) })
    req.on('close', () => clearTimeout(timer))
    req.end()
  })
}

export function runCli(world, args, { input = '', timeout = 20_000, env, until } = {}) {
  const bins = world.bins
  return new Promise((resolve) => {
    const child = spawn(bins.cli[0], [...bins.cli.slice(1), ...args], {
      env: env || world.env,
      cwd: world.dir,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    let done = false
    const finish = (code, signal) => {
      if (done) return
      done = true
      clearTimeout(timer)
      let json = null
      const trimmed = stdout.trim()
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try { json = JSON.parse(trimmed) } catch { json = null }
      }
      resolve({ code, signal, stdout, stderr, json })
    }
    const timer = setTimeout(() => {
      child.kill('SIGTERM')
      setTimeout(() => child.kill('SIGKILL'), 1000).unref?.()
    }, timeout)
    child.stdout.on('data', (b) => {
      stdout += b.toString('utf8')
      if (until && until(stdout, stderr)) child.kill('SIGTERM')
    })
    child.stderr.on('data', (b) => { stderr += b.toString('utf8') })
    child.on('error', (e) => finish(null, e.message))
    child.on('close', finish)
    child.stdin.end(input)
  })
}

export async function gateway(world, path, { method = 'GET', headers = {}, body, token, placeholder } = {}) {
  const h = { ...headers }
  if (token) h['av-session'] = token
  if (placeholder) h.authorization = `Bearer ${placeholder}`
  const res = await fetch(`http://127.0.0.1:${world.port}${path}`, {
    method,
    headers: h,
    body,
    redirect: 'manual',
  })
  const text = await res.text()
  let json = null
  if (text) {
    try { json = JSON.parse(text) } catch { json = null }
  }
  return { status: res.status, headers: Object.fromEntries(res.headers), text, json }
}

export async function seed(world, { slug = 'demo', budget = 40, approval = 'on-write', methods = ['GET', 'POST'] } = {}) {
  const added = await world.control('POST', '/v1/credentials', {
    slug,
    kind: 'http',
    host: `127.0.0.1:${world.upstream.port}`,
    scheme: 'http',
    value: SECRET,
    sites: ['header:authorization:Bearer'],
  })
  if (added.status !== 200) throw new Error(`seed credential failed ${added.status} ${added.text}`)
  const session = await world.control('POST', '/v1/sessions', {
    cred: slug,
    label: 'conformance',
    methods,
    paths: ['/**'],
    budget,
    approval,
    ttl_hours: 1,
  })
  if (session.status !== 200) throw new Error(`seed session failed ${session.status} ${session.text}`)
  world.slug = slug
  world.cred = added.json
  world.session = session.json
  return world
}

export function pinValue() {
  return `sha256/${createHash('sha256').update('conformance-pin').digest('base64')}`
}

export function presenceKey() {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  return {
    credentialId: randomBytes(16).toString('base64url'),
    publicKeySpki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    signCount: 0,
  }
}

export async function freshDir() {
  const dir = await mkdtemp(join(tempParent(), 'avc-'))
  await mkdir(dir, { recursive: true })
  return dir
}

export async function removeDir(dir) {
  if (dir) await rm(dir, { recursive: true, force: true })
}
