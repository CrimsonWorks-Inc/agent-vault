// The web UI the daemon's CLI serves: headers, the launch cookie, the dist
// allowlist, and Host and Origin checks. Started the way `agent-vault ui` starts.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { request as httpRequest } from 'node:http'
import { rustSkipReason, openWorld, leaksSecret, SECRET } from './lib/harness.js'

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"

function startUi(world) {
  return new Promise((resolve, reject) => {
    const child = spawn(world.bins.cli[0], [...world.bins.cli.slice(1), 'ui', '--json', '--port', '0', '--no-open'], {
      env: world.env, cwd: world.dir, stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      child.kill('SIGKILL')
      reject(new Error(`ui did not print a url\n${stdout}\n${stderr}`))
    }, 15_000)
    child.stdout.on('data', (b) => {
      stdout += b.toString('utf8')
      if (settled) return
      try {
        const json = JSON.parse(stdout.trim())
        if (json?.ok && json.data?.url) {
          settled = true
          clearTimeout(timer)
          resolve({
            url: json.data.url,
            port: json.data.port,
            stop() {
              if (child.exitCode === null && !child.signalCode) child.kill('SIGTERM')
            },
          })
        }
      } catch { /* not a whole line yet */ }
    })
    child.stderr.on('data', (b) => { stderr += b.toString('utf8') })
    child.once('exit', (code, signal) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(new Error(`ui exited ${code ?? signal}\n${stderr}\n${stdout}`))
    })
  })
}

function raw(port, path, headers = {}) {
  const { method, body, ...rest } = headers
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1', port, path, method: method || 'GET',
      headers: { host: `localhost:${port}`, ...rest },
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        resolve({ status: res.statusCode, headers: res.headers, text })
      })
    })
    req.on('error', reject)
    req.setTimeout(15_000, () => req.destroy(new Error(`no answer for ${path}`)))
    req.end(body)
  })
}

const skip = rustSkipReason()
if (skip) {
  test('ui', { skip }, () => {})
} else {
  describe('ui', { concurrency: false, timeout: 120_000 }, () => {
    let w
    let ui
    let cookie
    before(async () => {
      w = await openWorld()
      const added = await w.control('POST', '/v1/credentials', {
        slug: 'demo', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      if (added.status !== 200) throw new Error(added.text)
      const session = await w.control('POST', '/v1/sessions', {
        cred: 'demo', label: 'ordinary-traffic-control', methods: ['GET'], paths: ['/**'], budget: 5, approval: 'on-write', ttl_hours: 1,
      })
      if (session.status !== 200) throw new Error(session.text)
      w.session = session.json
      // A label is at most 80 characters, and a placeholder is most of that.
      const marked = await w.control('POST', '/v1/sessions', {
        cred: 'demo',
        label: `${session.json.placeholder} avs1.aa.bb`,
        methods: ['GET'], paths: ['/**'], budget: 5, approval: 'on-write', ttl_hours: 1,
      })
      if (marked.status !== 200) throw new Error(marked.text)
      w.marked = marked.json
      ui = await startUi(w)
    })
    after(async () => {
      ui?.stop()
      await w?.close()
    })

    test('the launch link sets an HttpOnly cookie once, and the page carries the strict CSP', async () => {
      const claim = await fetch(ui.url, { redirect: 'manual' })
      assert.equal(claim.status, 302)
      const setCookie = claim.headers.get('set-cookie') || ''
      assert.match(setCookie, /^av_ui=/)
      assert.match(setCookie, /HttpOnly/)
      assert.match(setCookie, /SameSite=Strict/)
      assert.match(setCookie, /Path=\//)
      assert.equal(leaksSecret(setCookie), null)
      cookie = setCookie.split(';')[0]
      const page = await fetch(new URL('/', ui.url), { headers: { cookie }, redirect: 'manual' })
      assert.equal(page.status, 200)
      assert.equal(page.headers.get('content-security-policy'), CSP)
      assert.equal(page.headers.get('cache-control'), 'no-store')
      assert.equal(page.headers.get('x-content-type-options'), 'nosniff')
      assert.equal(page.headers.get('referrer-policy'), 'no-referrer')
      const html = await page.text()
      assert.match(html, /<script/)
      assert.equal(leaksSecret(html), null)
      const again = await fetch(ui.url, { redirect: 'manual' })
      assert.equal(again.status, 409)
      assert.match(await again.text(), /already used/)
    })

    test('an allowlisted asset is served, and a file outside it or a traversal is refused', async () => {
      const page = await fetch(new URL('/', ui.url), { headers: { cookie } })
      const html = await page.text()
      const asset = html.match(/\/assets\/[A-Za-z0-9][A-Za-z0-9._-]+/)
      assert.ok(asset, html.slice(0, 200))
      const ok = await raw(ui.port, asset[0], { cookie })
      assert.equal(ok.status, 200, ok.text.slice(0, 120))
      assert.equal(ok.headers['content-security-policy'], CSP)
      assert.equal(ok.headers['cache-control'], 'no-store')
      assert.equal(ok.headers['x-content-type-options'], 'nosniff')
      assert.equal(leaksSecret(ok.text), null)
      for (const path of [
        '/assets/../index.html',
        '/assets/%2e%2e/index.html',
        '/assets/%2fhidden',
        '/package.json',
        '/assets/.env',
        '/assets/not-a-shipped-file.js',
      ]) {
        const refused = await raw(ui.port, path, { cookie })
        assert.equal(refused.status, 404, `${path} ${refused.status} ${refused.text}`)
        assert.equal(refused.text.includes(SECRET), false)
        assert.equal(leaksSecret(refused.text), null)
      }
    })

    test('a foreign Host or Origin is refused, and loopback is sent to localhost', async () => {
      const evil = await raw(ui.port, '/', { host: 'evil.test', cookie })
      assert.equal(evil.status, 403)
      assert.match(evil.text, /unexpected Host/)
      const ip = await raw(ui.port, '/', { host: `127.0.0.1:${ui.port}` })
      assert.equal(ip.status, 302)
      assert.match(ip.headers.location, /^http:\/\/localhost:\d+\//)
      const origin = await raw(ui.port, '/api/credentials', {
        cookie, origin: 'https://evil.test', 'x-av-ui': '1',
      })
      assert.equal(origin.status, 403)
      assert.match(origin.text, /cross-origin/)
    })

    test('the API withholds the secret, a session token, and a placeholder', async () => {
      const bare = await raw(ui.port, '/api/credentials', { 'x-av-ui': '1' })
      assert.equal(bare.status, 401)
      const form = await raw(ui.port, '/api/lock', { method: 'POST', cookie, body: '{}' })
      assert.equal(form.status, 403)
      const creds = await raw(ui.port, '/api/credentials', { cookie, 'x-av-ui': '1' })
      assert.equal(creds.status, 200, creds.text)
      assert.equal(creds.text.includes(SECRET), false)
      assert.equal(leaksSecret(creds.text), null)
      const state = await raw(ui.port, '/api/presence/state', { cookie, 'x-av-ui': '1' })
      assert.equal(state.status, 200, state.text)
      const parsed = JSON.parse(state.text)
      assert.equal(parsed.rpId, 'localhost')
      assert.match(parsed.origin, /^http:\/\/localhost:\d+$/)
      const sessions = await raw(ui.port, '/api/sessions', { cookie, 'x-av-ui': '1' })
      assert.equal(sessions.status, 200, sessions.text)
      assert.equal(sessions.text.includes(w.session.placeholder), false)
      assert.equal(sessions.text.includes(w.session.token), false)
      assert.equal(sessions.text.includes('avs1.aa.bb'), false)
      assert.ok(sessions.text.includes('«placeholder»'))
      assert.ok(sessions.text.includes('«token»'))
      assert.ok(sessions.text.includes('ordinary-traffic-control'))
      const docs = await raw(ui.port, '/api/docs/context', { cookie, 'x-av-ui': '1' })
      assert.equal(docs.status, 200, docs.text)
      const ctx = JSON.parse(docs.text)
      assert.equal(ctx.gateway_port, w.port)
      assert.ok(ctx.cred_slugs.includes('demo'))
      assert.match(ctx.mcp_url, /\/mcp$/)
      assert.equal(leaksSecret(docs.text), null)
      for (const path of ['/api/credentials/demo', '/api/secrets', '/api/reveal']) {
        const missing = await raw(ui.port, path, { cookie, 'x-av-ui': '1' })
        assert.ok(missing.status >= 400, path)
        assert.equal(leaksSecret(missing.text), null)
      }
    })
  })
}
