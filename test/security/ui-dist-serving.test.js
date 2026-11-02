// Serving the built page (UI contract U2): index.html at / behind the
// existing session logic, /assets/<name> from an allowlist read once at
// startup and held in memory, the strict content security policy, and
// no-store on all of it.
//
// The bundle is built by another piece of the change, so these run against a
// small fixture dist made here in a temp dir and handed to the UiServer
// constructor. Each request that should not be served is sent raw, as the
// bytes a hostile client would send, because fetch() would tidy the path
// first.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, unlinkSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { UiServer, STRICT_CSP, loadDist, literalPath } from '../../src/ui/server.js'
import { startStub } from './control-ui-helpers.js'

const EXACT_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
const INDEX = '<!doctype html><html><head><meta charset="utf-8"><title>agent-vault</title>' +
  '<script type="module" src="/assets/index-Ab12Cd.js"></script><link rel="stylesheet" href="/assets/index-Ef34Gh.css">' +
  '</head><body><div id="root"></div></body></html>'
const JS = 'console.log("fixture bundle")\n'
const CSS = 'body{color:#111}\n'
const FONT = Buffer.from([0x77, 0x4f, 0x46, 0x32, 0, 1, 2, 3, 250, 251, 252, 253])
const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><path d="M0 0h8v8z"/></svg>'
const OUTSIDE = 'OUTSIDE-THE-DIST-0f9e8d7c'

let root, dist, stub, ui, cookie

function fixtureDist(at) {
  mkdirSync(join(at, 'assets', 'nested'), { recursive: true })
  writeFileSync(join(at, 'index.html'), INDEX)
  writeFileSync(join(at, 'manifest.json'), JSON.stringify({ 'index.html': { file: 'assets/index-Ab12Cd.js', css: ['assets/index-Ef34Gh.css'] } }))
  writeFileSync(join(at, 'assets', 'index-Ab12Cd.js'), JS)
  writeFileSync(join(at, 'assets', 'index-Ef34Gh.css'), CSS)
  writeFileSync(join(at, 'assets', 'inter-latin-400-Zz99.woff2'), FONT)
  writeFileSync(join(at, 'assets', 'mark-Yy88.svg'), SVG)
  // Things in the directory that must never be served.
  writeFileSync(join(at, 'assets', '.hidden.js'), OUTSIDE)
  writeFileSync(join(at, 'assets', '.env'), OUTSIDE)
  writeFileSync(join(at, 'assets', 'index-Ab12Cd.js.map'), OUTSIDE)
  writeFileSync(join(at, 'assets', 'notes.txt'), OUTSIDE)
  writeFileSync(join(at, 'assets', 'page.html'), OUTSIDE)
  writeFileSync(join(at, 'assets', 'nested', 'inner.js'), OUTSIDE)
}

/** One request exactly as written: the path is not normalised on the way. */
function raw(path, { method = 'GET', headers = {}, withCookie = true } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: ui.boundPort, path, method, agent: false,
      headers: { host: `localhost:${ui.boundPort}`, ...(withCookie ? { cookie } : {}), ...headers },
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    req.on('error', reject)
    // A server that never answers is a failure here, not a hang.
    req.setTimeout(15_000, () => req.destroy(new Error(`no answer to ${method} ${path}`)))
    req.end()
  })
}

before(async () => {
  root = mkdtempSync(join(tmpdir(), 'av-dist-'))
  dist = join(root, 'dist')
  fixtureDist(dist)
  writeFileSync(join(root, 'secret.js'), OUTSIDE)
  symlinkSync(join(root, 'secret.js'), join(dist, 'assets', 'linked-Qq11.js'))
  stub = await startStub()
  ui = await new UiServer(stub.sock, { port: 0, distDir: dist }).start()
  const claim = await fetch(ui.url, { redirect: 'manual' })
  assert.equal(claim.status, 302)
  cookie = claim.headers.get('set-cookie').split(';')[0]
})

after(async () => {
  await ui?.stop()
  await stub?.stop()
  rmSync(root, { recursive: true, force: true })
})

test('the policy is exactly the strict one, with nothing inline allowed', () => {
  assert.equal(STRICT_CSP, EXACT_CSP)
  assert.ok(!STRICT_CSP.includes('unsafe-inline'))
  assert.ok(!STRICT_CSP.includes('unsafe-eval'))
})

test('with a session, / is the built index.html under the strict policy and no-store', async () => {
  const r = await raw('/')
  assert.equal(r.status, 200)
  assert.equal(r.body.toString(), INDEX)
  assert.equal(r.headers['content-type'], 'text/html; charset=utf-8')
  assert.equal(r.headers['content-security-policy'], EXACT_CSP)
  assert.equal(r.headers['cache-control'], 'no-store')
  assert.equal(r.headers['x-content-type-options'], 'nosniff')
  assert.equal(r.headers['referrer-policy'], 'no-referrer')
})

test('each allowlisted asset is served with its exact type, no-store and the strict policy', async () => {
  for (const [name, type, body] of [
    ['index-Ab12Cd.js', 'text/javascript; charset=utf-8', Buffer.from(JS)],
    ['index-Ef34Gh.css', 'text/css; charset=utf-8', Buffer.from(CSS)],
    ['inter-latin-400-Zz99.woff2', 'font/woff2', FONT],
    ['mark-Yy88.svg', 'image/svg+xml', Buffer.from(SVG)],
  ]) {
    const r = await raw(`/assets/${name}`)
    assert.equal(r.status, 200, name)
    assert.deepEqual(r.body, body, name)
    assert.equal(r.headers['content-type'], type, name)
    assert.equal(r.headers['cache-control'], 'no-store', name)
    assert.equal(r.headers['x-content-type-options'], 'nosniff', name)
    assert.equal(r.headers['content-security-policy'], EXACT_CSP, name)
    assert.equal(r.headers['cross-origin-resource-policy'], 'same-origin', name)
  }
})

test('assets need the session cookie, as the page does', async () => {
  const none = await raw('/assets/index-Ab12Cd.js', { withCookie: false })
  assert.equal(none.status, 401)
  assert.ok(!none.body.toString().includes('fixture bundle'))
  const wrong = await raw('/assets/index-Ab12Cd.js', { withCookie: false, headers: { cookie: 'av_ui=not-the-session' } })
  assert.equal(wrong.status, 401)
  assert.ok(!wrong.body.toString().includes('fixture bundle'))
  const page = await raw('/', { withCookie: false })
  assert.equal(page.status, 401)
  assert.ok(!page.body.toString().includes('id="root"'), 'the built page went to a caller with no session')
})

test('traversal, encoded slashes, backslashes and dot segments are all 404', async () => {
  const tries = [
    '/assets/../index.html', '/assets/../manifest.json', '/assets/../../secret.js',
    '/assets/%2e%2e/index.html', '/assets/%2E%2E/manifest.json', '/assets/.%2e/index.html',
    '/assets/..%2findex.html', '/assets/..%2Fmanifest.json', '/assets/%2e%2e%2f%2e%2e%2fsecret.js',
    '/assets/nested%2finner.js', '/assets/nested%2Finner.js', '/assets/nested/inner.js',
    '/assets/..\\index.html', '/assets/nested\\inner.js', '/assets/%5c..%5cindex.html',
    '/assets/./index-Ab12Cd.js', '/assets//index-Ab12Cd.js', '/assets/index-Ab12Cd.js/',
    '/assets/index-Ab12Cd.js%00', '/assets/index-Ab12Cd.js%20', '/assets/%69ndex-Ab12Cd.js',
    '/assets/', '/assets', '/index.html', '/manifest.json', '/page.html', '/dist/index.html', '/assets/manifest.json',
    // Paths the URL parser turns into / itself: still 404, never the page.
    '/assets/../', '/assets/..', '/assets/%2e%2e/', '/assets/%2E%2E', '/assets/..\\', '/assets/../?anything=1',
    '/./', '/.', '/%2e/', '/assets/./../', '/assets/nested/../../', '//', '/%2f', '/%5c',
    // And into an API route or an asset.
    '/assets/../api/credentials', '/x/../assets/index-Ab12Cd.js', '/assets/nested/../index-Ab12Cd.js',
  ]
  for (const path of tries) {
    const r = await raw(path)
    assert.equal(r.status, 404, path)
    assert.ok(!r.body.toString().includes(OUTSIDE), `${path} leaked a file outside the allowlist`)
    assert.ok(!r.body.toString().includes('"file"'), `${path} served the manifest`)
  }
})

test('a path is routed only as it arrived: the literal / and literal asset names still work', async () => {
  assert.equal((await raw('/')).status, 200)
  assert.equal((await raw('/?x=1')).status, 200)
  assert.equal((await raw('/assets/index-Ab12Cd.js')).status, 200)
  assert.equal((await raw('/assets/index-Ab12Cd.js?v=2')).status, 200)
  // An API path with a dot segment never reaches the API either.
  const api = await raw('/api/../api/credentials', { headers: { 'x-av-ui': '1' } })
  assert.equal(api.status, 404)
  // A target the URL parser refuses outright is a 404 too, and the server is still up after it.
  for (const bad of ['//', '//localhost:1/x', '//[']) assert.equal((await raw(bad)).status, 404, bad)
  assert.equal((await raw('/')).status, 200)
  const absolute = await raw(`http://localhost:${ui.boundPort}/`)
  assert.equal(absolute.status, 404, 'an absolute-form target is not a literal path')
})

test('literalPath: only a path the parser leaves as it is, with no dot segment or encoded separator', () => {
  const parsed = (r) => { try { return new URL(r, 'http://localhost:1').pathname } catch { return null } }
  for (const ok of ['/', '/api/credentials', '/assets/index-Ab12Cd.js', '/assets/index-Ab12Cd.js?v=1', '/api/'] ) {
    assert.equal(literalPath(ok, parsed(ok)), true, ok)
  }
  for (const bad of [
    '/assets/..%2findex.html', '/assets/x%2Fy.js', '/api/%2fcredentials', '/api/a%5cb', '/assets/a%2E.js',
    '/assets/a\\b.js', '/assets//x.js', '/api//credentials',
    '/assets/../', '/./', '/assets/%2e%2e/', '*', 'http://localhost:1/',
  ]) assert.equal(literalPath(bad, parsed(bad) ?? '/'), false, bad)
  // The same path the parser made is not enough on its own.
  assert.equal(literalPath('/api/x%2fy', '/api/x%2fy'), false)
  assert.equal(literalPath('/api/./x', '/api/./x'), false)
  assert.equal(literalPath('/api/a\\b', '/api/a\\b'), false)
  assert.equal(literalPath('/api//x', '/api//x'), false)
  // Nor is a path free of those marks that the parser still changed.
  assert.equal(literalPath('/api/a{b', '/api/a%7Bb'), false)
  assert.equal(literalPath('/api/x', '/api/y'), false)
})

test('dotfiles, unlisted types, nested files and symlinks are never served', async () => {
  for (const name of ['.hidden.js', '.env', 'index-Ab12Cd.js.map', 'notes.txt', 'page.html', 'linked-Qq11.js', 'nested']) {
    const r = await raw(`/assets/${name}`)
    assert.equal(r.status, 404, name)
    assert.ok(!r.body.toString().includes(OUTSIDE), name)
  }
})

test('only GET serves an asset', async () => {
  for (const method of ['POST', 'PUT', 'DELETE', 'HEAD']) {
    const r = await raw('/assets/index-Ab12Cd.js', { method })
    assert.equal(r.status, 404, method)
  }
})

test('the allowlist is read once at startup and served from memory', async () => {
  // A file that appears later is not served; a file changed or removed later
  // is served as it was at startup.
  writeFileSync(join(dist, 'assets', 'late-Ww77.js'), OUTSIDE)
  writeFileSync(join(dist, 'assets', 'index-Ef34Gh.css'), OUTSIDE)
  unlinkSync(join(dist, 'assets', 'mark-Yy88.svg'))
  try {
    assert.equal((await raw('/assets/late-Ww77.js')).status, 404)
    const css = await raw('/assets/index-Ef34Gh.css')
    assert.equal(css.status, 200)
    assert.equal(css.body.toString(), CSS)
    const svg = await raw('/assets/mark-Yy88.svg')
    assert.equal(svg.status, 200)
    assert.equal(svg.body.toString(), SVG)
  } finally {
    unlinkSync(join(dist, 'assets', 'late-Ww77.js'))
    writeFileSync(join(dist, 'assets', 'index-Ef34Gh.css'), CSS)
    writeFileSync(join(dist, 'assets', 'mark-Yy88.svg'), SVG)
  }
})

test('loadDist lists only regular, allowed files directly in assets', () => {
  const loaded = loadDist(dist)
  assert.deepEqual([...loaded.assets.keys()].sort(), [
    'index-Ab12Cd.js', 'index-Ef34Gh.css', 'inter-latin-400-Zz99.woff2', 'mark-Yy88.svg',
  ])
  assert.equal(loaded.index.toString(), INDEX)
  assert.equal(loadDist(join(root, 'nowhere')), null)
})

/** A throwaway dist beside an outside directory, for the symlink cases. */
function symlinkCase(build) {
  const at = mkdtempSync(join(tmpdir(), 'av-dist-link-'))
  const d = join(at, 'dist')
  const outside = join(at, 'outside')
  mkdirSync(d)
  mkdirSync(outside)
  writeFileSync(join(outside, 'secret-Ab12.js'), OUTSIDE)
  writeFileSync(join(outside, 'index.html'), OUTSIDE)
  try { return build(d, outside, at) } finally { rmSync(at, { recursive: true, force: true }) }
}
const REFUSED = /npm run build:ui/

test('loadDist refuses an assets directory that is a symlink, even to a directory beside dist', () => {
  symlinkCase((d, outside) => {
    writeFileSync(join(d, 'index.html'), INDEX)
    symlinkSync(outside, join(d, 'assets'), 'dir')
    assert.throws(() => loadDist(d), (e) => REFUSED.test(e.message) && /symlink/.test(e.message) && !e.message.includes(OUTSIDE))
  })
  // A symlink to a directory inside dist is refused too: the rule is no links.
  symlinkCase((d) => {
    writeFileSync(join(d, 'index.html'), INDEX)
    mkdirSync(join(d, 'real'))
    writeFileSync(join(d, 'real', 'app-Ab12.js'), JS)
    symlinkSync(join(d, 'real'), join(d, 'assets'), 'dir')
    assert.throws(() => loadDist(d), /symlink/)
  })
})

test('loadDist refuses an index.html that is a symlink, inside or outside dist, and a dangling one', () => {
  symlinkCase((d, outside) => {
    symlinkSync(join(outside, 'index.html'), join(d, 'index.html'))
    // Refused by the check on index.html itself, before the no-follow open.
    assert.throws(() => loadDist(d), /usable: index\.html is a symlink/)
  })
  symlinkCase((d) => {
    writeFileSync(join(d, 'real.html'), INDEX)
    symlinkSync(join(d, 'real.html'), join(d, 'index.html'))
    assert.throws(() => loadDist(d), /symlink/)
  })
  symlinkCase((d, outside) => {
    symlinkSync(join(outside, 'gone.html'), join(d, 'index.html'))
    assert.throws(() => loadDist(d), /symlink/, 'a dangling link is not "no bundle"')
  })
})

test('loadDist refuses a dist directory that is a symlink, and a dist or assets that is not a directory', () => {
  symlinkCase((d, outside, at) => {
    writeFileSync(join(outside, 'index.html'), INDEX)
    const linked = join(at, 'linked-dist')
    symlinkSync(outside, linked, 'dir')
    assert.throws(() => loadDist(linked), /dist directory is a symlink/)
  })
  symlinkCase((d) => {
    writeFileSync(join(d, 'index.html'), INDEX)
    writeFileSync(join(d, 'assets'), 'not a directory')
    assert.throws(() => loadDist(d), /not a directory/)
  })
  symlinkCase((d, outside, at) => {
    writeFileSync(join(at, 'flat'), INDEX)
    assert.throws(() => loadDist(join(at, 'flat')), /not a directory/)
  })
})

test('a server over a symlinked assets directory does not start, so nothing outside dist is ever served', async () => {
  await symlinkCase(async (d, outside) => {
    writeFileSync(join(d, 'index.html'), INDEX)
    symlinkSync(outside, join(d, 'assets'), 'dir')
    assert.throws(() => new UiServer(join(d, 'unused.sock'), { port: 0, distDir: d }), /symlink/)
  })
})

test('the error pages carry the strict policy and nothing inline', async () => {
  // A second claim of the spent launch link, and a visit with no session.
  const spent = await raw(`/?t=${ui.launchToken}`, { withCookie: false })
  assert.equal(spent.status, 409)
  const none = await raw('/', { withCookie: false })
  assert.equal(none.status, 401)
  for (const r of [spent, none]) {
    assert.equal(r.headers['content-security-policy'], EXACT_CSP)
    assert.equal(r.headers['cache-control'], 'no-store')
    const html = r.body.toString()
    assert.ok(!/<style|<script|\sstyle=|\son[a-z]+=/i.test(html), `inline style or script in an error page: ${html}`)
  }
})

test('no response the server makes allows unsafe-inline once the bundle is there', async () => {
  for (const path of ['/', '/assets/index-Ab12Cd.js', '/assets/index-Ef34Gh.css']) {
    const r = await raw(path)
    assert.ok(!String(r.headers['content-security-policy']).includes('unsafe'), path)
  }
})

// U2: there is no other page. A server with no built bundle does not start,
// and says which command builds it, rather than serving something else.
test('U2: with no dist/index.html the server refuses to start and names npm run build:ui', () => {
  const empty = mkdtempSync(join(tmpdir(), 'av-nodist-'))
  try {
    assert.throws(() => new UiServer(stub.sock, { port: 0, distDir: empty }), /the built UI is missing .*run npm run build:ui/)
    mkdirSync(join(empty, 'assets'))
    writeFileSync(join(empty, 'assets', 'index-Ab12Cd.js'), 'x')
    assert.throws(() => new UiServer(stub.sock, { port: 0, distDir: empty }), /npm run build:ui/, 'assets without an index.html is still no page')
  } finally {
    rmSync(empty, { recursive: true, force: true })
  }
})

test('U2: the shipped dist is what the server loads by default', () => {
  const dist = loadDist(new URL('../../src/ui/dist', import.meta.url).pathname)
  assert.ok(dist, 'src/ui/dist/index.html is missing; run npm run build:ui')
  const manifest = JSON.parse(readFileSync(new URL('../../src/ui/dist/manifest.json', import.meta.url), 'utf8'))
  for (const entry of Object.values(manifest)) {
    for (const f of [entry.file, ...(entry.css || []), ...(entry.assets || [])]) {
      assert.ok(dist.assets.has(f.replace(/^assets\//, '')), `${f} is in the manifest but would not be served`)
    }
  }
})
