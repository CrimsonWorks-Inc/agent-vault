// Contract U7: what the page's source and its built bundle may never contain.
//
// These read files rather than behaviour on purpose: an innerHTML that no test
// happens to reach is still an innerHTML, and a URL in the CSS is a request
// whether or not a test renders the rule that holds it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { join, extname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { listFiles } from '../scripts/compare-trees.mjs'

const WEB = fileURLToPath(new URL('..', import.meta.url))
const SRC = join(WEB, 'src')
const DIST = fileURLToPath(new URL('../../src/ui/dist', import.meta.url))
const read = (p) => readFileSync(p, 'utf8')
const sources = () => listFiles(SRC).filter((f) => /\.(jsx?|css|html)$/.test(f)).map((f) => ({ f, text: read(join(SRC, f)) }))

/** The source with comments and string-free test files left in; tests are part of web/src too. */
const FORBIDDEN = [
  ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
  ['innerHTML', /\binnerHTML\b/],
  ['outerHTML', /\bouterHTML\b/],
  ['insertAdjacentHTML', /insertAdjacentHTML/],
  ['document.write', /document\.write/],
  ['eval(', /(^|[^.\w])eval\s*\(/],
  ['new Function', /new\s+Function\s*\(/],
  ['setTimeout with a string', /setTimeout\(\s*['"`]/],
  ['javascript: URL', /javascript:/i],
]

test('web/src never renders markup from a string, or runs a string as code', () => {
  const hits = []
  for (const { f, text } of sources()) {
    if (f.endsWith('.test.jsx') || f.endsWith('.test.js')) continue
    for (const [name, re] of FORBIDDEN) if (re.test(text)) hits.push(`${f}: ${name}`)
  }
  assert.deepEqual(hits, [])
})

test('the tests do not use them either, except to prove they are absent', () => {
  for (const { f, text } of sources()) {
    if (!/\.test\.jsx?$/.test(f)) continue
    assert.ok(!/dangerouslySetInnerHTML=/.test(text), `${f} renders raw HTML`)
  }
})

test('no raw bidi or control characters hide in the source', () => {
  // A literal U+202E in a source file reorders what a reviewer reads (the
  // "trojan source" trick). Escapes like \u202e are fine; the characters are not.
  const bad = /[\u202a-\u202e\u2066-\u2069\u2028\u2029\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/
  for (const { f, text } of sources()) assert.ok(!bad.test(text), `${f} holds a raw bidi or control character`)
  for (const f of listFiles(join(WEB, 'test'))) assert.ok(!bad.test(read(join(WEB, 'test', f))), `test/${f} holds a raw bidi or control character`)
})

test('nothing the page stores in the browser can hold a token or a placeholder', () => {
  // Storage is for page conveniences only: the theme, the page size, whether
  // notifications are on. Each write's key is one of these constants.
  const allowed = new Set(['THEME_KEY', 'NOTIFY_KEY', 'key'])
  for (const { f, text } of sources()) {
    if (/\.test\.jsx?$/.test(f)) continue
    assert.ok(!/sessionStorage/.test(text), `${f} uses sessionStorage`)
    for (const m of text.matchAll(/setItem\(\s*([^,]+),/g)) {
      assert.ok(allowed.has(m[1].trim()), `${f} writes storage under ${m[1].trim()}`)
    }
  }
  const paging = read(join(SRC, 'lib/paging.js'))
  assert.match(paging, /storage\?\.setItem\(key, String\(clampLimit\(n\)\)\)/, 'the page size is the only value stored under a caller key')
})

test('every agent-written field the Overview shows goes through UntrustedText', () => {
  for (const { f, text } of sources()) {
    if (/\.test\.jsx?$/.test(f)) continue
    for (const m of text.matchAll(/\{[^{}]*_untrusted[^{}]*\}/g)) {
      assert.match(m[0], /UntrustedText|text=/, `${f} shows ${m[0]} outside UntrustedText`)
    }
  }
})

// ---- the built page ---------------------------------------------------------

const html = () => read(join(DIST, 'index.html'))

test('the built index.html has no inline script or style, and loads only its own assets', () => {
  assert.ok(existsSync(join(DIST, 'index.html')), 'run npm run build:ui')
  const page = html()
  for (const m of page.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    assert.match(m[1], /\bsrc="\/assets\/[\w.-]+\.js"/, 'every script is a file from /assets')
    assert.equal(m[2].trim(), '', 'no inline script')
  }
  assert.ok(!/<style\b/i.test(page), 'no inline <style>')
  assert.ok(!/\sstyle=/i.test(page), 'no style attributes')
  assert.ok(!/\son[a-z]+=/i.test(page), 'no inline event handlers')
  for (const m of page.matchAll(/\s(?:src|href)="([^"]*)"/gi)) {
    assert.match(m[1], /^\/assets\/[\w.-]+$/, `${m[1]} is not one of the page's own assets`)
  }
})

test('no third-party request: no http(s) URL in the page or its CSS except in comments', () => {
  assert.ok(!/https?:\/\//i.test(html()), 'index.html names an external URL')
  for (const f of listFiles(DIST).filter((x) => x.endsWith('.css'))) {
    const css = read(join(DIST, f)).replace(/\/\*[\s\S]*?\*\//g, '')
    assert.ok(!/https?:\/\//i.test(css), `${f} names an external URL`)
    assert.ok(!/@import/i.test(css), `${f} imports another stylesheet`)
    for (const m of css.matchAll(/url\(\s*['"]?([^'")]+)/g)) {
      assert.match(m[1], /^(\/assets\/[\w.-]+|data:)/, `${f} loads ${m[1]}`)
    }
  }
})

test('the bundle runs no string as code, and its raw-HTML paths are only React\'s own', () => {
  const js = listFiles(DIST).filter((x) => x.endsWith('.js'))
  assert.ok(js.length >= 1)
  const reactDom = read(fileURLToPath(new URL('../../node_modules/react-dom/cjs/react-dom-client.production.js', import.meta.url)))
  const count = (text, re) => (text.match(re) || []).length
  for (const f of js) {
    const text = read(join(DIST, f))
    assert.equal(count(text, /new Function\s*\(/g), 0, `${f} constructs a Function`)
    assert.equal(count(text, /(^|[^.\w$])eval\s*\(/g), 0, `${f} calls eval`)
    // React DOM's renderer carries both names (to apply the prop, and to warn
    // about it). The page adds none, so the bundle has no more than React has.
    for (const name of [/dangerouslySetInnerHTML/g, /\binnerHTML\b/g]) {
      assert.ok(count(text, name) <= count(reactDom, name), `${f} has more ${name.source} than react-dom itself`)
    }
  }
})

test('the dist is only what the server may serve: no sourcemaps, every asset in the manifest', () => {
  const files = listFiles(DIST)
  assert.ok(!files.some((f) => f.endsWith('.map')), 'a sourcemap would ship the source')
  const allowed = new Set(['.html', '.json', '.js', '.css', '.woff2', '.svg'])
  for (const f of files) assert.ok(allowed.has(extname(f)), `${f} is not a type the page needs`)
  const manifest = JSON.parse(read(join(DIST, 'manifest.json')))
  const named = new Set()
  for (const entry of Object.values(manifest)) {
    named.add(entry.file)
    for (const a of entry.assets || []) named.add(a)
    for (const c of entry.css || []) named.add(c)
  }
  for (const f of files.filter((x) => x.startsWith('assets/'))) assert.ok(named.has(f), `${f} is not in manifest.json`)
})
