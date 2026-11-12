// The in-app docs for wave 3, and the page as served.
//
// Each feature the page or the CLI gained is documented where a reader looks
// for it, with commands written through `${c.cli}` so they paste on this
// machine (and so a command added by another batch is never named here as a
// literal before it exists). The docs are the React sections in
// web/src/components/docs/sections.jsx; the page is the built bundle in
// src/ui/dist.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const read = (rel) => readFileSync(new URL(`${/^(web\/|src\/ui\/dist)/.test(rel) ? '../../../../' : '../../'}${rel}`, import.meta.url), 'utf8')

/** The docs sections' source, read as text. */
function docsSource() {
  return read('web/src/components/docs/sections.jsx')
}

const SRC = docsSource()
const LIST = [...SRC.matchAll(/\{ id: '([a-z]+)', title: '[^']+', Body: (\w+) \}/g)].map((m) => ({ id: m[1], body: m[2] }))

/**
 * One section: its Body function, plus what is declared between the previous
 * section's function and its own (the tool table before Connect, the command
 * reference before Commands).
 */
const section = (id) => {
  const i = LIST.findIndex((s) => s.id === id)
  assert.ok(i >= 0, `no ${id} section`)
  const end = (k) => {
    const start = SRC.indexOf(`\nfunction ${LIST[k].body}(`)
    assert.ok(start >= 0, `no ${LIST[k].body}()`)
    return SRC.indexOf('\n}\n', start) + 3
  }
  return SRC.slice(i === 0 ? 0 : end(i - 1), end(i))
}

test('the served page is one module script from the bundle, and nothing inline', () => {
  // The old page was one inline script that had to parse. The built page
  // loads exactly one module from /assets, named in the Vite manifest the
  // server's allowlist is read from, and carries no inline script or style
  // (U2: the policy has no 'unsafe-inline').
  const html = read('src/ui/dist/index.html')
  const manifest = JSON.parse(read('src/ui/dist/manifest.json'))
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
  assert.equal(scripts.length, 1, 'one script tag')
  const [, attrs, body] = scripts[0]
  assert.match(attrs, /\btype="module"/)
  assert.equal(body.trim(), '', 'the script tag carries no inline code')
  const src = /\bsrc="\/assets\/([^"]+)"/.exec(attrs)?.[1]
  assert.ok(src, 'the script is served from /assets')
  const entry = Object.values(manifest).find((e) => e.isEntry)
  assert.equal(entry?.file, `assets/${src}`, 'the script is the manifest entry')
  assert.ok(read(`src/ui/dist/assets/${src}`).length > 0)
  assert.doesNotMatch(html, /<style\b|\sstyle=|\son[a-z]+=/i, 'no inline style or handler')
})

test('containment and recovery covers every wave-3 safety feature', () => {
  const safety = section('safety')
  for (const heading of ['Narrow it instead', 'Panic', 'Quarantine a credential', 'Tripwires', 'Rotate a credential',
    'Know when a token runs out', 'Extra shapes to scrub, and pinned keys', 'Hear about it when something is waiting',
    'Review what each session did', 'Back up and restore', 'Keep a witness']) {
    assert.ok(safety.includes(`<H3>${heading}</H3>`), `safety has no "${heading}"`)
  }
  assert.ok(safety.includes('The backup is encrypted with a recovery passphrase that is not your vault passphrase. Sessions and placeholders are never backed up: after a restore, every agent needs a new session.'))
  assert.match(safety, /denial of service against your own work/, 'the trade panic and quarantine make is stated')
  assert.match(safety, /a witness file that an agent can write, it can truncate/, 'the witness limit is stated honestly')
  assert.match(safety, /0 \* \* \* \* \$\{c\.cli\} audit witness/, 'a cron line')
  for (const cmd of ['panic', 'cred quarantine', 'cred release', 'tripwire on', 'cred rotate', 'cred expiry', 'cred test',
    'cred scrub', 'cred pin', 'watch', 'notify set', 'session show', 'report', 'backup export', 'backup inspect',
    'backup restore', 'audit witness', 'audit verify --witness', 'session narrow']) {
    assert.ok(safety.includes(`\${c.cli} ${cmd}`), `safety never shows ${cmd}`)
  }
})

test('the agent tools are documented, read-only ones said to be so', () => {
  const connect = section('connect')
  assert.match(connect, /It gains nine tools/)
  // The tool list is MCP_TOOLS: [name, what it does], rendered "name — what".
  assert.match(connect, /\['vault_describe_access', '[^']*Read-only/)
  assert.match(connect, /\['vault_preflight', '[^']*Nothing is sent upstream and nothing is spent/)
  assert.match(connect, /\{what \? `— \$\{what\}`/, 'each tool is shown with what it does')
})

test('the new session limits and templates are explained where sessions are', () => {
  const start = section('start')
  for (const flag of ['--rate 60/min', '--concurrency 4', '--quota 1000/day', '--route GET:/repos/**', '--payload-file F',
    '--graphql query', '--spend-tokens', '--spend-usd', '--redirects 2', '--grant-ttl 30']) {
    assert.ok(start.includes(flag), `start never mentions ${flag}`)
  }
  assert.ok(start.includes('template save gh-read'))
  assert.ok(start.includes('session create --template gh-read'))
})

test('the commands section lists every command after wave 3 (A.5)', () => {
  const commands = section('commands')
  for (const cmd of ['cred rotate', 'cred test', 'cred expiry', 'cred scrub', 'cred pin', 'cred quarantine', 'session narrow',
    'session show', 'template save', 'template list', 'template show', 'template rm', 'preflight', 'watch', 'notify set',
    'panic', 'tripwire show', 'audit export', 'audit witness', 'report', 'backup export', '--template NAME', '--grant-ttl MIN']) {
    assert.ok(commands.includes(cmd), `commands does not list ${cmd}`)
  }
})
