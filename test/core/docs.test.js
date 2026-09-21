// Docs rot silently. These tests fail when the code grows something the docs
// do not mention, which is the only way a docs page stays true a year later.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { CODES } from '../../src/core/errors.js'
import { AGENTS } from '../../src/cli/mcp-install.js'
import { PROFILES } from '../../src/connectors/profiles.js'

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8')
const app = read('../../src/ui/app.html')
const cli = read('../../src/cli/index.js')
const readme = read('../../README.md')

/** The section ids the docs page defines, in order. */
const sections = [...app.matchAll(/^\s*id: '([a-z]+)',\n\s*title: '/gm)].map((m) => m[1])

test('the docs page defines the sections it advertises', () => {
  assert.ok(sections.length >= 6, `found only ${sections.length} docs sections`)
  assert.ok(sections.includes('connect'), 'connecting an agent is the whole point')
  assert.ok(sections.includes('refused'), 'a reader hitting a denial needs somewhere to go')
})

test('the docs command can reach every section of the page', () => {
  // `agent-vault docs <section>` opens the page at a fragment. A section the
  // CLI does not know is a section nobody can link to.
  const listed = cli.match(/const sections = \[([^\]]+)\]/)
  assert.ok(listed, 'the docs command should keep its section list in one place')
  const known = [...listed[1].matchAll(/'([a-z]+)'/g)].map((m) => m[1])
  assert.deepEqual(known, sections, 'the CLI and the docs page disagree about the sections')
})

test('every denial a caller can hit is explained in the docs', () => {
  // These four mean something is broken rather than something was decided, and
  // carry their own hint at the point of failure.
  const internal = new Set(['AV_INTERNAL', 'AV_NOT_FOUND', 'AV_MCP_PROTOCOL', 'AV_MCP_SESSION_UNKNOWN'])
  const missing = Object.keys(CODES).filter((c) => !internal.has(c) && !app.includes(`'${c}'`))
  assert.deepEqual(missing, [], `these denials have no entry in the docs table: ${missing.join(', ')}`)
})

test('the docs name every agent mcp install can configure', () => {
  const connect = app.slice(app.indexOf("id: 'connect'"), app.indexOf("id: 'models'"))
  for (const agent of Object.keys(AGENTS)) {
    assert.ok(connect.includes(agent), `mcp install supports ${agent} but the docs never say so`)
  }
})

test('the docs route every model profile that declares environment variables', () => {
  const models = app.slice(app.indexOf("id: 'models'"), app.indexOf("id: 'locking'"))
  // A profile with a base-url env var is one an SDK can be pointed at the vault
  // without touching its code, which is exactly what that section is for.
  const routable = Object.entries(PROFILES).filter(([, p]) => p.env)
  assert.ok(routable.length, 'no profile declares env vars; the section has nothing to document')
  for (const [kind, p] of routable) {
    assert.ok(models.includes(kind), `${kind} can be routed but the docs do not show how`)
    assert.ok(models.includes(p.env.base), `${kind} routing needs ${p.env.base}`)
    assert.ok(models.includes(p.env.key), `${kind} routing needs ${p.env.key}`)
  }
})

test('the mark in the page matches the one in mark.svg', () => {
  // The keyhole geometry lives in two files: mark.svg, and inline in the page's
  // brand block. Two copies of a shape drift, and a logo that is subtly
  // different in the sidebar than in the icon is worse than no logo.
  const mark = read('../../src/ui/mark.svg')
  const path = /d="(M28\.8[^"]+)"/.exec(mark)
  assert.ok(path, 'mark.svg should hold the keyhole path')
  assert.ok(app.includes(path[1]), 'the page and mark.svg disagree about the mark')
  assert.ok(app.includes('circle cx="32" cy="25" r="8.5"'), 'and about the bow')
})

test('the page carries a favicon that is well-formed', () => {
  const link = /<link rel="icon" href="data:image\/svg\+xml,([^"]+)">/.exec(app)
  assert.ok(link, 'the UI should have a favicon')
  const svg = decodeURIComponent(link[1])
  assert.match(svg, /^<svg /)
  assert.match(svg, /<\/svg>$/)
  // It cannot use currentColor — nothing sets a colour on a favicon — so it
  // carries both themes itself.
  assert.match(svg, /prefers-color-scheme:dark/)
})

test('the readme points at the docs page rather than duplicating it', () => {
  assert.match(readme, /agent-vault docs/, 'the readme should send the reader to the docs command')
})

test('a connector whose proxy is not built is marked as such', () => {
  // The postgres profile describes a design; the L4 proxy that would carry it
  // does not exist. Storing a credential against it would hand the agent a
  // placeholder that can only misfire — the HTTP path would try to send a
  // database password as URL userinfo to a Postgres port — while the human
  // believed the credential was being protected.
  const unimplemented = Object.entries(PROFILES).filter(([, p]) => p.implemented === false)
  assert.ok(unimplemented.length, 'postgres should still be marked unimplemented')
  for (const [kind] of unimplemented) {
    assert.match(readme, new RegExp(kind, 'i'), `${kind} should be named in the readme's limits`)
  }
  // And the daemon must refuse it rather than storing a secret it cannot use.
  const daemonSrc = read('../../src/daemon/server.js')
  assert.match(daemonSrc, /implemented === false/, 'the daemon must refuse unimplemented connectors')
  assert.match(daemonSrc, /not implemented yet/, 'and say so plainly')
})
