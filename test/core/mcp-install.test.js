// These configs belong to other tools and usually already hold the user's own
// servers, so the properties worth pinning down are: merge rather than
// overwrite, stay idempotent, and never write a token to disk.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { AGENTS, targetPath, serverEntry, mergeJson, mergeToml, install } from '../../src/cli/mcp-install.js'

const STDIO = { command: '/usr/bin/node', args: ['/app/bin/agent-vault.js', 'mcp'] }

function scratch(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'av-mcp-'))
  try { return fn(dir) } finally { rmSync(dir, { recursive: true, force: true }) }
}

test('every agent declares a format and at least one scope', () => {
  for (const [name, spec] of Object.entries(AGENTS)) {
    assert.ok(spec.label, name)
    assert.ok(['json', 'toml'].includes(spec.format), name)
    assert.ok(spec.paths.project || spec.paths.user, name)
  }
})

test('paths land where each tool actually looks', () => {
  const at = { cwd: '/proj', home: '/home/me', env: {} }
  assert.equal(targetPath('claude-code', 'project', at), '/proj/.mcp.json')
  assert.equal(targetPath('claude-code', 'user', at), '/home/me/.claude.json')
  assert.equal(targetPath('cursor', 'project', at), '/proj/.cursor/mcp.json')
  assert.equal(targetPath('gemini', 'user', at), '/home/me/.gemini/settings.json')
  assert.equal(targetPath('codex', 'user', at), '/home/me/.codex/config.toml')
})

test('codex honours CODEX_HOME and offers no project scope', () => {
  assert.equal(
    targetPath('codex', 'user', { home: '/home/me', env: { CODEX_HOME: '/elsewhere/codex' } }),
    '/elsewhere/codex/config.toml',
  )
  assert.equal(AGENTS.codex.paths.project, undefined)
  assert.equal(AGENTS.codex.defaultScope, 'user')
})

test('an unknown agent is refused and the known ones are named', () => {
  assert.throws(() => targetPath('emacs', 'project'), /unknown agent[\s\S]*claude-code/)
})

test('merging JSON keeps unrelated settings and other servers', () => {
  const existing = JSON.stringify({
    theme: 'dark',
    mcpServers: { github: { command: 'gh-mcp', args: [] } },
  })
  const { text } = mergeJson(existing, { key: 'mcpServers', name: 'agent-vault', entry: STDIO })
  const doc = JSON.parse(text)
  assert.equal(doc.theme, 'dark')
  assert.ok(doc.mcpServers.github)
  assert.deepEqual(doc.mcpServers['agent-vault'], STDIO)
})

test('a second JSON merge reports unchanged and rewrites the same text', () => {
  const first = mergeJson('', { key: 'mcpServers', name: 'agent-vault', entry: STDIO })
  assert.equal(first.unchanged, false)
  const second = mergeJson(first.text, { key: 'mcpServers', name: 'agent-vault', entry: STDIO })
  assert.equal(second.unchanged, true)
  assert.equal(second.text, first.text)
})

test('a JSON file we cannot parse is refused rather than replaced', () => {
  assert.throws(
    () => mergeJson('{ trailing, }', { key: 'mcpServers', name: 'x', entry: STDIO }),
    /not valid JSON/,
  )
})

test('TOML merge appends a table and leaves comments and neighbours alone', () => {
  const existing = '# hand written\nmodel = "o3"\n\n[mcp_servers.other]\ncommand = "other"\n'
  const { text } = mergeToml(existing, { key: 'mcp_servers', name: 'agent-vault', entry: STDIO })
  assert.match(text, /# hand written/)
  assert.match(text, /model = "o3"/)
  assert.match(text, /\[mcp_servers\.other\]/)
  assert.match(text, /\[mcp_servers\.agent-vault\]/)
  assert.match(text, /args = \["\/app\/bin\/agent-vault\.js", "mcp"\]/)
})

test('a second TOML merge neither duplicates nor changes the table', () => {
  const once = mergeToml('', { key: 'mcp_servers', name: 'agent-vault', entry: STDIO })
  const twice = mergeToml(once.text, { key: 'mcp_servers', name: 'agent-vault', entry: STDIO })
  assert.equal(twice.unchanged, true)
  assert.equal(twice.text.match(/\[mcp_servers\.agent-vault\]/g).length, 1)
})

test('TOML merge replaces a stale table in place, keeping what follows', () => {
  const start = '[mcp_servers.agent-vault]\ncommand = "old"\n\n[mcp_servers.zzz]\ncommand = "keep"\n'
  const { text } = mergeToml(start, { key: 'mcp_servers', name: 'agent-vault', entry: STDIO })
  assert.ok(!text.includes('"old"'), 'the stale command should be gone')
  assert.match(text, /\[mcp_servers\.zzz\]\ncommand = "keep"/)
  assert.equal(text.match(/\[mcp_servers\.agent-vault\]/g).length, 1)
})

test('stdio writes no session token into the config', () => {
  const entry = serverEntry({ transport: 'stdio', ...STDIO })
  assert.deepEqual(entry, STDIO)
})

test('HTTP points at an environment variable instead of embedding the token', () => {
  const json = serverEntry({ transport: 'http', url: 'http://localhost:7411/mcp', format: 'json' })
  assert.equal(json.type, 'http')
  assert.match(json.headers.Authorization, /\$\{AGENT_VAULT_SESSION\}/)

  const toml = serverEntry({ transport: 'http', url: 'http://localhost:7411/mcp', format: 'toml' })
  assert.equal(toml.bearer_token_env_var, 'AGENT_VAULT_SESSION')
  assert.ok(!('headers' in toml), 'Codex takes bearer_token_env_var, not headers')
})

test('install merges, keeps a copy of the old file, and is idempotent', () => scratch((dir) => {
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { existing: { command: 'x' } } }))

  const first = install({ agent: 'claude-code', scope: 'project', entry: STDIO, cwd: dir, home: dir })
  assert.equal(first.wrote, true)
  assert.ok(existsSync(first.backup), 'the previous file should be kept')
  const doc = JSON.parse(readFileSync(first.path, 'utf8'))
  assert.ok(doc.mcpServers.existing, 'the existing server should survive')
  assert.deepEqual(doc.mcpServers['agent-vault'], STDIO)

  const second = install({ agent: 'claude-code', scope: 'project', entry: STDIO, cwd: dir, home: dir })
  assert.equal(second.unchanged, true)
}))

test('print mode shows the block and touches nothing', () => scratch((dir) => {
  const r = install({ agent: 'codex', entry: STDIO, print: true, cwd: dir, home: dir, env: {} })
  assert.equal(r.wrote, false)
  assert.equal(r.scope, 'user', 'codex defaults to its single user-level config')
  assert.ok(!existsSync(r.path), 'print should not create the file')
  assert.match(r.block, /\[mcp_servers\.agent-vault\]/)
}))

test('install creates the parent directory when the tool has never run', () => scratch((dir) => {
  const r = install({ agent: 'cursor', scope: 'project', entry: STDIO, cwd: dir, home: dir })
  assert.match(r.path, /\.cursor\/mcp\.json$/)
  assert.ok(existsSync(r.path))
}))

test('project scope produces a config that is portable', () => {
  // Project scope exists so the file can be committed for a team. An entry
  // naming this interpreter and this checkout by absolute path is committable
  // to nobody, which made the feature's own stated purpose false.
  const cli = readFileSync(new URL('../../src/cli/index.js', import.meta.url), 'utf8')
  assert.match(cli, /const portable = shim && scope === 'project'/,
    'project scope should prefer a shim on PATH')
  assert.match(cli, /command: portable \? shim : process\.execPath/,
    'and fall back to the interpreter only when there is no shim')

  // The shape itself carries no machine-specific path.
  const entry = serverEntry({ transport: 'stdio', command: 'agent-vault', args: ['mcp'] })
  const text = JSON.stringify(entry)
  assert.ok(!text.includes('/Users/'), 'a home directory leaked into a shared config')
  assert.ok(!text.includes('node_modules'), 'an install path leaked into a shared config')
  assert.deepEqual(entry, { command: 'agent-vault', args: ['mcp'] })
})
