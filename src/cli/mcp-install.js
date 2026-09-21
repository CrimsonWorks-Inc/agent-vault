// Writing MCP server config into the agent's own config file.
//
// Every one of these files belongs to another tool and usually has the user's
// other servers in it, so the rules are: merge, never clobber; back up before
// touching; and be idempotent so running it twice is a no-op rather than a
// duplicate. `--print` shows the exact block without writing anything.
//
// Formats verified against each tool's own documentation:
//   Claude Code  .mcp.json / ~/.claude.json        { mcpServers: { name: {...} } }
//   Cursor       .cursor/mcp.json                  same shape
//   Gemini CLI   .gemini/settings.json             same shape, inside other settings
//   Codex CLI    .codex/config.toml                [mcp_servers.name] TOML table

import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs'
import { dirname, join, isAbsolute } from 'node:path'
import { homedir } from 'node:os'

export const AGENTS = {
  'claude-code': {
    label: 'Claude Code',
    format: 'json',
    key: 'mcpServers',
    paths: { project: '.mcp.json', user: '.claude.json' },
    notes: {
      project: 'Project scope puts it in .mcp.json, which you can commit for your team.',
      user: 'User scope makes it available in every project on this machine.',
    },
  },
  cursor: {
    label: 'Cursor',
    format: 'json',
    key: 'mcpServers',
    paths: { project: '.cursor/mcp.json', user: '.cursor/mcp.json' },
  },
  gemini: {
    label: 'Gemini CLI',
    format: 'json',
    key: 'mcpServers',
    paths: { project: '.gemini/settings.json', user: '.gemini/settings.json' },
    notes: { project: 'Merged into your existing Gemini settings; other keys are left alone.',
             user: 'Merged into your existing Gemini settings; other keys are left alone.' },
  },
  codex: {
    label: 'Codex CLI',
    format: 'toml',
    key: 'mcp_servers',
    // Codex reads one config file, in CODEX_HOME (default ~/.codex), so there
    // is no project scope to offer.
    paths: { user: '.codex/config.toml' },
    defaultScope: 'user',
    notes: { user: 'Codex picks stdio when `command` is present and HTTP when `url` is.' },
  },
}

/** Where the config for this agent and scope lives. */
export function targetPath(agent, scope, { cwd = process.cwd(), home = homedir(), env = process.env } = {}) {
  const spec = AGENTS[agent]
  if (!spec) throw new Error(`unknown agent: ${agent}. Known: ${Object.keys(AGENTS).join(', ')}`)
  const rel = spec.paths[scope]
  if (!rel) throw new Error(`${spec.label} has no ${scope} scope`)
  if (agent === 'codex' && env.CODEX_HOME) return join(env.CODEX_HOME, 'config.toml')
  return isAbsolute(rel) ? rel : join(scope === 'user' ? home : cwd, rel)
}

/**
 * The server definition to insert.
 *
 * stdio is the default and the safer one: the bridge resolves the session from
 * the CLI's own state, so no token is written into a config file at all. HTTP
 * needs the token, and where the tool supports it we reference an environment
 * variable instead of embedding the value.
 */
export function serverEntry({ transport = 'stdio', command, args = [], url, tokenEnv = 'AGENT_VAULT_SESSION', format = 'json' }) {
  if (transport === 'http') {
    if (format === 'toml') return { url, bearer_token_env_var: tokenEnv }
    return { type: 'http', url, headers: { Authorization: `Bearer \${${tokenEnv}}` } }
  }
  return { command, args }
}

/** Merge a server into a JSON config, leaving every other key untouched. */
export function mergeJson(existingText, { key, name, entry }) {
  let doc = {}
  if (existingText && existingText.trim()) {
    try {
      doc = JSON.parse(existingText)
    } catch (e) {
      throw new Error(`the existing file is not valid JSON (${e.message}); fix or move it first`)
    }
    if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
      throw new Error('the existing file is not a JSON object')
    }
  }
  const servers = { ...(doc[key] || {}) }
  const already = JSON.stringify(servers[name]) === JSON.stringify(entry)
  servers[name] = entry
  return { text: `${JSON.stringify({ ...doc, [key]: servers }, null, 2)}\n`, unchanged: already }
}

/**
 * Merge a server into a TOML config by replacing or appending its table.
 *
 * Deliberately text-level rather than a full TOML round-trip: a parser that
 * rewrites the whole file would reformat and drop comments from a config the
 * user maintains by hand.
 */
export function mergeToml(existingText, { key, name, entry }) {
  const header = `[${key}.${name}]`
  const block = renderTomlTable(key, name, entry)
  const text = existingText || ''

  // Find an existing table for this server and the extent of its body, which
  // runs until the next top-level table header.
  const lines = text.split('\n')
  const start = lines.findIndex((l) => l.trim() === header)
  if (start === -1) {
    const joined = text.trimEnd()
    return { text: `${joined ? `${joined}\n\n` : ''}${block}`, unchanged: false }
  }
  let end = start + 1
  while (end < lines.length && !/^\s*\[/.test(lines[end])) end++
  // A sub-table like [mcp_servers.name.env] belongs to this server too.
  while (end < lines.length && lines[end].trim().startsWith(`[${key}.${name}.`)) {
    end++
    while (end < lines.length && !/^\s*\[/.test(lines[end])) end++
  }
  const current = lines.slice(start, end).join('\n').trim()
  const replaced = [...lines.slice(0, start), ...block.trimEnd().split('\n'), ...lines.slice(end)]
  return { text: `${replaced.join('\n').trimEnd()}\n`, unchanged: current === block.trim() }
}

function tomlValue(v) {
  if (Array.isArray(v)) return `[${v.map(tomlValue).join(', ')}]`
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return JSON.stringify(String(v))
}

function renderTomlTable(key, name, entry) {
  const lines = [`[${key}.${name}]`]
  const sub = []
  for (const [k, v] of Object.entries(entry)) {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      sub.push(`\n[${key}.${name}.${k}]`)
      for (const [ek, ev] of Object.entries(v)) sub.push(`${ek} = ${tomlValue(ev)}`)
      continue
    }
    lines.push(`${k} = ${tomlValue(v)}`)
  }
  return `${[...lines, ...sub].join('\n')}\n`
}

/**
 * Write the server into the agent's config.
 * @returns {{path, block, wrote, unchanged, backup}}
 */
export function install({ agent, scope, name = 'agent-vault', entry, print = false, cwd, home, env }) {
  const spec = AGENTS[agent]
  if (!spec) throw new Error(`unknown agent: ${agent}. Known: ${Object.keys(AGENTS).join(', ')}`)
  scope = scope || spec.defaultScope || 'project'
  const path = targetPath(agent, scope, { cwd, home, env })
  const existing = existsSync(path) ? readFileSync(path, 'utf8') : ''

  const merged = spec.format === 'toml'
    ? mergeToml(existing, { key: spec.key, name, entry })
    : mergeJson(existing, { key: spec.key, name, entry })

  const block = spec.format === 'toml'
    ? renderTomlTable(spec.key, name, entry)
    : `${JSON.stringify({ [spec.key]: { [name]: entry } }, null, 2)}\n`

  if (print) return { path, scope, block, wrote: false, unchanged: merged.unchanged, backup: null }

  let backup = null
  if (existing) {
    // Keep a copy before editing someone else's config file.
    backup = `${path}.agent-vault-bak`
    copyFileSync(path, backup)
  }
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, merged.text, { mode: 0o600 })
  return { path, scope, block, wrote: true, unchanged: merged.unchanged, backup }
}
