// The state that lives on the human's side of the boundary.
//
// It holds capabilities and never a secret: a session token, the placeholder
// issued with it, the gateway port. The vault stores only `token_hash`, so a
// token's plaintext exists exactly once — at the moment the session is created
// — and nothing can ever hand it back. Whoever creates a session is therefore
// the only thing that can record it, which is why this is shared rather than
// owned by one surface.
//
// It was owned by the CLI, and the UI wrote nothing. So a session created in
// the UI existed in the vault and on the screen and nowhere else, while the
// MCP stdio bridge went on reading the CLI's copy — which, on a machine where
// the CLI had created a session days earlier, was a token that had since
// expired. Not "no session": confidently the wrong one. The UI's own docs page
// said "the bridge finds your current session from the CLI's own state", which
// is true only if the CLI made it.
//
// The file is still called cli-state.json. Renaming it would strand the state
// of every existing install for the sake of a tidier name.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'

/**
 * Follows AGENT_VAULT_DIR so a dev or test vault stays self-contained.
 *
 * Every writer passes its own path explicitly rather than relying on this. A
 * process that derives the location from the environment writes to whichever
 * vault the environment names, which is not necessarily the vault it is
 * serving — the UI server, handed a socket path for one vault, wrote state for
 * another. That is a data-loss bug waiting for anyone who runs two vaults, and
 * it cost the author a live state file to discover.
 */
export function stateDir() {
  return process.env.AGENT_VAULT_DIR || join(homedir(), '.agent-vault')
}
export function statePath(dir = stateDir()) {
  return join(dir, 'cli-state.json')
}

export function loadState(path = statePath()) {
  let raw
  try {
    raw = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {}
  } catch {
    // A truncated or hand-edited file must not take the CLI down. Everything
    // in here is recoverable by creating a session again.
    return {}
  }
  if (!raw || typeof raw !== 'object') return {}
  // This file holds no secrets by design, so it lives in the human's home
  // directory and anything running as them can edit it — including an agent.
  // The port went straight into `http://127.0.0.1:${port}/...`, so a value of
  // `1@attacker.example` made `127.0.0.1:1` the userinfo and the attacker's
  // name the HOST. `agent-vault env` then exported that URL, and the session
  // token with it, to somewhere else entirely — and it kept working long after
  // the agent that wrote it was gone.
  if (raw.gateway_port !== undefined) {
    const port = Number(raw.gateway_port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) delete raw.gateway_port
    else raw.gateway_port = port
  }
  return raw
}

export function saveState(patch, path = statePath()) {
  const dir = dirname(path)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 })
  const current = loadState(path)
  writeFileSync(path, JSON.stringify({ ...current, ...patch }, null, 2), { mode: 0o600 })
}

/**
 * Record a session so every local client can find it — the CLI, `env`, and the
 * MCP stdio bridge, which reads this file and has no other way to learn a
 * token. Called by whichever surface created the session.
 */
export function rememberSession({ session_id: sessionId, token, placeholder, base_url: baseUrl }, path = statePath()) {
  if (!token) return
  saveState({
    session_id: sessionId,
    token,
    ...(placeholder ? { placeholder } : {}),
    ...(baseUrl ? { base_url: baseUrl } : {}),
  }, path)
}
