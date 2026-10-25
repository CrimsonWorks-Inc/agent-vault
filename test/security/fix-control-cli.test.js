// The command line, run for real against a temp vault.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync, existsSync, mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { parseOverrides } from '../../src/pending.js'
import { startDaemon, cli, BIN, PASSPHRASE } from './fix-control-helpers.js'

const withCliDaemon = (opts = {}) => startDaemon({ socketName: 'control.sock', ...opts })

test('the printed try: command carries the token where it cannot collide with the placeholder', async () => {
  const d = await withCliDaemon()
  try {
    const r = await cli(d.dir, ['session', 'create', '--cred', 'demo'])
    assert.equal(r.code, 0, r.stderr)
    const tryLines = r.stdout.slice(r.stdout.indexOf('try:'))
    const auth = tryLines.match(/-H "Authorization:/g) || []
    assert.ok(auth.length <= 1, `two Authorization headers: the second is dropped:\n${tryLines}`)
    assert.match(tryLines, /-H "AV-Session: avs1\./)
    assert.match(tryLines, /-H "Authorization: Bearer av1\./, 'and the placeholder still goes at its site')
  } finally { await d.stop() }
})

test('listen add asks for the passphrase like every other gated command', async () => {
  const d = await withCliDaemon({ passphrase: PASSPHRASE })
  try {
    const r = await cli(d.dir, ['listen', 'add', 't1', '--address', '127.0.0.1:7499', '--surfaces', 'mcp'])
    assert.notEqual(r.code, 0)
    // Without a terminal it cannot ask — and says that, instead of telling the
    // reader to run it again when running it again fails the same way.
    assert.match(r.stderr, /no terminal to ask on/, r.stderr)
  } finally { await d.stop() }
})

test('the TLS listener port is the same everywhere it is written', () => {
  const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8')
  for (const file of ['README.md', 'src/ui/app.html', 'src/cli/index.js']) {
    assert.ok(!read(file).includes('7449'), `${file} still names 7449; the code binds 7443`)
  }
})

test('env quotes what it exports, and refuses what a token or placeholder cannot be', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-env-'))
  const pwned = join(dir, 'pwned')
  try {
    writeFileSync(join(dir, 'cli-state.json'), JSON.stringify({
      token: `avs1.x.y; touch ${pwned}-token #`,
      placeholder: `$(touch ${pwned}-ph)`,
    }))
    const r = await cli(dir, ['env'])
    // A value that is not shaped like a token is not a token: nothing to export.
    assert.notEqual(r.code, 0, `exported a planted token: ${r.stdout}`)
    assert.ok(!r.stdout.includes('touch'), r.stdout)
    spawnSync('sh', ['-c', `eval "$1"`, 'sh', r.stdout], { encoding: 'utf8' })
    assert.ok(!existsSync(`${pwned}-token`), 'a planted token ran a command')
    assert.ok(!existsSync(`${pwned}-ph`), 'a planted placeholder ran a command')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('env exports a real session faithfully', async () => {
  const d = await withCliDaemon()
  try {
    const created = await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])
    const s = JSON.parse(created.stdout).data
    const r = await cli(d.dir, ['env'])
    assert.equal(r.code, 0, r.stderr)
    const shown = spawnSync('sh', ['-c', 'eval "$1"; printf "%s\\n%s\\n%s\\n%s" "$AGENT_VAULT_SESSION" "$AGENT_VAULT_PLACEHOLDER" "$AGENT_VAULT_URL" "$AGENT_VAULT_HINT"', 'sh', r.stdout], { encoding: 'utf8' })
    const [token, placeholder, url, hint] = shown.stdout.split('\n')
    assert.match(hint, /^Credentials are placeholders\. .*agent-vault ph next <cred>$/, 'a value with spaces survives eval whole')
    assert.equal(token, s.token)
    assert.equal(placeholder, s.placeholder)
    assert.equal(url, `http://127.0.0.1:${d.daemon.gatewayPort}`, 'the URL names the port the session was made on')
  } finally { await d.stop() }
})

test('env and mcp url follow the session to a non-default port', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-port-'))
  try {
    writeFileSync(join(dir, 'cli-state.json'), JSON.stringify({
      session_id: 'abcdefghijkl', token: 'avs1.abcdefghijkl.c2VjcmV0',
      base_url: 'http://127.0.0.1:7420/p/demo',
    }))
    const env = await cli(dir, ['env'])
    assert.match(env.stdout, /AGENT_VAULT_URL='?http:\/\/127\.0\.0\.1:7420'?/)
    const url = await cli(dir, ['mcp', 'url'])
    assert.match(url.stdout, /http:\/\/127\.0\.0\.1:7420\/mcp/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('narrowing flags split and normalise the way every other input does', () => {
  assert.deepEqual(parseOverrides({ paths: '/a/**,/b/**', methods: 'get, post' }), {
    paths: ['/a/**', '/b/**'], methods: ['GET', 'POST'],
  })
  assert.deepEqual(parseOverrides({ paths: ['/a/**'], methods: 'GET', budget: '5' }), {
    paths: ['/a/**'], methods: ['GET'], budget: 5,
  })
})

test('exec drops real credentials from the child environment, and keeps the rest', async () => {
  const d = await withCliDaemon()
  try {
    await cli(d.dir, ['session', 'create', '--cred', 'demo'])
    const planted = {
      AWS_SECRET_ACCESS_KEY: 'x', STRIPE_SECRET_KEY: 'x', STRIPE_KEY: 'x', github_token: 'x',
      AZURE_CLIENT_SECRET: 'x', OPENAI_APIKEY: 'x', DATABASE_URL: 'postgres://user:hunter2@db.example/app',
      EDITOR: 'vi', KEEP_ME: 'yes', DOCS_URL: 'https://example.com/docs',
    }
    const r = await cli(d.dir, ['exec', '--', process.execPath, '-e', 'console.log(JSON.stringify(Object.keys(process.env)))'], { env: planted })
    assert.equal(r.code, 0, r.stderr)
    const keys = JSON.parse(r.stdout.trim().split('\n').pop())
    for (const k of ['AWS_SECRET_ACCESS_KEY', 'STRIPE_SECRET_KEY', 'STRIPE_KEY', 'github_token', 'AZURE_CLIENT_SECRET', 'OPENAI_APIKEY', 'DATABASE_URL']) {
      assert.ok(!keys.includes(k), `${k} reached the child`)
    }
    for (const k of ['EDITOR', 'KEEP_ME', 'DOCS_URL', 'PATH', 'AGENT_VAULT_SESSION']) assert.ok(keys.includes(k), `${k} was dropped`)
  } finally { await d.stop() }
})

test('exec reports a child killed by a signal as a failure, and a missing binary as an error', async () => {
  const d = await withCliDaemon()
  try {
    await cli(d.dir, ['session', 'create', '--cred', 'demo'])
    const killed = await cli(d.dir, ['exec', '--', process.execPath, '-e', 'process.kill(process.pid, "SIGTERM")'])
    assert.notEqual(killed.code, 0, 'a signal-killed child reported success')
    const missing = await cli(d.dir, ['exec', '--', 'definitely-not-a-command-av-fc'])
    assert.notEqual(missing.code, 0)
    assert.match(missing.stderr, /definitely-not-a-command-av-fc/)
    const ok = await cli(d.dir, ['exec', '--', process.execPath, '-e', 'process.exit(3)'])
    assert.equal(ok.code, 3, 'an ordinary exit code passes through')
  } finally { await d.stop() }
})

test('the stdio bridge heals from a dead launch token once a new session is recorded', async () => {
  const d = await withCliDaemon()
  try {
    const old = JSON.parse((await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])).stdout).data
    assert.match(old.token, /^avs1\./)
    await cli(d.dir, ['session', 'revoke', old.session_id])
    await cli(d.dir, ['session', 'create', '--cred', 'demo']) // the human makes a new one
    const child = spawn(process.execPath, [BIN, 'mcp'], {
      env: { ...process.env, AGENT_VAULT_DIR: d.dir, AGENT_VAULT_SESSION: old.token, NO_COLOR: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    const reply = new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`no reply: ${out}`)), 10_000)
      child.stdout.on('data', () => { if (out.includes('\n')) { clearTimeout(t); resolve(JSON.parse(out.split('\n')[0])) } })
    })
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'vault_list_creds', arguments: {} } })}\n`)
    const r = await reply
    child.kill()
    assert.ok(!r.result?.isError, `still on the dead session: ${JSON.stringify(r).slice(0, 300)}`)
    assert.match(r.result.content[0].text, /"slug": "demo"/)
  } finally { await d.stop() }
})

test('agent-vault ui warns when its page is on an origin the daemon does not trust', async () => {
  const d = await withCliDaemon()
  try {
    const child = spawn(process.execPath, [BIN, 'ui', '--no-open', '--port', '0'], {
      env: { ...process.env, AGENT_VAULT_DIR: d.dir, NO_COLOR: '1' }, stdio: ['pipe', 'pipe', 'pipe'],
    })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`no output: ${out}`)), 10_000)
      child.stdout.on('data', () => { if (/trusted UI origin|Ctrl-C/.test(out)) { clearTimeout(t); resolve() } })
    })
    await new Promise((r) => setTimeout(r, 200))
    child.kill()
    assert.match(out, /not a trusted UI origin/, out)
  } finally { await d.stop() }
})

test('a fresh-presence change on a vault with no factor says to set one, and exits 5', async () => {
  const d = await withCliDaemon()
  try {
    const r = await cli(d.dir, ['ui', '--no-open', '--port', '0', '--allow-origin'])
    assert.equal(r.code, 5, `${r.stdout}\n${r.stderr}`)
    assert.match(r.stderr, /agent-vault passphrase set/)
  } finally { await d.stop() }
})
