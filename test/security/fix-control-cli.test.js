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

// Round 2. The whole AGENT_VAULT prefix was exempt from the scrub, so
// AGENT_VAULT_SECRET went straight through; and a URL password with an empty
// user part — the usual Redis form — did not count as a password.
test('exec drops vault-prefixed secrets and user-less URL passwords', async () => {
  const d = await withCliDaemon()
  try {
    await cli(d.dir, ['session', 'create', '--cred', 'demo'])
    const planted = {
      AGENT_VAULT_SECRET: 'synthetic-av-secret', AGENT_VAULT_PASSWORD: 'synthetic-av-password',
      CACHE_URL: 'redis://:synthetic-redis-password@localhost:6379',
      QUEUE: 'amqps://:synthetic-amqp-password@mq.example:5671/vhost',
    }
    const r = await cli(d.dir, ['exec', '--', process.execPath, '-e', 'console.log(JSON.stringify(process.env))'], { env: planted })
    assert.equal(r.code, 0, r.stderr)
    const seen = JSON.parse(r.stdout.trim().split('\n').pop())
    for (const k of Object.keys(planted)) assert.ok(!(k in seen), `${k} reached the child`)
    assert.ok(!r.stdout.includes('synthetic-'), 'a planted value reached the child under some name')
  } finally { await d.stop() }
})

test('exec keeps the vault settings and URLs with no password in them', async () => {
  const d = await withCliDaemon()
  try {
    await cli(d.dir, ['session', 'create', '--cred', 'demo'])
    const kept = {
      AGENT_VAULT_PORT: '7420', REDIS_URL: 'redis://localhost:6379/0', API_BASE: 'http://[::1]:8080/v1',
      GIT_REMOTE: 'https://git@github.com/org/repo.git', NOTE: 'meet me @ 10:30 http://x/y',
    }
    const r = await cli(d.dir, ['exec', '--', process.execPath, '-e', 'console.log(JSON.stringify(process.env))'], { env: kept })
    assert.equal(r.code, 0, r.stderr)
    const seen = JSON.parse(r.stdout.trim().split('\n').pop())
    for (const [k, v] of Object.entries(kept)) assert.equal(seen[k], v, `${k} was dropped or changed`)
    assert.equal(seen.AGENT_VAULT_DIR, d.dir, 'the vault directory is a setting, not a secret')
    assert.match(seen.AGENT_VAULT_SESSION, /^avs1\./)
  } finally { await d.stop() }
})

/** Two sessions, with the state left holding the second token and no placeholder. */
async function tokenOnlyAfterAnother(d) {
  const first = JSON.parse((await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])).stdout).data
  const second = JSON.parse((await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])).stdout).data
  const path = join(d.dir, 'cli-state.json')
  const st = JSON.parse(readFileSync(path, 'utf8'))
  assert.equal(st.token, second.token, 'the fixture records the second session')
  delete st.placeholder
  writeFileSync(path, JSON.stringify(st))
  assert.match(first.placeholder, /^av1\./)
  return { first, second }
}

test('exec does not pass on a placeholder inherited from an earlier session', async () => {
  const d = await withCliDaemon()
  try {
    const { first, second } = await tokenOnlyAfterAnother(d)
    const r = await cli(d.dir, ['exec', '--', process.execPath, '-e', 'console.log(JSON.stringify(process.env))'], {
      env: { AGENT_VAULT_PLACEHOLDER: first.placeholder, AGENT_VAULT_SESSION: first.token, AGENT_VAULT_URL: 'http://127.0.0.1:1/' },
    })
    assert.equal(r.code, 0, r.stderr)
    const seen = JSON.parse(r.stdout.trim().split('\n').pop())
    assert.equal(seen.AGENT_VAULT_PLACEHOLDER, undefined, 'the old session\'s placeholder rode along')
    assert.equal(seen.AGENT_VAULT_SESSION, second.token)
    assert.notEqual(seen.AGENT_VAULT_URL, 'http://127.0.0.1:1/')
  } finally { await d.stop() }
})

test('env output clears a placeholder the shell already holds when there is none now', async () => {
  const d = await withCliDaemon()
  try {
    const { first } = await tokenOnlyAfterAnother(d)
    const r = await cli(d.dir, ['env'])
    assert.equal(r.code, 0, r.stderr)
    const shown = spawnSync('sh', ['-c', 'eval "$1"; printf "[%s]" "${AGENT_VAULT_PLACEHOLDER-unset}"', 'sh', r.stdout], {
      encoding: 'utf8', env: { ...process.env, AGENT_VAULT_PLACEHOLDER: first.placeholder },
    })
    assert.equal(shown.stdout, '[unset]', 'an earlier session\'s placeholder survived the eval')
  } finally { await d.stop() }
})

test('exec and env still deliver the current placeholder when there is one', async () => {
  const d = await withCliDaemon()
  try {
    const s = JSON.parse((await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])).stdout).data
    const r = await cli(d.dir, ['exec', '--', process.execPath, '-e', 'console.log(process.env.AGENT_VAULT_PLACEHOLDER)'], {
      env: { AGENT_VAULT_PLACEHOLDER: 'av1.stale' },
    })
    assert.equal(r.stdout.trim().split('\n').pop(), s.placeholder)
    const env = await cli(d.dir, ['env'])
    assert.ok(!env.stdout.includes('unset'), env.stdout)
  } finally { await d.stop() }
})

// Round 2. The bridge resent the WHOLE line whenever the answer contained the
// phrase "needs a live session". A batch of a session request and a refused
// call asked the human twice, and the first request's poll secret was lost.

/** Start the stdio bridge on `token`, and a way to send it one line and read one line back. */
function bridge(d, token) {
  const child = spawn(process.execPath, [BIN, 'mcp'], {
    env: { ...process.env, AGENT_VAULT_DIR: d.dir, AGENT_VAULT_SESSION: token, NO_COLOR: '1' },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  let out = ''
  child.stdout.on('data', (c) => { out += c })
  const ask = (message) => new Promise((resolve, reject) => {
    const from = out.length
    const t = setTimeout(() => reject(new Error(`no reply: ${out}`)), 10_000)
    const check = () => {
      const nl = out.indexOf('\n', from)
      if (nl === -1) return
      clearTimeout(t)
      child.stdout.off('data', check)
      resolve(JSON.parse(out.slice(from, nl)))
    }
    child.stdout.on('data', check)
    child.stdin.write(`${JSON.stringify(message)}\n`)
  })
  return { ask, stop: () => child.kill() }
}

const call = (id, name, args = {}) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } })
const toolText = (r) => JSON.parse(r.result.content[0].text)

test('the bridge resends only the refused calls of a mixed batch', async () => {
  const d = await withCliDaemon()
  let b
  try {
    const old = JSON.parse((await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])).stdout).data
    await cli(d.dir, ['session', 'revoke', old.session_id])
    await cli(d.dir, ['session', 'create', '--cred', 'demo'])
    b = bridge(d, old.token)
    const answers = await b.ask([
      call(1, 'vault_request_session', { cred: 'demo', reason: 'reading issues' }),
      call(2, 'vault_list_creds'),
    ])
    assert.ok(Array.isArray(answers) && answers.length === 2, JSON.stringify(answers).slice(0, 300))
    const pending = await d.control('GET', '/v1/session-requests')
    assert.equal(pending.body.length, 1, `one proposal became ${pending.body.length} requests`)

    const asked = toolText(answers.find((a) => a.id === 1))
    assert.equal(asked.request_id, pending.body[0].id, 'the answer the agent got is for the request that exists')
    const listed = answers.find((a) => a.id === 2)
    assert.ok(!listed.result.isError, `the refused call was not retried: ${JSON.stringify(listed).slice(0, 300)}`)
    assert.match(listed.result.content[0].text, /"slug": "demo"/)
  } finally {
    b?.stop()
    await d.stop()
  }
})

test('the bridge leaves a batch alone when nothing in it was refused for want of a session', async () => {
  const d = await withCliDaemon()
  let b
  try {
    const old = JSON.parse((await cli(d.dir, ['session', 'create', '--cred', 'demo', '--json'])).stdout).data
    await cli(d.dir, ['session', 'revoke', old.session_id])
    await cli(d.dir, ['session', 'create', '--cred', 'demo'])
    b = bridge(d, old.token)
    // A reason that is the very phrase the bridge used to search for.
    const answers = await b.ask([
      call(7, 'vault_request_session', { cred: 'demo', reason: 'this tool needs a live session' }),
      call(8, 'vault_status'),
    ])
    assert.equal(answers.length, 2)
    const pending = await d.control('GET', '/v1/session-requests')
    assert.equal(pending.body.length, 1, 'a call that did not need a session was sent twice')
  } finally {
    b?.stop()
    await d.stop()
  }
})

test('what the bridge resends is read from the answers, not searched for in their text', async () => {
  const { sessionRetry } = await import('../../src/cli/index.js')
  const refusal = (id) => ({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'this tool needs a live session' }) }] } })
  const ok = (id, text) => ({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }] } })

  // A success that merely mentions the phrase is not a refusal.
  assert.equal(sessionRetry(JSON.stringify(call(1, 'x')), JSON.stringify(ok(1, 'this tool needs a live session'))), null)
  assert.equal(sessionRetry(JSON.stringify([call(1, 'x')]), JSON.stringify([ok(1, '{"error":"this tool needs a live session"}')])), null)

  // A single refused call goes again whole, and its new answer replaces it.
  const single = sessionRetry(JSON.stringify(call(1, 'x')), JSON.stringify(refusal(1)))
  assert.equal(single.line, JSON.stringify(call(1, 'x')))
  assert.equal(single.merge('again'), 'again')

  // In a batch, only the refused ids, and every other answer kept as it came.
  const batch = [call('a', 'ask'), call('b', 'list'), call('c', 'status')]
  const plan = sessionRetry(JSON.stringify(batch), JSON.stringify([ok('a', 'asked'), refusal('b'), ok('c', 'fine')]))
  assert.deepEqual(JSON.parse(plan.line), [batch[1]])
  const merged = JSON.parse(plan.merge(JSON.stringify([ok('b', 'listed')])))
  assert.deepEqual(merged.map((m) => m.result.content[0].text), ['asked', 'listed', 'fine'])
  // A retry that comes back as something else leaves the original answers.
  assert.deepEqual(JSON.parse(plan.merge('not json')).map((m) => m.id), ['a', 'b', 'c'])
})
