import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync, readFileSync, writeFileSync, statSync, symlinkSync, lstatSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn, execFileSync } from 'node:child_process'
import { approvalPreviewLines } from '../../src/cli/control-commands.js'
import { saveState } from '../../src/client-state.js'
import { grantInput, sessionInput } from '../../src/cli/policy-input.js'

const BIN = new URL('../../bin/agent-vault.js', import.meta.url).pathname
async function fixture(t, handler, tcp = false) {
  const dir = mkdtempSync(join(tmpdir(), 'av-cli-files-'))
  const calls = []
  const server = createServer(async (req, res) => {
    let body = ''
    for await (const c of req) body += c
    const call = { method: req.method, path: req.url, headers: req.headers, body: body ? JSON.parse(body) : null }
    calls.push(call)
    const r = await handler(call, calls)
    res.writeHead(r?.status || 200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(r?.data ?? r))
  })
  await new Promise((resolve) => tcp ? server.listen(0, '127.0.0.1', resolve) : server.listen(join(dir, 'control.sock'), resolve))
  t.after(async () => { server.closeAllConnections(); await new Promise((r) => server.close(r)); rmSync(dir, { recursive: true, force: true }) })
  const run = (args, stdin = '') => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, AGENT_VAULT_DIR: dir, AGENT_VAULT_ALLOW_ROOT: '1' }, stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    child.stdout.on('data', (c) => { stdout += c }); child.stderr.on('data', (c) => { stderr += c })
    child.on('error', reject); child.on('close', (code) => resolve({ code, stdout, stderr }))
    child.stdin.end(stdin)
  })
  return { dir, run, calls, server }
}
const bundle = { format: 'agent-vault-backup', version: 1, ct: 'fake-encrypted-test-bundle' }

test('backup export writes exclusive 0600 JSON, refuses collisions and links, and needs matching stdin recovery proof', async (t) => {
  const f = await fixture(t, () => ({ bundle, summary: { credentials: 2, templates: 1 }, bundle_sha256: 'abc' }))
  const path = join(f.dir, 'backup.json'), victim = join(f.dir, 'victim')
  let r = await f.run(['backup', 'export', '--out', path, '--json'], 'fake-recovery-passphrase\nfake-recovery-passphrase\n')
  assert.equal(r.code, 0, r.stdout + r.stderr)
  assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), bundle)
  assert.equal(statSync(path).mode & 0o777, 0o600)
  assert.equal(f.calls[0].path, '/v1/backup/export')
  assert.equal(f.calls[0].body.recovery_passphrase, 'fake-recovery-passphrase')
  assert.doesNotMatch(r.stdout + r.stderr, /fake-recovery-passphrase/)
  r = await f.run(['backup', 'export', '--out', path, '--json'], 'p\np\n')
  assert.equal(r.code, 11)
  writeFileSync(victim, 'unchanged')
  const link = join(f.dir, 'link'); symlinkSync(victim, link)
  r = await f.run(['backup', 'export', '--out', link, '--force', '--json'], 'p\np\n')
  assert.equal(r.code, 11); assert.equal(readFileSync(victim, 'utf8'), 'unchanged')
  r = await f.run(['backup', 'export', '--out', path, '--force', '--json'], 'p\np\n')
  assert.equal(r.code, 0); assert.match(r.stderr, /replaced/)
  const before = f.calls.length
  r = await f.run(['backup', 'export', '--out', path, '--json'], 'a\nb\n')
  assert.equal(r.code, 2); assert.equal(f.calls.length, before)
})

test('backup inspect and restore read the bundle, inspect before restoring, and preserve conflict mode', async (t) => {
  const f = await fixture(t, (c) => c.path.endsWith('/inspect') ? { credentials: [{ slug: 'demo', kind: 'http', host: 'example.test' }] } : { restored: ['demo'], skipped: [], renamed: [] })
  const path = join(f.dir, 'bundle'); writeFileSync(path, JSON.stringify(bundle))
  let r = await f.run(['backup', 'inspect', path, '--json'], 'fake-passphrase\n')
  assert.equal(r.code, 0); assert.deepEqual(f.calls[0].body.bundle, bundle)
  r = await f.run(['backup', 'restore', path, '--on-conflict', 'rename', '--json'], 'fake-passphrase\n')
  assert.equal(r.code, 0, r.stdout)
  assert.deepEqual(f.calls.slice(1).map((c) => c.path), ['/v1/backup/inspect', '/v1/backup/restore'])
  assert.equal(f.calls.at(-1).body.on_conflict, 'rename')
  assert.deepEqual(JSON.parse(r.stdout).data.restored, ['demo'])
  const n = f.calls.length
  r = await f.run(['backup', 'restore', path, '--on-conflict', 'overwrite', '--json'])
  assert.equal(r.code, 2); assert.equal(f.calls.length, n)
})

test('audit export preserves JSONL chain rows, follows exclusive writer rules, and witness appends', async (t) => {
  const rows = [{ seq: 4, kind: 'request.allowed', hash: 'abcd', prev_hash: '1234' }]
  const checkpoint = { seq: 4, head: 'abcd', vault_id: 'fake-vault', mac: 'fake-mac' }
  const f = await fixture(t, (c) => c.path.startsWith('/v1/audit/export') ? { rows, next_seq: 4, head: { seq: 4, hash: 'abcd' } } : checkpoint)
  const path = join(f.dir, 'audit.jsonl')
  let r = await f.run(['audit', 'export', '--since-seq', '3', '--out', path, '--json'])
  assert.equal(r.code, 0); assert.equal(readFileSync(path, 'utf8'), JSON.stringify(rows[0]) + '\n')
  assert.equal(statSync(path).mode & 0o777, 0o600)
  assert.equal(f.calls[0].path, '/v1/audit/export?since_seq=3&limit=5000')
  r = await f.run(['audit', 'export', '--out', path, '--json']); assert.equal(r.code, 11)
  r = await f.run(['audit', 'export']); assert.equal(r.code, 0); assert.deepEqual(JSON.parse(r.stdout), rows[0])
  const witness = join(f.dir, 'witness.jsonl')
  for (let i = 0; i < 2; i++) assert.equal((await f.run(['audit', 'witness', '--out', witness, '--json'])).code, 0)
  assert.equal(readFileSync(witness, 'utf8'), (JSON.stringify(checkpoint) + '\n').repeat(2))
  assert.equal(statSync(witness).mode & 0o777, 0o600)
  const link = join(f.dir, 'link'); symlinkSync(witness, link)
  assert.equal((await f.run(['audit', 'witness', '--out', link, '--json'])).code, 11)
  assert.equal(readFileSync(witness, 'utf8').trim().split('\n').length, 2)
})

test('audit follow appends later pages, never truncates earlier evidence, and stops cleanly on SIGINT', async (t) => {
  const f = await fixture(t, (c, calls) => ({ rows: [{ seq: calls.length, kind: 'test' }], next_seq: calls.length, head: {} }))
  const path = join(f.dir, 'follow.jsonl')
  const child = spawn(process.execPath, [BIN, 'audit', 'export', '--follow', '--out', path, '--json'], { env: { ...process.env, AGENT_VAULT_DIR: f.dir, AGENT_VAULT_ALLOW_ROOT: '1' } })
  t.after(() => { if (child.exitCode === null) child.kill('SIGINT') })
  let stdout = '', stderr = ''
  child.stderr.on('data', (c) => { stderr += c })
  const done = new Promise((resolve) => child.on('close', resolve))
  child.stdout.on('data', (c) => { stdout += c; if (f.calls.length >= 2) child.kill('SIGINT') })
  assert.equal(await done, 0, stderr)
  assert.ok(stdout.includes('"ok": true'))
  const rows = readFileSync(path, 'utf8').trim().split('\n').map(JSON.parse)
  assert.deepEqual(rows.map((r) => r.seq), [1, 2])
  assert.match(f.calls[1].path, /since_seq=1/)
})

test('audit verify combines chain and witness decisions with strict booleans', async (t) => {
  let witnessOk = true
  const f = await fixture(t, (c) => c.path === '/v1/audit/verify' ? { ok: true, count: 1, head: 'abcd' } : { ok: witnessOk, checked: 1, ahead: witnessOk === true ? [] : [1], mismatched: [], forged: [] })
  const path = join(f.dir, 'witness'); writeFileSync(path, '{"seq":1}\n')
  let r = await f.run(['audit', 'verify', '--witness', path, '--json'])
  assert.equal(r.code, 0); assert.equal(JSON.parse(r.stdout).data.ok, true)
  assert.deepEqual(f.calls[1].body, { checkpoints: [{ seq: 1 }] })
  witnessOk = 'false'
  r = await f.run(['audit', 'verify', '--witness', path, '--json'])
  assert.equal(r.code, 1)
  const failed = JSON.parse(r.stdout)
  assert.equal(failed.ok, false); assert.equal(failed.data, undefined)
  assert.match(failed.error.message, /does not match the witness: 1 ahead/)
  assert.equal(failed.error.problem.ok, false); assert.equal(failed.error.problem.witness.ahead.length, 1)
})

test('audit verify on a broken chain is a failure envelope with exit 1, and an intact one is not', async (t) => {
  let chain = { ok: false, reason: 'tampered', count: 2, head: 'abcd' }
  const f = await fixture(t, (c) => c.path === '/v1/audit/verify' ? chain : { ok: true, checked: 1, ahead: [], mismatched: [], forged: [] })
  const path = join(f.dir, 'witness'); writeFileSync(path, '{"seq":1}\n')
  for (const extra of [[], ['--witness', path]]) {
    const r = await f.run(['audit', 'verify', ...extra, '--json'])
    assert.equal(r.code, 1, r.stderr)
    const envelope = JSON.parse(r.stdout)
    assert.equal(envelope.ok, false); assert.equal(envelope.data, undefined)
    assert.equal(envelope.error.message, 'the audit log cannot be trusted: tampered')
    assert.equal(envelope.error.problem.ok, false); assert.equal(envelope.error.problem.count, 2)
    if (extra.length) assert.equal(envelope.error.problem.witness.checked, 1)
  }
  let r = await f.run(['audit', 'verify'])
  assert.equal(r.code, 1); assert.equal(r.stdout, ''); assert.match(r.stderr, /cannot be trusted: tampered/)
  chain = { ok: false, brokenAt: 7, reason: 'hash mismatch', count: 9 }
  r = await f.run(['audit', 'verify', '--json'])
  assert.equal(r.code, 1); assert.equal(JSON.parse(r.stdout).error.message, 'chain broken at record 7: hash mismatch')
  // A truthy non-boolean is not an intact chain.
  chain = { ok: 'true', count: 2, head: 'abcd' }
  r = await f.run(['audit', 'verify', '--json'])
  assert.equal(r.code, 1); assert.equal(JSON.parse(r.stdout).ok, false)
  chain = { ok: true, count: 2, head: 'abcd' }
  r = await f.run(['audit', 'verify', '--json'])
  assert.equal(r.code, 0); assert.deepEqual(JSON.parse(r.stdout), { ok: true, data: chain })
})

test('audit witness refuses a planted fifo at once and writes nothing', async (t) => {
  const f = await fixture(t, () => ({ seq: 3, head: 'a'.repeat(64) }))
  const path = join(f.dir, 'witness.fifo')
  execFileSync('mkfifo', [path])
  const started = Date.now()
  const r = await Promise.race([f.run(['audit', 'witness', '--out', path, '--json']), new Promise((resolve) => setTimeout(() => resolve({ code: 'timeout' }), 5000))])
  assert.equal(r.code, 11, r.stdout + r.stderr)
  assert.ok(Date.now() - started < 5000)
  assert.equal(JSON.parse(r.stdout).ok, false)
  assert.ok(lstatSync(path).isFIFO())
})

test('--markdown takes no value on session show and report', async (t) => {
  const f = await fixture(t, () => ({}))
  for (const args of [['session', 'show', 'test', '--markdown=yes'], ['report', '--markdown=no']]) {
    const r = await f.run([...args, '--json'])
    assert.equal(r.code, 2, r.stdout + r.stderr)
    assert.match(JSON.parse(r.stdout).error.message, /--markdown takes no value/)
  }
  assert.equal(f.calls.length, 0)
})

test('state writes cannot follow a symlink and ordinary updates remain private', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'av-cli-state-')); t.after(() => rmSync(dir, { recursive: true, force: true }))
  const path = join(dir, 'state'), victim = join(dir, 'victim')
  saveState({ session_id: 'test', token: 'avs1.test.fake' }, path)
  saveState({ gateway_port: 1234 }, path)
  assert.equal(JSON.parse(readFileSync(path)).session_id, 'test'); assert.equal(statSync(path).mode & 0o777, 0o600)
  writeFileSync(victim, '{}'); rmSync(path); symlinkSync(victim, path)
  assert.throws(() => saveState({ gateway_port: 4567 }, path), { code: 'ENOTREGULAR' })
  assert.equal(readFileSync(victim, 'utf8'), '{}')
})

test('policy flags share one typed parser and reject malformed ordinary numeric spellings', () => {
  const flags = { rate: '60/min', quota: '1000/day', concurrency: '4', route: ['get,head:/repos/**', 'post:/repos/*/issues'], 'spend-usd': '5.000001', 'spend-tokens': '123', 'grant-ttl': '10', redirects: '2', graphql: 'query' }
  const shared = grantInput(flags)
  assert.deepEqual(shared.rate, { count: 60, per: 'minute' })
  assert.deepEqual(shared.routes[0], { methods: ['GET', 'HEAD'], paths: ['/repos/**'] })
  assert.equal(shared.spend_usd, 5.000001); assert.equal(shared.grant_ttl_minutes, 10)
  assert.deepEqual(sessionInput({ ...flags, cred: 'a,b' }).grants.map((g) => g.rate), [shared.rate, shared.rate])
  for (const invalid of [{ rate: '2/year' }, { quota: '0/day' }, { concurrency: '' }, { redirects: '6' }, { 'spend-usd': '1.0000001' }, { 'grant-ttl': '0' }, { route: ['GET'] }, { approval: 'whatever' }, { infinite: 'false', cred: 'a' }]) {
    assert.throws(() => sessionInput({ cred: 'a', ...invalid }), (e) => e.exit === 2)
  }
  assert.equal(grantInput({ 'spend-usd': '0' }).spend_usd, 0)
})

test('preflight calls only loopback gateway with session authentication, preserves repeated headers and returns verdict exit codes', async (t) => {
  let would = 'allow'
  const f = await fixture(t, () => ({ would, checks: [{ stage: 'policy', ok: would !== 'deny' }], advisory: 'A prediction, not a permission.' }), true)
  saveState({ token: 'avs1.test.fake', session_id: 'test', gateway_port: f.server.address().port }, join(f.dir, 'cli-state.json'))
  const body = join(f.dir, 'body'); writeFileSync(body, Buffer.from([0, 255, 42]))
  for (const [verdict, exit] of [['allow', 0], ['hold', 10], ['deny', 6]]) {
    would = verdict
    const r = await f.run(['preflight', '--cred', 'demo', '--method', 'post', '--path', '/messages', '--query', 'x=1', '--header', 'X-Test: one', '--header', 'X-Test: two', '--body-file', body, '--json'])
    assert.equal(r.code, exit, r.stdout + r.stderr); assert.equal(JSON.parse(r.stdout).data.would, verdict)
    const c = f.calls.at(-1)
    assert.equal(c.path, '/v1/preflight'); assert.equal(c.headers['av-session'], 'avs1.test.fake')
    assert.deepEqual(c.body, { method: 'POST', path: '/p/demo/messages', query: 'x=1', headers: [['X-Test', 'one'], ['X-Test', 'two']], body_base64: 'AP8q' })
  }
  rmSync(join(f.dir, 'cli-state.json'))
  assert.equal((await f.run(['preflight', '--cred', 'demo', '--method', 'GET', '--path', '/', '--json'])).code, 9)
  assert.equal(f.calls.length, 3)
})

test('new secret-bearing commands refuse argv values without echoing them or contacting daemon', async (t) => {
  const f = await fixture(t, () => ({}))
  for (const args of [['cred', 'rotate', 'demo', '--value'], ['notify', 'set', '--webhook-url'], ['backup', 'export', '--out', join(f.dir, 'backup'), '--recovery-passphrase']]) {
    const r = await f.run([...args, 'FAKE_ARGV_SECRET', '--json'], 'fake-stdin-secret\nfake-stdin-secret\n')
    assert.equal(r.code, 2); assert.doesNotMatch(r.stdout + r.stderr, /FAKE_ARGV_SECRET/)
  }
  assert.equal(f.calls.length, 0)
})

test('session detail reports policy, spend estimates, grant lifetime and incomplete history in text and Markdown', async (t) => {
  const detail = { session: { id: 'test', label: 'example', infinite: false }, grants: [{ cred: 'demo', grant_id: 'g1', expires_at: '2030-01-01', effective: { methods: ['GET'], payload: [] }, budget: { limit: 5, used: 2 }, spend: { tokens_used: 1234, limit_tokens: 50000, usd_micros_used: 420000, limit_usd_micros: 5000000 }, placeholders: [{ id: 'ledger', state: 'active' }] }], activity: { complete: false, note: 'anchor missing', requests: { allowed: 1 }, approvals: { requested: 1 }, paths: [{ count: 1, method: 'GET', path: '/ok' }], denials: [{ count: 1, code: 'AV_POLICY_DENIED', rule: 'methods' }] } }
  const f = await fixture(t, () => detail)
  for (const flags of [[], ['--markdown']]) {
    const r = await f.run(['session', 'show', 'test', ...flags])
    assert.equal(r.code, 0, r.stderr); assert.match(r.stdout, /1,234 \/ 50,000 tokens/); assert.match(r.stdout, /\$0.42 \/ \$5.00/)
    assert.match(r.stdout, /2030-01-01/); assert.match(r.stdout, /GET \/ok/); assert.match(r.stderr, /anchor missing/)
  }
})


test('approval previews strip terminal control bytes, bound body display and label agent text', () => {
  const preview = { content_type: 'text/plain', body: { bytes: 5000, text: '\x1b]52;c;payload\x07first\r\nsecond\nthird\nfourth\nfifth\nsixth\nseventh' }, query: [['q', 'test']], headers: [['X-Test', 'safe']], placeholders: [{ label: 'demo.token', location: 'header' }] }
  const short = approvalPreviewLines(preview).join('\n')
  assert.doesNotMatch(short, /[\x00-\x09\x0b-\x1f\x7f-\x9f]/)
  assert.match(short, /sixth/); assert.doesNotMatch(short, /seventh/)
  assert.match(short, /written by the agent, not verified/)
  const full = approvalPreviewLines(preview, true).join('\n')
  assert.match(full, /seventh/); assert.match(full, /demo.token/); assert.match(full, /X-Test/)
  const bounded = approvalPreviewLines({ body: { text: 'x'.repeat(5000) } }, true).join('\n')
  assert.equal((bounded.match(/x/g) || []).length, 4096)
  assert.match(approvalPreviewLines({ body: { text: 'ordinary text' } }).join('\n'), /ordinary text/)
})


test('probe results use strict decisions and registered exit codes; containment sends strict booleans', async (t) => {
  let ok = true
  const f = await fixture(t, (c) => {
    if (c.path === '/v1/credentials/test') return { ok, http_status: 200, latency_ms: 1, scopes: [] }
    if (c.path === '/v1/panic') return { revoked_sessions: 2, denied_approvals: 1, denied_session_requests: 1, locked: c.body.lock }
    if (c.path === '/v1/credentials/quarantine') return { slug: c.body.slug, quarantine: { since: 'now' }, denied_approvals: 1 }
    return { slug: c.body.slug, released: true }
  })
  assert.equal((await f.run(['cred', 'test', 'demo', '--json'])).code, 0)
  ok = 'false'
  assert.equal((await f.run(['cred', 'test', 'demo', '--json'])).code, 12)
  assert.equal((await f.run(['cred', 'test', 'demo', '--all', '--json'])).code, 2)
  assert.equal((await f.run(['panic', '--lock', '--reason', 'owner request', '--json'])).code, 0)
  assert.deepEqual(f.calls.at(-1).body, { lock: true, reason: 'owner request' })
  assert.equal((await f.run(['panic', '--lock=false', '--json'])).code, 2)
  assert.equal((await f.run(['cred', 'quarantine', 'demo', '--reason', 'inspect', '--json'])).code, 0)
  assert.deepEqual(f.calls.at(-1).body, { slug: 'demo', reason: 'inspect' })
  assert.equal((await f.run(['cred', 'release', 'demo', '--json'])).code, 0)
  assert.deepEqual(f.calls.at(-1).body, { slug: 'demo' })
})

test('reports preserve response data and label incomplete history in human and Markdown tables', async (t) => {
  const data = { since: '24h', generated_at: 'now', complete: false, credentials: [{ slug: 'demo', requests: 3, denials: 2 }], sessions: [{ id: 'sid', label: 'test', state: 'active', unused_methods: ['POST'] }] }
  const f = await fixture(t, () => data)
  for (const flags of [[], ['--markdown'], ['--json']]) {
    const r = await f.run(['report', '--since', '24h', ...flags])
    assert.equal(r.code, 0, r.stdout)
    assert.equal(f.calls.at(-1).path, '/v1/report/access?since=24h')
    if (flags.includes('--json')) assert.deepEqual(JSON.parse(r.stdout).data, data)
    else { assert.match(r.stdout, /Credentials/); assert.match(r.stdout, /Sessions/); assert.match(r.stdout, /POST/); assert.match(r.stderr, /incomplete/) }
  }
})


test('root help matches A.5 exactly and scrub help documents the bounded grammar', async (t) => {
  const f = await fixture(t, () => ({}))
  const expected = "agent-vault - a local credential proxy for agents\n\nsetup\n  setup [--dev] [--print-only]         install properly (--dev skips the uid boundary)\n  upgrade                              reinstall the daemon from this checkout\n  daemon [--port N]                    run the daemon (gateway + control socket)\n  status | doctor | profiles           what is running, and what is configured\n\nguided                               (run these with no arguments)\n  quickstart                           credential, session, and what to give the agent\n  cred add                             walks you through storing a credential\n  session create                       walks you through scoping a session\n\ncredentials                          (the value is read from the terminal, never argv)\n  cred add <slug> --kind <kind> [--host H] [--expires YYYY-MM-DD]\n  cred list | cred rm <slug>\n  cred rotate <slug> [--field F] [--revoke] [--retire-hours N]\n                                       replace the value; sessions keep working\n  cred test [<slug> | --all]           run the connector's read-only probe\n  cred expiry <slug> <YYYY-MM-DD|none> record when the token expires\n  cred scrub <slug> [--add PATTERN [--sample TEXT] | --rm ID]\n                                       extra token shapes to redact from responses\n  cred pin <slug> --host H [--add sha256/...] [--rm sha256/... | --clear] [--live]\n                                       refuse any TLS key you did not pin\n  cred quarantine <slug> [--reason T]  stop all use at once; cred release <slug> undoes it\n\nsessions and placeholders\n  session create --cred <slug>[,<slug>...] [--methods GET,POST] [--paths \"/repos/**\"]\n                 [--budget N] [--uses N] [--approval each|on-write|first-use|auto]\n                 [--ttl HOURS | --infinite] [--label TEXT] [--grants-file F]\n                 [--template NAME] [--rate 60/min] [--concurrency N] [--quota 1000/day]\n                 [--route GET:/repos/**]... [--payload-file F] [--graphql query]\n                 [--redirects N] [--spend-tokens N] [--spend-usd X] [--grant-ttl MIN]\n                                       --approval auto or first-use with writes,\n                                       and --infinite, ask for your passphrase\n                                       every time\n  session list | session revoke [<sid>]\n  session narrow [<sid>] [--cred S] [any limit above] [--ttl MIN]\n                                       tighten a live session; it can never widen\n  session show [<sid>] [--markdown]    what it may do, and what it did\n  template save <name> --cred <slug> [session flags] | template list\n  template show <name> | template rm <name>\n  ph next <cred> [--uses N]            issue a placeholder\n  ph check <placeholder> | ph pattern  validate one, or print the scanner regex\n  env [--out F [--force]] [--map NAME=<slug>[:base_url]]... [--map-file F] [--profile-vars]\n                                       placeholders for your tools; the file is 0600 and\n                                       never replaced unless you say so\n  exec [--map NAME=<slug>]... -- <command>\n                                       run a command with a scrubbed environment\n  preflight --cred S --method M --path P [--body-file F]\n                                       would this request pass? nothing is sent\n\napprovals, audit, listeners\n  approvals [--show <id>] | approve <id> | deny <id>\n  watch [--no-notify] [--open]         tell you the moment something is waiting\n  notify set | notify show | notify off | notify test\n                                       an optional webhook for the same signal\n  panic [--lock] [--reason T]          revoke every session, deny everything waiting\n  tripwire show | tripwire on | tripwire off | tripwire set --rule ID ...\n  lock | unlock                        stop and resume every proxied request\n  passphrase set | passphrase remove   make the lock cryptographic (or undo it)\n  audit tail [--limit N] | audit verify [--witness F]\n  audit export [--since-seq N] [--out F] [--follow] | audit witness [--out F]\n  report [--since 7d] [--markdown]     access review across every session\n  backup export --out F | backup inspect F | backup restore F [--on-conflict skip|rename|fail]\n  listen add <id> --address <iface:port> [--surfaces gateway,mcp]\n                 [--tls managed | --tls-cert F --tls-key F]\n  listen list | listen rm <id>\n  tls setup [--port 7443]              certificate for the loopback MCP listener\n  tls status                           fingerprint and expiry\n\nui\n  ui [--port N] [--no-open] [--idle 30] open the web UI (single-use link, no secrets rendered)\n\nmcp\n  mcp                                  stdio transport (for an MCP client)\n  mcp url                              the Streamable HTTP endpoint and header\n  mcp install --agent <claude-code|cursor|gemini|codex> [--scope project|user]\n                                       merge the server into that tool's config\n                                       (--print shows the block instead)\n              [--transport http --tls] a custom connector; the URL must be https\n\ndocs\n  docs [section]                       open the docs, written against this install\n                                       how | start | connect | models | locking\n                                       | safety | refused | commands\n\n--json on any command prints a machine-readable envelope.\n"
  assert.equal((await f.run(['help'])).stdout, expected)
  const json = await f.run(['help', '--json'])
  assert.equal(JSON.parse(json.stdout).data.help + '\n', expected)
  const scrub = await f.run(['cred', 'scrub', '--help'])
  assert.match(scrub.stdout, /at most one \? or \{n,m\}/)
  assert.match(scrub.stdout, /request_ambiguous/)
  assert.equal(f.calls.length, 0)
})
