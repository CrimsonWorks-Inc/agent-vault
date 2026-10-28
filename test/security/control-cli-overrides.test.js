// C23: an approval narrowing the CLI cannot read is a usage error, and nothing
// is sent. The field-error tests inject a throw; the rest run the real C23
// parseOverrides from src/pending.js.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { approvalOverrides, sessionInput } from '../../src/cli/policy-input.js'
import { parseOverrides } from '../../src/pending.js'

const BIN = fileURLToPath(new URL('../../bin/agent-vault.js', import.meta.url))
const args = (flags) => ({ _: ['sr_x'], ...flags })
const usage = (pattern) => (e) => e.exit === 2 && pattern.test(e.message) && /nothing was sent/.test(e.message)
// What C23's parseOverrides does on a value it cannot read.
const throwing = (field, why) => () => { throw Object.assign(new TypeError(`${field}: ${why}`), { field }) }

test('C23: a field error from parseOverrides becomes a usage error naming the flag', () => {
  for (const [field, flags] of [
    ['budget', { budget: '4' }],
    ['routes', { routes: '[not json' }],
    ['payload', { payload: '{' }],
    ['spend_usd', { spend_usd: 'Infinity' }],
  ]) {
    assert.throws(() => approvalOverrides(args(flags), throwing(field, 'not valid')),
      usage(new RegExp(`^--${field}: not valid;`)), field)
  }
})

test('C23: an error without a field is not dressed up as a usage error', () => {
  const plain = () => { throw new TypeError('a bug in the parser') }
  assert.throws(() => approvalOverrides(args({ budget: '4' }), plain), (e) => e.exit === undefined && e.message === 'a bug in the parser')
  const other = () => { throw Object.assign(new Error('budget: x'), { field: 'budget' }) }
  assert.throws(() => approvalOverrides(args({ budget: '4' }), other), (e) => e.exit === undefined)
})

test('approve overrides: ordinary narrowing passes through unchanged', () => {
  assert.deepEqual(approvalOverrides(args({ methods: 'get', budget: '4', 'ttl-minutes': '20', approval: 'on-write' }), parseOverrides),
    { methods: ['GET'], budget: 4, ttl_minutes: 20, approval: 'on-write' })
  assert.deepEqual(approvalOverrides(args({ ttl_minutes: '5', infinite: true }), parseOverrides), { ttl_minutes: 5, infinite: true })
  assert.deepEqual(approvalOverrides(args({}), parseOverrides), {}, 'no flags is a plain yes')
  // A parser that reads the wave-3 spellings, as C23's does.
  const wave3 = (a) => ({ ...parseOverrides(a), ...(a.routes ? { routes: JSON.parse(a.routes) } : {}), ...(a.spend_tokens ? { spend_tokens: Number(a.spend_tokens) } : {}) })
  assert.deepEqual(approvalOverrides(args({ routes: '[{"methods":["GET"],"paths":["/a"]}]', spend_tokens: '9' }), wave3),
    { routes: [{ methods: ['GET'], paths: ['/a'] }], spend_tokens: 9 })
  assert.deepEqual(approvalOverrides(args({ graphql: 'query' }), parseOverrides).payload, { graphql: { operations: ['query'] } })
})

test('approve overrides: a flag that was typed is never treated as nothing sent', () => {
  for (const [flags, pattern] of [
    [{ budgte: '3' }, /approve does not take --budgte/],
    [{ ttl: '5' }, /approve does not take --ttl;/],
    [{ 'ttl-minutes': true }, /--ttl-minutes needs a value/],
    [{ 'ttl-minutes': '' }, /--ttl-minutes was given but narrows nothing/],
    // C23: the merged parseOverrides throws for this, naming the field.
    [{ 'ttl-minutes': 'abc' }, /^--ttl_minutes: not a number/],
    [{ infinite: 'yes' }, /--infinite was given but narrows nothing/],
    [{ ttl_minutes: '5', 'ttl-minutes': '6' }, /give only one of --ttl_minutes, --ttl-minutes/],
    [{ concurrency: '2', max_concurrent: '3' }, /give only one of/],
  ]) assert.throws(() => approvalOverrides(args(flags), parseOverrides), (e) => e.exit === 2 && pattern.test(e.message) && /nothing was sent/.test(e.message), JSON.stringify(flags))
  assert.throws(() => approvalOverrides(args({ approval: '' }), parseOverrides), (e) => e.exit === 2 && /--approval/.test(e.message))
  // C23's parser throws before a non-finite number can come back; the CLI's
  // own check stays behind it for a parser that lets one through.
  for (const v of [NaN, Infinity]) {
    assert.throws(() => approvalOverrides(args({ 'ttl-minutes': '5' }), () => ({ ttl_minutes: v })), usage(/--ttl_minutes must be a number/), String(v))
  }
  // A JSON --routes must not vanish. With C23's parser it is read and sent
  // as typed, for the daemon to judge, and unreadable JSON is a usage error.
  assert.deepEqual(approvalOverrides(args({ routes: '[]' }), parseOverrides), { routes: [] })
  assert.throws(() => approvalOverrides(args({ routes: '[not json' }), parseOverrides), usage(/^--routes: not valid JSON;/))
})

test('session create and template flags: an unknown limit is refused, the known ones are not', () => {
  assert.throws(() => sessionInput({ _: [], cred: 'demo', spend_tokens: '5' }), usage(/session does not take --spend_tokens/))
  assert.deepEqual(sessionInput({ _: [], cred: 'demo', 'spend-tokens': '5', label: 'x' }), { label: 'x', cred: 'demo', spend_tokens: 5 })
})

async function harness(t) {
  const dir = await mkdtemp(join(process.platform === 'darwin' ? '/tmp' : tmpdir(), 'av-cli-c23-'))
  const calls = []
  const server = createServer((req, res) => {
    calls.push(`${req.method} ${req.url}`)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(req.url === '/v1/session-requests' ? JSON.stringify([{ id: 'sr_x', summary: 'requested demo', created_at: '2030-01-01', proposal: { cred: 'demo' } }]) : '[]')
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(join(dir, 'control.sock'), resolve) })
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await rm(dir, { recursive: true, force: true }) })
  const cli = (argv) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...argv, '--json'], {
      cwd: dir, env: { ...process.env, HOME: dir, AGENT_VAULT_DIR: dir, AGENT_VAULT_SESSION: '', NO_COLOR: '1' }, stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    child.stdout.on('data', (c) => { stdout += c })
    child.once('error', reject)
    child.once('close', (code) => resolve({ code, envelope: JSON.parse(stdout) }))
  })
  return { cli, calls }
}

test('approve with an unreadable narrowing exits 2 before contacting the daemon', async (t) => {
  const h = await harness(t)
  for (const argv of [
    ['approve', 'sr_x', '--ttl-minutes', 'abc'],
    ['approve', 'sr_x', '--budgte', '3'],
    ['approve', 'sr_x', '--ttl-minutes='],
    ['session', 'narrow', 'sid1', '--spend_tokens', '5'],
    ['session', 'create', '--cred', 'demo', '--grant_ttl', '5'],
  ]) {
    const r = await h.cli(argv)
    assert.equal(r.code, 2, argv.join(' '))
    assert.equal(r.envelope.ok, false)
    assert.match(r.envelope.error.message, /nothing was sent/)
  }
  assert.deepEqual(h.calls, [], 'not even the pending list was read')
})
