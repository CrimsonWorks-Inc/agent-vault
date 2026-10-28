import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BIN = fileURLToPath(new URL('../../bin/agent-vault.js', import.meta.url))
const session = { session_id: 'testsession', token: 'avs1.testsession.fake', grants: [], expires_at: '2030-01-01T00:00:00Z' }

// No vault or daemon: only a private temporary control socket and synthetic data.
async function harness(t, reply) {
  // /tmp keeps the socket below macOS's Unix-domain path length limit.
  const dir = await mkdtemp(join(process.platform === 'darwin' ? '/tmp' : tmpdir(), 'av-cli-routes-'))
  const calls = []
  const server = createServer(async (req, res) => {
    let text = ''
    for await (const chunk of req) text += chunk
    const call = { method: req.method, url: req.url, body: text ? JSON.parse(text) : null }
    calls.push(call)
    try {
      const result = await reply(call)
      res.writeHead(result?.status || 200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(result?.data ?? result))
    } catch (e) {
      res.writeHead(500, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ detail: e.message }))
    }
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(join(dir, 'control.sock'), resolve) })
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await rm(dir, { recursive: true, force: true }) })
  async function cli(args, input = '', exit = 0) {
    const argv = [BIN, ...args, '--json']
    const child = spawn(process.execPath, argv, {
      cwd: dir, env: { ...process.env, HOME: dir, AGENT_VAULT_DIR: dir, AGENT_VAULT_SESSION: '', NO_COLOR: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = '', stderr = ''
    child.stdout.on('data', (c) => { stdout += c })
    child.stderr.on('data', (c) => { stderr += c })
    const timer = setTimeout(() => child.kill('SIGKILL'), 10000)
    const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code) => resolve(code)) })
    child.stdin.on('error', () => {})
    child.stdin.end(input)
    let code
    try { code = await done } finally { clearTimeout(timer) }
    assert.equal(code, exit, `${args.join(' ')}\n${stdout}\n${stderr}`)
    // Parsing all stdout rejects stray prompts, human summaries and ANSI text.
    const envelope = JSON.parse(stdout)
    assert.equal(envelope.ok, exit === 0, stdout)
    assert.doesNotMatch(stdout, /\x1b/)
    if (exit === 0) assert.deepEqual(Object.keys(envelope).sort(), ['data', 'ok'])
    return { envelope, stdout, stderr, argv }
  }
  return { cli, calls, dir }
}
const route = (method, url, body = null) => ({ method, url, body })

test('control CLI rotate reads synthetic secret from stdin and sends rotation options', async (t) => {
  const h = await harness(t, () => ({ rotated: { version: 2, previous_fp8: '11111111', fp8: '22222222', retire_until: '2030-01-01' }, invalidated_approvals: 0 }))
  const secret = 'fake-rotation-secret-for-cli-tests'
  const r = await h.cli(['cred', 'rotate', 'demo', '--field', 'token', '--retire-hours', '24', '--expires', '2030-02-28'], `${secret}\n`)
  assert.deepEqual(h.calls, [route('POST', '/v1/credentials/rotate', { slug: 'demo', value: secret, mode: 'keep', field: 'token', retire_hours: 24, expires_at: '2030-02-28T00:00:00.000Z' })])
  assert.ok(!r.argv.some((arg) => arg.includes(secret)))
  assert.ok(!(r.stdout + r.stderr).includes(secret))
  await h.cli(['cred', 'rotate', 'demo', '--revoke'], 'fake-second-value\n')
  assert.equal(h.calls[1].body.mode, 'revoke')
})

test('control CLI scrub add/remove and repeatable pin add use exact route bodies', async (t) => {
  const h = await harness(t, (c) => c.url === '/v1/credentials/scrub' ? { id: 'pattern1', source: c.body.pattern, added_at: '2030-01-01', sample: { redacted: '[redacted]', matches: 1 } } : { ok: true, removed: true })
  await h.cli(['cred', 'scrub', 'demo', '--add', 'fake_[a-z]{4}', '--sample', 'fake_abcd'])
  await h.cli(['cred', 'scrub', 'demo', '--rm', 'pattern /?&'])
  const pins = ['sha256/' + Buffer.alloc(32, 1).toString('base64'), 'sha256/' + Buffer.alloc(32, 2).toString('base64')]
  await h.cli(['cred', 'pin', 'demo', '--host', 'api.example.test', '--add', pins[0], '--add', pins[1]])
  assert.deepEqual(h.calls, [
    route('POST', '/v1/credentials/scrub', { slug: 'demo', pattern: 'fake_[a-z]{4}', sample: 'fake_abcd' }),
    route('DELETE', '/v1/credentials/scrub?slug=demo&id=pattern+%2F%3F%26'),
    route('POST', '/v1/credentials/pins', { slug: 'demo', host: 'api.example.test', pins }),
  ])
})

test('control CLI expiry refuses invalid calendar dates locally and accepts none', async (t) => {
  const h = await harness(t, () => ({ slug: 'demo', expires_at: null }))
  for (const date of ['2030-02-30', '2030-13-01', 'tomorrow']) await h.cli(['cred', 'expiry', 'demo', date], '', 2)
  assert.deepEqual(h.calls, [])
  await h.cli(['cred', 'expiry', 'demo', 'none'])
  assert.deepEqual(h.calls, [route('POST', '/v1/credentials/expiry', { slug: 'demo', expires_at: null })])
})

test('control CLI tripwire replacement preserves unrelated rules and on/off preserve configured rules', async (t) => {
  const other = { id: 'keep', codes: ['AV_PH_REPLAY'], threshold: 3, window_s: 60, action: 'revoke_session' }
  let state = { enabled: false, rules: [other, { ...other, id: 'edit' }] }
  const h = await harness(t, (c) => { if (c.method === 'POST') state = { ...state, ...c.body }; return state })
  await h.cli(['tripwire', 'set', '--rule', 'edit', '--codes', 'AV_PH_REPLAY,AV_NO_GRANT', '--threshold', '5', '--window', '10m', '--action', 'panic'])
  const changed = { id: 'edit', codes: ['AV_PH_REPLAY', 'AV_NO_GRANT'], threshold: 5, window_s: 600, action: 'panic' }
  assert.deepEqual(h.calls[1], route('POST', '/v1/tripwires', { rules: [other, changed] }))
  await h.cli(['tripwire', 'on'])
  assert.deepEqual(h.calls[3], route('POST', '/v1/tripwires', { enabled: true }))
  await h.cli(['tripwire', 'off'])
  assert.deepEqual(h.calls[4], route('POST', '/v1/tripwires', { enabled: false }))
  await h.cli(['tripwire', 'show'])
  assert.deepEqual(state, { enabled: false, rules: [other, changed] })
})

test('control CLI tripwire on installs defaults only for an empty rule set', async (t) => {
  const h = await harness(t, () => ({ enabled: false, rules: [] }))
  await h.cli(['tripwire', 'on'])
  assert.deepEqual(h.calls, [route('GET', '/v1/tripwires'), route('POST', '/v1/tripwires', { enabled: true, rules: 'defaults' })])
})

test('control CLI template lifecycle and session create bind the reviewed template hash', async (t) => {
  const name = 'read template', spec = { cred: 'demo', methods: ['GET'], ttl_hours: 2 }
  const template = { name, spec, hash: 'a'.repeat(64), version: 1, summary: 'read demo', creds: ['demo'], elevated: [], lint: [], updated_at: '2030-01-01' }
  const h = await harness(t, (c) => {
    if (c.url === '/v1/sessions') return session
    if (c.method === 'DELETE') return { ok: true, removed: true }
    return c.url === '/v1/templates' && c.method === 'GET' ? [template] : template
  })
  await h.cli(['template', 'save', name, '--cred', 'demo', '--methods', 'get', '--ttl', '2'])
  await h.cli(['template', 'list'])
  await h.cli(['template', 'show', name])
  await h.cli(['session', 'create', '--template', name, '--methods', 'GET'])
  await h.cli(['template', 'rm', name])
  assert.deepEqual(h.calls, [
    route('POST', '/v1/templates', { name, spec }), route('GET', '/v1/templates'),
    route('GET', '/v1/templates?name=read+template'), route('GET', '/v1/templates?name=read%20template'),
    route('POST', '/v1/sessions', { template: name, template_hash: template.hash, methods: ['GET'] }),
    route('DELETE', '/v1/templates?name=read+template'),
  ])
})

test('control CLI notify reads secret URL from stdin and show/off/test use public responses', async (t) => {
  const publicConfig = { webhook: { host: 'notify.example.test', detail: 'headline', configured_at: '2030-01-01' } }
  const h = await harness(t, (c) => c.method === 'DELETE' ? { ok: true } : c.url.endsWith('/test') ? { sent: true } : publicConfig)
  const secret = 'https://notify.example.test/fake-webhook-secret'
  const r = await h.cli(['notify', 'set', '--detail', 'headline'], `${secret}\n`)
  assert.ok(!r.argv.some((arg) => arg.includes(secret)))
  assert.ok(!(r.stdout + r.stderr).includes(secret))
  await h.cli(['notify', 'show']); await h.cli(['notify', 'test']); await h.cli(['notify', 'off'])
  assert.deepEqual(h.calls, [route('POST', '/v1/notify', { webhook_url: secret, detail: 'headline' }), route('GET', '/v1/notify'), route('POST', '/v1/notify/test'), route('DELETE', '/v1/notify')])
})

for (const factors of [['passphrase'], ['passphrase', 'authenticator']]) test(`control CLI fresh backup refusal without TTY (${factors.join(',')}) never retries or opens a window`, async (t) => {
  const h = await harness(t, (c) => c.url === '/v1/lockstate' ? { locked: false } : { status: 403, data: { code: 'AV_PRESENCE_REQUIRED', rule: 'fresh_presence', detail: 'fresh proof required', factors } })
  const r = await h.cli(['backup', 'export', '--out', join(h.dir, 'unused.json')], 'fake-recovery-passphrase\nfake-recovery-passphrase\n', 5)
  assert.match(JSON.stringify(r.envelope), /no terminal to ask on/)
  assert.equal(JSON.stringify(r.envelope).includes('agent-vault ui'), factors.includes('authenticator'))
  assert.deepEqual(h.calls, [route('POST', '/v1/backup/export', { recovery_passphrase: 'fake-recovery-passphrase' }), route('GET', '/v1/lockstate')])
})

const limits = ['--methods', 'get,post', '--paths', '/repos/**', '--deny-paths', '/repos/private/**', '--rate', '3/min', '--quota', '20/day', '--concurrency', '2', '--redirects', '1', '--spend-tokens', '100', '--spend-usd', '0.125', '--route', 'get:/repos/**', '--route', 'post:/issues', '--graphql', 'query', '--grant-ttl', '15']
const policy = { methods: ['GET', 'POST'], paths: ['/repos/**'], deny_paths: ['/repos/private/**'], rate: { count: 3, per: 'minute' }, quota: { count: 20, window: 'day' }, max_concurrent: 2, redirects: 1, spend_tokens: 100, spend_usd: 0.125, routes: [{ methods: ['GET'], paths: ['/repos/**'] }, { methods: ['POST'], paths: ['/issues'] }], payload: { graphql: { operations: ['query'] } } }

test('control CLI session create and narrow normalize shared policy flags and route lifetimes', async (t) => {
  const h = await harness(t, (c) => c.url.endsWith('/narrow') ? { grants: [], expires_at: '2030-01-01' } : session)
  await h.cli(['session', 'create', '--cred', 'demo', ...limits])
  await h.cli(['session', 'narrow', 'testsession', '--cred', 'demo', '--ttl', '30', ...limits])
  assert.deepEqual(h.calls, [route('POST', '/v1/sessions', { label: 'cli session', cred: 'demo', ...policy, grant_ttl_minutes: 15 }), route('POST', '/v1/sessions/narrow', { sid: 'testsession', cred: 'demo', narrow: policy, session_ttl_minutes: 30, grant_ttl_minutes: 15 })])
})

test('control CLI approve routes session overrides and refuses overrides on held requests', async (t) => {
  const h = await harness(t, (c) => {
    if (c.url === '/v1/approvals') return [{ id: 'held1', summary: 'held request', created_at: '2030-01-01' }]
    if (c.url === '/v1/session-requests') return [{ id: 'proposal1', summary: 'requested demo', created_at: '2030-01-02', proposal: { cred: 'demo' } }]
    return { summary: 'approved session', granted: { cred: 'demo' }, session }
  })
  await h.cli(['approve', 'proposal1', '--methods', 'get', '--budget', '4', '--ttl-minutes', '20', '--approval', 'on-write'])
  assert.deepEqual(h.calls, [route('GET', '/v1/approvals'), route('GET', '/v1/session-requests'), route('POST', '/v1/session-requests/decide', { id: 'proposal1', granted: true, overrides: { methods: ['GET'], budget: 4, ttl_minutes: 20, approval: 'on-write' } })])
  h.calls.length = 0
  await h.cli(['approve', 'held1', '--methods', 'get'], '', 2)
  assert.deepEqual(h.calls, [route('GET', '/v1/approvals'), route('GET', '/v1/session-requests')])
})

test('control CLI session payload file and multiple credentials preserve structured policy', async (t) => {
  const h = await harness(t, () => session)
  const payload = { json: { keys: ['model'] } }
  const path = join(h.dir, 'payload.json')
  await writeFile(path, JSON.stringify(payload))
  await h.cli(['session', 'create', '--cred', 'demo,other', '--payload-file', path, '--rate', '2/sec'])
  assert.deepEqual(h.calls, [route('POST', '/v1/sessions', { label: 'cli session', grants: ['demo', 'other'].map((cred) => ({ cred, payload, rate: { count: 2, per: 'second' } })) })])
})

test('control CLI invalid policy flags fail before contacting the control socket', async (t) => {
  const h = await harness(t, () => session)
  for (const flags of [
    ['--rate', '2/week'], ['--quota', '0/day'], ['--concurrency', '1.5'],
    ['--redirects', '6'], ['--spend-usd', 'NaN'], ['--route', 'GET:not-a-path'],
    ['--graphql', 'invalid'], ['--grant-ttl', '0'], ['--ttl', '1', '--infinite'],
  ]) await h.cli(['session', 'create', '--cred', 'demo', ...flags], '', 2)
  assert.deepEqual(h.calls, [])
})

test('control CLI maps daemon refusal to the contracted JSON error fields and exit', async (t) => {
  const problem = { code: 'AV_POLICY_DENIED', detail: 'policy rejected', rule: 'template_changed', hint: 'Review the template again.' }
  const h = await harness(t, () => ({ status: 403, data: problem }))
  const r = await h.cli(['template', 'show', 'demo'], '', 6)
  assert.deepEqual(r.envelope, { ok: false, error: { message: problem.detail, code: problem.code, hint: problem.hint } })
  assert.deepEqual(h.calls, [route('GET', '/v1/templates?name=demo')])
})


test('control CLI refuses secret-bearing argv flags before sending any request', async (t) => {
  const h = await harness(t, () => ({ ok: true }))
  for (const args of [
    ['cred', 'rotate', 'demo', '--value', 'fake-argv-value'],
    ['notify', 'set', '--webhook-url', 'https://example.test/fake-argv-secret'],
  ]) {
    const r = await h.cli(args, '', 2)
    assert.match(r.envelope.error.message, /never command-line flags/)
    assert.doesNotMatch(r.stdout + r.stderr, /fake-argv/)
  }
  assert.deepEqual(h.calls, [])
})

test('control CLI has no --remote flag (R3): session create and template save refuse it and send nothing', async (t) => {
  const h = await harness(t, () => session)
  for (const flags of [['--remote'], ['--remote', '--infinite'], ['--remote=yes']]) {
    const r = await h.cli(['session', 'create', '--cred', 'demo', ...flags], '', 2)
    assert.match(r.envelope.error.message, /does not take --remote; nothing was sent/)
  }
  await h.cli(['template', 'save', 'demo-template', '--cred', 'demo', '--remote'], '', 2)
  assert.deepEqual(h.calls, [])
  await h.cli(['session', 'create', '--cred', 'demo'])
  assert.deepEqual(h.calls, [route('POST', '/v1/sessions', { label: 'cli session', cred: 'demo' })])
})

test('control CLI session narrow refuses --uses (C22) before contacting the daemon', async (t) => {
  const h = await harness(t, () => ({ grants: [], expires_at: '2030-01-01' }))
  for (const flags of [['--uses', '3'], ['--uses', '3', '--methods', 'get'], ['--uses']]) {
    const r = await h.cli(['session', 'narrow', 'testsession', ...flags], '', 2)
    assert.match(r.envelope.error.message, /cannot change --uses; nothing was sent/)
  }
  assert.deepEqual(h.calls, [])
  await h.cli(['session', 'narrow', 'testsession', '--methods', 'get'])
  assert.deepEqual(h.calls, [route('POST', '/v1/sessions/narrow', { sid: 'testsession', narrow: { methods: ['GET'] } })])
})
