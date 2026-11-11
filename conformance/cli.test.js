// Every CLI command's --json envelope and exit code, driven by spawning the binary.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  rustSkipReason, binaries, openWorld, runCli, leaksSecret, SECRET, pinValue, PASSPHRASE,
} from './lib/harness.js'

const skip = rustSkipReason()

function envFor(dir) {
  const env = { ...process.env, NO_COLOR: '1', AGENT_VAULT_DIR: dir }
  for (const key of ['AGENT_VAULT_SESSION', 'AGENT_VAULT_URL', 'AGENT_VAULT_PLACEHOLDER', 'AGENT_VAULT_PORT']) delete env[key]
  return env
}

function assertOk(res, label) {
  assert.equal(res.code, 0, `${label}\nexit ${res.code}\n${res.stderr}\n${res.stdout.slice(0, 800)}`)
  assert.equal(res.json?.ok, true, `${label} envelope ${res.stdout.slice(0, 400)}`)
  assert.equal(leaksSecret(res.stdout + res.stderr), null, label)
  return res.json.data
}

function assertFail(res, code, label) {
  assert.equal(res.code, code, `${label}\nexit ${res.code}\n${res.stderr}\n${res.stdout.slice(0, 800)}`)
  assert.equal(res.json?.ok, false, label)
  assert.equal(typeof res.json.error?.message, 'string', label)
  assert.equal(leaksSecret(res.stdout + res.stderr), null, label)
  return res.json.error
}

if (skip) {
  test('cli', { skip }, () => {})
} else {
  describe('cli', { concurrency: false, timeout: 180_000 }, () => {
    let w
    const box = {}
    before(async () => { w = await openWorld() })
    after(async () => { await w?.close() })

    test('setup, status, doctor, profiles, and help', async () => {
      const dev = assertOk(await runCli(w, ['setup', '--dev', '--json']), 'setup --dev')
      assert.equal(dev.existed, true)
      const system = assertOk(await runCli(w, ['setup', '--json']), 'setup')
      assert.equal(system.mode, 'system')
      assert.equal(system.installed, false)
      assert.match(system.command, /^sudo /)
      const status = assertOk(await runCli(w, ['status', '--json']), 'status')
      assert.equal(status.gateway_port, w.port)
      assert.equal(typeof status.credentials, 'number')
      const doctor = assertOk(await runCli(w, ['doctor', '--json']), 'doctor')
      assert.ok(Array.isArray(doctor))
      assert.ok(doctor.every((row) => typeof row.name === 'string' && typeof row.ok === 'boolean'))
      const profiles = assertOk(await runCli(w, ['profiles', '--json']), 'profiles')
      assert.ok(profiles.some((p) => p.kind === 'http' && p.implemented === true))
      assert.ok(profiles.some((p) => p.kind === 'postgres' && p.implemented === false))
      const help = assertOk(await runCli(w, ['help', '--json']), 'help')
      assert.match(help.help, /agent-vault/)
      assertFail(await runCli(w, ['upgrade', '--json']), 2, 'upgrade')
      assertFail(await runCli(w, ['quickstart', '--json']), 2, 'quickstart')
      assertFail(await runCli(w, ['no-such-command', '--json']), 2, 'unknown')
    })

    test('credentials, sessions, placeholders, env, and preflight', async () => {
      const host = `127.0.0.1:${w.upstream.port}`
      const added = assertOk(await runCli(w, ['cred', 'add', 'demo', '--kind', 'http', '--host', host, '--scheme', 'http', '--json'], { input: `${SECRET}\n` }), 'cred add')
      assert.equal(added.slug, 'demo')
      assert.equal(leaksSecret(JSON.stringify(added)), null)
      const list = assertOk(await runCli(w, ['cred', 'list', '--json']), 'cred list')
      assert.ok(list.some((c) => c.slug === 'demo'))
      const session = assertOk(await runCli(w, [
        'session', 'create', '--cred', 'demo', '--methods', 'GET,POST', '--paths', '/**',
        '--budget', '40', '--approval', 'on-write', '--ttl', '1', '--json',
      ]), 'session create')
      assert.equal(typeof session.token, 'string')
      assert.match(session.placeholder, /^av1\./)
      box.sid = session.session_id
      const sessions = assertOk(await runCli(w, ['session', 'list', '--json']), 'session list')
      assert.ok(sessions.some((s) => s.id === box.sid))
      assert.equal(JSON.stringify(sessions).includes(session.token), false)
      const ph = assertOk(await runCli(w, ['ph', 'next', 'demo', '--json']), 'ph next')
      assert.match(ph.placeholder, /^av1\./)
      assertOk(await runCli(w, ['ph', 'check', '--json', ph.placeholder]), 'ph check')
      const pattern = assertOk(await runCli(w, ['ph', 'pattern', '--json']), 'ph pattern')
      assert.equal(typeof pattern.pattern, 'string')
      assertFail(await runCli(w, ['ph', 'check', '--json', 'not-a-placeholder']), 8, 'ph check bad')
      const env = assertOk(await runCli(w, ['env', '--json']), 'env')
      assert.ok(env.env.some((line) => line.includes(ph.placeholder) || line.includes(session.placeholder)))
      assert.equal(leaksSecret(env.env.join('\n')), null)
      const allow = await runCli(w, ['preflight', '--json', '--cred', 'demo', '--method', 'GET', '--path', '/user'])
      assert.equal(allow.code, 0, allow.stdout)
      assert.equal(allow.json.ok, true)
      assert.equal(allow.json.data.would, 'allow')
      const hold = await runCli(w, ['preflight', '--json', '--cred', 'demo', '--method', 'POST', '--path', '/echo'])
      assert.equal(hold.code, 10, hold.stdout)
      assert.equal(hold.json.ok, true)
      assert.equal(hold.json.data.would, 'hold')
      const shown = assertOk(await runCli(w, ['session', 'show', '--json']), 'session show')
      assert.equal(shown.session.id, box.sid)
      assert.equal(leaksSecret(JSON.stringify(shown)), null)
    })

    test('templates, credential record commands, notify, tripwire, audit, listeners, and tls', async () => {
      assertOk(await runCli(w, [
        'template', 'save', 'read-user', '--cred', 'demo', '--methods', 'GET', '--paths', '/**', '--json',
      ]), 'template save')
      const templates = assertOk(await runCli(w, ['template', 'list', '--json']), 'template list')
      assert.ok(templates.some((t) => t.name === 'read-user'))
      assertOk(await runCli(w, ['template', 'show', 'read-user', '--json']), 'template show')
      assertOk(await runCli(w, ['template', 'rm', 'read-user', '--json']), 'template rm')

      assertOk(await runCli(w, ['cred', 'rotate', 'demo', '--json'], { input: 'test-secret-conform-rotate-0123456789ab\n' }), 'cred rotate')
      assertOk(await runCli(w, ['cred', 'expiry', 'demo', '2099-01-01', '--json']), 'cred expiry')
      const scrub = assertOk(await runCli(w, ['cred', 'scrub', 'demo', '--add', 'zzz[0-9]{8,16}', '--sample', 'zzz12345678', '--json']), 'cred scrub')
      assert.equal(typeof scrub.id, 'string')
      assertOk(await runCli(w, ['cred', 'scrub', 'demo', '--rm', scrub.id, '--json']), 'cred scrub rm')
      assertOk(await runCli(w, ['cred', 'pin', 'demo', '--host', '127.0.0.1', '--add', pinValue(), '--json']), 'cred pin')
      const tested = await runCli(w, ['cred', 'test', 'demo', '--json'])
      assert.equal(tested.code, 7, tested.stdout + tested.stderr)
      assert.equal(tested.json.ok, false)
      assert.equal(tested.json.error.code, 'AV_NOT_FOUND')
      assert.match(tested.json.error.message, /no probe/)
      const all = assertOk(await runCli(w, ['cred', 'test', '--all', '--json']), 'cred test --all')
      assert.ok(all.results.some((r) => r.slug === 'demo' && r.rule === 'no_probe'))

      const side = assertOk(await runCli(w, ['cred', 'add', 'side', '--kind', 'http', '--host', '127.0.0.1', '--json'], { input: `${SECRET}\n` }), 'cred add side')
      assert.equal(side.slug, 'side')
      assertOk(await runCli(w, ['cred', 'quarantine', 'side', '--reason', 'drill', '--json']), 'quarantine')
      assertOk(await runCli(w, ['cred', 'release', 'side', '--json']), 'release')
      const removed = assertOk(await runCli(w, ['cred', 'rm', 'side', '--json']), 'cred rm')
      assert.equal(removed.removed, 'side')

      const hook = `http://127.0.0.1:${w.upstream.port}/hook`
      assertOk(await runCli(w, ['notify', 'set', '--json'], { input: `${hook}\n` }), 'notify set')
      const shown = assertOk(await runCli(w, ['notify', 'show', '--json']), 'notify show')
      assert.match(shown.webhook.host, /^127\.0\.0\.1(:\d+)?$/)
      assert.equal(JSON.stringify(shown).includes('/hook'), false)
      const ping = assertOk(await runCli(w, ['notify', 'test', '--json']), 'notify test')
      assert.equal(ping.sent, true)
      assertOk(await runCli(w, ['notify', 'off', '--json']), 'notify off')

      assertOk(await runCli(w, ['tripwire', 'show', '--json']), 'tripwire show')
      assertOk(await runCli(w, ['tripwire', 'on', '--json']), 'tripwire on')
      assertOk(await runCli(w, [
        'tripwire', 'set', '--rule', 'conformance', '--window', '10m', '--threshold', '3',
        '--action', 'revoke_session', '--codes', 'AV_PH_REPLAY', '--json',
      ]), 'tripwire set')
      assertOk(await runCli(w, ['tripwire', 'off', '--json']), 'tripwire off')

      const tail = assertOk(await runCli(w, ['audit', 'tail', '--limit', '20', '--json']), 'audit tail')
      assert.ok(Array.isArray(tail))
      const chain = assertOk(await runCli(w, ['audit', 'verify', '--json']), 'audit verify')
      assert.equal(chain.ok, true)
      const exported = assertOk(await runCli(w, ['audit', 'export', '--json']), 'audit export')
      assert.ok(Array.isArray(exported.rows))
      const witness = join(w.dir, 'witness.jsonl')
      const witnessed = assertOk(await runCli(w, ['audit', 'witness', '--out', witness, '--json']), 'audit witness')
      assert.equal(typeof witnessed.head, 'string')
      assertOk(await runCli(w, ['audit', 'verify', '--witness', witness, '--json']), 'audit verify witness')
      const report = assertOk(await runCli(w, ['report', '--since', '7d', '--json']), 'report')
      assert.ok(report.credentials || report.sessions || typeof report === 'object')

      const listeners = assertOk(await runCli(w, ['listen', 'list', '--json']), 'listen list')
      assert.ok(Array.isArray(listeners))
      assertOk(await runCli(w, ['listen', 'add', 'loop', '--address', '127.0.0.1:59992', '--surfaces', 'gateway', '--json']), 'listen add')
      assertOk(await runCli(w, ['listen', 'rm', 'loop', '--json']), 'listen rm')
      assertOk(await runCli(w, ['tls', 'status', '--json']), 'tls status')
      const tls = assertOk(await runCli(w, ['tls', 'setup', '--json'], { timeout: 30_000 }), 'tls setup')
      assert.match(tls.certificate, /BEGIN CERTIFICATE/)
      assert.equal(leaksSecret(JSON.stringify(tls)), null)
      assert.equal(tls.certificate.includes('PRIVATE KEY'), false)
    })

    test('approvals, exec, mcp url, and mcp install', async () => {
      const pending = assertOk(await runCli(w, ['approvals', '--json']), 'approvals')
      assert.ok(Array.isArray(pending))
      const asked = await w.control('POST', '/v1/session-requests', {
        cred: 'demo', reason: 'conformance drill', methods: ['GET'], paths: ['/**'], budget: 5, ttl_minutes: 10,
      })
      assert.equal(asked.status, 200, asked.text)
      const denied = assertOk(await runCli(w, ['deny', asked.json.id, '--json']), 'deny')
      assert.equal(leaksSecret(JSON.stringify(denied)), null)
      const second = await w.control('POST', '/v1/session-requests', {
        cred: 'demo', reason: 'conformance drill', methods: ['GET'], paths: ['/**'], budget: 5, ttl_minutes: 10,
      })
      const approved = assertOk(await runCli(w, ['approve', second.json.id, '--json']), 'approve')
      assert.equal(leaksSecret(JSON.stringify(approved)), null)

      const child = await runCli(w, ['exec', '--json', '--', process.execPath, '-e', 'process.stdout.write("child-ok\\n")'])
      assert.equal(child.code, 0, child.stderr)
      assert.equal(child.stdout, 'child-ok\n')
      assert.equal(child.json, null)
      assertFail(await runCli(w, ['exec', '--json', '--', 'no-such-agent-vault-bin']), 127, 'exec missing')

      const url = assertOk(await runCli(w, ['mcp', 'url', '--json']), 'mcp url')
      assert.match(url.url, /\/mcp$/)
      const block = assertOk(await runCli(w, ['mcp', 'install', '--agent', 'claude-code', '--scope', 'project', '--print', '--json']), 'mcp install')
      assert.equal(block.wrote, false)
      assert.equal(typeof block.block, 'string')

      const narrowed = assertOk(await runCli(w, ['session', 'narrow', '--methods', 'GET', '--json']), 'session narrow')
      assert.ok(narrowed.grants)
      const extra = assertOk(await runCli(w, [
        'session', 'create', '--cred', 'demo', '--methods', 'GET', '--paths', '/**', '--budget', '5', '--json',
      ]), 'session create 2')
      assertOk(await runCli(w, ['session', 'revoke', extra.session_id, '--json']), 'session revoke')

      const backup = await runCli(w, ['backup', 'export', '--out', join(w.dir, 'backup.json'), '--json'], {
        input: 'recovery-phrase-ok\nrecovery-phrase-ok\n',
      })
      assert.equal(backup.code, 5, backup.stdout + backup.stderr)
      assert.equal(backup.json.ok, false)
      assert.match(backup.json.error.message, /human factor/)
    })

    test('a command against a directory with no daemon is unreachable', async () => {
      const dir = await mkdtemp(join(process.platform === 'win32' ? tmpdir() : '/tmp', 'avc-'))
      try {
        const world = { dir, env: envFor(dir), bins: binaries() }
        assertFail(await runCli(world, ['status', '--json']), 3, 'status down')
        const mcp = await runCli(world, ['mcp'], { timeout: 5000 })
        assert.equal(mcp.code, 9)
        assert.match(mcp.stderr, /no session/)
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    })

    test('daemon, ui, docs, and watch start and stop', async () => {
      const dir = await mkdtemp(join(process.platform === 'win32' ? tmpdir() : '/tmp', 'avc-'))
      const world = { dir, env: envFor(dir), bins: binaries() }
      try {
        const created = await runCli(world, ['setup', '--dev', '--json'])
        assert.equal(created.code, 0, created.stderr + created.stdout)
        assert.equal(created.json, null)
        assert.match(created.stdout, /created/)
        const daemon = await runCli(world, ['daemon', '--port', '0'], {
          timeout: 15_000,
          until: (out) => /gateway\s+http:\/\/127\.0\.0\.1:\d+/.test(out),
        })
        assert.match(daemon.stdout, /gateway\s+http:\/\/127\.0\.0\.1:\d+/)
        assert.equal(daemon.json, null)
        assert.equal(leaksSecret(daemon.stdout + daemon.stderr), null)
      } finally {
        await rm(dir, { recursive: true, force: true })
      }

      const complete = (out) => {
        const text = out.trim()
        if (!text.startsWith('{')) return false
        try { JSON.parse(text); return true } catch { return false }
      }
      const ui = await runCli(w, ['ui', '--port', '0', '--no-open', '--json'], {
        timeout: 15_000,
        until: complete,
      })
      assert.equal(ui.json?.ok, true, ui.stdout.slice(0, 500))
      assert.match(ui.json.data.url, /^http:\/\/(127\.0\.0\.1|localhost):\d+/)
      const docs = await runCli(w, ['docs', '--port', '0', '--no-open', '--json'], {
        timeout: 15_000,
        until: complete,
      })
      assert.equal(docs.json?.ok, true, docs.stdout.slice(0, 500))
      assert.match(docs.json.data.url, /#docs\//)
      const watch = await runCli(w, ['watch', '--no-notify', '--json'], { timeout: 2500 })
      assert.ok(watch.code === null || watch.signal === 'SIGTERM' || watch.signal === 'SIGKILL' || watch.code === 0)
      assert.equal(leaksSecret(watch.stdout + watch.stderr), null)
    })

    test('panic revokes sessions from its own vault', async () => {
      const own = await openWorld()
      try {
        const host = `127.0.0.1:${own.upstream.port}`
        assertOk(await runCli(own, ['cred', 'add', 'demo', '--kind', 'http', '--host', host, '--scheme', 'http', '--json'], { input: `${SECRET}\n` }), 'panic cred')
        assertOk(await runCli(own, ['session', 'create', '--cred', 'demo', '--methods', 'GET', '--json']), 'panic session')
        const panic = assertOk(await runCli(own, ['panic', '--reason', 'conformance drill', '--json']), 'panic')
        assert.ok(panic.revoked_sessions >= 1)
        const sessions = assertOk(await runCli(own, ['session', 'list', '--json']), 'panic list')
        assert.equal(sessions.some((s) => s.state === 'active'), false)
        assert.equal(PASSPHRASE.length >= 8, true)
      } finally {
        await own.close()
      }
    })
  })
}
