// A smoke test of the real command-line app: spawn the binary, drive the whole
// lifecycle through it, and assert that the CLI never prints a secret.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'

const BIN = new URL('../../bin/agent-vault.js', import.meta.url).pathname
const SECRET = 'ghp_CLITESTSECRET001122334455667788990011'

let dir, daemonProc

/**
 * Run the real binary. `input` is written to stdin, which is how a credential
 * value reaches the CLI: never on argv, where ps would show it.
 */
function av(args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      env: { ...process.env, AGENT_VAULT_DIR: dir, NO_COLOR: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d })
    child.stderr.on('data', (d) => { stderr += d })
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`timeout: ${args.join(' ')}`)) }, 15000)
    child.on('close', (code) => {
      clearTimeout(timer)
      if (code === 0) resolve({ stdout, stderr, code })
      else reject(Object.assign(new Error(`exit ${code}: ${stderr || stdout}`), { stdout, stderr, code }))
    })
    child.on('error', (e) => { clearTimeout(timer); reject(e) })
    if (input !== undefined) child.stdin.write(input)
    child.stdin.end()
  })
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-cli-'))
  await av(['setup', '--dev'])
  daemonProc = spawn(process.execPath, [BIN, 'daemon', '--port', '0'], {
    env: { ...process.env, AGENT_VAULT_DIR: dir, NO_COLOR: '1' },
    stdio: 'pipe',
  })
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('daemon did not start')), 8000)
    daemonProc.stdout.on('data', (d) => {
      if (d.toString().includes('control')) { clearTimeout(timer); resolve() }
    })
    daemonProc.on('error', reject)
  })
})

after(async () => {
  // Wait for the daemon to actually exit before removing its directory: it
  // unlinks its socket on the way out, and racing that leaves the directory
  // non-empty.
  if (daemonProc && daemonProc.exitCode === null) {
    const exited = new Promise((resolve) => daemonProc.once('exit', resolve))
    daemonProc.kill('SIGTERM')
    await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))])
  }
  if (dir) rmSync(dir, { recursive: true, force: true })
})

test('setup creates a vault and says what it does not protect against', async () => {
  const { stdout } = await av(['doctor', '--json'])
  const checks = JSON.parse(stdout).data
  assert.ok(checks.find((c) => c.name === 'vault present').ok)
  assert.ok(checks.find((c) => c.name === 'vault directory mode 0700').ok)
  const boundary = checks.find((c) => c.name === 'separate uid boundary')
  assert.equal(boundary.ok, false, 'the missing uid boundary must be reported, not hidden')
})

test('a credential value is read from stdin and never echoed back', async () => {
  const { stdout } = await av(['cred', 'add', 'cli-gh', '--kind', 'http', '--host', '127.0.0.1:1'], SECRET)
  assert.ok(!stdout.includes(SECRET), 'the CLI must not print the value it just stored')
  assert.match(stdout, /added cli-gh/)
  assert.match(stdout, /fingerprint/)
})

test('cred list shows a fingerprint and the injection site, never a value', async () => {
  const { stdout } = await av(['cred', 'list', '--json'])
  const creds = JSON.parse(stdout).data
  assert.equal(creds[0].slug, 'cli-gh')
  assert.ok(!JSON.stringify(creds).includes(SECRET))
  assert.deepEqual(creds[0].fields[0].sites, ['header:authorization:Bearer'])
})

test('session create returns a placeholder and tells the agent where to put it', async () => {
  const { stdout } = await av(['session', 'create', '--cred', 'cli-gh', '--json'])
  const s = JSON.parse(stdout).data
  assert.match(s.placeholder, /^av1\./)
  assert.match(s.usage[0], /Authorization: Bearer/)
  assert.ok(!stdout.includes(SECRET))
})

test('ph next issues a further placeholder for the same session', async () => {
  const { stdout } = await av(['ph', 'next', 'cli-gh', '--json'])
  assert.match(JSON.parse(stdout).data.placeholder, /^av1\./)
})

test('ph check validates shape and explains a corrupted placeholder', async () => {
  const { stdout } = await av(['ph', 'next', 'cli-gh', '--json'])
  const good = JSON.parse(stdout).data.placeholder
  const ok = await av(['ph', 'check', good, '--json'])
  assert.equal(JSON.parse(ok.stdout).ok, true)
  await assert.rejects(av(['ph', 'check', `${good}XX`, '--json']))
})

test('env prints only capabilities, never a credential', async () => {
  const { stdout } = await av(['env', '--json'])
  const lines = JSON.parse(stdout).data.env.join('\n')
  assert.ok(lines.includes('AGENT_VAULT_SESSION='))
  assert.ok(lines.includes('AGENT_VAULT_PLACEHOLDER='))
  assert.ok(!lines.includes(SECRET))
})

test('a vault with no human factor says so, loudly, in both status and doctor', async () => {
  // The uid boundary stops an agent reading the vault. Nothing stops it USING
  // the vault until a factor is enrolled: every widening operation is gated on
  // human presence, and presence cannot be required when there is nothing to
  // require it against. In that state the first caller to reach the control
  // socket can also set a passphrase of its own and keep the vault.
  //
  // The daemon creates the vault unattended, so this is the state every
  // install starts in and the one this harness is in. It is a real window and
  // it cannot be closed from inside the daemon — so the requirement is that it
  // is impossible to sit in without being told.
  const doctor = JSON.parse((await av(['doctor', '--json'])).stdout)
  const factor = doctor.data.find((c) => c.name === 'human factor enrolled')
  assert.ok(factor, 'doctor does not check for a human factor at all')
  assert.equal(factor.ok, false, 'this vault has no factor, so the check must not pass')
  assert.match(factor.note, /passphrase set/, 'the warning must name the command that fixes it')

  const { stdout } = await av(['status'])
  assert.match(stdout, /no human factor is enrolled/)
})

test('audit verify reports an intact chain', async () => {
  const { stdout } = await av(['audit', 'verify', '--json'])
  assert.equal(JSON.parse(stdout).data.ok, true)
})

test('listen add refuses the control surface on a network address', async () => {
  await assert.rejects(
    av(['listen', 'add', 'bad', '--address', 'eth0:7411', '--surfaces', 'gateway,control', '--json']),
    (e) => /AV_REMOTE_FORBIDDEN|never be bound/.test(e.stdout || e.message),
  )
})

test('setup shows the plan and the exact program root will run, before asking', async () => {
  // Run against a pristine dir so it takes the system-install path.
  const fresh = mkdtempSync(join(tmpdir(), 'av-setup-'))
  try {
    const { stdout } = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [BIN, 'setup'], {
        env: { ...process.env, AGENT_VAULT_DIR: fresh, NO_COLOR: '1' }, stdio: ['pipe', 'pipe', 'pipe'],
      })
      let o = ''
      child.stdout.on('data', (d) => { o += d })
      const t = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('setup hung')) }, 15000)
      child.on('close', () => { clearTimeout(t); resolve({ stdout: o }) })
      child.stdin.end()
    })
    assert.match(stdout, /root will run exactly one program/)
    assert.match(stdout, /agent-vault-setup\.js/)
    assert.match(stdout, /this is the boundary/, 'the plan must show what it would create')
    // With no terminal it must not hang waiting for an answer.
    assert.match(stdout, /run it yourself/i)
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('setup --print-only emits just the command, for scripting', async () => {
  const fresh = mkdtempSync(join(tmpdir(), 'av-setup2-'))
  try {
    const { stdout } = await av(['setup', '--print-only'])
    // The --from argument is what makes an upgrade install new code rather
            // than reinstalling whatever is already in the root-owned tree.
            assert.match(stdout.trim(), /^sudo \S+node\S* \S+agent-vault-setup\.js install --from \S+$/)
  } finally {
    rmSync(fresh, { recursive: true, force: true })
  }
})

test('the CLI refuses to run as root and names the command to use instead', async () => {
  // Simulated rather than actually elevated: the check is on getuid().
  const { stdout, stderr } = await new Promise((resolve) => {
    const child = spawn(process.execPath, [
      '-e',
      `process.getuid = () => 0; process.env.SUDO_COMMAND='/usr/bin/av status';` +
      `import(${JSON.stringify(new URL('../../src/cli/index.js', import.meta.url).href)}).then(m => m.main(['status']))`,
    ], { env: { ...process.env, AGENT_VAULT_DIR: dir, NO_COLOR: '1' }, stdio: ['pipe', 'pipe', 'pipe'] })
    let o = ''; let e = ''
    child.stdout.on('data', (d) => { o += d })
    child.stderr.on('data', (d) => { e += d })
    child.on('close', () => resolve({ stdout: o, stderr: e }))
    child.stdin.end()
  })
  const all = stdout + stderr
  assert.match(all, /Do not run agent-vault under sudo/)
  assert.match(all, /run this instead:\s+av status/)
})

test('an unknown command lists what is available instead of just failing', async () => {
  await assert.rejects(av(['frobnicate']), (e) => /unknown command/.test(e.stdout || e.stderr || ''))
})
