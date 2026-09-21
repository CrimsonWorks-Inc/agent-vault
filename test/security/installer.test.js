// The privileged installer, exercised through its dry run.
//
// The install itself needs root, so these tests drive the one path that does
// not: the plan. That is enough to catch the things that actually went wrong
// here, which were not crypto but ordinary systems mistakes. A vault retired
// inside a directory the next step deletes, a command printed for the operator
// that would not run, a socket group the daemon could not set.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const SETUP = new URL('../../bin/agent-vault-setup.js', import.meta.url).pathname
const SOURCE = readFileSync(SETUP, 'utf8')

const dryRun = (verb) => {
  const res = spawnSync(process.execPath, [SETUP, verb, '--dry-run'], { encoding: 'utf8' })
  return `${res.stdout}${res.stderr}`
}

test('the plan can be read without root, which is what makes it an inspection step', () => {
  const res = spawnSync(process.execPath, [SETUP, 'install', '--dry-run'], { encoding: 'utf8' })
  assert.equal(res.status, 0, res.stderr)
  assert.match(res.stdout, /dry run: nothing will change/)
})

test('the plan names the boundary explicitly', () => {
  const out = dryRun('install')
  assert.match(out, /0700/)
  assert.match(out, /this is the boundary/)
})

test('the vault directory is owned by the service user, not root and not you', () => {
  const out = dryRun('install')
  // The service uid placeholder in a dry run is 399; what matters is that the
  // vault is not owned by uid 0 or by the invoking user.
  const line = out.split('\n').find((l) => l.includes('/vault') && l.includes('mkdir'))
  assert.ok(line, 'the plan must create the vault directory')
  assert.match(line, /owner 399:399/)
  assert.ok(!line.includes('owner 0:0'), 'a root-owned vault would not exclude the agent')
})

test('the socket directory is setgid, so sockets inherit the client group', () => {
  // Without this the daemon has to chown every socket, which fails when it is
  // not a member of the group, and the CLI silently cannot connect.
  assert.match(dryRun('install'), /mkdir -m 02750 .*\/run/)
})

test('the service user is added to the client group', () => {
  const out = dryRun('install')
  assert.match(out, /_agentvault to _agentvault_users/)
})

test('the uninstall command it prints uses the root-owned runtime', () => {
  // Printing a bare .js means root resolves `node` from its own PATH, which on
  // a machine using a version manager has no node at all.
  const out = dryRun('install')
  const line = out.split('\n').find((l) => l.includes('To remove everything'))
  assert.ok(line)
  assert.match(line, /runtime\/node .*agent-vault-setup\.js uninstall/)
})

test('the command to verify the boundary does not itself need sudo', () => {
  const line = dryRun('install').split('\n').find((l) => l.includes('Check it'))
  assert.ok(line)
  assert.ok(!line.includes('sudo'), 'checking you cannot read a file should not require a password')
  assert.match(line, /Permission denied/)
})

test('uninstall retires the vault outside the tree it then deletes', () => {
  // The bug this guards: on macOS the vault lives inside the install root, so
  // retiring it to a sibling path inside that root and then removing the root
  // destroyed the credentials the retire step exists to preserve.
  const retirePath = /agent-vault-retired-\$\{Date\.now\(\)\}/
  assert.match(SOURCE, retirePath, 'the retired path must be built outside ROOT')
  assert.ok(
    !/\$\{VAULT_DIR\}\.retired-/.test(SOURCE),
    'retiring to a sibling of the vault puts it inside the install root on macOS',
  )
  assert.match(SOURCE, /refusing to remove .*your retired vault is inside it/,
    'there must be a guard in case that relationship changes again')
})

test('uninstall keeps credentials unless --purge is given', () => {
  assert.match(SOURCE, /--purge deletes them instead/)
  assert.match(SOURCE, /deleted the vault and every credential in it/)
})

test('the service user is left in place on uninstall, so its uid is not reused', () => {
  assert.match(SOURCE, /removing it would free its uid for reuse/)
})

test('the runtime version is checked before it is enshrined', () => {
  // sudo resets PATH, so the interpreter running the installer is often older
  // than the operator's shell, and it becomes the daemon's runtime for good.
  assert.match(SOURCE, /MIN_NODE_MAJOR/)
  assert.match(SOURCE, /sudo resets PATH/)
})

test('install refuses a path chain that is writable by anyone but root', () => {
  assert.match(SOURCE, /assertRootOwnedChain/)
  assert.match(SOURCE, /root must not execute from it/)
})

test('the installer refuses to install its own directory over itself', () => {
  // The root-owned copy resolves its source relative to itself, so without a
  // guard an upgrade would reinstall the code already present and report
  // success. That is worse than failing: it looks like it worked.
  assert.match(SOURCE, /refusing to install the app directory over itself/)
  assert.match(SOURCE, /Pass --from/)
})

test('--from selects the checkout to install', () => {
  assert.match(SOURCE, /value\('from'\)/)
  const out = spawnSync(process.execPath, [SETUP, 'install', '--dry-run'], { encoding: 'utf8' }).stdout
  assert.match(out, /copied the daemon into .* from \//)
})

test('an installer predating --from cannot be used to upgrade itself', () => {
  // The root-owned copy is preferred because an agent cannot edit it, but one
  // that resolves its source relative to itself would reinstall the code
  // already present. The CLI has to detect that and bootstrap past it.
  const cli = readFileSync(new URL('../../src/cli/index.js', import.meta.url).pathname, 'utf8')
  assert.match(cli, /includes\("value\('from'\)"\)/, 'the CLI must probe the installed installer for --from support')
  assert.match(cli, /too old to upgrade itself/)
})

test('the service load waits out the teardown race rather than failing on it', () => {
  // launchctl bootout returns before the job is gone, so an immediate
  // bootstrap fails with "Bootstrap failed: 5: Input/output error". That is
  // exactly what a reinstall does, so it has to be handled rather than hit.
  assert.match(SOURCE, /serviceLoaded\(\)/)
  assert.match(SOURCE, /returns before the job is actually gone/)
  assert.match(SOURCE, /kickstart/, 'a service still registered can be restarted instead')
})

test('a failed service load prints the command that recovers it', () => {
  // The files are already installed at that point, so the operator needs the
  // one command that finishes the job, not a stack trace.
  assert.match(SOURCE, /could not start the service/)
  assert.match(SOURCE, /sudo launchctl bootout .* sudo launchctl bootstrap/)
})

test('the installer verifies the socket appeared instead of assuming', () => {
  assert.match(SOURCE, /control\.sock/)
  assert.match(SOURCE, /socket has not appeared yet/)
})

test('a reinstall restarts systemd rather than no-opping on an already-enabled unit', () => {
  assert.match(SOURCE, /'restart', 'agent-vault\.service'/)
})

// ------------------------------------------------ what root is asked to copy
//
// The installer runs as root and copies a checkout into the directory the
// daemon executes from. Node's cpSync keeps symbolic links as links, so a link
// planted in the checkout would leave the privileged daemon loading its own
// code through a path the human's account — and therefore an agent running as
// them — can still rewrite. That turns the documented one-time
// trust-on-first-use window into permanent code execution inside the daemon,
// which is precisely what the uid boundary exists to prevent.

test('a symbolic link in the checkout stops the install', () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-inst-'))
  try {
    mkdirSync(join(dir, 'src', 'store'), { recursive: true })
    mkdirSync(join(dir, 'bin'), { recursive: true })
    writeFileSync(join(dir, 'package.json'), '{}')
    writeFileSync(join(dir, 'bin', 'agent-vault.js'), '// real')
    // Exactly what an agent would plant: a real-looking module that resolves
    // to a file it still owns.
    symlinkSync('/tmp/agent-owned.js', join(dir, 'src', 'store', 'vault.js'))

    const res = spawnSync(process.execPath, [SETUP, 'install', '--dry-run', '--from', dir], { encoding: 'utf8' })
    const out = res.stdout + res.stderr
    assert.match(out, /symbolic link/i, 'the install should refuse a symlinked checkout')
    assert.match(out, /src\/store\/vault\.js/, 'and name the offending path')
    assert.match(out, /\/tmp\/agent-owned\.js/, 'and say where it points')
    assert.ok(!/would copied the daemon/.test(out), 'it must not report a copy it refused to do')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('a checkout with no symlinks installs normally', () => {
  // The refusal above is only useful if the ordinary case still works.
  const dir = mkdtempSync(join(tmpdir(), 'av-inst2-'))
  try {
    mkdirSync(join(dir, 'src', 'store'), { recursive: true })
    mkdirSync(join(dir, 'bin'), { recursive: true })
    writeFileSync(join(dir, 'package.json'), '{}')
    writeFileSync(join(dir, 'bin', 'agent-vault.js'), '// real')
    writeFileSync(join(dir, 'src', 'store', 'vault.js'), '// real')

    const res = spawnSync(process.execPath, [SETUP, 'install', '--dry-run', '--from', dir], { encoding: 'utf8' })
    const out = res.stdout + res.stderr
    assert.ok(!/symbolic link/i.test(out), `a clean checkout was refused: ${out.slice(0, 300)}`)
    assert.match(out, /would copied the daemon/, 'it should plan the copy')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('the copy dereferences, so nothing linked can survive it', () => {
  // Belt and braces behind the refusal above: if a link ever does get past the
  // check, its contents are copied rather than the link itself.
  const copyLine = SOURCE.split('\n').find((l) => l.includes('cpSync(join(source, part)'))
  assert.ok(copyLine, 'the install copy should still be one recognisable line')
  assert.match(copyLine, /dereference: true/, 'the install copy must dereference')
})
