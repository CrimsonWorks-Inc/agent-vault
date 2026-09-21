// What would actually ship.
//
// Every other test runs against the checkout. `npm publish` ships whatever
// `files` in package.json says, which is a different thing — and the failure
// mode is silent and total: a module left out of `files` imports fine here and
// throws ENOENT on someone else's machine, after they have installed it.
//
// So this packs the real tarball, extracts it somewhere else, and uses it: runs
// the binary, imports the public export, and creates a working vault from the
// extracted copy alone. Slow by the standards of this suite, and worth it —
// nothing else checks that the product is a product.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const ROOT = new URL('../..', import.meta.url).pathname

function packed(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'av-pack-'))
  try {
    const pack = spawnSync('npm', ['pack', '--silent', '--pack-destination', dir], {
      cwd: ROOT, encoding: 'utf8',
    })
    if (pack.status !== 0) {
      // A machine without a usable npm is not a failing product.
      return { skipped: `npm pack unavailable: ${(pack.stderr || '').slice(0, 200)}` }
    }
    const tgz = pack.stdout.trim().split('\n').pop().trim()
    const tar = spawnSync('tar', ['xzf', join(dir, tgz)], { cwd: dir, encoding: 'utf8' })
    assert.equal(tar.status, 0, `extracting the tarball failed: ${tar.stderr}`)
    return fn(join(dir, 'package'), dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('the published package contains everything it needs and nothing it should not', () => {
  const r = packed((pkg) => {
    // Every file the code imports has to be in the tarball. A missing one
    // imports fine from the checkout and throws on a user's machine.
    for (const f of ['bin/agent-vault.js', 'bin/agent-vault-setup.js', 'src/core/index.js',
      'src/daemon/server.js', 'src/store/vault.js', 'src/ui/app.html', 'LICENSE']) {
      assert.ok(existsSync(join(pkg, f)), `${f} is missing from the published package`)
    }
    // And things that must NOT ship: the tests describe attacks, the demo
    // hardcodes a fake secret, and neither belongs in a dependency.
    for (const f of ['test', 'demo', '.github', 'node_modules']) {
      assert.ok(!existsSync(join(pkg, f)), `${f} was published`)
    }
    // A license users can actually read.
    assert.match(readFileSync(join(pkg, 'LICENSE'), 'utf8'), /Apache License/)
    return 'checked'
  })
  if (r?.skipped) return // npm unavailable; nothing to say about the package
  assert.equal(r, 'checked')
})

test('the published package runs, imports and creates a vault on its own', () => {
  const r = packed((pkg, dir) => {
    const node = process.execPath

    // The binary runs from the extracted copy.
    const help = spawnSync(node, [join(pkg, 'bin/agent-vault.js'), '--help'], { encoding: 'utf8' })
    assert.equal(help.status, 0, `the binary did not run: ${help.stderr}`)
    assert.match(help.stdout, /credential proxy/)

    // The documented entry point imports, and exports what it claims to.
    const imported = spawnSync(node, ['-e',
      `import(${JSON.stringify(join(pkg, 'src/core/index.js'))}).then(m => console.log(Object.keys(m).sort().join(',')))`,
    ], { encoding: 'utf8' })
    assert.equal(imported.status, 0, `the public export did not import: ${imported.stderr}`)
    for (const name of ['placeholder', 'policy', 'scrub', 'substitute', 'detect']) {
      assert.ok(imported.stdout.includes(name), `the package does not export ${name}`)
    }

    // And it can do the first thing a user does, using only its own files.
    const vaultDir = join(dir, 'vault')
    const setup = spawnSync(node, [join(pkg, 'bin/agent-vault.js'), 'setup', '--dev'], {
      encoding: 'utf8', env: { ...process.env, AGENT_VAULT_DIR: vaultDir, NO_COLOR: '1' },
    })
    assert.equal(setup.status, 0, `setup failed from the packed copy: ${setup.stderr || setup.stdout}`)
    assert.ok(existsSync(join(vaultDir, 'vault.json')), 'no vault was created')
    return 'checked'
  })
  if (r?.skipped) return
  assert.equal(r, 'checked')
})

test('the daemon reports the version the package actually is', () => {
  // It was written out twice in server.js as a literal. Two hardcoded copies
  // of a version string are two chances to report one the code is not — and
  // the CLI uses `daemon_version` to tell a human their daemon is older than
  // their commands, which is advice that has to be right.
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  const server = readFileSync(join(ROOT, 'src/daemon/server.js'), 'utf8')

  assert.ok(!/daemon_version: *'[\d.]/.test(server),
    'the version is hardcoded in server.js again')
  assert.match(server, /JSON\.parse\(readFileSync\(new URL\('\.\.\/\.\.\/package\.json'/,
    'the daemon should read its version from package.json')

  // And the version itself is a real one.
  assert.match(pkg.version, /^\d+\.\d+\.\d+(-[\w.]+)?$/, `"${pkg.version}" is not a version`)

  // The changelog's top entry names it, so a release cannot ship undocumented.
  const changelog = readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8')
  const firstHeading = /^## +(\S+)/m.exec(changelog)
  assert.ok(firstHeading, 'the changelog has no version heading')
  assert.equal(firstHeading[1], pkg.version,
    `the changelog's newest entry is ${firstHeading[1]} but the package is ${pkg.version}`)
})

test('no test can write state into the real vault directory', () => {
  // A UI server derives nothing about where state lives any more — it is told.
  // That mattered because it used to read AGENT_VAULT_DIR from the
  // environment, so an in-process test that never set it wrote a session token
  // into the author's own ~/.agent-vault/cli-state.json, replacing the live
  // one with a session in a temp vault that was about to be deleted.
  //
  // The rule this encodes: every writer of client state takes the path as an
  // argument. A default that reaches for the environment is a default that
  // will one day point at somebody's real vault.
  const state = readFileSync(join(ROOT, 'src/client-state.js'), 'utf8')
  for (const fn of ['loadState', 'saveState', 'rememberSession']) {
    const sig = new RegExp(`export function ${fn}\\(([^)]*)\\)`).exec(state)
    assert.ok(sig, `${fn} is gone`)
    assert.match(sig[1], /path = statePath\(\)|path\b/,
      `${fn} must take the state path as an argument, not reach for the environment`)
  }

  // And the UI takes it from its caller rather than the environment.
  const ui = readFileSync(join(ROOT, 'src/ui/server.js'), 'utf8')
  assert.match(ui, /this\.statePath = statePath \|\|/,
    'the UI server must be told where state lives')
  assert.ok(!/process\.env\.AGENT_VAULT_DIR/.test(ui),
    'the UI server must not derive the vault directory from the environment')
  assert.match(ui, /rememberSession\(created, this\.statePath\)/,
    'the UI must write to the path it was given')
})
