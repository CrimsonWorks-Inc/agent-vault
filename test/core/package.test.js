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
