// The command-line app.
//
// The CLI is untrusted by design: it holds no key material, and every command
// is a thin client of the daemon's control socket. Errors are written for an
// agent as much as a human, so a denial names the rule and the exact next
// command rather than just failing.

import { request } from 'node:http'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve as resolvePath } from 'node:path'
import { createInterface } from 'node:readline'
import { createHash } from 'node:crypto'
import * as nodeFs from 'node:fs'
import { Vault } from '../store/vault.js'
import { Daemon } from '../daemon/server.js'
import { listProfiles } from '../connectors/profiles.js'
import { EXIT } from '../core/errors.js'
import * as ph from '../core/placeholder.js'

// A system install puts the vault behind its own uid. The CLI finds it by the
// state file the privileged installer writes, and falls back to a dev vault in
// the home directory when there is none.
const SYSTEM_ROOT = process.platform === 'darwin' ? '/var/db/agent-vault' : '/usr/libexec/agent-vault'
const SYSTEM_VAULT = process.platform === 'darwin' ? join(SYSTEM_ROOT, 'vault') : '/var/lib/agent-vault'
const SYSTEM_RUN = process.platform === 'darwin' ? join(SYSTEM_ROOT, 'run') : '/run/agent-vault'
export const SYSTEM_INSTALLED = existsSync(join(SYSTEM_ROOT, 'state.json'))

// An explicit override always wins, so a dev or test vault is reachable even on
// a machine that already has the system install.
export const VAULT_OVERRIDDEN = !!process.env.AGENT_VAULT_DIR
/** True only when the system install is the vault actually in use. */
export const USING_SYSTEM = SYSTEM_INSTALLED && !process.env.AGENT_VAULT_DIR
const DEV_VAULT_DIR = process.env.AGENT_VAULT_DIR || join(homedir(), '.agent-vault')
export const VAULT_DIR = process.env.AGENT_VAULT_DIR
  || (SYSTEM_INSTALLED ? SYSTEM_VAULT : DEV_VAULT_DIR)
const SOCKET = process.env.AGENT_VAULT_DIR
  ? join(process.env.AGENT_VAULT_DIR, 'control.sock')
  : (SYSTEM_INSTALLED ? join(SYSTEM_RUN, 'control.sock') : join(VAULT_DIR, 'control.sock'))

// CLI-side state holds only capabilities, never a secret, so it lives beside
// the user rather than behind the boundary. It still follows AGENT_VAULT_DIR
// when that is set, so a dev or test vault stays fully self-contained.
const CLI_STATE_DIR = process.env.AGENT_VAULT_DIR || join(homedir(), '.agent-vault')
const STATE = join(CLI_STATE_DIR, 'cli-state.json')
const SETUP_BIN = new URL('../../bin/agent-vault-setup.js', import.meta.url).pathname

const C = process.stdout.isTTY && !process.env.NO_COLOR
  ? { dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`, red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`, cyan: (s) => `\x1b[36m${s}\x1b[0m` }
  : { dim: (s) => s, bold: (s) => s, green: (s) => s, red: (s) => s, yellow: (s) => s, cyan: (s) => s }

let JSON_OUT = false
const out = (human, data) => {
  if (JSON_OUT) console.log(JSON.stringify({ ok: true, data }, null, 2))
  else if (human) console.log(human)
}
const fail = (message, code = EXIT.FAILURE, extra = {}) => {
  if (JSON_OUT) console.log(JSON.stringify({ ok: false, error: { message, ...extra } }, null, 2))
  else {
    console.error(`${C.red('error')} ${message}`)
    if (extra.next) console.error(`${C.dim('next:')} ${extra.next}`)
  }
  process.exit(code)
}

// --------------------------------------------------------------- control API

function control(method, path, body) {
  return new Promise((resolve, reject) => {
    if (!existsSync(SOCKET)) {
      return reject(Object.assign(new Error('the daemon is not running'), {
        exit: EXIT.DAEMON_UNREACHABLE, next: 'agent-vault daemon',
      }))
    }
    const req = request({ socketPath: SOCKET, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        let parsed
        try { parsed = JSON.parse(text) } catch { parsed = { raw: text } }
        if (res.statusCode === 404 && /no control route/.test(parsed.detail || '')) {
          // The CLI and the daemon are from different builds. This is the only
          // way that shows up, so translate it into the thing to do about it.
          return reject(Object.assign(
            new Error('the running daemon is older than this command'),
            {
              exit: EXIT.VERSION_SKEW,
              skew: true,
              next: USING_SYSTEM
                ? 'agent-vault setup   (reinstalls from this checkout and restarts the service)'
                : 'restart the daemon you started with: agent-vault daemon',
              problem: parsed,
            },
          ))
        }
        if (res.statusCode >= 400) {
          reject(Object.assign(new Error(parsed.detail || parsed.message || text), { problem: parsed, exit: EXIT.FAILURE }))
        } else resolve(parsed)
      })
    })
    req.on('error', (e) => reject(Object.assign(e, { exit: EXIT.DAEMON_UNREACHABLE })))
    req.end(body ? JSON.stringify(body) : undefined)
  })
}

/**
 * Run a control call that may require human presence. On AV_PRESENCE_REQUIRED,
 * prompt for the passphrase to open a short window, then retry once.
 */
async function controlWithPresence(method, path, body) {
  try {
    return await control(method, path, body)
  } catch (e) {
    if (e.problem?.code !== 'AV_PRESENCE_REQUIRED') throw e
    // Asking for the passphrase and then refusing because the vault is locked
    // wastes the one secret the reader just typed, and the message arrives
    // after they have typed it. Check first, and name the command that helps.
    const state = await control('GET', '/v1/lockstate').catch(() => null)
    if (state?.locked) {
      throw Object.assign(new Error('the vault is locked'), {
        exit: EXIT.LOCKED, next: 'agent-vault unlock',
      })
    }
    // Work out what would actually satisfy this before deciding how to ask.
    // Checking the terminal first meant a vault whose only factor is an
    // authenticator reported "needs your passphrase" — naming a secret that
    // does not exist, which is the kind of error that costs an afternoon.
    const factors = e.problem?.factors || ['passphrase']
    if (!factors.includes('passphrase')) {
      throw Object.assign(new Error(`this change needs your ${factors.join(' or ')}`), {
        exit: EXIT.PRESENCE,
        next: 'agent-vault ui   (confirm it there with your authenticator)',
      })
    }
    if (!process.stdin.isTTY) {
      throw Object.assign(new Error('this change needs your passphrase, and there is no terminal to ask on'), {
        exit: EXIT.PRESENCE,
      })
    }
    console.error(`${C.dim('This change needs a human.')}`)
    const passphrase = await readSecret('passphrase: ')
    await control('POST', '/v1/presence/window', { passphrase })
    return control(method, path, body)
  }
}

function saveState(patch) {
  if (!existsSync(CLI_STATE_DIR)) mkdirSync(CLI_STATE_DIR, { recursive: true, mode: 0o700 })
  const current = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {}
  writeFileSync(STATE, JSON.stringify({ ...current, ...patch }, null, 2), { mode: 0o600 })
}
function loadState() {
  return existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {}
}

/**
 * How the reader is invoking this CLI, so printed commands can be pasted.
 * If it came from a shim on PATH we echo that name; run straight from the
 * checkout there is no such name, so we print the interpreter and the script.
 */
function cliInvocation() {
  const argv1 = process.argv[1] || ''
  const base = argv1.split('/').pop()
  if (base === 'agent-vault' || base === 'av') return base
  // Run straight from a checkout there is no such name in argv, but a shim may
  // still be installed; prefer it over a page full of absolute paths.
  for (const name of ['agent-vault', 'av']) {
    for (const dir of (process.env.PATH || '').split(':')) {
      if (dir && existsSync(join(dir, name))) return name
    }
  }
  return argv1 ? `${process.execPath} ${argv1}` : 'agent-vault'
}

/** Ask a plain question on the terminal. */
function ask(prompt) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    rl.question(prompt, (answer) => { rl.close(); resolve(answer) })
  })
}

// One shared line reader for piped input, so a command that asks for several
// secrets gets one line per prompt instead of the whole pipe on the first.
let pipedLines = null
function readPipedLine() {
  if (!pipedLines) {
    pipedLines = []
    pipedLines.rl = createInterface({ input: process.stdin })
    pipedLines.queue = []
    pipedLines.waiters = []
    pipedLines.ended = false
    pipedLines.rl.on('line', (line) => {
      if (pipedLines.waiters.length) pipedLines.waiters.shift()(line)
      else pipedLines.queue.push(line)
    })
    pipedLines.rl.on('close', () => {
      pipedLines.ended = true
      while (pipedLines.waiters.length) pipedLines.waiters.shift()('')
    })
  }
  return new Promise((resolve) => {
    if (pipedLines.queue.length) return resolve(pipedLines.queue.shift())
    if (pipedLines.ended) return resolve('')
    pipedLines.waiters.push(resolve)
  })
}

/** Read a secret from the terminal with echo off; never from argv. */
function readSecret(prompt) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      // A pipe is accepted so the demo and CI can run unattended; one line per
      // prompt, so a multi-secret command reads deterministically. A real
      // deployment gates this behind a presence proof instead.
      readPipedLine().then((line) => resolve(line.trim()))
      return
    }
    // Raw mode, drawn by hand. Using readline with terminal:true cleared the
    // line right after the prompt was written, so it only reappeared on the
    // first keystroke and felt hung. Here the prompt is written before any
    // input is read and stays put.
    const { stdin, stdout } = process
    const wasRaw = stdin.isRaw
    stdout.write(prompt)
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding('utf8')
    let value = ''
    const finish = (answer, err) => {
      stdin.setRawMode(wasRaw)
      stdin.pause()
      stdin.removeListener('data', onData)
      stdout.write('\n')
      if (err) reject(err); else resolve(answer)
    }
    const onData = (chunk) => {
      for (const ch of String(chunk)) {
        if (ch === '\r' || ch === '\n') return finish(value)
        if (ch === '\x03') return finish(null, Object.assign(new Error('cancelled'), { name: 'Cancelled' })) // Ctrl-C
        if (ch === '\x04') return finish(value) // Ctrl-D
        if (ch === '\x7f' || ch === '\b') { // backspace
          if (value.length) { value = value.slice(0, -1); stdout.write('\b \b') }
          continue
        }
        if (ch === '\x1b') return // ignore escape sequences (arrow keys, etc.)
        if (ch < ' ') continue // ignore other control characters
        value += ch
        stdout.write('*')
      }
    }
    stdin.on('data', onData)
  })
}

/**
 * Hash the code that actually runs, so an install can be compared with a
 * checkout. Version strings do not change during development, so comparing
 * those would call two different builds identical.
 */
function appFingerprint(root) {
  const { readdirSync, readFileSync: read, statSync } = nodeFs
  const hash = createHash('sha256')
  const walk = (dir, rel = '') => {
    let entries
    try { entries = readdirSync(dir, { withFileTypes: true }) } catch { return }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(dir, entry.name)
      const path = rel ? `${rel}/${entry.name}` : entry.name
      if (entry.isDirectory()) { walk(full, path); continue }
      if (!entry.name.endsWith('.js') && !entry.name.endsWith('.html')) continue
      try {
        hash.update(path)
        hash.update(read(full))
      } catch { /* unreadable files simply do not contribute */ }
    }
  }
  for (const part of ['src', 'bin']) walk(join(root, part), part)
  return hash.digest('hex').slice(0, 16)
}

/**
 * Run a guided flow. Ctrl-C during a wizard is an ordinary outcome, not an
 * error: nothing has been committed at that point.
 */
async function runWizard(flow) {
  try {
    return await flow()
  } catch (e) {
    if (e.name === 'Cancelled') {
      console.log(`\n${C.dim('cancelled; nothing was changed')}`)
      process.exit(0)
    }
    if (e.noTty) return fail(e.message, EXIT.USAGE, { next: 'pass the options as flags instead' })
    throw e
  }
}

// ----------------------------------------------------------------- commands

const COMMANDS = {
  async setup(args) {
    // Only report the system install when it is the one actually in use. An
    // explicit AGENT_VAULT_DIR, or --dev, means someone wants a different vault
    // and should not be told about this one instead.
    if (USING_SYSTEM && !args.dev) {
      const checkout = new URL('../..', import.meta.url).pathname.replace(/\/$/, '')
      const installedApp = join(SYSTEM_ROOT, 'app')
      const installed = appFingerprint(installedApp)
      const current = appFingerprint(checkout)
      const same = installed === current

      if (JSON_OUT) {
        return out(null, { mode: 'system', vault: SYSTEM_VAULT, installed, current, up_to_date: same })
      }
      console.log(`${C.green('ok')} system install present ${C.dim(`vault at ${SYSTEM_VAULT}`)}`)
      if (same) {
        console.log(C.dim(`  the installed daemon matches this checkout (${current})`))
        return
      }

      console.log()
      console.log(`  ${C.yellow('The installed daemon is not this code.')}`)
      console.log(`    running    ${C.dim(installed)}`)
      console.log(`    this tree  ${C.dim(current)}`)
      console.log()
      console.log('  Updating reinstalls the daemon from this checkout and restarts the service.')
      console.log(C.dim('  Your credentials are untouched; only the code is replaced.'))
      console.log()
      if (!process.stdin.isTTY) {
        console.log(`  Run it yourself: ${C.cyan('agent-vault upgrade')}`)
        return
      }
      if (!await ask('  Update it now? [y/N] ').then((a) => /^y(es)?$/i.test(a.trim()))) {
        console.log(`\n  Nothing changed. When you are ready: ${C.cyan('agent-vault upgrade')}`)
        return
      }
      return COMMANDS.upgrade({})
    }

    // The default is the real thing: a separate service user, which needs root.
    //
    // This command runs as you and hands root exactly one small program, by
    // absolute path. Running the whole CLI under sudo is a different and worse
    // thing, and is refused: it would put every code path in this package,
    // plus whatever interpreter is first on root's PATH, inside a root process.
    //
    // Once installed, the installer used from then on is the root-owned copy,
    // which an agent cannot edit. Only the first install is trust-on-first-use,
    // which is why it shows the plan and the file to verify before asking for
    // a password.
    if (!args.dev) {
      const { existsSync: exists } = await import('node:fs')
      const rootOwnedInstaller = join(SYSTEM_ROOT, 'app', 'bin', 'agent-vault-setup.js')
      const installer = exists(rootOwnedInstaller) ? rootOwnedInstaller : SETUP_BIN
      // Always name the checkout this CLI came from. Without it the root-owned
      // installer would reinstall the code it already has, so upgrading would
      // appear to work and change nothing.
      const checkout = new URL('../..', import.meta.url).pathname.replace(/\/$/, '')
      const argv = [process.execPath, installer, 'install', '--from', checkout]
      if (args.port) argv.push('--port', String(args.port))
      const cmd = `sudo ${argv.join(' ')}`

      if (JSON_OUT) return out(null, { mode: 'system', command: cmd, installer, installed: false })
      if (args['print-only']) return console.log(cmd)

      console.log(`${C.bold('agent-vault needs one privileged step.')}`)
      console.log()
      console.log('  It creates a system user and gives it sole ownership of the vault, so')
      console.log('  an agent running as you cannot read your credentials at all.')
      console.log()
      console.log(`  root will run exactly one program:`)
      console.log(`    ${C.cyan(installer)}`)
      if (installer === SETUP_BIN) {
        console.log(C.dim('    This copy lives in a directory you own, so this first run is'))
        console.log(C.dim('    trust-on-first-use. Read it first if that matters to you.'))
      } else {
        console.log(C.dim('    This is the root-owned copy from your existing install.'))
      }
      console.log()

      // Show the plan before asking for a password. The dry run is
      // unprivileged, so this costs nothing and reveals every change.
      const { spawnSync, spawn } = await import('node:child_process')
      console.log(C.dim('  Plan:'))
      const plan = spawnSync(process.execPath, [installer, 'install', '--dry-run'], { encoding: 'utf8' })
      for (const line of (plan.stdout || '').split('\n').slice(2)) {
        if (line.trim()) console.log(`  ${C.dim(line)}`)
      }
      console.log()

      if (!process.stdin.isTTY) {
        console.log('  No terminal here, so run it yourself:')
        console.log(`    ${C.cyan(cmd)}`)
        return
      }

      const answer = await ask(`  Run it now? sudo will ask for your password. [y/N] `)
      if (!/^y(es)?$/i.test(answer.trim())) {
        console.log()
        console.log(`  Nothing was changed. When you are ready:`)
        console.log(`    ${C.cyan(cmd)}`)
        return
      }

      console.log()
      const child = spawn('sudo', argv, { stdio: 'inherit' })
      const code = await new Promise((resolve) => child.on('exit', resolve))
      process.exitCode = code ?? 0
      if (code) return

      // The daemon has created the vault by now. Offer the passphrase here, so
      // "set one at setup time" is a real option and not just advice.
      try {
        await new Promise((r) => setTimeout(r, 800)) // let the socket appear
        const ls = await control('GET', '/v1/lockstate')
        if (!ls.has_passphrase && process.stdin.isTTY) {
          console.log()
          console.log('  Set a passphrase now? It makes the lock cryptographic, so a locked')
          console.log('  vault cannot be unlocked by anything that reaches the socket.')
          if (await ask('  Set a passphrase? [y/N] ').then((a) => /^y(es)?$/i.test(a.trim()))) {
            await COMMANDS['passphrase:set']({})
          } else {
            console.log(C.dim(`  You can set one later: ${C.cyan('agent-vault passphrase set')}`))
          }
        }
      } catch { /* the daemon may still be starting; the command stands alone */ }
      return
    }

    if (existsSync(join(DEV_VAULT_DIR, 'vault.json'))) {
      return out(`${C.green('ok')} dev vault already at ${DEV_VAULT_DIR}`, { dir: DEV_VAULT_DIR, existed: true })
    }
    mkdirSync(DEV_VAULT_DIR, { recursive: true, mode: 0o700 })
    const passphrase = args.passphrase ? await readSecret('passphrase: ') : null
    Vault.create(DEV_VAULT_DIR, { factor: passphrase ? 'passphrase' : 'none', passphrase })
    console.log(`${C.green('created')} ${DEV_VAULT_DIR} ${C.dim('(mode 0700)')}`)
    console.log()
    console.log(C.yellow('  Dev mode: the daemon will run as you, so the vault is protected by file'))
    console.log(C.yellow('  mode alone. Anything running as your account can read it, including an'))
    console.log(C.yellow('  agent. Do not put a credential here you would mind losing.'))
    console.log()
    console.log(`next: ${C.cyan('agent-vault daemon')} in one terminal, then ${C.cyan('agent-vault cred add <slug> --kind github')}`)
  },

  async daemon(args) {
    if (USING_SYSTEM) {
      return fail('the daemon is managed by the system service and is already running as its own user',
        EXIT.USAGE, { next: 'agent-vault status' })
    }
    const vault = Vault.open(VAULT_DIR)
    const unlocked = vault.startInRecordedState(args.passphrase ? await readSecret('passphrase: ') : null)
    const daemon = new Daemon(vault, { port: Number(args.port || process.env.AGENT_VAULT_PORT || 7411), socketPath: SOCKET })
    await daemon.start()
    console.log(`${C.green('agent-vault daemon')} listening`)
    console.log(`  gateway  http://127.0.0.1:${daemon.gatewayPort}`)
    console.log(`  mcp      http://127.0.0.1:${daemon.gatewayPort}/mcp ${C.dim('(Streamable HTTP)')}`)
    console.log(`  control  ${SOCKET} ${C.dim('(unix socket, mode 0600, never a network address)')}`)
    for (const l of daemon.listeners || []) {
      const scheme = l.tls ? 'https' : 'http'
      console.log(`  ${C.bold(l.id.padEnd(7))}  ${scheme}://${l.host}:${l.port} ${C.dim(`(${l.surfaces.join(',')}${l.tls ? ', tls' : ''})`)}`)
    }
    if (!unlocked) {
      console.log(`  ${C.yellow('vault is locked')} ${C.dim('(it was locked when the daemon last stopped)')}`)
      console.log(C.dim('  unlock it with: agent-vault unlock'))
    }
    console.log(C.dim('  ctrl-c to stop'))
    saveState({ gateway_port: daemon.gatewayPort })
    const shutdown = async () => { await daemon.stop(); process.exit(0) }
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)
  },

  /** Reinstall the daemon from this checkout. The only way to ship new code. */
  async upgrade(args) {
    if (!USING_SYSTEM) {
      return fail('there is no system install to upgrade', EXIT.USAGE, {
        next: 'agent-vault setup   (installs it), or just restart: agent-vault daemon',
      })
    }
    const checkout = new URL('../..', import.meta.url).pathname.replace(/\/$/, '')
    const rootOwned = join(SYSTEM_ROOT, 'app', 'bin', 'agent-vault-setup.js')

    // Prefer the root-owned installer, which an agent cannot edit. But an
    // installer predating --from resolves its source relative to itself, so it
    // would reinstall the code already there and report success. When the
    // installed copy is that old, the checkout's installer is the only one that
    // can bootstrap the upgrade.
    let installer = SETUP_BIN
    let usingRootOwned = false
    if (existsSync(rootOwned)) {
      try {
        if (readFileSync(rootOwned, 'utf8').includes("value('from')")) {
          installer = rootOwned
          usingRootOwned = true
        }
      } catch { /* unreadable: fall back to the checkout copy */ }
    }
    const argv = [process.execPath, installer, 'install', '--from', checkout]
    const cmd = `sudo ${argv.join(' ')}`

    if (args['print-only'] || JSON_OUT) return out(cmd, { command: cmd })
    if (!process.stdin.isTTY) {
      console.log(`Run this to update the installed daemon:\n  ${C.cyan(cmd)}`)
      return
    }
    console.log(`${C.dim('root will run:')} ${C.cyan(installer)}`)
    console.log(`${C.dim('installing from:')} ${checkout}`)
    if (!usingRootOwned) {
      console.log(C.dim('  (the installed copy is too old to upgrade itself, so this uses the'))
      console.log(C.dim('   installer from your checkout; later upgrades use the root-owned one)'))
    }
    console.log()
    const { spawn } = await import('node:child_process')
    const child = spawn('sudo', argv, { stdio: 'inherit' })
    return new Promise((resolve) => child.on('exit', (code) => { process.exitCode = code ?? 0; resolve() }))
  },

  /** Nothing to an agent making a call, in one guided flow. */
  async quickstart() {
    if (!process.stdin.isTTY) {
      return fail('quickstart needs a terminal', EXIT.USAGE, {
        next: 'agent-vault cred add <slug> --kind <kind>, then agent-vault session create --cred <slug>',
      })
    }
    const { quickstart: run } = await import('./wizards.js')
    return runWizard(() => run(controlWithPresence))
  },

  async status() {
    const s = await control('GET', '/v1/status')
    if (JSON_OUT) return out(null, s)
    console.log(`${C.bold('agent-vault')} ${s.daemon_version}  ${s.locked ? C.red('locked') : C.green('unlocked')}`)
    console.log(`  gateway        http://127.0.0.1:${s.gateway_port}`)
    console.log(`  credentials    ${s.credentials}`)
    console.log(`  sessions       ${s.sessions_active} active`)
    console.log(`  grants         ${s.grants_active} active`)
    console.log(`  placeholders   ${s.placeholders_live} live`)
    console.log(`  audit records  ${s.audit_records ?? C.dim('unavailable while locked')}`)
    // With neither factor enrolled the control socket is open to anything
    // running as you, and the first thing that reaches it can set a passphrase
    // of its own choosing and keep the vault. That is a bad thing to learn
    // later, so it is on the status line.
    const ls = await control('GET', '/v1/lockstate').catch(() => null)
    if (ls && !ls.has_passphrase && !ls.has_touchid) {
      console.log()
      console.log(`  ${C.yellow('no human factor is enrolled')}`)
      console.log(C.dim('  Anything running as you can use every credential here, and can set a'))
      console.log(C.dim('  passphrase of its own — after which the vault is no longer yours.'))
      console.log(`  ${C.cyan('agent-vault passphrase set')}`)
    }
  },

  async 'cred:add'(args) {
    const slug = args._[0]

    // No arguments and a terminal means someone wants to be walked through it.
    // With arguments, or without a terminal, behave exactly as before so
    // scripts keep working.
    if (!slug && !JSON_OUT) {
      if (!process.stdin.isTTY) {
        return fail('cred add needs a name when there is no terminal', EXIT.USAGE, {
          next: 'agent-vault cred add <slug> --kind github   (value on stdin)',
        })
      }
      const { credentialWizard } = await import('./wizards.js')
      return runWizard(() => credentialWizard(controlWithPresence))
    }
    if (!slug) return fail('usage: agent-vault cred add <slug> --kind <kind> [--host <host>]', EXIT.USAGE)
    const value = await readSecret(`value for ${slug} (not echoed): `)
    if (!value) return fail('no value given', EXIT.USAGE)
    const cred = await controlWithPresence('POST', '/v1/credentials', {
      slug, kind: args.kind || 'http', host: args.host, scheme: args.scheme, value,
    })
    out(`${C.green('added')} ${cred.slug} ${C.dim(`(${cred.kind}, fingerprint ${cred.fields[0].fp8})`)}\n` +
        `  placeholder goes at: ${cred.fields[0].sites.join(', ')}`, cred)
    // A limit of the scrubber, stated at the one moment anyone can act on it.
    for (const w of cred.warnings || []) console.error(`${C.yellow('note')} ${w}`)
  },

  async 'cred:list'() {
    const creds = await control('GET', '/v1/credentials')
    if (JSON_OUT) return out(null, creds)
    if (!creds.length) return console.log(C.dim('no credentials yet'))
    for (const c of creds) {
      console.log(`${C.bold(c.slug)} ${C.dim(c.kind)} ${C.dim(c.connector.host || '')}`)
      for (const f of c.fields) console.log(`  ${f.name} ${C.dim(`fp:${f.fp8} -> ${f.sites.join(', ')}`)}`)
    }
  },

  async 'cred:rm'(args) {
    await controlWithPresence('DELETE', `/v1/credentials?slug=${encodeURIComponent(args._[0])}`)
    out(`${C.green('removed')} ${args._[0]}`, { removed: args._[0] })
  },

  async 'session:create'(args) {
    if (!args.cred && !JSON_OUT && process.stdin.isTTY) {
      const { sessionWizard } = await import('./wizards.js')
      return runWizard(() => sessionWizard(controlWithPresence))
    }
    if (!args.cred) return fail('usage: agent-vault session create --cred <slug> [--methods GET,POST] [--paths "/repos/**"]', EXIT.USAGE)
    const body = {
      cred: args.cred,
      label: args.label || 'cli session',
      ttl_hours: args.ttl ? Number(args.ttl) : undefined,
      methods: args.methods ? args.methods.split(',') : undefined,
      paths: args.paths ? args.paths.split(',') : undefined,
      budget: args.budget ? Number(args.budget) : undefined,
      approval: args.approval,
      uses: args.uses ? Number(args.uses) : undefined,
    }
    const s = await controlWithPresence('POST', '/v1/sessions', body)
    saveState({ session_id: s.session_id, token: s.token, placeholder: s.placeholder, base_url: s.base_url })
    if (JSON_OUT) return out(null, s)
    console.log(`${C.green('session')} ${s.session_id} ${C.dim(`expires ${s.expires_at}`)}`)
    console.log(`  base url     ${s.base_url}`)
    console.log(`  placeholder  ${s.placeholder}`)
    console.log(`  put it at    ${s.usage.join(' | ')}`)
    for (const p of s.lint || []) console.log(`  ${p.level === 'error' ? C.red('lint') : C.yellow('lint')} ${p.message}`)
    // Build the example from this credential's own declared site. A hardcoded
    // Authorization header was telling the reader to do the one thing the
    // vault refuses, directly under the line saying where it actually goes.
    const site = (s.usage || [])[0] || ''
    const asHeader = /^[\w-]+:\s/.test(site) ? site : null
    console.log()
    console.log(C.dim('  try:'))
    console.log(C.dim(`    curl "${s.base_url}${s.probe_path || '/'}" \\`))
    console.log(C.dim(`      -H "Authorization: Bearer ${s.token}" \\`))
    if (asHeader) console.log(C.dim(`      -H "${asHeader}"`))
    else console.log(C.dim(`      # then put the placeholder at: ${site}`))
  },

  async 'session:list'() {
    const sessions = await control('GET', '/v1/sessions')
    if (JSON_OUT) return out(null, sessions)
    for (const s of sessions) {
      const state = s.state === 'active' ? C.green(s.state) : C.dim(s.state)
      console.log(`${s.id}  ${state}  ${s.label} ${C.dim(`grants:${s.grants} expires:${s.expires_at}`)}`)
    }
  },

  async 'session:revoke'(args) {
    await control('DELETE', `/v1/sessions?sid=${encodeURIComponent(args._[0] || loadState().session_id)}`)
    out(`${C.green('revoked')}`, { revoked: true })
  },

  async 'ph:next'(args) {
    const cred = args._[0]
    if (!cred) return fail('usage: agent-vault ph next <cred>', EXIT.USAGE)
    const r = await controlWithPresence('POST', '/v1/placeholders', {
      cred, sid: args.session || loadState().session_id, uses: args.uses ? Number(args.uses) : undefined,
    })
    saveState({ placeholder: r.placeholder })
    if (JSON_OUT) return out(null, r)
    console.log(r.placeholder)
    console.error(C.dim(`put it at: ${r.usage.join(' | ')}`))
  },

  async 'ph:check'(args) {
    const text = (args._[0] || (await readSecret(''))).trim()
    const parsed = ph.parseAt(text)
    // The scanner's parser is anchored, so it happily finds a placeholder with
    // trailing characters. Checking a value someone typed is different: the
    // whole string must be the placeholder, or the surrounding characters are
    // exactly the corruption worth reporting.
    if (!parsed || parsed.text !== text) {
      return fail(`not a valid placeholder: ${ph.diagnose(text)}`, EXIT.PLACEHOLDER)
    }
    out(`${C.green('well formed')} session ${parsed.sid}, credential ${parsed.slug}, field ${parsed.field}`, parsed)
  },

  async 'ph:pattern'() {
    out(ph.SCANNER_PATTERN, { pattern: ph.SCANNER_PATTERN })
  },

  async env() {
    const st = loadState()
    if (!st.token) return fail('no session yet', EXIT.SESSION, { next: 'agent-vault session create --cred <slug>' })
    const lines = [
      `export AGENT_VAULT=1`,
      `export AGENT_VAULT_URL=http://127.0.0.1:${st.gateway_port || 7411}`,
      `export AGENT_VAULT_SESSION=${st.token}`,
      `export AGENT_VAULT_PLACEHOLDER=${st.placeholder}`,
      `export AGENT_VAULT_HINT="Credentials are placeholders. Put one only where the usage says. On AV_PH_EXHAUSTED run: agent-vault ph next <cred>"`,
    ]
    out(lines.join('\n'), { env: lines })
  },

  async exec(args) {
    const st = loadState()
    if (!st.token) return fail('no session yet', EXIT.SESSION, { next: 'agent-vault session create --cred <slug>' })
    const { spawn } = await import('node:child_process')
    const argv = args._
    if (!argv.length) return fail('usage: agent-vault exec -- <command>', EXIT.USAGE)
    // The child gets a scrubbed environment: known credential variables are
    // dropped so a stale real token cannot shadow the vault.
    const env = { ...process.env }
    for (const k of Object.keys(env)) {
      if (/_(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)$/.test(k)) delete env[k]
    }
    Object.assign(env, {
      AGENT_VAULT: '1',
      AGENT_VAULT_URL: `http://127.0.0.1:${st.gateway_port || 7411}`,
      AGENT_VAULT_SESSION: st.token,
      AGENT_VAULT_PLACEHOLDER: st.placeholder,
    })
    const child = spawn(argv[0], argv.slice(1), { stdio: 'inherit', env })
    child.on('exit', (code) => process.exit(code ?? 0))
  },

  async approvals() {
    const pending = await control('GET', '/v1/approvals')
    if (JSON_OUT) return out(null, pending)
    if (!pending.length) return console.log(C.dim('nothing waiting'))
    for (const a of pending) {
      console.log(`${C.yellow('pending')} ${a.id}`)
      console.log(`  ${C.bold(a.summary)}`)
      if (a.reason) console.log(`  ${C.dim(`claimed by the agent (unverified): ${a.reason}`)}`)
      console.log(`  ${C.dim(`approve: agent-vault approve ${a.id}`)}`)
    }
  },

  async approve(args) {
    const r = await control('POST', '/v1/approvals', { id: args._[0], granted: true })
    out(`${C.green('approved')} ${r.summary}`, r)
  },

  async deny(args) {
    const r = await control('POST', '/v1/approvals', { id: args._[0], granted: false })
    out(`${C.red('denied')} ${r.summary}`, r)
  },

  async 'audit:tail'(args) {
    const rows = await control('GET', `/v1/audit?limit=${args.limit || 20}`)
    if (JSON_OUT) return out(null, rows)
    for (const r of rows) {
      const decision = r.decision === 'deny' ? C.red('deny') : r.decision === 'allow' ? C.green('allow') : C.dim('-')
      const detail = r.reason_code || r.credential_slug || r.detail || ''
      console.log(`${C.dim(r.ts.slice(11, 19))} ${String(r.seq).padStart(4)} ${decision.padEnd(16)} ${C.bold(r.kind)} ${C.dim(detail)}`)
    }
  },

  async 'audit:verify'() {
    const v = await control('GET', '/v1/audit/verify')
    if (v.ok) out(`${C.green('chain intact')} ${v.count} records, head ${v.head?.slice(0, 16)}...`, v)
    // Not every finding has a record number: a log that is missing its head
    // anchor, or that ends short of where it should, is broken between records
    // rather than at one. "broken at record undefined" would be the daemon
    // reporting tampering and sounding like a bug instead.
    else if (v.brokenAt) fail(`chain broken at record ${v.brokenAt}: ${v.reason}`, EXIT.FAILURE, { problem: v })
    else fail(`the audit log cannot be trusted: ${v.reason}`, EXIT.FAILURE, { problem: v })
  },

  async 'listen:add'(args) {
    const entry = {
      id: args._[0],
      address: args.address,
      surfaces: (args.surfaces || 'gateway,mcp').split(','),
      advertise: args.advertise ? args.advertise.split(',') : [],
      // What actually authenticates a caller on this listener. Mutual TLS is
      // not implemented, and recording 'mtls-required' for a listener that
      // accepts a bearer token was a field that lied about its own security.
      client_auth: 'bearer',
      allow_cidr: args['allow-cidr'] ? args['allow-cidr'].split(',') : [],
    }
    if (args.tls === 'managed' || args.tls === true) {
      // The daemon's own certificate, which `agent-vault tls setup` generated.
      entry.tls = { managed: true }
    } else if (args['tls-cert'] || args['tls-key']) {
      if (!args['tls-cert'] || !args['tls-key']) {
        return fail('--tls-cert and --tls-key go together', EXIT.USAGE)
      }
      // Absolute, because the daemon runs as another user from another
      // directory and a relative path would resolve somewhere else entirely.
      entry.tls = { cert: resolvePath(args['tls-cert']), key: resolvePath(args['tls-key']) }
    }
    if (!entry.id || !entry.address) return fail('usage: agent-vault listen add <id> --address <iface:port|ip:port>', EXIT.USAGE)
    const r = await control('POST', '/v1/listeners', entry)
    out(`${C.green('listener')} ${r.id} ${r.address} ${C.dim(`surfaces: ${r.surfaces.join(',')}`)}`, r)
  },

  /**
   * Set up HTTPS for the loopback MCP listener.
   *
   * Claude Desktop and Claude Code refuse an MCP connector URL that is not
   * https, with no exemption for loopback, so even a vault that never talks to
   * anything but its own machine needs a certificate. The daemon generates and
   * keeps the key; this writes the public certificate where the client can
   * read it and prints the one environment variable that makes it trusted.
   */
  async 'tls:setup'(args) {
    const info = await controlWithPresence('POST', '/v1/tls/ensure', { force: !!args.force })
    const caPath = join(CLI_STATE_DIR, 'agent-vault-ca.pem')
    if (!existsSync(CLI_STATE_DIR)) mkdirSync(CLI_STATE_DIR, { recursive: true, mode: 0o700 })
    writeFileSync(caPath, info.certificate, { mode: 0o644 })

    const port = Number(args.port || 7443)
    if (JSON_OUT) return out(null, { ...info, ca_path: caPath, port })

    console.log(`${C.green(info.created ? 'certificate generated' : 'certificate present')}`)
    console.log(`  ${C.dim('fingerprint')} ${info.fingerprint.slice(0, 47)}...`)
    if (info.not_after) console.log(`  ${C.dim('expires')}     ${info.not_after.slice(0, 10)}`)
    console.log(`  ${C.dim('trust anchor')} ${C.cyan(caPath)}`)
    console.log()
    console.log('  The private key stays inside the vault and never leaves that uid.')
    console.log('  The file above is the public certificate, which is also its own CA,')
    console.log('  so pointing a client at it is what makes the listener trusted.')
    console.log()
    console.log(`  ${C.bold('1.')} Bind the TLS listener:`)
    console.log(`     ${C.cyan(`agent-vault listen add mcp-tls --address 127.0.0.1:${port} --surfaces mcp --tls managed`)}`)
    console.log()
    console.log(`  ${C.bold('2.')} Make the client trust it. Node does not read the keychain by`)
    console.log(`     default, so this variable is the reliable way:`)
    console.log(`     ${C.cyan(`export NODE_EXTRA_CA_CERTS="${caPath}"`)}`)
    console.log()
    console.log(`  ${C.bold('3.')} Add the connector:`)
    console.log(`     ${C.cyan(`agent-vault mcp install --agent claude-code --transport http --tls`)}`)
  },

  async 'tls:status'() {
    const info = await control('GET', '/v1/tls')
    if (JSON_OUT) return out(null, info)
    if (!info.configured) {
      return console.log(`${C.dim('no certificate yet')}  ${C.dim('agent-vault tls setup')}`)
    }
    console.log(`${C.green('certificate')} expires ${info.not_after?.slice(0, 10) || 'unknown'}`)
    console.log(`  ${C.dim(info.fingerprint)}`)
  },

  async 'listen:list'() {
    const rows = await control('GET', '/v1/listeners')
    if (JSON_OUT) return out(null, rows)
    console.log(`${C.bold('local')}  unix + 127.0.0.1  ${C.dim('gateway,mcp,connect  (always present, cannot be removed)')}`)
    for (const l of rows) console.log(`${C.bold(l.id)}  ${l.address}  ${C.dim(l.surfaces.join(','))}`)
  },

  async 'listen:rm'(args) {
    await control('DELETE', `/v1/listeners?id=${encodeURIComponent(args._[0])}`)
    out(`${C.green('removed')} ${args._[0]}`, { removed: args._[0] })
  },

  /** Write the MCP server into an agent's own config file. */
  async 'mcp:install'(args) {
    const { AGENTS, serverEntry, install } = await import('./mcp-install.js')
    const agent = args.agent || args._[0]
    if (!agent || !AGENTS[agent]) {
      return fail(`--agent is required`, EXIT.USAGE, {
        next: `agent-vault mcp install --agent ${Object.keys(AGENTS).join('|')}`,
      })
    }
    const spec = AGENTS[agent]
    const scope = args.scope || spec.defaultScope || 'project'
    if (!spec.paths[scope]) {
      return fail(`${spec.label} has no ${scope} scope`, EXIT.USAGE, {
        next: `agent-vault mcp install --agent ${agent} --scope ${Object.keys(spec.paths).join('|')}`,
      })
    }
    const transport = args.transport || 'stdio'
    const name = args.name || 'agent-vault'

    // `Number('nope')` is NaN, and writing `https://localhost:NaN/mcp` into a
    // config file is a failure the reader only discovers when their agent
    // cannot connect and the URL looks almost right.
    const port = args.port === undefined ? 7443 : Number(args.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return fail(`--port must be a number between 1 and 65535, not ${JSON.stringify(args.port)}`, EXIT.USAGE)
    }

    // Prefer the bare name when a shim is on PATH. Absolute paths to this
    // interpreter and this checkout work on this machine and nowhere else —
    // which made project scope, whose whole point is that you can commit the
    // file for your team, produce a file committable to nobody. Fall back to
    // the interpreter and script only when there is no shim to name.
    const selfBin = new URL('../../bin/agent-vault.js', import.meta.url).pathname
    const shim = ['agent-vault', 'av'].find((name) => (process.env.PATH || '').split(':')
      .some((d) => d && existsSync(join(d, name))))
    const portable = shim && scope === 'project'
    const entry = serverEntry({
      transport,
      format: spec.format,
      command: portable ? shim : process.execPath,
      args: portable ? ['mcp'] : [selfBin, 'mcp'],
      // A connector URL must be https: Claude Desktop and Claude Code refuse
      // plain http, and there is no exemption for loopback. --tls points at the
      // TLS listener instead of the plain gateway.
      url: args.tls
        ? `https://localhost:${port}/mcp`
        : `http://127.0.0.1:${loadState().gateway_port || 7411}/mcp`,
    })

    const result = install({
      agent, scope, name, entry, print: !!args.print,
      cwd: process.cwd(), home: homedir(),
    })

    if (JSON_OUT) return out(null, { agent, scope, transport, ...result })

    if (args.print) {
      console.log(C.dim(`# ${result.path}`))
      console.log(result.block)
      return
    }
    console.log(`${C.green(result.unchanged ? 'already configured' : 'configured')} ${C.bold(spec.label)} ${C.dim(`(${scope} scope)`)}`)
    console.log(`  ${C.cyan(result.path)}`)
    if (result.backup) console.log(C.dim(`  previous file kept at ${result.backup}`))
    const note = spec.notes?.[scope]
    if (note) console.log(C.dim(`  ${note}`))
    console.log()
    if (transport === 'stdio') {
      console.log(C.dim('  The stdio bridge finds your session from the CLI, so no token is'))
      console.log(C.dim('  written into that file. Create a session first if you have not:'))
      console.log(`    ${C.cyan('agent-vault session create --cred <slug>')}`)
    } else {
      console.log(C.dim(`  HTTP transport reads the token from $AGENT_VAULT_SESSION at launch.`))
      console.log(`    ${C.cyan('eval "$(agent-vault env)"')}`)
      if (args.tls) {
        console.log()
        console.log(C.dim('  The certificate is self-signed, so the client will refuse it until'))
        console.log(C.dim('  it is told to trust it. Node does not read the keychain by default:'))
        console.log(`    ${C.cyan(`export NODE_EXTRA_CA_CERTS="${join(CLI_STATE_DIR, 'agent-vault-ca.pem')}"`)}`)
      } else {
        console.log()
        console.log(C.yellow('  Note: a custom connector URL must be https. Plain http is refused'))
        console.log(C.yellow('  even on loopback. Run: agent-vault tls setup'))
      }
    }
    console.log()
    console.log(C.dim(`  Restart ${spec.label} so it picks up the new server.`))
  },

  async 'mcp:url'() {
    const st = loadState()
    const url = `http://127.0.0.1:${st.gateway_port || 7411}/mcp`
    if (JSON_OUT) return out(null, { url, header: `Authorization: Bearer ${st.token}` })
    console.log(url)
    console.error(C.dim(`header: Authorization: Bearer ${st.token || '<session token>'}`))
  },

  /**
   * The stdio transport is a bridge: it frames stdin and stdout onto the
   * daemon's Streamable HTTP endpoint. It holds no key material and never
   * opens the vault, which is what lets it work when the vault belongs to
   * another uid.
   */
  async mcp() {
    // Resolved per request, not once at launch. A session lasts hours and an
    // agent outlives it; freezing the token here means that the moment it
    // expires the bridge is dead until the whole client restarts, which is a
    // miserable way to find out. Re-reading lets `session create` in another
    // terminal heal a running agent on its next call.
    const currentToken = () => process.env.AGENT_VAULT_SESSION || loadState().token || null
    if (!currentToken()) {
      process.stderr.write('agent-vault mcp: no session. Run: agent-vault session create --cred <slug>\n')
      process.exit(EXIT.SESSION)
    }
    const status = await control('GET', '/v1/status')
    const endpoint = `http://127.0.0.1:${status.gateway_port}/mcp`
    let mcpSessionId = null
    let buffer = ''

    process.stdin.setEncoding('utf8')
    process.stdin.on('data', async (chunk) => {
      buffer += chunk
      let nl
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim()
        buffer = buffer.slice(nl + 1)
        if (!line) continue
        try {
          const send = (tok) => fetch(endpoint, {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              accept: 'application/json, text/event-stream',
              authorization: `Bearer ${tok}`,
              ...(mcpSessionId ? { 'mcp-session-id': mcpSessionId } : {}),
            },
            body: line,
          })
          let res = await send(currentToken())
          if (res.status === 401) {
            // The session ended mid-flight. If a human has since created a new
            // one, pick it up and retry rather than making them restart the
            // client to collect a token that is already sitting on disk.
            const fresh = (loadState().token || null)
            if (fresh && fresh !== currentToken()) {
              delete process.env.AGENT_VAULT_SESSION
              mcpSessionId = null
              res = await send(fresh)
            }
          }
          const sid = res.headers.get('mcp-session-id')
          if (sid) mcpSessionId = sid
          const text = await res.text()
          if (text) process.stdout.write(`${text}\n`)
        } catch (e) {
          const parsed = (() => { try { return JSON.parse(line) } catch { return {} } })()
          process.stdout.write(`${JSON.stringify({
            jsonrpc: '2.0', id: parsed.id ?? null,
            error: { code: -32603, message: `agent-vault daemon unreachable: ${e.message}` },
          })}\n`)
        }
      }
    })
  },

  /**
   * Start the web UI. It binds an ephemeral loopback port and prints a link
   * carrying a single-use token: the first browser to open it claims the
   * session and the token is burned.
   */
  async ui(args, { hash = '' } = {}) {
    const { UiServer } = await import('../ui/server.js')
    await control('GET', '/v1/status') // fail fast if the daemon is not up
    const ui = new UiServer(SOCKET, {
      port: Number(args.port || 0),
      idleMs: (Number(args.idle) || 30) * 60_000,
      cli: cliInvocation(),
    })
    await ui.start()
    // A fragment survives the redirect that burns the launch token, so it is
    // how we open the page on something other than Overview.
    const url = `${ui.url}${hash}`

    if (JSON_OUT) return out(null, { url, port: ui.boundPort })
    console.log(`${C.green('agent-vault ui')} ${C.dim(`on 127.0.0.1:${ui.boundPort}`)}`)
    console.log()
    console.log(`  ${C.cyan(url)}`)
    console.log()
    console.log(C.dim('  The link works once. If your browser says the session was already'))
    console.log(C.dim('  claimed, something else opened it first: check agent-vault audit tail.'))
    console.log(C.dim('  No credential value is ever sent to the page. Ctrl-C to stop.'))

    if (args.open !== false && !args['no-open']) {
      const { spawn } = await import('node:child_process')
      const opener = process.platform === 'darwin' ? 'open' : 'xdg-open'
      spawn(opener, [url], { stdio: 'ignore', detached: true }).unref()
    }

    ui.onStop = () => { console.log(C.dim('\nui: idle, stopped')); process.exit(0) }
    const shutdown = async () => { await ui.stop(); process.exit(0) }
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)
  },

  /**
   * The docs live in the UI, where they can be written against this actual
   * install. This is the same page, opened on the right section.
   */
  async docs(args) {
    const sections = ['how', 'start', 'connect', 'models', 'locking', 'refused', 'commands']
    const asked = args._[0]
    if (asked && !sections.includes(asked)) {
      return fail(`no docs section named ${asked}`, EXIT.USAGE, {
        next: `agent-vault docs [${sections.join('|')}]`,
      })
    }
    return COMMANDS.ui(args, { hash: `#docs/${asked || 'how'}` })
  },

  async 'passphrase:set'(args) {
    const state = await control('GET', '/v1/lockstate')
    if (state.locked) return fail('unlock the vault first', EXIT.LOCKED, { next: 'agent-vault unlock' })
    const current = state.has_passphrase ? await readSecret('current passphrase: ') : null
    const next1 = await readSecret('new passphrase (min 8 chars): ')
    if (next1.length < 8) return fail('a passphrase must be at least 8 characters', EXIT.USAGE)
    const next2 = await readSecret('confirm new passphrase: ')
    if (next1 !== next2) return fail('the two passphrases do not match', EXIT.USAGE)
    await control('POST', '/v1/passphrase', { action: 'set', passphrase: next1, current })
    console.log(`${C.green('passphrase set')}`)
    console.log(C.dim('  The lock is now cryptographic: locking zeroizes the key, and unlocking'))
    console.log(C.dim('  needs this passphrase. An agent that reaches the socket cannot undo it.'))
  },

  async 'passphrase:remove'() {
    const state = await control('GET', '/v1/lockstate')
    if (state.locked) return fail('unlock the vault first', EXIT.LOCKED, { next: 'agent-vault unlock' })
    if (!state.has_passphrase) return out(`${C.green('ok')} no passphrase is set`, { removed: false })
    const current = await readSecret('current passphrase: ')
    await control('POST', '/v1/passphrase', { action: 'remove', current })
    console.log(`${C.yellow('passphrase removed')} ${C.dim('the vault is back to UID-boundary-only protection')}`)
  },

  async lock() {
    await control('POST', '/v1/lock', {})
    out(`${C.green('locked')} keys zeroized; the gateway answers 423 until you unlock`, { locked: true })
  },

  async unlock() {
    // An older daemon may have neither route. Probe, but degrade rather than
    // failing on the probe itself.
    let state = { locked: true, needs_secret: false }
    try {
      state = await control('GET', '/v1/lockstate')
    } catch (e) {
      if (!e.skew) throw e
    }
    if (!state.locked) return out(`${C.green('ok')} already unlocked`, { locked: false })

    const passphrase = state.needs_secret
      ? await readSecret('passphrase: ')
      : null

    await control('POST', '/v1/unlock', { passphrase })
    if (JSON_OUT) return out(null, { locked: false })
    console.log(`${C.green('unlocked')}`)
    if (!state.needs_secret) {
      console.log(C.dim('  This vault has no passphrase, so unlocking needed no secret: the'))
      console.log(C.dim('  lock is a policy gate, not a cryptographic one. Anything that can'))
      console.log(C.dim('  reach the control socket can undo it.'))
      console.log(`  ${C.dim('Make the lock cryptographic:')} ${C.cyan('agent-vault passphrase set')}`)
    }
  },

  async profiles() {
    const rows = listProfiles()
    if (JSON_OUT) return out(null, rows)
    for (const p of rows) {
      // Say so in the list, rather than letting someone pick one and find out
      // when they try to store a secret in it.
      const note = p.implemented ? '' : C.yellow('  not implemented yet')
      console.log(`${C.bold(p.kind.padEnd(14))} ${C.dim(p.hosts.join(', ') || 'any host you name')}${note}`)
    }
  },

  async doctor() {
    const { statSync } = await import('node:fs')
    const checks = []
    checks.push(['install mode', true, USING_SYSTEM
      ? 'system (separate service user)'
      : `dev (runs as you)${SYSTEM_INSTALLED ? ', overriding the system install' : ''}`])

    let vaultReadable = null
    try { statSync(join(VAULT_DIR, 'vault.json')); vaultReadable = true } catch (e) { vaultReadable = e.code !== 'EACCES' ? null : false }

    if (USING_SYSTEM) {
      // The check that matters: can this process, running as the human, read
      // the vault? A refusal here is the boundary doing its job.
      checks.push(['vault unreadable by your account', vaultReadable === false,
        vaultReadable === false ? `EACCES on ${VAULT_DIR} - correct` : `readable at ${VAULT_DIR} - the boundary is NOT in effect`])
      try {
        const st = statSync(VAULT_DIR)
        checks.push(['vault owned by the service user', st.uid !== process.getuid(), `uid ${st.uid}, you are ${process.getuid()}`])
        checks.push(['vault mode 0700', (st.mode & 0o777) === 0o700, `0${(st.mode & 0o777).toString(8)}`])
      } catch {
        checks.push(['vault directory stat', false, 'cannot stat the vault directory'])
      }
    } else {
      const exists = existsSync(join(VAULT_DIR, 'vault.json'))
      checks.push(['vault present', exists, VAULT_DIR])
      if (exists) {
        const mode = statSync(VAULT_DIR).mode & 0o777
        checks.push(['vault directory mode 0700', mode === 0o700, `0${mode.toString(8)}`])
      }
      checks.push(['separate uid boundary', false,
        `dev mode: anything running as you can read ${VAULT_DIR}. Install it properly: sudo ${process.execPath} ${SETUP_BIN} install`])
    }
    checks.push(['daemon reachable', existsSync(SOCKET), SOCKET])

    // The uid boundary stops an agent READING the vault. Nothing stops it
    // USING the vault until a human factor is enrolled: every widening
    // operation is gated on presence, and presence cannot be required when
    // there is no factor to require. Worse, in that state the first caller to
    // reach the control socket can set a passphrase of its own and keep the
    // vault. The daemon creates the vault unattended, so this state is the
    // one every install passes through — it should not be quiet.
    // The log is the record of what an agent did with your credentials. A
    // broken chain is only useful if something looks at it, and nothing did
    // unless a human happened to run `audit verify`.
    const chain = await control('GET', '/v1/audit/verify').catch(() => null)
    if (chain) {
      checks.push(['audit chain intact', chain.ok === true,
        chain.ok ? `${chain.count} records` : chain.reason])
      // Reported separately from the chain, because it is a different claim: a
      // log with no anchor is intact but of unproven extent. Folding it into
      // the check above would make this permanently red on every vault written
      // before the anchor existed, and a check that always fails is a check
      // nobody reads.
      if (chain.unanchored_before) {
        checks.push(['audit log anchored throughout', false,
          `anchored from record ${chain.unanchored_before}; nothing proves how many records came before it`])
      }
    }

    const lock = await control('GET', '/v1/lockstate').catch(() => null)
    if (lock) {
      const enrolled = Boolean(lock.has_passphrase || lock.has_touchid)
      checks.push(['human factor enrolled', enrolled, enrolled
        ? [lock.has_passphrase && 'passphrase', lock.has_touchid && 'authenticator'].filter(Boolean).join(' + ')
        : `none: anything running as you can use every credential, and can claim the vault by setting its own passphrase. Run: agent-vault passphrase set`])
    }

    if (JSON_OUT) return out(null, checks.map(([name, ok, note]) => ({ name, ok, note })))
    for (const [name, ok, note] of checks) {
      console.log(`${ok ? C.green('ok  ') : C.yellow('warn')} ${name.padEnd(26)} ${C.dim(note)}`)
    }
  },

  help() { printHelp() },
}

// -------------------------------------------------------------------- parsing

function parseArgs(argv) {
  const args = { _: [] }
  let passthrough = false
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (passthrough) { args._.push(a); continue }
    if (a === '--') { passthrough = true; continue }
    if (a === '--json') { JSON_OUT = true; continue }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=')
      if (eq !== -1) { args[a.slice(2, eq)] = a.slice(eq + 1); continue }
      const next = argv[i + 1]
      if (next && !next.startsWith('-')) { args[a.slice(2)] = next; i++ }
      else args[a.slice(2)] = true
      continue
    }
    args._.push(a)
  }
  return args
}

function printHelp() {
  console.log(`${C.bold('agent-vault')} - a local credential proxy for agents

${C.bold('setup')}
  setup [--dev] [--print-only]         install properly (--dev skips the uid boundary)
  upgrade                              reinstall the daemon from this checkout
  daemon [--port N]                    run the daemon (gateway + control socket)
  status | doctor | profiles           what is running, and what is configured

${C.bold('guided')}                               ${C.dim('(run these with no arguments)')}
  quickstart                           credential, session, and what to give the agent
  cred add                             walks you through storing a credential
  session create                       walks you through scoping a session

${C.bold('credentials')}                          ${C.dim('(the value is read from the terminal, never argv)')}
  cred add <slug> --kind <kind> [--host H]
  cred list | cred rm <slug>

${C.bold('sessions and placeholders')}
  session create --cred <slug> [--methods GET,POST] [--paths "/repos/**"] [--budget N] [--uses N]
  session list | session revoke [<sid>]
  ph next <cred> [--uses N]            issue a placeholder
  ph check <placeholder> | ph pattern  validate one, or print the scanner regex
  env | exec -- <command>              hand a scrubbed environment to an agent

${C.bold('approvals, audit, listeners')}
  approvals | approve <id> | deny <id>
  lock | unlock                        stop and resume every proxied request
  passphrase set | passphrase remove   make the lock cryptographic (or undo it)
  audit tail [--limit N] | audit verify
  listen add <id> --address <iface:port> [--surfaces gateway,mcp]
                 [--tls managed | --tls-cert F --tls-key F]
  listen list | listen rm <id>
  tls setup [--port 7449]              certificate for the loopback MCP listener
  tls status                           fingerprint and expiry

${C.bold('ui')}
  ui [--port N] [--no-open] [--idle 30] open the web UI (single-use link, no secrets rendered)

${C.bold('mcp')}
  mcp                                  stdio transport (for an MCP client)
  mcp url                              the Streamable HTTP endpoint and header
  mcp install --agent <claude-code|cursor|gemini|codex> [--scope project|user]
                                       merge the server into that tool's config
                                       (--print shows the block instead)
              [--transport http --tls] a custom connector; the URL must be https

${C.bold('docs')}
  docs [section]                       open the docs, written against this install
                                       how | start | connect | models | locking
                                       | refused | commands

${C.dim('--json on any command prints a machine-readable envelope.')}`)
}

// --------------------------------------------------------------------- entry

export async function main(argv = process.argv.slice(2)) {
  // R3: root never runs agent-writable code. This file lives in a directory the
  // agent can write to, so it must never be what sudo executes. The privileged
  // verbs live in agent-vault-setup and are invoked by absolute path.
  if (process.getuid && process.getuid() === 0 && !process.env.AGENT_VAULT_ALLOW_ROOT) {
    const asked = argv.join(' ')
    const invoked = process.env.SUDO_COMMAND?.split('/').pop()?.split(' ')[0] || 'agent-vault'
    console.error('Do not run agent-vault under sudo.')
    console.error('')
    console.error(`  run this instead:  ${invoked}${asked ? ` ${asked}` : ''}`)
    console.error('')
    console.error('  Running the whole CLI as root would put every code path in this package,')
    console.error('  and whichever interpreter is first on root PATH, inside a root process.')
    console.error('  "agent-vault setup" already handles the privileged step for you: it runs')
    console.error('  as you and hands root one small installer by absolute path.')
    process.exit(EXIT.USAGE)
  }
  const args = parseArgs(argv)
  const [first, second] = args._
  if (!first || first === 'help' || args.help) { printHelp(); return }

  // Two-word commands (cred add) resolve to "cred:add"; one-word commands stay.
  const GROUPS = ['cred', 'session', 'ph', 'audit', 'listen', 'mcp', 'passphrase', 'tls']
  let name = first
  if (GROUPS.includes(first) && second && COMMANDS[`${first}:${second}`]) {
    name = `${first}:${second}`
    args._ = args._.slice(2)
  } else if (COMMANDS[first]) {
    args._ = args._.slice(1)
  }

  const command = COMMANDS[name]
  if (!command) {
    const known = Object.keys(COMMANDS).map((k) => k.replace(':', ' ')).join(', ')
    return fail(`unknown command "${args._[0] || first}"`, EXIT.USAGE, { next: `one of: ${known}` })
  }

  try {
    await command(args)
  } catch (e) {
    const problem = e.problem || {}
    // For version skew our own message is the useful one; the daemon's reply is
    // an internal route name that tells nobody anything.
    fail(e.skew ? e.message : (problem.detail || e.message), e.exit || EXIT.FAILURE, {
      next: problem.next?.cli?.[0] || e.next,
      code: problem.code,
      hint: problem.hint,
    })
  }
}
