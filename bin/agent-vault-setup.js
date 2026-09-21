#!/usr/bin/env node
// The privileged installer. This is the piece that makes the vault unreadable
// to an agent running as you.
//
//   sudo /path/to/agent-vault-setup.js install
//
// What it creates, and why each part is needed:
//
//   _agentvault             a system user with no shell and no home. The daemon
//                           runs as this user, so the vault's 0700 directory is
//                           unreadable to your uid. This is the whole point.
//   _agentvault_users       a group your account joins, so your CLI can reach
//                           the daemon's socket without being able to read the
//                           vault behind it.
//   <root>/vault            0700 _agentvault. Secrets live here.
//   <root>/app              the daemon's code, root-owned, so the agent cannot
//                           edit what the service executes.
//   <root>/runtime          a root-owned copy of the Node binary, for the same
//                           reason: a service that runs a user-writable
//                           interpreter is a root shell waiting to happen.
//   <root>/run              0750 _agentvault:_agentvault_users, plus an ACL for
//                           your uid so the socket works before your next login.
//   a launchd/systemd unit  so the daemon starts as the right user at boot.
//
// Honest limit, stated here rather than buried: this installer is itself
// JavaScript in a directory you own, so the very first `sudo` runs code an
// agent could have edited beforehand. The spec's answer is a signed native
// binary, and it is not built yet. After a successful install the trusted copy
// lives in the root-owned tree and `status` tells you which copy you are
// running. Verify this file before the first run if that matters to you.

import { execFileSync } from 'node:child_process'
import {
  existsSync, mkdirSync, writeFileSync, readFileSync, cpSync, rmSync,
  lstatSync, readlinkSync, readdirSync,
  chmodSync, chownSync, statSync, renameSync,
} from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { platform, userInfo } from 'node:os'

const IS_MAC = platform() === 'darwin'
const IS_LINUX = platform() === 'linux'

const SERVICE_USER = '_agentvault'
const CLIENT_GROUP = '_agentvault_users'
const LAUNCHD_LABEL = 'com.agentvault.daemon'
const PLIST = `/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist`
const SYSTEMD_UNIT = '/etc/systemd/system/agent-vault.service'

const ROOT = IS_MAC ? '/var/db/agent-vault' : '/usr/libexec/agent-vault'
const VAULT_DIR = IS_MAC ? join(ROOT, 'vault') : '/var/lib/agent-vault'
const RUN_DIR = IS_MAC ? join(ROOT, 'run') : '/run/agent-vault'
const APP_DIR = join(ROOT, 'app')
const RUNTIME_DIR = join(ROOT, 'runtime')
const STATE = join(ROOT, 'state.json')

const args = process.argv.slice(2)
const verb = args.find((a) => !a.startsWith('-')) || 'help'
const flag = (name) => args.includes(`--${name}`)
const value = (name) => {
  const i = args.indexOf(`--${name}`)
  return i === -1 ? null : args[i + 1]
}
const DRY = flag('dry-run')

const C = process.stdout.isTTY
  ? { b: (s) => `\x1b[1m${s}\x1b[0m`, d: (s) => `\x1b[2m${s}\x1b[0m`, g: (s) => `\x1b[32m${s}\x1b[0m`, r: (s) => `\x1b[31m${s}\x1b[0m`, y: (s) => `\x1b[33m${s}\x1b[0m` }
  : { b: (s) => s, d: (s) => s, g: (s) => s, r: (s) => s, y: (s) => s }

const say = (s = '') => console.log(s)
const step = (s) => say(`${DRY ? C.y('would') : C.g('ok   ')} ${s}`)
const die = (message, hint) => {
  console.error(`\n${C.r('cannot continue')}  ${message}`)
  if (hint) console.error(`${C.d('  ' + hint)}`)
  process.exit(1)
}

/** Run a command, or print it under --dry-run. */
function run(cmd, cmdArgs, { allowFail = false } = {}) {
  if (DRY) { say(`       ${C.d(`${cmd} ${cmdArgs.join(' ')}`)}`); return '' }
  try {
    return execFileSync(cmd, cmdArgs, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
  } catch (e) {
    if (allowFail) return ''
    throw new Error(`${cmd} ${cmdArgs.join(' ')} failed: ${(e.stderr || e.message).toString().trim()}`)
  }
}

// ---------------------------------------------------------------- state file

function loadState() {
  if (!existsSync(STATE)) return { created: [], version: 1 }
  try { return JSON.parse(readFileSync(STATE, 'utf8')) } catch { return { created: [], version: 1 } }
}
function saveState(state) {
  if (DRY) return
  writeFileSync(STATE, JSON.stringify(state, null, 2), { mode: 0o644 })
  chownSync(STATE, 0, 0)
}
/** Record that we, and not the operator, created something, so uninstall knows. */
function record(state, kind, id) {
  if (!state.created.some((c) => c.kind === kind && c.id === id)) state.created.push({ kind, id })
}

// ------------------------------------------------------------------- guards

function requireRoot() {
  // A dry run must be readable without sudo. Telling someone to inspect what a
  // privileged script will do, and then demanding root before it will tell
  // them, is not an inspection step.
  if (DRY) return
  if (process.getuid() !== 0) {
    die('this must run as root.', `try: sudo ${process.execPath} ${resolve(process.argv[1])} ${verb}`)
  }
}

function enrolledUser() {
  const name = value('user') || process.env.SUDO_USER || (DRY ? userInfo().username : null)
  if (!name) {
    die('cannot tell which account to enrol.', 'Run this through sudo from your own account, or pass --user <name>.')
  }
  if (name === 'root') die('refusing to enrol root.', 'Run sudo from your normal account.')
  let uid
  if (DRY) {
    uid = name === userInfo().username ? userInfo().uid : 0
  } else {
    try { uid = Number(execFileSync('id', ['-u', name], { encoding: 'utf8' }).trim()) } catch { die(`no such user: ${name}`) }
  }
  return { name, uid }
}

/**
 * Walk a path to the filesystem root and refuse if any component is writable by
 * anyone but root. A root-owned file under a directory you can rename is not
 * root-owned in any way that matters.
 */
function assertRootOwnedChain(path, what) {
  let p = resolve(path)
  for (;;) {
    if (existsSync(p)) {
      const st = statSync(p)
      const groupOrOtherWritable = (st.mode & 0o022) !== 0
      const sticky = (st.mode & 0o1000) !== 0
      if (st.uid !== 0 || (groupOrOtherWritable && !sticky)) {
        die(
          `${what} sits under ${p}, which is writable by uid ${st.uid}.`,
          'Anything there can be replaced by a process running as you, so root must not execute from it.',
        )
      }
    }
    const parent = dirname(p)
    if (parent === p) return
    p = parent
  }
}

// --------------------------------------------------------- users and groups

function macFreeUid() {
  if (DRY) return 399
  const used = new Set(
    run('dscl', ['.', '-list', '/Users', 'UniqueID'])
      .split('\n').map((l) => Number(l.trim().split(/\s+/).pop())).filter(Number.isFinite),
  )
  for (let uid = 300; uid < 400; uid++) if (!used.has(uid)) return uid
  die('no free system uid between 300 and 399.')
}

function userExists(name) {
  if (IS_MAC) return run('dscl', ['.', '-read', `/Users/${name}`, 'UniqueID'], { allowFail: true }).includes('UniqueID')
  return run('getent', ['passwd', name], { allowFail: true }).trim().length > 0
}

function groupExists(name) {
  if (IS_MAC) return run('dscl', ['.', '-read', `/Groups/${name}`], { allowFail: true }).includes('RecordName')
  return run('getent', ['group', name], { allowFail: true }).trim().length > 0
}

function createServiceUser(state) {
  // Under a dry run the service user was only described, not created, so ask
  // the plan to show this step anyway. A plan that silently omits a step that
  // will really happen is worse than no plan.
  if (DRY || userExists(SERVICE_USER)) { step(`service user ${SERVICE_USER} already exists`); return }
  if (IS_MAC) {
    const uid = macFreeUid()
    const u = `/Users/${SERVICE_USER}`
    run('dscl', ['.', '-create', u])
    run('dscl', ['.', '-create', u, 'UniqueID', String(uid)])
    run('dscl', ['.', '-create', u, 'PrimaryGroupID', String(uid)])
    run('dscl', ['.', '-create', u, 'UserShell', '/usr/bin/false'])
    run('dscl', ['.', '-create', u, 'NFSHomeDirectory', '/var/empty'])
    run('dscl', ['.', '-create', u, 'RealName', 'agent-vault daemon'])
    run('dscl', ['.', '-create', u, 'IsHidden', '1'])
    run('dscl', ['.', '-create', `/Groups/${SERVICE_USER}`], { allowFail: true })
    run('dscl', ['.', '-create', `/Groups/${SERVICE_USER}`, 'PrimaryGroupID', String(uid)], { allowFail: true })
  } else {
    run('useradd', [
      '--system', '--user-group', '--home-dir', VAULT_DIR,
      '--shell', '/usr/sbin/nologin', '--comment', 'agent-vault daemon', SERVICE_USER,
    ])
  }
  record(state, 'user', SERVICE_USER)
  step(`created service user ${C.b(SERVICE_USER)} ${C.d('(no shell, no home, hidden)')}`)
}

function createClientGroup(state, enrolled) {
  if (!groupExists(CLIENT_GROUP)) {
    if (IS_MAC) run('dseditgroup', ['-o', 'create', '-r', 'agent-vault clients', CLIENT_GROUP])
    else run('groupadd', ['--system', CLIENT_GROUP])
    record(state, 'group', CLIENT_GROUP)
    step(`created client group ${C.b(CLIENT_GROUP)}`)
  } else step(`client group ${CLIENT_GROUP} already exists`)

  if (IS_MAC) run('dseditgroup', ['-o', 'edit', '-a', enrolled.name, '-t', 'user', CLIENT_GROUP])
  else run('usermod', ['-aG', CLIENT_GROUP, enrolled.name])
  record(state, 'group-member', `${CLIENT_GROUP}:${enrolled.name}`)
  step(`added ${C.b(enrolled.name)} to ${CLIENT_GROUP} ${C.d('(effective at next login; an ACL covers this session)')}`)

  // The daemon sets the group on each socket it creates, and a process cannot
  // chown to a group it is not a member of. Without this the socket silently
  // falls back to 0600 and the CLI cannot reach the daemon at all.
  // Under a dry run the service user was only described, not created, so ask
  // the plan to show this step anyway. A plan that silently omits a step that
  // will really happen is worse than no plan.
  if (DRY || userExists(SERVICE_USER)) {
    if (IS_MAC) run('dseditgroup', ['-o', 'edit', '-a', SERVICE_USER, '-t', 'user', CLIENT_GROUP], { allowFail: true })
    else run('usermod', ['-aG', CLIENT_GROUP, SERVICE_USER], { allowFail: true })
    step(`added ${C.b(SERVICE_USER)} to ${CLIENT_GROUP} ${C.d('so it can group-own the sockets it creates')}`)
  }
}

function serviceIds() {
  if (DRY) return { uid: 399, gid: 399 }
  const uid = Number(run('id', ['-u', SERVICE_USER]).trim())
  const gid = Number(run('id', ['-g', SERVICE_USER]).trim())
  return { uid, gid }
}

function clientGid() {
  if (DRY) return 399
  if (IS_MAC) {
    const out = run('dscl', ['.', '-read', `/Groups/${CLIENT_GROUP}`, 'PrimaryGroupID'])
    return Number(out.split(':').pop().trim())
  }
  return Number(run('getent', ['group', CLIENT_GROUP]).split(':')[2])
}

// ------------------------------------------------------------- the file tree

function makeDir(path, mode, uid, gid) {
  if (DRY) { say(`       ${C.d(`mkdir -m 0${mode.toString(8)} ${path}  (owner ${uid}:${gid})`)}`); return }
  mkdirSync(path, { recursive: true, mode })
  chmodSync(path, mode)
  chownSync(path, uid, gid)
}

function buildTree(state, enrolled) {
  assertRootOwnedChain(dirname(ROOT), 'the install root')
  makeDir(ROOT, 0o755, 0, 0)
  record(state, 'dir', ROOT)

  const svc = serviceIds()

  // The boundary. 0700 owned by the service user: your uid cannot open it.
  makeDir(VAULT_DIR, 0o700, svc.uid, svc.gid)
  record(state, 'dir', VAULT_DIR)
  step(`${C.b(VAULT_DIR)} ${C.d(`0700 ${SERVICE_USER} - this is the boundary`)}`)

  // Sockets: the service owns them, your group may connect, nobody else.
  // 2750: the setgid bit makes every socket created inside inherit the client
  // group, which is what lets the enrolled account connect.
  makeDir(RUN_DIR, 0o2750, svc.uid, clientGid())
  record(state, 'dir', RUN_DIR)
  if (IS_MAC) run('chmod', ['+a', `user:${enrolled.name} allow read,write,execute,search,add_file,delete_child`, RUN_DIR], { allowFail: true })
  else run('setfacl', ['-m', `u:${enrolled.name}:rwx`, RUN_DIR], { allowFail: true })
  step(`${C.b(RUN_DIR)} ${C.d(`2750 ${SERVICE_USER}:${CLIENT_GROUP} setgid + ACL for ${enrolled.name}`)}`)
}

function installApp(state) {
  // --from names the checkout to install. Without it the installer resolves
  // relative to itself, which is right on a first install but wrong for the
  // root-owned copy: that would reinstall the code already present and make
  // every upgrade a no-op.
  const source = value('from')
    ? resolve(value('from'))
    : resolve(dirname(process.argv[1]), '..')
  for (const required of ['src', 'bin', 'package.json']) {
    if (!existsSync(join(source, required))) die(`${source} does not look like an agent-vault checkout (no ${required}).`)
  }
  if (resolve(source) === resolve(APP_DIR)) {
    die(
      'refusing to install the app directory over itself.',
      'Pass --from <path to your checkout> so there is something new to install.',
    )
  }

  // A symlink in the source tree survives the copy as a symlink, so the
  // daemon would end up loading its own code through a path the agent still
  // owns and can rewrite whenever it likes. That turns the one-time
  // trust-on-first-use window into permanent code execution inside the
  // privileged daemon, which is the one thing the uid boundary exists to
  // prevent. A real checkout has no symlinks, so finding one is a finding.
  assertNoSymlinks(source, ['src', 'bin', 'package.json'])

  if (!DRY) {
    rmSync(APP_DIR, { recursive: true, force: true })
    mkdirSync(APP_DIR, { recursive: true, mode: 0o755 })
    for (const part of ['src', 'bin', 'package.json']) {
      // dereference as well as refusing above: belt and braces, because this
      // copy runs as root and its destination is executable code.
      cpSync(join(source, part), join(APP_DIR, part), { recursive: true, dereference: true })
    }
    run('chown', ['-R', 'root:wheel', APP_DIR], { allowFail: !IS_MAC })
    if (!IS_MAC) run('chown', ['-R', 'root:root', APP_DIR])
    run('chmod', ['-R', 'go-w', APP_DIR])
  }
  record(state, 'dir', APP_DIR)
  step(`copied the daemon into ${C.b(APP_DIR)} ${C.d(`from ${source}`)}`)
}

/**
 * Refuse to install a tree containing symbolic links.
 *
 * Root is about to copy this into the directory the daemon executes from. A
 * link there would point outside the root-owned tree, at something the human's
 * account — and therefore an agent running as them — can still modify.
 */
function assertNoSymlinks(source, parts) {
  const walk = (abs, shown) => {
    const st = lstatSync(abs)
    if (st.isSymbolicLink()) {
      die(
        `refusing to install: ${shown} is a symbolic link.`,
        `It points at ${readlinkSync(abs)}, which is outside the tree root is about to own.`,
        'A checkout has no symlinks. If you did not put this here, treat the checkout as compromised.',
      )
    }
    if (st.isDirectory()) {
      for (const entry of readdirSync(abs)) walk(join(abs, entry), `${shown}/${entry}`)
    }
  }
  for (const part of parts) walk(join(source, part), part)
}

const MIN_NODE_MAJOR = 20

/**
 * The runtime this installer is running under becomes the daemon's runtime for
 * good, and sudo resets PATH, so it is easy to enshrine an older Node than the
 * one the operator tests with. Check it rather than discovering it later.
 */
function assertRuntimeVersion(path, version) {
  const major = Number(String(version).replace(/^v/, '').split('.')[0])
  if (!Number.isFinite(major) || major < MIN_NODE_MAJOR) {
    die(
      `that Node is ${version}; agent-vault needs ${MIN_NODE_MAJOR} or newer.`,
      `sudo resets PATH, so this is often an older Node than your shell uses.\n  Re-run with the one you want: sudo $(which node) ${resolve(process.argv[1])} ${verb}`,
    )
  }
  return major
}

function installRuntime(state) {
  const supplied = value('use-node')
  if (supplied) {
    assertRootOwnedChain(supplied, 'the Node binary')
    const suppliedVersion = DRY ? process.version : execFileSync(supplied, ['--version'], { encoding: 'utf8' }).trim()
    assertRuntimeVersion(supplied, suppliedVersion)
    if (!DRY) writeFileSync(join(ROOT, 'runtime-path'), supplied, { mode: 0o644 })
    step(`using the root-owned Node at ${C.b(supplied)}`)
    return supplied
  }

  // The running interpreter is almost always under a version manager in your
  // home directory. Pointing a root service at it would let anything running as
  // you replace root's interpreter, so a copy goes into the root-owned tree.
  const nodePath = process.execPath
  assertRuntimeVersion(nodePath, process.version)
  const target = join(RUNTIME_DIR, 'node')
  if (!DRY) {
    mkdirSync(RUNTIME_DIR, { recursive: true, mode: 0o755 })
    cpSync(nodePath, target)
    chownSync(target, 0, 0)
    chmodSync(target, 0o755)
    chownSync(RUNTIME_DIR, 0, 0)
    chmodSync(RUNTIME_DIR, 0o755)
    writeFileSync(join(ROOT, 'runtime-path'), target, { mode: 0o644 })
  }
  record(state, 'dir', RUNTIME_DIR)
  const mb = existsSync(nodePath) ? Math.round(statSync(nodePath).size / 1e6) : 0
  step(`copied the Node runtime into ${C.b(RUNTIME_DIR)} ${C.d(`${process.version}, ${mb} MB, from ${nodePath}`)}`)
  return target
}

// ------------------------------------------------------------- service units

function installService(state, nodeBin, enrolled) {
  const entry = join(APP_DIR, 'bin', 'agent-vault-daemon.js')
  const env = {
    AV_VAULT_DIR: VAULT_DIR,
    AV_RUN_DIR: RUN_DIR,
    AV_ENROLLED_UID: String(enrolled.uid),
    AV_CLIENT_GROUP: CLIENT_GROUP,
    AV_PORT: value('port') || '7411',
  }

  if (IS_MAC) {
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>${nodeBin}</string><string>${entry}</string></array>
  <key>UserName</key><string>${SERVICE_USER}</string>
  <key>GroupName</key><string>${SERVICE_USER}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Adaptive</string>
  <key>EnvironmentVariables</key>
  <dict>${Object.entries(env).map(([k, v]) => `
    <key>${k}</key><string>${v}</string>`).join('')}
  </dict>
  <key>StandardOutPath</key><string>${join(VAULT_DIR, 'daemon.out')}</string>
  <key>StandardErrorPath</key><string>${join(VAULT_DIR, 'daemon.err')}</string>
  <key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
</dict>
</plist>
`
    if (!DRY) {
      writeFileSync(PLIST, plist, { mode: 0o644 })
      chownSync(PLIST, 0, 0)
    } else say(`       ${C.d(`write ${PLIST}`)}`)
    record(state, 'file', PLIST)
    bootstrapLaunchd()
    step(`installed and started the launchd service ${C.d(LAUNCHD_LABEL)}`)
  } else {
    const unit = `[Unit]
Description=agent-vault daemon
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
SupplementaryGroups=${CLIENT_GROUP}
ExecStart=${nodeBin} ${entry}
${Object.entries(env).map(([k, v]) => `Environment=${k}=${v}`).join('\n')}
RuntimeDirectory=agent-vault
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${VAULT_DIR} ${RUN_DIR}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
MemoryDenyWriteExecute=yes
LockPersonality=yes
LimitCORE=0
Restart=always

[Install]
WantedBy=multi-user.target
`
    if (!DRY) writeFileSync(SYSTEMD_UNIT, unit, { mode: 0o644 })
    else say(`       ${C.d(`write ${SYSTEMD_UNIT}`)}`)
    record(state, 'file', SYSTEMD_UNIT)
    run('systemctl', ['daemon-reload'])
    run('systemctl', ['enable', 'agent-vault.service'], { allowFail: true })
    // restart rather than start, so a reinstall picks up the new binary.
    run('systemctl', ['restart', 'agent-vault.service'])
    step('installed and started the systemd service')
  }
}

/** Is the service currently known to launchd? */
function serviceLoaded() {
  if (DRY) return false
  try {
    execFileSync('launchctl', ['print', `system/${LAUNCHD_LABEL}`], { stdio: ['ignore', 'ignore', 'ignore'] })
    return true
  } catch { return false }
}

function sleepMs(ms) {
  // Deliberately synchronous: the installer is a linear script and this is the
  // only place it has to wait for the kernel to catch up.
  execFileSync('/bin/sleep', [String(ms / 1000)], { stdio: 'ignore' })
}

/**
 * Load the service, tolerating the teardown race.
 *
 * `launchctl bootout` returns before the job is actually gone, so an immediate
 * bootstrap fails with "Bootstrap failed: 5: Input/output error". Waiting for
 * the service to really disappear, and falling back to kickstart when it is
 * still registered, is what makes a reinstall reliable.
 */
function bootstrapLaunchd() {
  if (DRY) {
    say(`       ${C.d(`launchctl bootout system/${LAUNCHD_LABEL}  (then wait for teardown)`)}`)
    say(`       ${C.d(`launchctl enable system/${LAUNCHD_LABEL}`)}`)
    say(`       ${C.d(`launchctl bootstrap system ${PLIST}`)}`)
    return
  }

  run('launchctl', ['bootout', `system/${LAUNCHD_LABEL}`], { allowFail: true })
  for (let i = 0; i < 40 && serviceLoaded(); i++) sleepMs(250)

  // A service can be marked disabled in launchd's database, which makes
  // bootstrap fail no matter how long you wait.
  run('launchctl', ['enable', `system/${LAUNCHD_LABEL}`], { allowFail: true })

  let lastError = null
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      execFileSync('launchctl', ['bootstrap', 'system', PLIST], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
      lastError = null
      break
    } catch (e) {
      lastError = (e.stderr || e.message).toString().trim()
      if (serviceLoaded()) { lastError = null; break } // already up; nothing to retry
      sleepMs(500 * attempt)
    }
  }

  if (lastError && !serviceLoaded()) {
    // One more path: if launchd still has it registered, restarting is enough.
    try {
      execFileSync('launchctl', ['kickstart', '-k', `system/${LAUNCHD_LABEL}`], { stdio: ['ignore', 'ignore', 'pipe'] })
      lastError = null
    } catch { /* reported below */ }
  }

  if (lastError && !serviceLoaded()) {
    die(
      `could not start the service: ${lastError}`,
      `The files are installed. Start it with:\n` +
      `    sudo launchctl bootout system/${LAUNCHD_LABEL} ; sudo launchctl bootstrap system ${PLIST}`,
    )
  }

  // Confirm it actually came up rather than assuming.
  for (let i = 0; i < 20; i++) {
    if (existsSync(join(RUN_DIR, 'control.sock'))) return
    sleepMs(250)
  }
  say(`  ${C.y('warn')}  the service loaded but its socket has not appeared yet; check: agent-vault status`)
}

// ------------------------------------------------------------------- verbs

function install() {
  requireRoot()
  const enrolled = enrolledUser()
  const state = loadState()

  say(`\n${C.b('agent-vault install')}${DRY ? C.y('  (dry run: nothing will change)') : ''}`)
  say(C.d(`  enrolling ${enrolled.name} (uid ${enrolled.uid}) on ${IS_MAC ? 'macOS' : 'Linux'}\n`))

  createServiceUser(state)
  createClientGroup(state, enrolled)
  buildTree(state, enrolled)
  installApp(state)
  const nodeBin = installRuntime(state)
  installService(state, nodeBin, enrolled)
  saveState(state)

  say(`\n${C.b('done')}`)
  say(`  The daemon runs as ${C.b(SERVICE_USER)}. Your account cannot read ${VAULT_DIR}.`)
  say(`  Check it: ${C.b(`cat ${join(VAULT_DIR, 'vault.json')}`)} ${C.d('should say Permission denied')}`)
  say()
  say(`  Next, as ${enrolled.name}:`)
  say(`    ${C.b('agent-vault status')}`)
  say(`    ${C.b('agent-vault cred add gh --kind github')}`)
  say()
  const rootRuntime = join(RUNTIME_DIR, 'node')
  const installedSetup = join(APP_DIR, 'bin', 'agent-vault-setup.js')
  say(C.d(`  To remove everything: sudo ${rootRuntime} ${installedSetup} uninstall`))
  say(C.d('  (that runtime path matters: root PATH has no nvm node)'))
  say()
}

function uninstall() {
  requireRoot()
  const state = loadState()
  const purge = flag('purge')
  say(`\n${C.b('agent-vault uninstall')}${DRY ? C.y('  (dry run)') : ''}\n`)

  if (IS_MAC) run('launchctl', ['bootout', `system/${LAUNCHD_LABEL}`], { allowFail: true })
  else { run('systemctl', ['disable', '--now', 'agent-vault.service'], { allowFail: true }) }
  step('stopped the service')

  // The vault is kept by default. Deleting someone's only copy of their
  // credentials because they typed "uninstall" is not a recovery story.
  if (existsSync(VAULT_DIR) && !DRY) {
    if (purge) {
      rmSync(VAULT_DIR, { recursive: true, force: true })
      step(C.r('deleted the vault and every credential in it'))
    } else {
      // Deliberately outside ROOT: the last step of uninstall removes ROOT, and
      // on macOS the vault lives inside it. Retiring to a sibling there would
      // delete the credentials this branch exists to preserve.
      const retired = `${dirname(ROOT)}/agent-vault-retired-${Date.now()}`
      renameSync(VAULT_DIR, retired)
      state.retired = retired
      step(`kept your credentials at ${C.b(retired)} ${C.d('(--purge deletes them instead)')}`)
    }
  }

  for (const item of [...state.created].reverse()) {
    if (item.kind === 'dir' && item.id !== VAULT_DIR) {
      if (!DRY) rmSync(item.id, { recursive: true, force: true })
      step(`removed ${item.id}`)
    }
    if (item.kind === 'file') {
      if (!DRY) rmSync(item.id, { force: true })
      step(`removed ${item.id}`)
    }
  }

  // The service user is deliberately left in place. Deleting it frees its uid,
  // and a future service that reuses that uid would inherit access to any
  // retired vault still on disk.
  // Under a dry run the service user was only described, not created, so ask
  // the plan to show this step anyway. A plan that silently omits a step that
  // will really happen is worse than no plan.
  if (DRY || userExists(SERVICE_USER)) {
    say(C.d(`       left the ${SERVICE_USER} account in place; removing it would free its uid for reuse`))
  }
  if (!DRY && existsSync(ROOT)) {
    if (state.retired && state.retired.startsWith(ROOT)) {
      die(`refusing to remove ${ROOT}: your retired vault is inside it at ${state.retired}`)
    }
    rmSync(ROOT, { recursive: true, force: true })
  }
  say(`\n${C.b('done')}  Your own ~/.agent-vault dev vault, if any, is untouched.\n`)
}

function status() {
  const installed = existsSync(STATE)
  say(`\n${C.b('agent-vault system install')}\n`)
  if (!installed) {
    say(`  ${C.y('not installed')}  no ${STATE}`)
    say(`  ${C.d(`install with: sudo ${process.execPath} ${resolve(process.argv[1])} install`)}\n`)
    return
  }
  const checks = []
  const svcExists = userExists(SERVICE_USER)
  checks.push(['service user', svcExists, SERVICE_USER])
  if (existsSync(VAULT_DIR)) {
    const st = statSync(VAULT_DIR)
    const mode = st.mode & 0o777
    checks.push(['vault mode 0700', mode === 0o700, `0${mode.toString(8)}`])
    checks.push(['vault owned by service user', st.uid !== 0 && st.uid !== process.getuid(), `uid ${st.uid}`])
  } else checks.push(['vault directory', false, 'missing'])
  checks.push(['service unit', existsSync(IS_MAC ? PLIST : SYSTEMD_UNIT), IS_MAC ? PLIST : SYSTEMD_UNIT])
  checks.push(['socket directory', existsSync(RUN_DIR), RUN_DIR])
  const trustedCopy = resolve(process.argv[1]).startsWith(APP_DIR)
  checks.push(['running the root-owned installer', trustedCopy, trustedCopy ? APP_DIR : resolve(process.argv[1])])

  for (const [name, ok, note] of checks) {
    say(`  ${ok ? C.g('ok  ') : C.y('warn')} ${name.padEnd(32)} ${C.d(note)}`)
  }
  say()
}

function help() {
  say(`\n${C.b('agent-vault-setup')}  the privileged installer

  ${C.b('sudo agent-vault-setup.js install')} [--user <name>] [--port 7411] [--use-node <path>] [--dry-run]
  ${C.b('sudo agent-vault-setup.js uninstall')} [--purge] [--dry-run]
  ${C.b('agent-vault-setup.js status')}

  install creates the ${SERVICE_USER} system user and a root-owned tree, so the
  vault is unreadable to anything running as you. --dry-run prints every change
  it would make and touches nothing.
`)
}

try {
  switch (verb) {
    case 'install': install(); break
    case 'uninstall': uninstall(); break
    case 'status': status(); break
    default: help()
  }
} catch (e) {
  die(e.message)
}
