#!/usr/bin/env node
// The service entry point. launchd and systemd start this as the _agentvault
// user; it is not meant to be run by hand.
//
// It reads its paths from the environment the unit file sets, creates the vault
// on first start, and exposes the control socket to the client group only.

import { existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { Vault } from '../src/store/vault.js'
import { Daemon } from '../src/daemon/server.js'

const VAULT_DIR = process.env.AV_VAULT_DIR
const RUN_DIR = process.env.AV_RUN_DIR
const PORT = Number(process.env.AV_PORT || 7411)
const ENROLLED_UID = process.env.AV_ENROLLED_UID ? Number(process.env.AV_ENROLLED_UID) : null

if (!VAULT_DIR || !RUN_DIR) {
  console.error('agent-vault-daemon: AV_VAULT_DIR and AV_RUN_DIR must be set; this runs under launchd or systemd')
  process.exit(2)
}

// Running as root would defeat the entire point of the install: the daemon is
// meant to be the one uid that can read the vault, not the one uid that can do
// anything at all.
if (process.getuid() === 0) {
  console.error('agent-vault-daemon: refusing to run as root; the service unit must set the service user')
  process.exit(2)
}

const socketPath = join(RUN_DIR, 'control.sock')

let vault
let unlocked = true
if (existsSync(join(VAULT_DIR, 'vault.json'))) {
  vault = Vault.open(VAULT_DIR)
  // Come up the way the vault was left. A daemon that silently unlocks on
  // restart would mean a reboot undoes a lock.
  unlocked = vault.startInRecordedState(null)
} else {
  mkdirSync(VAULT_DIR, { recursive: true, mode: 0o700 })
  vault = Vault.create(VAULT_DIR, { factor: 'none' })
}

const daemon = new Daemon(vault, {
  port: PORT,
  socketPath,
  // The socket is group-readable so the enrolled account's CLI can connect,
  // while the vault behind it stays 0700 and unreadable to that same account.
  socketGroup: process.env.AV_CLIENT_GROUP || null,
  enrolledUid: ENROLLED_UID,
})

await daemon.start()
console.log(`agent-vault daemon ready as uid ${process.getuid()}`)
console.log(`  vault    ${VAULT_DIR}`)
console.log(`  gateway  http://127.0.0.1:${daemon.gatewayPort}`)
console.log(`  control  ${socketPath}`)
if (!unlocked) console.log('  vault is LOCKED; run: agent-vault unlock')

const shutdown = async () => { await daemon.stop(); process.exit(0) }
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
