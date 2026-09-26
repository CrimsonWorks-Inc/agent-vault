#!/usr/bin/env node
//
// Check the tests against themselves.
//
// Three hundred passing tests say nothing unless they fail when a protection
// is removed. This breaks each critical one in turn and asserts that the suite
// notices. A mutation that survives means the thing it broke is not really
// tested, whatever the test names claim.
//
// Run with: npm run test:mutation
//
// It restores files from an in-memory copy rather than `git checkout`, because
// checkout restores the last COMMIT — which silently destroys uncommitted work
// if you happen to be mid-change. That is not hypothetical; it ate a fix.

import { readFileSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const node = process.execPath

/**
 * Each entry breaks one protection by a literal string swap, then names the
 * tests that must go red. `from` has to appear exactly once.
 */
const MUTATIONS = [
  {
    // An approved lifetime that use can extend is not a lifetime.
    what: 'idle activity extends a session past its approved lifetime',
    file: 'src/store/vault.js',
    from: 'const ceiling = ttlMs == null ? hardCapMs : life',
    to: 'const ceiling = hardCapMs',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'a requested lifetime may exceed the hard ceiling',
    file: 'src/store/vault.js',
    from: 'const life = Math.min(ttlMs ?? 8 * 3600_000, hardCapMs)',
    to: 'const life = ttlMs ?? 8 * 3600_000',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    // A denial nobody can be attributed to cannot be investigated.
    what: 'a policy denial is filed without the session that was refused',
    file: 'src/daemon/pipeline.js',
    from: 'session_id: session?.id ?? null,',
    to: 'session_id: null,',
    tests: ['test/security/audit-content.test.js'],
  },
  {
    what: 'the human-presence gate never refuses',
    file: 'src/daemon/server.js',
    from: "throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human",
    to: "if (0) throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human",
    tests: ['test/security/control-gate.test.js'],
  },
  {
    what: 'the streaming scrubber tears matches at the cut',
    file: 'src/core/scrub.js',
    from: 'const { text, redactions: r } = self.scrub(combined.slice(0, cut))',
    to: 'const { text, redactions: r } = self.scrub(combined.slice(0, combined.length - keep))',
    tests: ['test/core/scrub-fuzz.test.js'],
  },
  {
    what: 'an encoded placeholder counts as an injection site',
    file: 'src/core/substitute.js',
    from: "if (location.encoding !== 'raw') return false",
    to: 'if (false) return false',
    tests: ['test/core/integrity-fuzz.test.js'],
  },
  {
    what: 'the placeholder checksum always verifies',
    file: 'src/core/placeholder.js',
    from: 'return want.length === got.length && timingSafeEqual(want, got)',
    to: 'return true',
    tests: ['test/core/integrity-fuzz.test.js', 'test/core/placeholder.test.js'],
  },
  {
    what: 'a grant is not confined to its credential’s hosts',
    file: 'src/core/policy.js',
    from: 'export function confineHosts(requested, ceiling) {',
    to: 'export function confineHosts(requested, ceiling) {\n  if (requested && requested.length) return requested',
    tests: ['test/security/exfil.test.js', 'test/core/host-confinement.test.js'],
  },
  {
    what: 'the session token is forwarded upstream',
    file: 'src/daemon/pipeline.js',
    from: 'if (carriesToken) continue',
    to: 'if (false) continue',
    tests: ['test/security/carrier.test.js'],
  },
  {
    what: 'an approval is not bound to its request',
    file: 'src/daemon/pipeline.js',
    from: 'const existing = this.approvals.get(requestHash)',
    to: 'const existing = [...this.approvals.values()][0]',
    tests: ['test/security/control-gate.test.js'],
  },
  {
    what: 'error details reach the agent unscrubbed',
    file: 'src/daemon/pipeline.js',
    from: 'err.detail = this.#safeMessage({ message: err.detail }, scrubber)',
    to: '',
    tests: ['test/security/response.test.js'],
  },
  {
    what: 'a control character in a path is allowed through',
    file: 'src/core/policy.js',
    from: "throw deny('AV_POLICY_DENIED', `path contains a control character (0x${code})`, {",
    to: "if (0) throw deny('AV_POLICY_DENIED', `path contains a control character (0x${code})`, {",
    tests: ['test/security/path-parsing.test.js'],
  },
  {
    what: 'a non-ASCII secret is not scrubbed',
    file: 'src/core/scrub.js',
    from: "add(Buffer.from(secret, 'utf8').toString('latin1'))",
    to: '',
    tests: ['test/core/scrub-fuzz.test.js'],
  },
  {
    what: 'the MCP session is read from shared state again',
    file: 'src/daemon/server.js',
    from: 'const r = await this.mcp.handle(m, session, token)',
    to: 'const r = await this.mcp.handle(m)',
    tests: ['test/security/mcp-tools.test.js'],
  },
  {
    what: 'a child may widen past a ceiling',
    file: 'src/core/policy.js',
    from: '  if (outer === inner) return true\n  const o = String(outer)',
    to: '  if (outer === inner) return true\n  if (String(outer).includes("**")) return String(inner).startsWith(String(outer).slice(0, String(outer).indexOf("**")))\n  const o = String(outer)',
    tests: ['test/core/detect-fuzz.test.js'],
  },
  {
    what: 'an agent can enroll its own unlock factor',
    file: 'src/daemon/server.js',
    from: "          this.#requireHumanForWidening(\n            input.action === 'remove' ? 'touch id removal' : 'touch id enrollment',",
    to: "          if (0) this.#requireHumanForWidening(\n            input.action === 'remove' ? 'touch id removal' : 'touch id enrollment',",
    tests: ['test/security/control-gate.test.js'],
  },
  {
    what: 'removing the last wrap leaves the vault unopenable',
    file: 'src/store/vault.js',
    from: '    if (!this.db.kv.vmk_wraps.length) {\n      const deviceKey = readFileSync(this.deviceKeyPath)',
    to: '    if (false) {\n      const deviceKey = readFileSync(this.deviceKeyPath)',
    tests: ['test/core/passphrase.test.js'],
  },
  {
    what: 'the base64 needle drops the secret’s tail',
    file: 'src/core/scrub.js',
    from: 'const end = Math.floor((4 * (pad + bytes.length)) / 3)',
    to: 'const end = std.length - 4',
    tests: ['test/core/scrub-fuzz.test.js'],
  },
  {
    what: 'a budget with no limit means no limit',
    file: 'src/core/policy.js',
    from: '  return limits.length ? { unit, limit: Math.min(...limits) } : { unit }',
    to: '  return { unit, limit: Math.min(a.limit, b.limit) }',
    tests: ['test/security/pipeline.test.js'],
  },
  {
    what: 'a server name can rewrite someone else’s config',
    file: 'src/cli/mcp-install.js',
    from: "  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) {",
    to: '  if (false) {',
    tests: ['test/core/mcp-install.test.js'],
  },
  {
    what: 'the audit log’s end is not anchored',
    file: 'src/store/audit.js',
    from: "    if (anchor && anchor.seq > last.seq) {",
    to: '    if (false) {',
    tests: ['test/security/audit-content.test.js'],
  },
  {
    what: 'locate() does not read header names',
    file: 'src/core/substitute.js',
    from: "      add(hit, { region: 'header-name', name: lower, index, encoding: hit.encoding })",
    to: '      void hit',
    tests: ['test/security/pipeline.test.js'],
  },
  {
    what: 'wrapped base64 is invisible to the detector',
    file: 'src/core/detect.js',
    from: "    if (/\\s|\\\\[nrtbf]/.test(v)) variants.add(v.replace(/\\\\[nrtbf]|\\s+/g, ''))",
    to: '    void v',
    tests: ['test/core/detect-fuzz.test.js'],
  },
  {
    what: 'the placeholder checksum is never checked',
    file: 'src/daemon/pipeline.js',
    from: '      if (!ph.verify(this.vault.kPh, occ.parsed)) {',
    to: '      if (false) {',
    tests: ['test/security/pipeline.test.js'],
  },
  {
    what: 'the fingerprint is an oracle for the checksum key',
    file: 'src/store/vault.js',
    from: '        fp8: crypt.fingerprint8(this.kFingerprint, value),',
    to: '        fp8: crypt.fingerprint8(this.kPh, value),',
    tests: ['test/security/pipeline.test.js'],
  },
  {
    what: 'an approval is not bound to its headers',
    file: 'src/core/canon.js',
    from: "    headers: [...(headers || [])]",
    to: "    headers: [].concat([]) || [...(headers || [])]",
    tests: ['test/security/pipeline.test.js'],
  },
  {
    what: 'a compressed event stream bypasses the scrubber',
    file: 'src/daemon/pipeline.js',
    from: '        source = res.res.pipe(gunzip)',
    to: '        source = res.res',
    tests: ['test/security/response.test.js'],
  },
  {
    what: 'derived token shapes match mid-word',
    file: 'src/core/scrub.js',
    from: "const BOUNDARY = '(?<![A-Za-z0-9_-])'",
    to: "const BOUNDARY = ''",
    tests: ['test/core/scrub.test.js', 'test/security/response.test.js'],
  },
  {
    what: 'the listener never reaches the pipeline',
    file: 'src/daemon/server.js',
    from: '      listener: req.listener || null,',
    to: '      listener: null,',
    tests: ['test/security/listener.test.js'],
  },
  {
    what: 'a one-time placeholder renews itself unlimited',
    file: 'src/store/vault.js',
    from: '      grantId: old.grant_id, field: old.field, uses: old.max_uses,',
    to: '      grantId: old.grant_id, field: old.field,',
    tests: ['test/security/pipeline.test.js'],
  },
  {
    what: 'an agent can enrol a presence key on a fresh vault',
    file: 'src/daemon/server.js',
    from: '          if (!this.vault.hasPassphrase) {\n            throw deny(\'AV_POLICY_DENIED\', \'set a passphrase before enrolling an authenticator\', {',
    to: '          if (false) {\n            throw deny(\'AV_POLICY_DENIED\', \'set a passphrase before enrolling an authenticator\', {',
    tests: ['test/security/control-gate.test.js'],
  },
  {
    what: 'the stdio bridge writes non-protocol bytes to stdout',
    file: 'src/cli/index.js',
    from: 'process.stdout.write(`${asRpc(text, line, res.status)}',
    to: 'process.stdout.write(`${text}',
    tests: ['test/security/bridge.test.js'],
  },
  {
    what: 'an agent can approve its own session request',
    file: 'src/daemon/server.js',
    from: "          this.#requireHumanForWidening(\n            'session request approval',",
    to: "          if (0) this.#requireHumanForWidening(\n            'session request approval',",
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'a session request is created from what was asked, not what was approved',
    file: 'src/daemon/server.js',
    from: '          const created = this.#createSession({\n            ...final,',
    to: '          const created = this.#createSession({\n            ...record.proposal,',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'the session-request store caches a null audit handle',
    file: 'src/daemon/session-requests.js',
    from: '  get audit() { return this.vault?.audit ?? null }',
    to: '  get audit() { return this._c ?? (this._c = this.vault?.audit ?? null) }',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'approving a session request records nothing',
    file: 'src/pending.js',
    from: '  remember(got)',
    to: '  void got',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'pending session requests are lost on a restart',
    file: 'src/daemon/session-requests.js',
    from: '    this.#load()',
    to: '    // disabled',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'an approved token is persisted to disk',
    file: 'src/daemon/session-requests.js',
    // Copies, like the real code, so change-detection still works — it just
    // keeps `result`. A mutation that also broke persistence would mask the
    // leak rather than reveal it, which is what the first attempt did.
    from: "      .filter((r) => r.state === 'pending' || r.state === 'denied')\n      .map(({ result, ...rest }) => rest)",
    to: '      .map((r) => ({ ...r }))',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'the installer accepts a symlinked checkout',
    file: 'bin/agent-vault-setup.js',
    from: "assertNoSymlinks(source, ['src', 'bin', 'package.json'])",
    to: '// disabled',
    tests: ['test/security/installer.test.js'],
  },
]

let survived = 0

// Restore on the way out, however we leave.
//
// The `finally` below covers a thrown error, and nothing else. A SIGINT, a
// SIGTERM, or a harness that gives up on a slow run all skip it and leave a
// protection disabled in the working tree — which is exactly what happened:
// `if (!ph.verify(...))` sat as `if (false)` for several commits' worth of
// work, and only the drift report caught it. A tool that can silently switch
// off a security check is worse than no tool.
const inFlight = new Map()
const restoreAll = () => {
  for (const [path, original] of inFlight) {
    try { writeFileSync(path, original) } catch { /* nothing better to do while exiting */ }
  }
  inFlight.clear()
}
process.on('exit', restoreAll)
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => { restoreAll(); process.exit(130) })
}

console.log(`Checking ${MUTATIONS.length} protections against the suite.\n`)

for (const m of MUTATIONS) {
  const path = join(ROOT, m.file)
  const original = readFileSync(path, 'utf8')
  const occurrences = original.split(m.from).length - 1
  if (occurrences !== 1) {
    console.log(`?  ${m.what}\n   anchor appears ${occurrences} times in ${m.file}; the check has drifted`)
    survived++
    continue
  }

  inFlight.set(path, original)
  writeFileSync(path, original.replace(m.from, m.to))
  try {
    const res = spawnSync(node, ['--test', ...m.tests.map((t) => join(ROOT, t))], { encoding: 'utf8' })
    const failed = /^[#ℹ] fail (\d+)/m.exec(res.stdout)
    const count = failed ? Number(failed[1]) : 0
    if (count > 0) {
      console.log(`ok ${m.what}\n   caught by ${count} test${count > 1 ? 's' : ''}`)
    } else {
      console.log(`SURVIVED  ${m.what}\n   nothing failed — this protection is not really tested`)
      survived++
    }
  } finally {
    // Always, even if the run threw — and the exit and signal handlers above
    // cover the ways a `finally` never runs at all.
    writeFileSync(path, original)
    inFlight.delete(path)
  }
}

console.log()
if (survived) {
  console.log(`${survived} mutation${survived > 1 ? 's' : ''} survived. A protection with no test behind it is a claim.`)
  process.exit(1)
}
console.log('Every protection is held up by at least one failing test.')
