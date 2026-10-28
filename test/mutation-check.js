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
    // Bulk approval without a gate is an agent approving its own work.
    what: 'a batch of decisions is settled with no human present',
    file: 'src/daemon/server.js',
    from: "            'bulk decision',",
    to: "            'bulk decision', null) || (0 &&",
    tests: ['test/security/session-requests.test.js', 'test/security/widening.test.js'],
  },
  {
    // `granted: "false"` is a non-empty string: under truthiness it APPROVES.
    what: 'a batch verdict is read by truthiness rather than as a boolean',
    file: 'src/pending.js',
    from: "if (typeof d.granted !== 'boolean')",
    to: 'if (false)',
    tests: ['test/security/session-requests.test.js'],
  },
  {
    // Binding the PROTOCOL to capability, which is what broke reconnects.
    what: 'the MCP endpoint refuses the handshake without a live session',
    file: 'src/daemon/server.js',
    from: 'let session = this.vault.sessionByToken(token)',
    to: "let session = this.vault.sessionByToken(token); if (!session) return send(401, { code: 'AV_SESSION_REQUIRED' })",
    tests: ['test/security/mcp.test.js'],
  },
  {
    // And the other direction: the tools must still check for themselves. The
    // anchor carries the case label, because the guard line alone appears four
    // times and the checker refuses an ambiguous anchor rather than guessing.
    what: 'a tool that spends capability runs without a session',
    file: 'src/daemon/mcp.js',
    from: "case 'vault_http': {\n        if (!session) return this.#needsSession(token, listener)",
    to: "case 'vault_http': {",
    tests: ['test/security/mcp.test.js', 'test/security/bridge.test.js'],
  },
  {
    // The approval hash. Binding the placeholder's identity instead of its
    // capability made every held write un-resendable over MCP.
    what: 'an approval is bound to which placeholder carried the credential',
    file: 'src/daemon/pipeline.js',
    from: 'credentials: substitutions.map((s) => `${s.row.grant_id}:${s.row.field}`),',
    to: 'credentials: substitutions.map((s) => s.row.id),',
    tests: ['test/security/pipeline.test.js'],
  },
  {
    // The other half: the placeholder's TEXT is in the headers it rides in.
    what: 'the placeholder text is hashed raw, so a resend never matches',
    file: 'src/daemon/pipeline.js',
    from: '}).map(([n, v]) => [n, stableHeader(n, v)]),',
    to: '}),',
    tests: ['test/security/pipeline.test.js'],
  },
  {
    what: 'a resend may change the bytes the human approved',
    file: 'src/daemon/pipeline.js',
    from: "const bodySha = view.body ? canon.sha256(Buffer.from(stable(view.body.toString('latin1')), 'latin1')) : ''",
    to: "const bodySha = ''",
    tests: ['test/security/pipeline.test.js'],
  },
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
    from: "throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human: confirm",
    to: "if (0) throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human: confirm",
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
    from: 'const r = await this.mcp.handle(m, session, token, listener)',
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
    from: "          this.#requireFreshPresence(\n            input.action === 'remove' ? 'touch id removal' : 'touch id enrollment',",
    to: "          if (0) this.#requireFreshPresence(\n            input.action === 'remove' ? 'touch id removal' : 'touch id enrollment',",
    tests: ['test/security/control-gate.test.js'],
  },
  {
    what: 'removing the last wrap leaves the vault unopenable',
    file: 'src/store/vault.js',
    // Re-anchored in fix-control round 4, when removal went through the
    // factor commit.
    from: '    const downgraded = !wraps.length\n',
    to: '    const downgraded = false\n',
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
    from: "  return limits.length ? { unit: 'requests', limit: Math.min(...limits) } : { unit: 'requests' }",
    to: "  return { unit: 'requests', limit: Math.min(a?.limit, b?.limit) }",
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
    from: 'const decoder = compressed ? decompressStream(contentEncoding) : new PassThrough()',
    to: 'const decoder = new PassThrough()',
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
    from: '          if (!existed && !this.vault.hasPassphrase) {\n            throw deny(\'AV_POLICY_DENIED\', \'set a passphrase before enrolling an authenticator\', {',
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
    // Re-anchored when the gate became #gateSession, which picks the widening
    // or the fresh level from the decision's elevation.
    from: "          this.#gateSession(\n            'session request approval',",
    to: "          if (0) this.#gateSession(\n            'session request approval',",
    tests: ['test/security/session-requests.test.js'],
  },
  {
    what: 'a session request is created from what was asked, not what was approved',
    file: 'src/daemon/server.js',
    // Re-anchored when the settle path moved out of the route into
    // #settleSessionRequest, so the single and bulk routes could share it. The
    // indentation changed with it and the old anchor stopped matching - the
    // drift report is the only reason that was noticed rather than quietly
    // leaving this protection unchecked.
    // And again when ttl_minutes was split off the final spec before it is
    // passed on, so a lifetime of 0 is refused rather than read as default.
    // And again in wave 3, when that split moved into requestSpec so the
    // proposer's dry run and the settle path read a proposal the same way.
    from: '      ...requestSpec(final),\n',
    to: '      ...requestSpec(record.proposal),\n',
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
  // fix-control: the protections added by the fix-control batch.
  {
    what: 'a request field can rewrite the signed op or a digest',
    file: 'src/ui/webauthn.js',
    from: "if (key === 'op' || key.endsWith('_sha256')) {",
    to: "if (false) {",
    tests: ['test/security/fix-control-webauthn.test.js'],
  },
  {
    what: 'denying a held request needs no human',
    file: 'src/daemon/server.js',
    from: "          this.#requireHumanForWidening(\n            granted ? 'approval grant' : 'approval deny',",
    to: "          if (granted) this.#requireHumanForWidening(\n            granted ? 'approval grant' : 'approval deny',",
    tests: ['test/security/fix-control-approvals.test.js'],
  },
  {
    what: "the control API hands back an approval's cached upstream response",
    file: 'src/daemon/server.js',
    from: "  const { result, ...rest } = approval\n  return rest",
    to: "  return approval",
    // With the pipeline refusing anything not pending, only a test that
    // stands in for a regressed pipeline can reach this layer.
    tests: ['test/security/fix-control-approvals.test.js', 'test/security/wave1-compose.test.js'],
  },
  {
    what: 'an authenticator-only vault reports its socket as ungated',
    file: 'src/daemon/server.js',
    from: '            if (this.vault.db?.kv?.webauthn) {\n              return json(200, {\n                granted: false,\n                ungated: false,',
    to: '            if (false) {\n              return json(200, {\n                granted: false,\n                ungated: false,',
    tests: ['test/security/fix-control-factors.test.js'],
  },
  {
    what: 'Touch ID changes from the UI drop the proof on the way to the daemon',
    file: 'src/ui/server.js',
    from: "action: 'remove', presence: body?.presence,",
    to: "action: 'remove',",
    tests: ['test/security/fix-control-touchid.test.js'],
  },
  {
    what: '--allow-cidr is stored and not enforced',
    file: 'src/daemon/server.js',
    from: "if (peerAllowed(allow, socket.remoteAddress)) return",
    to: "return",
    tests: ['test/security/fix-control-listeners.test.js'],
  },
  {
    what: 'listen rm leaves the bound server serving',
    file: 'src/daemon/server.js',
    from: "const unbound = await this.#unbindListener(lid)",
    to: "const unbound = false",
    tests: ['test/security/fix-control-listeners.test.js'],
  },
  {
    what: 'an uncaught error ends the daemon',
    file: 'src/daemon/server.js',
    from: "    guardProcess(this)\n",
    to: "\n",
    tests: ['test/security/fix-control-process.test.js'],
  },
  {
    what: 'vault_http never sends the session token',
    file: 'src/daemon/mcp.js',
    // Anchored on the comment above it since vault_preflight (wave 3) pushes
    // the same header line.
    from: "        // as carrier, which only a header site allows.\n        headers.push(['av-session', this.#tokenFor(session, token)])",
    to: "        // as carrier, which only a header site allows.\n        headers.push(['av-session', this.#tokenFor(session)])",
    tests: ['test/security/fix-control-mcp.test.js'],
  },
  {
    what: 'vault_http leaves its placeholder live after the call',
    file: 'src/daemon/mcp.js',
    from: "if (live?.state === 'active' && !this.vault.locked) this.vault.burnPlaceholder(row.id, 'spent')",
    to: "void live",
    tests: ['test/security/fix-control-mcp.test.js'],
  },
  {
    what: 'narrowing a grant can widen it',
    file: 'src/store/vault.js',
    from: "g.policy = policyMod.intersect([g.policy, narrow])",
    to: "g.policy = { ...g.policy, ...narrow }",
    tests: ['test/security/fix-control-store.test.js'],
  },
  {
    what: 'an expired session leaves its placeholders live',
    file: 'src/store/vault.js',
    from: "if (p.sid === session.id && p.state === 'active') { p.state = 'dead'; p.dead_reason = 'session_ended' }",
    to: "if (false) {}",
    tests: ['test/security/fix-control-store.test.js'],
  },
  {
    what: 'booting a locked vault runs a full unlock',
    file: 'src/store/vault.js',
    from: "this.#openWith({ passphrase }, { unlock: !wasLocked })",
    to: "this.#openWith({ passphrase }, { unlock: true })",
    tests: ['test/security/fix-control-store.test.js'],
  },
  {
    what: 'a deleted audit log is re-created and re-anchored',
    file: 'src/store/audit.js',
    from: "    if (!existsSync(path)) writeFileSync(path, '', { mode: 0o600 })\n    this.#recover()",
    to: "    if (!existsSync(path)) writeFileSync(path, '', { mode: 0o600 })\n    else this.#recover()",
    tests: ['test/security/fix-control-audit.test.js'],
  },
  {
    what: 'an emptied log with no anchor ignores the anchored stamp',
    file: 'src/store/audit.js',
    from: "else if (!anchor && this.stamp?.anchored) this.anchorMissing",
    to: "else if (false) this.anchorMissing",
    tests: ['test/security/fix-control-audit.test.js'],
  },
  {
    what: 'an unreadable audit line throws out of unlock',
    file: 'src/store/audit.js',
    from: "return { unreadable: true, line: i + 1 }",
    to: "throw new Error('unreadable audit line')",
    tests: ['test/security/fix-control-audit.test.js'],
  },
  {
    what: 'a float in audit fields throws after the change is made',
    file: 'src/store/audit.js',
    from: 'const own = recordable(fields) ?? {}',
    to: 'const own = fields ?? {}',
    tests: ['test/security/fix-control-audit.test.js'],
  },
  {
    what: 'anyone with a request id collects its session',
    file: 'src/daemon/server.js',
    from: "if (!SessionRequests.mayCollect(record, url.searchParams.get('secret'))) {",
    to: "if (false) {",
    tests: ['test/security/fix-control-session-requests.test.js'],
  },
  {
    what: 'settled session requests count against the waiting-room cap',
    file: 'src/daemon/session-requests.js',
    from: ".filter((r) => r.state === 'pending').length\n    if (waiting >= MAX_PENDING)",
    to: ".length\n    if (waiting >= MAX_PENDING)",
    tests: ['test/security/fix-control-session-requests.test.js'],
  },
  {
    what: 'anonymous MCP handshakes are unbounded',
    file: 'src/daemon/mcp.js',
    from: "while (this.sessions.size >= MAX_MCP_SESSIONS) {",
    to: "while (false) {",
    tests: ['test/security/fix-control-session-requests.test.js'],
  },
  {
    what: 'the shared window can change presence factors',
    file: 'src/daemon/server.js',
    from: "  #requireFreshPresence(op, operation, presence) {\n",
    to: "  #requireFreshPresence(op, operation, presence) {\n    if (Date.now() < this.presenceGraceUntil) return\n",
    tests: ['test/security/fix-control-presence.test.js'],
  },
  {
    what: 'what the window admits is not recorded',
    file: 'src/daemon/server.js',
    from: "this.vault.audit?.write('presence.window_used', { op })",
    to: "void op",
    tests: ['test/security/fix-control-presence.test.js'],
  },
  {
    what: 'locking leaves the presence window open',
    file: 'src/daemon/server.js',
    from: "          this.presenceGraceUntil = 0\n          return json(200, { ok: true, locked: true })",
    to: "          return json(200, { ok: true, locked: true })",
    tests: ['test/security/fix-control-presence.test.js'],
  },
  {
    what: 'an assertion from an untrusted origin is accepted',
    file: 'src/daemon/server.js',
    from: "expectedOrigins: this.uiOrigins(),",
    to: "expectedOrigins: [...this.uiOrigins(), 'http://localhost:6666'],",
    tests: ['test/security/fix-control-presence.test.js'],
  },
  {
    what: 'env exports agent-planted state unquoted',
    file: 'src/cli/index.js',
    from: "const lines = vars.map(([k, v]) => `export ${k}=${shellQuote(v)}`)",
    to: "const lines = vars.map(([k, v]) => `export ${k}=${v}`)",
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    what: 'the state file accepts a token of any shape',
    file: 'src/client-state.js',
    from: "if (raw[field] !== undefined && !(typeof raw[field] === 'string' && shape.test(raw[field]))) delete raw[field]",
    to: "if (false) delete raw[field]",
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    what: 'exec passes real credentials to the child',
    file: 'src/cli/index.js',
    from: "if (!VAULT_GENERATED.includes(k) && !looksLikeCredential(k, v)) env[k] = v",
    to: "if (!VAULT_GENERATED.includes(k)) env[k] = v",
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    what: 'the stdio bridge stays on a dead launch token',
    file: 'src/cli/index.js',
    from: "if (res.status === 401 || res.headers.get('av-session-invalid')) {",
    to: "if (res.status === 401) {",
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    what: 'the page signs the raw narrowing text',
    file: 'src/ui/app.html',
    from: "const overrides = parseOverrides(typed)",
    to: "const overrides = typed",
    tests: ['test/security/fix-control-page.test.js'],
  },
  {
    what: 'the UI login cookie never slides',
    file: 'src/ui/server.js',
    from: "missing X-AV-UI header' })\n    this.#touch(res)",
    to: "missing X-AV-UI header' })",
    tests: ['test/security/fix-control-uicookie.test.js'],
  },
  {
    what: 'a fresh-presence change goes through on a vault with no factor',
    file: 'src/daemon/server.js',
    from: "    if (!factors.length) {\n      throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human factor",
    to: "    if (!factors.length) {\n      return\n      throw deny('AV_PRESENCE_REQUIRED', `${op} needs a human factor",
    tests: ['test/security/fix-control-presence.test.js'],
  },
  {
    // Fix-control round 2: parsing is not the same as being a record.
    what: 'a parseable line without the chain fields is taken as a record',
    file: 'src/store/audit.js',
    from: '        if (isRecord(row)) return row',
    to: "        if (row && typeof row === 'object') return row",
    tests: ['test/security/fix-control-audit.test.js'],
  },
  {
    // Fix-control round 2: closeAllConnections() cannot see a TLS handshake.
    what: 'listen rm leaves pre-handshake TLS sockets connected',
    file: 'src/daemon/server.js',
    from: '      for (const socket of sockets) socket.destroy()',
    to: '      for (const socket of []) socket.destroy()',
    tests: ['test/security/fix-control-listeners.test.js'],
  },
  {
    // Fix-control round 2: the prefix is not an allowlist.
    what: 'every AGENT_VAULT_* variable is exempt from the exec scrub',
    file: 'src/cli/index.js',
    from: '  if (VAULT_CONFIG.has(name)) return false',
    to: '  if (/^AGENT_VAULT/i.test(name)) return false',
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    what: 'a URL password with an empty user part is not a password',
    file: 'src/cli/index.js',
    from: '  return urlHasPassword(String(value))',
    to: '  return /:\\/\\/[^/\\s:@]+:[^/\\s@]+@/.test(String(value))',
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    what: 'exec inherits the variables it generates',
    file: 'src/cli/index.js',
    from: '      if (!VAULT_GENERATED.includes(k) && !looksLikeCredential(k, v)) env[k] = v',
    to: '      if (!looksLikeCredential(k, v)) env[k] = v',
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    what: 'env leaves an earlier placeholder in the shell',
    file: 'src/cli/index.js',
    // legacyEnv() is a function of its own now, one indent shallower.
    from: "  if (!st.placeholder) lines.push('unset AGENT_VAULT_PLACEHOLDER')",
    to: '',
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    // Fix-control round 2: a batch is not one call.
    what: 'the bridge resends a whole batch when one call in it was refused',
    file: 'src/cli/index.js',
    from: "  const redo = request.filter((m) => m && m.id !== undefined && m.id !== null && ids.has(key(m.id)))\n  if (!redo.length) return null\n  return {\n    line: JSON.stringify(redo),",
    to: "  const redo = request.filter((m) => m && m.id !== undefined && m.id !== null && ids.has(key(m.id)))\n  if (!redo.length) return null\n  return {\n    line,",
    tests: ['test/security/fix-control-cli.test.js'],
  },
  {
    // Fix-control round 2: a bound that skips used rows bounds nothing.
    what: 'only unused placeholders count towards rotation at max_active',
    file: 'src/store/vault.js',
    from: '    for (const p of active.slice(0, Math.max(0, active.length - maxActive + 1))) {',
    to: '    for (const p of active.filter((x) => x.uses === 0).slice(0, 1)) {',
    tests: ['test/security/fix-control-ledger.test.js'],
  },
  {
    what: 'a max_active that is not a number disables the live-row bound',
    file: 'src/store/vault.js',
    from: '    const maxActive = Number.isSafeInteger(phPolicy.max_active) && phPolicy.max_active >= 1 ? phPolicy.max_active : 8',
    to: '    const maxActive = phPolicy.max_active ?? 8',
    tests: ['test/security/fix-control-ledger.test.js'],
  },
  {
    what: "an explicit placeholder ttl replaces the grant's ttl ceiling",
    file: 'src/store/vault.js',
    from: '    const ttl = Math.min(positive(Number(ttlMs ?? NaN)), positive(Number(phPolicy.ttl) * 1000))',
    to: '    const ttl = ttlMs ?? positive(Number(phPolicy.ttl) * 1000)',
    tests: ['test/security/fix-control-ledger.test.js'],
  },
  {
    // Fix-control round 2: a quiet open needs a quiet close.
    what: 'every MCP transport close is audited, anonymous ones included',
    file: 'src/daemon/mcp.js',
    from: "    if (entry.recorded || record) this.vault.audit?.write('mcp.session_closed'",
    to: "    if (true) this.vault.audit?.write('mcp.session_closed'",
    tests: ['test/security/fix-control-session-requests.test.js'],
  },
  {
    // Fix-control round 2: a narrowing that DROPS constraints. The old
    // regression helper read an absent list as empty and let this through.
    what: 'narrowGrant drops the method, path and host lists it was asked to widen',
    file: 'src/store/vault.js',
    from: '    g.policy = policyMod.intersect([g.policy, narrow])',
    // Only when the narrowing names a host, as an attempted widening here
    // does and an ordinary narrowing does not, so the ordinary tests pass.
    to: '    g.policy = { ...policyMod.intersect([g.policy, narrow]), ...(narrow.hosts ? { methods: null, paths: null, hosts: null } : {}) }',
    tests: ['test/security/fix-control-store.test.js'],
  },
  {
    what: 'a forked grant drops the constraints its narrowing tried to widen',
    file: 'src/store/vault.js',
    from: '      policy: narrow && Object.keys(narrow).length ? policyMod.intersect([policy, narrow]) : policy,',
    to: '      policy: narrow && Object.keys(narrow).length ? { ...policyMod.intersect([policy, narrow]), ...(narrow.hosts ? { methods: undefined, paths: undefined, hosts: undefined } : {}) } : policy,',
    tests: ['test/security/fix-control-store.test.js'],
  },
  {
    // Fix-control round 3: review finding 5, option C. Without a passphrase
    // Touch ID unlock is refused, because nothing would recover the vault.
    what: 'Touch ID unlock is enrolled on a vault with no passphrase to recover it',
    file: 'src/store/vault.js',
    from: '    if (this.hasPassphrase) return\n',
    to: '    return\n',
    tests: ['test/security/fix-control-touchid.test.js'],
  },
  {
    // Round 4: the store's own enforcement of decision C is the factor
    // invariant, which addWebauthnUnlock and Vault.create both go through.
    what: 'the store wraps the vault key to Touch ID without checking for a recovery factor',
    file: 'src/store/vault.js',
    from: '    if (!hasPassphrase(prev)) throw recoveryRefusal()\n',
    to: '    if (!hasPassphrase(prev)) return\n',
    tests: ['test/security/fix-control-touchid.test.js', 'test/security/fix-control-factors.test.js'],
  },
  {
    what: 'the daemon asks for a tap before refusing Touch ID unlock without a passphrase',
    file: 'src/daemon/server.js',
    from: "          if (input.action !== 'remove') this.vault.requireRecoveryFactor()",
    to: "          if (false) this.vault.requireRecoveryFactor()",
    tests: ['test/security/fix-control-touchid.test.js'],
  },
  {
    what: 'the page asks for a tap on a vault with no passphrase instead of saying what to do',
    file: 'src/ui/app.html',
    from: '    if (!params.has_passphrase) throw new Error(TOUCHID_NEEDS_PASSPHRASE)',
    to: '    if (false) throw new Error(TOUCHID_NEEDS_PASSPHRASE)',
    tests: ['test/security/fix-control-page.test.js'],
  },
  {
    // Fix-control round 4: the factor invariant, checked in one place.
    what: 'factor changes commit without the factor invariant',
    file: 'src/store/vault.js',
    from: 'export function assertFactorInvariant(prev, next) {\n',
    to: 'export function assertFactorInvariant(prev, next) {\n  return\n',
    tests: ['test/security/fix-control-factors.test.js', 'test/core/passphrase.test.js'],
  },
  {
    what: "the vault's last human factor can be removed",
    file: 'src/store/vault.js',
    from: '  if (had.length && !humanFactors(next).length) {',
    to: '  if (false) {',
    tests: ['test/security/fix-control-factors.test.js'],
  },
  {
    what: 'a presence key that ES256 cannot verify is stored',
    file: 'src/store/vault.js',
    from: "  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {",
    to: '  if (false) {',
    tests: ['test/security/fix-control-factors.test.js'],
  },
  {
    what: 'the presence route stores whatever record it is sent',
    file: 'src/daemon/server.js',
    from: '          const { replaced } = this.vault.setPresenceKey(withoutProof(input))',
    to: '          this.vault.db.kv.webauthn = withoutProof(input); this.vault.save(); const replaced = existed',
    tests: ['test/security/fix-control-factors.test.js'],
  },
  {
    what: 'an approval that already ran can be decided again',
    file: 'src/daemon/pipeline.js',
    from: "if (approval.state !== 'pending') {",
    to: 'if (false) {',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: "a request carrying the hash marker's text literally collides with one carrying the placeholder",
    file: 'src/daemon/pipeline.js',
    from: "let out = String(value).split('<').join('<<')",
    to: 'let out = String(value)',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'the request hash sorts the values of a repeated header',
    file: 'src/core/canon.js',
    from: '(a[0] === b[0] ? 0 :',
    to: '(a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) :',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'a method-override header escapes the methods allowlist',
    file: 'src/daemon/pipeline.js',
    from: 'if (effective.methods && !effective.methods.includes(m)) {',
    to: 'if (false) {',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'a method-override header escapes the approval rule',
    file: 'src/daemon/pipeline.js',
    from: '[decision.method, ...overrides].some(',
    to: '[decision.method].some(',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'a pre-connect failure refunds only the last placeholder',
    file: 'src/daemon/pipeline.js',
    from: 'for (const row of consumed) this.vault.refundPlaceholder(row.id)',
    to: 'for (const row of consumed.slice(-1)) this.vault.refundPlaceholder(row.id)',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'a spent approval with nothing to replay holds its resend forever',
    file: 'src/daemon/pipeline.js',
    from: "if (!existing.executed_at) return { status: 'pending', approval: existing }",
    to: "return { status: 'pending', approval: existing }",
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'a secret in a response header name reaches the agent',
    file: 'src/daemon/pipeline.js',
    from: 'if (scrubber.scrub(lower).redactions || scrubber.containsIgnoringCase(lower)) {',
    to: 'if (false) {',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a case-folded secret in a response header name reaches the agent',
    file: 'src/daemon/pipeline.js',
    from: '|| scrubber.containsIgnoringCase(lower)) {',
    to: ') {',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a secret split across one JSON field of two events is not reassembled',
    file: 'src/daemon/pipeline.js',
    from: "return data.length > 0 ? leakedByPath(data.join('\\n')) : null",
    to: 'return null',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event stream is framed on LF only',
    file: 'src/daemon/pipeline.js',
    from: "return t.replace(/\\r\\n?/g, '\\n')",
    to: 'return t',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event that never ends is held without bound',
    file: 'src/daemon/pipeline.js',
    from: 'if (pending.length > MAX_EVENT_BYTES) {',
    to: 'if (false) {',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a compressed event stream is bounded per chunk only',
    file: 'src/daemon/pipeline.js',
    from: 'if (total > maxBytes) {',
    to: 'if (false) {',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: "an event stream's source is piped without its errors",
    file: 'src/daemon/pipeline.js',
    from: 'const source = streamPipeline(res.res, decoder, () => {})',
    to: 'const source = res.res.pipe(decoder)',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a failing event stream throws at the response writer',
    file: 'src/daemon/pipeline.js',
    from: "  } catch {\n    // The upstream failed part way.",
    to: "  } catch (e) { throw e\n    // The upstream failed part way.",
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a request body goes upstream without a Content-Length',
    file: 'src/daemon/pipeline.js',
    from: "if (outgoing.body) headers['content-length'] = String(outgoing.body.length)",
    to: '',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a forged placeholder touches the session it names',
    file: 'src/daemon/pipeline.js',
    from: 'if (!ph.verify(this.vault.kPh, carrier.parsed)) {',
    to: 'if (false) {',
    tests: ['test/security/gateway-routing.test.js'],
  },
  {
    what: '/t/https/ to an http credential goes out in the clear',
    file: 'src/daemon/pipeline.js',
    from: "const useScheme = scheme === 'https' ? 'https' : credScheme",
    to: 'const useScheme = credScheme',
    tests: ['test/security/gateway-routing.test.js'],
  },
  {
    what: 'the scrubber reads only the fixed needles, not decoded or unwrapped text',
    file: 'src/core/scrub.js',
    from: 'const { spans, unscannable } = this.collectSpans(out)',
    to: 'const spans = [], unscannable = false',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'uppercase hex of a secret is not a needle',
    file: 'src/core/scrub.js',
    from: 'out.add(hex.toUpperCase())',
    to: '',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'a derived token straddling the stream cut is emitted in halves',
    file: 'src/core/scrub.js',
    from: 'if (end >= cut) { cut = m.index; break }',
    to: 'if (false) break',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'an escaped secret straddling the stream cut is scrubbed in halves',
    file: 'src/core/scrub.js',
    from: 'if (start < cut && end > cut) cut = end',
    to: '',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'a backslash encoded twice passes the separator check',
    file: 'src/core/policy.js',
    from: '|| /%2f|%5c|\\\\/i.test(p)) {',
    to: ') {',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'intersecting two rates compares their counts whatever the units',
    file: 'src/core/policy.js',
    from: '  const ar = a.count / units[a[key]], br = b.count / units[b[key]]',
    to: '  const ar = a.count, br = b.count',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'Basic substitution writes the first Authorization header by name',
    file: 'src/core/substitute.js',
    from: "const indexed = Number.isInteger(at) && out.headers[at] && out.headers[at][0].toLowerCase() === 'authorization'",
    to: 'const indexed = false',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'a placeholder left in the outgoing request after substitution is not looked for',
    file: 'src/core/substitute.js',
    from: 'return locate(req).occurrences.find((o) => wanted.has(o.parsed.nonce)) ?? null',
    to: 'return null',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'a JSON string literal the parse does not expose is not searched for placeholders',
    file: 'src/core/substitute.js',
    from: '    if (live) continue\n',
    to: '    continue\n',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'a form placeholder with an encoded character is decoded and re-encoded with its whole value',
    file: 'src/core/substitute.js',
    from: 'return [k, replaceEncoded(v, placeholderText, encodeURIComponent(secret)), eq]',
    to: 'return [k, v.includes(placeholderText) ? v.split(placeholderText).join(encodeURIComponent(secret)) : encodeURIComponent(detect.percentDecode(v).split(placeholderText).join(secret)), eq]',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'wrapped base64 is joined up only when its first line is 16 or longer',
    file: 'src/core/scrub.js',
    from: 'for (const run of wrappedRuns(text, BLOB_CHAR)) {',
    to: 'for (const run of [...wrappedRuns(text, BLOB_CHAR)].filter((r) => /^[A-Za-z0-9+/=_-]{16}/.test(r.text))) {',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'mixed-case hex on one line is not folded before it is searched',
    file: 'src/core/scrub.js',
    from: 'folded({ index: m.index, text: text.slice(m.index, end) })',
    to: 'void end',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'mixed-case hex wrapped over lines is not folded before it is searched',
    file: 'src/core/scrub.js',
    from: '        folded(run)\n',
    to: '\n',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'an event-stream path run is trimmed before the new value is searched',
    file: 'src/daemon/pipeline.js',
    from: 'const r = scrubber.scrub(run)',
    to: 'const r = scrubber.scrub(run.slice(-keep))',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'the joined event-stream view is trimmed before the new event is searched',
    file: 'src/daemon/pipeline.js',
    from: 'const reason = leaked(joined)',
    to: 'const reason = leaked(assembled)',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event stream past the key-path limit forgets the oldest path and carries on',
    file: 'src/daemon/pipeline.js',
    from: "const room = (key) => (runs.has(key) || runs.size < MAX_SSE_PATHS ? null : 'too_many_paths')",
    to: 'const room = (key) => { if (!runs.has(key) && runs.size >= MAX_SSE_PATHS) runs.delete(runs.keys().next().value); return null }',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a buffered upstream reset mid-body escapes as an internal error',
    file: 'src/daemon/pipeline.js',
    from: "      if (e instanceof VaultError) throw e\n      throw deny('AV_UPSTREAM_UNREACHABLE', `${decision.host} failed while sending its response",
    to: "      throw e\n      throw deny('AV_UPSTREAM_UNREACHABLE', `${decision.host} failed while sending its response",
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'the placeholder in a Basic header is not made stable for the request hash',
    file: 'src/daemon/pipeline.js',
    from: "return `${basic[1]}${Buffer.from(stable(decoded), 'utf8').toString('base64')}${basic[3]}`",
    to: 'return stable(value)',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'a Basic header that does not encode back to itself shares an approval with one that does',
    file: 'src/daemon/pipeline.js',
    from: "if (Buffer.from(decoded, 'utf8').toString('base64') === basic[2]) {",
    to: 'if (true) {',
    tests: ['test/security/gateway-approvals.test.js'],
  },
  {
    what: 'an event-stream key path is the keys joined with a dot, so a dotted key names another path',
    file: 'src/daemon/pipeline.js',
    from: 'yield { gathering: JSON.stringify(path), indexes, appended }',
    to: "yield { gathering: path.join('.'), indexes, appended }",
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event-stream array index is the same path segment as a key spelled like it',
    file: 'src/daemon/pipeline.js',
    from: 'yield* jsonStringsByPath(value[i], [...path, i], indexes)',
    to: 'yield* jsonStringsByPath(value[i], [...path, String(i)], indexes)',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'a path whose escape was itself encoded is sent instead of refused',
    file: 'src/core/policy.js',
    from: 'if (/%(?:[0-9a-f]{2}|u[0-9a-f]{4})/i.test(p)) {',
    to: 'if (false) {',
    tests: ['test/security/gateway-core.test.js', 'test/security/path-parsing.test.js'],
  },
  {
    what: 'an encoded %u escape, which IIS decodes, is not treated as an escape',
    file: 'src/core/policy.js',
    from: '/%(?:[0-9a-f]{2}|u[0-9a-f]{4})/i',
    to: '/%(?:[0-9a-f]{2})/i',
    tests: ['test/security/gateway-core.test.js'],
  },
  {
    what: 'an event-stream value is gathered by key path only, not by the indexes a client groups it by',
    file: 'src/daemon/pipeline.js',
    from: 'choices = choices.flatMap((c) => [c, ...values.map((v) => [...c, [depth, key, v]])])',
    to: 'choices = choices.flatMap((c) => [c])',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event-stream value is gathered by all of its indexes at once, so a decoy index splits the run',
    file: 'src/daemon/pipeline.js',
    from: 'choices = choices.flatMap((c) => [c, ...values.map((v) => [...c, [depth, key, v]])])',
    to: 'choices = choices.flatMap((c) => values.map((v) => [...c, [depth, key, v]]))',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event payload with NaN or Infinity, which Python reads, is not reassembled by path',
    file: 'src/daemon/pipeline.js',
    from: "try { return JSON.parse(swapped + payload.slice(from)) } catch { return undefined }",
    to: 'return undefined',
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event-stream value under more index fields than are combined is passed instead of cut',
    file: 'src/daemon/pipeline.js',
    from: "if (slots.length > MAX_SSE_INDEXES) return 'too_many_indexes'",
    to: "if (false) return 'too_many_indexes'",
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'an event-stream array element is gathered by its position only, not wherever its index puts it',
    file: 'src/daemon/pipeline.js',
    from: '    yield { gathering: JSON.stringify(path.map((s) => (typeof s === \'number\' ? null : s))), indexes, appended }\n',
    to: '',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'a content block\'s starting text is not gathered with the deltas that continue it',
    file: 'src/daemon/pipeline.js',
    from: '    yield { gathering: `#${continued}`, indexes: [...own, ...positions], appended: true }',
    to: '',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'a Responses item\'s content position is not read as its content_index',
    file: 'src/daemon/pipeline.js',
    from: 'indexes: [...own, ...positions], appended: true }',
    to: 'indexes, appended: true }',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'an index field missing from one event is not read as zero or as a group of its own',
    file: 'src/daemon/pipeline.js',
    from: 'if (!indexes.some(([d, k]) => d === depth && k === key)) slots.push([depth, key, MISSING])',
    to: 'if (false) slots.push([depth, key, MISSING])',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'a missing index that came before the field was first seen is not filed with it',
    file: 'src/daemon/pipeline.js',
    from: 'runs.set(to, runs.get(from))',
    to: "runs.set(to, '')",
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'a missing index field is read as zero only, never as a group of its own',
    file: 'src/daemon/pipeline.js',
    from: 'const MISSING = [0, null]',
    to: 'const MISSING = [0]',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'an index written as a string is not also read as its number',
    file: 'src/daemon/pipeline.js',
    from: "const valuesOf = (v) => (typeof v === 'string' && /^(?:0|[1-9][0-9]{0,15})$/.test(v) ? [v, Number(v)] : [v])",
    to: 'const valuesOf = (v) => [v]',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    // A false positive: an ordinary Responses url_citation event was cut.
    what: 'an annotation\'s character offsets are counted as index fields',
    file: 'src/daemon/pipeline.js',
    from: 'const INDEX_FIELD = /^(?:index|(?!start_|end_).+_index)$/',
    to: 'const INDEX_FIELD = /^(?:index|.+_index)$/',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'the decoded view leaves JSON\'s two-character escapes such as \\/ as they are',
    file: 'src/core/scrub.js',
    from: '|\\\\(["\\\\/bfnrt])/g',
    to: '/g',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'the decoded view is searched for the secret only, not its base64, so percent-encoded base64 passes',
    file: 'src/core/scrub.js',
    from: 'this.decoded = [...this.plain, ...this.blobs]',
    to: 'this.decoded = [...this.plain]',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    // Nesting one encoding inside another (base64 in percent in a JSON string)
    // is caught only because the scrubber peels more than one layer. Held to a
    // single layer, every stacked encoding reaches the agent.
    what: 'the response scrubber peels only one layer, so nested encodings leak',
    file: 'src/core/scrub.js',
    from: 'const DECODE_DEPTH = 3',
    to: 'const DECODE_DEPTH = 1',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    // A body the layered decoder could not finish within budget must be
    // refused, not forwarded part-scanned. Ignoring the flag passes those
    // bytes through unread.
    what: 'a response too nested to finish scanning is forwarded instead of refused',
    file: 'src/daemon/pipeline.js',
    from: 'if (scrubbedBody.unscannable) {',
    to: 'if (false) {',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  // ---- wave 2, requested: R1 (elevated sessions) -----------------------------
  {
    // Contract 0.4: unreadable means elevated, whatever the approval mode.
    what: 'elevationOf reads an unreadable methods or routes list as ordinary unless it says auto',
    file: 'src/daemon/session-requests.js',
    from: 'grants.some((g) => !readable(g) || (g.approval === \'auto\' && permitsWrite(g)))',
    to: 'grants.some((g) => (g.approval === \'auto\' && permitsWrite(g)))',
    tests: ['test/security/requested-r1.test.js'],
  },
  {
    // `granted: "false"` is truthy and approved an ordinary request.
    what: 'the single decide route takes any truthy verdict',
    file: 'src/daemon/server.js',
    // The comment pins it to this route: the approvals route has the same check.
    from: "// Before the gate, which reads the verdict to decide what to ask for.\n          if (typeof input.granted !== 'boolean') {",
    to: '// Before the gate, which reads the verdict to decide what to ask for.\n          if (false) {',
    tests: ['test/security/requested-r1.test.js'],
  },
  {
    // `input.granted !== false` approved a held request on "false", 0 or null.
    what: 'the approvals route takes any verdict that is not literally false',
    file: 'src/daemon/server.js',
    from: "// reads the verdict to name the operation it asks a human for.\n          if (typeof input.granted !== 'boolean') {",
    to: '// reads the verdict to name the operation it asks a human for.\n          if (false) {',
    tests: ['test/security/approval-verdict.test.js'],
  },
  {
    // One function decides elevation for create, decide and decide-many. If it
    // calls everything ordinary, the window lets an agent make auto-writes.
    what: 'elevationOf calls every session ordinary, so auto with writes rides the window',
    file: 'src/daemon/session-requests.js',
    from: 'export function elevationOf(spec) {',
    to: 'export function elevationOf(spec) { return []',
    tests: ['test/security/requested-r1.test.js', 'test/security/control-gate.test.js'],
  },
  {
    // The fresh level exists because a window admits every caller on the
    // socket. Accepting it makes the elevated gate the widening one.
    what: 'the fresh presence gate accepts the shared passphrase window',
    file: 'src/daemon/server.js',
    from: '  #requireFreshPresence(op, operation, presence) {',
    to: '  #requireFreshPresence(op, operation, presence) {\n    if (Date.now() < this.presenceGraceUntil) return',
    tests: ['test/security/requested-r1.test.js', 'test/security/control-gate.test.js'],
  },
  {
    what: 'POST /v1/sessions gates an elevated body as ordinary widening',
    file: 'src/daemon/server.js',
    from: "this.#gateSession('session create', this.#wideningOperation(route, url, input), plan.elevated, input.presence)",
    to: "this.#gateSession('session create', this.#wideningOperation(route, url, input), [], input.presence)",
    tests: ['test/security/requested-r1.test.js', 'test/security/control-gate.test.js'],
  },
  {
    what: 'approving a session request into auto with writes needs only the window',
    file: 'src/daemon/server.js',
    from: '            input.granted ? elevationOf(final) : [],',
    to: '            [],',
    tests: ['test/security/requested-r1.test.js', 'test/security/control-gate.test.js'],
  },
  {
    what: 'a bulk decision with an elevated item needs only the window',
    file: 'src/daemon/server.js',
    from: "            elevated ? ['approval_auto_writes'] : [],",
    to: '            [],',
    tests: ['test/security/requested-r1.test.js', 'test/security/control-gate.test.js'],
  },
  {
    // An agent that could ask for approval: auto gets it the moment a human
    // clicks approve without reading closely.
    what: 'a session request may carry an owner-only field',
    file: 'src/daemon/server.js',
    // Re-anchored in wave 3: the check moved into proposeSessionRequest, which
    // the route and vault_request_session share.
    from: '    if (owned.length) {',
    to: '          if (false) {',
    tests: ['test/security/requested-r1.test.js'],
  },
  {
    // needsApproval falls through to false, so a mode nobody knows meant auto.
    what: 'an unknown approval mode is stored instead of refused',
    file: 'src/daemon/server.js',
    from: 'if (spec.approval != null && !APPROVAL_MODES.includes(spec.approval)) {',
    to: 'if (false) {',
    tests: ['test/security/requested-r1.test.js'],
  },
  // ---- wave 2, requested: R2 (env files) --------------------------------------
  {
    // Without O_EXCL an existing .env is opened and written over.
    what: 'the env file writer opens an existing file instead of refusing it',
    file: 'src/cli/files.js',
    from: 'fd = openSync(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)',
    to: 'fd = openSync(path, O_WRONLY | O_CREAT | O_NOFOLLOW, mode)',
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    // The umask only removes bits; without fchmod a 0277 umask leaves 0400 and
    // a permissive one is never tightened on a replaced file.
    what: 'the env file mode is left to the umask',
    file: 'src/cli/files.js',
    from: '  fchmodSync(fd, mode)',
    to: '  void fchmodSync',
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    // --force through a symlink would replace the link and report success.
    what: 'force replaces a symlink or someone else\'s file',
    file: 'src/cli/files.js',
    from: "if (!st.isFile() || st.uid !== process.getuid()) throw problem('ENOTREGULAR'",
    to: "if (false) throw problem('ENOTREGULAR'",
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    // The second line of defence: whatever the batch answers, only a
    // placeholder for this session and credential reaches the file or child.
    what: 'env and exec write whatever the batch answered, unchecked',
    file: 'src/cli/index.js',
    from: '    assertPlaceholderOnly(entries, { sid, port, slugs })',
    to: '    void assertPlaceholderOnly',
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    // The temporary name can be swapped for a symlink between close and
    // rename; without the check the link lands and success is reported.
    what: 'force does not check that what the rename put in place is the file it wrote',
    file: 'src/cli/files.js',
    from: '  if (!isFile(path, written)) {',
    to: '  if (false) {',
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    // open() never changes the mode of a file that exists, and the umask can leave 0400.
    what: 'an appended file keeps whatever mode it had',
    file: 'src/cli/files.js',
    from: '    fchmodSync(fd, 0o600)',
    to: '    void fchmodSync',
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    what: 'the final check accepts a placeholder for another session',
    file: 'src/cli/files.js',
    from: "parsed?.text === v && parsed.sid === sid && parsed.slug === e.cred",
    to: "parsed?.text === v && parsed.slug === e.cred",
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    // #route picks a grant by credential, so two grants for one would be ambiguous.
    what: 'a multi-grant session may name one credential twice',
    file: 'src/daemon/server.js',
    from: '      if (seen.has(spec.cred)) throw shape(`credential ${spec.cred} appears twice`)',
    to: '      if (false) throw shape(`credential ${spec.cred} appears twice`)',
    tests: ['test/security/requested-r2.test.js'],
  },
  {
    // Each placeholder is a fresh authorization to spend a credential.
    what: 'the placeholder batch is issued with no human',
    file: 'src/daemon/server.js',
    from: "          this.#requireHumanForWidening('placeholder issue', this.#wideningOperation(route, url, input), input.presence)\n          if (this.vault.locked) throw deny('AV_LOCKED', 'the vault is locked')",
    to: "          if (this.vault.locked) throw deny('AV_LOCKED', 'the vault is locked')",
    tests: ['test/security/requested-r2.test.js', 'test/security/control-gate.test.js'],
  },
  // ---- wave 2, requested: R3 (infinite sessions) ------------------------------
  {
    // A capability that never ends must not be reachable from the network.
    // Checked before the gate, so it is refused before anyone is asked.
    what: 'the daemon lets an infinite session be remote',
    file: 'src/daemon/server.js',
    from: '    if (infinite && remote) {',
    to: '    if (false) {',
    tests: ['test/security/requested-r3.test.js'],
  },
  {
    // NaN became a RangeError, 0 the default, and a negative number a session
    // born expired.
    what: 'ttl_hours is not required to be a positive number',
    file: 'src/daemon/server.js',
    from: "      if (typeof input.ttl_hours !== 'number' || !Number.isFinite(input.ttl_hours) || !(input.ttl_hours > 0)) {",
    to: '      if (false) {',
    tests: ['test/security/requested-r3.test.js'],
  },
  // ---- wave 2, requested: C3 (the elevation reaches the audit log) ----------
  {
    // The daemon decides the elevation and the store records it. Dropping it
    // here makes every session.created say [] while the gate still ran fresh.
    what: 'the daemon does not hand a session its elevation',
    file: 'src/daemon/server.js',
    from: 'infinite: plan.infinite, elevated: plan.elevated,',
    to: 'infinite: plan.infinite, elevated: [],',
    tests: ['test/security/requested-c3.test.js'],
  },
  {
    // The store refuses the grant as well, but only after the gate has asked
    // for a passphrase and a session.created has been written and revoked.
    what: 'a session for a quarantined credential is planned and gated',
    file: 'src/daemon/server.js',
    // Re-anchored in wave 3: only saving a template skips the check.
    from: '      if (cred.quarantine && !savingTemplate) throw quarantined(cred)',
    to: '      if (false) throw quarantined(cred)',
    tests: ['test/security/requested-seams.test.js'],
  },
  {
    // The store refuses one placeholder at a time, so a quarantined second
    // item would leave the first one issued.
    what: 'a placeholder batch resolves a quarantined credential',
    file: 'src/daemon/server.js',
    from: '            if (cred.quarantine) throw quarantined(cred)\n            const grant = grants.find',
    to: '            if (false) throw quarantined(cred)\n            const grant = grants.find',
    tests: ['test/security/requested-r2.test.js'],
  },
  // ---- store slice A (R3, F6, F10, F15, F16, F18, C3) ----
  {
    // R3 mutation 1: a null expiry read as "never" without asking whether the
    // session is infinite. A legacy or corrupted row then lives forever.
    what: 'sessionExpiryMs treats any null expiry as infinite',
    file: 'src/store/vault.js',
    from: 'return s.infinite === true && s.expires_at === null ? Infinity : -Infinity',
    to: 'return Infinity',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // `Date.parse('garbage')` is NaN, and `NaN <= now` is false.
    what: 'an unparseable expiry is NaN instead of already past',
    file: 'src/store/vault.js',
    from: '  return Number.isNaN(ms) ? -Infinity : ms\n}',
    to: '  return ms\n}',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // R3 mutation 2.
    what: 'an infinite session may be remote',
    file: 'src/store/vault.js',
    from: '    if (infinite && remote) {',
    to: '    if (false) {',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: 'a session lifetime that is not a positive number is accepted',
    file: 'src/store/vault.js',
    from: "if (ttlMs !== null && (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0)) {\n      throw deny('AV_POLICY_DENIED', 'a session lifetime must be a positive number', { rule: 'ttl' })",
    to: "if (false) {\n      throw deny('AV_POLICY_DENIED', 'a session lifetime must be a positive number', { rule: 'ttl' })",
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // C3: the audit record would carry whatever the caller put there.
    what: 'an unrecognised elevation is recorded instead of refused',
    file: 'src/store/vault.js',
    from: 'if (!Array.isArray(elevated) || elevated.length > ELEVATIONS.size || !elevated.every((e) => ELEVATIONS.has(e))) {',
    to: 'if (false) {',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // F18's own mutation: the test uses a placeholder minted before the end.
    what: 'consumePlaceholder does not ask whether the grant has ended',
    file: 'src/store/vault.js',
    from: '    const grant = this.assertGrantLive(this.db.grants[row.grant_id])\n',
    to: '    const grant = this.db.grants[row.grant_id]\n',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: "assertGrantLive never notices a grant's lifetime",
    file: 'src/store/vault.js',
    from: '    if (!(expiryMs(grant.expires_at) > Date.now())) {',
    to: '    if (false) {',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: 'a grant lifetime is not clamped to its session',
    file: 'src/store/vault.js',
    from: 'new Date(Math.min(Date.now() + ttlMs, sessionExpiryMs(session))).toISOString()',
    to: 'new Date(Date.now() + ttlMs).toISOString()',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // `used + NaN > limit` is false forever: no budget at all.
    what: 'chargeGrant takes any n, NaN included',
    file: 'src/store/vault.js',
    from: '    if (!Number.isSafeInteger(n) || n < 1) return false\n',
    to: '',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: 'chargeGrant charges past the budget',
    file: 'src/store/vault.js',
    from: '    if (limit === null || used + n > limit) return false',
    to: '    if (limit === null) return false',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // Fail-open: a budget nobody can read becomes no budget.
    what: 'an unreadable grant budget means no limit',
    file: 'src/store/vault.js',
    from: '  return policyMod.budgetLimit(policy?.budget)\n',
    to: '  return policyMod.budgetLimit(policy?.budget) ?? Infinity\n',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // F10's own mutation: caught by the flood test.
    what: 'cred.health_recorded is written on every observation',
    file: 'src/store/vault.js',
    from: 'if (health.status !== before.status || health.observed_expires_at !== (before.observed_expires_at ?? null)) {',
    to: 'if (true) {',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: 'a credential expiry that is not a date is stored',
    file: 'src/store/vault.js',
    from: '    if (expires === undefined) {\n      throw deny',
    to: '    if (false) {\n      throw deny',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: 'a quarantined credential still issues placeholders',
    file: 'src/store/vault.js',
    from: "    if (!grant.fields.includes(fieldName)) throw deny('AV_NO_GRANT', `grant does not cover field ${fieldName}`)\n    if (cred.quarantine) throw quarantined(cred)\n",
    to: "    if (!grant.fields.includes(fieldName)) throw deny('AV_NO_GRANT', `grant does not cover field ${fieldName}`)\n",
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: 'a tripwire rule set is stored without being checked',
    file: 'src/store/vault.js',
    from: "      if (problem) throw deny('AV_POLICY_DENIED', problem, { rule: 'tripwire_rule' })",
    to: '      if (false) throw new Error(problem)',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // F15: "shorten" that can lengthen is an extension anyone can ask for.
    what: 'shortening can push an end later',
    file: 'src/store/vault.js',
    from: '  const at = Math.min(current, now + ttlMs)',
    to: '  const at = now + ttlMs',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // 0.6: a grant that never stated redirects follows none.
    what: 'a narrow may raise redirects above zero',
    file: 'src/store/vault.js',
    from: "    if (Object.hasOwn(narrow, 'redirects') && narrow.redirects?.max !== 0) {",
    to: '    if (false) {',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    // The durability guard is itself a protection: a revocation a power cut
    // forgets is access a human took away coming back.
    what: 'a revocation is written without an fsync',
    file: 'src/store/vault.js',
    from: "    this.#persist()\n    this.audit.write('session.revoked', { session_id: sid, reason })",
    to: "    this.#persist({ durable: false })\n    this.audit.write('session.revoked', { session_id: sid, reason })",
    tests: ['test/core/passphrase.test.js'],
  },
  // ---- store F4: scrub-pattern CRUD ----
  {
    // A pattern is shown to whoever lists credentials: with a secret in it,
    // the listing publishes the secret.
    what: 'a scrub pattern may contain a stored credential value',
    file: 'src/store/vault.js',
    from: "      if (secret && source.includes(secret)) throw refuse('it contains a stored credential value')",
    to: '      if (false) throw refuse(secret)',
    tests: ['test/security/store-scrub.test.js'],
  },
  {
    what: 'a scrub pattern may contain a placeholder',
    file: 'src/store/vault.js',
    from: "    if (ph.findAll(source).length) throw refuse('it contains a placeholder')\n",
    to: '',
    tests: ['test/security/store-scrub.test.js'],
  },
  {
    what: 'a credential takes any number of scrub patterns',
    file: 'src/store/vault.js',
    from: '    if (mine.length >= MAX_SCRUB_PER_CRED) throw refuse',
    to: '    if (false) throw refuse',
    tests: ['test/security/store-scrub.test.js'],
  },
  {
    // 0.7: the source is not recorded, only its digest.
    what: 'the scrub pattern source is written to the audit log',
    file: 'src/store/vault.js',
    from: "      credential_slug: cred.slug, pattern_id: pattern.id,\n",
    to: "      credential_slug: cred.slug, pattern_id: pattern.id, source,\n",
    tests: ['test/security/store-scrub.test.js'],
  },
  // ---- store F7: rotation ----
  {
    // F7 mutation 1: an upstream echoing the old token reaches the agent.
    what: 'allSecrets skips the retired values',
    file: 'src/store/vault.js',
    from: '        for (const r of f.retired || []) {',
    to: '        for (const r of []) {',
    tests: ['test/security/store-rotate.test.js'],
  },
  {
    what: 'revoke-mode rotation leaves the grants live',
    file: 'src/store/vault.js',
    from: "    if (mode === 'revoke') {\n      for (const g of Object.values(this.db.grants)) {",
    to: "    if (false) {\n      for (const g of Object.values(this.db.grants)) {",
    tests: ['test/security/store-rotate.test.js'],
  },
  {
    // Checked after the grants were revoked, a bad expiry left a half-done
    // rotation: grants gone, value unchanged.
    what: 'rotation does not check the expiry before it changes anything',
    file: 'src/store/vault.js',
    from: "    if (expires === undefined) throw deny('AV_POLICY_DENIED', 'expires_at must be an ISO date, or null', { rule: 'expires_at' })\n",
    to: '',
    tests: ['test/security/store-rotate.test.js'],
  },
  {
    what: 'rotating to the same value is accepted',
    file: 'src/store/vault.js',
    from: '    if (crypt.constantTimeEqual(current, value)) {',
    to: '    if (false) {',
    tests: ['test/security/store-rotate.test.js'],
  },
  // ---- store F14: sealed webhook ----
  {
    // F14 mutation 2: the URL is a bearer credential.
    what: 'the webhook URL is stored unsealed beside its sealed copy',
    file: 'src/store/vault.js',
    from: '    this.db.kv.notify = { sealed, host: parsed.host, detail,',
    to: '    this.db.kv.notify = { sealed, url, host: parsed.host, detail,',
    tests: ['test/security/store-notify.test.js'],
  },
  {
    what: 'the webhook URL is audited whole instead of by host',
    file: 'src/store/vault.js',
    from: "    this.audit.write('notify.configured', { host: parsed.host, detail })",
    to: "    this.audit.write('notify.configured', { host: url, detail })",
    tests: ['test/security/store-notify.test.js'],
  },
  {
    what: 'a plaintext http webhook to another machine is accepted',
    file: 'src/store/vault.js',
    from: "    if (!(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && loopback))) throw refuse",
    to: '    if (false) throw refuse',
    tests: ['test/security/store-notify.test.js'],
  },
  {
    what: 'a webhook URL with userinfo is accepted',
    file: 'src/store/vault.js',
    from: '    if (parsed.username || parsed.password) throw refuse',
    to: '    if (false) throw refuse',
    tests: ['test/security/store-notify.test.js'],
  },
  // ---- store F17: templates ----
  {
    // The hash is what a human's signature binds; over raw JSON text it
    // depends on key order, and the CLI and the daemon would disagree.
    what: 'the template hash is taken over the JSON text, not the canonical form',
    file: 'src/store/vault.js',
    from: '      hash: createHash(\'sha256\').update(canonicalOperation(stored)).digest(\'hex\'),',
    to: '      hash: createHash(\'sha256\').update(text).digest(\'hex\'),',
    tests: ['test/security/store-templates.test.js'],
  },
  {
    what: 'a template spec may carry template, template_hash or presence',
    file: 'src/store/vault.js',
    from: "      if (Object.hasOwn(spec, k)) throw deny('AV_POLICY_DENIED', `a template spec cannot carry ${k}`",
    to: "      if (false) throw deny('AV_POLICY_DENIED', `a template spec cannot carry ${k}`",
    tests: ['test/security/store-templates.test.js'],
  },
  {
    what: 'a template spec of any size is stored',
    file: 'src/store/vault.js',
    from: '    if (Buffer.byteLength(text) > MAX_TEMPLATE_BYTES) {',
    to: '    if (false) {',
    tests: ['test/security/store-templates.test.js'],
  },
  // ---- store F9: audit export and witness; C10 ----
  {
    // F9's own mutation.
    what: 'a witness ahead of the log is treated as ok',
    file: 'src/store/audit.js',
    from: '    out.ok = !out.forged.length && !out.ahead.length && !out.mismatched.length',
    to: '    out.ok = !out.forged.length && !out.mismatched.length',
    tests: ['test/security/store-audit-witness.test.js'],
  },
  {
    what: 'a witness past the last record is not reported ahead',
    file: 'src/store/audit.js',
    from: '      } else if (c.seq > last) {',
    to: '      } else if (false) {',
    tests: ['test/security/store-audit-witness.test.js'],
  },
  {
    what: "a witness checkpoint's MAC is not checked",
    file: 'src/store/audit.js',
    from: "      if (!shaped || !timingSafeEqual(Buffer.from(c.mac, 'hex'), Buffer.from(this.#witnessMac(c.vault_id, c.seq, c.head, c.ts), 'hex'))) {",
    to: '      if (!shaped) {',
    tests: ['test/security/store-audit-witness.test.js'],
  },
  {
    // C10: `seq` from a caller rewrote the record's place in the chain.
    what: 'a caller may set a chain field in an audit record',
    file: 'src/store/audit.js',
    from: '    if (reserved) throw deny(',
    to: '    if (false) throw deny(',
    tests: ['test/security/store-audit-witness.test.js'],
  },
  // ---- store F8: backup and restore ----
  {
    // F8 mutation 2: a restore must give no capability back.
    what: 'the backup plaintext includes the sessions',
    file: 'src/store/backup.js',
    from: "  const bytes = Buffer.from(JSON.stringify({ credentials, templates }), 'utf8')",
    to: "  const bytes = Buffer.from(JSON.stringify({ credentials, templates, sessions: vault.db.sessions }), 'utf8')",
    tests: ['test/security/store-backup.test.js'],
  },
  {
    what: 'a bundle that carries more than credentials and templates is read anyway',
    file: 'src/store/backup.js',
    from: "  if (!plainObject(plain) || !onlyKeys(plain, new Set(['credentials', 'templates'])) ||",
    to: '  if (!plainObject(plain) ||',
    tests: ['test/security/store-backup.test.js'],
  },
  {
    what: 'the backup is written to the audit log, not just its digest',
    file: 'src/store/backup.js',
    from: "  vault.audit.write('backup.exported', { credentials: credentials.length, templates: templates.length, bundle_sha256: digest })",
    to: "  vault.audit.write('backup.exported', { credentials: credentials.length, templates: templates.length, bundle_sha256: digest, bundle })",
    tests: ['test/security/store-backup.test.js'],
  },
  {
    // A work factor of 2^17 on the event loop stalls the whole gateway.
    what: 'the backup key is derived synchronously',
    file: 'src/store/backup.js',
    from: '  return crypt.scryptAsync(recoveryPassphrase, salt, { ...BACKUP_KDF, keylen: 32, maxmem: MAXMEM })',
    to: '  return Promise.resolve(crypt.passphraseFactor(recoveryPassphrase, salt))',
    tests: ['test/security/store-backup.test.js'],
  },
  {
    what: 'a fail-mode restore with a conflict writes what it can',
    file: 'src/store/backup.js',
    from: "      if (onConflict === 'fail') throw refused(",
    to: "      if (false) throw refused(",
    tests: ['test/security/store-backup.test.js'],
  },
  {
    // Pins that setPins would refuse are refused by a restore too, never
    // stored or dropped. (Re-anchored in integrate-2: the restore stores pins
    // now, so the old "cannot restore pins yet" refusal is gone.)
    what: "a restore goes ahead when it cannot restore a bundle's pins",
    file: 'src/store/vault.js',
    from: '        cred.pins = { ...pinTableOf(cred.pins, key), [key]: pinList(list) }',
    to: '        cred.pins = { ...pinTableOf(cred.pins, key), [key]: list }',
    tests: ['test/security/store-pins.test.js'],
  },
  // ---- store F19: activity ----
  {
    // F19's own mutation.
    what: "a denial's detail is copied into the activity",
    file: 'src/store/activity.js',
    from: '      const d = denials.get(key) ?? { code, rule, count: 0 }',
    to: '      const d = denials.get(key) ?? { code, rule, count: 0, detail: r.detail }',
    tests: ['test/security/store-activity.test.js'],
  },
  {
    // Missing records are not zero activity.
    what: 'a log that starts after the session is reported complete',
    file: 'src/store/activity.js',
    from: "  const note = anomaly ?? (created ? null : 'the audit log starts after this session was created, so its early activity is not in it')",
    to: '  const note = anomaly',
    tests: ['test/security/store-activity.test.js'],
  },
  {
    what: 'a truncated or unanchored log is reported complete',
    file: 'src/store/activity.js',
    from: '  const hit = rows.find((r) => ANOMALIES.has(r.kind))',
    to: '  const hit = null',
    tests: ['test/security/store-activity.test.js'],
  },
  {
    what: 'a placeholder in a recorded path is repeated in the activity',
    file: 'src/store/activity.js',
    from: "  for (const hit of ph.findAll(out).reverse()) out = `${out.slice(0, hit.offset)}[[av:placeholder]]${out.slice(hit.end)}`\n",
    to: '',
    tests: ['test/security/store-activity.test.js'],
  },
  {
    // A held write counted as a use hides it from unused_methods. This is
    // the inference for logs written before the gateway marked holds.
    what: 'a request held for approval counts as a use',
    file: 'src/store/activity.js',
    from: "  return (r) => r.decision === 'held' || ids.has(r.request_id) || (r.req?.status === 202 && r.req?.path == null)",
    to: "  return (r) => r.decision === 'held'",
    tests: ['test/security/store-activity.test.js'],
  },
  // ---- store: coordinator conditions on the slice B review ----
  {
    // A placeholder is bounded by its session's ceiling, so an idle-expired
    // session's placeholder is still in date: only the session check stops it.
    what: 'consumePlaceholder does not ask whether the session is still live',
    file: 'src/store/vault.js',
    from: '    this.assertSessionLive(this.db.sessions[row.sid])\n',
    to: '',
    tests: ['test/security/store-slice-a.test.js'],
  },
  {
    what: "a row the gateway marks as held is counted as a use",
    file: 'src/store/activity.js',
    from: "  return (r) => r.decision === 'held' || ids.has(r.request_id)",
    to: '  return (r) => ids.has(r.request_id)',
    tests: ['test/security/store-activity.test.js'],
  },
  // ---- store: round-2 review of the wave-2 store ----
  {
    // Finding 1: a pattern the restore did not check stopped it halfway.
    what: "a restore does not check a credential's scrub patterns before it writes",
    file: 'src/store/vault.js',
    from: '      for (const p of patterns) this.#checkScrubSource(p?.source, secrets)\n',
    to: '',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: 'a restore whose write fails keeps its credentials in memory',
    file: 'src/store/vault.js',
    from: '      for (const cred of staged) delete this.db.credentials[cred.id]\n',
    to: '',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: 'a restore writes each credential as it goes',
    file: 'src/store/vault.js',
    from: '    for (const cred of staged) this.db.credentials[cred.id] = cred\n',
    to: '    for (const cred of staged) { this.db.credentials[cred.id] = cred; this.#persist() }\n',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: "a restore the vault refuses is not recorded as a refusal",
    file: 'src/store/backup.js',
    from: '  try { out = vault.restoreEntries({ credentials: plan, templates: plain.templates }) } catch (e) { throw refused(e) }',
    to: '  out = vault.restoreEntries({ credentials: plan, templates: plain.templates })',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    // Finding 2.
    what: 'touchSession extends a session that has ended',
    file: 'src/store/vault.js',
    from: "    if (!session || session.state !== 'active' || !(sessionExpiryMs(session) > now)) return false\n",
    to: '    if (!session) return false\n',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: 'a session marked ended is live again once its date is later',
    file: 'src/store/vault.js',
    from: "    if (session.state !== 'active') throw deny('AV_SESSION_EXPIRED', `session ${session.id} has ended`)\n",
    to: '',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: 'touchSession extends past the ceiling',
    file: 'src/store/vault.js',
    from: '      const extended = Math.min(now + session.idle_timeout_ms, sessionCeilingMs(session))',
    to: '      const extended = now + session.idle_timeout_ms',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    // Finding 3.
    what: 'a quarantined credential is consumed through a placeholder issued before it',
    file: 'src/store/vault.js',
    from: '    if (cred.quarantine) throw quarantined(cred)\n    if (!(rowExpiryMs(row) > Date.now())) {',
    to: '    if (!(rowExpiryMs(row) > Date.now())) {',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: 'a quarantined credential is revealed',
    file: 'src/store/vault.js',
    from: '    if (cred.quarantine) throw quarantined(cred)\n    return this.#unseal(cred, fieldName)',
    to: '    return this.#unseal(cred, fieldName)',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    // Finding 4.
    what: 'a budget of 0 issues a placeholder',
    file: 'src/store/vault.js',
    from: '    if (limit === 0) throw budgetSpent(limit)\n',
    to: '',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: 'consume does not re-check the grant budget',
    file: 'src/store/vault.js',
    from: '    if (limit === null || !Number.isSafeInteger(grant.budget_used) || grant.budget_used + 1 > limit) throw budgetSpent(limit)\n',
    to: '',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    what: "consume does not re-check a placeholder ceiling narrowed after issue",
    file: 'src/store/vault.js',
    from: '    if (Number.isFinite(phMax) && row.uses >= phMax) {',
    to: '    if (false) {',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    // Finding 5.
    what: 'a rotation is written without an fsync',
    file: 'src/store/vault.js',
    from: '    this.#persist()\n    const rotated = {',
    to: '    this.#persist({ durable: false })\n    const rotated = {',
    tests: ['test/core/passphrase.test.js'],
  },
  {
    what: 'a restore is written without an fsync',
    file: 'src/store/vault.js',
    from: '    try {\n      this.#persist()\n    } catch {',
    to: '    try {\n      this.#persist({ durable: false })\n    } catch {',
    tests: ['test/core/passphrase.test.js'],
  },
  {
    // A writer the lists do not name: the classification test must see it.
    what: 'a vault writer is on neither durability list',
    file: 'src/store/vault.js',
    from: '  removeScrubPattern(slug, patternId) {',
    to: '  dropScrubPattern(slug, patternId) {',
    tests: ['test/core/passphrase.test.js'],
  },
  {
    // Finding 6.
    what: "a forked grant drops the lifetime of the grant it copies",
    file: 'src/store/vault.js',
    from: '      this.createGrant({ sessionId: session.id, credentialId: g.credential_id, fields: g.fields, policy: g.policy, narrow, ttlMs })',
    to: '      this.createGrant({ sessionId: session.id, credentialId: g.credential_id, fields: g.fields, policy: g.policy, narrow })',
    tests: ['test/security/store-review-r2.test.js'],
  },
  {
    // Round 3 (a): a restore must never release a quarantine.
    what: "a backup leaves out each credential's quarantine",
    file: 'src/store/vault.js',
    from: '      quarantine: c.quarantine ? structuredClone(c.quarantine) : null,',
    to: '      quarantine: null,',
    tests: ['test/security/store-review-r3.test.js'],
  },
  {
    // Round 3 (b).
    what: "a restore drops the bundle's quarantine instead of re-applying it",
    file: 'src/store/vault.js',
    from: '      if (c.quarantine != null) cred.quarantine = restoredQuarantine(c.quarantine, format)',
    to: '      if (c.quarantine != null) restoredQuarantine(c.quarantine, format)',
    tests: ['test/security/store-review-r3.test.js'],
  },
  {
    // Round 3 (c).
    what: "a restore releases the copy of a credential this vault holds quarantined",
    file: 'src/store/vault.js',
    from: '        if (held) cred.quarantine = structuredClone(held)',
    to: '        if (held) void held',
    tests: ['test/security/store-review-r3.test.js'],
  },
  {
    // Round 3 (c): a renamed copy holds the restore too.
    what: "only the exact slug holds a restore, not a renamed copy of it",
    file: 'src/store/vault.js',
    from: '  return a === b || copyOf(a, b) || copyOf(b, a)',
    to: '  return a === b',
    tests: ['test/security/store-review-r3.test.js'],
  },
  {
    // An unparseable provider date is not an expiry. Keeping the raw text
    // would store whatever the upstream sent as observed_expires_at.
    what: 'an unparseable expiry header is kept as the observed expiry',
    file: 'src/connectors/profiles.js',
    from: 'if (iso) out.observed_expires_at = iso',
    to: 'out.observed_expires_at = iso || String(rawExpiry).trim()',
    tests: ['test/security/connectors-health.test.js'],
  },
  {
    // Node flushes the request, headers and all, once the handshake has
    // completed. Ending before the pin comparison delivers the secret.
    what: 'the request is ended before the certificate pin is checked',
    file: 'src/connectors/pinning.js',
    from: 'const verdict = pinVerdict(socket, identity, pinList)',
    to: 'req.end(body); const verdict = pinVerdict(socket, identity, pinList)',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // The bytes go to the URL host, so that is the name a certificate must
    // carry. Taking the name from the Host header (and so no longer refusing
    // one that differs) let a certificate for the header's name, chaining to
    // a pinned intermediate or root, receive the secret. With the refusal in
    // place a Host header can only name the URL host, so both go together.
    what: 'the certificate identity check reads the Host header',
    file: 'src/connectors/pinning.js',
    from: 'const identity = urlIdentity(parsed)\n    if (!hostHeaderValues(sent).every((v) => hostHeaderMatches(v, parsed))) {',
    to: "const identity = String(hostHeaderValues(sent)[0] || urlIdentity(parsed)).replace(/:\\d+$/, '')\n    if (false) {",
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'a Host header naming another host is sent instead of refused',
    file: 'src/connectors/pinning.js',
    from: 'if (!hostHeaderValues(sent).every((v) => hostHeaderMatches(v, parsed))) {',
    to: 'if (false) {',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'any Host header value passes as the URL host',
    file: 'src/connectors/pinning.js',
    from: "return parsed.port === '' && !!defaultPort",
    to: "return true || parsed.port === '' && !!defaultPort",
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'a Host header under another spelling of the name is not checked',
    file: 'src/connectors/pinning.js',
    from: "filter((name) => name.toLowerCase() === 'host')",
    to: "filter((name) => name === 'host')",
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // Only an exact leaf pin stands in for CA trust. Treating every pinned
    // handshake as verified lets an intermediate or root pin accept a chain
    // nothing trusts, or a certificate for another name.
    what: 'a pinned request treats an unverified chain as verified',
    file: 'src/connectors/pinning.js',
    from: '  if (socket.authorized) {\n    const wrongName',
    to: '  if (true) {\n    const wrongName',
    tests: ['test/security/connectors-pinning.test.js', 'test/security/connectors-probe.test.js'],
  },
  {
    // The leaf's key is the one the handshake proves. A pin on any other
    // certificate in the chain, even one whose signature checks, must still
    // wait for the chain to verify to a trusted root.
    what: 'a pin on a non-leaf certificate stands in for CA trust',
    file: 'src/connectors/pinning.js',
    from: 'const leafPinned = leafPin !== null && pinList.includes(leafPin)',
    to: 'const leafPinned = verifiedChainPins(socket).some((p) => pinList.includes(p))',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'a pin on any presented certificate stands in for CA trust',
    file: 'src/connectors/pinning.js',
    from: 'const leafPinned = leafPin !== null && pinList.includes(leafPin)',
    to: 'const leafPinned = chainPins(socket).some((p) => pinList.includes(p))',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // With the chain unverified Node never ran the name check. Skipping it
    // here lets a pinned leaf for one host answer for another.
    what: 'a pinned leaf skips the host name check',
    file: 'src/connectors/pinning.js',
    from: 'if (nameError) return nameError',
    to: 'if (false) return nameError',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'an expired pinned leaf is accepted',
    file: 'src/connectors/pinning.js',
    from: "if (!(now <= Date.parse(leafX509.validTo))) return",
    to: "if (false) return",
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'a pinned leaf that is not yet valid is accepted',
    file: 'src/connectors/pinning.js',
    from: "if (!(now >= Date.parse(leafX509.validFrom))) return",
    to: "if (false) return",
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // Node links issuers by name and key identifier only. Without the
    // signature check, a forged leaf borrows a real intermediate's pin.
    what: 'an issuer satisfies a pin without having signed the certificate below it',
    file: 'src/connectors/pinning.js',
    from: 'signed = child.checkIssued(x509) && child.verify(x509.publicKey)',
    to: 'signed = child.checkIssued(x509)',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'a pins value that is not an array is read as no pins',
    file: 'src/connectors/pinning.js',
    from: "if (!Array.isArray(pins)) return 'invalid'",
    to: "if (!Array.isArray(pins)) return 'none'",
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    what: 'a pin list with a malformed entry is used anyway',
    file: 'src/connectors/pinning.js',
    from: "return pins.every((p) => typeof p === 'string' && PIN_RE.test(p)) ? 'pinned' : 'invalid'",
    to: "return 'pinned'",
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // The Host check reads a copy of the headers. Handing Node the caller's
    // object instead lets a getter or a Proxy answer the check with the URL
    // host and Node with another, and the secret goes out under that Host.
    what: 'pinnedRequest gives Node the caller\'s headers, not the copy it checked',
    file: 'src/connectors/pinning.js',
    from: '      method,\n      headers: sent,\n    }',
    to: '      method,\n      headers,\n    }',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // parsed.hostname keeps IPv6 brackets, and Node looks '[::1]' up as a
    // name. Every IPv6 request failed with ENOTFOUND.
    what: 'pinnedRequest connects to the bracketed IPv6 host',
    file: 'src/connectors/pinning.js',
    from: '    const opts = {\n      hostname: identity,',
    to: '    const opts = {\n      hostname: parsed.hostname,',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // A pin key written as a bare IPv6 address names the same host as the
    // bracketed URL host, and must not be skipped.
    what: 'probe pin keys that are a bare IPv6 address are not read as a host',
    file: 'src/connectors/pinning.js',
    from: "const host = isIP(bare) === 6 ? `[${bare}]` : hostOnly(key)",
    to: 'const host = hostOnly(key)',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    // With no pins, verification has to stay exactly what Node already does.
    // Turning it off would accept any certificate for an unpinned host.
    what: 'a request with no pins skips certificate verification',
    file: 'src/connectors/pinning.js',
    from: '// Certificate verification stays at Node\'s default.\n      const req = open(opts, onResponse)',
    to: 'opts.rejectUnauthorized = false\n      const req = open(opts, onResponse)',
    tests: ['test/security/connectors-pinning.test.js'],
  },
  {
    // Pins belong to the host the secret is written to. Looking them up by
    // the declared spelling missed a key written the way the URL reads it,
    // and the probe went out unpinned.
    what: 'probe pins are looked up by the declared host, not the URL host',
    file: 'src/connectors/probe.js',
    from: 'const pins = pinsFor(cred, urlIdentity(new URL(url)))',
    to: 'const pins = pinsFor(cred, destination.host)',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    // The probe target is the profile constant. A path on the call would aim
    // the credential at whatever the caller asked for.
    what: 'the probe takes its path from the request input',
    file: 'src/connectors/probe.js',
    from: 'const probePath = probe.path',
    to: 'const probePath = path || probe.path',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'the probe takes its method from the request input',
    file: 'src/connectors/probe.js',
    from: 'method: probeMethod,',
    to: 'method: method || probeMethod,',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'the probe sends a body supplied by the caller',
    file: 'src/connectors/probe.js',
    from: 'body: requestBody,',
    to: 'body: body || requestBody,',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'a second probe inside a minute is sent anyway',
    file: 'src/connectors/probe.js',
    from: 'if (Number.isInteger(prev) && now - prev < PROBE_WINDOW_MS) {',
    to: 'if (false && Number.isInteger(prev) && now - prev < PROBE_WINDOW_MS) {',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    // A route that spreads its body into runProbe would hand the caller the
    // throttle's clock: skip the window, or lock the credential out.
    what: 'the probe throttle reads a time supplied on the call',
    file: 'src/connectors/probe.js',
    from: 'takeProbeSlot(cred.id, probeClock.now())',
    to: 'takeProbeSlot(cred.id, arguments[0]?.now ?? probeClock.now())',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'a probe body past the drain bound is left open',
    file: 'src/connectors/probe.js',
    from: 'if (cut) {\n        try { stream.destroy?.() } catch { /* already gone */ }',
    to: 'if (false) {\n        try { stream.destroy?.() } catch { /* already gone */ }',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'a probe body that never ends holds the probe open',
    file: 'src/connectors/probe.js',
    from: 'const timer = setTimeout(() => finish(true), DRAIN_TIMEOUT_MS)',
    to: 'const timer = null',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'a recordHealth failure is swallowed',
    file: 'src/connectors/probe.js',
    from: "// upstream already answered and is not \"unreachable\".\n      throw scrubThrown(e, scrubber)",
    to: "// upstream already answered and is not \"unreachable\".\n      void e",
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'a probe pin entry of the wrong shape is skipped',
    file: 'src/connectors/pinning.js',
    from: 'if (!Array.isArray(value)) return false',
    to: 'if (!Array.isArray(value)) continue',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'an expiry offset outside +-14:00 is applied',
    file: 'src/connectors/profiles.js',
    from: 'if (hours > 14 || minutes > 59 || (hours === 14 && minutes > 0)) return null',
    to: 'if (false) return null',
    tests: ['test/security/connectors-health.test.js'],
  },
  {
    // Scopes are copied off a response header. Without the scrub, a header
    // that echoes the secret is returned and stored on the health record.
    what: 'probe scopes are returned without scrubbing the credential',
    file: 'src/connectors/probe.js',
    from: 'const scopes = scrubList(extracted?.scopes, scrubber)',
    to: 'const scopes = extracted?.scopes ?? null',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'the probe result includes the credential value',
    file: 'src/connectors/probe.js',
    from: 'observed_expires_at: observed,\n      checked_at,\n    }',
    to: 'observed_expires_at: observed,\n      checked_at,\n      secret,\n    }',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'a probe host that is not a hostname is used anyway',
    file: 'src/connectors/probe.js',
    from: 'const parts = splitHostPort(declared)\n  if (!parts) {\n    throw deny(\'AV_POLICY_DENIED\', \'host is outside what this credential permits\', { rule: \'credential_host\' })\n  }',
    to: 'const parts = splitHostPort(declared)\n  if (false) {\n    throw deny(\'AV_POLICY_DENIED\', \'host is outside what this credential permits\', { rule: \'credential_host\' })\n  }',
    tests: ['test/security/connectors-probe.test.js'],
  },
  {
    what: 'a probe accepts a scheme other than http or https',
    file: 'src/connectors/probe.js',
    from: "if (scheme !== 'https' && scheme !== 'http') {",
    to: "if (false && scheme !== 'https' && scheme !== 'http') {",
    tests: ['test/security/connectors-probe.test.js'],
  },
  // ------------------------------------------------- wave 2, gateway batch
  {
    // R1: a mode nobody knows is the strictest one, never auto.
    what: 'an unknown approval mode needs no approval',
    file: 'src/core/policy.js',
    from: "    case 'each': return true\n    default: return true",
    to: "    case 'each': return true\n    default: return false",
    tests: ['test/core/policy.test.js', 'test/security/gateway-w2-policy.test.js'],
  },
  {
    // 0.6: a child can only narrow. Taking the inner layer's value is the
    // widening the property test exists to catch.
    what: 'intersecting max_concurrent takes the inner layer instead of the minimum',
    file: 'src/core/policy.js',
    from: '  return minNum(a, b)\n}\nexport function budgetInteger',
    to: '  return b ?? a\n}\nexport function budgetInteger',
    tests: ['test/core/policy.test.js'],
  },
  {
    what: 'intersecting two rates takes the inner layer',
    file: 'src/core/policy.js',
    from: "function intersectRate(a, b) {\n  return intersectWindow(a, b, PER_MS, 'per', 1_000_000)",
    to: 'function intersectRate(a, b) {\n  return b ?? a',
    tests: ['test/core/policy.test.js', 'test/security/gateway-core.test.js'],
  },
  {
    what: 'intersecting two spend limits takes the inner layer',
    file: 'src/core/policy.js',
    from: "  return Object.fromEntries(['tokens', 'usd_micros'].filter((k) => a[k] != null || b[k] != null).map((k) => [k, minNum(a[k], b[k])]))",
    to: '  return b',
    tests: ['test/core/policy.test.js'],
  },
  {
    // F1: a concurrency slot is released however the request ends.
    what: 'a concurrency slot is released only when the upstream answered',
    file: 'src/daemon/pipeline.js',
    from: '      if (!streaming) resources.release?.()',
    to: '      if (!streaming && upstreamOpened) resources.release?.()',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'the rolling quota admits a request that would take it past the limit',
    file: 'src/daemon/pipeline.js',
    from: 'if (enforce && estimate + 1 > effective.quota.count)',
    to: 'if (enforce && estimate > effective.quota.count)',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // F2: every operation in the document, not only the first or the named one.
    what: 'a GraphQL document is judged by its first operation only',
    file: 'src/core/payload.js',
    from: "    if (!rules.operations.includes(op)) fail('payload:graphql:operation')",
    to: "    if (!operations && !rules.operations.includes(op)) fail('payload:graphql:operation')",
    tests: ['test/security/gateway-w2-payload.test.js'],
  },
  {
    what: 'a duplicate JSON key is read last-wins instead of refused',
    file: 'src/core/payload.js',
    from: "          if (own(out,k)) fail('payload_duplicate_key')",
    to: "          if (false) fail('payload_duplicate_key')",
    tests: ['test/security/gateway-w2-payload.test.js'],
  },
  {
    what: 'only the last payload rule-set is enforced',
    file: 'src/core/payload.js',
    from: '  for (const set of sets) {\n    // A repeated name',
    to: '  for (const set of sets.slice(-1)) {\n    // A repeated name',
    tests: ['test/security/gateway-w2-payload.test.js'],
  },
  {
    // F3: every inherited route set must allow the request.
    what: 'a request allowed by any one route set passes the others',
    file: 'src/core/policy.js',
    from: "    if (!pair) throw deny('AV_POLICY_DENIED', 'request is outside the allowed routes', {",
    to: "    if (!pair && (policy.route_sets ?? []).some((s) => s.some((x) => x.methods.includes(m) && x.paths.some((g) => matchPath(g, p))))) continue\n    if (!pair) throw deny('AV_POLICY_DENIED', 'request is outside the allowed routes', {",
    tests: ['test/security/gateway-w2-policy.test.js', 'test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a route pair matches the method from one pair and the path from another',
    file: 'src/core/policy.js',
    from: '    const pair = set.find((pair) => pair.methods.includes(m) && pair.paths.some((glob) => matchPath(glob, p)))',
    to: '    const pair = set.some((x) => x.methods.includes(m)) && set.some((x) => x.paths.some((glob) => matchPath(glob, p))) ? { paths: set.flatMap((x) => x.paths) } : null',
    tests: ['test/security/gateway-w2-policy.test.js'],
  },
  {
    // F4 (C5, revised): only literals may follow the variable quantifier.
    // With this rule in place a second variable quantifier is refused by it
    // too, so the one-variable rule has no separate entry: it cannot fail
    // on its own.
    what: 'a scrub pattern may put classes after its variable quantifier, which backtracks for seconds',
    file: 'src/core/scrub.js',
    from: "      if (afterVariable && (!literal || quantified)) bad('only literal characters may follow the variable quantifier')",
    to: '',
    tests: ['test/security/gateway-w2-scrub.test.js'],
  },
  {
    what: 'a scrub pattern branch may match more than 512 characters',
    file: 'src/core/scrub.js',
    from: "    if (length > 512) bad('a branch can match more than 512 characters')",
    to: '',
    tests: ['test/security/gateway-w2-scrub.test.js'],
  },
  {
    what: 'the stream scrubber holds back less than an extra pattern can match',
    file: 'src/core/scrub.js',
    from: '        const keep = Math.min(Math.max(self.overlap, self.extraHold), combined.length)',
    to: '        const keep = Math.min(self.overlap, combined.length)',
    tests: ['test/security/gateway-w2-scrub.test.js'],
  },
  {
    what: 'the stream scrubber cuts through an extra-pattern match instead of moving past it',
    file: 'src/core/scrub.js',
    from: '        for (const { re } of self.extraPatterns) {\n          re.lastIndex = 0',
    to: '        for (const { re } of []) {\n          re.lastIndex = 0',
    tests: ['test/security/gateway-w2-scrub.test.js'],
  },
  {
    what: 'a stored scrub pattern that no longer compiles is skipped instead of withholding the response',
    file: 'src/daemon/pipeline.js',
    from: "          throw deny('AV_UNSCANNABLE', 'a stored scrub pattern is invalid', { rule: 'scrub_pattern_invalid' })",
    to: '          continue',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // F5: missing usage is charged in full, never as free.
    what: 'a call with no usage report is charged nothing',
    file: 'src/core/model-usage.js',
    from: '  if (!usage || !count(usage.input_tokens) || !count(usage.output_tokens)) return { ...reservation }',
    to: '  if (!usage || !count(usage.input_tokens) || !count(usage.output_tokens)) return { tokens: 0, usd_micros: 0 }',
    tests: ['test/security/gateway-w2-pipeline.test.js', 'test/security/gateway-w2-model.test.js'],
  },
  {
    what: 'the spend check ignores what calls in flight have reserved',
    file: 'src/daemon/pipeline.js',
    from: '      const committed = state[`${key}_used`] + reserved',
    to: '      const committed = state[`${key}_used`]',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // F6: a hop is a request, and policy decides where it may go.
    what: 'a redirect hop is followed without checking the grant',
    file: 'src/daemon/pipeline.js',
    from: '        try { hop = policyMod.evaluateHttp(effective, { method: hopView.method, host: next.hostname, path: next.pathname }) }',
    to: '        try { hop = { host: next.hostname, path: next.pathname, method } }',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'redirects are followed for every method',
    file: 'src/daemon/pipeline.js',
    from: "      const asked = [decision.method, ...overrides, method]",
    to: '      const asked = [method]',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a redirect may choose another port on an allowed host',
    file: 'src/daemon/pipeline.js',
    from: "        if (next.port !== credPort) reason = 'host'",
    to: '',
    tests: ['test/security/gateway-w2-seams.test.js'],
  },
  {
    // F13: the human reads the preview; the scrub is what makes that safe.
    what: 'an approval preview is not scrubbed',
    file: 'src/daemon/pipeline.js',
    from: "      scrub: (text) => { const r = scrubber.scrub(text); return r.unscannable ? '[withheld: unscannable]' : r.text },",
    to: '      scrub: (text) => text,',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'the agent-facing approval status carries the preview',
    file: 'src/daemon/pipeline.js',
    from: '        request_hash: approval.request_hash,\n        created_at',
    to: '        request_hash: approval.request_hash, preview: approval.preview,\n        created_at',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // F16: only authenticated denials count.
    what: 'a tripwire counts a denial against the session its placeholder names, before authentication',
    file: 'src/daemon/pipeline.js',
    from: '        await this.tripwires.observe({ sessionId: session?.id ?? null,',
    to: '        await this.tripwires.observe({ sessionId: session?.id ?? sub.locate(req).occurrences[0]?.parsed?.sid ?? null,',
    tests: ['test/security/gateway-w2-seams.test.js'],
  },
  {
    what: 'a quarantined credential is not refused before its use is spent',
    file: 'src/daemon/pipeline.js',
    from: "      stage('quarantine')\n      this.#checkQuarantine(cred)\n      stage('grant')\n      const grant",
    to: "      stage('grant')\n      const grant",
    tests: ['test/security/gateway-w2-seams.test.js', 'test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // F18: the grant's own lifetime is checked before anything happens.
    what: 'the gateway does not ask the store whether the grant is still live',
    file: 'src/daemon/pipeline.js',
    from: '      if (peek) this.#peekGrant(grant)\n      else this.vault.assertGrantLive(grant)',
    to: '      if (peek) this.#peekGrant(grant)',
    tests: ['test/security/gateway-w2-pipeline.test.js', 'test/security/gateway-w2-seams.test.js'],
  },
  {
    // F20: a preflight spends nothing and touches nothing.
    what: 'preflight extends the session it is asked about',
    file: 'src/daemon/pipeline.js',
    from: '      if (touch) this.vault.touchSession(session)\n      return session\n    }\n\n    // Placeholder-as-carrier',
    to: '      this.vault.touchSession(session)\n      return session\n    }\n\n    // Placeholder-as-carrier',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'preflight creates the approval it predicts',
    file: 'src/daemon/pipeline.js',
    from: '    if (preflight) {\n      const held = this.approvals.get(requestHash)',
    to: '    if (preflight && false) {\n      const held = this.approvals.get(requestHash)',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a preflight denial is fed to the tripwires',
    file: 'src/daemon/pipeline.js',
    from: "      code = err.code; rule = err.rule ?? null; would = 'deny'",
    to: "      code = err.code; rule = err.rule ?? null; would = 'deny'; this.tripwires.observe({ sessionId: session.id, credentialId: route?.cred?.id ?? null, code, rule })",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a method-override header is not held to the route pairs',
    file: 'src/daemon/pipeline.js',
    from: '    policyMod.evaluateHttp({ ...effective, methods: null }, { method: m, host, path })',
    to: '',
    tests: ['test/security/gateway-w2-seams.test.js'],
  },
  {
    // C11: a held request says so in the record, rather than looking allowed.
    what: 'a request held for approval is recorded as allowed',
    file: 'src/daemon/pipeline.js',
    from: "        decision: result.headers?.['av-decision'] === 'pending' ? 'held' : 'allow',",
    to: "        decision: 'allow',",
    tests: ['test/security/gateway-w2-seams.test.js'],
  },
  {
    // Round 2: a redirect hop is a body-less GET, held to every payload rule.
    what: 'a redirect hop skips the GraphQL rules',
    file: 'src/daemon/pipeline.js',
    from: "        try { evaluatePayload(effective.payload_sets, { ...hopView, path: hop.path }) } catch { reason = 'path' }",
    to: "        try { evaluatePayload(effective.payload_sets?.map(({ graphql, ...rest }) => rest), { ...hopView, path: hop.path }) } catch { reason = 'path' }",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a redirect hop silently drops the body rules',
    file: 'src/daemon/pipeline.js',
    from: "        try { evaluatePayload(effective.payload_sets, { ...hopView, path: hop.path }) } catch { reason = 'path' }",
    to: "        try { evaluatePayload(effective.payload_sets?.map(({ json, form, ...rest }) => rest), { ...hopView, path: hop.path }) } catch { reason = 'path' }",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // Round 2: one value per single-valued header, read and sent.
    what: 'a single-valued header sent twice with different values is let through',
    file: 'src/daemon/pipeline.js',
    from: '    if (differs) {',
    to: '    if (false) {',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a request is checked on headers that were never folded',
    file: 'src/daemon/pipeline.js',
    from: '      req = { ...req, headers: foldHeaders(req.headers) }\n      session = this.#authenticate(req)',
    to: '      session = this.#authenticate(req)',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'preflight reads headers that were never folded',
    file: 'src/daemon/pipeline.js',
    from: '    req = { ...req, headers: foldHeaders(req.headers) }\n    session = this.#authenticate(req, { touch: false })',
    to: '    session = this.#authenticate(req, { touch: false })',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'two header keys differing only in case reach the client, and the last one wins',
    file: 'src/daemon/pipeline.js',
    from: '      if (key === undefined) { spelled.set(lower, n); headers[n] = v } else headers[key] = [headers[key], v].flat()',
    to: '      headers[n] = v',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // Round 2: the query rules read only what the URL will carry.
    what: 'a query the URL would cut at # or rewrite is checked as written',
    file: 'src/core/request-view.js',
    from: '    unsendable: /[#\\t\\n\\r]|[\\x00-\\x20]$/.test(q),',
    to: '    unsendable: false,',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },  {
    // Round 3: a redirect hop sends only what it was checked as.
    what: 'a request a method override made a DELETE has its redirect followed',
    file: 'src/daemon/pipeline.js',
    from: '      const asked = [decision.method, ...overrides, method]',
    to: '      const asked = [decision.method, method]',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a redirect hop copies the request\'s headers, method overrides included',
    file: 'src/daemon/pipeline.js',
    from: '      if (HOP_FORWARDED.has(lower) || credentialHeaders.has(lower)) out[name] = value',
    to: "      if (!['content-type', 'content-length'].includes(lower)) out[name] = value",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a redirect hop sends a body or framing header a credential is declared at',
    file: 'src/daemon/pipeline.js',
    from: '      if (HOP_NEVER.has(lower)) continue',
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a redirect hop follows a Location carrying a method-override field',
    file: 'src/daemon/pipeline.js',
    from: "        try { checkOverrides(effective, hopView, { host: hop.host, path: hop.path }) } catch { reason = 'path' }",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a 307 or 308 hop is sent as a GET whatever the request was',
    file: 'src/daemon/pipeline.js',
    from: "      const method = [307, 308].includes(res.status) || decision.method === 'HEAD' ? decision.method : 'GET'",
    to: "      const method = 'GET'",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // Round 4: an override in a field, and the headers a hop keeps.
    what: 'a method-override field naming another method is let through',
    file: 'src/daemon/pipeline.js',
    from: '    if (String(value).toUpperCase() !== view.method) {',
    to: '    if (false) {',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a method-override field in the query is not read',
    file: 'src/core/request-view.js',
    from: '  read(bothReadings(query))\n',
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a method-override field in a form body is not read',
    file: 'src/core/request-view.js',
    from: "  if (mediaType === 'application/x-www-form-urlencoded') read(bothReadings(text))",
    to: '  if (false) read(bothReadings(text))',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a method-override field in a multipart body is not read',
    file: 'src/core/request-view.js',
    from: "  else if (mediaType === 'multipart/form-data') {",
    to: '  else if (false) {',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a method-override field in a JSON body is not read',
    file: 'src/core/request-view.js',
    from: '  } else if (/[/+]json$/.test(mediaType)) {',
    to: '  } else if (false) {',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: "a JSON body's repeated _method is read as its last copy only",
    file: 'src/core/request-view.js',
    from: 'for (const [k, v] of topLevelJsonFields(text, isOverrideField))',
    to: 'for (const [k, v] of Object.entries(parsed))',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a method-override field name is not folded as PHP and Rack read it',
    file: 'src/core/request-view.js',
    from: "    const n = base.toLowerCase().replace(/[ .-]/g, '_')",
    to: '    const n = base.toLowerCase()',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a hop drops the API-version headers a provider needs',
    file: 'src/daemon/pipeline.js',
    from: "  'anthropic-version', 'anthropic-beta', 'openai-beta', 'openai-organization', 'openai-project',\n  'x-api-version', 'api-version', 'x-github-api-version',\n",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: "a hop forwards the agent's cookie and forwarding headers",
    file: 'src/daemon/pipeline.js',
    from: "  'accept', 'user-agent', 'accept-language',",
    to: "  'cookie', 'x-forwarded-for', 'x-forwarded-host', 'accept', 'user-agent', 'accept-language',",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // Round 5: one view of the request, read by every check and sent.
    what: 'the view stops splitting a query on ;',
    file: 'src/core/request-view.js',
    from: 'export function queryParams(raw, separator = /[&;]/) {',
    to: "export function queryParams(raw, separator = '&') {",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: "a hop's override check reads the raw URL instead of the view",
    file: 'src/daemon/pipeline.js',
    from: "        try { checkOverrides(effective, hopView, { host: hop.host, path: hop.path }) } catch { reason = 'path' }",
    to: "        try { checkOverrides(effective, { ...hopView, overrides: { headers: [], fields: next.searchParams.getAll('_method') } }, { host: hop.host, path: hop.path }) } catch { reason = 'path' }",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: "the query rules' name check reads the raw query instead of the view",
    file: 'src/core/payload.js',
    from: '    if (set.query) { getQuery(); respelled(set.query, view.params) }',
    to: '    if (set.query) { getQuery(); respelled(set.query, [...new URLSearchParams(view.query)].map(([name, value]) => ({ rawName: name, name, value }))) }',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a ; query is read one way while payload rules are active',
    file: 'src/core/payload.js',
    from: "  if (view.semicolon) ambiguous('semicolon')",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a ; form body is read one way while form rules are active',
    file: 'src/core/payload.js',
    from: "    if (text().includes(';')) ambiguous('form_semicolon')",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: "a JSON key differing from a rule's only by case is let through",
    file: 'src/core/payload.js',
    from: "          if (object(v) && Object.keys(v).some(x => x !== k && x.toLowerCase() === k.toLowerCase())) ambiguous('spelling')",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'an override value is read only as a ;-splitting reader reads it',
    file: 'src/core/request-view.js',
    from: "...(raw.includes(';') ? queryParams(raw, '&') : [])",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // Round 6: a name its readers do not agree on.
    what: 'a name with a NUL, a control or non-ASCII character, an edge space or none is read like any other',
    file: 'src/core/request-view.js',
    from: '    strayName: read.names.some(isStrayName) || read.keys.some(isStrayKey),',
    to: '    strayName: false,',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a direct request with a stray name is sent',
    file: 'src/daemon/pipeline.js',
    from: '    if (view.strayName) {',
    to: '    if (false) {',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a hop to a Location with a stray name is followed',
    file: 'src/daemon/pipeline.js',
    from: "        if (hopView.strayName) reason = 'path'",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a name with DEL or a non-ASCII character is not stray',
    file: 'src/core/request-view.js',
    from: 'export const isStrayKey = (name) => !name || /[^\\x20-\\x7e]|^ | $/.test(name)',
    to: 'export const isStrayKey = (name) => !name || /[\\x00-\\x1f]|^ | $/.test(name)',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a top-level JSON key is not checked for a stray name',
    file: 'src/core/request-view.js',
    from: '{ keys.push(k); if (isOverrideField(k))',
    to: '{ if (isOverrideField(k))',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a name is not folded as PHP registers it, cut at NUL and without leading spaces',
    file: 'src/core/request-view.js',
    from: "  for (const base of [String(name), String(name).split('\\0')[0].replace(/^ +/, '')]) {",
    to: '  for (const base of [String(name)]) {',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a folded multipart Content-Disposition is read up to its first line break',
    file: 'src/core/request-view.js',
    from: ".replace(/;[ \\t]*\\r?\\n|\\r?\\n[ \\t]+/g, (s) => (s[0] === ';' ? '; ' : ' '))",
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    // Round 7: bracket names.
    what: 'a name that opens with a bracket or other punctuation is not stray',
    file: 'src/core/request-view.js',
    from: 'export const isStrayName = (name) => isStrayKey(name) || !/^[A-Za-z0-9_.$-]/.test(name)',
    to: 'export const isStrayName = isStrayKey',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a name is not folded as qs and Rack 2.2 read brackets, so [_method] and force] are other names',
    file: 'src/core/request-view.js',
    from: '.add(/^[[\\]]*([^[\\]]*)/.exec(n)[1])',
    to: '',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a repeated list name such as expand[] is refused as a duplicate',
    file: 'src/core/payload.js',
    from: "if (own(out,name) && !listBase(name)) fail('payload_duplicate_key')",
    to: "if (own(out,name)) fail('payload_duplicate_key')",
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  {
    what: 'a rule on a list name checks only its first entry',
    file: 'src/core/payload.js',
    from: 'for (const v of values) check(kind,key,c,true,v)',
    to: 'for (const v of values.slice(0,1)) check(kind,key,c,true,v)',
    tests: ['test/security/gateway-w2-pipeline.test.js'],
  },
  // ---- integrate-2: the wave-2 seams, F11 pin storage, C12, one budget reader ----
  {
    // F11 (C2 resolved): the gateway's upstream is pinnedRequest, with the
    // credential's pins. The lazy loader and its "no checker" fallback are gone.
    what: "the gateway's upstream drops the credential's pins",
    file: 'src/daemon/pipeline.js',
    from: '  return pinnedRequest({ url, method, headers: lines, body, pins })',
    to: '  return pinnedRequest({ url, method, headers: lines, body, pins: null })',
    tests: ['test/security/integrate2-seams.test.js'],
  },
  {
    // C9: pins by the canonical URL host, and a table that cannot be read is
    // pinned, not unpinned. An exact-key lookup read a malformed table as none.
    what: 'the gateway looks pins up by exact key, so a malformed pin table means no pins',
    file: 'src/daemon/pipeline.js',
    from: 'pins: pinsFor(cred, urlIdentity(new URL(upstreamUrl))) })',
    to: 'pins: cred.pins?.[decision.host] ?? null })',
    tests: ['test/security/integrate2-seams.test.js'],
  },
  {
    // pinnedRequest's own refusals (host_mismatch, header_format) happen before
    // a connection: refunded, and reported as themselves.
    what: "a refusal from pinnedRequest is reported as an unreachable upstream and not refunded",
    file: 'src/daemon/pipeline.js',
    from: "      if (e instanceof VaultError && e.code === 'AV_POLICY_DENIED') {\n        throw deny('AV_POLICY_DENIED', e.detail, { rule: e.rule, refunded: true })\n      }\n",
    to: '',
    tests: ['test/security/integrate2-seams.test.js'],
  },
  {
    // pinnedRequest refuses a header value that is not one string, so a
    // repeated list header must be folded, or ordinary requests fail.
    what: 'a repeated header reaches pinnedRequest as a list and the request is refused',
    file: 'src/daemon/pipeline.js',
    from: "    lines[name] = Array.isArray(value) ? value.map(String).join(name.toLowerCase() === 'cookie' ? '; ' : ', ') : String(value)",
    to: '    lines[name] = value',
    tests: ['test/security/integrate2-seams.test.js'],
  },
  {
    // C12: an infinite session is never reachable from the network, at use.
    // One check for every surface since round 2: it lives in the vault.
    what: 'an infinite session is usable from a network listener',
    file: 'src/store/vault.js',
    from: '    if (session && session.infinite === true && listener?.remote) {',
    to: '    if (false) {',
    tests: ['test/security/integrate2-seams.test.js', 'test/security/integrate2-c12-surfaces.test.js'],
  },
  {
    // C4, one reader: an unreadable budget refuses at the gateway and the store.
    what: 'the shared budget reader calls an unreadable budget no limit',
    file: 'src/core/policy.js',
    from: '  if (!validBudget(budget)) return null\n',
    to: '  if (!validBudget(budget)) return Infinity\n',
    tests: ['test/security/budget-reader.test.js'],
  },
  {
    // C4, one reader: the store's old reading of a limit-less layer, which
    // stopped a redirect hop the gateway had counted.
    what: 'the store reads a budget layer with no limit as unreadable',
    file: 'src/store/vault.js',
    from: '  return policyMod.budgetLimit(policy?.budget)\n',
    to: "  return policy?.budget && typeof policy.budget === 'object' && policy.budget.limit === undefined ? null : policyMod.budgetLimit(policy?.budget)\n",
    tests: ['test/security/budget-reader.test.js', 'test/security/integrate2-seams.test.js'],
  },
  {
    // F4 + C5: the store saves only what the gateway's scrubber can compile.
    what: 'the store saves a scrub pattern the gateway grammar refuses',
    file: 'src/store/vault.js',
    from: '    compileScrubPattern(source)\n',
    to: '',
    tests: ['test/security/integrate2-seams.test.js'],
  },
  {
    // F11 store: one pin format (PIN_RE through pinListState).
    what: 'setPins stores a malformed pin list',
    file: 'src/store/vault.js',
    from: "  if (pinListState(pins) !== 'pinned') {",
    to: '  if (false) {',
    tests: ['test/security/store-pins.test.js'],
  },
  {
    what: 'setPins pins a host the credential cannot reach',
    file: 'src/store/vault.js',
    from: '    if (!key || !ceiling.some((h) => urlHostOf(h) === key || policyMod.matchHost(h, key))) {',
    to: '    if (!key) {',
    tests: ['test/security/store-pins.test.js'],
  },
  {
    // The gateway and the probe look pins up by the canonical URL host.
    what: 'setPins stores a host as written, not as the connectors read it',
    file: 'src/store/vault.js',
    from: '    const key = this.#pinHost(cred, host)\n    const list = pinList(pins)',
    to: '    const key = (this.#pinHost(cred, host), host)\n    const list = pinList(pins)',
    tests: ['test/security/store-pins.test.js'],
  },
  {
    // F11 + F8: a restore puts pins back; dropping them is less protection.
    what: "a restore drops a bundle's pins",
    file: 'src/store/vault.js',
    from: '        cred.pins = { ...pinTableOf(cred.pins, key), [key]: pinList(list) }',
    to: '        pinList(list)',
    tests: ['test/security/store-pins.test.js'],
  },
  {
    what: 'the public credential view carries the pins themselves, not counts',
    file: 'src/store/vault.js',
    from: '      pins: pinCounts(cred.pins),',
    to: '      pins: structuredClone(cred.pins ?? {}),',
    tests: ['test/security/store-pins.test.js'],
  },
  {
    // The durability scan reads one-line methods (Grok's residual): a
    // one-line writer used to be on no list and was never checked.
    what: 'a one-line method that writes the vault is on no durability list',
    file: 'src/store/vault.js',
    from: '  listListeners() { return Object.values(this.db.listeners) }',
    to: '  listListeners() { this.#persist(); return Object.values(this.db.listeners) }',
    tests: ['test/core/passphrase.test.js'],
  },
  {
    // C12 on every surface (round 2): discovery asks the one usability check,
    // not liveness alone, or an infinite token reads grants and mints
    // placeholders on a network listener.
    what: 'discovery checks liveness but not whether the session is usable on this listener',
    file: 'src/daemon/server.js',
    from: '      this.vault.assertSessionUsable(session, req.listener ?? null)\n',
    to: '      this.vault.assertSessionLive(session)\n',
    tests: ['test/security/integrate2-c12-surfaces.test.js'],
  },
  {
    what: 'the MCP endpoint checks liveness but not whether the session is usable on this listener',
    file: 'src/daemon/server.js',
    from: '      try { this.vault.assertSessionUsable(session, listener, { peek: true }) } catch { session = null }',
    to: '      try { this.vault.assertSessionLive(session) } catch { session = null }',
    tests: ['test/security/integrate2-c12-surfaces.test.js'],
  },
  {
    // Defence in depth: the pipeline under vault_http asks for itself.
    what: 'vault_http does not hand its listener to the pipeline',
    file: 'src/daemon/mcp.js',
    from: '            listener,\n          })',
    to: '          })',
    tests: ['test/security/integrate2-c12-surfaces.test.js'],
  },
  {
    // control-api (wave 3). C17: refused in #planSession, before anyone is asked for a passphrase.
    what: "a budget of 0 reaches the presence gate before it is refused (C17)",
    file: "src/daemon/server.js",
    from: "      if (budget === 0) {",
    to: "      if (false) {",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3). Wave 3: every GrantSpec field goes through the one converter (0.6).
    what: "a session body is converted inline, so its rate, quota, routes and payload rules are dropped",
    file: "src/daemon/server.js",
    from: "      const policy = policyMod.grantPolicyFromInput(spec, { profile, ceiling })",
    to: "      const policy = { hosts: policyMod.confineHosts(spec.hosts, ceiling), methods: spec.methods ?? ['GET', 'HEAD'], paths: spec.paths ?? ['/**'], budget: { unit: profile.defaultBudget.unit, limit: budget ?? profile.defaultBudget.limit }, approval: spec.approval ?? 'on-write' }",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a grant lifetime is accepted and never given to the store (F18)",
    file: "src/daemon/server.js",
    from: "          sessionId: session.id, credentialId: cred.id, fields: [field.name], policy, ttlMs,",
    to: "          sessionId: session.id, credentialId: cred.id, fields: [field.name], policy,",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3). The proposer dry-runs the plan: it is also what refuses a quarantined credential (C12 note).
    what: "a session request is opened without being built first, so one that could never be created reaches a human",
    file: "src/daemon/server.js",
    from: "    this.#planSession(requestSpec(proposal))\n    try {",
    to: "    try {",
    tests: ["test/security/control-api-mcp.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3). The proposal for one is refused here too.
    what: "a session can be planned for a quarantined credential",
    file: "src/daemon/server.js",
    from: "      if (cred.quarantine && !savingTemplate) throw quarantined(cred)",
    to: "",
    tests: ["test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template create is not bound to the hash the human looked at (F17)",
    file: "src/daemon/server.js",
    from: "if (typeof input.template_hash !== 'string' || input.template_hash !== template.hash) {",
    to: "if (false) {",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template create's signed operation binds the name but not template_hash (F17)",
    file: "src/daemon/server.js",
    from: "      case 'POST /v1/sessions': return of('session.create', input)",
    to: "      case 'POST /v1/sessions': return of('session.create', input?.template !== undefined ? { template: input.template } : input)",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a session request from a template is resolved again at approval, not snapshotted (F17)",
    file: "src/daemon/server.js",
    from: "      ...requestSpec(final),\n      label: `requested by an agent (${record.id})`,",
    to: "      ...(final.template ? { template: final.template, template_hash: this.vault.getTemplate(final.template)?.hash } : requestSpec(final)),\n      label: `requested by an agent (${record.id})`,",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a narrowing that names nothing does nothing silently (F15)",
    file: "src/daemon/server.js",
    from: "    if (!fields.length && sessionTtl === null && grantTtl === null) {",
    to: "    if (false) {",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a narrowing that turns redirects on is only refused after the session was shortened (F15)",
    file: "src/daemon/server.js",
    from: "    if (Object.hasOwn(narrow, 'redirects') && narrow.redirects !== 0) {",
    to: "    if (false) {",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a narrowing silently ignores a field it cannot narrow (F15)",
    file: "src/daemon/server.js",
    from: "    if (unknown.length) throw bad(`a narrowing cannot carry ${unknown[0]}`)",
    to: "",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3).
    what: "narrowGrant spreads a narrowing over the grant instead of intersecting (F15, through the route)",
    file: "src/store/vault.js",
    from: "    g.policy = policyMod.intersect([g.policy, narrow])",
    to: "    g.policy = { ...g.policy, ...narrow }",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3).
    what: "rotation keeps the held approvals a human gave against the old key (F7)",
    file: "src/daemon/server.js",
    from: "const invalidated = this.pipeline.denyApprovals({ credentialId: this.vault.findCredential(input.slug).id }, 'credential_rotated')",
    to: "const invalidated = 0",
    tests: ["test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a rotation retire window is read by coercion",
    file: "src/daemon/server.js",
    from: "if (input.retire_hours !== undefined && !(Number.isInteger(input.retire_hours) && input.retire_hours >= 0 && input.retire_hours <= 168)) {",
    to: "if (false) {",
    tests: ["test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a scrub pattern is stored without being compiled (F4)",
    file: "src/daemon/server.js",
    from: "          const { re } = compileScrubPattern(input.pattern)",
    to: "          const re = /(?!)/g",
    tests: ["test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "cred rotate runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('cred rotate',",
    to: "void ('cred rotate',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "cred scrub add runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('cred scrub add',",
    to: "void ('cred scrub add',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "cred scrub remove runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('cred scrub remove',",
    to: "void ('cred scrub remove',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "cred expiry runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('cred expiry',",
    to: "void ('cred expiry',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "cred pins runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('cred pins',",
    to: "void ('cred pins',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "cred pins remove runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('cred pins remove',",
    to: "void ('cred pins remove',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "cred release runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('cred release',",
    to: "void ('cred release',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "template save runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('template save',",
    to: "void ('template save',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "backup restore runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('backup restore',",
    to: "void ('backup restore',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-backup-audit.test.js"],
  },
  {
    // control-api (wave 3).
    what: "notify set runs with no human (A.2 widening)",
    file: "src/daemon/server.js",
    from: "this.#requireHumanForWidening('notify set',",
    to: "void ('notify set',",
    tests: ["test/security/control-gate.test.js", "test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "backup export accepts the window instead of a fresh proof (F8)",
    file: "src/daemon/server.js",
    from: "this.#requireFreshPresence('backup export',",
    to: "this.#requireHumanForWidening('backup export',",
    tests: ["test/security/control-api-backup-audit.test.js", "test/security/control-gate.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a wrong recovery passphrase on inspect is not counted (F8)",
    file: "src/daemon/server.js",
    from: "            inspected = await inspectBackup(input.bundle, { recoveryPassphrase: input.recovery_passphrase })\n          } catch (e) {\n            if (e?.rule === 'backup_auth') this.#recordPassphraseAttempt(false)",
    to: "            inspected = await inspectBackup(input.bundle, { recoveryPassphrase: input.recovery_passphrase })\n          } catch (e) {\n            if (false) this.#recordPassphraseAttempt(false)",
    tests: ["test/security/control-api-backup-audit.test.js"],
  },
  {
    // control-api (wave 3). An agent could inspect a bundle it made itself to reset the backoff on the passphrase it is guessing.
    what: "a right recovery passphrase on inspect clears the vault passphrase throttle (F8)",
    file: "src/daemon/server.js",
    from: "          this.vault.audit.write('backup.inspected',",
    to: "          this.#recordPassphraseAttempt(true); this.vault.audit.write('backup.inspected',",
    tests: ["test/security/control-api-backup-audit.test.js"],
  },
  {
    // control-api (wave 3).
    what: "POST /v1/tripwires {enabled:false} is open (F16)",
    file: "src/daemon/server.js",
    from: "const enableOnly = keys.length === 1 && keys[0] === 'enabled' && body.enabled === true",
    to: "const enableOnly = keys.length === 1 && keys[0] === 'enabled' && typeof body.enabled === 'boolean'",
    tests: ["test/security/control-api-containment.test.js", "test/security/control-gate.test.js"],
  },
  {
    // control-api (wave 3).
    what: "POST /v1/tripwires reads enabled by truthiness, so 'true' and 1 are open (C20)",
    file: "src/daemon/server.js",
    from: "const enableOnly = keys.length === 1 && keys[0] === 'enabled' && body.enabled === true",
    to: "const enableOnly = keys.length === 1 && keys[0] === 'enabled' && !!body.enabled",
    tests: ["test/security/control-api-containment.test.js"],
  },
  {
    // control-api (wave 3).
    what: "tripwire changes other than enabling run with no human (F16)",
    file: "src/daemon/server.js",
    from: "if (!enableOnly) this.#requireHumanForWidening('tripwires set',",
    to: "if (false) this.#requireHumanForWidening('tripwires set',",
    tests: ["test/security/control-api-containment.test.js", "test/security/control-gate.test.js"],
  },
  {
    // control-api (wave 3).
    what: "panic is never told about session requests (C1)",
    file: "src/daemon/server.js",
    from: "    this.pipeline.onPanic = async () => ({ session_requests_denied: this.#denyPendingSessionRequests('panic') })",
    to: "    this.pipeline.onPanic = null",
    tests: ["test/security/control-api-containment.test.js", "test/security/integrate2-seams.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a panic that locks leaves the passphrase window open",
    file: "src/daemon/server.js",
    from: "          if (result.locked) this.presenceGraceUntil = 0",
    to: "",
    tests: ["test/security/control-api-containment.test.js"],
  },
  {
    // control-api (wave 3).
    what: "panic reads lock by truthiness, so 'true' panics without locking",
    file: "src/daemon/server.js",
    from: "          if (input.lock !== undefined && typeof input.lock !== 'boolean') {",
    to: "          if (false) {",
    tests: ["test/security/control-api-containment.test.js"],
  },
  {
    // control-api (wave 3).
    what: "an agent-written quarantine reason is stored with its placeholder and secret in it (F16)",
    file: "src/daemon/server.js",
    from: "reason: this.#untrustedText(input.reason) })",
    to: "reason: input.reason ?? null })",
    tests: ["test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "the gateway preflight route ignores the listener it arrived on (C18)",
    file: "src/daemon/server.js",
    from: "        this.vault.assertSessionUsable(session, req.listener ?? null, { peek: true })\n        const described = preflightRequest(body)\n        return json(200, await this.pipeline.preflight({\n          ...described,\n          headers: [...described.headers, ['av-session', token]],\n          listener: req.listener ?? null,\n        }))",
    to: "        this.vault.assertSessionUsable(session, null, { peek: true })\n        const described = preflightRequest(body)\n        return json(200, await this.pipeline.preflight({\n          ...described,\n          headers: [...described.headers, ['av-session', token]],\n          listener: null,\n        }))",
    tests: ["test/security/control-api-c18.test.js"],
  },
  {
    // control-api (wave 3).
    what: "vault_describe_access checks the session without its listener (C18)",
    file: "src/daemon/mcp.js",
    from: "        try { this.vault.assertSessionUsable(session, listener, { peek: true }) } catch (e) {",
    to: "        try { this.vault.assertSessionUsable(session, null, { peek: true }) } catch (e) {",
    tests: ["test/security/control-api-c18.test.js"],
  },
  {
    // control-api (wave 3).
    what: "vault_preflight does not hand its listener to the pipeline (C18)",
    file: "src/daemon/mcp.js",
    from: "            // The listener this call arrived on, so the pipeline asks the\n            // same usability question a real request would.\n            listener,\n          }, { assumePlaceholder: true }))",
    to: "          }, { assumePlaceholder: true }))",
    tests: ["test/security/control-api-c18.test.js"],
  },
  {
    // control-api (wave 3).
    what: "vault_request_session drops an owner field instead of refusing it (R3)",
    file: "src/daemon/mcp.js",
    from: "        if (owned.length) {\n          return this.#refusal({",
    to: "        if (false) {\n          return this.#refusal({",
    tests: ["test/security/requested-r1.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a ninth watcher is let in (F14)",
    file: "src/daemon/notify.js",
    from: "    if (this.subscribers.size >= MAX_SUBSCRIBERS) {",
    to: "    if (false) {",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "the minimal webhook payload carries headlines (F14)",
    file: "src/daemon/notify.js",
    from: "  if (detail === 'headline') body.items =",
    to: "  body.items =",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a notification headline keeps placeholder text (F14)",
    file: "src/daemon/notify.js",
    from: "  for (const hit of ph.findAll(s).reverse()) s = `${s.slice(0, hit.offset)}«placeholder»${s.slice(hit.end)}`",
    to: "",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "the webhook is POSTed for every item, not once per interval (F14)",
    file: "src/daemon/notify.js",
    from: "    const wait = Math.max(0, this.lastSent + WEBHOOK_INTERVAL_MS - Date.now())",
    to: "    const wait = 0",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a test notification is not throttled (F14)",
    file: "src/daemon/notify.js",
    from: "    if (now - this.lastTest < TEST_INTERVAL_MS) {",
    to: "    if (false) {",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "every webhook failure is recorded, so a dead endpoint floods the log (F14)",
    file: "src/daemon/notify.js",
    from: "    if (now - this.lastFailureRecorded < FAILURE_RECORD_MS) return",
    to: "",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a session request never tells the notifier it is waiting (F14)",
    file: "src/daemon/session-requests.js",
    from: "    try { this.onPending?.({ kind: 'session',",
    to: "    try { void ({ kind: 'session',",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template override's methods replace the template's instead of intersecting (F17)",
    file: "src/daemon/session-requests.js",
    from: "      g.methods = o.methods.filter((m) => base.includes(m))",
    to: "      g.methods = o.methods",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template override that is not one is ignored instead of refused (F17)",
    file: "src/daemon/session-requests.js",
    from: "    if (!TEMPLATE_OVERRIDES.includes(k)) throw refuse(`a template cannot be overridden with ${k}`)",
    to: "",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template override's budget replaces the template's instead of taking the minimum (F17)",
    file: "src/daemon/session-requests.js",
    from: "      g.budget = Math.min(baseInt, budget)",
    to: "      g.budget = budget",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template override's approval mode replaces a stricter one (F17)",
    file: "src/daemon/session-requests.js",
    from: "g.approval = !order.includes(base) ? 'each' : (order.indexOf(o.approval) > order.indexOf(base) ? o.approval : base)",
    to: "g.approval = o.approval",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template override's lifetime replaces a shorter one (F17)",
    file: "src/daemon/session-requests.js",
    from: "      spec.ttl_hours = Math.min(base, o.ttl_hours)",
    to: "      spec.ttl_hours = o.ttl_hours",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a template override can make a finite template infinite (F17)",
    file: "src/daemon/session-requests.js",
    from: "    if (o.infinite === true && spec.infinite !== true) throw refuse('an override cannot remove a template\\'s lifetime')",
    to: "",
    tests: ["test/security/control-api-templates.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a human's numeric override is coerced, so a typo becomes null and is dropped",
    file: "src/pending.js",
    from: "    const n = typeof v === 'number' ? v : (typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN)",
    to: "    const n = Number(v)",
    tests: ["test/security/control-api-sessions.test.js", "test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a held request's preview is dropped from the human's list (F13)",
    file: "src/pending.js",
    from: "    preview: raw.preview ?? null,",
    to: "    preview: null,",
    tests: ["test/security/control-api-mcp.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a probe refusal (a pin mismatch) is answered as an internal error (F12)",
    file: "src/daemon/server.js",
    from: "      if (e instanceof VaultError || typeof e?.code !== 'string' || !Object.hasOwn(CODES, e.code)) throw e",
    to: "      throw e",
    tests: ["test/security/control-api-credentials.test.js"],
  },
  {
    // control-api (wave 3).
    what: "a grant lifetime given twice in a narrowing is taken from one place silently (C22)",
    file: "src/daemon/server.js",
    from: "    if (input.grant_ttl_minutes !== undefined && narrow.grant_ttl_minutes !== undefined) {",
    to: "    if (false) {",
    tests: ["test/security/control-api-sessions.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "a JSON-string routes narrowing is dropped, so the agent's wider routes are approved (C21, C23)",
    file: "src/pending.js",
    from: "  if (given(args.routes)) out.routes = json('routes', args.routes)",
    to: "  if (Array.isArray(args.routes)) out.routes = args.routes",
    tests: ["test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "a JSON-string payload narrowing is dropped (C21, C23)",
    file: "src/pending.js",
    from: "  if (given(args.payload)) out.payload = json('payload', args.payload)",
    to: "  if (given(args.payload) && typeof args.payload === 'object') out.payload = args.payload",
    tests: ["test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "a routes or payload narrowing that is not JSON is dropped instead of refused (C23)",
    file: "src/pending.js",
    from: "    try { parsed = JSON.parse(v) } catch { throw fail(field, 'not valid JSON') }",
    to: "    try { parsed = JSON.parse(v) } catch { return undefined }",
    tests: ["test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "parseOverrides reaches outside its own body, so the page's injected copy throws (C21, C23)",
    file: "src/pending.js",
    from: "export function parseOverrides(args = {}) {\n  const out = {}",
    to: "const NO_OVERRIDES = () => ({})\nexport function parseOverrides(args = {}) {\n  const out = NO_OVERRIDES()",
    tests: ["test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "a numeric narrowing that is not finite is sent as NaN, which JSON drops (C23)",
    file: "src/pending.js",
    from: "    if (!Number.isFinite(n)) throw fail(field, `not a number: ${JSON.stringify(v)}`)",
    to: "",
    tests: ["test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "a blank numeric narrowing becomes a limit of 0 (C23)",
    file: "src/pending.js",
    from: "(typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN)",
    to: "(typeof v === 'string' ? Number(v) : NaN)",
    tests: ["test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "a rate or quota narrowing is stringified and not trimmed (C23)",
    file: "src/pending.js",
    from: "  const shape = (v) => (typeof v === 'string' ? v.trim() : v)",
    to: "  const shape = (v) => String(v)",
    tests: ["test/security/control-api-overrides.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "a notification headline keeps a stored secret an agent put in a path (F14)",
    file: "src/daemon/notify.js",
    from: "    headline: secrets ? cleanHeadline(redactStored(event.headline, secrets)) : '',",
    to: "    headline: cleanHeadline(event.headline),",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "the stored-secret scrub matches values under the scrubber's floor (F14)",
    file: "src/daemon/notify.js",
    from: "    if (typeof secret === 'string' && secret.length >= MIN_SECRET_LEN) out = out.split(secret)",
    to: "    if (typeof secret === 'string') out = out.split(secret)",
    tests: ["test/security/control-api-notify.test.js"],
  },
  {
    // control-api (wave 3, fix round 1).
    what: "an agent-written reason is cut before it is scrubbed, so a secret across the cut leaves half behind (F16)",
    file: "src/daemon/server.js",
    from: "    let out = redactStored(text, this.vault.allSecrets())",
    to: "    let out = redactStored(text.slice(0, max), this.vault.allSecrets())",
    tests: ["test/security/control-api-credentials.test.js"],
  },
  // control-ui (wave 3): the UI proxy routes, what reaches the page, and the page itself.
  {
    what: 'a non-string secret field (a backup bundle) is digested as "[object Object]"',
    file: 'src/ui/webauthn.js',
    from: "const text = typeof v === 'string' ? v : canonicalOperation(v)",
    to: 'const text = String(v)',
    tests: ['test/security/control-ui-webauthn.test.js'],
  },
  {
    what: 'the wave-3 secret fields are bound in clear',
    file: 'src/ui/webauthn.js',
    from: "export const DIGESTED = new Set(['value', 'prf_secret', 'recovery_passphrase', 'bundle', 'webhook_url'])",
    to: "export const DIGESTED = new Set(['value', 'prf_secret'])",
    tests: ['test/security/control-ui-webauthn.test.js'],
  },
  {
    what: 'a daemon answer reaches the page without the token and placeholder guard',
    file: 'src/ui/server.js',
    from: 'const send = (status, obj) => this.#send(res, status, towardPage(obj))',
    to: 'const send = (status, obj) => this.#send(res, status, obj)',
    tests: ['test/security/control-ui-guard.test.js'],
  },
  {
    what: 'credential-record writes, tripwire rules and templates go through the UI unsigned',
    file: 'src/ui/server.js',
    from: "    'POST credentials/rotate', 'POST credentials/scrub', 'DELETE credentials/scrub',\n    'POST credentials/expiry', 'POST credentials/release',\n    'POST tripwires', 'POST templates', 'DELETE templates',\n",
    to: '',
    tests: ['test/security/control-ui-routes.test.js'],
  },
  {
    what: 'removing a scrub pattern drops the proof on the way to the daemon',
    file: 'src/ui/server.js',
    from: "`/v1/credentials/scrub${queryOf(url, ['slug', 'id'])}`,\n            { presence: body?.presence },",
    to: "`/v1/credentials/scrub${queryOf(url, ['slug', 'id'])}`,\n            {},",
    tests: ['test/security/control-ui-routes.test.js'],
  },
  {
    what: 'a replacement authenticator other than the one just registered is accepted by the UI',
    file: 'src/ui/server.js',
    from: 'if (canonical(record) !== canonical(pending.credential)) {',
    to: 'if (false) {',
    tests: ['test/security/control-ui-rotate.test.js'],
  },
  {
    what: 'panic reads a string as a lock decision',
    file: 'src/ui/server.js',
    from: "if (key === 'POST panic' && body?.lock !== undefined && typeof body.lock !== 'boolean') {",
    to: 'if (false) {',
    tests: ['test/security/control-ui-routes.test.js'],
  },
  {
    what: 'the page can steer the credential probe',
    file: 'src/ui/server.js',
    from: 'body?.all === true ? { all: true } : { slug: body?.slug }))',
    to: 'body))',
    tests: ['test/security/control-ui-routes.test.js'],
  },
  {
    what: 'the audit kind filter takes any text into the daemon path',
    file: 'src/ui/server.js',
    from: "if (kind !== null && !/^[a-z_]+(\\.[a-z_]+)*$/.test(kind)) {",
    to: 'if (false) {',
    tests: ['test/security/control-ui-routes.test.js'],
  },
  {
    what: 'the page is served without the one narrowing parser (C21)',
    file: 'src/ui/server.js',
    from: 'return html.replace(PARSER_MARKER, () => source)',
    to: 'return html',
    tests: ['test/security/control-ui-guard.test.js'],
  },
  {
    what: 'an approval preview is painted as markup',
    file: 'src/ui/app.html',
    from: '? `<pre class="untrusted">${esc(body.text)}</pre>`',
    to: '? `<pre class="untrusted">${body.text}</pre>`',
    tests: ['test/security/control-ui-page.test.js'],
  },
  {
    what: "a desktop notification carries the agent's claim",
    file: 'src/ui/app.html',
    from: "const text = `${lead}${String(item?.headline ?? '')}`",
    to: "const text = `${lead}${String(item?.claim ?? item?.headline ?? '')}`",
    tests: ['test/security/control-ui-page.test.js'],
  },
  {
    what: 'a template override can lengthen the lifetime',
    file: 'src/ui/app.html',
    from: 'if (!limits.infinite && h > limits.ttlHours) return',
    to: 'if (false) return',
    tests: ['test/security/control-ui-page.test.js'],
  },
  {
    what: 'a template override can relax the approval mode',
    file: 'src/ui/app.html',
    from: 'APPROVAL_ORDER.indexOf(chosen.approval) < limits.approvalFloor',
    to: 'false',
    tests: ['test/security/control-ui-page.test.js'],
  },
  {
    what: 'the payload rules are signed without being parsed',
    file: 'src/ui/app.html',
    from: 'try { payload = JSON.parse(raw.payload) } catch (e) { return { error: `The payload rules are not JSON: ${e.message}` } }',
    to: 'payload = raw.payload',
    tests: ['test/security/control-ui-page.test.js'],
  },
  {
    what: 'an error from POST sessions reaches the page as a hand-off, unfiltered',
    file: 'src/ui/server.js',
    from: 'const send = (status, obj) => this.#send(res, status, towardPage(obj))',
    to: 'const send = (status, obj) => this.#send(res, status, UiServer.HANDOFF.has(key) ? obj : towardPage(obj))',
    tests: ['test/security/control-ui-handoff.test.js'],
  },
  {
    what: 'the session hand-off carries the whole daemon answer, not only the card fields',
    file: 'src/ui/server.js',
    from: 'UiServer.HANDOFF.has(key) ? handoffTowardPage(obj) : towardPage(obj))',
    to: 'UiServer.HANDOFF.has(key) ? obj : towardPage(obj))',
    tests: ['test/security/control-ui-handoff.test.js'],
  },
  {
    what: 'a hand-off card field is copied back with whatever is nested in it',
    file: 'src/ui/server.js',
    from: 'if (isScalar(v) || (Array.isArray(v) && v.every(isScalar))) to[n] = v',
    to: 'to[n] = v',
    tests: ['test/security/control-ui-handoff.test.js'],
  },
  {
    what: 'a withheld key in another case reaches the page',
    file: 'src/ui/server.js',
    from: "const withheldKey = (k) => WITHHELD_KEYS.has(k.toLowerCase().replaceAll('-', '_'))",
    to: 'const withheldKey = (k) => WITHHELD_KEYS.has(k)',
    tests: ['test/security/control-ui-handoff.test.js'],
  },
  {
    what: 'a hyphenated withheld key reaches the page',
    file: 'src/ui/server.js',
    from: "const withheldKey = (k) => WITHHELD_KEYS.has(k.toLowerCase().replaceAll('-', '_'))",
    to: 'const withheldKey = (k) => WITHHELD_KEYS.has(k.toLowerCase())',
    tests: ['test/security/control-ui-handoff.test.js'],
  },
  {
    what: 'a parser that can end its own script is served in the page',
    file: 'src/ui/server.js',
    from: "if (/<\\/script/i.test(source) || source.includes('<!--') || source.includes(PARSER_MARKER)) {",
    to: 'if (false) {',
    tests: ['test/security/control-ui-handoff.test.js'],
  },
  {
    what: 'a VaultError refusal from the UI is reported as a crash',
    file: 'src/ui/server.js',
    from: 'return send(e.status || e.http || 500,',
    to: 'return send(e.status || 500,',
    tests: ['test/security/control-ui-handoff.test.js'],
  },
  {
    what: 'a decision is sent when its narrowing does not parse (C23)',
    file: 'src/ui/app.html',
    from: 'if (narrowing.error) return toast(narrowing.error)',
    to: 'if (false) return toast(narrowing.error)',
    tests: ['test/security/control-ui-narrowing.test.js'],
  },
  {
    what: 'a narrowing that does not parse is read as no narrowing (C23)',
    file: 'src/ui/app.html',
    from: 'return { error: `That narrowing does not parse, so nothing was sent: ${e?.message ?? e}` }',
    to: 'return { overrides: {} }',
    tests: ['test/security/control-ui-narrowing.test.js'],
  },
  // ---- wave 3, control-cli: parsing, files and untrusted presentation ----
  {
    what: "CLI numeric limits accept invalid finite or integer bounds",
    file: "src/cli/policy-input.js",
    from: "if (!Number.isFinite(n) || n < min || n > max || (integer && !Number.isSafeInteger(n))) usage(",
    to: "if (false) usage(",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI session creation drops the reviewed template hash",
    file: "src/cli/index.js",
    from: "      body.template_hash = template.hash",
    to: "      body.template_hash = undefined",
    tests: ["test/security/control-cli-routes.test.js"],
  },
  {
    what: "CLI accepts secret-bearing command-line flags",
    file: "src/cli/index.js",
    from: "if (['value', 'webhook-url', 'webhook_url', 'recovery-passphrase', 'recovery_passphrase'].some((key) => Object.hasOwn(args, key))) usageError(",
    to: "if (false) usageError(",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI backup and audit export overwrite files without force",
    file: "src/cli/control-commands.js",
    from: "return writeFileExclusive(path, text, { force })",
    to: "return writeFileExclusive(path, text, { force: true })",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI witness writes erase prior checkpoints",
    file: "src/cli/control-commands.js",
    from: "try { appendLineExclusive(path, line) } catch (e) {",
    to: "try { writeFileExclusive(path, line + \"\\n\", { force: true }) } catch (e) {",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI probe treats a truthy non-boolean result as success",
    file: "src/cli/control-commands.js",
    from: "if (results.some((v) => v.ok !== true)) process.exitCode",
    to: "if (results.some((v) => !v.ok)) process.exitCode",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI approval preview renders agent terminal controls",
    file: "src/cli/control-commands.js",
    from: "  const body = cleanText(p.body?.text || '')",
    to: "  const body = p.body?.text || ''",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI watch puts notification text inside AppleScript code",
    file: "src/cli/watch.js",
    from: "'-e', 'display notification (item 1 of argv) with title \"agent-vault\"'",
    to: "'-e', `display notification \"${text}\" with title \"agent-vault\"`",
    tests: ["test/security/control-cli-watch.test.js"],
  },
  {
    what: "CLI watch omits notification control-character stripping",
    file: "src/cli/watch.js",
    from: "String(value ?? '').replace(/[\\x00-\\x1f\\x7f-\\x9f]/g, '')",
    to: "String(value ?? '')",
    tests: ["test/security/control-cli-watch.test.js"],
  },
  {
    what: "CLI approve sends an approval when parseOverrides cannot read a narrowing (C23)",
    file: "src/cli/policy-input.js",
    from: "if (e instanceof TypeError && typeof e.field === 'string' && e.field) {",
    to: "if (false) {",
    tests: ["test/security/control-cli-overrides.test.js"],
  },
  {
    what: "CLI approve drops a typed narrowing flag that parsed into nothing",
    file: "src/cli/policy-input.js",
    from: "for (const flag of given) if (!Object.hasOwn(overrides, APPROVAL_FLAGS[flag])) usage(",
    to: "for (const flag of given) if (false) usage(",
    tests: ["test/security/control-cli-overrides.test.js"],
  },
  {
    what: "CLI approve sends a non-finite number, which JSON turns into an absent narrowing",
    file: "src/cli/policy-input.js",
    from: "if (typeof v === 'number' && !Number.isFinite(v)) usage(",
    to: "if (false) usage(",
    tests: ["test/security/control-cli-overrides.test.js"],
  },
  {
    what: "CLI approve reads a bare value flag as true",
    file: "src/cli/policy-input.js",
    from: "if (args[flag] === true && flag !== 'infinite') usage(",
    to: "if (false) usage(",
    tests: ["test/security/control-cli-overrides.test.js"],
  },
  {
    what: "CLI approve sends only one of two spellings of a field",
    file: "src/cli/policy-input.js",
    from: "if (flags.length > 1 && !merged) usage(",
    to: "if (false) usage(",
    tests: ["test/security/control-cli-overrides.test.js"],
  },
  {
    what: "CLI session and approve commands ignore unknown limit flags",
    file: "src/cli/policy-input.js",
    from: "if (flag !== '_' && !allowed.includes(flag)) usage(",
    to: "if (false) usage(",
    tests: ["test/security/control-cli-overrides.test.js"],
  },
  {
    what: "CLI approve reads the daemon before refusing an unreadable narrowing",
    file: "src/cli/index.js",
    from: "  const overrides = granted ? approvalOverrides(args, parseOverrides) : null\n  const pending = await fetchPending((path) => control('GET', path))",
    to: "  const pending = await fetchPending((path) => control('GET', path))\n  const overrides = granted ? approvalOverrides(args, parseOverrides) : null",
    tests: ["test/security/control-cli-overrides.test.js"],
  },
  {
    what: "CLI watch --json prints the raw stream frame instead of the cleaned display fields",
    file: "src/cli/watch.js",
    from: "data: { ...data, event: name }",
    to: "data: { ...raw, event: name }",
    tests: ["test/security/control-cli-watch.test.js"],
  },
  {
    what: "CLI watch keeps placeholders in the headline",
    file: "src/cli/watch.js",
    from: ".replace(/av1\\.[A-Za-z0-9_.-]+/g, '[placeholder]')",
    to: "",
    tests: ["test/security/control-cli-watch.test.js"],
  },
  {
    what: "CLI audit verify reports a broken chain inside a success envelope",
    file: "src/cli/control-commands.js",
    from: "if (chain.ok !== true) {",
    to: "if (false) {",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI audit verify reports a failing witness inside a success envelope",
    file: "src/cli/control-commands.js",
    from: "if (witness && witness.ok !== true) {",
    to: "if (false) {",
    tests: ["test/security/control-cli-files.test.js"],
  },
  {
    what: "CLI session create accepts --remote (R3 says the CLI has none)",
    file: "src/cli/policy-input.js",
    from: "'ttl', 'infinite', 'cred', 'grants-file', 'template'], 'session')",
    to: "'ttl', 'infinite', 'remote', 'cred', 'grants-file', 'template'], 'session')",
    tests: ["test/security/control-cli-routes.test.js"],
  },
  {
    what: "CLI session narrow sends --uses, which the daemon refuses (C22)",
    file: "src/cli/control-commands.js",
    from: "if (args.uses !== undefined) usage(",
    to: "if (false) usage(",
    tests: ["test/security/control-cli-routes.test.js"],
  },
  {
    what: "CLI appendLineExclusive opens a planted fifo without O_NONBLOCK and hangs",
    file: "src/cli/files.js",
    from: "O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0o600",
    to: "O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o600",
    tests: ["test/security/control-cli-fifo.test.js"],
  },
  {
    what: "CLI appendLineExclusive lets a fifo's ENXIO through as an unclassified error",
    file: "src/cli/files.js",
    from: "if (e.code === 'ELOOP' || e.code === 'ENXIO') throw problem",
    to: "if (e.code === 'ELOOP') throw problem",
    tests: ["test/security/control-cli-fifo.test.js"],
  },
  {
    what: "CLI session show reads --markdown=yes as an ordinary display flag",
    file: "src/cli/control-commands.js",
    from: "      const markdown = booleanFlag(args, 'markdown')\n      const r = await control('GET', `/v1/sessions/detail",
    to: "      const markdown = args.markdown === true\n      const r = await control('GET', `/v1/sessions/detail",
    tests: ["test/security/control-cli-files.test.js"],
  },
  // ---- integrate-3: the wave-3 seams, C22(4) on the UI, the session-request audit scrub ----
  {
    // C21: grantInput's reading of --rate and --quota won over parseOverrides',
    // so the CLI signed an object where the page signed the text.
    what: "the CLI's approve sends its own reading of a narrowing, not parseOverrides' (C21)",
    file: 'src/cli/policy-input.js',
    from: '    overrides = { ...grantInput(args), ...typed }',
    to: '    overrides = { ...typed, ...grantInput(args) }',
    tests: ['test/security/integrate3-narrowing.test.js'],
  },
  {
    what: 'a stored secret in a session request path is copied into the session_request.opened audit record',
    file: 'src/daemon/session-requests.js',
    from: 'request_id: record.id, summary: scrubbed(record.summary),',
    to: 'request_id: record.id, summary: record.summary,',
    tests: ['test/security/integrate3-seams.test.js'],
  },
  {
    what: "a stored secret in a session request's reason is copied into the session_request.opened audit record",
    file: 'src/daemon/session-requests.js',
    from: 'agent_reason_untrusted: scrubbed(record.reason_untrusted),',
    to: 'agent_reason_untrusted: record.reason_untrusted,',
    tests: ['test/security/integrate3-seams.test.js'],
  },
  {
    // With nothing to scrub against, the agent's text went in as written.
    what: 'a session request opened while the secrets cannot be read is audited unscrubbed',
    file: 'src/daemon/session-requests.js',
    from: '    try { return this.vault?.allSecrets?.() ?? null } catch { return null }',
    to: '    try { return this.vault?.allSecrets?.() ?? null } catch { return [] }',
    tests: ['test/security/integrate3-seams.test.js'],
  },
  {
    what: 'removing a pin from the UI needs no signature (C22(4))',
    file: 'src/ui/server.js',
    from: "    // Removing a pin takes away a check on the upstream's key (C22(4)).\n    'DELETE credentials/pins',\n",
    to: '',
    tests: ['test/security/integrate3-gates.test.js'],
  },
  {
    what: 'the UI treats the daemon-verified pin removal as its own check only',
    file: 'src/ui/server.js',
    from: "    'POST tripwires', 'POST templates', 'DELETE credentials/pins',\n",
    to: "    'POST tripwires', 'POST templates',\n",
    tests: ['test/security/integrate3-gates.test.js'],
  },
  {
    // The daemon binds an absent spki as null; omitting it is another operation.
    what: "the UI binds a pin removal with spki omitted rather than null (C22(4))",
    file: 'src/ui/server.js',
    from: "slug: url.searchParams.get('slug'), host: url.searchParams.get('host'), spki: url.searchParams.get('spki'),",
    to: "slug: url.searchParams.get('slug'), host: url.searchParams.get('host'), ...(url.searchParams.has('spki') ? { spki: url.searchParams.get('spki') } : {}),",
    tests: ['test/security/integrate3-gates.test.js'],
  },
  {
    // Signed for one pin, executed as "every pin for the host".
    what: 'the UI forwards a single-pin removal without the pin',
    file: 'src/ui/server.js',
    from: "queryOf(url, ['slug', 'host', 'spki'])",
    to: "queryOf(url, ['slug', 'host'])",
    tests: ['test/security/integrate3-gates.test.js'],
  },
  // ---- integrate-3 fix round 1: the approved-record scrub (F1), unapplied overrides (D1), passphrase (D2) ----
  {
    // The human approved the agent's paths; the log kept them as written.
    what: 'a stored secret in an approved session request is copied into the session_request.approved audit record',
    file: 'src/daemon/server.js',
    from: '      granted: this.sessionRequests.forAudit(final),',
    to: '      granted: final,',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    what: 'the approved-record scrub stops at a list, so a path inside one is kept as written',
    file: 'src/daemon/session-requests.js',
    from: '  if (Array.isArray(value)) return value.map((v) => redactDeep(v, secrets))',
    to: '  if (Array.isArray(value)) return value',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    what: 'the approved-record scrub stops at an object, so routes and payload text are kept as written',
    file: 'src/daemon/session-requests.js',
    from: '    return Object.fromEntries(Object.entries(value).map(([k, v]) => [redactStored(k, secrets), redactDeep(v, secrets)]))',
    to: '    return value',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    what: 'an approval recorded while the secrets cannot be read keeps the grant text unscrubbed',
    file: 'src/daemon/session-requests.js',
    from: '    return secrets ? redactDeep(value, secrets) : null',
    to: '    return secrets ? redactDeep(value, secrets) : value',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    // D1: a host list in the overrides was dropped and the approval succeeded.
    what: 'the daemon approves a session request whose overrides name a key it does not apply',
    file: 'src/daemon/server.js',
    from: '          const unread = overridesProblem(input.overrides)',
    to: '          const unread = null',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    what: 'a bulk decision drops a session override key it does not apply',
    file: 'src/daemon/server.js',
    from: '              ? overridesProblem(d.overrides)',
    to: '              ? null',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    what: 'a bulk decision drops the narrowing sent with a held request',
    file: 'src/daemon/server.js',
    from: '              : (d.overrides && Object.keys(d.overrides).length ? ',
    to: '              : (false ? ',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    what: 'overridesProblem lets through a key no decision reads',
    file: 'src/daemon/session-requests.js',
    from: '  const unread = Object.keys(input).filter((k) => !FIELDS.includes(k) && !OWNER_FIELDS.includes(k))',
    to: '  const unread = []',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    what: 'overridesProblem accepts a narrowing that is not an object',
    file: 'src/daemon/session-requests.js',
    from: "  if (typeof input !== 'object' || Array.isArray(input)) return 'the narrowing must be an object'",
    to: '  if (typeof input !== \'object\' || Array.isArray(input)) return null',
    tests: ['test/security/integrate3-fix1.test.js'],
  },
  {
    // D2: the short name passed the key filter.
    what: 'towardPage sends a passphrase to the page',
    file: 'src/ui/server.js',
    from: "'recovery_passphrase', 'passphrase', 'bundle',",
    to: "'recovery_passphrase', 'bundle',",
    tests: ['test/security/integrate3-fix1.test.js'],
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
