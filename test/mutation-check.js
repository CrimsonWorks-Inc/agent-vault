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
    from: "case 'vault_http': {\n        if (!session) return this.#needsSession(token)",
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
    from: "const bodySha = req.body ? canon.sha256(Buffer.from(stable(req.body.toString('latin1')), 'latin1')) : ''",
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
    from: "          this.#requireHumanForWidening(\n            'session request approval',",
    to: "          if (0) this.#requireHumanForWidening(\n            'session request approval',",
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
    from: '    const created = this.#createSession({\n      ...final,',
    to: '    const created = this.#createSession({\n      ...record.proposal,',
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
    from: "headers.push(['av-session', this.#tokenFor(session, token)])",
    to: "headers.push(['av-session', this.#tokenFor(session)])",
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
    from: "const overrides = parseNarrowing(typed)",
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
    from: "    if (!st.placeholder) lines.push('unset AGENT_VAULT_PLACEHOLDER')",
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
    what: 'intersecting two rates keeps the first window whatever the units',
    file: 'src/core/policy.js',
    from: 'return { count, per: pa >= pb ? a.per : b.per }',
    to: 'return { count, per: a.per }',
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
    from: '  return Number.isSafeInteger(n) && n >= 0 ? n : null\n}',
    to: '  return Number.isSafeInteger(n) && n >= 0 ? n : Infinity\n}',
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
    // Dropping the pins restores a credential with less protection than the
    // human gave it.
    what: "a restore goes ahead when it cannot restore a bundle's pins",
    file: 'src/store/vault.js',
    from: "      if (Object.values(c.pins ?? {}).some((l) => l.length) && typeof this.setPins !== 'function') {",
    to: '      if (false) {',
    tests: ['test/security/store-backup.test.js'],
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
