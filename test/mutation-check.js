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
    from: "...recordable(fields)",
    to: "...fields",
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
    // F11 (C2): pins nothing can check are refused, never dropped.
    what: 'pins configured with no pin checker installed are ignored',
    file: 'src/daemon/pipeline.js',
    from: "  if (pins != null) throw Object.assign(new Error('certificate pins are set and pin checking is not available')",
    to: "  if (false) throw Object.assign(new Error('certificate pins are set and pin checking is not available')",
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
    from: '      if (peek) this.#peekGrant(grant)\n      else this.vault.assertGrantLive?.(grant)',
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
