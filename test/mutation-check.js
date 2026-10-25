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
    from: 'const spans = this.viewSpans(out)',
    to: 'const spans = []',
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
    from: "if (scrubber.scrub(run).redactions > 0) return 'credential_split_across_events'",
    to: "if (scrubber.scrub(run.slice(-keep)).redactions > 0) return 'credential_split_across_events'",
    tests: ['test/security/gateway-response.test.js'],
  },
  {
    what: 'the joined event-stream view is trimmed before the new event is searched',
    file: 'src/daemon/pipeline.js',
    from: "if (leaked(joined)) return 'credential_split_across_events'",
    to: "if (leaked(assembled)) return 'credential_split_across_events'",
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
    to: 'choices = choices.flatMap((c) => (c.length ? [c] : [c, ...values.map((v) => [...c, [depth, key, v]])]))',
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
    from: '|%([0-9a-fA-F]{2})|\\\\(["\\\\/bfnrt])/g',
    to: '|%([0-9a-fA-F]{2})/g',
    tests: ['test/security/gateway-hardening.test.js'],
  },
  {
    what: 'the decoded view is searched for the secret only, not its base64, so percent-encoded base64 passes',
    file: 'src/core/scrub.js',
    from: 'this.decoded = [...this.plain, ...this.blobs]',
    to: 'this.decoded = [...this.plain]',
    tests: ['test/security/gateway-hardening.test.js'],
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
