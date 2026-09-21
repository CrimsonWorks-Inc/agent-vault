# Changelog

## 0.1.0 — first release

The M0/M1 core of the [v1 build spec](https://claude.ai/artifact/4kFDYZBoSCb8fujQqD4kjg): an
agent sends a placeholder, the daemon substitutes the real secret at the one
declared injection site, for a destination the grant allows, while the
placeholder has uses left. The response comes back scrubbed.

What is not built is listed under [Honest limits](README.md#honest-limits) and is
not repeated here. This file records what changed and, for the security work,
what was actually wrong — a first release of a credential proxy is worth more
with its findings attached than with a feature list.

### The mechanism

- Placeholder grammar with a keyed checksum, and a ledger that is the only thing
  authorising an injection. A use is consumed before the first upstream byte, so
  twenty concurrent uses of a one-time placeholder produce exactly one request.
- Location-bound substitution: `header:authorization:Bearer`, `basic:pass`,
  `json:/ptr`, `query:key`, `form:field`, `url:userinfo`. A placeholder anywhere
  else is refused before an upstream socket exists.
- A detector that is a superset of the substituter by construction, across raw,
  percent, double-percent, JSON-unicode, escaped-slash and base64 at three
  alignments in both alphabets — wrapped or not.
- A response scrubber over every injected secret and every other stored
  credential, in every encoding a response is likely to carry one in, including
  across streaming chunk boundaries.
- Policy as profile ∩ workspace ∩ session ∩ grant, with deny lists that survive
  every path spelling, host confinement to the credential's own hosts, budgets,
  and approvals bound to the request.
- A hash-chained audit log with an authenticated head anchor.
- A privileged installer that puts the vault behind its own uid, a web UI whose
  confirmations are WebAuthn assertions the daemon verifies itself, MCP over
  stdio and Streamable HTTP, and a CLI.

### Security findings fixed before release

Four independent adversarial reviews — the crypto and storage layer, the request
pipeline, the control surface and MCP, and the privileged installer — read this
code without being told what had already been fixed, and were asked for
reproductions rather than opinions. Everything below was reproduced first and
carries a test that fails without its fix.

**Critical**

- A gzipped `text/event-stream` response returned before the decompression step,
  so the scrubber searched DEFLATE bytes for a plaintext needle. The agent
  gunzipped the stream and read the credential in full, counted as zero
  redactions and audited as a clean `response.streamed`.
- The installer spawned every privileged helper by bare name while running as
  root, resolving `chown`, `dscl` and `launchctl` through a PATH inherited from
  the user's shell.
- An agent could enrol its own authenticator on a factor-less vault, becoming
  the only party able to satisfy any presence gate — and leaving the owner
  unable to set a passphrase, because setting the first one is itself gated.

**High**

- Truncating the audit log *and* deleting its anchor reported "chain intact",
  repeatably, erasing the previous round's evidence each time.
- `req.listener` was dropped between the server and the pipeline, so the rule
  refusing a bare placeholder on a network listener, a listener's `advertise`
  list, and the peer recorded in the audit log had never once worked.
- A one-time placeholder's automatic successor was issued with the grant's
  entire budget.
- One `POST /mcp` with a body of `null` ended the daemon process.
- `POST /v1/passphrase` verified the current passphrase with scrypt and had no
  throttle: unlimited guessing, and unlimited event-loop stall.
- The signature counter could be walked up in individually-legal steps until the
  owner's real authenticator read as cloned, permanently.
- Approvals were not bound to their headers, so `X-HTTP-Method-Override: DELETE`
  rode along under a human's approval of a `POST`.
- `locate()` never read header names, query keys, form keys, JSON object keys, or
  the first of two duplicate JSON keys.
- The base64 detector missed any wrapped encoding — which is what `base64`, MIME
  and PEM all produce.
- A budget layer naming a unit but no limit made `used >= NaN` false forever, so
  the grant silently stopped being counted.

**Also fixed**

The scrubber left a secret's last three characters when it appeared inside a
base64 blob, and its shape patterns matched mid-word (`disk-usage_by_repository`
came back redacted). `wirePath` percent-encoded characters that are legal in a
path, breaking `…/gemini-pro:generateContent`, scoped npm packages and OData.
`fingerprint8` shared a key with the placeholder checksum, giving a
chosen-message oracle, and the checksum was never verified anywhere. A torn
final line in the audit log — an ordinary crash mid-append — locked every factor
out permanently. The placeholder ledger grew without bound at 13.5 ms a write.
`isLoopbackHost` treated `127.evil.com` as loopback. A tampered port in the CLI
state file could redirect the exported gateway URL to another host. Plus bounds
on everything a caller can grow or make expensive, and a guard so a rejected
promise costs one request rather than the daemon.

### Testing

421 tests on Node 20, 22 and 24. `npm run test:mutation` removes each of
twenty-nine critical protections in turn and asserts the suite notices; it has
twice caught its own anchors drifting after a refactor. `test/security/invariants.test.js`
drives a real daemon and a hostile upstream through 2400 randomized requests
across four seeds, checking the five claims the README makes.
`test/core/package.test.js` packs the real tarball and uses it, because
`npm publish` ships something different from the checkout.
