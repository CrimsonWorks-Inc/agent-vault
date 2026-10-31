# Changelog

## 0.2.0

Three things users asked for, twenty features, and the security work they
needed. As in 0.1.0, the findings come with what was actually wrong. Each one was
reproduced first and has a test that fails without its fix.

### Asked for

- **Auto-approval, documented and safe to use.** `--approval
  each|on-write|first-use|auto` is in `--help`, the README and the UI. An unknown
  mode used to mean `auto`; it is now the strictest. When you approve an agent's
  request you can set the mode yourself (`approve sr_… --approval auto`). An agent
  cannot ask for it. `auto` with write methods needs your passphrase or
  fingerprint every time, and is refused on a vault with no human factor.
- **Env files with several keys under your names.** A session can hold several
  credentials. `agent-vault env --out .env --map GH_TOKEN=gh --map
  OPENAI_API_KEY=openai` writes placeholders and loopback URLs, never a secret or
  the session token. The file is 0600 and is never replaced without `--force`.
  `exec --map` does the same for one command.
- **Sessions that do not expire.** `session create --infinite` has no idle
  expiry. It lasts until revoked, narrowed to a finite lifetime, or ended by
  panic. It needs a fresh passphrase or fingerprint, cannot be remote, and its
  token is refused on every non-loopback listener.

### New

- Per-grant rate, concurrency and rolling quotas (`--rate 60/min`,
  `--concurrency`, `--quota 1000/day`).
- Request payload rules for JSON fields, form and query parameters, and GraphQL
  operations (`--payload-file`, `--graphql`).
- Method-bound routes (`--route POST:/repos/*/issues`).
- Extra scrub patterns per credential, in a grammar that cannot backtrack (`cred
  scrub`).
- Token and spend budgets for model providers (`--spend-tokens`,
  `--spend-usd`), metered from usage and dated prices.
- Redirects followed only where the grant allows the hop (`--redirects N`).
- Credential rotation with a cutover window (`cred rotate --retire-hours`).
- Encrypted backup and controlled restore (`backup export|inspect|restore`).
- Audit export and an external head witness (`audit export`, `audit witness`,
  `audit verify --witness`).
- Expiry dates and observed health for credentials (`cred expiry`, `status`).
- SPKI pins for connector hosts (`cred pin`).
- `cred test`, a read-only probe on the profile's fixed path.
- Scrubbed previews of held requests (`approvals --show`).
- `agent-vault watch` and an optional webhook that says something is waiting.
- Live narrowing of an active session (`session narrow`). It can only tighten.
- Panic, credential quarantine and tripwires (`panic`, `cred quarantine`,
  `tripwire`).
- Session templates (`template save|list|show|rm`, `session create
  --template`).
- A grant lifetime shorter than its session (`--grant-ttl MIN`).
- Session activity and an access review (`session show`, `report`).
- Preflight (`agent-vault preflight`, MCP `vault_preflight`) and MCP
  `vault_describe_access`.

### Security fixes

Waves of independent review, each asked for reproductions, found these:

- An SPKI pin on an intermediate certificate was satisfied by a forged leaf plus
  the public intermediate. TLS proves only the leaf's key. An issuer now counts
  only if it actually signed the certificate below it.
- A redirect hop copied the request's headers, so `X-HTTP-Method-Override:
  DELETE` rode a hop that was checked as a GET. Hops now send only an allowlist.
- The policy checks and the request sent upstream each parsed the request their
  own way. Override and separator spellings got past one reader or the other.
  Now one view of the request is checked and sent, and a request its readers
  disagree on is refused as `request_ambiguous`.
- A stored secret placed by an agent in a proposal path, label, reason, glob,
  payload key, method or upstream header reached the audit log and its export.
  Audit rows now hold codes, indexes and scrubbed paths (see below).
- A refused Touch ID confirmation logged the client's own unsigned text.
- `vault_explain_denial` answered for any request id, from any caller. It now
  answers only for the caller's own session.
- An approval narrowing that could not be parsed was dropped, so the agent's
  request was approved as asked. It is now refused everywhere: CLI, page, UI
  server and daemon.
- Bidi controls in agent-written text (U+202A–202E, U+2066–2069) reordered what
  the terminal and the page showed, so `fix`, U+202E, `evil` read as `fixlive`. They are
  stripped, and so are U+2028/2029 in terminal output.

### Changes you will notice

- **Audit rows carry codes, not text.**
  - A denial has `reason_code`, `rule`, the method (or `OTHER`) and the scrubbed
    path, but no `detail` or `hint`.
  - Path and route rules are recorded by index (`path_rule: 0`,
    `deny_paths:1`, `payload:json:1:absent`), never by their pattern text.
  - Session requests record their shape only: fields and counts, not values.
  - `session.created` records `has_label`, not the label.
  - `presence.denied` records a closed code.
  - `response.streamed` records `text/event-stream` and a known encoding.
  - Faults record an error class.
  - `vault_explain_denial` still returns the full sentence for an hour (for the
    last 1000 denials), and the code and rule after that.
  - If you parse the log, read `reason_code` and `rule`.
- **`first-use` with write methods counts as elevated**, like `auto` with
  writes. It needs a fresh passphrase or fingerprint.
- **CLI flags are strict.** An unknown flag, a value given to a boolean flag
  (`--tls=false`, `--infinite=no`), or a limit that does not apply (`session
  narrow --uses`) exits 2 and sends nothing.
- **Unknown override keys are refused.** An approval or narrowing that names a
  field the daemon would not apply is refused, not silently ignored.
- **The CLI's `preflight` assumes the placeholder.** Without one at the
  credential's site, it judges the request as the agent would send it, as
  `vault_preflight` does. A placeholder you do pass is still checked.
- **`tripwire show` always lists the rules in force.** Before any are saved,
  those are the defaults (`rules_saved: false`). `tripwire set` edits them.
- **`cred test --all` skips a kind with no probe** instead of failing.

### Testing

1512 tests. `npm run test:mutation` now breaks 569 protections in turn and
expects the suite to fail each time. The new end-to-end tests drive the real
CLI, control API, MCP and gateway against a throwaway daemon and a local
upstream.

## 0.1.0 — first release

The M0/M1 core of the v1 build spec: an
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
