# agent-vault

A local credential proxy for coding agents. The agent sends a **placeholder**; the daemon replaces it with the real secret, but only at the exact place that credential is ever injected, only for a destination the grant allows, and only while the placeholder has uses left. The response comes back scrubbed. The agent never holds a credential.

```
agent                          agent-vault daemon                    upstream
  │  Authorization: Bearer av1.7f2x…c4d9tz                                │
  ├──────────────────────────────▶  check session, grant, site, budget    │
  │                                 consume one use                       │
  │                                 substitute at the declared site  ─────▶ Authorization: Bearer ghp_real…
  │                                                                       │
  │  {"login":"frozencrow", "token_used":"av1.7f2x…"}  ◀── scrub ─────────┤ {"token_used":"ghp_real…"}
  ◀──────────────────────────────┤                                        │
```

This repository is the **M0/M1 working core** of the [v1 build spec](https://claude.ai/artifact/4kFDYZBoSCb8fujQqD4kjg). It runs, it is tested, and the central mechanism works end to end. It is not yet the production daemon; see [Honest limits](#honest-limits).

## Try it

Requires Node 20.10 or newer. The suite has been run on 20, 22 and 24 on macOS; `.github/workflows/test.yml` adds Linux and the 20.10 floor, but has not executed yet — this is not in a remote. No dependencies to install.

```bash
node demo/demo.js
```

The demo starts a real daemon and a stand-in upstream, then walks through: a successful call, an upstream echoing the token back, a prompt-injection attempt, the same attempt base64-encoded, an attempt to send the placeholder elsewhere, an approval, budget exhaustion, and the audit chain. It ends by confirming the real token reached the upstream and nothing else.

```bash
npm test          # 418 tests
```

```bash
npm run test:mutation
```

The second one checks the tests against themselves: it removes each of
twenty-nine critical protections in turn and asserts the suite notices. Deleting the
human-presence gate fails 6 tests; host confinement, the placeholder checksum
and the approval's request-hash binding 4 each; the session-token strip, the
path control-character refusal and non-ASCII scrubbing 2 each; and the
streaming scrubber, the injection-site encoding check, error-detail scrubbing,
per-message MCP sessions, the ceiling on a child policy, the gate on Touch ID
enrollment, the last-unlock-wrap guard and the installer's symlink refusal 1
each. A mutation that survives means the thing it broke is not really tested,
whatever the test names say.

## Use it

```bash
agent-vault setup                      # shows the plan, then runs the installer for you
agent-vault daemon                     # only needed in --dev mode; otherwise it is a service

# store a credential; the value is read from the terminal, never from argv
agent-vault cred add gh --kind github
agent-vault session create --cred gh --paths "/repos/frozencrow/**"
```

Run either of those without arguments and you get a wizard instead of a flag list.

After installing, confirm the boundary is real. This should be refused:

```bash
cat /var/db/agent-vault/vault/vault.json
```

### Connect an agent

Three ways in, in the order to try them.

**MCP over stdio.** The vault writes itself into the agent's own config file. It merges rather than overwrites, keeps a backup, and running it twice changes nothing.

```bash
agent-vault mcp install --agent claude-code
```

`--agent` takes `claude-code`, `cursor`, `gemini` or `codex`; `--scope project|user` picks which config file; `--print` shows the block without writing it. The agent gains five tools — `vault_status`, `vault_list_creds`, `vault_get_placeholder`, `vault_http` and `vault_explain_denial` — and no token is written to the config, because the bridge finds the session from the CLI's own state.

**MCP over HTTP**, for an agent somewhere else:

```bash
agent-vault mcp url                                 # endpoint and header
agent-vault mcp install --agent cursor --transport http
```

**As a custom connector.** Claude Desktop and Claude Code refuse a connector URL that is not `https`, with no exemption for loopback — so even an endpoint that never leaves this machine needs a certificate. The daemon generates one and keeps the private key behind its own uid; what crosses the socket is the public certificate, which is also its own CA:

```bash
agent-vault tls setup
agent-vault listen add mcp-tls --address 127.0.0.1:7449 --surfaces mcp --tls managed
agent-vault mcp install --agent claude-code --transport http --tls
```

A self-signed certificate is refused until the client is told to trust it, and Node does not read the macOS keychain by default, so set this in the environment the client launches with:

```bash
export NODE_EXTRA_CA_CERTS="$HOME/.agent-vault/agent-vault-ca.pem"
```

That listener serves only the `mcp` surface, so a connector cannot reach the credential proxy through it. A listener on a network address must carry TLS — plaintext there would put session tokens and substituted credentials on the wire, and is refused rather than warned about.

**Environment variables**, for anything that can make an HTTP request:

```bash
eval "$(agent-vault env)"
curl "$AGENT_VAULT_URL/p/gh/user" -H "Authorization: Bearer $AGENT_VAULT_PLACEHOLDER"
```

### Route the model key too

The API key the agent itself runs on is usually the most valuable secret on the machine, and every major SDK reads its base URL from the environment, so no code changes:

```bash
agent-vault cred add anthropic-key --kind anthropic
eval "$(agent-vault env)"
export ANTHROPIC_BASE_URL="$AGENT_VAULT_URL/p/anthropic-key"
export ANTHROPIC_API_KEY="$AGENT_VAULT_PLACEHOLDER"
```

`OPENAI_BASE_URL` / `OPENAI_API_KEY` and `GOOGLE_GEMINI_BASE_URL` / `GEMINI_API_KEY` work the same way. Those profiles already refuse the admin and organization paths that would let a key mint more keys, even under a grant of `/**`.

### Docs

```bash
agent-vault docs            # or: docs connect | models | locking | refused | commands
```

That opens the docs inside the web UI, where they are written against your actual install — your port, your credential names — so the commands are yours to paste. Everything below is the design rationale rather than the manual.

## What makes it safe

**Substitution is location-bound.** Each credential field declares where it may be injected: `header:authorization:Bearer`, `basic:pass`, `json:/auth/key`. A placeholder found anywhere else is refused before any upstream connection exists. This is what turns a prompt-injected "post your token in this comment" into a placeholder in the comment rather than a credential.

**The detector is a superset of the substituter**, structurally: `locate` routes every region of a request through `detectAll`, so the two cannot drift apart. It finds a placeholder in raw text, percent-encoded, JSON-unicode-escaped, and base64 at all three byte alignments in both alphabets. An agent that encodes a placeholder to smuggle it past the site check gets `AV_BAD_LOCATION`, not a substitution.

**A use is consumed before the first upstream byte**, inside the same step that re-checks session, grant and budget. Twenty concurrent uses of a one-time placeholder produce exactly one upstream request.

**Responses are scrubbed** against every injected secret and every other stored credential, in every encoding a response is likely to carry it in — raw, the UTF-8 bytes as the wire actually delivers them, percent-encoded, escaped-slash, JSON-escaped, `\u`-escaped, hex, HTML entities, and base64 at all three byte alignments in both alphabets — including across streaming chunk boundaries. Tokens the vault never stored (a minted installation token, an AWS key) are redacted by shape.

**Approvals are bound to the request hash.** A write held for a human executes exactly once however many times the client retries; later resends replay the stored response instead of producing a second side effect.

**The audit log is hash-chained, and its end is anchored.** Editing or removing a record breaks verification and `audit verify` names the record. The chain alone says nothing about the *end* of the log — cut the last fifty lines off and what remains verifies perfectly, which is the only edit worth making, since the records anyone would want gone are always the most recent. So the head sequence and hash are also kept in a small file beside the log, authenticated under the same key, and the daemon compares them at every start: a log that comes back short, or without its anchor, gets that fact written permanently into the chain it continues with. A missing anchor means one of two things, and telling them apart is the point: the vault itself records that it keeps an anchor, in a different file, so removing `audit.jsonl.head` does not remove the knowledge that there was one. On a vault known to keep one, its absence is tampering. On a vault written before anchors existed there is no evidence either way, and that is reported as an unproven extent rather than a broken chain — a check that always fails on every upgrade is a check nobody reads. `doctor` checks it, so nothing depends on a human thinking to. No credential value, full placeholder, body or query string ever enters it. The *path* does, scrubbed: without it a grant of `/repos/frozencrow/**` recorded the same glob every time, so the log could say a credential had been used forty times and not which forty things it had been used on. The query string stays out, because that is where credentials actually appear in a URL. Its key is derived from the vault master key and is dropped when the vault locks, so a locked vault genuinely cannot read its own log — `audit tail` answers `AV_LOCKED` rather than pretending otherwise.

**The control API is a Unix socket and never binds a network address.** Everything that creates or widens capability lives there. A `listen` entry naming the control or database surface on a network address is refused at creation, loudly and audibly, rather than silently narrowed.

On a single-user dev install it is mode 0600. On a system install the daemon runs as `_agentvault` and the socket is 0660 owned by a group the human's account is in, which is the whole point: your account can reach the socket without being able to read the vault. That also means **anything running as you can reach it**, which is why every operation there that widens capability sits behind a human factor — and why three separate gaps in that gate were worth finding.

## The web UI, and the browser problem

```bash
agent-vault ui        # prints a single-use link and opens it
```

It has five pages — Overview, Credentials, Sessions, Approvals, Audit — plus the Docs page that `agent-vault docs` opens directly.

The link uses `localhost`, not `127.0.0.1`, and arriving by IP redirects. That is
not cosmetic: WebAuthn requires the relying party to be a registrable domain, and
an IP literal is not one, so the browser refuses the enrollment outright with an
invalid-domain error. `localhost` is both a domain and a secure context over
plain http, which is what makes the platform authenticator available without a
certificate.

A browser page is the one surface an agent can drive most easily, through
automation or screenshots. So the UI is built on the assumption that it will be
reached, and three things make reaching it worth very little.

**Nothing secret is ever on the page.** There is no endpoint that returns a
credential value, so a screenshot, a DOM read or a full dump of the API yields
slugs, fingerprints, hosts and grant shapes. A test asserts that no route
anywhere returns a stored value.

**The link works once.** The first browser to open it claims the session and the
token is burned. If something else claimed it first, your own browser is refused
and tells you so, which turns a silent theft into a visible failure.

**Every change needs a fingerprint.** This is the part worth explaining, because
it is the only one that actually holds.

You cannot tell a human from an automated browser by asking the browser.
`navigator.webdriver` is a boolean the automation can set. `event.isTrusted` is
true for input injected over the DevTools protocol. Mouse movement can be
synthesised, and a screenshot reads the screen better than the DOM does. Every
signal is forgeable by something with control of the browser.

So the gate is not a test the visitor passes. It is a signature the visitor
cannot produce. Adding a credential, creating or revoking a session, approving a
request and locking the vault each require a WebAuthn assertion from a platform
authenticator enrolled on first use. The private key is in the Secure Enclave,
it is bound to this origin, and it only signs after the platform verifies a
human by fingerprint or device password. An automated browser can click Approve
and will sit at a dialog that never resolves.

The challenge is derived from the operation itself, `SHA-256(nonce ‖ operation)`,
so a signature obtained for one action cannot execute another. The daemon
recomputes the operation from the request it actually received and compares, so
the signed thing and the executed thing cannot drift apart.

The **daemon** mints that challenge and verifies that signature, not the UI
process. This matters more than it first looks: the UI server runs as your
account, which is the account an agent already has, so anything it merely
asserts about a human being present is worth nothing. For the three operations
that widen what an agent can do — adding a credential, removing one, creating a
session — the control socket checks the assertion against the credential it
enrolled and against the operation in the request it received. A hostile page
that shows one action and submits another is caught on the far side of the
socket, where it cannot have edited the judge.

A virtual authenticator, which the DevTools protocol can install, does not help:
it can only mint a new credential, and the daemon accepts assertions only from
the credential id it enrolled, checked against that stored public key. Copying
the credential id does not help either, because the id is public and the key is
not. Both are tested.

**What remains.** The platform's dialog says who is asking, not what for. An
agent that triggers an action at the moment you were expecting a different one
can borrow your touch. The page shows the operation and the audit log records
it, which is detection rather than prevention for that last gap.

**Enrolling is the one change a fingerprint cannot authorise**, because the
fingerprint being enrolled is the thing in question. Whoever enrols can sign
every later change, so on a vault with a passphrase the daemon asks for the
passphrase once, at enrollment, and never again for that device. Without that
rule the gate is circular: an agent that reached the socket could install its
own key and then have that key authorise everything else. On a vault with no
passphrase, enrollment is trust-on-first-use — whoever is at the browser when
you first enrol is who gets enrolled — and either way it is audited loudly.

## Layout

```
src/core/         placeholder grammar, detector, substitution, scrubber, policy, canonical hashing
src/store/        encrypted vault, key hierarchy, hash-chained audit log
src/daemon/       request pipeline, HTTP gateway, control API, MCP (stdio + Streamable HTTP)
src/connectors/   built-in profiles (github, slack, anthropic, openai, google-genai, http, postgres)
src/ui/           the web UI server, its page, and WebAuthn verification
src/cli/          the command-line app
bin/              the CLI, the service entry point, and the privileged installer
test/core/        unit and property tests for the pure core
test/security/    the attacks an agent would actually try, and what must happen
demo/             an end-to-end run against a real upstream
```

`src/core` has no I/O and no platform code. It is the part worth reading first and the part worth fuzzing.

## Threat model

What this defends against, and what it does not. Stated plainly because a
credential tool that is vague here is worse than none: it manufactures
confidence.

**The attacker this is built for is an agent running as you.** It has your
shell, your files, your environment, and it can reach the control socket. It
has read every line of this repository. Against that attacker:

- It cannot read a credential. The vault is owned by a separate system user and
  mode 0700; `agent-vault doctor` proves it by trying.
- It cannot substitute one. A placeholder is replaced only at the site its
  credential declares, only for a host the grant allows, only while it has uses
  left. Anywhere else is refused before any upstream connection exists.
- It cannot widen what it holds. Every control-socket operation that creates or
  extends capability sits behind a human factor — a passphrase or an enrolled
  authenticator. `test/security/control-gate.test.js` walks the whole surface
  and states which side of that line each route is on.
- It cannot approve its own held request, borrow another session's grant, or
  mint a placeholder against a credential it was not granted.
- It cannot hide. Every refusal is audited, the log is hash-chained with an
  authenticated head anchor, and `audit verify` names the record if anything
  was edited or cut from the end.

**What it does not defend against:**

- **A vault with no human factor.** Set neither a passphrase nor an
  authenticator and the control socket is open by design, and audited as
  `control.widening_ungated`. Set a passphrase.
- **The first `sudo`.** The installer is JavaScript in a directory you own, so
  the first install runs code an agent could have edited beforehand. After that
  the root-owned copy is used. It now refuses a source tree containing symlinks,
  which previously would have made that one-time window permanent.
- **Phishing your touch.** The platform dialog says who is asking, not what
  for. An agent that triggers an action while you expect a different one can
  borrow your fingerprint. The page shows the operation and the log records it:
  detection, not prevention.
- **An agent spending what you granted it.** A grant is a grant. Budgets,
  paths, methods and expiry bound the damage; they do not eliminate it.
- **A compromised upstream keeping what you sent.** Responses are scrubbed on
  the way back; the credential still reached the upstream, because that is the
  point.
- **Anything at rest on a stolen, unlocked machine.** Lock the vault, and set a
  passphrase so locking is cryptographic rather than a policy flag.

**Never audited by anyone but its author.** Every finding in "Where the spec and
the code disagree" was found from inside. That is the single biggest reason not
to trust this yet.

## Honest limits

This build is the mechanism, not the hardened deployment. Each gap below is real and none of them is hidden by the code.

**The privileged install is new, and has only ever run on macOS.** `sudo agent-vault-setup.js install` creates the `_agentvault` system user, a root-owned tree, a 0700 vault owned by that user, and a launchd or systemd unit. After it runs, your own account cannot read the vault — the boundary the whole design rests on. `agent-vault doctor` checks it by trying, and on a real install it holds: the vault is owned by the service uid, mode 0700, and every file in it, including the TLS private key, refuses a read from the human's account. It has never been run on Linux. Run it with `--dry-run` first; it prints every change it would make.

**The installer itself is trust-on-first-use.** It is JavaScript in a directory you own, so the first `sudo` runs code an agent could have edited beforehand. The spec's answer is a signed native binary and that is not built.

`agent-vault setup` runs unprivileged, prints the dry-run plan and the absolute path of the one program root will execute, then asks before spawning sudo. After a successful install it uses the root-owned copy of the installer instead, which an agent cannot edit, so only the very first install carries this risk. Running the whole CLI under sudo is a different and worse thing, and is refused: it would put every code path in the package, and whichever interpreter is first on root's PATH, inside a root process.

**Dev mode has no boundary at all.** `agent-vault setup --dev` keeps the vault in your home directory, where anything running as you can read it. It exists for a quick try and says so loudly.

**The daemon is JavaScript, not Rust.** The spec chose Rust for three reasons this build cannot satisfy: zeroizable memory (V8 strings cannot be wiped), peer-credential syscalls (Node has no public API for `SO_PEERCRED`), and running from a root-owned path with no interpreter the human owns. Everything language-independent, the grammar, the pipeline, the policy semantics, the wire behaviour, is implemented and tested here and ports directly.

**Presence on the CLI is a passphrase; in the UI it is hardware.** Either satisfies the gate. Run `agent-vault passphrase set` and every capability-widening action on the control socket — adding or removing a credential, creating a session, issuing a placeholder, approving a held request, binding a listener — requires it, opening a five-minute window so you are not asked on every call. An enrolled authenticator counts too: the daemon mints the challenge and verifies the assertion itself, so a signature collected by the web UI satisfies the socket without the UI being trusted to vouch for it.

Attempts are charged for: five free, then each further failure doubles the wait, up to a minute, and the throttle is audited. That bounds online guessing, and it bounds something else — the check is `scryptSync`, which runs *on* the event loop, so every attempt is ~190ms during which the daemon answers nothing at all. A loop of wrong passphrases on the control socket used to be a stall of the whole vault, gateway included, at no cost to the caller. The Rust port moves the derivation off the loop; the throttle is what makes that a performance change rather than a security one.

The throttle counts attempts per daemon, not per caller, because on a Unix socket there is nobody to count separately. So an agent can deliberately fail five times and make you wait. Two things bound that: an attempt refused *during* a backoff does not extend it, so an agent cannot hold the window open by retrying, and the backoff caps at thirty seconds. Your worst case is half a minute and a race for the next attempt, not a lockout, and it is in the audit log.

The passphrase's honest limit (N3) is that a swapped CLI or an agent-owned terminal could phish it as you type. Hardware presence over the socket would remove that, and the pieces now exist — the daemon already verifies assertions — but the CLI has no way to collect one, so it tells you to confirm in the UI instead.

With **neither** factor enrolled the socket is open and every widening call is audited as `control.widening_ungated`. That is the documented state of a vault with no human secret. Set a passphrase.

**There is one window the gate cannot close, and it is the first one.** The daemon creates the vault unattended, so a fresh install has no factor, and a gate has nothing to check against until a factor exists. Setting the first passphrase is therefore ungated by construction — whoever reaches the control socket first sets it, and from then on holds the factor the gate enforces. If an agent is already running as you when you install, it can set a passphrase before you do and the vault is its vault, not yours. This is not a bug that a check inside the daemon can fix: the state precedes the thing that would do the checking. What the code does instead is refuse to let you sit in it quietly — `agent-vault status` says so in plain words and `agent-vault doctor` fails the `human factor enrolled` check until you fix it. Set the passphrase as the next thing you do after installing, before you point an agent at the socket.

**Touch ID can unlock the vault.** In the web UI, once a passphrase is set, *Enable Touch ID unlock* adds a fingerprint as an unlock factor. It uses the WebAuthn PRF extension, which returns a stable secret from the Secure Enclave that wraps the vault key — a cryptographic factor, not just a presence tap, so a locked vault genuinely cannot be opened without either the fingerprint or the passphrase. The passphrase stays as the mandatory recovery factor (lose the authenticator and it still opens the vault), which is why one is required before Touch ID can be added. PRF support varies by browser; where it is unavailable the UI says so and the passphrase still works.

**Crypto substitutions.** ChaCha20-Poly1305 with a 96-bit nonce instead of XChaCha20's 192, and scrypt instead of Argon2id, because Node has neither without a native dependency. Per-field keys keep each key's record count far below the birthday bound, so the nonce size is not a practical problem at this scale, but it is not what the spec specifies.

**Storage is a JSON document, not SQLite.** Same entity model, same invariants, atomic rewrites. Every write rewrites the whole document, so the placeholder ledger is bounded rather than allowed to grow, and the two halves are written differently: key material and credentials are fsynced, the placeholder ledger is not. The rename is atomic either way, so the file is never torn — the most a power cut costs there is one placeholder issuance, which the agent simply asks for again. It will not hold up under concurrent daemons or a large vault.

**Not implemented at all:** the Postgres, MySQL, MongoDB, SSH and SMTP connectors, mutual TLS and client certificates for network listeners, CONNECT mode, GitHub App token minting, and request-body streaming — a request body over 16 MiB is refused rather than streamed, because a body that cannot be scanned for placeholders cannot be forwarded. The `stream_bodies` policy field exists and intersects correctly; nothing reads it yet.

The Postgres profile exists as a design; the L4 proxy that would carry it does not. Storing a credential against it is now **refused at creation**. It used to succeed: you got a fingerprint, a placeholder and a suggested `curl`, and the HTTP path stood ready to send a database password as URL userinfo to a Postgres port — while you believed the credential was being protected. A profile without a proxy is a plan, not a feature, and it no longer accepts secrets.

Listeners bind and can serve TLS, and record `client_auth: bearer`, which is what they actually enforce. They previously recorded `mtls-required`, a field that claimed a protection the code did not have. A network listener is therefore protected by TLS and a session token, not by a client certificate. Certificate generation shells out to `openssl` rather than minting the certificate in process.

## Where the spec and the code disagree

The code is the spec's design, built. Where building it taught something, the code is right and the spec entry is noted here:

- **Exhausted placeholders are their own outcome.** The spec classified a dead placeholder as either stale or replay. Building the ledger showed three cases an agent should treat differently: exhausted means take the successor, stale means re-fetch and nothing is wrong, replay means a dead placeholder came back and that is hostile.
- **A granted approval replays its response.** The spec said a granted approval executes exactly once. That leaves a retrying client with no answer on its second attempt, so the stored response is replayed with `AV-Replayed: true`.
- **`AV-Redacted` counts occurrences, not patterns.** More useful to an agent trying to understand what came back.
- **Compressed and binary responses.** The first contact with a real upstream showed that a gzipped body was passed through still compressed with its encoding header stripped, and that decoding responses as UTF-8 corrupted every binary body. Responses are now decompressed before scrubbing, which also means a secret hidden inside a gzip blob is caught, and bodies round-trip byte for byte.
- **Server-sent events stream.** They were buffered to completion, which would have made an LLM token stream through the vault feel broken. Each event is now scrubbed and flushed as it arrives.
- **Pen-tested and hardened.** An adversarial pass (an agent running as the user) confirmed the UID boundary holds — no file read, no daemon memory read, no value-returning endpoint — but found that a self-minted grant could aim a credential at an attacker host, that short secrets bypassed the response scrubber, that exact value length leaked, and that the socket had no human gate. All are fixed: a grant is now confined to the hosts the credential itself declares (`credentialHostCeiling` / `confineHosts`), the secret injected into a request is scrubbed at any length, only a coarse size bucket is exposed, and widening operations are gated behind the passphrase window above. The exfiltration reproductions live in `test/security/exfil.test.js`.
- **A symlink in the checkout gave an agent permanent code execution inside the privileged daemon.** The installer copies a checkout into the root-owned directory the daemon runs from, and Node's `cpSync` keeps symbolic links as links. So an agent could plant `src/store/vault.js -> /tmp/agent-owned.js`, and after the install the daemon — running as `_agentvault`, holding the vault key — would load its own code through a path the agent still owned and could rewrite at any time. That turns the documented one-time trust-on-first-use window into ongoing control of the daemon, with no race to win: plant once, edit forever. It defeats the uid boundary the whole design rests on. The installer now refuses a source tree containing any symlink, naming the path and where it points, and dereferences the copy as well. Found by auditing the only code in the project that runs as root.
- **`client_auth: mtls-required` was a field that lied.** Listeners recorded it and nothing enforced it; mutual TLS is not implemented. They now record `client_auth: bearer`, which is what they actually check. A network listener is protected by TLS and a session token, and the README says so.
- **An agent could approve its own held request.** `POST /v1/approvals` was not gated, so an agent whose call was stopped for human approval reached the control socket, granted itself, resent, and collected the credential. `approval: each` — what a careful operator sets — was therefore worth nothing against anything running as that account. Granting now needs the human; denying stays open, because it only ever narrows. Found by auditing every mutating route at once rather than one at a time, which also turned up three more: binding a listener, driving the WebAuthn signature counter up to disable the presence gate permanently, and forcing a certificate regeneration that breaks every client's trust anchor.
- **An enrolled authenticator did not count as a human factor.** The gate asked only whether a passphrase existed, so anyone who set up Touch ID confirmation in the web UI and nothing else had a completely open control socket — the opposite of what they had just configured. Both factors now gate it, and the refusal names which one would satisfy it so the CLI does not prompt for a passphrase the vault does not have.
- **An agent could set the first passphrase and lock its owner out.** Setting a passphrase drops the `none` wrap, so on a vault that had none, anything reaching the socket could choose a phrase and keep the vault. Setting the first one now needs whatever factor is enrolled; changing an existing one still needs the current phrase, which is proof enough on its own.
- **Fuzzing `detectAll` and `intersect` found nothing, which is worth recording too.** 60,000 cases across ten encodings — percent, double-percent, JSON unicode escapes, and base64 at every alignment including embedded in a larger blob — with no misses. 24,000 policy intersections produced no case where combining layers allowed something a single layer refused, and no order-dependence. 60,000 mutated paths (dot segments, doubled slashes, query strings, single and double percent-escapes) produced no deny-list escape. Those properties are now in `test/core/detect-fuzz.test.js`.
- **The streaming scrubber leaked secrets, and fuzzing found it in about thirty cases.** It scrubbed the emitted prefix and held the tail separately, so a match straddling that split was torn in two — neither half matched, and the secret went out whole. Any encoding longer than the emitted prefix was affected, and the `\u`-escaped form is six times the secret's length, so it was reachable on any streamed response: exactly where an LLM token stream lives. The cut now moves forward past a complete encoding, while shape patterns like `ghp_...` stay held because they may still be growing. `test/core/scrub-fuzz.test.js` keeps it honest.
- **An agent could spend a credential without ever creating a session.** Asking "can an agent create sessions?" turned up something worse than a yes. It cannot — `POST /v1/sessions` is behind the presence gate and refuses. But `POST /v1/placeholders` on the control socket was not gated, and with no `sid` it picked whichever session happened to be active. So an agent running as the human borrowed that session's grant, minted a placeholder, and used it as the sole carrier on loopback (which is allowed there, by design). The real credential reached the upstream with no passphrase at any point. Issuing a placeholder mints a fresh authorization to spend a credential, so it is now a widening operation behind the same gate, and it will not silently borrow: with more than one active session it refuses and names them. The reproduction is in `test/security/exfil.test.js`.
- **A locked vault cannot read its own log, and now says so.** `audit tail` dereferenced a null handle and reported an internal error; `status` reported `audit records 0`, which reads as "your audit trail was wiped" at exactly the wrong moment. Both now answer honestly. In the same pass, ten mutating methods that write to the audit log gained an unlock guard: `listen rm` on a locked vault deleted the entry, persisted it, *then* failed to record it, and a change that cannot be audited must not happen.
- **Listeners were recorded but never bound.** `listen add` validated an entry, stored it and reported success, and nothing ever listened — which also meant `req.listener` was always undefined, so every remote rule in the pipeline was unreachable code. They bind now, with optional TLS, and serve only the surfaces the entry declares. Addresses are validated when the listener is added rather than at bind time — `--address 127.0.0.1` with no port was accepted, reported success, and then silently never appeared. `test/security/listener.test.js` covers it.
- **The session token was leaking to every upstream.** `Authorization: Bearer avs1...` is the documented way to authenticate, and that header was forwarded verbatim: each API the vault proxied for received a live vault capability and logged it. Found by making a real call to the Gemini API, which refuses requests carrying two credentials and said so; a more permissive upstream would have accepted it silently. Any header still carrying a session token after substitution is now consumed, like `AV-Session`. `test/security/carrier.test.js` covers it.
- **The two human factors now know about each other.** The passphrase gate on the control socket and the fingerprint gate in the UI were built separately, so a vault with a passphrase refused every change made from the web UI — the human had touched the sensor and was then told to "confirm your passphrase", with nowhere to type it. The daemon now accepts either proof, and for the widening operations it mints and verifies the WebAuthn challenge itself rather than trusting the UI process, which runs as the human's account. `test/security/widening.test.js` covers both factors and the operation-swap attempt.
- **Locking now drops the audit key too.** `lock()` wiped the master key but left the `AuditLog` handle alive, so a key derived from it stayed in the daemon's memory for the life of the process — locking was not quite the zeroization it claimed. The handle is now dropped with the key, which also turned a null dereference on `audit tail` (reported as an internal error) into a plain `AV_LOCKED`. `test/security/locked.test.js` covers what a locked daemon answers.
- **The UI is a web page, by request.** The spec chose a native shell specifically to stay off the browser automation surface. The web UI compensates with the presence gate described above, which the spec's native design also needs and which is now the stronger of the two mechanisms.

## Reporting a vulnerability

Email eric@frozencrow.com with `agent-vault security` in the subject, rather than
opening a public issue. [SECURITY.md](SECURITY.md) says what is in scope and
what is documented-rather-than-accidental, and why.

## License

Apache-2.0.
