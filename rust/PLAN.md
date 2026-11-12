# agent-vault: Rust + SQLite port — plan and contract

Change `rust-port` · Monogit-Change-Id `01M76BAS5P1GZV318KZCFMD5AY`

This file is the contract every worker builds against. Only the coordinator
edits it. If something here is wrong or missing, ask the coordinator; do not
work around it.

## Goal

Replace the Node.js implementation with Rust, and the `vault.json` store with
SQLite, **without changing anything a caller can observe** except what is
listed under "Intended changes". Add `agent-vault migrate`, which converts an
existing JSON vault into the new one.

The JavaScript in `src/`, `bin/` and `test/` is the **reference
implementation**. When this file does not say how something behaves, the
JavaScript decides. Since the cutover (0.3.0) it lives, frozen, in
`legacy/js` as the test reference.

## Branches

- `rust-port` is the integration branch (this file lives on it).
- Each piece works on `rust-port-<piece>` in its own Orca worktree, based on
  `rust-port`, and opens a **draft PR into `rust-port`**. Never push to `main`
  or merge anything.
- Every commit ends with:
  ```
  Monogit-Change-Id: 01M76BAS5P1GZV318KZCFMD5AY
  Monogit-Repos: agent-vault
  ```

## Frozen external contract (must not change)

1. **Control API** on the Unix socket: every route in `#onControl`
   (`src/daemon/server.js`), the same JSON request and response shapes, the
   same HTTP status codes, and the same `AV_*` error codes, `rule`, `hint` and
   `next` fields (`src/core/errors.js`).
2. **Gateway**: `/p/<slug>/...`, `/v1/status`, `/v1/preflight`,
   `/v1/session`, `/v1/credentials`, `/v1/placeholders`, the `AV-Session`
   header, Streamable HTTP MCP at `/mcp`, listeners and TLS.
3. **MCP**: the same tool names, input schemas, descriptions and server
   instructions (`src/daemon/mcp.js`), over stdio (the `agent-vault mcp`
   bridge) and Streamable HTTP.
4. **CLI**: the same commands, flags, exit codes (`EXIT` in
   `src/cli/index.js`), `--json` envelopes (`{ok, data}` / `{ok:false,
   error:{message,next}}`) and the wording of human output where tests check
   it. Both `agent-vault` and `av` names.
5. **Web UI**: the React app in `web/` is not ported. As today, the UI is
   served by the **`agent-vault ui` CLI process** (running as the human's
   account), not by the daemon; it talks to the daemon over the control
   socket. The built files are Vite's output in `src/ui/dist` (not
   `web/dist`); the Rust `agent-vault` binary **embeds them at compile time**,
   so the install needs no separate UI directory. Same API, headers, cookies,
   CSP, file allowlist, Host/Origin checks and WebAuthn op-gate. The UI server
   code lives in av-daemon as a library; av-cli's `ui` command runs it.
6. **Install layout and environment**: `/var/db/agent-vault/{app,run,vault,
   runtime}`, the `_agentvault` user and `_agentvault_users` group, the
   launchd label, and these variables with the same meaning:
   `AGENT_VAULT_DIR AV_VAULT_DIR AV_RUN_DIR AV_PORT AGENT_VAULT_PORT
   AGENT_VAULT_SESSION AV_ENROLLED_UID AV_CLIENT_GROUP AGENT_VAULT_ALLOW_ROOT
   NO_COLOR SUDO_USER SUDO_COMMAND`.
   Startup behavior the conformance harness depends on, now frozen:
   - `agent-vault-daemon` (and `agent-vault daemon`) prints
     `gateway http://127.0.0.1:<port>` on stdout once it is ready to serve.
   - `AV_PORT=0` (or `--port 0`) binds an ephemeral port, and the printed
     port is the one actually bound.
   - First start in an empty vault dir creates an unlocked vault with no
     unlock factor (as `bin/agent-vault-daemon.js` does in dev mode).
   - When stdin is not a TTY, the CLI reads secrets from it one line per
     prompt (`cred add`, `cred rotate`, `notify set`, `passphrase set`,
     `unlock`, `backup export`, and any other prompt).
7. **Placeholders and tokens**: same grammar, checksum and encodings
   (`src/core/placeholder.js`, `src/core/base32.js`). A placeholder or session
   token minted by the JS daemon must verify in the Rust daemon after
   `migrate`.
8. **Audit log semantics**: hash chain, authenticated head anchor, witness
   checkpoints, record kinds and fields (`src/store/audit.js`).
9. **Backups**: the Rust daemon must **restore** backups made by the JS daemon
   (format and version as in `src/store/backup.js`, scrypt N=131072 r=8 p=1,
   ChaCha20-Poly1305). New backups may use a new version (see below).

## Known JavaScript quirks the port keeps

The conformance worker listed eight places where today's CLI or control API
does not follow its own `--json` envelope, or refuses in a surprising way
(`conformance/QUESTIONS.md`): `passphrase set/remove --json`, `daemon
--json`, `setup --dev --json` on create, `exec --json`, `preflight --json`
exit codes, `backup export` on a pipe, `cred test` single vs `--all`, and
`POST /v1/sessions` with `{}` / rotating to the same value. A ninth, found by
the scaffold: the JS CLI **ignores unknown flags** on every command outside its
`knownFlags` set (`status --frob` runs normally), while clap refuses them; the
Rust CLI must accept and ignore them on exactly those commands. A tenth,
pinned by the conformance suite: when a request carries **two
`Authorization` headers**, Node keeps only the first, so the gateway sees just
that one (401 `AV_SESSION_REQUIRED`, rule `no_placeholder`, when the first is
not a session token). hyper keeps both; the Rust gateway must read only the
first value of `Authorization` and must never substitute into, forward, or
match against the second. **The port
reproduces all of them exactly.** Fixing them is a separate change after the
port, so the conformance suite stays a pure equivalence check.

## Intended changes

- **Storage**: SQLite, not `vault.json`.
- **Crypto**: XChaCha20-Poly1305 instead of ChaCha20-Poly1305; Argon2id
  instead of scrypt for the passphrase factor and for new backups.
- **Memory hygiene**: key material zeroized after use; the VMK held in
  `mlock`ed memory.
- **No Node runtime**: the install ships Rust binaries; `runtime/` holds no
  Node.
- **History pruning**: revoked or expired sessions and their grants are
  deleted after a retention window (default 30 days, setting
  `retention_days`). The audit log keeps their history, and each pruning
  pass writes one new audit record, `history.pruned`
  `{sessions, grants, placeholders, retention_days}`.
- **Audit storage**: audit records live in an insert-only `audit` table in
  `vault.db`, written in the same transaction as the change they record; the
  authenticated head anchor stays a separate file, `vault.db.head`.
- **Custom scrub patterns fail closed on non-BMP repetition.** JavaScript
  (without the `u` flag) counts a repetition such as `\S{253}` or
  `[^Q]{0,256}` in UTF-16 code units, the Rust `regex` crate in scalars, so
  the two disagree on emoji. Rather than match differently, `jsre` refuses a
  custom scrub pattern that repeats an atom able to match a non-BMP character
  (negated classes, `\S`, `\W`, `\D`, `.`, astral literals), with the same
  invalid-pattern refusal the JS gives. BMP-only repetitions (`\d{4}`,
  `[A-Za-z]{8}`) still work. The JS test case that accepts such patterns is
  ported with the Rust refusal as the expected result.
- **Panics unwind, and a handler fault costs one request.** The release
  profile uses `panic = "unwind"` (the default), not `abort`. Every request
  and connection handler runs under a guard that mirrors the JS `#guard`: a
  panic or an unexpected non-`VaultError` failure writes the audit record
  `daemon.handler_error` `{error: <class>}` (never the message) and answers
  500 `application/problem+json`
  `{code: "AV_INTERNAL", detail: "the request could not be handled"}`, or
  ends the response if headers were sent. Unwinding also runs the zeroizing
  drops that `abort` would skip. `daemon.uncaught` (the JS process-wide
  handler) has no Rust counterpart and stays not applicable.
- **`agent-vault help` lists `migrate`.** The help text is otherwise the
  JS text byte for byte; the one added line under "setup" names the new
  command so an upgrading user can find it.
- README "Honest limits" is updated to match.

## Layout and ownership

One owner per file. Edit only what your piece owns.

| Path | Owner |
|---|---|
| `rust/Cargo.toml`, `rust/rust-toolchain.toml`, `rust/deny.toml`, `.github/workflows/rust.yml`, `rust/xtask/` | scaffold |
| `rust/crates/av-core/` | scaffold writes signatures, then **core** owns it |
| `rust/crates/av-store/` | scaffold writes signatures and schema, then **store** owns it |
| `rust/crates/av-daemon/` | scaffold writes the skeleton, then **daemon** owns it |
| `rust/crates/av-cli/` (bins `agent-vault`, `agent-vault-setup`) | scaffold writes the skeleton, then **cli** owns it |
| `conformance/` | conformance |
| `rust/PLAN.md` | coordinator only |
| `src/`, `bin/`, `test/`, `web/` (JavaScript) | nobody: read-only reference |

Binaries: `agent-vault` (CLI, including `mcp` and `migrate`; `av` is an alias
installed by the setup), `agent-vault-daemon`, `agent-vault-setup`.

### Module map (JS → Rust)

| JavaScript | Rust crate |
|---|---|
| `src/core/*` (placeholder, base32, canon, detect, scrub, substitute, sites, policy, payload, request-view, model-usage, errors) | av-core |
| `src/store/*` (crypto, vault, audit, backup, activity, ids), `src/pending.js`, `src/client-state.js` | av-store |
| `src/daemon/*`, `src/ui/server.js`, `src/ui/webauthn.js`, `src/ui/list-paging.js`, `src/connectors/*` | av-daemon |
| The pure, I/O-free parts that the store needs: `src/connectors/profiles.js` (`PROFILES`, `getProfile`, `listProfiles`, `defaultSites`, `defaultField`, `extractHealth`) → `av_core::profiles`; from `src/connectors/pinning.js` (`PIN_RE`, `pinListState`, `urlHostOf`, `hostHeaderMatches`, `pinsFor`) → `av_core::pins`; from `src/ui/webauthn.js` (`canonicalOperation`, `DIGESTED`, `operationFor`, `challengeForOperation`) → `av_core::operation` | av-core (owned by core; av-daemon re-exports them and keeps the network, TLS and WebAuthn-verification parts) |
| `src/cli/*`, `bin/agent-vault.js`, `bin/agent-vault-setup.js` | av-cli |

## Dependencies

Approved crates (ask the coordinator before adding others): `tokio`, `hyper`
1.x + `hyper-util` + `http-body-util`, `rustls` + `tokio-rustls` + `rcgen`
(replaces the `openssl` subprocess), `rusqlite` with `bundled`,
`chacha20poly1305` (both `ChaCha20Poly1305` for reading legacy data and
`XChaCha20Poly1305`), `argon2`, `scrypt` (legacy only), `hkdf`, `hmac`,
`sha2`, `zeroize`, `secrecy`, `subtle`, `rand`/`getrandom`, `serde`,
`serde_json`, `base64`, `p256`/`ecdsa`, `ed25519-dalek`, `ciborium` (WebAuthn
CBOR), `libc` (`mlock`, peer credentials, uid/gid), `clap`, `rpassword`,
`regex` (only with linear-time guarantees; no backtracking), `url`, `time`,
`thiserror`, `tracing`; and, for av-daemon only, `flate2` (rust_backend),
`brotli-decompressor` (decode only), `webpki-roots`, `rustls-webpki` (the same version rustls uses, for the verified chain path pinning needs), and `x509-parser` or the
RustCrypto `x509-cert`/`spki` crates for certificate parsing (never a
hand-rolled DER parser). Response decompression keeps the JS cap of 64 MiB
(`MAX_DECOMPRESSED`), zstd stays refused, and upstream TLS trusts the Mozilla
roots plus `NODE_EXTRA_CA_CERTS`, as Node does. Dev: `proptest`, `tempfile`,
`assert_cmd`.

**JSON key order follows insertion, like JavaScript.** `serde_json` is built
with `preserve_order` (it applies to every crate). Code whose result depends
on key order (hashes, canonical forms, MAC inputs, anything compared as text)
must sort explicitly and say by what (UTF-8 bytes for `canonicalize`, UTF-16
code units for `canonical_operation`), never rely on the map's order.

**Regexes use JavaScript semantics.** The `regex` crate's `\s`, `\w`, `\d` and
`\b` are Unicode; JavaScript's are not (JS `\s` includes U+FEFF and excludes
U+0085; `\w` is `[A-Za-z0-9_]`; `\d` is `[0-9]`). Every crate compiles every
pattern through av-core's JavaScript-semantics helper (`av_core::jsre`), never
`Regex::new` directly, and each crate has a guard test for that. The core
review found three fail-opens from this (a FEFF-split placeholder undetected,
a FEFF-hidden method override, a content type metered that JS refuses).

No `unsafe` outside small, commented wrappers for `mlock` and socket peer
credentials. `#![forbid(unsafe_code)]` everywhere else.

## Storage contract (av-store)

- One SQLite file `vault.db` in the vault dir, mode `0600`, dir `0700`.
- Open with: `PRAGMA journal_mode=WAL`, `synchronous=FULL`,
  `secure_delete=ON`, `trusted_schema=OFF`, `foreign_keys=ON`,
  `cell_size_check=ON`; extension loading off.
- **One transaction per operation.** A whole control-API operation (for
  example a session with its grants and placeholders) commits once or not at
  all.
- After any change to unlock factors, VMK wraps, the WebAuthn factor, or any
  credential secret (add, rotate, delete): `PRAGMA wal_checkpoint(TRUNCATE)`
  so no old page survives in the WAL.
- **Prepared statements with bound parameters only.** No SQL text built from
  values. A test greps the crate source and fails on `format!` near SQL.
- Insert-only triggers: placeholder ledger rows can never move from a dead
  state back to `active`, with one exception that mirrors `refundPlaceholder`:
  `dead_reason='exhausted'` → `active` with `dead_reason` cleared, `uses`
  lowered by exactly one, no other column changed, and the row's grant and
  session both still `active`. Audit rows can never be updated or deleted.
- Schema versioning via a `schema_version` row; migrations are forward-only.
- The audit log may live in the same database or stay an append-only file;
  either way chain, anchor and witness semantics are unchanged.
- The factor invariant (`assertFactorInvariant` in `src/store/vault.js`) is
  enforced in one function that every factor change goes through.

## Crypto contract

- HKDF-SHA256 with the **same info labels** as `src/store/crypto.js`:
  `av/kek/v1`, `av/dek/<credId>`, `av/ph`, `av/fingerprint`, `av/audit`,
  `av/token`, `av/notify/webhook`, and AAD `av/vmk/<factor>`. So the same VMK
  gives the same placeholder, token, fingerprint and audit keys.
- Sealed value format v2: `{"v":2,"alg":"xchacha20poly1305","n":<b64 24-byte
  nonce>,"c":<b64 ciphertext+tag>}` with the same AAD strings as today.
  Readers accept the v1 (JS) format only inside `migrate` and backup restore.
- Passphrase factor: Argon2id, m = 64 MiB, t = 3, p = 1, 32-byte output,
  16-byte salt; parameters stored next to the wrap so they can be raised
  later. Verification runs off the async runtime (`spawn_blocking`), keeping
  the existing attempt throttle (5 free attempts, doubling backoff capped at
  30 s).
- Backups: restore v1 (scrypt + ChaCha20) and v2; export v2 (Argon2id
  m = 256 MiB, t = 3, p = 1, XChaCha20).
- Error `next` is **either a string or an object** exactly as the JS sends
  it (`{cli: [...], mcp: {tool, args?}}`), serialized identically; agents
  act on it. av-core's error type carries it as such.
- Tests may use cheaper Argon2id parameters under `cfg(test)` (parameters are
  stored beside each wrap, so production paths are unchanged), but at least
  one test derives with the production parameters.
- Secrets live in `Zeroizing`/`SecretBox` types; nothing that holds a secret
  implements `Debug` or `Display` with its contents. Comparisons of MACs,
  tokens and placeholders use constant-time equality.

## `agent-vault migrate` (owned by cli; store provides the library)

```
agent-vault migrate [--from <dir>] [--to <dir>] [--dry-run] [--json]
```

- `--from` defaults to the installed vault dir; `--to` defaults to the same
  dir (the new files sit beside `vault.json`).
- Steps, in order, stopping at the first failure with nothing written:
  1. Refuse if `vault.db` already exists at the target (re-running after a
     completed migration says so and exits 0).
  2. Refuse if the JS daemon is running against `--from`; say how to stop it.
  3. Read `vault.json`, the device key and the audit log. Verify the audit
     chain and anchor; refuse on any break and print where.
  4. Unlock with the passphrase (prompted; never an argument), or the device
     key alone for a factor-`none` vault. Keep the **same VMK**.
  5. Re-wrap the VMK under Argon2id; re-seal every credential field and
     sealed setting (webhook URL, etc.) as v2.
  6. Copy every entity (credentials, sessions, grants, placeholders,
     approvals, workspaces, listeners, templates, clients, settings, presence
     factors, pins, tripwires, notify) with ids unchanged.
  7. Import the audit log unchanged, then append a `vault.migrated` record
     whose `prev` is the old head hash, so `audit verify` covers the whole
     history.
  8. Write everything in one SQLite transaction to a temp file, fsync, then
     rename to `vault.db`.
  9. Leave `vault.json` and the old audit files untouched and say where they
     are and how to delete them once satisfied.
- A Touch ID / WebAuthn **PRF unlock wrap cannot be migrated** (it needs the
  authenticator). Drop it, keep the passphrase factor, and print the command
  to re-enroll. WebAuthn **presence** credentials (public keys) do migrate.
- `--dry-run` does steps 1–7 in memory and prints counts per entity, the
  audit range, and what would be dropped. Writes nothing.
- `--json` prints the same report as data.
- Tests: a JS-created fixture vault (made by running the JS code in a temp dir
  at test time, never the real vault) migrates; placeholders and session
  tokens minted before migration still work after; a tampered audit log is
  refused; a second run is a no-op; dry-run writes nothing.

## Tests and the regression net

- Each piece **ports the JavaScript tests that cover its modules** to Rust
  tests in its crate, and keeps a table `rust/crates/<crate>/PORTED.md`: JS
  test file and test name → Rust test, or "covered by conformance", or "not
  applicable, because …". Every JS test name must appear.
- Security tests are written as **hardening regression tests**: named input
  shapes, each with an ordinary-traffic control, asserting the secret never
  reaches the agent or a log.
- **Mutation check**: `test/mutation-check.js` lists the protections that
  must be caught. Each piece reproduces the ones in its modules as entries in
  `rust/crates/<crate>/mutations.toml` (file, exact `from` text, `to` text,
  name). Scaffold provides `cargo xtask mutation`, which applies each in turn
  on a copy of the tree and requires `cargo test` to fail.
- `conformance/` is the black-box suite. It drives only the control socket,
  the gateway, MCP and the CLI. It runs against the JS daemon (`npm run
  conformance`) and against the Rust binaries (`AV_IMPL=rust npm run
  conformance`). Every acceptance gate on the Rust binaries runs with
  `AV_REQUIRE_IMPL=1`, which fails instead of skipping when a binary is
  missing.

## Safety rules for every worker

- Never touch the real vault, `/var/db/agent-vault`, or the installed daemon,
  and never use `sudo`. Every test uses a temp dir and its own daemon in dev
  mode (`AGENT_VAULT_DIR=<tmp>`).
- **Never import `test/mutation-check.js`, and never run a bare `node --test`
  or `npm run test:mutation` in your worktree.** It rewrites `src/` while it
  runs. Run JS tests with `npm test` only.
- The machine is short on memory. Build with `CARGO_BUILD_JOBS=2`, and do not
  run more than one `cargo` build at a time in your worktree.
- No secrets in code, fixtures, commits or messages. Fixture credentials are
  obviously fake (`test-secret-…`).

## Waves

| Wave | Piece | Depends on |
|---|---|---|
| 0 | scaffold, conformance | none |
| 1 | core, store | scaffold |
| 2 | daemon, cli | core, store |
| — | integration (coordinator): conformance on Rust, mutation check, migrate on a copy, docs | daemon, cli |

Conformance keeps running through waves 0 and 1.

## Acceptance per piece

- **scaffold**: `cargo build --workspace` and `cargo test --workspace` pass;
  every public item that core, store, daemon and cli need is declared with
  `todo!()` bodies and doc comments naming the JS function it ports; the
  schema SQL is in `av-store`; `cargo xtask mutation` works on a sample entry;
  `.github/workflows/rust.yml` runs fmt, clippy (`-D warnings`), test and
  `cargo deny`.
- **core / store**: no `todo!()` left in the crate; `cargo test -p <crate>`
  passes; `PORTED.md` complete; `mutations.toml` entries all caught;
  `cargo clippy -p <crate> -- -D warnings` clean.
- **conformance**: passes against the JS daemon in a temp dir; covers every
  control route, the gateway, every MCP tool, every CLI command's `--json`
  shape, and the security properties named in `test/security/` that are
  observable from outside.
- **daemon / cli**: as core/store, plus `AV_IMPL=rust npm run conformance`
  passes, and `migrate` meets its test list.
