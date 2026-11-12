# agent-vault in Rust

agent-vault's implementation. [`PLAN.md`](PLAN.md) is the contract the port
was built to: what must not change, what changes on purpose. The original
JavaScript implementation is frozen in `../legacy/js` as the reference some
tests compare against (migrate builds its fixture vaults with it, and a few
core tests diff against it); it is never installed or run in production.

## Build and test

Everything runs from this directory. The toolchain is pinned in
`rust-toolchain.toml`; rustup installs it on first use.

```sh
cd rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check            # needs: cargo install cargo-deny
cargo xtask mutation        # see below
```

`.cargo/config.toml` limits builds to two jobs, because the development
machine is short on memory. Run one cargo command at a time per worktree.
CI (`.github/workflows/rust.yml`) runs fmt, clippy, test and deny on Linux
and macOS.

## Crate layout

| Crate | Kind | Ports | What it is |
|---|---|---|---|
| `crates/av-core` | lib | `src/core/*`, plus the pure parts of `src/connectors/profiles.js`, `src/connectors/pinning.js`, `src/ui/webauthn.js` | Placeholders, base32, canonical JSON, detection, scrubbing, substitution, sites, policy, payload rules, the error registry, and the secret-holding types (`secret`). No I/O. |
| `crates/av-store` | lib | `src/store/*`, `src/pending.js`, `src/client-state.js` | The SQLite vault (`schema`, `db`, `vault`, `model`), crypto, the audit log, backups, ids, activity reports. |
| `crates/av-daemon` | lib + bin `agent-vault-daemon` | `src/daemon/*`, `src/ui/server.js`, `src/ui/webauthn.js`, `src/ui/list-paging.js`, `src/connectors/*` | Control socket, gateway, MCP, the web UI server, connectors and pinning. |
| `crates/av-cli` | lib + bins `agent-vault`, `agent-vault-setup` | `src/cli/*`, `bin/agent-vault.js`, `bin/agent-vault-setup.js` | The command line (including `mcp` and `migrate`) and the installer. |
| `xtask` | bin | `test/mutation-check.js` | Workspace tasks (`cargo xtask mutation`). |

Every public item says, in its doc comment, which JS function it ports.
Dependencies come only from `[workspace.dependencies]` in `Cargo.toml`, which
is the PLAN's approved list; ask the coordinator before adding one.

`unsafe` is forbidden everywhere except two small, commented modules:
`av_store::mlock` (locking the VMK in memory) and `av_daemon::peercred`
(socket peer credentials).

## The database

`av_store::db::open` is the only way to get a connection. It creates
`vault.db` with mode `0600` and sets `journal_mode=WAL`, `synchronous=FULL`,
`secure_delete=ON`, `trusted_schema=OFF`, `foreign_keys=ON`,
`cell_size_check=ON`, defensive mode, and no extension loading, then applies
the forward-only migrations in `av_store::schema`. Triggers keep audit rows
append-only and stop a dead placeholder coming back to life (except the
one-use refund of an exhausted placeholder that `refundPlaceholder` makes).

## Mutation check

`cargo xtask mutation` is the Rust counterpart of `test/mutation-check.js`.
Each crate lists the protections its tests must catch in
`crates/<crate>/mutations.toml`:

```toml
[[mutation]]
name = "secure_delete is switched off when the vault database is opened"
file = "src/db.rs"                      # relative to the crate
from = '("secure_delete", "ON"),'       # must appear exactly once
to   = '("secure_delete", "OFF"),'
test = "db::tests::"                    # optional cargo test name filter
```

The task copies `rust/` to a temporary directory, together with the repo
inputs the tests read (`src/`, `legacy/`, `package.json`, `web/src`,
`README.md`); the working tree is never modified. It checks that the
unmutated tests pass, then applies each swap in turn and runs
`cargo test --workspace` there (only the owning crate with `--scoped`). A mutant must compile and must
make a test fail; a run that exceeds `MUTATION_TIMEOUT_SECS` (default 600)
counts as caught. It exits non-zero if any mutation survives or an entry's
`from` text no longer appears exactly once. `--only <name>` runs one entry;
`--keep` keeps the copy and the logs.

## Using the Rust build

```sh
cd rust
cargo build --release
# binaries: target/release/agent-vault, agent-vault-daemon, agent-vault-setup
```

The command line is the same as the JavaScript one (`agent-vault help`), with
one addition: `agent-vault migrate`.

### Moving an existing vault

`agent-vault migrate` converts a JavaScript vault (`vault.json` plus its
audit log) into `vault.db` beside it. Run the dry run first:

```sh
agent-vault migrate --dry-run          # counts per entity, audit range, what is dropped
agent-vault migrate                    # asks for the passphrase on the terminal
```

What it does, and what it refuses:

- It keeps the same vault master key, so placeholders and session tokens
  minted before the migration still work after it.
- It refuses while the JavaScript daemon is running against the vault; stop
  the service first.
- It verifies the old audit chain and its anchor first, and refuses on any
  break (printing where). A half-written last line is dropped, as the
  JavaScript reader drops it.
- It writes one SQLite transaction to a temporary file, then renames it to
  `vault.db`. `vault.json` and the old audit files are left untouched; delete
  them yourself once you are satisfied.
- A Touch ID / WebAuthn **unlock** wrap cannot be migrated, because it needs
  the authenticator. It is dropped and reported, with the command to
  re-enroll. WebAuthn **presence** keys do migrate.
- Running it again after it finished says so and changes nothing.

## Honest limits of the port

- **The installer is still trust-on-first-use.** The first `sudo` runs the
  `agent-vault-setup` binary you built in your checkout, which an agent
  running as you could have replaced. After that, `agent-vault upgrade`
  prints the root-owned installer, which an agent cannot edit, and it copies
  the new binaries from your checkout's `rust/target/release`. A signed
  release binary is still not built.
- **The web UI is still JavaScript in the browser.** Its built files are
  embedded in `agent-vault-daemon` at compile time. Its own tests stay in
  the JS suite, and `crates/av-daemon/tests/fixtures/ui-parity` pins what the
  browser and the Rust server must agree on.
- **Linux is tested by CI only.** The port has run end to end on macOS; the
  installer has never run as root on Linux.
- **Behavior that differs on purpose** is listed under "Intended changes" in
  [`PLAN.md`](PLAN.md); everything else is meant to match the JavaScript
  byte for byte, and the conformance suite (`AV_IMPL=rust npm run
  conformance`) checks it from outside.
