# agent-vault in Rust

The Rust + SQLite port of agent-vault. [`PLAN.md`](PLAN.md) is the contract:
what must not change, what changes on purpose, who owns which file. The
JavaScript in `src/`, `bin/` and `test/` stays the reference implementation
until the cutover.

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

The task copies `rust/` to a temporary directory (the working tree is never
modified), checks that the unmutated tests pass, then applies each swap in
turn and runs `cargo test --workspace` there. A mutant must compile and must
make a test fail; a run that exceeds `MUTATION_TIMEOUT_SECS` (default 600)
counts as caught. It exits non-zero if any mutation survives or an entry's
`from` text no longer appears exactly once. `--only <name>` runs one entry;
`--keep` keeps the copy and the logs.
