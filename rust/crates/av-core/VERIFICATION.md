# av-core verification

Draft PR: https://github.com/CrimsonWorks-Inc/agent-vault/pull/11 (base: `rust-port`).

Commands run from `rust/`:

| Command | Result |
|---|---|
| `CARGO_BUILD_JOBS=2 cargo test -p av-core` | 65 passed, 0 failed; includes fresh JS placeholder vectors and differential fixture suites |
| `CARGO_BUILD_JOBS=2 cargo test -p xtask` | 7 passed, 0 failed |
| `CARGO_BUILD_JOBS=2 cargo clippy -p av-core -p xtask -- -D warnings` | Passed, no warnings |
| `cargo fmt --check` | Passed |
| `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo xtask mutation --scoped --keep` | 83 caught, 0 not caught; all 80 av-core entries and 3 existing store entries |

`--scoped` is the coordinator-approved opt-in acceptance mode: the baseline tests the workspace and each mutant tests its owning crate. The default mode tests the workspace for every mutant. Both command shapes have runner unit coverage; the existing filters, compile-failure detection and timeout behavior apply in either mode.

[Mutation results](MUTATION-RESULTS.txt) lists every caught entry. The av-core manifest covers all 76 `src/core/*` protections from the read-only JS mutation harness, plus structured recovery instructions, explicit-null budget rejection, paired UTF-16 escapes and tolerant base64 padding. No mutant was accepted on a timeout or a compile failure.

[PORTED.md](PORTED.md) maps 850 named JS tests in 64 relevant files. Its integration rows delegate network, store, CLI and UI behavior to conformance. Fuzz cases use proptest; security regressions include ordinary-traffic controls and bounded pathological scans. JS vector generators import only the reference modules and use fake credentials.

All scaffold bodies are implemented and the crate retains `#![forbid(unsafe_code)]`. JavaScript reference files were unchanged. The generated Cargo.lock dependency update and the opt-in xtask changes were approved by the coordinator.
