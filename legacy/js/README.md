# The JavaScript implementation (frozen)

This is agent-vault as it was written in JavaScript, up to 0.2.0. It is kept,
unchanged, as a **test reference**: nothing installs it, nothing runs it in
production, and it gets no new features or fixes.

The Rust implementation in [`../../rust`](../../rust) is agent-vault. Some of
its tests compare against this code:

- `agent-vault migrate` tests build fixture vaults with this store
  (`rust/crates/av-store/src/tests/fixtures/make-js-vault.mjs`), so migrating a
  real JavaScript vault stays tested.
- A few av-core tests diff their output against these modules.
- The CLI contract tests start this daemon to check the Rust CLI against it.
- `AV_IMPL=js npm run conformance` runs the black-box suite against it.

Its own suite still runs in CI (`npm run test:legacy`) so the reference stays
trustworthy. The changes made since it moved here:

- The UI server reads the built page from the repo's `src/ui/dist`.
- Two docs tests read the live README and docs page, which describe the Rust
  daemon. Once it gained an MCP tool (0.6.0), they stopped requiring the
  documents to count exactly this implementation's tools, and only require
  every one of its tools to be named. The Rust tests check the exact count.

Upgrading a vault this version created: see
[`rust/README.md`](../../rust/README.md#moving-an-existing-vault).
