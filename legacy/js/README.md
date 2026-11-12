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
trustworthy. The one change made when it moved here: the UI server reads the
built page from the repo's `src/ui/dist`.

Upgrading a vault this version created: see
[`rust/README.md`](../../rust/README.md#moving-an-existing-vault).
