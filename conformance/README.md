# Conformance

Black-box checks both implementations must pass. The tests talk to a daemon through its control socket, its gateway, MCP, the CLI, and the UI server. Nothing here imports `src/`.

## Which implementation

`AV_IMPL` selects the binaries.

- Unset or `js` runs `bin/agent-vault-daemon.js` and `bin/agent-vault.js` under Node.
- `rust` runs `rust/target/debug/agent-vault-daemon` and `rust/target/debug/agent-vault`.

When those Rust binaries are missing, `AV_IMPL=rust` skips the suite and exits 0. Set `AV_REQUIRE_IMPL=1` to make that absence a failure instead of a skip. The error names the two binaries. Use that for an acceptance gate, so a run cannot pass by skipping. `AV_IMPL=js` (or unset) still runs when the flag is set, because those binaries are the Node scripts in this tree.

## UI

The suite starts the UI the way an operator does: `agent-vault ui`. That CLI process serves the files built in `src/ui/dist`. The daemon does not serve the UI, and `web/dist` is not used.

## Run

`npm run conformance` runs `conformance/*.test.js`. Each file starts its own daemon on an ephemeral port and deletes its temp directory afterwards. Do not point it at `/var/db/agent-vault`.
