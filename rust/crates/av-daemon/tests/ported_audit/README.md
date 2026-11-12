# Source-only test inventory audit

Run from this checkout (Node provides the parser; no packages are installed):

```sh
node --expose-internals rust/crates/av-daemon/tests/ported_audit/audit.cjs /tmp/av-ported-audit.json
```

This tool parses every `test/security/*.test.js` and `test/core/*.test.js` file with Node's bundled Acorn parser. It never imports test modules or executes their hooks, helpers, callbacks, or mutation harness. A small AST interpreter resolves literal names, templates, pure name-building expressions and finite declaration loops; unsupported dynamic declarations are reported as unresolved.

The JSON report includes source locations, nesting, all manifest mappings, missing entries, repeated references, duplicate source leaf names and conflicting coverage claims. Repeated references are expected when a crate defers ownership; a deferral does not assert coverage. Missing entries and unresolved declarations must be reviewed explicitly. This audit checks inventory completeness, not whether a mapped Rust test actually asserts the JS behavior.

It reads the four local crate inventories. If the CLI inventory is absent, it reads it with `git show` from `origin/ericuldall/rust-port-cli`; set `AV_CLI_REF` to choose another already-fetched revision. The parser is an internal Node API and requires `--expose-internals`; use a Node installation that includes the bundled Acorn module. The default report path is `/tmp/av-daemon-ported-audit.json`.
