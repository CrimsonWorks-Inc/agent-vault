# JS tests mapped to av-cli

The JavaScript under `src/`, `bin/` and `test/` is the reference. This crate
implements `agent-vault` / `av` and `agent-vault-setup`. Rust tests live in
`src/tests.rs` and `tests/contract.rs`. A JS daemon, when a test needs one,
is `node bin/agent-vault-daemon.js` in a temp dir (`AV_VAULT_DIR` /
`AV_RUN_DIR`). Migrate fixtures are built by the JS store via
`av-store`'s `make-js-vault.mjs`. Nothing touches `/var/db/agent-vault`.

## Adaptations

- The installer ships the Rust binaries and no Node runtime. Dry-run uninstall
  text is `sudo <app>/bin/agent-vault-setup uninstall`, not
  `runtime/node … agent-vault-setup.js`. `MIN_NODE_MAJOR` does not apply.
- `agent-vault setup --print-only` prints `sudo <agent-vault-setup> install
  --from <checkout>` with no `node` and no `.js`.
- Upgrade probes the installed installer for `value('from')` (JS) or `--from`
  (Rust binary) via `installer_supports_from`, and says the copy is too old
  to upgrade itself when neither marker is present. It does not spawn `sudo`.
- `--json` envelopes keep insertion order (`serde_json` `preserve_order`).

## Security and CLI tests

| JS test | Rust test |
| --- | --- |
| `test/security/cli.test.js` setup creates a vault and says what it does not protect against | `setup_dev_creates_a_mode_0700_vault_and_says_what_it_does_not_protect` |
| `test/security/cli.test.js` a credential value is read from stdin and never echoed back | `secret_flags_are_refused_and_not_echoed` (argv secrets). Stdin values are read by `read_secret` and not printed; a full cred-add round trip needs the daemon worker's routes. |
| `test/security/cli.test.js` cred list shows a fingerprint and the injection site, never a value | handler `cred_list` in `commands.rs`. Not a separate daemon assertion yet. |
| `test/security/cli.test.js` session create returns a placeholder and tells the agent where to put it | handler `session_create`. Not a separate daemon assertion yet. |
| `test/security/cli.test.js` ph next issues a further placeholder for the same session | handler `ph_next`. Not a separate daemon assertion yet. |
| `test/security/cli.test.js` ph check validates shape and explains a corrupted placeholder | handler `ph_check` uses `av_core::placeholder`. Not a separate assertion yet. |
| `test/security/cli.test.js` env prints only capabilities, never a credential | `legacy_env` / `assert_placeholder_only`. Not a separate daemon assertion yet. |
| `test/security/cli.test.js` a vault with no human factor says so, loudly, in both status and doctor | `status_against_a_js_daemon_in_a_temp_dir` covers status. Doctor's no-factor wording is the `doctor` handler. |
| `test/security/cli.test.js` audit verify reports an intact chain | handler `audit_verify`. Tamper refusal is `migrate_refuses_a_tampered_audit_and_a_live_socket`. |
| `test/security/cli.test.js` doctor checks the audit chain, so nothing has to remember to | handler `doctor`. Not a separate assertion yet. |
| `test/security/cli.test.js` listen add refuses the control surface on a network address | handler `listen_add`. Not a separate assertion yet. |
| `test/security/cli.test.js` setup shows the plan and the exact program root will run, before asking | `setup_plan_names_one_program_and_does_not_sudo` |
| `test/security/cli.test.js` setup --print-only emits just the command, for scripting | `setup_plan_names_one_program_and_does_not_sudo` (no `node`, no `.js`) |
| `test/security/cli.test.js` the CLI refuses to run as root and names the command to use instead | `refuse_root` in `lib.rs`, before clap. Not executed as uid 0 in CI. |
| `test/security/cli.test.js` an unknown command lists what is available instead of just failing | `prepare` in `argv.rs`. Scaffold parse tests cover the command tree. |
| `test/security/cli.test.js` a tampered gateway port in the CLI state file cannot redirect the URL | `gateway_port_of` ignores a non-numeric port. Not a separate assertion yet. |
| `test/security/control-cli-files.test.js` backup export writes exclusive 0600 JSON… | `write_file_exclusive` / backup handlers. Fifo refusal: `append_refuses_a_fifo_without_hanging`. |
| `test/security/control-cli-files.test.js` backup inspect and restore… | backup handlers in `control_commands.rs`. |
| `test/security/control-cli-files.test.js` audit export preserves JSONL… | audit handlers in `control_commands.rs`. |
| `test/security/control-cli-files.test.js` audit follow appends later pages… | `audit_export` follow loop. Not driven with SIGINT here. |
| `test/security/control-cli-files.test.js` audit verify combines chain and witness… | `fail_problem` keeps `ok: false` and nests `error.problem`. |
| `test/security/control-cli-files.test.js` audit verify on a broken chain is a failure envelope… | `fail_problem` |
| `test/security/control-cli-files.test.js` audit witness refuses a planted fifo… | `append_refuses_a_fifo_without_hanging` |
| `test/security/control-cli-files.test.js` --markdown takes no value… | `markdown_takes_no_value` |
| `test/security/control-cli-files.test.js` state writes cannot follow a symlink… | `write_file_exclusive` (`O_NOFOLLOW`) |
| `test/security/control-cli-files.test.js` policy flags share one typed parser… | `optional_number_rejects_a_missing_value`, `boolean_flag_rejects_a_value_and_empty_means_set` |
| `test/security/control-cli-files.test.js` preflight calls only loopback gateway… | `gateway_preflight` in `control_commands.rs`. Not a separate socket assertion yet. |
| `test/security/control-cli-files.test.js` new secret-bearing commands refuse argv values… | `secret_flags_are_refused_and_not_echoed` |
| `test/security/control-cli-files.test.js` session detail reports policy, spend estimates… | `session_summary` in `control_commands.rs`. |
| `test/security/control-cli-files.test.js` approval previews strip terminal control bytes… | `approval_preview_bounds_the_body_and_names_the_agent`, `clean_text_drops_controls_and_bidi_and_keeps_tab_and_newline` |
| `test/security/control-cli-files.test.js` probe results use strict decisions… | `cred_test` compares `ok` with `true` only (`Value::Bool(true)`). |
| `test/security/control-cli-files.test.js` reports preserve response data… | `report_summary`. |
| `test/security/control-cli-files.test.js` root help matches A.5 exactly… | `help_matches_the_contract_and_scrub_help_names_the_grammar` |
| `test/security/control-cli-fifo.test.js` appendLineExclusive refuses a fifo with no reader… | `append_refuses_a_fifo_without_hanging` |
| `test/security/control-cli-fifo.test.js` appendLineExclusive refuses a fifo with a reader… | same writer (`O_NONBLOCK`, no bytes written). Not a second reader assertion. |
| `test/security/control-cli-fifo.test.js` writeFileExclusive refuses a fifo… | `write_file_exclusive` |
| `test/security/control-cli-fifo.test.js` appendLineExclusive still creates and appends to an ordinary file | `append_line_exclusive` (the fifo test only covers the refusal). |
| `test/security/control-cli-overrides.test.js` C23 field error… | `approval_overrides` |
| `test/security/control-cli-overrides.test.js` C23 an error without a field… | `approval_overrides` |
| `test/security/control-cli-overrides.test.js` ordinary narrowing passes through unchanged | `approve_rate_stays_a_string` |
| `test/security/control-cli-overrides.test.js` a flag that was typed is never treated as nothing sent | `approve_keeps_each_spelling_apart` |
| `test/security/control-cli-overrides.test.js` an unknown limit is refused… | `known_flags_refuses_an_unknown_limit` |
| `test/security/control-cli-overrides.test.js` approve with an unreadable narrowing exits 2 before contacting the daemon | `approval_overrides` runs before `load_pending` in `decide`. |
| `test/security/control-cli-routes.test.js` (every case) | handlers in `control_commands.rs` and `commands.rs`. Secret argv refusal is `secret_flags_are_refused_and_not_echoed`. `--remote` is `known_flags_refuses_an_unknown_limit`. The route-body cases are not each a separate daemon assertion yet. |
| `test/security/control-cli-watch.test.js` (every case) | `watch.rs` (`watch_clean`, SSE framing, version-skew hint). Not driven against a live socket in this crate yet. |
| `test/security/fix-control-cli.test.js` (every case) | handlers in `commands.rs` (`legacy_env`, `exec`, `session_retry`, `looks_like_credential`). Bridge batch retry is `session_retry` / `refused`. Not each a separate daemon assertion yet. |
| `test/security/installer.test.js` the plan can be read without root | `installer_dry_run_names_the_boundary_without_root` |
| `test/security/installer.test.js` the plan names the boundary explicitly | same |
| `test/security/installer.test.js` the vault directory is owned by the service user | same (`owner 399:399`) |
| `test/security/installer.test.js` the socket directory is setgid | same (`mkdir -m 02750`) |
| `test/security/installer.test.js` the service user is added to the client group | same |
| `test/security/installer.test.js` the uninstall command it prints uses the root-owned runtime | same, adapted: no Node runtime, absolute `agent-vault-setup` |
| `test/security/installer.test.js` the command to verify the boundary does not itself need sudo | same (`Check it`, no sudo) |
| `test/security/installer.test.js` uninstall retires the vault outside the tree it then deletes | `retired_vault_path_is_outside_the_install_root` |
| `test/security/installer.test.js` uninstall keeps credentials unless --purge is given | `uninstall` in `setup.rs` (`--purge deletes them instead`) |
| `test/security/installer.test.js` the service user is left in place… | uninstall dry-run text `removing it would free its uid for reuse` |
| `test/security/installer.test.js` the runtime version is checked before it is enshrined | not applicable: the Rust installer does not copy Node (`MIN_NODE_MAJOR` is not part of this binary) |
| `test/security/installer.test.js` install refuses a path chain that is writable by anyone but root | `assert_root_owned_chain` (`root must not execute from it`) |
| `test/security/installer.test.js` the installer refuses to install its own directory over itself | `self_install_and_systemd_restart_and_from_probe` |
| `test/security/installer.test.js` --from selects the checkout to install | `installer_refuses_a_symlinked_checkout_and_plans_a_clean_one` |
| `test/security/installer.test.js` an installer predating --from cannot be used to upgrade itself | `self_install_and_systemd_restart_and_from_probe` (`too old to upgrade itself`) |
| `test/security/installer.test.js` the service load waits out the teardown race | `bootstrap_launchd` (`returns before the job is actually gone`, `kickstart`). Not executed; dry-run returns first. |
| `test/security/installer.test.js` a failed service load prints the command that recovers it | `could not start the service` plus `sudo launchctl bootout` / `bootstrap` in `bootstrap_launchd` |
| `test/security/installer.test.js` the installer verifies the socket appeared | `control.sock` / `socket has not appeared yet` in `bootstrap_launchd` |
| `test/security/installer.test.js` a reinstall restarts systemd… | `self_install_and_systemd_restart_and_from_probe` |
| `test/security/installer.test.js` a symbolic link in the checkout stops the install | `installer_refuses_a_symlinked_checkout_and_plans_a_clean_one` |
| `test/security/installer.test.js` a checkout with no symlinks installs normally | same |
| `test/security/installer.test.js` the copy dereferences | `copy_dereference_writes_the_target_bytes` |
| `test/security/installer.test.js` no privileged helper is ever resolved through an inherited PATH | `resolve_bin_is_absolute_and_refuses_path_fallback` |
| `test/security/installer.test.js` every helper the installer spawns is in the allow-list | `bin_candidates` / `resolve_bin` |
| `test/core/mcp-install.test.js` every agent declares a format… | `mcp_install::agent` |
| `test/core/mcp-install.test.js` paths land where each tool actually looks | `mcp_install::target_path` |
| `test/core/mcp-install.test.js` codex honours CODEX_HOME… | `target_path` |
| `test/core/mcp-install.test.js` an unknown agent is refused… | `agent` returns `None` |
| `test/core/mcp-install.test.js` merging JSON… | `merge_json` |
| `test/core/mcp-install.test.js` a second JSON merge reports unchanged… | `merge_json` |
| `test/core/mcp-install.test.js` a JSON file we cannot parse is refused… | `install` |
| `test/core/mcp-install.test.js` TOML merge appends a table… | `merge_toml` |
| `test/core/mcp-install.test.js` a second TOML merge neither duplicates… | `merge_toml` |
| `test/core/mcp-install.test.js` TOML merge replaces a stale table… | `merge_toml` |
| `test/core/mcp-install.test.js` stdio writes no session token… | `server_entry` |
| `test/core/mcp-install.test.js` HTTP points at an environment variable… | `server_entry` |
| `test/core/mcp-install.test.js` install merges, keeps a copy… | `install` |
| `test/core/mcp-install.test.js` print mode shows the block… | `mcp_install` handler (`--print`) |
| `test/core/mcp-install.test.js` install creates the parent directory… | `install` |
| `test/core/mcp-install.test.js` project scope produces a config that is portable | `mcp_install` handler (bare shim on PATH) |
| `test/core/mcp-install.test.js` a server name cannot close the table… | `merge_toml` |
| `test/core/mcp-install.test.js` user scope names the system install… | system path `SYSTEM_ROOT/app/bin/agent-vault`, not `runtime/node` |
| `test/core/wizards.test.js` (every case) | `wizards.rs` (access levels, scopes, budgets, slugs). |
| `test/core/package.test.js` the published package contains everything… | not applicable: the Rust crate is not the npm package. `package.json` remains the JS package. |
| `test/core/package.test.js` the published package runs, imports and creates a vault… | not applicable: same reason. `setup --dev` creates a Rust vault in `setup_dev_creates_a_mode_0700_vault_and_says_what_it_does_not_protect`. |
| `test/core/package.test.js` the daemon reports the version the package actually is | daemon worker. The CLI prints `daemon_version` from `/v1/status`. |
| `test/core/package.test.js` no test can write state into the real vault directory | this crate's tests set `AGENT_VAULT_DIR` to a temp dir and never write `/var/db/agent-vault`. |

## Migrate (PLAN, no JS test file)

| Case | Rust test |
| --- | --- |
| Fixture JS vault migrates; `vault.json` stays | `migrate_moves_a_js_vault_refuses_tampering_and_dry_run_writes_nothing` |
| Second run is a no-op, exit 0 | same |
| Dry-run writes nothing | same |
| Tampered audit is refused and writes nothing | `migrate_refuses_a_tampered_audit_and_a_live_socket` |
| A live control socket is refused, with how to stop the daemon | same |
| Passphrase is prompted, never an argument, and not echoed | `migrate_prompts_the_passphrase_and_never_takes_it_as_a_flag` |
