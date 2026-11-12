# JS tests mapped to av-cli

The JavaScript under `src/`, `bin/` and `test/` is the reference. This crate
implements `agent-vault` / `av` and `agent-vault-setup`. Rust tests live in
`src/tests.rs` and `tests/contract.rs`. A JS daemon, when a test needs one,
is `node bin/agent-vault-daemon.js` in a temp dir (`AV_VAULT_DIR` /
`AV_RUN_DIR`). Migrate fixtures are built by the JS store via
`av-store`'s `make-js-vault.mjs`. Nothing touches `/var/db/agent-vault`.

A row is a Rust test, `covered by conformance: <name>` when that conformance
test asserts the same property, or `not applicable, because ...`.

## Adaptations

- The installer ships the Rust binaries and no Node runtime. Dry-run uninstall
  text is `sudo <app>/bin/agent-vault-setup uninstall`, not
  `runtime/node … agent-vault-setup.js`. `MIN_NODE_MAJOR` does not apply.
- `agent-vault setup --print-only` prints `sudo <agent-vault-setup> install
  --from <checkout>` with no `node` and no `.js`.
- Upgrade probes the installed installer for `value('from')` (JS) or `--from`
  (Rust binary) via `installer_supports_from`, and says the copy is too old
  to upgrade itself when neither marker is present. It does not spawn `sudo`.
  A Rust installer inside `<root>/app/bin` is not used even when it contains
  `--from`: running it trips `binary_inside`, so `upgrade --print-only` names
  the checkout's `rust/target/release/agent-vault-setup` and `--from` the
  checkout. `install_app` copies those release binaries, not the directory of
  `current_exe`. When `--from` was already passed, the refusal says to run
  the installer from the checkout, not "Pass --from".
- `foo://u:p w@h st` (non-special scheme, space in the host) is an accepted
  safe difference. JS `new URL` throws, so `urlHasPassword` keeps the value.
  Rust encodes the space and then sees a password, so `exec` drops it.
  `probe_exec_scrub_drops_non_special_scheme_with_a_space_in_the_host` pins
  that. The other URL shapes agree with JS.
- `--use-node` is refused. This installer ships the Rust daemon and does not
  copy a Node runtime. `agent-vault-setup` help says so.
- `--json` envelopes keep insertion order (`serde_json` `preserve_order`).

## Security and CLI tests

| JS test | Rust test |
| --- | --- |
| `test/security/cli.test.js` setup creates a vault and says what it does not protect against | `setup_dev_creates_a_mode_0700_vault_and_says_what_it_does_not_protect` |
| `test/security/cli.test.js` a credential value is read from stdin and never echoed back | covered by conformance: `credentials, sessions, placeholders, env, and preflight` (cred add reads `SECRET` on stdin and `leaksSecret` is null) |
| `test/security/cli.test.js` cred list shows a fingerprint and the injection site, never a value | `cred_list_names_the_fingerprint_and_the_site` (human line). JSON list is the daemon document unchanged; conformance `credentials, sessions, placeholders, env, and preflight` asserts the slug and that the secret is absent |
| `test/security/cli.test.js` session create returns a placeholder and tells the agent where to put it | covered by conformance: `credentials, sessions, placeholders, env, and preflight` (`placeholder` matches `^av1\.`) |
| `test/security/cli.test.js` ph next issues a further placeholder for the same session | covered by conformance: `credentials, sessions, placeholders, env, and preflight` |
| `test/security/cli.test.js` ph check validates shape and explains a corrupted placeholder | covered by conformance: `credentials, sessions, placeholders, env, and preflight` (good check exits 0, `not-a-placeholder` exits 8) |
| `test/security/cli.test.js` env prints only capabilities, never a credential | `env_quotes_exported_values` and covered by conformance: `credentials, sessions, placeholders, env, and preflight` (env lines contain the placeholder and `leaksSecret` is null) |
| `test/security/cli.test.js` a vault with no human factor says so, loudly, in both status and doctor | `no_factor_is_named_in_status_and_doctor` |
| `test/security/cli.test.js` audit verify reports an intact chain | covered by conformance: `templates, credential record commands, notify, tripwire, audit, listeners, and tls` (`chain.ok` is true) |
| `test/security/cli.test.js` doctor checks the audit chain, so nothing has to remember to | `doctor_names_the_audit_chain` |
| `test/security/cli.test.js` listen add refuses the control surface on a network address | not applicable, because the CLI forwards `listen add`; av-store refuses a network bind of the control surface with `AV_REMOTE_FORBIDDEN` (`surfaces ... can never be bound to a network address`) |
| `test/security/cli.test.js` setup shows the plan and the exact program root will run, before asking | `setup_plan_names_one_program_and_does_not_sudo` |
| `test/security/cli.test.js` setup --print-only emits just the command, for scripting | `setup_plan_names_one_program_and_does_not_sudo` (no `node`, no `.js`) |
| `test/security/cli.test.js` the CLI refuses to run as root and names the command to use instead | not applicable, because `refuse_root` calls `/usr/bin/id -u` and these tests are not uid 0; the wording is `Do not run agent-vault under sudo` |
| `test/security/cli.test.js` an unknown command lists what is available instead of just failing | `unknown_command_names_itself` |
| `test/security/cli.test.js` a tampered gateway port in the CLI state file cannot redirect the URL | `gateway_port_ignores_a_tampered_value` |
| `test/security/control-cli-overrides.test.js` C23: a field error from parseOverrides becomes a usage error naming the flag | `approve_refuses_a_bad_payload_before_sending` |
| `test/security/control-cli-overrides.test.js` C23: an error without a field is not dressed up as a usage error | not applicable, because `pending::parse_overrides` always returns a field on `Err`, so the CLI has no field-less arm to dress up |
| `test/security/control-cli-overrides.test.js` approve overrides: ordinary narrowing passes through unchanged | `approve_rate_stays_a_string` |
| `test/security/control-cli-overrides.test.js` approve overrides: a flag that was typed is never treated as nothing sent | `approve_keeps_each_spelling_apart` |
| `test/security/control-cli-overrides.test.js` session create and template flags: an unknown limit is refused, the known ones are not | `known_flags_refuses_an_unknown_limit` |
| `test/security/control-cli-overrides.test.js` approve with an unreadable narrowing exits 2 before contacting the daemon | `approve_refuses_an_unreadable_narrowing_before_the_daemon` |
| `test/security/control-cli-watch.test.js` snapshot and pending deduplicate IDs across reconnects; SIGINT cleans resources | `watch_shows_an_id_once`. SIGINT ends the process; Rust has no listener or timer registry to clear |
| `test/security/control-cli-watch.test.js` JSON emits one envelope per SSE event, including fragmented multiline CRLF frames, without desktop effects | `watch_parses_a_crlf_field_and_a_split_character` and `watch_json_uses_cleaned_fields`. Conformance `daemon, ui, docs, and watch start and stop` sees one snapshot envelope with `--no-notify` |
| `test/security/control-cli-watch.test.js` notifications use argv, strip unsafe text, coalesce, and warn only once | `notify_script_passes_text_as_argv` and `watch_strips_controls_and_bidi` |
| `test/security/control-cli-watch.test.js` quiet suppresses human output; Linux notifications and no-notify work | not applicable, because this workspace builds the macOS `osascript` arm; `notify-send` is `cfg`d out. `--no-notify` is what conformance `daemon, ui, docs, and watch start and stop` runs |
| `test/security/control-cli-watch.test.js` startup connection errors reject with exit 3 and leave no listeners or timers | not applicable, because a dead socket returns `Exit::DaemonUnreachable` (3) from `watch` and Rust has no listener or timer table |
| `test/security/control-cli-watch.test.js` daemon refusals preserve the registered exit code | `watch_old_daemon_is_version_skew` (`AV_POLICY_DENIED` stays `Exit::PolicyDenied`) |
| `test/security/control-cli-watch.test.js` an old daemon returns the version-skew exit and restart hint | `watch_old_daemon_is_version_skew` |
| `test/security/control-cli-watch.test.js` reconnection backoff caps at 30 seconds and SIGINT cancels a pending retry | `watch_backoff_caps_at_30_seconds`. SIGINT drops the sleep with the process; there is no JS timer handle |
| `test/security/control-cli-watch.test.js` real Unix socket SSE decodes UTF-8 split across chunks and closes on SIGINT | `watch_parses_a_crlf_field_and_a_split_character` (the line is decoded after the newline, so a split character is whole). SIGINT is the process signal, not a JS abort controller |
| `test/security/control-cli-watch.test.js` JSON prints only the cleaned display fields of pending and snapshot entries | `watch_json_uses_cleaned_fields` |
| `test/security/control-cli-watch.test.js` JSON passes an ordinary entry through unchanged | `watch_json_uses_cleaned_fields` (id and headline kept; `reason` dropped) |
| `test/security/control-cli-files.test.js` backup export writes exclusive 0600 JSON, refuses collisions and links, and needs matching stdin recovery proof | `backup_export_does_not_replace_without_force`, `env_file_refuses_an_existing_path`, `force_refuses_a_symlink` |
| `test/security/control-cli-files.test.js` backup inspect and restore read the bundle, inspect before restoring, and preserve conflict mode | `conflict_mode_is_skip_rename_or_fail` (skip, rename, and fail are what restore posts after inspect). The bundle round trip is the daemon |
| `test/security/control-cli-files.test.js` audit export preserves JSONL chain rows, follows exclusive writer rules, and witness appends | `witness_append_keeps_earlier_lines` and `append_tightens_the_mode_to_0600` |
| `test/security/control-cli-files.test.js` audit follow appends later pages, never truncates earlier evidence, and stops cleanly on SIGINT | `witness_append_keeps_earlier_lines` (append does not truncate). SIGINT stops the process; there is no follow timer |
| `test/security/control-cli-files.test.js` audit verify combines chain and witness decisions with strict booleans | `audit_verify_requires_boolean_ok` |
| `test/security/control-cli-files.test.js` audit verify on a broken chain is a failure envelope with exit 1, and an intact one is not | `audit_verify_requires_boolean_ok` (`ok: false` and `ok: 1` are not success) |
| `test/security/control-cli-files.test.js` audit witness refuses a planted fifo at once and writes nothing | `append_refuses_a_fifo_without_hanging` |
| `test/security/control-cli-files.test.js` --markdown takes no value on session show and report | `prepare_refuses_markdown_equals_yes` and `markdown_takes_no_value` |
| `test/security/control-cli-files.test.js` state writes cannot follow a symlink and ordinary updates remain private | `force_refuses_a_symlink` and `append_tightens_the_mode_to_0600` |
| `test/security/control-cli-files.test.js` policy flags share one typed parser and reject malformed ordinary numeric spellings | `number_flag_rejects_a_fraction_when_an_integer_is_required` and `optional_number_rejects_a_missing_value` |
| `test/security/control-cli-files.test.js` preflight calls only loopback gateway with session authentication, preserves repeated headers and returns verdict exit codes | `preflight_sends_a_placeholder_assumption`. Verdict exits are conformance `credentials, sessions, placeholders, env, and preflight` (`would` allow exits 0, hold exits 10) |
| `test/security/control-cli-files.test.js` new secret-bearing commands refuse argv values without echoing them or contacting daemon | `secret_flags_are_refused_and_not_echoed` |
| `test/security/control-cli-files.test.js` session detail reports policy, spend estimates, grant lifetime and incomplete history in text and Markdown | `session_detail_names_spend_lifetime_and_incomplete_history` |
| `test/security/control-cli-files.test.js` approval previews strip terminal control bytes, bound body display and label agent text | `approval_preview_strips_controls_in_the_body` and `approval_preview_bounds_the_body_and_names_the_agent` |
| `test/security/control-cli-files.test.js` probe results use strict decisions and registered exit codes; containment sends strict booleans | `probe_decisions_are_strict` |
| `test/security/control-cli-files.test.js` reports preserve response data and label incomplete history in human and Markdown tables | `report_labels_incomplete_history_in_the_tables` |
| `test/security/control-cli-files.test.js` root help matches A.5 exactly and scrub help documents the bounded grammar | `help_matches_the_contract_and_scrub_help_names_the_grammar` |
| `test/security/control-cli-fifo.test.js` appendLineExclusive refuses a fifo with no reader at once and writes nothing | `append_refuses_a_fifo_without_hanging` |
| `test/security/control-cli-fifo.test.js` appendLineExclusive refuses a fifo with a reader and the reader gets no bytes | `append_refuses_a_fifo_a_reader_is_waiting_on` |
| `test/security/control-cli-fifo.test.js` writeFileExclusive refuses a fifo at once, with and without force | `write_refuses_a_fifo_with_and_without_force` |
| `test/security/control-cli-fifo.test.js` appendLineExclusive still creates and appends to an ordinary file | `witness_append_keeps_earlier_lines` |
| `test/security/control-cli-routes.test.js` control CLI rotate reads synthetic secret from stdin and sends rotation options | `rotate_body_carries_the_options_and_not_an_argv_secret` |
| `test/security/control-cli-routes.test.js` control CLI scrub add/remove and repeatable pin add use exact route bodies | `scrub_and_pin_bodies_match_the_routes` |
| `test/security/control-cli-routes.test.js` control CLI expiry refuses invalid calendar dates locally and accepts none | `expiry_refuses_a_non_calendar_date_and_accepts_none` |
| `test/security/control-cli-routes.test.js` control CLI tripwire replacement preserves unrelated rules and on/off preserve configured rules | `tripwire_null_rules_use_defaults` (null rules fall back to defaults; a saved set is not replaced by defaults) |
| `test/security/control-cli-routes.test.js` control CLI tripwire on installs defaults only for an empty rule set | `tripwire_null_rules_use_defaults` |
| `test/security/control-cli-routes.test.js` control CLI tripwire show reads a daemon that sends null for rules never saved, as the defaults (r6 B1) | `tripwire_null_rules_use_defaults` |
| `test/security/control-cli-routes.test.js` control CLI tripwire on stores the defaults when the daemon says none were saved (r6 B1) | `tripwire_null_rules_use_defaults` |
| `test/security/control-cli-routes.test.js` control CLI cred test --all skips a kind with no probe (r6 N2) | `probe_decisions_are_strict` and covered by conformance: `templates, credential record commands, notify, tripwire, audit, listeners, and tls` (`--all` reports `rule: no_probe` for `demo`) |
| `test/security/control-cli-routes.test.js` control CLI template lifecycle and session create bind the reviewed template hash | `template_hash_is_bound_onto_the_session_body` |
| `test/security/control-cli-routes.test.js` control CLI notify reads secret URL from stdin and show/off/test use public responses | covered by conformance: `templates, credential record commands, notify, tripwire, audit, listeners, and tls` (show keeps the host, drops the path, and the delivered body has no secret) |
| `test/security/control-cli-routes.test.js` control CLI fresh backup refusal without TTY (passphrase) never retries or opens a window | `fresh_backup_without_a_terminal_does_not_open_a_window` |
| `test/security/control-cli-routes.test.js` control CLI fresh backup refusal without TTY (passphrase,authenticator) never retries or opens a window | `fresh_backup_without_a_terminal_does_not_open_a_window` |
| `test/security/control-cli-routes.test.js` control CLI session create and narrow normalize shared policy flags and route lifetimes | `approve_keeps_each_spelling_apart` and `session_narrow_refuses_uses_before_the_daemon` |
| `test/security/control-cli-routes.test.js` control CLI approve routes session overrides and refuses overrides on held requests | `approve_rate_stays_a_string` and `approve_prints_what_was_granted` |
| `test/security/control-cli-routes.test.js` control CLI session payload file and multiple credentials preserve structured policy | `approve_rate_stays_a_string` (the signed text wins over the typed object) |
| `test/security/control-cli-routes.test.js` control CLI invalid policy flags fail before contacting the control socket | `approve_refuses_an_unreadable_narrowing_before_the_daemon` and `number_flag_rejects_a_fraction_when_an_integer_is_required` |
| `test/security/control-cli-routes.test.js` control CLI maps daemon refusal to the contracted JSON error fields and exit | `watch_old_daemon_is_version_skew` (a coded refusal keeps its registered exit) |
| `test/security/control-cli-routes.test.js` control CLI refuses secret-bearing argv flags before sending any request | `secret_flags_are_refused_and_not_echoed` |
| `test/security/control-cli-routes.test.js` control CLI has no --remote flag (R3): session create and template save refuse it and send nothing | `session_create_refuses_remote` |
| `test/security/control-cli-routes.test.js` control CLI session narrow refuses --uses (C22) before contacting the daemon | `session_narrow_refuses_uses_before_the_daemon` |
| `test/security/fix-control-cli.test.js` the printed try: command carries the token where it cannot collide with the placeholder | `try_command_puts_the_token_where_it_cannot_collide` |
| `test/security/fix-control-cli.test.js` listen add asks for the passphrase like every other gated command | `fresh_backup_without_a_terminal_does_not_open_a_window` (no terminal: no window, and the message names the passphrase) |
| `test/security/fix-control-cli.test.js` the TLS listener port is the same everywhere it is written | not applicable, because the port is one `optional_number` result passed to the daemon; conformance `templates, credential record commands, notify, tripwire, audit, listeners, and tls` checks the certificate text, not two copies of the port |
| `test/security/fix-control-cli.test.js` env quotes what it exports, and refuses what a token or placeholder cannot be | `env_quotes_exported_values` and `a_batch_value_that_is_not_a_placeholder_is_refused` |
| `test/security/fix-control-cli.test.js` env exports a real session faithfully | `env_quotes_exported_values` |
| `test/security/fix-control-cli.test.js` env and mcp url follow the session to a non-default port | `gateway_port_ignores_a_tampered_value` (base_url port 7420 is kept, and the mcp url is that port plus `/mcp`) |
| `test/security/fix-control-cli.test.js` narrowing flags split and normalise the way every other input does | `approve_keeps_each_spelling_apart` |
| `test/security/fix-control-cli.test.js` exec drops real credentials from the child environment, and keeps the rest | `exec_drops_credentials_and_generated_vars` and covered by conformance: `approvals, exec, mcp url, and mcp install` (`secret_present` is false, `ORDINARY` is kept) |
| `test/security/fix-control-cli.test.js` exec reports a child killed by a signal as a failure, and a missing binary as an error | `exec_reports_a_signal_as_a_failure_and_a_missing_binary_as_an_error` |
| `test/security/fix-control-cli.test.js` the stdio bridge heals from a dead launch token once a new session is recorded | `dead_launch_token_includes_the_session_header` |
| `test/security/fix-control-cli.test.js` agent-vault ui warns when its page is on an origin the daemon does not trust | `ui_warns_when_the_origin_is_not_trusted` |
| `test/security/fix-control-cli.test.js` a fresh-presence change on a vault with no factor says to set one, and exits 5 | `fresh_presence_without_a_factor_says_to_set_one` |
| `test/security/fix-control-cli.test.js` exec drops vault-prefixed secrets and user-less URL passwords | `exec_drops_credentials_and_generated_vars` |
| `test/security/fix-control-cli.test.js` exec keeps the vault settings and URLs with no password in them | `exec_drops_credentials_and_generated_vars` (`AGENT_VAULT_DIR` is kept; `PATH` is kept) |
| `test/security/fix-control-cli.test.js` exec does not pass on a placeholder inherited from an earlier session | `exec_drops_credentials_and_generated_vars` (`AGENT_VAULT_SESSION` is not inherited) |
| `test/security/fix-control-cli.test.js` env output clears a placeholder the shell already holds when there is none now | `env_unsets_a_placeholder_the_shell_already_holds` |
| `test/security/fix-control-cli.test.js` exec and env still deliver the current placeholder when there is one | covered by conformance: `approvals, exec, mcp url, and mcp install` and `credentials, sessions, placeholders, env, and preflight` |
| `test/security/fix-control-cli.test.js` the bridge resends only the refused calls of a mixed batch | `bridge_resends_only_the_refused_call` |
| `test/security/fix-control-cli.test.js` the bridge leaves a batch alone when nothing in it was refused for want of a session | `bridge_leaves_a_batch_alone_when_the_phrase_is_only_text` |
| `test/security/fix-control-cli.test.js` what the bridge resends is read from the answers, not searched for in their text | `bridge_leaves_a_batch_alone_when_the_phrase_is_only_text` and `bridge_resends_only_the_refused_call` |
| `test/security/installer.test.js` the plan can be read without root, which is what makes it an inspection step | `installer_dry_run_names_the_boundary_without_root` |
| `test/security/installer.test.js` the plan names the boundary explicitly | `installer_dry_run_names_the_boundary_without_root` |
| `test/security/installer.test.js` the vault directory is owned by the service user, not root and not you | `installer_dry_run_names_the_boundary_without_root` (`owner 399:399`) |
| `test/security/installer.test.js` the socket directory is setgid, so sockets inherit the client group | `installer_dry_run_names_the_boundary_without_root` (`mkdir -m 02750`) |
| `test/security/installer.test.js` the service user is added to the client group | `installer_dry_run_names_the_boundary_without_root` |
| `test/security/installer.test.js` the uninstall command it prints uses the root-owned runtime | `installer_dry_run_names_the_boundary_without_root` (no `runtime/node`, no `.js`) |
| `test/security/installer.test.js` the command to verify the boundary does not itself need sudo | `installer_dry_run_names_the_boundary_without_root` (`Check it` has no sudo) |
| `test/security/installer.test.js` uninstall retires the vault outside the tree it then deletes | `retired_vault_path_is_outside_the_install_root` |
| `test/security/installer.test.js` uninstall keeps credentials unless --purge is given | `installer_dry_run_names_the_boundary_without_root` (`To remove everything`) |
| `test/security/installer.test.js` the service user is left in place on uninstall, so its uid is not reused | `probe_dry_run_uninstall_says_the_service_user_stays` (stdout contains "removing it would free its uid for reuse") |
| `test/security/installer.test.js` the runtime version is checked before it is enshrined | not applicable, because the Rust installer does not copy a Node runtime (`MIN_NODE_MAJOR` is not part of this binary) |
| `test/security/installer.test.js` install refuses a path chain that is writable by anyone but root | `probe_dry_run_checks_the_root_chain_so_the_row_is_testable` (`AGENT_VAULT_SETUP_DRY_ROOT` under a user temp dir, install --dry-run, exit 1, "root must not execute from it") |
| `test/security/installer.test.js` the installer refuses to install its own directory over itself | `self_install_and_systemd_restart_and_from_probe` |
| `test/security/installer.test.js` --from selects the checkout to install | `installer_refuses_a_symlinked_checkout_and_plans_a_clean_one` |
| `test/security/installer.test.js` an installer predating --from cannot be used to upgrade itself | `self_install_and_systemd_restart_and_from_probe` and `upgrade_print_only_names_an_installer_and_source_install_app_accepts` (a Rust installer inside `app/bin` is not the one printed) |
| `test/security/installer.test.js` the service load waits out the teardown race rather than failing on it | not applicable, because `bootstrap_launchd` is the root path and these tests do not call launchctl |
| `test/security/installer.test.js` a failed service load prints the command that recovers it | not applicable, because the recovery text is printed only after a root `launchctl` failure, which these tests do not provoke |
| `test/security/installer.test.js` the installer verifies the socket appeared instead of assuming | not applicable, because the socket wait is the root bootstrap path |
| `test/security/installer.test.js` a reinstall restarts systemd rather than no-opping on an already-enabled unit | `self_install_and_systemd_restart_and_from_probe` (`restart`, not `start`) |
| `test/security/installer.test.js` a symbolic link in the checkout stops the install | `installer_refuses_a_symlinked_checkout_and_plans_a_clean_one` |
| `test/security/installer.test.js` a checkout with no symlinks installs normally | `installer_refuses_a_symlinked_checkout_and_plans_a_clean_one` |
| `test/security/installer.test.js` the copy dereferences, so nothing linked can survive it | `copy_dereference_writes_the_target_bytes` |
| `test/security/installer.test.js` no privileged helper is ever resolved through an inherited PATH | `resolve_bin_is_absolute_and_refuses_path_fallback` |
| `test/security/installer.test.js` every helper the installer spawns is in the allow-list | `resolve_bin_is_absolute_and_refuses_path_fallback` |

## Core tests

| JS test | Rust test |
| --- | --- |
| `test/core/mcp-install.test.js` every agent declares a format and at least one scope | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` paths land where each tool actually looks | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` codex honours CODEX_HOME and offers no project scope | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` an unknown agent is refused and the known ones are named | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` merging JSON keeps unrelated settings and other servers | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` a second JSON merge reports unchanged and rewrites the same text | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` a JSON file we cannot parse is refused rather than replaced | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` TOML merge appends a table and leaves comments and neighbours alone | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` a second TOML merge neither duplicates nor changes the table | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` TOML merge replaces a stale table in place, keeping what follows | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` stdio writes no session token into the config | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` HTTP points at an environment variable instead of embedding the token | `mcp_merge_keeps_neighbours_and_refuses_a_bad_name` |
| `test/core/mcp-install.test.js` install merges, keeps a copy of the old file, and is idempotent | `mcp_install_prints_backs_up_and_creates_the_parent` |
| `test/core/mcp-install.test.js` print mode shows the block and touches nothing | `mcp_install_prints_backs_up_and_creates_the_parent` |
| `test/core/mcp-install.test.js` install creates the parent directory when the tool has never run | `mcp_install_prints_backs_up_and_creates_the_parent` |
| `test/core/mcp-install.test.js` project scope produces a config that is portable | `mcp_launch_is_portable_for_a_project_and_absolute_for_the_system_install` |
| `test/core/mcp-install.test.js` a server name cannot close the table and open one of its own | `server_name_cannot_rewrite_a_config` and `mcp_install_prints_backs_up_and_creates_the_parent` |
| `test/core/mcp-install.test.js` user scope names the system install rather than a checkout | `mcp_launch_is_portable_for_a_project_and_absolute_for_the_system_install` |
| `test/core/wizards.test.js` read-only access cannot write, and needs no approval because it cannot | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` the write level asks before changing anything, and never deletes | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` the full level includes delete and says so by not asking | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` an unknown access level is refused rather than defaulted | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` the budget falls back to the profile default, not to unlimited | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` a suggested name avoids collisions with what is already stored | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` a suggested name is always a valid slug | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` the one-repository scope is genuinely narrow | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` the owner scope covers repos and orgs but not everything | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` custom paths are split and trimmed | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` every connector offers a scope list with a custom escape hatch | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` model APIs are offered a larger budget than ordinary APIs | `wizards_match_the_js_policy_tables` |
| `test/core/wizards.test.js` every access level has a label and a hint a person can act on | `wizards_match_the_js_policy_tables` |
| `test/core/package.test.js` the published package contains everything it needs and nothing it should not | not applicable, because the Rust crate is not the npm package |
| `test/core/package.test.js` the published package runs, imports and creates a vault on its own | not applicable, because the Rust crate is not the npm package. `setup_dev_creates_a_mode_0700_vault_and_says_what_it_does_not_protect` creates a dev vault |
| `test/core/package.test.js` the daemon reports the version the package actually is | not applicable, because the version string is the daemon binary's, not this crate's npm package |
| `test/core/package.test.js` no test can write state into the real vault directory | not applicable, because this crate's tests set `AGENT_VAULT_DIR` to a temp dir and never write `/var/db/agent-vault` |

## Migrate (PLAN, no JS test file)

| Case | Rust test |
| --- | --- |
| Fixture JS vault migrates; placeholders and the session token still work; `vault.json` stays and the message names it | `migrate_moves_a_js_vault_refuses_tampering_and_dry_run_writes_nothing` |
| Second run is an exit-0 already-migrated report | same |
| Dry-run writes nothing | same |
| Tampered audit is refused and writes nothing | `migrate_refuses_a_tampered_audit_and_a_live_socket` |
| A live control socket is refused, naming how to stop the daemon | same. The CLI's own socket is named by its path (`probe_migrate_refuses_the_cli_socket_path`), including when `AGENT_VAULT_DIR` is not `--from`. `AV_RUN_DIR` is not the directory beside `--from` (`probe_migrate_refuses_a_daemon_socket_under_av_run_dir`) |
| Passphrase is prompted, never a flag, and not echoed; a PRF wrap is reported dropped with `re-enroll: agent-vault ui` | `migrate_prompts_the_passphrase_and_never_takes_it_as_a_flag` |
