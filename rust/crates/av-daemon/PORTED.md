# av-daemon: JS tests ported

One row for every test in the JS files that cover av-daemon's modules:
test/security/control-*, gateway-*, pipeline, mcp*, approval*,
session-requests, serving, listener, webauthn, ui*, connectors-*, the
integrate*/fix-control*/requested* files, and exfil, carrier, remote,
locked, revocation, widening, invariants, response, bridge and path-parsing.

What each status means:

- **A Rust test path** (`tests::gateway::…`, `sse::tests::…`): an av-daemon
  test that makes the same check. Each was checked by hand against the JS
  test it is listed for.
- **covered by conformance**: the black-box test in conformance/ named there
  drives the same behaviour through the socket, gateway or MCP, and passes
  against the Rust daemon (`AV_IMPL=rust AV_REQUIRE_IMPL=1 npm run
  conformance`).
- **ported in av-core / av-store**: that crate's PORTED.md lists the same
  JS test against a Rust test of its own (a pure core or store check the JS
  tested through the daemon). Rows there that defer to av-daemon or to
  conformance are not counted.
- **not applicable to av-daemon**: the test drives the CLI; av-cli owns it.
- **not yet ported**: no av-daemon test and no conformance test makes this
  check yet. This is the remaining work for the piece, and it is listed as
  such rather than mapped to a test that only resembles it.

Totals: 1207 JS tests: 553 to an av-daemon Rust test, 1 covered by conformance, 24 ported in av-core or av-store, 85 CLI-only, 1 not applicable, **543 not yet ported**.

## Mutation check

`mutations.toml` reproduces 63 of the 260 test/mutation-check.js entries for
src/daemon/*, src/ui/*, src/connectors/pinning.js and src/connectors/probe.js
(the src/pending.js entries are av-store's). The rest are not yet
reproduced. A few have no Rust line of their own because the port is shaped
differently: the MCP session and token travel with each message by
construction (no shared field to reintroduce), the probe takes no path,
method or body from its caller at all, and the session-request store reads
the vault on every call instead of caching an audit handle.

## JS tests

| JS file | JS test | Rust |
|---|---|---|
| approval-verdict.test.js | only true or false decides on the approvals route, and anything else decides nothing | not yet ported |
| approval-verdict.test.js | a signature cannot carry a verdict that is not a boolean either | not yet ported |
| approval-verdict.test.js | the web UI refuses a verdict that is not a boolean, before it spends a signature | not yet ported |
| approval-verdict.test.js | the web UI no longer turns a string "false" into an approved session | not yet ported |
| approval-verdict.test.js | the shared decision builder will not coerce a verdict | ported in av-store (see rust/crates/av-store/PORTED.md) |
| bridge.test.js | the bridge answers over stdio with the session on disk | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| bridge.test.js | a session that ends mid-flight is replaced without restarting the client | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| bridge.test.js | with no replacement to find, the failure is still reported | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| bridge.test.js | the bridge refuses to start with no session at all | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| bridge.test.js | every line the bridge writes to stdout is a JSON-RPC message | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| bridge.test.js | a successful call is still forwarded byte for byte | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| bridge.test.js | a daemon restart does not leave the bridge permanently broken | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| bridge.test.js | a non-protocol answer from the daemon still reaches the client as JSON-RPC | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| carrier.test.js | the session token in Authorization never reaches the upstream | `ported_gateway_core::carrier_tokens_are_consumed_or_dropped_on_real_wire_while_declared_secret_and_ordinary_headers_arrive` |
| carrier.test.js | the credential still arrives, at its own declared site | `ported_gateway_core::carrier_tokens_are_consumed_or_dropped_on_real_wire_while_declared_secret_and_ordinary_headers_arrive` |
| carrier.test.js | the AV-Session carrier behaves the same way | `ported_gateway_core::carrier_tokens_are_consumed_or_dropped_on_real_wire_while_declared_secret_and_ordinary_headers_arrive` |
| carrier.test.js | a session token smuggled into an unrelated header is dropped too | `ported_gateway_core::carrier_tokens_are_consumed_or_dropped_on_real_wire_while_declared_secret_and_ordinary_headers_arrive` |
| carrier.test.js | headers that carry no token are forwarded untouched | `ported_gateway_core::carrier_tokens_are_consumed_or_dropped_on_real_wire_while_declared_secret_and_ordinary_headers_arrive` |
| connectors-health.test.js | a GitHub expiry header becomes observed_expires_at | not yet ported |
| connectors-health.test.js | ISO 8601 and RFC 1123 expiries parse, and the header name is case-insensitive | not yet ported |
| connectors-health.test.js | an unparseable expiry is ignored, and so is a calendar date that is not a date | not yet ported |
| connectors-health.test.js | a rate-limit header that is not a non-negative integer is ignored | not yet ported |
| connectors-health.test.js | an ordinary Date header is not treated as an expiry | not yet ported |
| connectors-health.test.js | a profile with no health block yields nothing, even when GitHub headers are present | not yet ported |
| connectors-health.test.js | no profile carries a built-in SPKI pin | not yet ported |
| connectors-health.test.js | header arrays and a Headers-like get() are read the same way | not yet ported |
| connectors-health.test.js | V-H2: an ISO expiry with an offset is a real calendar date, shifted by the offset | not yet ported |
| connectors-pinning.test.js | spkiOf is the SHA-256 of the SubjectPublicKeyInfo openssl emits | not yet ported |
| connectors-pinning.test.js | a trusted chain with a leaf, intermediate or root pin is sent, and the response comes back | not yet ported |
| connectors-pinning.test.js | a trusted chain with a mismatched pin sends nothing and rejects AV_PIN_MISMATCH | not yet ported |
| connectors-pinning.test.js | a rotated leaf still matches a backup pin on the intermediate | not yet ported |
| connectors-pinning.test.js | only non-leaf pins on a chain the trust store does not accept: refused with Node's code, and nothing is sent | not yet ported |
| connectors-pinning.test.js | V-L1: an exact leaf pin stands in for CA trust, for a self-signed leaf and an untrusted chain | not yet ported |
| connectors-pinning.test.js | V-L2: a pinned self-signed leaf for another host name is refused, and nothing is sent | not yet ported |
| connectors-pinning.test.js | V-L3: a self-signed leaf whose pin is not on the list is refused, and nothing is sent | not yet ported |
| connectors-pinning.test.js | V-L4: a leaf copying the pinned intermediate's key cannot finish a handshake, and the handshake leaf is the one checked | not yet ported |
| connectors-pinning.test.js | V-L5: a pinned self-signed leaf out of date is refused with AV_PIN_MISMATCH, and nothing is sent | not yet ported |
| connectors-pinning.test.js | a pinned, trusted certificate for another host name is refused, and nothing is sent | not yet ported |
| connectors-pinning.test.js | V-P1: a forged leaf plus the real intermediate does not satisfy an intermediate pin | not yet ported |
| connectors-pinning.test.js | V-P2: a forged leaf plus the real intermediate and root does not satisfy a root pin | not yet ported |
| connectors-pinning.test.js | V-P4: an unrelated leaf with the real intermediate appended does not satisfy an intermediate pin | not yet ported |
| connectors-pinning.test.js | verifiedChainPins counts an issuer only when its key signed the certificate below it | not yet ported |
| connectors-pinning.test.js | V-P5: pins that are not a list of pins are refused before a connection, never read as no pins | `tests::guards::hardening_a_malformed_pin_list_is_refused_before_connecting_and_plaintext_with_pins_is_refused` |
| connectors-pinning.test.js | V-P6: a list with a malformed entry is refused before a connection | `tests::guards::hardening_a_malformed_pin_list_is_refused_before_connecting_and_plaintext_with_pins_is_refused` |
| connectors-pinning.test.js | V-P7 and V-P9: each pinned request makes its own handshake, and a redirect is returned, not followed | not yet ported |
| connectors-pinning.test.js | no pins (null, undefined, []) keeps Node verification unchanged | not yet ported |
| connectors-pinning.test.js | pins on an http URL are refused before a connection, with reason plaintext | not yet ported |
| connectors-pinning.test.js | fetchChainPins returns the presented chain and sends no request | not yet ported |
| connectors-pinning.test.js | chainPins de-duplicates and stops when the issuer points at itself | not yet ported |
| connectors-pinning.test.js | profiles ship no built-in pins | not yet ported |
| connectors-pinning.test.js | F-1: a Host header the certificate names does not let a leaf, intermediate or root pin accept a server that does not name the URL host | not yet ported |
| connectors-pinning.test.js | F-1: the TLS server name is the URL host, and a Host header naming another host is refused before a connection, pinned or not | not yet ported |
| connectors-pinning.test.js | F-1: a Host header with another port, no port, another case of another name, or a list is refused | not yet ported |
| connectors-pinning.test.js | F-1: hostHeaderMatches allows only the URL host, any case, with or without the scheme's default port | not yet ported |
| connectors-pinning.test.js | F-1 controls: a matching or absent Host header is delivered with and without pins | not yet ported |
| connectors-pinning.test.js | Round 5 F-1: a getter or a Proxy cannot pass the Host check and then put another host on the wire | not yet ported |
| connectors-pinning.test.js | Round 5 F-1: headers that are not names with string values are refused before a connection | not yet ported |
| connectors-pinning.test.js | Round 5 F-2: an IPv6 URL connects, the certificate is checked against the IP SAN, and pins apply | not yet ported |
| connectors-probe.test.js | the probe hits only the profile method and path, and ignores a caller path, method and body | not yet ported |
| connectors-probe.test.js | slack is a POST to the profile path with an empty form body, not the caller body | not yet ported |
| connectors-probe.test.js | a header site with no scheme sends the raw secret, and the first header site wins | not yet ported |
| connectors-probe.test.js | the result and the health record never contain the secret, a placeholder, or the body | not yet ported |
| connectors-probe.test.js | status classes: 401, 403, other codes, and a network error | not yet ported |
| connectors-probe.test.js | http and postgres have no probe, and a credential with no header site is refused before any request | not yet ported |
| connectors-probe.test.js | a host that is not a hostname is refused and nothing is sent | not yet ported |
| connectors-probe.test.js | an ordinary host, port and http scheme are used as declared | not yet ported |
| connectors-probe.test.js | pins for the host are forwarded, and a missing recordHealth still returns the result | not yet ported |
| connectors-probe.test.js | the second probe inside 60 seconds is throttled, and one after the window is not | not yet ported |
| connectors-probe.test.js | V-Q5: a now on the call does not skip the throttle | not yet ported |
| connectors-probe.test.js | V-Q5: a far-future now on the call does not lock the credential out | not yet ported |
| connectors-probe.test.js | V-Q7: a body that never ends is cut off and destroyed, and the probe returns | not yet ported |
| connectors-probe.test.js | V-Q7: an ordinary short body is drained to its end and not cut | not yet ported |
| connectors-probe.test.js | V-Q8: a recordHealth failure after a 200 is a store error, not unreachable | not yet ported |
| connectors-probe.test.js | V-Q9: pins of the wrong shape refuse the probe before the secret is read | not yet ported |
| connectors-probe.test.js | pins under two spellings of the same host are joined, and an empty one does not hide the other | not yet ported |
| connectors-probe.test.js | F-1: pins are looked up by the host of the URL the probe sends to, however the key or the declared host spells it | not yet ported |
| connectors-probe.test.js | with the real upstream: a root pin adds to CA verification, a mismatch sends nothing, and a match probes only /user | not yet ported |
| control-api-backup-audit.test.js | export needs a fresh proof: the window is refused, the passphrase works, and the bundle holds no secret | `ported_gateway_core::control_backup_export_requires_factor_and_fresh_proof_even_with_window_and_hides_every_secret` |
| control-api-backup-audit.test.js | export is refused on a vault with no human factor, and while locked | `ported_gateway_core::control_backup_export_requires_factor_and_fresh_proof_even_with_window_and_hides_every_secret` |
| control-api-backup-audit.test.js | inspect is open, but a wrong recovery passphrase is counted, and a right one does not clear the count | `ported_gateway_core::control_backup_inspection_is_open_and_real_auth_failures_survive_success_until_backoff` |
| control-api-backup-audit.test.js | restore needs a human, and gives back credentials but never a session | `ported_gateway_core::control_backup_restore_is_gated_renames_credentials_but_never_imports_sessions` |
| control-api-backup-audit.test.js | audit export, checkpoint and witness check are open reads, refused while locked (F9) | `ported_gateway_core::control_audit_pages_validate_ranges_and_witnesses_are_open_but_refused_while_locked` |
| control-api-c18.test.js | gateway POST /v1/preflight: an infinite token on a network listener is refused, a finite one works (C18) | `ported_gateway_core::control_c18_real_tls_and_direct_tools_refuse_infinite_remote_peeks_without_mutation` |
| control-api-c18.test.js | MCP vault_describe_access: refused for an infinite session on a network listener, over HTTP and in the tool itself (C18) | `ported_gateway_core::control_c18_real_tls_and_direct_tools_refuse_infinite_remote_peeks_without_mutation` |
| control-api-c18.test.js | MCP vault_preflight: refused for an infinite session on a network listener, over HTTP and in the tool itself (C18) | `ported_gateway_core::control_c18_real_tls_and_direct_tools_refuse_infinite_remote_peeks_without_mutation` |
| control-api-c18.test.js | a refused peek records nothing and changes nothing | `ported_gateway_core::control_c18_real_tls_and_direct_tools_refuse_infinite_remote_peeks_without_mutation` |
| control-api-containment.test.js | panic is open, revokes every session including infinite ones, and denies everything waiting (C1) | `ported_gateway_core::control_containment_panic_is_open_and_revokes_finite_infinite_and_waiting_work` |
| control-api-containment.test.js | panic with lock locks the vault and closes the passphrase window; panicking a locked vault revokes nothing | `ported_gateway_core::control_containment_invalid_panic_changes_nothing_and_panic_lock_closes_the_window` |
| control-api-containment.test.js | panic reads its inputs strictly | `ported_gateway_core::control_containment_invalid_panic_changes_nothing_and_panic_lock_closes_the_window` |
| control-api-containment.test.js | tripwires: on is open, everything else needs a human (C20) | `ported_gateway_core::control_containment_only_exact_tripwire_enable_is_open_and_invalid_changes_store_nothing` |
| control-api-containment.test.js | a tripwire turned on through the route revokes a replaying session before its answer returns | `ported_gateway_core::control_containment_route_enabled_replay_revokes_before_response_but_disabled_control_keeps_session` |
| control-api-containment.test.js | with tripwires off, the same replay revokes nothing | `ported_gateway_core::control_containment_route_enabled_replay_revokes_before_response_but_disabled_control_keeps_session` |
| control-api-credentials.test.js | rotating needs a human; once rotated, the next request carries the new value | `ported_gateway_core::control_credentials_rotation_requires_presence_and_new_value_reaches_only_declared_site` |
| control-api-credentials.test.js | rotating denies the held requests a human approved against the old key | `ported_gateway_core::control_credentials_rotation_denies_held_approvals_and_invalid_shapes_change_nothing` |
| control-api-credentials.test.js | a rotation it cannot read is refused, and changes nothing | `ported_gateway_core::control_credentials_rotation_denies_held_approvals_and_invalid_shapes_change_nothing` |
| control-api-credentials.test.js | adding and removing a scrub pattern need a human; the sample is the human's own text | `ported_gateway_core::control_credentials_scrub_presence_sample_and_pre_gate_refusals_preserve_ordinary_traffic` |
| control-api-credentials.test.js | a pattern that could backtrack, match everything, or carry a secret is refused, before the gate | `ported_gateway_core::control_credentials_scrub_presence_sample_and_pre_gate_refusals_preserve_ordinary_traffic` |
| control-api-credentials.test.js | setting an expiry needs a human, and is metadata the gateway does not enforce | `ported_gateway_core::control_credentials_expiry_is_gated_metadata_and_bad_addition_stores_nothing` |
| control-api-credentials.test.js | a credential can be added with its expiry; a bad one leaves nothing stored | `ported_gateway_core::control_credentials_expiry_is_gated_metadata_and_bad_addition_stores_nothing` |
| control-api-credentials.test.js | setting and removing pins need a human, and only for a host the credential reaches | `ported_gateway_core::control_credentials_pin_writes_require_presence_and_match_the_credentials_host` |
| control-api-credentials.test.js | cred test is open, hits only the profile's probe, and never returns the body | `ported_gateway_core::control_credentials_probe_is_open_fixed_read_only_bodyless_and_honors_pins` |
| control-api-credentials.test.js | a second test within a minute is throttled through the route; another credential is not (C20) | `ported_gateway_core::control_credentials_probe_throttle_is_per_credential_and_all_reports_each_failure` |
| control-api-credentials.test.js | quarantine is open, stops every use at once, and denies held requests | `ported_gateway_core::control_credentials_quarantine_is_open_denies_holds_and_every_session_use` |
| control-api-credentials.test.js | an agent cannot ask for a session on a quarantined credential, over either door (C12 note) | `ported_gateway_core::control_credentials_quarantine_refuses_session_requests_on_both_doors_until_release` |
| control-api-credentials.test.js | releasing a quarantine needs a human, and a still-live session works again | `ported_gateway_core::control_credentials_release_requires_presence_and_reason_scrubbing_precedes_200_character_cut` |
| control-api-credentials.test.js | a secret across the 200-character cut of a quarantine reason leaves none of itself behind | `ported_gateway_core::control_credentials_release_requires_presence_and_reason_scrubbing_precedes_200_character_cut` |
| control-api-mcp.test.js | vault_describe_access says what the session may do, with no token, placeholder, fingerprint or size, and records nothing | `ported_gateway_core::control_mcp_access_description_is_read_only_and_instructions_name_both_advisory_tools` |
| control-api-mcp.test.js | vault_preflight changes nothing: no approval, no use, no budget, no touch, and no upstream connection | `ported_gateway_core::control_mcp_preflight_holds_allows_and_denies_without_touch_use_approval_or_upstream` |
| control-api-mcp.test.js | vault_preflight refuses what it cannot read, an unknown credential, and an eleventh call in a second | `ported_gateway_core::control_mcp_preflight_refuses_bad_shapes_unknown_credential_and_concurrent_eleventh_call` |
| control-api-mcp.test.js | a preflight with a placeholder in the wrong place says deny, and never trips a tripwire | `ported_gateway_core::control_mcp_gateway_preflight_strict_shapes_auth_and_bad_location_never_trip_or_touch` |
| control-api-mcp.test.js | the gateway preflight route authenticates like a real request, reads its body strictly, and touches nothing | `ported_gateway_core::control_mcp_gateway_preflight_strict_shapes_auth_and_bad_location_never_trip_or_touch` |
| control-api-mcp.test.js | vault_request_session forwards routes, uses and a grant lifetime, and nothing it does not offer | `ported_gateway_core::control_mcp_session_proposal_whitelists_fields_and_invalid_dry_runs_leave_no_state_or_audit` |
| control-api-mcp.test.js | the existing tools show lifetimes; the preview stays with the human (F13) | `ported_gateway_core::control_mcp_status_shows_lifetimes_but_only_human_pending_views_receive_scrubbed_preview` |
| control-api-mcp.test.js | the server instructions point at the two new tools | `ported_gateway_core::control_mcp_access_description_is_read_only_and_instructions_name_both_advisory_tools` |
| control-api-notify.test.js | the stream sends a snapshot, then each new item, without the agent's words | `ported_gateway_core::control_notify_real_stream_snapshots_updates_and_tokens_never_touch_session_or_disclose_agent_words` |
| control-api-notify.test.js | a ninth watcher is refused | not yet ported |
| control-api-notify.test.js | the stream resolves no session: a token sent to it is ignored and touches nothing (C20) | `ported_gateway_core::control_notify_real_stream_snapshots_updates_and_tokens_never_touch_session_or_disclose_agent_words` |
| control-api-notify.test.js | setting a webhook needs the owner; only its host is ever shown or recorded | `ported_gateway_core::control_notify_webhook_configuration_is_gated_encrypted_and_only_host_is_public` |
| control-api-notify.test.js | the minimal webhook is counts and ids only; one POST per interval | `ported_gateway_core::control_notify_minimal_webhook_posts_once_per_interval_and_secret_headlines_are_scrubbed_live_and_snapshot` |
| control-api-notify.test.js | the headline webhook adds the gateway's summary, never the agent's words | `ported_gateway_core::control_notify_payloads_are_bounded_counts_or_clean_headlines_and_stored_redaction_keeps_plain_text` |
| control-api-notify.test.js | a test notification is throttled, a failure is recorded once, and no webhook is not found | `ported_gateway_core::control_notify_test_route_throttles_and_real_http_500_failures_are_audited_once` |
| control-api-notify.test.js | a stored secret an agent puts in a proposal path does not reach the stream or the webhook (F14) | `ported_gateway_core::control_notify_minimal_webhook_posts_once_per_interval_and_secret_headlines_are_scrubbed_live_and_snapshot` |
| control-api-notify.test.js | a headline with no secret in it is sent as the summary, unchanged (F14) | `ported_gateway_core::control_notify_payloads_are_bounded_counts_or_clean_headlines_and_stored_redaction_keeps_plain_text` |
| control-api-overrides.test.js | parseOverrides is self-contained: built from its source in a fresh scope, it agrees on every field (C21, C23) | not yet ported |
| control-api-overrides.test.js | routes and payload as JSON strings are parsed; a value passes through; bad JSON throws (C23) | ported in av-store (see rust/crates/av-store/PORTED.md) |
| control-api-overrides.test.js | a numeric narrowing is Number(v), and anything not finite throws, naming the field (C23) | ported in av-store (see rust/crates/av-store/PORTED.md) |
| control-api-overrides.test.js | rate and quota: a string is trimmed, anything else passes through for the daemon (C23) | ported in av-store (see rust/crates/av-store/PORTED.md) |
| control-api-overrides.test.js | an approval narrowed with --routes or --payload as JSON creates a grant with the parsed value, not the proposal | `ported_gateway_core::control_overrides_routes_and_payload_json_create_the_narrowed_grant_instead_of_agent_proposal` |
| control-api-sessions.test.js | a budget of 0 is refused before the presence gate, and nothing is made (C17) | `ported_gateway_core::control_sessions_create_refuses_zero_budget_before_presence_and_unreadable_limits_are_atomic` |
| control-api-sessions.test.js | a create body carries every grant limit, converted by the one converter | `ported_gateway_core::control_sessions_create_converts_every_limit_defaults_and_grant_lifetimes` |
| control-api-sessions.test.js | a grant limit that cannot be read is refused and leaves nothing behind | `ported_gateway_core::control_sessions_create_refuses_zero_budget_before_presence_and_unreadable_limits_are_atomic` |
| control-api-sessions.test.js | a grant lifetime is set, clamped to the session, and refused when it is not a whole number (F18) | `ported_gateway_core::control_sessions_create_converts_every_limit_defaults_and_grant_lifetimes` |
| control-api-sessions.test.js | an expired grant is refused with its own code while the session's other grant works (F18) | `ported_gateway_core::control_sessions_expired_grant_has_its_own_code_on_gateway_and_mcp_while_other_grant_works` |
| control-api-sessions.test.js | narrowing intersects: auto plus DELETE on an on-write GET grant leaves on-write and no methods (F15) | `ported_gateway_core::control_sessions_narrow_intersects_approval_and_methods_and_never_requires_presence` |
| control-api-sessions.test.js | narrowing never widens, over random narrows (F15) | `ported_gateway_core::control_sessions_generated_narrows_only_reduce_methods_approval_and_budget` |
| control-api-sessions.test.js | a narrowing that turns redirects on is refused; turning them off is not (F15) | `ported_gateway_core::control_sessions_narrow_refuses_redirect_widening_without_shortening_and_bad_fields_are_atomic` |
| control-api-sessions.test.js | an agent can narrow its own session with no presence, and only ever loses capability (F15) | `ported_gateway_core::control_sessions_narrow_intersects_approval_and_methods_and_never_requires_presence` |
| control-api-sessions.test.js | a session lifetime in a narrowing makes an infinite session finite, and a grant lifetime shortens the grant (F15) | `ported_gateway_core::control_sessions_narrow_lifetimes_make_infinite_finite_and_only_touch_selected_credentials` |
| control-api-sessions.test.js | a narrowing that does nothing, or names what cannot be narrowed, is refused (F15) | `ported_gateway_core::control_sessions_narrow_refuses_redirect_widening_without_shortening_and_bad_fields_are_atomic` |
| control-api-sessions.test.js | narrowing one credential leaves the session's other grant alone (F15) | `ported_gateway_core::control_sessions_narrow_lifetimes_make_infinite_finite_and_only_touch_selected_credentials` |
| control-api-sessions.test.js | the session detail holds metadata only: no placeholder text, query or secret (F19) | `ported_gateway_core::control_sessions_detail_and_access_reports_expose_metadata_without_queries_secrets_or_capabilities` |
| control-api-sessions.test.js | the detail says when history is incomplete, and is refused while locked (F19) | `ported_gateway_core::control_sessions_detail_reports_missing_creation_history_and_both_reads_refuse_locked_vault` |
| control-api-sessions.test.js | the access report covers every session and credential, and refuses a since it cannot read (F19) | `ported_gateway_core::control_sessions_detail_and_access_reports_expose_metadata_without_queries_secrets_or_capabilities` |
| control-api-sessions.test.js | a typo in a narrowing is refused, by the parser and by the daemon, never dropped as null | `ported_gateway_core::control_sessions_override_typos_never_settle_pending_requests_and_parsed_budget_is_applied` |
| control-api-templates.test.js | saving a template needs a human, and is checked like a create first | `ported_gateway_core::control_templates_validate_before_presence_and_crud_metadata_stays_open` |
| control-api-templates.test.js | templates are listed with summaries, read in full by name, and deleted without presence | `ported_gateway_core::control_templates_validate_before_presence_and_crud_metadata_stays_open` |
| control-api-templates.test.js | creating from a template binds its hash: an edit after looking is refused, the current hash works | `ported_gateway_core::control_templates_hash_binding_detects_edits_and_overrides_only_reduce_the_saved_authority` |
| control-api-templates.test.js | a signature over one template hash cannot be spent on another | `ported_gateway_core::control_templates_signed_consent_binds_exact_template_hash_and_fresh_matching_signature_works` |
| control-api-templates.test.js | overrides only narrow: DELETE on a GET template still makes a GET-only session | `ported_gateway_core::control_templates_hash_binding_detects_edits_and_overrides_only_reduce_the_saved_authority` |
| control-api-templates.test.js | an infinite template can only be made finite, never the other way round | `ported_gateway_core::control_templates_infinite_only_becomes_finite_and_budget_without_a_ceiling_requires_default` |
| control-api-templates.test.js | an elevated template needs a fresh proof to create, and the window is not one | `ported_gateway_core::control_templates_elevated_creation_requires_fresh_proof_and_read_only_narrowing_uses_window` |
| control-api-templates.test.js | a session request from a template is a snapshot: an edit afterwards does not reach the session | `ported_gateway_core::control_templates_proposal_snapshots_survive_edits_and_owner_fields_cannot_be_supplied_by_agent` |
| control-api-templates.test.js | a template request names one credential, and a template's owner fields come only from the template | `ported_gateway_core::control_templates_proposal_snapshots_survive_edits_and_owner_fields_cannot_be_supplied_by_agent` |
| control-api-templates.test.js | MCP asks by template name, with no credential named, and lists single-credential templates | `ported_gateway_core::control_templates_mcp_lists_only_single_credential_templates_and_can_propose_by_name` |
| control-cli-fifo.test.js | appendLineExclusive refuses a fifo with no reader at once and writes nothing | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-fifo.test.js | appendLineExclusive refuses a fifo with a reader and the reader gets no bytes | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-fifo.test.js | writeFileExclusive refuses a fifo at once, with and without force | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-fifo.test.js | appendLineExclusive still creates and appends to an ordinary file | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | backup export writes exclusive 0600 JSON, refuses collisions and links, and needs matching stdin recovery proof | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | backup inspect and restore read the bundle, inspect before restoring, and preserve conflict mode | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | audit export preserves JSONL chain rows, follows exclusive writer rules, and witness appends | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | audit follow appends later pages, never truncates earlier evidence, and stops cleanly on SIGINT | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | audit verify combines chain and witness decisions with strict booleans | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | audit verify on a broken chain is a failure envelope with exit 1, and an intact one is not | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | audit witness refuses a planted fifo at once and writes nothing | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | --markdown takes no value on session show and report | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | state writes cannot follow a symlink and ordinary updates remain private | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | policy flags share one typed parser and reject malformed ordinary numeric spellings | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | preflight calls only loopback gateway with session authentication, preserves repeated headers and returns verdict exit codes | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | new secret-bearing commands refuse argv values without echoing them or contacting daemon | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | session detail reports policy, spend estimates, grant lifetime and incomplete history in text and Markdown | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | approval previews strip terminal control bytes, bound body display and label agent text | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | probe results use strict decisions and registered exit codes; containment sends strict booleans | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | reports preserve response data and label incomplete history in human and Markdown tables | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-files.test.js | root help matches A.5 exactly and scrub help documents the bounded grammar | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-overrides.test.js | C23: a field error from parseOverrides becomes a usage error naming the flag | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-overrides.test.js | C23: an error without a field is not dressed up as a usage error | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-overrides.test.js | approve overrides: ordinary narrowing passes through unchanged | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-overrides.test.js | approve overrides: a flag that was typed is never treated as nothing sent | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-overrides.test.js | session create and template flags: an unknown limit is refused, the known ones are not | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-overrides.test.js | approve with an unreadable narrowing exits 2 before contacting the daemon | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI rotate reads synthetic secret from stdin and sends rotation options | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI scrub add/remove and repeatable pin add use exact route bodies | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI expiry refuses invalid calendar dates locally and accepts none | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI tripwire replacement preserves unrelated rules and on/off preserve configured rules | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI tripwire on installs defaults only for an empty rule set | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI tripwire show reads a daemon that sends null for rules never saved, as the defaults (r6 B1) | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI tripwire on stores the defaults when the daemon says none were saved (r6 B1) | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI cred test --all skips a kind with no probe (r6 N2) | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI template lifecycle and session create bind the reviewed template hash | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI notify reads secret URL from stdin and show/off/test use public responses | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI session create and narrow normalize shared policy flags and route lifetimes | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI approve routes session overrides and refuses overrides on held requests | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI session payload file and multiple credentials preserve structured policy | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI invalid policy flags fail before contacting the control socket | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI maps daemon refusal to the contracted JSON error fields and exit | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI refuses secret-bearing argv flags before sending any request | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI has no --remote flag (R3): session create and template save refuse it and send nothing | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-routes.test.js | control CLI session narrow refuses --uses (C22) before contacting the daemon | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | snapshot and pending deduplicate IDs across reconnects; SIGINT cleans resources | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | JSON emits one envelope per SSE event, including fragmented multiline CRLF frames, without desktop effects | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | notifications use argv, strip unsafe text, coalesce, and warn only once | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | quiet suppresses human output; Linux notifications and no-notify work | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | startup connection errors reject with exit 3 and leave no listeners or timers | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | daemon refusals preserve the registered exit code | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | an old daemon returns the version-skew exit and restart hint | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | reconnection backoff caps at 30 seconds and SIGINT cancels a pending retry | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | real Unix socket SSE decodes UTF-8 split across chunks and closes on SIGINT | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | JSON prints only the cleaned display fields of pending and snapshot entries | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-cli-watch.test.js | JSON passes an ordinary entry through unchanged | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| control-gate.test.js | an agent cannot approve its own held request | `tests::mutants::hardening_every_answer_a_human_gives_needs_the_human` |
| control-gate.test.js | denying needs a human too, because it did not only narrow | `tests::mutants::hardening_every_answer_a_human_gives_needs_the_human` |
| control-gate.test.js | a human with a window can approve, so the gate is not a wall | `ported_gateway_core::control_gate_human_window_approves_but_agent_cannot_bind_or_replace_certificate_and_socket_is_private` |
| control-gate.test.js | an agent cannot bind a new listener | `ported_gateway_core::control_gate_human_window_approves_but_agent_cannot_bind_or_replace_certificate_and_socket_is_private` |
| control-gate.test.js | the signature counter cannot be moved by anyone who asks | `tests::presence::hardening_the_signature_counter_is_not_settable_and_a_trusted_origin_needs_fresh_presence` |
| control-gate.test.js | an agent cannot force a new certificate and break existing trust | `ported_gateway_core::control_gate_human_window_approves_but_agent_cannot_bind_or_replace_certificate_and_socket_is_private` |
| control-gate.test.js | no mutating control route widens capability without a human | `ported_gateway_core::control_gate_every_widening_route_refuses_without_writing_but_reads_remain_open` |
| control-gate.test.js | the wave-3 routes that only narrow or read stay open, even with the gate on (A.2) | `ported_gateway_core::control_gate_narrowing_and_read_only_wave_three_routes_remain_open_with_factor_enrolled` |
| control-gate.test.js | an elevated session is refused inside an open window without a fresh proof | `tests::presence::hardening_fresh_presence_never_rides_the_window` |
| control-gate.test.js | an elevated session is refused on a vault with no factor, where ordinary ones are open | `tests::control::hardening_an_elevated_session_needs_a_factor_and_the_list_reports_its_elevation` |
| control-gate.test.js | an enrolled authenticator counts as a human factor on its own | `ported_gateway_core::control_gate_authenticator_alone_gates_the_socket_and_cannot_be_ransomed_by_first_passphrase` |
| control-gate.test.js | an agent cannot enrol its own key on a fresh vault and take it over | `tests::presence::hardening_an_authenticator_needs_a_passphrase_first_and_cannot_be_enrolled_by_the_window` |
| control-gate.test.js | an agent cannot set the first passphrase and lock the owner out | `ported_gateway_core::control_gate_authenticator_alone_gates_the_socket_and_cannot_be_ransomed_by_first_passphrase` |
| control-gate.test.js | passphrase attempts are charged for, in time and in the log | `tests::presence::hardening_failed_passphrases_back_off_and_a_right_one_resets` |
| control-gate.test.js | every route that spends scrypt is throttled, not just the ones I remembered | `ported_gateway_core::control_gate_all_scrypt_routes_throttle_real_guesses_without_extending_backoff` |
| control-gate.test.js | the control socket is never world-connectable, not even for an instant | `ported_gateway_core::control_gate_human_window_approves_but_agent_cannot_bind_or_replace_certificate_and_socket_is_private` |
| control-gate.test.js | the CLI names the factor that exists, not the one it expects | av-cli |
| control-gate.test.js | one malformed byte on the control socket does not kill the daemon | `tests::control::hardening_malformed_json_and_an_unknown_route_are_answers_not_crashes` |
| control-gate.test.js | the grant’s placeholder ceiling beats what the agent asks for | `ported_gateway_core::control_gate_grant_placeholder_ceiling_beats_agent_control_and_direct_issuance` |
| control-ui-docs.test.js | the served page is one module script from the bundle, and nothing inline | not yet ported |
| control-ui-docs.test.js | containment and recovery covers every wave-3 safety feature | not yet ported |
| control-ui-docs.test.js | the agent tools are documented, read-only ones said to be so | not yet ported |
| control-ui-docs.test.js | the new session limits and templates are explained where sessions are | not yet ported |
| control-ui-docs.test.js | the commands section lists every command after wave 3 (A.5) | not yet ported |
| control-ui-guard.test.js | a token or placeholder a daemon route returns never reaches the page | not yet ported |
| control-ui-guard.test.js | ordinary text is untouched | not yet ported |
| control-ui-guard.test.js | the approvals list, a webhook URL and an error message are held to the same line | not yet ported |
| control-ui-guard.test.js | the hand-off for a session made here still carries what the agent needs | not yet ported |
| control-ui-guard.test.js | the page runs the very parser the server rebinds a narrowing with (C21) | not yet ported |
| control-ui-handoff.test.js | an error from POST sessions reaches the page with none of the withheld fields (F1) | not yet ported |
| control-ui-handoff.test.js | a successful hand-off carries the token and placeholders, and nothing else withheld (F1) | not yet ported |
| control-ui-handoff.test.js | a card field is copied back only as a scalar or a list of scalars (F1) | not yet ported |
| control-ui-handoff.test.js | a withheld key is withheld in any case, hyphenated, nested, and inside arrays (F2) | not yet ported |
| control-ui-handoff.test.js | towardPage folds case and hyphens and leaves other keys alone (F2) | not yet ported |
| control-ui-handoff.test.js | a reserved operation field is a 403 refusal, not a 500, and is not forwarded | not yet ported |
| control-ui-narrowing.test.js | a narrowing the parser refuses is said, and nothing is signed or sent (C23) | not yet ported |
| control-ui-narrowing.test.js | a narrowing that parses is signed and sent as parsed | not yet ported |
| control-ui-narrowing.test.js | a denial reads no narrowing, so text the parser refuses cannot block it | not yet ported |
| control-ui-narrowing.test.js | the narrowing is read by the shared parser, and a refusal is never read as no narrowing | not yet ported |
| control-ui-page.test.js | a notification says what the daemon saw, never what the agent claimed | not yet ported |
| control-ui-page.test.js | a notification has no actions; clicking it only opens the approvals view | not yet ported |
| control-ui-page.test.js | panic is confirmed in a dialog the page draws, never window.confirm, and is not gated | not yet ported |
| control-ui-page.test.js | a credential’s badges and pins say what is wrong without echoing anything | not yet ported |
| control-ui-page.test.js | the session Markdown says when it never expires and when history is incomplete | not yet ported |
| control-ui-page.test.js | Copy as Markdown carries no terminal controls from what the agent sent | not yet ported |
| control-ui-page.test.js | a narrow result lists only what changed | not yet ported |
| control-ui-page.test.js | a tripwire rule reads the way the CLI prints it | not yet ported |
| control-ui-page.test.js | a template’s limits are read across every grant | not yet ported |
| control-ui-page.test.js | overrides on a template only ever narrow it | not yet ported |
| control-ui-page.test.js | an untouched template form sends nothing, and a narrowing sends just that | not yet ported |
| control-ui-page.test.js | advanced limits become GrantSpec fields, and a bad payload is said before signing | not yet ported |
| control-ui-page.test.js | the session form sends spend limits only for a model provider’s credential | not yet ported |
| control-ui-page.test.js | a probe result is text, never markup | not yet ported |
| control-ui-rotate.test.js | the current key can enrol its replacement, and only the replacement works afterwards | not yet ported |
| control-ui-rotate.test.js | a replacement with no signature, or signed by the new key itself, is refused | not yet ported |
| control-ui-rotate.test.js | the record enrolled is the one registered here, not one the request names | not yet ported |
| control-ui-rotate.test.js | with nothing registered there is nothing to enrol | not yet ported |
| control-ui-rotate.test.js | a signature for the replacement is refused when it covers a different record | not yet ported |
| control-ui-rotate.test.js | a first enrolment still cannot be made this way | not yet ported |
| control-ui-routes.test.js | every wave-3 change is gated, and exactly the daemon-gated ones are re-verified (A.6) | not yet ported |
| control-ui-routes.test.js | without a signature, no change reaches the daemon | not yet ported |
| control-ui-routes.test.js | a signature over a different request is refused | not yet ported |
| control-ui-routes.test.js | a signature with another op name is refused, even over the same fields | not yet ported |
| control-ui-routes.test.js | with its own signature, each change reaches its route, carrying what the daemon re-verifies | not yet ported |
| control-ui-routes.test.js | a rotation value is bound by digest, never in clear | not yet ported |
| control-ui-routes.test.js | the probe takes a credential name and nothing that could steer it | not yet ported |
| control-ui-routes.test.js | quarantine needs no fingerprint, and passes on the name and the reason only | not yet ported |
| control-ui-routes.test.js | panic needs no fingerprint, and only a real true locks | not yet ported |
| control-ui-routes.test.js | the read routes reach the routes the contract names | not yet ported |
| control-ui-routes.test.js | the audit view can ask for one kind of record, and gets only that kind | not yet ported |
| control-ui-webauthn.test.js | every secret-bearing field is bound by digest, never in clear | not yet ported |
| control-ui-webauthn.test.js | a string digests exactly as it always did | not yet ported |
| control-ui-webauthn.test.js | two different bundles give two different operations | not yet ported |
| control-ui-webauthn.test.js | the same bundle with its keys in another order is the same operation | not yet ported |
| control-ui-webauthn.test.js | the page builds the same operation as the servers, field for field | not yet ported |
| control-ui-webauthn.test.js | the page's digested fields are the servers' digested fields | not yet ported |
| exfil.test.js | the control socket refuses a session aimed at a host the credential does not permit | `ported_gateway_core::exfil_control_refuses_foreign_hosts_and_ungated_session_creation_is_audited` |
| exfil.test.js | a session confined to the credential host cannot then be pointed elsewhere | `ported_gateway_core::exfil_real_gateway_cannot_deliver_secret_to_loopback_catcher_even_with_fresh_presence` |
| exfil.test.js | the real credential value never reaches a caller-controlled destination | `ported_gateway_core::exfil_real_gateway_cannot_deliver_secret_to_loopback_catcher_even_with_fresh_presence` |
| exfil.test.js | without a passphrase, widening is open but audited, not silently trusted | `ported_gateway_core::exfil_control_refuses_foreign_hosts_and_ungated_session_creation_is_audited` |
| exfil.test.js | with a passphrase set, the socket cannot unlock without it | `ported_gateway_core::exfil_passphrase_gates_unlock_creation_and_borrowed_grants_but_presence_restores_issuance` |
| exfil.test.js | with a passphrase set, an agent cannot mint capability without it | `ported_gateway_core::exfil_passphrase_gates_unlock_creation_and_borrowed_grants_but_presence_restores_issuance` |
| exfil.test.js | an agent cannot mint a placeholder against a grant it does not own | `ported_gateway_core::exfil_passphrase_gates_unlock_creation_and_borrowed_grants_but_presence_restores_issuance` |
| exfil.test.js | a human with a presence window can still issue placeholders | `ported_gateway_core::exfil_passphrase_gates_unlock_creation_and_borrowed_grants_but_presence_restores_issuance` |
| fix-control-approvals.test.js | denying with no human present is refused, and the request stays pending | not yet ported |
| fix-control-approvals.test.js | a signature for approving cannot be spent on denying | not yet ported |
| fix-control-approvals.test.js | a deny signed for exactly that deny goes through, as the UI sends it | not yet ported |
| fix-control-approvals.test.js | a deny inside a passphrase window goes through, as the CLI sends it | not yet ported |
| fix-control-approvals.test.js | an approval that already ran never hands its cached response back | not yet ported |
| fix-control-audit.test.js | an untouched log reopens and verifies clean | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | a brand-new vault verifies clean | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | deleting the log is not a fresh start | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | deleting the log and its anchor together is not a fresh start | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | emptying the log and deleting its anchor is not a fresh start | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | a log deleted while the daemon runs is reported, not passed | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | a damaged line in the middle does not lock the owner out, and is reported | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | a last line that lost only its newline survives two restarts | not yet ported |
| fix-control-audit.test.js | a torn half-written last line is still dropped quietly | not yet ported |
| fix-control-audit.test.js | the anchor is replaced whole, never rewritten in place | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | a float in caller fields is recorded, not thrown after the fact | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | a session request with a non-string reason is stored and recorded | not yet ported |
| fix-control-audit.test.js | an empty object as the last line does not lock the owner out, and is reported | not yet ported |
| fix-control-audit.test.js | a record with a string seq as the last line does not lock the owner out, and is reported | not yet ported |
| fix-control-audit.test.js | a record with no hashes as the last line does not lock the owner out, and is reported | not yet ported |
| fix-control-audit.test.js | an empty object in the middle does not lock the owner out, and is reported | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-audit.test.js | ordinary records, checkpoints included, are all recognised as records | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-cli.test.js | the printed try: command carries the token where it cannot collide with the placeholder | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | listen add asks for the passphrase like every other gated command | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | the TLS listener port is the same everywhere it is written | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | env quotes what it exports, and refuses what a token or placeholder cannot be | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | env exports a real session faithfully | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | env and mcp url follow the session to a non-default port | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | narrowing flags split and normalise the way every other input does | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | exec drops real credentials from the child environment, and keeps the rest | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | exec reports a child killed by a signal as a failure, and a missing binary as an error | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | the stdio bridge heals from a dead launch token once a new session is recorded | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | agent-vault ui warns when its page is on an origin the daemon does not trust | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | a fresh-presence change on a vault with no factor says to set one, and exits 5 | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | exec drops vault-prefixed secrets and user-less URL passwords | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | exec keeps the vault settings and URLs with no password in them | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | exec does not pass on a placeholder inherited from an earlier session | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | env output clears a placeholder the shell already holds when there is none now | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | exec and env still deliver the current placeholder when there is one | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | the bridge resends only the refused calls of a mixed batch | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | the bridge leaves a batch alone when nothing in it was refused for want of a session | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-cli.test.js | what the bridge resends is read from the answers, not searched for in their text | not applicable to av-daemon: drives the CLI (av-cli, cli worker) |
| fix-control-factors.test.js | F1: the only passphrase cannot be removed, and the socket stays gated | not yet ported |
| fix-control-factors.test.js | F1: removing Touch ID unlock first does not make the passphrase removable | not yet ported |
| fix-control-factors.test.js | a wrong passphrase is still a failed proof, not a factor refusal | not yet ported |
| fix-control-factors.test.js | control: with a presence authenticator left, the passphrase can be removed | not yet ported |
| fix-control-factors.test.js | an authenticator-only vault says widening is still gated when no window can open | not yet ported |
| fix-control-factors.test.js | control: a vault with no factor at all still says it is ungated | not yet ported |
| fix-control-factors.test.js | control: a passphrase changes with the current one | not yet ported |
| fix-control-factors.test.js | F2: a rotation to an unusable key is refused, and the sole key keeps working | not yet ported |
| fix-control-factors.test.js | F2: a rotation stores the credential and nothing else the caller sent | not yet ported |
| fix-control-factors.test.js | F2: a first enrolment is held to the same shape | not yet ported |
| fix-control-factors.test.js | a presence key that fails to save leaves the old one in place | not yet ported |
| fix-control-factors.test.js | F3: the store factory refuses a Touch ID unlock wrap with no passphrase | not yet ported |
| fix-control-factors.test.js | control: a vault created with a passphrase opens with it and nothing else | not yet ported |
| fix-control-factors.test.js | control: a vault with no passphrase keeps its none wrap | not yet ported |
| fix-control-ledger.test.js | asking for a placeholder and using it, over and over, stays within max_active | not yet ported |
| fix-control-ledger.test.js | a max_active that is not a number is not an unbounded ledger | not yet ported |
| fix-control-ledger.test.js | a placeholder in use keeps working while fewer than max_active are live | not yet ported |
| fix-control-ledger.test.js | a rotated placeholder says to ask again, and the newest still works | not yet ported |
| fix-control-ledger.test.js | an explicit placeholder ttl cannot outlast the grant's | not yet ported |
| fix-control-ledger.test.js | an explicit placeholder ttl shorter than the grant's is kept | not yet ported |
| fix-control-listeners.test.js | listen rm stops the listener at once, not at the next restart | not yet ported |
| fix-control-listeners.test.js | removing a listener that is configured but not bound still works | not yet ported |
| fix-control-listeners.test.js | --allow-cidr is enforced: a peer outside it is refused | not yet ported |
| fix-control-listeners.test.js | a peer inside --allow-cidr is served, and no list means no restriction | not yet ported |
| fix-control-listeners.test.js | an allow-cidr that cannot be parsed is refused, not stored and ignored | not yet ported |
| fix-control-listeners.test.js | a TLS peer connected before listen rm is not served after it | not yet ported |
| fix-control-listeners.test.js | an established TLS connection is dropped by listen rm, and a fresh one is served before it | not yet ported |
| fix-control-mcp.test.js | a streamed response comes back as a body, and the stream is read to the end | not yet ported |
| fix-control-mcp.test.js | a buffered response is unchanged | not yet ported |
| fix-control-mcp.test.js | vault_http does not leave a live placeholder behind per call | not yet ported |
| fix-control-mcp.test.js | the session token is what authenticates, so a query-site credential works | not yet ported |
| fix-control-mcp.test.js | vault_request_session carries ttl_minutes and uses to the human | not yet ported |
| fix-control-page.test.js | what the page signs for a narrowing is what the server rebuilds | not yet ported |
| fix-control-page.test.js | a narrowed approval made the way the page makes it goes through | not yet ported |
| fix-control-page.test.js | the hand-off example sends the token where it cannot displace the placeholder | not yet ported |
| fix-control-page.test.js | the docs name every MCP tool, and only injection sites that exist | not yet ported |
| fix-control-page.test.js | without a passphrase the page gives the daemon's guidance instead of a tap | not yet ported |
| fix-control-presence.test.js | the shared window cannot enrol an unlock factor or replace the authenticator | not yet ported |
| fix-control-presence.test.js | with the passphrase in the request, the same changes go through | not yet ported |
| fix-control-presence.test.js | a vault with only an authenticator can still rotate it, by assertion | not yet ported |
| fix-control-presence.test.js | removing Touch ID unlock by assertion works; by window it does not | not yet ported |
| fix-control-presence.test.js | one window still covers an ordinary multi-step flow, and each step is recorded | not yet ported |
| fix-control-presence.test.js | locking closes the window | not yet ported |
| fix-control-presence.test.js | the web UI enrolment passes the passphrase through, with no window | not yet ported |
| fix-control-presence.test.js | an assertion from a page the caller named is refused | not yet ported |
| fix-control-presence.test.js | an assertion from the default UI origin is accepted | not yet ported |
| fix-control-presence.test.js | trusting another UI origin needs the owner, and then it works | not yet ported |
| fix-control-presence.test.js | with no factor enrolled, a fresh-presence change is refused, not waved through | not yet ported |
| fix-control-presence.test.js | a fresh proof opens no window | not yet ported |
| fix-control-process.test.js | an uncaught error in the daemon is recorded, and the daemon keeps answering | not yet ported |
| fix-control-process.test.js | an ordinary run records no fault, and stopping removes the guard | not yet ported |
| fix-control-session-requests.test.js | asking returns a collect secret, and nothing lists it | not yet ported |
| fix-control-session-requests.test.js | another agent cannot collect a token by knowing the request id | not yet ported |
| fix-control-session-requests.test.js | over MCP, polling needs the secret the request returned | not yet ported |
| fix-control-session-requests.test.js | the human who approves gets the session in the gated decision itself | not yet ported |
| fix-control-session-requests.test.js | settled requests do not fill the waiting room | not yet ported |
| fix-control-session-requests.test.js | genuinely pending requests are still capped | not yet ported |
| fix-control-session-requests.test.js | settled requests age out of memory | not yet ported |
| fix-control-session-requests.test.js | tokenless MCP initialize cannot grow the session map or the audit log without bound | not yet ported |
| fix-control-session-requests.test.js | issuing a placeholder with no live session says so, not TypeError | not yet ported |
| fix-control-session-requests.test.js | the web page never sees the token, single or batch | not yet ported |
| fix-control-session-requests.test.js | anonymous MCP open and close cycles write nothing to the audit log | not yet ported |
| fix-control-session-requests.test.js | an authenticated client's MCP session is recorded when it opens and when it closes | not yet ported |
| fix-control-store.test.js | the no-wider check itself refuses a result that dropped a constraint | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | narrowGrant can only intersect, never widen | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | narrowGrant still narrows | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | a forked session can only narrow its parent's grants | not yet ported |
| fix-control-store.test.js | an expired session takes its placeholders with it | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | the ledger bound collects active rows whose time has passed | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | a placeholder lives as long as its session, idle extension included | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | a placeholder with its own ttl still expires on time | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | booting a locked vault does not record an unlock nobody performed | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-store.test.js | booting an unlocked vault still unlocks it | ported in av-store (see rust/crates/av-store/PORTED.md) |
| fix-control-touchid.test.js | enrolling Touch ID unlock from the UI works with one tap | not yet ported |
| fix-control-touchid.test.js | a tap over one PRF secret cannot enrol another | not yet ported |
| fix-control-touchid.test.js | the daemon still refuses an enrol that carries no proof at all | not yet ported |
| fix-control-touchid.test.js | removing Touch ID unlock from the UI works with one tap | not yet ported |
| fix-control-touchid.test.js | without a passphrase, Touch ID unlock is refused before the tap, and says what to do | not yet ported |
| fix-control-touchid.test.js | once a passphrase is set, the same vault enrols Touch ID unlock with one tap, and both open it | not yet ported |
| fix-control-touchid.test.js | a vault with no factor at all is refused Touch ID unlock with the same way forward | not yet ported |
| fix-control-touchid.test.js | without a passphrase, the presence authenticator rotates by a tap from itself, through the UI | not yet ported |
| fix-control-touchid.test.js | a first presence enrolment without a passphrase is refused with the same way forward | not yet ported |
| fix-control-uicookie.test.js | an authenticated call slides the cookie; an unauthenticated one is not activity | not yet ported |
| fix-control-webauthn.test.js | a request field named op cannot replace the route op | not yet ported |
| fix-control-webauthn.test.js | a supplied digest cannot replace the one computed from the secret | not yet ported |
| fix-control-webauthn.test.js | an ordinary request still binds every field, and the secret only by digest | not yet ported |
| fix-control-webauthn.test.js | a signature for a narrow session cannot issue a placeholder | not yet ported |
| fix-control-webauthn.test.js | a signature over the real placeholder request still works | not yet ported |
| gateway-approvals.test.js | an approval that already ran cannot be denied, and the deny hands back nothing | tests/ported_gateway_core.rs::consumed_approval_cannot_be_denied_or_rearmed_and_resend_only_replays |
| gateway-approvals.test.js | granting an approval that already ran does not arm it again | tests/ported_gateway_core.rs::consumed_approval_cannot_be_denied_or_rearmed_and_resend_only_replays |
| gateway-approvals.test.js | a granted approval cannot be flipped to denied before it is sent | tests/ported_gateway_core.rs::granted_approval_cannot_flip_and_pending_decisions_return_no_cached_result |
| gateway-approvals.test.js | deciding a pending approval still works, both ways, and returns no response body | tests/ported_gateway_core.rs::granted_approval_cannot_flip_and_pending_decisions_return_no_cached_result |
| gateway-approvals.test.js | literal marker text cannot make two different requests hash alike | tests/ported_gateway_core.rs::literal_hash_marker_cannot_swap_header_and_json_injection_sites |
| gateway-approvals.test.js | reordering the values of a repeated header changes the request hash | tests/ported_gateway_core_units.rs::repeated_header_values_keep_order_in_request_hash_but_header_names_do_not |
| gateway-approvals.test.js | a method-override header is held to the methods allowlist | `tests::gateway::hardening_a_method_override_is_held_to_the_methods_allowlist` |
| gateway-approvals.test.js | a method-override header counts for approval, and the human is shown it | tests/ported_gateway_core.rs::method_override_participates_in_approval_and_safe_ordinary_methods_pass |
| gateway-approvals.test.js | ordinary requests are not affected by the override checks | tests/ported_gateway_core.rs::method_override_participates_in_approval_and_safe_ordinary_methods_pass |
| gateway-approvals.test.js | a failure before connecting refunds every placeholder the request spent | tests/ported_gateway_core.rs::refund_depends_on_whether_upstream_could_have_received_both_placeholder_fields |
| gateway-approvals.test.js | a failure that may have reached the server refunds nothing | tests/ported_gateway_core.rs::refund_depends_on_whether_upstream_could_have_received_both_placeholder_fields |
| gateway-approvals.test.js | a streamed approval that ran does not leave its resend waiting forever | tests/ported_gateway_core.rs::streamed_or_failed_consumed_approval_gets_a_new_visible_pending_id |
| gateway-approvals.test.js | a buffered approval whose replay window closed is asked for again, not stuck | tests/ported_gateway_core.rs::expired_buffered_replay_is_held_under_a_new_visible_id |
| gateway-approvals.test.js | a request that failed after reaching the upstream is asked for again, not stuck | tests/ported_gateway_core.rs::streamed_or_failed_consumed_approval_gets_a_new_visible_pending_id |
| gateway-approvals.test.js | a resend while the approved request is still in flight keeps waiting on it | tests/ported_gateway_core.rs::in_flight_resend_waits_for_original_approval_and_replays_after_completion |
| gateway-approvals.test.js | renewing the placeholder inside a Basic header keeps the approval | tests/ported_gateway_core.rs::basic_placeholder_renewal_preserves_approval_but_user_and_padding_changes_do_not |
| gateway-approvals.test.js | a different Basic user, or another spelling of the same header, still needs its own approval | tests/ported_gateway_core.rs::basic_placeholder_renewal_preserves_approval_but_user_and_padding_changes_do_not |
| gateway-core.test.js | the scrubber catches the encodings it used to miss | tests/ported_gateway_core_units.rs::escaped_and_wrapped_secret_shapes_are_redacted_with_ordinary_controls |
| gateway-core.test.js | the scrubber leaves ordinary escaped and wrapped text alone | tests/ported_gateway_core_units.rs::ordinary_escaped_wrapped_and_partial_text_is_unchanged |
| gateway-core.test.js | a percent-encoded secret split across stream chunks is still caught | tests/ported_gateway_core_units.rs::percent_secret_and_derived_token_straddling_holdback_are_not_emitted_in_halves |
| gateway-core.test.js | a derived token straddling the stream hold-back is not emitted in halves | tests/ported_gateway_core_units.rs::percent_secret_and_derived_token_straddling_holdback_are_not_emitted_in_halves |
| gateway-core.test.js | the stream scrubber still emits ordinary text unchanged | tests/ported_gateway_core_units.rs::percent_secret_and_derived_token_straddling_holdback_are_not_emitted_in_halves |
| gateway-core.test.js | a backslash encoded more than once is still refused | tests/ported_gateway_core_units.rs::path_parser_refuses_reencoded_separators_but_preserves_ordinary_paths_and_literal_percent |
| gateway-core.test.js | ordinary encoded paths still normalise | tests/ported_gateway_core_units.rs::path_parser_refuses_reencoded_separators_but_preserves_ordinary_paths_and_literal_percent |
| gateway-core.test.js | a literal percent sign can be sent, and still cannot hide an escape | tests/ported_gateway_core_units.rs::path_parser_refuses_reencoded_separators_but_preserves_ordinary_paths_and_literal_percent |
| gateway-core.test.js | intersecting two rates never allows more than either | tests/ported_gateway_core_units.rs::rate_intersections_never_widen_and_invalid_units_are_refused |
| gateway-core.test.js | intersecting rates in the same unit is the smaller count | tests/ported_gateway_core_units.rs::rate_intersections_never_widen_and_invalid_units_are_refused |
| gateway-core.test.js | lint accepts valid enforced limits | tests/ported_gateway_core_units.rs::lint_accepts_valid_enforced_rate_concurrency_and_budget_limits |
| gateway-core.test.js | JSON substitution changes the one string and nothing else in the body | tests/ported_gateway_core.rs::json_substitution_preserves_numbers_spacing_and_escapes |
| gateway-core.test.js | JSON substitution follows the same duplicate key and pointer escaping as the parser | tests/ported_gateway_core_units.rs::json_duplicate_pointer_and_basic_header_substitution_use_the_parser_selected_position |
| gateway-core.test.js | form substitution leaves the rest of the field and the body as written | tests/ported_gateway_core.rs::form_substitution_preserves_other_bytes_and_encoded_placeholder_spelling |
| gateway-core.test.js | Basic substitution writes the Authorization header the placeholder was found in | tests/ported_gateway_core_units.rs::json_duplicate_pointer_and_basic_header_substitution_use_the_parser_selected_position |
| gateway-core.test.js | Basic substitution through the pipeline, with a second Authorization header present | tests/ported_gateway_core.rs::duplicate_basic_authorization_is_refused_and_single_basic_is_substituted |
| gateway-core.test.js | an ordinary single Basic header is substituted as before | tests/ported_gateway_core.rs::duplicate_basic_authorization_is_refused_and_single_basic_is_substituted |
| gateway-core.test.js | rate layers preserve canonical windows and refuse unknown units at evaluation | tests/ported_gateway_core_units.rs::rate_intersections_never_widen_and_invalid_units_are_refused |
| gateway-core.test.js | base64 wrapped at any width, and hex in mixed case, are redacted | tests/ported_gateway_core_units.rs::escaped_and_wrapped_secret_shapes_are_redacted_with_ordinary_controls |
| gateway-core.test.js | several wrapped blobs in one body are each searched, and the search ends | tests/ported_gateway_core_units.rs::each_wrapped_blob_is_searched_without_changing_neighbors |
| gateway-core.test.js | wrapped prose, short lines, ordinary blobs and ordinary mixed-case hex are left alone | tests/ported_gateway_core_units.rs::ordinary_escaped_wrapped_and_partial_text_is_unchanged |
| gateway-core.test.js | the wrapped and mixed-case views stay linear on large bodies | tests/ported_gateway_core_units.rs::wrapped_and_mixed_case_views_scale_linearly_on_large_ordinary_bodies |
| gateway-core.test.js | a path whose escape was itself encoded is refused, however many times it was | tests/ported_gateway_core.rs::nested_percent_escapes_never_reach_upstream |
| gateway-core.test.js | a path encoded once is sent and checked as before | tests/ported_gateway_core.rs::once_encoded_paths_are_normalized_and_preserved_on_wire |
| gateway-core.test.js | a form placeholder with a percent-encoded character leaves the rest of the body as written | tests/ported_gateway_core.rs::form_substitution_preserves_other_bytes_and_encoded_placeholder_spelling |
| gateway-core.test.js | a placeholder hidden by a duplicate JSON key is refused, however it is hidden | tests/ported_gateway_core.rs::shadowed_json_placeholders_are_refused_and_ordinary_duplicates_survive |
| gateway-core.test.js | locate() reports a placeholder in a shadowed duplicate by position | tests/ported_gateway_core_units.rs::shadowed_placeholder_and_unsubstituted_nonce_are_detected_by_position |
| gateway-core.test.js | a substituted placeholder left anywhere in the outgoing request is found | tests/ported_gateway_core_units.rs::shadowed_placeholder_and_unsubstituted_nonce_are_detected_by_position |
| gateway-core.test.js | ordinary JSON, duplicates without a placeholder in the shadowed copy included, is substituted as before | tests/ported_gateway_core.rs::shadowed_json_placeholders_are_refused_and_ordinary_duplicates_survive |
| gateway-hardening.test.js | a secret in a JSON body with `/` and `uXXXX` escapes does not reach the agent | tests/ported_gateway_core.rs::escaped_json_secrets_are_scrubbed_and_ordinary_json_survives |
| gateway-hardening.test.js | a secret that starts in a content block and continues in its deltas is cut, identity and gzip | `sse::tests::hardening_a_secret_split_across_json_fields_cuts_the_stream` |
| gateway-hardening.test.js | a secret split across events whose index disagrees with its array position is cut | tests/ported_gateway_core.rs::stream_client_indexes_override_array_positions_without_leaking_split_secrets |
| gateway-hardening.test.js | a secret split across events where the index is missing from some of them is cut | tests/ported_gateway_core.rs::missing_stream_indexes_are_safe_for_zero_default_and_distinct_missing_clients |
| gateway-hardening.test.js | a secret base64-encoded and then percent-encoded does not reach the agent in a body, a header or a redirect | tests/ported_gateway_core.rs::url_encoded_base64_secret_is_scrubbed_from_body_header_and_redirect |
| gateway-hardening.test.js | a secret base64-encoded and percent-encoded in a stream is cut | tests/ported_gateway_core.rs::url_encoded_base64_secret_is_removed_from_whole_and_split_stream_events |
| gateway-hardening.test.js | ordinary JSON with `/` in URLs and `u` escapes passes through unmodified | tests/ported_gateway_core.rs::escaped_json_secrets_are_scrubbed_and_ordinary_json_survives (ordinary_json_control) |
| gateway-hardening.test.js | ordinary percent-encoded query strings pass through unmodified in a body, a header and a redirect | tests/ported_gateway_core.rs::ordinary_percent_encoded_query_in_body_headers_and_redirect_survives |
| gateway-hardening.test.js | ordinary Anthropic, OpenAI chat, Responses and Gemini streams pass through unmodified, identity and gzip | tests/ported_gateway_core.rs::ordinary_provider_streams_are_byte_exact_with_identity_and_gzip_and_both_secret_shapes |
| gateway-hardening.test.js | the ordinary streams are left whole when the vault holds a base64-style secret | tests/ported_gateway_core.rs::ordinary_provider_streams_are_byte_exact_with_identity_and_gzip_and_both_secret_shapes |
| gateway-hardening.test.js | Grok's two-layer case: base64 percent-encoded with every % as a uXXXX escape is redacted | tests/ported_gateway_core.rs::json_escaped_percent_encoded_base64_is_scrubbed |
| gateway-hardening.test.js | every pair of the four encodings, nested, is redacted in a buffered body | tests/ported_gateway_core.rs::every_distinct_encoding_pair_is_scrubbed_in_buffered_responses |
| gateway-hardening.test.js | three-layer stacks within the limit are redacted | tests/ported_gateway_core.rs::three_layer_stacks_within_decode_limit_are_scrubbed |
| gateway-hardening.test.js | a four-layer stack is beyond the limit but does not crash | tests/ported_gateway_core.rs::four_layer_stack_is_handled_without_emitting_literal_secret |
| gateway-hardening.test.js | a buffered body whose nesting exceeds the decode budget fails closed, not through | tests/ported_gateway_core.rs::nested_decode_budget_refuses_buffered_body_and_default_budget_delivers_scrubbed_body |
| gateway-hardening.test.js | an event stream whose nesting exceeds the decode budget is cut | tests/ported_gateway_core.rs::nested_decode_budget_cuts_event_stream |
| gateway-hardening.test.js | an ordinary base64 image data URL passes through unmodified | tests/ported_gateway_core.rs::ordinary_base64_image_data_url_survives |
| gateway-hardening.test.js | a large ordinary JSON response with mixed encodings passes through unmodified and uncut | tests/ported_gateway_core.rs::large_ordinary_json_with_mixed_encodings_survives |
| gateway-response.test.js | a secret in a response header NAME does not reach the agent | `tests::gateway::hardening_a_reflected_secret_in_a_header_name_or_value_is_dropped_or_redacted` |
| gateway-response.test.js | a secret split across the text of two Anthropic-shaped events is cut | `sse::tests::hardening_a_secret_split_across_json_fields_cuts_the_stream` |
| gateway-response.test.js | an ordinary Anthropic-shaped stream passes through untouched | `sse::tests::hardening_a_secret_split_across_events_cuts_the_stream_and_ordinary_events_survive` |
| gateway-response.test.js | a CRLF-framed stream is released event by event | `sse::tests::crlf_framing_is_split_too` |
| gateway-response.test.js | a bare-CR stream is released, and a CRLF split across chunks is one line end | tests/ported_gateway_core.rs::bare_cr_and_split_crlf_are_one_stream_line_ending |
| gateway-response.test.js | an event that never ends is cut instead of held without bound | tests/ported_gateway_core.rs::unfinished_event_is_cut_before_unbounded_agent_output |
| gateway-response.test.js | a compressed stream is bounded by what it decodes to, not per chunk | `decode::tests::hardening_streamed_bomb_is_cut_over_the_whole_stream` |
| gateway-response.test.js | an ordinary compressed stream still streams in full | `tests::gateway::hardening_a_gzip_response_and_a_gzip_event_stream_are_decoded_and_scrubbed` |
| gateway-response.test.js | a compressed stream whose source errors neither crashes the daemon nor throws at the writer | tests/ported_gateway_core.rs::errored_identity_and_truncated_gzip_sources_cut_without_crashing_or_hanging |
| gateway-response.test.js | an uncompressed stream that errors before anyone reads it does not crash the daemon | tests/ported_gateway_core.rs::errored_identity_and_truncated_gzip_sources_cut_without_crashing_or_hanging |
| gateway-response.test.js | a compressed stream from a real upstream that resets mid-body ends instead of hanging | tests/ported_gateway_core.rs::real_gzip_upstream_reset_mid_stream_ends_with_cut_instead_of_hanging |
| gateway-response.test.js | a split secret is caught when the event that finishes it is long | tests/ported_gateway_core.rs::long_finishing_events_do_not_hide_split_secrets_and_ordinary_long_events_survive |
| gateway-response.test.js | a split secret is caught in plain-text events when the event that finishes it is long | tests/ported_gateway_core.rs::long_finishing_events_do_not_hide_split_secrets_and_ordinary_long_events_survive |
| gateway-response.test.js | an ordinary stream of long events passes through untouched, compressed or not | tests/ported_gateway_core.rs::long_finishing_events_do_not_hide_split_secrets_and_ordinary_long_events_survive |
| gateway-response.test.js | a stream with more key paths than are tracked is cut, not forgotten | tests/ported_gateway_core.rs::excess_paths_and_index_fields_cut_stream_and_ordinary_path_counts_survive |
| gateway-response.test.js | an ordinary stream over many key paths, below the limit, passes through | tests/ported_gateway_core.rs::excess_paths_and_index_fields_cut_stream_and_ordinary_path_counts_survive |
| gateway-response.test.js | a secret split across events is caught however the keys are spelled, compressed or not | tests/ported_gateway_core.rs::dotted_empty_and_array_key_collisions_cannot_hide_reassembled_secret |
| gateway-response.test.js | an ordinary stream with dotted, empty and numeric keys passes through untouched, compressed or not | tests/ported_gateway_core.rs::ordinary_dotted_empty_numeric_keys_and_multi_provider_nan_streams_survive |
| gateway-response.test.js | a secret split across events is caught however the client regroups them, compressed or not | tests/ported_gateway_core.rs::provider_index_regrouping_decoy_indexes_and_nan_beside_text_cannot_hide_secret |
| gateway-response.test.js | a stream with more index fields over one value than can be combined is cut | tests/ported_gateway_core.rs::excess_paths_and_index_fields_cut_stream_and_ordinary_path_counts_survive |
| gateway-response.test.js | ordinary multi-block, multi-choice and NaN-bearing streams pass through untouched, compressed or not | tests/ported_gateway_core.rs::ordinary_dotted_empty_numeric_keys_and_multi_provider_nan_streams_survive |
| gateway-response.test.js | a buffered upstream that resets mid-body is an upstream failure, and the use is not refunded | `tests::mutants::a_buffered_upstream_reset_mid_body_is_an_unreachable_upstream` |
| gateway-response.test.js | a buffered upstream that completes its body is answered as before | tests/ported_gateway_core.rs::real_buffered_complete_response_and_delete_body_have_correct_framing |
| gateway-response.test.js | a request body goes out with a Content-Length that matches it | `tests::gateway::hardening_a_compressed_request_body_and_a_duplicated_content_type_are_refused` |
| gateway-response.test.js | a DELETE with a body reaches a real upstream framed | tests/ported_gateway_core.rs::real_buffered_complete_response_and_delete_body_have_correct_framing |
| gateway-routing.test.js | /t/https/ to an http credential goes out over https, not in the clear | tests/ported_gateway_core.rs::explicit_https_target_upgrades_http_credential_while_explicit_http_stays_http |
| gateway-routing.test.js | a placeholder with a forged checksum does not keep its session alive | `ported_gateway_core::placeholder_only_authentication_touches_session_only_after_checksum_verification (forged row)` |
| gateway-routing.test.js | a real placeholder as the only carrier still authenticates and keeps the session alive | `ported_gateway_core::placeholder_only_authentication_touches_session_only_after_checksum_verification (authentic row)` |
| gateway-w2-model.test.js | model meters classify only the contracted endpoints and methods | tests/ported_gateway_model.rs::model_endpoint_and_method_classification_is_contract_exact |
| gateway-w2-model.test.js | metered JSON fails closed without echoing request contents | tests/ported_gateway_model.rs::malformed_metered_json_fails_without_echo_and_vendor_json_is_ordinary |
| gateway-w2-model.test.js | reservations use original UTF-8 byte length and provider output limits | tests/ported_gateway_model.rs::reservations_use_original_utf8_bytes_and_provider_output_limit_precedence |
| gateway-w2-model.test.js | invalid or absent output limits use the binding profile defaults | tests/ported_gateway_model.rs::reservations_use_original_utf8_bytes_and_provider_output_limit_precedence |
| gateway-w2-model.test.js | checked prices use microdollars per million tokens and reject unknown USD models | tests/ported_gateway_model.rs::checked_model_prices_round_up_reservations_and_refuse_unknown_or_overflow |
| gateway-w2-model.test.js | reservation prices round up exactly and reject integer overflow | tests/ported_gateway_model.rs::checked_model_prices_round_up_reservations_and_refuse_unknown_or_overflow |
| gateway-w2-model.test.js | buffered usage includes Anthropic cache tokens and both OpenAI response shapes | tests/ported_gateway_model.rs::buffered_provider_usage_includes_cache_and_thinking_tokens_and_rejects_partial_counts |
| gateway-w2-model.test.js | malformed, absent and partial usage cannot turn into a zero charge | tests/ported_gateway_model.rs::buffered_provider_usage_includes_cache_and_thinking_tokens_and_rejects_partial_counts |
| gateway-w2-model.test.js | Anthropic SSE merges message_start cache usage and cumulative message_delta | tests/ported_gateway_model.rs::cumulative_sse_usage_never_decreases_or_double_charges_and_survives_empty_chunks |
| gateway-w2-model.test.js | OpenAI and Google SSE final usage survives chunks without usage and repeated totals | tests/ported_gateway_model.rs::cumulative_sse_usage_never_decreases_or_double_charges_and_survives_empty_chunks |
| gateway-w2-model.test.js | missing usage charges the full reservation; actual usage may exceed it | tests/ported_gateway_model.rs::missing_or_unreadable_usage_charges_full_reservation_but_actual_usage_can_exceed_it |
| gateway-w2-model.test.js | Gemini thinking tokens are charged as output, and a thoughts-only reply still settles | tests/ported_gateway_model.rs::buffered_provider_usage_includes_cache_and_thinking_tokens_and_rejects_partial_counts |
| gateway-w2-payload.test.js | JSON constraints are strict, additive and pointer-aware | tests/ported_gateway_payload.rs::json_constraints_are_strict_additive_and_pointer_aware |
| gateway-w2-payload.test.js | JSON parser rejects duplicate decoded names, malformed input and excess depth | tests/ported_gateway_payload.rs::strict_json_refuses_decoded_duplicate_names_malformed_input_and_excess_depth |
| gateway-w2-payload.test.js | form/query refuse ambiguity and enforce strict names | tests/ported_gateway_payload.rs::form_query_ambiguity_strict_names_and_body_size_are_enforced |
| gateway-w2-payload.test.js | payload validation rejects unknown keys and all malformed constraints | tests/ported_gateway_payload.rs::payload_validation_refuses_unknown_keys_and_malformed_constraints |
| gateway-w2-payload.test.js | GraphQL parses full operations, fragments, arguments and strings | tests/ported_gateway_payload.rs::graphql_parser_checks_full_operations_fragments_arguments_and_strings |
| gateway-w2-payload.test.js | GraphQL request classification checks batches and persisted queries | tests/ported_gateway_payload.rs::graphql_request_classification_checks_batches_persisted_queries_and_decoded_duplicates |
| gateway-w2-pipeline.test.js | rate allows capacity, limits pending requests, and never spends a refused use | tests/ported_gateway_core.rs::rate_capacity_and_pending_requests_are_limited_before_use_or_budget_is_spent |
| gateway-w2-pipeline.test.js | malformed limits and persisted counters fail closed without an upstream | `ported_gateway_core::stored_invalid_limits_and_quota_counters_fail_closed_without_consumption` |
| gateway-w2-pipeline.test.js | quota charges one per call, survives restart and rollback, refunds pre-connect errors | tests/ported_gateway_core.rs::quota_charges_once_survives_restart_and_rollback_and_refunds_preconnect_failure |
| gateway-w2-pipeline.test.js | concurrency releases after success, pre-connect failure and post-connect failure | tests/ported_gateway_core.rs::concurrency_slots_release_after_success_and_both_classes_of_upstream_failure |
| gateway-w2-pipeline.test.js | SSE slots release on completion, immediate close and scrubber cut | tests/ported_gateway_core.rs::sse_concurrency_slots_release_on_completion_agent_close_and_scrubber_cut |
| gateway-w2-pipeline.test.js | payload and method-bound routes run before approval and consume | tests/ported_gateway_core.rs::payload_and_method_bound_routes_refuse_before_approval_or_consume |
| gateway-w2-pipeline.test.js | custom patterns from every credential scrub bodies, headers and errors; corrupt pattern withholds | `ported_gateway_core::global_custom_patterns_scrub_other_credentials_and_corrupt_sources_withhold_output` |
| gateway-w2-pipeline.test.js | token reservations block concurrent overspend and settle buffered usage | tests/ported_gateway_core.rs::token_reservations_refuse_concurrent_overspend_and_settle_buffered_usage |
| gateway-w2-pipeline.test.js | unpriced and unmodeled spend refuses while ordinary free GET passes | tests/ported_gateway_core.rs::unpriced_and_unmodeled_spend_refuse_while_free_get_uses_no_spend_ledger |
| gateway-w2-pipeline.test.js | missing usage and aborted SSE charge full reservation; completed SSE uses usage | tests/ported_gateway_core.rs::missing_or_cut_usage_charges_full_reservation_and_complete_crlf_streams_charge_actual_usage |
| gateway-w2-pipeline.test.js | restart charges outstanding reservation and pre-connect failure releases it | tests/ported_gateway_core.rs::preconnect_spend_is_refunded_and_restart_charges_outstanding_reservations |
| gateway-w2-pipeline.test.js | redirects check hosts, paths, scheme, method, approval and max before sending | `ported_gateway_core::redirect_guards_include_malformed_stored_maximum_and_per_request_approval` |
| gateway-w2-pipeline.test.js | allowed redirect follows, charges each hop and forwards correct pins without body | tests/ported_gateway_core.rs::allowed_redirect_charges_each_hop_preserves_pins_and_never_forwards_body |
| gateway-w2-pipeline.test.js | pins map to safe problem and refund; health observer receives response metadata | `ported_gateway_core::pin_problem_is_safe_and_refunded_and_real_profile_health_receives_metadata` |
| gateway-w2-pipeline.test.js | approval preview scrubs secrets and placeholders and notifications fire once | tests/ported_gateway_core.rs::approval_preview_hides_secrets_and_placeholders_and_notifies_exactly_once |
| gateway-w2-pipeline.test.js | quarantine and grant expiry stop before consume, and denyApprovals returns only a count | tests/ported_gateway_core.rs::quarantine_and_grant_expiry_stop_before_consume_and_bulk_deny_returns_count |
| gateway-w2-pipeline.test.js | preflight is observational, peeks limits and reports a hold without creating approval | tests/ported_gateway_core.rs::preflight_observes_limits_without_mutating_vault_or_creating_approval |
| gateway-w2-pipeline.test.js | preflight denial never trips and the eleventh call is throttled | `ported_gateway_core::preflight_bad_location_denials_do_not_trip_and_eleventh_call_is_throttled` |
| gateway-w2-pipeline.test.js | tripwires revoke only authenticated matching session and deny its approvals | `ported_gateway_core::authenticated_replay_revokes_only_its_session_and_denies_held_approvals` |
| gateway-w2-pipeline.test.js | tripwires default off; panic hook awaits and reports unwired or failed denial honestly | `ported_gateway_core::tripwire_panic_is_opt_in_and_reports_real_success_and_failure_counts` |
| gateway-w2-pipeline.test.js | legacy decimal budgets work while noncanonical values never reach comparisons | `ported_gateway_core::stored_decimal_budget_counts_twice_and_noncanonical_values_are_refused` |
| gateway-w2-pipeline.test.js | a held request previews its label, a redacted secret and no placeholder, token or audit body | tests/ported_gateway_core.rs::held_preview_labels_injection_redacts_secret_and_token_and_keeps_comment_out_of_audit |
| gateway-w2-pipeline.test.js | the preview builder replaces encoded placeholders, keeps duplicate JSON keys as sent, and stays under 8 KiB | tests/ported_gateway_core.rs::preview_builder_replaces_encoded_placeholders_preserves_duplicate_json_and_caps_size |
| gateway-w2-pipeline.test.js | preflight expiration has no state changes and uses the shared expiry predicates | `ported_gateway_core::stored_session_and_grant_expiry_predicates_agree_in_preflight_and_execution` |
| gateway-w2-pipeline.test.js | expired grant fallback keeps its specific error after store marked it expired | `ported_gateway_core::store_marked_expired_grant_retains_its_specific_gateway_error` |
| gateway-w2-pipeline.test.js | quarantine tripwire pauses only its credential and leaves other sessions active | `ported_gateway_core::quarantine_tripwire_pauses_its_credential_and_preserves_active_sessions` |
| gateway-w2-pipeline.test.js | a redirect hop is held to the GraphQL rules a direct request is held to | tests/ported_gateway_core.rs::graphql_and_required_body_rules_are_applied_to_bodyless_redirect_hops |
| gateway-w2-pipeline.test.js | a redirect hop answers to the body rules as a body-less request, not to none | tests/ported_gateway_core.rs::graphql_and_required_body_rules_are_applied_to_bodyless_redirect_hops |
| gateway-w2-pipeline.test.js | a single-valued header sent twice, differently, is refused before anything is sent | tests/ported_gateway_core.rs::conflicting_single_valued_headers_are_refused_without_spending_or_upstream |
| gateway-w2-pipeline.test.js | one Content-Type, or an exact repeat of it, is checked and sent as that one value | tests/ported_gateway_core.rs::exact_repeat_content_type_is_sent_once_and_the_selected_form_rules_apply |
| gateway-w2-pipeline.test.js | a repeated list header goes upstream once per name, carrying every value | `ported_gateway_core::repeated_list_headers_preserve_every_value_and_substitute_only_the_targeted_copy`; ported (header-name casing compared case-insensitively; RFC 9110) |
| gateway-w2-pipeline.test.js | a query a URL would cut or rewrite is refused before the payload rules read it | tests/ported_gateway_core.rs::query_url_rewrite_shapes_are_refused_and_encoded_value_controls_pass |
| gateway-w2-pipeline.test.js | a request a method override made a write does not have its redirect followed | tests/ported_gateway_core.rs::method_override_writes_never_follow_redirect_even_after_human_approval |
| gateway-w2-pipeline.test.js | a followed redirect sends nothing of the agent's but the credential and the hop allowlist | tests/ported_gateway_core.rs::hop_forwards_only_credential_and_allowlisted_agent_headers_and_omits_framing_credentials |
| gateway-w2-pipeline.test.js | a credential declared at a body or framing header is not sent on a hop | tests/ported_gateway_core.rs::hop_forwards_only_credential_and_allowlisted_agent_headers_and_omits_framing_credentials |
| gateway-w2-pipeline.test.js | a Location carrying _method is not followed | tests/ported_gateway_core.rs::location_method_override_fields_are_not_followed |
| gateway-w2-pipeline.test.js | a hop is checked as the method it is sent with: 307 and 308 keep it, 301 to 303 send a GET | tests/ported_gateway_core.rs::redirect_method_is_checked_and_post_is_never_followed_under_any_status |
| gateway-w2-pipeline.test.js | a method override on a direct request is still refused, and an ordinary redirect still follows | tests/ported_gateway_core.rs::direct_route_override_is_denied_but_ordinary_redirect_still_follows |
| gateway-w2-pipeline.test.js | a method-override field naming another method is refused, and nothing is sent | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls |
| gateway-w2-pipeline.test.js | a method-override field naming the request's own method is sent as it is | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls |
| gateway-w2-pipeline.test.js | a hop keeps the API-version headers a provider needs, and never a cookie, override or forwarding header | tests/ported_gateway_core.rs::provider_version_headers_survive_hops_and_cookie_override_forwarding_headers_do_not |
| gateway-w2-pipeline.test.js | Grok round 5, finding 1: a Location naming another method in a folded spelling is not followed | tests/ported_gateway_core.rs::folded_override_location_cannot_gain_a_method_or_skip_onwrite_approval |
| gateway-w2-pipeline.test.js | Grok round 5, finding 2: a ; in the query cannot hide a parameter from the payload rules | tests/ported_gateway_core.rs::semicolon_queries_cannot_hide_ruled_parameters_and_unruled_queries_keep_exact_bytes |
| gateway-w2-pipeline.test.js | every override spelling is refused on a direct request and stops a hop | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control |
| gateway-w2-pipeline.test.js | a ; query is refused under any payload rule on both paths, and goes out unchanged under none | tests/ported_gateway_core.rs::semicolon_queries_cannot_hide_ruled_parameters_and_unruled_queries_keep_exact_bytes |
| gateway-w2-pipeline.test.js | a name a server could fold onto a rule's name is refused, and a repeated name is a duplicate | tests/ported_gateway_core.rs::names_folded_onto_payload_rules_are_ambiguous_and_plain_repeated_names_are_duplicates |
| gateway-w2-pipeline.test.js | generated requests: what the policy read is what a local upstream received, and every reader reads it within the policy | tests/ported_gateway_core.rs::generated_gateway_queries_match_real_wire_and_every_reader_with_positive_and_negative_controls |
| gateway-w2-pipeline.test.js | ordinary traffic is untouched: & queries, provider APIs, and a redirect that keeps its version headers | tests/ported_gateway_core.rs::ordinary_ampersand_provider_and_versioned_redirect_traffic_is_unchanged |
| gateway-w2-pipeline.test.js | the view reads a query as the union of its readers | tests/ported_gateway_payload.rs::query_view_is_union_of_readers_and_payload_rejects_ambiguous_semicolons |
| gateway-w2-pipeline.test.js | Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths |
| gateway-w2-pipeline.test.js | Grok round 6, method: a name PHP reads as _method is refused, and a hop to it is not followed | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths |
| gateway-w2-pipeline.test.js | a stray name is refused on every path under any rules, and a hop to one is not followed | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes |
| gateway-w2-pipeline.test.js | a multipart part is named by every name in its Content-Disposition, folded or not | tests/ported_gateway_core.rs::multipart_content_disposition_reads_every_folded_name_and_preserves_name_star_control |
| gateway-w2-pipeline.test.js | a name is folded the way PHP registers it: cut at NUL, leading spaces dropped | tests/ported_gateway_payload.rs::php_name_folding_cuts_at_nul_drops_leading_spaces_and_marks_only_stray_names |
| gateway-w2-pipeline.test.js | ordinary provider traffic is sent unchanged under the name check | tests/ported_gateway_core.rs::ordinary_nonascii_provider_values_bracket_queries_forms_and_filename_uploads_are_sent_unchanged |
| gateway-w2-pipeline.test.js | Grok round 7, payload: a bracket-wrapped name is refused, and a hop to it is not followed | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths |
| gateway-w2-pipeline.test.js | Grok round 7, method: a bracket-wrapped _method is refused, and a hop to it is not followed | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths |
| gateway-w2-pipeline.test.js | a name Rack 2.2 reads as a ruled one or as _method is refused | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls |
| gateway-w2-pipeline.test.js | a name that starts with punctuation is refused on every path, and a hop to it is not followed | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls |
| gateway-w2-pipeline.test.js | ordinary traffic that opens a name with $ or a JSON key with $ or @ is sent | tests/ported_gateway_core.rs::dollar_query_names_and_dollar_or_at_json_keys_pass_without_rewriting |
| gateway-w2-pipeline.test.js | a repeated list name is sent under unrelated rules, and a rule on its base checks every entry | tests/ported_gateway_core.rs::repeated_list_names_preserve_entries_and_apply_rules_to_each_base_entry |
| gateway-w2-pipeline.test.js | query _method=DELETE | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | form body _method=DELETE | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | JSON {"_method":"DELETE"} | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | lower case value | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | __method | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | percent-encoded name | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | upper case name | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | PHP reads .method as _method | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | PHP reads " method" as _method | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | bracketed | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | semicolon-separated | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | override header spelled as a field | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | form copy after a matching one | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | JSON duplicate, last matches | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | JSON duplicate, first matches | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | JSON non-string value | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | JSON escaped key | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | JSON +json type | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming another method is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | multipart | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | query _method=POST | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | form _method=post | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | JSON {"_method":"POST"} | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | nested JSON field | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | a value, not a name | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | another name | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | a body no framework reads as form | tests/ported_gateway_core.rs::method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls; named subtest of a method-override field naming the request's own method is sent as it is |
| gateway-w2-pipeline.test.js | _method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | %5Fmethod=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | _METHOD=PUT | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | __method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | .method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | %2Emethod=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | _method[]=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | _method%5B%5D=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | _method[0]=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | +method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | %20method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | x-http-method-override=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | X-HTTP-Method-Override=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | x_http_method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | X-Method-Override=PATCH | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | a=1;_method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | a=1;__method=DELETE | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | __method=DELETE&__method=GET | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | .method=GET;force=1 | tests/ported_gateway_core.rs::every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control; named subtest of every override spelling is refused on a direct request and stops a hop |
| gateway-w2-pipeline.test.js | query dry_run=true&force%00=true | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | query dry_run=true&force%00x=true | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | query dry_run=true&force%00[]=true | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | query dry_run=true&+force=true | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | query dry_run=true&%20force=true | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | query dry_run=true&++force=true | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | form amount=2000&force%00=1 | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | form amount=2000&+force=1 | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent |
| gateway-w2-pipeline.test.js | query _method%00=DELETE | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, method: a name PHP reads as _method is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | form a=1&_method%00=DELETE | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, method: a name PHP reads as _method is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | form a=1&%20%20_method=DELETE | tests/ported_gateway_core.rs::php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 6, method: a name PHP reads as _method is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | force%00=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | +force=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | %20%20force=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x%00=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | %00x=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x%01=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | %1Fx=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x%7F=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | %09x=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x%09=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | +x=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x+=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | %20x=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x%20=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x%0Ay=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | %C3%A9=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | caf%C3%A9=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | x%FF=1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | =1 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | a=1&=2 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | a=1;%20b=2 | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/x-www-form-urlencoded "a=1&%09b=2" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/x-www-form-urlencoded "a=1&b%C3%A9=2" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/x-www-form-urlencoded "a=1&force%00=1" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | multipart/form-data; boundary=XyZ "--XyZ\\r\\nContent-Disposition: form-data; name=\\" force\\"\\r\\n\\r\\n1\\r\\n--XyZ--\\r\\n" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | multipart/form-data; boundary=XyZ "--XyZ\\r\\nContent-Disposition: form-data; name=\\"a\\u0001\\"\\r\\n\\r\\n1\\r\\n--XyZ--\\r\\n" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | multipart/form-data; boundary=XyZ "--XyZ\\r\\nContent-Disposition: form-data; name=\\"a\\"; name=\\"bé\\"\\r\\n\\r\\n1\\r\\n--XyZ--\\r\\n" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | multipart/form-data; boundary=XyZ "--XyZ\\r\\nContent-Disposition: form-data;\\r\\n name=\\"a\\t\\"\\r\\n\\r\\n1\\r\\n--XyZ--\\r\\n" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/json "{\\"a\\":1,\\" force\\":true}" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/json "{\\"force\\\\u0000\\":true}" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/json "{\\"model\\":\\"x\\",\\"\\":1}" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/json "{\\"modèle\\":\\"x\\"}" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | multipart/form-data; boundary=XyZ "--XyZ\\r\\nContent-Disposition: form-data; name=\\" _method\\"\\r\\n\\r\\nDELETE\\r\\n--XyZ--\\r\\n" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/json "{\\"a\\":1,\\" _method\\":\\"DELETE\\"}" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | application/json "{\\"_method\\\\u0000\\":\\"DELETE\\"}" | tests/ported_gateway_core.rs::stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes; named subtest of a stray name is refused on every path under any rules, and a hop to one is not followed |
| gateway-w2-pipeline.test.js | query dry_run=true&[force]=true | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 7, payload: a bracket-wrapped name is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | query dry_run=true&%5Bforce%5D=true | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 7, payload: a bracket-wrapped name is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | query dry_run=true&[force][]=true | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 7, payload: a bracket-wrapped name is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | form amount=2000&[force]=1 | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 7, payload: a bracket-wrapped name is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | query [_method]=DELETE | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 7, method: a bracket-wrapped _method is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | form a=1&[_method]=DELETE | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 7, method: a bracket-wrapped _method is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | form a=1&%5B_method%5D=DELETE | tests/ported_gateway_core.rs::bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths; named subtest of Grok round 7, method: a bracket-wrapped _method is refused, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | [x]=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | %5Bx%5D=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | ]x=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | []=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | [_method]=GET | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | @x=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | ~x=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | !x=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | *x=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | %2Fx=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | :x=1 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-pipeline.test.js | a=1&{x}=2 | tests/ported_gateway_core.rs::rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls; named subtest of a name that starts with punctuation is refused on every path, and a hop to it is not followed |
| gateway-w2-policy.test.js | route pairs bind methods to their own paths and every inherited set applies | tests/ported_gateway_core_units.rs::route_pairs_bind_methods_to_paths_and_every_inherited_set_applies |
| gateway-w2-policy.test.js | stored effective route and payload policies retain all ancestor constraints | tests/ported_gateway_core_units.rs::reused_effective_route_and_payload_sets_retain_every_ancestor_constraint |
| gateway-w2-policy.test.js | malformed stored route and payload constraints refuse before reaching upstream | tests/ported_gateway_core_units.rs::malformed_stored_route_payload_and_unknown_approval_modes_fail_closed |
| gateway-w2-policy.test.js | creation refuses coercion, supports zero limits, and cannot escape credential hosts | tests/ported_gateway_core_units.rs::grant_creation_rejects_coercion_and_host_escape_but_allows_zero_limits |
| gateway-w2-scrub.test.js | restricted scrub grammar refuses dangerous or broad expressions | tests/ported_gateway_scrub.rs::restricted_custom_pattern_grammar_rejects_dangerous_and_broad_expressions |
| gateway-w2-scrub.test.js | extra patterns are additive to stored secret and derived protections | tests/ported_gateway_scrub.rs::custom_patterns_are_additive_to_stored_and_derived_secret_protection |
| gateway-w2-scrub.test.js | extra patterns survive every stream chunk boundary | tests/ported_gateway_scrub.rs::custom_token_is_redacted_at_every_two_chunk_cut_and_every_odd_chunk_width |
| gateway-w2-scrub.test.js | long custom tokens do not leak when bounded suffix spans stream windows | tests/ported_gateway_scrub.rs::long_bounded_tokens_and_escaped_prefixes_are_redacted_across_single_character_chunks |
| gateway-w2-scrub.test.js | invalid persisted compiled patterns fail closed | not applicable, because Rust ExtraPattern stores source and recompiles it; the JS precompiled-regex-without-metadata shape is unrepresentable (corrupt-source control: tests/ported_gateway_scrub.rs::corrupt_persisted_pattern_source_fails_closed_before_any_output) |
| gateway-w2-scrub.test.js | escaped literal prefixes retain custom matches across chunks | tests/ported_gateway_scrub.rs::long_bounded_tokens_and_escaped_prefixes_are_redacted_across_single_character_chunks |
| gateway-w2-scrub.test.js | bounded grammar refuses combinatorial repetition and accepts realistic shapes promptly | tests/ported_gateway_scrub.rs::bounded_grammar_refuses_combinatorial_repetition_and_scans_realistic_shapes_promptly |
| gateway-w2-scrub.test.js | every accepted pattern scans hostile input in under 50 ms | tests/ported_gateway_scrub.rs::hostile_input_scans_meet_bound_and_non_bmp_repetitions_are_refused_as_planned; ported (intended difference: rust/PLAN.md non-BMP repetition) |
| gateway-w2-scrub.test.js | a stream that mentions a pattern prefix keeps flowing, and its holdback stays bounded | tests/ported_gateway_scrub.rs::ordinary_prefix_traffic_keeps_flowing_with_bounded_holdback |
| gateway-w2-scrub.test.js | a custom token straddling every possible cut is redacted whole, in any chunking | tests/ported_gateway_scrub.rs::custom_token_is_redacted_at_every_two_chunk_cut_and_every_odd_chunk_width |
| gateway-w2-seams.test.js | pins on a plaintext credential refuse before any connection; no pins still connects | `ported_gateway_core::plaintext_pins_refuse_before_connecting_and_unpinned_control_connects` |
| gateway-w2-seams.test.js | a throwing health reader or recorder never turns an executed request into a failure | `ported_gateway_core::real_health_write_contention_preserves_executed_response_consumption_and_audit` |
| gateway-w2-seams.test.js | onPending gets the id and headline only, and a throwing hook still holds the request | `ported_gateway_core::pending_notice_contains_only_safe_summary_and_refusing_webhook_cannot_release_request` |
| gateway-w2-seams.test.js | denyApprovals filters by session, credential and grant ids, records the reason, and returns a count | tests/ported_gateway_core.rs::deny_approvals_filters_by_session_or_grant_records_reason_and_skips_consumed_requests |
| gateway-w2-seams.test.js | panic denies held requests, revokes every session including an infinite one, then the hook, then the record, then the lock | `ported_gateway_core::panic_denies_held_work_then_revokes_finite_and_infinite_sessions_before_record_and_lock` |
| gateway-w2-seams.test.js | a panic whose hook fails still revokes everything and records a partial panic | `ported_gateway_core::real_session_request_metadata_failure_does_not_prevent_panic_revocation_and_partial_record` |
| gateway-w2-seams.test.js | a tripwire that throws while firing cannot cost the agent its denial | `ported_gateway_core::failing_tripwire_quarantine_write_preserves_original_agent_denial` |
| gateway-w2-seams.test.js | with tripwires on, a bad-location run revokes the session; ordinary requests never count | `ported_gateway_core::malformed_tripwire_rules_keep_defaults_and_only_bad_location_requests_count` |
| gateway-w2-seams.test.js | an unauthenticated replay never counts against the session its placeholder names | `ported_gateway_core::unissued_placeholder_replay_counts_only_after_session_authentication` |
| gateway-w2-seams.test.js | a quarantined credential is refused before anything is spent, and works again once released | tests/ported_gateway_core.rs::quarantine_refuses_without_spending_limits_and_release_restores_ordinary_request |
| gateway-w2-seams.test.js | preflight and the real route agree on finite, expired, infinite and legacy sessions and grants | `ported_gateway_core::stored_session_and_grant_expiry_predicates_agree_in_preflight_and_execution` |
| gateway-w2-seams.test.js | preflight writes one record with nulls, not undefined, and puts no hint where there was none | tests/ported_gateway_core.rs::preflight_audit_uses_nulls_and_unhinted_checks_never_have_nonstring_hints |
| gateway-w2-seams.test.js | a redirect to another port on an allowed host is not followed; the same port is | tests/ported_gateway_core.rs::redirect_port_must_match_and_failed_hop_is_not_refunded |
| gateway-w2-seams.test.js | a redirect hop that cannot connect closes the redirect it was following and is not refunded | tests/ported_gateway_core.rs::redirect_port_must_match_and_failed_hop_is_not_refunded |
| gateway-w2-seams.test.js | GraphQL rules read the URL query on a POST too, and the decided path ends the /graphql check | tests/ported_gateway_core.rs::graphql_checks_post_url_query_and_normalized_graphql_path |
| gateway-w2-seams.test.js | a binary upload passes a grant whose payload rules only constrain the query | tests/ported_gateway_core.rs::query_only_payload_rules_allow_binary_upload_and_refuse_unsafe_query |
| gateway-w2-seams.test.js | a strict-query refusal names the parameter by its index and never echoes a name or value | tests/ported_gateway_core.rs::strict_query_denials_name_positions_and_never_echo_hostile_names_or_values |
| gateway-w2-seams.test.js | a spend refusal says what is left and what the call could cost; a call that fits passes | tests/ported_gateway_core.rs::spend_denial_explains_remaining_and_worst_case_while_bounded_call_settles_real_usage |
| gateway-w2-seams.test.js | a CRLF-framed stream settles on its usage; a cut stream charges the full reservation | tests/ported_gateway_core.rs::missing_or_cut_usage_charges_full_reservation_and_complete_crlf_streams_charge_actual_usage |
| gateway-w2-seams.test.js | a pipeline built while the vault is locked charges stale reservations at the first request after unlock | tests/ported_gateway_core.rs::locked_pipeline_recovers_stale_reservation_on_first_request_after_unlock |
| gateway-w2-seams.test.js | an extra pattern scrubs an error detail, is redacted within an event, and cuts a stream that splits it | `ported_gateway_core::custom_pattern_redacts_error_and_single_event_and_cuts_split_stream_with_prefix_control` |
| gateway-w2-seams.test.js | a method-override header is held to the route pairs as well as the methods list | tests/ported_gateway_core.rs::method_override_is_bound_by_route_pairs_and_allowed_tmp_control_runs |
| gateway-w2-seams.test.js | a held request is recorded as held, an allowed one as allow, a refused one as deny (C11) | tests/ported_gateway_core.rs::held_allowed_and_denied_requests_are_recorded_with_the_right_decisions |
| integrate2-c12-surfaces.test.js | /p/ on a network listener: the infinite token is refused before anything is sent, a finite one works | not yet ported |
| integrate2-c12-surfaces.test.js | /mcp on a network listener: every tool that needs a session refuses the infinite token as AV_REMOTE_FORBIDDEN, sends nothing, mints nothing, and records it | not yet ported |
| integrate2-c12-surfaces.test.js | /mcp on a network listener: the handshake and the ungated tools treat the infinite token as a dead one | not yet ported |
| integrate2-c12-surfaces.test.js | /mcp on a network listener: a finite token is unchanged | not yet ported |
| integrate2-c12-surfaces.test.js | /v1 on a network listener: every session route refuses the infinite token with 403 infinite_remote; /v1/status stays open | not yet ported |
| integrate2-c12-surfaces.test.js | /v1 on a network listener: a finite token is unchanged | not yet ported |
| integrate2-c12-surfaces.test.js | on loopback (built-in gateway, TCP and TLS listeners) the infinite token works on every surface | not yet ported |
| integrate2-c12-surfaces.test.js | stdio MCP has no network listener and stays loopback for an infinite session | not yet ported |
| integrate2-c12-surfaces.test.js | vault_http hands its listener to the pipeline, which refuses an infinite session there by itself | not yet ported |
| integrate2-c12-surfaces.test.js | the vault answers C12 for a peek and for a use alike, and records only the use | not yet ported |
| integrate2-seams.test.js | a correct leaf pin goes out through the real pinnedRequest, with the secret and the URL host | not yet ported |
| integrate2-seams.test.js | a wrong pin on an untrusted self-signed upstream sends nothing and is refunded; its own leaf pin is reached | not yet ported |
| integrate2-seams.test.js | on a chain the daemon trusts, an intermediate or leaf pin is honoured, and a pin that matches nothing is AV_PIN_MISMATCH, refunded and unsent | not yet ported |
| integrate2-seams.test.js | the same chain with an intermediate pin is refused, unsent, when the daemon does not trust its root | not yet ported |
| integrate2-seams.test.js | the agent's Host header never reaches the connector; a Host that did would be refused unsent (C9) | not yet ported |
| integrate2-seams.test.js | a repeated list header goes out folded into one line, not refused as header_format | not yet ported |
| integrate2-seams.test.js | a malformed pin table on a credential is pinned, not unpinned: refused before a connection | not yet ported |
| integrate2-seams.test.js | the connectors health reader and the store record what a response says (F10) | not yet ported |
| integrate2-seams.test.js | an expired grant is refused before anything is sent, and stays expired, not missing (F18) | not yet ported |
| integrate2-seams.test.js | each redirect hop is charged to the grant by the store, and the hop past the budget is not followed (F6) | not yet ported |
| integrate2-seams.test.js | a grant layer with no limit is bounded by the session layer, and its hops are charged (C4, one reader) | not yet ported |
| integrate2-seams.test.js | a credential the store quarantined is refused before any send, and a tripwire quarantines through the store (F16) | not yet ported |
| integrate2-seams.test.js | preflight and the real route agree, read with the store itself, on finite, expired, infinite and legacy sessions | not yet ported |
| integrate2-seams.test.js | a scrub pattern the store saves is applied by the gateway, and one the grammar refuses is never saved | not yet ported |
| integrate2-seams.test.js | a held request is recorded as held, and the store report counts it as held, not as a use (C11) | not yet ported |
| integrate2-seams.test.js | panic: the wired hook denies pending session requests, and a throwing hook still completes the panic (C1) | not yet ported |
| integrate2-seams.test.js | an infinite session is refused on a network listener, with nothing sent and the refusal recorded (C12) | not yet ported |
| integrate2-seams.test.js | a finite session on a network listener is unchanged by C12 | not yet ported |
| integrate3-c25.test.js | C25: shapeOf names the fields a proposal sets and counts its lists; narrowedOf names what a human changed | not yet ported |
| integrate3-c25.test.js | C25: every r2 and r3 form, in paths, routes, payload, reason and every number, reaches no record; decide keeps the grant whole | not yet ported |
| integrate3-c25.test.js | C25: decide-many records the same structure, and pending.decided_many holds only ids | not yet ported |
| integrate3-c25.test.js | C25: a denial, and a panic denial, record structure only | not yet ported |
| integrate3-c25.test.js | C25: a value rotated out (retireMs 0) between the ask and decide is in no record, and the gateway enforces the grant | not yet ported |
| integrate3-c25.test.js | C25: a human override holding a former secret and a PIN is recorded as the names it narrowed, nothing more | not yet ported |
| integrate3-c25.test.js | F6: placeholder.issued and placeholder.refunded carry no use ceiling; a human-made session keeps its expiry in the log | not yet ported |
| integrate3-c25.test.js | C25: no request record is written with a value even when the secrets cannot be read | not yet ported |
| integrate3-e2e-approvals.test.js | A.7 6 (F13, F14): watch prints a held POST, the preview hides the placeholder, and the approved resend runs once | not yet ported |
| integrate3-e2e-approvals.test.js | A.7 7 (F15): session narrow --methods GET mid-run refuses the next POST and keeps GET working | not yet ported |
| integrate3-e2e-approvals.test.js | A.7 7 (F16): with the tripwire on, a replayed placeholder revokes its session before the answer returns | not yet ported |
| integrate3-e2e-gateway.test.js | A.7 4 (F1): --rate and --quota refuse the call past the limit with retry_after, and nothing past it is sent | not yet ported |
| integrate3-e2e-gateway.test.js | A.7 4 (F1): --concurrency 1 refuses a second call while the first is in flight, and not one after it | not yet ported |
| integrate3-e2e-gateway.test.js | A.7 4 (F2): a JSON payload rule refuses a value outside it before anything is sent, and passes one inside it | not yet ported |
| integrate3-e2e-gateway.test.js | A.7 4 (F3): method-bound routes allow each method only on its own paths | not yet ported |
| integrate3-e2e-gateway.test.js | A.7 4 (F5): a token budget refuses a call that could exceed it, and settles a call that fits on its real usage | not yet ported |
| integrate3-e2e-gateway.test.js | A.7 4 (F6): --redirects follows a hop the policy allows, stops at one it does not, and never follows without it | not yet ported |
| integrate3-e2e-gateway.test.js | A.7 5 (F7): rotating with keep while an agent loops loses no request, and the old value stays scrubbed | not yet ported |
| integrate3-e2e-preflight.test.js | A.7 10 (F19, F20): a preflight changes nothing but its audit record, and session show counts only the real request | not yet ported |
| integrate3-e2e-sessions.test.js | A.7 1 (R1): --approval auto asks for the passphrase on a terminal, and a POST is then not held | not yet ported |
| integrate3-e2e-sessions.test.js | A.7 1 (R1): the same command with the window open and no passphrase is refused, and nothing is made | not yet ported |
| integrate3-e2e-sessions.test.js | A.7 2 (R2): env writes a 0600 file of placeholders, refuses to replace it, and exec sends the real value upstream | not yet ported |
| integrate3-e2e-sessions.test.js | A.7 3 (R3): an infinite session lists as never, says infinite over MCP, and panic revokes it | not yet ported |
| integrate3-e2e-templates.test.js | A.7 8 (F17): a session requested by template matches the snapshot it was asked from, not the edited template | not yet ported |
| integrate3-e2e-templates.test.js | A.7 9 (F18): a grant with --grant-ttl 1 ends with AV_GRANT_EXPIRED on a fake clock; the other grant still works | not yet ported |
| integrate3-fix1.test.js | D1: the daemon refuses a decision whose overrides name a key it will not apply, naming the key, and decides nothing | not yet ported |
| integrate3-fix1.test.js | D1: nothing the CLI or the page can send on a valid path names a key the daemon refuses | not yet ported |
| integrate3-fix1.test.js | D2: towardPage withholds passphrase at any depth, in any case or hyphenation | not yet ported |
| integrate3-fix1.test.js | D2 (round 3): a run of hyphens, underscores or spaces is one separator, so pass--phrase, pass__phrase and "pass phrase" are withheld | not yet ported |
| integrate3-gates.test.js | C19: the page, webauthn.js and so the daemon digest every secret-bearing key the same way | not yet ported |
| integrate3-gates.test.js | every gated UI route: the operation the page signs is the one the UI server and the real daemon rebuild | not yet ported |
| integrate3-gates.test.js | C22(4): a pin removal signed without spki, or for another spki, is refused by the UI and by the daemon | not yet ported |
| integrate3-gates.test.js | C19 end to end: a backup bundle is bound by its canonical digest when the daemon restores it | not yet ported |
| integrate3-gates.test.js | C19 end to end: a webhook URL is bound by digest, and the page signs what the daemon checks | not yet ported |
| integrate3-narrowing.test.js | the page reads every narrowing with the module's parser, and keeps no second one | not yet ported |
| integrate3-narrowing.test.js | the CLI and the page sign the same operation for the same narrowing, field by field | not yet ported |
| integrate3-narrowing.test.js | through the UI server, each narrowing signed by the page is approved by the real daemon, and kept | not yet ported |
| integrate3-narrowing.test.js | a narrowing that cannot be read: the CLI exits 2 naming the field, and sends nothing | not yet ported |
| integrate3-narrowing.test.js | a narrowing that cannot be read: the page shows why and builds, signs and sends nothing | not yet ported |
| integrate3-narrowing.test.js | a narrowing that cannot be read: the UI server answers 400 and the daemon 4xx, and nothing is approved | not yet ported |
| integrate3-narrowing.test.js | a key no approval applies is refused by the shared parser, the UI server (400), the page and the CLI, as the daemon refuses it | not yet ported |
| integrate3-narrowing.test.js | OVERRIDE_KEYS is the list the self-contained parser reads, key for key | not yet ported |
| integrate3-r4.test.js | C27: a secret as the path glob and the route glob is in no gateway row, before or after rotation; the grant still allows the path | not yet ported |
| integrate3-r4.test.js | C27: a path-only grant records path_rule and a null route_rule, never the glob | not yet ported |
| integrate3-r4.test.js | C27: a deny pattern added by an open narrowing is named by index in the denial, never by its text | not yet ported |
| integrate3-r4.test.js | F2: decide-many writes only ids the daemon minted, and counts the rest | not yet ported |
| integrate3-r4.test.js | C26: elevationOf names first-use with a write method, and not read-only first-use | not yet ported |
| integrate3-r4.test.js | C26: creating first-use with writes needs a fresh proof; read-only first-use rides the window | not yet ported |
| integrate3-r4.test.js | C26: approving a request into first-use with writes needs a fresh proof, not the window | not yet ported |
| integrate3-r4.test.js | C26: narrowing a request into first-use with a write left needs a fresh proof; narrowing it to read-only does not | not yet ported |
| integrate3-r4.test.js | C26: a live narrowing cannot loosen a write grant into first-use | not yet ported |
| integrate3-r4.test.js | a boolean flag given a value, even "false", is refused with exit 2 naming the flag | not yet ported |
| integrate3-r4.test.js | a numeric flag with no value is refused with exit 2 naming the flag, not read as 1 | not yet ported |
| integrate3-r5.test.js | F1: a refused Touch ID assertion records a closed code, never the client data it quotes, on all three surfaces | not yet ported |
| integrate3-r5.test.js | C28: a denial row has the code, rule, method and path, and no sentence; explain-denial gives the sentence to its own session only | not yet ported |
| integrate3-r5.test.js | C28: a payload rule names its key by index, and a strict query names the parameter by position, on all three surfaces | not yet ported |
| integrate3-r5.test.js | C28: a redirect refused for its host records no host it was not allowed to reach | not yet ported |
| integrate3-r5.test.js | C28: a fault is recorded by class, never by message | not yet ported |
| integrate3-r5.test.js | C28: a listener that cannot bind records its system code, not the message | not yet ported |
| integrate3-r5.test.js | C28: session.created says whether a session has a label, not what it says | not yet ported |
| integrate3-r5.test.js | C28: a failed webhook records a system code or `error`, never other text from the error | not yet ported |
| integrate3-r5.test.js | C28: every *_untrusted field is scrubbed whole, cleaned of placeholders, and cut to 200 | not yet ported |
| integrate3-r5.test.js | C28: a quarantine reason restored from a bundle is cleaned before it is recorded | not yet ported |
| integrate3-r5.test.js | item 3: mcp install --tls takes no value; bare --tls is the https URL and its absence the plain one | not yet ported |
| integrate3-r6.test.js | B1: tripwire show on a vault that never saved rules lists the defaults; set edits them; on keeps them | not yet ported |
| integrate3-r6.test.js | B1: the page shows the defaults as defaults, and turning on stores them, when none were saved | not yet ported |
| integrate3-r6.test.js | B2: preflight as documented predicts allow, hold and refuse correctly, and changes nothing but its records | not yet ported |
| integrate3-r6.test.js | N1: approving a narrowed session request prints what was granted, not what the agent asked for | not yet ported |
| integrate3-r6.test.js | N2: cred test names a kind with no probe as exit 7, and --all skips it without hiding a real failure | not yet ported |
| integrate3-r6.test.js | N4: bidi controls and line separators in agent text never reach the terminal | not yet ported |
| integrate3-r6.test.js | N4: every shared cleaner strips bidi controls; the terminal ones strip line separators too | not yet ported |
| integrate3-r6.test.js | r6 F1: a streamed response records a closed media type and encoding, never the upstream header text | not yet ported |
| integrate3-r6.test.js | r6 F2: explain-denial gives code and rule however much was logged since, after eviction and after a restart | not yet ported |
| integrate3-r6.test.js | r6 F2: a caller with no session gets the code and rule of a no-session denial, never its sentence | not yet ported |
| integrate3-seams.test.js | the README and the docs page say how many MCP tools there are, and it is how many mcp.js has | not yet ported |
| integrate3-seams.test.js | F13: a held request carries its preview from the gateway through pending.js and the UI server, and the page escapes it | not yet ported |
| integrate3-seams.test.js | C18: an infinite token is refused on a 0.0.0.0 and a [::] TLS listener by every wave-3 surface, and a finite one works | not yet ported |
| integrate3-seams.test.js | a stored secret an agent puts in a session request path or reason does not reach the audit log | not yet ported |
| integrate3-seams.test.js | an ordinary session request is recorded in the audit log by its shape | not yet ported |
| integrate3-seams.test.js | with the secrets unreadable, the opened record is the same shape and holds nothing the agent wrote | not yet ported |
| invariants.test.js | across thousands of random requests, no credential ever reaches the agent | `ported_gateway_core::invariants_generated_real_daemon_sequences_preserve_all_five_claims_for_2400_random_requests` |
| invariants.test.js | the granted credential reached only the host its grant allows, and nothing else did | `ported_gateway_core::invariants_generated_real_daemon_sequences_preserve_all_five_claims_for_2400_random_requests` |
| invariants.test.js | no placeholder and no session token was ever forwarded upstream | `ported_gateway_core::invariants_generated_real_daemon_sequences_preserve_all_five_claims_for_2400_random_requests` |
| invariants.test.js | a placeholder was never spent more times than it had uses | `ported_gateway_core::invariants_generated_real_daemon_sequences_preserve_all_five_claims_for_2400_random_requests` |
| invariants.test.js | nothing sensitive reached the audit log, and its chain still verifies | `ported_gateway_core::invariants_generated_real_daemon_sequences_preserve_all_five_claims_for_2400_random_requests` |
| listener.test.js | addresses parse, and nonsense is refused rather than half-bound | `tests::control::allow_lists_and_addresses_read_as_the_js_does` |
| listener.test.js | a hostname that merely starts with 127 is not loopback | `tests::control::allow_lists_and_addresses_read_as_the_js_does` |
| listener.test.js | loopback is recognised in every form it arrives in | `tests::control::allow_lists_and_addresses_read_as_the_js_does` |
| listener.test.js | the certificate covers both names a client may use to reach loopback | not yet ported |
| listener.test.js | the private key is not readable by anyone else | `tls::tests::makes_a_loopback_certificate_once_and_keeps_its_key_private` |
| listener.test.js | generating twice reuses the certificate rather than churning it | `tls::tests::makes_a_loopback_certificate_once_and_keeps_its_key_private` |
| listener.test.js | a key that became readable is refused, not loaded anyway | `tls::tests::hardening_a_group_readable_key_is_refused` |
| listener.test.js | a TLS listener binds and serves only the surface it declares | not yet ported |
| listener.test.js | an address with no port is refused when it is added, not at the next restart | `tests::control::listeners_are_validated_and_bound_and_unbound` |
| listener.test.js | a network listener with no TLS is refused at add time too | `tests::control::listeners_are_validated_and_bound_and_unbound` |
| listener.test.js | a listener on a network address without TLS is refused | `tests::control::listeners_are_validated_and_bound_and_unbound` |
| listener.test.js | the listener a request arrived on reaches the pipeline at all | not yet ported |
| locked.test.js | reading the audit log says the vault is locked, not that something broke | not yet ported |
| locked.test.js | verifying the audit chain says the same | not yet ported |
| locked.test.js | a locked vault says its record count is unknown, not zero | not yet ported |
| locked.test.js | the reads the unlock screen depends on still work | not yet ported |
| locked.test.js | unlocking restores the audit log | not yet ported |
| mcp-tools.test.js | a request inside the grant works, so the refusals below mean something | not yet ported |
| mcp-tools.test.js | a path outside the grant never reaches the upstream | not yet ported |
| mcp-tools.test.js | traversal cannot climb out of the granted path | not yet ported |
| mcp-tools.test.js | a credential this session was never granted is unreachable | not yet ported |
| mcp-tools.test.js | CRLF in a path or a header cannot smuggle anything upstream | not yet ported |
| mcp-tools.test.js | the agent cannot set the daemon’s own headers through a tool argument | not yet ported |
| mcp-tools.test.js | a body goes upstream with exactly one content-type | not yet ported |
| mcp-tools.test.js | vault_get_placeholder is bound to the session’s own grants | not yet ported |
| mcp-tools.test.js | no tool returns a credential value, whatever it is asked | not yet ported |
| mcp-tools.test.js | the tool list is exactly the documented tools | not yet ported |
| mcp-tools.test.js | the one capability-shaped tool cannot create capability | not yet ported |
| mcp-tools.test.js | a concurrent request cannot hijack a batch mid-flight | not yet ported |
| mcp-tools.test.js | an agent can ask for the least lifetime it needs, not just the least scope | not yet ported |
| mcp-tools.test.js | no error path names an MCP tool that does not exist | not yet ported |
| mcp-tools.test.js | an agent can find out whether the human answered | not yet ported |
| mcp.test.js | initialize returns a protocol version, server info and a session id | `tests::mcp::the_handshake_and_the_ungated_tools_work_without_a_session` |
| mcp.test.js | no bearer token buys no capability, on any tool that spends it | `tests::mcp::hardening_every_tool_that_spends_capability_checks_for_a_session` |
| mcp.test.js | the MCP session id alone never authenticates | not yet ported |
| mcp.test.js | the handshake works without a session, and says what is missing | `tests::mutants::hardening_the_mcp_handshake_works_without_a_session_over_http` |
| mcp.test.js | asking for a session needs no session, exactly as the HTTP route does not | `tests::mcp::request_session_is_the_proposer_and_polls_with_the_secret_only` |
| mcp.test.js | an unknown MCP session id is rejected rather than silently accepted | not yet ported |
| mcp.test.js | an unsupported protocol version is refused with the supported list | not yet ported |
| mcp.test.js | a browser cannot drive the MCP endpoint | `tests::mutants::hardening_the_mcp_handshake_works_without_a_session_over_http` |
| mcp.test.js | tools/list advertises the tools an agent needs and no secret-bearing tool | `tests::mcp::the_handshake_and_the_ungated_tools_work_without_a_session` |
| mcp.test.js | vault_list_creds tells the agent exactly where a placeholder goes | not yet ported |
| mcp.test.js | vault_http runs the full pipeline and never returns the secret | `tests::mcp::vault_http_runs_the_pipeline_sends_the_token_and_burns_its_placeholder` |
| mcp.test.js | vault_http is bound by the same policy as the gateway | not yet ported |
| mcp.test.js | DELETE ends the transport session but not the vault session | not yet ported |
| mcp.test.js | transport parity: stdio and HTTP produce identical tool results | not yet ported |
| mcp.test.js | batched JSON-RPC messages are answered as a batch | not yet ported |
| mcp.test.js | a notification gets 202 with no body, per the transport spec | not yet ported |
| path-parsing.test.js | the paths the deny list is for are denied | `ported_gateway_core::path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path` |
| path-parsing.test.js | a tab, newline or carriage return cannot smuggle a path past the deny list | `ported_gateway_core::path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path` |
| path-parsing.test.js | an encoded fragment or query cannot truncate the path after the check | `ported_gateway_core::path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path` |
| path-parsing.test.js | percent-encoding is resolved once, and a path that would decode again is refused | `ported_gateway_core::path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path` |
| path-parsing.test.js | an encoded slash is refused rather than guessed | `ported_gateway_core::path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path` |
| path-parsing.test.js | whatever the spelling, the policy reads what the wire will carry | `ported_gateway_core::path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path` |
| path-parsing.test.js | encoding for the wire keeps the characters a path is allowed to contain | `ported_gateway_core::path_wire_encoding_preserves_every_legal_segment_character_and_round_trips_required_escapes` |
| path-parsing.test.js | a path that is only control characters does not become the root | `ported_gateway_core::path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path` |
| pipeline.test.js | the placeholder is replaced with the real secret and only the upstream sees it | `tests::gateway::ordinary_request_substitutes_at_the_declared_site_and_scrubs_the_answer` |
| pipeline.test.js | the session token works as a carrier instead of a placeholder-derived session | `tests::gateway::ordinary_request_substitutes_at_the_declared_site_and_scrubs_the_answer` |
| pipeline.test.js | S06: a valid placeholder aimed at a non-granted host never opens a connection | `ported_gateway_core::pipeline_confinement_rejects_foreign_host_path_and_profile_webhook_before_wire` |
| pipeline.test.js | a path outside the grant is denied before the wire | `ported_gateway_core::pipeline_confinement_rejects_foreign_host_path_and_profile_webhook_before_wire` |
| pipeline.test.js | a write method under a read-only grant is denied | `tests::control::narrowing_only_takes_away` |
| pipeline.test.js | a profile deny list blocks webhook creation even under a wide grant | `ported_gateway_core::pipeline_confinement_rejects_foreign_host_path_and_profile_webhook_before_wire` |
| pipeline.test.js | S25: a placeholder in a request body is refused with zero upstream bytes | `ported_gateway_core::pipeline_encoded_body_and_parser_hidden_placeholder_shapes_never_reach_upstream` |
| pipeline.test.js | encoded placeholders in a body are caught in every encoding | `ported_gateway_core::pipeline_encoded_body_and_parser_hidden_placeholder_shapes_never_reach_upstream` |
| pipeline.test.js | a placeholder in the request path is refused: the path is never a site | `ported_gateway_core::pipeline_encoded_body_and_parser_hidden_placeholder_shapes_never_reach_upstream` |
| pipeline.test.js | a placeholder in an undeclared header is refused | `tests::gateway::hardening_a_placeholder_outside_its_site_is_refused_before_any_upstream_byte` |
| pipeline.test.js | the places a naive scan does not look are not hiding places | `ported_gateway_core::pipeline_encoded_body_and_parser_hidden_placeholder_shapes_never_reach_upstream` |
| pipeline.test.js | a second Authorization header is refused, so no placeholder goes upstream | covered by conformance: `gateway.test.js` “a placeholder in an undeclared header, an encoding, or a second Authorization is refused”; `util::tests::hardening_only_the_first_authorization_header_counts` |
| pipeline.test.js | a malformed percent-escape in a query key does not blind the scan | `ported_gateway_core::pipeline_encoded_body_and_parser_hidden_placeholder_shapes_never_reach_upstream` |
| pipeline.test.js | S05: a one-time placeholder cannot be used twice | `tests::gateway::hardening_a_tripwire_revokes_a_session_replaying_a_dead_placeholder` |
| pipeline.test.js | S05: concurrent uses of a one-time placeholder produce exactly one upstream call | `ported_gateway_core::twenty_racing_one_shot_uses_send_exactly_once_and_successors_remain_one_shot` |
| pipeline.test.js | an exhausted placeholder hands back a working successor | `tests::gateway::the_placeholder_successor_is_handed_back_when_one_is_spent` |
| pipeline.test.js | S04: a placeholder from another session is refused | `ported_gateway_core::cross_session_placeholders_and_bare_remote_carriers_are_refused_with_legitimate_controls` |
| pipeline.test.js | a budget layer that names no limit does not make the grant unlimited | `ported_gateway_core::unit_only_grant_budget_keeps_the_session_limit_and_charges_every_allowed_request` |
| pipeline.test.js | a budget limit written as a string still counts | `ported_gateway_core::stored_decimal_budget_counts_twice_and_noncanonical_values_are_refused` |
| pipeline.test.js | a budget limit that is not a number refuses rather than counts nothing | `ported_gateway_core::stored_decimal_budget_counts_twice_and_noncanonical_values_are_refused` |
| pipeline.test.js | held approvals are bounded, and do not hold response bodies forever | `ported_gateway_core::approval_pending_capacity_is_bounded_and_expired_entries_release_the_cap` |
| pipeline.test.js | a stale pending approval is forgotten, so the cap is not permanent | `ported_gateway_core::approval_pending_capacity_is_bounded_and_expired_entries_release_the_cap` |
| pipeline.test.js | a bare placeholder does not authorize on a network listener | `ported_gateway_core::cross_session_placeholders_and_bare_remote_carriers_are_refused_with_legitimate_controls` |
| pipeline.test.js | the successor to a one-time placeholder is also one-time | `ported_gateway_core::twenty_racing_one_shot_uses_send_exactly_once_and_successors_remain_one_shot` |
| pipeline.test.js | an approval does not carry over to a request with different headers | `ported_gateway_core::approval_cannot_cross_header_changes_denial_resends_or_unexecuted_failures` |
| pipeline.test.js | a fractional use count does not persist state the log never records | `ported_gateway_core::fractional_control_issuance_normalizes_uses_and_records_each_ledger_row_once` |
| pipeline.test.js | an upstream cannot choose how much of the daemon it occupies | `ported_gateway_core::buffered_upstream_is_cut_at_the_size_limit_instead_of_occupying_unbounded_memory` |
| pipeline.test.js | a use is given back when the request never reached anyone | `tests::gateway::a_denial_before_connecting_refunds_the_use` |
| pipeline.test.js | a use is NOT given back when the request may have been delivered | `tests::gateway::a_failure_after_connecting_is_not_refunded` |
| pipeline.test.js | a refused request does not decrypt the whole vault three times | `pipeline::decrypt_tests::a_refused_request_decrypts_the_vault_at_most_once` |
| pipeline.test.js | an approval survives a request that never reached the upstream | `ported_gateway_core::approval_cannot_cross_header_changes_denial_resends_or_unexecuted_failures` |
| pipeline.test.js | a refund into a revoked grant is refused, not quietly granted | `ported_gateway_core::refunds_require_a_live_grant_and_both_refund_decisions_are_audited` |
| pipeline.test.js | a legitimate refund is recorded, so the ledger and the log agree | `ported_gateway_core::refunds_require_a_live_grant_and_both_refund_decisions_are_audited` |
| pipeline.test.js | a placeholder cannot be spent under a grant it was not issued under | `ported_gateway_core::placeholder_grant_binding_cannot_bill_a_different_grant_for_a_wider_route` |
| pipeline.test.js | a revoked session stops working immediately | `ported_gateway_core::revocation_stops_an_existing_session_and_allow_deny_consumption_records_verify` |
| pipeline.test.js | a forged placeholder is refused by its checksum, before any lookup | `tests::mutants::hardening_the_placeholder_checksum_is_checked` |
| pipeline.test.js | a real placeholder with one character changed does not verify | `tests::mutants::hardening_the_placeholder_checksum_is_checked` |
| pipeline.test.js | the fingerprint shown in cred list is not an oracle for the checksum key | `ported_gateway_core::chosen_credential_fingerprint_is_domain_separated_from_placeholder_checksum_key` |
| pipeline.test.js | S09: an upstream echoing the secret back has it replaced by the placeholder | `tests::gateway::ordinary_request_substitutes_at_the_declared_site_and_scrubs_the_answer` |
| pipeline.test.js | an upstream echoing the secret in a header has it scrubbed too | `tests::gateway::hardening_a_reflected_secret_in_a_header_name_or_value_is_dropped_or_redacted` |
| pipeline.test.js | an upstream cannot forge AV-* headers or set cookies on the agent | `tests::gateway::hardening_a_reflected_secret_in_a_header_name_or_value_is_dropped_or_redacted` |
| pipeline.test.js | a derived token minted upstream is redacted by shape | `ported_gateway_core::upstream_minted_github_tokens_are_redacted_by_shape_and_ordinary_text_survives` |
| pipeline.test.js | S28: a request carrying Origin is refused, so a web page cannot use the gateway | `tests::gateway::hardening_browser_origin_and_foreign_host_are_refused` |
| pipeline.test.js | a Host header outside the allowed set is refused, blocking DNS rebinding | `tests::gateway::hardening_browser_origin_and_foreign_host_are_refused` |
| pipeline.test.js | a write under on-write approval is held, then executes exactly once on resend | `tests::gateway::approval_each_holds_then_executes_exactly_once_and_replays` |
| pipeline.test.js | a denied approval stays denied on resend | `ported_gateway_core::approval_cannot_cross_header_changes_denial_resends_or_unexecuted_failures` |
| pipeline.test.js | a spent budget stops the session without a human | `tests::gateway::budget_is_counted_and_spent` |
| pipeline.test.js | every decision is recorded in a chain that detects tampering | `ported_gateway_core::revocation_stops_an_existing_session_and_allow_deny_consumption_records_verify` |
| pipeline.test.js | no audit record contains the secret in any form | `tests::gateway::ordinary_request_substitutes_at_the_declared_site_and_scrubs_the_answer` |
| pipeline.test.js | a locked vault refuses every proxied request | `ported_gateway_core::locking_blocks_proxy_but_keeps_metadata_and_persists_until_explicit_unlock` |
| pipeline.test.js | locking is recorded on disk, so a restart comes back locked | `ported_gateway_core::locking_blocks_proxy_but_keeps_metadata_and_persists_until_explicit_unlock` |
| pipeline.test.js | unlocking clears the recorded state | `ported_gateway_core::locking_blocks_proxy_but_keeps_metadata_and_persists_until_explicit_unlock` |
| pipeline.test.js | a locked vault still answers questions that reveal nothing | `ported_gateway_core::locking_blocks_proxy_but_keeps_metadata_and_persists_until_explicit_unlock` |
| pipeline.test.js | a held write is resendable with a freshly minted placeholder | `tests::mutants::an_approval_survives_a_fresh_placeholder_on_the_resend` |
| pipeline.test.js | a resend cannot change what the human approved | `tests::mutants::hardening_a_resend_may_not_change_the_bytes_the_human_approved` |
| remote.test.js | on loopback a placeholder alone authenticates, which is the point | not yet ported |
| remote.test.js | over the network a placeholder alone does not authenticate | not yet ported |
| remote.test.js | over the network the same request works with the session token alongside | not yet ported |
| remote.test.js | a listener serving a surface that may never leave the machine is refused | not yet ported |
| remote.test.js | a refused listener is recorded, not silently dropped | not yet ported |
| remote.test.js | a remote session carries its own shorter ceiling | not yet ported |
| requested-c3.test.js | a session the owner creates records its elevation, [] when ordinary | not yet ported |
| requested-c3.test.js | an approved request records the elevation of what the owner approved | not yet ported |
| requested-c3.test.js | a bulk decision records each session's own elevation, not the batch's | not yet ported |
| requested-c3.test.js | an elevation the store does not know is refused, and nothing is written | not yet ported |
| requested-r1.test.js | elevationOf names auto with a write method, and nothing ordinary | not yet ported |
| requested-r1.test.js | elevationOf fails closed on anything it cannot read | not yet ported |
| requested-r1.test.js | elevationOf fails closed on an unreadable list whatever the approval mode | not yet ported |
| requested-r1.test.js | owner fields are read by one parser, and the CLI parse feeds it | not yet ported |
| requested-r1.test.js | auto with writes is refused inside an open window without a fresh proof | not yet ported |
| requested-r1.test.js | auto with writes is created with the passphrase in the request, and audited as fresh | not yet ported |
| requested-r1.test.js | a wrong passphrase for an elevated session is refused, and counted | not yet ported |
| requested-r1.test.js | read-only auto is not elevated: the window is enough, and nobody is asked again | not yet ported |
| requested-r1.test.js | a vault with no factor refuses auto with writes, and still makes ordinary sessions | not yet ported |
| requested-r1.test.js | an authenticator assertion over the exact body creates an elevated session | not yet ported |
| requested-r1.test.js | an unknown approval mode is refused, never read as auto | not yet ported |
| requested-r1.test.js | malformed limits are refused before anything is created | not yet ported |
| requested-r1.test.js | a session request that names an owner field is refused, not trimmed | not yet ported |
| requested-r1.test.js | the request store refuses an owner field from any caller | not yet ported |
| requested-r1.test.js | MCP cannot carry an owner field into a request | `tests::control::hardening_a_session_request_cannot_carry_an_owner_field` |
| requested-r1.test.js | the gateway has no route that creates a session | not yet ported |
| requested-r1.test.js | approving a request into auto with writes needs a fresh proof, not the window | not yet ported |
| requested-r1.test.js | a request approved without owner options stays ordinary, inside the window | not yet ported |
| requested-r1.test.js | a verdict that is not true or false is refused on the single decide route | not yet ported |
| requested-r1.test.js | an override with an unknown mode is refused when it is settled | not yet ported |
| requested-r1.test.js | a bulk decision with one elevated item needs a fresh proof for the whole list | not yet ported |
| requested-r1.test.js | the CLI refuses a mode it does not know before it calls anything | not yet ported |
| requested-r1.test.js | the CLI says what to do when auto with writes cannot be proved | not yet ported |
| requested-r1.test.js | the CLI exits with the refusal code’s own exit status | not yet ported |
| requested-r1.test.js | approvals offers the owner options, and approve validates them | not yet ported |
| requested-r1.test.js | the help text documents how to start an auto-approving session | not yet ported |
| requested-r2.test.js | a new file is created 0600 even under umask 000, and an existing one is refused | not yet ported |
| requested-r2.test.js | a symlink is never followed, with or without force | not yet ported |
| requested-r2.test.js | force replaces a regular file atomically and leaves it 0600 | not yet ported |
| requested-r2.test.js | a temporary file swapped for a symlink before the rename is refused, and no link is left | not yet ported |
| requested-r2.test.js | a destination that becomes a symlink just before the rename is replaced, and the target is untouched | not yet ported |
| requested-r2.test.js | appending makes the file 0600 whatever the umask, and tightens one that was not | not yet ported |
| requested-r2.test.js | appending creates 0600, appends whole lines, and refuses a symlink | not yet ported |
| requested-r2.test.js | the final check passes placeholders for the session and loopback gateway URLs | not yet ported |
| requested-r2.test.js | the final check refuses everything else, and never says what it refused | not yet ported |
| requested-r2.test.js | one session holds several credentials, each with its own grant and placeholder | not yet ported |
| requested-r2.test.js | an ambiguous or mixed session body is refused, and leaves nothing behind | not yet ported |
| requested-r2.test.js | two credentials for one host stay apart: /p/ picks by name, /t/ refuses the other one | not yet ported |
| requested-r2.test.js | a batch is gated like a single placeholder | not yet ported |
| requested-r2.test.js | a batch issues one placeholder per item, in order, and records the batch | not yet ported |
| requested-r2.test.js | a batch is all or nothing | not yet ported |
| requested-r2.test.js | a batch with one quarantined credential issues nothing, not even the items before it | not yet ported |
| requested-r2.test.js | a batch of the wrong shape is refused before anything is resolved | not yet ported |
| requested-r2.test.js | the grant’s use ceiling beats what a batch asks for | not yet ported |
| requested-r2.test.js | env writes a 0600 file of placeholders and URLs, and never a secret or the token | not yet ported |
| requested-r2.test.js | env never replaces a file unless told to, and never follows a link | not yet ported |
| requested-r2.test.js | env refuses bad mappings before it calls anything, without echoing what was pasted | not yet ported |
| requested-r2.test.js | env with a map file and no --out prints the lines | not yet ported |
| requested-r2.test.js | env without a session says how to make one | not yet ported |
| requested-r2.test.js | env warns when the file would be committed | not yet ported |
| requested-r2.test.js | a batch answer that is not a placeholder is never written | not yet ported |
| requested-r2.test.js | the same fake answering a real placeholder shape is written: the check is not a wall | not yet ported |
| requested-r2.test.js | exec --map puts a placeholder in the child under the name a tool reads | not yet ported |
| requested-r2.test.js | exec reports a missing command as 127 | not yet ported |
| requested-r2.test.js | session create takes several credentials and prints a block for each | not yet ported |
| requested-r3.test.js | a session with no expiry needs a fresh proof, and gets one from the passphrase | not yet ported |
| requested-r3.test.js | a vault with no factor refuses a session with no expiry | not yet ported |
| requested-r3.test.js | a session with no expiry is never remote, and says so before asking for anything | not yet ported |
| requested-r3.test.js | a lifetime is a positive number, and infinite has none to set | not yet ported |
| requested-r3.test.js | ordinary finite sessions are unchanged | not yet ported |
| requested-r3.test.js | revoking a session with no expiry kills its placeholders | not yet ported |
| requested-r3.test.js | the owner can add no expiry when approving, but not on top of a lifetime the agent asked for | not yet ported |
| requested-r3.test.js | an authenticator assertion creates one from the UI, which marks it everywhere | not yet ported |
| requested-r3.test.js | the CLI refuses --ttl with --infinite, and lists an infinite session as never | not yet ported |
| requested-r3.test.js | the CLI on a vault with no factor says to set a passphrase first | not yet ported |
| requested-r3.test.js | a stored expiry that does not parse is never live | not yet ported |
| requested-r3.test.js | an infinite session is the default for an implicit placeholder when it is the only one | not yet ported |
| requested-seams.test.js | a session for a quarantined credential is refused before the gate asks for anything | not yet ported |
| requested-seams.test.js | approving a request for a quarantined credential is refused and leaves it pending | not yet ported |
| requested-seams.test.js | a placeholder batch for a quarantined credential is refused whole, with the store's rule | not yet ported |
| requested-seams.test.js | a placeholder batch on a grant that has ended is refused by the store's grant check | not yet ported |
| requested-ui.test.js | the page reads owner options exactly as the CLI and the daemon do | not yet ported |
| requested-ui.test.js | a session with no expiry renders as never, and garbage as expired | not yet ported |
| requested-ui.test.js | the decisions that can be elevated are re-verified by the daemon | not yet ported |
| requested-ui.test.js | the page warns before it signs an elevated session | not yet ported |
| requested-ui.test.js | the hand-off card offers an env command with no session token in it | not yet ported |
| requested-ui.test.js | approving a request with owner options from the page creates the session they chose | not yet ported |
| requested-ui.test.js | a signature for one owner option cannot be spent on another | not yet ported |
| requested-ui.test.js | an auto-approving multi-credential session made from the page needs only its own signature | not yet ported |
| requested-ui.test.js | the docs say how to start an auto-approving session, and that read-only needs nothing | not yet ported |
| response.test.js | a gzipped response is decompressed before it reaches the agent | `ported_gateway_core::response_buffered_encodings_preserve_plaintext_and_every_binary_byte` |
| response.test.js | deflate and brotli are handled too | `ported_gateway_core::response_buffered_encodings_preserve_plaintext_and_every_binary_byte` |
| response.test.js | a secret hidden inside a compressed body is still scrubbed | `ported_gateway_core::response_gzip_echo_replaces_secret_with_the_exact_injected_placeholder` |
| response.test.js | an encoding we cannot decode is refused rather than passed through unread | `ported_gateway_core::response_unknown_encoding_refuses_buffered_and_streamed_bytes_with_readable_control` |
| response.test.js | a binary body survives byte for byte | `ported_gateway_core::response_buffered_encodings_preserve_plaintext_and_every_binary_byte` |
| response.test.js | a gzipped binary body round-trips through decompression unchanged | `ported_gateway_core::response_buffered_encodings_preserve_plaintext_and_every_binary_byte` |
| response.test.js | a COMPRESSED event stream is decompressed before it is scrubbed | `ported_gateway_core::response_all_compressed_sse_encodings_scrub_secrets_and_keep_event_order` |
| response.test.js | an event stream in an encoding we cannot read is refused, not passed through | `ported_gateway_core::response_unknown_encoding_refuses_buffered_and_streamed_bytes_with_readable_control` |
| response.test.js | a secret inside an event is scrubbed, and the rest survives | `ported_gateway_core::response_sse_literal_and_transport_split_secrets_are_scrubbed_and_repository_prose_survives` |
| response.test.js | the stream hold-back is bounded, not the whole response | `ported_gateway_core::response_stream_holdback_starts_output_before_one_quarter_and_delivers_every_event` |
| response.test.js | a secret split across two stream chunks is still caught | `ported_gateway_core::response_transport_chunk_split_does_not_reveal_secret_and_ordinary_frames_arrive` |
| response.test.js | end to end over real HTTP: a gzipping upstream and a streaming upstream both work | `ported_gateway_core::response_real_http_gateway_decodes_gzip_and_delivers_sse_through_default_connector` |
| response.test.js | a secret cannot escape through an internal error message | `ported_gateway_core::response_error_detail_cannot_disclose_stored_secret_and_keeps_useful_context` |
| response.test.js | a token stream that merely mentions a repository is not cut | `ported_gateway_core::response_repository_prose_is_byte_exact_and_never_cut_or_redacted` |
| response.test.js | a secret split across two SSE events is caught | `tests::gateway::hardening_a_secret_split_across_sse_events_cuts_the_stream` |
| revocation.test.js | revoking a session kills every placeholder it ever issued | `ported_gateway_core::revocation_session_kills_all_placeholders_and_token_and_replays_have_distinct_audit_events` |
| revocation.test.js | revoking one grant does not disturb another session | `ported_gateway_core::revocation_is_precise_across_sessions_but_credential_deletion_stops_every_dependent_grant` |
| revocation.test.js | deleting a credential stops every grant that used it | `ported_gateway_core::revocation_is_precise_across_sessions_but_credential_deletion_stops_every_dependent_grant` |
| revocation.test.js | locking the vault refuses everything, and unlocking restores it | `ported_gateway_core::locking_blocks_proxy_but_keeps_metadata_and_persists_until_explicit_unlock` |
| revocation.test.js | an expired session is refused even with a live placeholder | `ported_gateway_core::expired_session_stops_a_previously_working_placeholder_whose_own_expiry_remains_live` |
| revocation.test.js | a revoked placeholder coming back is treated as hostile, not as a mistake | `ported_gateway_core::revocation_session_kills_all_placeholders_and_token_and_replays_have_distinct_audit_events` |
| serving.test.js | a listener naming the control surface on a network address is refused outright | not yet ported |
| serving.test.js | a listener naming the database surface on a network address is refused | not yet ported |
| serving.test.js | the refusal is audited so a misconfiguration is loud, not silent | not yet ported |
| serving.test.js | the same surfaces are allowed on a loopback or unix address | not yet ported |
| serving.test.js | gateway and mcp surfaces may be bound to a network address | not yet ported |
| serving.test.js | loopback detection covers the forms an operator actually types | not yet ported |
| serving.test.js | removing a listener is allowed without ceremony: reducing reach is always safe | not yet ported |
| serving.test.js | the control socket is created with mode 0600 and no network address | not yet ported |
| serving.test.js | the vault directory is 0700 so another local user cannot read it | not yet ported |
| session-requests.test.js | asking for a session creates nothing at all | `tests::control::session_requests_create_nothing_until_a_human_answers_and_only_the_asker_collects` |
| session-requests.test.js | an agent cannot answer its own request | `tests::mutants::hardening_every_answer_a_human_gives_needs_the_human` |
| session-requests.test.js | a human approving gets a working session, collected exactly once | `tests::control::session_requests_create_nothing_until_a_human_answers_and_only_the_asker_collects` |
| session-requests.test.js | what the human edits is what gets created | `tests::mutants::an_approved_session_request_is_made_from_what_was_approved` |
| session-requests.test.js | approval supplies a human, never permission | not yet ported |
| session-requests.test.js | a denial creates nothing and cannot be reversed by asking again | not yet ported |
| session-requests.test.js | an agent cannot flood out a request a human is reading | not yet ported |
| session-requests.test.js | every request and answer is in the audit log | `tests::control::session_requests_create_nothing_until_a_human_answers_and_only_the_asker_collects` |
| session-requests.test.js | a request is audited on a vault that started locked, which is every real one | not yet ported |
| session-requests.test.js | approving records the session where a running agent will find it | not yet ported |
| session-requests.test.js | a denial records nothing | not yet ported |
| session-requests.test.js | a pending request survives a daemon restart | `tests::guards::pending_session_requests_survive_a_restart_and_approved_tokens_never_touch_disk` |
| session-requests.test.js | an approved token is never written to disk | `tests::guards::pending_session_requests_survive_a_restart_and_approved_tokens_never_touch_disk` |
| session-requests.test.js | a session request tells the human a command they can actually run | not yet ported |
| session-requests.test.js | no hint anywhere names an agent-vault command that does not exist | not yet ported |
| session-requests.test.js | an approved lifetime is a ceiling, not an opening bid | not yet ported |
| session-requests.test.js | a requested lifetime cannot exceed the hard ceiling | not yet ported |
| session-requests.test.js | an agent cannot settle a batch any more than it can settle one | `tests::mutants::hardening_every_answer_a_human_gives_needs_the_human` |
| session-requests.test.js | a batch refuses the shapes that would hide an approval | not yet ported |
| session-requests.test.js | a batch settles through the same path as a single decision | not yet ported |
| session-requests.test.js | an item that stopped being pending is reported, not skipped in silence | not yet ported |
| ui-audit-growth.test.js | Prev from the old first page holds only the rows appended since, and then there is no Prev | not yet ported |
| ui-audit-growth.test.js | a log with gaps that grows while it is walked: Next sees the first snapshot once, Prev reaches every new row once | not yet ported |
| ui-audit-growth.test.js | a real daemon, a kind and a search, rows arriving all the time: both directions, no row twice, none skipped | not yet ported |
| ui-audit-paging.test.js | the fixture wrote the log it claims to | not yet ported |
| ui-audit-paging.test.js | the daemon: a bare limit is the tail it always was | not yet ported |
| ui-audit-paging.test.js | the daemon: kind filters before the limit | `tests::control::audit_paging_filters_kind_before_the_limit_and_walks_both_ways` |
| ui-audit-paging.test.js | the daemon: before and after walk the whole log, each row once | not yet ported |
| ui-audit-paging.test.js | the daemon: paging parameters are whole numbers in range or refused | not yet ported |
| ui-audit-paging.test.js | the daemon: a kind-filtered tail is bounded at 500 even with no before or after | not yet ported |
| ui-audit-paging.test.js | the daemon: the unfiltered tail keeps its old reading of limit | not yet ported |
| ui-audit-paging.test.js | the CLI: audit tail reads the same tail as before | not yet ported |
| ui-audit-paging.test.js | the page: a kind walks every row of that kind, newest first, across the whole log | not yet ported |
| ui-audit-paging.test.js | the page: with no kind the whole log is walkable | not yet ported |
| ui-audit-paging.test.js | the page: q searches visible fields across the whole log, a page at a time | not yet ported |
| ui-audit-paging.test.js | the page: q never matches token or placeholder text in a row | not yet ported |
| ui-audit-paging.test.js | the page: audit cursors and limits are checked like every other list | not yet ported |
| ui-audit-paging.test.js | the page: without paged=1 the audit route is unchanged | not yet ported |
| ui-complete-lists.test.js | fetchAll reads every row of a list longer than 50 pages of 200 | not yet ported |
| ui-complete-lists.test.js | 32 tripwire rules: the list the page shows pages and searches; the snapshot has all 32 | not yet ported |
| ui-dist-serving.test.js | the policy is exactly the strict one, with nothing inline allowed | not yet ported |
| ui-dist-serving.test.js | with a session, / is the built index.html under the strict policy and no-store | not yet ported |
| ui-dist-serving.test.js | each allowlisted asset is served with its exact type, no-store and the strict policy | not yet ported |
| ui-dist-serving.test.js | assets need the session cookie, as the page does | not yet ported |
| ui-dist-serving.test.js | traversal, encoded slashes, backslashes and dot segments are all 404 | not yet ported |
| ui-dist-serving.test.js | a path is routed only as it arrived: the literal / and literal asset names still work | not yet ported |
| ui-dist-serving.test.js | literalPath: only a path the parser leaves as it is, with no dot segment or encoded separator | not yet ported |
| ui-dist-serving.test.js | dotfiles, unlisted types, nested files and symlinks are never served | not yet ported |
| ui-dist-serving.test.js | only GET serves an asset | not yet ported |
| ui-dist-serving.test.js | the allowlist is read once at startup and served from memory | not yet ported |
| ui-dist-serving.test.js | loadDist lists only regular, allowed files directly in assets | not yet ported |
| ui-dist-serving.test.js | loadDist refuses an assets directory that is a symlink, even to a directory beside dist | not yet ported |
| ui-dist-serving.test.js | loadDist refuses an index.html that is a symlink, inside or outside dist, and a dangling one | not yet ported |
| ui-dist-serving.test.js | loadDist refuses a dist directory that is a symlink, and a dist or assets that is not a directory | not yet ported |
| ui-dist-serving.test.js | a server over a symlinked assets directory does not start, so nothing outside dist is ever served | not yet ported |
| ui-dist-serving.test.js | the error pages carry the strict policy and nothing inline | not yet ported |
| ui-dist-serving.test.js | no response the server makes allows unsafe-inline once the bundle is there | not yet ported |
| ui-dist-serving.test.js | U2: with no dist/index.html the server refuses to start and names npm run build:ui | not yet ported |
| ui-dist-serving.test.js | U2: the shipped dist is what the server loads by default | not yet ported |
| ui-paging.test.js | without paged=1 every list route answers exactly as it always has | not yet ported |
| ui-paging.test.js | each list pages through every item once, in its documented order, and back | not yet ported |
| ui-paging.test.js | pending pages newest first, with both kinds of decision | not yet ported |
| ui-paging.test.js | an object answer keeps its other fields beside the page | not yet ported |
| ui-paging.test.js | limit is a whole number from 1 to 200; anything else is AV_BAD_LIMIT | not yet ported |
| ui-paging.test.js | a cursor that was not made by this server for this list and filter is AV_BAD_CURSOR | not yet ported |
| ui-paging.test.js | q is a case-insensitive match over visible fields, and filters before paging | not yet ported |
| ui-paging.test.js | q never matches a token, a placeholder or a value, even one the daemon leaked | not yet ported |
| ui-paging.test.js | the cursors in an answer survive the scrub that every answer passes | not yet ported |
| ui.test.js | the relying party id is a domain, not an IP literal | not yet ported |
| ui.test.js | arriving by IP is redirected to the domain the authenticator accepts | not yet ported |
| ui.test.js | the launch link works exactly once | not yet ported |
| ui.test.js | without the session cookie the API answers nothing | not yet ported |
| ui.test.js | a cross-origin caller is refused | not yet ported |
| ui.test.js | a request without the custom header is refused, which stops a form post | not yet ported |
| ui.test.js | the credential list carries no value, in any field | not yet ported |
| ui.test.js | there is no endpoint that returns a secret at all | not yet ported |
| ui.test.js | the docs context describes this install and carries no secret | not yet ported |
| ui.test.js | the docs page is reachable without changing anything | not yet ported |
| ui.test.js | before enrollment, every mutating call is refused | not yet ported |
| ui.test.js | a forged presence payload is refused | not yet ported |
| ui.test.js | enrollment registers the authenticator | not yet ported |
| ui.test.js | a second enrollment is refused, so an agent cannot add its own key | not yet ported |
| ui.test.js | after enrollment, a mutating call still fails without a signature | not yet ported |
| ui.test.js | a signature for the wrong operation is refused | not yet ported |
| ui.test.js | a valid signature for the right operation is accepted exactly once | not yet ported |
| ui.test.js | a session created here reaches the store every local client reads | not yet ported |
| ui.test.js | the enrollment is recorded in the audit log | not yet ported |
| ui.test.js | a batch with no signature is refused, like a single decision | not yet ported |
| ui.test.js | the operation bound for a batch is the list exactly as it was sent | not yet ported |
| webauthn.test.js | a registration produces a credential the daemon can store | not yet ported |
| webauthn.test.js | registration without user verification is refused | not yet ported |
| webauthn.test.js | a valid assertion for the issued challenge verifies | not yet ported |
| webauthn.test.js | a different authenticator cannot sign for the enrolled credential | not yet ported |
| webauthn.test.js | an attacker who copies the enrolled credential id still cannot sign | not yet ported |
| webauthn.test.js | a signature for one operation does not authorise another | not yet ported |
| webauthn.test.js | the operation challenge changes with every field of the operation | not yet ported |
| webauthn.test.js | the same operation with a fresh nonce yields a fresh challenge | not yet ported |
| webauthn.test.js | an assertion from another origin is refused | not yet ported |
| webauthn.test.js | a registration response replayed as an assertion is refused | not yet ported |
| webauthn.test.js | an assertion without user verification is refused | not yet ported |
| webauthn.test.js | a signature counter that goes backwards is treated as a cloned credential | not yet ported |
| webauthn.test.js | only ES256 on P-256 is accepted | not yet ported |
| webauthn.test.js | the CBOR reader rejects what it does not understand rather than guessing | not yet ported |
| webauthn.test.js | an assertion is bounded before anything parses it | not yet ported |
| widening.test.js | the passphrase gate is on, so an unsigned call is refused | `ported_gateway_core::widening_signed_ui_session_and_credential_changes_work_and_never_reveal_secret` |
| widening.test.js | creating a session from the UI works with one fingerprint | `ported_gateway_core::widening_signed_ui_session_and_credential_changes_work_and_never_reveal_secret` |
| widening.test.js | the credential list says where a placeholder may go | `ported_gateway_core::widening_signed_ui_session_and_credential_changes_work_and_never_reveal_secret` |
| widening.test.js | adding a credential from the UI works the same way | `ported_gateway_core::widening_signed_ui_session_and_credential_changes_work_and_never_reveal_secret` |
| widening.test.js | removing a credential from the UI works, signature and all | `ported_gateway_core::widening_signed_ui_session_and_credential_changes_work_and_never_reveal_secret` |
| widening.test.js | a signature for one operation cannot authorise another | `ported_gateway_core::widening_operation_swaps_unminted_challenges_unenrolled_keys_and_replays_never_authorize` |
| widening.test.js | a signature is good for exactly one call | `ported_gateway_core::widening_operation_swaps_unminted_challenges_unenrolled_keys_and_replays_never_authorize` |
| widening.test.js | a challenge the daemon never minted proves nothing | `ported_gateway_core::widening_operation_swaps_unminted_challenges_unenrolled_keys_and_replays_never_authorize` |
| widening.test.js | a key the daemon never enrolled proves nothing | `ported_gateway_core::widening_operation_swaps_unminted_challenges_unenrolled_keys_and_replays_never_authorize` |
| widening.test.js | an agent at the socket cannot enrol its own key and sign for itself | `ported_gateway_core::widening_operation_swaps_unminted_challenges_unenrolled_keys_and_replays_never_authorize` |
| widening.test.js | the passphrase window still works, for the CLI | `ported_gateway_core::exfil_passphrase_gates_unlock_creation_and_borrowed_grants_but_presence_restores_issuance` |
| widening.test.js | a wrong passphrase opens nothing | `ported_gateway_core::exfil_passphrase_gates_unlock_creation_and_borrowed_grants_but_presence_restores_issuance` |
| widening.test.js | a signature does not authorise fields it never covered | `ported_gateway_core::widening_operation_swaps_unminted_challenges_unenrolled_keys_and_replays_never_authorize` |
| widening.test.js | the value stored under a cred.add signature is bound to it | `ported_gateway_core::widening_credential_value_is_bound_to_consent_and_correctly_signed_value_is_stored` |
| widening.test.js | a batch signature covers exactly the items it named | `ported_gateway_core::widening_batch_consent_binds_exact_items_and_verdicts_and_handover_is_collected_once` |
| widening.test.js | a batch signature is spent by the batch it named | `ported_gateway_core::widening_batch_consent_binds_exact_items_and_verdicts_and_handover_is_collected_once` |
| widening.test.js | reordering a signed batch does not change what it authorises | `ported_gateway_core::widening_batch_consent_binds_exact_items_and_verdicts_and_handover_is_collected_once` |

## Inventory audit

The source-only AST audit resolves literal and generated names without importing any test file or running hooks. It found 1555 unique names (1556 declarations) across all 127 test/security and test/core files. This daemon inventory corrected the old 1090 total by adding five invariant names, 110 unique nested gateway names, and replacing one literal audit template with its three actual names: 1207 rows. Every added gateway subtest was matched to its exact existing Rust input table; the duplicate multipart leaf name is covered in both foreign-method and own-method rows of the same Rust test. The audit also reads the CLI branch inventory when that manifest is absent locally. All source names have an inventory entry; owning-crate deferrals describe responsibility and do not claim passing coverage.
