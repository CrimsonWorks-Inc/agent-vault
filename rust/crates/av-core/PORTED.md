# JavaScript → Rust test inventory

Scope: every named test in `test/core/*.test.js`, plus security files named by core mutation protections and every security file that imports core logic or one of the pure profile/pin/operation helpers assigned to av-core. Integration tests are delegated to conformance; this table does not claim to implement their network, store, UI, CLI or authenticator harnesses in av-core.

The Rust tests use fixed obviously fake credentials. `tests/fixtures/*-vectors.mjs` imports the read-only JS modules to generate checked-in differential cases; the Rust suites compare results and refusals, including their exact rule, hint and detail. `integrity::live_js_golden_vectors` also generates fresh JS placeholders at test time (the isolated mutation tree has no JS source and uses the checked-in vectors). Fuzz tests are proptest properties rather than reproductions of the JS PRNG, including every-field policy narrowing, operation injectivity, placeholder integrity, structural detector coverage and streamed scrub equivalence. Numeric JSON spelling vectors also pin JS binary64 and integer semantics. Cases using JS-only values such as undefined, NaN, getters or Headers adapters are represented by the scaffold's typed absence/invalid forms or tested at the conformance boundary.

`mutations.toml` contains all 76 entries whose JS source is `src/core/*`, plus regressions for structured error-recovery serialization (approved by the coordinator) preserving explicitly null budget members as invalid, paired UTF-16 response escapes, and Node-compatible base64 padding. C27 path/route identifiers are `Option<usize>` in the frozen scaffold: textual rule leakage cannot compile, and the corresponding mutations check the correctness of the returned indices. No JS source or mutation harness is modified or executed by the mutation runner.

| JavaScript file | JavaScript test name | Rust test / disposition |
|---|---|---|
| `test/core/detect-fuzz.test.js` | every encoding of a placeholder is detected, wherever it sits | detector_encodings_at_every_alignment; js_detector_vectors |
| `test/core/detect-fuzz.test.js` | wrapped base64 is still base64 | detector_encodings_at_every_alignment |
| `test/core/detect-fuzz.test.js` | the detector stays linear on a large body | detector_pathological_input_linear_bound |
| `test/core/detect-fuzz.test.js` | the detector is a superset of the substituter, structurally | js_substitution_vectors |
| `test/core/detect-fuzz.test.js` | a placeholder needs a boundary, and both sides agree about that | js_detector_vectors |
| `test/core/detect-fuzz.test.js` | intersecting policies can only narrow, never widen | every_field_randomized_intersections |
| `test/core/detect-fuzz.test.js` | a denied path stays denied however it is spelled | denied_path_spellings_never_escape |
| `test/core/detect-fuzz.test.js` | a child cannot widen past a ceiling with a mid-pattern ** | randomized_intersections_only_narrow |
| `test/core/detect-fuzz.test.js` | glob matching is linear, not exponential | hardening_path_shapes_with_ordinary_control |
| `test/core/docs.test.js` | the docs page defines the sections it advertises | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | the docs command can reach every section of the page | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | every denial a caller can hit is explained in the docs | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | the docs name every agent mcp install can configure | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | the docs route every model profile that declares environment variables | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | the mark in the page matches the one in mark.svg | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | the page carries a favicon that is well-formed | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | the readme points at the docs page rather than duplicating it | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/docs.test.js` | a connector whose proxy is not built is marked as such | not applicable, because documentation commands are src/cli/docs.js, owned by av-cli |
| `test/core/host-confinement.test.js` | a credential ceiling is its own host plus its profile hosts | host_ceiling_and_wire_path |
| `test/core/host-confinement.test.js` | the port is stripped from the ceiling, since it travels with the connection | host_ceiling_and_wire_path |
| `test/core/host-confinement.test.js` | confineHosts rejects any host outside the ceiling | js_policy_reference_vectors |
| `test/core/host-confinement.test.js` | confineHosts keeps hosts that are inside the ceiling | js_policy_reference_vectors |
| `test/core/host-confinement.test.js` | an empty request defaults to the whole ceiling, never to unrestricted | js_policy_reference_vectors |
| `test/core/host-confinement.test.js` | a credential that declares no host cannot be granted at all | js_policy_reference_vectors |
| `test/core/host-confinement.test.js` | a smuggled port cannot slip a host past the ceiling | host_ceiling_and_wire_path; js_policy_reference_vectors |
| `test/core/integrity-fuzz.test.js` | a minted placeholder always verifies under its own key | minted_always_verifies |
| `test/core/integrity-fuzz.test.js` | changing any single character makes a placeholder unusable | checksum_single_character_change |
| `test/core/integrity-fuzz.test.js` | a placeholder never verifies under a different key | wrong_key_never_verifies |
| `test/core/integrity-fuzz.test.js` | random text is never mistaken for a placeholder | random_text_never_verifies |
| `test/core/integrity-fuzz.test.js` | operations that differ in any way canonicalise differently | operation_shapes_canonicalize_injectively |
| `test/core/integrity-fuzz.test.js` | key order and absent fields do not change the canonical form | operation::tests::reserved_fields_and_secret_digests |
| `test/core/integrity-fuzz.test.js` | an encoded occurrence is never treated as an injection site | encoded_locations_refuse_and_raw_controls_match |
| `test/core/mcp-install.test.js` | every agent declares a format and at least one scope | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | paths land where each tool actually looks | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | codex honours CODEX_HOME and offers no project scope | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | an unknown agent is refused and the known ones are named | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | merging JSON keeps unrelated settings and other servers | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | a second JSON merge reports unchanged and rewrites the same text | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | a JSON file we cannot parse is refused rather than replaced | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | TOML merge appends a table and leaves comments and neighbours alone | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | a second TOML merge neither duplicates nor changes the table | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | TOML merge replaces a stale table in place, keeping what follows | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | stdio writes no session token into the config | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | HTTP points at an environment variable instead of embedding the token | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | install merges, keeps a copy of the old file, and is idempotent | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | print mode shows the block and touches nothing | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | install creates the parent directory when the tool has never run | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | project scope produces a config that is portable | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | a server name cannot close the table and open one of its own | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/mcp-install.test.js` | user scope names the system install rather than a checkout | not applicable, because MCP installation edits client configuration in src/cli/mcp-install.js, owned by av-cli |
| `test/core/package.test.js` | the published package contains everything it needs and nothing it should not | not applicable, because npm package and distribution layout are outside the av-core crate |
| `test/core/package.test.js` | the published package runs, imports and creates a vault on its own | not applicable, because npm package and distribution layout are outside the av-core crate |
| `test/core/package.test.js` | the daemon reports the version the package actually is | not applicable, because npm package and distribution layout are outside the av-core crate |
| `test/core/package.test.js` | no test can write state into the real vault directory | not applicable, because npm package and distribution layout are outside the av-core crate |
| `test/core/passphrase.test.js` | a none-vault unlocks with no secret; a passphrase vault does not | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | locking a passphrase vault zeroizes a key that disk alone cannot recover | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | changing a passphrase requires the current one | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | removing a passphrase requires the current one, then unlock needs no secret | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | the passphrase cannot be removed while it is the last human factor | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | a passphrase under 8 characters is refused | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | Touch ID (a PRF secret) unlocks the vault, alongside the passphrase | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | the passphrase cannot be removed while Touch ID is the other factor | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | removing the last unlock factor leaves the vault openable, not destroyed | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | setting a passphrase keeps an existing Touch ID factor | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | a passphrase vault comes up locked after a restart, not crashed | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | a crash mid-append does not lock the owner out of their own vault | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | a failed unlock leaves nothing half-open | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | a leftover temp file cannot hand the vault a permissive mode | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | the placeholder ledger does not grow without bound | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | key material and security decisions are written durably, whatever the ledger does | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/passphrase.test.js` | every method that writes the vault is classified as durable or as allowed to skip the fsync | not applicable, because passphrase factors and wraps are owned by av-store |
| `test/core/placeholder.test.js` | constants are derived from the grammar, not hard-coded independently | grammar_constants |
| `test/core/placeholder.test.js` | a minted placeholder is within the length bounds and round-trips | mint_roundtrip_and_longest_label |
| `test/core/placeholder.test.js` | the longest legal label still fits inside PH_MAX_LEN | mint_roundtrip_and_longest_label |
| `test/core/placeholder.test.js` | every character survives a URL, JSON, a shell word and a SCRAM username | transport_safe_and_scanner_pattern |
| `test/core/placeholder.test.js` | the check characters are keyed: another vault cannot forge one | wrong_key_never_verifies |
| `test/core/placeholder.test.js` | mutating any character breaks verification | checksum_single_character_change |
| `test/core/placeholder.test.js` | nonce entropy is 128 bits and never repeats across mints | entropy_unique |
| `test/core/placeholder.test.js` | diagnose names the actual corruption so an agent can self-correct | diagnose_and_find |
| `test/core/placeholder.test.js` | findAll locates placeholders in surrounding text and skips near-misses | diagnose_and_find |
| `test/core/placeholder.test.js` | a placeholder immediately followed by base32 text is not a placeholder | diagnose_and_find |
| `test/core/placeholder.test.js` | the scanner pattern published for gitleaks matches real placeholders | transport_safe_and_scanner_pattern |
| `test/core/placeholder.test.js` | base32 encodes and decodes round-trip | base32_roundtrip |
| `test/core/policy.test.js` | intersection narrows and never widens | randomized_intersections_only_narrow |
| `test/core/policy.test.js` | numeric limits take the minimum and approval takes the stricter mode | js_policy_reference_vectors |
| `test/core/policy.test.js` | enums narrow: a child cannot upgrade read-only to raw | js_policy_reference_vectors |
| `test/core/policy.test.js` | an allowed request passes and returns its normalized destination | js_policy_reference_vectors |
| `test/core/policy.test.js` | a host outside the grant is denied with the reachable hosts named | js_policy_reference_vectors |
| `test/core/policy.test.js` | a write method under a read-only grant is denied | js_policy_reference_vectors |
| `test/core/policy.test.js` | a profile deny list outranks a permissive grant | js_policy_reference_vectors |
| `test/core/policy.test.js` | path traversal cannot escape an allowed prefix | hardening_path_shapes_with_ordinary_control |
| `test/core/policy.test.js` | normalization rejects userinfo, trailing dots and illegal characters | js_policy_reference_vectors |
| `test/core/policy.test.js` | glob semantics: * spans one segment, ** spans many | js_policy_reference_vectors |
| `test/core/policy.test.js` | wildcard hosts over shared suffixes are refused by lint | js_policy_reference_vectors |
| `test/core/policy.test.js` | lint requires a budget on every grant | js_policy_reference_vectors |
| `test/core/policy.test.js` | approval modes behave as documented | js_policy_reference_vectors |
| `test/core/policy.test.js` | all policy fields validate strictly and malformed fields appear in lint | js_policy_reference_vectors |
| `test/core/policy.test.js` | payload and route validation covers bounds, unknown keys, pointers and constraints | js_policy_reference_vectors |
| `test/core/policy.test.js` | limit intersections preserve invalid values and canonical window winners | js_policy_reference_vectors |
| `test/core/policy.test.js` | grant input defaults, narrow conversion and detached description | js_policy_reference_vectors; every_field_randomized_intersections |
| `test/core/policy.test.js` | every-field randomized intersections only narrow, and an effective policy is a reusable layer | every_field_randomized_intersections |
| `test/core/scrub-fuzz.test.js` | a secret never survives the stream, in any encoding at any chunk size | secret_never_survives_stream |
| `test/core/scrub-fuzz.test.js` | streaming and whole-body scrubbing agree | secret_never_survives_stream |
| `test/core/scrub-fuzz.test.js` | text with no secret in it is passed through byte for byte | pathological_pattern_and_ordinary_controls |
| `test/core/scrub-fuzz.test.js` | every declared encoding of a secret is actually caught | js_encoding_sets; js_scrub_encoding_and_nested_vectors |
| `test/core/scrub-fuzz.test.js` | a secret inside a base64 blob does not come back with its tail intact | js_scrub_encoding_and_nested_vectors |
| `test/core/scrub-fuzz.test.js` | a secret is scrubbed as the response actually carries it, not as a JS string | js_scrub_encoding_and_nested_vectors |
| `test/core/scrub-fuzz.test.js` | the same holds through the streaming path, at any chunk size | stream_cut_regressions_with_ordinary_controls |
| `test/core/scrub.test.js` | a raw echo of the injected secret is replaced by the placeholder the agent used | js_scrub_encoding_and_nested_vectors |
| `test/core/scrub.test.js` | every encoding of the secret is covered | js_scrub_encoding_and_nested_vectors |
| `test/core/scrub.test.js` | base64 at all three alignments is covered | js_encoding_sets |
| `test/core/scrub.test.js` | a secret split across streaming chunks is still caught | streaming_every_encoding_all_chunk_sizes |
| `test/core/scrub.test.js` | a different vault credential echoed back is redacted, not revealed | js_scrub_encoding_and_nested_vectors |
| `test/core/scrub.test.js` | derived tokens the vault never stored are redacted by shape | js_scrub_encoding_and_nested_vectors |
| `test/core/scrub.test.js` | short values are never treated as secrets, so responses are not shredded | floor_and_untrusted_redaction_before_cut |
| `test/core/scrub.test.js` | a response with no secret passes through byte-identical | pathological_pattern_and_ordinary_controls |
| `test/core/scrub.test.js` | encodings() are distinct and deduplicated | js_encoding_sets |
| `test/core/scrub.test.js` | a secret this request injected is redacted even below the length floor | js_scrub_encoding_and_nested_vectors |
| `test/core/scrub.test.js` | a short OTHER vault secret keeps the length floor, to avoid shredding prose | floor_and_untrusted_redaction_before_cut |
| `test/core/scrub.test.js` | the derived-token shapes do not match ordinary English | pathological_pattern_and_ordinary_controls |
| `test/core/scrub.test.js` | the derived-token shapes still catch real tokens the vault never stored | js_scrub_encoding_and_nested_vectors |
| `test/core/substitute.test.js` | a placeholder at a declared header site is located and substituted | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | the scheme must match the declared site | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | scheme matching tolerates case and repeated whitespace, per RFC 9110 | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | Authorization: Basic is decoded so the password field is a real site | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a JSON body pointer is a site when declared, and substitutes in place | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a form field is a site when declared | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a query parameter is a site when declared and is re-encoded on substitution | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | the request path is never a site | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a placeholder in an undeclared body field is located and matches no site | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a placeholder in an undeclared header matches no declared site | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a placeholder is unchanged by ordinary URL encoding | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | percent-encoded placeholders are detected and never count as a site | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | double percent-encoding is detected | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | JSON unicode escapes are detected | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | base64 smuggling is detected at every alignment and in both alphabets | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a Basic header is read as its site and not double-reported as base64 | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | UTF-16 and other non-matching encodings do not produce false positives | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a body with no placeholder produces no occurrences | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | multiple placeholders in one request are each located separately | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | an oversized body is reported unscannable rather than forwarded unchecked | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | describeLocation is specific enough for an agent to fix its own request | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | the raw-bytes reconciliation does not refuse ordinary requests | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/substitute.test.js` | a second header of the same name is substituted in place | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match; substitution_sites_and_ordinary_controls |
| `test/core/wizards.test.js` | read-only access cannot write, and needs no approval because it cannot | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | the write level asks before changing anything, and never deletes | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | the full level includes delete and says so by not asking | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | an unknown access level is refused rather than defaulted | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | the budget falls back to the profile default, not to unlimited | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | a suggested name avoids collisions with what is already stored | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | a suggested name is always a valid slug | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | the one-repository scope is genuinely narrow | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | the owner scope covers repos and orgs but not everything | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | custom paths are split and trimmed | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | every connector offers a scope list with a custom escape hatch | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | model APIs are offered a larger budget than ordinary APIs | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/core/wizards.test.js` | every access level has a label and a hint a person can act on | not applicable, because the wizard is src/cli/wizards.js, owned by av-cli |
| `test/security/approval-verdict.test.js` | only true or false decides on the approvals route, and anything else decides nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/approval-verdict.test.js` | a signature cannot carry a verdict that is not a boolean either | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/approval-verdict.test.js` | the web UI refuses a verdict that is not a boolean, before it spends a signature | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/approval-verdict.test.js` | the web UI no longer turns a string "false" into an approved session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/approval-verdict.test.js` | the shared decision builder will not coerce a verdict | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/budget-reader.test.js` | the shared reader gives each listed budget its C4 meaning | budget_reader_all_legacy_shapes |
| `test/security/budget-reader.test.js` | the gateway and chargeGrant agree on every listed budget, at the limit and under it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-health.test.js` | a GitHub expiry header becomes observed_expires_at | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | ISO 8601 and RFC 1123 expiries parse, and the header name is case-insensitive | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | an unparseable expiry is ignored, and so is a calendar date that is not a date | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | a rate-limit header that is not a non-negative integer is ignored | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | an ordinary Date header is not treated as an expiry | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | a profile with no health block yields nothing, even when GitHub headers are present | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | no profile carries a built-in SPKI pin | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | header arrays and a Headers-like get() are read the same way | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-health.test.js` | V-H2: an ISO expiry with an offset is a real calendar date, shifted by the offset | profiles::tests::js_profiles_and_health_vectors; health_invalid_metadata_and_ordinary_controls |
| `test/security/connectors-pinning.test.js` | spkiOf is the SHA-256 of the SubjectPublicKeyInfo openssl emits | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | a trusted chain with a leaf, intermediate or root pin is sent, and the response comes back | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | a trusted chain with a mismatched pin sends nothing and rejects AV_PIN_MISMATCH | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | a rotated leaf still matches a backup pin on the intermediate | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | only non-leaf pins on a chain the trust store does not accept: refused with Node's code, and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-L1: an exact leaf pin stands in for CA trust, for a self-signed leaf and an untrusted chain | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-L2: a pinned self-signed leaf for another host name is refused, and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-L3: a self-signed leaf whose pin is not on the list is refused, and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-L4: a leaf copying the pinned intermediate's key cannot finish a handshake, and the handshake leaf is the one checked | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-L5: a pinned self-signed leaf out of date is refused with AV_PIN_MISMATCH, and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | a pinned, trusted certificate for another host name is refused, and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-P1: a forged leaf plus the real intermediate does not satisfy an intermediate pin | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-P2: a forged leaf plus the real intermediate and root does not satisfy a root pin | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-P4: an unrelated leaf with the real intermediate appended does not satisfy an intermediate pin | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | verifiedChainPins counts an issuer only when its key signed the certificate below it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-P5: pins that are not a list of pins are refused before a connection, never read as no pins | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-P6: a list with a malformed entry is refused before a connection | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | V-P7 and V-P9: each pinned request makes its own handshake, and a redirect is returned, not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | no pins (null, undefined, []) keeps Node verification unchanged | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | pins on an http URL are refused before a connection, with reason plaintext | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | fetchChainPins returns the presented chain and sends no request | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | chainPins de-duplicates and stops when the issuer points at itself | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | profiles ship no built-in pins | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | F-1: a Host header the certificate names does not let a leaf, intermediate or root pin accept a server that does not name the URL host | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | F-1: the TLS server name is the URL host, and a Host header naming another host is refused before a connection, pinned or not | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | F-1: a Host header with another port, no port, another case of another name, or a list is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | F-1: hostHeaderMatches allows only the URL host, any case, with or without the scheme's default port | pins::tests::malformed_pin_tables_never_mean_unpinned; pins::tests::identity_and_host_header (pure functions); covered by conformance for TLS transport |
| `test/security/connectors-pinning.test.js` | F-1 controls: a matching or absent Host header is delivered with and without pins | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | Round 5 F-1: a getter or a Proxy cannot pass the Host check and then put another host on the wire | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | Round 5 F-1: headers that are not names with string values are refused before a connection | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-pinning.test.js` | Round 5 F-2: an IPv6 URL connects, the certificate is checked against the IP SAN, and pins apply | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | the probe hits only the profile method and path, and ignores a caller path, method and body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | slack is a POST to the profile path with an empty form body, not the caller body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | a header site with no scheme sends the raw secret, and the first header site wins | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | the result and the health record never contain the secret, a placeholder, or the body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | status classes: 401, 403, other codes, and a network error | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | http and postgres have no probe, and a credential with no header site is refused before any request | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | a host that is not a hostname is refused and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | an ordinary host, port and http scheme are used as declared | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | pins for the host are forwarded, and a missing recordHealth still returns the result | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | the second probe inside 60 seconds is throttled, and one after the window is not | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | V-Q5: a now on the call does not skip the throttle | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | V-Q5: a far-future now on the call does not lock the credential out | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | V-Q7: a body that never ends is cut off and destroyed, and the probe returns | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | V-Q7: an ordinary short body is drained to its end and not cut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | V-Q8: a recordHealth failure after a 200 is a store error, not unreachable | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | V-Q9: pins of the wrong shape refuse the probe before the secret is read | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | pins under two spellings of the same host are joined, and an empty one does not hide the other | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | F-1: pins are looked up by the host of the URL the probe sends to, however the key or the declared host spells it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/connectors-probe.test.js` | with the real upstream: a root pin adds to CA verification, a mismatch sends nothing, and a match probes only /user | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | rotating needs a human; once rotated, the next request carries the new value | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | rotating denies the held requests a human approved against the old key | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | a rotation it cannot read is refused, and changes nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | adding and removing a scrub pattern need a human; the sample is the human's own text | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | a pattern that could backtrack, match everything, or carry a secret is refused, before the gate | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | setting an expiry needs a human, and is metadata the gateway does not enforce | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | a credential can be added with its expiry; a bad one leaves nothing stored | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | setting and removing pins need a human, and only for a host the credential reaches | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | cred test is open, hits only the profile's probe, and never returns the body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | a second test within a minute is throttled through the route; another credential is not (C20) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | quarantine is open, stops every use at once, and denies held requests | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | an agent cannot ask for a session on a quarantined credential, over either door (C12 note) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | releasing a quarantine needs a human, and a still-live session works again | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-credentials.test.js` | a secret across the 200-character cut of a quarantine reason leaves none of itself behind | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | the stream sends a snapshot, then each new item, without the agent's words | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | a ninth watcher is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | the stream resolves no session: a token sent to it is ignored and touches nothing (C20) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | setting a webhook needs the owner; only its host is ever shown or recorded | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | the minimal webhook is counts and ids only; one POST per interval | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | the headline webhook adds the gateway's summary, never the agent's words | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | a test notification is throttled, a failure is recorded once, and no webhook is not found | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | a stored secret an agent puts in a proposal path does not reach the stream or the webhook (F14) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-notify.test.js` | a headline with no secret in it is sent as the summary, unchanged (F14) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | saving a template needs a human, and is checked like a create first | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | templates are listed with summaries, read in full by name, and deleted without presence | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | creating from a template binds its hash: an edit after looking is refused, the current hash works | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | a signature over one template hash cannot be spent on another | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | overrides only narrow: DELETE on a GET template still makes a GET-only session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | an infinite template can only be made finite, never the other way round | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | an elevated template needs a fresh proof to create, and the window is not one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | a session request from a template is a snapshot: an edit afterwards does not reach the session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | a template request names one credential, and a template's owner fields come only from the template | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-api-templates.test.js` | MCP asks by template name, with no credential named, and lists single-credential templates | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-guard.test.js` | a token or placeholder a daemon route returns never reaches the page | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-guard.test.js` | ordinary text is untouched | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-guard.test.js` | the approvals list, a webhook URL and an error message are held to the same line | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-guard.test.js` | the hand-off for a session made here still carries what the agent needs | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-guard.test.js` | the page runs the very parser the server rebinds a narrowing with (C21) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-handoff.test.js` | an error from POST sessions reaches the page with none of the withheld fields (F1) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-handoff.test.js` | a successful hand-off carries the token and placeholders, and nothing else withheld (F1) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-handoff.test.js` | a card field is copied back only as a scalar or a list of scalars (F1) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-handoff.test.js` | a withheld key is withheld in any case, hyphenated, nested, and inside arrays (F2) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-handoff.test.js` | towardPage folds case and hyphens and leaves other keys alone (F2) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-handoff.test.js` | a reserved operation field is a 403 refusal, not a 500, and is not forwarded | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-rotate.test.js` | the current key can enrol its replacement, and only the replacement works afterwards | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-rotate.test.js` | a replacement with no signature, or signed by the new key itself, is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-rotate.test.js` | the record enrolled is the one registered here, not one the request names | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-rotate.test.js` | with nothing registered there is nothing to enrol | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-rotate.test.js` | a signature for the replacement is refused when it covers a different record | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-rotate.test.js` | a first enrolment still cannot be made this way | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | every wave-3 change is gated, and exactly the daemon-gated ones are re-verified (A.6) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | without a signature, no change reaches the daemon | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | a signature over a different request is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | a signature with another op name is refused, even over the same fields | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | with its own signature, each change reaches its route, carrying what the daemon re-verifies | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | a rotation value is bound by digest, never in clear | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | the probe takes a credential name and nothing that could steer it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | quarantine needs no fingerprint, and passes on the name and the reason only | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | panic needs no fingerprint, and only a real true locks | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | the read routes reach the routes the contract names | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-routes.test.js` | the audit view can ask for one kind of record, and gets only that kind | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-webauthn.test.js` | every secret-bearing field is bound by digest, never in clear | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-webauthn.test.js` | a string digests exactly as it always did | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-webauthn.test.js` | two different bundles give two different operations | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-webauthn.test.js` | the same bundle with its keys in another order is the same operation | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-webauthn.test.js` | the page builds the same operation as the servers, field for field | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/control-ui-webauthn.test.js` | the page's digested fields are the servers' digested fields | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | the control socket refuses a session aimed at a host the credential does not permit | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | a session confined to the credential host cannot then be pointed elsewhere | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | the real credential value never reaches a caller-controlled destination | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | without a passphrase, widening is open but audited, not silently trusted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | with a passphrase set, the socket cannot unlock without it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | with a passphrase set, an agent cannot mint capability without it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | an agent cannot mint a placeholder against a grant it does not own | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/exfil.test.js` | a human with a presence window can still issue placeholders | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-approvals.test.js` | denying with no human present is refused, and the request stays pending | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-approvals.test.js` | a signature for approving cannot be spent on denying | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-approvals.test.js` | a deny signed for exactly that deny goes through, as the UI sends it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-approvals.test.js` | a deny inside a passphrase window goes through, as the CLI sends it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-approvals.test.js` | an approval that already ran never hands its cached response back | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | F1: the only passphrase cannot be removed, and the socket stays gated | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | F1: removing Touch ID unlock first does not make the passphrase removable | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | a wrong passphrase is still a failed proof, not a factor refusal | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | control: with a presence authenticator left, the passphrase can be removed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | an authenticator-only vault says widening is still gated when no window can open | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | control: a vault with no factor at all still says it is ungated | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | control: a passphrase changes with the current one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | F2: a rotation to an unusable key is refused, and the sole key keeps working | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | F2: a rotation stores the credential and nothing else the caller sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | F2: a first enrolment is held to the same shape | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | a presence key that fails to save leaves the old one in place | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | F3: the store factory refuses a Touch ID unlock wrap with no passphrase | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | control: a vault created with a passphrase opens with it and nothing else | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-factors.test.js` | control: a vault with no passphrase keeps its none wrap | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-page.test.js` | what the page signs for a narrowing is what the server rebuilds | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-page.test.js` | a narrowed approval made the way the page makes it goes through | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-page.test.js` | the hand-off example sends the token where it cannot displace the placeholder | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-page.test.js` | the docs name every MCP tool, and only injection sites that exist | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-page.test.js` | without a passphrase the page gives the daemon's guidance instead of a tap | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | the shared window cannot enrol an unlock factor or replace the authenticator | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | with the passphrase in the request, the same changes go through | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | a vault with only an authenticator can still rotate it, by assertion | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | removing Touch ID unlock by assertion works; by window it does not | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | one window still covers an ordinary multi-step flow, and each step is recorded | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | locking closes the window | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | the web UI enrolment passes the passphrase through, with no window | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | an assertion from a page the caller named is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | an assertion from the default UI origin is accepted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | trusting another UI origin needs the owner, and then it works | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | with no factor enrolled, a fresh-presence change is refused, not waved through | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-presence.test.js` | a fresh proof opens no window | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | the no-wider check itself refuses a result that dropped a constraint | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | narrowGrant can only intersect, never widen | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | narrowGrant still narrows | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | a forked session can only narrow its parent's grants | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | an expired session takes its placeholders with it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | the ledger bound collects active rows whose time has passed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | a placeholder lives as long as its session, idle extension included | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | a placeholder with its own ttl still expires on time | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | booting a locked vault does not record an unlock nobody performed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-store.test.js` | booting an unlocked vault still unlocks it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | enrolling Touch ID unlock from the UI works with one tap | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | a tap over one PRF secret cannot enrol another | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | the daemon still refuses an enrol that carries no proof at all | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | removing Touch ID unlock from the UI works with one tap | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | without a passphrase, Touch ID unlock is refused before the tap, and says what to do | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | once a passphrase is set, the same vault enrols Touch ID unlock with one tap, and both open it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | a vault with no factor at all is refused Touch ID unlock with the same way forward | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | without a passphrase, the presence authenticator rotates by a tap from itself, through the UI | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-touchid.test.js` | a first presence enrolment without a passphrase is refused with the same way forward | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-webauthn.test.js` | a request field named op cannot replace the route op | operation::tests::reserved_fields_and_secret_digests |
| `test/security/fix-control-webauthn.test.js` | a supplied digest cannot replace the one computed from the secret | operation::tests::reserved_fields_and_secret_digests |
| `test/security/fix-control-webauthn.test.js` | an ordinary request still binds every field, and the secret only by digest | operation::tests::reserved_fields_and_secret_digests |
| `test/security/fix-control-webauthn.test.js` | a signature for a narrow session cannot issue a placeholder | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/fix-control-webauthn.test.js` | a signature over the real placeholder request still works | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | an approval that already ran cannot be denied, and the deny hands back nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | granting an approval that already ran does not arm it again | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a granted approval cannot be flipped to denied before it is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | deciding a pending approval still works, both ways, and returns no response body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | literal marker text cannot make two different requests hash alike | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | reordering the values of a repeated header changes the request hash | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a method-override header is held to the methods allowlist | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a method-override header counts for approval, and the human is shown it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | ordinary requests are not affected by the override checks | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a failure before connecting refunds every placeholder the request spent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a failure that may have reached the server refunds nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a streamed approval that ran does not leave its resend waiting forever | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a buffered approval whose replay window closed is asked for again, not stuck | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a request that failed after reaching the upstream is asked for again, not stuck | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a resend while the approved request is still in flight keeps waiting on it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | renewing the placeholder inside a Basic header keeps the approval | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-approvals.test.js` | a different Basic user, or another spelling of the same header, still needs its own approval | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | the scrubber catches the encodings it used to miss | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | the scrubber leaves ordinary escaped and wrapped text alone | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | a percent-encoded secret split across stream chunks is still caught | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | a derived token straddling the stream hold-back is not emitted in halves | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | the stream scrubber still emits ordinary text unchanged | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | a backslash encoded more than once is still refused | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | ordinary encoded paths still normalise | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | a literal percent sign can be sent, and still cannot hide an escape | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | intersecting two rates never allows more than either | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | intersecting rates in the same unit is the smaller count | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | lint accepts valid enforced limits | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | JSON substitution changes the one string and nothing else in the body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | JSON substitution follows the same duplicate key and pointer escaping as the parser | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match |
| `test/security/gateway-core.test.js` | form substitution leaves the rest of the field and the body as written | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | Basic substitution writes the Authorization header the placeholder was found in | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match |
| `test/security/gateway-core.test.js` | Basic substitution through the pipeline, with a second Authorization header present | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | an ordinary single Basic header is substituted as before | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | rate layers preserve canonical windows and refuse unknown units at evaluation | js_policy_reference_vectors; path_parsing_hardening_and_ordinary_wire_controls |
| `test/security/gateway-core.test.js` | base64 wrapped at any width, and hex in mixed case, are redacted | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | several wrapped blobs in one body are each searched, and the search ends | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | wrapped prose, short lines, ordinary blobs and ordinary mixed-case hex are left alone | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | the wrapped and mixed-case views stay linear on large bodies | js_scrub_encoding_and_nested_vectors; stream_cut_regressions_with_ordinary_controls; pathological_pattern_and_ordinary_controls |
| `test/security/gateway-core.test.js` | a path whose escape was itself encoded is refused, however many times it was | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | a path encoded once is sent and checked as before | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | a form placeholder with a percent-encoded character leaves the rest of the body as written | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | a placeholder hidden by a duplicate JSON key is refused, however it is hidden | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-core.test.js` | locate() reports a placeholder in a shadowed duplicate by position | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match |
| `test/security/gateway-core.test.js` | a substituted placeholder left anywhere in the outgoing request is found | js_substitution_vectors; encoded_locations_refuse_and_raw_controls_match |
| `test/security/gateway-core.test.js` | ordinary JSON, duplicates without a placeholder in the shadowed copy included, is substituted as before | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a secret in a JSON body with `\/` and `\uXXXX` escapes does not reach the agent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a secret that starts in a content block and continues in its deltas is cut, identity and gzip | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a secret split across events whose index disagrees with its array position is cut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a secret split across events where the index is missing from some of them is cut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a secret base64-encoded and then percent-encoded does not reach the agent in a body, a header or a redirect | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a secret base64-encoded and percent-encoded in a stream is cut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | ordinary JSON with `\/` in URLs and `\u` escapes passes through unmodified | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | ordinary percent-encoded query strings pass through unmodified in a body, a header and a redirect | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | ordinary Anthropic, OpenAI chat, Responses and Gemini streams pass through unmodified, identity and gzip | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | the ordinary streams are left whole when the vault holds a base64-style secret | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | Grok's two-layer case: base64 percent-encoded with every % as a \uXXXX escape is redacted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | every pair of the four encodings, nested, is redacted in a buffered body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | three-layer stacks within the limit are redacted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a four-layer stack is beyond the limit but does not crash | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a buffered body whose nesting exceeds the decode budget fails closed, not through | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | an event stream whose nesting exceeds the decode budget is cut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | an ordinary base64 image data URL passes through unmodified | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-hardening.test.js` | a large ordinary JSON response with mixed encodings passes through unmodified and uncut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-model.test.js` | model meters classify only the contracted endpoints and methods | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | metered JSON fails closed without echoing request contents | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | reservations use original UTF-8 byte length and provider output limits | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | invalid or absent output limits use the binding profile defaults | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | checked prices use microdollars per million tokens and reject unknown USD models | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | reservation prices round up exactly and reject integer overflow | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | buffered usage includes Anthropic cache tokens and both OpenAI response shapes | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | malformed, absent and partial usage cannot turn into a zero charge | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | Anthropic SSE merges message_start cache usage and cumulative message_delta | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | OpenAI and Google SSE final usage survives chunks without usage and repeated totals | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | missing usage charges the full reservation; actual usage may exceed it | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-model.test.js` | Gemini thinking tokens are charged as output, and a thoughts-only reply still settles | js_payload_and_model_reference_vectors; model_meter_missing_usage_and_overflow_controls |
| `test/security/gateway-w2-payload.test.js` | JSON constraints are strict, additive and pointer-aware | js_payload_and_model_reference_vectors; graphql_malformed_documents_and_ordinary_controls |
| `test/security/gateway-w2-payload.test.js` | JSON parser rejects duplicate decoded names, malformed input and excess depth | js_payload_and_model_reference_vectors; graphql_malformed_documents_and_ordinary_controls |
| `test/security/gateway-w2-payload.test.js` | form/query refuse ambiguity and enforce strict names | js_payload_and_model_reference_vectors; graphql_malformed_documents_and_ordinary_controls |
| `test/security/gateway-w2-payload.test.js` | payload validation rejects unknown keys and all malformed constraints | js_payload_and_model_reference_vectors; graphql_malformed_documents_and_ordinary_controls |
| `test/security/gateway-w2-payload.test.js` | GraphQL parses full operations, fragments, arguments and strings | js_payload_and_model_reference_vectors; graphql_malformed_documents_and_ordinary_controls |
| `test/security/gateway-w2-payload.test.js` | GraphQL request classification checks batches and persisted queries | js_payload_and_model_reference_vectors; graphql_malformed_documents_and_ordinary_controls |
| `test/security/gateway-w2-pipeline.test.js` | rate allows capacity, limits pending requests, and never spends a refused use | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | malformed limits and persisted counters fail closed without an upstream | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | quota charges one per call, survives restart and rollback, refunds pre-connect errors | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | concurrency releases after success, pre-connect failure and post-connect failure | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | SSE slots release on completion, immediate close and scrubber cut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | payload and method-bound routes run before approval and consume | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | custom patterns from every credential scrub bodies, headers and errors; corrupt pattern withholds | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | token reservations block concurrent overspend and settle buffered usage | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | unpriced and unmodeled spend refuses while ordinary free GET passes | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | missing usage and aborted SSE charge full reservation; completed SSE uses usage | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | restart charges outstanding reservation and pre-connect failure releases it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | redirects check hosts, paths, scheme, method, approval and max before sending | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | allowed redirect follows, charges each hop and forwards correct pins without body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | pins map to safe problem and refund; health observer receives response metadata | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | approval preview scrubs secrets and placeholders and notifications fire once | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | quarantine and grant expiry stop before consume, and denyApprovals returns only a count | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | preflight is observational, peeks limits and reports a hold without creating approval | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | preflight denial never trips and the eleventh call is throttled | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | tripwires revoke only authenticated matching session and deny its approvals | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | tripwires default off; panic hook awaits and reports unwired or failed denial honestly | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | legacy decimal budgets work while noncanonical values never reach comparisons | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a held request previews its label, a redacted secret and no placeholder, token or audit body | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | the preview builder replaces encoded placeholders, keeps duplicate JSON keys as sent, and stays under 8 KiB | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | preflight expiration has no state changes and uses the shared expiry predicates | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | expired grant fallback keeps its specific error after store marked it expired | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | quarantine tripwire pauses only its credential and leaves other sessions active | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a redirect hop is held to the GraphQL rules a direct request is held to | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a redirect hop answers to the body rules as a body-less request, not to none | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a single-valued header sent twice, differently, is refused before anything is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | one Content-Type, or an exact repeat of it, is checked and sent as that one value | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a repeated list header goes upstream once per name, carrying every value | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a query a URL would cut or rewrite is refused before the payload rules read it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a request a method override made a write does not have its redirect followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a followed redirect sends nothing of the agent's but the credential and the hop allowlist | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a credential declared at a body or framing header is not sent on a hop | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a Location carrying _method is not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a hop is checked as the method it is sent with: 307 and 308 keep it, 301 to 303 send a GET | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a method override on a direct request is still refused, and an ordinary redirect still follows | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a method-override field naming another method is refused, and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a method-override field naming the request's own method is sent as it is | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a hop keeps the API-version headers a provider needs, and never a cookie, override or forwarding header | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | Grok round 5, finding 1: a Location naming another method in a folded spelling is not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | Grok round 5, finding 2: a ; in the query cannot hide a parameter from the payload rules | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | every override spelling is refused on a direct request and stops a hop | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a ; query is refused under any payload rule on both paths, and goes out unchanged under none | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a name a server could fold onto a rule's name is refused, and a repeated name is a duplicate | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | generated requests: what the policy read is what a local upstream received, and every reader reads it within the policy | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | ordinary traffic is untouched: & queries, provider APIs, and a redirect that keeps its version headers | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | the view reads a query as the union of its readers | js_request_view_vectors |
| `test/security/gateway-w2-pipeline.test.js` | Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | ${where} ${pairs} | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | Grok round 6, method: a name PHP reads as _method is refused, and a hop to it is not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | ${where} ${pairs} | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a stray name is refused on every path under any rules, and a hop to one is not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | ${type[1]} ${JSON.stringify(body)} | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a multipart part is named by every name in its Content-Disposition, folded or not | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a name is folded the way PHP registers it: cut at NUL, leading spaces dropped | js_request_view_vectors |
| `test/security/gateway-w2-pipeline.test.js` | ordinary provider traffic is sent unchanged under the name check | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | Grok round 7, payload: a bracket-wrapped name is refused, and a hop to it is not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | ${where} ${pairs} | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | Grok round 7, method: a bracket-wrapped _method is refused, and a hop to it is not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | ${where} ${pairs} | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a name Rack 2.2 reads as a ruled one or as _method is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a name that starts with punctuation is refused on every path, and a hop to it is not followed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | ordinary traffic that opens a name with $ or a JSON key with $ or @ is sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-pipeline.test.js` | a repeated list name is sent under unrelated rules, and a rule on its base checks every entry | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-policy.test.js` | route pairs bind methods to their own paths and every inherited set applies | js_policy_reference_vectors; every_field_randomized_intersections |
| `test/security/gateway-w2-policy.test.js` | stored effective route and payload policies retain all ancestor constraints | js_policy_reference_vectors; every_field_randomized_intersections |
| `test/security/gateway-w2-policy.test.js` | malformed stored route and payload constraints refuse before reaching upstream | js_policy_reference_vectors; every_field_randomized_intersections |
| `test/security/gateway-w2-policy.test.js` | creation refuses coercion, supports zero limits, and cannot escape credential hosts | js_policy_reference_vectors; every_field_randomized_intersections |
| `test/security/gateway-w2-scrub.test.js` | restricted scrub grammar refuses dangerous or broad expressions | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | extra patterns are additive to stored secret and derived protections | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | extra patterns survive every stream chunk boundary | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | long custom tokens do not leak when bounded suffix spans stream windows | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | invalid persisted compiled patterns fail closed | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | escaped literal prefixes retain custom matches across chunks | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | bounded grammar refuses combinatorial repetition and accepts realistic shapes promptly | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | abc | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | every accepted pattern scans hostile input in under 50 ms | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | a stream that mentions a pattern prefix keeps flowing, and its holdback stays bounded | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-scrub.test.js` | a custom token straddling every possible cut is redacted whole, in any chunking | scrub_extra_patterns_validation_additivity_and_controls; stream_extra_pattern_hold_and_cut; js_scrub_pattern_grammar |
| `test/security/gateway-w2-seams.test.js` | pins on a plaintext credential refuse before any connection; no pins still connects | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a throwing health reader or recorder never turns an executed request into a failure | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | onPending gets the id and headline only, and a throwing hook still holds the request | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | denyApprovals filters by session, credential and grant ids, records the reason, and returns a count | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | panic denies held requests, revokes every session including an infinite one, then the hook, then the record, then the lock | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a panic whose hook fails still revokes everything and records a partial panic | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a tripwire that throws while firing cannot cost the agent its denial | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | with tripwires on, a bad-location run revokes the session; ordinary requests never count | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | an unauthenticated replay never counts against the session its placeholder names | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a quarantined credential is refused before anything is spent, and works again once released | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | preflight and the real route agree on finite, expired, infinite and legacy sessions and grants | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | preflight writes one record with nulls, not undefined, and puts no hint where there was none | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a redirect to another port on an allowed host is not followed; the same port is | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a redirect hop that cannot connect closes the redirect it was following and is not refunded | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | GraphQL rules read the URL query on a POST too, and the decided path ends the /graphql check | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a binary upload passes a grant whose payload rules only constrain the query | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a strict-query refusal names the parameter by its index and never echoes a name or value | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a spend refusal says what is left and what the call could cost; a call that fits passes | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a CRLF-framed stream settles on its usage; a cut stream charges the full reservation | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a pipeline built while the vault is locked charges stale reservations at the first request after unlock | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | an extra pattern scrubs an error detail, is redacted within an event, and cuts a stream that splits it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a method-override header is held to the route pairs as well as the methods list | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/gateway-w2-seams.test.js` | a held request is recorded as held, an allowed one as allow, a refused one as deny (C11) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a correct leaf pin goes out through the real pinnedRequest, with the secret and the URL host | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a wrong pin on an untrusted self-signed upstream sends nothing and is refunded; its own leaf pin is reached | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | on a chain the daemon trusts, an intermediate or leaf pin is honoured, and a pin that matches nothing is AV_PIN_MISMATCH, refunded and unsent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | the same chain with an intermediate pin is refused, unsent, when the daemon does not trust its root | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | the agent's Host header never reaches the connector; a Host that did would be refused unsent (C9) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a repeated list header goes out folded into one line, not refused as header_format | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a malformed pin table on a credential is pinned, not unpinned: refused before a connection | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | the connectors health reader and the store record what a response says (F10) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | an expired grant is refused before anything is sent, and stays expired, not missing (F18) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | each redirect hop is charged to the grant by the store, and the hop past the budget is not followed (F6) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a grant layer with no limit is bounded by the session layer, and its hops are charged (C4, one reader) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a credential the store quarantined is refused before any send, and a tripwire quarantines through the store (F16) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | preflight and the real route agree, read with the store itself, on finite, expired, infinite and legacy sessions | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a scrub pattern the store saves is applied by the gateway, and one the grammar refuses is never saved | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a held request is recorded as held, and the store report counts it as held, not as a use (C11) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | panic: the wired hook denies pending session requests, and a throwing hook still completes the panic (C1) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | an infinite session is refused on a network listener, with nothing sent and the refusal recorded (C12) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate2-seams.test.js` | a finite session on a network listener is unchanged by C12 | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-e2e-approvals.test.js` | A.7 6 (F13, F14): watch prints a held POST, the preview hides the placeholder, and the approved resend runs once | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-e2e-approvals.test.js` | A.7 7 (F15): session narrow --methods GET mid-run refuses the next POST and keeps GET working | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-e2e-approvals.test.js` | A.7 7 (F16): with the tripwire on, a replayed placeholder revokes its session before the answer returns | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-gates.test.js` | C19: the page, webauthn.js and so the daemon digest every secret-bearing key the same way | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-gates.test.js` | every gated UI route: the operation the page signs is the one the UI server and the real daemon rebuild | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-gates.test.js` | C22(4): a pin removal signed without spki, or for another spki, is refused by the UI and by the daemon | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-gates.test.js` | C19 end to end: a backup bundle is bound by its canonical digest when the daemon restores it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-gates.test.js` | C19 end to end: a webhook URL is bound by digest, and the page signs what the daemon checks | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | the page reads every narrowing with the module's parser, and keeps no second one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | the CLI and the page sign the same operation for the same narrowing, field by field | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | through the UI server, each narrowing signed by the page is approved by the real daemon, and kept | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | a narrowing that cannot be read: the CLI exits 2 naming the field, and sends nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | a narrowing that cannot be read: the page shows why and builds, signs and sends nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | a narrowing that cannot be read: the UI server answers 400 and the daemon 4xx, and nothing is approved | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | a key no approval applies is refused by the shared parser, the UI server (400), the page and the CLI, as the daemon refuses it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-narrowing.test.js` | OVERRIDE_KEYS is the list the self-contained parser reads, key for key | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C27: a secret as the path glob and the route glob is in no gateway row, before or after rotation; the grant still allows the path | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C27: a path-only grant records path_rule and a null route_rule, never the glob | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C27: a deny pattern added by an open narrowing is named by index in the denial, never by its text | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | F2: decide-many writes only ids the daemon minted, and counts the rest | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C26: elevationOf names first-use with a write method, and not read-only first-use | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C26: creating first-use with writes needs a fresh proof; read-only first-use rides the window | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C26: approving a request into first-use with writes needs a fresh proof, not the window | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C26: narrowing a request into first-use with a write left needs a fresh proof; narrowing it to read-only does not | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | C26: a live narrowing cannot loosen a write grant into first-use | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | a boolean flag given a value, even "false", is refused with exit 2 naming the flag | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r4.test.js` | a numeric flag with no value is refused with exit 2 naming the flag, not read as 1 | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | F1: a refused Touch ID assertion records a closed code, never the client data it quotes, on all three surfaces | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: a denial row has the code, rule, method and path, and no sentence; explain-denial gives the sentence to its own session only | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: a payload rule names its key by index, and a strict query names the parameter by position, on all three surfaces | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: a redirect refused for its host records no host it was not allowed to reach | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: a fault is recorded by class, never by message | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: a listener that cannot bind records its system code, not the message | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: session.created says whether a session has a label, not what it says | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: a failed webhook records a system code or `error`, never other text from the error | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: every *_untrusted field is scrubbed whole, cleaned of placeholders, and cut to 200 | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | C28: a quarantine reason restored from a bundle is cleaned before it is recorded | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/integrate3-r5.test.js` | item 3: mcp install --tls takes no value; bare --tls is the https URL and its absence the plain one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/path-parsing.test.js` | the paths the deny list is for are denied | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/path-parsing.test.js` | a tab, newline or carriage return cannot smuggle a path past the deny list | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/path-parsing.test.js` | an encoded fragment or query cannot truncate the path after the check | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/path-parsing.test.js` | percent-encoding is resolved once, and a path that would decode again is refused | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/path-parsing.test.js` | an encoded slash is refused rather than guessed | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/path-parsing.test.js` | whatever the spelling, the policy reads what the wire will carry | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/path-parsing.test.js` | encoding for the wire keeps the characters a path is allowed to contain | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/path-parsing.test.js` | a path that is only control characters does not become the root | path_parsing_hardening_and_ordinary_wire_controls; denied_path_spellings_never_escape |
| `test/security/pipeline.test.js` | the placeholder is replaced with the real secret and only the upstream sees it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | the session token works as a carrier instead of a placeholder-derived session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | S06: a valid placeholder aimed at a non-granted host never opens a connection | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a path outside the grant is denied before the wire | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a write method under a read-only grant is denied | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a profile deny list blocks webhook creation even under a wide grant | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | S25: a placeholder in a request body is refused with zero upstream bytes | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | encoded placeholders in a body are caught in every encoding | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a placeholder in the request path is refused: the path is never a site | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a placeholder in an undeclared header is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | the places a naive scan does not look are not hiding places | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a second Authorization header is refused, so no placeholder goes upstream | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a malformed percent-escape in a query key does not blind the scan | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | S05: a one-time placeholder cannot be used twice | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | S05: concurrent uses of a one-time placeholder produce exactly one upstream call | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | an exhausted placeholder hands back a working successor | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | S04: a placeholder from another session is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a budget layer that names no limit does not make the grant unlimited | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a budget limit written as a string still counts | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a budget limit that is not a number refuses rather than counts nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | held approvals are bounded, and do not hold response bodies forever | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a stale pending approval is forgotten, so the cap is not permanent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a bare placeholder does not authorize on a network listener | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | the successor to a one-time placeholder is also one-time | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | an approval does not carry over to a request with different headers | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a fractional use count does not persist state the log never records | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | an upstream cannot choose how much of the daemon it occupies | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a use is given back when the request never reached anyone | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a use is NOT given back when the request may have been delivered | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a refused request does not decrypt the whole vault three times | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | an approval survives a request that never reached the upstream | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a refund into a revoked grant is refused, not quietly granted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a legitimate refund is recorded, so the ledger and the log agree | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a placeholder cannot be spent under a grant it was not issued under | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a revoked session stops working immediately | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a forged placeholder is refused by its checksum, before any lookup | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a real placeholder with one character changed does not verify | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | the fingerprint shown in cred list is not an oracle for the checksum key | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | S09: an upstream echoing the secret back has it replaced by the placeholder | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | an upstream echoing the secret in a header has it scrubbed too | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | an upstream cannot forge AV-* headers or set cookies on the agent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a derived token minted upstream is redacted by shape | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | S28: a request carrying Origin is refused, so a web page cannot use the gateway | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a Host header outside the allowed set is refused, blocking DNS rebinding | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a write under on-write approval is held, then executes exactly once on resend | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a denied approval stays denied on resend | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a spent budget stops the session without a human | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | every decision is recorded in a chain that detects tampering | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | no audit record contains the secret in any form | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a locked vault refuses every proxied request | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | locking is recorded on disk, so a restart comes back locked | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | unlocking clears the recorded state | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a locked vault still answers questions that reveal nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a held write is resendable with a freshly minted placeholder | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/pipeline.test.js` | a resend cannot change what the human approved | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | elevationOf names auto with a write method, and nothing ordinary | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | elevationOf fails closed on anything it cannot read | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | elevationOf fails closed on an unreadable list whatever the approval mode | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | owner fields are read by one parser, and the CLI parse feeds it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | auto with writes is refused inside an open window without a fresh proof | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | auto with writes is created with the passphrase in the request, and audited as fresh | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | a wrong passphrase for an elevated session is refused, and counted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | read-only auto is not elevated: the window is enough, and nobody is asked again | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | a vault with no factor refuses auto with writes, and still makes ordinary sessions | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | an authenticator assertion over the exact body creates an elevated session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | an unknown approval mode is refused, never read as auto | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | malformed limits are refused before anything is created | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | a session request that names an owner field is refused, not trimmed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | the request store refuses an owner field from any caller | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | MCP cannot carry an owner field into a request | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | the gateway has no route that creates a session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | approving a request into auto with writes needs a fresh proof, not the window | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | a request approved without owner options stays ordinary, inside the window | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | a verdict that is not true or false is refused on the single decide route | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | an override with an unknown mode is refused when it is settled | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | a bulk decision with one elevated item needs a fresh proof for the whole list | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | the CLI refuses a mode it does not know before it calls anything | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | the CLI says what to do when auto with writes cannot be proved | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | the CLI exits with the refusal code’s own exit status | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | approvals offers the owner options, and approve validates them | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r1.test.js` | the help text documents how to start an auto-approving session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a new file is created 0600 even under umask 000, and an existing one is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a symlink is never followed, with or without force | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | force replaces a regular file atomically and leaves it 0600 | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a temporary file swapped for a symlink before the rename is refused, and no link is left | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a destination that becomes a symlink just before the rename is replaced, and the target is untouched | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | appending makes the file 0600 whatever the umask, and tightens one that was not | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | appending creates 0600, appends whole lines, and refuses a symlink | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | the final check passes placeholders for the session and loopback gateway URLs | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | the final check refuses everything else, and never says what it refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | one session holds several credentials, each with its own grant and placeholder | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | an ambiguous or mixed session body is refused, and leaves nothing behind | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | two credentials for one host stay apart: /p/ picks by name, /t/ refuses the other one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a batch is gated like a single placeholder | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a batch issues one placeholder per item, in order, and records the batch | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a batch is all or nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a batch with one quarantined credential issues nothing, not even the items before it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a batch of the wrong shape is refused before anything is resolved | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | the grant’s use ceiling beats what a batch asks for | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | env writes a 0600 file of placeholders and URLs, and never a secret or the token | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | env never replaces a file unless told to, and never follows a link | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | env refuses bad mappings before it calls anything, without echoing what was pasted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | env with a map file and no --out prints the lines | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | env without a session says how to make one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | env warns when the file would be committed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | a batch answer that is not a placeholder is never written | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | the same fake answering a real placeholder shape is written: the check is not a wall | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | exec --map puts a placeholder in the child under the name a tool reads | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | exec reports a missing command as 127 | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r2.test.js` | session create takes several credentials and prints a block for each | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | a session with no expiry needs a fresh proof, and gets one from the passphrase | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | a vault with no factor refuses a session with no expiry | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | a session with no expiry is never remote, and says so before asking for anything | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | a lifetime is a positive number, and infinite has none to set | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | ordinary finite sessions are unchanged | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | revoking a session with no expiry kills its placeholders | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | the owner can add no expiry when approving, but not on top of a lifetime the agent asked for | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | an authenticator assertion creates one from the UI, which marks it everywhere | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | the CLI refuses --ttl with --infinite, and lists an infinite session as never | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | the CLI on a vault with no factor says to set a passphrase first | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | a stored expiry that does not parse is never live | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-r3.test.js` | an infinite session is the default for an implicit placeholder when it is the only one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | the page reads owner options exactly as the CLI and the daemon do | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | a session with no expiry renders as never, and garbage as expired | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | the decisions that can be elevated are re-verified by the daemon | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | the page warns before it signs an elevated session | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | the hand-off card offers an env command with no session token in it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | approving a request with owner options from the page creates the session they chose | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | a signature for one owner option cannot be spent on another | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | an auto-approving multi-credential session made from the page needs only its own signature | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/requested-ui.test.js` | the docs say how to start an auto-approving session, and that read-only needs nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a gzipped response is decompressed before it reaches the agent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | deflate and brotli are handled too | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a secret hidden inside a compressed body is still scrubbed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | an encoding we cannot decode is refused rather than passed through unread | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a binary body survives byte for byte | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a gzipped binary body round-trips through decompression unchanged | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a COMPRESSED event stream is decompressed before it is scrubbed | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | an event stream in an encoding we cannot read is refused, not passed through | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a secret inside an event is scrubbed, and the rest survives | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | the stream hold-back is bounded, not the whole response | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a secret split across two stream chunks is still caught | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | end to end over real HTTP: a gzipping upstream and a streaming upstream both work | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a secret cannot escape through an internal error message | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a token stream that merely mentions a repository is not cut | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/response.test.js` | a secret split across two SSE events is caught | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-pins.test.js` | pins are stored under the canonical host, counted publicly, persisted, and logged as a count | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-pins.test.js` | a malformed pin list, or a host the credential cannot reach, is refused and changes nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-pins.test.js` | a host the profile reaches can be pinned on a profile credential | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-pins.test.js` | clearPins removes one pin or all of a host, records a count, and does nothing when nothing matches | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-pins.test.js` | a backup carries pins, and a restore puts them back under the same rules | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-pins.test.js` | a restore refuses pins it could not store, whole, and records only the refusal | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-pins.test.js` | a pinned, quarantined credential comes back both pinned and quarantined (C13) | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-templates.test.js` | a template is saved with a version and the hash of its canonical form, and audited | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-templates.test.js` | reads hand out copies, sorted, and know nothing of names that are not templates | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-templates.test.js` | deleting a template removes it once and records the version it had | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-templates.test.js` | a bad template name, shape or size is refused, and nothing is kept | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/store-templates.test.js` | session.created records the template and version a session came from, or null | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the fixture wrote the log it claims to | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the daemon: a bare limit is the tail it always was | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the daemon: kind filters before the limit | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the daemon: before and after walk the whole log, each row once | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the daemon: paging parameters are whole numbers in range or refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the daemon: a kind-filtered tail is bounded at 500 even with no before or after | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the daemon: the unfiltered tail keeps its old reading of limit | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the CLI: audit tail reads the same tail as before | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the page: a kind walks every row of that kind, newest first, across the whole log | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the page: with no kind the whole log is walkable | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the page: q searches visible fields across the whole log, a page at a time | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the page: q never matches token or placeholder text in a row | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the page: audit cursors and limits are checked like every other list | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-audit-paging.test.js` | the page: without paged=1 the audit route is unchanged | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | without paged=1 every list route answers exactly as it always has | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | each list pages through every item once, in its documented order, and back | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | pending pages newest first, with both kinds of decision | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | an object answer keeps its other fields beside the page | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | limit is a whole number from 1 to 200; anything else is AV_BAD_LIMIT | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | a cursor that was not made by this server for this list and filter is AV_BAD_CURSOR | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | q is a case-insensitive match over visible fields, and filters before paging | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | q never matches a token, a placeholder or a value, even one the daemon leaked | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui-paging.test.js` | the cursors in an answer survive the scrub that every answer passes | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | the relying party id is a domain, not an IP literal | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | arriving by IP is redirected to the domain the authenticator accepts | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | the launch link works exactly once | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | without the session cookie the API answers nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a cross-origin caller is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a request without the custom header is refused, which stops a form post | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | the credential list carries no value, in any field | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | there is no endpoint that returns a secret at all | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | the docs context describes this install and carries no secret | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | the docs page is reachable without changing anything | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | before enrollment, every mutating call is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a forged presence payload is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | enrollment registers the authenticator | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a second enrollment is refused, so an agent cannot add its own key | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | after enrollment, a mutating call still fails without a signature | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a signature for the wrong operation is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a valid signature for the right operation is accepted exactly once | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a session created here reaches the store every local client reads | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | the enrollment is recorded in the audit log | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | a batch with no signature is refused, like a single decision | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/ui.test.js` | the operation bound for a batch is the list exactly as it was sent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | denying a spent approval still needs the human, and changes nothing without one | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | a spent approval cannot be denied even with presence, and the refusal hands back nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | a spent approval cannot be granted again, so its write runs once | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | a bulk decision skips a spent approval, both ways, and reports no result | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | internally, deciding a spent approval throws and leaves it spent | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | a spent approval set aside for a new ask cannot be decided either | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | the control API strips a cached result even if the pipeline hands one back | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/wave1-compose.test.js` | a failing event stream neither crashes nor hangs the daemon, and the guard stays the backstop | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | a registration produces a credential the daemon can store | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | registration without user verification is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | a valid assertion for the issued challenge verifies | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | a different authenticator cannot sign for the enrolled credential | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | an attacker who copies the enrolled credential id still cannot sign | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | a signature for one operation does not authorise another | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | the operation challenge changes with every field of the operation | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | the same operation with a fresh nonce yields a fresh challenge | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | an assertion from another origin is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | a registration response replayed as an assertion is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | an assertion without user verification is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | a signature counter that goes backwards is treated as a cloned credential | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | only ES256 on P-256 is accepted | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | the CBOR reader rejects what it does not understand rather than guessing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/webauthn.test.js` | an assertion is bounded before anything parses it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | the passphrase gate is on, so an unsigned call is refused | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | creating a session from the UI works with one fingerprint | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | the credential list says where a placeholder may go | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | adding a credential from the UI works the same way | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | removing a credential from the UI works, signature and all | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a signature for one operation cannot authorise another | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a signature is good for exactly one call | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a challenge the daemon never minted proves nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a key the daemon never enrolled proves nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | an agent at the socket cannot enrol its own key and sign for itself | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | the passphrase window still works, for the CLI | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a wrong passphrase opens nothing | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a signature does not authorise fields it never covered | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | the value stored under a cred.add signature is bound to it | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a batch signature covers exactly the items it named | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | a batch signature is spent by the batch it named | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |
| `test/security/widening.test.js` | reordering a signed batch does not change what it authorises | covered by conformance (daemon/store/CLI/UI behavior outside av-core) |

Inventory: 850 named JS tests in 64 files. Multiple Rust names on a row jointly cover its pure-core assertions; a shared differential suite intentionally contains multiple JS cases.
