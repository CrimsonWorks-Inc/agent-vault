# PORTED.md: av-store

Every JavaScript test that covers the modules av-store ports (`src/store/*`, `src/pending.js`, `src/client-state.js`), by file and name, and where it lives in Rust: a test in this crate (`src/tests/<module>.rs` unless another path is given), "covered by conformance" / another crate, or "not applicable, because ...".

Run them with `cd rust && cargo test -p av-store`.

## The store's own test files

### `test/security/store-activity.test.js`

| JS test | Rust |
|---|---|
| a normal session reports complete activity with the right counts | `tests::activity::a_normal_session_reports_complete_activity_with_the_right_counts` |
| a log written before holds were marked reads the same: the hold is inferred, not counted as a use | `tests::activity::a_log_written_before_holds_were_marked_reads_the_same` |
| the activity carries no placeholder, no query, no secret and no detail text | `tests::activity::the_activity_carries_no_placeholder_no_query_no_secret_and_no_detail_text` |
| a log that starts after the session, or was cut back, is reported incomplete | `tests::activity::a_log_that_starts_after_the_session_or_was_cut_back_is_reported_incomplete` |
| another session's rows are not this session's activity | `tests::activity::another_sessions_rows_are_not_this_sessions_activity` |
| a tripwire that fired on the session is listed | `tests::activity::a_tripwire_that_fired_on_the_session_is_listed` |
| the access report counts use per credential and per session, and names granted methods never used | `tests::activity::the_access_report_counts_use_per_credential_and_per_session_and_names_granted_methods_never_used` |
| the report window, an expired session and a missing creation record are all honest | `tests::activity::the_report_window_an_expired_session_and_a_missing_creation_record_are_all_honest` |
| a row the gateway marks as held is a hold, whatever else it says | `tests::activity::a_row_the_gateway_marks_as_held_is_a_hold_whatever_else_it_says` |

### `test/security/store-audit-witness.test.js`

| JS test | Rust |
|---|---|
| export returns the records after since_seq exactly as they are on disk, and is recorded after reading | `tests::audit_witness::export_returns_the_records_after_since_seq_exactly_as_stored_and_is_recorded_after_reading` |
| the export limit is clamped to 1..5000 | `tests::audit_witness::the_export_limit_is_clamped_to_1_to_5000` |
| an export range that is not a whole number is refused, and nothing is recorded | `tests::audit_witness::an_export_range_that_is_not_a_whole_number_is_refused_and_nothing_is_recorded` |
| a checkpoint names a stable vault id, the head, and a MAC over both; it keeps the chain intact | `tests::audit_witness::a_checkpoint_names_a_stable_vault_id_the_head_and_a_mac_and_keeps_the_chain_intact` |
| an untouched log reports its witnesses ok, the genesis one included | `tests::audit_witness::an_untouched_log_reports_its_witnesses_ok_the_genesis_one_included` |
| a log cut back after a witness reports it ahead | `tests::audit_witness::a_log_cut_back_after_a_witness_reports_it_ahead` |
| a record whose hash was changed reports mismatched; a changed witness reports forged | `tests::audit_witness::a_record_whose_hash_was_changed_reports_mismatched_and_a_changed_witness_reports_forged` |
| a witness for another vault is reported, and does not by itself fail the check | `tests::audit_witness::a_witness_for_another_vault_is_reported_and_does_not_by_itself_fail_the_check` |
| a witness list that is not a list, or too long, is refused | `tests::audit_witness::a_witness_list_that_is_too_long_is_refused` |
| a caller cannot set a chain field: write refuses it, naming the field, and appends nothing | `tests::audit_witness::a_caller_cannot_set_a_chain_field_write_refuses_it_naming_the_field_and_appends_nothing` |
| no audit.write call in src passes a chain field | `tests::audit_witness::no_audit_write_in_the_store_passes_a_chain_field` |

### `test/security/store-backup.test.js`

| JS test | Rust |
|---|---|
| an export seals everything, holds no secret in the clear, and is logged by digest only | `tests::backup::an_export_seals_everything_holds_no_secret_in_the_clear_and_is_logged_by_digest_only` |
| the plaintext is credentials and templates only: no session, grant, placeholder, factor or retired value | `tests::backup::the_plaintext_is_credentials_and_templates_only` |
| inspect lists what a bundle holds without a single value | `tests::backup::inspect_lists_what_a_bundle_holds_without_a_single_value` |
| a restore brings back credentials, patterns, expiry and templates, and no session | `tests::backup::a_restore_brings_back_credentials_patterns_expiry_and_templates_and_no_session` |
| conflicts: skip by default, rename to -restored and -restored-2 within 24 characters, and fail writes nothing | `tests::backup::conflicts_skip_by_default_rename_within_24_characters_and_fail_writes_nothing` |
| a wrong passphrase or an altered bundle is one answer, and a restore writes nothing but the refusal | `tests::backup::a_wrong_passphrase_or_an_altered_bundle_is_one_answer_and_a_restore_writes_nothing_but_the_refusal` |
| an envelope that is not this format is refused before any key is derived | `tests::backup::an_envelope_that_is_not_this_format_is_refused_before_any_key_is_derived` |
| a correctly sealed bundle that carries anything outside the list is refused whole | `tests::backup::a_correctly_sealed_bundle_that_carries_anything_outside_the_list_is_refused_whole` |
| a scrub pattern in a bundle that would carry a secret into this vault is refused | `tests::backup::a_scrub_pattern_in_a_bundle_that_would_carry_a_secret_into_this_vault_is_refused` |
| a locked vault neither exports nor restores | `tests::backup::a_locked_vault_neither_exports_nor_restores` |
| a vault that locks while the key is derived hands nothing out | not applicable: the export holds `&mut Vault` for its whole run, so nothing can lock the vault while the key is derived; the locked case is `tests::backup::a_locked_vault_neither_exports_nor_restores` |
| the key derivation does not block the event loop | not applicable: the store has no event loop; its KDFs are blocking functions documented for `spawn_blocking`, which is the daemon's (av-daemon) |

### `test/security/store-notify.test.js`

| JS test | Rust |
|---|---|
| a webhook is sealed at rest, and only its host is shown or audited | `tests::notify::a_webhook_is_sealed_at_rest_and_only_its_host_is_shown_or_audited` |
| loopback http and the headline detail are accepted | `tests::notify::loopback_http_and_the_headline_detail_are_accepted` |
| a webhook that is not https, has userinfo or is not a URL is refused, and nothing is kept | `tests::notify::a_webhook_that_is_not_https_has_userinfo_or_is_not_a_url_is_refused_and_nothing_is_kept` |
| the sealed URL is bound to what it is: a credential\'s ciphertext does not open as one | `tests::notify::the_sealed_url_is_bound_to_what_it_is_a_credentials_ciphertext_does_not_open_as_one` |
| clearing the webhook removes it once, and a locked vault reveals nothing | `tests::notify::clearing_the_webhook_removes_it_once_and_a_locked_vault_reveals_nothing` |

### `test/security/store-pins.test.js`

| JS test | Rust |
|---|---|
| pins are stored under the canonical host, counted publicly, persisted, and logged as a count | `tests::pins::pins_are_stored_under_the_canonical_host_counted_publicly_persisted_and_logged_as_a_count` |
| a malformed pin list, or a host the credential cannot reach, is refused and changes nothing | `tests::pins::a_malformed_pin_list_or_a_host_the_credential_cannot_reach_is_refused_and_changes_nothing` |
| a host the profile reaches can be pinned on a profile credential | `tests::pins::a_host_the_profile_reaches_can_be_pinned_on_a_profile_credential` |
| clearPins removes one pin or all of a host, records a count, and does nothing when nothing matches | `tests::pins::clear_pins_removes_one_pin_or_all_of_a_host_records_a_count_and_does_nothing_when_nothing_matches` |
| a backup carries pins, and a restore puts them back under the same rules | `tests::pins::a_backup_carries_pins_and_a_restore_puts_them_back_under_the_same_rules` |
| a restore refuses pins it could not store, whole, and records only the refusal | `tests::pins::a_restore_refuses_pins_it_could_not_store_whole_and_records_only_the_refusal` |
| a pinned, quarantined credential comes back both pinned and quarantined (C13) | `tests::pins::a_pinned_quarantined_credential_comes_back_both_pinned_and_quarantined` |

### `test/security/store-review-r2.test.js`

| JS test | Rust |
|---|---|
| a restore that fails at the first, a middle or the last item leaves the vault exactly as it was | `tests::review_r2::a_restore_that_fails_at_the_first_a_middle_or_the_last_item_leaves_the_vault_exactly_as_it_was` |
| a restore whose last template does not fit writes none of the credentials before it | `tests::review_r2::a_restore_whose_last_template_does_not_fit_writes_none_of_the_credentials_before_it` |
| a restore whose one write fails is undone in memory and leaves the file as it was | `tests::review_r2::a_restore_whose_one_write_fails_is_undone_and_leaves_the_database_as_it_was` |
| an ordinary restore stores everything in one write and records each item | `tests::review_r2::an_ordinary_restore_stores_everything_in_one_write_and_records_each_item` |
| touching a session that has ended does not bring it back, in whatever order it is called | `tests::review_r2::touching_a_session_that_has_ended_does_not_bring_it_back_in_whatever_order` |
| a touch never moves an end earlier, nor past the ceiling, and does extend a live session | `tests::review_r2::a_touch_never_moves_an_end_earlier_nor_past_the_ceiling_and_does_extend_a_live_session` |
| a quarantine stops a placeholder issued before it, at consume and at reveal, until it is released | `tests::review_r2::a_quarantine_stops_a_placeholder_issued_before_it_at_consume_and_at_reveal_until_released` |
| a quarantined credential can still be rotated and backed up | `tests::review_r2::a_quarantined_credential_can_still_be_rotated_and_backed_up` |
| a budget of 0 issues nothing, and consume re-reads the budget and ceiling as they are now | `tests::review_r2::a_budget_of_0_issues_nothing_and_consume_rereads_the_budget_and_ceiling_as_they_are_now` |
| an ordinary budget spends to its limit, and a layer that names no limit is not refused | `tests::review_r2::an_ordinary_budget_spends_to_its_limit_and_a_layer_that_names_no_limit_is_not_refused` |
| a forked grant ends no later than the grant it copies, or its own session | `tests::review_r2::a_forked_grant_ends_no_later_than_the_grant_it_copies_or_its_own_session` |

### `test/security/store-review-r3.test.js`

| JS test | Rust |
|---|---|
| (a) a bundle carries each credential\'s quarantine record exactly as stored | `tests::review_r3::a_a_bundle_carries_each_credentials_quarantine_record_exactly_as_stored` |
| (b) a credential quarantined at backup time is quarantined after restore, until a human releases it | `tests::review_r3::b_a_credential_quarantined_at_backup_time_is_quarantined_after_restore_until_released` |
| (c) a credential quarantined in this vault keeps its restored copy quarantined, whatever the bundle says | `tests::review_r3::c_a_credential_quarantined_in_this_vault_keeps_its_restored_copy_quarantined` |
| (c) only the same credential holds a restore: an unrelated quarantine or a look-alike slug does not | `tests::review_r3::c_only_the_same_credential_holds_a_restore` |
| (d) a bundle with no quarantine field restores as not quarantined, and (c) still holds | `tests::review_r3::d_a_bundle_with_no_quarantine_field_restores_as_not_quarantined_and_c_still_holds` |
| an ordinary restore of credentials never quarantined stores no quarantine and records none | `tests::review_r3::an_ordinary_restore_of_credentials_never_quarantined_stores_no_quarantine_and_records_none` |
| a quarantine record that cannot be read refuses the whole restore rather than being dropped | `tests::review_r3::a_quarantine_record_that_cannot_be_read_refuses_the_whole_restore_rather_than_being_dropped` |

### `test/security/store-rotate.test.js`

| JS test | Rust |
|---|---|
| keep mode: the new value is substituted at once, and placeholders already handed out keep working | `tests::rotate::keep_mode_the_new_value_is_substituted_at_once_and_placeholders_already_handed_out_keep_working` |
| the rotation is audited with fingerprints and counts, never a value | `tests::rotate::the_rotation_is_audited_with_fingerprints_and_counts_never_a_value` |
| the old value is still scrubbed within the retire window, and not after it | `tests::rotate::the_old_value_is_still_scrubbed_within_the_retire_window_and_not_after_it` |
| a zero retire window keeps nothing of the old value | `tests::rotate::a_zero_retire_window_keeps_nothing_of_the_old_value` |
| a retired value still counts as a stored value for scrub patterns | `tests::rotate::a_retired_value_still_counts_as_a_stored_value_for_scrub_patterns` |
| revoke mode revokes the credential\'s grants and kills their placeholders, and nobody else\'s | `tests::rotate::revoke_mode_revokes_the_credentials_grants_and_kills_their_placeholders_and_nobody_elses` |
| the expiry is cleared by default and set when given | `tests::rotate::the_expiry_is_cleared_by_default_and_set_when_given` |
| a bad rotation is refused before anything changes, revoke mode included | `tests::rotate::a_bad_rotation_is_refused_before_anything_changes_revoke_mode_included` |

### `test/security/store-scrub.test.js`

| JS test | Rust |
|---|---|
| a scrub pattern is added, listed, persisted and audited by digest only | `tests::scrub::a_scrub_pattern_is_added_listed_persisted_and_audited_by_digest_only` |
| removing a pattern removes that one, once | `tests::scrub::removing_a_pattern_removes_that_one_once` |
| a pattern that is too short, too long or not text is refused | `tests::scrub::a_pattern_that_is_too_short_or_too_long_is_refused` |
| a pattern that contains a stored credential value or a placeholder is refused | `tests::scrub::a_pattern_that_contains_a_stored_credential_value_or_a_placeholder_is_refused` |
| at most 16 patterns per credential and 64 in the vault | `tests::scrub::at_most_16_patterns_per_credential_and_64_in_the_vault` |
| scrub-pattern writes need the credential to exist and the vault to be unlocked | `tests::scrub::scrub_pattern_writes_need_the_credential_to_exist_and_the_vault_to_be_unlocked` |

### `test/security/store-slice-a.test.js`

| JS test | Rust |
|---|---|
| an infinite session never expires, and says so in its record and its audit | `tests::slice_a::an_infinite_session_never_expires_and_says_so_in_its_record_and_its_audit` |
| an infinite session is revocable, and its placeholders die with it | `tests::slice_a::an_infinite_session_is_revocable_and_its_placeholders_die_with_it` |
| a finite session is unchanged: it expires, and idle activity extends it only up to its ceiling | `tests::slice_a::a_finite_session_expires_and_idle_activity_extends_it_only_up_to_its_ceiling` |
| a lifetime that is not a positive number, or infinite combined with one, is refused and writes nothing | `tests::slice_a::a_lifetime_that_is_not_a_positive_number_or_infinite_with_one_is_refused_and_writes_nothing` |
| a fork of an infinite session is finite | `tests::slice_a::a_fork_of_an_infinite_session_is_finite` |
| expiryMs: absent is no limit, a date is that date, and anything else has already passed | `tests::slice_a::expiry_ms_absent_is_no_limit_a_date_is_that_date_and_anything_else_has_passed` |
| sessionExpiryMs: only exactly infinite with exactly null lives forever | `tests::slice_a::session_expiry_ms_only_exactly_infinite_with_exactly_null_lives_forever` |
| a session record with an unreadable or missing expiry is expired, not live forever | `tests::slice_a::a_session_record_with_an_unreadable_or_missing_expiry_is_expired_not_live_forever` |
| a placeholder row: exactly null never expires, an unreadable date always has | `tests::slice_a::a_placeholder_row_exactly_null_never_expires_an_unreadable_date_always_has` |
| a grant with a lifetime ends on its own, kills its placeholders, and leaves the session\'s other grant working | `tests::slice_a::a_grant_with_a_lifetime_ends_on_its_own_kills_its_placeholders_and_leaves_the_other_grant_working` |
| an expired grant refuses issuance with its own code | `tests::slice_a::an_expired_grant_refuses_issuance_with_its_own_code` |
| idle activity on the session does not revive a grant | `tests::slice_a::idle_activity_on_the_session_does_not_revive_a_grant` |
| a grant lifetime longer than the session is clamped to it; a grant of an infinite session still ends | `tests::slice_a::a_grant_lifetime_longer_than_the_session_is_clamped_and_a_grant_of_an_infinite_session_still_ends` |
| a grant lifetime that is not a positive number is refused and writes nothing | `tests::slice_a::a_grant_lifetime_that_is_not_a_positive_number_is_refused_and_writes_nothing` |
| no grant is added to a session that has ended | `tests::slice_a::no_grant_is_added_to_a_session_that_has_ended` |
| a locked vault refuses an expired grant without recording what it cannot audit | `tests::slice_a::a_locked_vault_refuses_an_expired_grant_without_recording_what_it_cannot_audit` |
| findGrant returns the newest grant for the pair in any state, and null for none | `tests::slice_a::find_grant_returns_the_newest_grant_for_the_pair_in_any_state_and_none_for_none` |
| chargeGrant charges up to the budget and refuses past it | `tests::slice_a::charge_grant_charges_up_to_the_budget_and_refuses_past_it` |
| chargeGrant reads a decimal-string budget as its integer (C4) | `tests::slice_a::charge_grant_reads_a_decimal_string_budget_as_its_integer` |
| chargeGrant charges nothing when the budget, the count or the grant cannot be read | `tests::slice_a::charge_grant_charges_nothing_when_the_budget_the_count_or_the_grant_cannot_be_read` |
| credential expiry is stored as one ISO date, audited, and flagged when near | `tests::slice_a::credential_expiry_is_stored_as_one_iso_date_audited_and_flagged_when_near` |
| a credential expiry that is not a date is refused and writes nothing | `tests::slice_a::a_credential_expiry_that_is_not_a_date_is_refused_and_writes_nothing` |
| a thousand identical health observations write one audit record | `tests::slice_a::a_thousand_identical_health_observations_write_one_audit_record` |
| the sooner of the human\'s expiry and the observed one wins | `tests::slice_a::the_sooner_of_the_humans_expiry_and_the_observed_one_wins` |
| a health patch keeps only well-formed fields, and a locked vault records nothing | `tests::slice_a::a_health_patch_keeps_only_well_formed_fields_and_a_locked_vault_records_nothing` |
| settings: the default tripwire rules are stored, merged per key, audited and handed out as a copy | `tests::slice_a::settings_the_default_tripwire_rules_are_stored_merged_per_key_audited_and_handed_out_as_a_copy` |
| a tripwire rule that is not the Rule shape is refused, and nothing is kept | `tests::slice_a::a_tripwire_rule_that_is_not_the_rule_shape_is_refused_and_nothing_is_kept` |
| a quarantined credential issues nothing and gets no new grant, and release restores a live session | `tests::slice_a::a_quarantined_credential_issues_nothing_gets_no_new_grant_and_release_restores_a_live_session` |
| quarantining twice keeps who did it first; a bad quarantine is refused | `tests::slice_a::quarantining_twice_keeps_who_did_it_first_and_a_bad_quarantine_is_refused` |
| shortening an infinite session makes it finite, and brings its placeholders down with it | `tests::slice_a::shortening_an_infinite_session_makes_it_finite_and_brings_its_placeholders_down` |
| shortening never lengthens | `tests::slice_a::shortening_never_lengthens` |
| shortening a session whose expiry cannot be read ends it now instead of throwing | `tests::slice_a::shortening_a_session_whose_expiry_cannot_be_read_ends_it_now_instead_of_throwing` |
| shortening with a lifetime that is not a positive number, or a session that is gone, is refused | `tests::slice_a::shortening_with_a_lifetime_that_is_not_positive_or_a_session_that_is_gone_is_refused` |
| shortening a grant bounds it and its live placeholders, and is audited | `tests::slice_a::shortening_a_grant_bounds_it_and_its_live_placeholders_and_is_audited` |
| a narrow is audited by field name, and may only turn redirects off | `tests::slice_a::a_narrow_is_audited_by_field_name_and_may_only_turn_redirects_off` |
| the elevation a session was created with is recorded, [] by default | `tests::slice_a::the_elevation_a_session_was_created_with_is_recorded_and_empty_by_default` |
| an elevation the store does not recognise is refused, and nothing is written | `tests::slice_a::an_elevation_the_store_does_not_recognise_is_refused_and_nothing_is_written` |
| a placeholder of a session that expired idle is refused at use, though its own date has not passed | `tests::slice_a::a_placeholder_of_a_session_that_expired_idle_is_refused_at_use_though_its_own_date_has_not_passed` |
| settings never carry the webhook URL, locked or unlocked | `tests::slice_a::settings_never_carry_the_webhook_url_locked_or_unlocked` |

### `test/security/store-templates.test.js`

| JS test | Rust |
|---|---|
| a template is saved with a version and the hash of its canonical form, and audited | `tests::templates::a_template_is_saved_with_a_version_and_the_hash_of_its_canonical_form_and_audited` |
| reads hand out copies, sorted, and know nothing of names that are not templates | `tests::templates::reads_hand_out_copies_sorted_and_know_nothing_of_names_that_are_not_templates` |
| deleting a template removes it once and records the version it had | `tests::templates::deleting_a_template_removes_it_once_and_records_the_version_it_had` |
| a bad template name, shape or size is refused, and nothing is kept | `tests::templates::a_bad_template_name_shape_or_size_is_refused_and_nothing_is_kept` |
| session.created records the template and version a session came from, or null | `tests::templates::session_created_records_the_template_and_version_a_session_came_from_or_null` |

### `test/security/fix-control-store.test.js`

| JS test | Rust |
|---|---|
| the no-wider check itself refuses a result that dropped a constraint | `tests::store_fixes::the_no_wider_check_itself_refuses_a_result_that_dropped_a_constraint` |
| narrowGrant can only intersect, never widen | `tests::store_fixes::narrow_grant_can_only_intersect_never_widen` |
| narrowGrant still narrows | `tests::store_fixes::narrow_grant_still_narrows` |
| a forked session can only narrow its parent\'s grants | `tests::store_fixes::a_forked_session_can_only_narrow_its_parents_grants` |
| an expired session takes its placeholders with it | `tests::store_fixes::an_expired_session_takes_its_placeholders_with_it` |
| the ledger bound collects active rows whose time has passed | `tests::store_fixes::the_ledger_bound_collects_active_rows_whose_time_has_passed` |
| a placeholder lives as long as its session, idle extension included | `tests::store_fixes::a_placeholder_lives_as_long_as_its_session_idle_extension_included` |
| a placeholder with its own ttl still expires on time | `tests::store_fixes::a_placeholder_with_its_own_ttl_still_expires_on_time` |
| booting a locked vault does not record an unlock nobody performed | `tests::store_fixes::booting_a_locked_vault_does_not_record_an_unlock_nobody_performed` |
| booting an unlocked vault still unlocks it | `tests::store_fixes::booting_an_unlocked_vault_still_unlocks_it` |

### `test/security/fix-control-factors.test.js`

| JS test | Rust |
|---|---|
| F1: the only passphrase cannot be removed, and the socket stays gated | `tests::factors::f1_the_only_passphrase_cannot_be_removed` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| F1: removing Touch ID unlock first does not make the passphrase removable | `tests::factors::f1_removing_touch_id_unlock_first_does_not_make_the_passphrase_removable` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| a wrong passphrase is still a failed proof, not a factor refusal | `tests::factors::a_wrong_passphrase_is_still_a_failed_proof_not_a_factor_refusal` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| control: with a presence authenticator left, the passphrase can be removed | `tests::factors::control_with_a_presence_authenticator_left_the_passphrase_can_be_removed` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| an authenticator-only vault says widening is still gated when no window can open | `tests::factors::an_authenticator_only_vault_keeps_an_authenticator_as_its_human_factor` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| control: a vault with no factor at all still says it is ungated | `tests::factors::control_a_vault_with_no_factor_at_all_has_no_human_factor` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| control: a passphrase changes with the current one | `tests::factors::control_a_passphrase_changes_with_the_current_one` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| F2: a rotation to an unusable key is refused, and the sole key keeps working | `tests::factors::f2_a_rotation_to_an_unusable_key_is_refused_and_the_sole_key_keeps_working` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| F2: a rotation stores the credential and nothing else the caller sent | `tests::factors::f2_a_rotation_stores_the_credential_and_nothing_else_the_caller_sent` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| F2: a first enrolment is held to the same shape | `tests::factors::f2_a_first_enrolment_is_held_to_the_same_shape` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| a presence key that fails to save leaves the old one in place | `tests::factors::a_presence_key_that_fails_to_save_leaves_the_old_one_in_place` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| F3: the store factory refuses a Touch ID unlock wrap with no passphrase | `tests::factors::f3_the_store_factory_refuses_a_touch_id_unlock_wrap_with_no_passphrase` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| control: a vault created with a passphrase opens with it and nothing else | `tests::factors::control_a_vault_created_with_a_passphrase_opens_with_it_and_nothing_else` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |
| control: a vault with no passphrase keeps its none wrap | `tests::factors::control_a_vault_with_no_passphrase_keeps_its_none_wrap` (store level; the HTTP status and the presence gate are the daemon's and conformance's) |

### `test/security/fix-control-ledger.test.js`

| JS test | Rust |
|---|---|
| asking for a placeholder and using it, over and over, stays within max_active | `tests::ledger::asking_for_a_placeholder_and_using_it_over_and_over_stays_within_max_active` (store level; the MCP and gateway round trip is the daemon's and conformance's) |
| a max_active that is not a number is not an unbounded ledger | `tests::ledger::a_max_active_that_is_not_a_number_is_not_an_unbounded_ledger` (store level; the MCP and gateway round trip is the daemon's and conformance's) |
| a placeholder in use keeps working while fewer than max_active are live | `tests::ledger::a_placeholder_in_use_keeps_working_while_fewer_than_max_active_are_live` (store level; the MCP and gateway round trip is the daemon's and conformance's) |
| a rotated placeholder says to ask again, and the newest still works | `tests::ledger::a_rotated_placeholder_says_to_ask_again_and_the_newest_still_works` (store level; the MCP and gateway round trip is the daemon's and conformance's) |
| an explicit placeholder ttl cannot outlast the grant\'s | `tests::ledger::an_explicit_placeholder_ttl_cannot_outlast_the_grants` (store level; the MCP and gateway round trip is the daemon's and conformance's) |
| an explicit placeholder ttl shorter than the grant\'s is kept | `tests::ledger::an_explicit_placeholder_ttl_shorter_than_the_grants_is_kept` (store level; the MCP and gateway round trip is the daemon's and conformance's) |

### `test/core/passphrase.test.js`

| JS test | Rust |
|---|---|
| a none-vault unlocks with no secret; a passphrase vault does not | `tests::passphrase::a_none_vault_unlocks_with_no_secret_and_a_passphrase_vault_does_not` |
| locking a passphrase vault zeroizes a key that disk alone cannot recover | `tests::passphrase::locking_a_passphrase_vault_zeroizes_a_key_that_disk_alone_cannot_recover` |
| changing a passphrase requires the current one | `tests::passphrase::changing_a_passphrase_requires_the_current_one` |
| removing a passphrase requires the current one, then unlock needs no secret | `tests::passphrase::removing_a_passphrase_requires_the_current_one_then_unlock_needs_no_secret` |
| the passphrase cannot be removed while it is the last human factor | `tests::passphrase::the_passphrase_cannot_be_removed_while_it_is_the_last_human_factor` |
| a passphrase under 8 characters is refused | `tests::passphrase::a_passphrase_under_8_characters_is_refused` |
| Touch ID (a PRF secret) unlocks the vault, alongside the passphrase | `tests::passphrase::touch_id_a_prf_secret_unlocks_the_vault_alongside_the_passphrase` |
| the passphrase cannot be removed while Touch ID is the other factor | `tests::passphrase::the_passphrase_cannot_be_removed_while_touch_id_is_the_other_factor` |
| removing the last unlock factor leaves the vault openable, not destroyed | `tests::passphrase::removing_the_last_unlock_factor_leaves_the_vault_openable_not_destroyed` |
| setting a passphrase keeps an existing Touch ID factor | `tests::passphrase::setting_a_passphrase_keeps_an_existing_touch_id_factor` |
| a passphrase vault comes up locked after a restart, not crashed | `tests::passphrase::a_passphrase_vault_comes_up_locked_after_a_restart_not_crashed` |
| a crash mid-append does not lock the owner out of their own vault | not applicable: a SQLite write is a transaction, so there is no torn last line; the same protection for a damaged row is `tests::audit_witness::an_unreadable_row_is_reported_as_corruption_and_does_not_lock_the_owner_out` |
| a failed unlock leaves nothing half-open | `tests::passphrase::a_failed_unlock_leaves_nothing_half_open` |
| a leftover temp file cannot hand the vault a permissive mode | `tests::passphrase::a_permissive_vault_file_is_reset_to_0600_on_open` (SQLite has no temp file; the database itself is held to 0600) |
| the placeholder ledger does not grow without bound | `tests::passphrase::the_placeholder_ledger_does_not_grow_without_bound` |
| key material and security decisions are written durably, whatever the ledger does | not applicable as a source scan: every operation is one transaction under `synchronous=FULL` (`db::tests::pragmas_are_set_after_open`, mutation "a commit is not durable"), so no writer can skip the fsync |
| every method that writes the vault is classified as durable or as allowed to skip the fsync | not applicable: as above, there is one durability for every write |

### `test/core/integrity-fuzz.test.js`

| JS test | Rust |
|---|---|
| a minted placeholder always verifies under its own key | `tests::integrity::a_minted_placeholder_always_verifies_under_its_own_key` |
| changing any single character makes a placeholder unusable | `tests::integrity::changing_any_single_character_makes_a_placeholder_unusable` |
| a placeholder never verifies under a different key | `tests::integrity::a_placeholder_never_verifies_under_a_different_key` |
| random text is never mistaken for a placeholder | `tests::integrity::random_text_is_never_mistaken_for_a_placeholder` |
| operations that differ in any way canonicalise differently | `tests::integrity::operations_that_differ_in_any_way_canonicalise_differently` |
| key order and absent fields do not change the canonical form | `tests::integrity::key_order_and_absent_fields_do_not_change_the_canonical_form` |
| an encoded occurrence is never treated as an injection site | av-core (`substitute::matches_site`); not a store function |

### `test/security/invariants.test.js`

| JS test | Rust |
|---|---|
| across thousands of random requests, no credential ever reaches the agent | av-daemon: a gateway fuzz, which the store cannot run (it forwards nothing); not in `conformance/`. The store-level half is `tests::invariants::*` |
| the granted credential reached only the host its grant allows, and nothing else did | av-daemon: a gateway fuzz over upstream traffic; not in `conformance/` |
| no placeholder and no session token was ever forwarded upstream | av-daemon: a gateway fuzz over upstream traffic; not in `conformance/` |
| a placeholder was never spent more times than it had uses | `tests::invariants::a_placeholder_was_never_spent_more_times_than_it_had_uses` |
| nothing sensitive reached the audit log, and its chain still verifies | `tests::invariants::nothing_sensitive_reached_the_audit_log_and_its_chain_still_verifies` |

## Other JS tests that use the store

These files import a store module (directly or through a test helper that builds a vault) but test the daemon, the gateway, the CLI or the web UI. Their store-level assertions are ported where named; the rest belong to av-daemon, av-cli and the conformance suite.

### `test/core/package.test.js`

| JS test | Rust |
|---|---|
| the published package contains everything it needs and nothing it should not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the published package runs, imports and creates a vault on its own | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon reports the version the package actually is | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| no test can write state into the real vault directory | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/approval-verdict.test.js`

| JS test | Rust |
|---|---|
| only true or false decides on the approvals route, and anything else decides nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature cannot carry a verdict that is not a boolean either | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the web UI refuses a verdict that is not a boolean, before it spends a signature | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the web UI no longer turns a string "false" into an approved session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the shared decision builder will not coerce a verdict | `tests::pending::the_shared_decision_builder_includes_overrides_only_when_there_are_some` (the verdict is a `bool` by type, so a string cannot be passed) |

### `test/security/audit-content.test.js`

| JS test | Rust |
|---|---|
| no credential value reaches the audit log, in any field | `tests::invariants::nothing_sensitive_reached_the_audit_log_and_its_chain_still_verifies` for what the store writes; the gateway's records are av-daemon's and conformance's |
| no full placeholder and no session token reaches it either | `tests::invariants::nothing_sensitive_reached_the_audit_log_and_its_chain_still_verifies` for what the store writes; the gateway's records are av-daemon's and conformance's |
| the log says which resource was reached, not just which rule matched | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| request bodies never reach it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent-supplied reason is recorded as a claim, never as fact | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the chain verifies, and editing a record breaks it | `tests::audit_witness::the_chain_verifies_and_editing_a_record_breaks_it` |
| cutting the end off the log is detected, and cannot be quietly continued | `tests::audit_witness::a_log_cut_back_while_stopped_is_reported_and_the_report_survives_new_writes` |
| emptying the log entirely is detected too | `tests::audit_witness::emptying_the_log_is_not_a_fresh_start` |
| truncating and then deleting the anchor does not launder the truncation | `tests::audit_witness::truncating_and_then_deleting_the_anchor_does_not_launder_the_truncation` |
| a vault upgraded from a build without anchors is not accused of tampering | `tests::audit_witness::a_vault_upgraded_from_a_build_without_anchors_is_not_accused_of_tampering` |
| a normal restart is not mistaken for tampering | `tests::audit_witness::an_ordinary_restart_reports_nothing_and_verifies` |
| a policy denial names the session, credential and grant that were refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a denial before authentication names no session, which is the answer | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/bridge.test.js`

| JS test | Rust |
|---|---|
| the bridge answers over stdio with the session on disk | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session that ends mid-flight is replaced without restarting the client | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with no replacement to find, the failure is still reported | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the bridge refuses to start with no session at all | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| every line the bridge writes to stdout is a JSON-RPC message | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a successful call is still forwarded byte for byte | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a daemon restart does not leave the bridge permanently broken | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a non-protocol answer from the daemon still reaches the client as JSON-RPC | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/budget-reader.test.js`

| JS test | Rust |
|---|---|
| the shared reader gives each listed budget its C4 meaning | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the gateway and chargeGrant agree on every listed budget, at the limit and under it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/carrier.test.js`

| JS test | Rust |
|---|---|
| the session token in Authorization never reaches the upstream | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the credential still arrives, at its own declared site | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the AV-Session carrier behaves the same way | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session token smuggled into an unrelated header is dropped too | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| headers that carry no token are forwarded untouched | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-backup-audit.test.js`

| JS test | Rust |
|---|---|
| export needs a fresh proof: the window is refused, the passphrase works, and the bundle holds no secret | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| export is refused on a vault with no human factor, and while locked | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| inspect is open, but a wrong recovery passphrase is counted, and a right one does not clear the count | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| restore needs a human, and gives back credentials but never a session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| audit export, checkpoint and witness check are open reads, refused while locked (F9) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-c18.test.js`

| JS test | Rust |
|---|---|
| gateway POST /v1/preflight: an infinite token on a network listener is refused, a finite one works (C18) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| MCP vault_describe_access: refused for an infinite session on a network listener, over HTTP and in the tool itself (C18) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| MCP vault_preflight: refused for an infinite session on a network listener, over HTTP and in the tool itself (C18) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a refused peek records nothing and changes nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-containment.test.js`

| JS test | Rust |
|---|---|
| panic is open, revokes every session including infinite ones, and denies everything waiting (C1) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| panic with lock locks the vault and closes the passphrase window; panicking a locked vault revokes nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| panic reads its inputs strictly | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| tripwires: on is open, everything else needs a human (C20) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a tripwire turned on through the route revokes a replaying session before its answer returns | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with tripwires off, the same replay revokes nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-credentials.test.js`

| JS test | Rust |
|---|---|
| rotating needs a human; once rotated, the next request carries the new value | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| rotating denies the held requests a human approved against the old key | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a rotation it cannot read is refused, and changes nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| adding and removing a scrub pattern need a human; the sample is the human\'s own text | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a pattern that could backtrack, match everything, or carry a secret is refused, before the gate | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| setting an expiry needs a human, and is metadata the gateway does not enforce | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a credential can be added with its expiry; a bad one leaves nothing stored | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| setting and removing pins need a human, and only for a host the credential reaches | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| cred test is open, hits only the profile\'s probe, and never returns the body | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a second test within a minute is throttled through the route; another credential is not (C20) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| quarantine is open, stops every use at once, and denies held requests | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot ask for a session on a quarantined credential, over either door (C12 note) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| releasing a quarantine needs a human, and a still-live session works again | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret across the 200-character cut of a quarantine reason leaves none of itself behind | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-mcp.test.js`

| JS test | Rust |
|---|---|
| vault_describe_access says what the session may do, with no token, placeholder, fingerprint or size, and records nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_preflight changes nothing: no approval, no use, no budget, no touch, and no upstream connection | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_preflight refuses what it cannot read, an unknown credential, and an eleventh call in a second | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a preflight with a placeholder in the wrong place says deny, and never trips a tripwire | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the gateway preflight route authenticates like a real request, reads its body strictly, and touches nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_request_session forwards routes, uses and a grant lifetime, and nothing it does not offer | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the existing tools show lifetimes; the preview stays with the human (F13) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the server instructions point at the two new tools | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-notify.test.js`

| JS test | Rust |
|---|---|
| the stream sends a snapshot, then each new item, without the agent\'s words | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a ninth watcher is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the stream resolves no session: a token sent to it is ignored and touches nothing (C20) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| setting a webhook needs the owner; only its host is ever shown or recorded | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the minimal webhook is counts and ids only; one POST per interval | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the headline webhook adds the gateway\'s summary, never the agent\'s words | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a test notification is throttled, a failure is recorded once, and no webhook is not found | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a stored secret an agent puts in a proposal path does not reach the stream or the webhook (F14) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a headline with no secret in it is sent as the summary, unchanged (F14) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-overrides.test.js`

| JS test | Rust |
|---|---|
| parseOverrides is self-contained: built from its source in a fresh scope, it agrees on every field (C21, C23) | not applicable: the Rust function is not injected into a page; its behaviour on every field is `tests::pending::*` |
| routes and payload as JSON strings are parsed; a value passes through; bad JSON throws (C23) | `tests::pending::routes_and_payload_as_json_strings_are_parsed_a_value_passes_through_bad_json_throws` |
| a numeric narrowing is Number(v), and anything not finite throws, naming the field (C23) | `tests::pending::a_numeric_narrowing_is_number_v_and_anything_not_finite_throws_naming_the_field` |
| rate and quota: a string is trimmed, anything else passes through for the daemon (C23) | `tests::pending::rate_and_quota_a_string_is_trimmed_anything_else_passes_through` |
| an approval narrowed with --routes or --payload as JSON creates a grant with the parsed value, not the proposal | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-sessions.test.js`

| JS test | Rust |
|---|---|
| a budget of 0 is refused before the presence gate, and nothing is made (C17) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a create body carries every grant limit, converted by the one converter | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a grant limit that cannot be read is refused and leaves nothing behind | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a grant lifetime is set, clamped to the session, and refused when it is not a whole number (F18) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an expired grant is refused with its own code while the session\'s other grant works (F18) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| narrowing intersects: auto plus DELETE on an on-write GET grant leaves on-write and no methods (F15) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| narrowing never widens, over random narrows (F15) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a narrowing that turns redirects on is refused; turning them off is not (F15) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent can narrow its own session with no presence, and only ever loses capability (F15) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session lifetime in a narrowing makes an infinite session finite, and a grant lifetime shortens the grant (F15) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a narrowing that does nothing, or names what cannot be narrowed, is refused (F15) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| narrowing one credential leaves the session\'s other grant alone (F15) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the session detail holds metadata only: no placeholder text, query or secret (F19) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the detail says when history is incomplete, and is refused while locked (F19) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the access report covers every session and credential, and refuses a since it cannot read (F19) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a typo in a narrowing is refused, by the parser and by the daemon, never dropped as null | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-api-templates.test.js`

| JS test | Rust |
|---|---|
| saving a template needs a human, and is checked like a create first | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| templates are listed with summaries, read in full by name, and deleted without presence | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| creating from a template binds its hash: an edit after looking is refused, the current hash works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature over one template hash cannot be spent on another | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| overrides only narrow: DELETE on a GET template still makes a GET-only session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an infinite template can only be made finite, never the other way round | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an elevated template needs a fresh proof to create, and the window is not one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session request from a template is a snapshot: an edit afterwards does not reach the session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a template request names one credential, and a template\'s owner fields come only from the template | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| MCP asks by template name, with no credential named, and lists single-credential templates | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-cli-files.test.js`

| JS test | Rust |
|---|---|
| backup export writes exclusive 0600 JSON, refuses collisions and links, and needs matching stdin recovery proof | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| backup inspect and restore read the bundle, inspect before restoring, and preserve conflict mode | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| audit export preserves JSONL chain rows, follows exclusive writer rules, and witness appends | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| audit follow appends later pages, never truncates earlier evidence, and stops cleanly on SIGINT | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| audit verify combines chain and witness decisions with strict booleans | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| audit verify on a broken chain is a failure envelope with exit 1, and an intact one is not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| audit witness refuses a planted fifo at once and writes nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| --markdown takes no value on session show and report | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| state writes cannot follow a symlink and ordinary updates remain private | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| policy flags share one typed parser and reject malformed ordinary numeric spellings | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| preflight calls only loopback gateway with session authentication, preserves repeated headers and returns verdict exit codes | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| new secret-bearing commands refuse argv values without echoing them or contacting daemon | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| session detail reports policy, spend estimates, grant lifetime and incomplete history in text and Markdown | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approval previews strip terminal control bytes, bound body display and label agent text | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| probe results use strict decisions and registered exit codes; containment sends strict booleans | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| reports preserve response data and label incomplete history in human and Markdown tables | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| root help matches A.5 exactly and scrub help documents the bounded grammar | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-cli-overrides.test.js`

| JS test | Rust |
|---|---|
| C23: a field error from parseOverrides becomes a usage error naming the flag | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C23: an error without a field is not dressed up as a usage error | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approve overrides: ordinary narrowing passes through unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approve overrides: a flag that was typed is never treated as nothing sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| session create and template flags: an unknown limit is refused, the known ones are not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approve with an unreadable narrowing exits 2 before contacting the daemon | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-gate.test.js`

| JS test | Rust |
|---|---|
| an agent cannot approve its own held request | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| denying needs a human too, because it did not only narrow | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a human with a window can approve, so the gate is not a wall | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot bind a new listener | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the signature counter cannot be moved by anyone who asks | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot force a new certificate and break existing trust | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| no mutating control route widens capability without a human | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the wave-3 routes that only narrow or read stay open, even with the gate on (A.2) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an elevated session is refused inside an open window without a fresh proof | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an elevated session is refused on a vault with no factor, where ordinary ones are open | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an enrolled authenticator counts as a human factor on its own | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot enrol its own key on a fresh vault and take it over | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot set the first passphrase and lock the owner out | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| passphrase attempts are charged for, in time and in the log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| every route that spends scrypt is throttled, not just the ones I remembered | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the control socket is never world-connectable, not even for an instant | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI names the factor that exists, not the one it expects | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| one malformed byte on the control socket does not kill the daemon | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the grant’s placeholder ceiling beats what the agent asks for | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-ui-guard.test.js`

| JS test | Rust |
|---|---|
| a token or placeholder a daemon route returns never reaches the page | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary text is untouched | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the approvals list, a webhook URL and an error message are held to the same line | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the hand-off for a session made here still carries what the agent needs | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page runs the very parser the server rebinds a narrowing with (C21) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-ui-handoff.test.js`

| JS test | Rust |
|---|---|
| an error from POST sessions reaches the page with none of the withheld fields (F1) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a successful hand-off carries the token and placeholders, and nothing else withheld (F1) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a card field is copied back only as a scalar or a list of scalars (F1) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a withheld key is withheld in any case, hyphenated, nested, and inside arrays (F2) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| towardPage folds case and hyphens and leaves other keys alone (F2) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a reserved operation field is a 403 refusal, not a 500, and is not forwarded | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-ui-narrowing.test.js`

| JS test | Rust |
|---|---|
| a narrowing the parser refuses is said, and nothing is signed or sent (C23) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a narrowing that parses is signed and sent as parsed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a denial reads no narrowing, so text the parser refuses cannot block it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the narrowing is read by the shared parser, and a refusal is never read as no narrowing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/control-ui-rotate.test.js`

| JS test | Rust |
|---|---|
| the current key can enrol its replacement, and only the replacement works afterwards | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a replacement with no signature, or signed by the new key itself, is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the record enrolled is the one registered here, not one the request names | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with nothing registered there is nothing to enrol | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature for the replacement is refused when it covers a different record | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a first enrolment still cannot be made this way | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/exfil.test.js`

| JS test | Rust |
|---|---|
| the control socket refuses a session aimed at a host the credential does not permit | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session confined to the credential host cannot then be pointed elsewhere | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the real credential value never reaches a caller-controlled destination | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| without a passphrase, widening is open but audited, not silently trusted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with a passphrase set, the socket cannot unlock without it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with a passphrase set, an agent cannot mint capability without it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot mint a placeholder against a grant it does not own | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a human with a presence window can still issue placeholders | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-approvals.test.js`

| JS test | Rust |
|---|---|
| denying with no human present is refused, and the request stays pending | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature for approving cannot be spent on denying | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a deny signed for exactly that deny goes through, as the UI sends it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a deny inside a passphrase window goes through, as the CLI sends it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an approval that already ran never hands its cached response back | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-audit.test.js`

| JS test | Rust |
|---|---|
| an untouched log reopens and verifies clean | `tests::audit_witness::an_untouched_log_reopens_and_verifies_clean` |
| a brand-new vault verifies clean | `tests::audit_witness::a_brand_new_vault_verifies_clean` |
| deleting the log is not a fresh start | `tests::audit_witness::emptying_the_log_is_not_a_fresh_start` (the log is a table: deleting it is emptying it) |
| deleting the log and its anchor together is not a fresh start | `tests::audit_witness::emptying_the_log_and_deleting_its_anchor_together_is_not_a_fresh_start` |
| emptying the log and deleting its anchor is not a fresh start | `tests::audit_witness::emptying_the_log_and_deleting_its_anchor_together_is_not_a_fresh_start` |
| a log deleted while the daemon runs is reported, not passed | `tests::audit_witness::a_log_emptied_while_the_vault_is_open_is_reported_not_passed` |
| a damaged line in the middle does not lock the owner out, and is reported | `tests::audit_witness::an_unreadable_row_is_reported_as_corruption_and_does_not_lock_the_owner_out` |
| a last line that lost only its newline survives two restarts | not applicable: rows are not newline-delimited lines |
| a torn half-written last line is still dropped quietly | not applicable: a SQLite write is a transaction; `audit::parse_lines` keeps the rule for the JS log that migrate reads |
| the anchor is replaced whole, never rewritten in place | kept by construction: `audit::write_file_0600_atomic` writes a temp file and renames it; `tests::audit_witness::an_ordinary_restart_reports_nothing_and_verifies` |
| a float in caller fields is recorded, not thrown after the fact | `tests::audit_witness::a_float_in_caller_fields_is_recorded_not_thrown_after_the_fact` |
| a session request with a non-string reason is stored and recorded | covered by av-daemon and conformance (session requests are the daemon's) |
| ${name} as the last line does not lock the owner out, and is reported | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an empty object in the middle does not lock the owner out, and is reported | `tests::audit_witness::an_unreadable_row_is_reported_as_corruption_and_does_not_lock_the_owner_out` and `tests::audit_witness::a_record_shaped_wrongly_is_unreadable_even_when_it_parses` |
| ordinary records, checkpoints included, are all recognised as records | `tests::audit_witness::ordinary_records_checkpoints_included_are_all_recognised_as_records` |

### `test/security/fix-control-cli.test.js`

| JS test | Rust |
|---|---|
| the printed try: command carries the token where it cannot collide with the placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| listen add asks for the passphrase like every other gated command | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the TLS listener port is the same everywhere it is written | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env quotes what it exports, and refuses what a token or placeholder cannot be | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env exports a real session faithfully | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env and mcp url follow the session to a non-default port | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| narrowing flags split and normalise the way every other input does | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec drops real credentials from the child environment, and keeps the rest | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec reports a child killed by a signal as a failure, and a missing binary as an error | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the stdio bridge heals from a dead launch token once a new session is recorded | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| agent-vault ui warns when its page is on an origin the daemon does not trust | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a fresh-presence change on a vault with no factor says to set one, and exits 5 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec drops vault-prefixed secrets and user-less URL passwords | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec keeps the vault settings and URLs with no password in them | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec does not pass on a placeholder inherited from an earlier session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env output clears a placeholder the shell already holds when there is none now | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec and env still deliver the current placeholder when there is one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the bridge resends only the refused calls of a mixed batch | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the bridge leaves a batch alone when nothing in it was refused for want of a session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| what the bridge resends is read from the answers, not searched for in their text | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-listeners.test.js`

| JS test | Rust |
|---|---|
| listen rm stops the listener at once, not at the next restart | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| removing a listener that is configured but not bound still works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| --allow-cidr is enforced: a peer outside it is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a peer inside --allow-cidr is served, and no list means no restriction | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an allow-cidr that cannot be parsed is refused, not stored and ignored | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a TLS peer connected before listen rm is not served after it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an established TLS connection is dropped by listen rm, and a fresh one is served before it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-mcp.test.js`

| JS test | Rust |
|---|---|
| a streamed response comes back as a body, and the stream is read to the end | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a buffered response is unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_http does not leave a live placeholder behind per call | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the session token is what authenticates, so a query-site credential works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_request_session carries ttl_minutes and uses to the human | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-page.test.js`

| JS test | Rust |
|---|---|
| what the page signs for a narrowing is what the server rebuilds | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a narrowed approval made the way the page makes it goes through | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the hand-off example sends the token where it cannot displace the placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the docs name every MCP tool, and only injection sites that exist | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| without a passphrase the page gives the daemon\'s guidance instead of a tap | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-presence.test.js`

| JS test | Rust |
|---|---|
| the shared window cannot enrol an unlock factor or replace the authenticator | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with the passphrase in the request, the same changes go through | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a vault with only an authenticator can still rotate it, by assertion | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| removing Touch ID unlock by assertion works; by window it does not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| one window still covers an ordinary multi-step flow, and each step is recorded | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| locking closes the window | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the web UI enrolment passes the passphrase through, with no window | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an assertion from a page the caller named is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an assertion from the default UI origin is accepted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| trusting another UI origin needs the owner, and then it works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with no factor enrolled, a fresh-presence change is refused, not waved through | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a fresh proof opens no window | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-process.test.js`

| JS test | Rust |
|---|---|
| an uncaught error in the daemon is recorded, and the daemon keeps answering | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary run records no fault, and stopping removes the guard | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-session-requests.test.js`

| JS test | Rust |
|---|---|
| asking returns a collect secret, and nothing lists it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| another agent cannot collect a token by knowing the request id | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| over MCP, polling needs the secret the request returned | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the human who approves gets the session in the gated decision itself | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| settled requests do not fill the waiting room | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| genuinely pending requests are still capped | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| settled requests age out of memory | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| tokenless MCP initialize cannot grow the session map or the audit log without bound | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| issuing a placeholder with no live session says so, not TypeError | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the web page never sees the token, single or batch | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| anonymous MCP open and close cycles write nothing to the audit log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an authenticated client\'s MCP session is recorded when it opens and when it closes | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-touchid.test.js`

| JS test | Rust |
|---|---|
| enrolling Touch ID unlock from the UI works with one tap | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a tap over one PRF secret cannot enrol another | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon still refuses an enrol that carries no proof at all | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| removing Touch ID unlock from the UI works with one tap | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| without a passphrase, Touch ID unlock is refused before the tap, and says what to do | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| once a passphrase is set, the same vault enrols Touch ID unlock with one tap, and both open it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a vault with no factor at all is refused Touch ID unlock with the same way forward | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| without a passphrase, the presence authenticator rotates by a tap from itself, through the UI | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a first presence enrolment without a passphrase is refused with the same way forward | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-uicookie.test.js`

| JS test | Rust |
|---|---|
| an authenticated call slides the cookie; an unauthenticated one is not activity | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/fix-control-webauthn.test.js`

| JS test | Rust |
|---|---|
| a request field named op cannot replace the route op | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a supplied digest cannot replace the one computed from the secret | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary request still binds every field, and the secret only by digest | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature for a narrow session cannot issue a placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature over the real placeholder request still works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/gateway-approvals.test.js`

| JS test | Rust |
|---|---|
| an approval that already ran cannot be denied, and the deny hands back nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| granting an approval that already ran does not arm it again | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a granted approval cannot be flipped to denied before it is sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| deciding a pending approval still works, both ways, and returns no response body | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| literal marker text cannot make two different requests hash alike | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| reordering the values of a repeated header changes the request hash | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a method-override header is held to the methods allowlist | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a method-override header counts for approval, and the human is shown it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary requests are not affected by the override checks | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a failure before connecting refunds every placeholder the request spent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a failure that may have reached the server refunds nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a streamed approval that ran does not leave its resend waiting forever | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a buffered approval whose replay window closed is asked for again, not stuck | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a request that failed after reaching the upstream is asked for again, not stuck | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a resend while the approved request is still in flight keeps waiting on it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| renewing the placeholder inside a Basic header keeps the approval | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a different Basic user, or another spelling of the same header, still needs its own approval | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/gateway-core.test.js`

| JS test | Rust |
|---|---|
| the scrubber catches the encodings it used to miss | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the scrubber leaves ordinary escaped and wrapped text alone | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a percent-encoded secret split across stream chunks is still caught | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a derived token straddling the stream hold-back is not emitted in halves | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the stream scrubber still emits ordinary text unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a backslash encoded more than once is still refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary encoded paths still normalise | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a literal percent sign can be sent, and still cannot hide an escape | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| intersecting two rates never allows more than either | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| intersecting rates in the same unit is the smaller count | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| lint accepts valid enforced limits | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| JSON substitution changes the one string and nothing else in the body | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| JSON substitution follows the same duplicate key and pointer escaping as the parser | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| form substitution leaves the rest of the field and the body as written | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Basic substitution writes the Authorization header the placeholder was found in | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Basic substitution through the pipeline, with a second Authorization header present | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary single Basic header is substituted as before | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| rate layers preserve canonical windows and refuse unknown units at evaluation | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| base64 wrapped at any width, and hex in mixed case, are redacted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| several wrapped blobs in one body are each searched, and the search ends | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| wrapped prose, short lines, ordinary blobs and ordinary mixed-case hex are left alone | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the wrapped and mixed-case views stay linear on large bodies | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a path whose escape was itself encoded is refused, however many times it was | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a path encoded once is sent and checked as before | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a form placeholder with a percent-encoded character leaves the rest of the body as written | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a placeholder hidden by a duplicate JSON key is refused, however it is hidden | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| locate() reports a placeholder in a shadowed duplicate by position | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a substituted placeholder left anywhere in the outgoing request is found | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary JSON, duplicates without a placeholder in the shadowed copy included, is substituted as before | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/gateway-hardening.test.js`

| JS test | Rust |
|---|---|
| a secret in a JSON body with `\\/` and `\\uXXXX` escapes does not reach the agent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret that starts in a content block and continues in its deltas is cut, identity and gzip | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret split across events whose index disagrees with its array position is cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret split across events where the index is missing from some of them is cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret base64-encoded and then percent-encoded does not reach the agent in a body, a header or a redirect | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret base64-encoded and percent-encoded in a stream is cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary JSON with `\\/` in URLs and `\\u` escapes passes through unmodified | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary percent-encoded query strings pass through unmodified in a body, a header and a redirect | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary Anthropic, OpenAI chat, Responses and Gemini streams pass through unmodified, identity and gzip | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the ordinary streams are left whole when the vault holds a base64-style secret | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Grok\'s two-layer case: base64 percent-encoded with every % as a \\uXXXX escape is redacted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| every pair of the four encodings, nested, is redacted in a buffered body | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| three-layer stacks within the limit are redacted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a four-layer stack is beyond the limit but does not crash | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a buffered body whose nesting exceeds the decode budget fails closed, not through | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an event stream whose nesting exceeds the decode budget is cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary base64 image data URL passes through unmodified | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a large ordinary JSON response with mixed encodings passes through unmodified and uncut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/gateway-response.test.js`

| JS test | Rust |
|---|---|
| a secret in a response header NAME does not reach the agent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret split across the text of two Anthropic-shaped events is cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary Anthropic-shaped stream passes through untouched | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a CRLF-framed stream is released event by event | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a bare-CR stream is released, and a CRLF split across chunks is one line end | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an event that never ends is cut instead of held without bound | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a compressed stream is bounded by what it decodes to, not per chunk | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary compressed stream still streams in full | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a compressed stream whose source errors neither crashes the daemon nor throws at the writer | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an uncompressed stream that errors before anyone reads it does not crash the daemon | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a compressed stream from a real upstream that resets mid-body ends instead of hanging | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a split secret is caught when the event that finishes it is long | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a split secret is caught in plain-text events when the event that finishes it is long | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary stream of long events passes through untouched, compressed or not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a stream with more key paths than are tracked is cut, not forgotten | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary stream over many key paths, below the limit, passes through | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret split across events is caught however the keys are spelled, compressed or not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary stream with dotted, empty and numeric keys passes through untouched, compressed or not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret split across events is caught however the client regroups them, compressed or not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a stream with more index fields over one value than can be combined is cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary multi-block, multi-choice and NaN-bearing streams pass through untouched, compressed or not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a buffered upstream that resets mid-body is an upstream failure, and the use is not refunded | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a buffered upstream that completes its body is answered as before | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a request body goes out with a Content-Length that matches it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a DELETE with a body reaches a real upstream framed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/gateway-routing.test.js`

| JS test | Rust |
|---|---|
| /t/https/ to an http credential goes out over https, not in the clear | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a placeholder with a forged checksum does not keep its session alive | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a real placeholder as the only carrier still authenticates and keeps the session alive | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/gateway-w2-pipeline.test.js`

| JS test | Rust |
|---|---|
| rate allows capacity, limits pending requests, and never spends a refused use | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| malformed limits and persisted counters fail closed without an upstream | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| quota charges one per call, survives restart and rollback, refunds pre-connect errors | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| concurrency releases after success, pre-connect failure and post-connect failure | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| SSE slots release on completion, immediate close and scrubber cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| payload and method-bound routes run before approval and consume | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| custom patterns from every credential scrub bodies, headers and errors; corrupt pattern withholds | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| token reservations block concurrent overspend and settle buffered usage | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| unpriced and unmodeled spend refuses while ordinary free GET passes | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| missing usage and aborted SSE charge full reservation; completed SSE uses usage | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| restart charges outstanding reservation and pre-connect failure releases it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| redirects check hosts, paths, scheme, method, approval and max before sending | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| allowed redirect follows, charges each hop and forwards correct pins without body | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| pins map to safe problem and refund; health observer receives response metadata | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approval preview scrubs secrets and placeholders and notifications fire once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| quarantine and grant expiry stop before consume, and denyApprovals returns only a count | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| preflight is observational, peeks limits and reports a hold without creating approval | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| preflight denial never trips and the eleventh call is throttled | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| tripwires revoke only authenticated matching session and deny its approvals | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| tripwires default off; panic hook awaits and reports unwired or failed denial honestly | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| legacy decimal budgets work while noncanonical values never reach comparisons | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a held request previews its label, a redacted secret and no placeholder, token or audit body | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the preview builder replaces encoded placeholders, keeps duplicate JSON keys as sent, and stays under 8 KiB | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| preflight expiration has no state changes and uses the shared expiry predicates | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| expired grant fallback keeps its specific error after store marked it expired | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| quarantine tripwire pauses only its credential and leaves other sessions active | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a redirect hop is held to the GraphQL rules a direct request is held to | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a redirect hop answers to the body rules as a body-less request, not to none | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a single-valued header sent twice, differently, is refused before anything is sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| one Content-Type, or an exact repeat of it, is checked and sent as that one value | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a repeated list header goes upstream once per name, carrying every value | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a query a URL would cut or rewrite is refused before the payload rules read it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a request a method override made a write does not have its redirect followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a followed redirect sends nothing of the agent\'s but the credential and the hop allowlist | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a credential declared at a body or framing header is not sent on a hop | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a Location carrying _method is not followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a hop is checked as the method it is sent with: 307 and 308 keep it, 301 to 303 send a GET | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a method override on a direct request is still refused, and an ordinary redirect still follows | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a method-override field naming another method is refused, and nothing is sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a method-override field naming the request\'s own method is sent as it is | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a hop keeps the API-version headers a provider needs, and never a cookie, override or forwarding header | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Grok round 5, finding 1: a Location naming another method in a folded spelling is not followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Grok round 5, finding 2: a ; in the query cannot hide a parameter from the payload rules | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| every override spelling is refused on a direct request and stops a hop | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a ; query is refused under any payload rule on both paths, and goes out unchanged under none | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a name a server could fold onto a rule\'s name is refused, and a repeated name is a duplicate | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| generated requests: what the policy read is what a local upstream received, and every reader reads it within the policy | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary traffic is untouched: & queries, provider APIs, and a redirect that keeps its version headers | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the view reads a query as the union of its readers | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Grok round 6, method: a name PHP reads as _method is refused, and a hop to it is not followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a stray name is refused on every path under any rules, and a hop to one is not followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a multipart part is named by every name in its Content-Disposition, folded or not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a name is folded the way PHP registers it: cut at NUL, leading spaces dropped | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary provider traffic is sent unchanged under the name check | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Grok round 7, payload: a bracket-wrapped name is refused, and a hop to it is not followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| Grok round 7, method: a bracket-wrapped _method is refused, and a hop to it is not followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a name Rack 2.2 reads as a ruled one or as _method is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a name that starts with punctuation is refused on every path, and a hop to it is not followed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary traffic that opens a name with $ or a JSON key with $ or @ is sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a repeated list name is sent under unrelated rules, and a rule on its base checks every entry | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/gateway-w2-seams.test.js`

| JS test | Rust |
|---|---|
| pins on a plaintext credential refuse before any connection; no pins still connects | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a throwing health reader or recorder never turns an executed request into a failure | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| onPending gets the id and headline only, and a throwing hook still holds the request | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| denyApprovals filters by session, credential and grant ids, records the reason, and returns a count | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| panic denies held requests, revokes every session including an infinite one, then the hook, then the record, then the lock | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a panic whose hook fails still revokes everything and records a partial panic | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a tripwire that throws while firing cannot cost the agent its denial | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with tripwires on, a bad-location run revokes the session; ordinary requests never count | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an unauthenticated replay never counts against the session its placeholder names | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a quarantined credential is refused before anything is spent, and works again once released | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| preflight and the real route agree on finite, expired, infinite and legacy sessions and grants | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| preflight writes one record with nulls, not undefined, and puts no hint where there was none | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a redirect to another port on an allowed host is not followed; the same port is | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a redirect hop that cannot connect closes the redirect it was following and is not refunded | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| GraphQL rules read the URL query on a POST too, and the decided path ends the /graphql check | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a binary upload passes a grant whose payload rules only constrain the query | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a strict-query refusal names the parameter by its index and never echoes a name or value | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a spend refusal says what is left and what the call could cost; a call that fits passes | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a CRLF-framed stream settles on its usage; a cut stream charges the full reservation | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a pipeline built while the vault is locked charges stale reservations at the first request after unlock | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an extra pattern scrubs an error detail, is redacted within an event, and cuts a stream that splits it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a method-override header is held to the route pairs as well as the methods list | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a held request is recorded as held, an allowed one as allow, a refused one as deny (C11) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate2-c12-surfaces.test.js`

| JS test | Rust |
|---|---|
| /p/ on a network listener: the infinite token is refused before anything is sent, a finite one works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| /mcp on a network listener: every tool that needs a session refuses the infinite token as AV_REMOTE_FORBIDDEN, sends nothing, mints nothing, and records it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| /mcp on a network listener: the handshake and the ungated tools treat the infinite token as a dead one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| /mcp on a network listener: a finite token is unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| /v1 on a network listener: every session route refuses the infinite token with 403 infinite_remote; /v1/status stays open | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| /v1 on a network listener: a finite token is unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| on loopback (built-in gateway, TCP and TLS listeners) the infinite token works on every surface | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| stdio MCP has no network listener and stays loopback for an infinite session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_http hands its listener to the pipeline, which refuses an infinite session there by itself | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the vault answers C12 for a peek and for a use alike, and records only the use | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate2-seams.test.js`

| JS test | Rust |
|---|---|
| a correct leaf pin goes out through the real pinnedRequest, with the secret and the URL host | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a wrong pin on an untrusted self-signed upstream sends nothing and is refunded; its own leaf pin is reached | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| on a chain the daemon trusts, an intermediate or leaf pin is honoured, and a pin that matches nothing is AV_PIN_MISMATCH, refunded and unsent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the same chain with an intermediate pin is refused, unsent, when the daemon does not trust its root | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the agent's Host header never reaches the connector; a Host that did would be refused unsent (C9) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a repeated list header goes out folded into one line, not refused as header_format | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a malformed pin table on a credential is pinned, not unpinned: refused before a connection | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the connectors health reader and the store record what a response says (F10) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an expired grant is refused before anything is sent, and stays expired, not missing (F18) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| each redirect hop is charged to the grant by the store, and the hop past the budget is not followed (F6) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a grant layer with no limit is bounded by the session layer, and its hops are charged (C4, one reader) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a credential the store quarantined is refused before any send, and a tripwire quarantines through the store (F16) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| preflight and the real route agree, read with the store itself, on finite, expired, infinite and legacy sessions | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a scrub pattern the store saves is applied by the gateway, and one the grammar refuses is never saved | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a held request is recorded as held, and the store report counts it as held, not as a use (C11) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| panic: the wired hook denies pending session requests, and a throwing hook still completes the panic (C1) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an infinite session is refused on a network listener, with nothing sent and the refusal recorded (C12) | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a finite session on a network listener is unchanged by C12 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-c25.test.js`

| JS test | Rust |
|---|---|
| C25: shapeOf names the fields a proposal sets and counts its lists; narrowedOf names what a human changed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C25: every r2 and r3 form, in paths, routes, payload, reason and every number, reaches no record; decide keeps the grant whole | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C25: decide-many records the same structure, and pending.decided_many holds only ids | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C25: a denial, and a panic denial, record structure only | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C25: a value rotated out (retireMs 0) between the ask and decide is in no record, and the gateway enforces the grant | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C25: a human override holding a former secret and a PIN is recorded as the names it narrowed, nothing more | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| F6: placeholder.issued and placeholder.refunded carry no use ceiling; a human-made session keeps its expiry in the log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C25: no request record is written with a value even when the secrets cannot be read | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-e2e-approvals.test.js`

| JS test | Rust |
|---|---|
| A.7 6 (F13, F14): watch prints a held POST, the preview hides the placeholder, and the approved resend runs once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 7 (F15): session narrow --methods GET mid-run refuses the next POST and keeps GET working | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 7 (F16): with the tripwire on, a replayed placeholder revokes its session before the answer returns | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-e2e-gateway.test.js`

| JS test | Rust |
|---|---|
| A.7 4 (F1): --rate and --quota refuse the call past the limit with retry_after, and nothing past it is sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 4 (F1): --concurrency 1 refuses a second call while the first is in flight, and not one after it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 4 (F2): a JSON payload rule refuses a value outside it before anything is sent, and passes one inside it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 4 (F3): method-bound routes allow each method only on its own paths | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 4 (F5): a token budget refuses a call that could exceed it, and settles a call that fits on its real usage | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 4 (F6): --redirects follows a hop the policy allows, stops at one it does not, and never follows without it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 5 (F7): rotating with keep while an agent loops loses no request, and the old value stays scrubbed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-e2e-preflight.test.js`

| JS test | Rust |
|---|---|
| A.7 10 (F19, F20): a preflight changes nothing but its audit record, and session show counts only the real request | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-e2e-sessions.test.js`

| JS test | Rust |
|---|---|
| A.7 1 (R1): --approval auto asks for the passphrase on a terminal, and a POST is then not held | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 1 (R1): the same command with the window open and no passphrase is refused, and nothing is made | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 2 (R2): env writes a 0600 file of placeholders, refuses to replace it, and exec sends the real value upstream | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 3 (R3): an infinite session lists as never, says infinite over MCP, and panic revokes it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-e2e-templates.test.js`

| JS test | Rust |
|---|---|
| A.7 8 (F17): a session requested by template matches the snapshot it was asked from, not the edited template | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| A.7 9 (F18): a grant with --grant-ttl 1 ends with AV_GRANT_EXPIRED on a fake clock; the other grant still works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-fix1.test.js`

| JS test | Rust |
|---|---|
| D1: the daemon refuses a decision whose overrides name a key it will not apply, naming the key, and decides nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| D1: nothing the CLI or the page can send on a valid path names a key the daemon refuses | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| D2: towardPage withholds passphrase at any depth, in any case or hyphenation | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| D2 (round 3): a run of hyphens, underscores or spaces is one separator, so pass--phrase, pass__phrase and "pass phrase" are withheld | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-gates.test.js`

| JS test | Rust |
|---|---|
| C19: the page, webauthn.js and so the daemon digest every secret-bearing key the same way | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| every gated UI route: the operation the page signs is the one the UI server and the real daemon rebuild | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C22(4): a pin removal signed without spki, or for another spki, is refused by the UI and by the daemon | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C19 end to end: a backup bundle is bound by its canonical digest when the daemon restores it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C19 end to end: a webhook URL is bound by digest, and the page signs what the daemon checks | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-narrowing.test.js`

| JS test | Rust |
|---|---|
| the page reads every narrowing with the module\'s parser, and keeps no second one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI and the page sign the same operation for the same narrowing, field by field | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| through the UI server, each narrowing signed by the page is approved by the real daemon, and kept | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a narrowing that cannot be read: the CLI exits 2 naming the field, and sends nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a narrowing that cannot be read: the page shows why and builds, signs and sends nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a narrowing that cannot be read: the UI server answers 400 and the daemon 4xx, and nothing is approved | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a key no approval applies is refused by the shared parser, the UI server (400), the page and the CLI, as the daemon refuses it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| OVERRIDE_KEYS is the list the self-contained parser reads, key for key | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-r4.test.js`

| JS test | Rust |
|---|---|
| C27: a secret as the path glob and the route glob is in no gateway row, before or after rotation; the grant still allows the path | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C27: a path-only grant records path_rule and a null route_rule, never the glob | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C27: a deny pattern added by an open narrowing is named by index in the denial, never by its text | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| F2: decide-many writes only ids the daemon minted, and counts the rest | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C26: elevationOf names first-use with a write method, and not read-only first-use | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C26: creating first-use with writes needs a fresh proof; read-only first-use rides the window | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C26: approving a request into first-use with writes needs a fresh proof, not the window | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C26: narrowing a request into first-use with a write left needs a fresh proof; narrowing it to read-only does not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C26: a live narrowing cannot loosen a write grant into first-use | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a boolean flag given a value, even "false", is refused with exit 2 naming the flag | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a numeric flag with no value is refused with exit 2 naming the flag, not read as 1 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-r5.test.js`

| JS test | Rust |
|---|---|
| F1: a refused Touch ID assertion records a closed code, never the client data it quotes, on all three surfaces | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: a denial row has the code, rule, method and path, and no sentence; explain-denial gives the sentence to its own session only | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: a payload rule names its key by index, and a strict query names the parameter by position, on all three surfaces | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: a redirect refused for its host records no host it was not allowed to reach | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: a fault is recorded by class, never by message | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: a listener that cannot bind records its system code, not the message | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: session.created says whether a session has a label, not what it says | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: a failed webhook records a system code or `error`, never other text from the error | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: every *_untrusted field is scrubbed whole, cleaned of placeholders, and cut to 200 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C28: a quarantine reason restored from a bundle is cleaned before it is recorded | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| item 3: mcp install --tls takes no value; bare --tls is the https URL and its absence the plain one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-r6.test.js`

| JS test | Rust |
|---|---|
| B1: tripwire show on a vault that never saved rules lists the defaults; set edits them; on keeps them | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| B1: the page shows the defaults as defaults, and turning on stores them, when none were saved | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| B2: preflight as documented predicts allow, hold and refuse correctly, and changes nothing but its records | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| N1: approving a narrowed session request prints what was granted, not what the agent asked for | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| N2: cred test names a kind with no probe as exit 7, and --all skips it without hiding a real failure | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| N4: bidi controls and line separators in agent text never reach the terminal | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| N4: every shared cleaner strips bidi controls; the terminal ones strip line separators too | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| r6 F1: a streamed response records a closed media type and encoding, never the upstream header text | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| r6 F2: explain-denial gives code and rule however much was logged since, after eviction and after a restart | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| r6 F2: a caller with no session gets the code and rule of a no-session denial, never its sentence | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/integrate3-seams.test.js`

| JS test | Rust |
|---|---|
| the README and the docs page say how many MCP tools there are, and it is how many mcp.js has | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| F13: a held request carries its preview from the gateway through pending.js and the UI server, and the page escapes it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C18: an infinite token is refused on a 0.0.0.0 and a [::] TLS listener by every wave-3 surface, and a finite one works | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a stored secret an agent puts in a session request path or reason does not reach the audit log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ordinary session request is recorded in the audit log by its shape | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| with the secrets unreadable, the opened record is the same shape and holds nothing the agent wrote | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/listener.test.js`

| JS test | Rust |
|---|---|
| addresses parse, and nonsense is refused rather than half-bound | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a hostname that merely starts with 127 is not loopback | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| loopback is recognised in every form it arrives in | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the certificate covers both names a client may use to reach loopback | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the private key is not readable by anyone else | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| generating twice reuses the certificate rather than churning it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a key that became readable is refused, not loaded anyway | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a TLS listener binds and serves only the surface it declares | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an address with no port is refused when it is added, not at the next restart | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a network listener with no TLS is refused at add time too | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a listener on a network address without TLS is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the listener a request arrived on reaches the pipeline at all | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/locked.test.js`

| JS test | Rust |
|---|---|
| reading the audit log says the vault is locked, not that something broke | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| verifying the audit chain says the same | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a locked vault says its record count is unknown, not zero | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the reads the unlock screen depends on still work | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| unlocking restores the audit log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/mcp-tools.test.js`

| JS test | Rust |
|---|---|
| a request inside the grant works, so the refusals below mean something | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a path outside the grant never reaches the upstream | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| traversal cannot climb out of the granted path | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a credential this session was never granted is unreachable | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| CRLF in a path or a header cannot smuggle anything upstream | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the agent cannot set the daemon’s own headers through a tool argument | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a body goes upstream with exactly one content-type | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_get_placeholder is bound to the session’s own grants | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| no tool returns a credential value, whatever it is asked | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the tool list is exactly the documented tools | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the one capability-shaped tool cannot create capability | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a concurrent request cannot hijack a batch mid-flight | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent can ask for the least lifetime it needs, not just the least scope | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| no error path names an MCP tool that does not exist | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent can find out whether the human answered | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/mcp.test.js`

| JS test | Rust |
|---|---|
| initialize returns a protocol version, server info and a session id | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| no bearer token buys no capability, on any tool that spends it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the MCP session id alone never authenticates | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the handshake works without a session, and says what is missing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| asking for a session needs no session, exactly as the HTTP route does not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an unknown MCP session id is rejected rather than silently accepted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an unsupported protocol version is refused with the supported list | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a browser cannot drive the MCP endpoint | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| tools/list advertises the tools an agent needs and no secret-bearing tool | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_list_creds tells the agent exactly where a placeholder goes | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_http runs the full pipeline and never returns the secret | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| vault_http is bound by the same policy as the gateway | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| DELETE ends the transport session but not the vault session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| transport parity: stdio and HTTP produce identical tool results | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| batched JSON-RPC messages are answered as a batch | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a notification gets 202 with no body, per the transport spec | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/one-source-of-truth.test.js`

| JS test | Rust |
|---|---|
| both interfaces read the same list from the same module | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page paints the list and decides nothing about it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| narrowing flags are parsed identically wherever they are typed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a new kind of decision reaches both interfaces by construction | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a lifetime can be narrowed, like every other dimension of a proposal | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| C21: the shipped bundle\'s parseOverrides is src/pending.js\'s, and the server binds with the same function | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/pipeline.test.js`

| JS test | Rust |
|---|---|
| the placeholder is replaced with the real secret and only the upstream sees it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the session token works as a carrier instead of a placeholder-derived session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| S06: a valid placeholder aimed at a non-granted host never opens a connection | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a path outside the grant is denied before the wire | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a write method under a read-only grant is denied | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a profile deny list blocks webhook creation even under a wide grant | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| S25: a placeholder in a request body is refused with zero upstream bytes | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| encoded placeholders in a body are caught in every encoding | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a placeholder in the request path is refused: the path is never a site | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a placeholder in an undeclared header is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the places a naive scan does not look are not hiding places | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a second Authorization header is refused, so no placeholder goes upstream | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a malformed percent-escape in a query key does not blind the scan | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| S05: a one-time placeholder cannot be used twice | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| S05: concurrent uses of a one-time placeholder produce exactly one upstream call | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an exhausted placeholder hands back a working successor | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| S04: a placeholder from another session is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a budget layer that names no limit does not make the grant unlimited | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a budget limit written as a string still counts | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a budget limit that is not a number refuses rather than counts nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| held approvals are bounded, and do not hold response bodies forever | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a stale pending approval is forgotten, so the cap is not permanent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a bare placeholder does not authorize on a network listener | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the successor to a one-time placeholder is also one-time | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an approval does not carry over to a request with different headers | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a fractional use count does not persist state the log never records | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an upstream cannot choose how much of the daemon it occupies | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a use is given back when the request never reached anyone | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a use is NOT given back when the request may have been delivered | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a refused request does not decrypt the whole vault three times | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an approval survives a request that never reached the upstream | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a refund into a revoked grant is refused, not quietly granted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a legitimate refund is recorded, so the ledger and the log agree | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a placeholder cannot be spent under a grant it was not issued under | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a revoked session stops working immediately | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a forged placeholder is refused by its checksum, before any lookup | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a real placeholder with one character changed does not verify | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the fingerprint shown in cred list is not an oracle for the checksum key | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| S09: an upstream echoing the secret back has it replaced by the placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an upstream echoing the secret in a header has it scrubbed too | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an upstream cannot forge AV-* headers or set cookies on the agent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a derived token minted upstream is redacted by shape | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| S28: a request carrying Origin is refused, so a web page cannot use the gateway | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a Host header outside the allowed set is refused, blocking DNS rebinding | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a write under on-write approval is held, then executes exactly once on resend | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a denied approval stays denied on resend | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a spent budget stops the session without a human | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| every decision is recorded in a chain that detects tampering | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| no audit record contains the secret in any form | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a locked vault refuses every proxied request | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| locking is recorded on disk, so a restart comes back locked | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| unlocking clears the recorded state | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a locked vault still answers questions that reveal nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a held write is resendable with a freshly minted placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a resend cannot change what the human approved | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/remote.test.js`

| JS test | Rust |
|---|---|
| on loopback a placeholder alone authenticates, which is the point | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| over the network a placeholder alone does not authenticate | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| over the network the same request works with the session token alongside | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a listener serving a surface that may never leave the machine is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a refused listener is recorded, not silently dropped | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a remote session carries its own shorter ceiling | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/requested-c3.test.js`

| JS test | Rust |
|---|---|
| a session the owner creates records its elevation, [] when ordinary | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an approved request records the elevation of what the owner approved | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a bulk decision records each session\'s own elevation, not the batch\'s | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an elevation the store does not know is refused, and nothing is written | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/requested-r1.test.js`

| JS test | Rust |
|---|---|
| elevationOf names auto with a write method, and nothing ordinary | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| elevationOf fails closed on anything it cannot read | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| elevationOf fails closed on an unreadable list whatever the approval mode | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| owner fields are read by one parser, and the CLI parse feeds it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| auto with writes is refused inside an open window without a fresh proof | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| auto with writes is created with the passphrase in the request, and audited as fresh | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a wrong passphrase for an elevated session is refused, and counted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| read-only auto is not elevated: the window is enough, and nobody is asked again | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a vault with no factor refuses auto with writes, and still makes ordinary sessions | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an authenticator assertion over the exact body creates an elevated session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an unknown approval mode is refused, never read as auto | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| malformed limits are refused before anything is created | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session request that names an owner field is refused, not trimmed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the request store refuses an owner field from any caller | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| MCP cannot carry an owner field into a request | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the gateway has no route that creates a session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approving a request into auto with writes needs a fresh proof, not the window | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a request approved without owner options stays ordinary, inside the window | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a verdict that is not true or false is refused on the single decide route | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an override with an unknown mode is refused when it is settled | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a bulk decision with one elevated item needs a fresh proof for the whole list | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI refuses a mode it does not know before it calls anything | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI says what to do when auto with writes cannot be proved | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI exits with the refusal code’s own exit status | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approvals offers the owner options, and approve validates them | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the help text documents how to start an auto-approving session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/requested-r2.test.js`

| JS test | Rust |
|---|---|
| a new file is created 0600 even under umask 000, and an existing one is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a symlink is never followed, with or without force | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| force replaces a regular file atomically and leaves it 0600 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a temporary file swapped for a symlink before the rename is refused, and no link is left | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a destination that becomes a symlink just before the rename is replaced, and the target is untouched | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| appending makes the file 0600 whatever the umask, and tightens one that was not | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| appending creates 0600, appends whole lines, and refuses a symlink | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the final check passes placeholders for the session and loopback gateway URLs | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the final check refuses everything else, and never says what it refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| one session holds several credentials, each with its own grant and placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an ambiguous or mixed session body is refused, and leaves nothing behind | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| two credentials for one host stay apart: /p/ picks by name, /t/ refuses the other one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch is gated like a single placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch issues one placeholder per item, in order, and records the batch | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch is all or nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch with one quarantined credential issues nothing, not even the items before it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch of the wrong shape is refused before anything is resolved | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the grant’s use ceiling beats what a batch asks for | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env writes a 0600 file of placeholders and URLs, and never a secret or the token | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env never replaces a file unless told to, and never follows a link | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env refuses bad mappings before it calls anything, without echoing what was pasted | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env with a map file and no --out prints the lines | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env without a session says how to make one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| env warns when the file would be committed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch answer that is not a placeholder is never written | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the same fake answering a real placeholder shape is written: the check is not a wall | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec --map puts a placeholder in the child under the name a tool reads | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| exec reports a missing command as 127 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| session create takes several credentials and prints a block for each | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/requested-r3.test.js`

| JS test | Rust |
|---|---|
| a session with no expiry needs a fresh proof, and gets one from the passphrase | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a vault with no factor refuses a session with no expiry | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session with no expiry is never remote, and says so before asking for anything | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a lifetime is a positive number, and infinite has none to set | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| ordinary finite sessions are unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| revoking a session with no expiry kills its placeholders | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the owner can add no expiry when approving, but not on top of a lifetime the agent asked for | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an authenticator assertion creates one from the UI, which marks it everywhere | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI refuses --ttl with --infinite, and lists an infinite session as never | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI on a vault with no factor says to set a passphrase first | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a stored expiry that does not parse is never live | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an infinite session is the default for an implicit placeholder when it is the only one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/requested-seams.test.js`

| JS test | Rust |
|---|---|
| a session for a quarantined credential is refused before the gate asks for anything | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approving a request for a quarantined credential is refused and leaves it pending | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a placeholder batch for a quarantined credential is refused whole, with the store\'s rule | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a placeholder batch on a grant that has ended is refused by the store\'s grant check | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/requested-ui.test.js`

| JS test | Rust |
|---|---|
| the page reads owner options exactly as the CLI and the daemon do | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session with no expiry renders as never, and garbage as expired | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the decisions that can be elevated are re-verified by the daemon | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page warns before it signs an elevated session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the hand-off card offers an env command with no session token in it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approving a request with owner options from the page creates the session they chose | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature for one owner option cannot be spent on another | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an auto-approving multi-credential session made from the page needs only its own signature | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the docs say how to start an auto-approving session, and that read-only needs nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/response.test.js`

| JS test | Rust |
|---|---|
| a gzipped response is decompressed before it reaches the agent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| deflate and brotli are handled too | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret hidden inside a compressed body is still scrubbed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an encoding we cannot decode is refused rather than passed through unread | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a binary body survives byte for byte | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a gzipped binary body round-trips through decompression unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a COMPRESSED event stream is decompressed before it is scrubbed | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an event stream in an encoding we cannot read is refused, not passed through | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret inside an event is scrubbed, and the rest survives | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the stream hold-back is bounded, not the whole response | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret split across two stream chunks is still caught | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| end to end over real HTTP: a gzipping upstream and a streaming upstream both work | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret cannot escape through an internal error message | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a token stream that merely mentions a repository is not cut | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a secret split across two SSE events is caught | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/revocation.test.js`

| JS test | Rust |
|---|---|
| revoking a session kills every placeholder it ever issued | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| revoking one grant does not disturb another session | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| deleting a credential stops every grant that used it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| locking the vault refuses everything, and unlocking restores it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an expired session is refused even with a live placeholder | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a revoked placeholder coming back is treated as hostile, not as a mistake | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/serving.test.js`

| JS test | Rust |
|---|---|
| a listener naming the control surface on a network address is refused outright | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a listener naming the database surface on a network address is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the refusal is audited so a misconfiguration is loud, not silent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the same surfaces are allowed on a loopback or unix address | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| gateway and mcp surfaces may be bound to a network address | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| loopback detection covers the forms an operator actually types | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| removing a listener is allowed without ceremony: reducing reach is always safe | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the control socket is created with mode 0600 and no network address | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the vault directory is 0700 so another local user cannot read it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/session-requests.test.js`

| JS test | Rust |
|---|---|
| asking for a session creates nothing at all | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot answer its own request | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a human approving gets a working session, collected exactly once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| what the human edits is what gets created | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approval supplies a human, never permission | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a denial creates nothing and cannot be reversed by asking again | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot flood out a request a human is reading | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| every request and answer is in the audit log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a request is audited on a vault that started locked, which is every real one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| approving records the session where a running agent will find it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a denial records nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a pending request survives a daemon restart | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an approved token is never written to disk | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session request tells the human a command they can actually run | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| no hint anywhere names an agent-vault command that does not exist | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an approved lifetime is a ceiling, not an opening bid | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a requested lifetime cannot exceed the hard ceiling | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent cannot settle a batch any more than it can settle one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch refuses the shapes that would hide an approval | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch settles through the same path as a single decision | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an item that stopped being pending is reported, not skipped in silence | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/ui-audit-growth.test.js`

| JS test | Rust |
|---|---|
| Prev from the old first page holds only the rows appended since, and then there is no Prev | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a log with gaps that grows while it is walked: Next sees the first snapshot once, Prev reaches every new row once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a real daemon, a kind and a search, rows arriving all the time: both directions, no row twice, none skipped | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/ui-audit-paging.test.js`

| JS test | Rust |
|---|---|
| the fixture wrote the log it claims to | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon: a bare limit is the tail it always was | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon: kind filters before the limit | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon: before and after walk the whole log, each row once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon: paging parameters are whole numbers in range or refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon: a kind-filtered tail is bounded at 500 even with no before or after | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the daemon: the unfiltered tail keeps its old reading of limit | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the CLI: audit tail reads the same tail as before | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page: a kind walks every row of that kind, newest first, across the whole log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page: with no kind the whole log is walkable | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page: q searches visible fields across the whole log, a page at a time | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page: q never matches token or placeholder text in a row | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page: audit cursors and limits are checked like every other list | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the page: without paged=1 the audit route is unchanged | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/ui-complete-lists.test.js`

| JS test | Rust |
|---|---|
| fetchAll reads every row of a list longer than 50 pages of 200 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| 32 tripwire rules: the list the page shows pages and searches; the snapshot has all 32 | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/ui-paging.test.js`

| JS test | Rust |
|---|---|
| without paged=1 every list route answers exactly as it always has | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| each list pages through every item once, in its documented order, and back | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| pending pages newest first, with both kinds of decision | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an object answer keeps its other fields beside the page | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| limit is a whole number from 1 to 200; anything else is AV_BAD_LIMIT | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a cursor that was not made by this server for this list and filter is AV_BAD_CURSOR | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| q is a case-insensitive match over visible fields, and filters before paging | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| q never matches a token, a placeholder or a value, even one the daemon leaked | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the cursors in an answer survive the scrub that every answer passes | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/ui.test.js`

| JS test | Rust |
|---|---|
| the relying party id is a domain, not an IP literal | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| arriving by IP is redirected to the domain the authenticator accepts | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the launch link works exactly once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| without the session cookie the API answers nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a cross-origin caller is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a request without the custom header is refused, which stops a form post | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the credential list carries no value, in any field | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| there is no endpoint that returns a secret at all | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the docs context describes this install and carries no secret | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the docs page is reachable without changing anything | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| before enrollment, every mutating call is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a forged presence payload is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| enrollment registers the authenticator | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a second enrollment is refused, so an agent cannot add its own key | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| after enrollment, a mutating call still fails without a signature | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature for the wrong operation is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a valid signature for the right operation is accepted exactly once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a session created here reaches the store every local client reads | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the enrollment is recorded in the audit log | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch with no signature is refused, like a single decision | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the operation bound for a batch is the list exactly as it was sent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/wave1-compose.test.js`

| JS test | Rust |
|---|---|
| denying a spent approval still needs the human, and changes nothing without one | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a spent approval cannot be denied even with presence, and the refusal hands back nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a spent approval cannot be granted again, so its write runs once | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a bulk decision skips a spent approval, both ways, and reports no result | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| internally, deciding a spent approval throws and leaves it spent | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a spent approval set aside for a new ask cannot be decided either | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the control API strips a cached result even if the pipeline hands one back | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a failing event stream neither crashes nor hangs the daemon, and the guard stays the backstop | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |

### `test/security/widening.test.js`

| JS test | Rust |
|---|---|
| the passphrase gate is on, so an unsigned call is refused | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| creating a session from the UI works with one fingerprint | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the credential list says where a placeholder may go | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| adding a credential from the UI works the same way | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| removing a credential from the UI works, signature and all | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature for one operation cannot authorise another | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature is good for exactly one call | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a challenge the daemon never minted proves nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a key the daemon never enrolled proves nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| an agent at the socket cannot enrol its own key and sign for itself | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the passphrase window still works, for the CLI | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a wrong passphrase opens nothing | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a signature does not authorise fields it never covered | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| the value stored under a cred.add signature is bound to it | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch signature covers exactly the items it named | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| a batch signature is spent by the batch it named | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
| reordering a signed batch does not change what it authorises | covered by av-daemon / av-cli and conformance: it drives the daemon, the CLI or the web UI |
