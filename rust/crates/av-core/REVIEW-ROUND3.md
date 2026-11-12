# Core follow-up: jsre fail-closed

Fresh branch `rust-port-core-followup` from merged `origin/rust-port`.
Addresses findings 1–6 of `review-core-2.md`.

1. An unescaped dot outside a class becomes `[^\n\r\x{2028}\x{2029}]`.
   Escaped dots and class-member dots stay literal. Matching still consumes one
   Unicode scalar, not one UTF-16 code unit; this limitation is documented in
   jsre and explicitly exercised with an emoji vector.
2. Class ampersands and tildes are escaped, preventing Rust intersection and
   symmetric-difference semantics. An unescaped class `--` refuses compilation.
3. Custom scrub patterns refuse quantification of any atom that can consume
   non-BMP text: `\S`, `\W`, `\D`, negated classes, positive classes containing
   those complement shorthands or astral literals, and astral literals.
   `\s`, `\w`, `\d` and their positive-class forms are BMP-only and remain safe
   to repeat. Dot remains refused by the existing scrub grammar. The new
   refusal uses the same `AV_POLICY_DENIED`, `scrub_pattern` problem and
   `scrub pattern refused: it is not a valid expression` detail as a JS-invalid
   expression; the full problem value is compared with Node's invalid-class
   oracle. Earlier grammar failures retain their original messages. Existing
   successful negated-class/repeated-\S test controls were replaced with
   BMP-only controls, with explicit refusal assertions where applicable.
4. Request credentials and lowercased header names sort stably by UTF-16 code
   units. This corrects the round-2 audit's mistaken claim that no comparator
   change was needed: explicit sorting was present, but its UTF-8 comparator
   disagreed with JS for non-BMP strings. Canonical object's UTF-8 sorting and
   WebAuthn operation's UTF-16 sorting retain their separate JS contracts.
5. Any `(?` construct except a noncapturing `(?:` group refuses, after removing
   at most one leading `(?i)` flag. Non-leading, duplicate, scoped and other
   inline flags therefore cannot enable Rust Unicode case folding. Public
   `translate` retains its String signature and returns deliberately unsupported
   syntax for refused inputs; `compile` returns a descriptive Syntax error.
6. The source guard rejects direct regex namespace usage/imports, RegexSet,
   RegexSetBuilder, bytes Regex, renamed constructors, crate aliases and
   whitespace-split constructors outside jsre. Regex and Captures types are
   re-exported by jsre for other core code's annotations. Guard bait vectors
   cover each bypass and a shared-compiler control.

`jsre-followup-vectors.mjs` runs only read-only Node reference code. It
produces dot/line-terminator probes, literal class operators, invalid class
and inline-flag syntax, the quantified-emoji example plus ASCII controls,
custom scrub compilation results, non-BMP and ASCII request hashes (including the reviewer's exact
`f9eb2734…66609f3` input), and
explicit Rust source guard bait/control rows. Deliberate stricter refusals
are marked separately from exact parity. A live Node test compares all stored
vectors on the repository checkout; mutation copies retain the stored tests
and skip live regeneration because they contain only rust/.

New tests:

- `js_dot_classes_and_flag_refusals`
- `js_scrub_non_bmp_repetitions_refuse_with_invalid_pattern_problem`
- `js_request_hash_utf16_names_credentials_and_ascii_control`
- `followup_vectors_regenerate_from_node`
- `guard_rejects_sets_bytes_aliases_and_split_constructors`

Five mutation entries cover dot, literal class operators, nonleading flags,
and both request-hash comparators. The existing repeated-header mutation was
updated to target the new comparator while retaining its original behavior.

## Verification

From `rust/`, all builds use `CARGO_BUILD_JOBS=2`, one at a time:

- `cargo fmt --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test --workspace`: 120 passed, 0 failed, 0 ignored, including all
  live Node fixture regeneration tests and the five new follow-up tests.
- `cargo xtask mutation --scoped`: 91/91 caught, 0 missed/invalid/timeouts
  (88 av-core and 3 existing av-store entries), with full output in
  `MUTATION-ROUND3-RESULTS.txt`.

The mutation copy contains the complete implementation and original follow-up
vectors. Two additive test refinements were made while it ran: guard bait for
aliases of jsre-re-exported types, and the reviewer's exact non-BMP request
hash input in addition to the original equivalent-shape vector. The final
workspace checks cover both refinements; runtime code and mutation entries
were unchanged during the mutation run.

The first workspace test attempt exposed an older successful negated-class
control that the new rule intentionally refuses; that control now asserts
refusal and uses a BMP-only class for its linear-time benchmark. A previous
successful repeated-complement control also now uses the corresponding safe
word shorthand. The completed workspace test run includes these changes.

