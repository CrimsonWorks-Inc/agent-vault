# Core review round 2

Addresses `review-core-1.md` findings 1–5. All regex compilation now goes
through public `av_core::jsre::compile`, which translates JavaScript's
whitespace, word, digit and boundary classes and applies legacy, non-`u`
case folding to the ASCII/BMP literals and ranges used by the port. The
engine remains the linear-time `regex` crate. The guard test scans both
source and Rust tests for direct engine construction outside `jsre.rs`.

`regex-review-vectors.mjs` executes the read-only JS reference functions.
The checked-in output covers FEFF/NEL split base64 placeholders (and prose
BOM/newline/unsplit controls), FEFF/NEL multipart method overrides (and title
controls), the six content types from the review, Arabic-Indic JSON and
GraphQL numbers, profile dates and model snapshots, empty/GET/POST approval,
and exact serialized problem bytes with object-valued next and all optional
fields. A live Node test regenerates the fixture and compares every probe;
only randomly minted placeholder text is excluded from that regeneration
comparison. The stored placeholder text and expected detector hits are
compared exactly by the detector test.

Three new mutation entries restore direct Unicode regex compilation in the
detector, multipart disposition parser and model content type parser. Each
selects its differential regression test, so the mutant must fail on behavior
rather than merely trip the source guard.

## Approved insertion-order feature and canonicalization audit

The coordinator approved enabling `serde_json/preserve_order` in av-core and
committing its Cargo.lock feature dependencies. Cargo unifies this feature
across the workspace: all `serde_json::Map` instances now preserve insertion
order, including nested object-valued recovery instructions. Other crate
owners must account for this feature when checking their own canonical data.
The feature grew av-cli CliError to 128 bytes; the coordinator separately
approved boxing its problem Value in av-cli/src/lib.rs (one field, separate
commit) to retain a clean workspace clippy gate.

Audited all av-core JSON serialization and hash/HMAC inputs:

- `canon::canonicalize`: explicitly sorts object keys by UTF-8 bytes recursively;
  no change needed.
- `canon::hash` and `canon::hmac`: consume `canonicalize` bytes; no change needed.
- `canon::request_hash`: explicitly sorts credentials and stably sorts headers by
  name, then calls `hash`; no change needed.
- `canon::sha256`: hashes caller-provided raw bytes; no object serialization.
- `operation::canonical_operation`: explicitly sorts keys by UTF-16 code units
  recursively; no change needed.
- `operation::operation_for`: previously iterated the serde map, relying on its
  implicit sorting; changed to explicit UTF-16 key sorting like JS
  `Object.keys(params).sort()`. Non-string digested fields already use
  `canonical_operation`; strings are hashed as raw bytes.
- `operation::challenge_for_operation`: hashes nonce followed by explicit
  `canonical_operation`; no change needed.
- `placeholder::checksum` and `placeholder::hash_nonce`: HMAC fixed-format
  placeholder text and nonce bytes respectively; no object serialization.
- `request_view` JSON override values: uses JSON serialization to retain the
  original object's text order like JS `JSON.stringify`; insertion order is
  desired and no sorting was added.
- `substitute` and `scrub` JSON serialization: serializes individual strings,
  not maps; no change needed. Substitution keeps original JSON body structure
  rather than reserializing objects.
- `policy` and `payload` serialize typed rules to values for validation, not
  hashing or text equality; insertion order is desired, no sort needed.
- `errors::to_problem`: moved next_placeholder after next/factors/refunded to
  match JS insertion order, with a byte-for-byte differential test.

`js_insertion_order_keeps_canonical_hashes_and_operation_digests_stable`
compares canonical bytes, hash, HMAC, request hash, canonical operation,
operation wire bytes (including a structured secret digest), and challenge
against Node, using reverse insertion and non-BMP keys to distinguish UTF-8
and UTF-16 sorting.

## Verification

All commands run from `rust/`, with `CARGO_BUILD_JOBS=2` and one build at a time:

- `cargo fmt --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass after the
  approved CLI boxing change.
- `cargo test -p av-core -p xtask`: 82 passed (75 av-core, 7 xtask), 0 failed.
- `cargo test --workspace`: 115 passed, 0 failed, 0 ignored.
- `cargo xtask mutation --scoped`: 86/86 caught, 0 missed or invalid
  (83 av-core, 3 existing av-store entries); full output is in
  `MUTATION-ROUND2-RESULTS.txt`.

The first mutation attempt correctly refused its baseline because the new
live Node test assumed the JS tree existed in the mutation copy. Like the
existing live placeholder test, it now skips regeneration when the read-only
reference tree is absent; checked-in differential vectors remain exercised in
all copies. The completed 86-entry run used this corrected baseline.

