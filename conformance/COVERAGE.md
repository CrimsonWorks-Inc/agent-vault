# Security coverage

Each file in `test/security/` and where its externally observable behavior shows up in this suite. "Internal only" means the assertion cannot be seen from the control socket, the gateway, MCP, the CLI, or the UI server `agent-vault ui` starts. A behavior that those surfaces do show is named in a conformance test, even when the security file also has a unit helper. This is not a line-by-line port of those tests.

The conformance tests named below live in `conformance/*.test.js`.

| File | Where the observable behavior is covered |
| --- | --- |
| approval-verdict.test.js | gateway: an on-write request is held, then runs once when granted and stays refused when denied. The in-process verdict table is internal only. |
| audit-content.test.js | control: audit, templates, tripwires, listeners, tls, notify, ui, presence. lifecycle: lock, unlock, revocation, panic, and audit. Record-shape unit checks are internal only. |
| bridge.test.js | mcp: stdio bridge proxies a session and refuses to start without one. cli: a command against a directory with no daemon is unreachable (exit 9). |
| budget-reader.test.js | Internal only: the budget reader is a pure function. The number it produces is what control "sessions, placeholders, narrowing and detail" and gateway "preflight predicts" read back as `budget.used`. |
| carrier.test.js | gateway: substitution only at the declared authorization site. bodies: a JSON pointer, a form field, and a GraphQL variable (`json:/variables/token`) are substituted only where that site is declared. |
| cli.test.js | cli: setup, status, doctor, profiles, and help; credentials, sessions, placeholders, env, and preflight. Root-only and state-file tamper cases are internal only (this suite never runs as root and never rewrites another process's state parser). |
| connectors-health.test.js | Internal only: connector health records. cred test's observable refusal is control "credential record routes" (`no_probe`) and cli "templates, credential record commands". |
| connectors-pinning.test.js | Internal only: SPKI pin parsing. The control pin route is control "credential record routes" and cli cred pin. |
| connectors-probe.test.js | Observable refusal: control "credential record routes" and cli cred test (`no_probe` / exit 7, `--all` exit 0). Probe URL construction and the 60-second clock are internal only. |
| control-api-backup-audit.test.js | lifecycle: backup export, inspect, and restore round trip; lock, unlock, revocation, panic, and audit. |
| control-api-c18.test.js | control listeners and gateway host confinement. Per-listener session usability beyond loopback is internal only (no non-loopback bind in this suite). |
| control-api-containment.test.js | control quarantine/release; cli panic; lifecycle panic and revocation. |
| control-api-credentials.test.js | control: credentials, and credential record routes. |
| control-api-helpers.js | Helper, not a test. |
| control-api-mcp.test.js | mcp: handshake, tool schemas, and one call of every tool; dead token; notification stream. |
| control-api-notify.test.js | control notify routes; cli notify set/show/test/off. The webhook body shows the host, not the path. |
| control-api-overrides.test.js | control session narrow; cli session narrow and approve/deny. Override parsing internals are internal only. |
| control-api-sessions.test.js | control: sessions, placeholders, narrowing and detail; revoking a session removes it. |
| control-api-templates.test.js | control templates; cli template save/list/show/rm. |
| control-cli-fifo.test.js | Internal only: FIFO and exclusive-write helpers under `src/cli/files.js`. |
| control-cli-files.test.js | cli env and exec. Exclusive-create races are internal only. |
| control-cli-overrides.test.js | cli approve/deny. Flag parsing shared with the UI is internal only. |
| control-cli-routes.test.js | cli: the command envelopes, usage exit 2, unreachable exit 3, placeholder exit 8. |
| control-cli-watch.test.js | cli: daemon, ui, docs, and watch start and stop. Desktop-notification text is internal only. |
| control-gate.test.js | control: a first passphrase is open, and later widening is refused without it. lifecycle passphrase throttle. |
| control-ui-docs.test.js | ui: `/api/docs/context` returns the gateway port, the credential slug, and an mcp url, and no secret. Page copy is internal only: it is not a protocol. |
| control-ui-guard.test.js | ui: a foreign Host is 403, loopback is redirected to localhost, a foreign Origin is 403, a missing cookie is 401, a POST without `X-AV-UI` is 403, and a label's placeholder and `avs1` token become `«placeholder»` and `«token»` while ordinary text stays. |
| control-ui-handoff.test.js | cli approve, which collects a session. The UI handoff page is internal only. |
| control-ui-helpers.js | Helper, not a test. |
| control-ui-narrowing.test.js | Internal only: UI narrowing form. The daemon narrow route is control "sessions, placeholders, narrowing and detail". |
| control-ui-page.test.js | Internal only: UI page state. |
| control-ui-rotate.test.js | Internal only: UI rotation signature. Daemon rotate is control "credential record routes". |
| control-ui-routes.test.js | Observable slice: control quarantine (open) and lifecycle panic. The signed UI routes are internal only. |
| control-ui-webauthn.test.js | Internal only: UI WebAuthn ceremony. Daemon enrollment is control "presence enrollment and a touch-id wrap". |
| exfil.test.js | exfil: the eight cases, each its own test. A session cannot aim at a host the credential does not permit; a confined session cannot be pointed at a catcher; the catcher never receives the secret; widening with no passphrase is audited; unlock and removing the last factor match the daemon; minting capability or a placeholder without presence is refused; a presence window can still issue a placeholder. |
| fix-control-approvals.test.js | gateway approval hold, grant, replay, and deny; control approval refusals (missing id, non-boolean). |
| fix-control-audit.test.js | Internal only: torn audit lines and anchor files. The intact chain is lifecycle "lock, unlock, revocation, panic, and audit". |
| fix-control-cli.test.js | cli env, exec, mcp url, backup export's exit 5, and the stdio bridge. |
| fix-control-factors.test.js | lifecycle: passphrase set/remove refusal of the last factor; control passphrase gate. |
| fix-control-helpers.js | Helper, not a test. |
| fix-control-ledger.test.js | gateway: once the live ledger rotates, the oldest placeholder is `AV_PH_STALE` and the newest still returns ordinary traffic. ttl math that writes the store directly is internal only. |
| fix-control-listeners.test.js | control listeners: loopback without TLS is stored, a non-loopback address without TLS is `AV_REMOTE_FORBIDDEN`, a bad address is refused. |
| fix-control-mcp.test.js | mcp handshake, schemas, dead token header, and stdio bridge. |
| fix-control-page.test.js | Internal only: UI page behavior. |
| fix-control-presence.test.js | control presence routes: counter not settable, factor order, challenge without an authenticator, window ungated. |
| fix-control-process.test.js | control: malformed JSON and an unknown route do not take the daemon down. |
| fix-control-session-requests.test.js | control session requests (collect secret not listed, wrong secret refused, approve/deny); mcp `vault_request_session`. Anonymous initialize writing nothing is not separately asserted. |
| fix-control-store.test.js | Internal only: store invariants under the daemon. |
| fix-control-touchid.test.js | control: presence enrollment and the Touch ID wrap, including the factor-order refusal before a passphrase. UI tap ceremonies are internal only. |
| fix-control-uicookie.test.js | ui: the launch link sets `av_ui` once, HttpOnly, SameSite=Strict, Path=/, and a second use is 409. Cookie crypto is internal only. |
| fix-control-webauthn.test.js | Internal only: WebAuthn assertion binding. The daemon enroll route is the control presence test. |
| gateway-approvals.test.js | gateway: held write, grant once, replay, deny. Header-order and Basic-auth hash cases are internal only. |
| gateway-core.test.js | gateway substitution, scrub, bad location, and discovery. |
| gateway-hardening.test.js | paths: percent-encoded, double-encoded, dot-segment, backslash, and overlong spellings against a path glob. scrub: gzip, deflate, brotli, a secret split across chunks, a secret split across event-stream events (the stream is cut with `AV_UNSCANNABLE`), and the same encodings in a plain-text body. A four-layer decode stack is not asserted. |
| gateway-helpers.js | Helper, not a test. |
| gateway-response.test.js | scrub: a secret in a header name or value, a redirect Location, a gzip, deflate, or brotli body, a chunked body, and an event stream. An encoding the daemon cannot read is 502 `AV_UNSCANNABLE` rule `content_encoding`, and the body is discarded. |
| gateway-routing.test.js | gateway host confinement and `/p/<slug>` substitution. Route-parser units are internal only. |
| gateway-w2-model.test.js | Internal only: policy model objects. Host ceiling shows up as gateway "host confinement". |
| gateway-w2-payload.test.js | bodies: JSON, form, and a GraphQL variable, plus an operation allowlist (`payload.graphql`) that refuses a mutation and a denied field while a query is forwarded. Parser helpers that never reach a grant are internal only. |
| gateway-w2-pipeline.test.js | gateway substitution, budget, and approval. |
| gateway-w2-policy.test.js | Internal only: route-policy intersection. Budget 0 is control "sessions, placeholders, narrowing and detail". |
| gateway-w2-scrub.test.js | scrub: a stored pattern redacts a gateway response, and plain-text encodings of the secret are removed while ordinary percent-encoding stays. Regex timing is internal only. |
| gateway-w2-seams.test.js | gateway preflight does not spend or create an approval; discovery routes. |
| installer.test.js | cli setup does not run sudo and `upgrade --json` exits 2 when there is no system install. The installer itself is internal only (this suite never runs it and never uses sudo). |
| integrate2-c12-surfaces.test.js | control listener refusal off loopback without TLS. Infinite-plus-remote session creation is not given its own test. |
| integrate2-seams.test.js | gateway and control session routes. Seam unit tests are internal only. |
| integrate3-c25.test.js | Internal only: audit field allowlists. The suite checks that audit JSON and CLI audit output do not contain the secret (hardening, lifecycle). |
| integrate3-e2e-approvals.test.js | gateway approval flow; cli approve and deny. |
| integrate3-e2e-gateway.test.js | gateway substitution, scrub, and confinement. |
| integrate3-e2e-helpers.js | Helper, not a test. |
| integrate3-e2e-preflight.test.js | gateway: preflight predicts and does not spend a budget or create an approval. cli preflight exits 0 or 10. |
| integrate3-e2e-sessions.test.js | control sessions and lifecycle revocation. |
| integrate3-e2e-templates.test.js | control and cli templates. |
| integrate3-fix1.test.js | control session requests and gateway approvals. |
| integrate3-gates.test.js | control passphrase gate; lifecycle lock. |
| integrate3-helpers.js | Helper, not a test. |
| integrate3-narrowing.test.js | control session narrow. |
| integrate3-r4.test.js | control listeners, tls ensure, and notify. |
| integrate3-r5.test.js | mcp `vault_explain_denial`; cli mcp install `--print` does not write a config. Denial-sentence storage details are internal only. |
| integrate3-r6.test.js | control tripwires and lifecycle panic. |
| integrate3-seams.test.js | gateway discovery and mcp initialize. |
| invariants.test.js | hardening: the secret is absent from gateway, MCP, CLI, and audit output. Cross-module constant checks are internal only. |
| listener.test.js | control listeners. |
| locked.test.js | lifecycle: lock, unlock, audit 423 while locked, status does not report zero audit records. |
| mcp-tools.test.js | mcp: one call of every tool, including schema `required` lists. |
| mcp.test.js | mcp handshake, protocol versions, Origin refusal, dead token, DELETE, and the stdio bridge. |
| one-source-of-truth.test.js | Internal only: shared parser identity between CLI and UI. cli approve/deny exercises the daemon side of a decision. |
| path-parsing.test.js | paths: allowed spellings reach the upstream at the normalized path; a glob escape, a double encoding, an encoded separator, a raw backslash that leaves the glob, an invalid percent-escape, and a control character are refused with the daemon's status and rule, and the upstream is not called. `encodePathForWire` as a pure function is internal only. |
| pipeline.test.js | gateway (substitution, bad location, confinement, budget, approval, Origin, method-override header and `_method` field), lifecycle (revoke, lock, audit), scrub. One-time placeholder concurrency, refund accounting, and body cuts are internal only: they are store counters, not a response. |
| remote.test.js | control: a non-loopback listener without TLS is `AV_REMOTE_FORBIDDEN`. Placeholder-as-carrier on a real network listener is internal only here. |
| requested-c3.test.js | Internal only: elevation labels stored on a session. Creating an ordinary session is control "sessions". |
| requested-r1.test.js | control session requests: asking creates a pending request, and a human decision settles it. |
| requested-r2.test.js | control session requests and cli approve. |
| requested-r3.test.js | control bulk `decide-many` and the empty-decisions refusal. |
| requested-seams.test.js | control session requests. Restart persistence is internal only. |
| requested-ui.test.js | Internal only: the requests page. The daemon routes are control "session requests". |
| response.test.js | scrub: headers, redirect Location, compressed bodies, chunked and event-stream splits, an unknown content-encoding, and plain-text encodings. Each allowed response keeps its ordinary text. |
| revocation.test.js | lifecycle revocation and panic; control "revoking a session removes it". |
| serving.test.js | paths: the vault directory is mode 0700 and the control socket is mode 0600. ui: the dist allowlist and traversal. Listener address classification that never binds a socket is internal only. |
| session-requests.test.js | control session requests, including the collect secret staying off the list. |
| store-activity.test.js | Internal only: activity summarizer. Session detail's public shape is control "sessions, placeholders, narrowing and detail". |
| store-audit-witness.test.js | Internal only: witness MAC and tamper cases. cli `audit witness` plus `audit verify --witness` covers the happy path. |
| store-backup.test.js | Internal only: bundle bytes. The round trip is lifecycle "backup export, inspect, and restore". |
| store-helpers.js | Helper, not a test. |
| store-notify.test.js | Internal only: webhook URL validator unit. The route is control notify and cli notify. |
| store-pins.test.js | Internal only: pin list storage. The route is control "credential record routes". |
| store-review-r2.test.js | Internal only: restore atomicity and grant copying. The successful restore is the lifecycle backup test. |
| store-review-r3.test.js | Internal only: quarantine preserved across restore. Quarantine on the live vault is control "credential record routes". |
| store-rotate.test.js | Internal only: rotation bookkeeping. The route is control "credential record routes" (a new value; the same value is refused). |
| store-scrub.test.js | control scrub (`zzz[0-9]{8,16}` matches, `.*` is `scrub_pattern`) and scrub: that pattern redacts a gateway response while ordinary text stays. The bytes on disk are internal only. |
| store-slice-a.test.js | Internal only: early store slice. |
| store-templates.test.js | Internal only: template hash storage. The route is control and cli templates. |
| ui-audit-growth.test.js | Internal only: UI audit list growth. |
| ui-audit-paging.test.js | Internal only: UI audit paging. Control audit `?before=` refusal is the control audit test. |
| ui-complete-lists.test.js | Internal only: UI list completeness. |
| ui-dist-serving.test.js | ui: CSP, no-store, nosniff, no-referrer, an allowlisted asset is served, and a file outside the allowlist or a traversal is 404. |
| ui-paging.test.js | Internal only: UI paging. |
| ui.test.js | ui: launch cookie, CSP, allowlist, Host and Origin, and redaction of a placeholder and a session token on `/api/sessions`. WebAuthn ceremonies need a stub authenticator and are internal only. |
| wave1-compose.test.js | gateway approval replay (a spent approval runs once). Bulk spent-approval bookkeeping is internal only. |
| webauthn.test.js | Internal only: WebAuthn crypto. Daemon enroll and the counter refusal are the control presence tests. |
| widening.test.js | control: a first passphrase is open, and later widening is refused without it. |
