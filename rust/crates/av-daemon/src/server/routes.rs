//! Every route of `#onControl` in `src/daemon/server.js`, in the JS order.
//! Each answers `(status, body)`; a refusal is the `VaultError` the JS threw.

use std::sync::Arc;

use av_core::policy::{self, Checked};
use av_core::secret::{ExposeSecret, SecretString};
use av_store::model::{QuarantineBy, SessionState};
use av_store::vault::{IssueOptions, NewCredential, NewListener, QuarantineOptions, RotateMode, RotateOptions, UnlockMaterial};
use serde_json::{json, Map, Value};

use super::*;

const MIN_SECRET_LEN: usize = av_core::scrub::MIN_SECRET_LEN;

fn short_warning() -> String {
    format!(
        "this value is under {MIN_SECRET_LEN} characters, so it is only scrubbed from responses to requests that used it; another credential's response could echo it back to the agent unredacted"
    )
}

fn str_of(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

fn truthy_str(v: Option<&Value>) -> Option<String> {
    v.filter(|x| crate::util::truthy(x)).map(js_string)
}

/// `reportSince(raw)`.
fn report_since(raw: Option<String>) -> R<String> {
    let text = raw.unwrap_or_else(|| "7d".into());
    if let Some(unit) = text.chars().last().filter(|c| *c == 'd' || *c == 'h') {
        let n = &text[..text.len() - 1];
        if !n.is_empty() && n.len() <= 5 && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()) {
            let n: i64 = n.parse().unwrap_or(0);
            let ms = n * if unit == 'd' { 86_400_000 } else { 3_600_000 };
            return Ok(iso_of_ms(now_ms() - ms));
        }
    }
    let b = text.as_bytes();
    let dated = b.len() >= 10 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[5..7].iter().all(u8::is_ascii_digit) && b[7] == b'-' && b[8..10].iter().all(u8::is_ascii_digit);
    if dated {
        if let Some(ms) = crate::util::parse_iso_ms(&text) {
            return Ok(iso_of_ms(ms));
        }
    }
    Err(dr(C::PolicyDenied, "since is an ISO date, or a span like 7d or 24h", "report_since"))
}

/// `wholeParam(raw, fallback, name)`.
fn whole_param(raw: Option<String>, fallback: u64, name: &str) -> R<u64> {
    let Some(raw) = raw else { return Ok(fallback) };
    let ok = raw == "0" || (!raw.is_empty() && raw.len() <= 16 && !raw.starts_with('0') && raw.bytes().all(|b| b.is_ascii_digit()));
    if !ok {
        return Err(dr(C::PolicyDenied, format!("{name} must be a whole number"), "audit_range"));
    }
    Ok(raw.parse().unwrap_or(0))
}

fn audit_kind_ok(k: &str) -> bool {
    !k.is_empty() && k.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
}

/// `auditRows(audit, params)`.
fn audit_rows(core: &mut Core, query: &str) -> R<Value> {
    let p = |k: &str| search_param(query, k);
    let kind = p("kind");
    if kind.as_deref().is_some_and(|k| !audit_kind_ok(k)) {
        return Err(dr(C::PolicyDenied, "kind is a record kind, like tripwire.fired", "audit_range"));
    }
    let (before, after) = (p("before"), p("after"));
    let log = core.vault.audit().ok_or_else(|| d(C::Locked, "the audit log is encrypted; unlock the vault to read it"))?;
    let read = |limit: usize| -> R<Vec<Value>> {
        let rows = log.read(&av_store::audit::ReadFilter { limit, ..Default::default() }).v()?;
        Ok(rows.into_iter().map(|r| serde_json::to_value(r).unwrap_or(Value::Null)).collect())
    };
    let of_kind = |rows: Vec<Value>| -> Vec<Value> {
        match &kind {
            None => rows,
            Some(k) => rows
                .into_iter()
                .filter(|r| r["kind"].as_str().is_some_and(|rk| rk == k || rk.starts_with(&format!("{k}."))))
                .collect(),
        }
    };
    if before.is_none() && after.is_none() && kind.is_none() {
        // The old lenient reading: Number(limit || 30).
        let raw = p("limit").filter(|s| !s.is_empty()).unwrap_or_else(|| "30".into());
        let n = raw.trim().parse::<f64>().unwrap_or(f64::NAN);
        let limit = if n.is_nan() { 0 } else if n.is_infinite() { usize::MAX } else { n.max(0.0) as usize };
        return Ok(Value::Array(read(limit)?));
    }
    if before.is_some() && after.is_some() {
        return Err(dr(C::PolicyDenied, "give before or after, not both", "audit_range"));
    }
    let limit_raw = p("limit");
    if let Some(l) = &limit_raw {
        let ok = !l.is_empty() && l.len() <= 3 && !l.starts_with('0') && l.bytes().all(|b| b.is_ascii_digit()) && l.parse::<usize>().is_ok_and(|n| n <= AUDIT_PAGE_MAX);
        if !ok {
            return Err(dr(C::PolicyDenied, format!("limit must be a whole number from 1 to {AUDIT_PAGE_MAX}"), "audit_range"));
        }
    }
    let all = of_kind(read(usize::MAX)?);
    if before.is_none() && after.is_none() {
        let n = limit_raw.as_deref().map_or(30, |l| l.parse().unwrap_or(30));
        let start = all.len().saturating_sub(n);
        return Ok(Value::Array(all[start..].to_vec()));
    }
    let limit = limit_raw.as_deref().map_or(100, |l| l.parse().unwrap_or(100));
    let name = if before.is_some() { "before" } else { "after" };
    let at = whole_param(before.clone().or(after.clone()), 0, name)?;
    let rows: Vec<Value> = all.into_iter().filter(|r| r["seq"].as_u64().is_some()).collect();
    if before.is_some() {
        let older: Vec<Value> = rows.into_iter().filter(|r| r["seq"].as_u64().unwrap_or(0) < at).collect();
        let start = older.len().saturating_sub(limit);
        Ok(Value::Array(older[start..].to_vec()))
    } else {
        Ok(Value::Array(rows.into_iter().filter(|r| r["seq"].as_u64().unwrap_or(0) > at).take(limit).collect()))
    }
}

fn whole_session_fields(s: &av_store::model::SessionRecord) -> Value {
    json!({"id": s.id, "label": s.label, "expires_at": s.expires_at, "infinite": s.infinite})
}

impl Daemon {
    /// One control route.
    pub(crate) async fn control_route(self: &Arc<Self>, route: &str, query: &str, input: Value) -> R<(u16, Value)> {
        let q = |k: &str| search_param(query, k);
        let presence = input.get("presence").cloned();
        let op = Daemon::widening_operation(route, query, &input);
        let port = self.gateway_port().unwrap_or(0);
        match route {
            "GET /v1/status" => {
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let mut out = json!({"daemon_version": VERSION, "gateway_port": port});
                        if let Value::Object(m) = serde_json::to_value(core.vault.stats().v()?).unwrap_or(json!({})) {
                            for (k, v) in m {
                                out[&k] = v;
                            }
                        }
                        Ok(out)
                    })
                    .await??;
                Ok((200, v))
            }

            "POST /v1/credentials" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred add", op?, presence).await?;
                let v = self.shared.run(move |core| add_credential(core, &input)).await??;
                Ok((200, v))
            }
            "GET /v1/credentials" => Ok((200, self.shared.run(|core| core.vault.list_credentials().v().map(|v| json!(v))).await??)),
            "DELETE /v1/credentials" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred delete", op?, presence).await?;
                let slug = q("slug").unwrap_or_else(|| "null".into());
                self.shared.run(move |core| core.vault.delete_credential(&slug).v()).await??;
                Ok((200, json!({"ok": true})))
            }

            "POST /v1/sessions" => {
                let i2 = input.clone();
                let plan = self.shared.run(move |core| core.dm_plan_session(&i2, false, false)).await??;
                self.gate_session("session create", op?.unwrap_or(Value::Null), &plan.elevated, presence).await?;
                let v = self.shared.run(move |core| core.dm_make_session(&plan, None, false)).await??;
                Ok((200, v))
            }

            "POST /v1/session-requests" => {
                let (record, secret) = self.propose_session_request(input).await?;
                let id = record["id"].as_str().unwrap_or("").to_string();
                let mut out = record;
                out["collect_secret"] = secret.into();
                out["next"] = json!({
                    "agent": "poll GET /v1/session-requests/collect?id=<id>&secret=<collect_secret> until a human answers",
                    "human": ["agent-vault approvals", format!("agent-vault approve {id}")],
                });
                Ok((200, out))
            }
            "GET /v1/session-requests" => Ok((200, self.shared.run(|core| Value::Array(core.sr_pending().iter().map(|r| r.redact()).collect())).await?)),
            "GET /v1/session-requests/collect" => {
                let (id, secret) = (q("id"), q("secret"));
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let record = id.as_deref().and_then(|i| core.sr_get(i)).ok_or_else(|| d(C::NotFound, "no such session request"))?;
                        if !record.may_collect(secret.as_deref()) {
                            return Err(dr(C::PolicyDenied, "that is not the secret this request was opened with", "collect_secret")
                                .hinted("Only the agent that asked can collect: pass the collect_secret it was given as &secret=."));
                        }
                        if record.state == "pending" {
                            return Ok(json!({"state": "pending"}));
                        }
                        if record.state == "denied" {
                            return Ok(json!({"state": "denied"}));
                        }
                        if record.result.is_none() {
                            return Ok(json!({"state": record.state, "detail": "the answer is no longer available; ask again"}));
                        }
                        let result = core.dm_hand_over(&record.id, "collect").unwrap_or(json!({}));
                        let mut out = json!({"state": "approved"});
                        if let Value::Object(m) = result {
                            for (k, v) in m {
                                out[&k] = v;
                            }
                        }
                        Ok(out)
                    })
                    .await??;
                Ok((200, v))
            }
            "POST /v1/session-requests/decide" => {
                if !field(&input, "granted")?.is_some_and(Value::is_boolean) {
                    return Err(dr(C::PolicyDenied, "the verdict must be true or false", "bulk_decision"));
                }
                if let Some(problem) = overrides_problem(input.get("overrides")) {
                    return Err(dr(C::PolicyDenied, problem, "session_overrides"));
                }
                let i2 = input.clone();
                let (record, final_, elevated, operation) = self
                    .shared
                    .run(move |core| -> R<_> {
                        let id = i2.get("id").map(js_string).unwrap_or_else(|| "undefined".into());
                        let record = core.sr_get(&id).ok_or_else(|| d(C::NotFound, format!("no session request {id}")))?;
                        if record.state != "pending" {
                            return Err(dr(C::PolicyDenied, format!("that request was already {}", record.state), "session_requests"));
                        }
                        let ov = overrides_of(i2.get("overrides").unwrap_or(&json!({})));
                        let final_ = merge(&record.proposal, &ov);
                        let granted = i2["granted"] == Value::Bool(true);
                        let mut params = json!({"id": record.id, "granted": granted});
                        if let Value::Object(m) = &ov {
                            for (k, v) in m {
                                params[k] = v.clone();
                            }
                        }
                        let operation = crate::util::operation_for("session_request.decide", &params)?;
                        let elevated = if granted { elevation_of(&final_) } else { Vec::new() };
                        Ok((record, final_, elevated, operation))
                    })
                    .await??;
                self.gate_session("session request approval", operation, &elevated, presence).await?;
                let granted = input["granted"].clone();
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let id = record.id.clone();
                        let mut settled = core.dm_settle_session_request(record, &granted, final_)?;
                        if granted == Value::Bool(true) && core.sr.find_mut(&id).is_some_and(|r| r.result.is_some()) {
                            settled["session"] = core.dm_hand_over(&id, "decide").unwrap_or(Value::Null);
                        }
                        Ok(settled)
                    })
                    .await??;
                Ok((200, v))
            }
            "POST /v1/pending/decide-many" => {
                let decisions = if input.is_object() { input.get("decisions").cloned().unwrap_or(Value::Null) } else { Value::Null };
                if let Some(problem) = av_store::pending::check_decisions(&decisions) {
                    return Err(dr(C::PolicyDenied, problem, "bulk_decision"));
                }
                let list = decisions.as_array().cloned().unwrap_or_default();
                for dd in &list {
                    let unread = if dd.get("kind").and_then(Value::as_str) == Some("session") {
                        overrides_problem(dd.get("overrides"))
                    } else if dd.get("overrides").is_some_and(|o| o.as_object().is_some_and(|m| !m.is_empty()) || (!o.is_null() && !o.is_object() && crate::util::truthy(o) && o.is_array() && !o.as_array().is_some_and(Vec::is_empty))) {
                        Some(format!("{} is a held request, which takes no narrowing; nothing was decided", js_string(&dd["id"])))
                    } else {
                        None
                    };
                    if let Some(u) = unread {
                        return Err(dr(C::PolicyDenied, u, "session_overrides"));
                    }
                }
                let l2 = list.clone();
                let elevated = self
                    .shared
                    .run(move |core| {
                        l2.iter().any(|dd| {
                            if dd.get("kind").and_then(Value::as_str) != Some("session") || dd.get("granted") != Some(&Value::Bool(true)) {
                                return false;
                            }
                            let id = dd.get("id").map(js_string).unwrap_or_default();
                            let Some(r) = core.sr_get(&id).filter(|r| r.state == "pending") else { return false };
                            !elevation_of(&merge(&r.proposal, &overrides_of(dd.get("overrides").unwrap_or(&json!({}))))).is_empty()
                        })
                    })
                    .await?;
                let operation = crate::util::operation_for("pending.decide_many", &json!({"decisions": decisions}))?;
                let elevated = if elevated { vec!["approval_auto_writes".to_string()] } else { Vec::new() };
                self.gate_session("bulk decision", operation, &elevated, presence).await?;
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let known: Vec<String> = list.iter().filter(|dd| core.dm_knows(dd)).map(|dd| js_string(&dd["id"])).collect();
                        let mut decided: Vec<Value> = Vec::new();
                        for dd in &list {
                            let mut row = Map::new();
                            row.insert("id".into(), dd.get("id").cloned().unwrap_or(Value::Null));
                            row.insert("kind".into(), dd.get("kind").cloned().unwrap_or(Value::Null));
                            match core.dm_settle_one(dd) {
                                Ok(r) => {
                                    row.insert("outcome".into(), "decided".into());
                                    row.insert("result".into(), r);
                                }
                                Err(e) => {
                                    row.insert("outcome".into(), "skipped".into());
                                    row.insert("reason".into(), e.detail.clone().into());
                                }
                            }
                            decided.push(Value::Object(row));
                        }
                        let granted: Vec<usize> = decided
                            .iter()
                            .enumerate()
                            .filter(|(_, r)| r["kind"] == "session" && r["outcome"] == "decided" && r["result"]["state"] == "approved")
                            .map(|(i, _)| i)
                            .collect();
                        if granted.len() == 1 {
                            let id = js_string(&decided[granted[0]]["id"]);
                            if core.sr.find_mut(&id).is_some_and(|r| r.result.is_some()) {
                                decided[granted[0]]["result"]["session"] = core.dm_hand_over(&id, "decide").unwrap_or(Value::Null);
                            }
                        }
                        let logged = |dd: &Value| known.contains(&js_string(&dd["id"]));
                        core.audit_opt(
                            "pending.decided_many",
                            json!({
                                "granted": list.iter().filter(|dd| crate::util::truthy(dd.get("granted").unwrap_or(&Value::Null)) && logged(dd)).map(|dd| dd["id"].clone()).collect::<Vec<_>>(),
                                "denied": list.iter().filter(|dd| !crate::util::truthy(dd.get("granted").unwrap_or(&Value::Null)) && logged(dd)).map(|dd| dd["id"].clone()).collect::<Vec<_>>(),
                                "skipped": decided.iter().filter(|r| r["outcome"] == "skipped" && logged(r)).map(|r| r["id"].clone()).collect::<Vec<_>>(),
                                "unknown": list.iter().filter(|dd| !logged(dd)).count(),
                            }),
                        );
                        Ok(json!({"decided": decided}))
                    })
                    .await??;
                Ok((200, v))
            }

            "GET /v1/sessions" => {
                let v = self
                    .shared
                    .run(|core| -> R<Value> {
                        let mut out = Vec::new();
                        for s in core.vault.sessions().v()? {
                            let grants = core.vault.grants_for_session(&s.id).v()?;
                            let mut creds = Vec::new();
                            let mut eg = Vec::new();
                            for g in &grants {
                                let slug = core.vault.credential(&g.credential_id).v()?.map(|c| c.slug);
                                creds.push(json!({"slug": slug, "grant_id": g.id, "approval": g.policy.approval, "methods": g.policy.methods}));
                                let mut e = json!({"approval": g.policy.approval.clone().map_or(Value::from("auto"), |a| serde_json::to_value(a).unwrap_or(Value::Null))});
                                if let Some(m) = &g.policy.methods {
                                    e["methods"] = serde_json::to_value(m).unwrap_or(Value::Null);
                                }
                                if let Some(r) = &g.policy.routes {
                                    e["routes"] = serde_json::to_value(r).unwrap_or(Value::Null);
                                }
                                eg.push(e);
                            }
                            let state = serde_json::to_value(s.state).unwrap_or(Value::Null);
                            out.push(json!({
                                "id": s.id, "label": s.label, "state": state, "expires_at": s.expires_at, "remote": s.remote,
                                "created_at": s.created_at, "grants": grants.len(), "creds": creds, "infinite": s.infinite,
                                "elevated": elevation_of(&json!({"infinite": s.infinite, "grants": eg})),
                            }));
                        }
                        Ok(Value::Array(out))
                    })
                    .await??;
                Ok((200, v))
            }
            "DELETE /v1/sessions" => {
                let sid = q("sid").unwrap_or_else(|| "null".into());
                self.shared.run(move |core| core.vault.revoke_session(&sid, "revoked").v()).await??;
                Ok((200, json!({"ok": true})))
            }

            "POST /v1/placeholders" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("placeholder issue", op?, presence).await?;
                let v = self.shared.run(move |core| issue_one(core, &input)).await??;
                Ok((200, v))
            }
            "POST /v1/placeholders/batch" => {
                batch_shape(&input)?;
                let presence = field(&input, "presence")?.cloned();
                self.require_human("placeholder issue", op?, presence).await?;
                let v = self.shared.run(move |core| issue_batch(core, &input, port)).await??;
                Ok((200, v))
            }

            "GET /v1/approvals" => Ok((200, Value::Array(self.pipeline.pending_approvals().await))),
            "POST /v1/approvals" => {
                let Some(granted) = field(&input, "granted")?.and_then(Value::as_bool) else {
                    return Err(dr(C::PolicyDenied, "the verdict must be true or false", "bulk_decision"));
                };
                self.require_human(if granted { "approval grant" } else { "approval deny" }, op?, presence).await?;
                let id = input.get("id").map(js_string).unwrap_or_else(|| "undefined".into());
                Ok((200, self.pipeline.decide_approval(id, granted).await?))
            }

            "GET /v1/audit" => {
                let query = query.to_string();
                Ok((200, self.shared.run(move |core| audit_rows(core, &query)).await??))
            }
            "GET /v1/audit/verify" => Ok((
                200,
                self.shared
                    .run(|core| -> R<Value> {
                        let log = core.vault.audit().ok_or_else(|| d(C::Locked, "the audit log is encrypted; unlock the vault to verify it"))?;
                        Ok(serde_json::to_value(log.verify().v()?).unwrap_or(Value::Null))
                    })
                    .await??,
            )),

            "GET /v1/listeners" => Ok((200, self.shared.run(|core| core.vault.list_listeners().v().map(|l| json!(l))).await??)),
            "POST /v1/listeners" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("listener add", op?, presence).await?;
                let address = input.get("address").map(js_string).unwrap_or_default();
                let (host, _) = parse_address(if input.get("address").is_some_and(|a| !a.is_null()) { &address } else { "" })
                    .map_err(|e| dr(C::NotFound, e, "listener_address").hinted("An address is <host>:<port>, for example 127.0.0.1:7443."))?;
                parse_allow_cidr(input.get("allow_cidr")).map_err(|e| {
                    dr(C::PolicyDenied, e, "listener_allow_cidr").hinted("Each entry is <address>/<prefix>, for example 100.64.0.0/10 or fd7a:115c:a1e0::/48.")
                })?;
                if !is_loopback_host(&host) && !input.get("tls").is_some_and(crate::util::truthy) {
                    return Err(dr(C::RemoteForbidden, format!("listener {} is on a network address and has no TLS", input.get("id").map_or("undefined".into(), js_string)), "listener_tls")
                        .hinted("Plaintext off loopback would put session tokens and substituted credentials on the wire. Add --tls managed."));
                }
                let entry: NewListener = serde_json::from_value(without_presence(&input)).map_err(|e| internal(e.to_string()))?;
                Ok((200, self.shared.run(move |core| core.vault.add_listener(entry).v().map(|l| json!(l))).await??))
            }
            "DELETE /v1/listeners" => {
                let lid = q("id").unwrap_or_else(|| "null".into());
                let l2 = lid.clone();
                self.shared.run(move |core| core.vault.remove_listener(&l2).v()).await??;
                let unbound = self.unbind_listener(&lid).await;
                Ok((200, json!({"ok": true, "unbound": unbound})))
            }

            "GET /v1/presence" => Ok((200, self.shared.run(|core| core.vault.presence_key().v().map(|k| json!(k))).await??)),
            "POST /v1/presence" => {
                let existed_pass = self.shared.run(|core| -> R<(bool, bool)> { Ok((core.vault.presence_key().v()?.is_some(), core.vault.has_passphrase().v()?)) }).await??;
                field(&input, "presence")?;
                if !existed_pass.0 && !existed_pass.1 {
                    return Err(dr(C::PolicyDenied, "set a passphrase before enrolling an authenticator", "factor_order")
                        .hinted("agent-vault passphrase set. The passphrase is the recovery factor, and enrolling first would let whoever enrolled lock everyone else out.")
                        .next(Value::from("agent-vault passphrase set")));
                }
                self.require_fresh("presence enroll", op?.unwrap_or(Value::Null), presence).await?;
                let rec = without_proof(&input);
                let replaced = self.shared.run(move |core| core.vault.set_presence_key(&rec).v()).await??;
                Ok((200, json!({"ok": true, "replaced": replaced})))
            }
            "PATCH /v1/presence" => Err(dr(C::PolicyDenied, "the signature counter is not settable; the daemon maintains it from assertions it verifies itself", "counter_not_settable")),

            "POST /v1/lock" => {
                self.shared
                    .run(|core| -> R<()> {
                        core.vault.lock().v()?;
                        core.dm.presence_grace_until = 0;
                        Ok(())
                    })
                    .await??;
                Ok((200, json!({"ok": true, "locked": true})))
            }

            "GET /v1/ui" => Ok((200, self.shared.run(|core| json!({"port": core.dm.ui_port, "origins": core.dm_ui_origins()})).await?)),
            "POST /v1/ui/origins" => {
                let origin = field(&input, "origin")?.filter(|o| crate::util::truthy(o)).map(js_string).unwrap_or_default();
                if !ui_origin_ok(&origin) {
                    return Err(dr(C::PolicyDenied, format!("not a web UI origin: {}", input.get("origin").map_or("undefined".into(), crate::util::js_stringify)), "ui_origin")
                        .hinted("The UI is served on loopback under the name the authenticator is bound to: http://localhost:<port>."));
                }
                self.require_fresh("ui origin add", op?.unwrap_or(Value::Null), presence).await?;
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        core.vault.add_ui_origin(&origin).v()?;
                        core.audit_opt("ui.origin_added", json!({"origin": origin}));
                        Ok(json!({"ok": true, "origins": core.dm_ui_origins()}))
                    })
                    .await??;
                Ok((200, v))
            }

            "POST /v1/unlock" => self.unlock(input).await,
            "GET /v1/unlock/webauthn-params" => Ok((
                200,
                self.shared
                    .run(|core| -> R<Value> {
                        if !core.vault.has_webauthn_unlock().v()? {
                            return Err(d(C::NotFound, "no Touch ID unlock enrolled"));
                        }
                        Ok(json!({"rp_id": "localhost", "credential_id": core.vault.webauthn_unlock_credential_id().v()?, "prf_salt": core.vault.prf_salt().v()?}))
                    })
                    .await??,
            )),
            "POST /v1/factors/webauthn" => {
                let remove = field(&input, "action")?.and_then(Value::as_str) == Some("remove");
                self.shared
                    .run(move |core| -> R<()> {
                        if core.vault.locked() {
                            return Err(d(C::Locked, "unlock the vault first"));
                        }
                        if !remove {
                            core.vault.require_recovery_factor().v()?;
                        }
                        Ok(())
                    })
                    .await??;
                self.require_fresh(if remove { "touch id removal" } else { "touch id enrollment" }, op?.unwrap_or(Value::Null), presence).await?;
                if remove {
                    let removed = self.shared.run(|core| core.vault.remove_webauthn_unlock().v()).await??;
                    return Ok((200, json!({"ok": true, "removed": removed})));
                }
                let cid = input.get("credential_id").map(js_string).unwrap_or_default();
                let prf = input.get("prf_secret").map(js_string).unwrap_or_default();
                self.shared
                    .run(move |core| core.vault.add_webauthn_unlock(&cid, &av_core::secret::SecretBytes::from(prf.into_bytes())).v())
                    .await??;
                Ok((200, json!({"ok": true, "enrolled": true})))
            }
            "GET /v1/factors/webauthn-enroll-params" => Ok((
                200,
                self.shared
                    .run(|core| -> R<Value> { Ok(json!({"rp_id": "localhost", "has_passphrase": core.vault.has_passphrase().v()?, "prf_salt": core.vault.prf_salt().v()?})) })
                    .await??,
            )),
            "POST /v1/presence/challenge" => {
                let operation = field(&input, "operation")?.filter(|o| crate::util::truthy(o)).cloned().unwrap_or(json!({}));
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let Some(enrolled) = core.vault.presence_key().v()? else {
                            return Err(d(C::PresenceRequired, "no authenticator is enrolled"));
                        };
                        if crate::util::js_stringify(&operation).encode_utf16().count() > MAX_OPERATION_BYTES {
                            return Err(d(C::PolicyDenied, "that operation description is too large to sign"));
                        }
                        let challenge = av_core::operation::challenge_for_operation(&crate::util::random_bytes::<32>(), &operation);
                        let id = crate::util::random_b64url(12);
                        let now = now_ms();
                        core.dm.op_challenges.retain(|(_, c)| c.expires >= now);
                        while core.dm.op_challenges.len() >= MAX_OPEN_CHALLENGES {
                            core.dm.op_challenges.remove(0);
                        }
                        core.dm.op_challenges.push((id.clone(), OpChallenge { challenge, operation, expires: now + 60_000 }));
                        Ok(json!({"challengeId": id, "challenge": webauthn::b64url(&challenge), "allowCredentials": [{"id": enrolled.credential_id, "type": "public-key"}], "rpId": "localhost"}))
                    })
                    .await??;
                Ok((200, v))
            }
            "POST /v1/tls/ensure" => {
                let force = field(&input, "force")?.is_some_and(crate::util::truthy);
                if force {
                    self.require_human("tls regenerate", Some(json!({"op": "tls.regenerate"})), presence).await?;
                }
                let dir = self.shared.dir().to_path_buf();
                let info = tokio::task::spawn_blocking(move || crate::tls::ensure_certificate(&dir, force))
                    .await
                    .map_err(|_| internal("the certificate could not be made"))?
                    .map_err(|e| internal(e.to_string()))?;
                let (fp, na, created) = (info.fingerprint.clone(), info.not_after.clone(), info.created);
                self.shared.run(move |core| core.audit_opt("tls.certificate", json!({"fingerprint": fp, "not_after": na, "created": created}))).await?;
                Ok((200, json!({"created": info.created, "fingerprint": info.fingerprint, "not_after": info.not_after, "certificate": info.pem, "key_path": info.key.display().to_string()})))
            }
            "GET /v1/tls" => {
                let dir = self.shared.dir().to_path_buf();
                if !crate::tls::tls_paths(&dir).cert.exists() {
                    return Ok((200, json!({"configured": false})));
                }
                let info = tokio::task::spawn_blocking(move || crate::tls::ensure_certificate(&dir, false))
                    .await
                    .map_err(|_| internal("the certificate could not be read"))?
                    .map_err(|e| internal(e.to_string()))?;
                Ok((200, json!({"configured": true, "fingerprint": info.fingerprint, "not_after": info.not_after, "certificate": info.pem})))
            }
            "POST /v1/presence/window" => self.presence_window(input).await,
            "POST /v1/passphrase" => self.passphrase(input).await,
            "GET /v1/lockstate" => Ok((
                200,
                self.shared
                    .run(|core| -> R<Value> {
                        let has_p = core.vault.has_passphrase().v()?;
                        let has_t = core.vault.has_webauthn_unlock().v()?;
                        Ok(json!({"locked": core.vault.locked(), "factors": core.vault.factors().v()?, "has_passphrase": has_p, "has_touchid": has_t, "needs_secret": has_p || has_t}))
                    })
                    .await??,
            )),

            "POST /v1/sessions/narrow" => Ok((200, self.shared.run(move |core| narrow_session(core, &input)).await??)),
            "GET /v1/sessions/detail" => {
                let sid = q("sid");
                Ok((200, self.shared.run(move |core| session_detail(core, sid.as_deref())).await??))
            }
            "GET /v1/report/access" => {
                let since = q("since");
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let log = core.vault.audit().ok_or_else(|| d(C::Locked, "the audit log is encrypted; unlock the vault to read it"))?;
                        let since = report_since(since)?;
                        let rows = log.read(&av_store::audit::ReadFilter { limit: 100_000, ..Default::default() }).v()?;
                        let sessions = core.vault.sessions().v()?;
                        let grants = core.vault.grants().v()?;
                        let creds = core.vault.credential_records().v()?;
                        let rep = av_store::activity::access_report(&rows, av_store::activity::AccessReportInput { sessions: &sessions, grants: &grants, credentials: &creds, since: &since }).v()?;
                        Ok(serde_json::to_value(rep).unwrap_or(Value::Null))
                    })
                    .await??;
                Ok((200, v))
            }

            "POST /v1/credentials/rotate" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred rotate", op?, presence).await?;
                let v = self.shared.run(move |core| rotate(core, &input)).await??;
                Ok((200, v))
            }
            "POST /v1/credentials/scrub" => {
                let Some(pattern) = field(&input, "pattern")?.and_then(Value::as_str).map(str::to_string) else {
                    return Err(dr(C::PolicyDenied, "pattern is the pattern text", "scrub_pattern"));
                };
                if input.get("sample").is_some_and(|s| !s.as_str().is_some_and(|t| t.encode_utf16().count() <= 64 * 1024)) {
                    return Err(dr(C::PolicyDenied, "sample is text of at most 64 KiB", "policy_invalid"));
                }
                let compiled = av_core::scrub::compile_scrub_pattern(&pattern)?;
                self.require_human("cred scrub add", op?, presence).await?;
                let slug = input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into());
                let added = self.shared.run(move |core| core.vault.add_scrub_pattern(&slug, &pattern).v()).await??;
                let mut out = serde_json::to_value(added).unwrap_or(Value::Null);
                if let Some(sample) = input.get("sample").and_then(Value::as_str) {
                    let mut matches = 0u64;
                    let redacted = compiled.regex.replace_all(sample, |_: &regex::Captures<'_>| {
                        matches += 1;
                        "[[av:derived]]".to_string()
                    });
                    out["sample"] = json!({"redacted": redacted, "matches": matches});
                }
                Ok((200, out))
            }
            "DELETE /v1/credentials/scrub" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred scrub remove", op?, presence).await?;
                let (slug, id) = (q("slug").unwrap_or_else(|| "null".into()), q("id").unwrap_or_else(|| "null".into()));
                let removed = self.shared.run(move |core| core.vault.remove_scrub_pattern(&slug, &id).v()).await??;
                Ok((200, json!({"ok": true, "removed": removed})))
            }
            "POST /v1/credentials/expiry" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred expiry", op?, presence).await?;
                let exp = input.get("expires_at");
                if !(exp == Some(&Value::Null) || exp.is_some_and(Value::is_string)) {
                    return Err(dr(C::PolicyDenied, "expires_at is an ISO date, or null to clear it", "expires_at"));
                }
                let (slug, iso) = (input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into()), str_of(exp));
                Ok((200, self.shared.run(move |core| core.vault.set_credential_expiry(&slug, iso.as_deref()).v().map(|c| json!(c))).await??))
            }
            "POST /v1/credentials/pins" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred pins", op?, presence).await?;
                let Some(pins) = input.get("pins").and_then(Value::as_array) else {
                    return Err(dr(C::PolicyDenied, "pins is a list of sha256/<base64> values", "pin_format"));
                };
                let pins: Vec<String> = pins.iter().map(js_string).collect();
                let (slug, host) = (input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into()), input.get("host").map(js_string).unwrap_or_else(|| "undefined".into()));
                Ok((200, self.shared.run(move |core| core.vault.set_pins(&slug, &host, &pins).v().map(|p| json!(p))).await??))
            }
            "DELETE /v1/credentials/pins" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred pins remove", op?, presence).await?;
                let (slug, host, spki) = (q("slug").unwrap_or_else(|| "null".into()), q("host").unwrap_or_else(|| "null".into()), q("spki"));
                let remaining = self.shared.run(move |core| core.vault.clear_pins(&slug, &host, spki.as_deref()).v()).await??;
                Ok((200, json!({"ok": true, "remaining": remaining})))
            }
            "POST /v1/credentials/test" => {
                let all = field(&input, "all")?.cloned();
                if self.shared.run(|core| core.vault.locked()).await? {
                    return Err(d(C::Locked, "unlock the vault to test a credential"));
                }
                if all.as_ref().is_some_and(|a| *a != Value::Bool(true)) {
                    return Err(dr(C::PolicyDenied, "all is true, or absent", "policy_invalid"));
                }
                if all == Some(Value::Bool(true)) {
                    let slugs = self.shared.run(|core| core.vault.credential_records().v().map(|cs| cs.into_iter().map(|c| c.slug).collect::<Vec<_>>())).await??;
                    let mut results = Vec::new();
                    for slug in slugs {
                        match crate::connectors::probe::run_probe(&self.shared, slug.clone(), self.upstream_for_probe.clone()).await {
                            Ok(r) => {
                                let mut x = json!({"slug": slug});
                                if let Value::Object(m) = r {
                                    for (k, v) in m {
                                        x[&k] = v;
                                    }
                                }
                                results.push(x);
                            }
                            Err(e) => {
                                let mut x = json!({"slug": slug, "error": e.code.as_str()});
                                if let Some(r) = rule_of(&e) {
                                    x["rule"] = r.into();
                                }
                                if let Some(ra) = e.extra.retry_after {
                                    x["retry_after"] = ra.into();
                                }
                                results.push(x);
                            }
                        }
                    }
                    return Ok((200, json!({"results": results})));
                }
                let slug = input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into());
                Ok((200, crate::connectors::probe::run_probe(&self.shared, slug, self.upstream_for_probe.clone()).await?))
            }
            "POST /v1/credentials/quarantine" => {
                let reason = field(&input, "reason")?.cloned();
                if reason.as_ref().is_some_and(|r| !r.is_null() && !r.is_string()) {
                    return Err(dr(C::PolicyDenied, "reason is text", "policy_invalid"));
                }
                let slug = input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into());
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        if core.vault.locked() {
                            return Err(d(C::Locked, "unlock the vault to quarantine a credential"));
                        }
                        let cred = core.vault.find_credential(&slug).v()?.ok_or_else(|| d(C::NotFound, format!("no credential {slug}")))?;
                        let text = match reason.as_ref().and_then(Value::as_str) {
                            Some(r) => Some(core.vault.untrusted_text(r, 200).v()?),
                            None => None,
                        };
                        let q = core.vault.set_quarantine(&cred.slug, QuarantineOptions { by: QuarantineBy::Control, rule_id: None, reason: text }).v()?;
                        let denied = core.pl_deny_approvals(&ApprovalFilter { credential_id: Some(cred.id.clone()), ..Default::default() }, "quarantined")?;
                        Ok(json!({"slug": cred.slug, "quarantine": q, "denied_approvals": denied}))
                    })
                    .await??;
                Ok((200, v))
            }
            "POST /v1/credentials/release" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("cred release", op?, presence).await?;
                let slug = input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into());
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let cred = core.vault.find_credential(&slug).v()?.ok_or_else(|| d(C::NotFound, format!("no credential {slug}")))?;
                        Ok(json!({"slug": cred.slug, "released": core.vault.clear_quarantine(&cred.slug).v()?}))
                    })
                    .await??;
                Ok((200, v))
            }

            "POST /v1/panic" => {
                let lock = field(&input, "lock")?.cloned();
                if lock.as_ref().is_some_and(|l| !l.is_boolean()) {
                    return Err(dr(C::PolicyDenied, "lock is true or false", "policy_invalid"));
                }
                let reason = input.get("reason").filter(|r| !r.is_null()).cloned();
                if reason.as_ref().is_some_and(|r| !r.as_str().is_some_and(|s| s.encode_utf16().count() <= 200)) {
                    return Err(dr(C::PolicyDenied, "reason is text of at most 200 characters", "policy_invalid"));
                }
                let lock = lock == Some(Value::Bool(true));
                let v = self
                    .shared
                    .run(move |core| -> R<(u16, Value)> {
                        if core.vault.locked() {
                            let e = d(C::Locked, "the vault is already locked, so nothing was revoked");
                            let mut p = e.to_problem();
                            p["locked"] = true.into();
                            p["already"] = true.into();
                            return Ok((e.http(), p));
                        }
                        let r = core.pl_panic(reason.and_then(|r| r.as_str().map(str::to_string)), lock)?;
                        if r["locked"] == Value::Bool(true) {
                            core.dm.presence_grace_until = 0;
                        }
                        Ok((200, r))
                    })
                    .await??;
                Ok(v)
            }
            "GET /v1/tripwires" => {
                let v = self
                    .shared
                    .run(|core| -> R<Value> {
                        let s = core.vault.get_settings().v()?;
                        let t = s.get("tripwires").cloned().unwrap_or(json!({}));
                        let saved = t.get("rules").is_some_and(Value::is_array);
                        let defaults = crate::tripwire::default_rules_json();
                        Ok(json!({"enabled": t.get("enabled") == Some(&Value::Bool(true)), "rules": if saved { t["rules"].clone() } else { defaults.clone() }, "rules_saved": saved, "defaults": defaults}))
                    })
                    .await??;
                Ok((200, v))
            }
            "POST /v1/tripwires" => {
                let mut body = if input.is_object() { input.as_object().cloned().unwrap_or_default() } else { Map::new() };
                let presence = body.remove("presence");
                let keys: Vec<String> = body.keys().cloned().collect();
                let enable_only = keys.len() == 1 && keys[0] == "enabled" && body["enabled"] == Value::Bool(true);
                if !enable_only {
                    self.require_human("tripwires set", op?, presence).await?;
                }
                if let Some(k) = keys.iter().find(|k| *k != "enabled" && *k != "rules") {
                    return Err(dr(C::PolicyDenied, format!("tripwires has no setting {k}"), "tripwire_rule"));
                }
                if body.get("enabled").is_some_and(|e| !e.is_boolean()) {
                    return Err(dr(C::PolicyDenied, "enabled is true or false", "tripwire_rule"));
                }
                if body.get("rules").is_some_and(|r| r.as_str() != Some("defaults") && !r.is_array()) {
                    return Err(dr(C::PolicyDenied, "rules is a list of rules, or 'defaults'", "tripwire_rule"));
                }
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let s = core.vault.get_settings().v()?;
                        let current = s.get("tripwires").cloned().unwrap_or(json!({}));
                        let defaults = crate::tripwire::default_rules_json();
                        let enabled = body.get("enabled").cloned().unwrap_or(Value::Bool(current.get("enabled") == Some(&Value::Bool(true))));
                        let rules = match body.get("rules") {
                            Some(Value::String(_)) => defaults,
                            Some(r) => r.clone(),
                            None => current.get("rules").filter(|r| r.is_array()).cloned().unwrap_or(defaults),
                        };
                        let saved = core.vault.update_settings(&json!({"tripwires": {"enabled": enabled, "rules": rules}})).v()?;
                        let t = saved.get("tripwires").cloned().unwrap_or(json!({}));
                        Ok(json!({"enabled": t.get("enabled") == Some(&Value::Bool(true)), "rules": t.get("rules").cloned().unwrap_or(Value::Null)}))
                    })
                    .await??;
                Ok((200, v))
            }

            "GET /v1/templates" => {
                let name = q("name");
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        if let Some(name) = name {
                            let t = core.vault.get_template(&name).v()?.ok_or_else(|| d(C::NotFound, format!("no template {name}")))?;
                            let spec = Value::Object(t.spec.clone());
                            let mut out = serde_json::to_value(&t).unwrap_or(json!({}));
                            out["summary"] = template_summary(&spec).into();
                            out["creds"] = json!(template_creds(&spec));
                            out["elevated"] = json!(elevation_of(&spec));
                            return Ok(out);
                        }
                        let list: Vec<Value> = core
                            .vault
                            .list_templates()
                            .v()?
                            .into_iter()
                            .map(|t| {
                                let spec = Value::Object(t.spec.clone());
                                json!({"name": t.name, "version": t.version, "hash": t.hash, "summary": template_summary(&spec), "creds": template_creds(&spec), "elevated": elevation_of(&spec), "updated_at": t.updated_at})
                            })
                            .collect();
                        Ok(Value::Array(list))
                    })
                    .await??;
                Ok((200, v))
            }
            "POST /v1/templates" => {
                let spec = field(&input, "spec")?.cloned().unwrap_or(Value::Null);
                if !spec.is_object() {
                    return Err(dr(C::PolicyDenied, "spec is a session-create object", "session_shape"));
                }
                for k in ["template", "template_hash", "presence"] {
                    if spec.get(k).is_some() {
                        return Err(dr(C::PolicyDenied, format!("a template spec cannot carry {k}"), "session_shape"));
                    }
                }
                let s2 = spec.clone();
                let plan = self.shared.run(move |core| core.dm_plan_session(&s2, true, false)).await??;
                self.require_human("template save", op?, presence).await?;
                let name = input.get("name").map(js_string).unwrap_or_else(|| "undefined".into());
                let lint: Vec<Value> = plan.grants.iter().flat_map(|g| g.lint.as_array().cloned().unwrap_or_default()).collect();
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let saved = core.vault.save_template(&name, &spec).v()?;
                        let sp = Value::Object(saved.spec.clone());
                        Ok(json!({"name": saved.name, "version": saved.version, "hash": saved.hash, "spec": sp, "lint": lint, "elevated": elevation_of(&sp)}))
                    })
                    .await??;
                Ok((200, v))
            }
            "DELETE /v1/templates" => {
                let name = q("name").unwrap_or_else(|| "null".into());
                let removed = self.shared.run(move |core| core.vault.delete_template(&name).v()).await??;
                Ok((200, json!({"ok": true, "removed": removed})))
            }

            "POST /v1/backup/export" => {
                if self.shared.run(|core| core.vault.locked()).await? {
                    return Err(d(C::Locked, "unlock the vault to export it"));
                }
                let presence = field(&input, "presence")?.cloned();
                self.require_fresh("backup export", op?.unwrap_or(Value::Null), presence).await?;
                let pass = SecretString::from(input.get("recovery_passphrase").map(js_string).unwrap_or_default());
                let v = self
                    .shared
                    .run(move |core| av_store::backup::export_backup(&mut core.vault, &pass).v().map(|r| json!(r)))
                    .await??;
                Ok((200, v))
            }
            "POST /v1/backup/inspect" => self.backup_inspect(input).await,
            "POST /v1/backup/restore" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("backup restore", op?, presence).await?;
                let _gate = self.passphrase_gate.lock().await;
                self.shared
                    .run(|core| -> R<()> {
                        if core.vault.locked() {
                            return Err(d(C::Locked, "unlock the vault to restore into it"));
                        }
                        core.dm_throttle()
                    })
                    .await??;
                let pass = SecretString::from(input.get("recovery_passphrase").map(js_string).unwrap_or_default());
                let bundle = input.get("bundle").cloned().unwrap_or(Value::Null);
                let mode: av_store::backup::ConflictMode = match input.get("on_conflict").filter(|v| !v.is_null()) {
                    None => Default::default(),
                    Some(v) => serde_json::from_value(v.clone()).map_err(|_| dr(C::PolicyDenied, "on_conflict is skip, rename or fail", "backup_conflict"))?,
                };
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        match av_store::backup::restore_backup(&mut core.vault, &bundle, &pass, mode).v() {
                            Ok(r) => Ok(json!(r)),
                            Err(e) => {
                                if rule_of(&e) == Some("backup_auth") {
                                    core.dm_record_attempt(false);
                                }
                                Err(e)
                            }
                        }
                    })
                    .await??;
                Ok((200, v))
            }

            "GET /v1/audit/export" => {
                let (s, l) = (q("since_seq"), q("limit"));
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let log = core.vault.audit_mut().ok_or_else(|| d(C::Locked, "the audit log is encrypted; unlock the vault to read it"))?;
                        let since = whole_param(s, 0, "since_seq")?;
                        let limit = whole_param(l, 5000, "limit")?;
                        Ok(json!(log.export(av_store::audit::ExportOptions { since_seq: since, limit: limit as usize, ..Default::default() }).v()?))
                    })
                    .await??;
                Ok((200, v))
            }
            "GET /v1/audit/checkpoint" => Ok((
                200,
                self.shared
                    .run(|core| -> R<Value> {
                        let log = core.vault.audit_mut().ok_or_else(|| d(C::Locked, "the audit log is encrypted; unlock the vault to witness it"))?;
                        Ok(json!(log.checkpoint().v()?))
                    })
                    .await??,
            )),
            "POST /v1/audit/verify-witness" => {
                let cps = field(&input, "checkpoints")?.cloned();
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let log = core.vault.audit_mut().ok_or_else(|| d(C::Locked, "the audit log is encrypted; unlock the vault to verify it"))?;
                        let list: Vec<Value> = match &cps {
                            Some(Value::Array(a)) => a.clone(),
                            _ => Vec::new(),
                        };
                        Ok(json!(log.verify_witness(&list).v()?))
                    })
                    .await??;
                Ok((200, v))
            }

            "GET /v1/notify" => Ok((200, self.shared.run(|core| core.vault.notify_config().v().map(|c| json!({"webhook": c}))).await??)),
            "POST /v1/notify" => {
                let presence = field(&input, "presence")?.cloned();
                self.require_human("notify set", op?, presence).await?;
                let url = SecretString::from(input.get("webhook_url").map(js_string).unwrap_or_default());
                let detail: av_store::model::NotifyDetail = serde_json::from_value(input.get("detail").filter(|v| !v.is_null()).cloned().unwrap_or(json!("minimal")))
                    .map_err(|_| dr(C::PolicyDenied, "detail is minimal or headline", "notify_detail"))?;
                Ok((200, self.shared.run(move |core| core.vault.set_notify_webhook(&url, detail).v().map(|c| json!({"webhook": c}))).await??))
            }
            "DELETE /v1/notify" => Ok((
                200,
                self.shared
                    .run(|core| -> R<Value> {
                        if core.vault.locked() {
                            return Err(d(C::Locked, "unlock the vault to remove the webhook"));
                        }
                        Ok(json!({"ok": true, "removed": core.vault.clear_notify_webhook().v()?}))
                    })
                    .await??,
            )),
            "POST /v1/notify/test" => Ok((200, self.notifier.test().await?)),

            _ => Ok((404, json!({"code": "AV_NOT_FOUND", "detail": format!("no control route {route}")}))),
        }
    }

    /// `POST /v1/unlock`.
    async fn unlock(&self, input: Value) -> R<(u16, Value)> {
        let _gate = self.passphrase_gate.lock().await;
        let pass = field(&input, "passphrase")?.filter(|p| !p.is_null()).map(js_string);
        let prf = truthy_str(input.get("prf_secret"));
        let guessing = pass.is_some();
        let state = self.shared.run(move |core| -> R<bool> {
            if !core.vault.locked() {
                return Ok(false);
            }
            if guessing {
                core.dm_throttle()?;
            }
            Ok(true)
        });
        if !state.await?? {
            return Ok((200, json!({"ok": true, "locked": false, "already": true})));
        }
        // An Argon2 check off the lock first: a wrong guess never holds it.
        let pre_ok = match &pass {
            Some(p) if prf.is_none() => {
                let ok = self.shared.verify_passphrase(SecretString::from(p.clone())).await;
                if !ok {
                    let has = self.shared.run(|core| core.vault.has_passphrase().unwrap_or(false)).await?;
                    if has {
                        // Fall through to the real unlock, which refuses with the
                        // store's own error and records the attempt.
                    }
                }
                ok
            }
            _ => true,
        };
        let _ = pre_ok;
        let v = self
            .shared
            .run(move |core| -> R<Value> {
                let material = UnlockMaterial {
                    passphrase: pass.clone().map(SecretString::from),
                    prf_secret: prf.map(|s| av_core::secret::SecretBytes::from(s.into_bytes())),
                };
                match core.vault.unlock_with(&material).v() {
                    Ok(factor) => {
                        if guessing {
                            core.dm_record_attempt(true);
                        }
                        core.pl_recover_spend();
                        Ok(json!({"ok": true, "locked": false, "factor": factor, "factors": core.vault.factors().v()?}))
                    }
                    Err(e) => {
                        if guessing {
                            core.dm_record_attempt(false);
                        }
                        Err(e)
                    }
                }
            })
            .await??;
        Ok((200, v))
    }

    /// `POST /v1/presence/window`.
    async fn presence_window(&self, input: Value) -> R<(u16, Value)> {
        let _gate = self.passphrase_gate.lock().await;
        let pass = field(&input, "passphrase")?.filter(|p| crate::util::truthy(p)).map(js_string).unwrap_or_default();
        let pre = self
            .shared
            .run(|core| -> R<Option<Value>> {
                if core.vault.locked() {
                    return Err(d(C::Locked, "unlock the vault first"));
                }
                if !core.vault.has_passphrase().v()? {
                    if core.vault.presence_key().v()?.is_some() {
                        return Ok(Some(json!({
                            "granted": false, "ungated": false, "factors": ["authenticator"],
                            "detail": "this vault has no passphrase, so no window was opened; every widening change still needs your authenticator",
                            "next": "agent-vault ui   (confirm it there with your authenticator)",
                        })));
                    }
                    return Ok(Some(json!({
                        "granted": false, "ungated": true,
                        "detail": "this vault has no passphrase, so nothing is gated and no window was opened",
                        "next": "agent-vault passphrase set",
                    })));
                }
                core.dm_throttle()?;
                Ok(None)
            })
            .await??;
        if let Some(v) = pre {
            return Ok((200, v));
        }
        let ok = self.shared.verify_passphrase(SecretString::from(pass)).await;
        let v = self
            .shared
            .run(move |core| -> R<Value> {
                core.dm_record_attempt(ok);
                if !ok {
                    return Err(d(C::PresenceDenied, "passphrase did not verify"));
                }
                core.dm.presence_grace_until = now_ms() + core.dm.presence_grace_ms;
                let until = iso_of_ms(core.dm.presence_grace_until);
                core.audit("presence.window_opened", json!({"until": until}))?;
                Ok(json!({"granted": true, "until": until}))
            })
            .await??;
        Ok((200, v))
    }

    /// `POST /v1/passphrase`.
    async fn passphrase(&self, input: Value) -> R<(u16, Value)> {
        let (locked, has) = self.shared.run(|core| (core.vault.locked(), core.vault.has_passphrase().unwrap_or(false))).await?;
        if locked {
            return Err(d(C::Locked, "unlock the vault before changing its passphrase"));
        }
        let presence = field(&input, "presence")?.cloned();
        if !has {
            self.require_human("first passphrase", Some(json!({"op": "passphrase.first"})), presence).await?;
        }
        let _gate = self.passphrase_gate.lock().await;
        if has {
            self.shared.run(|core| core.dm_throttle()).await??;
        }
        let current = truthy_str(input.get("current"));
        let remove = input.get("action").and_then(Value::as_str) == Some("remove");
        let newp = input.get("passphrase").map(js_string);
        let v = self
            .shared
            .run(move |core| -> R<Value> {
                let attempt = if remove {
                    let cur = SecretString::from(current.clone().unwrap_or_default());
                    core.vault.remove_passphrase(&cur).v().map(|removed| json!({"ok": true, "removed": removed}))
                } else {
                    let n = SecretString::from(newp.unwrap_or_default());
                    let c = current.clone().map(SecretString::from);
                    core.vault.set_passphrase(&n, c.as_ref()).v().map(|_| json!({"ok": true, "has_passphrase": true}))
                };
                match attempt {
                    Ok(v) => {
                        if has {
                            core.dm_record_attempt(true);
                        }
                        Ok(v)
                    }
                    Err(e) => {
                        if has && e.code == C::Locked {
                            core.dm_record_attempt(false);
                        }
                        Err(e)
                    }
                }
            })
            .await??;
        Ok((200, v))
    }

    /// `POST /v1/backup/inspect`.
    async fn backup_inspect(&self, input: Value) -> R<(u16, Value)> {
        let _gate = self.passphrase_gate.lock().await;
        self.shared
            .run(|core| -> R<()> {
                if core.vault.locked() {
                    return Err(d(C::Locked, "unlock the vault to inspect a backup"));
                }
                core.dm_throttle()
            })
            .await??;
        let bundle = field(&input, "bundle")?.cloned().unwrap_or(Value::Null);
        let pass = SecretString::from(input.get("recovery_passphrase").map(js_string).unwrap_or_default());
        let b2 = bundle.clone();
        let inspected = tokio::task::spawn_blocking(move || av_store::backup::inspect_backup(&b2, &pass).v())
            .await
            .map_err(|_| internal("the backup could not be read"))?;
        let v = self
            .shared
            .run(move |core| -> R<Value> {
                match inspected {
                    Err(e) => {
                        if rule_of(&e) == Some("backup_auth") {
                            core.dm_record_attempt(false);
                        }
                        if let Some(r) = rule_of(&e) {
                            if !core.vault.locked() {
                                core.audit("backup.refused", json!({"reason": r}))?;
                            }
                        }
                        Err(e)
                    }
                    Ok(i) => {
                        core.audit("backup.inspected", json!({"credentials": i.credentials.len(), "bundle_sha256": av_store::backup::bundle_digest(&bundle)}))?;
                        Ok(json!(i))
                    }
                }
            })
            .await??;
        Ok((200, v))
    }
}

fn without_presence(input: &Value) -> Value {
    let mut m = input.as_object().cloned().unwrap_or_default();
    m.remove("presence");
    Value::Object(m)
}

/// `POST /v1/credentials` after its gate.
fn add_credential(core: &mut Core, input: &Value) -> R<Value> {
    let kind = truthy_str(input.get("kind")).unwrap_or_else(|| "http".into());
    let profile = av_core::profiles::get_profile(&kind).map_err(|e| d(C::NotFound, e.to_string()))?;
    if !profile.implemented {
        return Err(dr(C::PolicyDenied, format!("the {kind} connector is not implemented yet"), "connector_implemented")
            .hinted("Its profile exists but the proxy that would carry it does not, so a credential of this kind could not be used. Do not store one here yet."));
    }
    let field_name = truthy_str(input.get("field")).unwrap_or_else(|| av_core::profiles::default_field(&kind).to_string());
    let exp = input.get("expires_at").filter(|v| !v.is_null());
    if exp.is_some_and(|e| !e.as_str().is_some_and(|s| crate::util::parse_iso_ms(s).is_some())) {
        return Err(dr(C::PolicyDenied, "expires_at must be an ISO date", "expires_at"));
    }
    let mut connector = Map::new();
    connector.insert("host".into(), truthy_str(input.get("host")).map_or_else(|| Value::from(profile.hosts.first().copied().unwrap_or("")), Value::from));
    connector.insert("scheme".into(), Value::from(truthy_str(input.get("scheme")).unwrap_or_else(|| "https".into())));
    let sites: Vec<String> = match input.get("sites").filter(|s| crate::util::truthy(s)) {
        Some(Value::Array(a)) => a.iter().map(js_string).collect(),
        _ => av_core::profiles::default_sites(&kind, &field_name).iter().map(|s| s.to_string()).collect(),
    };
    let value = input.get("value").map(js_string).unwrap_or_default();
    let value_len = value.encode_utf16().count();
    let mut sites_map = std::collections::BTreeMap::new();
    sites_map.insert(field_name.clone(), sites);
    let cred = core
        .vault
        .add_credential(NewCredential {
            slug: input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into()),
            kind,
            connector,
            fields: vec![(field_name, SecretString::from(value))],
            sites: sites_map,
        })
        .v()?;
    let mut out = serde_json::to_value(&cred).unwrap_or(json!({}));
    if let Some(e) = exp.and_then(Value::as_str) {
        match core.vault.set_credential_expiry(&cred.slug, Some(e)).v() {
            Ok(c) => out = serde_json::to_value(c).unwrap_or(json!({})),
            Err(err) => {
                let _ = core.vault.delete_credential(&cred.slug);
                return Err(err);
            }
        }
    }
    if value_len < MIN_SECRET_LEN {
        out["warnings"] = json!([short_warning()]);
    }
    Ok(out)
}

/// `POST /v1/placeholders` after its gate.
fn issue_one(core: &mut Core, input: &Value) -> R<Value> {
    let slug = input.get("cred").map(js_string).unwrap_or_else(|| "undefined".into());
    let cred = core.vault.find_credential(&slug).v()?.ok_or_else(|| d(C::NotFound, format!("no credential {slug}")))?;
    let now = now_ms() as f64;
    let active: Vec<_> = core
        .vault
        .sessions()
        .v()?
        .into_iter()
        .filter(|s| s.state == SessionState::Active && av_store::vault::session_expiry_ms(s) > now)
        .collect();
    let sid = input.get("sid").filter(|s| crate::util::truthy(s)).map(js_string);
    if sid.is_none() && active.len() > 1 {
        return Err(dr(C::SessionRequired, format!("{} sessions are active; name the one to issue for", active.len()), "explicit_session")
            .hinted(format!("Pass sid. Active: {}", active.iter().map(|s| s.id.clone()).collect::<Vec<_>>().join(", "))));
    }
    let session = match &sid {
        Some(s) => core.vault.session(s).v()?,
        None => active.into_iter().next(),
    };
    if let (Some(s), None) = (&sid, &session) {
        return Err(d(C::NotFound, format!("no session {s}")));
    }
    let Some(session) = session else {
        return Err(d(C::SessionRequired, "no session is active to issue a placeholder for").next(json!({"cli": [format!("agent-vault session create --cred {}", cred.slug)]})));
    };
    core.vault.assert_session_live(Some(&session)).v()?;
    let grant = core.vault.grants_for_session(&session.id).v()?.into_iter().find(|g| g.credential_id == cred.id);
    let Some(grant) = grant else {
        return Err(d(C::NoGrant, format!("no grant for {slug} in session {}", session.id)));
    };
    let field = cred.fields.first().ok_or_else(|| internal("Cannot read properties of undefined (reading 'name')"))?;
    let uses = input.get("uses").filter(|u| !u.is_null()).map(|u| as_whole(u).ok_or_else(|| dr(C::PolicyDenied, "uses must be a whole number, 1 or more", "policy_invalid"))).transpose()?;
    let issued = core.vault.issue_placeholder(IssueOptions { grant_id: grant.id, field: Some(field.name.clone()), uses, ttl_ms: None }).v()?;
    Ok(json!({"placeholder": issued.placeholder, "usage": field.sites.iter().map(|s| describe(s, Some(&issued.placeholder))).collect::<Vec<_>>()}))
}

fn batch_shape(input: &Value) -> R<()> {
    let shape = |detail: &str| {
        dr(C::PolicyDenied, detail, "batch_shape").hinted(format!("Send {{ sid, items: [{{ cred, field?, uses? }}] }} with 1 to {MAX_BATCH} items, one per credential field."))
    };
    if !field(input, "sid")?.and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
        return Err(shape("name the session: sid"));
    }
    let items = input.get("items").and_then(Value::as_array).filter(|a| !a.is_empty() && a.len() <= MAX_BATCH);
    let Some(items) = items else { return Err(shape(&format!("items is a list of 1 to {MAX_BATCH} entries"))) };
    if input.get("purpose").is_some_and(|p| !p.is_null() && !matches!(p.as_str(), Some("env") | Some("exec"))) {
        return Err(shape("purpose is env, exec or null"));
    }
    let mut pairs = std::collections::HashSet::new();
    for item in items {
        if !item.is_object() {
            return Err(shape("each item must be an object"));
        }
        if !item.get("cred").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
            return Err(shape("each item names a credential: cred"));
        }
        if item.get("field").is_some_and(|f| !f.is_null() && !f.as_str().is_some_and(|s| !s.is_empty())) {
            return Err(shape("field is a field name"));
        }
        if item.get("uses").is_some_and(|u| !u.is_null() && !as_integer(u).is_some_and(|n| n >= 1)) {
            return Err(shape("uses is a whole number, 1 or more"));
        }
        let key = format!("{}\u{0}{}", js_string(&item["cred"]), item.get("field").and_then(Value::as_str).unwrap_or(""));
        if !pairs.insert(key) {
            return Err(shape("each credential field appears once"));
        }
    }
    Ok(())
}

/// `POST /v1/placeholders/batch` after its gate.
fn issue_batch(core: &mut Core, input: &Value, port: u16) -> R<Value> {
    if core.vault.locked() {
        return Err(d(C::Locked, "the vault is locked"));
    }
    let sid = input["sid"].as_str().unwrap_or("").to_string();
    let session = core.vault.session(&sid).v()?.ok_or_else(|| d(C::NotFound, format!("no session {sid}")))?;
    core.vault.assert_session_live(Some(&session)).v()?;
    let grants = core.vault.grants_for_session(&session.id).v()?;
    let mut resolved = Vec::new();
    for item in input["items"].as_array().cloned().unwrap_or_default() {
        let slug = js_string(&item["cred"]);
        let cred = core.vault.find_credential(&slug).v()?.ok_or_else(|| d(C::NotFound, format!("no credential {slug}")))?;
        if cred.quarantine.is_some() {
            return Err(quarantined(&cred.slug));
        }
        let grant = grants.iter().find(|g| g.credential_id == cred.id).cloned().ok_or_else(|| d(C::NoGrant, format!("no grant for {} in session {}", cred.slug, session.id)))?;
        let grant = core.vault.assert_grant_live(Some(&grant)).v()?;
        let name = item.get("field").and_then(Value::as_str).map(str::to_string).or_else(|| grant.fields.first().cloned()).unwrap_or_default();
        let f = cred.fields.iter().find(|f| f.name == name).cloned();
        let Some(f) = f.filter(|_| grant.fields.contains(&name)) else {
            return Err(d(C::NoGrant, format!("the grant for {} does not cover that field", cred.slug)));
        };
        let max = match &grant.policy.placeholder_policy {
            Some(Checked::Valid(p)) => p.max_uses,
            _ => None,
        };
        let asked = item.get("uses").and_then(as_whole);
        let uses = match max {
            None => asked,
            Some(m) => Some(asked.unwrap_or(m).min(m)),
        };
        resolved.push((cred, grant, f, uses));
    }
    let mut items = Vec::new();
    for (cred, grant, f, uses) in resolved {
        let issued = core.vault.issue_placeholder(IssueOptions { grant_id: grant.id.clone(), field: Some(f.name.clone()), uses, ttl_ms: None }).v()?;
        let profile = av_core::profiles::get_profile(&cred.connector_kind).ok();
        items.push(json!({
            "cred": cred.slug, "field": f.name, "placeholder": issued.placeholder,
            "usage": f.sites.iter().map(|s| describe(s, Some(&issued.placeholder))).collect::<Vec<_>>(),
            "base_url": format!("http://127.0.0.1:{port}/p/{}", cred.slug),
            "env": profile.and_then(|p| p.env).map(|e| json!({"base": e.base, "key": e.key})),
        }));
    }
    let mut slugs: Vec<Value> = Vec::new();
    for i in &items {
        if !slugs.contains(&i["cred"]) {
            slugs.push(i["cred"].clone());
        }
    }
    core.audit(
        "placeholder.issued_batch",
        json!({"session_id": session.id, "count": items.len(), "credential_slugs": slugs, "purpose": input.get("purpose").cloned().unwrap_or(Value::Null)}),
    )?;
    Ok(json!({"session_id": session.id, "gateway_url": format!("http://127.0.0.1:{port}"), "items": items}))
}

/// `POST /v1/credentials/rotate` after its gate.
fn rotate(core: &mut Core, input: &Value) -> R<Value> {
    if let Some(h) = input.get("retire_hours") {
        if !as_integer(h).is_some_and(|n| (0..=168).contains(&n)) {
            return Err(dr(C::PolicyDenied, "retire_hours is a whole number from 0 to 168", "retire_window"));
        }
    }
    let slug = input.get("slug").map(js_string).unwrap_or_else(|| "undefined".into());
    let value = input.get("value").map(js_string).unwrap_or_default();
    let short = value.encode_utf16().count() < MIN_SECRET_LEN;
    let mode: RotateMode = match input.get("mode").filter(|m| !m.is_null()) {
        None => RotateMode::Keep,
        Some(m) => serde_json::from_value(m.clone()).map_err(|_| dr(C::PolicyDenied, "mode is keep or revoke", "rotate_mode"))?,
    };
    let result = core
        .vault
        .rotate_credential(
            &slug,
            RotateOptions {
                field: input.get("field").filter(|f| !f.is_null()).map(js_string),
                value: SecretString::from(value),
                mode,
                retire_ms: input.get("retire_hours").and_then(as_integer).map_or(av_store::vault::DAY_MS, |h| h * 3_600_000),
                expires_at: input.get("expires_at").and_then(Value::as_str).map(str::to_string),
            },
        )
        .v()?;
    let cred = core.vault.find_credential(&slug).v()?.ok_or_else(|| internal("Cannot read properties of null (reading 'id')"))?;
    let invalidated = core.pl_deny_approvals(&ApprovalFilter { credential_id: Some(cred.id), ..Default::default() }, "credential_rotated")?;
    let mut out = serde_json::to_value(&result).unwrap_or(json!({}));
    out["invalidated_approvals"] = invalidated.into();
    if short {
        out["warnings"] = json!([short_warning()]);
    }
    Ok(out)
}

/// `#narrowSession(input)`.
fn narrow_session(core: &mut Core, input: &Value) -> R<Value> {
    let bad = |detail: &str, rule: &str| dr(C::PolicyDenied, detail, rule);
    if !input.is_object() {
        return Err(bad("send { sid, cred?, narrow, session_ttl_minutes?, grant_ttl_minutes? }", "policy_invalid"));
    }
    let Some(sid) = input.get("sid").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return Err(d(C::NotFound, "name the session: sid"));
    };
    if core.vault.locked() {
        return Err(d(C::Locked, "unlock the vault to narrow a session"));
    }
    let session = core.vault.session(sid).v()?.ok_or_else(|| d(C::NotFound, format!("no session {sid}")))?;
    if input.get("cred").is_some_and(|c| !c.as_str().is_some_and(|s| !s.is_empty())) {
        return Err(bad("cred is a credential slug", "policy_invalid"));
    }
    if input.get("narrow").is_some_and(|n| !n.is_object()) {
        return Err(bad("narrow is an object of grant limits", "policy_invalid"));
    }
    let narrow = input.get("narrow").and_then(Value::as_object).cloned().unwrap_or_default();
    let allowed = narrow_fields();
    if let Some(k) = narrow.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(bad(&format!("a narrowing cannot carry {k}"), "policy_invalid"));
    }
    let minutes = |v: Option<&Value>, rule: &str| -> R<Option<i64>> {
        match v {
            None => Ok(None),
            Some(x) => match as_integer(x).filter(|n| *n >= 1) {
                Some(n) => Ok(Some(n)),
                None => Err(bad("a lifetime is a whole number of minutes, 1 or more", rule)),
            },
        }
    };
    let session_ttl = minutes(input.get("session_ttl_minutes"), "ttl")?;
    if input.get("grant_ttl_minutes").is_some() && narrow.contains_key("grant_ttl_minutes") {
        return Err(bad("grant_ttl_minutes given twice", "policy_invalid"));
    }
    let grant_ttl = minutes(input.get("grant_ttl_minutes").or(narrow.get("grant_ttl_minutes")), "grant_ttl")?;
    let fields: Vec<String> = narrow.keys().filter(|k| *k != "grant_ttl_minutes").cloned().collect();
    if fields.is_empty() && session_ttl.is_none() && grant_ttl.is_none() {
        return Err(bad("name at least one limit or lifetime to narrow", "narrow_empty"));
    }
    if narrow.contains_key("redirects") && narrow["redirects"] != json!(0) {
        return Err(bad("a narrowing can only turn redirect following off: redirects 0", "narrow_widens"));
    }
    if narrow.get("approval").is_some_and(|a| !a.as_str().is_some_and(|s| APPROVAL_MODES.contains(&s))) {
        return Err(dr(C::PolicyDenied, "approval is not one of the four modes", "approval").hinted("approval is one of: each, on-write, first-use, auto"));
    }
    if narrow.get("budget").is_some_and(|b| policy::budget_integer(b).is_none()) {
        return Err(bad("budget must be a whole number of requests, 0 or more", "policy_invalid"));
    }
    core.vault.assert_session_usable(Some(&session), None, Default::default()).v()?;
    let mut grants = core.vault.grants_for_session(&session.id).v()?;
    if let Some(c) = input.get("cred").and_then(Value::as_str) {
        let mut kept = Vec::new();
        for g in grants {
            if core.vault.credential(&g.credential_id).v()?.is_some_and(|cr| cr.slug == c) {
                kept.push(g);
            }
        }
        grants = kept;
        if grants.is_empty() {
            return Err(d(C::NotFound, format!("session {} has no grant for {c}", session.id)));
        }
    }
    let describe_g = |g: &av_store::model::GrantRecord, profile: &av_core::profiles::Profile, s: &av_store::model::SessionRecord| {
        let ceiling = profile.policy_ceiling();
        json!(policy::describe_effective(&policy::intersect(&[Some(&ceiling), Some(&s.policy), Some(&g.policy)])))
    };
    let mut planned = Vec::new();
    for g in &grants {
        let cred = core.vault.credential(&g.credential_id).v()?.ok_or_else(|| internal("no credential"))?;
        let profile = av_core::profiles::get_profile(&cred.connector_kind).map_err(|e| internal(e.to_string()))?;
        let hosts: Vec<String> = profile.hosts.iter().map(|s| s.to_string()).collect();
        let ceiling = policy::credential_host_ceiling(cred.connector.get("host").and_then(Value::as_str), &hosts);
        let mut spec = Map::new();
        for k in &fields {
            spec.insert(k.clone(), narrow[k].clone());
        }
        let layer = if fields.is_empty() {
            None
        } else {
            Some(policy::grant_policy_from_input(&Value::Object(spec), &policy::GrantPolicyOptions { profile: Some(profile), ceiling: policy::GrantCeiling::Hosts(ceiling), defaults: false })?)
        };
        planned.push((g.clone(), cred, profile, layer, describe_g(g, profile, &session)));
    }
    if let Some(m) = session_ttl {
        core.vault.shorten_session(&session.id, m * 60_000).v()?;
    }
    let mut out = Vec::new();
    for (g, cred, profile, layer, before) in planned {
        if let Some(l) = layer {
            core.vault.narrow_grant(&g.id, &serde_json::to_value(l).unwrap_or(json!({}))).v()?;
        }
        if let Some(m) = grant_ttl {
            core.vault.shorten_grant(&g.id, m * 60_000).v()?;
        }
        let now_g = core.vault.grant(&g.id).v()?.ok_or_else(|| internal("no grant"))?;
        let s_now = core.vault.session(&session.id).v()?.unwrap_or(session.clone());
        out.push(json!({"cred": cred.slug, "grant_id": g.id, "before": before, "after": describe_g(&now_g, profile, &s_now), "expires_at": now_g.expires_at}));
    }
    let s_now = core.vault.session(&session.id).v()?.unwrap_or(session);
    Ok(json!({"session_id": s_now.id, "expires_at": s_now.expires_at, "infinite": s_now.infinite, "grants": out}))
}

/// `#sessionDetail(sid)`.
fn session_detail(core: &mut Core, sid: Option<&str>) -> R<Value> {
    if core.vault.audit().is_none() {
        return Err(d(C::Locked, "the audit log is encrypted; unlock the vault to read it"));
    }
    let session = match sid {
        Some(s) => core.vault.session(s).v()?,
        None => None,
    };
    let Some(session) = session else {
        return Err(d(C::NotFound, format!("no session {}", sid.unwrap_or("null"))));
    };
    let grants: Vec<_> = core.vault.grants().v()?.into_iter().filter(|g| g.session_id == session.id).collect();
    let rows = core.vault.audit().map(|l| l.read(&av_store::audit::ReadFilter { limit: 100_000, ..Default::default() })).transpose().v()?.unwrap_or_default();
    let placeholders = core.vault.list_placeholders(None).v()?;
    let mut gout = Vec::new();
    for g in &grants {
        let cred = core.vault.credential(&g.credential_id).v()?;
        let profile = cred.as_ref().and_then(|c| av_core::profiles::get_profile(&c.connector_kind).ok());
        let ceiling = profile.map(|p| p.policy_ceiling());
        let effective = policy::intersect(&[ceiling.as_ref(), Some(&session.policy), Some(&g.policy)]);
        let used = g.budget_used;
        let budget = match policy::budget_limit(effective.budget.as_ref()) {
            policy::BudgetLimit::Limit(l) => json!({"limit": l, "used": used, "remaining": l.saturating_sub(used)}),
            policy::BudgetLimit::Unlimited => json!({"limit": null, "used": used, "remaining": 0}),
            policy::BudgetLimit::Unreadable => json!({"limit": null, "used": used, "remaining": null, "invalid": true}),
        };
        let budget = match policy::budget_limit(effective.budget.as_ref()) {
            // JS: no limit is null with remaining null; an unreadable one is
            // `limit: null` too, flagged invalid, with nothing remaining.
            policy::BudgetLimit::Unlimited => json!({"limit": null, "used": used, "remaining": null}),
            policy::BudgetLimit::Unreadable => json!({"limit": null, "used": used, "remaining": 0, "invalid": true}),
            _ => budget,
        };
        let spend = match core.pl_spend_for(&g.id) {
            Ok(s) => s.unwrap_or(Value::Null),
            Err(_) => json!({"invalid": true}),
        };
        let limits = core.pl_limits_for(&g.id).ok().flatten().unwrap_or(Value::Null);
        let phs: Vec<Value> = placeholders
            .iter()
            .filter(|p| p.grant_id == g.id)
            .map(|p| json!({"id": p.id, "field": p.field, "uses": p.uses, "max_uses": p.max_uses, "state": p.state, "dead_reason": p.dead_reason, "expires_at": p.expires_at}))
            .collect();
        gout.push(json!({
            "grant_id": g.id, "cred": cred.as_ref().map(|c| c.slug.clone()), "state": g.state, "expires_at": g.expires_at,
            "effective": policy::describe_effective(&effective), "budget": budget, "limits": limits, "spend": spend,
            "counters": g.counters, "placeholders": phs,
        }));
    }
    let activity = av_store::activity::summarize_session(&rows, &session, &grants);
    Ok(json!({
        "session": {
            "id": session.id, "label": session.label, "state": session.state, "created_at": session.created_at,
            "expires_at": session.expires_at, "infinite": session.infinite, "remote": session.remote,
            "last_seen_at": session.last_seen_at, "template": session.template, "elevated": session.elevated,
        },
        "grants": gout,
        "activity": activity,
    }))
}

#[allow(dead_code)]
fn unused(_: &PlaceholderState, s: &av_store::model::SessionRecord) -> Value {
    whole_session_fields(s)
}
