//! The MCP server: tool definitions, JSON-RPC dispatch, and the stdio
//! transport. Ports `src/daemon/mcp.js`.
//!
//! Tool names, input schemas, descriptions and the server instructions are
//! frozen (PLAN.md, "Frozen external contract" item 3) and copied from the
//! JS verbatim.

use std::sync::{Arc, Mutex, Weak};

use av_core::errors::VaultError;
use av_core::policy::{self, Checked};
use av_store::model::SessionRecord;
use av_store::vault::{IssueOptions, ListenerContext, UsableOptions};
use serde_json::{json, Map, Value};

use crate::err::{rule_of, C};
use crate::pipeline::{GatewayRequest, ListenerInfo, Pipeline};
use crate::server::{describe, Daemon};
use crate::session_requests::{grant_specs_of, template_creds, template_summary, OWNER_FIELDS};
use crate::state::{StoreResult, VaultRef};
use crate::util::{as_whole, js_pretty, js_string, now_ms};

/// MCP protocol versions the server speaks, newest first.
pub const PROTOCOL_VERSIONS: [&str; 2] = ["2025-06-18", "2025-03-26"];
/// The version offered when the client asks for one we do not speak.
pub const LATEST_PROTOCOL: &str = PROTOCOL_VERSIONS[0];
/// `serverInfo.name`.
pub const SERVER_NAME: &str = "agent-vault";
/// Transport sessions held at once.
pub const MAX_MCP_SESSIONS: usize = 256;
/// The server instructions sent on `initialize` (frozen text).
pub const INSTRUCTIONS: &str = "Credentials are placeholders, never real secrets. Never ask the user for a real secret. \
Prefer vault_http for API calls; use vault_get_placeholder only for tools that must run natively. \
Put a placeholder only where the usage field says. A placeholder anywhere else is refused. \
On AV_PH_EXHAUSTED or AV_PH_STALE, call vault_get_placeholder again and retry. \
On a denial, call vault_explain_denial with the request_id to learn the rule and the allowed alternatives. \
Before a write you are unsure of, call vault_preflight; to learn your limits, call vault_describe_access.";
/// What `vault_request_session` forwards.
pub const REQUEST_ARGS: [&str; 10] = [
    "cred",
    "methods",
    "paths",
    "budget",
    "uses",
    "ttl_minutes",
    "routes",
    "grant_ttl_minutes",
    "template",
    "reason",
];
/// Largest tool-call body `vault_http` returns, in characters.
pub const MAX_TOOL_BODY: usize = 256 * 1024;

type R<T> = Result<T, VaultError>;

/// The `tools/list` array.
pub fn tools() -> Value {
    json!([
        {"name": "vault_status", "description": "Whether the vault is reachable and unlocked, and a summary of the current session.", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "vault_list_creds", "description": "Credentials this session may use, with the exact place a placeholder goes for each.", "inputSchema": {"type": "object", "properties": {"available_only": {"type": "boolean"}}}},
        {"name": "vault_get_placeholder", "description": "Get a placeholder for a credential. Returns the placeholder plus where to put it.", "inputSchema": {"type": "object", "properties": {
            "cred": {"type": "string", "description": "credential slug"},
            "reason": {"type": "string", "description": "why you need it; shown to the human as an unverified claim"},
            "uses": {"type": "number", "description": "optional: make it n-use instead of session-lifetime"}
        }, "required": ["cred", "reason"]}},
        {"name": "vault_request_session", "description": "Ask a human for a session. This creates nothing by itself: it opens a request a human must approve, and they may narrow it first. Poll the returned id until they answer. Two error paths already tell you to call this.", "inputSchema": {"type": "object", "properties": {
            "cred": {"type": "string", "description": "credential slug"},
            "reason": {"type": "string", "description": "why you need it; shown to the human as an unverified claim"},
            "methods": {"type": "array", "items": {"type": "string"}, "description": "ask for the least you need"},
            "paths": {"type": "array", "items": {"type": "string"}},
            "budget": {"type": "number", "description": "how many requests"},
            "ttl_minutes": {"type": "number", "description": "how long you need it for; ask for the least you need"},
            "uses": {"type": "number", "description": "optional: n-use placeholders instead of session-lifetime ones"},
            "grant_ttl_minutes": {"type": "number", "description": "how long the access itself is needed, if shorter than the session"},
            "routes": {"type": "array", "description": "optional: method-bound routes, each a set of methods allowed only on these paths", "items": {"type": "object", "properties": {"methods": {"type": "array", "items": {"type": "string"}}, "paths": {"type": "array", "items": {"type": "string"}}}, "required": ["methods", "paths"]}},
            "template": {"type": "string", "description": "a template name the human saved; they see the template, not a policy to read"},
            "poll_id": {"type": "string", "description": "an id from an earlier call: check whether it has been answered"},
            "poll_secret": {"type": "string", "description": "the poll_secret that earlier call returned; only the asker can poll"}
        }, "required": ["reason"]}},
        {"name": "vault_approval_status", "description": "Whether a human has answered a held request. The 202 from a held write names this tool and the id to pass.", "inputSchema": {"type": "object", "properties": {
            "approval_id": {"type": "string", "description": "the approval_id from the 202"}
        }, "required": ["approval_id"]}},
        {"name": "vault_http", "description": "Make an HTTP request through the vault. The credential is injected by the daemon; you never handle it.", "inputSchema": {"type": "object", "properties": {
            "cred": {"type": "string"}, "method": {"type": "string"}, "path": {"type": "string"}, "query": {"type": "string"},
            "headers": {"type": "object"}, "body": {"type": "string"}, "reason": {"type": "string"}
        }, "required": ["cred", "method", "path", "reason"]}},
        {"name": "vault_explain_denial", "description": "Explain why a request this session made was denied and what this session is allowed to do instead. The code and rule are always given; the full sentence is kept for an hour (the last 1000 denials) and is null after that, after the daemon restarts, or for a caller with no session.", "inputSchema": {"type": "object", "properties": {"request_id": {"type": "string"}}, "required": ["request_id"]}},
        {"name": "vault_describe_access", "description": "What this session may do right now: hosts, methods, paths, approval mode, budgets and limits, lifetimes, and where each placeholder goes.", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "vault_preflight", "description": "Check whether a request would be allowed, held for a human, or refused, without sending it or spending anything. Advisory only.", "inputSchema": {"type": "object", "properties": {
            "cred": {"type": "string", "description": "credential slug"}, "method": {"type": "string"},
            "path": {"type": "string", "description": "the upstream path, as for vault_http"}, "query": {"type": "string"},
            "headers": {"type": "object"}, "body": {"type": "string"}
        }, "required": ["cred", "method", "path"]}}
    ])
}

fn text(v: Value) -> Value {
    let t = match &v {
        Value::String(s) => s.clone(),
        other => js_pretty(other),
    };
    json!({"content": [{"type": "text", "text": t}]})
}

fn error_text(v: Value) -> Value {
    json!({"isError": true, "content": [{"type": "text", "text": js_pretty(&v)}]})
}

/// `#refusal(e)`.
fn refusal(e: &VaultError) -> Value {
    let mut body = Map::new();
    body.insert(
        "error".into(),
        Value::from(if e.detail.is_empty() {
            e.to_string()
        } else {
            e.detail.clone()
        }),
    );
    body.insert("code".into(), e.code.as_str().into());
    if let Some(r) = rule_of(e) {
        body.insert("rule".into(), r.into());
    }
    let h = e.hint();
    if !h.is_empty() {
        body.insert("hint".into(), h.into());
    }
    if let Some(ra) = e.extra.retry_after {
        body.insert("retry_after".into(), ra.into());
    }
    error_text(Value::Object(body))
}

#[derive(Default)]
struct Transport {
    sessions: Vec<(String, bool)>,
}

/// The MCP server shared by the stdio bridge and Streamable HTTP. Ports
/// `class McpServer`.
pub struct McpServer {
    shared: VaultRef,
    pipeline: Arc<Pipeline>,
    daemon: Mutex<Weak<Daemon>>,
    transport: Mutex<Transport>,
}

fn lctx(l: Option<&ListenerInfo>) -> Option<ListenerContext> {
    l.map(|l| ListenerContext {
        id: Some(l.id.clone()),
        kind: Some(l.kind.clone()),
        remote: l.remote,
    })
}

impl McpServer {
    /// Ports `new McpServer(vault, pipeline, resolveSession, daemon)`.
    pub fn new(shared: VaultRef, pipeline: Arc<Pipeline>) -> McpServer {
        McpServer {
            shared,
            pipeline,
            daemon: Mutex::new(Weak::new()),
            transport: Mutex::new(Transport::default()),
        }
    }

    /// The daemon that owns the session-request store.
    pub fn set_daemon(&self, d: Weak<Daemon>) {
        *self.daemon.lock().unwrap_or_else(|p| p.into_inner()) = d;
    }

    fn daemon(&self) -> Option<Arc<Daemon>> {
        self.daemon
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .upgrade()
    }

    /// `openSession({ record })`.
    pub async fn open_session(&self, record: bool) -> String {
        let sid = uuid4();
        {
            let mut t = self.transport.lock().unwrap_or_else(|p| p.into_inner());
            while t.sessions.len() >= MAX_MCP_SESSIONS {
                t.sessions.remove(0);
            }
            t.sessions.push((sid.clone(), record));
        }
        if record {
            let s = sid.clone();
            let _ = self
                .shared
                .run(move |core| core.audit_opt("mcp.session_opened", json!({"mcp_session_id": s})))
                .await;
        }
        sid
    }

    /// `closeSession(sid, { record })`.
    pub async fn close_session(&self, sid: &str, record: bool) -> bool {
        let entry = {
            let mut t = self.transport.lock().unwrap_or_else(|p| p.into_inner());
            t.sessions
                .iter()
                .position(|(s, _)| s == sid)
                .map(|i| t.sessions.remove(i))
        };
        let Some((_, recorded)) = entry else {
            return false;
        };
        if recorded || record {
            let s = sid.to_string();
            let _ = self
                .shared
                .run(move |core| core.audit_opt("mcp.session_closed", json!({"mcp_session_id": s})))
                .await;
        }
        true
    }

    /// `hasSession(sid)`.
    pub fn has_session(&self, sid: &str) -> bool {
        self.transport
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .sessions
            .iter()
            .any(|(s, _)| s == sid)
    }

    /// The `tools/list` array.
    pub fn tools(&self) -> Vec<Value> {
        tools().as_array().cloned().unwrap_or_default()
    }

    /// Handle one JSON-RPC message; `None` for a notification. Ports
    /// `handle(message, forSession, forToken, forListener)`.
    pub async fn handle(
        &self,
        message: Value,
        session: Option<SessionRecord>,
        token: Option<String>,
        listener: Option<ListenerInfo>,
    ) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message.get("method").cloned().unwrap_or(Value::Null);
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let ok = |result: Value| {
            id.clone()
                .map(|id| json!({"jsonrpc": "2.0", "id": id, "result": result}))
        };
        let token = token.unwrap_or_default();
        let r: R<Option<Value>> = async {
            Ok(match method.as_str() {
                Some("initialize") => {
                    let asked = params.get("protocolVersion").and_then(Value::as_str);
                    let v = asked.filter(|a| PROTOCOL_VERSIONS.contains(a)).unwrap_or(LATEST_PROTOCOL);
                    ok(json!({
                        "protocolVersion": v,
                        "capabilities": {"tools": {"listChanged": false}, "resources": {"listChanged": false}},
                        "serverInfo": {"name": SERVER_NAME, "version": crate::server::VERSION},
                        "instructions": INSTRUCTIONS,
                    }))
                }
                Some("notifications/initialized") => None,
                Some("ping") => ok(json!({})),
                Some("tools/list") => ok(json!({"tools": tools()})),
                Some("resources/list") => ok(json!({"resources": [{"uri": "agent-vault://session", "name": "Current session", "mimeType": "application/json"}]})),
                Some("resources/read") => {
                    let status = self.status(session.as_ref(), &token, listener.as_ref()).await?;
                    ok(json!({"contents": [{"uri": params.get("uri").cloned().unwrap_or(Value::Null), "mimeType": "application/json", "text": js_pretty(&status)}]}))
                }
                Some("tools/call") => {
                    let name = params.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                    let args = params.get("arguments").filter(|a| crate::util::truthy(a)).cloned().unwrap_or(json!({}));
                    ok(self.call_tool(&name, args, session.clone(), &token, listener.clone()).await?)
                }
                _ => id.clone().map(|id| json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("unknown method: {}", if method.is_null() { "undefined".to_string() } else { js_string(&method) })}})),
            })
        }
        .await;
        match r {
            Ok(v) => v,
            Err(e) if e.code != C::Internal => ok(json!({
                "isError": true,
                "content": [{"type": "text", "text": js_pretty(&json!({"code": e.code.as_str(), "detail": e.detail, "hint": e.hint(), "next": e.extra.next}))}],
            })),
            Err(e) => {
                if crate::err::is_fault(&e) {
                    let _ = self
                        .shared
                        .run(|core| {
                            core.audit_opt(
                                "daemon.handler_error",
                                json!({"error": crate::server::PANIC_CLASS}),
                            )
                        })
                        .await;
                }
                id.map(|id| json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32603, "message": e.detail}}))
            }
        }
    }

    /// `#templates()`.
    fn templates_of(core: &crate::state::Core) -> Value {
        let list = core.vault.list_templates().unwrap_or_default();
        Value::Array(
            list.into_iter()
                .filter_map(|t| {
                    let spec = Value::Object(t.spec.clone());
                    let creds = template_creds(&spec);
                    (creds.len() == 1 && grant_specs_of(&spec).len() == 1).then(|| json!({"name": t.name, "cred": creds[0], "summary": template_summary(&spec)}))
                })
                .collect(),
        )
    }

    /// `#status(session, token, listener)`.
    async fn status(
        &self,
        session: Option<&SessionRecord>,
        token: &str,
        listener: Option<&ListenerInfo>,
    ) -> R<Value> {
        let (s, t, l) = (session.cloned(), token.to_string(), listener.cloned());
        self.shared
            .run(move |core| -> R<Value> {
                let problem = match &s {
                    Some(_) => Value::Null,
                    None => session_problem(core, &t, l.as_ref(), false).map(|(d, _)| Value::from(d)).unwrap_or(Value::Null),
                };
                let available = match &s {
                    Some(s) => core.vault.grants_for_session(&s.id).v()?.len(),
                    None => 0,
                };
                Ok(json!({
                    "daemon": "agent-vault", "version": crate::server::VERSION,
                    "locked": core.vault.locked(),
                    "session": s.as_ref().map(|s| json!({"id": s.id, "label": s.label, "expires_at": s.expires_at, "infinite": s.infinite})),
                    "session_problem": problem,
                    "credentials_available": available,
                    "templates": McpServer::templates_of(core),
                }))
            })
            .await?
    }

    async fn needs_session(&self, token: &str, listener: Option<&ListenerInfo>) -> R<Value> {
        let (t, l) = (token.to_string(), listener.cloned());
        let problem = self
            .shared
            .run(move |core| session_problem(core, &t, l.as_ref(), true))
            .await?;
        if let Some((_, Some(e))) = &problem {
            if e.code == C::RemoteForbidden {
                return Ok(error_text(
                    json!({"code": e.code.as_str(), "rule": rule_of(e), "detail": e.detail, "hint": e.hint()}),
                ));
            }
        }
        Ok(error_text(json!({
            "error": "this tool needs a live session",
            "detail": problem.map(|(d, _)| Value::from(d)).unwrap_or(Value::Null),
            "next": "call vault_request_session to ask a human for one, or ask them to run: agent-vault session create --cred <slug>",
        })))
    }

    async fn call_tool(
        &self,
        name: &str,
        args: Value,
        session: Option<SessionRecord>,
        token: &str,
        listener: Option<ListenerInfo>,
    ) -> R<Value> {
        match name {
            "vault_status" => Ok(text(
                self.status(session.as_ref(), token, listener.as_ref())
                    .await?,
            )),
            "vault_list_creds" => {
                let Some(s) = session else {
                    return self.needs_session(token, listener.as_ref()).await;
                };
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let mut out = Vec::new();
                        for g in core.vault.grants_for_session(&s.id).v()? {
                            let cred = core.vault.credential(&g.credential_id).v()?.ok_or_else(|| crate::err::internal("Cannot read properties of undefined (reading 'connector_kind')"))?;
                            let profile = av_core::profiles::get_profile(&cred.connector_kind).map_err(|e| crate::err::internal(e.to_string()))?;
                            let limit = match &g.policy.budget {
                                Some(Checked::Valid(b)) => b.limit.as_ref().and_then(|l| policy::budget_integer(&serde_json::to_value(l).unwrap_or(Value::Null))).map(|n| n as i64).unwrap_or(0),
                                _ => 0,
                            };
                            let warning = av_store::vault::expiry_warning(&cred, now_ms());
                            out.push(json!({
                                "slug": cred.slug, "kind": cred.connector_kind, "base_url": format!("/p/{}", cred.slug),
                                "allowed": {"methods": g.policy.methods, "paths": g.policy.paths, "hosts": g.policy.hosts},
                                "budget_remaining": limit - g.budget_used as i64,
                                "usage": cred.fields.iter().map(|f| json!({"field": f.name, "put_placeholder_at": f.sites.iter().map(|x| describe(x, None)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
                                "profile_denies": profile.deny_paths.iter().take(5).collect::<Vec<_>>(),
                                "expiry_warning": warning,
                                "quarantined": cred.quarantine.is_some(),
                                "expires_at": g.expires_at,
                            }));
                        }
                        Ok(Value::Array(out))
                    })
                    .await??;
                Ok(text(v))
            }
            "vault_request_session" => self.request_session(args).await,
            "vault_get_placeholder" => {
                let Some(s) = session else {
                    return self.needs_session(token, listener.as_ref()).await;
                };
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let slug = args.get("cred").map(js_string).unwrap_or_else(|| "undefined".into());
                        let Some(cred) = core.vault.find_credential(&slug).v()? else {
                            let known: Vec<String> = core.vault.list_credentials().v()?.into_iter().map(|c| c.slug).collect();
                            return Ok(text(json!({"error": format!("no credential {slug}"), "known": known})));
                        };
                        let grant = match grant_for(core, &s, &cred)? {
                            Ok(g) => g,
                            Err(refused) => return Ok(refused),
                        };
                        let field = cred.fields.first().cloned().ok_or_else(|| crate::err::internal("no field"))?;
                        let ceiling = match &grant.policy.placeholder_policy {
                            Some(Checked::Valid(p)) => p.max_uses,
                            _ => None,
                        };
                        let asked = args.get("uses").filter(|u| !u.is_null()).and_then(as_whole);
                        let uses = match ceiling {
                            None => asked,
                            Some(c) => Some(asked.unwrap_or(c).min(c)),
                        };
                        let issued = match core.vault.issue_placeholder(IssueOptions { grant_id: grant.id.clone(), field: Some(field.name.clone()), uses, ttl_ms: None }).v() {
                            Ok(i) => i,
                            Err(e) => return Ok(refusal(&e)),
                        };
                        let reason = args.get("reason").map(js_string).unwrap_or_default();
                        let reason = core.vault.untrusted_text(&reason, 200).v()?;
                        core.audit("placeholder.issued_via_mcp", json!({"credential_slug": cred.slug, "agent_reason_untrusted": reason}))?;
                        Ok(text(json!({
                            "placeholder": issued.placeholder,
                            "usage": {
                                "put_it_at": field.sites.iter().map(|x| describe(x, Some(&issued.placeholder))).collect::<Vec<_>>(),
                                "url": format!("/p/{}/<path>", cred.slug),
                                "warning": "A placeholder anywhere other than the site above is refused and audited.",
                            },
                        })))
                    })
                    .await??;
                Ok(v)
            }
            "vault_approval_status" => {
                if session.is_none() {
                    return self.needs_session(token, listener.as_ref()).await;
                }
                let id = args
                    .get("approval_id")
                    .map(js_string)
                    .unwrap_or_else(|| "undefined".into());
                match self.pipeline.approval_status(id.clone()).await {
                    Some(s) => Ok(text(s)),
                    None => Ok(text(
                        json!({"error": format!("no approval {id}"), "detail": "it may have expired, or already been spent"}),
                    )),
                }
            }
            "vault_http" => {
                let Some(s) = session else {
                    return self.needs_session(token, listener.as_ref()).await;
                };
                self.vault_http(args, s, token, listener).await
            }
            "vault_explain_denial" => {
                let sid = session.as_ref().map(|s| s.id.clone());
                let rid = args
                    .get("request_id")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let explained = match &rid {
                    Some(r) if sid.is_some() => {
                        self.pipeline.explain_denial(r.clone(), sid.clone()).await
                    }
                    _ => None,
                };
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        let rows: Vec<Value> = match &rid {
                            Some(r) => {
                                let log = core.vault.audit().ok_or_else(|| crate::err::internal("Cannot read properties of null (reading 'read')"))?;
                                log.read(&av_store::audit::ReadFilter { request_id: Some(r.clone()), limit: 100, ..Default::default() })
                                    .v()?
                                    .into_iter()
                                    .map(|x| serde_json::to_value(x).unwrap_or(Value::Null))
                                    .filter(|x| x.get("session_id").and_then(Value::as_str).map(str::to_string) == sid)
                                    .collect()
                            }
                            None => Vec::new(),
                        };
                        if rows.is_empty() {
                            return Ok(text(json!({"error": format!("no record of request {}", args.get("request_id").map_or("undefined".into(), js_string))})));
                        }
                        let denial = rows.iter().find(|r| r["decision"] == "deny").or(rows.last()).cloned().unwrap_or(Value::Null);
                        let allowed: Vec<Value> = match &sid {
                            Some(s) => core.vault.grants_for_session(s).v()?.into_iter().map(|g| serde_json::to_value(g.policy).unwrap_or(Value::Null)).collect(),
                            None => Vec::new(),
                        };
                        let mut out = Map::new();
                        out.insert("request_id".into(), Value::from(rid.clone().unwrap_or_default()));
                        out.insert("decision".into(), denial.get("decision").cloned().unwrap_or(Value::Null));
                        out.insert("code".into(), denial.get("reason_code").cloned().unwrap_or(Value::Null));
                        out.insert("rule".into(), denial.get("rule").cloned().unwrap_or(Value::Null));
                        out.insert("detail".into(), explained.as_ref().and_then(|e| e.get("detail")).cloned().unwrap_or(Value::Null));
                        if let Some(h) = explained.as_ref().and_then(|e| e.get("hint")).filter(|h| crate::util::truthy(h)) {
                            out.insert("hint".into(), h.clone());
                        }
                        out.insert("allowed_here".into(), Value::Array(allowed));
                        Ok(text(Value::Object(out)))
                    })
                    .await??;
                Ok(v)
            }
            "vault_describe_access" => {
                let Some(s) = session else {
                    return self.needs_session(token, listener.as_ref()).await;
                };
                let l = lctx(listener.as_ref());
                let v = self
                    .shared
                    .run(move |core| -> R<Value> {
                        if let Err(e) = core
                            .vault
                            .assert_session_usable(
                                Some(&s),
                                l.as_ref(),
                                UsableOptions {
                                    peek: true,
                                    record: true,
                                },
                            )
                            .v()
                        {
                            return Ok(refusal(&e));
                        }
                        Ok(text(describe_access(core, &s)?))
                    })
                    .await??;
                Ok(v)
            }
            "vault_preflight" => {
                let Some(s) = session else {
                    return self.needs_session(token, listener.as_ref()).await;
                };
                self.preflight(args, s, token, listener).await
            }
            other => Ok(text(json!({"error": format!("unknown tool {other}")}))),
        }
    }

    async fn request_session(&self, args: Value) -> R<Value> {
        let daemon = self.daemon();
        if let Some(poll) = args.get("poll_id").filter(|p| crate::util::truthy(p)) {
            let poll = js_string(poll);
            let secret = args
                .get("poll_secret")
                .and_then(Value::as_str)
                .map(str::to_string);
            return self
                .shared
                .run(move |core| -> R<Value> {
                    let Some(record) = core.sr_get(&poll) else {
                        return Ok(text(json!({"error": format!("no session request {poll}")})));
                    };
                    if !record.may_collect(secret.as_deref()) {
                        return Ok(text(json!({"error": "poll_secret does not match this request; only the agent that asked can poll it"})));
                    }
                    if record.state == "pending" {
                        return Ok(text(json!({"state": "pending", "detail": "a human has not answered yet; poll again or carry on without it"})));
                    }
                    if record.state == "denied" {
                        return Ok(text(json!({"state": "denied", "detail": "a human declined; do not ask again for the same thing"})));
                    }
                    if record.result.is_none() {
                        if record.state == "collected" {
                            return Ok(text(json!({"state": "approved", "detail": "a human approved this and your session is already active — the bridge found it. Call vault_status to see it, and use the tools normally."})));
                        }
                        return Ok(text(json!({"state": record.state, "detail": "the answer is no longer available; ask again"})));
                    }
                    let result = core.sr.find_mut(&record.id).and_then(|r| {
                        r.state = "collected".into();
                        r.result.take()
                    });
                    core.sr_save();
                    core.audit_opt("session_request.collected", json!({"request_id": record.id, "via": "mcp"}));
                    let mut out = json!({"state": "approved", "detail": "a human approved this, possibly narrower than you asked. Use what you were given."});
                    if let Some(Value::Object(m)) = result {
                        for (k, v) in m {
                            out[&k] = v;
                        }
                    }
                    Ok(text(out))
                })
                .await?;
        }
        let Some(daemon) = daemon else {
            return Ok(text(
                json!({"error": "session requests are not available on this daemon"}),
            ));
        };
        let owned: Vec<&str> = OWNER_FIELDS
            .iter()
            .copied()
            .filter(|f| args.get(*f).is_some())
            .collect();
        if !owned.is_empty() {
            return Ok(refusal(&crate::err::dr(C::PolicyDenied, format!("a session request cannot carry {}", owned.join(" or ")), "owner_only_field").hint_s(
                "Only the owner can choose the approval mode or an unlimited lifetime. Ask without it and say why in reason.",
            )));
        }
        if !args.get("cred").is_some_and(crate::util::truthy)
            && !args.get("template").is_some_and(crate::util::truthy)
        {
            let v = self
                .shared
                .run(|core| -> R<Value> {
                    let known: Vec<String> = core.vault.list_credentials().v()?.into_iter().map(|c| c.slug).collect();
                    Ok(json!({"error": "name the credential you need, or a template", "known": known, "templates": McpServer::templates_of(core)}))
                })
                .await??;
            return Ok(text(v));
        }
        let mut asked = Map::new();
        for k in REQUEST_ARGS {
            if let Some(v) = args.get(k).filter(|v| !v.is_null()) {
                asked.insert(k.into(), v.clone());
            }
        }
        match daemon.propose_session_request(Value::Object(asked)).await {
            Ok((record, secret)) => Ok(text(json!({
                "state": "pending", "request_id": record["id"], "poll_secret": secret, "asked_for": record["summary"],
                "detail": "a human must approve this. Poll with vault_request_session { poll_id: request_id, poll_secret }. They may narrow it.",
            }))),
            Err(e) if e.code == C::Internal => Ok(text(json!({"error": e.detail}))),
            Err(e) => Ok(refusal(&e)),
        }
    }

    async fn vault_http(
        &self,
        args: Value,
        s: SessionRecord,
        token: &str,
        listener: Option<ListenerInfo>,
    ) -> R<Value> {
        let sid = s.id.clone();
        let a2 = args.clone();
        let prep = self
            .shared
            .run(
                move |core| -> R<Result<(String, String, av_core::sites::Site, String), Value>> {
                    let slug = a2
                        .get("cred")
                        .map(js_string)
                        .unwrap_or_else(|| "undefined".into());
                    let Some(cred) = core.vault.find_credential(&slug).v()? else {
                        return Ok(Err(text(json!({"error": format!("no credential {slug}")}))));
                    };
                    let grant = match grant_for(core, &s, &cred)? {
                        Ok(g) => g,
                        Err(r) => return Ok(Err(r)),
                    };
                    let field = cred
                        .fields
                        .first()
                        .cloned()
                        .ok_or_else(|| crate::err::internal("no field"))?;
                    let site = av_core::sites::parse_site(
                        field.sites.first().map(String::as_str).unwrap_or(""),
                    )
                    .map_err(|e| crate::err::internal(e.0))?;
                    match core
                        .vault
                        .issue_placeholder(IssueOptions {
                            grant_id: grant.id.clone(),
                            field: Some(field.name.clone()),
                            uses: None,
                            ttl_ms: None,
                        })
                        .v()
                    {
                        Ok(i) => Ok(Ok((cred.slug.clone(), i.placeholder, site, i.row.id))),
                        Err(e) => Ok(Err(refusal(&e))),
                    }
                },
            )
            .await??;
        let (slug, placeholder, site, row_id) = match prep {
            Ok(x) => x,
            Err(v) => return Ok(v),
        };
        let mut headers = vec![("host".to_string(), "127.0.0.1".to_string())];
        let user_headers: Vec<(String, String)> = args
            .get("headers")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), js_string(v))).collect())
            .unwrap_or_default();
        for (k, v) in &user_headers {
            if (k.len() >= 3 && k[..3].eq_ignore_ascii_case("av-"))
                || k.eq_ignore_ascii_case("host")
            {
                continue;
            }
            headers.push((k.clone(), v.clone()));
        }
        let mut query = args
            .get("query")
            .filter(|q| crate::util::truthy(q))
            .map(js_string)
            .unwrap_or_default();
        match site.kind {
            av_core::sites::SiteKind::Header => {
                let name = site.name.clone().unwrap_or_default();
                headers.push((
                    name,
                    match &site.scheme {
                        Some(s) => format!("{s} {placeholder}"),
                        None => placeholder.clone(),
                    },
                ));
            }
            av_core::sites::SiteKind::Query => {
                let k = crate::util::encode_uri_component(site.key.as_deref().unwrap_or(""));
                query = if query.is_empty() {
                    format!("{k}={placeholder}")
                } else {
                    format!("{query}&{k}={placeholder}")
                };
            }
            _ => {}
        }
        headers.push(("av-session".into(), token.to_string()));
        if let Some(r) = args.get("reason").filter(|r| crate::util::truthy(r)) {
            headers.push(("av-reason".into(), js_string(r)));
        }
        let body = args
            .get("body")
            .filter(|b| crate::util::truthy(b))
            .map(js_string);
        let caller_type = user_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if body.is_some() && !caller_type {
            headers.push(("content-type".into(), "application/json".into()));
        }
        let path = format!(
            "/p/{slug}{}",
            args.get("path").map_or("undefined".into(), js_string)
        );
        let mut res = self
            .pipeline
            .handle(GatewayRequest {
                method: args.get("method").map_or("undefined".into(), js_string),
                path,
                query,
                headers,
                body: body.map(String::into_bytes),
                listener,
            })
            .await;
        let body_text = match res.stream.take() {
            Some(mut rx) => {
                let mut out = String::new();
                while let Some(chunk) = rx.recv().await {
                    if out.encode_utf16().count() < MAX_TOOL_BODY {
                        out.push_str(&String::from_utf8_lossy(&chunk));
                    }
                }
                cut16(&out, MAX_TOOL_BODY)
            }
            None => cut16(&String::from_utf8_lossy(&res.body), MAX_TOOL_BODY),
        };
        let _ = self
            .shared
            .run(move |core| {
                let live = core
                    .vault
                    .list_placeholders(Some(&sid))
                    .ok()
                    .and_then(|rows| rows.into_iter().find(|r| r.id == row_id));
                if live.is_some_and(|r| r.state == av_store::model::PlaceholderState::Active)
                    && !core.vault.locked()
                {
                    let _ = core.vault.burn_placeholder(&row_id, "spent");
                }
            })
            .await;
        let mut hmap = Map::new();
        for (k, v) in &res.headers {
            hmap.insert(k.clone(), Value::from(v.clone()));
        }
        Ok(text(json!({
            "status": res.status, "request_id": res.request_id, "decision": res.header("av-decision"),
            "headers": hmap, "body": body_text,
        })))
    }

    async fn preflight(
        &self,
        args: Value,
        s: SessionRecord,
        token: &str,
        listener: Option<ListenerInfo>,
    ) -> R<Value> {
        let shape =
            |detail: &str| refusal(&crate::err::dr(C::PolicyDenied, detail, "preflight_shape"));
        let cred = args
            .get("cred")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty());
        let Some(cred) = cred.map(str::to_string) else {
            return Ok(shape("cred is a credential slug"));
        };
        let method = args.get("method").and_then(Value::as_str).filter(|m| {
            !m.is_empty() && m.len() <= 16 && m.bytes().all(|b| b.is_ascii_alphabetic())
        });
        let Some(method) = method.map(str::to_string) else {
            return Ok(shape("method is an HTTP method name"));
        };
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .filter(|p| p.starts_with('/'));
        let Some(path) = path.map(str::to_string) else {
            return Ok(shape("path is the upstream path, starting with /"));
        };
        if args
            .get("query")
            .is_some_and(|q| !q.is_null() && !q.is_string())
        {
            return Ok(shape("query is a string"));
        }
        if args
            .get("body")
            .is_some_and(|q| !q.is_null() && !q.is_string())
        {
            return Ok(shape("body is a string"));
        }
        if args
            .get("headers")
            .is_some_and(|h| !h.is_null() && !h.is_object())
        {
            return Ok(shape("headers is an object"));
        }
        let c2 = cred.clone();
        let found = self
            .shared
            .run(move |core| {
                core.vault
                    .find_credential(&c2)
                    .ok()
                    .flatten()
                    .map(|c| c.slug)
            })
            .await?;
        let Some(slug) = found else {
            return Ok(refusal(&crate::err::d(
                C::NotFound,
                format!("no credential {cred}"),
            )));
        };
        let _ = s;
        let mut headers = vec![("host".to_string(), "127.0.0.1".to_string())];
        if let Some(m) = args.get("headers").and_then(Value::as_object) {
            for (k, v) in m {
                if (k.len() >= 3 && k[..3].eq_ignore_ascii_case("av-"))
                    || k.eq_ignore_ascii_case("host")
                {
                    continue;
                }
                headers.push((k.clone(), js_string(v)));
            }
        }
        headers.push(("av-session".into(), token.to_string()));
        let body = args
            .get("body")
            .filter(|b| crate::util::truthy(b))
            .map(js_string)
            .map(String::into_bytes);
        match self
            .pipeline
            .preflight(
                GatewayRequest {
                    method: method.to_uppercase(),
                    path: format!("/p/{slug}{path}"),
                    query: args
                        .get("query")
                        .filter(|q| crate::util::truthy(q))
                        .map(js_string)
                        .unwrap_or_default(),
                    headers,
                    body,
                    listener,
                },
                true,
            )
            .await
        {
            Ok(v) => Ok(text(v)),
            Err(e) => Ok(refusal(&e)),
        }
    }
}

fn cut16(s: &str, n: usize) -> String {
    let u: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&u)
}

trait HintS {
    fn hint_s(self, h: &str) -> Self;
}

impl HintS for VaultError {
    fn hint_s(self, h: &str) -> Self {
        crate::err::DenyExt::hinted(self, h)
    }
}

/// `#sessionProblem(token, listener, { record })`: `(detail, error)`.
fn session_problem(
    core: &mut crate::state::Core,
    token: &str,
    listener: Option<&ListenerInfo>,
    record: bool,
) -> Option<(String, Option<VaultError>)> {
    if token.is_empty() {
        return Some((
            "no session token was sent with this connection".into(),
            None,
        ));
    }
    let Some(found) = core.vault.session_by_token(token).ok().flatten() else {
        return Some((
            "that session token is not recognised; it may belong to a vault that was reset".into(),
            None,
        ));
    };
    match core
        .vault
        .assert_session_usable(
            Some(&found),
            lctx(listener).as_ref(),
            UsableOptions {
                peek: false,
                record,
            },
        )
        .v()
    {
        Ok(_) => None,
        Err(e) => Some((e.detail.clone(), Some(e))),
    }
}

/// `#grantFor(session, cred)`.
fn grant_for(
    core: &mut crate::state::Core,
    s: &SessionRecord,
    cred: &av_store::model::CredentialRecord,
) -> R<Result<av_store::model::GrantRecord, Value>> {
    if let Some(g) = core
        .vault
        .grants_for_session(&s.id)
        .v()?
        .into_iter()
        .find(|g| g.credential_id == cred.id)
    {
        return Ok(Ok(g));
    }
    if core
        .vault
        .find_grant(&s.id, &cred.id)
        .v()?
        .is_some_and(|g| g.state == av_store::model::GrantState::Expired)
    {
        let e = crate::err::d(C::GrantExpired, format!("this session's grant for {} expired", cred.slug))
            .hint_s("This grant's lifetime ran out; the session may still hold others. Ask a human for a new grant.");
        let mut body = Map::new();
        body.insert("error".into(), e.detail.clone().into());
        body.insert("code".into(), "AV_GRANT_EXPIRED".into());
        body.insert("hint".into(), e.hint().into());
        return Ok(Err(error_text(Value::Object(body))));
    }
    Ok(Err(
        json!({"content": [{"type": "text", "text": js_pretty(&json!({"error": format!("this session has no grant for {}", cred.slug)}))}]}),
    ))
}

/// `#describeAccess(session)`.
fn describe_access(core: &mut crate::state::Core, s: &SessionRecord) -> R<Value> {
    let mut grants = Vec::new();
    for g in core.vault.grants_for_session(&s.id).v()? {
        let cred = core
            .vault
            .credential(&g.credential_id)
            .v()?
            .ok_or_else(|| crate::err::internal("no credential"))?;
        let profile = av_core::profiles::get_profile(&cred.connector_kind)
            .map_err(|e| crate::err::internal(e.to_string()))?;
        let ceiling = profile.policy_ceiling();
        let effective = policy::intersect(&[Some(&ceiling), Some(&s.policy), Some(&g.policy)]);
        let remaining = match policy::budget_limit(effective.budget.as_ref()) {
            policy::BudgetLimit::Unlimited => Value::Null,
            policy::BudgetLimit::Unreadable => Value::from(0),
            policy::BudgetLimit::Limit(l) => Value::from(l.saturating_sub(g.budget_used)),
        };
        let spend = match core.pl_spend_for(&g.id) {
            Ok(Some(sp)) => {
                let mut m = Map::new();
                if !sp["limit_tokens"].is_null() {
                    m.insert(
                        "tokens".into(),
                        json!((sp["limit_tokens"].as_i64().unwrap_or(0)
                            - sp["tokens_used"].as_i64().unwrap_or(0)
                            - sp["reserved_tokens"].as_i64().unwrap_or(0))
                        .max(0)),
                    );
                }
                if !sp["limit_usd_micros"].is_null() {
                    m.insert(
                        "usd_micros".into(),
                        json!((sp["limit_usd_micros"].as_i64().unwrap_or(0)
                            - sp["usd_micros_used"].as_i64().unwrap_or(0)
                            - sp["reserved_usd_micros"].as_i64().unwrap_or(0))
                        .max(0)),
                    );
                }
                Value::Object(m)
            }
            Ok(None) => Value::Null,
            Err(_) => json!({"tokens": 0, "usd_micros": 0}),
        };
        let put: Vec<String> = cred
            .fields
            .iter()
            .filter(|f| g.fields.contains(&f.name))
            .flat_map(|f| {
                f.sites
                    .iter()
                    .map(|x| describe(x, None))
                    .collect::<Vec<_>>()
            })
            .collect();
        grants.push(json!({
            "cred": cred.slug, "kind": cred.connector_kind, "base_url": format!("/p/{}", cred.slug),
            "put_it_at": put, "quarantined": cred.quarantine.is_some(), "expires_at": g.expires_at,
            "effective": policy::describe_effective(&effective), "budget_remaining": remaining, "spend_remaining": spend,
        }));
    }
    Ok(json!({
        "session": {"id": s.id, "label": s.label, "expires_at": s.expires_at, "infinite": s.infinite, "remote": s.remote},
        "grants": grants,
        "templates": McpServer::templates_of(core),
        "next": "need more? call vault_request_session; it creates nothing until a human approves",
    }))
}

/// `randomUUID()`.
fn uuid4() -> String {
    let mut b = crate::util::random_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::util::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Serve the MCP server over newline-delimited JSON-RPC. Ports
/// `serveStdio(server, input, output)`; the session and token come from
/// `resolve` for each message (the bridge re-reads its state file).
pub async fn serve_stdio<Rd, W, F>(
    server: Arc<McpServer>,
    input: Rd,
    output: W,
    resolve: F,
) -> std::io::Result<()>
where
    Rd: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn() -> (Option<SessionRecord>, Option<String>),
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut lines = tokio::io::BufReader::new(input).lines();
    let mut output = output;
    while let Some(line) = lines.next_line().await? {
        let line = crate::pipeline::js_trim(&line).to_string();
        if line.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let (session, token) = resolve();
        if let Some(r) = server.handle(message, session, token, None).await {
            output
                .write_all(format!("{}\n", crate::util::js_stringify(&r)).as_bytes())
                .await?;
            output.flush().await?;
        }
    }
    Ok(())
}
