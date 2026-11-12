//! The daemon: control socket (`#onControl`), gateway, discovery routes,
//! Streamable HTTP MCP, extra listeners, presence gating and the session
//! request flow. Ports `src/daemon/server.js`.
//!
//! Every control route in `#onControl`, with its request and response
//! shapes, status codes and `AV_*` codes, is frozen (PLAN.md, "Frozen
//! external contract" items 1 and 2). Each route's body mirrors the JS case
//! of the same name; the comments there explain the why.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use av_core::errors::VaultError;
use av_core::policy::{self, Checked};
use av_core::secret::SecretString;
use av_store::model::PlaceholderState;
use av_store::vault::{CreateGrantOptions, CreateSessionOptions, IssueOptions};
use serde_json::{json, Map, Value};

use crate::err::{d, dr, internal, rule_of, DenyExt, C};
use crate::http::{json_pretty, Resp};
use crate::mcp::McpServer;
use crate::notify::{Notifier, NotifierOptions};
use crate::pipeline::{ApprovalFilter, GatewayRequest, ListenerInfo, Pipeline, PipelineOptions};
use crate::session_requests::{
    self as srq, elevation_of, grant_specs_of, overrides_of, overrides_problem, proposal_of,
    resolve_template, shape_of, template_creds, template_summary, OWNER_FIELDS,
};
use crate::state::{Core, StoreResult, VaultRef};
use crate::ui::webauthn;
use crate::util::{
    as_finite, as_integer, as_whole, iso_now, iso_of_ms, js_string, now_ms, num, search_param,
};

type R<T> = Result<T, VaultError>;

/// The daemon's version, reported on `/v1/status` and to MCP clients.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The port the web UI listens on by default. Ports `DEFAULT_UI_PORT`.
pub const DEFAULT_UI_PORT: u16 = 7412;
/// The gateway's default port.
pub const DEFAULT_GATEWAY_PORT: u16 = 7411;
/// Largest request body read. Ports `MAX_BODY`.
pub const MAX_BODY: usize = 16 * 1024 * 1024;
/// Most grants in one session. Ports `MAX_GRANTS`.
pub const MAX_GRANTS: usize = 16;
/// Most items in one batch. Ports `MAX_BATCH`.
pub const MAX_BATCH: usize = 32;
/// Most headers in a preflight. Ports `MAX_PREFLIGHT_HEADERS`.
pub const MAX_PREFLIGHT_HEADERS: usize = 100;
/// Open WebAuthn challenges at once. Ports `MAX_OPEN_CHALLENGES`.
pub const MAX_OPEN_CHALLENGES: usize = 64;
/// Largest signed operation. Ports `MAX_OPERATION_BYTES`.
pub const MAX_OPERATION_BYTES: usize = 8 * 1024;
/// Passphrase attempts before backoff. Ports `PASSPHRASE_FREE_ATTEMPTS`.
pub const PASSPHRASE_FREE_ATTEMPTS: u32 = 5;
/// Cap on the doubling backoff. Ports `PASSPHRASE_MAX_BACKOFF_MS`.
pub const PASSPHRASE_MAX_BACKOFF_MS: u64 = 30_000;
/// Largest audit page. Ports `AUDIT_PAGE_MAX`.
pub const AUDIT_PAGE_MAX: usize = 500;

const GRANT_FIELDS: [&str; 17] = [
    "cred",
    "hosts",
    "methods",
    "paths",
    "deny_paths",
    "budget",
    "approval",
    "uses",
    "rate",
    "max_concurrent",
    "quota",
    "routes",
    "payload",
    "redirects",
    "spend_tokens",
    "spend_usd",
    "grant_ttl_minutes",
];
const APPROVAL_MODES: [&str; 4] = ["each", "on-write", "first-use", "auto"];

fn narrow_fields() -> Vec<&'static str> {
    GRANT_FIELDS
        .iter()
        .copied()
        .filter(|f| *f != "cred" && *f != "uses")
        .collect()
}

/// The class name recorded for a fault: an `AV_*` code, else `other`.
/// Ports `errorClass(err)`.
/// The class a panic is recorded under in `daemon.handler_error`: what JS
/// `errorClass` gives a plain `Error`.
pub const PANIC_CLASS: &str = "Error";

/// Whether a handler answered with a fault (an [`crate::err::internal`]
/// error that reached the response), which `#guard` would have caught.
fn answers_fault(r: &Resp) -> bool {
    if r.status() != 500 {
        return false;
    }
    let crate::http::AvBody::Full(Some(b)) = r.body() else {
        return false;
    };
    serde_json::from_slice::<Value>(b)
        .is_ok_and(|v| v["code"] == "AV_INTERNAL" && v["detail"] == crate::err::FAULT_DETAIL)
}

/// `errorClass(err)` for a panic: its class, never its message (C28).
fn fault_class(fault: &(dyn std::any::Any + Send)) -> String {
    let _ = fault;
    PANIC_CLASS.to_string()
}

/// A handler future whose panic is caught where it is polled, in the same
/// task (`catch_unwind` on each poll).
struct CatchUnwind<F: std::future::Future> {
    inner: std::pin::Pin<Box<F>>,
}

impl<F: std::future::Future> std::future::Future for CatchUnwind<F> {
    type Output = Result<F::Output, Box<dyn std::any::Any + Send>>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let inner = &mut self.inner;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.as_mut().poll(cx))) {
            Ok(p) => p.map(Ok),
            Err(fault) => std::task::Poll::Ready(Err(fault)),
        }
    }
}

pub fn error_class(err: &VaultError) -> String {
    err.code.as_str().to_string()
}

// --------------------------------------------------------------- listeners

/// A parsed `allow_cidr` list. Ports the `BlockList` of `parseAllowCidr`.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    /// `(network, prefix length)` blocks.
    pub blocks: Vec<(IpAddr, u8)>,
}

impl AllowList {
    /// `peerAllowed(allow, address)`: an IPv4-mapped peer counts as IPv4.
    pub fn allows(&self, address: &str) -> bool {
        let a = address
            .strip_prefix("::ffff:")
            .or_else(|| address.strip_prefix("::FFFF:"))
            .filter(|rest| rest.parse::<std::net::Ipv4Addr>().is_ok())
            .unwrap_or(address);
        let Ok(ip) = a.parse::<IpAddr>() else {
            return false;
        };
        self.blocks
            .iter()
            .any(|(net, prefix)| in_block(&ip, net, *prefix))
    }
}

fn in_block(ip: &IpAddr, net: &IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix as u32)
            };
            (u32::from(*a) & m) == (u32::from(*b) & m)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix as u32)
            };
            (u128::from(*a) & m) == (u128::from(*b) & m)
        }
        _ => false,
    }
}

/// A listener's `allow_cidr` as an allow list; `None` means no restriction.
/// Ports `parseAllowCidr(list)`.
pub fn parse_allow_cidr(list: Option<&Value>) -> Result<Option<AllowList>, String> {
    let Some(list) = list.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let Some(items) = list.as_array() else {
        return Err("allow_cidr must be a list of CIDR blocks".into());
    };
    if items.is_empty() {
        return Ok(None);
    }
    let mut allow = AllowList::default();
    for raw in items {
        let text = js_string(raw);
        let t = crate::pipeline::js_trim(&text);
        let bad = || format!("{} is not a CIDR block", crate::util::js_stringify(raw));
        let (addr, prefix) = t.split_once('/').ok_or_else(bad)?;
        if addr.is_empty()
            || addr.contains(char::is_whitespace)
            || prefix.is_empty()
            || prefix.len() > 3
            || !prefix.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(bad());
        }
        let ip: IpAddr = addr.parse().map_err(|_| bad())?;
        let p: u8 = prefix.parse().map_err(|_| bad())?;
        if p > if ip.is_ipv4() { 32 } else { 128 } {
            return Err(bad());
        }
        allow.blocks.push((ip, p));
    }
    Ok(Some(allow))
}

/// `iface:port`, where iface may be a name, an IPv4 literal, or `[v6]`.
/// Ports `parseAddress(address)`.
pub fn parse_address(address: &str) -> Result<(String, u16), String> {
    let s = crate::pipeline::js_trim(address);
    let shown = crate::util::js_stringify(&Value::from(address));
    let m = if let Some(rest) = s.strip_prefix('[') {
        rest.rsplit_once("]:")
            .filter(|(h, p)| {
                !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            })
            .map(|(h, p)| (h.to_string(), p.to_string()))
    } else {
        s.split_once(':')
            .filter(|(h, p)| {
                !h.is_empty()
                    && !h.contains(':')
                    && !p.contains(':')
                    && !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_digit())
            })
            .map(|(h, p)| (h.to_string(), p.to_string()))
    };
    let Some((host, port)) = m else {
        return Err(format!("address must be <host>:<port>, got {shown}"));
    };
    let port: u64 = port.parse().unwrap_or(u64::MAX);
    if port > 65535 {
        return Err(format!("bad port in {s}"));
    }
    Ok((host, port as u16))
}

/// Ports `isLoopbackHost(host)`.
pub fn is_loopback_host(host: &str) -> bool {
    if ["127.0.0.1", "::1", "localhost", "[::1]"].contains(&host) {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let octets: Vec<u32> = parts.iter().map(|p| p.parse().unwrap_or(999)).collect();
    if octets.iter().any(|n| *n > 255) {
        return false;
    }
    octets[0] == 127
}

/// The refusal for a quarantined credential. Ports `quarantined(cred)`.
pub fn quarantined(slug: &str) -> VaultError {
    dr(
        C::Quarantined,
        format!("{slug} is quarantined"),
        "quarantine",
    )
    .hinted(format!(
        "A human can release it: agent-vault cred release {slug}"
    ))
}

fn ui_origin_ok(origin: &str) -> bool {
    let Some(port) = origin.strip_prefix("http://localhost:") else {
        return false;
    };
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| p > 0 && p <= 65535)
}

// ----------------------------------------------------------- daemon state

#[derive(Debug, Clone)]
struct OpChallenge {
    challenge: [u8; 32],
    operation: Value,
    expires: i64,
}

/// The daemon's in-memory state. Ports the instance fields of `Daemon`.
#[derive(Debug)]
pub struct DaemonState {
    /// End of the passphrase window.
    pub presence_grace_until: i64,
    presence_grace_ms: i64,
    op_challenges: Vec<(String, OpChallenge)>,
    passphrase_failures: u32,
    passphrase_locked_until: i64,
    refused_peers: HashMap<String, i64>,
    ui_port: u16,
    configured_ui_origins: Vec<String>,
}

impl Default for DaemonState {
    fn default() -> Self {
        DaemonState {
            presence_grace_until: 0,
            presence_grace_ms: 5 * 60_000,
            op_challenges: Vec::new(),
            passphrase_failures: 0,
            passphrase_locked_until: 0,
            refused_peers: HashMap::new(),
            ui_port: DEFAULT_UI_PORT,
            configured_ui_origins: Vec::new(),
        }
    }
}

/// What a fresh-presence gate needs after the lock: nothing, or an Argon2
/// check of this passphrase.
enum Fresh {
    Done,
    Passphrase(String),
}

impl Core {
    /// `#waitingItems()`.
    pub fn dm_waiting_items(&mut self) -> Vec<Value> {
        let mut out: Vec<Value> = self
            .pl_pending_approvals()
            .into_iter()
            .map(|a| json!({"kind": "request", "id": a["id"], "headline": a["summary"], "created_at": a["created_at"]}))
            .collect();
        for r in self.sr_pending() {
            out.push(json!({"kind": "session", "id": r.id, "headline": r.summary, "created_at": r.created_at}));
        }
        out
    }

    /// `#denyPendingSessionRequests(reason)`.
    pub fn dm_deny_pending_session_requests(&mut self, reason: &str) -> R<usize> {
        let mut n = 0;
        for mut record in self.sr_pending() {
            let mut shape = self.dm_request_shape(&record, "denied")?;
            shape["actor"] = reason.into();
            shape["reason"] = reason.into();
            self.audit("session_request.denied", shape)?;
            record.state = "denied".into();
            record.decided_at = Some(iso_now());
            self.sr_put(record);
            n += 1;
        }
        if n > 0 {
            self.sr_save();
        }
        Ok(n)
    }

    fn dm_request_shape(&self, record: &srq::SrRecord, decision: &str) -> R<Value> {
        let cred = match record.proposal.get("cred").and_then(Value::as_str) {
            Some(c) => self.vault.find_credential(c).v()?.map(|c| c.slug),
            None => None,
        };
        Ok(
            json!({"request_id": record.id, "decision": decision, "cred": cred, "proposed": shape_of(&record.proposal)["fields"]}),
        )
    }

    /// How many op-gate challenges are open (tests).
    pub fn dm_open_challenges(&self) -> usize {
        self.dm.op_challenges.len()
    }

    /// `#throttlePassphrase()`.
    fn dm_throttle(&self) -> R<()> {
        let now = now_ms();
        if now < self.dm.passphrase_locked_until {
            let wait = ((self.dm.passphrase_locked_until - now) as f64 / 1000.0).ceil() as u64;
            let mut e = dr(
                C::RateLimited,
                format!("too many failed passphrase attempts; try again in {wait}s"),
                "passphrase_throttle",
            );
            e.extra.retry_after = Some(wait);
            return Err(e);
        }
        Ok(())
    }

    /// `#recordPassphraseAttempt(ok)`.
    fn dm_record_attempt(&mut self, ok: bool) {
        if ok {
            self.dm.passphrase_failures = 0;
            self.dm.passphrase_locked_until = 0;
            return;
        }
        self.dm.passphrase_failures += 1;
        if self.dm.passphrase_failures < PASSPHRASE_FREE_ATTEMPTS {
            return;
        }
        let over = self.dm.passphrase_failures - PASSPHRASE_FREE_ATTEMPTS;
        let backoff = 1000u64
            .saturating_mul(1u64.checked_shl(over).unwrap_or(u64::MAX))
            .min(PASSPHRASE_MAX_BACKOFF_MS);
        self.dm.passphrase_locked_until = now_ms() + backoff as i64;
        let until = iso_of_ms(self.dm.passphrase_locked_until);
        let failures = self.dm.passphrase_failures;
        self.audit_opt(
            "presence.throttled",
            json!({"consecutive_failures": failures, "until": until}),
        );
    }

    fn dm_factors(&self) -> R<Vec<String>> {
        let mut f = Vec::new();
        if self.vault.has_passphrase().v()? {
            f.push("passphrase".to_string());
        }
        if self.vault.presence_key().v()?.is_some() {
            f.push("authenticator".to_string());
        }
        Ok(f)
    }

    /// `uiOrigins()`.
    pub fn dm_ui_origins(&self) -> Vec<String> {
        let mut out = vec![format!("http://localhost:{}", self.dm.ui_port)];
        for o in self
            .dm
            .configured_ui_origins
            .iter()
            .cloned()
            .chain(self.vault.ui_origins().unwrap_or_default())
        {
            if !out.contains(&o) {
                out.push(o);
            }
        }
        out
    }

    /// `#verifyOpAssertion(operation, presence)`.
    fn dm_verify_op_assertion(&mut self, operation: &Value, presence: &Value) -> R<bool> {
        let Some(enrolled) = self.vault.presence_key().v()? else {
            return Ok(false);
        };
        let Some(cid) = presence
            .get("challengeId")
            .filter(|v| crate::util::truthy(v))
        else {
            return Ok(false);
        };
        let cid = js_string(cid);
        let pending = self
            .dm
            .op_challenges
            .iter()
            .position(|(k, _)| *k == cid)
            .map(|i| self.dm.op_challenges.remove(i).1);
        let Some(pending) = pending.filter(|p| p.expires >= now_ms()) else {
            return Ok(false);
        };
        if webauthn::canonical_operation(&pending.operation)
            != webauthn::canonical_operation(operation)
        {
            self.audit_opt("presence.denied", json!({"reason": "operation_mismatch"}));
            return Ok(false);
        }
        let origins = self.dm_ui_origins();
        let e = webauthn::EnrolledCredential::from_key(&enrolled);
        let null = Value::Null;
        let input = webauthn::AssertionInput {
            credential_id: presence.get("credentialId").unwrap_or(&null),
            authenticator_data: presence.get("authenticatorData").unwrap_or(&null),
            client_data_json: presence.get("clientDataJSON").unwrap_or(&null),
            signature: presence.get("signature").unwrap_or(&null),
            expected_challenge: &pending.challenge,
            expected_origins: &origins,
            rp_id: "localhost",
            enrolled: &e,
        };
        match webauthn::verify_assertion(&input) {
            Ok(count) => {
                if count > 0 {
                    self.vault.record_presence_sign_count(count).v()?;
                }
                Ok(true)
            }
            Err(err) => {
                self.audit_opt(
                    "presence.denied",
                    json!({"reason": webauthn::failure_of(&err)}),
                );
                Ok(false)
            }
        }
    }

    /// `#requireHumanForWidening(op, operation, presence)`.
    fn dm_require_human(
        &mut self,
        op: &str,
        operation: Option<&Value>,
        presence: Option<&Value>,
    ) -> R<()> {
        if now_ms() < self.dm.presence_grace_until {
            self.audit_opt("presence.window_used", json!({"op": op}));
            return Ok(());
        }
        if let (Some(p), Some(o)) = (presence.filter(|p| crate::util::truthy(p)), operation) {
            if self.dm_verify_op_assertion(o, p)? {
                self.audit_opt(
                    "presence.verified",
                    json!({"op": op, "factor": "webauthn-platform"}),
                );
                return Ok(());
            }
        }
        let factors = self.dm_factors()?;
        if factors.is_empty() {
            self.audit_opt("control.widening_ungated", json!({"op": op}));
            return Ok(());
        }
        let via = factors.iter().any(|f| f == "passphrase");
        Err(dr(
            C::PresenceRequired,
            format!("{op} needs a human: confirm your {}", factors.join(" or ")),
            "human_presence",
        )
        .factors(factors)
        .hinted(if via {
            "Run the command again; agent-vault will ask for your passphrase."
        } else {
            "Confirm it in the web UI with your authenticator: agent-vault ui"
        }))
    }

    /// The lock half of `#requireFreshPresence`.
    fn dm_fresh_begin(
        &mut self,
        op: &str,
        operation: &Value,
        presence: Option<&Value>,
    ) -> R<Fresh> {
        let p = presence.cloned().unwrap_or(Value::Null);
        if p.get("challengeId").is_some_and(crate::util::truthy)
            && self.dm_verify_op_assertion(operation, &p)?
        {
            self.audit_opt(
                "presence.verified",
                json!({"op": op, "factor": "webauthn-platform", "fresh": true}),
            );
            return Ok(Fresh::Done);
        }
        if let Some(pass) = p.get("passphrase").and_then(Value::as_str) {
            if self.vault.has_passphrase().v()? {
                self.dm_throttle()?;
                return Ok(Fresh::Passphrase(pass.to_string()));
            }
        }
        let factors = self.dm_factors()?;
        if factors.is_empty() {
            return Err(dr(C::PresenceRequired, format!("{op} needs a human factor, and none is enrolled"), "factor_required")
                .factors(vec![])
                .hinted("This change needs a human factor and none is enrolled. Set one first: agent-vault passphrase set"));
        }
        let via = factors.iter().any(|f| f == "passphrase");
        Err(dr(C::PresenceRequired, format!("{op} needs your {} for this one operation", factors.join(" or ")), "fresh_presence")
            .factors(factors)
            .hinted(if via {
                "This change needs your passphrase for this one operation, even inside a confirmation window. Run the command again; agent-vault will ask."
            } else {
                "Confirm it in the web UI with your authenticator: agent-vault ui"
            }))
    }

    fn dm_fresh_end(&mut self, op: &str, ok: bool) -> R<()> {
        self.dm_record_attempt(ok);
        if !ok {
            return Err(dr(
                C::PresenceDenied,
                "passphrase did not verify",
                "fresh_presence",
            ));
        }
        self.audit_opt(
            "presence.verified",
            json!({"op": op, "factor": "passphrase", "fresh": true}),
        );
        Ok(())
    }
}

// ------------------------------------------------------------------ Daemon

/// Construction options. Ports the options of `new Daemon(vault, opts)`.
#[derive(Clone)]
pub struct DaemonOptions {
    /// Gateway port (0 picks one).
    pub port: u16,
    /// Control socket path.
    pub socket_path: Option<PathBuf>,
    /// Gateway bind host.
    pub host: String,
    /// Group that may connect to the control socket.
    pub socket_group: Option<String>,
    /// The enrolled user's uid.
    pub enrolled_uid: Option<u32>,
    /// The trusted UI port.
    pub ui_port: u16,
    /// Extra trusted UI origins.
    pub ui_origins: Vec<String>,
    /// Pipeline options (the network, for tests).
    pub pipeline: PipelineOptions,
    /// Notifier options (the webhook sender, for tests).
    pub notify: NotifierOptions,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        DaemonOptions {
            port: DEFAULT_GATEWAY_PORT,
            socket_path: None,
            host: "127.0.0.1".into(),
            socket_group: None,
            enrolled_uid: None,
            ui_port: DEFAULT_UI_PORT,
            ui_origins: Vec::new(),
            pipeline: PipelineOptions::default(),
            notify: NotifierOptions::default(),
        }
    }
}

/// One bound listener.
pub(crate) struct Bound {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub stop: tokio::sync::watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<()>,
}

/// The daemon. Ports `class Daemon`.
pub struct Daemon {
    pub(crate) shared: VaultRef,
    pub(crate) pipeline: Arc<Pipeline>,
    pub(crate) mcp: Arc<McpServer>,
    pub(crate) notifier: Arc<Notifier>,
    pub(crate) opts: DaemonOptions,
    gateway_port: AtomicU16,
    pub(crate) listeners: tokio::sync::Mutex<Vec<Bound>>,
    tasks: Mutex<
        Vec<(
            tokio::sync::watch::Sender<bool>,
            tokio::task::JoinHandle<()>,
        )>,
    >,
    passphrase_gate: tokio::sync::Mutex<()>,
    upstream_for_probe: Option<Arc<dyn crate::upstream::Upstream>>,
}

impl Daemon {
    /// Ports `new Daemon(vault, opts)`.
    pub fn new(shared: VaultRef, opts: DaemonOptions) -> Result<Arc<Daemon>, String> {
        for o in &opts.ui_origins {
            if !ui_origin_ok(o) {
                return Err(format!(
                    "not a web UI origin: {} (http://localhost:<port>)",
                    crate::util::js_stringify(&Value::from(o.clone()))
                ));
            }
        }
        let notifier = Notifier::new(opts.notify.clone());
        notifier.bind(&shared);
        let (ui_port, origins) = (opts.ui_port, opts.ui_origins.clone());
        let n2 = notifier.clone();
        shared.run_sync(move |core| {
            core.dm.ui_port = ui_port;
            core.dm.configured_ui_origins = origins;
            core.notifier = Some(n2);
        });
        let probe_upstream = opts.pipeline.upstream.clone();
        let pipeline = Arc::new(Pipeline::new(shared.clone(), opts.pipeline.clone()));
        let mcp = Arc::new(McpServer::new(shared.clone(), pipeline.clone()));
        let d = Arc::new(Daemon {
            shared,
            pipeline,
            mcp,
            notifier,
            opts,
            gateway_port: AtomicU16::new(0),
            listeners: tokio::sync::Mutex::new(Vec::new()),
            tasks: Mutex::new(Vec::new()),
            passphrase_gate: tokio::sync::Mutex::new(()),
            upstream_for_probe: probe_upstream,
        });
        d.mcp.set_daemon(Arc::downgrade(&d));
        Ok(d)
    }

    /// The shared state.
    pub fn shared(&self) -> &VaultRef {
        &self.shared
    }

    /// The pipeline.
    pub fn pipeline(&self) -> &Arc<Pipeline> {
        &self.pipeline
    }

    /// The MCP server.
    pub fn mcp(&self) -> &Arc<McpServer> {
        &self.mcp
    }

    /// The gateway's bound port, once started.
    pub fn gateway_port(&self) -> Option<u16> {
        match self.gateway_port.load(Ordering::SeqCst) {
            0 => None,
            p => Some(p),
        }
    }

    /// `uiOrigins()`.
    pub async fn ui_origins(&self) -> Vec<String> {
        self.shared
            .run(|core| core.dm_ui_origins())
            .await
            .unwrap_or_default()
    }

    /// `allowUiOrigin(origin)`: in process, by whoever runs the daemon.
    pub async fn allow_ui_origin(&self, origin: &str) -> Result<Vec<String>, String> {
        if !ui_origin_ok(origin) {
            return Err(format!(
                "not a web UI origin: {} (http://localhost:<port>)",
                crate::util::js_stringify(&Value::from(origin))
            ));
        }
        let o = origin.to_string();
        Ok(self
            .shared
            .run(move |core| {
                if !core.dm.configured_ui_origins.contains(&o) {
                    core.dm.configured_ui_origins.push(o);
                }
                core.dm_ui_origins()
            })
            .await
            .unwrap_or_default())
    }

    /// Bind the gateway, the control socket and every configured listener.
    /// Ports `Daemon.start()`.
    pub async fn start(self: &Arc<Self>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.opts.host, self.opts.port);
        let gateway = tokio::net::TcpListener::bind(&addr).await?;
        let port = gateway.local_addr()?.port();
        self.gateway_port.store(port, Ordering::SeqCst);
        self.shared
            .run(move |core| core.gateway_port = port)
            .await
            .ok();
        let me = self.clone();
        self.spawn_loop(crate::listen::serve_tcp(gateway, None, move |req, peer| {
            let me = me.clone();
            async move { me.on_gateway(req, None, peer).await }
        }));
        if let Some(sock) = self.opts.socket_path.clone() {
            let limit = if cfg!(target_os = "macos") { 104 } else { 108 };
            let len = sock.as_os_str().len();
            if len >= limit {
                return Err(std::io::Error::other(format!(
                    "the control socket path is {len} bytes and the limit is {limit}: {}\nUse a shorter AGENT_VAULT_DIR.",
                    sock.display()
                )));
            }
            let listener = crate::listen::bind_unix(&sock)?;
            crate::listen::secure_socket(
                &self.shared,
                &sock,
                self.opts.socket_group.as_deref(),
                self.opts.enrolled_uid,
            )
            .await;
            let me = self.clone();
            let enrolled = self.opts.enrolled_uid;
            self.spawn_loop(crate::listen::serve_unix(listener, enrolled, move |req| {
                let me = me.clone();
                async move { me.on_control(req).await }
            }));
        }
        let entries = self
            .shared
            .run(|core| core.vault.list_listeners().unwrap_or_default())
            .await
            .unwrap_or_default();
        let mut bound_ids = Vec::new();
        for entry in entries {
            match crate::listen::bind_listener(self, &entry).await {
                Ok(b) => {
                    bound_ids.push(b.id.clone());
                    self.listeners.lock().await.push(b);
                }
                Err(e) => {
                    let code = e.0.clone();
                    let id = entry.id.clone();
                    self.shared
                        .run(move |core| {
                            core.audit_opt(
                                "listen.bind_failed",
                                json!({"listener_id": id, "reason": code}),
                            )
                        })
                        .await
                        .ok();
                    eprintln!(
                        "agent-vault: listener {} ({}) did not bind: {}",
                        entry.id, entry.address, e.1
                    );
                }
            }
        }
        let sock = self
            .opts
            .socket_path
            .as_ref()
            .map(|p| p.display().to_string());
        self.shared
            .run(move |core| {
                core.audit_opt(
                    "daemon.start",
                    json!({"port": port, "socket": sock, "listeners": bound_ids}),
                )
            })
            .await
            .ok();
        Ok(())
    }

    fn spawn_loop(&self, fut: impl std::future::Future<Output = ()> + Send + 'static) {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = fut => {}
                _ = rx.changed() => {}
            }
        });
        self.tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((tx, task));
    }

    /// Ports `Daemon.bindListener(entry)` (exposed for tests).
    pub async fn bind_listener(
        self: &Arc<Self>,
        entry: &av_store::model::ListenerRecord,
    ) -> Result<(String, u16), String> {
        let b = crate::listen::bind_listener(self, entry)
            .await
            .map_err(|e| e.1)?;
        let out = (b.host.clone(), b.port);
        self.listeners.lock().await.push(b);
        Ok(out)
    }

    /// Close every listener, the notifier and pending work. Ports `stop()`.
    pub async fn stop(&self) {
        self.notifier.close();
        let tasks: Vec<_> =
            std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|p| p.into_inner()));
        for (tx, t) in tasks {
            let _ = tx.send(true);
            let _ = t.await;
        }
        for b in std::mem::take(&mut *self.listeners.lock().await) {
            let _ = b.stop.send(true);
            b.task.abort();
        }
        if let Some(p) = &self.opts.socket_path {
            let _ = std::fs::remove_file(p);
        }
        self.shared
            .run(|core| core.audit_opt("daemon.stop", json!({})))
            .await
            .ok();
    }

    /// `#unbindListener(lid)`.
    async fn unbind_listener(&self, lid: &str) -> bool {
        let found = {
            let mut l = self.listeners.lock().await;
            l.iter().position(|b| b.id == lid).map(|i| l.remove(i))
        };
        let Some(b) = found else { return false };
        let _ = b.stop.send(true);
        b.task.abort();
        let _ = b.task.await;
        let id = lid.to_string();
        self.shared
            .run(move |core| core.audit_opt("listen.unbound", json!({"listener_id": id})))
            .await
            .ok();
        true
    }

    /// `#peerRefused(listenerId, address)`.
    pub(crate) async fn peer_refused(&self, listener_id: &str, address: &str) {
        let (lid, addr) = (listener_id.to_string(), address.to_string());
        self.shared
            .run(move |core| {
                let key = format!("{lid}|{addr}");
                let now = now_ms();
                if now - core.dm.refused_peers.get(&key).copied().unwrap_or(0) < 60_000 {
                    return;
                }
                if core.dm.refused_peers.len() >= 256 {
                    core.dm.refused_peers.clear();
                }
                core.dm.refused_peers.insert(key, now);
                core.audit_opt("listen.peer_refused", json!({"listener_id": lid, "peer": if addr.is_empty() { "unknown".to_string() } else { addr }}));
            })
            .await
            .ok();
    }

    // ------------------------------------------------------------ gates

    async fn require_human(
        &self,
        op: &str,
        operation: Option<Value>,
        presence: Option<Value>,
    ) -> R<()> {
        let op = op.to_string();
        self.shared
            .run(move |core| core.dm_require_human(&op, operation.as_ref(), presence.as_ref()))
            .await?
    }

    async fn require_fresh(&self, op: &str, operation: Value, presence: Option<Value>) -> R<()> {
        let _gate = self.passphrase_gate.lock().await;
        let op_c = op.to_string();
        let begun = self
            .shared
            .run(move |core| core.dm_fresh_begin(&op_c, &operation, presence.as_ref()))
            .await??;
        match begun {
            Fresh::Done => Ok(()),
            Fresh::Passphrase(p) => {
                let ok = self.shared.verify_passphrase(SecretString::from(p)).await;
                let op_c = op.to_string();
                self.shared
                    .run(move |core| core.dm_fresh_end(&op_c, ok))
                    .await?
            }
        }
    }

    async fn gate_session(
        &self,
        op: &str,
        operation: Value,
        elevated: &[String],
        presence: Option<Value>,
    ) -> R<()> {
        if !elevated.is_empty() {
            self.require_fresh(op, operation, presence).await
        } else {
            self.require_human(op, Some(operation), presence).await
        }
    }

    /// `#wideningOperation(route, url, input)`.
    fn widening_operation(route: &str, query: &str, input: &Value) -> R<Option<Value>> {
        let of = |op: &str, params: &Value| crate::util::operation_for(op, params).map(Some);
        let q = |k: &str| search_param(query, k).map_or(Value::Null, Value::from);
        match route {
            "POST /v1/credentials" => of("cred.add", input),
            "DELETE /v1/credentials" => of("cred.remove", &json!({"slug": q("slug")})),
            "POST /v1/sessions" => of("session.create", input),
            "POST /v1/placeholders" => of("placeholder.issue", input),
            "POST /v1/placeholders/batch" => of("placeholder.issue_many", input),
            "POST /v1/approvals" => of(
                if input.get("granted") == Some(&Value::Bool(false)) {
                    "approval.deny"
                } else {
                    "approval.approve"
                },
                input,
            ),
            "POST /v1/pending/decide-many" => {
                let mut m = Map::new();
                if let Some(d) = input.get("decisions") {
                    m.insert("decisions".into(), d.clone());
                }
                of("pending.decide_many", &Value::Object(m))
            }
            "POST /v1/listeners" => of("listener.add", input),
            "POST /v1/factors/webauthn" => {
                let mut rest = input.as_object().cloned().unwrap_or_default();
                let action = rest.remove("action");
                if action.as_ref().and_then(Value::as_str) == Some("remove") {
                    of("touchid.remove", &json!({}))
                } else {
                    of("touchid.enroll", &Value::Object(rest))
                }
            }
            "POST /v1/presence" => of("presence.enroll", input),
            "POST /v1/ui/origins" => of("ui.origin_add", input),
            "POST /v1/credentials/rotate" => of("cred.rotate", input),
            "POST /v1/credentials/scrub" => of("cred.scrub_add", input),
            "DELETE /v1/credentials/scrub" => of(
                "cred.scrub_remove",
                &json!({"slug": q("slug"), "id": q("id")}),
            ),
            "POST /v1/credentials/expiry" => of("cred.expiry_set", input),
            "POST /v1/credentials/pins" => of("cred.pins_set", input),
            "DELETE /v1/credentials/pins" => of(
                "cred.pins_remove",
                &json!({"slug": q("slug"), "host": q("host"), "spki": q("spki")}),
            ),
            "POST /v1/credentials/release" => of("cred.release", input),
            "POST /v1/tripwires" => of("tripwires.set", input),
            "POST /v1/templates" => of("template.save", input),
            "POST /v1/backup/export" => of("backup.export", input),
            "POST /v1/backup/restore" => of("backup.restore", input),
            "POST /v1/notify" => of("notify.set", input),
            _ => Ok(None),
        }
    }
}

/// A gateway request as the HTTP layer hands it over.
pub struct Incoming {
    /// Method.
    pub method: String,
    /// The raw request target.
    pub target: String,
    /// Headers as Node's `req.headers`.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Incoming {
    /// The first header named `name` (lower-case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn token_of(req: &Incoming) -> String {
    if let Some(t) = req.header("av-session").filter(|t| !t.is_empty()) {
        return t.to_string();
    }
    let auth = req.header("authorization").unwrap_or("");
    let re = av_core::jsre::compile(r"(?i)^Bearer\s+").expect("bearer");
    re.replace(auth, "").into_owned()
}

fn problem(e: &VaultError) -> Resp {
    let mut h = Vec::new();
    if let Some(r) = e.extra.retry_after {
        h.push(("retry-after".to_string(), r.to_string()));
    }
    json_pretty(e.http(), &e.to_problem(), &h)
}

impl Daemon {
    // ---------------------------------------------------------- the gateway

    /// `#guard(req, res, fn)`: a handler that panics costs one request, not
    /// the daemon. The fault is recorded as `daemon.handler_error` by class
    /// only (a panic is JS's plain `Error`; its message never leaves), and
    /// the request is answered 500. Runs in the handler's own task, so the
    /// connection watch it was given still holds.
    pub(crate) async fn guard(
        self: &Arc<Self>,
        handler: impl std::future::Future<Output = Resp> + Send,
    ) -> Resp {
        match (CatchUnwind {
            inner: Box::pin(handler),
        })
        .await
        {
            Ok(r) => {
                if answers_fault(&r) {
                    let _ = self
                        .shared
                        .run(|core| {
                            core.audit_opt("daemon.handler_error", json!({"error": PANIC_CLASS}))
                        })
                        .await;
                }
                r
            }
            Err(fault) => {
                let class = fault_class(fault.as_ref());
                let _ = self
                    .shared
                    .run(move |core| {
                        core.audit_opt("daemon.handler_error", json!({"error": class}))
                    })
                    .await;
                crate::http::response(
                    500,
                    &[("content-type".into(), "application/problem+json".into())],
                    crate::util::js_stringify(
                        &json!({"code": "AV_INTERNAL", "detail": "the request could not be handled"}),
                    )
                    .into_bytes(),
                )
            }
        }
    }

    /// `#onGateway(req, res)`, under [`Daemon::guard`].
    pub(crate) async fn on_gateway(
        self: &Arc<Self>,
        req: Incoming,
        listener: Option<ListenerInfo>,
        peer: Option<String>,
    ) -> Resp {
        let me = Arc::clone(self);
        self.guard(async move { me.on_gateway_inner(req, listener, peer).await })
            .await
    }

    async fn on_gateway_inner(
        self: &Arc<Self>,
        req: Incoming,
        listener: Option<ListenerInfo>,
        _peer: Option<String>,
    ) -> Resp {
        let Some((path, query)) = crate::http::parse_target(&req.target, "http://placeholder")
        else {
            return crate::http::json_compact(
                500,
                &json!({"code": "AV_INTERNAL", "detail": "the request could not be handled"}),
            );
        };
        if path == "/mcp" {
            return self.on_mcp_http(req, listener).await;
        }
        if path.starts_with("/v1/") {
            return self.on_discovery(req, &path, &query, listener).await;
        }
        let result = self
            .pipeline
            .handle(GatewayRequest {
                method: req.method.clone(),
                path,
                query,
                headers: req.headers.clone(),
                body: if req.body.is_empty() {
                    None
                } else {
                    Some(req.body)
                },
                listener,
            })
            .await;
        match result.stream {
            Some(rx) => crate::http::streamed(
                result.status,
                &result.headers,
                crate::http::AvBody::Frames(rx),
            ),
            None => crate::http::response(result.status, &result.headers, result.body),
        }
    }

    /// `#onDiscovery(req, res, url, body)`.
    async fn on_discovery(
        self: &Arc<Self>,
        req: Incoming,
        path: &str,
        query: &str,
        listener: Option<ListenerInfo>,
    ) -> Resp {
        let token = token_of(&req);
        let json = |s: u16, v: Value| json_pretty(s, &v, &[]);
        let path = path.to_string();
        let query = query.to_string();
        let lctx = listener.as_ref().map(|l| av_store::vault::ListenerContext {
            id: Some(l.id.clone()),
            kind: Some(l.kind.clone()),
            remote: l.remote,
        });
        if path == "/v1/status" {
            return match self
                .shared
                .run(|core| -> R<Value> {
                    let mut s = serde_json::to_value(core.vault.stats().v()?).unwrap_or(json!({}));
                    let locked = core.vault.locked();
                    let mut out =
                        json!({"daemon_version": VERSION, "api_version": "1", "locked": locked});
                    if let Value::Object(m) = &mut s {
                        for (k, v) in m.iter() {
                            out[k] = v.clone();
                        }
                    }
                    Ok(out)
                })
                .await
            {
                Ok(Ok(v)) => json(200, v),
                Ok(Err(e)) | Err(e) => problem(&e),
            };
        }
        if path == "/v1/preflight" {
            if req.method != "POST" {
                return json(
                    404,
                    json!({"code": "AV_NOT_FOUND", "detail": "preflight is POST /v1/preflight"}),
                );
            }
            if req.header("origin").is_some_and(|v| !v.is_empty())
                || req.header("sec-fetch-site").is_some_and(|v| !v.is_empty())
            {
                return json(
                    403,
                    json!({"code": "AV_BROWSER_ORIGIN", "detail": "requests carrying Origin are refused"}),
                );
            }
            let (t, l) = (token.clone(), lctx.clone());
            let session = self
                .shared
                .run(move |core| -> R<Option<()>> {
                    let Some(s) = core.vault.session_by_token(&t).v()? else {
                        return Ok(None);
                    };
                    core.vault
                        .assert_session_usable(
                            Some(&s),
                            l.as_ref(),
                            av_store::vault::UsableOptions {
                                peek: true,
                                record: true,
                            },
                        )
                        .v()?;
                    Ok(Some(()))
                })
                .await;
            match session {
                Ok(Ok(Some(()))) => {}
                Ok(Ok(None)) => {
                    return json(
                        401,
                        json!({"code": "AV_SESSION_REQUIRED", "hint": "send Authorization: Bearer <session token>"}),
                    )
                }
                Ok(Err(e)) | Err(e) => return problem(&e),
            }
            let described = match preflight_request(&req.body) {
                Ok(x) => x,
                Err(e) => return problem(&e),
            };
            let (asked, assume) = described;
            let mut asked = asked;
            asked.headers.push(("av-session".into(), token));
            asked.listener = listener;
            return match self.pipeline.preflight(asked, assume).await {
                Ok(v) => json(200, v),
                Err(e) => problem(&e),
            };
        }
        let (t, l, m) = (token.clone(), lctx.clone(), req.method.clone());
        let port = self.gateway_port().unwrap_or(0);
        let out = self
            .shared
            .run(move |core| -> R<(u16, Value)> {
                let Some(session) = core.vault.session_by_token(&t).v()? else {
                    return Ok((401, json!({"code": "AV_SESSION_REQUIRED", "hint": "send Authorization: Bearer <session token>"})));
                };
                core.vault.assert_session_usable(Some(&session), l.as_ref(), Default::default()).v()?;
                let _ = port;
                match path.as_str() {
                    "/v1/session" => Ok((200, json!({"id": session.id, "label": session.label, "expires_at": session.expires_at, "infinite": session.infinite, "remote": session.remote}))),
                    "/v1/credentials" => {
                        let mut out = Vec::new();
                        for g in core.vault.grants_for_session(&session.id).v()? {
                            let cred = core.vault.credential(&g.credential_id).v()?.ok_or_else(|| internal("Cannot read properties of undefined (reading 'slug')"))?;
                            let limit = match &g.policy.budget {
                                Some(Checked::Valid(b)) => b.limit.as_ref().and_then(|l| policy::budget_integer(&serde_json::to_value(l).unwrap_or(Value::Null))).map(|n| n as i64).unwrap_or(0),
                                _ => 0,
                            };
                            out.push(json!({
                                "slug": cred.slug, "kind": cred.connector_kind, "base_url": format!("/p/{}", cred.slug),
                                "allowed": g.policy, "budget_remaining": limit - g.budget_used as i64,
                                "usage": cred.fields.iter().map(|f| json!({"field": f.name, "sites": f.sites.iter().map(|s| describe(s, None)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
                            }));
                        }
                        Ok((200, Value::Array(out)))
                    }
                    "/v1/placeholders" if m == "POST" => {
                        let Some(cred) = core.vault.find_credential(&search_param(&query, "cred").unwrap_or_default()).v()? else {
                            return Ok((404, json!({"code": "AV_NOT_FOUND"})));
                        };
                        let Some(grant) = core.vault.grants_for_session(&session.id).v()?.into_iter().find(|g| g.credential_id == cred.id) else {
                            return Ok((403, json!({"code": "AV_NO_GRANT"})));
                        };
                        let field = cred.fields.first().map(|f| f.name.clone());
                        let issued = core.vault.issue_placeholder(IssueOptions { grant_id: grant.id.clone(), field: field.clone(), uses: None, ttl_ms: None }).v()?;
                        let sites = cred.fields.first().map(|f| f.sites.clone()).unwrap_or_default();
                        Ok((200, json!({"placeholder": issued.placeholder, "usage": sites.iter().map(|s| describe(s, Some(&issued.placeholder))).collect::<Vec<_>>()})))
                    }
                    p => Ok((404, json!({"code": "AV_NOT_FOUND", "detail": format!("no discovery endpoint {p}")}))),
                }
            })
            .await;
        match out {
            Ok(Ok((s, v))) => json(s, v),
            Ok(Err(e)) | Err(e) => problem(&e),
        }
    }

    /// `#onMcpHttp(req, res, body, url)`.
    async fn on_mcp_http(self: &Arc<Self>, req: Incoming, listener: Option<ListenerInfo>) -> Resp {
        let mut session_header: Vec<(String, String)> = Vec::new();
        let send = |status: u16,
                    obj: Option<Value>,
                    sh: &[(String, String)],
                    extra: &[(String, String)]| {
            let mut h = vec![("content-type".to_string(), "application/json".to_string())];
            h.extend(sh.iter().cloned());
            h.extend(extra.iter().cloned());
            crate::http::response(
                status,
                &h,
                obj.map(|o| crate::util::js_stringify(&o).into_bytes())
                    .unwrap_or_default(),
            )
        };
        if req.header("origin").is_some_and(|v| !v.is_empty())
            || req.header("sec-fetch-site").is_some_and(|v| !v.is_empty())
        {
            return send(
                403,
                Some(
                    json!({"code": "AV_BROWSER_ORIGIN", "detail": "requests carrying Origin are refused"}),
                ),
                &[],
                &[],
            );
        }
        let token = token_of(&req);
        let (t, l) = (token.clone(), listener.clone());
        let session = self
            .shared
            .run(move |core| -> Option<av_store::model::SessionRecord> {
                let s = core.vault.session_by_token(&t).ok().flatten()?;
                let lc = l.as_ref().map(|l| av_store::vault::ListenerContext {
                    id: Some(l.id.clone()),
                    kind: Some(l.kind.clone()),
                    remote: l.remote,
                });
                core.vault
                    .assert_session_usable(
                        Some(&s),
                        lc.as_ref(),
                        av_store::vault::UsableOptions {
                            peek: true,
                            record: true,
                        },
                    )
                    .ok()
                    .map(|_| s)
            })
            .await
            .ok()
            .flatten();
        if !token.is_empty() && session.is_none() {
            session_header.push(("av-session-invalid".into(), "1".into()));
        }
        if req.method == "DELETE" {
            if let Some(sid) = req.header("mcp-session-id").filter(|s| !s.is_empty()) {
                self.mcp.close_session(sid, session.is_some()).await;
            }
            return send(204, None, &session_header, &[]);
        }
        if req.method == "GET" {
            let sid = req.header("mcp-session-id").unwrap_or("");
            if sid.is_empty() || !self.mcp.has_session(sid) {
                return send(
                    404,
                    Some(json!({"code": "AV_MCP_SESSION_UNKNOWN"})),
                    &session_header,
                    &[],
                );
            }
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let _ = tx.send(": agent-vault notification stream\n\n".into());
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(15_000)).await;
                    if tx.send(": ping\n\n".into()).is_err() {
                        return;
                    }
                }
            });
            return crate::http::streamed(
                200,
                &[
                    ("content-type".into(), "text/event-stream".into()),
                    ("cache-control".into(), "no-cache".into()),
                    ("connection".into(), "keep-alive".into()),
                ],
                crate::http::text_stream(rx),
            );
        }
        if req.method != "POST" {
            return send(
                405,
                Some(json!({"code": "AV_MCP_PROTOCOL", "detail": "use POST, GET or DELETE"})),
                &session_header,
                &[],
            );
        }
        let Ok(message) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&req.body)) else {
            return send(
                400,
                Some(
                    json!({"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}}),
                ),
                &session_header,
                &[],
            );
        };
        let invalid = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "invalid request"}});
        match &message {
            Value::Array(a) => {
                if a.is_empty() || !a.iter().all(Value::is_object) {
                    return send(400, Some(invalid), &session_header, &[]);
                }
            }
            Value::Object(_) => {}
            _ => return send(400, Some(invalid), &session_header, &[]),
        }
        let first_method = match &message {
            Value::Array(a) => a.first().and_then(|m| m.get("method")).cloned(),
            m => m.get("method").cloned(),
        };
        let is_init = first_method.as_ref().and_then(Value::as_str) == Some("initialize");
        if let Some(v) = req.header("mcp-protocol-version").filter(|v| !v.is_empty()) {
            if !is_init && !crate::mcp::PROTOCOL_VERSIONS.contains(&v) {
                return send(
                    400,
                    Some(
                        json!({"code": "AV_MCP_PROTOCOL", "detail": format!("unsupported MCP-Protocol-Version: {v}"), "supported": crate::mcp::PROTOCOL_VERSIONS}),
                    ),
                    &session_header,
                    &[],
                );
            }
        }
        let mut extra = Vec::new();
        if is_init {
            let sid = self.mcp.open_session(session.is_some()).await;
            extra.push(("mcp-session-id".to_string(), sid));
            extra.push((
                "mcp-protocol-version".to_string(),
                crate::mcp::LATEST_PROTOCOL.to_string(),
            ));
        } else if let Some(sid) = req.header("mcp-session-id").filter(|s| !s.is_empty()) {
            if !self.mcp.has_session(sid) {
                return send(
                    404,
                    Some(
                        json!({"code": "AV_MCP_SESSION_UNKNOWN", "detail": "unknown Mcp-Session-Id; call initialize again"}),
                    ),
                    &session_header,
                    &[],
                );
            }
        }
        let batch = message.is_array();
        let messages = match message {
            Value::Array(a) => a,
            m => vec![m],
        };
        let mut responses = Vec::new();
        for m in messages {
            if let Some(r) = self
                .mcp
                .handle(m, session.clone(), Some(token.clone()), listener.clone())
                .await
            {
                responses.push(r);
            }
        }
        if responses.is_empty() {
            return send(202, None, &session_header, &extra);
        }
        let body = if batch {
            Value::Array(responses)
        } else {
            responses.into_iter().next().unwrap_or(Value::Null)
        };
        send(200, Some(body), &session_header, &extra)
    }
}

/// `describeSite(parseSite(spec), placeholder)`.
pub(crate) fn describe(spec: &str, placeholder: Option<&str>) -> String {
    av_core::sites::parse_site(spec)
        .map(|s| {
            av_core::sites::describe_site(
                &s,
                placeholder.unwrap_or(av_core::sites::DEFAULT_PLACEHOLDER_HINT),
            )
        })
        .unwrap_or_default()
}

/// `preflightRequest(raw)`.
fn preflight_request(raw: &[u8]) -> R<(GatewayRequest, bool)> {
    let refuse = |detail: &str| {
        dr(C::PolicyDenied, detail, "preflight_shape").hinted("Send { method, path: \"/p/<slug>/…\", query?, headers?, body? | body_base64?, assume_placeholder? }.")
    };
    let text = if raw.is_empty() {
        "{}".to_string()
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    let input: Value = serde_json::from_str(&text).map_err(|_| refuse("the body is not JSON"))?;
    if !input.is_object() {
        return Err(refuse("the body is a JSON object"));
    }
    let method = input
        .get("method")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty() && m.len() <= 16 && m.bytes().all(|b| b.is_ascii_alphabetic()));
    let Some(method) = method else {
        return Err(refuse("method is an HTTP method name"));
    };
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| p.starts_with("/p/") || p.starts_with("/t/"));
    let Some(path) = path else {
        return Err(refuse("path starts with /p/<slug>/ or /t/<scheme>/<host>/"));
    };
    if input.get("query").is_some_and(|q| !q.is_string()) {
        return Err(refuse("query is a string"));
    }
    if input
        .get("assume_placeholder")
        .is_some_and(|q| !q.is_boolean())
    {
        return Err(refuse("assume_placeholder is true or false"));
    }
    if input.get("body").is_some() && input.get("body_base64").is_some() {
        return Err(refuse("send body or body_base64, not both"));
    }
    if input.get("body").is_some_and(|b| !b.is_string()) {
        return Err(refuse("body is a string"));
    }
    if let Some(b) = input.get("body_base64") {
        let ok = b.as_str().is_some_and(|s| {
            let t = s.trim_end_matches('=');
            s.len() - t.len() <= 2
                && t.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
        });
        if !ok {
            return Err(refuse("body_base64 is base64"));
        }
    }
    let pairs: Vec<Value> = match input.get("headers") {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Object(m)) => m.iter().map(|(k, v)| json!([k, v])).collect(),
        Some(_) => return Err(refuse("headers are [name, value] pairs or an object")),
        None => Vec::new(),
    };
    if pairs.len() > MAX_PREFLIGHT_HEADERS {
        return Err(refuse(&format!("at most {MAX_PREFLIGHT_HEADERS} headers")));
    }
    let mut headers = vec![("host".to_string(), "127.0.0.1".to_string())];
    for pair in pairs {
        let ok = pair
            .as_array()
            .filter(|a| a.len() == 2 && a[0].is_string() && a[1].is_string());
        let Some(a) = ok else {
            return Err(refuse("each header is a name and a string value"));
        };
        let n = a[0].as_str().unwrap_or("");
        if n.len() >= 3 && n[..3].eq_ignore_ascii_case("av-") || n.eq_ignore_ascii_case("host") {
            continue;
        }
        headers.push((n.to_string(), a[1].as_str().unwrap_or("").to_string()));
    }
    let body = match (input.get("body"), input.get("body_base64")) {
        (Some(b), _) => b.as_str().map(|s| s.as_bytes().to_vec()),
        (None, Some(b)) => b.as_str().map(crate::util::b64_lenient),
        _ => None,
    };
    Ok((
        GatewayRequest {
            method: method.to_uppercase(),
            path: path.to_string(),
            query: input
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            headers,
            body: body.filter(|b| !b.is_empty()),
            listener: None,
        },
        input.get("assume_placeholder") == Some(&Value::Bool(true)),
    ))
}

/// `requestSpec(final)`.
fn request_spec(final_: &Value) -> Value {
    let mut spec = final_.as_object().cloned().unwrap_or_default();
    let ttl = spec.remove("ttl_minutes");
    spec.remove("template");
    spec.remove("template_hash");
    spec.remove("template_version");
    if let Some(t) = ttl.filter(|t| !t.is_null()) {
        spec.insert(
            "ttl_hours".into(),
            match as_finite(&t).or_else(|| t.as_f64()) {
                Some(m) if t.is_number() => num(m / 60.0),
                _ => t,
            },
        );
    }
    Value::Object(spec)
}

/// `templateOf(proposal)`.
fn template_of(p: &Value) -> Option<(String, u32)> {
    let name = p.get("template").and_then(Value::as_str)?;
    let v = p.get("template_version").and_then(as_integer)?;
    Some((name.to_string(), v as u32))
}

fn without_proof(input: &Value) -> Value {
    let mut m = input.as_object().cloned().unwrap_or_default();
    m.remove("presence");
    m.remove("passphrase");
    Value::Object(m)
}

/// A plan of a session (`#planSession`'s result).
#[derive(Debug, Clone)]
struct PlanGrant {
    cred: av_store::model::CredentialRecord,
    probe_path: Option<String>,
    env: Option<(String, String)>,
    uses: Option<Value>,
    policy: policy::Policy,
    ttl_ms: Option<i64>,
    lint: Value,
}

#[derive(Debug, Clone)]
struct SessionPlan {
    label: Option<String>,
    ttl_ms: Option<i64>,
    infinite: bool,
    remote: bool,
    grants: Vec<PlanGrant>,
    elevated: Vec<String>,
    template: Option<(String, u32)>,
}

fn field<'a>(input: &'a Value, k: &str) -> R<Option<&'a Value>> {
    if input.is_null() {
        return Err(internal(format!(
            "Cannot read properties of null (reading '{k}')"
        )));
    }
    Ok(input.get(k))
}

impl Core {
    /// `#planSession(input, { savingTemplate, resolved })`.
    fn dm_plan_session(
        &mut self,
        input: &Value,
        saving_template: bool,
        resolved: bool,
    ) -> R<SessionPlan> {
        let shape = |detail: &str| {
            dr(C::PolicyDenied, detail, "session_shape")
                .hinted("A session is either one credential (cred and its limits at the top level) or grants: [{cred, …}, …], one entry per credential.")
        };
        if !input.is_object() {
            return Err(shape("send one of cred, grants or template"));
        }
        let has = |k: &str| input.get(k).is_some();
        if has("template") && (has("cred") || has("grants")) {
            return Err(shape("send one of cred, grants or template"));
        }
        if has("template") {
            if resolved {
                return Err(shape("a template cannot name another template"));
            }
            let (t, spec) = self.dm_resolve_template_input(input)?;
            let mut plan = self.dm_plan_session(&spec, saving_template, true)?;
            plan.template = Some((t.name, t.version));
            return Ok(plan);
        }
        if has("grants") && GRANT_FIELDS.iter().any(|f| has(f)) {
            return Err(shape("send one of cred, grants or template"));
        }
        let specs: Vec<Value> = if has("grants") {
            match input.get("grants") {
                Some(Value::Array(a)) if !a.is_empty() && a.len() <= MAX_GRANTS => a.clone(),
                _ => {
                    return Err(shape(&format!(
                        "grants is a list of 1 to {MAX_GRANTS} grant specs"
                    )))
                }
            }
        } else {
            let mut m = Map::new();
            for f in GRANT_FIELDS {
                if let Some(v) = input.get(f) {
                    m.insert(f.into(), v.clone());
                }
            }
            vec![Value::Object(m)]
        };
        let mut seen: Vec<Value> = Vec::new();
        for s in &specs {
            if !s.is_object() {
                return Err(shape("each grant spec must be an object"));
            }
            let c = s.get("cred").cloned().unwrap_or(Value::Null);
            if seen.contains(&c) {
                return Err(shape(&format!(
                    "credential {} appears twice",
                    crate::util::js_string(&c)
                )));
            }
            seen.push(c);
        }
        let invalid = |f: &str, detail: &str| {
            let mut e = dr(C::PolicyDenied, detail, "policy_invalid");
            e.extra.next = None;
            let _ = f;
            e
        };
        if input.get("label").is_some_and(|l| {
            !l.is_null() && !l.as_str().is_some_and(|s| s.encode_utf16().count() <= 80)
        }) {
            return Err(invalid(
                "label",
                "label is a string of at most 80 characters",
            ));
        }
        let ttl = |detail: &str| dr(C::PolicyDenied, detail, "ttl");
        if input
            .get("infinite")
            .is_some_and(|v| !v.is_null() && !v.is_boolean())
        {
            return Err(ttl("infinite is true or false"));
        }
        let infinite = input.get("infinite") == Some(&Value::Bool(true));
        if let Some(h) = input.get("ttl_hours").filter(|v| !v.is_null()) {
            if infinite {
                return Err(ttl("an infinite session has no lifetime to set"));
            }
            if !as_finite(h).is_some_and(|x| x > 0.0) {
                return Err(ttl("ttl_hours must be a positive number of hours"));
            }
        }
        if input
            .get("remote")
            .is_some_and(|v| !v.is_null() && !v.is_boolean())
        {
            return Err(invalid("remote", "remote is true or false"));
        }
        let remote = input.get("remote") == Some(&Value::Bool(true));
        if infinite && remote {
            return Err(dr(
                C::RemoteForbidden,
                "a session without expiry cannot be remote",
                "infinite_remote",
            ));
        }
        let strings = |v: &Value| {
            v.as_array()
                .is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty())))
        };
        let mut grants = Vec::new();
        for spec in &specs {
            let slug = spec
                .get("cred")
                .map(crate::util::js_string)
                .unwrap_or_else(|| "undefined".into());
            let cred = match spec.get("cred").and_then(Value::as_str) {
                Some(c) => self.vault.find_credential(c).v()?,
                None => None,
            };
            let Some(cred) = cred else {
                return Err(d(C::NotFound, format!("no credential {slug}")));
            };
            if cred.quarantine.is_some() && !saving_template {
                return Err(quarantined(&cred.slug));
            }
            if spec.get("approval").is_some_and(|a| {
                !a.is_null() && !a.as_str().is_some_and(|s| APPROVAL_MODES.contains(&s))
            }) {
                return Err(dr(
                    C::PolicyDenied,
                    "approval is not one of the four modes",
                    "approval",
                )
                .hinted("approval is one of: each, on-write, first-use, auto"));
            }
            if spec
                .get("methods")
                .is_some_and(|v| !v.is_null() && !strings(v))
            {
                return Err(invalid("methods", "methods must be a list of method names"));
            }
            if spec
                .get("paths")
                .is_some_and(|v| !v.is_null() && !strings(v))
            {
                return Err(invalid("paths", "paths must be a list of path globs"));
            }
            let budget = spec
                .get("budget")
                .filter(|v| !v.is_null())
                .map(policy::budget_integer);
            if budget == Some(None) {
                return Err(invalid(
                    "budget",
                    "budget must be a whole number of requests, 0 or more",
                ));
            }
            if budget == Some(Some(0)) {
                return Err(dr(
                    C::PolicyDenied,
                    "a budget of 0 allows no request at all",
                    "budget",
                )
                .hinted(
                    "Give a budget of at least 1, or leave it out for the connector default.",
                ));
            }
            if spec
                .get("uses")
                .is_some_and(|v| !v.is_null() && !as_integer(v).is_some_and(|n| n >= 1))
            {
                return Err(invalid("uses", "uses must be a whole number, 1 or more"));
            }
            if spec
                .get("grant_ttl_minutes")
                .is_some_and(|v| !v.is_null() && !as_integer(v).is_some_and(|n| n >= 1))
            {
                return Err(dr(
                    C::PolicyDenied,
                    "grant_ttl_minutes must be a whole number of minutes, 1 or more",
                    "grant_ttl",
                ));
            }
            let profile = av_core::profiles::get_profile(&cred.connector_kind)
                .map_err(|e| internal(e.to_string()))?;
            let hosts: Vec<String> = profile.hosts.iter().map(|s| s.to_string()).collect();
            let ceiling = policy::credential_host_ceiling(
                cred.connector.get("host").and_then(Value::as_str),
                &hosts,
            );
            let pol = policy::grant_policy_from_input(
                spec,
                &policy::GrantPolicyOptions {
                    profile: Some(profile),
                    ceiling: policy::GrantCeiling::Hosts(ceiling),
                    defaults: true,
                },
            )?;
            let lint = serde_json::to_value(policy::lint(
                &pol,
                &policy::ValidateOptions {
                    kind: Some(cred.connector_kind.clone()),
                },
            ))
            .unwrap_or(json!([]));
            grants.push(PlanGrant {
                ttl_ms: spec
                    .get("grant_ttl_minutes")
                    .and_then(as_integer)
                    .map(|m| m * 60_000),
                uses: spec.get("uses").filter(|v| !v.is_null()).cloned(),
                probe_path: profile
                    .probe
                    .map(|p| p.path.to_string())
                    .filter(|p| !p.is_empty()),
                env: profile.env.map(|e| (e.base.to_string(), e.key.to_string())),
                policy: pol,
                lint,
                cred,
            });
        }
        Ok(SessionPlan {
            label: input
                .get("label")
                .and_then(Value::as_str)
                .map(str::to_string),
            ttl_ms: input
                .get("ttl_hours")
                .and_then(as_finite)
                .map(|h| (h * 3_600_000.0) as i64),
            infinite,
            remote,
            grants,
            elevated: elevation_of(input),
            template: None,
        })
    }

    /// `#resolveTemplateInput(input)`.
    fn dm_resolve_template_input(
        &mut self,
        input: &Value,
    ) -> R<(av_store::model::TemplateRecord, Value)> {
        let name = input
            .get("template")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let Some(name) = name else {
            return Err(dr(
                C::PolicyDenied,
                "template is the name of a saved template",
                "session_shape",
            ));
        };
        let t = self
            .vault
            .get_template(name)
            .v()?
            .ok_or_else(|| d(C::NotFound, format!("no template {name}")))?;
        if input.get("template_hash").and_then(Value::as_str) != Some(t.hash.as_str()) {
            return Err(dr(C::PolicyDenied, "the template changed after you looked at it; review it again", "template_changed")
                .hinted("Fetch the template again, read what it now grants, and send its current template_hash."));
        }
        let mut overrides = input.as_object().cloned().unwrap_or_default();
        overrides.remove("template");
        overrides.remove("template_hash");
        overrides.remove("presence");
        let vault = &self.vault;
        let budget = |g: &Value| -> Option<u64> {
            let c = g.get("cred").and_then(Value::as_str)?;
            let cred = vault.find_credential(c).ok().flatten()?;
            av_core::profiles::get_profile(&cred.connector_kind)
                .ok()
                .map(|p| p.default_budget.limit)
        };
        let spec = resolve_template(
            &Value::Object(t.spec.clone()),
            &Value::Object(overrides),
            Some(&budget),
        )?;
        Ok((t, spec))
    }

    /// `#makeSession(plan, { template, requested })`.
    fn dm_make_session(
        &mut self,
        plan: &SessionPlan,
        template: Option<(String, u32)>,
        requested: bool,
    ) -> R<Value> {
        let from = plan.template.clone().or(template);
        let created = self
            .vault
            .create_session(CreateSessionOptions {
                label: plan.label.clone(),
                ttl_ms: plan.ttl_ms,
                infinite: plan.infinite,
                elevated: plan.elevated.clone(),
                policy: Default::default(),
                remote: plan.remote,
                template: from.as_ref().map(|t| t.0.clone()),
                template_version: from.as_ref().map(|t| t.1),
                requested,
                ..Default::default()
            })
            .v()?;
        let session = created.session.clone();
        let token = {
            use av_core::secret::ExposeSecret;
            created.token.expose_secret().to_string()
        };
        let port = self.gateway_port;
        let result = (|| -> R<Value> {
            if plan.infinite && !session.infinite {
                return Err(dr(
                    C::PolicyDenied,
                    "this vault cannot create a session without expiry",
                    "ttl",
                ));
            }
            let mut grants = Vec::new();
            for g in &plan.grants {
                let field = g.cred.fields.first().ok_or_else(|| {
                    internal("Cannot read properties of undefined (reading 'name')")
                })?;
                let grant = self
                    .vault
                    .create_grant(CreateGrantOptions {
                        session_id: session.id.clone(),
                        credential_id: g.cred.id.clone(),
                        fields: Some(vec![field.name.clone()]),
                        policy: g.policy.clone(),
                        ttl_ms: g.ttl_ms,
                        requested,
                        ..Default::default()
                    })
                    .v()?;
                let max_uses = match &grant.policy.placeholder_policy {
                    Some(Checked::Valid(p)) => p.max_uses,
                    _ => None,
                };
                let asked = g.uses.as_ref().and_then(as_whole);
                let uses = match max_uses {
                    None => asked,
                    Some(m) => Some(asked.unwrap_or(m).min(m)),
                };
                let issued = self
                    .vault
                    .issue_placeholder(IssueOptions {
                        grant_id: grant.id.clone(),
                        field: Some(field.name.clone()),
                        uses,
                        ttl_ms: None,
                    })
                    .v()?;
                grants.push(json!({
                    "cred": g.cred.slug, "grant_id": grant.id, "placeholder": issued.placeholder,
                    "usage": field.sites.iter().map(|s| describe(s, Some(&issued.placeholder))).collect::<Vec<_>>(),
                    "base_url": format!("http://127.0.0.1:{port}/p/{}", g.cred.slug),
                    "probe_path": g.probe_path,
                    "env": g.env.as_ref().map(|(b, k)| json!({"base": b, "key": k})),
                    "expires_at": grant.expires_at,
                    "lint": g.lint,
                }));
            }
            let first = grants.first().cloned().unwrap_or(Value::Null);
            Ok(json!({
                "session_id": session.id, "token": token, "label": session.label,
                "expires_at": session.expires_at, "infinite": session.infinite,
                "grants": grants,
                "grant_id": first["grant_id"], "placeholder": first["placeholder"], "usage": first["usage"],
                "base_url": first["base_url"], "probe_path": first["probe_path"], "lint": first["lint"],
            }))
        })();
        if result.is_err() {
            let _ = self.vault.revoke_session(&session.id, "incomplete");
        }
        result
    }

    /// The decision on one session request, after the gate. Ports
    /// `#settleSessionRequest(record, granted, final)`.
    fn dm_settle_session_request(
        &mut self,
        mut record: srq::SrRecord,
        granted: &Value,
        final_: Value,
    ) -> R<Value> {
        let Some(granted) = granted.as_bool() else {
            return Err(dr(
                C::PolicyDenied,
                "the verdict must be true or false",
                "bulk_decision",
            ));
        };
        if !granted {
            record.state = "denied".into();
            record.decided_at = Some(iso_now());
            self.sr_put(record.clone());
            self.sr_save();
            let mut shape = self.dm_request_shape(&record, "denied")?;
            shape["actor"] = "human".into();
            self.audit_opt("session_request.denied", shape);
            return Ok(record.redact());
        }
        if final_.get("infinite") == Some(&Value::Bool(true))
            && final_.get("ttl_minutes").is_some_and(|v| !v.is_null())
        {
            return Err(dr(
                C::PolicyDenied,
                "an infinite session has no lifetime to set, and this request names one",
                "ttl",
            ));
        }
        let mut spec = request_spec(&final_);
        spec["label"] = Value::from(format!("requested by an agent ({})", record.id));
        let plan = self.dm_plan_session(&spec, false, false)?;
        let created = self.dm_make_session(&plan, template_of(&record.proposal), true)?;
        record.state = "approved".into();
        record.decided_at = Some(iso_now());
        record.granted_proposal = Some(final_.clone());
        record.result = Some(created.clone());
        self.sr_put(record.clone());
        self.sr_save();
        let shape = shape_of(&final_);
        let narrowed = srq::narrowed_of(&record.proposal, &final_);
        let mut rec = self.dm_request_shape(&record, "approved")?;
        rec["actor"] = "human".into();
        rec["session_id"] = created["session_id"].clone();
        rec["granted"] = shape["fields"].clone();
        rec["counts"] = shape["counts"].clone();
        rec["edited"] = Value::Bool(!narrowed.is_empty());
        rec["narrowed"] = json!(narrowed);
        let mut ordered = Map::new();
        for k in [
            "request_id",
            "decision",
            "cred",
            "proposed",
            "actor",
            "session_id",
            "granted",
            "counts",
            "narrowed",
            "edited",
        ] {
            ordered.insert(k.into(), rec[k].clone());
        }
        self.audit_opt("session_request.approved", Value::Object(ordered));
        let mut out = record.redact();
        out["granted"] = final_;
        Ok(out)
    }

    /// `#handOver(record, via)`.
    fn dm_hand_over(&mut self, id: &str, via: &str) -> Option<Value> {
        let r = self.sr.find_mut(id)?;
        let result = r.result.take();
        r.state = "collected".into();
        self.sr_save();
        self.audit_opt(
            "session_request.collected",
            json!({"request_id": id, "via": via}),
        );
        result
    }

    /// `#settleOne(d)`.
    fn dm_settle_one(&mut self, d: &Value) -> R<Value> {
        let id = d.get("id").map(js_string).unwrap_or_default();
        if d.get("kind").and_then(Value::as_str) == Some("session") {
            let Some(record) = self.sr_get(&id) else {
                return Err(crate::err::d(
                    C::NotFound,
                    format!("no session request {id}"),
                ));
            };
            if record.state != "pending" {
                return Err(dr(
                    C::PolicyDenied,
                    format!("already {}", record.state),
                    "session_requests",
                ));
            }
            let final_ = merge(
                &record.proposal,
                &overrides_of(d.get("overrides").unwrap_or(&json!({}))),
            );
            return self.dm_settle_session_request(
                record,
                d.get("granted").unwrap_or(&Value::Null),
                final_,
            );
        }
        let Some(granted) = d.get("granted").and_then(Value::as_bool) else {
            return Err(dr(
                C::PolicyDenied,
                "the verdict must be true or false",
                "bulk_decision",
            ));
        };
        self.pl_decide_approval(&id, granted)
    }

    /// `#knows(d)`.
    fn dm_knows(&mut self, d: &Value) -> bool {
        let id = d.get("id").map(js_string).unwrap_or_default();
        if d.get("kind").and_then(Value::as_str) == Some("session") {
            return self.sr_get(&id).is_some();
        }
        self.pl_has_approval(&id)
    }

    /// `proposeSessionRequest(input)`.
    pub fn dm_propose(&mut self, input: &Value) -> R<(srq::SrRecord, String)> {
        if !input.is_object() {
            return Err(dr(
                C::PolicyDenied,
                "a session request is an object",
                "session_shape",
            ));
        }
        let owned: Vec<&str> = OWNER_FIELDS
            .iter()
            .copied()
            .filter(|f| input.get(*f).is_some())
            .collect();
        if !owned.is_empty() {
            return Err(dr(C::PolicyDenied, format!("a session request cannot carry {}", owned.join(" or ")), "owner_only_field")
                .hinted("Only the owner can choose the approval mode or an unlimited lifetime. Ask without it and say why in reason."));
        }
        let (proposal, from_template) = if input.get("template").is_some() {
            (self.dm_template_proposal(input)?, true)
        } else {
            (proposal_of(input), false)
        };
        let cred = proposal
            .get("cred")
            .filter(|c| crate::util::truthy(c))
            .cloned();
        let Some(cred) = cred else {
            return Err(d(C::NotFound, "a session request must name a credential"));
        };
        let found = match cred.as_str() {
            Some(c) => self.vault.find_credential(c).v()?,
            None => None,
        };
        if found.is_none() {
            return Err(d(
                C::NotFound,
                format!("no credential {}", js_string(&cred)),
            ));
        }
        self.dm_plan_session(&request_spec(&proposal), false, false)?;
        let reason = input
            .get("reason")
            .filter(|r| crate::util::truthy(r))
            .map(js_string);
        self.sr_propose(proposal, reason, from_template)
            .map_err(|e| {
                if e.code == C::TooManyRequests {
                    dr(C::PolicyDenied, e.detail.clone(), "session_requests")
                } else {
                    e
                }
            })
    }

    /// `#templateProposal(input)`.
    fn dm_template_proposal(&mut self, input: &Value) -> R<Value> {
        let name = input
            .get("template")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let Some(name) = name else {
            return Err(dr(
                C::PolicyDenied,
                "template is the name of a saved template",
                "session_shape",
            ));
        };
        let t = self
            .vault
            .get_template(name)
            .v()?
            .ok_or_else(|| d(C::NotFound, format!("no template {name}")))?;
        let spec = Value::Object(t.spec.clone());
        let creds = template_creds(&spec);
        if creds.len() != 1 || grant_specs_of(&spec).len() != 1 {
            return Err(dr(C::PolicyDenied, format!("template {} covers {} credentials; a request names exactly one", t.name, creds.len()), "template_multi_cred")
                .hinted("Ask with a template for one credential, or name the credential and its limits yourself."));
        }
        let mut narrowing = proposal_of(input).as_object().cloned().unwrap_or_default();
        let cred = narrowing.remove("cred");
        let ttl = narrowing.remove("ttl_minutes");
        if let Some(c) = cred {
            if c.as_str() != Some(creds[0].as_str()) {
                return Err(dr(
                    C::PolicyDenied,
                    format!(
                        "template {} is for {}, not {}",
                        t.name,
                        creds[0],
                        js_string(&c)
                    ),
                    "session_shape",
                ));
            }
        }
        let mut overrides = narrowing;
        if let Some(m) = ttl {
            let Some(mins) = as_finite(&m).filter(|x| *x > 0.0) else {
                return Err(dr(
                    C::PolicyDenied,
                    "ttl_minutes must be a positive number of minutes",
                    "ttl",
                ));
            };
            overrides.insert("ttl_hours".into(), num(mins / 60.0));
        }
        let vault = &self.vault;
        let budget = |g: &Value| -> Option<u64> {
            let c = g.get("cred").and_then(Value::as_str)?;
            let cred = vault.find_credential(c).ok().flatten()?;
            av_core::profiles::get_profile(&cred.connector_kind)
                .ok()
                .map(|p| p.default_budget.limit)
        };
        let resolved = resolve_template(&spec, &Value::Object(overrides), Some(&budget))?;
        let grant = grant_specs_of(&resolved)
            .into_iter()
            .next()
            .unwrap_or(json!({}));
        let mut proposal = Map::new();
        for k in GRANT_FIELDS {
            if let Some(v) = grant.get(k) {
                proposal.insert(k.into(), v.clone());
            }
        }
        if resolved.get("infinite") == Some(&Value::Bool(true)) {
            proposal.insert("infinite".into(), Value::Bool(true));
        } else if let Some(h) = resolved.get("ttl_hours") {
            proposal.insert("ttl_minutes".into(), num(h.as_f64().unwrap_or(0.0) * 60.0));
        }
        proposal.insert("template".into(), Value::from(t.name.clone()));
        proposal.insert("template_hash".into(), Value::from(t.hash.clone()));
        proposal.insert("template_version".into(), Value::from(t.version));
        Ok(Value::Object(proposal))
    }
}

/// `{ ...a, ...b }`.
fn merge(a: &Value, b: &Value) -> Value {
    let mut m = a.as_object().cloned().unwrap_or_default();
    if let Some(bm) = b.as_object() {
        for (k, v) in bm {
            m.insert(k.clone(), v.clone());
        }
    }
    Value::Object(m)
}

impl Daemon {
    /// `proposeSessionRequest(input)`.
    pub async fn propose_session_request(&self, input: Value) -> R<(Value, String)> {
        self.shared
            .run(move |core| core.dm_propose(&input).map(|(r, s)| (r.redact(), s)))
            .await?
    }

    /// The control API, under [`Daemon::guard`]. Ports `#onControl(req, res)`.
    pub(crate) async fn on_control(self: &Arc<Self>, req: Incoming) -> Resp {
        let me = Arc::clone(self);
        self.guard(async move { me.on_control_inner(req).await })
            .await
    }

    async fn on_control_inner(self: &Arc<Self>, req: Incoming) -> Resp {
        #[cfg(test)]
        if req.target == "/v1/test-only/panic" {
            panic!("a test-only handler fault with a secret-looking message: s3cr3t");
        }
        let json = |s: u16, v: Value| json_pretty(s, &v, &[]);
        let Some((path, query)) = crate::http::parse_target(&req.target, "http://control") else {
            return crate::http::json_compact(
                500,
                &json!({"code": "AV_INTERNAL", "detail": "the request could not be handled"}),
            );
        };
        let input: Value = if req.body.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return json(
                        400,
                        json!({"code": "AV_MCP_PROTOCOL", "detail": format!("request body is not valid JSON: {}", js_json_error(&e, &req.body))}),
                    )
                }
            }
        };
        let route = format!("{} {}", req.method, path);
        if route == "GET /v1/pending/stream" {
            let snap = self.shared.run(Notifier::waiting).await.unwrap_or_default();
            return match self.notifier.subscribe(snap) {
                Ok(rx) => crate::http::streamed(
                    200,
                    &[
                        ("content-type".into(), "text/event-stream".into()),
                        ("cache-control".into(), "no-cache".into()),
                        ("connection".into(), "keep-alive".into()),
                    ],
                    crate::http::text_stream(rx),
                ),
                Err(e) => json(e.http(), e.to_problem()),
            };
        }
        match self.control_route(&route, &query, input).await {
            Ok((s, v)) => json(s, v),
            Err(e) => json(e.http(), e.to_problem()),
        }
    }
}

/// `SyntaxError.message` for `JSON.parse` of a bad body, near enough.
fn js_json_error(e: &serde_json::Error, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if e.is_eof() {
        return "Unexpected end of JSON input".into();
    }
    let col = e.column().saturating_sub(1);
    let line_start: usize = text
        .lines()
        .take(e.line().saturating_sub(1))
        .map(|l| l.len() + 1)
        .sum();
    let pos = line_start + col;
    let tok = text[pos.min(text.len())..]
        .chars()
        .next()
        .map(|c| c.to_string())
        .unwrap_or_default();
    format!(
        "Unexpected token '{tok}', \"{}\" is not valid JSON",
        text.chars().take(32).collect::<String>()
    )
}

mod routes;
