//! Tests of the daemon as a whole, run in-process against a temp vault and a
//! fake upstream (the JS `fetchImpl`). Each module ports one family of JS
//! tests; `rust/crates/av-daemon/PORTED.md` maps them.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::pipeline::{GatewayRequest, GatewayResponse, PipelineOptions};
use crate::server::{Daemon, DaemonOptions};
use crate::state::{Shared, VaultRef};
use crate::upstream::{Body, BoxFuture, Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

mod control;
mod gateway;
mod guards;
mod mcp;
mod presence;
mod ui;

/// The fixture secret (obviously fake).
pub const SECRET: &str = "test-secret-daemon-0123456789abcdef";

/// What the fake upstream answers with.
pub type Handler = Box<dyn Fn(&UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> + Send + Sync>;

/// A fake upstream that records every request it is sent.
pub struct FakeUp {
    pub hits: Mutex<Vec<UpstreamRequest>>,
    handler: Mutex<Handler>,
}

impl FakeUp {
    pub fn new() -> Arc<FakeUp> {
        Arc::new(FakeUp { hits: Mutex::new(Vec::new()), handler: Mutex::new(Box::new(|_| Ok(json_response(200, &json!({"ok": true}))))) })
    }

    pub fn answer(&self, h: Handler) {
        *self.handler.lock().unwrap() = h;
    }

    pub fn count(&self) -> usize {
        self.hits.lock().unwrap().len()
    }

    pub fn last_auth(&self) -> Option<String> {
        self.hits.lock().unwrap().last().and_then(|r| r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.clone()))
    }
}

impl Upstream for FakeUp {
    fn send(&self, req: UpstreamRequest) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        let out = (self.handler.lock().unwrap())(&req);
        self.hits.lock().unwrap().push(req);
        Box::pin(async move { out })
    }
}

pub fn json_response(status: u16, v: &Value) -> UpstreamResponse {
    UpstreamResponse { status, headers: vec![("content-type".into(), "application/json".into())], body: Body::Full(crate::util::js_stringify(v).into_bytes()) }
}

pub fn text_response(status: u16, ty: &str, body: &str) -> UpstreamResponse {
    UpstreamResponse { status, headers: vec![("content-type".into(), ty.into())], body: Body::Full(body.as_bytes().to_vec()) }
}

/// One daemon over one temp vault.
pub struct World {
    pub _dir: tempfile::TempDir,
    pub shared: VaultRef,
    pub daemon: Arc<Daemon>,
    pub up: Arc<FakeUp>,
    pub slug: String,
    pub token: String,
    pub placeholder: String,
    pub session_id: String,
}

impl World {
    /// A daemon with no credential.
    pub async fn bare() -> World {
        let dir = tempfile::tempdir().unwrap();
        let vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
        let shared = Shared::new(vault);
        let up = FakeUp::new();
        let daemon = Daemon::new(
            shared.clone(),
            DaemonOptions {
                port: 0,
                pipeline: PipelineOptions { upstream: Some(up.clone()), ..Default::default() },
                ..Default::default()
            },
        )
        .unwrap();
        daemon.start().await.unwrap();
        World { _dir: dir, shared, daemon, up, slug: String::new(), token: String::new(), placeholder: String::new(), session_id: String::new() }
    }

    /// A daemon with credential `demo` (host api.example.test, Bearer
    /// header) and one session over it.
    pub async fn seeded(session: Value) -> World {
        let mut w = World::bare().await;
        let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "demo", "kind": "http", "host": "api.example.test", "value": SECRET, "sites": ["header:authorization:Bearer"]})).await;
        assert_eq!(s, 200, "{v}");
        let mut spec = json!({"cred": "demo", "label": "test", "methods": ["GET", "POST"], "paths": ["/**"], "budget": 40, "approval": "on-write", "ttl_hours": 1});
        if let Value::Object(m) = session {
            for (k, x) in m {
                spec[&k] = x;
            }
        }
        let (s, v) = w.control("POST", "/v1/sessions", spec).await;
        assert_eq!(s, 200, "{v}");
        w.slug = "demo".into();
        w.token = v["token"].as_str().unwrap().into();
        w.placeholder = v["placeholder"].as_str().unwrap().into();
        w.session_id = v["session_id"].as_str().unwrap().into();
        w
    }

    /// One control call; `path` may carry a query.
    pub async fn control(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        match self.daemon.control_route(&format!("{method} {p}"), q, body).await {
            Ok((s, v)) => (s, v),
            Err(e) => (e.http(), e.to_problem()),
        }
    }

    /// A gateway request with the session token and the placeholder at the
    /// credential's site.
    pub async fn get(&self, path: &str) -> GatewayResponse {
        self.send("GET", path, vec![("authorization".into(), format!("Bearer {}", self.placeholder))], None).await
    }

    pub async fn send(&self, method: &str, path: &str, headers: Vec<(String, String)>, body: Option<&str>) -> GatewayResponse {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut h = vec![("host".to_string(), "127.0.0.1".to_string()), ("av-session".to_string(), self.token.clone())];
        h.extend(headers);
        self.daemon
            .pipeline
            .handle(GatewayRequest { method: method.into(), path: format!("/p/{}{p}", self.slug), query: q.into(), headers: h, body: body.map(|b| b.as_bytes().to_vec()), listener: None })
            .await
    }

    /// Every audit record, as JSON.
    pub async fn audit(&self) -> Vec<Value> {
        self.shared
            .run(|core| {
                core.vault
                    .audit()
                    .map(|l| l.read(&av_store::audit::ReadFilter { limit: usize::MAX, ..Default::default() }).unwrap())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| serde_json::to_value(r).unwrap())
                    .collect()
            })
            .await
            .unwrap()
    }

    /// The text of everything the daemon recorded.
    pub async fn audit_text(&self) -> String {
        crate::util::js_stringify(&Value::Array(self.audit().await))
    }
}

/// Every encoding of the secret a leak check looks for.
pub fn secret_forms(secret: &str) -> Vec<String> {
    let hex = crate::util::hex(secret.as_bytes());
    let b64 = crate::util::b64(secret.as_bytes());
    vec![secret.to_string(), crate::util::encode_uri_component(secret), b64.clone(), b64.replace('+', "-").replace('/', "_"), hex.clone(), hex.to_uppercase()]
}

/// Whether text carries the secret in any form.
pub fn leaks(text: &str) -> bool {
    secret_forms(SECRET).iter().any(|f| text.contains(f.as_str()))
}

/// The body of a response, streamed or not.
pub async fn body_of(mut r: GatewayResponse) -> (u16, String, GatewayResponse) {
    let mut out = r.body.clone();
    if let Some(mut rx) = r.stream.take() {
        while let Some(c) = rx.recv().await {
            out.extend(c);
        }
    }
    (r.status, String::from_utf8_lossy(&out).into_owned(), r)
}
