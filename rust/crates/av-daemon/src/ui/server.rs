//! The local web UI server: serves the built page, proxies the page's API
//! calls to the control socket, gates changes on a WebAuthn assertion over
//! the exact operation, and withholds every capability from the page. Ports
//! `src/ui/server.js`; the comments there explain each rule.
//!
//! It runs in the `agent-vault ui` CLI process, as the human's account
//! (rust/PLAN.md, frozen contract item 5). av-cli calls [`UiServer::start`]
//! (or [`serve`]) and prints [`UiServer::url`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};

use crate::http::{response, Resp};
use crate::ui::list_paging::{self, page_answer, paging_of, Cursors, PagingError};
use crate::ui::webauthn;
use crate::util::{
    ct_eq, encode_uri_component, js_string, js_stringify, now_ms, random_b64url, search_param,
    search_params,
};

/// The UI exits after this long idle. Ports `IDLE_EXIT_MS`.
pub const IDLE_EXIT_MS: u64 = 30 * 60_000;
/// The page's Content-Security-Policy. Ports `STRICT_CSP`; frozen.
pub const STRICT_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'";

/// Calls that need a WebAuthn assertion over the operation. Ports `GATED`.
pub const GATED: [&str; 21] = [
    "POST credentials",
    "DELETE credentials",
    "POST sessions",
    "DELETE sessions",
    "POST approvals",
    "POST session-requests/decide",
    "POST pending/decide-many",
    "POST lock",
    "POST touchid/enroll",
    "POST touchid/remove",
    "POST sessions/narrow",
    "POST credentials/rotate",
    "POST credentials/scrub",
    "DELETE credentials/scrub",
    "POST credentials/expiry",
    "POST credentials/release",
    "POST tripwires",
    "POST templates",
    "DELETE templates",
    "DELETE credentials/pins",
    "POST presence/rotate",
];
/// Gated calls the daemon checks again itself. Ports `DAEMON_VERIFIED`.
pub const DAEMON_VERIFIED: [&str; 14] = [
    "POST credentials",
    "DELETE credentials",
    "POST sessions",
    "POST session-requests/decide",
    "POST pending/decide-many",
    "POST credentials/rotate",
    "POST credentials/scrub",
    "DELETE credentials/scrub",
    "POST credentials/expiry",
    "POST credentials/release",
    "POST tripwires",
    "POST templates",
    "DELETE credentials/pins",
    "POST presence/rotate",
];
/// The one response that may carry a capability. Ports `HANDOFF`.
pub const HANDOFF: [&str; 1] = ["POST sessions"];
/// Keys dropped at any depth. Ports `WITHHELD_KEYS`.
pub const WITHHELD_KEYS: [&str; 9] = [
    "token",
    "placeholder",
    "value",
    "secret",
    "prf_secret",
    "recovery_passphrase",
    "passphrase",
    "bundle",
    "webhook_url",
];
/// Top-level fields of the hand-off card. Ports `HANDOFF_FIELDS`.
pub const HANDOFF_FIELDS: [&str; 6] = [
    "token",
    "session_id",
    "expires_at",
    "infinite",
    "label",
    "cli",
];
/// Per-grant fields of the hand-off card. Ports `HANDOFF_GRANT_FIELDS`.
pub const HANDOFF_GRANT_FIELDS: [&str; 6] =
    ["placeholder", "base_url", "usage", "cred", "sites", "probe"];

const AUDIT_BATCH: usize = 500;
const ASSET_BYTES_MAX: usize = 32 * 1024 * 1024;

/// Construction options. Ports `new UiServer(socketPath, opts)`.
#[derive(Debug, Clone, Default)]
pub struct UiServerOptions {
    /// Port (0 picks one).
    pub port: u16,
    /// Idle exit; default [`IDLE_EXIT_MS`].
    pub idle_ms: Option<u64>,
    /// How the CLI is invoked, for printed commands.
    pub cli: Option<String>,
    /// The client-state file the hand-off writes; default beside the socket.
    pub state_path: Option<PathBuf>,
    /// The built UI on disk; default the copy embedded at compile time.
    pub dist_dir: Option<PathBuf>,
}

/// The built UI, read once and checked. Ports the result of `loadDist`.
#[derive(Debug, Clone, Default)]
pub struct Dist {
    /// `index.html`.
    pub index: Vec<u8>,
    /// `name → (content type, bytes)` for `dist/assets`.
    pub assets: HashMap<String, (String, Vec<u8>)>,
}

fn asset_name_ok(name: &str) -> bool {
    let mut parts = name.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let ok = |s: &str, lead: bool| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            && (!lead || s.as_bytes()[0].is_ascii_alphanumeric())
    };
    let rest: Vec<&str> = parts.collect();
    ok(first, true) && !rest.is_empty() && rest.iter().all(|p| ok(p, false))
}

fn asset_type(name: &str) -> Option<&'static str> {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_lowercase())?;
    Some(match ext.as_str() {
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        _ => return None,
    })
}

/// The copy of `src/ui/dist` embedded at compile time; `None` when the
/// build had no UI.
pub fn embedded_dist() -> Option<Dist> {
    mod embedded {
        include!(concat!(env!("OUT_DIR"), "/dist.rs"));
    }
    let mut dist = Dist::default();
    let mut found = false;
    let mut total = 0usize;
    for (name, bytes) in embedded::EMBEDDED {
        if *name == "index.html" {
            dist.index = bytes.to_vec();
            found = true;
            total += bytes.len();
        } else if let Some(n) = name.strip_prefix("assets/") {
            if let (true, Some(t)) = (asset_name_ok(n), asset_type(n)) {
                total += bytes.len();
                if total > ASSET_BYTES_MAX {
                    return None;
                }
                dist.assets
                    .insert(n.to_string(), (t.to_string(), bytes.to_vec()));
            }
        }
    }
    found.then_some(dist)
}

/// Load the built UI; `Ok(None)` when there is no `index.html`. Ports
/// `loadDist(distDir)`: nothing outside dist is read, no symlink is
/// followed, and a file must be the one that was opened.
pub fn load_dist(dist_dir: &Path) -> std::io::Result<Option<Dist>> {
    use std::os::unix::fs::MetadataExt;
    let refuse = |what: String| {
        std::io::Error::other(format!(
            "the built UI in {} is not usable: {what}; rebuild it with npm run build:ui",
            dist_dir.display()
        ))
    };
    let kind = |p: &Path| match std::fs::symlink_metadata(p) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let Some(top) = kind(dist_dir)? else {
        return Ok(None);
    };
    if top.file_type().is_symlink() {
        return Err(refuse("the dist directory is a symlink".into()));
    }
    if !top.is_dir() {
        return Err(refuse("dist is not a directory".into()));
    }
    let root = std::fs::canonicalize(dist_dir)?;
    let read_inside = |p: &Path| -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(p)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    refuse(format!("{} is a symlink", p.display()))
                } else {
                    e
                }
            })?;
        let opened = f.metadata()?;
        if !opened.is_file() {
            return Err(refuse(format!("{} is not a regular file", p.display())));
        }
        let real = std::fs::canonicalize(p)?;
        if !real.starts_with(&root) || real == root {
            return Err(refuse(format!("{} is outside dist", p.display())));
        }
        let named = std::fs::metadata(&real)?;
        if named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(refuse(format!("{} changed while it was read", p.display())));
        }
        let mut out = Vec::new();
        f.read_to_end(&mut out)?;
        Ok(out)
    };
    let index_path = dist_dir.join("index.html");
    let Some(ik) = kind(&index_path)? else {
        return Ok(None);
    };
    if ik.file_type().is_symlink() {
        return Err(refuse("index.html is a symlink".into()));
    }
    if !ik.is_file() {
        return Err(refuse("index.html is not a regular file".into()));
    }
    let index = read_inside(&index_path)?;
    let assets_dir = dist_dir.join("assets");
    let ak = kind(&assets_dir)?;
    if ak.as_ref().is_some_and(|m| m.file_type().is_symlink()) {
        return Err(refuse("the assets directory is a symlink".into()));
    }
    if ak.as_ref().is_some_and(|m| !m.is_dir()) {
        return Err(refuse("assets is not a directory".into()));
    }
    let mut assets = HashMap::new();
    let mut total = index.len();
    if ak.is_some() {
        for e in std::fs::read_dir(&assets_dir)?.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !ft.is_file() || !asset_name_ok(&name) {
                continue;
            }
            let Some(t) = asset_type(&name) else { continue };
            let body = read_inside(&e.path())?;
            total += body.len();
            if total > ASSET_BYTES_MAX {
                return Err(std::io::Error::other(format!("the built UI in {} is over {ASSET_BYTES_MAX} bytes; rebuild it with npm run build:ui", dist_dir.display())));
            }
            assets.insert(name, (t.to_string(), body));
        }
    }
    Ok(Some(Dist { index, assets }))
}

/// Ports `literalPath(rawUrl, pathname)`.
pub fn literal_path(raw_url: &str, pathname: &str) -> bool {
    let raw = raw_url.split('?').next().unwrap_or("");
    if raw != pathname || !raw.starts_with('/') {
        return false;
    }
    let lower = raw.to_lowercase();
    if raw.contains('\\') || lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c")
    {
        return false;
    }
    let parts: Vec<&str> = raw[1..].split('/').collect();
    let n = parts.len();
    !parts
        .iter()
        .enumerate()
        .any(|(i, p)| *p == "." || *p == ".." || (p.is_empty() && i < n - 1))
}

fn withheld_key(k: &str) -> bool {
    let mut norm = String::new();
    let mut sep = false;
    for c in k.to_lowercase().chars() {
        if c == '-' || c == '_' || c.is_whitespace() {
            if !sep {
                norm.push('_');
            }
            sep = true;
        } else {
            norm.push(c);
            sep = false;
        }
    }
    let norm = norm.replace("pass_phrase", "passphrase");
    WITHHELD_KEYS.contains(&norm.as_str())
}

fn withheld_text(s: &str) -> String {
    let re = av_core::jsre::compile(r"avs1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").expect("token");
    let out = re.replace_all(s, "«token»").into_owned();
    let mut out2 = out.clone();
    for p in av_core::placeholder::find_all(&out).into_iter().rev() {
        out2 = format!("{}«placeholder»{}", &out2[..p.offset], &out2[p.end..]);
    }
    out2
}

/// A daemon answer as the page may see it. Ports `towardPage(value, depth)`.
pub fn toward_page(value: &Value, depth: usize) -> Value {
    if depth > 64 {
        return Value::Null;
    }
    match value {
        Value::String(s) => Value::String(withheld_text(s)),
        Value::Array(a) => Value::Array(a.iter().map(|v| toward_page(v, depth + 1)).collect()),
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                if withheld_key(k) {
                    continue;
                }
                out.insert(k.clone(), toward_page(v, depth + 1));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn is_scalar(v: &Value) -> bool {
    matches!(
        v,
        Value::Null | Value::String(_) | Value::Number(_) | Value::Bool(_)
    )
}

fn copy_shown(to: &mut Map<String, Value>, from: &Map<String, Value>, names: &[&str]) {
    for n in names {
        if let Some(v) = from.get(*n) {
            if is_scalar(v) || v.as_array().is_some_and(|a| a.iter().all(is_scalar)) {
                to.insert(n.to_string(), v.clone());
            }
        }
    }
}

/// Ports `handoffTowardPage(created)`.
pub fn handoff_toward_page(created: &Value) -> Value {
    let mut out = toward_page(created, 0);
    let (Some(from), Some(to)) = (created.as_object(), out.as_object_mut()) else {
        return out;
    };
    copy_shown(to, from, &HANDOFF_FIELDS);
    copy_shown(to, from, &HANDOFF_GRANT_FIELDS);
    if let (Some(Value::Array(cg)), Some(Value::Array(og))) =
        (from.get("grants"), to.get_mut("grants"))
    {
        for (i, g) in cg.iter().enumerate() {
            if let (Some(gm), Some(Value::Object(om))) = (g.as_object(), og.get_mut(i)) {
                copy_shown(om, gm, &HANDOFF_GRANT_FIELDS);
            }
        }
    }
    out
}

/// A UI error: the JS `Object.assign(new Error(message), { status, problem })`.
#[derive(Debug, Clone)]
struct UiErr {
    status: u16,
    message: String,
    code: Option<String>,
    detail: Option<Box<Value>>,
}

impl UiErr {
    fn new(status: u16, message: impl Into<String>) -> UiErr {
        UiErr {
            status,
            message: message.into(),
            code: None,
            detail: None,
        }
    }
    fn with_problem(mut self, code: &str, rule: Option<&str>) -> UiErr {
        let mut p = json!({"code": code});
        if let Some(r) = rule {
            p["rule"] = r.into();
        }
        self.code = Some(code.into());
        self.detail = Some(Box::new(p));
        self
    }
}

impl From<av_core::errors::VaultError> for UiErr {
    fn from(e: av_core::errors::VaultError) -> Self {
        UiErr {
            status: e.http(),
            message: e.to_string(),
            code: Some(e.code.as_str().into()),
            detail: Some(Box::new(e.to_problem())),
        }
    }
}

impl From<PagingError> for UiErr {
    fn from(e: PagingError) -> Self {
        UiErr {
            status: 400,
            message: e.message.clone(),
            code: Some(e.code.into()),
            detail: Some(Box::new(e.problem())),
        }
    }
}

impl From<webauthn::WebauthnError> for UiErr {
    fn from(e: webauthn::WebauthnError) -> Self {
        UiErr::new(500, e.message)
    }
}

#[derive(Debug, Clone)]
struct Pending {
    challenge: Vec<u8>,
    expires: i64,
    operation: Value,
}

struct State {
    session_cookie: Option<String>,
    last_seen: i64,
    challenges: HashMap<String, Pending>,
    rotation: Option<(Value, i64)>,
    last_state_error: Option<String>,
}

struct Inner {
    socket_path: PathBuf,
    state_path: PathBuf,
    idle_ms: u64,
    cli: String,
    launch_token: String,
    dist: Dist,
    cursors: Cursors,
    origin: String,
    port: u16,
    state: Mutex<State>,
    stop: tokio::sync::watch::Sender<bool>,
}

/// The UI server. Ports `class UiServer`.
#[derive(Clone)]
pub struct UiServer {
    inner: Arc<Inner>,
}

/// Start a UI server: the entry point `agent-vault ui` calls.
pub async fn serve(socket_path: &Path, opts: UiServerOptions) -> std::io::Result<UiServer> {
    UiServer::start(socket_path, opts).await
}

impl UiServer {
    /// Bind `127.0.0.1:<port>` (and `[::1]` on the same port when it can)
    /// and start serving. Ports `new UiServer(...)` and `start()`; refuses
    /// when the built UI is missing.
    pub async fn start(socket_path: &Path, opts: UiServerOptions) -> std::io::Result<UiServer> {
        let dist = match &opts.dist_dir {
            Some(d) => load_dist(d)?.ok_or_else(|| std::io::Error::other(format!("the built UI is missing (no index.html in {}); run npm run build:ui", d.display())))?,
            None => embedded_dist().ok_or_else(|| std::io::Error::other("the built UI is missing (this binary was built without src/ui/dist); run npm run build:ui and rebuild"))?,
        };
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", opts.port)).await?;
        let port = listener.local_addr()?.port();
        let v6 = tokio::net::TcpListener::bind(("::1", port)).await.ok();
        let (stop, _) = tokio::sync::watch::channel(false);
        let state_path = opts.state_path.clone().unwrap_or_else(|| {
            socket_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("cli-state.json")
        });
        let inner = Arc::new(Inner {
            socket_path: socket_path.to_path_buf(),
            state_path,
            idle_ms: opts.idle_ms.unwrap_or(IDLE_EXIT_MS),
            cli: opts.cli.clone().unwrap_or_else(|| "agent-vault".into()),
            launch_token: random_b64url(24),
            dist,
            cursors: Cursors::new(),
            origin: format!("http://localhost:{port}"),
            port,
            state: Mutex::new(State {
                session_cookie: None,
                last_seen: now_ms(),
                challenges: HashMap::new(),
                rotation: None,
                last_state_error: None,
            }),
            stop,
        });
        let server = UiServer { inner };
        for l in std::iter::once(listener).chain(v6) {
            let s = server.clone();
            let mut stop = s.inner.stop.subscribe();
            tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! {
                        a = l.accept() => a,
                        _ = stop.changed() => return,
                    };
                    let Ok((stream, _)) = accepted else { continue };
                    let s2 = s.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            let s3 = s2.clone();
                            async move { Ok::<_, std::convert::Infallible>(s3.handle(req).await) }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .half_close(true)
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
        }
        let s = server.clone();
        tokio::spawn(async move {
            let mut stop = s.inner.stop.subscribe();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                    _ = stop.changed() => return,
                }
                let idle = now_ms() - s.state().last_seen > s.inner.idle_ms as i64;
                if idle {
                    let _ = s.inner.stop.send(true);
                    return;
                }
            }
        });
        Ok(server)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Stop serving. Ports `stop()`.
    pub async fn stop(&self) {
        let _ = self.inner.stop.send(true);
    }

    /// Resolves once the server has stopped (idle exit or [`Self::stop`]).
    pub async fn stopped(&self) {
        let mut rx = self.inner.stop.subscribe();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// `http://localhost:<port>`.
    pub fn origin(&self) -> String {
        self.inner.origin.clone()
    }

    /// The bound port.
    pub fn bound_port(&self) -> u16 {
        self.inner.port
    }

    /// The single-use launch link `<origin>/?t=<launch token>`.
    pub fn url(&self) -> String {
        format!("{}/?t={}", self.inner.origin, self.inner.launch_token)
    }

    /// The last failure to record a session in the client-state file.
    pub fn last_state_error(&self) -> Option<String> {
        self.state().last_state_error.clone()
    }

    fn send(status: u16, obj: &Value) -> Resp {
        response(
            status,
            &[
                ("content-type".into(), "application/json".into()),
                ("cache-control".into(), "no-store".into()),
                ("x-content-type-options".into(), "nosniff".into()),
            ],
            js_stringify(obj).into_bytes(),
        )
    }

    fn send_html(status: u16, html: Vec<u8>, cookie: Option<String>) -> Resp {
        let mut h = vec![
            ("content-type".into(), "text/html; charset=utf-8".into()),
            ("cache-control".into(), "no-store".into()),
            ("x-content-type-options".into(), "nosniff".into()),
            ("referrer-policy".into(), "no-referrer".into()),
            ("content-security-policy".into(), STRICT_CSP.into()),
        ];
        if let Some(c) = cookie {
            h.insert(0, ("set-cookie".into(), c));
        }
        response(status, &h, html)
    }

    /// `#touch(res)`: the sliding cookie.
    fn touch(&self) -> String {
        let mut s = self.state();
        s.last_seen = now_ms();
        format!(
            "av_ui={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            s.session_cookie.clone().unwrap_or_default(),
            self.inner.idle_ms / 1000
        )
    }

    fn authed(&self, headers: &hyper::HeaderMap) -> bool {
        let raw = headers
            .get("cookie")
            .map(|v| crate::util::latin1_string(v.as_bytes()))
            .unwrap_or_default();
        let cookie = cookie_from(&raw);
        let s = self.state();
        matches!((&s.session_cookie, cookie), (Some(have), Some(got)) if ct_eq(have.as_bytes(), got.as_bytes()))
    }

    async fn handle(&self, req: hyper::Request<hyper::body::Incoming>) -> Resp {
        let (parts, body) = req.into_parts();
        // `req.url` as Node gives it: the target as it arrived. An
        // absolute-form target keeps its scheme and authority, so it is
        // never a literal path and never routed (ui-dist-serving.test.js).
        let raw_url = if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
            parts.uri.to_string()
        } else {
            parts
                .uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| parts.uri.to_string())
        };
        let Some((pathname, query)) = crate::http::parse_target(&raw_url, &self.inner.origin)
        else {
            return Self::send(404, &json!({"error": "not found"}));
        };
        let host = parts
            .headers
            .get("host")
            .map(|v| crate::util::latin1_string(v.as_bytes()))
            .unwrap_or_default();
        let host_name = if host.starts_with('[') {
            host[..host.find(']').map_or(host.len(), |i| i + 1)].to_string()
        } else {
            host.split(':').next().unwrap_or("").to_string()
        };
        if !host_name.is_empty() && host_name != "localhost" {
            if !["127.0.0.1", "[::1]", "::1"].contains(&host_name.as_str()) {
                return Self::send(
                    403,
                    &json!({"error": format!("unexpected Host: {host_name}")}),
                );
            }
            return response(
                302,
                &[(
                    "location".into(),
                    format!("{}{}", self.inner.origin, raw_url),
                )],
                Vec::new(),
            );
        }
        if let Some(o) = parts
            .headers
            .get("origin")
            .map(|v| crate::util::latin1_string(v.as_bytes()))
        {
            if !o.is_empty() && o != self.inner.origin {
                return Self::send(403, &json!({"error": "cross-origin request refused"}));
            }
        }
        if !literal_path(&raw_url, &pathname) {
            return Self::send(404, &json!({"error": "not found"}));
        }
        if pathname == "/" {
            return self.serve_page(&parts.headers, &query);
        }
        if let Some(route) = pathname.strip_prefix("/api/") {
            let method = parts.method.as_str().to_string();
            return self
                .serve_api(&method, route, &query, &parts.headers, body)
                .await;
        }
        if let Some(name) = pathname.strip_prefix("/assets/") {
            if !self.authed(&parts.headers) {
                return Self::send(401, &json!({"error": "not authenticated"}));
            }
            let asset = (parts.method == hyper::Method::GET && asset_name_ok(name))
                .then(|| self.inner.dist.assets.get(name))
                .flatten();
            let Some((ty, bytes)) = asset else {
                return Self::send(404, &json!({"error": "not found"}));
            };
            let cookie = self.touch();
            return response(
                200,
                &[
                    ("set-cookie".into(), cookie),
                    ("content-type".into(), ty.clone()),
                    ("content-length".into(), bytes.len().to_string()),
                    ("cache-control".into(), "no-store".into()),
                    ("x-content-type-options".into(), "nosniff".into()),
                    ("referrer-policy".into(), "no-referrer".into()),
                    ("cross-origin-resource-policy".into(), "same-origin".into()),
                    ("content-security-policy".into(), STRICT_CSP.into()),
                ],
                bytes.clone(),
            );
        }
        Self::send(404, &json!({"error": "not found"}))
    }

    fn serve_page(&self, headers: &hyper::HeaderMap, query: &str) -> Resp {
        let offered = search_param(query, "t").filter(|t| !t.is_empty());
        if self.authed(headers) {
            let c = self.touch();
            return Self::send_html(200, self.inner.dist.index.clone(), Some(c));
        }
        let claimed = self.state().session_cookie.is_some();
        if let Some(t) = &offered {
            if !claimed && ct_eq(t.as_bytes(), self.inner.launch_token.as_bytes()) {
                self.state().session_cookie = Some(random_b64url(32));
                let c = self.touch();
                return response(
                    302,
                    &[("set-cookie".into(), c), ("location".into(), "/".into())],
                    Vec::new(),
                );
            }
            if claimed {
                return Self::send_html(409, error_page("This link was already used", "Another browser claimed this session first. If that was not you, close it and start a new one with <code>agent-vault ui</code>, then check <code>agent-vault audit tail</code>."), None);
            }
        }
        Self::send_html(
            401,
            error_page(
                "No session",
                "Open the UI with the link printed by <code>agent-vault ui</code>.",
            ),
            None,
        )
    }

    async fn serve_api(
        &self,
        method: &str,
        route: &str,
        query: &str,
        headers: &hyper::HeaderMap,
        body: hyper::body::Incoming,
    ) -> Resp {
        let key = format!("{method} {route}");
        if !self.authed(headers) {
            return Self::send(401, &toward_page(&json!({"error": "not authenticated"}), 0));
        }
        if headers.get("x-av-ui").map(|v| v.as_bytes()) != Some(b"1") {
            return Self::send(
                403,
                &toward_page(&json!({"error": "missing X-AV-UI header"}), 0),
            );
        }
        let cookie = self.touch();
        let body = match crate::http::read_body(body, 1_000_000).await {
            Ok(b) => serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        };
        let out = self.api(&key, query, body).await;
        let mut resp = match out {
            Ok((status, v, handoff)) => Self::send(
                status,
                &if handoff && HANDOFF.contains(&key.as_str()) {
                    handoff_toward_page(&v)
                } else {
                    toward_page(&v, 0)
                },
            ),
            Err(e) => {
                let mut m = Map::new();
                m.insert("error".into(), e.message.into());
                m.insert("code".into(), e.code.map_or(Value::Null, Value::from));
                if let Some(dd) = e.detail {
                    m.insert("detail".into(), *dd);
                }
                Self::send(e.status, &toward_page(&Value::Object(m), 0))
            }
        };
        if let Ok(v) = hyper::header::HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert("set-cookie", v);
        }
        resp
    }

    /// `#control(method, path, body)`.
    async fn control(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, UiErr> {
        let payload = body
            .filter(|b| !b.is_null())
            .map(|b| js_stringify(&b).into_bytes());
        let stream = tokio::net::UnixStream::connect(&self.inner.socket_path)
            .await
            .map_err(|e| {
                UiErr::new(
                    503,
                    format!(
                        "connect {} {}",
                        io_code(&e),
                        self.inner.socket_path.display()
                    ),
                )
            })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<
            _,
            http_body_util::Full<hyper::body::Bytes>,
        >(TokioIo::new(stream))
        .await
        .map_err(|e| UiErr::new(503, e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut b = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("av-client", "agent-vault-ui");
        if let Some(p) = &payload {
            b = b.header("content-length", p.len().to_string());
        }
        let req = b
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                payload.unwrap_or_default(),
            )))
            .map_err(|e| UiErr::new(500, e.to_string()))?;
        let res = sender
            .send_request(req)
            .await
            .map_err(|e| UiErr::new(503, e.to_string()))?;
        let status = res.status().as_u16();
        use http_body_util::BodyExt;
        let bytes = res
            .into_body()
            .collect()
            .await
            .map_err(|e| UiErr::new(503, e.to_string()))?
            .to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}));
        if status >= 400 {
            let msg = parsed
                .get("detail")
                .filter(|v| crate::util::truthy(v))
                .or_else(|| parsed.get("error").filter(|v| crate::util::truthy(v)))
                .map(js_string)
                .unwrap_or_else(|| "daemon error".into());
            return Err(UiErr {
                status,
                message: msg,
                code: parsed
                    .get("code")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                detail: Some(Box::new(parsed)),
            });
        }
        Ok(parsed)
    }

    async fn listed(
        &self,
        query: &str,
        spec: &str,
        load: Value,
        within: Option<&str>,
        drop: &[&str],
        filters: Value,
    ) -> Result<Value, UiErr> {
        let Some(paging) = paging_of(&search_params(query))? else {
            return Ok(load);
        };
        let shown = toward_page(&load, 0);
        Ok(page_answer(
            &shown,
            list_paging::list_spec(spec).expect("spec"),
            &paging,
            within,
            drop,
            &filters,
            &self.inner.cursors,
        )?)
    }

    async fn fetch_pending(&self) -> Value {
        let mut rows = Vec::new();
        for src in av_store::pending::SOURCES {
            let got = self
                .control("GET", src.path, None)
                .await
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            rows.push((src.kind, got));
        }
        serde_json::to_value(av_store::pending::collect_pending(rows)).unwrap_or(json!([]))
    }

    fn remember(&self, session: &Value) {
        let rs = av_store::client_state::RememberedSession {
            session_id: session
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            token: session
                .get("token")
                .and_then(Value::as_str)
                .map(str::to_string),
            placeholder: session
                .get("placeholder")
                .and_then(Value::as_str)
                .map(str::to_string),
            base_url: session
                .get("base_url")
                .and_then(Value::as_str)
                .map(str::to_string),
        };
        if let Err(e) = av_store::client_state::remember_session(&rs, &self.inner.state_path) {
            self.state().last_state_error = Some(e.to_string());
        }
    }

    /// The operation the page must sign for `key` (tests).
    #[cfg(test)]
    pub(crate) fn operation_of(key: &str, query: &str, body: &Value) -> Option<Value> {
        Self::operation_for(key, query, body).ok()
    }

    /// `#operationFor(key, url, body)`.
    fn operation_for(key: &str, query: &str, body: &Value) -> Result<Value, UiErr> {
        let of = |op: &str, p: &Value| crate::util::operation_for(op, p).map_err(UiErr::from);
        let q = |k: &str| search_param(query, k).map_or(Value::Null, Value::from);
        let b = |k: &str| body.get(k).cloned().unwrap_or(Value::Null);
        let undef = |m: &mut Map<String, Value>, k: &str, v: Value| {
            if !v.is_null() || body.get(k).is_some() {
                m.insert(k.into(), v);
            }
        };
        match key {
            "POST credentials" => of("cred.add", body),
            "DELETE credentials" => of("cred.remove", &json!({"slug": q("slug")})),
            "POST sessions" => of("session.create", body),
            "DELETE sessions" => of("session.revoke", &json!({"sid": q("sid")})),
            "POST approvals" => of(
                if body.get("granted") == Some(&Value::Bool(false)) {
                    "approval.deny"
                } else {
                    "approval.approve"
                },
                body,
            ),
            "POST pending/decide-many" => {
                let mut m = Map::new();
                if let Some(d) = body.get("decisions") {
                    m.insert("decisions".into(), d.clone());
                }
                of("pending.decide_many", &Value::Object(m))
            }
            "POST session-requests/decide" => {
                let ov = parsed_overrides(body.get("overrides"))?;
                let mut m = Map::new();
                undef(&mut m, "id", b("id"));
                undef(&mut m, "granted", b("granted"));
                if let Value::Object(o) = crate::session_requests::overrides_of(&ov) {
                    for (k, v) in o {
                        m.insert(k, v);
                    }
                }
                of("session_request.decide", &Value::Object(m))
            }
            "POST lock" => of("vault.lock", &json!({})),
            "POST touchid/enroll" => {
                let mut m = Map::new();
                undef(&mut m, "credential_id", b("credential_id"));
                undef(&mut m, "prf_secret", b("prf_secret"));
                of("touchid.enroll", &Value::Object(m))
            }
            "POST touchid/remove" => of("touchid.remove", &json!({})),
            "POST sessions/narrow" => of("session.narrow", body),
            "POST credentials/rotate" => of("cred.rotate", body),
            "POST credentials/scrub" => of("cred.scrub_add", body),
            "DELETE credentials/scrub" => of(
                "cred.scrub_remove",
                &json!({"slug": q("slug"), "id": q("id")}),
            ),
            "DELETE credentials/pins" => of(
                "cred.pins_remove",
                &json!({"slug": q("slug"), "host": q("host"), "spki": q("spki")}),
            ),
            "POST credentials/expiry" => of("cred.expiry_set", body),
            "POST credentials/release" => of("cred.release", body),
            "POST tripwires" => of("tripwires.set", body),
            "POST templates" => of("template.save", body),
            "DELETE templates" => of("template.delete", &json!({"name": q("name")})),
            "POST presence/rotate" => of("presence.enroll", body),
            other => Ok(json!({"op": other})),
        }
    }

    /// `#requirePresence(key, url, body, req)`.
    async fn require_presence(&self, key: &str, query: &str, body: &Value) -> Result<(), UiErr> {
        let enrolled = self.control("GET", "/v1/presence", None).await?;
        if !crate::util::truthy(&enrolled) {
            return Err(UiErr::new(
                412,
                "no authenticator is enrolled, so no change can be made from this page",
            ));
        }
        let presence = body.get("presence").cloned().unwrap_or(Value::Null);
        let Some(cid) = presence
            .get("challengeId")
            .filter(|c| crate::util::truthy(c))
            .map(js_string)
        else {
            return Err(UiErr::new(
                401,
                "this action needs a fresh authenticator signature",
            ));
        };
        let pending = self.state().challenges.remove(&cid);
        let Some(pending) = pending else {
            return Err(UiErr::new(401, "unknown or already-used challenge"));
        };
        if pending.expires < now_ms() {
            return Err(UiErr::new(401, "challenge expired; try again"));
        }
        let actual = Self::operation_for(key, query, body)?;
        if webauthn::canonical_operation(&pending.operation)
            != webauthn::canonical_operation(&actual)
        {
            return Err(UiErr::new(
                409,
                "the signature was made for a different operation than the one submitted",
            ));
        }
        let key_rec: av_store::model::PresenceKey =
            serde_json::from_value(enrolled).map_err(|e| UiErr::new(500, e.to_string()))?;
        let e = webauthn::EnrolledCredential::from_key(&key_rec);
        let null = Value::Null;
        let origins = vec![self.inner.origin.clone()];
        webauthn::verify_assertion(&webauthn::AssertionInput {
            credential_id: presence.get("credentialId").unwrap_or(&null),
            authenticator_data: presence.get("authenticatorData").unwrap_or(&null),
            client_data_json: presence.get("clientDataJSON").unwrap_or(&null),
            signature: presence.get("signature").unwrap_or(&null),
            expected_challenge: &pending.challenge,
            expected_origins: &origins,
            rp_id: "localhost",
            enrolled: &e,
        })?;
        Ok(())
    }

    /// The API routes: `(status, body, may hand off)`.
    async fn api(&self, key: &str, query: &str, body: Value) -> Result<(u16, Value, bool), UiErr> {
        let ok = |v: Value| Ok((200, v, false));
        let b = |k: &str| body.get(k).cloned();
        let q = |k: &str| search_param(query, k);
        match key {
            "GET unlock/state" => {
                let ls = self.control("GET", "/v1/lockstate", None).await?;
                return ok(
                    json!({"locked": ls["locked"], "has_passphrase": ls["has_passphrase"], "has_touchid": ls["has_touchid"]}),
                );
            }
            "GET unlock/webauthn-params" => {
                return ok(self
                    .control("GET", "/v1/unlock/webauthn-params", None)
                    .await?)
            }
            "POST unlock/touchid" => {
                return ok(self
                    .control(
                        "POST",
                        "/v1/unlock",
                        Some(obj_of(&[("prf_secret", b("prf_secret"))])),
                    )
                    .await?)
            }
            "POST unlock/passphrase" => {
                return ok(self
                    .control(
                        "POST",
                        "/v1/unlock",
                        Some(obj_of(&[("passphrase", b("passphrase"))])),
                    )
                    .await?)
            }
            "GET touchid/enroll-params" => {
                return ok(self
                    .control("GET", "/v1/factors/webauthn-enroll-params", None)
                    .await?)
            }
            "GET docs/context" => {
                let st = self
                    .control("GET", "/v1/status", None)
                    .await
                    .unwrap_or(json!({}));
                let creds = self
                    .control("GET", "/v1/credentials", None)
                    .await
                    .unwrap_or(json!([]));
                let port = st
                    .get("gateway_port")
                    .filter(|p| crate::util::truthy(p))
                    .cloned()
                    .unwrap_or(json!(7411));
                let ps = js_string(&port);
                return ok(json!({
                    "version": st.get("daemon_version").filter(|v| crate::util::truthy(v)).cloned().unwrap_or(Value::Null),
                    "gateway_port": port, "gateway_url": format!("http://127.0.0.1:{ps}"), "mcp_url": format!("http://127.0.0.1:{ps}/mcp"),
                    "cli": if self.inner.cli.is_empty() { "agent-vault".to_string() } else { self.inner.cli.clone() },
                    "cred_slugs": creds.as_array().map(|a| a.iter().map(|c| c["slug"].clone()).collect::<Vec<_>>()).unwrap_or_default(),
                }));
            }
            "POST presence/window" => {
                let p = b("passphrase")
                    .filter(crate::util::truthy)
                    .unwrap_or(json!(""));
                return ok(self
                    .control(
                        "POST",
                        "/v1/presence/window",
                        Some(json!({"passphrase": p})),
                    )
                    .await?);
            }
            "GET presence/state" => {
                let enrolled = self.control("GET", "/v1/presence", None).await?;
                return ok(
                    json!({"enrolled": crate::util::truthy(&enrolled), "credentialId": enrolled.get("credentialId").filter(|c| crate::util::truthy(c)).cloned().unwrap_or(Value::Null), "rpId": "localhost", "origin": self.inner.origin}),
                );
            }
            "POST presence/enroll/begin" => {
                let existing = self.control("GET", "/v1/presence", None).await?;
                if crate::util::truthy(&existing) {
                    return Err(UiErr::new(409, "already enrolled; replace it with Replace authenticator, confirming with the one you have"));
                }
                let ch = webauthn::new_challenge();
                self.state().challenges.insert(
                    "enroll".into(),
                    Pending {
                        challenge: ch.to_vec(),
                        expires: now_ms() + 120_000,
                        operation: json!({"op": "enroll"}),
                    },
                );
                return ok(
                    json!({"challenge": webauthn::b64url(&ch), "rp": {"id": "localhost", "name": "agent-vault"}, "user": {"id": webauthn::b64url(b"agent-vault-operator"), "name": "operator", "displayName": "Vault operator"}}),
                );
            }
            "POST presence/enroll/finish" => {
                let pending = self.state().challenges.get("enroll").cloned();
                let Some(pending) = pending.filter(|p| p.expires >= now_ms()) else {
                    return Err(UiErr::new(500, "enrollment challenge expired; start again"));
                };
                self.state().challenges.remove("enroll");
                let null = Value::Null;
                let origins = vec![self.inner.origin.clone()];
                let cred = webauthn::verify_registration(&webauthn::RegistrationInput {
                    attestation_object: body.get("attestationObject").unwrap_or(&null),
                    client_data_json: body.get("clientDataJSON").unwrap_or(&null),
                    expected_challenge: &pending.challenge,
                    expected_origins: &origins,
                    rp_id: "localhost",
                })?;
                let mut rec = cred.to_value();
                if let Some(p) = body.get("passphrase").and_then(Value::as_str) {
                    rec["presence"] = json!({"passphrase": p});
                }
                self.control("POST", "/v1/presence", Some(rec)).await?;
                return ok(json!({"ok": true, "credentialId": cred.credential_id}));
            }
            "POST presence/rotate/begin" => {
                let existing = self.control("GET", "/v1/presence", None).await?;
                if !crate::util::truthy(&existing) {
                    return Err(UiErr::new(
                        412,
                        "nothing to replace; set up change confirmation first",
                    ));
                }
                let ch = webauthn::new_challenge();
                self.state().challenges.insert(
                    "rotate".into(),
                    Pending {
                        challenge: ch.to_vec(),
                        expires: now_ms() + 120_000,
                        operation: json!({"op": "rotate"}),
                    },
                );
                return ok(
                    json!({"challenge": webauthn::b64url(&ch), "rp": {"id": "localhost", "name": "agent-vault"}, "user": {"id": webauthn::b64url(b"agent-vault-operator"), "name": "operator", "displayName": "Vault operator"}, "exclude": existing["credentialId"]}),
                );
            }
            "POST presence/rotate/register" => {
                let pending = self.state().challenges.remove("rotate");
                let Some(pending) = pending.filter(|p| p.expires >= now_ms()) else {
                    return Err(UiErr::new(
                        401,
                        "the replacement challenge expired; start again",
                    ));
                };
                let null = Value::Null;
                let origins = vec![self.inner.origin.clone()];
                let cred = webauthn::verify_registration(&webauthn::RegistrationInput {
                    attestation_object: body.get("attestationObject").unwrap_or(&null),
                    client_data_json: body.get("clientDataJSON").unwrap_or(&null),
                    expected_challenge: &pending.challenge,
                    expected_origins: &origins,
                    rp_id: "localhost",
                })?;
                let v = cred.to_value();
                self.state().rotation = Some((v.clone(), now_ms() + 120_000));
                return ok(json!({"credential": v}));
            }
            "POST presence/challenge" => {
                let enrolled = self.control("GET", "/v1/presence", None).await?;
                if !crate::util::truthy(&enrolled) {
                    return Err(UiErr::new(412, "no authenticator enrolled"));
                }
                let operation = b("operation")
                    .filter(crate::util::truthy)
                    .unwrap_or(json!({}));
                let minted = self
                    .control(
                        "POST",
                        "/v1/presence/challenge",
                        Some(json!({"operation": operation, "origins": [self.inner.origin]})),
                    )
                    .await?;
                let id = js_string(&minted["challengeId"]);
                let ch = crate::util::b64url_lenient(minted["challenge"].as_str().unwrap_or(""));
                self.state().challenges.insert(
                    id,
                    Pending {
                        challenge: ch,
                        expires: now_ms() + 60_000,
                        operation,
                    },
                );
                let mut out = minted.clone();
                out["rpId"] = "localhost".into();
                return ok(out);
            }
            _ => {}
        }
        if (key == "POST approvals" || key == "POST session-requests/decide")
            && !body.get("granted").is_some_and(Value::is_boolean)
        {
            return Err(UiErr::new(403, "the verdict must be true or false")
                .with_problem("AV_POLICY_DENIED", Some("bulk_decision")));
        }
        if key == "POST session-requests/decide" && body.get("overrides").is_some() {
            if let Err(e) = parsed_overrides(body.get("overrides")) {
                return Err(UiErr::new(
                    400,
                    format!("the narrowing does not parse: {}", e.message),
                )
                .with_problem("AV_POLICY_DENIED", Some("policy_invalid")));
            }
        }
        if key == "POST presence/rotate" {
            let pending = self.state().rotation.clone();
            let Some((cred, expires)) = pending.filter(|(_, e)| *e >= now_ms()) else {
                self.state().rotation = None;
                return Err(UiErr::new(
                    409,
                    "no replacement key is waiting; register it again",
                ));
            };
            let _ = expires;
            let mut record = body.as_object().cloned().unwrap_or_default();
            record.remove("presence");
            if webauthn::canonical_operation(&Value::Object(record))
                != webauthn::canonical_operation(&cred)
            {
                return Err(UiErr::new(
                    409,
                    "that is not the key registered for this replacement",
                ));
            }
        }
        if key == "POST panic" && body.get("lock").is_some_and(|l| !l.is_boolean()) {
            return Err(UiErr::new(400, "lock must be true or false")
                .with_problem("AV_POLICY_DENIED", Some("panic_shape")));
        }
        if GATED.contains(&key) {
            self.require_presence(key, query, &body).await?;
        }
        if key == "POST touchid/enroll" {
            return ok(self
                .control(
                    "POST",
                    "/v1/factors/webauthn",
                    Some(obj_of(&[
                        ("action", Some(json!("enroll"))),
                        ("credential_id", b("credential_id")),
                        ("prf_secret", b("prf_secret")),
                        ("presence", b("presence")),
                    ])),
                )
                .await?);
        }
        if key == "POST touchid/remove" {
            return ok(self
                .control(
                    "POST",
                    "/v1/factors/webauthn",
                    Some(obj_of(&[
                        ("action", Some(json!("remove"))),
                        ("presence", b("presence")),
                    ])),
                )
                .await?);
        }
        if key == "POST presence/rotate" {
            let cred = self
                .state()
                .rotation
                .take()
                .map(|(c, _)| c)
                .unwrap_or(json!({}));
            let mut rec = cred;
            rec["presence"] = b("presence").unwrap_or(Value::Null);
            return ok(self.control("POST", "/v1/presence", Some(rec)).await?);
        }
        let qof = |names: &[&str]| {
            let pairs: Vec<(String, String)> = names
                .iter()
                .filter_map(|n| q(n).map(|v| (n.to_string(), v)))
                .collect();
            let t = crate::util::search_string(&pairs);
            if t.is_empty() {
                String::new()
            } else {
                format!("?{t}")
            }
        };
        let presence_only = || obj_of(&[("presence", b("presence"))]);
        match key {
            "GET status" => ok(self.control("GET", "/v1/status", None).await?),
            "GET credentials" => ok(self
                .listed(
                    query,
                    "credentials",
                    self.control("GET", "/v1/credentials", None).await?,
                    None,
                    &[],
                    json!({}),
                )
                .await?),
            "GET sessions" => ok(self
                .listed(
                    query,
                    "sessions",
                    self.control("GET", "/v1/sessions", None).await?,
                    None,
                    &[],
                    json!({}),
                )
                .await?),
            "GET pending" => ok(self
                .listed(
                    query,
                    "pending",
                    self.fetch_pending().await,
                    None,
                    &[],
                    json!({}),
                )
                .await?),
            "GET listeners" => ok(self
                .listed(
                    query,
                    "listeners",
                    self.control("GET", "/v1/listeners", None).await?,
                    None,
                    &[],
                    json!({}),
                )
                .await?),
            "GET audit" => {
                let kind = q("kind");
                if kind.as_deref().is_some_and(|k| {
                    !(!k.is_empty()
                        && k.split('.').all(|p| {
                            !p.is_empty() && p.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                        }))
                }) {
                    return Err(UiErr::new(
                        400,
                        "kind is a record kind, like tripwire.fired",
                    ));
                }
                if let Some(paging) = paging_of(&search_params(query))? {
                    return ok(self.audit_page(kind, paging).await?);
                }
                let limit_raw = q("limit")
                    .filter(|l| !l.is_empty())
                    .unwrap_or_else(|| "40".into());
                let limit = limit_raw.trim().parse::<f64>().unwrap_or(f64::NAN);
                let lim_s = crate::util::js_f64(limit);
                let path = match &kind {
                    None => format!("/v1/audit?limit={lim_s}"),
                    Some(k) => format!(
                        "/v1/audit?limit={AUDIT_BATCH}&kind={}",
                        encode_uri_component(k)
                    ),
                };
                let rows = self.control("GET", &path, None).await?;
                if kind.is_none() {
                    return ok(rows);
                }
                let k = kind.unwrap_or_default();
                let filtered: Vec<Value> = rows
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter(|r| r.get("kind").and_then(Value::as_str) == Some(k.as_str()))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                let n = if limit.is_nan() {
                    0
                } else {
                    limit.max(0.0) as usize
                };
                let start = filtered.len().saturating_sub(n);
                ok(Value::Array(if n == 0 {
                    Vec::new()
                } else {
                    filtered[start..].to_vec()
                }))
            }
            "GET audit/checkpoint" => ok(self.control("GET", "/v1/audit/checkpoint", None).await?),
            "GET sessions/detail" => {
                let sid = q("sid").unwrap_or_default();
                let load = self
                    .control(
                        "GET",
                        &format!("/v1/sessions/detail?sid={}", encode_uri_component(&sid)),
                        None,
                    )
                    .await?;
                ok(self
                    .listed(
                        query,
                        "detailGrants",
                        load,
                        Some("grants"),
                        &[],
                        json!({"sid": sid}),
                    )
                    .await?)
            }
            "GET report/access" => {
                let since = q("since")
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "7d".into());
                let which = q("list").unwrap_or_else(|| "sessions".into());
                if which != "sessions" && which != "credentials" {
                    return Err(UiErr::new(400, "list is sessions or credentials"));
                }
                let load = self
                    .control(
                        "GET",
                        &format!("/v1/report/access?since={}", encode_uri_component(&since)),
                        None,
                    )
                    .await?;
                let spec = if which == "sessions" {
                    "reportSessions"
                } else {
                    "reportCredentials"
                };
                ok(self
                    .listed(
                        query,
                        spec,
                        load,
                        Some(&which),
                        &["sessions", "credentials"],
                        json!({"since": since}),
                    )
                    .await?)
            }
            "GET tripwires" => ok(self
                .listed(
                    query,
                    "tripwireRules",
                    self.control("GET", "/v1/tripwires", None).await?,
                    Some("rules"),
                    &[],
                    json!({}),
                )
                .await?),
            "GET templates" => {
                if let Some(name) = q("name") {
                    return ok(self
                        .control(
                            "GET",
                            &format!("/v1/templates?name={}", encode_uri_component(&name)),
                            None,
                        )
                        .await?);
                }
                ok(self
                    .listed(
                        query,
                        "templates",
                        self.control("GET", "/v1/templates", None).await?,
                        None,
                        &[],
                        json!({}),
                    )
                    .await?)
            }
            "GET notify" => ok(self.control("GET", "/v1/notify", None).await?),
            "POST sessions/narrow" => {
                let mut m = body.as_object().cloned().unwrap_or_default();
                m.remove("presence");
                ok(self
                    .control("POST", "/v1/sessions/narrow", Some(Value::Object(m)))
                    .await?)
            }
            "POST credentials/rotate" => ok(self
                .control("POST", "/v1/credentials/rotate", Some(body.clone()))
                .await?),
            "POST credentials/scrub" => ok(self
                .control("POST", "/v1/credentials/scrub", Some(body.clone()))
                .await?),
            "DELETE credentials/scrub" => ok(self
                .control(
                    "DELETE",
                    &format!("/v1/credentials/scrub{}", qof(&["slug", "id"])),
                    Some(presence_only()),
                )
                .await?),
            "DELETE credentials/pins" => ok(self
                .control(
                    "DELETE",
                    &format!("/v1/credentials/pins{}", qof(&["slug", "host", "spki"])),
                    Some(presence_only()),
                )
                .await?),
            "POST credentials/expiry" => ok(self
                .control("POST", "/v1/credentials/expiry", Some(body.clone()))
                .await?),
            "POST credentials/release" => ok(self
                .control("POST", "/v1/credentials/release", Some(body.clone()))
                .await?),
            "POST credentials/test" => {
                let b2 = if body.get("all") == Some(&Value::Bool(true)) {
                    json!({"all": true})
                } else {
                    obj_of(&[("slug", b("slug"))])
                };
                ok(self
                    .control("POST", "/v1/credentials/test", Some(b2))
                    .await?)
            }
            "POST credentials/quarantine" => {
                let mut m = obj_of(&[("slug", b("slug"))]);
                if let Some(r) = body
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|r| !r.is_empty())
                {
                    m["reason"] = r.into();
                }
                ok(self
                    .control("POST", "/v1/credentials/quarantine", Some(m))
                    .await?)
            }
            "POST panic" => {
                let mut m = json!({"lock": body.get("lock") == Some(&Value::Bool(true))});
                if let Some(r) = body
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|r| !r.is_empty())
                {
                    m["reason"] = r.into();
                }
                ok(self.control("POST", "/v1/panic", Some(m)).await?)
            }
            "POST tripwires" => ok(self
                .control("POST", "/v1/tripwires", Some(body.clone()))
                .await?),
            "POST templates" => ok(self
                .control("POST", "/v1/templates", Some(body.clone()))
                .await?),
            "DELETE templates" => ok(self
                .control("DELETE", &format!("/v1/templates{}", qof(&["name"])), None)
                .await?),
            "POST credentials" => ok(self
                .control("POST", "/v1/credentials", Some(body.clone()))
                .await?),
            "DELETE credentials" => ok(self
                .control(
                    "DELETE",
                    &format!(
                        "/v1/credentials?slug={}",
                        encode_uri_component(&q("slug").unwrap_or_else(|| "null".into()))
                    ),
                    Some(presence_only()),
                )
                .await?),
            "POST sessions" => {
                let created = self
                    .control("POST", "/v1/sessions", Some(body.clone()))
                    .await?;
                self.remember(&created);
                Ok((200, created, true))
            }
            "DELETE sessions" => ok(self
                .control(
                    "DELETE",
                    &format!(
                        "/v1/sessions?sid={}",
                        encode_uri_component(&q("sid").unwrap_or_else(|| "null".into()))
                    ),
                    None,
                )
                .await?),
            "POST approvals" => ok(self
                .control("POST", "/v1/approvals", Some(body.clone()))
                .await?),
            "POST pending/decide-many" => {
                let mut answered = self
                    .control(
                        "POST",
                        "/v1/pending/decide-many",
                        Some(obj_of(&[
                            ("decisions", b("decisions")),
                            ("presence", b("presence")),
                        ])),
                    )
                    .await?;
                let decided = answered
                    .get("decided")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let granted = decided
                    .iter()
                    .filter(|r| {
                        r["kind"] == "session"
                            && r["outcome"] == "decided"
                            && r["result"]["state"] == "approved"
                    })
                    .count();
                let mut new_decided = decided.clone();
                for r in new_decided.iter_mut() {
                    let Some(session) = r.get("result").and_then(|x| x.get("session")).cloned()
                    else {
                        continue;
                    };
                    if let Some(m) = r.get_mut("result").and_then(Value::as_object_mut) {
                        m.remove("session");
                    }
                    if session.get("token").is_some_and(crate::util::truthy) {
                        self.remember(&session);
                        answered["recorded"] = r["id"].clone();
                    }
                }
                answered["decided"] = Value::Array(new_decided);
                if granted > 1 {
                    answered["recorded"] = Value::Null;
                    answered["note"] = "several sessions were approved, so each agent collects its own; this page records one at a time".into();
                }
                ok(answered)
            }
            "POST session-requests/decide" => {
                let granted = body.get("granted") == Some(&Value::Bool(true));
                let mut send = obj_of(&[("id", b("id")), ("granted", b("granted"))]);
                if granted {
                    send["overrides"] = parsed_overrides(body.get("overrides"))?;
                }
                if let Some(p) = b("presence") {
                    send["presence"] = p;
                }
                let mut answered = self
                    .control("POST", "/v1/session-requests/decide", Some(send))
                    .await?;
                let session = answered.as_object_mut().and_then(|m| m.remove("session"));
                if !granted {
                    return ok(answered);
                }
                let recorded =
                    match session.filter(|s| s.get("token").is_some_and(crate::util::truthy)) {
                        Some(s) => {
                            self.remember(&s);
                            json!({"session_id": s["session_id"], "expires_at": s["expires_at"]})
                        }
                        None => Value::Null,
                    };
                answered["recorded"] = recorded;
                ok(answered)
            }
            "POST lock" => ok(self.control("POST", "/v1/lock", Some(json!({}))).await?),
            "POST unlock" => {
                let p = b("passphrase")
                    .filter(crate::util::truthy)
                    .unwrap_or(Value::Null);
                ok(self
                    .control("POST", "/v1/unlock", Some(json!({"passphrase": p})))
                    .await?)
            }
            "GET lockstate" => ok(self.control("GET", "/v1/lockstate", None).await?),
            "GET audit/verify" => ok(self.control("GET", "/v1/audit/verify", None).await?),
            _ => {
                let (method, route) = key.split_once(' ').unwrap_or((key, ""));
                Ok((
                    404,
                    json!({"error": format!("no route {method} {route}")}),
                    false,
                ))
            }
        }
    }

    /// `#auditPage(kind, paging)`.
    async fn audit_page(
        &self,
        kind: Option<String>,
        paging: list_paging::Paging,
    ) -> Result<Value, UiErr> {
        let filters = json!({"kind": kind, "q": paging.q});
        let cursor = match &paging.cursor {
            Some(c) => Some(self.inner.cursors.open(c, "audit", &filters)?),
            None => None,
        };
        if cursor
            .as_ref()
            .is_some_and(|c| !c.key[0].is_u64() && !c.key[0].is_i64())
        {
            return Err(PagingError::new(
                "AV_BAD_CURSOR",
                "that cursor is not one this server made; start the list again from the first page",
            )
            .into());
        }
        let seal = |dir: &str, seq: i64| {
            self.inner
                .cursors
                .seal("audit", &filters, dir, &[Value::from(seq)])
        };
        let want = paging.limit + 1;
        let batch = if paging.q.is_empty() {
            want
        } else {
            AUDIT_BATCH
        };
        let of_kind = kind
            .as_ref()
            .map(|k| format!("&kind={}", encode_uri_component(k)))
            .unwrap_or_default();
        let shown_if = |r: &Value| -> Option<Value> {
            let s = toward_page(r, 0);
            list_paging::matches(&s, list_paging::audit_fields, &paging.q).then_some(s)
        };
        let seq_of = |r: &Value| r.get("seq").and_then(Value::as_i64);
        if cursor.as_ref().is_some_and(|c| c.dir == "prev") {
            let c = cursor.expect("cursor");
            let mut found = Vec::new();
            let mut at = c.key[0].as_i64().unwrap_or(0);
            loop {
                let rows = self
                    .control(
                        "GET",
                        &format!("/v1/audit?limit={batch}{of_kind}&after={at}"),
                        None,
                    )
                    .await?;
                let rows = rows.as_array().cloned().unwrap_or_default();
                for r in &rows {
                    let Some(s) = seq_of(r).filter(|s| *s > at) else {
                        continue;
                    };
                    let _ = s;
                    if let Some(x) = shown_if(r) {
                        found.push(x);
                    }
                    if found.len() >= want {
                        break;
                    }
                }
                let last = rows.last().and_then(seq_of);
                if found.len() >= want || rows.len() < batch || last.is_none_or(|l| l <= at) {
                    break;
                }
                at = last.unwrap_or(at);
            }
            let mut items: Vec<Value> = found.iter().take(paging.limit).cloned().collect();
            items.reverse();
            let more = found.len() > paging.limit;
            let oldest = if items.is_empty() {
                c.key[0].as_i64().map(|k| k + 1)
            } else {
                items.last().and_then(seq_of)
            };
            return Ok(json!({
                "items": items.clone(),
                "next_cursor": oldest.map(|o| seal("next", o)),
                "prev_cursor": if more { items.first().and_then(seq_of).map(|s| seal("prev", s)) } else { None },
                "total": null,
            }));
        }
        let mut found = Vec::new();
        let mut at: Option<i64> = cursor.as_ref().and_then(|c| c.key[0].as_i64());
        loop {
            let where_ = at.map(|a| format!("&before={a}")).unwrap_or_default();
            let rows = self
                .control(
                    "GET",
                    &format!("/v1/audit?limit={batch}{of_kind}{where_}"),
                    None,
                )
                .await?;
            let rows = rows.as_array().cloned().unwrap_or_default();
            for r in rows.iter().rev() {
                let Some(s) = seq_of(r) else { continue };
                if at.is_some_and(|a| s >= a) {
                    continue;
                }
                if let Some(x) = shown_if(r) {
                    found.push(x);
                }
                if found.len() >= want {
                    break;
                }
            }
            let first = rows.first().and_then(seq_of);
            if found.len() >= want
                || rows.len() < batch
                || first.is_none()
                || at.is_some_and(|a| first.unwrap_or(a) >= a)
            {
                break;
            }
            at = first;
        }
        let items: Vec<Value> = found.iter().take(paging.limit).cloned().collect();
        Ok(json!({
            "items": items.clone(),
            "next_cursor": if found.len() > paging.limit { items.last().and_then(seq_of).map(|s| seal("next", s)) } else { None },
            "prev_cursor": if cursor.is_some() && !items.is_empty() { items.first().and_then(seq_of).map(|s| seal("prev", s)) } else { None },
            "total": null,
        }))
    }
}

/// `{k: v}` for every pair whose value is present (the JS literal drops
/// `undefined` values when stringified).
fn obj_of(pairs: &[(&str, Option<Value>)]) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        if let Some(v) = v {
            m.insert(k.to_string(), v.clone());
        }
    }
    Value::Object(m)
}

/// `parseOverrides(body?.overrides || {})` as the JSON the daemon is sent.
fn parsed_overrides(raw: Option<&Value>) -> Result<Value, UiErr> {
    let empty = Map::new();
    let m = match raw.filter(|v| crate::util::truthy(v)) {
        Some(Value::Object(m)) => m.clone(),
        Some(_) => empty,
        None => empty,
    };
    let o = av_store::pending::parse_overrides(&m).map_err(|e| UiErr::new(500, e.to_string()))?;
    Ok(serde_json::to_value(o).unwrap_or(json!({})))
}

fn cookie_from(raw: &str) -> Option<String> {
    for part in raw.split(';') {
        let p = part.trim_start();
        if let Some(v) = p.strip_prefix("av_ui=") {
            let v = v.split(';').next().unwrap_or("");
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn io_code(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::NotFound => "ENOENT",
        std::io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
        std::io::ErrorKind::PermissionDenied => "EACCES",
        _ => "ECONNRESET",
    }
}

fn error_page(title: &str, detail: &str) -> Vec<u8> {
    format!("<!doctype html><meta charset=\"utf-8\"><meta name=\"color-scheme\" content=\"light dark\"><title>agent-vault</title>\n<main><h1>{title}</h1><p>{detail}</p></main>").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_paths_only() {
        assert!(literal_path("/", "/"));
        assert!(literal_path("/assets/a.js", "/assets/a.js"));
        assert!(literal_path("/api/status?x=1", "/api/status"));
        assert!(!literal_path("/assets/../index.html", "/index.html"));
        assert!(!literal_path("/assets/%2e%2e/x", "/assets/%2e%2e/x"));
        assert!(!literal_path("/a//b", "/a//b"));
        assert!(!literal_path("/a\\b", "/a/b"));
        assert!(!literal_path("/a/./b", "/a/b"));
    }

    #[test]
    fn hardening_the_page_never_receives_a_capability() {
        let v = json!({
            "token": "avs1.abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAA",
            "nested": {"Pass-Phrase": "x", "webhook URL": "y", "WEBHOOK_URL": "z", "ok": "avs1.abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAA in text"},
            "list": [{"value": "v", "kept": 1}],
        });
        let out = toward_page(&v, 0);
        assert!(out.get("token").is_none());
        assert!(out["nested"].get("Pass-Phrase").is_none());
        assert!(out["nested"].get("WEBHOOK_URL").is_none());
        assert_eq!(out["nested"]["ok"], "«token» in text");
        assert!(out["list"][0].get("value").is_none());
        assert_eq!(out["list"][0]["kept"], 1);
        // Control: an ordinary answer passes through.
        assert_eq!(
            toward_page(&json!({"slug": "gh", "n": 2}), 0),
            json!({"slug": "gh", "n": 2})
        );
    }

    #[test]
    fn handoff_puts_back_only_the_card() {
        let created = json!({"token": "avs1.abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAA", "session_id": "s", "grants": [{"placeholder": "p", "secret": "no", "usage": ["a"]}], "webhook_url": "w"});
        let out = handoff_toward_page(&created);
        assert_eq!(out["token"], created["token"]);
        assert_eq!(out["grants"][0]["placeholder"], "p");
        assert!(out["grants"][0].get("secret").is_none());
        assert!(out.get("webhook_url").is_none());
    }

    #[test]
    fn asset_names_are_plain() {
        assert!(asset_name_ok("index-abc123.js"));
        assert!(!asset_name_ok(".hidden.js"));
        assert!(!asset_name_ok("a..js"));
        assert!(!asset_name_ok("noext"));
        assert_eq!(asset_type("x.JS"), Some("text/javascript; charset=utf-8"));
        assert_eq!(asset_type("x.html"), None);
    }
}
