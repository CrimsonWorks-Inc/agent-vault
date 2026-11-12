//! The web UI server over real HTTP against a daemon's control socket:
//! the launch claim, the cookie, Host and Origin, the literal path rule, the
//! asset allowlist and CSP, withheld capabilities, the signature gate and
//! paging. Ports the internal parts of test/security/ui*.test.js,
//! serving.test.js, control-ui-*.test.js and requested-ui.test.js (see
//! PORTED.md).

use std::path::Path;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::ui::server::{UiServer, UiServerOptions, STRICT_CSP};

struct Ui {
    _sock: tempfile::TempDir,
    _w: World,
    _dist: tempfile::TempDir,
    ui: UiServer,
    cookie: Option<String>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, n: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn raw(port: u16, head: &str, body: &str) -> Reply {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(
        format!(
            "{head}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let (h, b) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = h.split("\r\n");
    let status = lines
        .next()
        .unwrap_or("")
        .split(' ')
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: b.to_string(),
    }
}

fn dist(dir: &Path) {
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>agent-vault</title>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app-1.js"), "console.log(1)").unwrap();
    std::fs::write(dir.join("assets/app-1.js.map"), "{}").unwrap();
    std::fs::write(dir.join("assets/notes.txt"), "no").unwrap();
    std::os::unix::fs::symlink("/etc/hosts", dir.join("assets/link.js")).unwrap();
}

impl Ui {
    async fn start() -> Ui {
        let sockdir = tempfile::Builder::new()
            .prefix("avd")
            .tempdir_in("/tmp")
            .unwrap();
        let sock = sockdir.path().join("c.sock");
        let w = World::seeded(json!({})).await;
        let listener = crate::listen::bind_unix(&sock).unwrap();
        let d = w.daemon.clone();
        tokio::spawn(crate::listen::serve_unix(listener, None, move |req| {
            let d = d.clone();
            async move { d.on_control(req).await }
        }));
        let distdir = tempfile::tempdir().unwrap();
        dist(distdir.path());
        let ui = UiServer::start(
            &sock,
            UiServerOptions {
                port: 0,
                dist_dir: Some(distdir.path().to_path_buf()),
                state_path: Some(sockdir.path().join("state.json")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        Ui {
            _sock: sockdir,
            _w: w,
            _dist: distdir,
            ui,
            cookie: None,
        }
    }

    fn port(&self) -> u16 {
        self.ui.bound_port()
    }

    async fn get(&self, path: &str, extra: &str) -> Reply {
        let cookie = self
            .cookie
            .as_ref()
            .map(|c| format!("Cookie: av_ui={c}\r\n"))
            .unwrap_or_default();
        raw(
            self.port(),
            &format!(
                "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\n{cookie}{extra}",
                self.port()
            ),
            "",
        )
        .await
    }

    async fn api(&self, method: &str, route: &str, body: Value) -> Reply {
        let cookie = self
            .cookie
            .as_ref()
            .map(|c| format!("Cookie: av_ui={c}\r\n"))
            .unwrap_or_default();
        let b = crate::util::js_stringify(&body);
        raw(self.port(), &format!("{method} /api/{route} HTTP/1.1\r\nHost: localhost:{}\r\nX-AV-UI: 1\r\nContent-Type: application/json\r\n{cookie}", self.port()), &b).await
    }

    async fn claim(&mut self) {
        let token = self.ui.url().split("?t=").nth(1).unwrap().to_string();
        let r = self.get(&format!("/?t={token}"), "").await;
        assert_eq!(r.status, 302);
        let c = r.header("set-cookie").unwrap().to_string();
        assert!(
            c.contains("HttpOnly") && c.contains("SameSite=Strict"),
            "{c}"
        );
        self.cookie = Some(
            c.trim_start_matches("av_ui=")
                .split(';')
                .next()
                .unwrap()
                .to_string(),
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_launch_link_is_single_use_and_the_page_carries_the_strict_csp() {
    let mut u = Ui::start().await;
    let token = u.ui.url().split("?t=").nth(1).unwrap().to_string();
    assert_eq!(u.get("/", "").await.status, 401);
    u.claim().await;
    let again = raw(
        u.port(),
        &format!(
            "GET /?t={token} HTTP/1.1\r\nHost: localhost:{}\r\n",
            u.port()
        ),
        "",
    )
    .await;
    assert_eq!(
        again.status, 409,
        "a second claimant is told the link was used"
    );
    let page = u.get("/", "").await;
    assert_eq!(page.status, 200);
    assert_eq!(page.header("content-security-policy"), Some(STRICT_CSP));
    assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
}

#[tokio::test(flavor = "multi_thread")]
async fn assets_are_an_allowlist_served_only_to_the_session() {
    let mut u = Ui::start().await;
    assert_eq!(u.get("/assets/app-1.js", "").await.status, 401);
    u.claim().await;
    let a = u.get("/assets/app-1.js", "").await;
    assert_eq!(a.status, 200);
    assert_eq!(
        a.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(a.header("content-security-policy"), Some(STRICT_CSP));
    for p in [
        "/assets/app-1.js.map",
        "/assets/notes.txt",
        "/assets/link.js",
        "/assets/../index.html",
        "/assets/%2e%2e/index.html",
        "/index.html",
    ] {
        assert_eq!(u.get(p, "").await.status, 404, "{p}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_foreign_host_or_origin_is_refused_and_loopback_is_sent_to_localhost() {
    let mut u = Ui::start().await;
    u.claim().await;
    let r = raw(
        u.port(),
        &format!("GET / HTTP/1.1\r\nHost: evil.test:{}\r\n", u.port()),
        "",
    )
    .await;
    assert_eq!(r.status, 403);
    let r = raw(
        u.port(),
        &format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n", u.port()),
        "",
    )
    .await;
    assert_eq!(r.status, 302);
    assert_eq!(
        r.header("location"),
        Some(format!("http://localhost:{}/x", u.port()).as_str())
    );
    let r = u.get("/", "Origin: http://localhost:1\r\n").await;
    assert_eq!(r.status, 403);
    let cookie = format!("Cookie: av_ui={}\r\n", u.cookie.clone().unwrap());
    let r = raw(
        u.port(),
        &format!(
            "GET /api/status HTTP/1.1\r\nHost: localhost:{}\r\n{cookie}",
            u.port()
        ),
        "",
    )
    .await;
    assert_eq!(r.status, 403, "no X-AV-UI header");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_the_api_withholds_tokens_placeholders_and_values() {
    let mut u = Ui::start().await;
    u.claim().await;
    let r = u.api("GET", "credentials", json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("demo"));
    let r = u.api("GET", "sessions", json!({})).await;
    assert!(!r.body.contains("avs1."), "{}", r.body);
    let r = u.api("GET", "audit", json!({})).await;
    assert_eq!(r.status, 200);
    assert!(!leaks(&r.body));
    assert!(
        !r.body.contains("av1."),
        "no placeholder text reaches the page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_an_unsigned_change_is_refused_and_nothing_changes() {
    let mut u = Ui::start().await;
    u.claim().await;
    let r = u.api("POST", "sessions", json!({"cred": "demo"})).await;
    assert_eq!(r.status, 412, "{}", r.body);
    let r = u
        .api("POST", "approvals", json!({"id": "x", "granted": "true"}))
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["code"], "AV_POLICY_DENIED");
    let r = u.api("POST", "panic", json!({"lock": "false"})).await;
    assert_eq!(r.status, 400);
    let (_, list) = u._w.control("GET", "/v1/sessions", json!({})).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn paging_refuses_a_bad_limit_or_cursor() {
    let mut u = Ui::start().await;
    u.claim().await;
    let r = u
        .get("/api/credentials?paged=1&limit=500", "X-AV-UI: 1\r\n")
        .await;
    assert_eq!(
        (r.status, r.json()["code"].as_str()),
        (400, Some("AV_BAD_LIMIT"))
    );
    let r = u
        .get("/api/credentials?paged=1&cursor=forged", "X-AV-UI: 1\r\n")
        .await;
    assert_eq!(
        (r.status, r.json()["code"].as_str()),
        (400, Some("AV_BAD_CURSOR"))
    );
    let r = u
        .get("/api/credentials?paged=1&limit=1", "X-AV-UI: 1\r\n")
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["total"], 1);
    let r = u.get("/api/audit?paged=1&limit=2", "X-AV-UI: 1\r\n").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 2);
    assert!(r.json()["next_cursor"].is_string());
}

#[test]
fn a_dist_that_is_a_symlink_or_missing_its_index_is_refused() {
    let d = tempfile::tempdir().unwrap();
    assert!(crate::ui::server::load_dist(&d.path().join("missing"))
        .unwrap()
        .is_none());
    std::fs::create_dir_all(d.path().join("real")).unwrap();
    std::fs::write(d.path().join("real/index.html"), "x").unwrap();
    std::os::unix::fs::symlink(d.path().join("real"), d.path().join("link")).unwrap();
    assert!(crate::ui::server::load_dist(&d.path().join("link")).is_err());
    assert!(crate::ui::server::load_dist(&d.path().join("real"))
        .unwrap()
        .is_some());
}
