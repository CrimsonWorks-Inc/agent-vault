//! Gateway-core regressions through the public daemon/pipeline API.
#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use av_daemon::pipeline::{GatewayRequest, GatewayResponse, PipelineOptions};
use av_daemon::server::{Daemon, DaemonOptions};
use av_daemon::state::{Shared, VaultRef};
use av_daemon::upstream::{
    Body, BoxFuture, Upstream, UpstreamError, UpstreamRequest, UpstreamResponse,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

const SECRET: &str = "test-secret-ported-gateway-0123456789";

#[derive(Default)]
struct RecordingUpstream(Mutex<Vec<UpstreamRequest>>);

impl Upstream for RecordingUpstream {
    fn send(&self, req: UpstreamRequest) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        self.0.lock().unwrap().push(req);
        Box::pin(async {
            Ok(UpstreamResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: Body::Full(b"ordinary-traffic-control".to_vec()),
            })
        })
    }
}

async fn control(socket: &std::path::Path, path: &str, body: Value) -> (u16, Value) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

struct Fixture {
    _dir: tempfile::TempDir,
    shared: VaultRef,
    daemon: Arc<Daemon>,
    up: Arc<RecordingUpstream>,
    token: String,
    ph: String,
}

impl Fixture {
    async fn new(sites: &[&str]) -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
        let shared = Shared::new(vault);
        let up = Arc::new(RecordingUpstream::default());
        let daemon = Daemon::new(
            shared.clone(),
            DaemonOptions {
                port: 0,
                socket_path: Some(dir.path().join("control.sock")),
                pipeline: PipelineOptions {
                    upstream: Some(up.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        daemon.start().await.unwrap();
        let (status, cred) = control(
            &dir.path().join("control.sock"),
            "/v1/credentials",
            json!({
                "slug": "demo", "kind": "http", "host": "api.example.test",
                "value": SECRET, "sites": sites
            }),
        )
        .await;
        assert_eq!(status, 200, "{cred}");
        // Like gateway-helpers.js, seed the auto grant directly in the temp
        // vault: the control API intentionally requires a factor for auto writes.
        let (token, ph) = shared.run(|core| {
            use av_core::secret::ExposeSecret;
            use av_store::vault::{CreateSessionOptions, CreateGrantOptions, IssueOptions};
            let credential = core.vault.find_credential("demo").unwrap().unwrap();
            let session = core.vault.create_session(CreateSessionOptions::default()).unwrap();
            let grant = core.vault.create_grant(CreateGrantOptions {
                session_id: session.session.id,
                credential_id: credential.id,
                policy: serde_json::from_value(json!({"hosts": ["api.example.test"], "methods": ["GET", "POST"], "paths": ["/**"], "budget": {"unit": "requests", "limit": 1000}, "approval": "auto"})).unwrap(),
                ..Default::default()
            }).unwrap();
            let ph = core.vault.issue_placeholder(IssueOptions { grant_id: grant.id, ..Default::default() }).unwrap();
            (session.token.expose_secret().to_string(), ph.placeholder)
        }).await.unwrap();
        Self {
            _dir: dir,
            shared,
            daemon,
            up,
            token,
            ph,
        }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
    ) -> GatewayResponse {
        let mut h = vec![
            ("host".into(), "127.0.0.1".into()),
            ("av-session".into(), self.token.clone()),
        ];
        h.extend(headers);
        self.daemon
            .pipeline()
            .handle(GatewayRequest {
                method: method.into(),
                path: format!("/p/demo{path}"),
                headers: h,
                body: body.map(String::into_bytes),
                ..Default::default()
            })
            .await
    }

    async fn post(&self, content_type: &str, body: String) -> GatewayResponse {
        self.send(
            "POST",
            "/",
            vec![("content-type".into(), content_type.into())],
            Some(body),
        )
        .await
    }

    fn last(&self) -> UpstreamRequest {
        self.up.0.lock().unwrap().last().unwrap().clone()
    }

    async fn clean(&self, response: &GatewayResponse) {
        assert!(!String::from_utf8_lossy(&response.body).contains(SECRET));
        assert!(!serde_json::to_string(&response.headers)
            .unwrap()
            .contains(SECRET));
        let audit = self
            .shared
            .run(|core| {
                core.vault
                    .audit()
                    .unwrap()
                    .read(&av_store::audit::ReadFilter {
                        limit: usize::MAX,
                        ..Default::default()
                    })
                    .unwrap()
            })
            .await
            .unwrap();
        assert!(!serde_json::to_string(&audit).unwrap().contains(SECRET));
    }
}

#[tokio::test]
async fn json_substitution_preserves_numbers_spacing_and_escapes() {
    let f = Fixture::new(&["json:/auth/token"]).await;
    let raw = format!(
        r#"{{ "id": 12345678901234567891, "ratio": 1.0, "auth": {{"token": "{}", "n": [1e3, -0.50]}}, "z": "\u00e9" }}"#,
        f.ph
    );
    let r = f.post("application/json", raw.clone()).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        f.last().body.unwrap(),
        raw.replace(&f.ph, SECRET).as_bytes()
    );
    assert_eq!(r.body, b"ordinary-traffic-control");
    f.clean(&r).await;
}

#[tokio::test]
async fn form_substitution_preserves_other_bytes_and_encoded_placeholder_spelling() {
    for encoded in [false, true] {
        let f = Fixture::new(&["form:token"]).await;
        let spelled = if encoded {
            format!("%61{}", &f.ph[1..])
        } else {
            f.ph.clone()
        };
        let raw = format!("token=Bearer+{spelled}+x%C3%A9&text=a+b%21&flag=&bare");
        let r = f
            .post("application/x-www-form-urlencoded", raw.clone())
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(
            f.last().body.unwrap(),
            raw.replace(&spelled, SECRET).as_bytes()
        );
        assert_eq!(r.body, b"ordinary-traffic-control");
        f.clean(&r).await;
    }
}

#[tokio::test]
async fn duplicate_basic_authorization_is_refused_and_single_basic_is_substituted() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let f = Fixture::new(&["basic:pass"]).await;
    let basic = format!("Basic {}", STANDARD.encode(format!("user:{}", f.ph)));
    let r = f
        .send(
            "GET",
            "/",
            vec![
                ("Authorization".into(), "Bearer x".into()),
                ("authorization".into(), basic.clone()),
            ],
            None,
        )
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("header_duplicate")
    );
    assert!(f.up.0.lock().unwrap().is_empty());
    f.clean(&r).await;
    let r = f
        .send("GET", "/", vec![("authorization".into(), basic)], None)
        .await;
    assert_eq!(r.status, 200);
    assert!(f
        .last()
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("authorization")
            && v == &format!("Basic {}", STANDARD.encode(format!("user:{SECRET}")))));
    assert_eq!(r.body, b"ordinary-traffic-control");
    f.clean(&r).await;
}

#[tokio::test]
async fn nested_percent_escapes_never_reach_upstream() {
    use av_core::policy::{evaluate_http, HttpTarget, Policy};
    let deny: Policy = serde_json::from_value(json!({"hosts": ["up.test"], "methods": ["GET"], "paths": ["/**"], "deny_paths": ["/a/b%20c", "/a/b c", "/admin", "/user/keys"]})).unwrap();
    for path in ["/a/b%252520c", "/a/b%2520c", "/%2561dmin"] {
        let err = evaluate_http(
            &deny,
            &HttpTarget {
                method: Some("GET"),
                host: "up.test",
                path,
            },
        )
        .unwrap_err();
        assert_eq!(err.extra.rule.as_deref(), Some("path_ambiguous_encoding"));
    }
    let f = Fixture::new(&["header:x-key"]).await;
    for path in [
        "/a/b%252520c",
        "/a/b%2520c",
        "/a/b%25252520c",
        "/%2561dmin",
        "/%252561dmin",
        "/user/%2525256beys",
        "/repos/%252e%252e/admin",
        "/repos/%25252e%25252e/admin",
        "/%25u0061dmin",
        "/a/b%25%32%30c",
    ] {
        let r = f
            .send("GET", path, vec![("x-key".into(), f.ph.clone())], None)
            .await;
        assert_eq!(r.status, 403, "{path}");
        assert_eq!(
            r.error.as_ref().unwrap().extra.rule.as_deref(),
            Some("path_ambiguous_encoding"),
            "{path}"
        );
        f.clean(&r).await;
    }
    assert!(f.up.0.lock().unwrap().is_empty());
    let r = f
        .send(
            "GET",
            "/ordinary",
            vec![("x-key".into(), f.ph.clone())],
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"ordinary-traffic-control");
    f.clean(&r).await;
}

#[tokio::test]
async fn once_encoded_paths_are_normalized_and_preserved_on_wire() {
    use av_core::policy::{evaluate_http, normalize_path, HttpTarget, Policy};
    assert_eq!(
        normalize_path("/a%2Fb").unwrap_err().extra.rule.as_deref(),
        Some("path_ambiguous_separator")
    );
    let allow: Policy = serde_json::from_value(
        json!({"hosts": ["up.test"], "methods": ["GET"], "paths": ["/a/**"]}),
    )
    .unwrap();
    for (path, expected) in [("/a/b%20c", "/a/b c"), ("/a/caf%C3%A9", "/a/café")] {
        assert_eq!(
            evaluate_http(
                &allow,
                &HttpTarget {
                    method: Some("GET"),
                    host: "up.test",
                    path
                }
            )
            .unwrap()
            .path,
            expected
        );
    }
    let f = Fixture::new(&["header:x-key"]).await;
    for (path, wire) in [
        ("/b%20c/100%25", "/b%20c/100%25"),
        ("/caf%C3%A9/na%C3%AFve", "/caf%C3%A9/na%C3%AFve"),
        ("/q/50%25off/%25", "/q/50%25off/%25"),
        (
            "/x/%2e%2e/models/gemini-pro:generateContent",
            "/models/gemini-pro:generateContent",
        ),
        ("/%E2%9C%93/%7Euser", "/%E2%9C%93/~user"),
    ] {
        let r = f
            .send("GET", path, vec![("x-key".into(), f.ph.clone())], None)
            .await;
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(url::Url::parse(&f.last().url).unwrap().path(), wire);
        f.clean(&r).await;
    }
}

#[tokio::test]
async fn shadowed_json_placeholders_are_refused_and_ordinary_duplicates_survive() {
    let f = Fixture::new(&["json:/token", "json:/auth/token"]).await;
    for shape in [
        r#"{"token":"PH","token":"PH"}"#,
        r#"{"token":"PH","\u0074oken":"PH"}"#,
        r#"{"auth":{"token":"PH"},"auth":{"token":"PH"}}"#,
        r#"{"auth":{"token":"PH"},"auth":"x","auth":{"token":"PH"}}"#,
        r#"{"PH":1,"token":"PH"}"#,
    ] {
        let r = f.post("application/json", shape.replace("PH", &f.ph)).await;
        assert_eq!(r.status, 403, "{shape}");
        assert_eq!(r.error.as_ref().unwrap().code.as_str(), "AV_BAD_LOCATION");
        f.clean(&r).await;
    }
    assert!(f.up.0.lock().unwrap().is_empty());
    let raw = format!(
        r#"{{"token":"first","token":"{}","n":12345678901234567891,"keys":{{"a":"{}","a":"y"}}}}"#,
        f.ph,
        "x".repeat(80)
    );
    let r = f.post("application/json", raw.clone()).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        f.last().body.unwrap(),
        raw.replace(&f.ph, SECRET).as_bytes()
    );
    assert_eq!(r.body, b"ordinary-traffic-control");
    f.clean(&r).await;
}
