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
struct RecordingUpstream {
    hits: Mutex<Vec<UpstreamRequest>>,
    reply: Mutex<Option<Reply>>,
}

#[derive(Clone)]
struct Reply {
    streaming: bool,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Upstream for RecordingUpstream {
    fn send(&self, req: UpstreamRequest) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        self.hits.lock().unwrap().push(req);
        let reply = self.reply.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(reply) = reply {
                return Ok(UpstreamResponse {
                    status: reply.status,
                    headers: reply.headers,
                    body: if reply.streaming {
                        Body::chunks(vec![Ok(reply.body)])
                    } else {
                        Body::Full(reply.body)
                    },
                });
            }
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
    secret: String,
}

impl Fixture {
    async fn new(sites: &[&str]) -> Self {
        Self::with_secret(sites, SECRET).await
    }

    async fn with_secret(sites: &[&str], secret: &str) -> Self {
        Self::with_budget(sites, secret, None).await
    }

    async fn with_budget(
        sites: &[&str],
        secret: &str,
        scrub_budget: Option<(Option<usize>, Option<usize>)>,
    ) -> Self {
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
                    scrub_budget,
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
                "value": secret, "sites": sites
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
            secret: secret.into(),
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

    fn reply(&self, status: u16, content_type: &str, body: String) {
        *self.up.reply.lock().unwrap() = Some(Reply {
            streaming: false,
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.into_bytes(),
        });
    }

    async fn get(&self) -> GatewayResponse {
        self.send(
            "GET",
            "/ordinary",
            vec![("x-key".into(), self.ph.clone())],
            None,
        )
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
        self.up.hits.lock().unwrap().last().unwrap().clone()
    }

    async fn clean(&self, response: &GatewayResponse) {
        let body = String::from_utf8_lossy(&response.body);
        let headers = serde_json::to_string(&response.headers).unwrap();
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
        let audit = serde_json::to_string(&audit).unwrap();
        let forms = [
            self.secret.clone(),
            encode(&self.secret, Layer::Base64),
            encode(&self.secret, Layer::Hex),
            encode(&self.secret, Layer::Hex).to_uppercase(),
            av_daemon::util::encode_uri_component(&self.secret),
        ];
        for form in forms {
            assert!(!body.contains(&form), "secret encoding in agent body");
            assert!(!headers.contains(&form), "secret encoding in agent headers");
            assert!(!audit.contains(&form), "secret encoding in audit log");
        }
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
    assert!(f.up.hits.lock().unwrap().is_empty());
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
    assert!(f.up.hits.lock().unwrap().is_empty());
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
    assert!(f.up.hits.lock().unwrap().is_empty());
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

// gateway-hardening.test.js: buffered response encodings and their controls.
const SLASHED: &str = "test-secret-Zq7/Bv3+Kd9/Wm2?>Hx5~Lp8sTe";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Layer {
    Json,
    Percent,
    Base64,
    Hex,
}

fn encode(text: &str, layer: Layer) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    match layer {
        Layer::Json => text.bytes().map(|b| format!("\\u{b:04x}")).collect(),
        Layer::Percent => text.bytes().map(|b| format!("%{b:02x}")).collect(),
        Layer::Base64 => STANDARD.encode(text),
        Layer::Hex => text.bytes().map(|b| format!("{b:02x}")).collect(),
    }
}

fn decode(text: &str, layer: Layer) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    match layer {
        Layer::Json => serde_json::from_str::<String>(&format!("\"{text}\"")).ok(),
        Layer::Base64 => String::from_utf8(STANDARD.decode(text).ok()?).ok(),
        Layer::Hex => {
            if !text.len().is_multiple_of(2) {
                return None;
            }
            let bytes = (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<_>>>()?;
            String::from_utf8(bytes).ok()
        }
        Layer::Percent => {
            let mut out = Vec::new();
            let mut i = 0;
            while i < text.len() {
                if text.as_bytes()[i] == b'%' {
                    out.push(u8::from_str_radix(text.get(i + 1..i + 3)?, 16).ok()?);
                    i += 3;
                } else {
                    out.push(text.as_bytes()[i]);
                    i += 1;
                }
            }
            String::from_utf8(out).ok()
        }
    }
}

fn wrap(text: &str, layers: &[Layer]) -> String {
    layers
        .iter()
        .rev()
        .fold(text.to_owned(), |s, l| encode(&s, *l))
}

fn unwrap(text: &str, layers: &[Layer]) -> Option<String> {
    layers
        .iter()
        .try_fold(text.to_owned(), |s, l| decode(&s, *l))
}

async fn ordinary_json_control(f: &Fixture) {
    let body = r#"{"html_url":"https:\/\/github.com\/o\/r\/pull\/7","next":"\/v1\/items?page=2&q=%2Fdocs","note":"caf\u00e9 \u2014 \"quoted\" \u003cb>&amp;\u003c/b>","path":"C:\\Users\\a","b64":"aGVsbG8vd29ybGQ="}"#;
    f.reply(200, "application/json", body.into());
    let r = f.get().await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, body.as_bytes());
    assert!(r.header("av-redacted").is_none());
    f.clean(&r).await;
}

#[tokio::test]
async fn escaped_json_secrets_are_scrubbed_and_ordinary_json_survives() {
    for secret in [SECRET, SLASHED] {
        let f = Fixture::with_secret(&["header:x-key"], secret).await;
        let escaped = |step, upper| {
            secret
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if c == '/' {
                        "\\/".into()
                    } else if i % step != 0 {
                        c.to_string()
                    } else if upper {
                        format!("\\u{:04X}", c as u32)
                    } else {
                        format!("\\u{:04x}", c as u32)
                    }
                })
                .collect::<String>()
        };
        for raw in [
            secret.replace('/', "\\/"),
            escaped(3, false),
            escaped(3, true),
            escaped(1000, false),
            secret.replace('/', "\\u002f"),
        ] {
            let body = format!(r#"{{"error":{{"message":"bad key {raw}","echo":"{raw}"}}}}"#);
            assert!(
                serde_json::from_str::<Value>(&body).unwrap()["error"]["echo"]
                    .as_str()
                    .unwrap()
                    .contains(secret)
            );
            f.reply(401, "application/json", body);
            let r = f.get().await;
            assert_eq!(r.status, 401);
            let parsed: Value = serde_json::from_slice(&r.body).unwrap();
            assert!(!parsed["error"]["message"]
                .as_str()
                .unwrap()
                .contains(secret));
            assert!(!parsed["error"]["echo"].as_str().unwrap().contains(secret));
            f.clean(&r).await;
        }
        ordinary_json_control(&f).await;
    }
}

async fn check_stacks(stacks: &[Vec<Layer>]) {
    for secret in [SECRET, SLASHED] {
        let f = Fixture::with_secret(&["header:x-key"], secret).await;
        for layers in stacks {
            let raw = wrap(secret, layers);
            assert_eq!(unwrap(&raw, layers).as_deref(), Some(secret));
            // Match the JS fixture byte for byte: a JSON outer layer here
            // consists of literal escapes inside the response's JSON string.
            f.reply(200, "application/json", format!(r#"{{"echo":"{raw}"}}"#));
            let r = f.get().await;
            assert_eq!(r.status, 200, "{layers:?}");
            let bytes = String::from_utf8(r.body.clone()).unwrap();
            let got = serde_json::from_str::<Value>(&bytes)
                .ok()
                .and_then(|v| v["echo"].as_str().map(str::to_owned))
                .unwrap_or(bytes);
            assert!(
                !unwrap(&got, layers).unwrap_or_default().contains(secret),
                "{layers:?}: {got}"
            );
            assert!(!got.contains(secret));
            f.clean(&r).await;
        }
        ordinary_json_control(&f).await;
    }
}

#[tokio::test]
async fn every_distinct_encoding_pair_is_scrubbed_in_buffered_responses() {
    let kinds = [Layer::Json, Layer::Percent, Layer::Base64, Layer::Hex];
    let mut stacks = Vec::new();
    for a in kinds {
        for b in kinds {
            if a != b {
                stacks.push(vec![a, b]);
            }
        }
    }
    check_stacks(&stacks).await;
}

#[tokio::test]
async fn three_layer_stacks_within_decode_limit_are_scrubbed() {
    use Layer::*;
    check_stacks(&[
        vec![Json, Percent, Base64],
        vec![Base64, Json, Percent],
        vec![Percent, Hex, Json],
        vec![Json, Base64, Hex],
    ])
    .await;
}

#[tokio::test]
async fn four_layer_stack_is_handled_without_emitting_literal_secret() {
    use Layer::*;
    let f = Fixture::with_secret(&["header:x-key"], SLASHED).await;
    let layers = [Json, Percent, Base64, Hex];
    let raw = wrap(SLASHED, &layers);
    assert_eq!(unwrap(&raw, &layers).as_deref(), Some(SLASHED));
    f.reply(200, "application/json", format!(r#"{{"echo":"{raw}"}}"#));
    let r = f.get().await;
    assert_eq!(r.status, 200);
    f.clean(&r).await;
    ordinary_json_control(&f).await;
}

#[tokio::test]
async fn json_escaped_percent_encoded_base64_is_scrubbed() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    for secret in [SECRET, SLASHED] {
        let f = Fixture::with_secret(&["header:x-key"], secret).await;
        let raw =
            av_daemon::util::encode_uri_component(&STANDARD.encode(secret)).replace('%', "\\u0025");
        let decoded: String = serde_json::from_str(&format!("\"{raw}\"")).unwrap();
        assert_eq!(
            decode(&decode(&decoded, Layer::Percent).unwrap(), Layer::Base64).as_deref(),
            Some(secret)
        );
        f.reply(200, "application/json", format!(r#"{{"echo":"{raw}"}}"#));
        let r = f.get().await;
        assert_eq!(r.status, 200);
        let parsed: Value = serde_json::from_slice(&r.body).unwrap();
        let got = parsed["echo"].as_str().unwrap();
        assert!(!got.contains(&raw));
        assert!(!decode(got, Layer::Percent)
            .and_then(|s| decode(&s, Layer::Base64))
            .unwrap_or_default()
            .contains(secret));
        f.clean(&r).await;
        ordinary_json_control(&f).await;
    }
}

#[tokio::test]
async fn ordinary_percent_encoded_query_in_body_headers_and_redirect_survives() {
    let f = Fixture::new(&["header:x-key"]).await;
    let query = "q=hello%20world&tag=%2Fdocs%2F&b64=aGVsbG8vd29ybGQ%3D&sig=dGhpcyBpcyBub3Qgc2VjcmV0%2B%2F&redirect_uri=https%3A%2F%2Fapp.test%2Fcb";
    let location = format!("https://api.example.test/next?{query}");
    *f.up.reply.lock().unwrap() = Some(Reply {
        streaming: false,
        status: 302,
        headers: vec![
            (
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
            ("location".into(), location.clone()),
            ("x-next".into(), query.into()),
        ],
        body: query.as_bytes().to_vec(),
    });
    let r = f.get().await;
    assert_eq!(r.status, 302);
    assert_eq!(r.body, query.as_bytes());
    assert_eq!(r.header("location"), Some(location.as_str()));
    assert_eq!(r.header("x-next"), Some(query));
    assert!(r.header("av-redacted").is_none());
    f.clean(&r).await;
}

#[tokio::test]
async fn ordinary_base64_image_data_url_survives() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let f = Fixture::with_secret(&["header:x-key"], SLASHED).await;
    let png = STANDARD.encode(format!(
        "{}a perfectly ordinary image not a secret",
        "x".repeat(4096)
    ));
    let body = serde_json::to_string(
        &json!({"name":"avatar", "image":format!("data:image/png;base64,{png}"), "size":4135}),
    )
    .unwrap();
    f.reply(200, "application/json", body.clone());
    let r = f.get().await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, body.as_bytes());
    assert!(r.header("av-redacted").is_none());
    f.clean(&r).await;
}

#[tokio::test]
async fn large_ordinary_json_with_mixed_encodings_survives() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let f = Fixture::with_secret(&["header:x-key"], SLASHED).await;
    let mut records = Vec::new();
    let mut size = 2;
    while size < 256 * 1024 {
        let i = records.len();
        let record = json!({"id":i,"url":format!("https:\\/\\/api.example.com\\/v1\\/items\\/{i}?q=%2Fdocs&page={}",i%10), "sha":"a3f10b9c".repeat(8), "note":format!("item \\u00e9 {i} \\u2014 \"ok\""), "blob":STANDARD.encode("z".repeat(48+i%7))});
        size += serde_json::to_vec(&record).unwrap().len() + 1;
        records.push(record);
    }
    let body = serde_json::to_string(&records).unwrap();
    f.reply(200, "application/json", body.clone());
    let r = f.get().await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, body.as_bytes());
    assert!(r.header("av-redacted").is_none());
    f.clean(&r).await;
}

fn url_base64(secret: &str, pad: usize) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    av_daemon::util::encode_uri_component(&STANDARD.encode(format!("{}{secret}", &"abc"[..pad])))
}

fn recovers(text: &str, secret: &str) -> bool {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let plain = decode(text, Layer::Percent).unwrap_or_else(|| text.into());
    if plain.contains(secret) {
        return true;
    }
    let runs = av_core::jsre::compile(r"[A-Za-z0-9+/]{8,}={0,2}").unwrap();
    for run in runs.find_iter(&plain) {
        for skip in 0..4 {
            // Node's Buffer decoder accepts unpadded base64.
            let mut candidate = run.as_str()[skip..].to_string();
            while !candidate.len().is_multiple_of(4) {
                candidate.push('=');
            }
            if STANDARD
                .decode(&candidate)
                .ok()
                .is_some_and(|bytes| String::from_utf8_lossy(&bytes).contains(secret))
            {
                return true;
            }
        }
    }
    false
}

#[tokio::test]
async fn url_encoded_base64_secret_is_scrubbed_from_body_header_and_redirect() {
    for secret in [SECRET, SLASHED] {
        let f = Fixture::with_secret(&["header:x-key"], secret).await;
        for pad in 0..3 {
            let enc = url_base64(secret, pad);
            assert!(recovers(&enc, secret));
            *f.up.reply.lock().unwrap() = Some(Reply {
                streaming: false,
                status: 302,
                headers: vec![
                    (
                        "content-type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                    (
                        "location".into(),
                        format!(
                            "https://api.example.test/callback?state=xyz&token={enc}&next=%2Fhome"
                        ),
                    ),
                    ("x-debug-token".into(), format!("t={enc}")),
                ],
                body: format!("grant=ok&token={enc}&scope=read%20write").into_bytes(),
            });
            let r = f.get().await;
            assert_eq!(r.status, 302);
            assert!(!recovers(&String::from_utf8_lossy(&r.body), secret));
            assert!(!recovers(r.header("location").unwrap_or_default(), secret));
            assert!(!recovers(
                r.header("x-debug-token").unwrap_or_default(),
                secret
            ));
            f.clean(&r).await;
        }
        ordinary_json_control(&f).await;
    }
}

fn stream_reply(f: &Fixture, events: &str, compressed: bool) {
    use std::io::Write;
    let mut headers = vec![("content-type".into(), "text/event-stream".into())];
    let body = if compressed {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(events.as_bytes()).unwrap();
        headers.push(("content-encoding".into(), "gzip".into()));
        encoder.finish().unwrap()
    } else {
        events.as_bytes().to_vec()
    };
    *f.up.reply.lock().unwrap() = Some(Reply {
        streaming: true,
        status: 200,
        headers,
        body,
    });
}

async fn drain(mut r: GatewayResponse) -> GatewayResponse {
    if let Some(mut stream) = r.stream.take() {
        while let Some(chunk) = stream.recv().await {
            r.body.extend(chunk);
        }
    }
    r
}

fn data(v: Value) -> String {
    format!("data: {v}\n\n")
}

async fn ordinary_stream_control(f: &Fixture, compressed: bool) {
    let events =
        data(json!({"choices":[{"index":0,"delta":{"content":"ordinary-traffic-control"}}]}));
    stream_reply(f, &events, compressed);
    let r = drain(f.get().await).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, events.as_bytes());
    f.clean(&r).await;
}

#[tokio::test]
async fn nested_decode_budget_refuses_buffered_body_and_default_budget_delivers_scrubbed_body() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let raw =
        av_daemon::util::encode_uri_component(&STANDARD.encode(SLASHED)).replace('%', "\\u0025");
    let body = format!(r#"{{"echo":"{raw}"}}"#);
    for (budget, status) in [(Some((None, Some(4))), 502), (None, 200)] {
        let f = Fixture::with_budget(&["header:x-key"], SLASHED, budget).await;
        f.reply(200, "application/json", body.clone());
        let r = f.get().await;
        assert_eq!(r.status, status);
        let got = String::from_utf8_lossy(&r.body);
        assert!(!got.contains(&raw));
        if status == 502 {
            assert!(got.contains("AV_UNSCANNABLE"));
        }
        f.clean(&r).await;
        // A plain non-encoded response is inside either budget.
        f.reply(200, "text/plain", "ordinary-traffic-control".into());
        let r = f.get().await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"ordinary-traffic-control");
        f.clean(&r).await;
    }
}

#[tokio::test]
async fn nested_decode_budget_cuts_event_stream() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let raw =
        av_daemon::util::encode_uri_component(&STANDARD.encode(SLASHED)).replace('%', "\\u0025");
    let events =
        data(json!({"choices":[{"index":0,"delta":{"content":format!("payload {raw}")}}]}));
    let f = Fixture::with_budget(&["header:x-key"], SLASHED, Some((None, Some(4)))).await;
    stream_reply(&f, &events, false);
    let r = drain(f.get().await).await;
    let got = String::from_utf8_lossy(&r.body);
    assert!(got.contains("AV_UNSCANNABLE"));
    assert!(!got.contains(&raw));
    f.clean(&r).await;
    // This small event has no nested encoding candidates to exhaust budget.
    stream_reply(&f, "data: ok\n\n", false);
    let r = drain(f.get().await).await;
    assert_eq!(r.body, b"data: ok\n\n");
    f.clean(&r).await;
}

#[tokio::test]
async fn url_encoded_base64_secret_is_removed_from_whole_and_split_stream_events() {
    for secret in [SECRET, SLASHED] {
        let enc = url_base64(secret, 0);
        for compressed in [false, true] {
            let f = Fixture::with_secret(&["header:x-key"], secret).await;
            let event = data(
                json!({"choices":[{"index":0,"delta":{"content":format!("see https://api.example.test/x?t={enc}")}}]}),
            );
            stream_reply(&f, &event, compressed);
            let r = drain(f.get().await).await;
            assert!(!recovers(&String::from_utf8_lossy(&r.body), secret));
            f.clean(&r).await;
            let events = data(
                json!({"choices":[{"index":0,"delta":{"content":format!("t={}",&enc[..12])}}]}),
            ) + &data(json!({"choices":[{"index":0,"delta":{"content":&enc[12..]}}]}));
            assert!(recovers(&format!("t={enc}"), secret));
            stream_reply(&f, &events, compressed);
            let r = drain(f.get().await).await;
            let got = String::from_utf8_lossy(&r.body);
            assert!(got.contains("AV_UNSCANNABLE"));
            let combined: String = got
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter_map(|v| {
                    v["choices"][0]["delta"]["content"]
                        .as_str()
                        .map(str::to_owned)
                })
                .collect();
            assert!(!recovers(&combined, secret));
            f.clean(&r).await;
            ordinary_stream_control(&f, compressed).await;
        }
    }
}
