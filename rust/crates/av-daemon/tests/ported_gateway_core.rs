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
    sequence: Mutex<std::collections::VecDeque<Result<Reply, UpstreamError>>>,
    failure: Mutex<Option<UpstreamError>>,
    gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
    source: Mutex<Option<Body>>,
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
        let queued = self.sequence.lock().unwrap().pop_front();
        let failure = self.failure.lock().unwrap().clone();
        let gate = self.gate.lock().unwrap().clone();
        let source = self.source.lock().unwrap().take();
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.notified().await;
            }
            if let Some(failure) = failure {
                return Err(failure);
            }
            if let Some(reply) = queued.transpose()?.or(reply) {
                return Ok(UpstreamResponse {
                    status: reply.status,
                    headers: reply.headers,
                    body: if let Some(source) = source {
                        source
                    } else if reply.streaming {
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
    grant_id: String,
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
        Self::configured(sites, secret, scrub_budget, json!({})).await
    }

    async fn configured(
        sites: &[&str],
        secret: &str,
        scrub_budget: Option<(Option<usize>, Option<usize>)>,
        policy_patch: Value,
    ) -> Self {
        Self::configured_kind(
            sites,
            secret,
            scrub_budget,
            policy_patch,
            "http",
            "api.example.test",
        )
        .await
    }

    async fn configured_kind(
        sites: &[&str],
        secret: &str,
        scrub_budget: Option<(Option<usize>, Option<usize>)>,
        policy_patch: Value,
        kind: &'static str,
        host: &'static str,
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
                "slug": "demo", "kind": kind, "host": host,
                "value": secret, "sites": sites
            }),
        )
        .await;
        assert_eq!(status, 200, "{cred}");
        // Like gateway-helpers.js, seed the auto grant directly in the temp
        // vault: the control API intentionally requires a factor for auto writes.
        let (token, ph, grant_id) = shared.run(move |core| {
            use av_core::secret::ExposeSecret;
            use av_store::vault::{CreateSessionOptions, CreateGrantOptions, IssueOptions};
            let credential = core.vault.find_credential("demo").unwrap().unwrap();
            let session = core.vault.create_session(CreateSessionOptions::default()).unwrap();
            let mut policy = json!({"hosts": [host], "methods": ["GET", "POST"], "paths": ["/**"], "budget": {"unit": "requests", "limit": 1000}, "approval": "auto"});
            for (k,v) in policy_patch.as_object().unwrap() { policy[k] = v.clone(); }
            let grant = core.vault.create_grant(CreateGrantOptions {
                session_id: session.session.id,
                credential_id: credential.id,
                policy: serde_json::from_value(policy).unwrap(),
                ..Default::default()
            }).unwrap();
            let ph = core.vault.issue_placeholder(IssueOptions { grant_id: grant.id.clone(), ..Default::default() }).unwrap();
            (session.token.expose_secret().to_string(), ph.placeholder, grant.id)
        }).await.unwrap();
        Self {
            _dir: dir,
            shared,
            daemon,
            up,
            token,
            ph,
            secret: secret.into(),
            grant_id,
        }
    }

    async fn mint(&self, uses: Option<u64>) -> String {
        let grant_id = self.grant_id.clone();
        self.shared
            .run(move |core| {
                core.vault
                    .issue_placeholder(av_store::vault::IssueOptions {
                        grant_id,
                        uses,
                        ..Default::default()
                    })
                    .unwrap()
                    .placeholder
            })
            .await
            .unwrap()
    }

    async fn write(&self, body: &str) -> GatewayResponse {
        self.send(
            "POST",
            "/write",
            vec![("x-key".into(), self.ph.clone())],
            Some(body.into()),
        )
        .await
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

// Byte-exact ordinary stream fixtures from gateway-hardening.test.js,
// extracted from its pure constant declarations without importing the test.
const ORDINARY_PROVIDER_STREAMS: &str = r###"{"anthropic":["event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-x\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n","event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\",\"signature\":\"\"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"The user wants the file. \"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"I should read it first.\"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"EqQBCgIYAhIM1gbcDa9GJwZA2b3hGgxBdjrkzLoky3dl1pkiMOYds\"}}\n\n","event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n","event: ping\ndata: {\"type\":\"ping\"}\n\n","event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Sure\"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\" — I'll read \"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"https://example.com/a/b?q=1 \"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"and the disk-usage_by_repository report.\"}}\n\n","event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n","event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"read_file\",\"input\":{}}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\": \\\"/tmp\"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"/report.txt\\\",\"}}\n\n","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\" \\\"limit\\\": 200}\"}}\n\n","event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n","event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":89}}\n\n","event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"],"chat":["data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\",\"refusal\":null},\"logprobs\":null,\"finish_reason\":null}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Let me\"},\"finish_reason\":null}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" check\"},\"finish_reason\":null}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" https://example.com/a/b\"},\"finish_reason\":null}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\".\"},\"finish_reason\":null}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"loc\"}}]}}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ation\\\":\"}}]}}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\" \\\"Paris\\\"}\"}}]}}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_def\",\"type\":\"function\",\"function\":{\"name\":\"get_time\",\"arguments\":\"\"}}]}}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"{\\\"tz\\\":\"}}]}}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\" \\\"CET\\\"}\"}}]}}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n","data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":12,\"total_tokens\":21}}\n\n","data: [DONE]\n\n"],"responses":["event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":1700000000,\"status\":\"in_progress\",\"model\":\"gpt-x\",\"output\":[],\"tools\":[{\"type\":\"web_search\"}],\"text\":{\"format\":{\"type\":\"text\"}},\"usage\":null},\"sequence_number\":0}\n\n","event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"rs_1\",\"type\":\"reasoning\",\"summary\":[]},\"sequence_number\":1}\n\n","event: response.reasoning_summary_part.added\ndata: {\"type\":\"response.reasoning_summary_part.added\",\"item_id\":\"rs_1\",\"output_index\":0,\"summary_index\":0,\"part\":{\"type\":\"summary_text\",\"text\":\"\"},\"sequence_number\":2}\n\n","event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"item_id\":\"rs_1\",\"output_index\":0,\"summary_index\":0,\"delta\":\"Looked \",\"sequence_number\":3}\n\n","event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"item_id\":\"rs_1\",\"output_index\":0,\"summary_index\":0,\"delta\":\"it up.\",\"sequence_number\":4}\n\n","event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"id\":\"rs_1\",\"type\":\"reasoning\",\"summary\":[{\"type\":\"summary_text\",\"text\":\"Looked it up.\"}]},\"sequence_number\":5}\n\n","event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":1,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"status\":\"in_progress\",\"role\":\"assistant\",\"content\":[]},\"sequence_number\":6}\n\n","event: response.content_part.added\ndata: {\"type\":\"response.content_part.added\",\"item_id\":\"msg_1\",\"output_index\":1,\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"\",\"annotations\":[]},\"sequence_number\":7}\n\n","event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":1,\"content_index\":0,\"delta\":\"Paris is \",\"sequence_number\":8}\n\n","event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":1,\"content_index\":0,\"delta\":\"the capital \",\"sequence_number\":9}\n\n","event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":1,\"content_index\":0,\"delta\":\"of France [1].\",\"sequence_number\":10}\n\n","event: response.output_text.annotation.added\ndata: {\"type\":\"response.output_text.annotation.added\",\"item_id\":\"msg_1\",\"output_index\":1,\"content_index\":0,\"annotation_index\":0,\"annotation\":{\"type\":\"url_citation\",\"start_index\":31,\"end_index\":34,\"url\":\"https://en.wikipedia.org/wiki/Paris\",\"title\":\"Paris - Wikipedia\"},\"sequence_number\":11}\n\n","event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"item_id\":\"msg_1\",\"output_index\":1,\"content_index\":0,\"text\":\"Paris is the capital of France [1].\",\"sequence_number\":12}\n\n","event: response.content_part.done\ndata: {\"type\":\"response.content_part.done\",\"item_id\":\"msg_1\",\"output_index\":1,\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"Paris is the capital of France [1].\",\"annotations\":[{\"type\":\"url_citation\",\"start_index\":31,\"end_index\":34,\"url\":\"https://en.wikipedia.org/wiki/Paris\",\"title\":\"Paris - Wikipedia\"}]},\"sequence_number\":13}\n\n","event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Paris is the capital of France [1].\",\"annotations\":[{\"type\":\"url_citation\",\"start_index\":31,\"end_index\":34,\"url\":\"https://en.wikipedia.org/wiki/Paris\",\"title\":\"Paris - Wikipedia\"}]}]},\"sequence_number\":14}\n\n","event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":2,\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"lookup\",\"arguments\":\"\",\"status\":\"in_progress\"},\"sequence_number\":15}\n\n","event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"output_index\":2,\"delta\":\"{\\\"city\\\":\",\"sequence_number\":16}\n\n","event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"output_index\":2,\"delta\":\"\\\"Paris\\\"}\",\"sequence_number\":17}\n\n","event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"fc_1\",\"output_index\":2,\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\",\"sequence_number\":18}\n\n","event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":2,\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"lookup\",\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\",\"status\":\"completed\"},\"sequence_number\":19}\n\n","event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":1700000000,\"status\":\"completed\",\"model\":\"gpt-x\",\"output\":[{\"id\":\"rs_1\",\"type\":\"reasoning\",\"summary\":[{\"type\":\"summary_text\",\"text\":\"Looked it up.\"}]},{\"id\":\"msg_1\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Paris is the capital of France [1].\",\"annotations\":[{\"type\":\"url_citation\",\"start_index\":31,\"end_index\":34,\"url\":\"https://en.wikipedia.org/wiki/Paris\",\"title\":\"Paris - Wikipedia\"}]}]},{\"id\":\"fc_1\",\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"lookup\",\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\",\"status\":\"completed\"}],\"tools\":[{\"type\":\"web_search\"}],\"text\":{\"format\":{\"type\":\"text\"}},\"usage\":{\"input_tokens\":30,\"output_tokens\":40,\"total_tokens\":70}},\"sequence_number\":20}\n\n"],"gemini":["data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"The capital\"}],\"role\":\"model\"},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":8,\"totalTokenCount\":8},\"modelVersion\":\"gemini-x\",\"responseId\":\"r1\"}\n\n","data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" of France is Paris; see https://example.com/a/b.\"}],\"role\":\"model\"}}],\"modelVersion\":\"gemini-x\",\"responseId\":\"r1\"}\n\n","data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"lookup\",\"args\":{\"city\":\"Paris\",\"fields\":[\"population\",\"area\"]}}}],\"role\":\"model\"},\"index\":0}],\"modelVersion\":\"gemini-x\",\"responseId\":\"r1\"}\n\n","data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"\"}],\"role\":\"model\"},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":20,\"totalTokenCount\":28},\"modelVersion\":\"gemini-x\",\"responseId\":\"r1\"}\n\n"]}"###;

#[tokio::test]
async fn ordinary_provider_streams_are_byte_exact_with_identity_and_gzip_and_both_secret_shapes() {
    let fixtures: Value = serde_json::from_str(ORDINARY_PROVIDER_STREAMS).unwrap();
    for secret in [SECRET, SLASHED] {
        let f = Fixture::with_secret(&["header:x-key"], secret).await;
        for (name, events) in fixtures.as_object().unwrap() {
            let bytes = events
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e.as_str().unwrap())
                .collect::<String>();
            for compressed in [false, true] {
                stream_reply(&f, &bytes, compressed);
                let r = drain(f.get().await).await;
                assert_eq!(r.status, 200, "{name} gzip={compressed}");
                assert_eq!(r.body, bytes.as_bytes(), "{name} gzip={compressed}");
                f.clean(&r).await;
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Client {
    Chat,
    Responses,
}
fn client_index(v: &Value, missing: &str) -> String {
    match v {
        Value::Null => missing.into(),
        Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}
fn reassemble(events: &str, client: Client, missing: &str) -> Vec<String> {
    let mut groups = std::collections::BTreeMap::<String, String>::new();
    let mut add = |key: String, text: &Value| {
        if let Some(text) = text.as_str() {
            groups.entry(key).or_default().push_str(text);
        }
    };
    for v in events
        .lines()
        .filter_map(|s| s.strip_prefix("data: "))
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
    {
        match client {
            Client::Chat => {
                for choice in v["choices"].as_array().into_iter().flatten() {
                    let i = client_index(&choice["index"], missing);
                    add(i.clone(), &choice["delta"]["content"]);
                    for tool in choice["delta"]["tool_calls"]
                        .as_array()
                        .into_iter()
                        .flatten()
                    {
                        add(
                            format!("{i}.tool.{}", client_index(&tool["index"], missing)),
                            &tool["function"]["arguments"],
                        );
                    }
                }
            }
            Client::Responses => {
                let output = client_index(&v["output_index"], missing);
                match v["type"].as_str().unwrap_or_default() {
                    "response.output_item.added" => {
                        for (i, part) in v["item"]["content"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .enumerate()
                        {
                            add(format!("{output}/{i}"), &part["text"]);
                        }
                    }
                    "response.content_part.added" => add(
                        format!("{output}/{}", client_index(&v["content_index"], missing)),
                        &v["part"]["text"],
                    ),
                    "response.output_text.delta" => add(
                        format!("{output}/{}", client_index(&v["content_index"], missing)),
                        &v["delta"],
                    ),
                    _ => {}
                }
            }
        }
    }
    groups.into_values().collect()
}
fn choice(index: Option<u32>, text: &str) -> Value {
    let mut v = json!({"delta":{"content":text}});
    if let Some(i) = index {
        v["index"] = json!(i);
    }
    v
}
fn call(index: Option<u32>, args: &str) -> Value {
    let mut v = json!({"function":{"arguments":args}});
    if let Some(i) = index {
        v["index"] = json!(i);
    }
    v
}
fn chat(choices: Vec<Value>) -> Value {
    json!({"id":"chatcmpl-1","object":"chat.completion.chunk","choices":choices})
}
fn tool(tool_calls: Vec<Value>) -> Value {
    json!({"index":0,"delta":{"tool_calls":tool_calls}})
}
fn response_text(output: Option<u32>, content: Option<u32>, text: &str) -> Value {
    let mut v = json!({"type":"response.output_text.delta","item_id":"msg_1","delta":text});
    if let Some(i) = output {
        v["output_index"] = json!(i);
    }
    if let Some(i) = content {
        v["content_index"] = json!(i);
    }
    v
}

async fn assert_client_cannot_reassemble(
    name: &str,
    events: Vec<Value>,
    client: Client,
    missing: &str,
    secret: &str,
) {
    let events = events.into_iter().map(data).collect::<String>();
    assert!(
        reassemble(&events, client, missing)
            .iter()
            .any(|s| s.contains(secret)),
        "invalid fixture {name}"
    );
    let f = Fixture::with_secret(&["header:x-key"], secret).await;
    for compressed in [false, true] {
        stream_reply(&f, &events, compressed);
        let r = drain(f.get().await).await;
        let out = String::from_utf8_lossy(&r.body);
        assert!(
            out.contains("AV_UNSCANNABLE"),
            "{name} gzip={compressed}: {out}"
        );
        assert!(
            !reassemble(&out, client, missing)
                .iter()
                .any(|s| s.contains(secret)),
            "{name}"
        );
        f.clean(&r).await;
        ordinary_stream_control(&f, compressed).await;
    }
}

#[tokio::test]
async fn stream_client_indexes_override_array_positions_without_leaking_split_secrets() {
    for secret in [SECRET, SLASHED] {
        let (a, b) = secret.split_at(11);
        let cases = vec![
            (
                "choice moves array position",
                Client::Chat,
                vec![
                    chat(vec![choice(Some(0), a)]),
                    chat(vec![choice(Some(1), "x"), choice(Some(0), b)]),
                ],
            ),
            (
                "tool moves array position",
                Client::Chat,
                vec![
                    chat(vec![tool(vec![call(Some(1), a)])]),
                    chat(vec![tool(vec![call(Some(0), "x"), call(Some(1), b)])]),
                ],
            ),
            (
                "response item starts with text",
                Client::Responses,
                vec![
                    json!({"type":"response.output_item.added","output_index":1,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":a,"annotations":[]}]}}),
                    response_text(Some(0), Some(0), "x"),
                    response_text(Some(1), Some(0), b),
                ],
            ),
            (
                "response content position is index",
                Client::Responses,
                vec![
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"x"},{"type":"output_text","text":a}]}}),
                    response_text(Some(0), Some(0), "y"),
                    response_text(Some(0), Some(1), b),
                ],
            ),
            (
                "response part starts with text",
                Client::Responses,
                vec![
                    json!({"type":"response.content_part.added","output_index":0,"content_index":1,"part":{"type":"output_text","text":a,"annotations":[]}}),
                    response_text(Some(0), Some(0), "x"),
                    response_text(Some(0), Some(1), b),
                ],
            ),
        ];
        for (name, client, events) in cases {
            assert_client_cannot_reassemble(name, events, client, "0", secret).await;
        }
    }
}

#[tokio::test]
async fn missing_stream_indexes_are_safe_for_zero_default_and_distinct_missing_clients() {
    for secret in [SECRET, SLASHED] {
        let (a, b) = secret.split_at(11);
        for missing in ["0", "none"] {
            let first = if missing == "0" { Some(0) } else { None };
            let other = if missing == "0" { Some(1) } else { Some(0) };
            let cases = vec![
                (
                    "chat missing after",
                    Client::Chat,
                    vec![
                        chat(vec![choice(first, a)]),
                        chat(vec![choice(other, "x")]),
                        chat(vec![choice(None, b)]),
                    ],
                ),
                (
                    "chat missing before",
                    Client::Chat,
                    vec![
                        chat(vec![choice(None, a)]),
                        chat(vec![choice(other, "x")]),
                        chat(vec![choice(first, b)]),
                    ],
                ),
                (
                    "tool call missing index",
                    Client::Chat,
                    vec![
                        chat(vec![tool(vec![call(None, a)])]),
                        chat(vec![tool(vec![call(other, "x")])]),
                        chat(vec![tool(vec![call(first, b)])]),
                    ],
                ),
                (
                    "response missing output after",
                    Client::Responses,
                    vec![
                        response_text(first, Some(0), a),
                        response_text(other, Some(0), "x"),
                        response_text(None, Some(0), b),
                    ],
                ),
                (
                    "response missing output before",
                    Client::Responses,
                    vec![
                        response_text(None, Some(0), a),
                        response_text(other, Some(0), "x"),
                        response_text(first, Some(0), b),
                    ],
                ),
                (
                    "response missing content",
                    Client::Responses,
                    vec![
                        response_text(Some(0), None, a),
                        response_text(Some(0), other, "x"),
                        response_text(Some(0), first, b),
                    ],
                ),
            ];
            for (name, client, events) in cases {
                assert_client_cannot_reassemble(name, events, client, missing, secret).await;
            }
        }
    }
}

// gateway-approvals.test.js: one decision must execute only what was approved.
async fn approval_fixture(mode: &str, sites: &[&str]) -> Fixture {
    Fixture::configured(sites, SECRET, None, json!({"approval":mode})).await
}
fn held_id(r: &GatewayResponse) -> String {
    assert_eq!(r.status, 202);
    serde_json::from_slice::<Value>(&r.body).unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .into()
}
#[tokio::test]
async fn consumed_approval_cannot_be_denied_or_rearmed_and_resend_only_replays() {
    let mut f = approval_fixture("on-write", &["header:x-key"]).await;
    f.ph = f.mint(Some(1)).await;
    let id = held_id(&f.write("x").await);
    f.daemon
        .pipeline()
        .decide_approval(id.clone(), true)
        .await
        .unwrap();
    let ran = f.write("x").await;
    assert_eq!(ran.status, 200);
    assert!(ran.header("av-placeholder-next").is_some());
    f.clean(&ran).await;
    for decision in [false, true] {
        let error = f
            .daemon
            .pipeline()
            .decide_approval(id.clone(), decision)
            .await
            .unwrap_err();
        assert_eq!(error.code.as_str(), "AV_POLICY_DENIED");
        assert_eq!(
            f.daemon
                .pipeline()
                .approval_status(id.clone())
                .await
                .unwrap()["state"],
            "consumed"
        );
    }
    let again = f.write("x").await;
    assert_eq!(again.header("av-replayed"), Some("true"));
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&again).await;
}
#[tokio::test]
async fn granted_approval_cannot_flip_and_pending_decisions_return_no_cached_result() {
    let f = approval_fixture("on-write", &["header:x-key"]).await;
    let yes = held_id(&f.write("yes").await);
    let no = held_id(&f.write("no").await);
    for (id, granted, state) in [
        (yes.clone(), true, "granted"),
        (no.clone(), false, "denied"),
    ] {
        let returned = f
            .daemon
            .pipeline()
            .decide_approval(id, granted)
            .await
            .unwrap();
        assert_eq!(returned["state"], state);
        assert!(returned.get("result").is_none());
    }
    assert_eq!(
        f.daemon
            .pipeline()
            .decide_approval(yes, false)
            .await
            .unwrap_err()
            .code
            .as_str(),
        "AV_POLICY_DENIED"
    );
    let allowed = f.write("yes").await;
    assert_eq!(allowed.status, 200);
    f.clean(&allowed).await;
    let denied = f.write("no").await;
    assert_eq!(denied.status, 403);
    f.clean(&denied).await;
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn literal_hash_marker_cannot_swap_header_and_json_injection_sites() {
    let f = approval_fixture("each", &["header:x-key", "json:/token"]).await;
    let marker = format!(
        "<av:{}:{}>",
        f.grant_id,
        av_core::profiles::default_field("http")
    );
    let send = |header: String, token: String| {
        f.send(
            "POST",
            "/write",
            vec![
                ("content-type".into(), "application/json".into()),
                ("x-key".into(), header),
            ],
            Some(json!({"token":token}).to_string()),
        )
    };
    let id = held_id(&send(f.ph.clone(), marker.clone()).await);
    f.daemon.pipeline().decide_approval(id, true).await.unwrap();
    let swapped = send(marker.clone(), f.ph.clone()).await;
    assert_eq!(swapped.status, 202);
    f.clean(&swapped).await;
    let id = held_id(&send(format!("{} {marker}", f.ph), "x".into()).await);
    f.daemon.pipeline().decide_approval(id, true).await.unwrap();
    assert_eq!(
        send(format!("{marker} {}", f.ph), "x".into()).await.status,
        202
    );
    assert!(f.up.hits.lock().unwrap().is_empty());
    let original = send(f.ph.clone(), marker).await;
    assert_eq!(original.status, 200);
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    assert!(f
        .last()
        .headers
        .iter()
        .any(|(k, v)| k == "x-key" && v == SECRET));
    f.clean(&original).await;
}
#[tokio::test]
async fn method_override_participates_in_approval_and_safe_ordinary_methods_pass() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"approval":"on-write","methods":["GET","POST","DELETE"]}),
    )
    .await;
    let send = |method: &'static str, value: &str| {
        f.send(
            method,
            "/x",
            vec![
                ("x-key".into(), f.ph.clone()),
                ("x-http-method-override".into(), value.into()),
            ],
            None,
        )
    };
    let r = send("GET", "DELETE").await;
    assert_eq!(r.status, 202);
    assert!(f.daemon.pipeline().pending_approvals().await[0]["summary"]
        .as_str()
        .unwrap()
        .contains("DELETE"));
    assert!(f.up.hits.lock().unwrap().is_empty());
    f.clean(&r).await;
    for override_ in [false, true] {
        let r = if override_ {
            send("GET", "GET").await
        } else {
            f.get().await
        };
        assert_eq!(r.status, 200);
        f.clean(&r).await;
    }
    let r = f
        .send(
            "POST",
            "/x",
            vec![("x-key".into(), f.ph.clone())],
            Some("x".into()),
        )
        .await;
    assert_eq!(r.status, 202);
    assert!(f
        .daemon
        .pipeline()
        .pending_approvals()
        .await
        .iter()
        .any(|a| a["summary"] == "POST api.example.test/x"));
    f.clean(&r).await;
}
#[tokio::test]
async fn streamed_or_failed_consumed_approval_gets_a_new_visible_pending_id() {
    for streamed in [false, true] {
        let f = approval_fixture("each", &["header:x-key"]).await;
        if streamed {
            stream_reply(&f, "data: hi\n\n", false);
        } else {
            *f.up.failure.lock().unwrap() = Some(UpstreamError::new("ECONNRESET", "test reset"));
        }
        let first = held_id(&f.get().await);
        f.daemon
            .pipeline()
            .decide_approval(first.clone(), true)
            .await
            .unwrap();
        let ran = drain(f.get().await).await;
        assert_eq!(ran.status, if streamed { 200 } else { 502 });
        f.clean(&ran).await;
        *f.up.failure.lock().unwrap() = None;
        let retry = f.get().await;
        let second = held_id(&retry);
        assert_ne!(second, first);
        assert!(f
            .daemon
            .pipeline()
            .pending_approvals()
            .await
            .iter()
            .any(|a| a["id"] == second));
        assert_eq!(
            f.daemon.pipeline().approval_status(first).await.unwrap()["state"],
            "consumed"
        );
        f.clean(&retry).await;
        f.daemon
            .pipeline()
            .decide_approval(second, true)
            .await
            .unwrap();
        let reran = drain(f.get().await).await;
        assert_eq!(reran.status, 200);
        f.clean(&reran).await;
    }
}
#[tokio::test]
async fn expired_buffered_replay_is_held_under_a_new_visible_id() {
    let f = approval_fixture("each", &["header:x-key"]).await;
    let first = held_id(&f.get().await);
    f.daemon
        .pipeline()
        .decide_approval(first.clone(), true)
        .await
        .unwrap();
    assert_eq!(f.get().await.status, 200);
    assert_eq!(f.get().await.header("av-replayed"), Some("true"));
    f.shared
        .run(|core| {
            for (_, approval) in &mut core.pl.approvals {
                approval.decided_at = Some("2000-01-01T00:00:00.000Z".into());
            }
        })
        .await
        .unwrap();
    assert_eq!(
        f.send("GET", "/other", vec![("x-key".into(), f.ph.clone())], None)
            .await
            .status,
        202
    );
    let retry = f.get().await;
    let second = held_id(&retry);
    assert_ne!(first, second);
    assert!(f
        .daemon
        .pipeline()
        .pending_approvals()
        .await
        .iter()
        .any(|a| a["id"] == second));
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&retry).await;
}
#[tokio::test]
async fn in_flight_resend_waits_for_original_approval_and_replays_after_completion() {
    let f = approval_fixture("each", &["header:x-key"]).await;
    let first = held_id(&f.get().await);
    f.daemon
        .pipeline()
        .decide_approval(first.clone(), true)
        .await
        .unwrap();
    let release = Arc::new(tokio::sync::Notify::new());
    *f.up.gate.lock().unwrap() = Some(release.clone());
    let running = f.get();
    tokio::pin!(running);
    tokio::time::timeout(std::time::Duration::from_secs(5), async { tokio::select! { _ = &mut running => panic!("upstream should wait"), _=async { loop { if !f.up.hits.lock().unwrap().is_empty() { break; } tokio::task::yield_now().await; } }=>{} } }).await.expect("upstream was never entered");
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    let meanwhile = f.get().await;
    assert_eq!(held_id(&meanwhile), first);
    f.clean(&meanwhile).await;
    release.notify_one();
    let ran = running.await;
    assert_eq!(ran.status, 200);
    f.clean(&ran).await;
    let again = f.get().await;
    assert_eq!(again.header("av-replayed"), Some("true"));
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&again).await;
}
#[tokio::test]
async fn basic_placeholder_renewal_preserves_approval_but_user_and_padding_changes_do_not() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let f = approval_fixture("each", &["basic:pass"]).await;
    let send = |header: String| {
        f.send(
            "POST",
            "/write",
            vec![("authorization".into(), header)],
            None,
        )
    };
    let header =
        |user: &str, ph: &str| format!("Basic {}", STANDARD.encode(format!("{user}:{ph}")));
    let first = f.mint(None).await;
    let id = held_id(&send(header("user", &first)).await);
    f.daemon.pipeline().decide_approval(id, true).await.unwrap();
    let fresh = f.mint(None).await;
    let r = send(header("user", &fresh)).await;
    assert_eq!(r.status, 200);
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    assert!(f
        .last()
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == &header("user", SECRET)));
    f.clean(&r).await;
    let g = approval_fixture("each", &["basic:pass"]).await;
    let ph = g.mint(None).await;
    let user = ["user", "users", "userss"]
        .into_iter()
        .find(|user| STANDARD.encode(format!("{user}:{ph}")).ends_with('='))
        .unwrap();
    let send = |header: String| {
        g.send(
            "POST",
            "/write",
            vec![("authorization".into(), header)],
            None,
        )
    };
    let id = held_id(&send(header(user, &ph)).await);
    g.daemon.pipeline().decide_approval(id, true).await.unwrap();
    let r = send(header("admin", &g.mint(None).await)).await;
    assert_eq!(r.status, 202);
    g.clean(&r).await;
    let r = send(
        header(user, &g.mint(None).await)
            .trim_end_matches('=')
            .into(),
    )
    .await;
    assert_eq!(r.status, 202);
    assert!(g.up.hits.lock().unwrap().is_empty());
    g.clean(&r).await;
}

#[tokio::test]
async fn refund_depends_on_whether_upstream_could_have_received_both_placeholder_fields() {
    const SECOND: &str = "test-secret-second-refund-0123456789";
    for (error, uses, budget) in [("ECONNREFUSED", 0, 0), ("ECONNRESET", 1, 2)] {
        let f = Fixture::new(&["header:x-key"]).await;
        let (token,grant_id,placeholders)=f.shared.run(|core| {
            use av_store::vault::{NewCredential,CreateSessionOptions,CreateGrantOptions,IssueOptions};
            use av_core::secret::ExposeSecret;
            let credential=core.vault.add_credential(NewCredential {slug:"pair".into(),kind:"http".into(),connector:serde_json::from_value(json!({"host":"api.example.test","scheme":"https"})).unwrap(),fields:vec![("key".into(),SECRET.to_string().into()),("second".into(),SECOND.to_string().into())],sites:std::collections::BTreeMap::from([("key".into(),vec!["header:x-key".into()]),("second".into(),vec!["header:x-second".into()])])}).unwrap();
            let session=core.vault.create_session(CreateSessionOptions::default()).unwrap();
            let grant=core.vault.create_grant(CreateGrantOptions{session_id:session.session.id,credential_id:credential.id,policy:serde_json::from_value(json!({"hosts":["api.example.test"],"methods":["GET"],"paths":["/**"],"budget":{"unit":"requests","limit":1000},"approval":"auto"})).unwrap(),..Default::default()}).unwrap();
            let placeholders=["key","second"].into_iter().map(|field|core.vault.issue_placeholder(IssueOptions{grant_id:grant.id.clone(),field:Some(field.into()),..Default::default()}).unwrap()).collect::<Vec<_>>();
            (session.token.expose_secret().to_string(),grant.id,placeholders)
        }).await.unwrap();
        let request = || GatewayRequest {
            method: "GET".into(),
            path: "/p/pair/x".into(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), token.clone()),
                ("x-key".into(), placeholders[0].placeholder.clone()),
                ("x-second".into(), placeholders[1].placeholder.clone()),
            ],
            ..Default::default()
        };
        *f.up.failure.lock().unwrap() = Some(UpstreamError::new(error, "test upstream failure"));
        let r = f.daemon.pipeline().handle(request()).await;
        assert_eq!(r.status, 502);
        f.clean(&r).await;
        assert!(!String::from_utf8_lossy(&r.body).contains(SECOND));
        let ids = placeholders
            .iter()
            .map(|p| p.row.id.clone())
            .collect::<Vec<_>>();
        let check_grant = grant_id.clone();
        f.shared
            .run(move |core| {
                for row in core
                    .vault
                    .list_placeholders(None)
                    .unwrap()
                    .into_iter()
                    .filter(|row| ids.contains(&row.id))
                {
                    assert_eq!(row.uses, uses);
                }
                assert_eq!(
                    core.vault.grant(&check_grant).unwrap().unwrap().budget_used,
                    budget
                );
                let records = core
                    .vault
                    .audit()
                    .unwrap()
                    .read(&av_store::audit::ReadFilter {
                        limit: usize::MAX,
                        ..Default::default()
                    })
                    .unwrap();
                assert!(!serde_json::to_string(&records).unwrap().contains(SECOND));
            })
            .await
            .unwrap();
        *f.up.failure.lock().unwrap() = None;
        let r = f.daemon.pipeline().handle(request()).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"ordinary-traffic-control");
        f.clean(&r).await;
    }
}

// gateway-response.test.js: stream framing, failure, and reassembly bounds.
fn anthropic_text(index: u32, text: &str) -> String {
    format!(
        "event: content_block_delta\n{}",
        data(
            json!({"type":"content_block_delta","index":index,"delta":{"type":"text_delta","text":text}})
        )
    )
}
fn payloads(out: &str) -> impl Iterator<Item = Value> + '_ {
    out.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|s| serde_json::from_str(s).ok())
}
fn anthropic_reassemble(out: &str) -> String {
    payloads(out)
        .filter_map(|v| v["delta"]["text"].as_str().map(str::to_owned))
        .collect()
}
#[tokio::test]
async fn bare_cr_and_split_crlf_are_one_stream_line_ending() {
    let f = Fixture::new(&["header:x-key"]).await;
    stream_reply(&f, "", false);
    *f.up.source.lock().unwrap() = Some(Body::chunks(
        ["data: a\r\r", "data: b\r", "\n\r", "\ndata: c\n\n"]
            .into_iter()
            .map(|s| Ok(s.as_bytes().to_vec()))
            .collect(),
    ));
    let r = drain(f.get().await).await;
    assert_eq!(r.body, b"data: a\n\ndata: b\n\ndata: c\n\n");
    f.clean(&r).await;
    ordinary_stream_control(&f, false).await;
}
#[tokio::test]
async fn errored_identity_and_truncated_gzip_sources_cut_without_crashing_or_hanging() {
    use std::io::Write;
    for compressed in [false, true] {
        let f = Fixture::new(&["header:x-key"]).await;
        stream_reply(&f, "", compressed);
        let mut chunks = vec![];
        if compressed {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(b"data: one\n\n").unwrap();
            let bytes = enc.finish().unwrap();
            chunks.push(Ok(bytes[..15].to_vec()));
        }
        chunks.push(Err("test read ECONNRESET".into()));
        *f.up.source.lock().unwrap() = Some(Body::chunks(chunks));
        let response = f.get().await;
        // In the identity case the error already exists before the agent reads.
        tokio::task::yield_now().await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), drain(response))
            .await
            .expect("stream hung after source error");
        assert!(String::from_utf8_lossy(&r.body).contains("AV_UNSCANNABLE"));
        f.clean(&r).await;
        ordinary_stream_control(&f, compressed).await;
    }
}
#[tokio::test]
async fn unfinished_event_is_cut_before_unbounded_agent_output() {
    let f = Fixture::new(&["header:x-key"]).await;
    stream_reply(&f, "", false);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    *f.up.source.lock().unwrap() = Some(Body::Stream(rx));
    let writer = tokio::spawn(async move {
        if tx.send(Ok(b"data: ".to_vec())).await.is_err() {
            return;
        }
        for _ in 0..18 {
            if tx.send(Ok(vec![b'a'; 1024 * 1024])).await.is_err() {
                break;
            }
        }
    });
    let r = drain(f.get().await).await;
    writer.await.unwrap();
    assert!(r.body.len() < 1024 * 1024);
    assert!(String::from_utf8_lossy(&r.body).contains("AV_UNSCANNABLE"));
    f.clean(&r).await;
    ordinary_stream_control(&f, false).await;
}
#[tokio::test]
async fn long_finishing_events_do_not_hide_split_secrets_and_ordinary_long_events_survive() {
    let f = Fixture::new(&["header:x-key"]).await;
    for compressed in [false, true] {
        let events = anthropic_text(0, &SECRET[..14])
            + &anthropic_text(0, &format!("{}{}", &SECRET[14..], "x".repeat(2000)));
        assert!(anthropic_reassemble(&events).contains(SECRET));
        stream_reply(&f, &events, compressed);
        let r = drain(f.get().await).await;
        let out = String::from_utf8_lossy(&r.body);
        assert!(!anthropic_reassemble(&out).contains(SECRET));
        assert!(out.contains("AV_UNSCANNABLE"));
        f.clean(&r).await;
        let events = (0..6)
            .map(|i| {
                anthropic_text(
                    0,
                    &format!("{}{i}", "lorem ipsum dolor sit amet ".repeat(100)),
                )
            })
            .collect::<String>();
        stream_reply(&f, &events, compressed);
        let r = drain(f.get().await).await;
        assert_eq!(r.body, events.as_bytes());
        f.clean(&r).await;
    }
    let events = format!(
        "data: {}\n\ndata: {}{}\n\n",
        &SECRET[..14],
        &SECRET[14..],
        "x".repeat(2000)
    );
    stream_reply(&f, &events, false);
    let r = drain(f.get().await).await;
    let out = String::from_utf8_lossy(&r.body);
    assert!(!out
        .replace("\n\ndata: ", "")
        .replace("data: ", "")
        .contains(SECRET));
    assert!(out.contains("AV_UNSCANNABLE"));
    f.clean(&r).await;
    ordinary_stream_control(&f, false).await;
}
#[tokio::test]
async fn excess_paths_and_index_fields_cut_stream_and_ordinary_path_counts_survive() {
    let f = Fixture::new(&["header:x-key"]).await;
    let map = (0..1025)
        .map(|i| (format!("k{i}"), json!("metadata")))
        .collect::<serde_json::Map<_, _>>();
    let events = anthropic_text(0, &SECRET[..14])
        + &data(Value::Object(map))
        + &anthropic_text(0, &SECRET[14..]);
    stream_reply(&f, &events, false);
    let r = drain(f.get().await).await;
    let out = String::from_utf8_lossy(&r.body);
    assert!(out.contains("AV_UNSCANNABLE") && out.contains("JSON key paths"));
    assert!(!anthropic_reassemble(&out).contains(SECRET));
    f.clean(&r).await;
    let events =
        data(json!({"a_index":1,"b_index":2,"c_index":3,"d_index":4,"e_index":5,"delta":"hello"}));
    stream_reply(&f, &events, false);
    let r = drain(f.get().await).await;
    let out = String::from_utf8_lossy(&r.body);
    assert!(out.contains("AV_UNSCANNABLE") && out.contains("index fields"));
    f.clean(&r).await;
    let mut events = anthropic_text(0, "Hello");
    for n in 0..5 {
        let map = (0..10)
            .map(|i| (format!("m{n}_{i}"), json!("value")))
            .collect::<serde_json::Map<_, _>>();
        events += &data(Value::Object(map));
    }
    events += &anthropic_text(0, " world");
    stream_reply(&f, &events, false);
    let r = drain(f.get().await).await;
    assert_eq!(r.body, events.as_bytes());
    f.clean(&r).await;
}
#[tokio::test]
async fn dotted_empty_and_array_key_collisions_cannot_hide_reassembled_secret() {
    let f = Fixture::new(&["header:x-key"]).await;
    let (a, b) = SECRET.split_at(14);
    let cases = vec![
        (
            "dotted vs nested",
            vec![json!({"a":{"b":a},"a.b":"x"}), json!({"a":{"b":b}})],
            "/a/b",
            false,
        ),
        (
            "literal dot",
            vec![json!({".":{".":a},"...":"x"}), json!({".":{".":b}})],
            "/./.",
            false,
        ),
        (
            "empty parent",
            vec![json!({"":{"x":a},"x":"y"}), json!({"":{"x":b}})],
            "//x",
            false,
        ),
        (
            "dot suffix",
            vec![json!({"a":{"":a},"a.":"x"}), json!({"a":{"":b}})],
            "/a/",
            false,
        ),
        (
            "array vs object numeric key",
            vec![json!({"c":[a]}), json!({"c":{"0":"x"}}), json!({"c":[b]})],
            "/c/0",
            true,
        ),
    ];
    for (name, values, pointer, array_only) in cases {
        let events = values.into_iter().map(data).collect::<String>();
        let gather = |out: &str| {
            payloads(out)
                .filter(|v| !array_only || v["c"].is_array())
                .filter_map(|v| {
                    v.pointer(pointer)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect::<String>()
        };
        assert!(gather(&events).contains(SECRET));
        for compressed in [false, true] {
            stream_reply(&f, &events, compressed);
            let r = drain(f.get().await).await;
            let out = String::from_utf8_lossy(&r.body);
            assert!(!gather(&out).contains(SECRET), "{name}");
            assert!(out.contains("AV_UNSCANNABLE"), "{name}");
            f.clean(&r).await;
            ordinary_stream_control(&f, compressed).await;
        }
    }
}
#[tokio::test]
async fn ordinary_dotted_empty_numeric_keys_and_multi_provider_nan_streams_survive() {
    let f = Fixture::new(&["header:x-key"]).await;
    let mut blocks = String::new();
    for i in 0..60 {
        blocks += &format!(
            "event: content_block_start\n{}",
            data(
                json!({"type":"content_block_start","index":i,"content_block":if i%2==1{json!({"type":"tool_use","id":format!("toolu_{i}"),"name":"Read","input":{}})}else{json!({"type":"text","text":""})}})
            )
        );
        blocks += &if i % 2 == 1 {
            format!(
                "event: content_block_delta\n{}",
                data(
                    json!({"type":"content_block_delta","index":i,"delta":{"type":"input_json_delta","partial_json":format!("{{\"path\":\"/tmp/f{i}\"}}")}})
                )
            )
        } else {
            anthropic_text(i, &format!("Paragraph {i}. "))
        };
        blocks += &format!(
            "event: content_block_stop\n{}",
            data(json!({"type":"content_block_stop","index":i}))
        );
    }
    let mut choices = String::new();
    let mut responses = String::new();
    for i in 0..40 {
        choices += &data(
            json!({"id":"c1","choices":[{"index":0,"delta":{"content":format!("alpha {i} ")}}]}),
        );
        choices += &data(
            json!({"id":"c1","choices":[{"index":1,"delta":{"content":format!("beta {i} ")}}]}),
        );
        choices += &data(
            json!({"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":i%3,"function":{"arguments":format!("{{\"n\":{i}}}")}}]}}]}),
        );
        responses += &data(
            json!({"type":"response.output_text.delta","output_index":i%4,"content_index":i%2,"delta":format!("part {i} "),"item_id":format!("msg_{}",i%4),"sequence_number":i}),
        );
    }
    let nan="data: {\"index\":0,\"delta\":{\"text\":\"Hello\"},\"score\":NaN}\n\ndata: {\"index\":0,\"delta\":{\"text\":\" world\"},\"score\":Infinity}\n\n".to_string();
    let dotted = data(
        json!({"choices":[{"index":0,"delta":{"content":"Hello"}}],"x.request.id":"req_1",".":"dot","":"empty"}),
    ) + &data(
        json!({"choices":[{"index":0,"delta":{"content":" world"}}],"meta":{"0":"zero","a.b":"c"}}),
    ) + &data(json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}));
    for (name, events) in [
        ("blocks", blocks),
        ("choices", choices),
        ("responses", responses),
        ("nan", nan),
        ("dotted", dotted),
    ] {
        for compressed in [false, true] {
            stream_reply(&f, &events, compressed);
            let r = drain(f.get().await).await;
            assert_eq!(r.body, events.as_bytes(), "{name} gzip={compressed}");
            f.clean(&r).await;
        }
    }
}

#[tokio::test]
async fn provider_index_regrouping_decoy_indexes_and_nan_beside_text_cannot_hide_secret() {
    let f = Fixture::new(&["header:x-key"]).await;
    let (a, b) = SECRET.split_at(14);
    let cases=vec![
        ("Anthropic blocks",anthropic_text(0,a)+&anthropic_text(1,"x")+&anthropic_text(0,b),"anthropic"),
        ("OpenAI choices",data(chat(vec![choice(Some(0),a)]))+&data(chat(vec![choice(Some(1),"x")]))+&data(chat(vec![choice(Some(0),b)])),"chat"),
        ("OpenAI tools",data(chat(vec![tool(vec![call(Some(0),a)])]))+&data(chat(vec![tool(vec![call(Some(1),"x")])]))+&data(chat(vec![tool(vec![call(Some(0),b)])])),"chat"),
        ("Responses parts",data(response_text(Some(0),Some(0),a))+&data(response_text(Some(0),Some(1),"x"))+&data(response_text(Some(0),Some(0),b)),"responses"),
        ("decoy retry index",data(json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":a,"retry_index":1}))+&data(json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"x","retry_index":2}))+&data(json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":b,"retry_index":3})),"responses"),
        ("NaN beside text",format!("data: {{\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{a}\"}},\"p\":NaN}}\n\ndata: {{\"index\":0,\"delta\":{{\"type\":\"x\",\"text\":\"{b}\"}},\"p\":-Infinity}}\n\n"),"nan"),
    ];
    for (name, events, client) in cases {
        let gather = |out: &str| -> Vec<String> {
            match client {
                "chat" => reassemble(out, Client::Chat, "0"),
                "responses" => reassemble(out, Client::Responses, "0"),
                "nan" => vec![anthropic_reassemble(
                    &out.replace("NaN", "null").replace("-Infinity", "null"),
                )],
                _ => {
                    let mut groups = std::collections::BTreeMap::<String, String>::new();
                    for v in payloads(out) {
                        if let Some(s) = v["delta"]["text"].as_str() {
                            groups
                                .entry(v["index"].to_string())
                                .or_default()
                                .push_str(s);
                        }
                    }
                    groups.into_values().collect()
                }
            }
        };
        assert!(
            gather(&events).iter().any(|s| s.contains(SECRET)),
            "fixture {name}"
        );
        for compressed in [false, true] {
            stream_reply(&f, &events, compressed);
            let r = drain(f.get().await).await;
            let out = String::from_utf8_lossy(&r.body);
            assert!(out.contains("AV_UNSCANNABLE"), "{name}");
            assert!(!gather(&out).iter().any(|s| s.contains(SECRET)), "{name}");
            f.clean(&r).await;
            ordinary_stream_control(&f, compressed).await;
        }
    }
}

async fn network_pipeline(
    f: &Fixture,
    port: u16,
    method: &str,
    body: Option<Vec<u8>>,
) -> (av_daemon::pipeline::Pipeline, GatewayRequest) {
    let (token,ph)=f.shared.run(move |core| {
        use av_core::secret::ExposeSecret;
        use av_store::vault::{NewCredential,CreateSessionOptions,CreateGrantOptions,IssueOptions};
        let credential=core.vault.add_credential(NewCredential {slug:"network".into(),kind:"http".into(),connector:serde_json::from_value(json!({"host":format!("127.0.0.1:{port}"),"scheme":"http"})).unwrap(),fields:vec![("key".into(),SECRET.to_string().into())],sites:std::collections::BTreeMap::from([("key".into(),vec!["header:x-key".into()])])}).unwrap();
        let session=core.vault.create_session(CreateSessionOptions::default()).unwrap();
        let grant=core.vault.create_grant(CreateGrantOptions {session_id:session.session.id,credential_id:credential.id,policy:serde_json::from_value(json!({"hosts":["127.0.0.1"],"methods":["GET","DELETE"],"paths":["/**"],"budget":{"unit":"requests","limit":100},"approval":"auto"})).unwrap(),..Default::default()}).unwrap();
        let ph=core.vault.issue_placeholder(IssueOptions{grant_id:grant.id,..Default::default()}).unwrap();(session.token.expose_secret().to_string(),ph.placeholder)
    }).await.unwrap();
    let pipeline = av_daemon::pipeline::Pipeline::new(f.shared.clone(), PipelineOptions::default());
    (
        pipeline,
        GatewayRequest {
            method: method.into(),
            path: "/p/network/x".into(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), token),
                ("x-key".into(), ph),
            ],
            body,
            ..Default::default()
        },
    )
}
async fn read_wire_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let end = loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break bytes.len();
        }
        assert!(bytes.len() < 65536);
    };
    let headers = String::from_utf8(bytes).unwrap();
    let length = headers
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(end, headers.len());
    (headers, body)
}
#[tokio::test]
async fn real_buffered_complete_response_and_delete_body_have_correct_framing() {
    use tokio::io::AsyncWriteExt;
    for method in ["GET", "DELETE"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let seen = read_wire_request(&mut socket).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\npartial").await.unwrap();
            seen
        });
        let f = Fixture::new(&["header:x-key"]).await;
        let (pipeline, request) = network_pipeline(
            &f,
            port,
            method,
            if method == "DELETE" {
                Some(b"hello".to_vec())
            } else {
                None
            },
        )
        .await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), pipeline.handle(request))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"partial");
        f.clean(&r).await;
        let (headers, body) = server.await.unwrap();
        if method == "DELETE" {
            assert_eq!(body, b"hello");
            assert!(headers
                .lines()
                .any(|l| l.eq_ignore_ascii_case("content-length: 5")));
        } else {
            assert!(body.is_empty());
        }
    }
}
#[tokio::test]
async fn real_gzip_upstream_reset_mid_stream_ends_with_cut_instead_of_hanging() {
    use std::io::Write;
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = read_wire_request(&mut socket).await;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"data: one\n\n").unwrap();
        let bytes = enc.finish().unwrap();
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n").await.unwrap();
        socket.write_all(&bytes[..15]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });
    let f = Fixture::new(&["header:x-key"]).await;
    let (pipeline, request) = network_pipeline(&f, port, "GET", None).await;
    let r = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        drain(pipeline.handle(request).await).await
    })
    .await
    .expect("real reset stream hung");
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("AV_UNSCANNABLE"));
    f.clean(&r).await;
    server.await.unwrap();
    ordinary_stream_control(&f, true).await;
}

#[tokio::test]
async fn explicit_https_target_upgrades_http_credential_while_explicit_http_stays_http() {
    let f = Fixture::new(&["header:x-key"]).await;
    let (_, request) = network_pipeline(&f, 12345, "GET", None).await;
    let pipeline = av_daemon::pipeline::Pipeline::new(
        f.shared.clone(),
        PipelineOptions {
            upstream: Some(f.up.clone()),
            ..Default::default()
        },
    );
    for scheme in ["https", "http"] {
        let mut req = request.clone();
        req.path = format!("/t/{scheme}/127.0.0.1:12345/x");
        let r = pipeline.handle(req).await;
        assert_eq!(r.status, 200);
        assert!(f
            .last()
            .url
            .starts_with(&format!("{scheme}://127.0.0.1:12345/x")));
        f.clean(&r).await;
    }
}

async fn grant_counters(f: &Fixture) -> (u64, Vec<u64>) {
    let id = f.grant_id.clone();
    f.shared
        .run(move |core| {
            let budget = core.vault.grant(&id).unwrap().unwrap().budget_used;
            let uses = core
                .vault
                .list_placeholders(None)
                .unwrap()
                .into_iter()
                .filter(|p| p.grant_id == id)
                .map(|p| p.uses)
                .collect();
            (budget, uses)
        })
        .await
        .unwrap()
}
#[tokio::test]
async fn rate_capacity_and_pending_requests_are_limited_before_use_or_budget_is_spent() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"rate":{"count":2,"per":"hour"}}),
    )
    .await;
    for _ in 0..2 {
        let r = f.get().await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
    }
    let before = grant_counters(&f).await;
    let r = f.get().await;
    assert_eq!(r.status, 429);
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("rate")
    );
    assert!(r.header("retry-after").unwrap().parse::<u64>().unwrap() >= 1);
    assert_eq!(grant_counters(&f).await, before);
    f.clean(&r).await;
    let held = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"approval":"each","rate":{"count":1,"per":"hour"}}),
    )
    .await;
    let r = held.get().await;
    assert_eq!(r.status, 202);
    held.clean(&r).await;
    let r = held.get().await;
    assert_eq!(r.status, 429);
    assert_eq!(grant_counters(&held).await, (0, vec![0]));
    assert!(held.up.hits.lock().unwrap().is_empty());
    held.clean(&r).await;
}
#[tokio::test]
async fn concurrency_slots_release_after_success_and_both_classes_of_upstream_failure() {
    for error in [None, Some("ECONNREFUSED"), Some("ECONNRESET")] {
        let f =
            Fixture::configured(&["header:x-key"], SECRET, None, json!({"max_concurrent":1})).await;
        let release = Arc::new(tokio::sync::Notify::new());
        *f.up.gate.lock().unwrap() = Some(release.clone());
        *f.up.failure.lock().unwrap() = error.map(|s| UpstreamError::new(s, "test failure"));
        let first = f.get();
        tokio::pin!(first);
        tokio::time::timeout(std::time::Duration::from_secs(5), async { tokio::select! { _ = &mut first => panic!("upstream did not wait"), _=async { loop { if !f.up.hits.lock().unwrap().is_empty() { break; } tokio::task::yield_now().await; } }=>{} } }).await.expect("upstream was never entered");
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        let denied = f.get().await;
        assert_eq!(
            denied.error.as_ref().unwrap().extra.rule.as_deref(),
            Some("max_concurrent")
        );
        f.clean(&denied).await;
        release.notify_one();
        let result = first.await;
        assert_eq!(result.status, if error.is_some() { 502 } else { 200 });
        f.clean(&result).await;
        assert_eq!(
            f.daemon
                .pipeline()
                .limits_for(f.grant_id.clone())
                .await
                .unwrap()["max_concurrent"]["in_flight"],
            0
        );
        *f.up.failure.lock().unwrap() = None;
        *f.up.gate.lock().unwrap() = None;
        let ordinary = f.get().await;
        assert_eq!(ordinary.status, 200);
        f.clean(&ordinary).await;
    }
}
#[tokio::test]
async fn sse_concurrency_slots_release_on_completion_agent_close_and_scrubber_cut() {
    for mode in ["complete", "abort", "cut"] {
        let f =
            Fixture::configured(&["header:x-key"], SECRET, None, json!({"max_concurrent":1})).await;
        stream_reply(&f, "", false);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        *f.up.source.lock().unwrap() = Some(Body::Stream(rx));
        let r = f.get().await;
        assert_eq!(r.status, 200);
        assert_eq!(
            f.daemon
                .pipeline()
                .limits_for(f.grant_id.clone())
                .await
                .unwrap()["max_concurrent"]["in_flight"],
            1
        );
        if mode == "abort" {
            drop(r);
            drop(tx);
        } else {
            let events = if mode == "cut" {
                format!(
                    "data: {{\"delta\":\"{}\"}}\n\ndata: {{\"delta\":\"{}\"}}\n\n",
                    &SECRET[..15],
                    &SECRET[15..]
                )
            } else {
                "data: {\"ok\":true}\n\n".into()
            };
            tx.send(Ok(events.into_bytes())).await.unwrap();
            drop(tx);
            let r = drain(r).await;
            if mode == "cut" {
                assert!(String::from_utf8_lossy(&r.body).contains("AV_UNSCANNABLE"));
            }
            f.clean(&r).await;
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if f.daemon
                    .pipeline()
                    .limits_for(f.grant_id.clone())
                    .await
                    .unwrap()["max_concurrent"]["in_flight"]
                    == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("SSE slot leaked");
        ordinary_stream_control(&f, false).await;
    }
}
#[tokio::test]
async fn payload_and_method_bound_routes_refuse_before_approval_or_consume() {
    let f=Fixture::configured(&["header:x-key"],SECRET,None,json!({"approval":"each","routes":[{"methods":["GET"],"paths":["/ordinary"]},{"methods":["POST"],"paths":["/comment"]}],"payload":{"json":{"/channel":{"one_of":["safe"]}}}})).await;
    let bad = f
        .send(
            "POST",
            "/comment",
            vec![
                ("x-key".into(), f.ph.clone()),
                ("content-type".into(), "application/json".into()),
            ],
            Some("{\"channel\":\"bad\"}".into()),
        )
        .await;
    assert_eq!(
        bad.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("payload:json:0:one_of")
    );
    assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    f.clean(&bad).await;
    let bad = f
        .send(
            "POST",
            "/ordinary",
            vec![("x-key".into(), f.ph.clone())],
            None,
        )
        .await;
    assert_eq!(
        bad.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("routes")
    );
    f.clean(&bad).await;
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 202);
    assert!(f.up.hits.lock().unwrap().is_empty());
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    f.clean(&ordinary).await;
}

fn gateway_input(
    f: &Fixture,
    method: &str,
    path: &str,
    query: &str,
    content_type: Option<&str>,
    body: Option<Vec<u8>>,
) -> GatewayRequest {
    let mut headers = vec![
        ("host".into(), "127.0.0.1".into()),
        ("av-session".into(), f.token.clone()),
        ("x-key".into(), f.ph.clone()),
    ];
    if let Some(ct) = content_type {
        headers.push(("content-type".into(), ct.into()));
    }
    GatewayRequest {
        method: method.into(),
        path: format!("/p/demo{path}"),
        query: query.into(),
        headers,
        body,
        ..Default::default()
    }
}
async fn audit_records(f: &Fixture) -> Vec<Value> {
    f.shared
        .run(|core| {
            core.vault
                .audit()
                .unwrap()
                .read(&av_store::audit::ReadFilter {
                    limit: usize::MAX,
                    ..Default::default()
                })
                .unwrap()
                .into_iter()
                .map(|r| serde_json::to_value(r).unwrap())
                .collect()
        })
        .await
        .unwrap()
}
#[tokio::test]
async fn graphql_checks_post_url_query_and_normalized_graphql_path() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"graphql":{"operations":["query"]}}}),
    )
    .await;
    let bad = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/graphql",
            "query=mutation%7Bx%7D",
            Some("application/json"),
            Some(b"{\"query\":\"{a}\"}".to_vec()),
        ))
        .await;
    assert_eq!(
        bad.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("payload:graphql:operation")
    );
    f.clean(&bad).await;
    let good = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/graphql",
            "",
            Some("application/json"),
            Some(b"{\"query\":\"{a}\"}".to_vec()),
        ))
        .await;
    assert_eq!(good.status, 200);
    f.clean(&good).await;
    let bad = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/graphql/.",
            "",
            Some("text/plain"),
            Some(b"x=1".to_vec()),
        ))
        .await;
    assert_eq!(
        bad.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("graphql_unreadable")
    );
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&bad).await;
}
#[tokio::test]
async fn query_only_payload_rules_allow_binary_upload_and_refuse_unsafe_query() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"query":{"mode":{"one_of":["safe"]}}}}),
    )
    .await;
    let good = gateway_input(
        &f,
        "POST",
        "/upload",
        "mode=safe",
        Some("application/octet-stream"),
        Some(vec![0xff, 0xfe, 0, 0x81]),
    );
    let r = f.daemon.pipeline().handle(good.clone()).await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().body, Some(vec![0xff, 0xfe, 0, 0x81]));
    f.clean(&r).await;
    let mut bad = good;
    bad.query = "mode=unsafe".into();
    let r = f.daemon.pipeline().handle(bad).await;
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("payload:query:0:one_of")
    );
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&r).await;
}
#[tokio::test]
async fn strict_query_denials_name_positions_and_never_echo_hostile_names_or_values() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"query":{"a":{}},"query_strict":true}}),
    )
    .await;
    for (name, rule) in [
        ("evil<> \"name\"", "payload:query:1:strict"),
        ("évil\nname", "request_ambiguous"),
    ] {
        let query = format!(
            "a=1&{}=test-secret-marker",
            av_daemon::util::encode_uri_component(name)
        );
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(&f, "GET", "/ordinary", &query, None, None))
            .await;
        assert_eq!(r.error.as_ref().unwrap().extra.rule.as_deref(), Some(rule));
        let out = String::from_utf8_lossy(&r.body);
        assert!(
            !out.contains("test-secret-marker") && !out.contains("evil") && !out.contains("vil")
        );
        f.clean(&r).await;
    }
    // The pure payload reader also uses the parameter's position.
    let query = format!(
        "a=1&{}=test-secret-marker",
        av_daemon::util::encode_uri_component("évil\nname")
    );
    let view = av_core::request_view::request_view(&av_core::request_view::RequestInput {
        query: Some(&query),
        ..Default::default()
    });
    let sets = serde_json::from_value(json!([{"query":{"a":{}},"query_strict":true}])).unwrap();
    let e = av_core::payload::evaluate_payload(
        Some(&sets),
        &av_core::payload::PayloadInput {
            view: &view,
            path: "",
        },
    )
    .unwrap_err();
    assert_eq!(e.extra.rule.as_deref(), Some("payload:query:1:strict"));
    let good = f
        .daemon
        .pipeline()
        .handle(gateway_input(&f, "GET", "/ordinary", "a=1", None, None))
        .await;
    assert_eq!(good.status, 200);
    f.clean(&good).await;
    let log = serde_json::to_string(&audit_records(&f).await).unwrap();
    assert!(!log.contains("test-secret-marker") && !log.contains("evil"));
}
#[tokio::test]
async fn method_override_is_bound_by_route_pairs_and_allowed_tmp_control_runs() {
    let f=Fixture::configured(&["header:x-key"],SECRET,None,json!({"methods":["GET","POST","DELETE"],"routes":[{"methods":["GET","POST"],"paths":["/**"]},{"methods":["DELETE"],"paths":["/tmp/**"]}]})).await;
    for (path, status) in [("/repos/x", 403), ("/tmp/x", 200)] {
        let mut req = gateway_input(&f, "POST", path, "", None, Some(b"x".to_vec()));
        req.headers
            .push(("x-http-method-override".into(), "DELETE".into()));
        let r = f.daemon.pipeline().handle(req).await;
        assert_eq!(r.status, status);
        if status == 403 {
            assert_eq!(
                r.error.as_ref().unwrap().extra.rule.as_deref(),
                Some("routes")
            );
        }
        f.clean(&r).await;
    }
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn preflight_audit_uses_nulls_and_unhinted_checks_never_have_nonstring_hints() {
    let f = Fixture::new(&["header:x-key"]).await;
    let allowed = f
        .daemon
        .pipeline()
        .preflight(gateway_input(&f, "GET", "/ordinary", "", None, None), true)
        .await
        .unwrap();
    assert_eq!(allowed["would"], "allow");
    let denied = f
        .daemon
        .pipeline()
        .preflight(
            gateway_input(&f, "DELETE", "/ordinary", "", None, None),
            true,
        )
        .await
        .unwrap();
    assert_eq!(denied["would"], "deny");
    let rows = audit_records(&f)
        .await
        .into_iter()
        .filter(|r| r["kind"] == "request.preflighted")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    let flat = serde_json::to_string(&rows).unwrap();
    assert!(flat.contains("\"code\":null") && flat.contains("\"rule\":null"));
    assert!(!flat.contains("DELETE"));
    let mut req = gateway_input(&f, "GET", "/x", "", None, None);
    req.headers.retain(|(k, _)| k != "x-key");
    let unhinted = f.daemon.pipeline().preflight(req, false).await.unwrap();
    assert_eq!(unhinted["would"], "deny");
    for check in unhinted["checks"].as_array().unwrap() {
        assert!(check.get("hint").is_none_or(Value::is_string));
    }
    assert!(f.up.hits.lock().unwrap().is_empty());
}
#[tokio::test]
async fn held_allowed_and_denied_requests_are_recorded_with_the_right_decisions() {
    let f = approval_fixture("on-write", &["header:x-key"]).await;
    let held = f.write("x").await;
    assert_eq!(held.status, 202);
    f.clean(&held).await;
    let allowed = f.get().await;
    assert_eq!(allowed.status, 200);
    f.clean(&allowed).await;
    let denied = f
        .send(
            "DELETE",
            "/ordinary",
            vec![("x-key".into(), f.ph.clone())],
            None,
        )
        .await;
    assert_eq!(denied.status, 403);
    f.clean(&denied).await;
    let rows = audit_records(&f).await;
    let held = rows
        .iter()
        .filter(|r| r["kind"] == "request.allowed" && r["decision"] == "held")
        .collect::<Vec<_>>();
    let allowed = rows
        .iter()
        .filter(|r| r["kind"] == "request.allowed" && r["decision"] == "allow")
        .collect::<Vec<_>>();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["req"]["status"], 202);
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0]["req"]["status"], 200);
    assert_eq!(
        held[0]["request_id"],
        rows.iter()
            .find(|r| r["kind"] == "approval.requested")
            .unwrap()["request_id"]
    );
    assert_eq!(rows.iter().filter(|r| r["decision"] == "deny").count(), 1);
}
#[tokio::test]
async fn quarantine_refuses_without_spending_limits_and_release_restores_ordinary_request() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"rate":{"count":5,"per":"hour"},"quota":{"count":5,"window":"day"}}),
    )
    .await;
    f.shared
        .run(|core| {
            core.vault
                .set_quarantine("demo", Default::default())
                .unwrap()
        })
        .await
        .unwrap();
    let r = f.get().await;
    assert_eq!(r.error.as_ref().unwrap().code.as_str(), "AV_QUARANTINED");
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("quarantine")
    );
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    assert_eq!(
        f.daemon
            .pipeline()
            .limits_for(f.grant_id.clone())
            .await
            .unwrap()["rate"]["tokens_now"],
        5.0
    );
    assert!(f.up.hits.lock().unwrap().is_empty());
    let id = f.grant_id.clone();
    f.shared
        .run(move |core| {
            assert!(core
                .vault
                .grant_runtime(&id)
                .unwrap()
                .is_none_or(|r| r.quota_state.is_none()))
        })
        .await
        .unwrap();
    f.clean(&r).await;
    f.shared
        .run(|core| core.vault.clear_quarantine("demo").unwrap())
        .await
        .unwrap();
    let r = f.get().await;
    assert_eq!(r.status, 200);
    f.clean(&r).await;
}

#[tokio::test]
async fn quota_charges_once_survives_restart_and_rollback_and_refunds_preconnect_failure() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"quota":{"count":1,"window":"hour"}}),
    )
    .await;
    let first = f.get().await;
    assert_eq!(first.status, 200);
    f.clean(&first).await;
    let denied = f.get().await;
    assert_eq!(
        denied.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("quota")
    );
    f.clean(&denied).await;
    let mut reopened = av_store::vault::Vault::open(f._dir.path()).unwrap();
    reopened.unlock(None).unwrap();
    let shared = Shared::new(reopened);
    let fresh = av_daemon::pipeline::Pipeline::new(
        shared,
        PipelineOptions {
            upstream: Some(f.up.clone()),
            ..Default::default()
        },
    );
    let r = fresh
        .handle(gateway_input(&f, "GET", "/ordinary", "", None, None))
        .await;
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("quota")
    );
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&r).await;
    let id = f.grant_id.clone();
    f.shared
        .run(move |core| {
            let mut rt = core.vault.grant_runtime(&id).unwrap().unwrap();
            let q = rt.quota_state.as_mut().unwrap();
            q["start"] = json!(q["start"].as_i64().unwrap() + 3_600_000);
            core.vault.set_grant_runtime(&id, &rt).unwrap();
        })
        .await
        .unwrap();
    let r = f.get().await;
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("quota")
    );
    f.clean(&r).await;
    let retry = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"quota":{"count":1,"window":"hour"}}),
    )
    .await;
    *retry.up.failure.lock().unwrap() = Some(UpstreamError::new("ECONNREFUSED", "test refused"));
    let r = retry.get().await;
    assert_eq!(r.status, 502);
    f.clean(&r).await;
    let id = retry.grant_id.clone();
    retry
        .shared
        .run(move |core| {
            assert_eq!(
                core.vault
                    .grant_runtime(&id)
                    .unwrap()
                    .unwrap()
                    .quota_state
                    .unwrap()["count"],
                0
            )
        })
        .await
        .unwrap();
    assert_eq!(grant_counters(&retry).await, (0, vec![0]));
    *retry.up.failure.lock().unwrap() = None;
    let r = retry.get().await;
    assert_eq!(r.status, 200);
    retry.clean(&r).await;
}
#[tokio::test]
async fn conflicting_single_valued_headers_are_refused_without_spending_or_upstream() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"json":{"/channel":{"one_of":["safe"]}}}}),
    )
    .await;
    let pairs = vec![
        vec![
            ("content-type", "application/json"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        vec![
            ("content-type", "application/json"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        vec![
            ("content-type", "application/json"),
            ("Content-Type", "application/json"),
        ],
        // A JS array-valued field is represented by repeated pairs here.
        vec![
            ("content-type", "application/json"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        vec![
            ("content-type", "application/json"),
            ("content-encoding", "identity"),
            ("Content-Encoding", "gzip"),
        ],
        vec![
            ("content-type", "application/json"),
            ("content-length", "18"),
            ("content-length", "2"),
        ],
        vec![
            ("content-type", "application/json"),
            ("transfer-encoding", "chunked"),
            ("Transfer-Encoding", "identity"),
        ],
    ];
    for extra in pairs {
        let mut req = gateway_input(
            &f,
            "POST",
            "/ordinary",
            "",
            None,
            Some(b"{\"channel\":\"safe\"}".to_vec()),
        );
        req.headers
            .extend(extra.into_iter().map(|(k, v)| (k.into(), v.into())));
        let r = f.daemon.pipeline().handle(req).await;
        assert_eq!(r.status, 403);
        assert_eq!(
            r.error.as_ref().unwrap().extra.rule.as_deref(),
            Some("header_duplicate")
        );
        f.clean(&r).await;
    }
    let req = GatewayRequest {
        method: "GET".into(),
        path: "/p/demo/ordinary".into(),
        headers: vec![
            ("host".into(), "localhost".into()),
            ("authorization".into(), format!("Bearer {}", f.token)),
            ("Authorization".into(), format!("Bearer {}", f.ph)),
        ],
        ..Default::default()
    };
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("header_duplicate")
    );
    f.clean(&r).await;
    let mut req = gateway_input(
        &f,
        "POST",
        "/ordinary",
        "",
        Some("application/json"),
        Some(b"{\"channel\":\"safe\"}".to_vec()),
    );
    req.headers
        .push(("Content-Type".into(), "text/plain".into()));
    let before = grant_counters(&f).await;
    let e = f.daemon.pipeline().preflight(req, true).await.unwrap_err();
    assert_eq!(e.extra.rule.as_deref(), Some("header_duplicate"));
    assert_eq!(grant_counters(&f).await, before);
    assert!(f.up.hits.lock().unwrap().is_empty());
    assert_eq!(before, (0, vec![0]));
    let ordinary = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/ordinary",
            "",
            Some("application/json"),
            Some(b"{\"channel\":\"safe\"}".to_vec()),
        ))
        .await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
}
#[tokio::test]
async fn exact_repeat_content_type_is_sent_once_and_the_selected_form_rules_apply() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"json":{"/channel":{"one_of":["safe"]}}}}),
    )
    .await;
    for repeat in [false, true] {
        let mut req = gateway_input(
            &f,
            "POST",
            "/ordinary",
            "",
            Some("application/json"),
            Some(b"{\"channel\":\"safe\"}".to_vec()),
        );
        if repeat {
            req.headers
                .push(("content-type".into(), "application/json".into()));
        }
        let r = f.daemon.pipeline().handle(req).await;
        assert_eq!(r.status, 200);
        assert_eq!(
            f.last()
                .headers
                .into_iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .collect::<Vec<_>>(),
            vec![("content-type".into(), "application/json".into())]
        );
        f.clean(&r).await;
    }
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"form":{"channel":{"one_of":["safe"]}}}}),
    )
    .await;
    let mut req = gateway_input(
        &f,
        "POST",
        "/ordinary",
        "",
        None,
        Some(b"channel=safe".to_vec()),
    );
    req.headers.push((
        "Content-Type".into(),
        "application/x-www-form-urlencoded".into(),
    ));
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    assert!(f
        .last()
        .headers
        .iter()
        .any(|(k, v)| k == "Content-Type" && v == "application/x-www-form-urlencoded"));
    f.clean(&r).await;
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/ordinary",
            "",
            Some("application/x-www-form-urlencoded"),
            Some(b"channel=other".to_vec()),
        ))
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&r).await;
}
#[tokio::test]
async fn repeated_list_headers_preserve_every_value_and_substitute_only_the_targeted_copy() {
    let f = Fixture::new(&["header:x-key", "header:x-api-key"]).await;
    let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
    req.headers.extend([
        ("X-Trace".into(), "checked".into()),
        ("x-trace".into(), "other".into()),
        ("accept".into(), "a/b".into()),
    ]);
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    let sent = f.last();
    let trace = sent
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("x-trace"))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        trace,
        vec![
            ("X-Trace".into(), "checked".into()),
            ("X-Trace".into(), "other".into())
        ]
    );
    assert!(sent
        .headers
        .iter()
        .any(|(k, v)| k == "accept" && v == "a/b"));
    f.clean(&r).await;
    let ph = f.mint(Some(5)).await;
    let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
    req.headers.extend([
        ("x-api-key".into(), "not-a-secret".into()),
        ("X-Api-Key".into(), ph.clone()),
    ]);
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    let sent = f.last();
    assert_eq!(
        sent.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-api-key"))
            .cloned()
            .collect::<Vec<_>>(),
        vec![
            ("x-api-key".into(), "not-a-secret".into()),
            ("x-api-key".into(), SECRET.into())
        ]
    );
    assert!(!serde_json::to_string(&sent.headers).unwrap().contains(&ph));
    f.clean(&r).await;
}
#[tokio::test]
async fn query_url_rewrite_shapes_are_refused_and_encoded_value_controls_pass() {
    let f=Fixture::configured(&["header:x-key"],SECRET,None,json!({"payload":{"query":{"dry_run":{"required":true},"force":{"absent":true},"op":{}},"query_strict":true}})).await;
    for query in [
        "op=delete#&dry_run=true",
        "dry_run=true&fo\nrce=true",
        "dry_run=true&fo\trce=true",
        "dry_run=true&fo\rrce=true",
        "dry_run=true&op=x ",
    ] {
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(&f, "GET", "/ordinary", query, None, None))
            .await;
        assert_eq!(r.status, 403);
        assert_eq!(
            r.error.as_ref().unwrap().extra.rule.as_deref(),
            Some("query_unsendable")
        );
        f.clean(&r).await;
    }
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    assert!(f.up.hits.lock().unwrap().is_empty());
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "GET",
            "/ordinary",
            "dry_run=true&op=a%23b%0A%20",
            None,
            None,
        ))
        .await;
    assert_eq!(r.status, 200);
    assert!(f.last().url.ends_with("?dry_run=true&op=a%23b%0A%20"));
    f.clean(&r).await;
}

#[tokio::test]
async fn deny_approvals_filters_by_session_or_grant_records_reason_and_skips_consumed_requests() {
    use av_daemon::pipeline::ApprovalFilter;
    let f = approval_fixture("each", &["header:x-key"]).await;
    let mut ids = Vec::new();
    for path in ["/a", "/b"] {
        ids.push(held_id(
            &f.send("GET", path, vec![("x-key".into(), f.ph.clone())], None)
                .await,
        ));
    }
    for filter in [
        ApprovalFilter {
            session_id: Some("ses_other".into()),
            ..Default::default()
        },
        ApprovalFilter {
            grant_ids: Some(vec!["grt_other".into()]),
            ..Default::default()
        },
    ] {
        assert_eq!(
            f.daemon
                .pipeline()
                .deny_approvals(filter, "tripwire".into())
                .await
                .unwrap(),
            0
        );
    }
    assert_eq!(f.daemon.pipeline().pending_approvals().await.len(), 2);
    assert_eq!(
        f.daemon
            .pipeline()
            .deny_approvals(
                ApprovalFilter {
                    grant_ids: Some(vec![f.grant_id.clone()]),
                    ..Default::default()
                },
                "credential_rotated".into()
            )
            .await
            .unwrap(),
        2
    );
    for id in ids {
        f.shared
            .run(move |core| {
                let approval = core.pl.approvals.iter().find(|(_, a)| a.id == id).unwrap();
                assert_eq!(approval.1.state, "denied");
                assert_eq!(
                    approval.1.denied_reason.as_deref(),
                    Some("credential_rotated")
                );
            })
            .await
            .unwrap();
    }
    let reasons = audit_records(&f)
        .await
        .into_iter()
        .filter(|r| r["kind"] == "approval.denied")
        .map(|r| r["reason"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec![json!("credential_rotated"), json!("credential_rotated")]
    );
    assert!(f.up.hits.lock().unwrap().is_empty());
    let g = approval_fixture("each", &["header:x-key"]).await;
    let id = held_id(&g.get().await);
    g.daemon.pipeline().decide_approval(id, true).await.unwrap();
    let r = g.get().await;
    assert_eq!(r.status, 200);
    g.clean(&r).await;
    assert_eq!(
        g.daemon
            .pipeline()
            .deny_all_pending("panic".into())
            .await
            .unwrap(),
        0
    );
}
#[tokio::test]
async fn quarantine_and_grant_expiry_stop_before_consume_and_bulk_deny_returns_count() {
    use av_daemon::pipeline::ApprovalFilter;
    let f = approval_fixture("each", &["header:x-key"]).await;
    assert_eq!(f.get().await.status, 202);
    let token = f.token.clone();
    let sid = f
        .shared
        .run(move |core| core.vault.session_by_token(&token).unwrap().unwrap().id)
        .await
        .unwrap();
    assert_eq!(
        f.daemon
            .pipeline()
            .deny_approvals(
                ApprovalFilter {
                    session_id: Some(sid),
                    ..Default::default()
                },
                "panic".into()
            )
            .await
            .unwrap(),
        1
    );
    assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
    f.shared
        .run(|core| {
            core.vault
                .set_quarantine("demo", Default::default())
                .unwrap()
        })
        .await
        .unwrap();
    for target in ["/p/demo/ordinary", "/t/https/api.example.test/ordinary"] {
        let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
        req.path = target.into();
        let r = f.daemon.pipeline().handle(req).await;
        assert_eq!(r.error.as_ref().unwrap().code.as_str(), "AV_QUARANTINED");
        f.clean(&r).await;
    }
    f.shared
        .run(|core| core.vault.clear_quarantine("demo").unwrap())
        .await
        .unwrap();
    let id = f.grant_id.clone();
    f.shared
        .run(move |core| core.vault.shorten_grant(&id, 1).unwrap())
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let r = f.get().await;
    assert_eq!(r.error.as_ref().unwrap().code.as_str(), "AV_GRANT_EXPIRED");
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    assert!(f.up.hits.lock().unwrap().is_empty());
    f.clean(&r).await;
}
async fn store_snapshot(f: &Fixture) -> Value {
    f.shared.run(|core|json!({"credentials":core.vault.credential_records().unwrap(),"sessions":core.vault.sessions().unwrap(),"grants":core.vault.grants().unwrap(),"placeholders":core.vault.list_placeholders(None).unwrap(),"runtime":core.vault.grants().unwrap().into_iter().map(|g|core.vault.grant_runtime(&g.id).unwrap()).collect::<Vec<_>>()})).await.unwrap()
}
#[tokio::test]
async fn preflight_observes_limits_without_mutating_vault_or_creating_approval() {
    let f=Fixture::configured(&["header:x-key"],SECRET,None,json!({"approval":"each","rate":{"count":2,"per":"hour"},"quota":{"count":2,"window":"hour"}})).await;
    let before = store_snapshot(&f).await;
    let result = f
        .daemon
        .pipeline()
        .preflight(gateway_input(&f, "GET", "/ordinary", "", None, None), true)
        .await
        .unwrap();
    assert_eq!(result["would"], "hold");
    assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
    assert_eq!(store_snapshot(&f).await, before);
    assert!(f.up.hits.lock().unwrap().is_empty());
    assert_eq!(
        f.daemon
            .pipeline()
            .limits_for(f.grant_id.clone())
            .await
            .unwrap()["rate"]["tokens_now"],
        2.0
    );
    let mut request = gateway_input(&f, "GET", "/ordinary", "", None, None);
    request.headers = vec![("av-session".into(), f.token.clone())];
    assert_eq!(
        f.daemon.pipeline().preflight(request, true).await.unwrap()["would"],
        "hold"
    );
    assert_eq!(store_snapshot(&f).await, before);
    let id = f.grant_id.clone();
    f.shared
        .run(move |core| {
            core.vault
                .narrow_grant(&id, &json!({"methods":["HEAD"]}))
                .unwrap()
        })
        .await
        .unwrap();
    let r = f.get().await;
    assert_eq!(r.status, 403);
    f.clean(&r).await;
}

// Model spend is reserved before an upstream byte and settled after usage.
fn model_body() -> Vec<u8> {
    serde_json::to_vec(&json!({"model":"gpt-4.1-mini","max_tokens":30,"messages":[{"role":"user","content":"hi"}]})).unwrap()
}
fn model_request(f: &Fixture, body: Vec<u8>) -> GatewayRequest {
    gateway_input(
        f,
        "POST",
        "/v1/chat/completions",
        "",
        Some("application/json"),
        Some(body),
    )
}
fn model_reservation() -> u64 {
    use av_core::model_usage::*;
    let body = model_body();
    let m = meter_request(
        "openai",
        &MeterInput {
            method: Some("POST"),
            path: Some("/v1/chat/completions"),
            content_type: Some("application/json"),
            body: Some(&body),
        },
    )
    .unwrap();
    reservation_for("openai", &m, Default::default())
        .unwrap()
        .tokens
}
async fn model_fixture(policy: Value) -> Fixture {
    Fixture::configured_kind(
        &["header:x-key"],
        SECRET,
        None,
        policy,
        "openai",
        "api.openai.com",
    )
    .await
}
async fn spend_state(f: &Fixture) -> Value {
    let id = f.grant_id.clone();
    f.shared
        .run(move |core| {
            core.vault
                .grant_runtime(&id)
                .unwrap()
                .and_then(|r| r.spend)
                .unwrap_or(Value::Null)
        })
        .await
        .unwrap()
}
async fn wait_settled(f: &Fixture) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let state = spend_state(f).await;
            if state["reserved"] == json!({}) {
                return state;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("spend never settled")
}
#[tokio::test]
async fn token_reservations_refuse_concurrent_overspend_and_settle_buffered_usage() {
    let reserve = model_reservation();
    let f = model_fixture(json!({"spend":{"tokens":reserve+1}})).await;
    f.reply(200,"application/json",json!({"usage":{"prompt_tokens":5,"completion_tokens":7},"ordinary":"ordinary-traffic-control"}).to_string());
    let release = Arc::new(tokio::sync::Notify::new());
    *f.up.gate.lock().unwrap() = Some(release.clone());
    let running = f.daemon.pipeline().handle(model_request(&f, model_body()));
    tokio::pin!(running);
    tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::select!{_=&mut running=>panic!("upstream did not wait"),_=async{loop{if !f.up.hits.lock().unwrap().is_empty(){break;}tokio::task::yield_now().await;}}=>{}}}).await.unwrap();
    assert_eq!(
        f.daemon
            .pipeline()
            .spend_for(f.grant_id.clone())
            .await
            .unwrap()
            .unwrap()["reserved_tokens"],
        reserve
    );
    let denied = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        f.daemon.pipeline().handle(model_request(&f, model_body())),
    )
    .await
    .expect("second call reached gated upstream");
    assert_eq!(
        denied.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("spend")
    );
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&denied).await;
    release.notify_one();
    let r = running.await;
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("ordinary-traffic-control"));
    f.clean(&r).await;
    let state = wait_settled(&f).await;
    assert_eq!(state["tokens_used"], 12);
    assert_eq!(
        f.daemon
            .pipeline()
            .spend_for(f.grant_id.clone())
            .await
            .unwrap()
            .unwrap()["reserved_tokens"],
        0
    );
}
#[tokio::test]
async fn unpriced_and_unmodeled_spend_refuse_while_free_get_uses_no_spend_ledger() {
    let f = model_fixture(json!({"spend":{"tokens":100000,"usd_micros":100000}})).await;
    let req = model_request(&f, b"{\"model\":\"unknown\",\"max_tokens\":1}".to_vec());
    let r = f.daemon.pipeline().handle(req.clone()).await;
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("spend_unpriced")
    );
    f.clean(&r).await;
    let mut unmodeled = req;
    unmodeled.path = "/p/demo/v1/unknown".into();
    let r = f.daemon.pipeline().handle(unmodeled).await;
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("spend_unmodeled")
    );
    f.clean(&r).await;
    assert!(f.up.hits.lock().unwrap().is_empty());
    let r = f.get().await;
    assert_eq!(r.status, 200);
    assert_eq!(spend_state(&f).await, Value::Null);
    f.clean(&r).await;
}
#[tokio::test]
async fn missing_or_cut_usage_charges_full_reservation_and_complete_crlf_streams_charge_actual_usage(
) {
    for mode in ["buffer", "abort", "complete", "crlf", "cut"] {
        let f = model_fixture(json!({"spend":{"tokens":10000}})).await;
        let reserve = model_reservation();
        let mut writer = None;
        if mode != "buffer" {
            stream_reply(&f, "", false);
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            *f.up.source.lock().unwrap() = Some(Body::Stream(rx));
            writer = Some(tx);
        }
        let r = f
            .daemon
            .pipeline()
            .handle(model_request(&f, model_body()))
            .await;
        assert_eq!(r.status, 200);
        if mode == "abort" {
            drop(r);
            drop(writer);
        } else if let Some(tx) = writer {
            let events=match mode {"cut"=>format!("data: {{\"delta\":\"{}\"}}\n\ndata: {{\"delta\":\"{}\"}}\n\ndata: {{\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":4}}}}\n\n",&SECRET[..15],&SECRET[15..]),"crlf"=>"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\r\n\r\n".into(),_=>"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n".into()};
            tx.send(Ok(events.into_bytes())).await.unwrap();
            drop(tx);
            let r = drain(r).await;
            if mode == "cut" {
                assert!(String::from_utf8_lossy(&r.body).contains("AV_UNSCANNABLE"));
            }
            f.clean(&r).await;
        } else {
            assert_eq!(r.body, b"ordinary-traffic-control");
            f.clean(&r).await;
        }
        let state = wait_settled(&f).await;
        assert_eq!(
            state["tokens_used"],
            if ["complete", "crlf"].contains(&mode) {
                7
            } else {
                reserve
            },
            "{mode}"
        );
        if mode != "buffer" {
            assert_eq!(
                audit_records(&f)
                    .await
                    .into_iter()
                    .filter(|r| r["kind"] == "spend.settled")
                    .count(),
                1,
                "{mode}"
            );
        }
    }
}
#[tokio::test]
async fn preconnect_spend_is_refunded_and_restart_charges_outstanding_reservations() {
    let f = model_fixture(json!({"spend":{"tokens":10000}})).await;
    *f.up.failure.lock().unwrap() = Some(UpstreamError::new("ENOTFOUND", "test missing host"));
    let r = f
        .daemon
        .pipeline()
        .handle(model_request(&f, model_body()))
        .await;
    assert_eq!(r.status, 502);
    f.clean(&r).await;
    let state = wait_settled(&f).await;
    assert_eq!(state["tokens_used"], 0);
    let id = f.grant_id.clone();
    f.shared
        .run(move |core| {
            let mut rt = core.vault.grant_runtime(&id).unwrap().unwrap();
            rt.spend.as_mut().unwrap()["reserved"]["rq_stale"] =
                json!({"tokens":50,"usd_micros":6,"at":av_daemon::util::now_ms()});
            core.vault.set_grant_runtime(&id, &rt).unwrap();
        })
        .await
        .unwrap();
    let _fresh = av_daemon::pipeline::Pipeline::new(f.shared.clone(), PipelineOptions::default());
    let state = spend_state(&f).await;
    assert_eq!(state["tokens_used"], 50);
    assert_eq!(state["usd_micros_used"], 6);
    assert_eq!(state["reserved"], json!({}));
    *f.up.failure.lock().unwrap() = None;
    let r = f.get().await;
    assert_eq!(r.status, 200);
    f.clean(&r).await;
}
#[tokio::test]
async fn locked_pipeline_recovers_stale_reservation_on_first_request_after_unlock() {
    let f = model_fixture(json!({"spend":{"tokens":100000}})).await;
    let id = f.grant_id.clone();
    f.shared.run(move |core|core.vault.set_grant_runtime(&id,&av_store::model::GrantRuntime{quota_state:None,spend:Some(json!({"tokens_used":0,"usd_micros_used":0,"reserved":{"rq_stale":{"tokens":40,"usd_micros":0,"at":av_daemon::util::now_ms()}}}))}).unwrap()).await.unwrap();
    let reopened = av_store::vault::Vault::open(f._dir.path()).unwrap();
    assert!(reopened.locked());
    let shared = Shared::new(reopened);
    let pipeline = av_daemon::pipeline::Pipeline::new(
        shared.clone(),
        PipelineOptions {
            upstream: Some(f.up.clone()),
            ..Default::default()
        },
    );
    let id = f.grant_id.clone();
    shared
        .run(move |core| {
            core.vault.unlock(None).unwrap();
            assert_eq!(
                core.vault
                    .grant_runtime(&id)
                    .unwrap()
                    .unwrap()
                    .spend
                    .unwrap()["reserved"]
                    .as_object()
                    .unwrap()
                    .len(),
                1
            );
        })
        .await
        .unwrap();
    let r = pipeline
        .handle(gateway_input(&f, "GET", "/ordinary", "", None, None))
        .await;
    assert_eq!(r.status, 200);
    f.clean(&r).await;
    let state = spend_state(&f).await;
    assert_eq!(state["tokens_used"], 40);
    assert_eq!(state["reserved"], json!({}));
    assert_eq!(
        audit_records(&f)
            .await
            .into_iter()
            .filter(|r| r["kind"] == "spend.reservation_charged")
            .count(),
        1
    );
}

#[tokio::test]
async fn spend_denial_explains_remaining_and_worst_case_while_bounded_call_settles_real_usage() {
    let f = model_fixture(json!({"spend":{"tokens":1000}})).await;
    let r = f
        .daemon
        .pipeline()
        .handle(model_request(
            &f,
            b"{\"model\":\"gpt-4.1-mini\",\"messages\":[]}".to_vec(),
        ))
        .await;
    let e = r.error.as_ref().unwrap();
    assert_eq!(e.extra.rule.as_deref(), Some("spend"));
    let problem = e.to_problem();
    assert!(av_core::jsre::compile(
        r"may spend 1000 more tokens; this call could cost up to 16\d{3} tokens"
    )
    .unwrap()
    .is_match(problem["hint"].as_str().unwrap()));
    assert!(f.up.hits.lock().unwrap().is_empty());
    f.clean(&r).await;
    f.reply(
        200,
        "application/json",
        json!({"usage":{"prompt_tokens":5,"completion_tokens":7}}).to_string(),
    );
    let r = f
        .daemon
        .pipeline()
        .handle(model_request(
            &f,
            b"{\"model\":\"gpt-4.1-mini\",\"max_tokens\":50,\"messages\":[]}".to_vec(),
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(wait_settled(&f).await["tokens_used"], 12);
    f.clean(&r).await;
}
#[tokio::test]
async fn approval_preview_hides_secrets_and_placeholders_and_notifies_exactly_once() {
    let f = approval_fixture("each", &["header:authorization:Bearer"]).await;
    let mut notices = f
        .shared
        .run(|core| core.notifier.as_ref().unwrap().subscribe(vec![]).unwrap())
        .await
        .unwrap();
    assert!(notices.recv().await.unwrap().starts_with("event: snapshot"));
    for _ in 0..2 {
        let r = f
            .send(
                "POST",
                "/ordinary",
                vec![
                    ("authorization".into(), format!("Bearer {}", f.ph)),
                    ("content-type".into(), "application/json".into()),
                ],
                Some(json!({"comment":format!("hello {SECRET}")}).to_string()),
            )
            .await;
        assert_eq!(r.status, 202);
        f.clean(&r).await;
    }
    let pending = f.daemon.pipeline().pending_approvals().await;
    assert_eq!(pending.len(), 1);
    let approval = &pending[0];
    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), notices.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(payloads(&frame).next().unwrap()["id"], approval["id"]);
    assert!(notices.try_recv().is_err());
    let preview = &approval["preview"];
    assert!(preview["body"]["text"].as_str().unwrap().contains("hello"));
    let all = serde_json::to_string(preview).unwrap();
    assert!(!all.contains(SECRET) && !all.contains(&f.ph));
    assert!(!preview["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h[0] == "authorization"));
    assert!(all.len() <= 8192);
    assert!(f
        .daemon
        .pipeline()
        .approval_status(approval["id"].as_str().unwrap().into())
        .await
        .unwrap()
        .get("preview")
        .is_none());
    assert!(f.up.hits.lock().unwrap().is_empty());
}
#[tokio::test]
async fn held_preview_labels_injection_redacts_secret_and_token_and_keeps_comment_out_of_audit() {
    let f = approval_fixture("each", &["header:authorization:Bearer", "json:/auth"]).await;
    let r = f
        .send(
            "POST",
            "/ordinary",
            vec![
                ("authorization".into(), format!("Bearer {}", f.ph)),
                ("content-type".into(), "application/json".into()),
                ("x-trace".into(), "ordinary-header".into()),
            ],
            Some(
                json!({"auth":f.ph,"text":format!("private comment {SECRET} {}",f.token)})
                    .to_string(),
            ),
        )
        .await;
    assert_eq!(r.status, 202);
    f.clean(&r).await;
    let pending = f.daemon.pipeline().pending_approvals().await;
    let preview = &pending[0]["preview"];
    let text = preview["body"]["text"].as_str().unwrap();
    assert!(text.contains("«demo.token @ JSON body at /auth»"));
    assert!(text.contains("[[av:redacted:demo]]"));
    assert!(text.contains("«session token»"));
    assert!(text.contains("private comment"));
    assert!(preview["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h == &json!(["x-trace", "ordinary-header"])));
    assert!(!preview["headers"].as_array().unwrap().iter().any(|h| h[0]
        .as_str()
        .is_some_and(|n| n == "authorization" || n.starts_with("av-"))));
    let all = serde_json::to_string(preview).unwrap();
    for value in [&f.ph, &f.token, &SECRET.to_string()] {
        assert!(!all.contains(value));
    }
    assert!(!serde_json::to_string(&audit_records(&f).await)
        .unwrap()
        .contains("private comment"));
    assert!(f
        .daemon
        .pipeline()
        .approval_status(pending[0]["id"].as_str().unwrap().into())
        .await
        .unwrap()
        .get("preview")
        .is_none());
}
#[tokio::test]
async fn preview_builder_replaces_encoded_placeholders_preserves_duplicate_json_and_caps_size() {
    use av_daemon::preview::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    let f = approval_fixture("each", &["header:authorization:Bearer"]).await;
    let encoded = av_daemon::util::encode_uri_component(&f.ph).replace('.', "%2E");
    let b64 = STANDARD.encode(&f.ph);
    let headers = vec![
        ("content-type".into(), "application/json".into()),
        ("authorization".into(), format!("Bearer {}", f.ph)),
        ("x-carrier".into(), format!("Bearer {}", f.ph)),
    ];
    let subs = vec![PreviewSub {
        text: f.ph.clone(),
        label: "demo.key".into(),
        location: "header authorization".into(),
        part: "headers",
    }];
    let build = |body: &str, query: &str| {
        approval_preview(
            &PreviewRequest {
                query,
                headers: &headers,
                body: Some(body.as_bytes()),
            },
            &PreviewDecision {
                method: "POST",
                host: "api.example.test",
                path: "/x",
            },
            &subs,
            &mut |s| s.replace(SECRET, "[[av:redacted:demo]]"),
        )
    };
    let preview = build(
        &json!({"a":encoded,"b":b64,"c":SECRET}).to_string(),
        &format!("q={encoded}"),
    );
    let all = serde_json::to_string(&preview).unwrap();
    assert!(preview["body"]["text"]
        .as_str()
        .unwrap()
        .contains("«placeholder»"));
    for value in [&f.ph, &encoded, &b64, &SECRET.to_string()] {
        assert!(!all.contains(value));
    }
    assert!(preview["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h == &json!(["x-carrier", "Bearer «demo.key @ header authorization»"])));
    assert_eq!(
        preview["query"],
        json!([["q", "«demo.key @ header authorization»"]])
    );
    let dup = build(
        "{\"channel\":\"general\",\"channel\":\"secret-ops\"}",
        &format!("q={encoded}"),
    );
    let text = dup["body"]["text"].as_str().unwrap();
    assert!(text.contains("general") && text.contains("secret-ops"));
    let big = build(
        &json!({"x":"y".repeat(50000)}).to_string(),
        &format!("q={}", "z".repeat(20000)),
    );
    assert!(serde_json::to_vec(&big).unwrap().len() <= 8192);
    assert_eq!(big["body"]["truncated"], true);
}

fn redirect_reply(status: u16, location: &str) -> Reply {
    Reply {
        streaming: false,
        status,
        headers: vec![
            ("location".into(), location.into()),
            ("content-type".into(), "text/plain".into()),
        ],
        body: b"redirect".to_vec(),
    }
}
fn done_reply() -> Reply {
    Reply {
        streaming: false,
        status: 200,
        headers: vec![("content-type".into(), "text/plain".into())],
        body: b"done".to_vec(),
    }
}
async fn hop_fixture(policy: Value, location: &str, status: u16) -> Fixture {
    let mut spec = json!({"methods":["GET","HEAD","POST","DELETE"],"redirects":{"max":2}});
    for (k, v) in policy.as_object().unwrap() {
        spec[k] = v.clone();
    }
    let f = Fixture::configured(&["header:authorization:Bearer"], SECRET, None, spec).await;
    f.up.sequence
        .lock()
        .unwrap()
        .extend([Ok(redirect_reply(status, location)), Ok(done_reply())]);
    f
}
fn hop_request(f: &Fixture, method: &str, path: &str) -> GatewayRequest {
    let mut req = gateway_input(f, method, path, "", None, None);
    req.headers.retain(|(k, _)| k != "x-key");
    req.headers
        .push(("authorization".into(), format!("Bearer {}", f.ph)));
    req
}
#[tokio::test]
async fn redirect_port_must_match_and_failed_hop_is_not_refunded() {
    for (location, stopped, hits) in [
        ("https://api.example.test:8443/ordinary", Some("host"), 1),
        ("https://api.example.test/next", None, 2),
    ] {
        let f = hop_fixture(json!({}), location, 302).await;
        let r = f
            .daemon
            .pipeline()
            .handle(hop_request(&f, "GET", "/ordinary"))
            .await;
        assert_eq!(r.header("av-redirect-stopped"), stopped);
        assert_eq!(f.up.hits.lock().unwrap().len(), hits);
        f.clean(&r).await;
    }
    let f = hop_fixture(json!({}), "/next", 302).await;
    let closed = Arc::new(tokio::sync::Notify::new());
    // A streamed redirect body is dropped before the next connection starts.
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    *f.up.source.lock().unwrap() = Some(Body::Stream(rx));
    let observed = closed.clone();
    let watcher = tokio::spawn(async move {
        tx.closed().await;
        observed.notify_one();
    });
    f.up.sequence.lock().unwrap().pop_back();
    f.up.sequence
        .lock()
        .unwrap()
        .push_back(Err(UpstreamError::new("ECONNRESET", "test reset")));
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(
        r.error.as_ref().unwrap().code.as_str(),
        "AV_UPSTREAM_UNREACHABLE"
    );
    assert_eq!(r.error.as_ref().unwrap().extra.refunded, Some(false));
    tokio::time::timeout(std::time::Duration::from_secs(2), closed.notified())
        .await
        .expect("redirect source was not closed");
    watcher.await.unwrap();
    assert_eq!(grant_counters(&f).await.1, vec![1]);
    f.clean(&r).await;
}
#[tokio::test]
async fn allowed_redirect_charges_each_hop_preserves_pins_and_never_forwards_body() {
    let f = hop_fixture(json!({}), "/ordinary", 302).await;
    let pin = format!("sha256/{}=", "A".repeat(43));
    let expected = pin.clone();
    f.shared
        .run(move |core| {
            core.vault
                .set_pins("demo", "api.example.test", &[pin])
                .unwrap()
        })
        .await
        .unwrap();
    *f.up.sequence.lock().unwrap() = std::collections::VecDeque::from([
        Ok(redirect_reply(302, "/ordinary")),
        Ok(redirect_reply(302, "/ordinary")),
        Ok(done_reply()),
    ]);
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.body, b"done");
    assert_eq!(f.up.hits.lock().unwrap().len(), 3);
    assert_eq!(grant_counters(&f).await.0, 3);
    let sent = f.up.hits.lock().unwrap().clone();
    for hop in &sent[1..] {
        assert_eq!(hop.body, None);
        assert_eq!(
            hop.pins,
            av_daemon::upstream::Pins::List(vec![json!(expected)])
        );
    }
    f.clean(&r).await;
    f.up.hits.lock().unwrap().clear();
    *f.up.reply.lock().unwrap() = Some(redirect_reply(302, "/ordinary"));
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.header("av-redirect-stopped"), Some("max"));
    f.clean(&r).await;
}
#[tokio::test]
async fn graphql_and_required_body_rules_are_applied_to_bodyless_redirect_hops() {
    let graphql = json!({"operations":["query"],"deny_fields":["createDeployKey"]});
    for document in [
        "mutation { createDeployKey(input:{title:\"x\"}) { id } }",
        "mutation { innocent: createDeployKey(input:{title:\"x\"}) { id } }",
        "query A { viewer { id } } mutation B { createDeployKey(input:{title:\"x\"}) { id } }",
    ] {
        let f = hop_fixture(
            json!({"payload":{"graphql":graphql}}),
            &format!(
                "https://api.example.test/graphql?query={}",
                av_daemon::util::encode_uri_component(document)
            ),
            302,
        )
        .await;
        let r = f
            .daemon
            .pipeline()
            .handle(hop_request(&f, "GET", "/ordinary"))
            .await;
        assert_eq!(r.status, 302);
        assert_eq!(r.header("av-redirect-stopped"), Some("path"));
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        assert_eq!(grant_counters(&f).await.0, 1);
        f.clean(&r).await;
    }
    let f = hop_fixture(
        json!({"payload":{"graphql":{"operations":["query"]}}}),
        &format!(
            "/graphql?query={}",
            av_daemon::util::encode_uri_component("mutation { a }")
        ),
        302,
    )
    .await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.header("av-redirect-stopped"), Some("path"));
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&r).await;
    let f = hop_fixture(
        json!({"payload":{"graphql":graphql}}),
        &format!(
            "/graphql?query={}",
            av_daemon::util::encode_uri_component("{ viewer { id } }")
        ),
        302,
    )
    .await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"done");
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    f.clean(&r).await;
    let f = hop_fixture(
        json!({"payload":{"json":{"/confirm":{"required":true}}}}),
        "/next",
        302,
    )
    .await;
    let mut req = hop_request(&f, "GET", "/ordinary");
    req.headers
        .push(("content-type".into(), "application/json".into()));
    req.body = Some(b"{\"confirm\":true}".to_vec());
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.header("av-redirect-stopped"), Some("path"));
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&r).await;
    let f = hop_fixture(
        json!({"payload":{"json":{"/force":{"absent":true}},"form":{"mode":{"one_of":["safe"]}}}}),
        "/next",
        302,
    )
    .await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    f.clean(&r).await;
}
#[tokio::test]
async fn location_method_override_fields_are_not_followed() {
    for location in [
        "/next?_method=DELETE",
        "/next?a=1&%5Fmethod=delete",
        "/next?_METHOD=PUT",
    ] {
        let f = hop_fixture(json!({}), location, 302).await;
        let r = f
            .daemon
            .pipeline()
            .handle(hop_request(&f, "GET", "/ordinary"))
            .await;
        assert_eq!(r.status, 302);
        assert_eq!(r.header("av-redirect-stopped"), Some("path"));
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        f.clean(&r).await;
    }
    let f = hop_fixture(json!({}), "/next?q=ordinary", 302).await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"done");
    f.clean(&r).await;
}
#[tokio::test]
async fn redirect_method_is_checked_and_post_is_never_followed_under_any_status() {
    for status in [303, 307, 308] {
        let f = hop_fixture(
            json!({"routes":[{"methods":["POST","GET"],"paths":["/**"]}]}),
            "/next",
            status,
        )
        .await;
        let mut req = hop_request(&f, "POST", "/ordinary");
        req.body = Some(b"{}".to_vec());
        req.headers
            .push(("content-type".into(), "application/json".into()));
        let r = f.daemon.pipeline().handle(req).await;
        assert_eq!(r.status, status);
        assert_eq!(r.header("av-redirect-stopped"), Some("approval"));
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        f.clean(&r).await;
    }
    for status in [302, 303, 307, 308] {
        let f = hop_fixture(json!({}), "/next", status).await;
        let r = f
            .daemon
            .pipeline()
            .handle(hop_request(&f, "HEAD", "/ordinary"))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(f.last().method, "HEAD");
        f.clean(&r).await;
        let f=hop_fixture(json!({"routes":[{"methods":["HEAD"],"paths":["/ordinary"]},{"methods":["GET"],"paths":["/next"]}]}),"/next",status).await;
        let r = f
            .daemon
            .pipeline()
            .handle(hop_request(&f, "HEAD", "/ordinary"))
            .await;
        assert_eq!(r.header("av-redirect-stopped"), Some("path"));
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        f.clean(&r).await;
    }
    for status in [301, 302, 303, 307, 308] {
        let f = hop_fixture(json!({}), "/next", status).await;
        let r = f
            .daemon
            .pipeline()
            .handle(hop_request(&f, "GET", "/ordinary"))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(f.last().method, "GET");
        f.clean(&r).await;
    }
}

fn route_pairs() -> Value {
    json!([{"methods":["GET","DELETE"],"paths":["/public/**"]},{"methods":["GET"],"paths":["/admin/**"]}])
}
fn header_names(req: &UpstreamRequest) -> Vec<String> {
    let mut names = req
        .headers
        .iter()
        .map(|(n, _)| n.to_lowercase())
        .collect::<Vec<_>>();
    names.sort();
    names
}
#[tokio::test]
async fn method_override_writes_never_follow_redirect_even_after_human_approval() {
    for name in [
        "X-HTTP-Method-Override",
        "x-http-method",
        "X-Method-Override",
    ] {
        let f = hop_fixture(
            json!({"routes":route_pairs()}),
            "https://api.example.test/admin/keys",
            302,
        )
        .await;
        let mut req = hop_request(&f, "GET", "/public/start");
        req.headers.push((name.into(), "DELETE".into()));
        let r = f.daemon.pipeline().handle(req).await;
        assert_eq!(r.status, 302);
        assert_eq!(r.header("av-redirect-stopped"), Some("approval"));
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        assert_eq!(grant_counters(&f).await.0, 1);
        f.clean(&r).await;
    }
    let f = hop_fixture(
        json!({"methods":["GET","DELETE"],"approval":"on-write"}),
        "/other",
        302,
    )
    .await;
    let mut req = hop_request(&f, "GET", "/ordinary");
    req.headers
        .push(("X-HTTP-Method-Override".into(), "DELETE".into()));
    let id = held_id(&f.daemon.pipeline().handle(req.clone()).await);
    f.daemon.pipeline().decide_approval(id, true).await.unwrap();
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.header("av-redirect-stopped"), Some("approval"));
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&r).await;
}
#[tokio::test]
async fn direct_route_override_is_denied_but_ordinary_redirect_still_follows() {
    let f = hop_fixture(json!({"routes":route_pairs()}), "/public/next", 302).await;
    let mut req = hop_request(&f, "GET", "/admin/keys");
    req.headers
        .push(("X-HTTP-Method-Override".into(), "DELETE".into()));
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 403);
    assert_eq!(
        r.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("routes")
    );
    assert!(f.up.hits.lock().unwrap().is_empty());
    f.clean(&r).await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/public/start"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"done");
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    let hop = f.last();
    assert_eq!(hop.url, "https://api.example.test/public/next");
    assert!(hop
        .headers
        .iter()
        .any(|(n, v)| n == "authorization" && v == &format!("Bearer {SECRET}")));
    f.clean(&r).await;
}
#[tokio::test]
async fn hop_forwards_only_credential_and_allowlisted_agent_headers_and_omits_framing_credentials()
{
    let f = hop_fixture(
        json!({"routes":route_pairs()}),
        "https://api.example.test/admin/keys",
        302,
    )
    .await;
    let mut req = hop_request(&f, "GET", "/public/start");
    req.headers.extend(
        [
            ("X-HTTP-Method-Override", "GET"),
            ("content-type", "application/json"),
            ("range", "bytes=0-1"),
            ("if-match", "\"x\""),
            ("x-custom", "dropped"),
            ("accept", "application/json"),
            ("user-agent", "probe/1"),
        ]
        .into_iter()
        .map(|(n, v)| (n.into(), v.into())),
    );
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    let hop = f.last();
    assert_eq!(hop.method, "GET");
    assert_eq!(hop.body, None);
    assert_eq!(url::Url::parse(&hop.url).unwrap().path(), "/admin/keys");
    assert_eq!(
        header_names(&hop),
        vec![
            "accept",
            "accept-encoding",
            "authorization",
            "host",
            "user-agent"
        ]
    );
    for (n, v) in [
        ("authorization", format!("Bearer {SECRET}")),
        ("accept-encoding", "identity".into()),
        ("host", "api.example.test".into()),
        ("accept", "application/json".into()),
        ("user-agent", "probe/1".into()),
    ] {
        assert!(hop.headers.iter().any(|(hn, hv)| hn == n && hv == &v));
    }
    f.clean(&r).await;
    let f = Fixture::configured(
        &["header:content-type"],
        SECRET,
        None,
        json!({"redirects":{"max":2}}),
    )
    .await;
    f.up.sequence
        .lock()
        .unwrap()
        .extend([Ok(redirect_reply(302, "/next")), Ok(done_reply())]);
    let r = f
        .send(
            "GET",
            "/ordinary",
            vec![("content-type".into(), f.ph.clone())],
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(f.up.hits.lock().unwrap()[0]
        .headers
        .iter()
        .any(|(n, v)| n == "content-type" && v == SECRET));
    assert_eq!(header_names(&f.last()), vec!["accept-encoding", "host"]);
    f.clean(&r).await;
}
#[tokio::test]
async fn provider_version_headers_survive_hops_and_cookie_override_forwarding_headers_do_not() {
    let f = Fixture::configured_kind(
        &["header:x-api-key"],
        SECRET,
        None,
        json!({"redirects":{"max":2}}),
        "anthropic",
        "api.anthropic.com",
    )
    .await;
    f.up.sequence.lock().unwrap().extend([
        Ok(redirect_reply(302, "/v1/models?limit=5")),
        Ok(done_reply()),
    ]);
    let mut req = gateway_input(&f, "GET", "/v1/models", "", None, None);
    req.headers.retain(|(k, _)| k != "x-key");
    req.headers.push(("x-api-key".into(), f.ph.clone()));
    req.headers.extend(
        [
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "tools-2024"),
            ("accept-language", "en"),
            ("cache-control", "no-cache"),
            ("if-none-match", "\"e\""),
            ("if-modified-since", "Mon, 26 Oct 2026 00:00:00 GMT"),
            ("cookie", "session=agent"),
            ("X-HTTP-Method-Override", "GET"),
            ("x-forwarded-for", "10.0.0.1"),
            ("x-forwarded-host", "evil.test"),
            ("range", "bytes=0-1"),
            ("authorization", "Bearer agent-chosen"),
        ]
        .into_iter()
        .map(|(n, v)| (n.into(), v.into())),
    );
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    let hop = f.last();
    assert_eq!(
        header_names(&hop),
        vec![
            "accept-encoding",
            "accept-language",
            "anthropic-beta",
            "anthropic-version",
            "cache-control",
            "host",
            "if-modified-since",
            "if-none-match",
            "x-api-key"
        ]
    );
    for (n, v) in [
        ("anthropic-version", "2023-06-01"),
        ("x-api-key", SECRET),
        ("host", "api.anthropic.com"),
    ] {
        assert!(hop.headers.iter().any(|(hn, hv)| hn == n && hv == v));
    }
    f.clean(&r).await;
    let f = hop_fixture(json!({}), "/next", 302).await;
    let mut req = hop_request(&f, "GET", "/ordinary");
    req.headers.extend(
        [
            ("OpenAI-Beta", "assistants=v2"),
            ("openai-organization", "org"),
            ("openai-project", "p"),
            ("x-api-version", "1"),
            ("api-version", "2"),
            ("Cookie", "a=b"),
        ]
        .into_iter()
        .map(|(n, v)| (n.into(), v.into())),
    );
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        header_names(&f.last()),
        vec![
            "accept-encoding",
            "api-version",
            "authorization",
            "host",
            "openai-beta",
            "openai-organization",
            "openai-project",
            "x-api-version"
        ]
    );
    f.clean(&r).await;
}
