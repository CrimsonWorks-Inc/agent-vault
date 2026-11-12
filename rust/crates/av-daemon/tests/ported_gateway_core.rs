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
    control_method(socket, "POST", path, body).await
}
async fn control_method(
    socket: &std::path::Path,
    method: &str,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method(method)
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
    network_policy_pipeline(f, port, method, body, json!({})).await
}
async fn network_policy_pipeline(
    f: &Fixture,
    port: u16,
    method: &str,
    body: Option<Vec<u8>>,
    policy_patch: Value,
) -> (av_daemon::pipeline::Pipeline, GatewayRequest) {
    let (token,ph)=f.shared.run(move |core| {
        use av_core::secret::ExposeSecret;
        use av_store::vault::{NewCredential,CreateSessionOptions,CreateGrantOptions,IssueOptions};
        let credential=core.vault.add_credential(NewCredential {slug:"network".into(),kind:"http".into(),connector:serde_json::from_value(json!({"host":format!("127.0.0.1:{port}"),"scheme":"http"})).unwrap(),fields:vec![("key".into(),SECRET.to_string().into())],sites:std::collections::BTreeMap::from([("key".into(),vec!["header:x-key".into()])])}).unwrap();
        let session=core.vault.create_session(CreateSessionOptions::default()).unwrap();
        let mut policy = json!({"hosts":["127.0.0.1"],"methods":["GET","DELETE"],"paths":["/**"],"budget":{"unit":"requests","limit":100},"approval":"auto"});
        for (k,v) in policy_patch.as_object().unwrap() { policy[k] = v.clone(); }
        let grant=core.vault.create_grant(CreateGrantOptions {session_id:session.session.id,credential_id:credential.id,policy:serde_json::from_value(policy).unwrap(),..Default::default()}).unwrap();
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
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        trace,
        vec![
            ("x-trace".into(), "checked".into()),
            ("x-trace".into(), "other".into())
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
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
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

// Exact literal request tables extracted from gateway-w2-pipeline.test.js,
// without importing or executing the test module.
const PARSER_SHAPES: &str = r###"{"spellings":["_method=DELETE","%5Fmethod=DELETE","_METHOD=PUT","__method=DELETE",".method=DELETE","%2Emethod=DELETE","_method[]=DELETE","_method%5B%5D=DELETE","_method[0]=DELETE","+method=DELETE","%20method=DELETE","x-http-method-override=DELETE","X-HTTP-Method-Override=DELETE","x_http_method=DELETE","X-Method-Override=PATCH","a=1;_method=DELETE","a=1;__method=DELETE","__method=DELETE&__method=GET",".method=GET;force=1"],"stray":["force%00=1","+force=1","%20%20force=1","x%00=1","%00x=1","x%01=1","%1Fx=1","x%7F=1","%09x=1","x%09=1","+x=1","x+=1","%20x=1","x%20=1","x%0Ay=1","%C3%A9=1","caf%C3%A9=1","x%FF=1","=1","a=1&=2","a=1;%20b=2"],"php_payload":[["query","dry_run=true&force%00=true"],["query","dry_run=true&force%00x=true"],["query","dry_run=true&force%00[]=true"],["query","dry_run=true&+force=true"],["query","dry_run=true&%20force=true"],["query","dry_run=true&++force=true"],["form","amount=2000&force%00=1"],["form","amount=2000&+force=1"]],"php_method":[["query","_method%00=DELETE"],["form","a=1&_method%00=DELETE"],["form","a=1&%20%20_method=DELETE"]],"bracket_payload":[["query","dry_run=true&[force]=true"],["query","dry_run=true&%5Bforce%5D=true"],["query","dry_run=true&[force][]=true"],["form","amount=2000&[force]=1"]],"bracket_method":[["query","[_method]=DELETE"],["form","a=1&[_method]=DELETE"],["form","a=1&%5B_method%5D=DELETE"]],"foreign_override":[["query _method=DELETE",{"query":"_method=DELETE"}],["form body _method=DELETE",{"extra":[["content-type","application/x-www-form-urlencoded"]],"body":"a=1&_method=DELETE"}],["JSON {\"_method\":\"DELETE\"}",{"extra":[["content-type","application/json"]],"body":"{\"_method\":\"DELETE\"}"}],["lower case value",{"query":"x=1&_method=delete"}],["__method",{"query":"__method=DELETE"}],["percent-encoded name",{"query":"%5Fmethod=DELETE"}],["upper case name",{"extra":[["content-type","application/x-www-form-urlencoded"]],"body":"_METHOD=DELETE"}],["PHP reads .method as _method",{"query":".method=DELETE"}],["PHP reads \" method\" as _method",{"query":"+method=DELETE"}],["bracketed",{"extra":[["content-type","application/x-www-form-urlencoded"]],"body":"_method[]=DELETE"}],["semicolon-separated",{"query":"a=1;_method=DELETE"}],["override header spelled as a field",{"query":"X-HTTP-Method-Override=DELETE"}],["form copy after a matching one",{"extra":[["content-type","application/x-www-form-urlencoded"]],"body":"_method=POST&_method=DELETE"}],["JSON duplicate, last matches",{"extra":[["content-type","application/json"]],"body":"{\"_method\":\"DELETE\",\"_method\":\"POST\"}"}],["JSON duplicate, first matches",{"extra":[["content-type","application/json"]],"body":"{\"_method\":\"POST\", \"a\":{\"b\":[1,\"}\"]},\"_method\":\"DELETE\"}"}],["JSON non-string value",{"extra":[["content-type","application/json"]],"body":"{\"_method\":[\"DELETE\"]}"}],["JSON escaped key",{"extra":[["content-type","application/json"]],"body":" { \"a\" : \"x\\\",\" , \"\\u005fmethod\" : \"DELETE\" } "}],["JSON +json type",{"extra":[["content-type","application/vnd.api+json"]],"body":"{\"_method\":\"PUT\"}"}],["multipart",{"extra":[["content-type","multipart/form-data; boundary=XyZ"]],"body":"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XyZ\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nDELETE\r\n--XyZ--\r\n"}]],"own_override":[["query _method=POST",{"query":"_method=POST"}],["form _method=post",{"extra":[["content-type","application/x-www-form-urlencoded"]],"body":"_method=post&a=1"}],["JSON {\"_method\":\"POST\"}",{"extra":[["content-type","application/json"]],"body":"{\"_method\":\"POST\"}"}],["multipart",{"extra":[["content-type","multipart/form-data; boundary=XyZ"]],"body":"--XyZ\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nPOST\r\n--XyZ--\r\n"}],["nested JSON field",{"extra":[["content-type","application/json"]],"body":"{\"a\":{\"_method\":\"DELETE\"}}"}],["a value, not a name",{"query":"note=_method%3DDELETE"}],["another name",{"query":"my_method=DELETE"}],["a body no framework reads as form",{"extra":[["content-type","text/plain"]],"body":"_method=DELETE"}]],"multipart":[["folded","form-data;\r\n name=\"_method\"",403],["folded with a tab","form-data; name=\"a\";\r\n\tname=\"_method\"",403],["a second name","form-data; name=\"a\"; name=\"_method\"",403],["name*","form-data; name*=utf-8''_method",200]],"stray_bodies":[[["content-type","application/x-www-form-urlencoded"],"a=1&%09b=2","request_ambiguous"],[["content-type","application/x-www-form-urlencoded"],"a=1&b%C3%A9=2","request_ambiguous"],[["content-type","application/x-www-form-urlencoded"],"a=1&force%00=1","request_ambiguous"],[["content-type","multipart/form-data; boundary=XyZ"],"--XyZ\r\nContent-Disposition: form-data; name=\" force\"\r\n\r\n1\r\n--XyZ--\r\n","request_ambiguous"],[["content-type","multipart/form-data; boundary=XyZ"],"--XyZ\r\nContent-Disposition: form-data; name=\"a\u0001\"\r\n\r\n1\r\n--XyZ--\r\n","request_ambiguous"],[["content-type","multipart/form-data; boundary=XyZ"],"--XyZ\r\nContent-Disposition: form-data; name=\"a\"; name=\"bé\"\r\n\r\n1\r\n--XyZ--\r\n","request_ambiguous"],[["content-type","multipart/form-data; boundary=XyZ"],"--XyZ\r\nContent-Disposition: form-data;\r\n name=\"a\t\"\r\n\r\n1\r\n--XyZ--\r\n","request_ambiguous"],[["content-type","application/json"],"{\"a\":1,\" force\":true}","request_ambiguous"],[["content-type","application/json"],"{\"force\\u0000\":true}","request_ambiguous"],[["content-type","application/json"],"{\"model\":\"x\",\"\":1}","request_ambiguous"],[["content-type","application/json"],"{\"modèle\":\"x\"}","request_ambiguous"],[["content-type","multipart/form-data; boundary=XyZ"],"--XyZ\r\nContent-Disposition: form-data; name=\" _method\"\r\n\r\nDELETE\r\n--XyZ--\r\n","method_override"],[["content-type","application/json"],"{\"a\":1,\" _method\":\"DELETE\"}","method_override"],[["content-type","application/json"],"{\"_method\\u0000\":\"DELETE\"}","method_override"]]}"###;

fn parser_shapes() -> Value {
    serde_json::from_str(PARSER_SHAPES).unwrap()
}
fn shape_request(f: &Fixture, method: &str, shape: &Value) -> GatewayRequest {
    let mut req = gateway_input(
        f,
        method,
        "/ordinary",
        shape["query"].as_str().unwrap_or(""),
        None,
        shape["body"].as_str().map(|s| s.as_bytes().to_vec()),
    );
    for header in shape["extra"].as_array().into_iter().flatten() {
        req.headers.push((
            header[0].as_str().unwrap().into(),
            header[1].as_str().unwrap().into(),
        ));
    }
    req
}
async fn assert_direct_refusal(f: &Fixture, req: GatewayRequest, rule: &str) {
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.error.as_ref().unwrap().code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(r.error.as_ref().unwrap().extra.rule.as_deref(), Some(rule));
    assert!(f.up.hits.lock().unwrap().is_empty());
    assert_eq!(grant_counters(f).await, (0, vec![0]));
    f.clean(&r).await;
}
async fn assert_stopped_hop(policy: Value, location: &str, path: &str, query: &str) {
    let f = hop_fixture(policy, location, 302).await;
    let mut req = hop_request(&f, "GET", path);
    req.query = query.into();
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 302, "{location}");
    assert_eq!(r.header("av-redirect-stopped"), Some("path"), "{location}");
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    assert_eq!(grant_counters(&f).await.0, 1);
    f.clean(&r).await;
}
async fn ordinary_hop_control() {
    let f = hop_fixture(json!({}), "/next?ordinary=1", 302).await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"done");
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    f.clean(&r).await;
}
#[tokio::test]
async fn method_override_field_shapes_refuse_other_methods_and_preserve_own_method_controls() {
    let tables = parser_shapes();
    for row in tables["foreign_override"].as_array().unwrap() {
        let f = Fixture::configured(
            &["header:x-key"],
            SECRET,
            None,
            json!({"methods":["GET","POST","DELETE"]}),
        )
        .await;
        assert_direct_refusal(&f, shape_request(&f, "POST", &row[1]), "method_override").await;
        let r = f.get().await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
    }
    let f = Fixture::new(&["header:x-key"]).await;
    assert_direct_refusal(
        &f,
        gateway_input(&f, "GET", "/ordinary", "_method=DELETE", None, None),
        "method_override",
    )
    .await;
    let before = store_snapshot(&f).await;
    let predicted = f
        .daemon
        .pipeline()
        .preflight(
            gateway_input(&f, "GET", "/ordinary", "_method=DELETE", None, None),
            true,
        )
        .await
        .unwrap();
    assert_eq!(predicted["would"], "deny");
    assert_eq!(
        predicted["checks"].as_array().unwrap().last().unwrap()["rule"],
        "method_override"
    );
    assert_eq!(store_snapshot(&f).await, before);
    for row in tables["own_override"].as_array().unwrap() {
        let f = Fixture::new(&["header:x-key"]).await;
        let req = shape_request(&f, "POST", &row[1]);
        let expected = req.body.clone();
        let r = f.daemon.pipeline().handle(req).await;
        assert_eq!(r.status, 200, "{}", row[0]);
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        assert_eq!(f.last().method, "POST");
        assert_eq!(f.last().body, expected);
        f.clean(&r).await;
    }
}
#[tokio::test]
async fn every_override_spelling_is_denied_directly_and_on_redirect_with_own_method_control() {
    for query in parser_shapes()["spellings"].as_array().unwrap() {
        let query = query.as_str().unwrap();
        let methods = json!({"methods":["GET","HEAD","POST","PUT","PATCH","DELETE"]});
        let f = Fixture::configured(&["header:x-key"], SECRET, None, methods.clone()).await;
        assert_direct_refusal(
            &f,
            gateway_input(&f, "GET", "/ordinary", query, None, None),
            "method_override",
        )
        .await;
        assert_stopped_hop(methods, &format!("/next?{query}"), "/ordinary", "").await;
    }
    let f = Fixture::new(&["header:x-key"]).await;
    let query = "a=1;.method=get";
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(&f, "GET", "/ordinary", query, None, None))
        .await;
    assert_eq!(r.status, 200);
    assert!(f.last().url.ends_with(&format!("?{query}")));
    f.clean(&r).await;
    let f = hop_fixture(json!({}), "/next?_method[]=GET", 302).await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().url, "https://api.example.test/next?_method[]=GET");
    f.clean(&r).await;
}
#[tokio::test]
async fn folded_override_location_cannot_gain_a_method_or_skip_onwrite_approval() {
    assert_stopped_hop(
        json!({"routes":route_pairs()}),
        "https://api.example.test/admin/keys?.method=DELETE",
        "/public/start",
        "",
    )
    .await;
    for query in [
        ".method=DELETE",
        "a=1;_method=DELETE",
        "_method[]=DELETE",
        "__method=DELETE",
    ] {
        let f = hop_fixture(
            json!({"methods":["GET","DELETE"],"approval":"on-write","redirects":{"max":1}}),
            &format!("https://api.example.test/other?{query}"),
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
        assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
        f.clean(&r).await;
    }
    ordinary_hop_control().await;
}
async fn registered_payload_rows(key: &str) {
    for row in parser_shapes()[key].as_array().unwrap() {
        let form = row[0] == "form";
        let pairs = row[1].as_str().unwrap();
        let policy = if form {
            json!({"payload":{"form":{"force":{"absent":true},"amount":{"required":true}}}})
        } else {
            json!({"payload":{"query":{"force":{"absent":true},"dry_run":{"required":true}}}})
        };
        let f = Fixture::configured(&["header:x-key"], SECRET, None, policy).await;
        let req = if form {
            gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some("application/x-www-form-urlencoded"),
                Some(pairs.as_bytes().to_vec()),
            )
        } else {
            gateway_input(&f, "GET", "/ordinary", pairs, None, None)
        };
        assert_direct_refusal(&f, req, "request_ambiguous").await;
        let control = if form {
            gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some("application/x-www-form-urlencoded"),
                Some(b"amount=1".to_vec()),
            )
        } else {
            gateway_input(&f, "GET", "/ordinary", "dry_run=true", None, None)
        };
        let r = f.daemon.pipeline().handle(control).await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
        let hop_policy = if form {
            json!({"payload":{"query":{"force":{"absent":true},"amount":{"required":true}}}})
        } else {
            json!({"payload":{"query":{"force":{"absent":true},"dry_run":{"required":true}}}})
        };
        assert_stopped_hop(
            hop_policy,
            &format!("https://api.example.test/next?{pairs}"),
            "/ordinary",
            if form { "amount=1" } else { "dry_run=true" },
        )
        .await;
    }
}
async fn registered_method_rows(key: &str) {
    for row in parser_shapes()[key].as_array().unwrap() {
        let form = row[0] == "form";
        let pairs = row[1].as_str().unwrap();
        let f = Fixture::new(&["header:x-key"]).await;
        let req = if form {
            gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some("application/x-www-form-urlencoded"),
                Some(pairs.as_bytes().to_vec()),
            )
        } else {
            gateway_input(&f, "POST", "/ordinary", pairs, None, None)
        };
        assert_direct_refusal(&f, req, "method_override").await;
        let r = f.get().await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
        assert_stopped_hop(
            json!({"routes":route_pairs()}),
            &format!("https://api.example.test/admin/keys?{pairs}"),
            "/public/start",
            "",
        )
        .await;
    }
}
#[tokio::test]
async fn php_registered_payload_and_method_names_are_denied_on_direct_and_redirect_paths() {
    registered_payload_rows("php_payload").await;
    registered_method_rows("php_method").await;
}
#[tokio::test]
async fn bracket_wrapped_payload_and_method_names_are_denied_on_direct_and_redirect_paths() {
    registered_payload_rows("bracket_payload").await;
    registered_method_rows("bracket_method").await;
}
#[tokio::test]
async fn multipart_content_disposition_reads_every_folded_name_and_preserves_name_star_control() {
    for row in parser_shapes()["multipart"].as_array().unwrap() {
        let f = Fixture::configured(
            &["header:x-key"],
            SECRET,
            None,
            json!({"methods":["GET","POST","DELETE"]}),
        )
        .await;
        let body = format!(
            "--XyZ\r\nContent-Disposition: {}\r\n\r\nDELETE\r\n--XyZ--\r\n",
            row[1].as_str().unwrap()
        );
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some("multipart/form-data; boundary=XyZ"),
                Some(body.into_bytes()),
            ))
            .await;
        let status = row[2].as_u64().unwrap() as u16;
        assert_eq!(r.status, status, "{}", row[0]);
        assert_eq!(f.up.hits.lock().unwrap().len(), usize::from(status == 200));
        if status == 403 {
            assert_eq!(
                r.error.as_ref().unwrap().extra.rule.as_deref(),
                Some("method_override")
            );
        }
        f.clean(&r).await;
    }
}
#[tokio::test]
async fn stray_names_are_denied_in_queries_forms_json_multipart_and_redirects_without_preflight_changes(
) {
    for query in parser_shapes()["stray"].as_array().unwrap() {
        let query = query.as_str().unwrap();
        let f = Fixture::new(&["header:x-key"]).await;
        assert_direct_refusal(
            &f,
            gateway_input(&f, "GET", "/ordinary", query, None, None),
            "request_ambiguous",
        )
        .await;
        assert_stopped_hop(json!({}), &format!("/next?{query}"), "/ordinary", "").await;
        let r = f.get().await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
    }
    for row in parser_shapes()["stray_bodies"].as_array().unwrap() {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_direct_refusal(
            &f,
            gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some(row[0][1].as_str().unwrap()),
                Some(row[1].as_str().unwrap().as_bytes().to_vec()),
            ),
            row[2].as_str().unwrap(),
        )
        .await;
        let r = f.get().await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
    }
    let f = Fixture::new(&["header:x-key"]).await;
    let before = store_snapshot(&f).await;
    let predicted = f
        .daemon
        .pipeline()
        .preflight(
            gateway_input(&f, "GET", "/ordinary", "+force=1", None, None),
            true,
        )
        .await
        .unwrap();
    assert_eq!(predicted["would"], "deny");
    assert_eq!(
        predicted["checks"].as_array().unwrap().last().unwrap()["rule"],
        "request_ambiguous"
    );
    assert_eq!(store_snapshot(&f).await, before);
    ordinary_hop_control().await;
}

fn force_policy() -> Value {
    json!({"payload":{"query":{"force":{"absent":true},"dry_run":{"required":true}}}})
}
#[tokio::test]
async fn semicolon_queries_cannot_hide_ruled_parameters_and_unruled_queries_keep_exact_bytes() {
    for strict in [false, true] {
        let mut policy = force_policy();
        if strict {
            policy["payload"]["query_strict"] = json!(true);
        }
        let f = Fixture::configured(&["header:x-key"], SECRET, None, policy).await;
        assert_direct_refusal(
            &f,
            gateway_input(
                &f,
                "GET",
                "/ordinary",
                "dry_run=true;force=true",
                None,
                None,
            ),
            "request_ambiguous",
        )
        .await;
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(
                &f,
                "GET",
                "/ordinary",
                "dry_run=true",
                None,
                None,
            ))
            .await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
    }
    assert_stopped_hop(
        force_policy(),
        "https://api.example.test/next?dry_run=true;force=true",
        "/ordinary",
        "dry_run=true",
    )
    .await;
    let unrelated = json!({"payload":{"json":{"/model":{"max_length":64}}}});
    let f = Fixture::configured(&["header:x-key"], SECRET, None, unrelated.clone()).await;
    assert_direct_refusal(
        &f,
        gateway_input(&f, "GET", "/ordinary", "a=1;b=2", None, None),
        "request_ambiguous",
    )
    .await;
    assert_stopped_hop(unrelated, "/next?a=1;b=2", "/ordinary", "").await;
    let f = Fixture::new(&["header:x-key"]).await;
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(&f, "GET", "/ordinary", "a=1;b=2", None, None))
        .await;
    assert_eq!(r.status, 200);
    assert!(f.last().url.ends_with("/ordinary?a=1;b=2"));
    f.clean(&r).await;
    let f = hop_fixture(json!({}), "/next?a=1;b=2", 302).await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().url, "https://api.example.test/next?a=1;b=2");
    f.clean(&r).await;
    let f = Fixture::configured(&["header:x-key"], SECRET, None, force_policy()).await;
    let query = "dry_run=true&note=a%3Bforce%3Dtrue";
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(&f, "GET", "/ordinary", query, None, None))
        .await;
    assert_eq!(r.status, 200);
    assert!(f.last().url.ends_with(&format!("?{query}")));
    f.clean(&r).await;
}
#[tokio::test]
async fn names_folded_onto_payload_rules_are_ambiguous_and_plain_repeated_names_are_duplicates() {
    for (query, rule) in [
        ("dry_run=true&FORCE=true", "request_ambiguous"),
        ("dry_run=true&%66orce=true", "request_ambiguous"),
        ("dry_run=true&force[]=true", "payload:query:0:absent"),
        ("dry_run=true&Force=1", "request_ambiguous"),
        ("%64ry_run=true", "request_ambiguous"),
        ("dry.run=true", "request_ambiguous"),
        ("DRY_RUN=true", "request_ambiguous"),
        ("dry_run=true&dry_run=false", "payload_duplicate_key"),
        ("dry_run=true&%64ry_run=true", "payload_duplicate_key"),
        ("dry_run=true&force=1&force=1", "payload_duplicate_key"),
    ] {
        let f = Fixture::configured(&["header:x-key"], SECRET, None, force_policy()).await;
        assert_direct_refusal(
            &f,
            gateway_input(&f, "GET", "/ordinary", query, None, None),
            rule,
        )
        .await;
    }
    for (policy, content_type, body) in [
        (
            json!({"payload":{"form":{"force":{"absent":true}}}}),
            "application/x-www-form-urlencoded",
            "a=1&FORCE=1",
        ),
        (
            json!({"payload":{"form":{"force":{"absent":true}}}}),
            "application/x-www-form-urlencoded",
            "a=1;force=1",
        ),
        (
            json!({"payload":{"json":{"/force":{"absent":true}}}}),
            "application/json",
            "{\"a\":1,\"Force\":true}",
        ),
        (
            json!({"payload":{"json":{"/opts/force":{"absent":true}}}}),
            "application/json",
            "{\"opts\":{\"FORCE\":true}}",
        ),
    ] {
        let f = Fixture::configured(&["header:x-key"], SECRET, None, policy).await;
        assert_direct_refusal(
            &f,
            gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some(content_type),
                Some(body.as_bytes().to_vec()),
            ),
            "request_ambiguous",
        )
        .await;
    }
    let f = Fixture::configured(&["header:x-key"], SECRET, None, force_policy()).await;
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "GET",
            "/ordinary",
            "dry_run=true&forced=1&my_force=1&force_x=1",
            None,
            None,
        ))
        .await;
    assert_eq!(r.status, 200);
    f.clean(&r).await;
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"json":{"/force":{"absent":true}}}}),
    )
    .await;
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/ordinary",
            "",
            Some("application/json"),
            Some(b"{\"forced\":true,\"opts\":{\"Force\":1}}".to_vec()),
        ))
        .await;
    assert_eq!(r.status, 200);
    f.clean(&r).await;
}
#[tokio::test]
async fn rack_bracket_readings_and_punctuation_names_are_refused_with_plain_name_controls() {
    for query in [
        "dry_run=true&]force=true",
        "dry_run=true&[]force=true",
        "dry_run=true&[[force]]=true",
        "dry_run=true&force]=true",
        "dry_run=true&[force=true",
    ] {
        let f = Fixture::configured(&["header:x-key"], SECRET, None, force_policy()).await;
        assert_direct_refusal(
            &f,
            gateway_input(&f, "GET", "/ordinary", query, None, None),
            "request_ambiguous",
        )
        .await;
    }
    for query in ["_method]=DELETE", "]_method=DELETE"] {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_direct_refusal(
            &f,
            gateway_input(&f, "POST", "/ordinary", query, None, None),
            "method_override",
        )
        .await;
    }
    for query in [
        "[x]=1",
        "%5Bx%5D=1",
        "]x=1",
        "[]=1",
        "[_method]=GET",
        "@x=1",
        "~x=1",
        "!x=1",
        "*x=1",
        "%2Fx=1",
        ":x=1",
        "a=1&{x}=2",
    ] {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_direct_refusal(
            &f,
            gateway_input(&f, "GET", "/ordinary", query, None, None),
            "request_ambiguous",
        )
        .await;
        assert_stopped_hop(json!({}), &format!("/next?{query}"), "/ordinary", "").await;
    }
    for (content_type, body) in [
        ("application/x-www-form-urlencoded", "a=1&[force]=1"),
        (
            "multipart/form-data; boundary=XyZ",
            "--XyZ\r\nContent-Disposition: form-data; name=\"[force]\"\r\n\r\n1\r\n--XyZ--\r\n",
        ),
    ] {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_direct_refusal(
            &f,
            gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some(content_type),
                Some(body.as_bytes().to_vec()),
            ),
            "request_ambiguous",
        )
        .await;
    }
    use av_core::request_view::{folded_names, is_override_field, is_stray_name};
    for name in [
        "[_method]",
        "_method]",
        "]_method",
        "[]_method",
        "[_METHOD][]",
    ] {
        assert!(is_override_field(name));
    }
    for name in ["[force]", "[force][]", "]force", "force]"] {
        assert!(folded_names(name).contains(&"force".into()));
    }
    for query in [
        "dry_run=true&[force]=true",
        "dry_run=true&%5Bforce%5D=true",
        "dry_run=true&[force][]=true",
        "dry_run=true&force]=true",
    ] {
        let view = av_core::request_view::request_view(&av_core::request_view::RequestInput {
            query: Some(query),
            ..Default::default()
        });
        let sets = serde_json::from_value(json!([force_policy()["payload"]])).unwrap();
        let e = av_core::payload::evaluate_payload(
            Some(&sets),
            &av_core::payload::PayloadInput {
                view: &view,
                path: "",
            },
        )
        .unwrap_err();
        assert_eq!(e.extra.rule.as_deref(), Some("request_ambiguous"));
    }
    for name in ["[x]", "]x", "@x", "~x", "!x"] {
        assert!(is_stray_name(name));
    }
    for name in [
        "x",
        "0",
        "_x",
        "-x",
        ".x",
        "$filter",
        "expand[]",
        "items[0][price]",
    ] {
        assert!(!is_stray_name(name));
    }
    let f = Fixture::new(&["header:x-key"]).await;
    let r = f.get().await;
    assert_eq!(r.status, 200);
    f.clean(&r).await;
    ordinary_hop_control().await;
}
#[tokio::test]
async fn dollar_query_names_and_dollar_or_at_json_keys_pass_without_rewriting() {
    for query in [
        "$select=displayName,mail&$filter=startswith(displayName,%27a%27)&$top=10",
        "$expand=members&$count=true",
    ] {
        let f = Fixture::configured(
            &["header:x-key"],
            SECRET,
            None,
            json!({"payload":{"query":{"$top":{"max_length":4}}}}),
        )
        .await;
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(&f, "GET", "/v1.0/users", query, None, None))
            .await;
        assert_eq!(r.status, 200);
        assert!(f.last().url.ends_with(&format!("?{query}")));
        f.clean(&r).await;
    }
    let f = hop_fixture(json!({}), "/v1.0/users?$skiptoken=abc&$top=10", 302).await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        f.last().url,
        "https://api.example.test/v1.0/users?$skiptoken=abc&$top=10"
    );
    f.clean(&r).await;
    let f = Fixture::new(&["header:x-key"]).await;
    let body=b"{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"@context\":\"https://schema.org\",\"name\":\"x\"}".to_vec();
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/ordinary",
            "",
            Some("application/json"),
            Some(body.clone()),
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().body, Some(body));
    f.clean(&r).await;
}

// Literal provider/list-name controls from the read-only JS reference.
const PROVIDER_LIST_SHAPES: &str = r###"{"list_good":[[{"payload":{"query":{"limit":{"required":true}}}},"/p/test/v1/charges","limit=10&expand[]=customer&expand[]=invoice"],[{"payload":{"query":{"limit":{"required":true}}}},"/p/test/v1/charges","limit=10&expand%5B%5D=customer&expand%5B%5D=invoice"],[{"payload":{"query":{"limit":{"required":true}}}},"/p/test/v1/charges","limit=10&created[gte]=1609459200&created[lte]=1640995200"],[{"payload":{"query":{"expand":{"one_of":["customer","invoice"]}}}},"/p/test/v1/charges","expand[]=customer&expand[]=invoice"],[{"payload":{"query":{"expand":{"required":true}}}},"/p/test/v1/charges","expand[]=customer"],[{"payload":{"query":{"expand":{}},"query_strict":true}},"/p/test/v1/charges","expand[]=customer&expand[]=invoice"]],"list_bad":[[{"payload":{"query":{"force":{"absent":true},"dry_run":{"required":true}}}},"dry_run=true&force=1&force=2","payload_duplicate_key"],[{"payload":{"query":{"limit":{"required":true}}}},"limit=10&limit=20","payload_duplicate_key"],[{"payload":{"query":{"expand":{"one_of":["customer","invoice"]}}}},"expand[]=customer&expand[]=balance_transaction","payload:query:0:one_of"],[{"payload":{"query":{"expand":{"one_of":["customer"]}}}},"expand=customer&expand[]=invoice","payload:query:0:one_of"],[{"payload":{"query":{"expand":{"one_of":["customer"]}}}},"expand%5B%5D=customer&expand%5B%5D=invoice","payload:query:0:one_of"],[{"payload":{"query":{"expand":{"one_of":["customer"]}}}},"expand[x]=invoice","payload:query:0:one_of"],[{"payload":{"query":{"expand":{"max_length":8}}}},"expand[]=customer&expand[]=balance_transaction","payload:query:0:max_length"],[{"payload":{"query":{"expand":{"absent":true}}}},"expand[]=customer","payload:query:0:absent"],[{"payload":{"query":{"expand":{"one_of":["customer"]}}}},"%65xpand[]=invoice","request_ambiguous"],[{"payload":{"query":{"expand":{}},"query_strict":true}},"expand[]=customer&other[]=x","payload:query:1:strict"]],"list_form":[["mode=payment&items[]=a&items[]=b",200],["mode=payment&items[]=a&items[]=c",403],["mode=payment&mode=setup",403]],"provider_queries":[[{},"/p/test/v1/models","limit=20&after_id=model_1"],[{},"/p/test/repos/o/r/contents","ref=main"],[{},"/p/test/search/issues","q=org%3Afoo+language%3Ago&per_page=30"],[{},"/p/test/search/code","q=caf%C3%A9+in%3Afile"],[{},"/p/test/v1/charges","limit=10&starting_after=ch_123&expand[]=data"],[{},"/p/test/v1/charges","expand[]=data.customer&expand[]=data.invoice"],[{"payload":{"query":{"starting_after":{"max_length":64}}}},"/p/test/v1/charges","limit=10&starting_after=ch_123&expand[]=data"]]}"###;

#[tokio::test]
async fn ordinary_ampersand_provider_and_versioned_redirect_traffic_is_unchanged() {
    let f = Fixture::configured(&["header:x-key"], SECRET, None, force_policy()).await;
    let query = "dry_run=true&limit=5&cursor=abc%3D%3D&tag=a+b&empty=&flag";
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(&f, "GET", "/ordinary", query, None, None))
        .await;
    assert_eq!(r.status, 200);
    assert!(f.last().url.ends_with(&format!("/ordinary?{query}")));
    f.clean(&r).await;
    let f = model_fixture(json!({})).await;
    let body = model_body();
    let r = f
        .daemon
        .pipeline()
        .handle(model_request(&f, body.clone()))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().body, Some(body));
    f.clean(&r).await;
    let f = Fixture::configured_kind(
        &["header:x-key"],
        SECRET,
        None,
        json!({}),
        "anthropic",
        "api.anthropic.com",
    )
    .await;
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "GET",
            "/v1/models",
            "limit=20&after_id=model_1",
            None,
            None,
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        f.last().url,
        "https://api.anthropic.com/v1/models?limit=20&after_id=model_1"
    );
    f.clean(&r).await;
    let f = hop_fixture(json!({}), "/repos/o/r/contents?ref=main", 302).await;
    let mut req = hop_request(&f, "GET", "/ordinary");
    req.headers.extend([
        ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
        ("accept".into(), "application/vnd.github+json".into()),
    ]);
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        f.last().url,
        "https://api.example.test/repos/o/r/contents?ref=main"
    );
    assert!(f
        .last()
        .headers
        .iter()
        .any(|(k, v)| k == "X-GitHub-Api-Version" && v == "2022-11-28"));
    f.clean(&r).await;
}
#[tokio::test]
async fn ordinary_nonascii_provider_values_bracket_queries_forms_and_filename_uploads_are_sent_unchanged(
) {
    let f = model_fixture(json!({})).await;
    let body=serde_json::to_vec(&json!({"model":"gpt-4.1-mini","messages":[{"role":"user","content":"héllo ✓ 日本"}],"metadata":{"clé":"v"},"response_format":{"type":"json_object"}})).unwrap();
    let r = f
        .daemon
        .pipeline()
        .handle(model_request(&f, body.clone()))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().body, Some(body));
    f.clean(&r).await;
    let f = Fixture::configured_kind(
        &["header:x-api-key"],
        SECRET,
        None,
        json!({}),
        "anthropic",
        "api.anthropic.com",
    )
    .await;
    let body=serde_json::to_vec(&json!({"model":"claude-sonnet-4-5","max_tokens":32,"system":"Réponds.","messages":[{"role":"user","content":"ping"}]})).unwrap();
    let mut req = gateway_input(
        &f,
        "POST",
        "/v1/messages",
        "",
        Some("application/json"),
        Some(body.clone()),
    );
    req.headers.retain(|(k, _)| k != "x-key");
    req.headers.extend([
        ("x-api-key".into(), f.ph.clone()),
        ("anthropic-version".into(), "2023-06-01".into()),
    ]);
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().body, Some(body));
    assert!(f
        .last()
        .headers
        .iter()
        .any(|(k, v)| k == "anthropic-version" && v == "2023-06-01"));
    assert!(f
        .last()
        .headers
        .iter()
        .any(|(k, v)| k == "x-api-key" && v == SECRET));
    f.clean(&r).await;
    let shapes: Value = serde_json::from_str(PROVIDER_LIST_SHAPES).unwrap();
    for row in shapes["provider_queries"].as_array().unwrap() {
        let f = Fixture::configured(&["header:x-key"], SECRET, None, row[0].clone()).await;
        let path = row[1].as_str().unwrap().strip_prefix("/p/test").unwrap();
        let query = row[2].as_str().unwrap();
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(&f, "GET", path, query, None, None))
            .await;
        assert_eq!(r.status, 200);
        assert!(f.last().url.ends_with(&format!("?{query}")));
        f.clean(&r).await;
    }
    for policy in [
        json!({}),
        json!({"payload":{"form":{"amount":{"required":true},"currency":{"one_of":["usd"]}}}}),
    ] {
        let f = Fixture::configured(&["header:x-key"], SECRET, None, policy).await;
        let body=b"amount=2000&currency=usd&source=tok_visa&metadata[order_id]=6735&metadata[note]=caf%C3%A9&description=Order+6735".to_vec();
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(
                &f,
                "POST",
                "/v1/charges",
                "",
                Some("application/x-www-form-urlencoded"),
                Some(body.clone()),
            ))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(f.last().body, Some(body));
        f.clean(&r).await;
    }
    let f = Fixture::new(&["header:x-key"]).await;
    let body="--XyZ\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nfine-tune\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"données.jsonl\"\r\nContent-Type: application/jsonl\r\n\r\n{\"é\":1}\r\n--XyZ--\r\n".as_bytes().to_vec();
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/ordinary",
            "",
            Some("multipart/form-data; boundary=XyZ"),
            Some(body.clone()),
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().body, Some(body));
    f.clean(&r).await;
    let f = hop_fixture(json!({}), "/v1/charges?limit=10&expand[]=data", 302).await;
    let r = f
        .daemon
        .pipeline()
        .handle(hop_request(&f, "GET", "/ordinary"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        f.last().url,
        "https://api.example.test/v1/charges?limit=10&expand[]=data"
    );
    f.clean(&r).await;
}
#[tokio::test]
async fn repeated_list_names_preserve_entries_and_apply_rules_to_each_base_entry() {
    let shapes: Value = serde_json::from_str(PROVIDER_LIST_SHAPES).unwrap();
    for row in shapes["list_good"].as_array().unwrap() {
        let f = Fixture::configured(&["header:x-key"], SECRET, None, row[0].clone()).await;
        let path = row[1].as_str().unwrap().strip_prefix("/p/test").unwrap();
        let query = row[2].as_str().unwrap();
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(&f, "GET", path, query, None, None))
            .await;
        assert_eq!(r.status, 200, "{query}");
        assert!(f.last().url.ends_with(&format!("?{query}")));
        f.clean(&r).await;
    }
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"payload":{"form":{"mode":{"one_of":["payment"]}}}}),
    )
    .await;
    let items=b"mode=payment&line_items[0][price]=price_1&line_items[0][quantity]=1&line_items[1][price]=price_2&line_items[1][quantity]=2&payment_method_types[]=card&payment_method_types[]=link".to_vec();
    let r = f
        .daemon
        .pipeline()
        .handle(gateway_input(
            &f,
            "POST",
            "/v1/checkout/sessions",
            "",
            Some("application/x-www-form-urlencoded"),
            Some(items.clone()),
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(f.last().body, Some(items));
    f.clean(&r).await;
    let f = hop_fixture(
        json!({"payload":{"query":{"limit":{"required":true}}}}),
        "/v1/charges?limit=10&expand[]=customer&expand[]=invoice",
        302,
    )
    .await;
    let mut req = hop_request(&f, "GET", "/ordinary");
    req.query = "limit=1".into();
    let r = f.daemon.pipeline().handle(req).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        f.last().url,
        "https://api.example.test/v1/charges?limit=10&expand[]=customer&expand[]=invoice"
    );
    f.clean(&r).await;
    for row in shapes["list_bad"].as_array().unwrap() {
        let f = Fixture::configured(&["header:x-key"], SECRET, None, row[0].clone()).await;
        assert_direct_refusal(
            &f,
            gateway_input(&f, "GET", "/ordinary", row[1].as_str().unwrap(), None, None),
            row[2].as_str().unwrap(),
        )
        .await;
    }
    for row in shapes["list_form"].as_array().unwrap() {
        let f=Fixture::configured(&["header:x-key"],SECRET,None,json!({"payload":{"form":{"mode":{"one_of":["payment"]},"items":{"one_of":["a","b"]}}}})).await;
        let r = f
            .daemon
            .pipeline()
            .handle(gateway_input(
                &f,
                "POST",
                "/ordinary",
                "",
                Some("application/x-www-form-urlencoded"),
                Some(row[0].as_str().unwrap().as_bytes().to_vec()),
            ))
            .await;
        assert_eq!(u64::from(r.status), row[1].as_u64().unwrap());
        f.clean(&r).await;
    }
    for (query, policy, rule) in [
        (
            "limit=1&expand[]=a&expand[]=b",
            json!({"query":{"limit":{"required":true}}}),
            None,
        ),
        (
            "expand[]=a&expand[]=b",
            json!({"query":{"expand":{"one_of":["a"]}}}),
            Some("payload:query:0:one_of"),
        ),
    ] {
        let view = av_core::request_view::request_view(&av_core::request_view::RequestInput {
            query: Some(query),
            ..Default::default()
        });
        let sets = serde_json::from_value(json!([policy])).unwrap();
        let r = av_core::payload::evaluate_payload(
            Some(&sets),
            &av_core::payload::PayloadInput {
                view: &view,
                path: "",
            },
        );
        if let Some(rule) = rule {
            assert_eq!(r.unwrap_err().extra.rule.as_deref(), Some(rule));
        } else {
            r.unwrap();
        }
    }
}

fn reader_violations(query: &str, rules: bool) -> Vec<String> {
    let mut violations = Vec::new();
    for reader in ["whatwg", "rack", "qs", "php", "caseBlind"] {
        let raw = if reader == "rack" {
            query.replace(';', "&")
        } else {
            query.to_string()
        };
        let pairs = url::form_urlencoded::parse(raw.as_bytes())
            .map(|(name, value)| {
                let name = name.into_owned();
                let folded = match reader {
                    "rack" => name
                        .trim_start_matches(['[', ']'])
                        .split(['[', ']'])
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    "qs" => {
                        if let Some(rest) = name.strip_prefix('[') {
                            rest.split_once(']')
                                .filter(|(inside, _)| !inside.contains(['[', ']']))
                                .map_or_else(|| name.clone(), |(inside, _)| inside.to_string())
                        } else {
                            name.split('[').next().unwrap_or("").to_string()
                        }
                    }
                    "php" => name
                        .split('\0')
                        .next()
                        .unwrap_or("")
                        .trim_start_matches(' ')
                        .replace([' ', '.'], "_")
                        .split('[')
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    "caseBlind" => name.to_lowercase(),
                    _ => name,
                };
                (folded, value.into_owned())
            })
            .collect::<Vec<_>>();
        if pairs.iter().any(|(k, v)| {
            [
                "_method",
                "__method",
                "x-http-method-override",
                "x_http_method_override",
                "x-http-method",
                "x_http_method",
                "x-method-override",
                "x_method_override",
            ]
            .contains(&k.to_lowercase().as_str())
                && v.to_uppercase() != "GET"
        }) {
            violations.push(format!("{reader}: override"));
        }
        if rules && pairs.iter().any(|(k, _)| k == "force") {
            violations.push(format!("{reader}: force"));
        }
        if rules && !pairs.iter().any(|(k, _)| k == "dry_run") {
            violations.push(format!("{reader}: no dry_run"));
        }
    }
    violations
}
fn property_queries() -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::prelude::*;
    let names = vec![
        "a",
        "dry_run",
        "force",
        "note",
        "_method",
        ".method",
        "%5Fmethod",
        "FORCE",
        "%66orce",
        "dry.run",
        "force[]",
        "x-http-method-override",
        "__method",
        "b+c",
        "q%20x",
        "%64ry_run",
        "force%00",
        "force%00x",
        "_method%00",
        "+force",
        "++force",
        "%20force",
        "%20%20_method",
        "+_method",
        "force+",
        "force%20",
        "%09force",
        "force%09",
        "%01_method",
        "%7Fforce",
        "forc%C3%A9",
        "%C3%A9",
        "",
        "[force]",
        "%5Bforce%5D",
        "[force][]",
        "[_method]",
        "%5B_method%5D",
        "]force",
        "[]force",
        "force]",
        "_method]",
        "expand[]",
        "items[0][price]",
        "force[x]",
    ];
    let values = vec![
        "1",
        "true",
        "GET",
        "DELETE",
        "x%3By",
        "a+b",
        "",
        "%26force%3D1",
    ];
    (
        any::<bool>(),
        proptest::collection::vec(
            (
                proptest::sample::select(names),
                proptest::sample::select(values),
                any::<bool>(),
                0u8..4,
            ),
            1..4,
        ),
    )
        .prop_map(|(prefix, entries)| {
            let mut q = if prefix {
                "dry_run=true".to_string()
            } else {
                String::new()
            };
            for (name, value, assigned, separator) in entries {
                if !q.is_empty() {
                    q.push(if separator == 0 { ';' } else { '&' });
                }
                q.push_str(name);
                if assigned {
                    q.push('=');
                    q.push_str(value);
                }
            }
            q
        })
}
async fn check_query_wire_property(
    generated: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    use proptest::prelude::*;
    use tokio::io::AsyncWriteExt;
    // A positive and a negative control ensure every generated case exercises
    // both outcomes on the direct path and the redirect path.
    for rules in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let record = seen.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (headers, _) = read_wire_request(&mut socket).await;
                let target = headers
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string();
                record.lock().unwrap().push(target.clone());
                let parsed = url::Url::parse(&format!("http://upstream{target}")).unwrap();
                let destination = parsed
                    .query_pairs()
                    .find(|(k, _)| k == "to")
                    .map(|(_, v)| v.into_owned());
                let response = if let ("/start", Some(destination)) = (parsed.path(), destination) {
                    format!("HTTP/1.1 302 Found\r\nLocation: /next?{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",destination)
                } else {
                    let body = "ordinary-traffic-control";
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
                };
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let f = Fixture::new(&["header:x-key"]).await;
        let mut policy = if rules { force_policy() } else { json!({}) };
        policy["redirects"] = json!({"max":1});
        let (pipeline, base) = network_policy_pipeline(&f, port, "GET", None, policy).await;
        let mut outcomes = [0usize; 4];
        for query in ["dry_run=true&note=ordinary", "_method=DELETE", generated] {
            let before = seen.lock().unwrap().len();
            let mut req = base.clone();
            req.path = "/p/network/ok".into();
            req.query = query.into();
            let r = pipeline.handle(req).await;
            let arrived = seen.lock().unwrap()[before..].to_vec();
            f.clean(&r).await;
            if r.status == 200 {
                outcomes[0] += 1;
                prop_assert_eq!(arrived.len(), 1);
                let sent = arrived[0]
                    .strip_prefix("/ok")
                    .unwrap()
                    .strip_prefix('?')
                    .unwrap_or("");
                let view =
                    av_core::request_view::request_view(&av_core::request_view::RequestInput {
                        query: Some(query),
                        ..Default::default()
                    });
                prop_assert_eq!(sent, &view.query);
                let received =
                    av_core::request_view::request_view(&av_core::request_view::RequestInput {
                        query: Some(sent),
                        ..Default::default()
                    });
                prop_assert_eq!(
                    received
                        .params
                        .iter()
                        .map(|p| (&p.raw_name, &p.name, &p.value))
                        .collect::<Vec<_>>(),
                    view.params
                        .iter()
                        .map(|p| (&p.raw_name, &p.name, &p.value))
                        .collect::<Vec<_>>()
                );
                prop_assert!(reader_violations(sent, rules).is_empty(), "query={sent:?}");
            } else {
                outcomes[1] += 1;
                prop_assert_eq!(r.status, 403);
                prop_assert!(arrived.is_empty());
            }
            let before = seen.lock().unwrap().len();
            let mut req = base.clone();
            req.path = "/p/network/start".into();
            req.query = format!(
                "dry_run=true&to={}",
                av_daemon::util::encode_uri_component(query)
            );
            let r = pipeline.handle(req).await;
            let arrived = seen.lock().unwrap()[before..].to_vec();
            f.clean(&r).await;
            prop_assert!(arrived.first().is_some_and(|s| s.starts_with("/start?")));
            if arrived.len() == 2 {
                outcomes[2] += 1;
                prop_assert_eq!(r.status, 200);
                let sent = arrived[1]
                    .strip_prefix("/next")
                    .unwrap()
                    .strip_prefix('?')
                    .unwrap_or("");
                let expected = url::Url::parse(&format!("http://x/next?{query}")).unwrap();
                prop_assert_eq!(sent, expected.query().unwrap_or(""));
                prop_assert!(
                    reader_violations(sent, rules).is_empty(),
                    "hop query={sent:?}"
                );
            } else {
                outcomes[3] += 1;
                prop_assert_eq!(arrived.len(), 1);
                prop_assert!(r.header("av-redirect-stopped").is_some());
            }
        }
        prop_assert!(outcomes.into_iter().all(|n| n >= 1));
        server.abort();
    }
    Ok(())
}
proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 64, failure_persistence: None, ..Default::default() })]
    #[test]
    fn generated_gateway_queries_match_real_wire_and_every_reader_with_positive_and_negative_controls(query in property_queries()) {
        let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(check_query_wire_property(&query))?;
    }
}

#[tokio::test]
async fn plaintext_pins_refuse_before_connecting_and_unpinned_control_connects() {
    use tokio::io::AsyncWriteExt;
    let f = Fixture::new(&["header:x-key"]).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (pipeline, request) = network_pipeline(&f, port, "GET", None).await;
    f.shared
        .run(|core| {
            core.vault
                .set_pins(
                    "network",
                    "127.0.0.1",
                    &[format!("sha256/{}=", "A".repeat(43))],
                )
                .unwrap();
        })
        .await
        .unwrap();
    let refused = pipeline.handle(request.clone()).await;
    assert_eq!(
        refused.error.as_ref().unwrap().code.as_str(),
        "AV_PIN_MISMATCH"
    );
    assert_eq!(
        refused.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("pin_plaintext")
    );
    assert_eq!(refused.error.as_ref().unwrap().extra.refunded, Some(true));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "pinned plaintext must never open a connection"
    );
    f.clean(&refused).await;
    f.shared
        .run(|core| {
            let credential = core.vault.find_credential("network").unwrap().unwrap();
            let grant = core
                .vault
                .grants()
                .unwrap()
                .into_iter()
                .find(|g| g.credential_id == credential.id)
                .unwrap();
            assert_eq!(grant.budget_used, 0);
            assert!(core
                .vault
                .list_placeholders(None)
                .unwrap()
                .iter()
                .filter(|p| p.grant_id == grant.id)
                .all(|p| p.uses == 0));
        })
        .await
        .unwrap();
    f.shared
        .run(|core| {
            core.vault.clear_pins("network", "127.0.0.1", None).unwrap();
        })
        .await
        .unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (headers, body) = read_wire_request(&mut socket).await;
        assert!(headers.contains(SECRET));
        assert!(body.is_empty());
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\nConnection: close\r\n\r\nordinary-traffic-control").await.unwrap();
    });
    let ordinary =
        tokio::time::timeout(std::time::Duration::from_secs(5), pipeline.handle(request))
            .await
            .unwrap();
    assert_eq!(ordinary.status, 200);
    assert_eq!(ordinary.body, b"ordinary-traffic-control");
    server.await.unwrap();
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn authenticated_replay_revokes_only_its_session_and_denies_held_approvals() {
    use av_daemon::tripwire::Observation;
    use av_store::model::SessionState;
    let f = approval_fixture("each", &["header:x-key"]).await;
    let id = held_id(&f.get().await);
    let token = f.token.clone();
    let (sid, other) = f.shared.run(move |core| {
        core.vault.update_settings(&json!({"tripwires":{"enabled":true,"rules":av_daemon::tripwire::default_rules_json()}})).unwrap();
        let sid = core.vault.session_by_token(&token).unwrap().unwrap().id;
        let other = core.vault.create_session(Default::default()).unwrap().session.id;
        assert!(core.tw_observe(&Observation { code:"AV_PH_REPLAY".into(), ..Default::default() }).unwrap().is_none());
        let row = core.vault.list_placeholders(None).unwrap().into_iter().next().unwrap();
        core.vault.burn_placeholder(&row.id, "fixture replay").unwrap();
        (sid, other)
    }).await.unwrap();
    f.daemon.pipeline().decide_approval(id, true).await.unwrap();
    let replay = f.get().await;
    assert_eq!(replay.error.as_ref().unwrap().code.as_str(), "AV_PH_REPLAY");
    assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
    f.shared
        .run(move |core| {
            assert_eq!(
                core.vault.session(&sid).unwrap().unwrap().state,
                SessionState::Revoked
            );
            assert_eq!(
                core.vault.session(&other).unwrap().unwrap().state,
                SessionState::Active
            );
        })
        .await
        .unwrap();
    let revoked = f.get().await;
    assert_eq!(
        revoked.error.as_ref().unwrap().code.as_str(),
        "AV_SESSION_REVOKED"
    );
    assert!(f.up.hits.lock().unwrap().is_empty());
    f.clean(&replay).await;
    f.clean(&revoked).await;
    let ordinary = Fixture::new(&["header:x-key"]).await;
    let response = ordinary.get().await;
    assert_eq!(response.status, 200);
    ordinary.clean(&response).await;
}

#[tokio::test]
async fn quarantine_tripwire_pauses_its_credential_and_preserves_active_sessions() {
    use av_daemon::tripwire::Observation;
    use av_store::model::{QuarantineBy, SessionState};
    let f = Fixture::new(&["header:x-key"]).await;
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
    let token = f.token.clone();
    f.shared.run(move |core| {
        core.vault.update_settings(&json!({"tripwires":{"enabled":true,"rules":[{"id":"quarantine","codes":["AV_BAD_LOCATION"],"threshold":1,"window_s":10,"action":"quarantine_credential"}]}})).unwrap();
        let sid = core.vault.session_by_token(&token).unwrap().unwrap().id;
        let other = core.vault.create_session(Default::default()).unwrap().session.id;
        let cred = core.vault.find_credential("demo").unwrap().unwrap();
        let rule = core.tw_observe(&Observation { session_id:sid.clone(), credential_id:Some(cred.id), code:"AV_BAD_LOCATION".into(), ..Default::default() }).unwrap().unwrap();
        assert_eq!(rule["id"], "quarantine");
        assert_eq!(core.vault.find_credential("demo").unwrap().unwrap().quarantine.unwrap().by, QuarantineBy::Tripwire);
        for id in [sid, other] { assert_eq!(core.vault.session(&id).unwrap().unwrap().state, SessionState::Active); }
    }).await.unwrap();
    let refused = f.get().await;
    assert_eq!(
        refused.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("quarantine")
    );
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&refused).await;
    f.shared
        .run(|core| core.vault.clear_quarantine("demo").unwrap())
        .await
        .unwrap();
    let released = f.get().await;
    assert_eq!(released.status, 200);
    f.clean(&released).await;
}

mod ported_common;

#[tokio::test]
async fn placeholder_only_authentication_touches_session_only_after_checksum_verification() {
    use av_store::vault::{CreateGrantOptions, IssueOptions, NewCredential};
    for forged in [true, false] {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
        let cred = vault
            .add_credential(NewCredential {
                slug: "demo".into(),
                kind: "http".into(),
                connector: serde_json::from_value(json!({"host":"api.example.test"})).unwrap(),
                fields: vec![("key".into(), SECRET.to_string().into())],
                sites: std::collections::BTreeMap::from([(
                    "key".into(),
                    vec!["header:x-key".into()],
                )]),
            })
            .unwrap();
        let session = vault.create_session(Default::default()).unwrap().session;
        let grant = vault.create_grant(CreateGrantOptions {
            session_id:session.id.clone(), credential_id:cred.id,
            policy:serde_json::from_value(json!({"hosts":["api.example.test"],"methods":["GET"],"paths":["/**"],"approval":"auto","budget":{"unit":"requests","limit":10}})).unwrap(),
            ..Default::default()
        }).unwrap();
        let ph = vault
            .issue_placeholder(IssueOptions {
                grant_id: grant.id.clone(),
                ..Default::default()
            })
            .unwrap()
            .placeholder;
        let soon = (time::OffsetDateTime::now_utc() + time::Duration::minutes(1))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        drop(vault);
        ported_common::seed_session_expiry(dir.path(), &session.id, &soon);
        let mut reopened = av_store::vault::Vault::open(dir.path()).unwrap();
        reopened.unlock(None).unwrap();
        let shared = Shared::new(reopened);
        let up = Arc::new(RecordingUpstream::default());
        let pipeline = av_daemon::pipeline::Pipeline::new(
            shared.clone(),
            PipelineOptions {
                upstream: Some(up.clone()),
                ..Default::default()
            },
        );
        let mut marker = ph.clone();
        if forged {
            let suffix = if ph.ends_with("aaaaaa") {
                "bbbbbb"
            } else {
                "aaaaaa"
            };
            marker.replace_range(marker.len() - 6.., suffix);
        }
        let response = pipeline
            .handle(GatewayRequest {
                method: "GET".into(),
                path: "/p/demo/ordinary".into(),
                headers: vec![
                    ("host".into(), "127.0.0.1".into()),
                    ("x-key".into(), marker),
                ],
                ..Default::default()
            })
            .await;
        assert_eq!(response.status, if forged { 400 } else { 200 });
        if forged {
            assert_eq!(
                response.error.as_ref().unwrap().code.as_str(),
                "AV_PH_MALFORMED"
            );
        }
        assert_eq!(up.hits.lock().unwrap().len(), usize::from(!forged));
        let sid = session.id.clone();
        shared
            .run(move |core| {
                let after = core
                    .vault
                    .session(&sid)
                    .unwrap()
                    .unwrap()
                    .expires_at
                    .unwrap();
                if forged {
                    assert_eq!(after, soon);
                } else {
                    let parse = |s: &str| {
                        time::OffsetDateTime::parse(
                            s,
                            &time::format_description::well_known::Rfc3339,
                        )
                        .unwrap()
                    };
                    assert!(parse(&after) > parse(&soon));
                }
                assert_eq!(
                    core.vault.grant(&grant.id).unwrap().unwrap().budget_used,
                    u64::from(!forged)
                );
                let audit = serde_json::to_string(
                    &core
                        .vault
                        .audit()
                        .unwrap()
                        .read(&Default::default())
                        .unwrap(),
                )
                .unwrap();
                assert!(!audit.contains(SECRET));
            })
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&response.body).contains(SECRET));
        assert!(!serde_json::to_string(&response.headers)
            .unwrap()
            .contains(SECRET));
    }
}

struct SeededGateway {
    _dir: tempfile::TempDir,
    shared: VaultRef,
    pipeline: av_daemon::pipeline::Pipeline,
    upstream: Arc<RecordingUpstream>,
    request: GatewayRequest,
    sid: String,
    gid: String,
}

fn seeded_policy() -> Value {
    json!({"hosts":["api.example.test"],"methods":["GET","POST"],"paths":["/**"],"approval":"auto","budget":{"unit":"requests","limit":100}})
}

impl SeededGateway {
    fn new(session_patch: Value, grant_patch: Value) -> Self {
        Self::with_tripwires(session_patch, grant_patch, None)
    }
    fn with_tripwires(session_patch: Value, grant_patch: Value, tripwires: Option<Value>) -> Self {
        Self::configured(session_patch, grant_patch, tripwires, None)
    }
    fn configured(
        session_patch: Value,
        grant_patch: Value,
        tripwires: Option<Value>,
        patterns: Option<Value>,
    ) -> Self {
        use av_core::secret::ExposeSecret;
        use av_store::vault::{CreateGrantOptions, IssueOptions, NewCredential};
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
        let credential = vault
            .add_credential(NewCredential {
                slug: "seeded".into(),
                kind: "http".into(),
                connector: serde_json::from_value(json!({"host":"api.example.test"})).unwrap(),
                fields: vec![("key".into(), SECRET.to_string().into())],
                sites: std::collections::BTreeMap::from([(
                    "key".into(),
                    vec!["header:x-key".into()],
                )]),
            })
            .unwrap();
        let session = vault.create_session(Default::default()).unwrap();
        let token = session.token.expose_secret().to_string();
        let sid = session.session.id;
        let grant = vault
            .create_grant(CreateGrantOptions {
                session_id: sid.clone(),
                credential_id: credential.id,
                policy: serde_json::from_value(seeded_policy()).unwrap(),
                ..Default::default()
            })
            .unwrap();
        let gid = grant.id;
        let marker = vault
            .issue_placeholder(IssueOptions {
                grant_id: gid.clone(),
                ..Default::default()
            })
            .unwrap()
            .placeholder;
        if patterns.is_some() {
            vault
                .add_credential(NewCredential {
                    slug: "pattern-source".into(),
                    kind: "http".into(),
                    connector: serde_json::from_value(json!({"host":"other.example.test"}))
                        .unwrap(),
                    fields: vec![(
                        "key".into(),
                        "fake-other-secret-0123456789".to_string().into(),
                    )],
                    sites: std::collections::BTreeMap::from([(
                        "key".into(),
                        vec!["header:x-key".into()],
                    )]),
                })
                .unwrap();
        }
        drop(vault);
        ported_common::seed_gateway_rows(dir.path(), &sid, &gid, &session_patch, &grant_patch);
        if let Some(patterns) = patterns {
            ported_common::seed_scrub_patterns(dir.path(), "pattern-source", &patterns);
        }

        if let Some(value) = tripwires {
            ported_common::seed_tripwires(dir.path(), &value);
        }
        let mut reopened = av_store::vault::Vault::open(dir.path()).unwrap();
        reopened.unlock(None).unwrap();
        let shared = Shared::new(reopened);
        let upstream = Arc::new(RecordingUpstream::default());
        let pipeline = av_daemon::pipeline::Pipeline::new(
            shared.clone(),
            PipelineOptions {
                upstream: Some(upstream.clone()),
                ..Default::default()
            },
        );
        let request = GatewayRequest {
            method: "GET".into(),
            path: "/p/seeded/ordinary".into(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), token),
                ("x-key".into(), marker),
            ],
            ..Default::default()
        };
        Self {
            _dir: dir,
            shared,
            pipeline,
            upstream,
            request,
            sid,
            gid,
        }
    }
    async fn snapshot(&self) -> Value {
        let sid = self.sid.clone();
        let gid = self.gid.clone();
        self.shared.run(move |core| json!({"session":core.vault.session(&sid).unwrap(),"grant":core.vault.grant(&gid).unwrap(),"placeholders":core.vault.list_placeholders(None).unwrap()})).await.unwrap()
    }
    async fn clean(&self, response: &GatewayResponse) {
        assert!(!String::from_utf8_lossy(&response.body).contains(SECRET));
        assert!(!serde_json::to_string(&response.headers)
            .unwrap()
            .contains(SECRET));
        self.shared
            .run(|core| {
                assert!(!serde_json::to_string(
                    &core
                        .vault
                        .audit()
                        .unwrap()
                        .read(&Default::default())
                        .unwrap()
                )
                .unwrap()
                .contains(SECRET));
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn stored_invalid_limits_and_quota_counters_fail_closed_without_consumption() {
    for (name, patch, rule) in [
        (
            "NaN rate serialized as null",
            json!({"rate":{"count":null,"per":"second"}}),
            "rate_invalid",
        ),
        (
            "string rate",
            json!({"rate":{"count":"5","per":"min"}}),
            "rate_invalid",
        ),
        (
            "fractional concurrency",
            json!({"max_concurrent":1.5}),
            "max_concurrent_invalid",
        ),
        (
            "NaN quota serialized as null",
            json!({"quota":{"count":null,"window":"day"}}),
            "quota_invalid",
        ),
        (
            "NaN budget serialized as null",
            json!({"budget":{"limit":null}}),
            "budget_invalid",
        ),
        (
            "corrupt quota counter",
            json!({"quota":{"count":10,"window":"hour"}}),
            "quota_invalid",
        ),
    ] {
        let mut policy = seeded_policy();
        for (k, v) in patch.as_object().unwrap() {
            policy[k] = v.clone();
        }
        let mut grant = json!({"policy":policy});
        if name == "corrupt quota counter" {
            grant["quota_state"] = json!({"window_ms":3600000,"start":0,"count":null,"prev":0});
        }
        let f = SeededGateway::new(json!({}), grant);
        let response = f.pipeline.handle(f.request.clone()).await;
        assert_eq!(response.status, 403, "{name}: {:?}", response.error);
        assert_eq!(
            response.error.as_ref().unwrap().extra.rule.as_deref(),
            Some(rule),
            "{name}"
        );
        assert!(f.upstream.hits.lock().unwrap().is_empty(), "{name}");
        let after = f.snapshot().await;
        assert_eq!(after["grant"]["budget_used"], 0, "{name}");
        assert_eq!(after["placeholders"][0]["uses"], 0, "{name}");
        f.clean(&response).await;
    }
    let control = SeededGateway::new(json!({}), json!({}));
    let response = control.pipeline.handle(control.request.clone()).await;
    assert_eq!(response.status, 200);
    control.clean(&response).await;
}

#[tokio::test]
async fn stored_decimal_budget_counts_twice_and_noncanonical_values_are_refused() {
    let mut policy = seeded_policy();
    policy["budget"]["limit"] = json!("2");
    let f = SeededGateway::new(json!({}), json!({"policy":policy}));
    for _ in 0..2 {
        let response = f.pipeline.handle(f.request.clone()).await;
        assert_eq!(response.status, 200);
        f.clean(&response).await;
    }
    let spent = f.pipeline.handle(f.request.clone()).await;
    assert_eq!(
        spent.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("budget")
    );
    f.clean(&spent).await;
    for value in [
        json!(""),
        json!("5.5"),
        json!("-1"),
        json!("1e3"),
        json!("abc"),
        json!("lots"),
        Value::Null,
    ] {
        let mut policy = seeded_policy();
        policy["budget"]["limit"] = value.clone();
        let f = SeededGateway::new(json!({}), json!({"policy":policy}));
        let response = f.pipeline.handle(f.request.clone()).await;
        assert_eq!(
            response.error.as_ref().unwrap().extra.rule.as_deref(),
            Some("budget_invalid"),
            "{value}"
        );
        assert!(f.upstream.hits.lock().unwrap().is_empty());
        f.clean(&response).await;
    }
}

#[tokio::test]
async fn stored_session_and_grant_expiry_predicates_agree_in_preflight_and_execution() {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        let iso = |offset| {
            (time::OffsetDateTime::now_utc() + time::Duration::seconds(offset))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        };
        let future = iso(3600);
        let past = iso(-60);
        for approval in ["auto", "each"] {
            for (name, expiry, infinite, expected) in [
                ("finite", json!(future), false, "allow"),
                ("expired", json!(past), false, "AV_SESSION_EXPIRED"),
                ("infinite", Value::Null, true, "allow"),
                (
                    "legacy absent expiry and false infinite",
                    Value::Null,
                    false,
                    "AV_SESSION_EXPIRED",
                ),
                ("invalid", json!("not a date"), false, "AV_SESSION_EXPIRED"),
            ] {
                let mut policy = seeded_policy();
                policy["approval"] = json!(approval);
                let f = SeededGateway::new(
                    json!({"expires_at":expiry,"infinite":infinite}),
                    json!({"policy":policy}),
                );
                let before = f.snapshot().await;
                let pre = f.pipeline.preflight(f.request.clone(), false).await;
                if expected == "allow" {
                    assert_eq!(
                        pre.unwrap()["would"],
                        if approval == "each" { "hold" } else { "allow" },
                        "{name}"
                    );
                } else {
                    assert_eq!(pre.unwrap_err().code.as_str(), expected, "{name}");
                }
                assert_eq!(
                    before,
                    f.snapshot().await,
                    "{name}: preflight mutated persistent state"
                );
                assert!(f.pipeline.pending_approvals().await.is_empty());
                let real = f.pipeline.handle(f.request.clone()).await;
                if expected == "allow" {
                    assert_eq!(
                        real.status,
                        if approval == "each" { 202 } else { 200 },
                        "{name}: {:?}",
                        real.error
                    );
                } else {
                    assert_eq!(
                        real.error.as_ref().unwrap().code.as_str(),
                        expected,
                        "{name}"
                    );
                }
                assert_eq!(
                    f.upstream.hits.lock().unwrap().len(),
                    usize::from(expected == "allow" && approval == "auto")
                );
                f.clean(&real).await;
            }
        }
        for (name, expiry, expected) in [
            ("no ttl", Value::Null, "allow"),
            ("future", json!(future), "allow"),
            ("past", json!(past), "AV_GRANT_EXPIRED"),
            ("garbage", json!("nope"), "AV_GRANT_EXPIRED"),
        ] {
            let f = SeededGateway::new(
                json!({"infinite":true,"expires_at":null}),
                json!({"expires_at":expiry}),
            );
            let before = f.snapshot().await;
            let pre = f
                .pipeline
                .preflight(f.request.clone(), false)
                .await
                .unwrap();
            if expected == "allow" {
                assert_eq!(pre["would"], "allow", "{name}");
            } else {
                assert_eq!(pre["would"], "deny", "{name}");
                assert_eq!(
                    pre["checks"].as_array().unwrap().last().unwrap()["code"],
                    expected,
                    "{name}"
                );
            }
            assert_eq!(
                before,
                f.snapshot().await,
                "{name}: preflight changed state"
            );
            let real = f.pipeline.handle(f.request.clone()).await;
            if expected == "allow" {
                assert_eq!(real.status, 200, "{name}");
            } else {
                assert_eq!(
                    real.error.as_ref().unwrap().code.as_str(),
                    expected,
                    "{name}"
                );
            }
            f.clean(&real).await;
        }
    })
    .await
    .expect("integration seam timed out");
}

#[tokio::test]
async fn store_marked_expired_grant_retains_its_specific_gateway_error() {
    let f = SeededGateway::new(json!({}), json!({"state":"expired"}));
    let response = f.pipeline.handle(f.request.clone()).await;
    assert_eq!(
        response.error.as_ref().unwrap().code.as_str(),
        "AV_GRANT_EXPIRED"
    );
    assert!(f.upstream.hits.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().await["placeholders"][0]["uses"], 0);
    f.clean(&response).await;
    let control = SeededGateway::new(json!({}), json!({}));
    let response = control.pipeline.handle(control.request.clone()).await;
    assert_eq!(response.status, 200);
    control.clean(&response).await;
}

#[tokio::test]
async fn redirect_guards_include_malformed_stored_maximum_and_per_request_approval() {
    for (name, patch, method, location, expected) in [
        (
            "foreign host",
            json!({"redirects":{"max":2}}),
            "GET",
            "https://evil.test/stolen",
            "host",
        ),
        (
            "foreign path",
            json!({"redirects":{"max":2},"paths":["/ordinary"]}),
            "GET",
            "/other",
            "path",
        ),
        (
            "plaintext downgrade",
            json!({"redirects":{"max":2}}),
            "GET",
            "http://api.example.test/ordinary",
            "scheme",
        ),
        (
            "write method",
            json!({"redirects":{"max":2}}),
            "POST",
            "/ordinary",
            "approval",
        ),
        (
            "NaN maximum serialized as null",
            json!({"redirects":{"max":null}}),
            "GET",
            "/ordinary",
            "max",
        ),
        (
            "per-request approval",
            json!({"redirects":{"max":2},"approval":"each"}),
            "GET",
            "/ordinary",
            "approval",
        ),
    ] {
        let mut policy = seeded_policy();
        for (k, v) in patch.as_object().unwrap() {
            policy[k] = v.clone();
        }
        let f = SeededGateway::new(json!({}), json!({"policy":policy}));
        *f.upstream.reply.lock().unwrap() = Some(redirect_reply(302, location));
        let mut req = f.request.clone();
        req.method = method.into();
        if name == "per-request approval" {
            let held = f.pipeline.handle(req.clone()).await;
            let id = held_id(&held);
            f.pipeline.decide_approval(id, true).await.unwrap();
            assert!(f.upstream.hits.lock().unwrap().is_empty());
        }
        let result = f.pipeline.handle(req).await;
        assert_eq!(result.status, 302, "{name}: {:?}", result.error);
        assert_eq!(
            result.header("av-redirect-stopped"),
            Some(expected),
            "{name}"
        );
        assert_eq!(f.upstream.hits.lock().unwrap().len(), 1, "{name}");
        f.clean(&result).await;
    }
    let mut policy = seeded_policy();
    policy["redirects"] = json!({"max":2});
    let control = SeededGateway::new(json!({}), json!({"policy":policy}));
    *control.upstream.sequence.lock().unwrap() =
        std::collections::VecDeque::from([Ok(redirect_reply(302, "/next")), Ok(done_reply())]);
    let response = control.pipeline.handle(control.request.clone()).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"done");
    assert_eq!(control.upstream.hits.lock().unwrap().len(), 2);
    control.clean(&response).await;
}

#[tokio::test]
async fn pin_problem_is_safe_and_refunded_and_real_profile_health_receives_metadata() {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        let f = Fixture::configured_kind(
            &["header:x-key"],
            SECRET,
            None,
            json!({}),
            "github",
            "api.github.com",
        )
        .await;
        *f.up.failure.lock().unwrap() = Some(UpstreamError {
            code: "AV_PIN_MISMATCH".into(),
            message: SECRET.into(),
            presented: vec!["sha256/presented".into()],
            ..Default::default()
        });
        let response = f.get().await;
        assert_eq!(
            response.error.as_ref().unwrap().code.as_str(),
            "AV_PIN_MISMATCH"
        );
        assert_eq!(response.error.as_ref().unwrap().extra.refunded, Some(true));
        assert_eq!(grant_counters(&f).await, (0, vec![0]));
        f.clean(&response).await;
        *f.up.failure.lock().unwrap() = None;
        *f.up.reply.lock().unwrap() = Some(Reply {
            streaming: false,
            status: 401,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                (
                    "github-authentication-token-expiration".into(),
                    "2027-01-31T00:00:00.000Z".into(),
                ),
            ],
            body: b"{}".to_vec(),
        });
        let executed = f.get().await;
        assert_eq!(executed.status, 401);
        f.shared
            .run(|core| {
                let health = serde_json::to_value(
                    core.vault
                        .find_credential("demo")
                        .unwrap()
                        .unwrap()
                        .health
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(health["status"], "unauthorized");
                assert_eq!(health["http_status"], 401);
                assert_eq!(health["source"], "response");
                let public = serde_json::to_value(core.vault.list_credentials().unwrap()).unwrap();
                assert_eq!(public[0]["health"]["status"], "unauthorized");
                assert_eq!(health["observed_expires_at"], "2027-01-31T00:00:00.000Z");
            })
            .await
            .unwrap();
        f.clean(&executed).await;
        f.reply(200, "application/json", "{}".into());
        let ordinary = f.get().await;
        assert_eq!(ordinary.status, 200);
        f.clean(&ordinary).await;
    })
    .await
    .expect("integration seam timed out");
}

#[tokio::test]
async fn malformed_tripwire_rules_keep_defaults_and_only_bad_location_requests_count() {
    use av_store::model::SessionState;
    let f = SeededGateway::with_tripwires(
        json!({}),
        json!({}),
        Some(json!({"enabled":true,"rules":"not a list"})),
    );
    for _ in 0..10 {
        let response = f.pipeline.handle(f.request.clone()).await;
        assert_eq!(response.status, 200);
        f.clean(&response).await;
    }
    let marker = f
        .request
        .headers
        .iter()
        .find(|(k, _)| k == "x-key")
        .unwrap()
        .1
        .clone();
    let mut bad = f.request.clone();
    bad.method = "POST".into();
    bad.headers
        .push(("content-type".into(), "application/json".into()));
    bad.body = Some(json!({"x":marker}).to_string().into_bytes());
    for n in 0..3 {
        let response = f.pipeline.handle(bad.clone()).await;
        assert_eq!(
            response.error.as_ref().unwrap().code.as_str(),
            "AV_BAD_LOCATION"
        );
        let sid = f.sid.clone();
        let state = f
            .shared
            .run(move |core| core.vault.session(&sid).unwrap().unwrap().state)
            .await
            .unwrap();
        assert_eq!(
            state,
            if n < 2 {
                SessionState::Active
            } else {
                SessionState::Revoked
            }
        );
        f.clean(&response).await;
    }
    assert_eq!(f.upstream.hits.lock().unwrap().len(), 10);
    assert_eq!(f.snapshot().await["placeholders"][0]["uses"], 10);
}

#[tokio::test]
async fn unissued_placeholder_replay_counts_only_after_session_authentication() {
    use av_core::placeholder::{mint, MintInput};
    use av_store::model::SessionState;
    let f = SeededGateway::with_tripwires(json!({}), json!({}), Some(json!({"enabled":true})));
    let sid = f.sid.clone();
    let marker = f
        .shared
        .run(move |core| {
            mint(&MintInput {
                k_ph: &core.vault.k_ph().unwrap(),
                sid: &sid,
                slug: "seeded",
                field: "key",
            })
            .unwrap()
            .text
        })
        .await
        .unwrap();
    let mut unauthenticated = f.request.clone();
    unauthenticated.headers = vec![
        ("host".into(), "localhost".into()),
        ("x-key".into(), marker),
    ];
    for _ in 0..3 {
        let response = f.pipeline.handle(unauthenticated.clone()).await;
        assert_eq!(
            response.error.as_ref().unwrap().code.as_str(),
            "AV_PH_REPLAY"
        );
        f.clean(&response).await;
    }
    let sid = f.sid.clone();
    f.shared
        .run(move |core| {
            assert_eq!(
                core.vault.session(&sid).unwrap().unwrap().state,
                SessionState::Active
            );
            let row = core.vault.list_placeholders(Some(&sid)).unwrap().remove(0);
            core.vault
                .burn_placeholder(&row.id, "fixture replay")
                .unwrap();
        })
        .await
        .unwrap();
    let response = f.pipeline.handle(f.request.clone()).await;
    assert_eq!(
        response.error.as_ref().unwrap().code.as_str(),
        "AV_PH_REPLAY"
    );
    f.clean(&response).await;
    let sid = f.sid.clone();
    f.shared
        .run(move |core| {
            assert_eq!(
                core.vault.session(&sid).unwrap().unwrap().state,
                SessionState::Revoked
            )
        })
        .await
        .unwrap();
    assert!(f.upstream.hits.lock().unwrap().is_empty());
    let ordinary =
        SeededGateway::with_tripwires(json!({}), json!({}), Some(json!({"enabled":true})));
    let response = ordinary.pipeline.handle(ordinary.request.clone()).await;
    assert_eq!(response.status, 200);
    ordinary.clean(&response).await;
}

#[tokio::test]
async fn pending_notice_contains_only_safe_summary_and_refusing_webhook_cannot_release_request() {
    use tokio::io::AsyncWriteExt;
    for status in [200, 503] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (_, body) = read_wire_request(&mut socket).await;
            assert!(!String::from_utf8_lossy(&body).contains(SECRET));
            socket.write_all(format!("HTTP/1.1 {status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        });
        let f = approval_fixture("each", &["header:x-key"]).await;
        let mut notices = f
            .shared
            .run(move |core| {
                core.vault
                    .set_notify_webhook(
                        &format!("http://127.0.0.1:{port}/hook").into(),
                        av_store::model::NotifyDetail::Headline,
                    )
                    .unwrap();
                core.notifier.as_ref().unwrap().subscribe(vec![]).unwrap()
            })
            .await
            .unwrap();
        assert!(notices.recv().await.unwrap().starts_with("event: snapshot"));
        let held = f
            .send(
                "GET",
                "/ordinary",
                vec![
                    ("x-key".into(), f.ph.clone()),
                    ("av-reason".into(), "please <script>".into()),
                ],
                None,
            )
            .await;
        let id = held_id(&held);
        let frame = notices.recv().await.unwrap();
        let notice = payloads(&frame).next().unwrap();
        let mut keys = notice
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["created_at", "headline", "id", "kind"]);
        assert_eq!(notice["id"], id);
        assert_eq!(notice["kind"], "request");
        for unsafe_text in [SECRET, f.ph.as_str(), "script"] {
            assert!(!frame.contains(unsafe_text));
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        if status == 503 {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if audit_records(&f)
                        .await
                        .iter()
                        .any(|r| r["kind"] == "notify.failed")
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        let pending = f.daemon.pipeline().pending_approvals().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["id"], id);
        assert_eq!(grant_counters(&f).await, (0, vec![0]));
        assert!(f.up.hits.lock().unwrap().is_empty());
        f.clean(&held).await;
        f.daemon.pipeline().decide_approval(id, true).await.unwrap();
        let allowed = f.get().await;
        assert_eq!(allowed.status, 200);
        f.clean(&allowed).await;
    }
}

#[tokio::test]
async fn failing_tripwire_quarantine_write_preserves_original_agent_denial() {
    use av_store::model::SessionState;
    // Legacy rule id reaches set_quarantine, whose actual store validation
    // returns an error; pl_fail must preserve the original security denial.
    let f = SeededGateway::with_tripwires(
        json!({}),
        json!({}),
        Some(
            json!({"enabled":true,"rules":[{"id":"not allowed!","codes":["AV_BAD_LOCATION"],"threshold":1,"window_s":10,"action":"quarantine_credential"}]}),
        ),
    );
    let ordinary = f.pipeline.handle(f.request.clone()).await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
    let sid = f.sid.clone();
    f.shared
        .run(move |core| {
            let error = core
                .vault
                .set_quarantine(
                    "seeded",
                    av_store::vault::QuarantineOptions {
                        rule_id: Some("not allowed!".into()),
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert!(error.to_string().contains("rule id"));
            assert_eq!(
                core.vault.session(&sid).unwrap().unwrap().state,
                SessionState::Active
            );
        })
        .await
        .unwrap();
    let mut bad = f.request.clone();
    bad.method = "POST".into();
    bad.headers
        .push(("content-type".into(), "application/json".into()));
    let marker = bad
        .headers
        .iter()
        .find(|(k, _)| k == "x-key")
        .unwrap()
        .1
        .clone();
    bad.body = Some(json!({"x":marker}).to_string().into_bytes());
    let response = f.pipeline.handle(bad).await;
    assert_eq!(response.status, 403);
    assert_eq!(
        response.error.as_ref().unwrap().code.as_str(),
        "AV_BAD_LOCATION"
    );
    assert_eq!(f.upstream.hits.lock().unwrap().len(), 1);
    f.clean(&response).await;
    let control = f.pipeline.handle(f.request.clone()).await;
    assert_eq!(control.status, 200);
    f.clean(&control).await;
}

#[tokio::test]
async fn global_custom_patterns_scrub_other_credentials_and_corrupt_sources_withhold_output() {
    let custom = "xyz_CUSTOM123456";
    for (name, source) in [("valid", "xyz_[A-Z0-9]{6,30}"), ("corrupt", "(a+)+")] {
        let f = SeededGateway::configured(
            json!({}),
            json!({}),
            None,
            Some(
                json!([{"id":"sp_fixture","source":source,"added_at":"2026-01-01T00:00:00.000Z"}]),
            ),
        );
        *f.upstream.reply.lock().unwrap() = Some(Reply {
            streaming: false,
            status: 200,
            headers: vec![("x-test".into(), custom.into())],
            body: format!("{custom} ordinary").into_bytes(),
        });
        let response = f.pipeline.handle(f.request.clone()).await;
        if name == "valid" {
            assert_eq!(response.status, 200);
            assert!(String::from_utf8_lossy(&response.body).contains("ordinary"));
            assert!(!String::from_utf8_lossy(&response.body).contains(custom));
            assert!(!serde_json::to_string(&response.headers)
                .unwrap()
                .contains(custom));
            *f.upstream.failure.lock().unwrap() = Some(UpstreamError::new(
                "ECONNREFUSED",
                format!("refused for {custom}"),
            ));
            let failed = f.pipeline.handle(f.request.clone()).await;
            assert_eq!(
                failed.error.as_ref().unwrap().code.as_str(),
                "AV_UPSTREAM_UNREACHABLE"
            );
            assert!(!String::from_utf8_lossy(&failed.body).contains(custom));
            f.clean(&failed).await;
        } else {
            assert_eq!(
                response.error.as_ref().unwrap().extra.rule.as_deref(),
                Some("scrub_pattern_invalid")
            );
            assert!(!String::from_utf8_lossy(&response.body).contains(custom));
        }
        f.clean(&response).await;
        f.shared
            .run(move |core| {
                let audit = serde_json::to_string(
                    &core
                        .vault
                        .audit()
                        .unwrap()
                        .read(&Default::default())
                        .unwrap(),
                )
                .unwrap();
                assert!(!audit.contains(custom));
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn custom_pattern_redacts_error_and_single_event_and_cuts_split_stream_with_prefix_control() {
    let custom = format!("acme_{}", "K".repeat(30));
    let f = Fixture::new(&["header:x-key"]).await;
    f.shared
        .run(|core| {
            core.vault
                .add_scrub_pattern("demo", "acme_[A-Z]{20,40}")
                .unwrap()
        })
        .await
        .unwrap();
    *f.up.failure.lock().unwrap() = Some(UpstreamError::new(
        "ECONNREFUSED",
        format!("refused for {custom}"),
    ));
    let failed = f.get().await;
    assert_eq!(
        failed.error.as_ref().unwrap().code.as_str(),
        "AV_UPSTREAM_UNREACHABLE"
    );
    assert!(!String::from_utf8_lossy(&failed.body).contains(&custom));
    f.clean(&failed).await;
    *f.up.failure.lock().unwrap() = None;
    for (events, cut) in [
        (data(json!({"text":custom})), false),
        (
            format!(
                "{}{}",
                data(json!({"d":&custom[..12]})),
                data(json!({"d":&custom[12..]}))
            ),
            true,
        ),
        (data(json!({"text":"we use acme_ tooling"})), false),
    ] {
        let ordinary = events.contains("tooling");
        stream_reply(&f, &events, false);
        let response = drain(f.get().await).await;
        let text = String::from_utf8_lossy(&response.body);
        assert!(!text.contains(&custom));
        assert_eq!(text.contains("AV_UNSCANNABLE"), cut);
        if ordinary {
            assert_eq!(text, events);
        }
        f.clean(&response).await;
    }
    let log = serde_json::to_string(&audit_records(&f).await).unwrap();
    assert!(!log.contains(&custom));
}

#[tokio::test]
async fn panic_denies_held_work_then_revokes_finite_and_infinite_sessions_before_record_and_lock() {
    tokio::time::timeout(std::time::Duration::from_secs(40),async {
    use av_store::model::SessionState;
    let f = approval_fixture("each", &["header:x-key"]).await;
    let held = f.get().await;
    let id = held_id(&held);
    f.clean(&held).await;
    f.shared
        .run(|core| {
            core.vault
                .create_session(av_store::vault::CreateSessionOptions {
                    infinite: true,
                    ..Default::default()
                })
                .unwrap();
            for reason in ["first", "second"] {
                core.sr_propose(json!({"cred":"demo"}), Some(reason.into()), false)
                    .unwrap();
            }
            assert_eq!(core.sr_pending().len(), 2);
        })
        .await
        .unwrap();
    let out = f
        .daemon
        .pipeline()
        .panic(Some("it looked wrong".into()), true)
        .await
        .unwrap();
    assert_eq!(
        out,
        json!({"revoked_sessions":2,"denied_approvals":1,"denied_session_requests":2,"locked":true})
    );
    let e = f.daemon.pipeline().panic(None, false).await.unwrap_err();
    assert_eq!(e.code.as_str(), "AV_LOCKED");
    f.shared
        .run(move |core| {
            assert!(core.vault.locked());
            assert!(core
                .vault
                .sessions()
                .unwrap()
                .iter()
                .all(|s| s.state == SessionState::Revoked));
            let approval = core.pl.approvals.iter().find(|(_, a)| a.id == id).unwrap();
            assert_eq!(approval.1.state, "denied");
            assert_eq!(approval.1.denied_reason.as_deref(), Some("panic"));
            assert!(core.sr_pending().is_empty());
        })
        .await
        .unwrap();
    let mut reopened = av_store::vault::Vault::open(f._dir.path()).unwrap();
    reopened.unlock(None).unwrap();
    let rows = reopened
        .audit()
        .unwrap()
        .read(&av_store::audit::ReadFilter {
            limit: 1000,
            ..Default::default()
        })
        .unwrap();
    let rows = serde_json::to_value(rows).unwrap();
    let mut rows = rows.as_array().unwrap().clone();
    rows.sort_by_key(|r| r["seq"].as_u64().unwrap());
    let positions = |kind: &str| {
        rows.iter()
            .enumerate()
            .filter_map(|(i, r)| (r["kind"] == kind).then_some(i))
            .collect::<Vec<_>>()
    };
    let denied = positions("approval.denied");
    let revoked = positions("session.revoked");
    let requests = positions("session_request.denied");
    let panic = positions("panic.triggered");
    assert_eq!(denied.len(), 1);
    assert_eq!(revoked.len(), 2);
    assert_eq!(requests.len(), 2);
    assert_eq!(panic.len(), 1);
        assert_eq!(rows[panic[0]]["denied_session_requests"],2);
    assert!(denied[0] < *revoked.iter().min().unwrap());
    assert!(*revoked.iter().max().unwrap() < *requests.iter().min().unwrap());
    assert!(*requests.iter().max().unwrap() < panic[0]);
    assert!(!serde_json::to_string(&rows).unwrap().contains(SECRET));
    assert!(f.up.hits.lock().unwrap().is_empty());
    let ordinary = Fixture::new(&["header:x-key"]).await;
    let response = ordinary.get().await;
    assert_eq!(response.status, 200);
    ordinary.clean(&response).await;

    }).await.expect("integration seam timed out");
}

#[tokio::test]
async fn real_session_request_metadata_failure_does_not_prevent_panic_revocation_and_partial_record(
) {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        use av_store::model::SessionState;
        let (_dir, shared, pipeline, sid) = panic_failure_fixture();
        shared
            .run(|core| {
                assert_eq!(core.sr_pending().len(), 1);
                assert!(
                    core.dm_deny_pending_session_requests("fixture probe")
                        .is_err(),
                    "the side-system fixture must actually fail"
                );
            })
            .await
            .unwrap();
        let out = pipeline.panic(None, false).await.unwrap();
        assert_eq!(out["revoked_sessions"], 1);
        assert!(out["denied_session_requests"].is_null());
        shared
            .run(move |core| {
                assert_eq!(
                    core.vault.session(&sid).unwrap().unwrap().state,
                    SessionState::Revoked
                );
                let audit = core
                    .vault
                    .audit()
                    .unwrap()
                    .read(&av_store::audit::ReadFilter {
                        limit: 1000,
                        ..Default::default()
                    })
                    .unwrap();
                let audit = serde_json::to_value(audit).unwrap();
                let rows = audit.as_array().unwrap();
                assert_eq!(
                    rows.iter()
                        .filter(|r| r["kind"] == "tripwire.panic_partial")
                        .count(),
                    1
                );
                assert_eq!(
                    rows.iter()
                        .filter(|r| r["kind"] == "panic.triggered")
                        .count(),
                    1
                );
                assert!(rows
                    .iter()
                    .find(|r| r["kind"] == "panic.triggered")
                    .unwrap()["denied_session_requests"]
                    .is_null());
                assert!(!serde_json::to_string(&audit).unwrap().contains(SECRET));
            })
            .await
            .unwrap();
        let ordinary = SeededGateway::new(json!({}), json!({}));
        let clean = ordinary.pipeline.panic(None, false).await.unwrap();
        assert_eq!(clean["revoked_sessions"], 1);
        assert_eq!(clean["denied_session_requests"], 0);
    })
    .await
    .expect("integration seam timed out");
}

fn panic_failure_fixture() -> (
    tempfile::TempDir,
    VaultRef,
    av_daemon::pipeline::Pipeline,
    String,
) {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
    vault
        .add_credential(av_store::vault::NewCredential {
            slug: "broken-health".into(),
            kind: "http".into(),
            connector: serde_json::from_value(json!({"host":"api.example.test"})).unwrap(),
            fields: vec![("key".into(), SECRET.to_string().into())],
            sites: std::collections::BTreeMap::from([("key".into(), vec!["header:x-key".into()])]),
        })
        .unwrap();
    let sid = vault.create_session(Default::default()).unwrap().session.id;
    drop(vault);
    ported_common::seed_panic_side_system_failure(dir.path());
    let mut vault = av_store::vault::Vault::open(dir.path()).unwrap();
    vault.unlock(None).unwrap();
    let shared = Shared::new(vault);
    let pipeline = av_daemon::pipeline::Pipeline::new(shared.clone(), Default::default());
    (dir, shared, pipeline, sid)
}

#[tokio::test]
async fn tripwire_panic_is_opt_in_and_reports_real_success_and_failure_counts() {
    use av_daemon::tripwire::Observation;
    use av_store::model::SessionState;
    for enabled in [false, true] {
        let f = SeededGateway::with_tripwires(
            json!({}),
            json!({}),
            Some(
                json!({"enabled":enabled,"rules":[{"id":"panic","codes":["AV_PH_REPLAY"],"threshold":1,"window_s":10,"action":"panic"}]}),
            ),
        );
        let sid = f.sid.clone();
        f.shared
            .run(move |core| {
                for _ in 0..3 {
                    core.sr_propose(json!({"cred":"seeded"}), None, false)
                        .unwrap();
                }
                let rule = core
                    .tw_observe(&Observation {
                        session_id: sid.clone(),
                        code: "AV_PH_REPLAY".into(),
                        ..Default::default()
                    })
                    .unwrap();
                assert_eq!(rule.is_some(), enabled);
                assert_eq!(
                    core.vault.session(&sid).unwrap().unwrap().state,
                    if enabled {
                        SessionState::Revoked
                    } else {
                        SessionState::Active
                    }
                );
                if enabled {
                    assert_eq!(
                        core.tw.last_panic.as_ref().unwrap()["denied_session_requests"],
                        3
                    );
                    assert!(core.sr_pending().is_empty());
                } else {
                    assert!(core.tw.last_panic.is_none());
                    assert_eq!(core.sr_pending().len(), 3);
                }
            })
            .await
            .unwrap();
        let response = f.pipeline.handle(f.request.clone()).await;
        if enabled {
            assert_eq!(
                response.error.as_ref().unwrap().code.as_str(),
                "AV_SESSION_REVOKED"
            );
        } else {
            assert_eq!(response.status, 200);
        }
        f.clean(&response).await;
    }
    let (_dir, shared, _pipeline, sid) = panic_failure_fixture();
    shared.run(move |core| {
        core.vault.update_settings(&json!({"tripwires":{"enabled":true,"rules":[{"id":"panic","codes":["AV_PH_REPLAY"],"threshold":1,"window_s":10,"action":"panic"}]}})).unwrap();
        let fired=core.tw_observe(&Observation{session_id:sid.clone(),code:"AV_PH_REPLAY".into(),..Default::default()}).unwrap();assert!(fired.is_some());
        assert_eq!(core.vault.session(&sid).unwrap().unwrap().state,SessionState::Revoked);
        assert!(core.tw.last_panic.as_ref().unwrap()["denied_session_requests"].is_null());
        let records=serde_json::to_value(core.vault.audit().unwrap().read(&av_store::audit::ReadFilter{limit:1000,..Default::default()}).unwrap()).unwrap();
        assert_eq!(records.as_array().unwrap().iter().filter(|r|r["kind"]=="tripwire.panic_partial").count(),1);
        assert!(!serde_json::to_string(&records).unwrap().contains(SECRET));
    }).await.unwrap();
}

#[tokio::test]
async fn preflight_bad_location_denials_do_not_trip_and_eleventh_call_is_throttled() {
    // Use a real monotonic bucket. Retry a fresh fixture only if scheduling
    // paused this process long enough to cross its one-second boundary.
    let mut checked = false;
    for _ in 0..4 {
        let f = SeededGateway::with_tripwires(json!({}), json!({}), Some(json!({"enabled":true})));
        let mut bad = f.request.clone();
        bad.method = "POST".into();
        bad.body = Some(
            bad.headers
                .iter()
                .find(|(k, _)| k == "x-key")
                .unwrap()
                .1
                .as_bytes()
                .to_vec(),
        );
        let before = f.snapshot().await;
        let at = std::time::Instant::now();
        for _ in 0..10 {
            let pre = f.pipeline.preflight(bad.clone(), false).await.unwrap();
            assert_eq!(pre["would"], "deny");
        }
        if at.elapsed() >= std::time::Duration::from_millis(900) {
            continue;
        }
        let last = f.pipeline.preflight(bad, false).await;
        if at.elapsed() >= std::time::Duration::from_secs(1) {
            continue;
        }
        let error = last.unwrap_err();
        assert_eq!(error.extra.rule.as_deref(), Some("preflight_rate"));
        assert_eq!(
            before,
            f.snapshot().await,
            "preflight denials must not change session or consumption state"
        );
        assert!(f.upstream.hits.lock().unwrap().is_empty());
        assert!(f.pipeline.pending_approvals().await.is_empty());
        checked = true;
        break;
    }
    assert!(
        checked,
        "scheduler prevented four complete preflight rate windows"
    );
    let ordinary =
        SeededGateway::with_tripwires(json!({}), json!({}), Some(json!({"enabled":true})));
    assert_eq!(
        ordinary
            .pipeline
            .preflight(ordinary.request.clone(), false)
            .await
            .unwrap()["would"],
        "allow"
    );
    let response = ordinary.pipeline.handle(ordinary.request.clone()).await;
    assert_eq!(response.status, 200);
    ordinary.clean(&response).await;
}

#[tokio::test]
async fn real_health_write_contention_preserves_executed_response_consumption_and_audit() {
    let f = Fixture::new(&["header:x-key"]).await;
    f.reply(401, "application/json", "{}".into());
    let gate = Arc::new(tokio::sync::Notify::new());
    *f.up.gate.lock().unwrap() = Some(gate.clone());
    let request = f.get();
    tokio::pin!(request);
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        tokio::select! {
            _=&mut request=>panic!("upstream did not wait"),
            _=async {loop {if !f.up.hits.lock().unwrap().is_empty(){break;}tokio::task::yield_now().await;}}=>{}
        }
    }).await.unwrap();
    // Consume and charge have finished before send; only response-side work
    // competes with this real SQLite writer. RAII also releases on panic.
    assert_eq!(grant_counters(&f).await, (1, vec![1]));
    let lock = ported_common::TempWriteLock::acquire(f._dir.path());
    gate.notify_one();
    let response = tokio::select! {
        response=&mut request=>{drop(lock);response},
        _=tokio::time::sleep(std::time::Duration::from_secs(6))=>{
            drop(lock);
            tokio::time::timeout(std::time::Duration::from_secs(5),&mut request).await.unwrap()
        }
    };
    assert_eq!(
        response.status, 401,
        "health failure changed an executed response: {:?}",
        response.error
    );
    assert_eq!(response.body, b"{}");
    assert_eq!(grant_counters(&f).await, (1, vec![1]));
    f.shared
        .run(|core| {
            assert!(
                core.vault
                    .find_credential("demo")
                    .unwrap()
                    .unwrap()
                    .health
                    .is_none(),
                "fixture must actually prevent the health write"
            )
        })
        .await
        .unwrap();
    let rows = audit_records(&f).await;
    assert_eq!(
        rows.iter()
            .filter(|r| r["kind"] == "request.allowed" && r["req"]["status"] == 401)
            .count(),
        1
    );
    f.clean(&response).await;
    *f.up.gate.lock().unwrap() = None;
    let control = f.get().await;
    assert_eq!(control.status, 401);
    assert_eq!(grant_counters(&f).await, (2, vec![2]));
    f.shared
        .run(|core| {
            assert!(core
                .vault
                .find_credential("demo")
                .unwrap()
                .unwrap()
                .health
                .is_some())
        })
        .await
        .unwrap();
    f.clean(&control).await;
    f.reply(200, "application/json", "{}".into());
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn pipeline_confinement_rejects_foreign_host_path_and_profile_webhook_before_wire() {
    let f = Fixture::configured_kind(
        &["header:authorization:Bearer"],
        SECRET,
        None,
        json!({"paths":["/user","/repos/allowed/**"]}),
        "github",
        "api.github.com",
    )
    .await;
    for (name, path, rule, code) in [
        (
            "foreign host",
            "/t/https/evil.test/steal",
            None,
            "AV_NO_GRANT",
        ),
        (
            "foreign path",
            "/p/demo/repos/someone-else/private",
            Some("paths"),
            "AV_POLICY_DENIED",
        ),
    ] {
        let mut request = gateway_input(&f, "GET", "/user", "", None, None);
        request.path = path.into();
        request.headers.retain(|(k, _)| k != "x-key");
        request
            .headers
            .push(("authorization".into(), format!("Bearer {}", f.ph)));
        let response = f.daemon.pipeline().handle(request).await;
        assert_eq!(response.status, 403, "{name}");
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.code.as_str(), code, "{name}");
        if let Some(rule) = rule {
            assert_eq!(error.extra.rule.as_deref(), Some(rule), "{name}");
        }
        assert!(f.up.hits.lock().unwrap().is_empty());
        assert_eq!(grant_counters(&f).await, (0, vec![0]));
        f.clean(&response).await;
    }
    let allowed = f
        .send(
            "GET",
            "/user",
            vec![("authorization".into(), format!("Bearer {}", f.ph))],
            None,
        )
        .await;
    assert_eq!(allowed.status, 200);
    f.clean(&allowed).await;
    let wide = Fixture::configured_kind(
        &["header:authorization:Bearer"],
        SECRET,
        None,
        json!({}),
        "github",
        "api.github.com",
    )
    .await;
    let denied = wide
        .send(
            "POST",
            "/repos/allowed/project/hooks",
            vec![("authorization".into(), format!("Bearer {}", wide.ph))],
            None,
        )
        .await;
    assert_eq!(denied.status, 403);
    assert!(denied
        .error
        .as_ref()
        .unwrap()
        .extra
        .rule
        .as_deref()
        .unwrap()
        .starts_with("deny_paths"));
    assert!(wide.up.hits.lock().unwrap().is_empty());
    wide.clean(&denied).await;
    let control = wide
        .send(
            "POST",
            "/repos/allowed/project/issues",
            vec![("authorization".into(), format!("Bearer {}", wide.ph))],
            None,
        )
        .await;
    assert_eq!(control.status, 200);
    wide.clean(&control).await;
}

#[tokio::test]
async fn pipeline_encoded_body_and_parser_hidden_placeholder_shapes_never_reach_upstream() {
    use base64::Engine;
    let f = Fixture::new(&["header:x-key"]).await;
    let encodings = [
        (
            "base64",
            base64::engine::general_purpose::STANDARD.encode(&f.ph),
        ),
        (
            "base64url",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&f.ph),
        ),
        (
            "base64 offset",
            base64::engine::general_purpose::STANDARD.encode(format!("xy{}", f.ph)),
        ),
        ("percent", f.ph.replace('.', "%2e")),
        (
            "JSON escapes",
            f.ph.chars()
                .map(|c| format!("\\u{:04x}", c as u32))
                .collect::<String>(),
        ),
    ];
    for (name, text) in encodings {
        let response = f
            .post("application/json", format!("{{\"body\":\"{text}\"}}"))
            .await;
        assert_eq!(response.status, 403, "{name}");
        assert_eq!(
            response.error.as_ref().unwrap().code.as_str(),
            "AV_BAD_LOCATION",
            "{name}"
        );
        f.clean(&response).await;
    }
    for name in [
        "JSON body value",
        "request path",
        "header name",
        "query name",
        "form name",
        "JSON key",
        "shadowed JSON value",
        "malformed query key",
    ] {
        let mut req = gateway_input(&f, "POST", "/ordinary", "", None, None);
        req.headers.retain(|(k, _)| k != "x-key");
        match name {
            "JSON body value" => {
                req.headers
                    .push(("content-type".into(), "application/json".into()));
                req.body = Some(
                    json!({"body":format!("my token is {}",f.ph)})
                        .to_string()
                        .into_bytes(),
                );
            }
            "request path" => req.path = format!("/p/demo/repos/{}", f.ph),
            "header name" => req.headers.push((format!("x-{}", f.ph), "1".into())),
            "query name" => req.query = format!("{}=1", f.ph),
            "form name" => {
                req.headers.push((
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ));
                req.body = Some(format!("{}=1", f.ph).into_bytes());
            }
            "JSON key" => {
                req.headers
                    .push(("content-type".into(), "application/json".into()));
                req.body = Some(json!({f.ph.clone():"x"}).to_string().into_bytes());
            }
            "shadowed JSON value" => {
                req.headers
                    .push(("content-type".into(), "application/json".into()));
                req.body =
                    Some(format!("{{\"note\":\"{}\",\"note\":\"harmless\"}}", f.ph).into_bytes());
            }
            "malformed query key" => req.query = format!("bad%={}", f.ph),
            _ => unreachable!(),
        }
        let response = f.daemon.pipeline().handle(req).await;
        assert_eq!(response.status, 403, "{name}: {:?}", response.error);
        assert_eq!(
            response.error.as_ref().unwrap().code.as_str(),
            "AV_BAD_LOCATION",
            "{name}"
        );
        if name == "JSON body value" {
            let error = response.error.as_ref().unwrap();
            assert!(error.detail.contains("JSON body at /body"));
            assert!(error
                .extra
                .hint
                .as_deref()
                .unwrap()
                .contains("only ever injected at"));
        }
        f.clean(&response).await;
    }
    assert!(f.up.hits.lock().unwrap().is_empty());
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn twenty_racing_one_shot_uses_send_exactly_once_and_successors_remain_one_shot() {
    let f = Fixture::new(&["header:x-key"]).await;
    let once = f.mint(Some(1)).await;
    let mut attempts = Vec::new();
    for _ in 0..20 {
        let daemon = f.daemon.clone();
        let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
        req.headers
            .iter_mut()
            .find(|(k, _)| k == "x-key")
            .unwrap()
            .1 = once.clone();
        attempts.push(tokio::spawn(
            async move { daemon.pipeline().handle(req).await },
        ));
    }
    let mut success = None;
    for attempt in attempts {
        let response = attempt.await.unwrap();
        if response.status == 200 {
            assert!(success.is_none());
            success = Some(response);
        } else {
            assert_eq!(response.status, 401);
            assert_eq!(
                response.error.as_ref().unwrap().code.as_str(),
                "AV_PH_EXHAUSTED"
            );
            f.clean(&response).await;
        }
    }
    let success = success.unwrap();
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&success).await;
    let successor = success.header("av-placeholder-next").unwrap().to_string();
    let gid = f.grant_id.clone();
    f.shared
        .run(move |core| {
            let rows = core.vault.list_placeholders(None).unwrap();
            let successors = rows
                .iter()
                .filter(|p| p.grant_id == gid && p.replaces_id.is_some())
                .collect::<Vec<_>>();
            assert_eq!(successors.len(), 1);
            assert_eq!(successors[0].max_uses, 1);
        })
        .await
        .unwrap();
    for expected in [200, 401] {
        let response = f
            .send(
                "GET",
                "/ordinary",
                vec![("x-key".into(), successor.clone())],
                None,
            )
            .await;
        assert_eq!(response.status, expected);
        if expected == 401 {
            assert_eq!(
                response.error.as_ref().unwrap().code.as_str(),
                "AV_PH_EXHAUSTED"
            );
        }
        f.clean(&response).await;
    }
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn cross_session_placeholders_and_bare_remote_carriers_are_refused_with_legitimate_controls()
{
    use av_store::vault::{CreateGrantOptions, IssueOptions};
    let f = Fixture::new(&["header:x-key"]).await;
    let foreign = f
        .shared
        .run(|core| {
            let other = core.vault.create_session(Default::default()).unwrap();
            let credential = core.vault.find_credential("demo").unwrap().unwrap();
            let grant = core
                .vault
                .create_grant(CreateGrantOptions {
                    session_id: other.session.id,
                    credential_id: credential.id,
                    policy: serde_json::from_value(seeded_policy()).unwrap(),
                    ..Default::default()
                })
                .unwrap();
            core.vault
                .issue_placeholder(IssueOptions {
                    grant_id: grant.id,
                    ..Default::default()
                })
                .unwrap()
                .placeholder
        })
        .await
        .unwrap();
    let cross = f
        .send("GET", "/ordinary", vec![("x-key".into(), foreign)], None)
        .await;
    assert_eq!(cross.status, 403);
    assert_eq!(
        cross.error.as_ref().unwrap().code.as_str(),
        "AV_PH_CROSS_SESSION"
    );
    assert!(f.up.hits.lock().unwrap().is_empty());
    f.clean(&cross).await;
    for (name, remote, token, expected) in [
        ("loopback bare", false, false, 200),
        ("network bare", true, false, 401),
        ("network explicit token", true, true, 200),
    ] {
        let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
        if !token {
            req.headers.retain(|(k, _)| k != "av-session");
        }
        req.listener = Some(av_daemon::pipeline::ListenerInfo {
            id: if remote { "remote" } else { "local" }.into(),
            kind: if remote { "tls" } else { "tcp" }.into(),
            remote,
            advertise: vec![],
        });
        let response = f.daemon.pipeline().handle(req).await;
        assert_eq!(response.status, expected, "{name}: {:?}", response.error);
        if expected == 401 {
            let e = response.error.as_ref().unwrap();
            assert_eq!(e.code.as_str(), "AV_SESSION_REQUIRED");
            assert_eq!(e.extra.rule.as_deref(), Some("remote_carrier"));
            assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        }
        f.clean(&response).await;
    }
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn approval_pending_capacity_is_bounded_and_expired_entries_release_the_cap() {
    let f = approval_fixture("each", &["header:x-key"]).await;
    for n in 0..av_daemon::pipeline::MAX_APPROVALS {
        let response = f
            .send(
                "GET",
                &format!("/pending/{n}"),
                vec![("x-key".into(), f.ph.clone())],
                None,
            )
            .await;
        assert_eq!(response.status, 202, "held {n}");
    }
    let capped = f
        .send(
            "GET",
            "/over-cap",
            vec![("x-key".into(), f.ph.clone())],
            None,
        )
        .await;
    assert_eq!(capped.status, 403);
    assert!(capped
        .error
        .as_ref()
        .unwrap()
        .detail
        .contains("waiting for approval"));
    assert_eq!(f.daemon.pipeline().pending_approvals().await.len(), 1000);
    assert!(f.up.hits.lock().unwrap().is_empty());
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    f.clean(&capped).await;
    f.shared
        .run(|core| {
            let old = (time::OffsetDateTime::now_utc() - time::Duration::minutes(20))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            for (_, approval) in &mut core.pl.approvals {
                approval.created_at = old.clone();
            }
        })
        .await
        .unwrap();
    let fresh = f
        .send(
            "GET",
            "/new-after-sweep",
            vec![("x-key".into(), f.ph.clone())],
            None,
        )
        .await;
    assert_eq!(fresh.status, 202);
    let id = held_id(&fresh);
    let pending = f.daemon.pipeline().pending_approvals().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["id"], id);
    f.clean(&fresh).await;
    f.daemon.pipeline().decide_approval(id, true).await.unwrap();
    let control = f
        .send(
            "GET",
            "/new-after-sweep",
            vec![("x-key".into(), f.ph.clone())],
            None,
        )
        .await;
    assert_eq!(control.status, 200);
    f.clean(&control).await;
}

#[tokio::test]
async fn refunds_require_a_live_grant_and_both_refund_decisions_are_audited() {
    for revoked in [false, true] {
        let f = Fixture::new(&["header:x-key"]).await;
        let _ = f.mint(Some(1)).await;
        let token = f.token.clone();
        let gid = f.grant_id.clone();
        f.shared
            .run(move |core| {
                let row = core
                    .vault
                    .list_placeholders(None)
                    .unwrap()
                    .into_iter()
                    .find(|p| p.grant_id == gid && p.max_uses == 1)
                    .unwrap();
                core.vault.consume_placeholder(&row.id).unwrap();
                assert_eq!(
                    core.vault
                        .list_placeholders(None)
                        .unwrap()
                        .iter()
                        .find(|p| p.id == row.id)
                        .unwrap()
                        .uses,
                    1
                );
                if revoked {
                    let sid = core.vault.session_by_token(&token).unwrap().unwrap().id;
                    core.vault
                        .revoke_session(&sid, "fixture revocation")
                        .unwrap();
                }
                core.vault.refund_placeholder(&row.id).unwrap();
                let after = core
                    .vault
                    .list_placeholders(None)
                    .unwrap()
                    .into_iter()
                    .find(|p| p.id == row.id)
                    .unwrap();
                assert_eq!(after.uses, u64::from(revoked));
                assert_eq!(
                    after.state == av_store::model::PlaceholderState::Active,
                    !revoked
                );
            })
            .await
            .unwrap();
        let records = audit_records(&f).await;
        let event = if revoked {
            "placeholder.refund_refused"
        } else {
            "placeholder.refunded"
        };
        assert_eq!(records.iter().filter(|r| r["kind"] == event).count(), 1);
        let response = f.get().await;
        if revoked {
            assert_eq!(
                response.error.as_ref().unwrap().code.as_str(),
                "AV_SESSION_REVOKED"
            );
            assert!(f.up.hits.lock().unwrap().is_empty());
        } else {
            assert_eq!(response.status, 200);
        }
        f.clean(&response).await;
    }
}

#[tokio::test]
async fn locking_blocks_proxy_but_keeps_metadata_and_persists_until_explicit_unlock() {
    let f = Fixture::new(&["header:x-key"]).await;
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
    f.shared
        .run(|core| {
            core.vault.lock().unwrap();
            assert!(core.vault.locked_on_disk().unwrap());
            assert_eq!(core.vault.list_credentials().unwrap().len(), 1);
            assert!(core.vault.stats().unwrap().locked);
            let cred = core.vault.find_credential("demo").unwrap().unwrap();
            assert!(core.vault.reveal_field(&cred.id, "token").is_err());
        })
        .await
        .unwrap();
    let response = f.get().await;
    assert_eq!(response.status, 423);
    assert_eq!(response.error.as_ref().unwrap().code.as_str(), "AV_LOCKED");
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    assert!(!String::from_utf8_lossy(&response.body).contains(SECRET));
    let mut restarted = av_store::vault::Vault::open(f._dir.path()).unwrap();
    assert!(!restarted.start_in_recorded_state(None).unwrap());
    assert!(restarted.locked());
    drop(restarted);
    f.shared
        .run(|core| {
            core.vault.unlock(None).unwrap();
            assert!(!core.vault.locked());
            assert!(!core.vault.locked_on_disk().unwrap());
        })
        .await
        .unwrap();
    let restored = f.get().await;
    assert_eq!(restored.status, 200);
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    f.clean(&restored).await;
    let mut restarted = av_store::vault::Vault::open(f._dir.path()).unwrap();
    assert!(restarted.start_in_recorded_state(None).unwrap());
    assert!(!restarted.locked());
}

#[tokio::test]
async fn revocation_stops_an_existing_session_and_allow_deny_consumption_records_verify() {
    let f = Fixture::new(&["header:x-key"]).await;
    let allowed = f.get().await;
    assert_eq!(allowed.status, 200);
    f.clean(&allowed).await;
    let mut foreign = gateway_input(&f, "GET", "/ordinary", "", None, None);
    foreign.path = "/t/https/evil.test/steal".into();
    let denied = f.daemon.pipeline().handle(foreign).await;
    assert_eq!(denied.status, 403);
    f.clean(&denied).await;
    f.shared
        .run(|core| assert!(core.vault.audit().unwrap().verify().unwrap().ok))
        .await
        .unwrap();
    let records = audit_records(&f).await;
    for kind in ["request.allowed", "request.denied", "placeholder.resolved"] {
        assert!(records.iter().any(|r| r["kind"] == kind), "{kind}");
    }
    let token = f.token.clone();
    f.shared
        .run(move |core| {
            let sid = core.vault.session_by_token(&token).unwrap().unwrap().id;
            core.vault.revoke_session(&sid, "fixture revoked").unwrap();
        })
        .await
        .unwrap();
    let revoked = f.get().await;
    assert_eq!(
        revoked.error.as_ref().unwrap().code.as_str(),
        "AV_SESSION_REVOKED"
    );
    assert_eq!(f.up.hits.lock().unwrap().len(), 1);
    f.clean(&revoked).await;
}

#[tokio::test]
async fn upstream_minted_github_tokens_are_redacted_by_shape_and_ordinary_text_survives() {
    let f = Fixture::configured_kind(
        &["header:x-key"],
        SECRET,
        None,
        json!({}),
        "github",
        "api.github.com",
    )
    .await;
    f.reply(200,"application/json",json!({"token":"ghs_MINTEDINSTALLATION1234567890abcdef","ordinary":"ordinary-traffic-control"}).to_string());
    let response = f.get().await;
    assert_eq!(response.status, 200);
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("[[av:derived]]"));
    assert!(!text.contains("ghs_MINTEDINSTALLATION"));
    assert!(text.contains("ordinary-traffic-control"));
    f.clean(&response).await;
    assert!(!serde_json::to_string(&audit_records(&f).await)
        .unwrap()
        .contains("ghs_MINTEDINSTALLATION"));
}

#[tokio::test]
async fn chosen_credential_fingerprint_is_domain_separated_from_placeholder_checksum_key() {
    let f = Fixture::new(&["header:x-key"]).await;
    let token = f.token.clone();
    f.shared
        .run(move |core| {
            let sid = core.vault.session_by_token(&token).unwrap().unwrap().id;
            let message = format!("av1.{sid}.demo_token.5a8e1n0t2rc7q9x4wz6vhb3pdk");
            let public = core
                .vault
                .add_credential(av_store::vault::NewCredential {
                    slug: "chosen-message-probe".into(),
                    kind: "http".into(),
                    connector: serde_json::from_value(json!({"host":"probe.example.test"}))
                        .unwrap(),
                    fields: vec![("token".into(), message.clone().into())],
                    sites: std::collections::BTreeMap::from([(
                        "token".into(),
                        vec!["header:authorization:Bearer".into()],
                    )]),
                })
                .unwrap();
            let under_checksum =
                av_store::crypto::fingerprint8(&core.vault.k_ph().unwrap(), message.as_bytes());
            let under_fingerprint = av_store::crypto::fingerprint8(
                &core.vault.k_fingerprint().unwrap(),
                message.as_bytes(),
            );
            assert_ne!(public.fields[0].fp8, under_checksum);
            assert_eq!(public.fields[0].fp8, under_fingerprint);
        })
        .await
        .unwrap();
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn unit_only_grant_budget_keeps_the_session_limit_and_charges_every_allowed_request() {
    use av_core::secret::ExposeSecret;
    use av_store::vault::{CreateGrantOptions, CreateSessionOptions, IssueOptions};
    let f = Fixture::new(&["header:x-key"]).await;
    let (token,marker,gid)=f.shared.run(|core| {
        let credential=core.vault.find_credential("demo").unwrap().unwrap();
        let session=core.vault.create_session(CreateSessionOptions{policy:serde_json::from_value(json!({"hosts":["api.example.test"],"methods":["GET"],"paths":["/**"],"budget":{"unit":"requests","limit":2}})).unwrap(),..Default::default()}).unwrap();
        let grant=core.vault.create_grant(CreateGrantOptions{session_id:session.session.id,credential_id:credential.id,policy:serde_json::from_value(json!({"hosts":["api.example.test"],"methods":["GET"],"paths":["/**"],"budget":{"unit":"requests"},"approval":"auto"})).unwrap(),..Default::default()}).unwrap();
        let marker=core.vault.issue_placeholder(IssueOptions{grant_id:grant.id.clone(),..Default::default()}).unwrap().placeholder;
        (session.token.expose_secret().to_string(),marker,grant.id)
    }).await.unwrap();
    for expected in [200, 200, 403] {
        let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
        for (k, v) in &mut req.headers {
            if k == "av-session" {
                *v = token.clone();
            }
            if k == "x-key" {
                *v = marker.clone();
            }
        }
        let response = f.daemon.pipeline().handle(req).await;
        assert_eq!(response.status, expected);
        if expected == 403 {
            assert!(response.error.as_ref().unwrap().detail.contains("budget"));
        }
        f.clean(&response).await;
    }
    assert_eq!(f.up.hits.lock().unwrap().len(), 2);
    f.shared
        .run(move |core| assert_eq!(core.vault.grant(&gid).unwrap().unwrap().budget_used, 2))
        .await
        .unwrap();
}

#[tokio::test]
async fn approval_cannot_cross_header_changes_denial_resends_or_unexecuted_failures() {
    let f = Fixture::configured(
        &["header:x-key"],
        SECRET,
        None,
        json!({"approval":"each","methods":["GET","POST","DELETE"]}),
    )
    .await;
    let base = || {
        f.send(
            "POST",
            "/ordinary",
            vec![("x-key".into(), f.ph.clone())],
            Some("{\"title\":\"a\"}".into()),
        )
    };
    let id = held_id(&base().await);
    f.daemon
        .pipeline()
        .decide_approval(id.clone(), true)
        .await
        .unwrap();
    *f.up.failure.lock().unwrap() = Some(UpstreamError::new("ENOTFOUND", "fake DNS failure"));
    let failed = base().await;
    assert_eq!(failed.status, 502);
    assert_eq!(failed.error.as_ref().unwrap().extra.refunded, Some(true));
    f.clean(&failed).await;
    let expected = id.clone();
    f.shared
        .run(move |core| {
            assert_eq!(
                core.pl
                    .approvals
                    .iter()
                    .find(|(_, a)| a.id == expected)
                    .unwrap()
                    .1
                    .state,
                "granted"
            )
        })
        .await
        .unwrap();
    *f.up.failure.lock().unwrap() = None;
    let before = f.up.hits.lock().unwrap().len();
    let executed = base().await;
    assert_eq!(executed.status, 200);
    assert_eq!(f.up.hits.lock().unwrap().len(), before + 1);
    f.clean(&executed).await;
    let replay = base().await;
    assert_eq!(replay.status, 200);
    assert_eq!(replay.header("av-replayed"), Some("true"));
    assert_eq!(f.up.hits.lock().unwrap().len(), before + 1);
    f.clean(&replay).await;
    let changed = f
        .send(
            "POST",
            "/ordinary",
            vec![
                ("x-key".into(), f.ph.clone()),
                ("x-http-method-override".into(), "DELETE".into()),
            ],
            Some("{\"title\":\"a\"}".into()),
        )
        .await;
    assert_eq!(changed.status, 202);
    let other = held_id(&changed);
    assert_ne!(other, id);
    assert_eq!(f.up.hits.lock().unwrap().len(), before + 1);
    f.clean(&changed).await;
    f.daemon
        .pipeline()
        .decide_approval(other, false)
        .await
        .unwrap();
    for _ in 0..2 {
        let denied = f
            .send(
                "POST",
                "/ordinary",
                vec![
                    ("x-key".into(), f.ph.clone()),
                    ("x-http-method-override".into(), "DELETE".into()),
                ],
                Some("{\"title\":\"a\"}".into()),
            )
            .await;
        assert_eq!(denied.status, 403);
        f.clean(&denied).await;
    }
    assert_eq!(f.up.hits.lock().unwrap().len(), before + 1);
}

#[tokio::test]
async fn placeholder_grant_binding_cannot_bill_a_different_grant_for_a_wider_route() {
    use av_store::vault::{CreateGrantOptions, IssueOptions};
    let f = Fixture::new(&["header:x-key"]).await;
    let token = f.token.clone();
    let (marker,narrow)=f.shared.run(move |core| {
        let sid=core.vault.session_by_token(&token).unwrap().unwrap().id;let credential=core.vault.find_credential("demo").unwrap().unwrap();
        let grant=core.vault.create_grant(CreateGrantOptions{session_id:sid,credential_id:credential.id,policy:serde_json::from_value(json!({"hosts":["api.example.test"],"methods":["GET"],"paths":["/ordinary"],"budget":{"unit":"requests","limit":2},"approval":"auto"})).unwrap(),..Default::default()}).unwrap();
        let ph=core.vault.issue_placeholder(IssueOptions{grant_id:grant.id.clone(),..Default::default()}).unwrap().placeholder;(ph,grant.id)
    }).await.unwrap();
    let refused = f
        .send("GET", "/ordinary", vec![("x-key".into(), marker)], None)
        .await;
    assert_eq!(refused.status, 403);
    assert_eq!(
        refused.error.as_ref().unwrap().extra.rule.as_deref(),
        Some("placeholder_grant")
    );
    assert!(f.up.hits.lock().unwrap().is_empty());
    assert_eq!(grant_counters(&f).await, (0, vec![0]));
    f.shared
        .run(move |core| assert_eq!(core.vault.grant(&narrow).unwrap().unwrap().budget_used, 0))
        .await
        .unwrap();
    f.clean(&refused).await;
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn buffered_upstream_is_cut_at_the_size_limit_instead_of_occupying_unbounded_memory() {
    let f = Fixture::new(&["header:x-key"]).await;
    *f.up.reply.lock().unwrap() = Some(Reply {
        streaming: false,
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: vec![],
    });
    *f.up.source.lock().unwrap() = Some(Body::chunks(
        (0..33).map(|_| Ok(vec![b'A'; 1024 * 1024])).collect(),
    ));
    let refused = f.get().await;
    assert_eq!(refused.status, 502);
    let error = refused.error.as_ref().unwrap();
    assert_eq!(error.code.as_str(), "AV_UNSCANNABLE");
    assert_eq!(error.extra.rule.as_deref(), Some("response_size"));
    assert!(refused.body.len() < 16384);
    f.clean(&refused).await;
    f.reply(200, "application/json", "{\"ordinary\":true}".into());
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    assert_eq!(ordinary.body, b"{\"ordinary\":true}");
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn fractional_control_issuance_normalizes_uses_and_records_each_ledger_row_once() {
    let f = Fixture::new(&["header:x-key"]).await;
    let token = f.token.clone();
    let sid = f
        .shared
        .run(move |core| core.vault.session_by_token(&token).unwrap().unwrap().id)
        .await
        .unwrap();
    for (value, exact) in [
        (json!(1.5), Some(1)),
        (json!(2), Some(2)),
        (json!(0), None),
        (json!(-3), None),
        (json!(0.2), None),
        (Value::Null, None),
        (json!("lots"), None),
    ] {
        let before = f
            .shared
            .run(|core| core.vault.list_placeholders(None).unwrap().len())
            .await
            .unwrap();
        let audit_before = audit_records(&f)
            .await
            .iter()
            .filter(|r| r["kind"] == "placeholder.issued")
            .count();
        let (status, body) = control(
            &f._dir.path().join("control.sock"),
            "/v1/placeholders",
            json!({"cred":"demo","sid":sid,"uses":value}),
        )
        .await;
        assert_eq!(status, 200, "uses={value}: {body}");
        let ph = body["placeholder"].as_str().unwrap().to_string();
        let wanted = ph.clone();
        f.shared
            .run(move |core| {
                let rows = core.vault.list_placeholders(None).unwrap();
                assert_eq!(rows.len(), before + 1);
                let parsed = av_core::placeholder::parse_at(&wanted, 0).unwrap();
                let row = rows
                    .iter()
                    .find(|p| p.nonce_hash == av_core::placeholder::hash_nonce(&parsed.nonce))
                    .unwrap();
                assert!(row.max_uses >= 1);
                if let Some(exact) = exact {
                    assert_eq!(row.max_uses, exact);
                }
            })
            .await
            .unwrap();
        let after = audit_records(&f).await;
        assert_eq!(
            after
                .iter()
                .filter(|r| r["kind"] == "placeholder.issued")
                .count(),
            audit_before + 1
        );
        assert!(!serde_json::to_string(&body).unwrap().contains(SECRET));
        assert!(!serde_json::to_string(&after).unwrap().contains(SECRET));
    }
}

async fn loopback_http(
    port: u16,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    loopback_http_host(port, "127.0.0.1", method, path, headers, body).await
}
async fn loopback_http_host(
    port: u16,
    host: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let response = sender
        .send_request(request.body(Full::new(Bytes::from(body))).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().into(), v.to_str().unwrap().into()))
        .collect();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn exfil_control_refuses_foreign_hosts_and_ungated_session_creation_is_audited() {
    let f = Fixture::new(&["header:authorization:Bearer"]).await;
    let socket = f._dir.path().join("control.sock");
    let before = f
        .shared
        .run(|core| core.vault.sessions().unwrap().len())
        .await
        .unwrap();
    let(status,denied)=control(&socket,"/v1/sessions",json!({"cred":"demo","hosts":["127.0.0.1"],"methods":["GET"],"paths":["/**"],"approval":"auto","budget":10})).await;
    assert_eq!(status, 403);
    assert_eq!(denied["code"], "AV_POLICY_DENIED");
    assert!(denied["detail"]
        .as_str()
        .unwrap()
        .contains("outside what credential permits"));
    assert_eq!(
        f.shared
            .run(|core| core.vault.sessions().unwrap().len())
            .await
            .unwrap(),
        before
    );
    let (status, made) = control(
        &socket,
        "/v1/sessions",
        json!({"cred":"demo","methods":["GET"],"paths":["/**"]}),
    )
    .await;
    assert_eq!(status, 200, "{made}");
    assert!(made["token"].as_str().unwrap().starts_with("avs1."));
    assert!(audit_records(&f)
        .await
        .iter()
        .any(|r| r["kind"] == "control.widening_ungated"));
    assert!(f.up.hits.lock().unwrap().is_empty());
    let ordinary = f
        .send(
            "GET",
            "/ordinary",
            vec![("authorization".into(), format!("Bearer {}", f.ph))],
            None,
        )
        .await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
    for response in [denied, made] {
        assert!(!serde_json::to_string(&response).unwrap().contains(SECRET));
    }
}

#[tokio::test]
async fn exfil_passphrase_gates_unlock_creation_and_borrowed_grants_but_presence_restores_issuance()
{
    const PASS: &str = "fake-exfil-passphrase-123";
    let f = Fixture::new(&["header:authorization:Bearer"]).await;
    let socket = f._dir.path().join("control.sock");
    let token = f.token.clone();
    let sid = f
        .shared
        .run(move |core| core.vault.session_by_token(&token).unwrap().unwrap().id)
        .await
        .unwrap();
    let (s, v) = control(
        &socket,
        "/v1/passphrase",
        json!({"action":"set","passphrase":PASS}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(control(&socket, "/v1/lock", json!({})).await.0, 200);
    for body in [json!({}), json!({"passphrase":"fake-wrong-guess"})] {
        assert_eq!(control(&socket, "/v1/unlock", body).await.0, 423);
    }
    let (s, v) = control(&socket, "/v1/unlock", json!({"passphrase":PASS})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["locked"], false);
    let (s, v) = control(
        &socket,
        "/v1/passphrase",
        json!({"action":"remove","current":PASS}),
    )
    .await;
    assert_eq!(s, 403);
    assert_eq!(v["rule"], "last_factor");
    for (path, body) in [
        (
            "/v1/credentials",
            json!({"slug":"unauthorized","kind":"http","host":"foreign.example.test","value":"fake-credential-value"}),
        ),
        (
            "/v1/sessions",
            json!({"cred":"demo","methods":["GET"],"paths":["/**"]}),
        ),
        ("/v1/placeholders", json!({"cred":"demo"})),
        ("/v1/placeholders", json!({"cred":"demo","sid":sid})),
    ] {
        let (s, v) = control(&socket, path, body).await;
        assert_eq!(s, 401, "{path}: {v}");
        assert_eq!(v["code"], "AV_PRESENCE_REQUIRED");
        assert!(v.get("placeholder").is_none());
        assert!(!serde_json::to_string(&v).unwrap().contains(SECRET));
    }
    let (s, v) = control(
        &socket,
        "/v1/presence/window",
        json!({"passphrase":"fake-wrong-window"}),
    )
    .await;
    assert_eq!(s, 403);
    assert_eq!(v["code"], "AV_PRESENCE_DENIED");
    assert_eq!(
        control(&socket, "/v1/presence/window", json!({"passphrase":PASS}))
            .await
            .0,
        200
    );
    let (s, v) = control(
        &socket,
        "/v1/sessions",
        json!({"cred":"demo","methods":["GET"],"paths":["/**"]}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = control(
        &socket,
        "/v1/placeholders",
        json!({"cred":"demo","sid":sid}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(v["placeholder"].as_str().unwrap().starts_with("av1."));
    assert!(f.up.hits.lock().unwrap().is_empty());
    let ordinary = f
        .send(
            "GET",
            "/ordinary",
            vec![("authorization".into(), format!("Bearer {}", f.ph))],
            None,
        )
        .await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
    let logs = serde_json::to_string(&audit_records(&f).await).unwrap();
    assert!(!logs.contains(PASS));
}

#[tokio::test]
async fn exfil_real_gateway_cannot_deliver_secret_to_loopback_catcher_even_with_fresh_presence() {
    use tokio::io::AsyncWriteExt;
    for passphrase in [false, true] {
        let f = Fixture::new(&["header:authorization:Bearer"]).await;
        let socket = f._dir.path().join("control.sock");
        let mut input = json!({"cred":"demo","methods":if passphrase {vec!["GET","POST"]}else{vec!["GET"]},"paths":["/**"],"approval":"auto","budget":10});
        if passphrase {
            let (s, v) = control(
                &socket,
                "/v1/passphrase",
                json!({"passphrase":"fake-fresh-exfil-pass"}),
            )
            .await;
            assert_eq!(s, 200, "{v}");
            input["presence"] = json!({"passphrase":"fake-fresh-exfil-pass"});
        }
        let (s, made) = control(&socket, "/v1/sessions", input).await;
        assert_eq!(s, 200, "{made}");
        let token = made["token"].as_str().unwrap().to_string();
        let marker = made["placeholder"].as_str().unwrap().to_string();
        let catcher = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = catcher.local_addr().unwrap().port();
        let real = Daemon::new(
            f.shared.clone(),
            DaemonOptions {
                port: 0,
                socket_path: Some(f._dir.path().join("real-control.sock")),
                ..Default::default()
            },
        )
        .unwrap();
        real.start().await.unwrap();
        let gateway = real.gateway_port().unwrap();
        for method in if passphrase {
            vec!["GET", "POST"]
        } else {
            vec!["GET"]
        } {
            let body = if method == "POST" {
                json!({"token":marker}).to_string().into_bytes()
            } else {
                vec![]
            };
            let (status, _, response) = loopback_http(
                gateway,
                method,
                &format!("/t/http/127.0.0.1:{port}/x"),
                vec![
                    ("authorization".into(), format!("Bearer {marker}")),
                    ("av-session".into(), token.clone()),
                ],
                body,
            )
            .await;
            assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
            let problem: Value = serde_json::from_slice(&response).unwrap();
            assert_eq!(problem["code"], "AV_NO_GRANT");
            assert!(!String::from_utf8_lossy(&response).contains(SECRET));
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), catcher.accept())
                .await
                .is_err(),
            "a forbidden gateway request connected to the catcher"
        );
        let expected = marker.clone();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = catcher.accept().await.unwrap();
            let (headers, body) = read_wire_request(&mut socket).await;
            let captured = format!("{headers}{}", String::from_utf8_lossy(&body));
            assert!(captured.contains(&expected));
            assert!(!captured.contains(SECRET));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
        });
        let (status, _, _) = loopback_http(
            port,
            "POST",
            "/collect",
            vec![
                ("authorization".into(), format!("Bearer {marker}")),
                ("av-session".into(), token),
            ],
            serde_json::to_vec(&made).unwrap(),
        )
        .await;
        assert_eq!(status, 200);
        peer.await.unwrap();
        real.stop().await;
        assert!(!serde_json::to_string(&audit_records(&f).await)
            .unwrap()
            .contains(SECRET));
        assert!(f.up.hits.lock().unwrap().is_empty());
    }
}

// Fake Brotli fixtures generated once from the literal payloads below.
const RESPONSE_BR_BODY: &str = "CxSAeyJvcmRpbmFyeSI6ImNvbXByZXNzZWQgYnkgdGhlIHVwc3RyZWFtIn0D";
const RESPONSE_BR_SSE: &str = "G2QAMIzDdOMry7oIYb2n6ZqyS/0lA3Zu/OQAU0GnzylnGgiXJdbS0wH8DneDkzTN4jBMpimN7MfVB8I0Y6rJ1tKKOdp+UN00hVZppMedXuJCKm2s8yHQIwshv40=";

fn response_compress(encoding: &str, bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    match encoding {
        "gzip" => {
            let mut w = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        }
        "deflate" => {
            let mut w = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        }
        "identity" => bytes.to_vec(),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn response_buffered_encodings_preserve_plaintext_and_every_binary_byte() {
    use base64::Engine;
    let f = Fixture::new(&["header:x-key"]).await;
    let ordinary = b"{\"ordinary\":\"compressed by the upstream\"}".to_vec();
    let mut png = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    png.extend(0..=255);
    let binary = (0..512).map(|i| (i % 256) as u8).collect::<Vec<_>>();
    for (name, encoding, content_type, plain, expected) in [
        (
            "gzip ordinary",
            "gzip",
            "application/json",
            ordinary.clone(),
            ordinary.clone(),
        ),
        (
            "deflate ordinary",
            "deflate",
            "application/json",
            ordinary.clone(),
            ordinary.clone(),
        ),
        (
            "brotli ordinary",
            "br",
            "application/json",
            ordinary.clone(),
            ordinary.clone(),
        ),
        ("PNG every byte", "identity", "image/png", png.clone(), png),
        (
            "gzip binary",
            "gzip",
            "application/octet-stream",
            binary.clone(),
            binary,
        ),
    ] {
        let body = if encoding == "br" {
            base64::engine::general_purpose::STANDARD
                .decode(RESPONSE_BR_BODY)
                .unwrap()
        } else {
            response_compress(encoding, &plain)
        };
        let mut headers = vec![("content-type".into(), content_type.into())];
        if encoding != "identity" {
            headers.push(("content-encoding".into(), encoding.into()));
        }
        *f.up.reply.lock().unwrap() = Some(Reply {
            streaming: false,
            status: 200,
            headers,
            body,
        });
        let response = f.get().await;
        assert_eq!(response.status, 200, "{name}: {:?}", response.error);
        assert_eq!(response.body, expected, "{name}");
        assert!(response.header("content-encoding").is_none());
        f.clean(&response).await;
    }
}

#[tokio::test]
async fn response_unknown_encoding_refuses_buffered_and_streamed_bytes_with_readable_control() {
    let f = Fixture::new(&["header:x-key"]).await;
    for streaming in [false, true] {
        *f.up.reply.lock().unwrap() = Some(Reply {
            streaming,
            status: 200,
            headers: vec![
                (
                    "content-type".into(),
                    if streaming {
                        "text/event-stream"
                    } else {
                        "application/json"
                    }
                    .into(),
                ),
                ("content-encoding".into(), "exotic-v9".into()),
            ],
            body: format!("data: {SECRET}\n\n").into_bytes(),
        });
        let response = f.get().await;
        assert_eq!(response.status, 502);
        assert_eq!(
            response.error.as_ref().unwrap().code.as_str(),
            "AV_UNSCANNABLE"
        );
        f.clean(&response).await;
    }
    f.reply(200, "application/json", "{\"ordinary\":true}".into());
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    assert_eq!(ordinary.body, b"{\"ordinary\":true}");
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn response_all_compressed_sse_encodings_scrub_secrets_and_keep_event_order() {
    use base64::Engine;
    let f = Fixture::new(&["header:x-key"]).await;
    let events=format!("data: {{\"delta\":\"hi\"}}\n\ndata: {{\"leak\":\"{SECRET}\"}}\n\ndata: {{\"delta\":\"bye\"}}\n\n");
    for encoding in ["gzip", "deflate", "br"] {
        let compressed = if encoding == "br" {
            base64::engine::general_purpose::STANDARD
                .decode(RESPONSE_BR_SSE)
                .unwrap()
        } else {
            response_compress(encoding, events.as_bytes())
        };
        *f.up.reply.lock().unwrap() = Some(Reply {
            streaming: true,
            status: 200,
            headers: vec![
                ("content-type".into(), "text/event-stream".into()),
                ("content-encoding".into(), encoding.into()),
            ],
            body: compressed,
        });
        let response = f.get().await;
        assert_eq!(response.status, 200, "{encoding}");
        assert!(response.stream.is_some());
        assert!(response.header("content-encoding").is_none());
        let response = drain(response).await;
        let text = String::from_utf8_lossy(&response.body);
        assert!(!text.contains(SECRET));
        assert!(text.contains(&f.ph));
        assert!(text.find("hi").unwrap() < text.find("bye").unwrap());
        for decoder in ["gzip", "deflate", "br"] {
            if let Ok(decoded) = av_daemon::decode::decompress(&response.body, decoder) {
                assert!(!String::from_utf8_lossy(&decoded).contains(SECRET));
            }
        }
        f.clean(&response).await;
    }
}

#[tokio::test]
async fn response_sse_literal_and_transport_split_secrets_are_scrubbed_and_repository_prose_survives(
) {
    let f = Fixture::new(&["header:x-key"]).await;
    for split in [false, true] {
        let events=format!("data: {{\"delta\":\"hello\"}}\n\ndata: {{\"leak\":\"{SECRET}\"}}\n\ndata: {{\"delta\":\"done\"}}\n\n");
        stream_reply(&f, &events, false);
        if split {
            let at = events.find(SECRET).unwrap() + SECRET.len() / 2;
            *f.up.source.lock().unwrap() = Some(Body::chunks(vec![
                Ok(events.as_bytes()[..at].to_vec()),
                Ok(events.as_bytes()[at..].to_vec()),
            ]));
        }
        let response = f.get().await;
        assert!(response.stream.is_some());
        let response = drain(response).await;
        let text = String::from_utf8_lossy(&response.body);
        assert!(!text.contains(SECRET));
        assert!(text.contains(&f.ph));
        assert!(text.find("hello").unwrap() < text.find("done").unwrap());
        f.clean(&response).await;
    }
}

#[tokio::test]
async fn response_stream_holdback_starts_output_before_one_quarter_and_delivers_every_event() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let events = (0..200)
            .map(|i| format!("data: {{\"delta\":\"tok{i}\"}}\n\n"))
            .collect::<Vec<_>>();
        let all = events.concat();
        stream_reply(&f, &all, false);
        *f.up.source.lock().unwrap() = Some(Body::chunks(
            events.into_iter().map(|e| Ok(e.into_bytes())).collect(),
        ));
        let mut response = f.get().await;
        let mut source = response.stream.take().unwrap();
        let first = source.recv().await.unwrap();
        assert!(
            first.len() < all.len() / 4,
            "{} of {} bytes held before output",
            first.len(),
            all.len()
        );
        response.body = first;
        while let Some(chunk) = source.recv().await {
            response.body.extend(chunk);
        }
        assert_eq!(response.body, all.as_bytes());
        f.clean(&response).await;
    })
    .await
    .expect("SSE output progress timed out");
}

#[tokio::test]
async fn response_error_detail_cannot_disclose_stored_secret_and_keeps_useful_context() {
    let f = Fixture::new(&["header:x-key"]).await;
    *f.up.failure.lock().unwrap() = Some(UpstreamError::new(
        "UNEXPECTED",
        format!("boom while sending {SECRET} upstream"),
    ));
    let response = f.get().await;
    assert!(response.status >= 400);
    let text = String::from_utf8_lossy(&response.body);
    assert!(!text.contains(SECRET));
    assert!(text.contains("boom") || text.contains("[[av:") || text.contains("REDACT"));
    f.clean(&response).await;
    *f.up.failure.lock().unwrap() = None;
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn response_real_http_gateway_decodes_gzip_and_delivers_sse_through_default_connector() {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let compressed = response_compress("gzip", b"{\"gzipped\":true}");
    let peer = tokio::spawn(async move {
        for streaming in [false, true] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (headers, body) = read_wire_request(&mut socket).await;
            assert!(headers.contains(SECRET));
            assert!(!headers.contains("avs1."));
            assert!(body.is_empty());
            let (kind, encoding, bytes) = if streaming {
                (
                    "text/event-stream",
                    "",
                    b"data: one\n\ndata: two\n\n".to_vec(),
                )
            } else {
                (
                    "application/json",
                    "Content-Encoding: gzip\r\n",
                    compressed.clone(),
                )
            };
            let h=format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\n{encoding}Content-Length: {}\r\nConnection: close\r\n\r\n",bytes.len());
            socket.write_all(h.as_bytes()).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        }
    });
    let f = Fixture::new(&["header:x-key"]).await;
    let (_pipeline, request) = network_pipeline(&f, port, "GET", None).await;
    let real = Daemon::new(
        f.shared.clone(),
        DaemonOptions {
            port: 0,
            socket_path: Some(f._dir.path().join("response-real.sock")),
            ..Default::default()
        },
    )
    .unwrap();
    real.start().await.unwrap();
    let gateway = real.gateway_port().unwrap();
    for (path, expected) in [
        ("/p/network/data", b"{\"gzipped\":true}".as_slice()),
        ("/p/network/sse", b"data: one\n\ndata: two\n\n".as_slice()),
    ] {
        let headers = request
            .headers
            .iter()
            .filter(|(k, _)| k != "host")
            .cloned()
            .collect();
        let (status, headers, body) = loopback_http(gateway, "GET", path, headers, vec![]).await;
        assert_eq!(status, 200);
        assert_eq!(body, expected);
        assert!(!headers.iter().any(|(k, _)| k == "content-encoding"));
        if path.ends_with("sse") {
            assert!(headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "text/event-stream"));
        }
        assert!(!String::from_utf8_lossy(&body).contains(SECRET));
    }
    peer.await.unwrap();
    real.stop().await;
    assert!(!serde_json::to_string(&audit_records(&f).await)
        .unwrap()
        .contains(SECRET));
}

#[tokio::test]
async fn path_policy_refuses_every_ambiguous_deny_spelling_and_wire_controls_keep_the_decided_path()
{
    use av_core::policy::{encode_path_for_wire, normalize_path};
    let f=Fixture::configured_kind(&["header:x-key"],SECRET,None,json!({"methods":["GET","POST","DELETE"],"deny_paths":["/user/keys","/user/keys/**","/user/gpg_keys","/repos/*/*/hooks","/repos/*/*/keys","/settings/**","/api/admin.*"]}),"github","api.github.com").await;
    let mut denied = vec![
        "/user/keys".to_string(),
        "/user/gpg_keys".into(),
        "/repos/o/r/hooks".into(),
        "/repos/o/r/keys".into(),
        "/settings/x".into(),
        "/api/admin.users".into(),
    ];
    for encoding in ["%09", "%0a", "%0d"] {
        for base in ["/user/keys", "/repos/o/r/hooks", "/settings/x"] {
            denied.push(format!("{base}{encoding}"));
        }
        denied.push(format!("/api/a{encoding}dmin.users"));
    }
    denied.extend(
        [
            "/user/keys%23",
            "/user/keys%3Fz=1",
            "/repos/o/r/hooks%23x",
            "/settings/x%3f",
            "/repos/%252e%252e/admin",
            "/repos/%25252e%25252e/admin",
            "/user/%25256beys",
            "/user/%6beys",
            "/repos/o%2fr/hooks",
            "/user%2Fkeys",
            "/a%5Cb",
            "/%09%09%09",
        ]
        .map(str::to_string),
    );
    denied.push(format!("/user/{}6beys", "%25".repeat(12)));
    for path in denied {
        let response = f
            .send("POST", &path, vec![("x-key".into(), f.ph.clone())], None)
            .await;
        assert_eq!(response.status, 403, "{path}: {:?}", response.error);
        assert!(
            f.up.hits.lock().unwrap().is_empty(),
            "{path} reached upstream"
        );
        assert_eq!(grant_counters(&f).await, (0, vec![0]));
        f.clean(&response).await;
    }
    for path in [
        "/repos/o/r/issues",
        "/repos/o/r/issues/",
        "/repos/./o/r/issues",
        "/repos/o/x/../r/issues",
        "/repos//o//r//issues",
        "/repos/%6f/r/issues",
    ] {
        let decided = normalize_path(path).unwrap();
        let expected = encode_path_for_wire(&decided);
        let response = f
            .send("POST", path, vec![("x-key".into(), f.ph.clone())], None)
            .await;
        assert_eq!(response.status, 200, "{path}");
        let parsed = url::Url::parse(&f.last().url).unwrap();
        assert_eq!(parsed.path(), expected, "{path}");
        assert_eq!(wire_path_decoded(parsed.path()), decided, "{path}");
        f.clean(&response).await;
    }
    assert_eq!(normalize_path("/repos/%2e%2e/admin").unwrap(), "/admin");
    for path in ["/repos/%252e%252e/admin", "/repos/%25252e%25252e/admin"] {
        let e = normalize_path(path).unwrap_err();
        assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
        assert_eq!(e.extra.rule.as_deref(), Some("path_ambiguous_encoding"));
    }
}

fn wire_path_decoded(path: &str) -> String {
    let mut decoded = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            decoded.push(u8::from_str_radix(&path[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).unwrap()
}

#[test]
fn path_wire_encoding_preserves_every_legal_segment_character_and_round_trips_required_escapes() {
    use av_core::policy::encode_path_for_wire;
    for path in [
        "/v1beta/models/gemini-pro:generateContent",
        "/@scope/package",
        "/Products(1)/Name",
        "/a,b;c=d/e+f/g&h/i$j/k'l/m!n/o*p/q(r)s",
        "/plain/path/with-dashes_and.dots~here",
    ] {
        assert_eq!(encode_path_for_wire(path), path);
        assert_eq!(
            wire_path_decoded(url::Url::parse(&format!("https://h{path}")).unwrap().path()),
            path
        );
    }
    for (raw, encoded) in [
        ("/a b", "/a%20b"),
        ("/a?b", "/a%3Fb"),
        ("/a#b", "/a%23b"),
        ("/a%b", "/a%25b"),
        ("/a\"b", "/a%22b"),
        ("/café", "/caf%C3%A9"),
    ] {
        assert_eq!(encode_path_for_wire(raw), encoded);
        assert_eq!(
            wire_path_decoded(
                url::Url::parse(&format!("https://h{encoded}"))
                    .unwrap()
                    .path()
            ),
            raw
        );
    }
}

#[tokio::test]
async fn carrier_tokens_are_consumed_or_dropped_on_real_wire_while_declared_secret_and_ordinary_headers_arrive(
) {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        for name in [
            "Authorization carrier",
            "AV-Session carrier",
            "side-header token",
            "ordinary headers",
        ] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (headers, body) = read_wire_request(&mut socket).await;
            assert!(body.is_empty());
            assert!(
                !headers.contains("avs1."),
                "{name}: session capability reached upstream"
            );
            assert!(
                !headers.contains("av1."),
                "{name}: placeholder reached upstream"
            );
            let fields = headers
                .lines()
                .skip(1)
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                .collect::<Vec<_>>();
            assert!(
                fields.iter().any(|(k, v)| k == "x-key" && v == SECRET),
                "{name}: declared credential missing"
            );
            for key in ["authorization", "av-session", "x-note"] {
                assert!(
                    !fields.iter().any(|(k, _)| k == key),
                    "{name}: carrier header {key} survived"
                );
            }
            if name == "ordinary headers" {
                assert!(fields.iter().any(|(k, v)| k == "x-trace" && v == "abc123"));
                assert!(fields
                    .iter()
                    .any(|(k, v)| k == "accept" && v == "application/json"));
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}").await.unwrap();
        }
    });
    let f = Fixture::new(&["header:x-key"]).await;
    let (_pipeline, request) = network_pipeline(&f, port, "GET", None).await;
    let token = request
        .headers
        .iter()
        .find(|(k, _)| k == "av-session")
        .unwrap()
        .1
        .clone();
    let real = Daemon::new(
        f.shared.clone(),
        DaemonOptions {
            port: 0,
            socket_path: Some(f._dir.path().join("carrier-real.sock")),
            ..Default::default()
        },
    )
    .unwrap();
    real.start().await.unwrap();
    let gateway = real.gateway_port().unwrap();
    for name in [
        "Authorization carrier",
        "AV-Session carrier",
        "side-header token",
        "ordinary headers",
    ] {
        let mut headers = request
            .headers
            .iter()
            .filter(|(k, _)| k != "host")
            .cloned()
            .collect::<Vec<_>>();
        match name {
            "Authorization carrier" => {
                headers.retain(|(k, _)| k != "av-session");
                headers.push(("authorization".into(), format!("Bearer {token}")));
            }
            "side-header token" => headers.push(("x-note".into(), format!("fyi {token}"))),
            "ordinary headers" => {
                headers.push(("x-trace".into(), "abc123".into()));
                headers.push(("accept".into(), "application/json".into()));
            }
            _ => {}
        }
        let (status, headers, body) =
            loopback_http(gateway, "GET", "/p/network/thing", headers, vec![]).await;
        assert_eq!(status, 200, "{name}: {}", String::from_utf8_lossy(&body));
        assert_eq!(body, b"{}");
        assert!(!serde_json::to_string(&headers).unwrap().contains(SECRET));
        assert!(!String::from_utf8_lossy(&body).contains(SECRET));
    }
    peer.await.unwrap();
    real.stop().await;
    let logs = serde_json::to_string(&audit_records(&f).await).unwrap();
    assert!(!logs.contains(SECRET));
    assert!(!logs.contains(&token));
}

#[tokio::test]
async fn response_repository_prose_is_byte_exact_and_never_cut_or_redacted() {
    let f = Fixture::new(&["header:x-key"]).await;
    let prose="data: {\"delta\":\"here is the disk-usage_by_repository\"}\n\ndata: {\"delta\":\"_over_time report you asked for\"}\n\ndata: {\"delta\":\", plus a task-oriented_summary_of_findings\"}\n\n";
    stream_reply(&f, prose, false);
    let ordinary = drain(f.get().await).await;
    assert_eq!(ordinary.body, prose.as_bytes());
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn response_gzip_echo_replaces_secret_with_the_exact_injected_placeholder() {
    let f = Fixture::new(&["header:x-key"]).await;
    let plain = json!({"echo":SECRET}).to_string();
    *f.up.reply.lock().unwrap() = Some(Reply {
        streaming: false,
        status: 200,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("content-encoding".into(), "gzip".into()),
        ],
        body: response_compress("gzip", plain.as_bytes()),
    });
    let response = f.get().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, json!({"echo":f.ph}).to_string().as_bytes());
    f.clean(&response).await;
}

#[tokio::test]
async fn response_transport_chunk_split_does_not_reveal_secret_and_ordinary_frames_arrive() {
    let f = Fixture::new(&["header:x-key"]).await;
    let half = SECRET.len() / 2;
    let events = format!("data: {{\"leak\":\"{SECRET}\"}}\n\n");
    stream_reply(&f, &events, false);
    *f.up.source.lock().unwrap() = Some(Body::chunks(vec![
        Ok(format!("data: {{\"leak\":\"{}", &SECRET[..half]).into_bytes()),
        Ok(format!("{}\"}}\n\n", &SECRET[half..]).into_bytes()),
    ]));
    let response = f.get().await;
    assert!(response.stream.is_some());
    let response = drain(response).await;
    assert!(!String::from_utf8_lossy(&response.body).contains(SECRET));
    f.clean(&response).await;
    let control = "data: {\"ordinary\":true}\n\n";
    stream_reply(&f, control, false);
    let ordinary = drain(f.get().await).await;
    assert_eq!(ordinary.body, control.as_bytes());
    f.clean(&ordinary).await;
}

#[tokio::test]
async fn revocation_session_kills_all_placeholders_and_token_and_replays_have_distinct_audit_events(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let second = f.mint(None).await;
        for marker in [&f.ph, &second] {
            let response = f
                .send(
                    "GET",
                    "/ordinary",
                    vec![("x-key".into(), marker.clone())],
                    None,
                )
                .await;
            assert_eq!(response.status, 200);
            f.clean(&response).await;
        }
        let token = f.token.clone();
        f.shared
            .run(move |core| {
                let sid = core.vault.session_by_token(&token).unwrap().unwrap().id;
                core.vault.revoke_session(&sid, "test revocation").unwrap();
            })
            .await
            .unwrap();
        for marker in [&f.ph, &second] {
            let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
            req.headers.retain(|(k, _)| k != "av-session");
            req.headers
                .iter_mut()
                .find(|(k, _)| k == "x-key")
                .unwrap()
                .1 = marker.clone();
            let response = f.daemon.pipeline().handle(req).await;
            assert_ne!(response.status, 200);
            let code = response.error.as_ref().unwrap().code.as_str();
            assert!(
                code == "AV_SESSION_REVOKED"
                    || code == "AV_SESSION_REQUIRED"
                    || code.starts_with("AV_PH_")
            );
            f.clean(&response).await;
        }
        let mut req = gateway_input(&f, "GET", "/ordinary", "", None, None);
        req.headers
            .retain(|(k, _)| k != "x-key" && k != "av-session");
        req.headers
            .push(("authorization".into(), format!("Bearer {}", f.token)));
        let response = f.daemon.pipeline().handle(req).await;
        assert_ne!(response.status, 200);
        assert_eq!(f.up.hits.lock().unwrap().len(), 2);
        f.clean(&response).await;
        let replay = Fixture::new(&["header:x-key"]).await;
        let once = replay.mint(Some(1)).await;
        let send = || {
            replay.send(
                "GET",
                "/ordinary",
                vec![("x-key".into(), once.clone())],
                None,
            )
        };
        let first = send().await;
        assert_eq!(first.status, 200);
        replay.clean(&first).await;
        let second = send().await;
        assert_ne!(second.status, 200);
        assert!(second
            .error
            .as_ref()
            .unwrap()
            .code
            .as_str()
            .starts_with("AV_PH_"));
        assert_eq!(replay.up.hits.lock().unwrap().len(), 1);
        replay.clean(&second).await;
        assert!(audit_records(&replay)
            .await
            .iter()
            .any(|r| r["kind"].as_str().is_some_and(|kind| [
                "placeholder.exhausted",
                "placeholder.replay",
                "placeholder.stale"
            ]
            .iter()
            .any(|prefix| kind.starts_with(prefix)))));
    })
    .await
    .expect("revocation regression timed out");
}

async fn second_revocation_capability(
    f: &Fixture,
    same_credential: bool,
) -> (GatewayRequest, String) {
    use av_core::secret::ExposeSecret;
    use av_store::vault::{CreateGrantOptions, IssueOptions, NewCredential};
    let (token, marker, gid, slug) = f
        .shared
        .run(move |core| {
            let credential = if same_credential {
                core.vault.find_credential("demo").unwrap().unwrap()
            } else {
                let added = core
                    .vault
                    .add_credential(NewCredential {
                        slug: "other-revocation".into(),
                        kind: "http".into(),
                        connector: serde_json::from_value(json!({"host":"api.example.test"}))
                            .unwrap(),
                        fields: vec![("token".into(), SECRET.to_string().into())],
                        sites: std::collections::BTreeMap::from([(
                            "token".into(),
                            vec!["header:x-key".into()],
                        )]),
                    })
                    .unwrap();
                core.vault.credential(&added.id).unwrap().unwrap()
            };
            let session = core.vault.create_session(Default::default()).unwrap();
            let grant = core
                .vault
                .create_grant(CreateGrantOptions {
                    session_id: session.session.id,
                    credential_id: credential.id,
                    policy: serde_json::from_value(seeded_policy()).unwrap(),
                    ..Default::default()
                })
                .unwrap();
            let marker = core
                .vault
                .issue_placeholder(IssueOptions {
                    grant_id: grant.id.clone(),
                    ..Default::default()
                })
                .unwrap()
                .placeholder;
            (
                session.token.expose_secret().to_string(),
                marker,
                grant.id,
                credential.slug,
            )
        })
        .await
        .unwrap();
    (
        GatewayRequest {
            method: "GET".into(),
            path: format!("/p/{slug}/ordinary"),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), token),
                ("x-key".into(), marker),
            ],
            ..Default::default()
        },
        gid,
    )
}

#[tokio::test]
async fn revocation_is_precise_across_sessions_but_credential_deletion_stops_every_dependent_grant()
{
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for delete in [false, true] {
            let f = Fixture::new(&["header:x-key"]).await;
            let (other, other_grant) = second_revocation_capability(&f, delete).await;
            let first = f.get().await;
            assert_eq!(first.status, 200);
            f.clean(&first).await;
            let second = f.daemon.pipeline().handle(other.clone()).await;
            assert_eq!(second.status, 200);
            f.clean(&second).await;
            let gid = f.grant_id.clone();
            f.shared
                .run(move |core| {
                    if delete {
                        core.vault.delete_credential("demo").unwrap();
                    } else {
                        core.vault.revoke_grant(&gid, "test revocation").unwrap();
                    }
                })
                .await
                .unwrap();
            let first = f.get().await;
            assert_ne!(first.status, 200);
            f.clean(&first).await;
            let second = f.daemon.pipeline().handle(other).await;
            assert_eq!(second.status == 200, !delete);
            f.clean(&second).await;
            assert_eq!(f.up.hits.lock().unwrap().len(), if delete { 2 } else { 3 });
            f.shared
                .run(move |core| {
                    let other = core.vault.grant(&other_grant).unwrap().unwrap();
                    assert_eq!(other.state == av_store::model::GrantState::Active, !delete);
                })
                .await
                .unwrap();
        }
    })
    .await
    .expect("grant and credential revocation timed out");
}

#[tokio::test]
async fn expired_session_stops_a_previously_working_placeholder_whose_own_expiry_remains_live() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = SeededGateway::new(json!({}), json!({}));
        let ordinary = f.pipeline.handle(f.request.clone()).await;
        assert_eq!(ordinary.status, 200);
        f.clean(&ordinary).await;
        let before = f.snapshot().await;
        let expiry = before["placeholders"][0]["expires_at"].clone();
        let SeededGateway {
            _dir,
            shared,
            pipeline,
            upstream,
            request,
            sid,
            gid: _,
        } = f;
        drop(pipeline);
        drop(shared);
        let past = (time::OffsetDateTime::now_utc() - time::Duration::seconds(1))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        ported_common::seed_session_expiry(_dir.path(), &sid, &past);
        let mut reopened = av_store::vault::Vault::open(_dir.path()).unwrap();
        reopened.unlock(None).unwrap();
        let row = reopened.list_placeholders(Some(&sid)).unwrap().remove(0);
        assert_eq!(serde_json::to_value(row.expires_at).unwrap(), expiry);
        assert_eq!(row.state, av_store::model::PlaceholderState::Active);
        let shared = Shared::new(reopened);
        let pipeline = av_daemon::pipeline::Pipeline::new(
            shared.clone(),
            PipelineOptions {
                upstream: Some(upstream.clone()),
                ..Default::default()
            },
        );
        let response = pipeline.handle(request).await;
        assert_ne!(response.status, 200);
        assert_eq!(
            response.error.as_ref().unwrap().code.as_str(),
            "AV_SESSION_EXPIRED"
        );
        assert_eq!(upstream.hits.lock().unwrap().len(), 1);
        assert!(!String::from_utf8_lossy(&response.body).contains(SECRET));
        shared
            .run(|core| {
                assert!(!serde_json::to_string(
                    &core
                        .vault
                        .audit()
                        .unwrap()
                        .read(&Default::default())
                        .unwrap()
                )
                .unwrap()
                .contains(SECRET))
            })
            .await
            .unwrap();
    })
    .await
    .expect("session expiry regression timed out");
}

const WIDEN_PASS: &str = "fake-widening-passphrase-012345";
struct WidenFixture {
    f: Fixture,
    ui: av_daemon::ui::server::UiServer,
    cookie: String,
    auth: ported_common::FakeAuthenticator,
}
impl WidenFixture {
    async fn new() -> Self {
        let f = Fixture::new(&["header:authorization:Bearer"]).await;
        let socket = f._dir.path().join("control.sock");
        let (s, v) = control(&socket, "/v1/passphrase", json!({"passphrase":WIDEN_PASS})).await;
        assert_eq!(s, 200, "{v}");
        let dist = f._dir.path().join("fake-ui-dist");
        std::fs::create_dir(&dist).unwrap();
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><title>fake test UI</title>",
        )
        .unwrap();
        let ui = av_daemon::ui::server::UiServer::start(
            &socket,
            av_daemon::ui::server::UiServerOptions {
                port: 0,
                dist_dir: Some(dist),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        f.daemon.allow_ui_origin(&ui.origin()).await.unwrap();
        let url = url::Url::parse(&ui.url()).unwrap();
        let path = format!("{}?{}", url.path(), url.query().unwrap());
        let (s, h, _) =
            loopback_http_host(ui.bound_port(), "localhost", "GET", &path, vec![], vec![]).await;
        assert_eq!(s, 302);
        let cookie = h
            .iter()
            .find(|(k, _)| k == "set-cookie")
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let w = Self {
            f,
            ui,
            cookie,
            auth: ported_common::FakeAuthenticator::new(7),
        };
        let (s, begin) = w.api("POST", "presence/enroll/begin", json!({})).await;
        assert_eq!(s, 200, "{begin}");
        let mut att = w
            .auth
            .register(begin["challenge"].as_str().unwrap(), &w.ui.origin());
        att["passphrase"] = json!(WIDEN_PASS);
        let (s, v) = w.api("POST", "presence/enroll/finish", att).await;
        assert_eq!(s, 200, "{v}");
        // Close the enrolment grace window through the public lock/unlock API.
        assert_eq!(w.ctl("POST", "/v1/lock", json!({})).await.0, 200);
        assert_eq!(
            w.ctl("POST", "/v1/unlock", json!({"passphrase":WIDEN_PASS}))
                .await
                .0,
            200
        );
        w
    }
    async fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (s, _, bytes) = loopback_http_host(
            self.ui.bound_port(),
            "localhost",
            method,
            &format!("/api/{path}"),
            vec![
                ("x-av-ui".into(), "1".into()),
                ("cookie".into(), self.cookie.clone()),
                ("content-type".into(), "application/json".into()),
            ],
            serde_json::to_vec(&body).unwrap(),
        )
        .await;
        (
            s,
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                panic!("UI {method} {path}: {}", String::from_utf8_lossy(&bytes))
            }),
        )
    }
    async fn ctl(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        control_method(&self.f._dir.path().join("control.sock"), method, path, body).await
    }
    async fn proof(&self, operation: &str, params: &Value) -> Value {
        let operation = av_daemon::util::operation_for(operation, params).unwrap();
        let (s, ch) = self
            .api("POST", "presence/challenge", json!({"operation":operation}))
            .await;
        assert_eq!(s, 200, "{ch}");
        let mut assertion = self
            .auth
            .assertion(ch["challenge"].as_str().unwrap(), &self.ui.origin());
        assertion["challengeId"] = ch["challengeId"].clone();
        assertion
    }
    async fn stop(&self) {
        let logs = serde_json::to_string(&audit_records(&self.f).await).unwrap();
        assert!(!logs.contains(SECRET));
        assert!(!logs.contains(WIDEN_PASS));
        self.ui.stop().await;
    }
}

#[tokio::test]
async fn widening_signed_ui_session_and_credential_changes_work_and_never_reveal_secret() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let w=WidenFixture::new().await;
        let(s,v)=w.ctl("POST","/v1/sessions",json!({"cred":"demo","methods":["GET"],"paths":["/**"]})).await;assert_eq!(s,401);assert_eq!(v["code"],"AV_PRESENCE_REQUIRED");
        let(s,list)=w.ctl("GET","/v1/credentials",json!({})).await;assert_eq!(s,200);let demo=list.as_array().unwrap().iter().find(|v|v["slug"]=="demo").unwrap();assert_eq!(demo["fields"][0]["sites"],json!(["header:authorization:Bearer"]));assert!(!serde_json::to_string(&list).unwrap().contains(SECRET));
        let mut body=json!({"cred":"demo","methods":["GET"],"paths":["/**"]});body["presence"]=w.proof("session.create",&body).await;
        let(s,made)=w.api("POST","sessions",body).await;assert_eq!(s,200,"{made}");assert!(made["session_id"].is_string());assert!(made["token"].as_str().unwrap().starts_with("avs1."));assert!(made["placeholder"].as_str().unwrap().starts_with("av1."));assert!(made["base_url"].as_str().unwrap().ends_with("/p/demo"));assert!(!made["usage"].as_array().unwrap().is_empty());assert!(!serde_json::to_string(&made).unwrap().contains(SECRET));
        let mut add=json!({"slug":"signed-second","kind":"http","host":"other.example.test","value":"fake-signed-credential-012345"});add["presence"]=w.proof("cred.add",&add).await;
        let(s,v)=w.api("POST","credentials",add).await;assert_eq!(s,200,"{v}");w.f.shared.run(|core|assert!(core.vault.find_credential("signed-second").unwrap().is_some())).await.unwrap();
        let proof=w.proof("cred.remove",&json!({"slug":"signed-second"})).await;let(s,v)=w.api("DELETE","credentials?slug=signed-second",json!({"presence":proof})).await;assert_eq!(s,200,"{v}");w.f.shared.run(|core|assert!(core.vault.find_credential("signed-second").unwrap().is_none())).await.unwrap();
        w.stop().await;
    }).await.expect("signed UI widening timed out");
}

#[tokio::test]
async fn widening_operation_swaps_unminted_challenges_unenrolled_keys_and_replays_never_authorize()
{
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let w=WidenFixture::new().await;let benign=json!({"cred":"demo","methods":["GET"],"paths":["/**"]});
        for shape in ["method swap","unsigned session fields","unminted challenge","unenrolled key"] {
            let before=w.f.shared.run(|core|core.vault.sessions().unwrap().len()).await.unwrap();
            let operation=av_daemon::util::operation_for("session.create",&benign).unwrap();let(s,ch)=w.api("POST","presence/challenge",json!({"operation":operation})).await;assert_eq!(s,200,"{ch}");
            let mut proof=if shape=="unenrolled key" {ported_common::FakeAuthenticator::new(8).assertion(ch["challenge"].as_str().unwrap(),&w.ui.origin())}else{w.auth.assertion(ch["challenge"].as_str().unwrap(),&w.ui.origin())};proof["challengeId"]=ch["challengeId"].clone();
            let mut body=benign.clone();
            match shape {
                "method swap"=>body["methods"]=json!(["GET","POST","DELETE"]),
                "unsigned session fields"=>{for(k,v)in json!({"remote":true,"approval":"auto","budget":1000000000,"ttl_hours":87600,"uses":1000000}).as_object().unwrap(){body[k]=v.clone();}},
                "unminted challenge"=>{proof=w.auth.assertion("ZmFrZS11bm1pbnRlZC1jaGFsbGVuZ2U",&w.ui.origin());proof["challengeId"]=json!("fake-unminted-id");},
                _=>{}
            }
            body["presence"]=proof;let(s,v)=w.ctl("POST","/v1/sessions",body).await;assert_eq!(s,401,"{shape}: {v}");assert_eq!(v["code"],"AV_PRESENCE_REQUIRED");
            assert_eq!(w.f.shared.run(|core|core.vault.sessions().unwrap().len()).await.unwrap(),before,"{shape}: denial changed sessions");
            let mut control=benign.clone();control["presence"]=w.proof("session.create",&benign).await;let(s,v)=w.ctl("POST","/v1/sessions",control).await;assert_eq!(s,200,"{shape} control: {v}");assert!(!serde_json::to_string(&v).unwrap().contains(SECRET));
        }
        let mut once=benign.clone();once["presence"]=w.proof("session.create",&benign).await;
        let(s,v)=w.ctl("POST","/v1/sessions",once.clone()).await;assert_eq!(s,200,"{v}");let(s,v)=w.ctl("POST","/v1/sessions",once).await;assert_eq!(s,401,"signature reused: {v}");
        let mine=ported_common::FakeAuthenticator::new(9);let before=w.ctl("GET","/v1/presence",json!({})).await.1;
        let(s,v)=w.ctl("POST","/v1/presence",json!({"credentialId":"aGVsbG8","publicKeySpki":"x","signCount":0,"attestation":mine.register("ZmFrZS1yZWdpc3RyYXRpb24",&w.ui.origin())})).await;
        assert_eq!(s,401,"self enrolment: {v}");assert_eq!(v["code"],"AV_PRESENCE_REQUIRED");let after=w.ctl("GET","/v1/presence",json!({})).await.1;assert_eq!(after["credentialId"],before["credentialId"]);assert_ne!(after["credentialId"],"aGVsbG8");
        w.stop().await;
    }).await.expect("hostile widening proofs timed out");
}

#[tokio::test]
async fn widening_credential_value_is_bound_to_consent_and_correctly_signed_value_is_stored() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        use av_core::secret::ExposeSecret;
        let w=WidenFixture::new().await;let intended=json!({"slug":"bound","kind":"http","host":"api.example.test","value":"INTENDED-SECRET-0001"});
        let proof=w.proof("cred.add",&intended).await;let mut swapped=intended.clone();swapped["value"]=json!("ATTACKER-SUBSTITUTED-VALUE-0002");swapped["presence"]=proof;
        let(s,v)=w.ctl("POST","/v1/credentials",swapped).await;assert_eq!(s,401,"{v}");w.f.shared.run(|core|assert!(core.vault.find_credential("bound").unwrap().is_none())).await.unwrap();
        let mut control=intended.clone();control["presence"]=w.proof("cred.add",&intended).await;let(s,v)=w.ctl("POST","/v1/credentials",control).await;assert_eq!(s,200,"{v}");
        w.f.shared.run(|core|{let cred=core.vault.find_credential("bound").unwrap().unwrap();assert_eq!(core.vault.reveal_field(&cred.id,"token").unwrap().expose_secret(),"INTENDED-SECRET-0001");}).await.unwrap();
        let logs=serde_json::to_string(&audit_records(&w.f).await).unwrap();for value in ["INTENDED-SECRET-0001","ATTACKER-SUBSTITUTED-VALUE-0002"]{assert!(!logs.contains(value));assert!(!serde_json::to_string(&v).unwrap().contains(value));}
        w.stop().await;
    }).await.expect("credential value consent binding timed out");
}

#[tokio::test]
async fn widening_batch_consent_binds_exact_items_and_verdicts_and_handover_is_collected_once() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        for shape in ["extra item","swapped verdicts"] {
            let w=WidenFixture::new().await;let mut asks=Vec::new();
            for path in ["/a","/b"] {let(s,v)=w.ctl("POST","/v1/session-requests",json!({"cred":"demo","methods":["GET"],"paths":[path]})).await;assert_eq!(s,200,"{v}");asks.push(v);}
            let signed=if shape=="extra item" {json!([{"id":asks[0]["id"],"kind":"session","granted":true}])}else{json!([{"id":asks[0]["id"],"kind":"session","granted":true},{"id":asks[1]["id"],"kind":"session","granted":false}])};
            let proof=w.proof("pending.decide_many",&json!({"decisions":signed})).await;
            let swapped=if shape=="extra item" {json!([{"id":asks[0]["id"],"kind":"session","granted":true},{"id":asks[1]["id"],"kind":"session","granted":true}])}else{json!([{"id":asks[0]["id"],"kind":"session","granted":false},{"id":asks[1]["id"],"kind":"session","granted":true}])};
            let(s,v)=w.ctl("POST","/v1/pending/decide-many",json!({"decisions":swapped,"presence":proof})).await;assert_eq!(s,401,"{shape}: {v}");assert_eq!(v["code"],"AV_PRESENCE_REQUIRED");
            for ask in &asks {let path=format!("/v1/session-requests/collect?id={}&secret={}",ask["id"].as_str().unwrap(),ask["collect_secret"].as_str().unwrap());let(s,v)=w.ctl("GET",&path,json!({})).await;assert_eq!(s,200,"{v}");assert_eq!(v["state"],"pending","{shape}: refusal settled a request");}
            let proof=w.proof("pending.decide_many",&json!({"decisions":signed})).await;let body=json!({"decisions":signed,"presence":proof});
            let(s,v)=w.ctl("POST","/v1/pending/decide-many",body.clone()).await;assert_eq!(s,200,"{shape} control: {v}");
            assert_eq!(v["decided"][0]["outcome"],"decided");let mut result=v["decided"][0]["result"].as_object().unwrap().clone();assert_eq!(result["state"],"approved");let session=result.remove("session").unwrap();assert!(session["token"].as_str().unwrap().starts_with("avs1."));assert!(!serde_json::to_string(&result).unwrap().contains("avs1."));assert!(!serde_json::to_string(&v).unwrap().contains(SECRET));
            let path=format!("/v1/session-requests/collect?id={}&secret={}",asks[0]["id"].as_str().unwrap(),asks[0]["collect_secret"].as_str().unwrap());let(s,polled)=w.ctl("GET",&path,json!({})).await;assert_eq!(s,200);assert_eq!(polled["state"],"collected");assert!(polled.get("token").is_none());
            let(s,v)=w.ctl("POST","/v1/pending/decide-many",body).await;assert_eq!(s,401,"batch signature reused: {v}");
            w.stop().await;
        }
    }).await.expect("batch signature binding timed out");
}

const INVARIANT_SECRETS: [&str; 3] = [
    "ghp_INVARIANTGRANTED00112233445566778899",
    "xoxb-9999-INVARIANTBYSTANDERVALUE00",
    "contraseña-INVARIANT-über-0123456789",
];
#[derive(Clone, Debug)]
struct InvariantShape {
    kind: u8,
    inline: u8,
    body_encoding: u8,
    limited: bool,
    path: u8,
}

fn invariant_encoding(marker: &str, encoding: u8) -> String {
    use base64::Engine;
    match encoding {
        0 => marker.into(),
        1 => marker.replace('.', "%2E"),
        2 => base64::engine::general_purpose::STANDARD.encode(marker),
        3 => marker
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect(),
        4 | 5 => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(marker);
            let width = if encoding == 4 { 64 } else { 76 };
            encoded
                .as_bytes()
                .chunks(width)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(if encoding == 4 { "\n" } else { "\r\n" })
        }
        _ => unreachable!(),
    }
}

async fn invariant_gateway(
    port: u16,
    path: &str,
    method: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> (u16, Vec<u8>) {
    // Like Node's request helper, a client-side URI refusal yields no wire
    // bytes and no credential; the ordinary control in every case still runs.
    if path.parse::<hyper::Uri>().is_err() {
        return (0, vec![]);
    }
    let (status, _, bytes) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        loopback_http(port, method, path, headers, body),
    )
    .await
    .expect("invariant gateway stopped responding");
    (status, bytes)
}

async fn check_invariant_sequence(shapes: &[InvariantShape]) {
    use av_core::secret::ExposeSecret;
    use av_store::vault::{CreateGrantOptions, CreateSessionOptions, IssueOptions, NewCredential};
    use base64::Engine;
    use tokio::io::AsyncWriteExt;
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let wire = Arc::new(Mutex::new(Vec::<(String, String, Vec<u8>)>::new()));
    let recorded = wire.clone();
    let peer = tokio::spawn(async move {
        loop {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let (headers, body) = read_wire_request(&mut socket).await;
            let path = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_string();
            recorded
                .lock()
                .unwrap()
                .push((path.clone(), headers.clone(), body.clone()));
            // The real hostile peer echoes the entire request in three views,
            // plus bystander values the request did not involve.
            let echo=serde_json::to_string(&json!({"url":path,"headers":headers,"body":String::from_utf8_lossy(&body),"bystander":INVARIANT_SECRETS[1],"accented":INVARIANT_SECRETS[2]})).unwrap();
            let reply = format!(
                "{}\n{}\n{}",
                echo,
                base64::engine::general_purpose::STANDARD.encode(&echo),
                encode(&echo, Layer::Percent)
            );
            let head=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.len());
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
    let mut granted = None;
    for (slug, host, field, value, site) in [
        (
            "prod",
            format!("127.0.0.1:{up_port}"),
            "token",
            INVARIANT_SECRETS[0],
            "header:authorization:Bearer",
        ),
        (
            "other",
            "slack.test".into(),
            "token",
            INVARIANT_SECRETS[1],
            "header:authorization:Bearer",
        ),
        (
            "accented",
            "example.test".into(),
            "password",
            INVARIANT_SECRETS[2],
            "basic:pass",
        ),
    ] {
        let credential = vault
            .add_credential(NewCredential {
                slug: slug.into(),
                kind: "http".into(),
                connector: serde_json::from_value(
                    json!({"host":host,"scheme":if slug=="prod" {"http"}else{"https"}}),
                )
                .unwrap(),
                fields: vec![(field.into(), value.to_string().into())],
                sites: std::collections::BTreeMap::from([(field.into(), vec![site.into()])]),
            })
            .unwrap();
        if slug == "prod" {
            granted = Some(credential.id);
        }
    }
    let session = vault
        .create_session(CreateSessionOptions::default())
        .unwrap();
    let token = session.token.expose_secret().to_string();
    let grant=vault.create_grant(CreateGrantOptions{session_id:session.session.id,credential_id:granted.unwrap(),policy:serde_json::from_value(json!({"hosts":["127.0.0.1"],"methods":["GET","POST"],"paths":["/allowed/**"],"budget":{"unit":"requests","limit":100000},"approval":"auto"})).unwrap(),..Default::default()}).unwrap();
    let marker = vault
        .issue_placeholder(IssueOptions {
            grant_id: grant.id.clone(),
            ..Default::default()
        })
        .unwrap()
        .placeholder;
    let limited = vault
        .issue_placeholder(IssueOptions {
            grant_id: grant.id,
            uses: Some(3),
            ..Default::default()
        })
        .unwrap();
    let limited_id = limited.row.id;
    let shared = Shared::new(vault);
    let daemon = Daemon::new(
        shared.clone(),
        DaemonOptions {
            port: 0,
            socket_path: Some(dir.path().join("invariants.sock")),
            ..Default::default()
        },
    )
    .unwrap();
    daemon.start().await.unwrap();
    let gateway = daemon.gateway_port().unwrap();
    let headers = |p: &str| {
        vec![
            ("authorization".into(), format!("Bearer {p}")),
            ("av-session".into(), token.clone()),
        ]
    };
    let assert_private = |bytes: &[u8], label: &str| {
        let utf8 = String::from_utf8_lossy(bytes);
        let latin1 = bytes.iter().map(|b| char::from(*b)).collect::<String>();
        for secret in INVARIANT_SECRETS {
            assert!(!utf8.contains(secret), "{label}: secret in UTF-8 response");
            assert!(
                !latin1.contains(secret),
                "{label}: secret in Latin-1 response"
            );
        }
    };
    let (first, bytes) = invariant_gateway(
        gateway,
        "/p/prod/allowed/limited-control",
        "GET",
        headers(&limited.placeholder),
        vec![],
    )
    .await;
    assert_eq!(first, 200);
    assert_private(&bytes, "limited control");
    let mut allowed = 0;
    for (i, shape) in shapes.iter().enumerate() {
        // An actual ordinary request in every generated row prevents an
        // all-deny implementation from satisfying any invariant.
        let (status, bytes) = invariant_gateway(
            gateway,
            "/p/prod/allowed/ordinary-control",
            "GET",
            headers(&marker),
            vec![],
        )
        .await;
        assert_eq!(status, 200, "row {i} ordinary control");
        allowed += 1;
        assert_private(&bytes, &format!("row {i} control"));
        let p = if shape.limited {
            &limited.placeholder
        } else {
            &marker
        };
        let carried = invariant_encoding(p, shape.inline);
        let body_marker = invariant_encoding(p, shape.body_encoding);
        let mut path = match shape.path % 3 {
            0 => "/p/prod/allowed/a",
            1 => "/p/prod/allowed/b/c",
            _ => "/p/prod/allowed/deep/er/still",
        }
        .to_string();
        let mut h = headers(p);
        let mut method = "GET";
        let mut body = Vec::new();
        match shape.kind {
            0 => {}
            1 => path = format!("/p/prod/allowed/{carried}"),
            2 => h.push(("x-note".into(), carried)),
            3 => h.push((
                format!(
                    "x-{}",
                    p.chars()
                        .map(|c| if c.is_ascii_alphanumeric() || c == '-' {
                            c
                        } else {
                            '-'
                        })
                        .collect::<String>()
                ),
                "1".into(),
            )),
            4 => path = format!("/p/prod/allowed/a?{carried}=1"),
            5 => path = format!("/p/prod/allowed/a?note={carried}"),
            6..=8 => {
                method = "POST";
                h.push(("content-type".into(), "application/json".into()));
                body = match shape.kind {
                    6 => json!({"note":body_marker}).to_string(),
                    7 => format!(
                        "{{\"k\":{},\"k\":\"harmless\"}}",
                        serde_json::to_string(&body_marker).unwrap()
                    ),
                    _ => json!({body_marker:"v"}).to_string(),
                }
                .into_bytes();
            }
            9 => {
                method = "POST";
                h.push((
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ));
                body = format!("f={}", encode(&body_marker, Layer::Percent)).into_bytes();
            }
            10 => {
                method = "POST";
                h.push(("content-type".into(), "text/plain".into()));
                body = format!("here: {body_marker}").into_bytes();
            }
            11 => path = "/p/prod/forbidden/a".into(),
            12 => method = "DELETE",
            13 => path = format!("/t/http/127.0.0.1:{up_port}/allowed/a"),
            14 => path = "/p/other/allowed/a".into(),
            15 => h.retain(|(k, _)| k != "av-session"),
            16 => {
                h.iter_mut().find(|(k, _)| k == "authorization").unwrap().1 =
                    "Bearer av1.notreal.x_y.aaaaaaaaaaaaaaaaaaaaaaaaaa.zzzzzz".into()
            }
            _ => unreachable!(),
        }
        let (status, bytes) = invariant_gateway(gateway, &path, method, h, body).await;
        if status == 200 {
            allowed += 1;
        }
        assert_private(&bytes, &format!("row {i} {shape:?}"));
    }
    assert!(allowed > 50, "fixture must exercise ordinary traffic");
    for _ in 0..4 {
        let (_, bytes) = invariant_gateway(
            gateway,
            "/p/prod/allowed/final-limited",
            "GET",
            headers(&limited.placeholder),
            vec![],
        )
        .await;
        assert_private(&bytes, "limited final attempts");
    }
    for (path, headers, body) in wire.lock().unwrap().iter() {
        assert!(
            path.starts_with("/allowed/"),
            "upstream received a path outside the grant"
        );
        let sent = format!("{path}\n{headers}\n{}", String::from_utf8_lossy(body));
        assert!(
            headers.lines().any(|l| l
                .split_once(':')
                .is_some_and(|(k, v)| k.eq_ignore_ascii_case("host")
                    && v.trim() == format!("127.0.0.1:{up_port}"))),
            "credential sent to a different authority"
        );
        assert!(headers.lines().any(|l| l
            .split_once(':')
            .is_some_and(|(k, v)| k.eq_ignore_ascii_case("authorization")
                && v.trim() == format!("Bearer {}", INVARIANT_SECRETS[0]))));
        for secret in &INVARIANT_SECRETS[1..] {
            assert!(
                !sent.contains(secret),
                "bystander credential reached upstream"
            );
        }
        for cap in [&marker, &limited.placeholder, &token] {
            assert!(!sent.contains(cap), "daemon capability reached upstream");
        }
        assert!(!path.contains(INVARIANT_SECRETS[0]));
        assert!(!String::from_utf8_lossy(body).contains(INVARIANT_SECRETS[0]));
    }
    shared
        .run(move |core| {
            let row = core
                .vault
                .list_placeholders(None)
                .unwrap()
                .into_iter()
                .find(|r| r.id == limited_id)
                .unwrap();
            assert_eq!(row.max_uses, 3);
            assert!(row.uses <= row.max_uses);
            if row.uses == 3 {
                assert_eq!(row.state, av_store::model::PlaceholderState::Dead);
            }
            let audit = core.vault.audit().unwrap();
            let verified = audit.verify().unwrap();
            assert!(verified.ok, "audit chain: {verified:?}");
            assert!(
                verified.count > 1000,
                "expected a busy log, got {}",
                verified.count
            );
            let raw = serde_json::to_string(
                &audit
                    .read(&av_store::audit::ReadFilter {
                        limit: usize::MAX,
                        ..Default::default()
                    })
                    .unwrap(),
            )
            .unwrap();
            for secret in INVARIANT_SECRETS {
                assert!(!raw.contains(secret), "credential reached audit log");
            }
            for cap in [&marker, &limited.placeholder, &token] {
                assert!(!raw.contains(cap), "daemon capability reached audit log");
            }
        })
        .await
        .unwrap();
    daemon.stop().await;
    peer.abort();
    let _ = peer.await;
}

#[test]
fn invariants_generated_real_daemon_sequences_preserve_all_five_claims_for_2400_random_requests() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngSeed, TestRunner};
    let shape = (0u8..17, 0u8..4, 0u8..6, 0u8..20, 0u8..3).prop_map(
        |(kind, inline, body_encoding, limited, path)| InvariantShape {
            kind,
            inline,
            body_encoding,
            limited: limited < 3,
            path,
        },
    );
    let sequences = proptest::collection::vec(shape, 600);
    for seed in [20260921, 7, 31337, 999983] {
        let mut runner = TestRunner::new(Config {
            cases: 1,
            rng_seed: RngSeed::Fixed(seed),
            max_shrink_iters: 0,
            failure_persistence: None,
            ..Config::default()
        });
        runner
            .run(&sequences, |rows| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(180),
                        check_invariant_sequence(&rows),
                    )
                    .await
                    .expect("invariant sequence timed out");
                });
                Ok(())
            })
            .unwrap_or_else(|e| panic!("invariants seed {seed}: {e}"));
    }
}

// control-api-credentials.test.js: all routes use a disposable vault and the
// public control socket. The real presence window is opened/closed via API.
const CONTROL_ROTATED: &str = "ghp_PORTEDROTATEDVALUE99887766554433221100aa";
async fn credential_api(f: &Fixture, method: &str, path: &str, body: Value) -> (u16, Value) {
    let r = control_method(&f._dir.path().join("control.sock"), method, path, body).await;
    let text = serde_json::to_string(&r.1).unwrap();
    for secret in [
        &f.secret,
        CONTROL_ROTATED,
        "OTHER-SECRET-0099887766",
        "LATER-SECRET-00112233",
    ] {
        assert!(
            !text.contains(secret),
            "control response revealed credential"
        );
    }
    r
}
async fn credential_gate(f: &Fixture, open: bool) {
    if open {
        let (s, v) = credential_api(
            f,
            "POST",
            "/v1/presence/window",
            json!({"passphrase":WIDEN_PASS}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["granted"], true);
    } else {
        assert_eq!(
            credential_api(f, "POST", "/v1/lock", json!({})).await.0,
            200
        );
        assert_eq!(
            credential_api(f, "POST", "/v1/unlock", json!({"passphrase":WIDEN_PASS}))
                .await
                .0,
            200
        );
    }
}
async fn credential_factor(f: &Fixture) {
    assert_eq!(
        credential_api(
            f,
            "POST",
            "/v1/passphrase",
            json!({"passphrase":WIDEN_PASS})
        )
        .await
        .0,
        200
    );
    credential_gate(f, false).await;
}
fn credential_presence_refused(r: (u16, Value)) {
    assert_eq!(r.0, 401, "{}", r.1);
    assert_eq!(r.1["code"], "AV_PRESENCE_REQUIRED");
}
async fn credential_tool(f: &Fixture, name: &str, args: Value, session: bool) -> Value {
    let record = if session {
        let t = f.token.clone();
        f.shared
            .run(move |c| c.vault.session_by_token(&t).unwrap())
            .await
            .unwrap()
    } else {
        None
    };
    let result=f.daemon.mcp().handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),record,session.then(||f.token.clone()),None).await.unwrap();
    let text = result["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains(&f.secret));
    serde_json::from_str(text).unwrap()
}
async fn credential_finish(f: &Fixture) {
    let text = serde_json::to_string(&audit_records(f).await).unwrap();
    for secret in [
        &f.secret,
        CONTROL_ROTATED,
        WIDEN_PASS,
        CONTROL_RECOVERY,
        "OTHER-SECRET-0099887766",
        "LATER-SECRET-00112233",
    ] {
        assert!(!text.contains(secret), "credential leaked to audit");
    }
    f.daemon.stop().await;
}

#[tokio::test]
async fn control_credentials_rotation_requires_presence_and_new_value_reaches_only_declared_site() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:authorization:Bearer"]).await;
        credential_factor(&f).await;
        let rotate = json!({"slug":"demo","value":CONTROL_ROTATED,"retire_hours":2});
        credential_presence_refused(
            credential_api(&f, "POST", "/v1/credentials/rotate", rotate.clone()).await,
        );
        let ordinary = f
            .send(
                "GET",
                "/x",
                vec![("authorization".into(), format!("Bearer {}", f.ph))],
                None,
            )
            .await;
        assert_eq!(ordinary.status, 200);
        assert_eq!(
            f.up.hits
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .unwrap()
                .1,
            format!("Bearer {}", f.secret)
        );
        credential_gate(&f, true).await;
        let (s, v) = credential_api(&f, "POST", "/v1/credentials/rotate", rotate).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["rotated"]["version"], 2);
        assert_eq!(v["rotated"]["mode"], "keep");
        assert_eq!(v["invalidated_approvals"], 0);
        f.reply(200, "text/plain", format!("ordinary {CONTROL_ROTATED}"));
        let response = f
            .send(
                "GET",
                "/x",
                vec![("authorization".into(), format!("Bearer {}", f.ph))],
                None,
            )
            .await;
        assert_eq!(response.status, 200);
        assert!(!String::from_utf8_lossy(&response.body).contains(CONTROL_ROTATED));
        assert_eq!(
            f.up.hits
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .unwrap()
                .1,
            format!("Bearer {CONTROL_ROTATED}")
        );
        credential_finish(&f).await;
    })
    .await
    .expect("rotation timed out");
}

#[tokio::test]
async fn control_credentials_rotation_denies_held_approvals_and_invalid_shapes_change_nothing() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        for (body, rule) in [
            (
                json!({"slug":"demo","value":CONTROL_ROTATED,"retire_hours":169}),
                "retire_window",
            ),
            (
                json!({"slug":"demo","value":CONTROL_ROTATED,"retire_hours":1.5}),
                "retire_window",
            ),
            (
                json!({"slug":"demo","value":CONTROL_ROTATED,"retire_hours":"2"}),
                "retire_window",
            ),
            (
                json!({"slug":"demo","value":CONTROL_ROTATED,"mode":"later"}),
                "rotate_mode",
            ),
            (json!({"slug":"demo","value":SECRET}), "rotate_same_value"),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/credentials/rotate", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], rule);
        }
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/rotate",
                json!({"slug":"missing","value":CONTROL_ROTATED})
            )
            .await
            .0,
            404
        );
        assert_eq!(f.get().await.status, 200);
        assert_eq!(
            f.up.hits
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-key"))
                .unwrap()
                .1,
            SECRET
        );
        credential_finish(&f).await;
        let f = approval_fixture("each", &["header:x-key"]).await;
        assert_eq!(f.get().await.status, 202);
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/credentials/rotate",
            json!({"slug":"demo","value":CONTROL_ROTATED}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["invalidated_approvals"], 1);
        assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
        assert!(audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "approval.denied" && r["reason"] == "credential_rotated"));
        credential_finish(&f).await;
    })
    .await
    .expect("rotation refusals timed out");
}

#[tokio::test]
async fn control_credentials_scrub_presence_sample_and_pre_gate_refusals_preserve_ordinary_traffic()
{
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;
        let pattern="acme_[A-Za-z0-9]{20,40}";
        credential_presence_refused(credential_api(&f,"POST","/v1/credentials/scrub",json!({"slug":"demo","pattern":pattern})).await);
        let(_,list)=credential_api(&f,"GET","/v1/credentials",json!({})).await;assert_eq!(list[0]["scrub_patterns"].as_array().unwrap().len(),0);
        for pattern in [json!("(a+)+b"),json!(".*"),json!("a"),json!("[a-z]+"),json!(42)] {let(s,v)=credential_api(&f,"POST","/v1/credentials/scrub",json!({"slug":"demo","pattern":pattern})).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"scrub_pattern");}
        credential_gate(&f,true).await;
        let(_,v)=credential_api(&f,"POST","/v1/credentials/scrub",json!({"slug":"demo","pattern":SECRET})).await;assert_eq!(v["rule"],"scrub_pattern");
        let(_,v)=credential_api(&f,"POST","/v1/credentials/scrub",json!({"slug":"demo","pattern":"acme_[a-z]{4}","sample":5})).await;assert_eq!(v["rule"],"policy_invalid");
        let(s,v)=credential_api(&f,"POST","/v1/credentials/scrub",json!({"slug":"demo","pattern":pattern,"sample":"before acme_abcdefghijklmnopqrstuvwx after, and acme_short"})).await;assert_eq!(s,200,"{v}");let id=v["id"].as_str().unwrap();assert!(id.starts_with("sp_"));assert_eq!(v["sample"]["matches"],1);assert_eq!(v["sample"]["redacted"],"before [[av:derived]] after, and acme_short");
        let(_,list)=credential_api(&f,"GET","/v1/credentials",json!({})).await;assert_eq!(list[0]["scrub_patterns"][0]["source"],pattern);
        let rows=audit_records(&f).await;let added=rows.iter().find(|r|r["kind"]=="cred.scrub_pattern_added").unwrap();assert_eq!(added["length"],pattern.len());assert!(!added.to_string().contains(pattern));
        credential_gate(&f,false).await;let path=format!("/v1/credentials/scrub?slug=demo&id={id}");credential_presence_refused(credential_api(&f,"DELETE",&path,json!({})).await);credential_gate(&f,true).await;
        assert_eq!(credential_api(&f,"DELETE",&path,json!({})).await.1,json!({"ok":true,"removed":true}));assert_eq!(credential_api(&f,"DELETE",&path,json!({})).await.1,json!({"ok":true,"removed":false}));assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("scrub routes timed out");
}

#[tokio::test]
async fn control_credentials_expiry_is_gated_metadata_and_bad_addition_stores_nothing() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;
        credential_presence_refused(credential_api(&f,"POST","/v1/credentials/expiry",json!({"slug":"demo","expires_at":"2020-01-01"})).await);credential_gate(&f,true).await;
        for body in [json!({"slug":"demo","expires_at":"not a date"}),json!({"slug":"demo","expires_at":20200101}),json!({"slug":"demo"})] {assert_eq!(credential_api(&f,"POST","/v1/credentials/expiry",body).await.1["rule"],"expires_at");}
        let(s,v)=credential_api(&f,"POST","/v1/credentials/expiry",json!({"slug":"demo","expires_at":"2020-01-01T00:00:00Z"})).await;assert_eq!(s,200,"{v}");assert_eq!(v["expiry_warning"],"expired");assert_eq!(f.get().await.status,200);
        assert_eq!(credential_tool(&f,"vault_list_creds",json!({}),true).await[0]["expiry_warning"],"expired");assert_eq!(credential_api(&f,"GET","/v1/status",json!({})).await.1["credentials_expiring"],1);
        assert!(credential_api(&f,"POST","/v1/credentials/expiry",json!({"slug":"demo","expires_at":null})).await.1["expires_at"].is_null());
        let mut body=json!({"slug":"later","kind":"http","host":"api.example.test","value":"LATER-SECRET-00112233","expires_at":"soonish"});assert_eq!(credential_api(&f,"POST","/v1/credentials",body.clone()).await.1["rule"],"expires_at");
        let(_,list)=credential_api(&f,"GET","/v1/credentials",json!({})).await;assert!(!list.as_array().unwrap().iter().any(|c|c["slug"]=="later"));body["expires_at"]=json!("2099-01-01");let(s,v)=credential_api(&f,"POST","/v1/credentials",body).await;assert_eq!(s,200,"{v}");assert_eq!(v["expires_at"],"2099-01-01T00:00:00.000Z");assert!(!v.to_string().contains("LATER-SECRET-00112233"));credential_finish(&f).await;
    }).await.expect("expiry routes timed out");
}

#[tokio::test]
async fn control_credentials_pin_writes_require_presence_and_match_the_credentials_host() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let pin = format!("sha256/{}=", "A".repeat(43));
        let request = json!({"slug":"demo","host":"api.example.test","pins":[pin]});
        credential_presence_refused(
            credential_api(&f, "POST", "/v1/credentials/pins", request.clone()).await,
        );
        credential_gate(&f, true).await;
        let mut elsewhere = request.clone();
        elsewhere["host"] = json!("evil.example");
        assert_eq!(
            credential_api(&f, "POST", "/v1/credentials/pins", elsewhere)
                .await
                .1["rule"],
            "pin_host"
        );
        for pins in [json!(["sha256/short"]), json!("sha256/x"), Value::Null] {
            let mut bad = request.clone();
            bad["pins"] = pins;
            assert_eq!(
                credential_api(&f, "POST", "/v1/credentials/pins", bad)
                    .await
                    .1["rule"],
                "pin_format"
            );
        }
        assert_eq!(
            credential_api(&f, "POST", "/v1/credentials/pins", request)
                .await
                .1,
            json!({"slug":"demo","host":"api.example.test","pins":1})
        );
        credential_gate(&f, false).await;
        let path = "/v1/credentials/pins?slug=demo&host=api.example.test";
        credential_presence_refused(credential_api(&f, "DELETE", path, json!({})).await);
        credential_gate(&f, true).await;
        assert_eq!(
            credential_api(&f, "DELETE", path, json!({})).await.1,
            json!({"ok":true,"remaining":0})
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("pins routes timed out");
}

#[tokio::test]
async fn control_credentials_quarantine_is_open_denies_holds_and_every_session_use() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = approval_fixture("each", &["header:x-key"]).await;
        credential_factor(&f).await;
        assert_eq!(f.get().await.status, 202);
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/credentials/quarantine",
            json!({"slug":"demo","reason":format!("because {} and {}",f.ph,SECRET)}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["denied_approvals"], 1);
        assert_eq!(v["quarantine"]["by"], "control");
        assert!(!v.to_string().contains(&f.ph));
        let rows = audit_records(&f).await;
        let record = rows
            .iter()
            .find(|r| r["kind"] == "cred.quarantined")
            .unwrap();
        assert!(!record.to_string().contains(&f.ph));
        assert!(record["reason_untrusted"]
            .as_str()
            .unwrap()
            .contains("«placeholder»"));
        let r = f.get().await;
        assert_eq!(
            serde_json::from_slice::<Value>(&r.body).unwrap()["code"],
            "AV_QUARANTINED"
        );
        assert!(f.up.hits.lock().unwrap().is_empty());
        for (name, args) in [
            (
                "vault_http",
                json!({"cred":"demo","method":"GET","path":"/x","reason":"x"}),
            ),
            ("vault_get_placeholder", json!({"cred":"demo","reason":"x"})),
        ] {
            assert_eq!(
                credential_tool(&f, name, args, true).await["code"],
                "AV_QUARANTINED"
            );
        }
        credential_gate(&f, true).await;
        assert_eq!(
            credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"}))
                .await
                .1["code"],
            "AV_QUARANTINED"
        );
        assert_eq!(
            credential_tool(&f, "vault_list_creds", json!({}), true).await[0]["quarantined"],
            true
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/release",
                json!({"slug":"demo"})
            )
            .await
            .0,
            200
        );
        let ordinary = || {
            f.send(
                "GET",
                "/after-release",
                vec![("x-key".into(), f.ph.clone())],
                None,
            )
        };
        let held = ordinary().await;
        let id = held_id(&held);
        f.daemon.pipeline().decide_approval(id, true).await.unwrap();
        assert_eq!(ordinary().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("quarantine routes timed out");
}

#[tokio::test]
async fn control_credentials_quarantine_refuses_session_requests_on_both_doors_until_release() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/quarantine",
                json!({"slug":"demo"})
            )
            .await
            .0,
            200
        );
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","reason":"please"}),
        )
        .await;
        assert_eq!(s, 403, "{v}");
        assert_eq!(v["code"], "AV_QUARANTINED");
        assert_eq!(v["rule"], "quarantine");
        assert_eq!(
            credential_tool(
                &f,
                "vault_request_session",
                json!({"cred":"demo","reason":"please"}),
                false
            )
            .await["code"],
            "AV_QUARANTINED"
        );
        let (s, v) = credential_api(&f, "GET", "/v1/session-requests", json!({})).await;
        assert_eq!(s, 200, "{v}");
        assert!(v.as_array().unwrap().is_empty());
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/release",
                json!({"slug":"demo"})
            )
            .await
            .0,
            200
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/session-requests",
                json!({"cred":"demo","reason":"please"})
            )
            .await
            .0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("quarantined requests timed out");
}

#[tokio::test]
async fn control_credentials_release_requires_presence_and_reason_scrubbing_precedes_200_character_cut(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        assert_eq!(f.get().await.status, 200);
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/quarantine",
                json!({"slug":"demo","reason":format!("{}{}","x".repeat(190),SECRET)})
            )
            .await
            .0,
            200
        );
        let rows = audit_records(&f).await;
        let reason = rows
            .iter()
            .find(|r| r["kind"] == "cred.quarantined")
            .unwrap()["reason_untrusted"]
            .as_str()
            .unwrap();
        assert!(reason.chars().count() <= 200);
        assert!(!reason.contains(&SECRET[..10]));
        credential_presence_refused(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/release",
                json!({"slug":"demo"}),
            )
            .await,
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&f.get().await.body).unwrap()["code"],
            "AV_QUARANTINED"
        );
        credential_gate(&f, true).await;
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/release",
                json!({"slug":"demo"})
            )
            .await
            .1,
            json!({"slug":"demo","released":true})
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/release",
                json!({"slug":"missing"})
            )
            .await
            .0,
            404
        );
        assert_eq!(f.get().await.status, 200);
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/quarantine",
                json!({"slug":"demo","reason":7})
            )
            .await
            .1["rule"],
            "policy_invalid"
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/quarantine",
                json!({"slug":"demo","reason":"rotating after a leak"})
            )
            .await
            .0,
            200
        );
        let rows = audit_records(&f).await;
        assert_eq!(
            rows.iter()
                .rev()
                .find(|r| r["kind"] == "cred.quarantined")
                .unwrap()["reason_untrusted"],
            "rotating after a leak"
        );
        credential_finish(&f).await;
    })
    .await
    .expect("release and bounded reason timed out");
}

struct CredentialProbeFixture {
    f: Fixture,
    hits: Arc<Mutex<Vec<String>>>,
    peer: tokio::task::JoinHandle<()>,
}
impl CredentialProbeFixture {
    async fn new() -> Self {
        use tokio::io::AsyncWriteExt;
        let mut f = Fixture::new(&["header:x-key"]).await;
        f.daemon.stop().await;
        // Replace the injected recording transport with the production HTTP
        // transport, so the pin-over-plaintext refusal is tested on real wire.
        f.daemon = Daemon::new(
            f.shared.clone(),
            DaemonOptions {
                port: 0,
                socket_path: Some(f._dir.path().join("control.sock")),
                ..Default::default()
            },
        )
        .unwrap();
        f.daemon.start().await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let recorded = hits.clone();
        let peer = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (h, body) = read_wire_request(&mut socket).await;
                assert!(body.is_empty());
                recorded.lock().unwrap().push(h.clone());
                let reply = json!({"login":"octo","echoed":h}).to_string();
                let head=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-oauth-scopes: repo, read:org\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.len());
                socket.write_all(head.as_bytes()).await.unwrap();
                socket.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        for slug in ["gh", "gh2"] {
            let(s,v)=credential_api(&f,"POST","/v1/credentials",json!({"slug":slug,"kind":"github","host":format!("127.0.0.1:{port}"),"scheme":"http","value":format!("ghp_PROBE{}SECRET0011223344556677",slug.to_uppercase()),"sites":["header:authorization:Bearer"]})).await;
            assert_eq!(s, 200, "{v}");
            assert!(!v.to_string().contains("PROBEGH"));
        }
        Self { f, hits, peer }
    }
    async fn request(&self, body: Value) -> (u16, Value) {
        let r = credential_api(&self.f, "POST", "/v1/credentials/test", body).await;
        assert!(!r.1.to_string().contains("PROBEGH"));
        r
    }
    async fn finish(self) {
        assert!(!serde_json::to_string(&audit_records(&self.f).await)
            .unwrap()
            .contains("PROBEGH"));
        credential_finish(&self.f).await;
        self.peer.abort();
        let _ = self.peer.await;
    }
}

#[tokio::test]
async fn control_credentials_probe_is_open_fixed_read_only_bodyless_and_honors_pins() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let p=CredentialProbeFixture::new().await;credential_factor(&p.f).await;
        let(s,v)=p.request(json!({"slug":"gh","path":"/repos/x/y/keys","method":"DELETE","body":"x"})).await;assert_eq!(s,200,"{v}");assert_eq!(v["ok"],true);assert_eq!(v["status"],"ok");assert_eq!(v["http_status"],200);
        let hits=p.hits.lock().unwrap().clone();assert_eq!(hits.len(),1);assert_eq!(hits[0].lines().next().unwrap(),"GET /user HTTP/1.1");assert!(hits[0].to_ascii_lowercase().contains("authorization: bearer ghp_probeghsecret0011223344556677"));
        let rows=audit_records(&p.f).await;let record=rows.iter().find(|r|r["kind"]=="cred.tested").unwrap();assert_eq!(record["credential_slug"],"gh");assert_eq!(record["http_status"],200);
        credential_gate(&p.f,true).await;assert_eq!(credential_api(&p.f,"POST","/v1/credentials/pins",json!({"slug":"gh2","host":"127.0.0.1","pins":[format!("sha256/{}=","B".repeat(43))]})).await.0,200);
        let(s,v)=p.request(json!({"slug":"gh2"})).await;assert_eq!(s,502,"{v}");assert_eq!(v["code"],"AV_PIN_MISMATCH");assert_eq!(v["rule"],"pin_plaintext");assert_eq!(p.hits.lock().unwrap().len(),1);
        assert_eq!(p.request(json!({"slug":"demo"})).await.1["rule"],"no_probe");assert_eq!(p.request(json!({"slug":"missing"})).await.0,404);assert_eq!(p.request(json!({"all":"yes"})).await.1["rule"],"policy_invalid");p.finish().await;
    }).await.expect("real probe routes timed out");
}

#[tokio::test]
async fn control_credentials_probe_throttle_is_per_credential_and_all_reports_each_failure() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let p = CredentialProbeFixture::new().await;
        assert_eq!(p.request(json!({"slug":"gh"})).await.0, 200);
        let (s, v) = p.request(json!({"slug":"gh"})).await;
        assert_eq!(s, 429, "{v}");
        assert_eq!(v["code"], "AV_QUOTA_EXCEEDED");
        assert_eq!(v["rule"], "probe_throttle");
        assert!(v["retry_after"].as_u64().unwrap() > 0);
        assert_eq!(p.hits.lock().unwrap().len(), 1);
        assert_eq!(p.request(json!({"slug":"gh2"})).await.0, 200);
        assert_eq!(p.hits.lock().unwrap().len(), 2);
        let (s, v) = p.request(json!({"all":true})).await;
        assert_eq!(s, 200, "{v}");
        let results = v["results"].as_array().unwrap();
        let gh = results.iter().find(|r| r["slug"] == "gh").unwrap();
        assert_eq!(gh["error"], "AV_QUOTA_EXCEEDED");
        assert!(gh["retry_after"].as_u64().unwrap() > 0);
        assert_eq!(
            results.iter().find(|r| r["slug"] == "demo").unwrap()["error"],
            "AV_NOT_FOUND"
        );
        assert_eq!(p.hits.lock().unwrap().len(), 2);
        p.finish().await;
    })
    .await
    .expect("probe throttling timed out");
}

#[tokio::test]
async fn control_containment_panic_is_open_and_revokes_finite_infinite_and_waiting_work() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        use av_core::secret::ExposeSecret;
        use av_store::vault::{CreateSessionOptions,CreateGrantOptions,IssueOptions};
        let f=approval_fixture("each",&["header:x-key"]).await;credential_factor(&f).await;
        let gid=f.grant_id.clone();let extras=f.shared.run(move|c| {
            let cred=c.vault.grant(&gid).unwrap().unwrap().credential_id;
            [false,true].into_iter().map(|infinite| {
                let session=c.vault.create_session(CreateSessionOptions{infinite,..Default::default()}).unwrap();
                let grant=c.vault.create_grant(CreateGrantOptions{session_id:session.session.id,credential_id:cred.clone(),policy:serde_json::from_value(json!({"hosts":["api.example.test"],"paths":["/**"],"methods":["GET"],"approval":"auto"})).unwrap(),..Default::default()}).unwrap();
                let ph=c.vault.issue_placeholder(IssueOptions{grant_id:grant.id,..Default::default()}).unwrap();(session.token.expose_secret().to_string(),ph.placeholder)
            }).collect::<Vec<_>>()
        }).await.unwrap();
        let request=|token:&str,ph:&str|GatewayRequest{method:"GET".into(),path:"/p/demo/x".into(),headers:vec![("host".into(),"127.0.0.1".into()),("av-session".into(),token.into()),("x-key".into(),ph.into())],..Default::default()};
        let ordinary=f.daemon.pipeline().handle(request(&extras[0].0,&extras[0].1)).await;assert_eq!(ordinary.status,200);f.clean(&ordinary).await;
        assert_eq!(f.get().await.status,202);let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","reason":"later"})).await;assert_eq!(s,200,"{asked}");
        let(s,v)=credential_api(&f,"POST","/v1/panic",json!({"reason":"agent went rogue"})).await;assert_eq!(s,200,"{v}");assert_eq!(v,json!({"revoked_sessions":3,"denied_approvals":1,"denied_session_requests":1,"locked":false}));
        f.shared.run(|c| {assert!(c.vault.sessions().unwrap().iter().all(|s|s.state==av_store::model::SessionState::Revoked));assert!(c.sr_pending().is_empty());}).await.unwrap();assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
        let rows=audit_records(&f).await;assert!(rows.iter().any(|r|r["kind"]=="session_request.denied"&&r["request_id"]==asked["id"]&&r["reason"]=="panic"));let triggered=rows.iter().find(|r|r["kind"]=="panic.triggered").unwrap();assert_eq!(triggered["denied_session_requests"],1);assert_eq!(triggered["reason_untrusted"],"agent went rogue");
        let before=f.up.hits.lock().unwrap().len();for(token,ph)in extras {assert_ne!(f.daemon.pipeline().handle(request(&token,&ph)).await.status,200);}assert_ne!(f.get().await.status,200);assert_eq!(f.up.hits.lock().unwrap().len(),before);credential_finish(&f).await;
    }).await.expect("control panic timed out");
}

#[tokio::test]
async fn control_containment_invalid_panic_changes_nothing_and_panic_lock_closes_the_window() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        for body in [
            json!({"lock":"true"}),
            json!({"lock":1}),
            json!({"reason":5}),
            json!({"reason":"x".repeat(201)}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/panic", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "policy_invalid");
            assert_eq!(f.get().await.status, 200);
        }
        f.shared
            .run(|c| {
                assert!(!c.vault.locked());
                assert!(c
                    .vault
                    .sessions()
                    .unwrap()
                    .iter()
                    .all(|s| s.state == av_store::model::SessionState::Active));
            })
            .await
            .unwrap();
        credential_gate(&f, true).await;
        let (s, v) = credential_api(&f, "POST", "/v1/panic", json!({"lock":true})).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["locked"], true);
        f.shared.run(|c| assert!(c.vault.locked())).await.unwrap();
        let (s, v) = credential_api(&f, "POST", "/v1/panic", json!({})).await;
        assert_eq!(s, 423, "{v}");
        assert_eq!(v["code"], "AV_LOCKED");
        assert_eq!(v["locked"], true);
        assert_eq!(v["already"], true);
        assert_eq!(
            credential_api(&f, "POST", "/v1/unlock", json!({"passphrase":WIDEN_PASS}))
                .await
                .0,
            200
        );
        credential_presence_refused(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/expiry",
                json!({"slug":"demo","expires_at":null}),
            )
            .await,
        );
        credential_finish(&f).await;
    })
    .await
    .expect("strict panic and lock timed out");
}

#[tokio::test]
async fn control_containment_only_exact_tripwire_enable_is_open_and_invalid_changes_store_nothing()
{
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;
        let(s,v)=credential_api(&f,"GET","/v1/tripwires",json!({})).await;assert_eq!(s,200,"{v}");assert_eq!(v["enabled"],false);assert_eq!(v["rules_saved"],false);assert_eq!(v["rules"],v["defaults"]);assert!(v["defaults"].as_array().unwrap().iter().any(|r|r["id"]=="replay"));
        for body in [json!({"enabled":false}),json!({"enabled":"true"}),json!({"enabled":1}),json!({"enabled":true,"extra":1}),json!({"enabled":true,"rules":"defaults"}),json!({"rules":[]}),json!({})] {credential_presence_refused(credential_api(&f,"POST","/v1/tripwires",body).await);}
        f.shared.run(|c|assert!(c.vault.get_settings().unwrap().get("tripwires").is_none())).await.unwrap();
        let(s,v)=credential_api(&f,"POST","/v1/tripwires",json!({"enabled":true})).await;assert_eq!(s,200,"{v}");assert_eq!(v["enabled"],true);assert!(v["rules"].as_array().unwrap().iter().any(|r|r["id"]=="replay"));credential_presence_refused(credential_api(&f,"POST","/v1/tripwires",json!({"enabled":false})).await);
        credential_gate(&f,true).await;let custom=json!([{"id":"mine","codes":["AV_BAD_LOCATION"],"threshold":2,"window_s":60,"action":"revoke_session"}]);assert_eq!(credential_api(&f,"POST","/v1/tripwires",json!({"rules":custom})).await.1,json!({"enabled":true,"rules":custom}));
        for body in [json!({"rules":[{"id":"X Y","threshold":0}]}),json!({"enabled":"no"})] {assert_eq!(credential_api(&f,"POST","/v1/tripwires",body).await.1["rule"],"tripwire_rule");let(_,v)=credential_api(&f,"GET","/v1/tripwires",json!({})).await;assert_eq!(v["rules"],custom);assert_eq!(v["enabled"],true);}
        assert_eq!(credential_api(&f,"POST","/v1/tripwires",json!({"enabled":false})).await.1["enabled"],false);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("tripwire settings timed out");
}

#[tokio::test]
async fn control_containment_route_enabled_replay_revokes_before_response_but_disabled_control_keeps_session(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for enabled in [false, true] {
            let f = approval_fixture("on-write", &["header:x-key"]).await;
            assert_eq!(f.get().await.status, 200);
            if enabled {
                assert_eq!(
                    credential_api(&f, "POST", "/v1/tripwires", json!({"enabled":true}))
                        .await
                        .0,
                    200
                );
                assert_eq!(f.write("ordinary held write").await.status, 202);
            }
            let gid = f.grant_id.clone();
            let marker = f
                .shared
                .run(move |c| {
                    let issued = c
                        .vault
                        .issue_placeholder(av_store::vault::IssueOptions {
                            grant_id: gid,
                            ..Default::default()
                        })
                        .unwrap();
                    c.vault.burn_placeholder(&issued.row.id, "spent").unwrap();
                    issued.placeholder
                })
                .await
                .unwrap();
            let r = f
                .send("GET", "/replay", vec![("x-key".into(), marker)], None)
                .await;
            assert_eq!(
                serde_json::from_slice::<Value>(&r.body).unwrap()["code"],
                "AV_PH_REPLAY"
            );
            f.clean(&r).await;
            let fired = audit_records(&f)
                .await
                .iter()
                .filter(|r| r["kind"] == "tripwire.fired")
                .count();
            assert_eq!(fired > 0, enabled);
            let token = f.token.clone();
            let state = f
                .shared
                .run(move |c| c.vault.session_by_token(&token).unwrap().unwrap().state)
                .await
                .unwrap();
            assert_eq!(
                state,
                if enabled {
                    av_store::model::SessionState::Revoked
                } else {
                    av_store::model::SessionState::Active
                }
            );
            if enabled {
                assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
                assert_ne!(f.get().await.status, 200);
            } else {
                assert_eq!(f.get().await.status, 200);
            }
            credential_finish(&f).await;
        }
    })
    .await
    .expect("tripwire replay routes timed out");
}

const CONTROL_RECOVERY: &str = "fake recovery passphrase for disposable vault";
async fn control_export(f: &Fixture) -> Value {
    use base64::Engine;
    let (s, v) = credential_api(
        f,
        "POST",
        "/v1/backup/export",
        json!({"recovery_passphrase":CONTROL_RECOVERY,"presence":{"passphrase":WIDEN_PASS}}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let text = v.to_string();
    assert!(!text.contains(CONTROL_RECOVERY));
    assert!(!text.contains(&base64::engine::general_purpose::STANDARD.encode(&f.secret)));
    v
}
fn is_hex_digest(v: &Value) {
    let s = v.as_str().unwrap();
    assert_eq!(s.len(), 64);
    assert!(s
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
}

#[tokio::test]
async fn control_backup_export_requires_factor_and_fresh_proof_even_with_window_and_hides_every_secret(
) {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/backup/export",
            json!({"recovery_passphrase":CONTROL_RECOVERY}),
        )
        .await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["rule"], "factor_required");
        assert_eq!(
            credential_api(&f, "POST", "/v1/lock", json!({})).await.0,
            200
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/backup/export",
                json!({"recovery_passphrase":CONTROL_RECOVERY})
            )
            .await
            .1["code"],
            "AV_LOCKED"
        );
        assert_eq!(
            credential_api(&f, "POST", "/v1/unlock", json!({})).await.0,
            200
        );
        credential_factor(&f).await;
        credential_gate(&f, true).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/backup/export",
            json!({"recovery_passphrase":CONTROL_RECOVERY}),
        )
        .await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["rule"], "fresh_presence");
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/backup/export",
                json!({"recovery_passphrase":CONTROL_RECOVERY,"presence":{"passphrase":"not it"}})
            )
            .await
            .1["code"],
            "AV_PRESENCE_DENIED"
        );
        credential_gate(&f, false).await;
        let exported = control_export(&f).await;
        assert_eq!(exported["summary"]["credentials"], 1);
        is_hex_digest(&exported["bundle_sha256"]);
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/backup/export",
                json!({"recovery_passphrase":"short","presence":{"passphrase":WIDEN_PASS}})
            )
            .await
            .1["rule"],
            "recovery_passphrase"
        );
        assert!(audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "presence.verified"
                && r["op"] == "backup export"
                && r["fresh"] == true));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("backup export timed out");
}

#[tokio::test]
async fn control_backup_inspection_is_open_and_real_auth_failures_survive_success_until_backoff() {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let bundle = control_export(&f).await["bundle"].clone();
        let inspect = |pass: &str| json!({"bundle":bundle,"recovery_passphrase":pass});
        let (s, v) =
            credential_api(&f, "POST", "/v1/backup/inspect", inspect(CONTROL_RECOVERY)).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            v["credentials"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c["slug"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["demo"]
        );
        assert_eq!(
            audit_records(&f)
                .await
                .iter()
                .filter(|r| r["kind"] == "backup.inspected")
                .count(),
            1
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/backup/inspect",
                json!({"bundle":{"format":"other"},"recovery_passphrase":CONTROL_RECOVERY})
            )
            .await
            .1["rule"],
            "backup_format"
        );
        for _ in 0..3 {
            assert_eq!(
                credential_api(
                    &f,
                    "POST",
                    "/v1/backup/inspect",
                    inspect("wrong recovery passphrase")
                )
                .await
                .1["rule"],
                "backup_auth"
            );
        }
        // A successful recovery read must not erase three real failed guesses.
        assert_eq!(
            credential_api(&f, "POST", "/v1/backup/inspect", inspect(CONTROL_RECOVERY))
                .await
                .0,
            200
        );
        for _ in 0..2 {
            assert_eq!(
                credential_api(
                    &f,
                    "POST",
                    "/v1/backup/inspect",
                    inspect("wrong recovery passphrase")
                )
                .await
                .1["rule"],
                "backup_auth"
            );
        }
        let (s, v) =
            credential_api(&f, "POST", "/v1/backup/inspect", inspect(CONTROL_RECOVERY)).await;
        assert_eq!(s, 429, "{v}");
        assert_eq!(v["code"], "AV_RATE_LIMITED");
        assert!(audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "presence.throttled" && r["consecutive_failures"] == 5));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("backup inspection and real throttle timed out");
}

#[tokio::test]
async fn control_backup_restore_is_gated_renames_credentials_but_never_imports_sessions() {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let a = Fixture::new(&["header:x-key"]).await;
        let b = Fixture::new(&["header:x-key"]).await;
        credential_factor(&a).await;
        credential_factor(&b).await;
        let bundle = control_export(&a).await["bundle"].clone();
        let request =
            json!({"bundle":bundle,"recovery_passphrase":CONTROL_RECOVERY,"on_conflict":"rename"});
        credential_presence_refused(
            credential_api(&b, "POST", "/v1/backup/restore", request.clone()).await,
        );
        credential_gate(&b, true).await;
        let mut wrong = request.clone();
        wrong["recovery_passphrase"] = json!("wrong recovery passphrase");
        assert_eq!(
            credential_api(&b, "POST", "/v1/backup/restore", wrong)
                .await
                .1["rule"],
            "backup_auth"
        );
        let (s, v) = credential_api(&b, "POST", "/v1/backup/restore", request).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["renamed"], json!([{"from":"demo","to":"demo-restored"}]));
        let (_, creds) = credential_api(&b, "GET", "/v1/credentials", json!({})).await;
        assert!(creds
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["slug"] == "demo-restored"));
        let refused = b
            .daemon
            .pipeline()
            .handle(GatewayRequest {
                method: "GET".into(),
                path: "/p/demo-restored/x".into(),
                headers: vec![
                    ("host".into(), "127.0.0.1".into()),
                    ("authorization".into(), format!("Bearer {}", a.token)),
                ],
                ..Default::default()
            })
            .await;
        assert_ne!(refused.status, 200);
        assert!(b.up.hits.lock().unwrap().is_empty());
        assert_eq!(
            credential_api(
                &b,
                "POST",
                "/v1/backup/restore",
                json!({"bundle":bundle,"recovery_passphrase":CONTROL_RECOVERY,"on_conflict":"fail"})
            )
            .await
            .1["rule"],
            "backup_conflict"
        );
        // Four further real auth failures prove the restore failure was charged.
        for _ in 0..4 {
            assert_eq!(
                credential_api(
                    &b,
                    "POST",
                    "/v1/backup/inspect",
                    json!({"bundle":bundle,"recovery_passphrase":"wrong recovery passphrase"})
                )
                .await
                .1["rule"],
                "backup_auth"
            );
        }
        assert!(audit_records(&b)
            .await
            .iter()
            .any(|r| r["kind"] == "presence.throttled" && r["consecutive_failures"] == 5));
        assert_eq!(a.get().await.status, 200);
        assert_eq!(b.get().await.status, 200);
        credential_finish(&a).await;
        credential_finish(&b).await;
    })
    .await
    .expect("backup restoration timed out");
}

#[tokio::test]
async fn control_audit_pages_validate_ranges_and_witnesses_are_open_but_refused_while_locked() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let (s, page) =
            credential_api(&f, "GET", "/v1/audit/export?since_seq=0&limit=3", json!({})).await;
        assert_eq!(s, 200, "{page}");
        assert_eq!(page["rows"].as_array().unwrap().len(), 3);
        assert_eq!(page["next_seq"], page["rows"][2]["seq"]);
        let (_, rest) = credential_api(
            &f,
            "GET",
            &format!("/v1/audit/export?since_seq={}", page["next_seq"]),
            json!({}),
        )
        .await;
        assert!(rest["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["seq"].as_u64().unwrap() > page["next_seq"].as_u64().unwrap()));
        for query in [
            "since_seq=x",
            "since_seq=-1",
            "since_seq=1.5",
            "limit=",
            "limit=1e3",
            "since_seq=%201",
        ] {
            let (s, v) =
                credential_api(&f, "GET", &format!("/v1/audit/export?{query}"), json!({})).await;
            assert_eq!(s, 403, "{query}: {v}");
            assert_eq!(v["rule"], "audit_range");
        }
        let (s, cp) = credential_api(&f, "GET", "/v1/audit/checkpoint", json!({})).await;
        assert_eq!(s, 200, "{cp}");
        is_hex_digest(&cp["mac"]);
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/audit/verify-witness",
                json!({"checkpoints":[cp]})
            )
            .await
            .1["ok"],
            true
        );
        let mut forged = cp.clone();
        forged["seq"] = json!(cp["seq"].as_u64().unwrap() - 1);
        let (_, v) = credential_api(
            &f,
            "POST",
            "/v1/audit/verify-witness",
            json!({"checkpoints":[forged]}),
        )
        .await;
        assert_eq!(v["ok"], false);
        assert_eq!(v["forged"], json!([0]));
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/audit/verify-witness",
                json!({"checkpoints":"all"})
            )
            .await
            .1["rule"],
            "audit_range"
        );
        assert_eq!(
            credential_api(&f, "POST", "/v1/lock", json!({})).await.0,
            200
        );
        for (method, path, body) in [
            ("GET", "/v1/audit/export", json!({})),
            ("GET", "/v1/audit/checkpoint", json!({})),
            (
                "POST",
                "/v1/audit/verify-witness",
                json!({"checkpoints":[]}),
            ),
        ] {
            assert_eq!(
                credential_api(&f, method, path, body).await.1["code"],
                "AV_LOCKED"
            );
        }
        assert_eq!(
            credential_api(&f, "POST", "/v1/unlock", json!({})).await.0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("audit read routes timed out");
}

async fn control_session_sid(f: &Fixture) -> String {
    let t = f.token.clone();
    f.shared
        .run(move |c| c.vault.session_by_token(&t).unwrap().unwrap().id)
        .await
        .unwrap()
}
async fn control_session_policy(f: &Fixture, gid: &str) -> Value {
    let gid = gid.to_owned();
    f.shared
        .run(move |c| serde_json::to_value(c.vault.grant(&gid).unwrap().unwrap().policy).unwrap())
        .await
        .unwrap()
}
async fn control_session_request(
    f: &Fixture,
    body: &Value,
    cred: &str,
    method: &str,
    path: &str,
) -> GatewayResponse {
    let grant = body["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["cred"] == cred)
        .unwrap();
    f.daemon
        .pipeline()
        .handle(GatewayRequest {
            method: method.into(),
            path: format!("/p/{cred}{path}"),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), body["token"].as_str().unwrap().into()),
                (
                    "x-key".into(),
                    grant["placeholder"].as_str().unwrap().into(),
                ),
            ],
            ..Default::default()
        })
        .await
}

#[tokio::test]
async fn control_sessions_create_refuses_zero_budget_before_presence_and_unreadable_limits_are_atomic(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let before = f
            .shared
            .run(|c| c.vault.sessions().unwrap().len())
            .await
            .unwrap();
        let audits = audit_records(&f).await.len();
        for body in [
            json!({"cred":"demo","budget":0}),
            json!({"cred":"demo","budget":"0"}),
            json!({"grants":[{"cred":"demo","budget":0}]}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/sessions", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "budget");
        }
        assert_eq!(
            f.shared
                .run(|c| c.vault.sessions().unwrap().len())
                .await
                .unwrap(),
            before
        );
        assert_eq!(audit_records(&f).await.len(), audits);
        credential_presence_refused(
            credential_api(
                &f,
                "POST",
                "/v1/sessions",
                json!({"cred":"demo","budget":1}),
            )
            .await,
        );
        credential_gate(&f, true).await;
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/sessions",
                json!({"cred":"demo","budget":1})
            )
            .await
            .0,
            200
        );
        let before = f
            .shared
            .run(|c| c.vault.sessions().unwrap().len())
            .await
            .unwrap();
        for body in [
            json!({"cred":"demo","rate":"5/fortnight"}),
            json!({"cred":"demo","rate":{"count":"NaN","per":"second"}}),
            json!({"cred":"demo","max_concurrent":1.5}),
            json!({"cred":"demo","quota":"10/s"}),
            json!({"cred":"demo","routes":[{"methods":["FETCH"],"paths":["/x"]}]}),
            json!({"cred":"demo","redirects":9}),
            json!({"cred":"demo","spend_tokens":100}),
            json!({"cred":"demo","remote":"yes"}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/sessions", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "policy_invalid");
        }
        assert_eq!(
            f.shared
                .run(|c| c.vault.sessions().unwrap().len())
                .await
                .unwrap(),
            before
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("session create refusal timed out");
}

#[tokio::test]
async fn control_sessions_create_converts_every_limit_defaults_and_grant_lifetimes() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;
        let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","methods":["GET","POST"],"rate":"2/s","quota":"100/day","max_concurrent":2,"routes":[{"methods":["GET"],"paths":["/repos/**"]}],"redirects":1,"deny_paths":["/admin/**"],"budget":"7"})).await;assert_eq!(s,200,"{v}");let p=control_session_policy(&f,v["grant_id"].as_str().unwrap()).await;
        for(k,want)in [("rate",json!({"count":2,"per":"second"})),("quota",json!({"count":100,"window":"day"})),("max_concurrent",json!(2)),("routes",json!([{"methods":["GET"],"paths":["/repos/**"]}])),("redirects",json!({"max":1})),("deny_paths",json!(["/admin/**"]))] {assert_eq!(p[k],want,"{k}");}assert_eq!(p["budget"]["limit"],7);
        let(_,plain)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await;let p=control_session_policy(&f,plain["grant_id"].as_str().unwrap()).await;assert_eq!(p["redirects"],json!({"max":0}));assert_eq!(p["methods"],json!(["GET","HEAD"]));assert!(plain["grants"][0]["expires_at"].is_null());assert_eq!(control_session_request(&f,&plain,"demo","GET","/ordinary").await.status,200);
        for ttl in [json!(0),json!(-5),json!("x"),json!(1.5)] {let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","grant_ttl_minutes":ttl})).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"grant_ttl");}
        let(s,short)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","grant_ttl_minutes":5})).await;assert_eq!(s,200,"{short}");let ends=av_daemon::util::parse_iso_ms(short["grants"][0]["expires_at"].as_str().unwrap()).unwrap();assert!((ends-av_daemon::util::now_ms()-300000).abs()<5000);
        let(s,long)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","ttl_hours":1,"grant_ttl_minutes":600})).await;assert_eq!(s,200,"{long}");assert!(av_daemon::util::parse_iso_ms(long["grants"][0]["expires_at"].as_str().unwrap()).unwrap()<=av_daemon::util::parse_iso_ms(long["expires_at"].as_str().unwrap()).unwrap()+1000);credential_finish(&f).await;
    }).await.expect("session limits and lifetimes timed out");
}

#[tokio::test]
async fn control_sessions_narrow_intersects_approval_and_methods_and_never_requires_presence() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::configured(
            &["header:x-key"],
            SECRET,
            None,
            json!({"methods":["GET"],"approval":"on-write"}),
        )
        .await;
        let sid = control_session_sid(&f).await;
        assert_eq!(f.get().await.status, 200);
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/sessions/narrow",
            json!({"sid":sid,"narrow":{"approval":"auto","methods":["DELETE"]}}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["grants"][0]["before"]["approval"], "on-write");
        assert_eq!(v["grants"][0]["after"]["approval"], "on-write");
        assert_eq!(v["grants"][0]["after"]["methods"], json!([]));
        let p = control_session_policy(&f, &f.grant_id).await;
        assert_eq!(p["approval"], "on-write");
        assert_eq!(p["methods"], json!([]));
        assert_eq!(f.get().await.status, 403);
        assert!(audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "grant.narrowed"
                && r["grant_id"] == f.grant_id
                && r["fields"].as_array().unwrap().contains(&json!("methods"))));
        credential_finish(&f).await;
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let sid = control_session_sid(&f).await;
        assert_eq!(f.write("ordinary").await.status, 200);
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/sessions/narrow",
                json!({"sid":sid,"narrow":{"methods":["GET"]}})
            )
            .await
            .0,
            200
        );
        assert_eq!(f.write("ordinary").await.status, 403);
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("live session narrowing timed out");
}

#[test]
fn control_sessions_generated_narrows_only_reduce_methods_approval_and_budget() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngSeed, TestRunner};
    let mut runner = TestRunner::new(Config {
        cases: 40,
        rng_seed: RngSeed::Fixed(7),
        failure_persistence: None,
        ..Default::default()
    });
    runner.run(&(any::<[bool;6]>(),any::<[bool;6]>(),0usize..4,0usize..4,0u64..100),|(before,chosen,mode,narrow_mode,budget)| {
        let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10),async {
                let methods=["GET","HEAD","POST","PUT","PATCH","DELETE"];let modes=["auto","first-use","on-write","each"];
                let initial=methods.iter().zip(before).filter_map(|(m,on)|on.then_some(*m)).collect::<Vec<_>>();let narrowed=methods.iter().zip(chosen).filter_map(|(m,on)|on.then_some(*m)).collect::<Vec<_>>();
                let f=Fixture::configured(&["header:x-key"],SECRET,None,json!({"methods":initial,"approval":modes[mode],"budget":{"unit":"requests","limit":50}})).await;let sid=control_session_sid(&f).await;
                let(s,v)=credential_api(&f,"POST","/v1/sessions/narrow",json!({"sid":sid,"narrow":{"methods":narrowed,"approval":modes[narrow_mode],"budget":budget}})).await;assert_eq!(s,200,"{v}");let g=&v["grants"][0];assert!(g["after"]["methods"].as_array().unwrap().iter().all(|m|g["before"]["methods"].as_array().unwrap().contains(m)));let rank=|v:&Value|modes.iter().position(|m|v==m).unwrap();assert!(rank(&g["after"]["approval"])>=rank(&g["before"]["approval"]));assert!(g["after"]["budget"]["limit"].as_u64().unwrap()<=50);credential_finish(&f).await;
            }).await.expect("generated narrowing timed out");
        });Ok(())
    }).unwrap();
}

#[tokio::test]
async fn control_sessions_narrow_refuses_redirect_widening_without_shortening_and_bad_fields_are_atomic(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let sid = control_session_sid(&f).await;
        let original = control_session_policy(&f, &f.grant_id).await;
        let session_before = f
            .shared
            .run({
                let sid = sid.clone();
                move |c| serde_json::to_value(c.vault.session(&sid).unwrap().unwrap()).unwrap()
            })
            .await
            .unwrap();
        for body in [
            json!({"sid":sid,"narrow":{"redirects":5}}),
            json!({"sid":sid,"narrow":{"redirects":3},"session_ttl_minutes":5}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/sessions/narrow", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "narrow_widens");
        }
        let after = f
            .shared
            .run({
                let sid = sid.clone();
                move |c| serde_json::to_value(c.vault.session(&sid).unwrap().unwrap()).unwrap()
            })
            .await
            .unwrap();
        assert_eq!(session_before, after);
        assert!(!audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "session.shortened"));
        for (narrow, rule) in [
            (json!({}), "narrow_empty"),
            (json!({"narrow":{}}), "narrow_empty"),
            (json!({"narrow":{"uses":1}}), "policy_invalid"),
            (json!({"narrow":{"cred":"demo"}}), "policy_invalid"),
            (json!({"narrow":"GET"}), "policy_invalid"),
            (json!({"narrow":{"approval":"sometimes"}}), "approval"),
            (json!({"narrow":{"budget":"lots"}}), "policy_invalid"),
            (json!({"narrow":{"rate":"5/fortnight"}}), "policy_invalid"),
            (json!({"session_ttl_minutes":0}), "ttl"),
            (json!({"grant_ttl_minutes":"5"}), "grant_ttl"),
            (json!({"narrow":{"grant_ttl_minutes":0}}), "grant_ttl"),
            (
                json!({"grant_ttl_minutes":5,"narrow":{"grant_ttl_minutes":10}}),
                "policy_invalid",
            ),
        ] {
            let mut body = narrow;
            body["sid"] = json!(sid);
            let (s, v) = credential_api(&f, "POST", "/v1/sessions/narrow", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], rule);
        }
        assert_eq!(control_session_policy(&f, &f.grant_id).await, original);
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/sessions/narrow",
                json!({"sid":"nope","narrow":{"methods":["GET"]}})
            )
            .await
            .0,
            404
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/sessions/narrow",
                json!({"sid":sid,"cred":"missing","narrow":{"methods":["GET"]}})
            )
            .await
            .0,
            404
        );
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/sessions/narrow",
            json!({"sid":sid,"narrow":{"redirects":0}}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["grants"][0]["after"]["redirects"], json!({"max":0}));
        assert_eq!(f.get().await.status, 200);
        assert_eq!(
            credential_api(&f, "DELETE", &format!("/v1/sessions?sid={sid}"), json!({}))
                .await
                .0,
            200
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/sessions/narrow",
                json!({"sid":sid,"narrow":{"methods":["GET"]}})
            )
            .await
            .1["code"],
            "AV_SESSION_REVOKED"
        );
        credential_finish(&f).await;
    })
    .await
    .expect("atomic narrowing refusals timed out");
}

#[tokio::test]
async fn control_sessions_narrow_lifetimes_make_infinite_finite_and_only_touch_selected_credentials(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;
        let gid=f.grant_id.clone();let v=f.shared.run(move|c|{let parent=c.vault.grant(&gid).unwrap().unwrap();let s=c.vault.create_session(av_store::vault::CreateSessionOptions{infinite:true,..Default::default()}).unwrap();let g=c.vault.create_grant(av_store::vault::CreateGrantOptions{session_id:s.session.id.clone(),credential_id:parent.credential_id,policy:parent.policy,..Default::default()}).unwrap();json!({"session_id":s.session.id,"grant_id":g.id})}).await.unwrap();let sid=v["session_id"].as_str().unwrap();let gid=v["grant_id"].as_str().unwrap();
        let(s,v)=credential_api(&f,"POST","/v1/sessions/narrow",json!({"sid":sid,"session_ttl_minutes":30,"narrow":{"grant_ttl_minutes":10}})).await;assert_eq!(s,200,"{v}");assert_eq!(v["infinite"],false);assert!(av_daemon::util::parse_iso_ms(v["expires_at"].as_str().unwrap()).unwrap()<=av_daemon::util::now_ms()+1801000);assert!(av_daemon::util::parse_iso_ms(v["grants"][0]["expires_at"].as_str().unwrap()).unwrap()<=av_daemon::util::now_ms()+601000);
        f.shared.run({let sid=sid.to_owned();move|c|assert!(!c.vault.session(&sid).unwrap().unwrap().infinite)}).await.unwrap();let rows=audit_records(&f).await;assert!(rows.iter().any(|r|r["kind"]=="session.shortened"&&r["session_id"]==sid&&r["was_infinite"]==true));assert!(rows.iter().any(|r|r["kind"]=="grant.shortened"&&r["grant_id"]==gid));
        assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"other","kind":"http","host":"api.example.test","value":"OTHER-SECRET-0099887766","sites":["header:x-key"]})).await.0,200);
        let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"grants":[{"cred":"demo","methods":["GET","POST"]},{"cred":"other","methods":["GET","POST"]}]})).await;assert_eq!(s,200,"{v}");
        let(s,n)=credential_api(&f,"POST","/v1/sessions/narrow",json!({"sid":v["session_id"],"cred":"other","narrow":{"methods":["GET"]}})).await;assert_eq!(s,200,"{n}");assert_eq!(n["grants"].as_array().unwrap().iter().map(|g|g["cred"].as_str().unwrap()).collect::<Vec<_>>(),vec!["other"]);
        assert_eq!(control_session_policy(&f,v["grants"][0]["grant_id"].as_str().unwrap()).await["methods"],json!(["GET","POST"]));assert_eq!(control_session_policy(&f,v["grants"][1]["grant_id"].as_str().unwrap()).await["methods"],json!(["GET"]));assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("narrowed lifetimes and selected credential timed out");
}

#[tokio::test]
async fn control_sessions_detail_and_access_reports_expose_metadata_without_queries_secrets_or_capabilities(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::configured(
            &["header:x-key"],
            SECRET,
            None,
            json!({"budget":{"unit":"requests","limit":100}}),
        )
        .await;
        let sid = control_session_sid(&f).await;
        for path in ["/repos/x?token=QUERYSECRET123", "/repos/y"] {
            assert_eq!(
                f.send("GET", path, vec![("x-key".into(), f.ph.clone())], None)
                    .await
                    .status,
                200
            );
        }
        assert_eq!(
            f.send(
                "GET",
                &format!("/items/{}", f.ph),
                vec![("x-key".into(), f.ph.clone())],
                None
            )
            .await
            .status,
            403
        );
        let (s, v) = credential_api(
            &f,
            "GET",
            &format!("/v1/sessions/detail?sid={sid}"),
            json!({}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let text = v.to_string();
        for private in [&f.ph, &f.token, "QUERYSECRET123"] {
            assert!(!text.contains(private));
        }
        let grant = &v["grants"][0];
        assert!(!grant["placeholders"].as_array().unwrap().is_empty());
        for p in grant["placeholders"].as_array().unwrap() {
            assert!(p["id"].as_str().unwrap().starts_with("ph_"));
            assert!(p.get("placeholder").is_none());
        }
        assert_eq!(v["activity"]["complete"], true);
        assert_eq!(v["activity"]["requests"]["allowed"], 2);
        assert!(v["activity"]["requests"]["denied"].as_u64().unwrap() >= 1);
        assert_eq!(grant["budget"]["limit"], 100);
        assert_eq!(grant["budget"]["used"], 2);
        assert_eq!(grant["budget"]["remaining"], 98);
        assert_eq!(v["session"]["infinite"], false);
        credential_finish(&f).await;
        let f = Fixture::new(&["header:x-key"]).await;
        let sid = control_session_sid(&f).await;
        assert_eq!(f.get().await.status, 200);
        let iso = av_daemon::util::iso_of_ms(av_daemon::util::now_ms() - 3600000);
        let escaped = url::form_urlencoded::byte_serialize(iso.as_bytes()).collect::<String>();
        for since in [
            String::new(),
            "?since=7d".into(),
            "?since=24h".into(),
            format!("?since={escaped}"),
        ] {
            let (s, v) =
                credential_api(&f, "GET", &format!("/v1/report/access{since}"), json!({})).await;
            assert_eq!(s, 200, "{v}");
            let mine = v["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["id"] == sid)
                .unwrap();
            assert_eq!(mine["unused_methods"], json!(["POST"]));
            assert_eq!(
                v["credentials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|c| c["slug"] == "demo")
                    .unwrap()["requests"],
                1
            );
        }
        for since in ["yesterday", "7", "-1d", "0d", "1e3h"] {
            let (s, v) = credential_api(
                &f,
                "GET",
                &format!("/v1/report/access?since={since}"),
                json!({}),
            )
            .await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "report_since");
        }
        credential_finish(&f).await;
    })
    .await
    .expect("session detail and report timed out");
}

#[tokio::test]
async fn control_sessions_override_typos_never_settle_pending_requests_and_parsed_budget_is_applied(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let parse=|v:Value|av_store::pending::parse_overrides(v.as_object().unwrap());
        let parsed=serde_json::to_value(parse(json!({"uses":"2","concurrency":"4","spend-usd":"1.25"})).unwrap()).unwrap();assert_eq!(parsed,json!({"uses":2.0,"max_concurrent":4.0,"spend_usd":1.25}));for(flag,field)in [("budget","budget"),("grant-ttl","grant_ttl_minutes")] {assert_eq!(parse(json!({flag:"abc"})).unwrap_err().field,field);}assert_eq!(serde_json::to_value(parse(json!({"route":["get,head:/repos/**"]})).unwrap()).unwrap()["routes"],json!([{"methods":["GET","HEAD"],"paths":["/repos/**"]}]));
        let f=Fixture::new(&["header:x-key"]).await;let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","budget":50,"reason":"x"})).await;assert_eq!(s,200,"{asked}");
        let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":true,"overrides":{"budget":"abc"}})).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"policy_invalid");let(_,pending)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;assert!(pending.as_array().unwrap().iter().any(|r|r["id"]==asked["id"]));
        let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":true,"overrides":parse(json!({"budget":"5"})).unwrap()})).await;assert_eq!(s,200,"{v}");assert_eq!(control_session_policy(&f,v["session"]["grant_id"].as_str().unwrap()).await["budget"]["limit"],5);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("narrowing override typos timed out");
}

async fn control_session_restart_after_seed(
    f: Fixture,
    seed: impl FnOnce(&std::path::Path),
) -> Fixture {
    control_session_restart_with_pass(f, seed, None).await
}
async fn control_session_restart_with_pass(
    f: Fixture,
    seed: impl FnOnce(&std::path::Path),
    pass: Option<&str>,
) -> Fixture {
    let Fixture {
        _dir,
        shared,
        daemon,
        up,
        token,
        ph,
        secret,
        grant_id,
    } = f;
    daemon.stop().await;
    drop(daemon);
    drop(shared);
    seed(_dir.path());
    let mut vault = av_store::vault::Vault::open(_dir.path()).unwrap();
    let pass = pass.map(|p| av_core::secret::SecretString::from(p.to_string()));
    vault.unlock(pass.as_ref()).unwrap();
    let shared = Shared::new(vault);
    let daemon = Daemon::new(
        shared.clone(),
        DaemonOptions {
            port: 0,
            socket_path: Some(_dir.path().join("control.sock")),
            pipeline: PipelineOptions {
                upstream: Some(up.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    daemon.start().await.unwrap();
    Fixture {
        _dir,
        shared,
        daemon,
        up,
        token,
        ph,
        secret,
        grant_id,
    }
}

#[tokio::test]
async fn control_sessions_expired_grant_has_its_own_code_on_gateway_and_mcp_while_other_grant_works(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let mut f=Fixture::new(&["header:x-key"]).await;assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"other","kind":"http","host":"api.example.test","value":"OTHER-SECRET-0099887766","sites":["header:x-key"]})).await.0,200);
        let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"grants":[{"cred":"demo","grant_ttl_minutes":1},{"cred":"other"}]})).await;assert_eq!(s,200,"{v}");assert_eq!(control_session_request(&f,&v,"demo","GET","/ordinary").await.status,200);let sid=v["session_id"].as_str().unwrap().to_owned();let gid=v["grants"][0]["grant_id"].as_str().unwrap().to_owned();
        f=control_session_restart_after_seed(f,move|dir|ported_common::seed_gateway_rows(dir,&sid,&gid,&json!({}),&json!({"expires_at":"2000-01-01T00:00:00.000Z"}))).await;
        let r=control_session_request(&f,&v,"demo","GET","/x").await;assert_eq!(serde_json::from_slice::<Value>(&r.body).unwrap()["code"],"AV_GRANT_EXPIRED");assert_eq!(control_session_request(&f,&v,"other","GET","/x").await.status,200);
        f.token=v["token"].as_str().unwrap().into();for(name,args)in [("vault_get_placeholder",json!({"cred":"demo","reason":"x"})),("vault_http",json!({"cred":"demo","method":"GET","path":"/x","reason":"x"}))] {assert_eq!(credential_tool(&f,name,args,true).await["code"],"AV_GRANT_EXPIRED");}credential_finish(&f).await;
    }).await.expect("expired grant route timed out");
}

#[tokio::test]
async fn control_sessions_detail_reports_missing_creation_history_and_both_reads_refuse_locked_vault(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let sid = control_session_sid(&f).await;
        let f = control_session_restart_after_seed(f, move |dir| {
            ported_common::seed_unaudited_session(dir, &sid, "ghostsession1")
        })
        .await;
        let (s, v) = credential_api(
            &f,
            "GET",
            "/v1/sessions/detail?sid=ghostsession1",
            json!({}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["activity"]["complete"], false);
        assert_eq!(
            credential_api(&f, "GET", "/v1/sessions/detail?sid=nope", json!({}))
                .await
                .0,
            404
        );
        assert_eq!(f.get().await.status, 200);
        assert_eq!(
            credential_api(&f, "POST", "/v1/lock", json!({})).await.0,
            200
        );
        for path in ["/v1/sessions/detail?sid=ghostsession1", "/v1/report/access"] {
            assert_eq!(
                credential_api(&f, "GET", path, json!({})).await.1["code"],
                "AV_LOCKED"
            );
        }
        assert_eq!(
            credential_api(&f, "POST", "/v1/unlock", json!({})).await.0,
            200
        );
        credential_finish(&f).await;
    })
    .await
    .expect("incomplete detail and lock timed out");
}

async fn control_mcp_call(
    f: &Fixture,
    name: &str,
    args: Value,
    authenticated: bool,
) -> (bool, Value) {
    let session = if authenticated {
        let token = f.token.clone();
        f.shared
            .run(move |c| c.vault.session_by_token(&token).unwrap())
            .await
            .unwrap()
    } else {
        None
    };
    let r=f.daemon.mcp().handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),session,authenticated.then(||f.token.clone()),None).await.unwrap();
    let result = &r["result"];
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains(&f.secret));
    (
        result["isError"].as_bool().unwrap_or(false),
        serde_json::from_str(text).unwrap(),
    )
}
async fn control_mcp_preflight_http(
    f: &Fixture,
    method: &str,
    body: String,
    headers: Vec<(String, String)>,
) -> (u16, Value) {
    let mut h = vec![("content-type".into(), "application/json".into())];
    h.extend(headers);
    let (s, _, bytes) = loopback_http(
        f.daemon.gateway_port().unwrap(),
        method,
        "/v1/preflight",
        h,
        body.into_bytes(),
    )
    .await;
    let v = serde_json::from_slice(&bytes).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(&f.secret));
    (s, v)
}

#[tokio::test]
async fn control_mcp_access_description_is_read_only_and_instructions_name_both_advisory_tools() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let mut f=Fixture::configured(&["header:x-key"],SECRET,None,json!({"methods":["GET"],"rate":{"count":5,"per":"second"},"budget":{"unit":"requests","limit":100}})).await;
        let gid=f.grant_id.clone();f.shared.run(move|c|{c.vault.shorten_grant(&gid,600000).unwrap();c.vault.save_template("read",&json!({"cred":"demo","methods":["GET"]})).unwrap();}).await.unwrap();let sid=control_session_sid(&f).await;let audits=audit_records(&f).await;let before=store_snapshot(&f).await;
        let(error,v)=control_mcp_call(&f,"vault_describe_access",json!({}),true).await;assert!(!error,"{v}");assert_eq!(audit_records(&f).await,audits);assert_eq!(store_snapshot(&f).await,before);assert_eq!(v["session"]["id"],sid);assert_eq!(v["session"]["infinite"],false);let g=&v["grants"][0];assert_eq!(g["cred"],"demo");assert_eq!(g["effective"]["methods"],json!(["GET"]));assert_eq!(g["effective"]["rate"],json!({"count":5,"per":"second"}));assert_eq!(g["budget_remaining"],100);assert!(g["spend_remaining"].is_null());assert_eq!(g["quarantined"],false);assert!(g["expires_at"].is_string());assert!(!g["put_it_at"].as_array().unwrap().is_empty());assert_eq!(v["templates"].as_array().unwrap().iter().map(|t|t["name"].as_str().unwrap()).collect::<Vec<_>>(),vec!["read"]);assert!(v["next"].as_str().unwrap().contains("vault_request_session"));let text=v.to_string();for p in [&f.ph,&f.token,"av1.","\"fp8\"","\"size\"","\"length\"","\"token_hash\""] {assert!(!text.contains(p),"private metadata {p}");}
        assert_eq!(f.get().await.status,200);
        let token=f.shared.run(|c|{use av_core::secret::ExposeSecret;c.vault.create_session(av_store::vault::CreateSessionOptions{infinite:true,..Default::default()}).unwrap().token.expose_secret().to_string()}).await.unwrap();f.token=token;let(_,v)=control_mcp_call(&f,"vault_describe_access",json!({}),true).await;assert_eq!(v["session"]["infinite"],true);assert!(v["session"]["expires_at"].is_null());assert!(control_mcp_call(&f,"vault_describe_access",json!({}),false).await.0);
        let init=f.daemon.mcp().handle(json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}),None,None,None).await.unwrap();assert!(init["result"]["instructions"].as_str().unwrap().contains("Before a write you are unsure of, call vault_preflight; to learn your limits, call vault_describe_access."));credential_finish(&f).await;
    }).await.expect("MCP description timed out");
}

#[tokio::test]
async fn control_mcp_preflight_holds_allows_and_denies_without_touch_use_approval_or_upstream() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = approval_fixture("on-write", &["header:x-key"]).await;
        let before = store_snapshot(&f).await;
        let (error, v) = control_mcp_call(
            &f,
            "vault_preflight",
            json!({"cred":"demo","method":"POST","path":"/repos/x","body":"{\"a\":1}"}),
            true,
        )
        .await;
        assert!(!error, "{v}");
        assert_eq!(v["would"], "hold");
        assert!(v["advisory"]
            .as_str()
            .unwrap()
            .contains("A prediction, not a permission"));
        for (method, would) in [("GET", "allow"), ("DELETE", "deny")] {
            assert_eq!(
                control_mcp_call(
                    &f,
                    "vault_preflight",
                    json!({"cred":"demo","method":method,"path":"/repos/x"}),
                    true
                )
                .await
                .1["would"],
                would
            );
        }
        assert_eq!(store_snapshot(&f).await, before);
        assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
        assert!(f.up.hits.lock().unwrap().is_empty());
        let rows = audit_records(&f).await;
        assert_eq!(
            rows.iter()
                .filter(|r| r["kind"] == "request.preflighted")
                .count(),
            3
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r["kind"] == "placeholder.issued")
                .count(),
            1
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("MCP preflight no-side-effects timed out");
}

#[tokio::test]
async fn control_mcp_preflight_refuses_bad_shapes_unknown_credential_and_concurrent_eleventh_call()
{
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_eq!(
            control_mcp_call(
                &f,
                "vault_preflight",
                json!({"cred":"missing","method":"GET","path":"/x"}),
                true
            )
            .await
            .1["code"],
            "AV_NOT_FOUND"
        );
        for args in [
            json!({"cred":"demo","method":"GET","path":"x"}),
            json!({"cred":"demo","method":"G E T","path":"/x"}),
            json!({"cred":"demo","method":"GET","path":"/x","headers":["a"]}),
        ] {
            assert_eq!(
                control_mcp_call(&f, "vault_preflight", args, true).await.1["rule"],
                "preflight_shape"
            );
        }
        assert!(
            control_mcp_call(
                &f,
                "vault_preflight",
                json!({"cred":"demo","method":"GET","path":"/x"}),
                false
            )
            .await
            .0
        );
        let mut throttled = None;
        for _ in 0..3 {
            let call = || {
                Box::pin(control_mcp_call(
                    &f,
                    "vault_preflight",
                    json!({"cred":"demo","method":"GET","path":"/x"}),
                    true,
                ))
            };
            let (a, b, c, d, e, g, h, i, j, k, l, m) = tokio::join!(
                call(),
                call(),
                call(),
                call(),
                call(),
                call(),
                call(),
                call(),
                call(),
                call(),
                call(),
                call()
            );
            throttled = [a, b, c, d, e, g, h, i, j, k, l, m]
                .into_iter()
                .map(|(_, v)| v)
                .find(|v| v["code"] == "AV_QUOTA_EXCEEDED");
            if throttled.is_some() {
                break;
            }
        }
        let v = throttled.expect("more than ten preflights all passed");
        assert_eq!(v["rule"], "preflight_rate");
        assert!(v["retry_after"].as_u64().is_some());
        assert!(f.up.hits.lock().unwrap().is_empty());
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("MCP preflight strictness and rate timed out");
}

#[tokio::test]
async fn control_mcp_gateway_preflight_strict_shapes_auth_and_bad_location_never_trip_or_touch() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=approval_fixture("on-write",&["header:x-key"]).await;assert_eq!(credential_api(&f,"POST","/v1/tripwires",json!({"enabled":true,"rules":[{"id":"loc","codes":["AV_BAD_LOCATION"],"threshold":1,"window_s":600,"action":"revoke_session"}]})).await.0,200);
        let before=store_snapshot(&f).await;let auth=||vec![("authorization".into(),format!("Bearer {}",f.token))];
        let(s,v)=control_mcp_preflight_http(&f,"POST",json!({"method":"GET","path":format!("/p/demo/items/{}",f.ph),"headers":[["x-key",f.ph]]}).to_string(),auth()).await;assert_eq!(s,200,"{v}");assert_eq!(v["would"],"deny");assert_eq!(v["checks"].as_array().unwrap().last().unwrap()["code"],"AV_BAD_LOCATION");assert!(!audit_records(&f).await.iter().any(|r|r["kind"]=="tripwire.fired"));
        assert_eq!(control_mcp_preflight_http(&f,"POST",json!({"method":"POST","path":"/p/demo/repos/x"}).to_string(),auth()).await.1["would"],"deny");
        let(s,v)=control_mcp_preflight_http(&f,"POST",json!({"method":"post","path":"/p/demo/repos/x","body":"{}","headers":{"content-type":"application/json","x-key":f.ph}}).to_string(),auth()).await;assert_eq!(s,200,"{v}");assert_eq!(v["would"],"hold");assert_eq!(control_mcp_preflight_http(&f,"POST",json!({"method":"GET","path":"/p/demo/x","body_base64":"aGk=","headers":[["x-key",f.ph]]}).to_string(),auth()).await.1["would"],"allow");assert_eq!(store_snapshot(&f).await,before);assert!(f.daemon.pipeline().pending_approvals().await.is_empty());assert!(f.up.hits.lock().unwrap().is_empty());
        for body in [json!({"method":"GET","path":"/p/demo/x","body":"a","body_base64":"YQ=="}).to_string(),json!({"method":"GET","path":"/v1/status"}).to_string(),json!({"method":"GET"}).to_string(),json!({"method":5,"path":"/p/demo/x"}).to_string(),json!({"method":"GET","path":"/p/demo/x","headers":[["a"]]}).to_string(),json!({"method":"GET","path":"/p/demo/x","query":1}).to_string(),json!({"method":"GET","path":"/p/demo/x","body_base64":"not base64!"}).to_string(),"not json".into(),"[]".into()] {let(s,v)=control_mcp_preflight_http(&f,"POST",body,auth()).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"preflight_shape");}
        assert_eq!(control_mcp_preflight_http(&f,"POST",json!({"method":"GET","path":"/p/demo/x"}).to_string(),vec![]).await.0,401);let mut evil=auth();evil.push(("origin".into(),"http://evil.example".into()));assert_eq!(control_mcp_preflight_http(&f,"POST","{}".into(),evil).await.0,403);assert_eq!(control_mcp_preflight_http(&f,"GET","{}".into(),auth()).await.0,404);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("HTTP preflight strictness timed out");
}

#[tokio::test]
async fn control_mcp_session_proposal_whitelists_fields_and_invalid_dry_runs_leave_no_state_or_audit(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;let(error,v)=control_mcp_call(&f,"vault_request_session",json!({"cred":"demo","reason":"x","methods":["GET","POST"],"uses":5,"grant_ttl_minutes":15,"routes":[{"methods":["POST"],"paths":["/repos/*/issues"]}],"hosts":["evil.example"],"rate":"1000/s"}),false).await;assert!(!error,"{v}");assert_eq!(v["state"],"pending");let(_,pending)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;let proposal=&pending.as_array().unwrap().iter().find(|r|r["id"]==v["request_id"]).unwrap()["proposal"];assert_eq!(proposal["uses"],5);assert_eq!(proposal["grant_ttl_minutes"],15);assert_eq!(proposal["routes"],json!([{"methods":["POST"],"paths":["/repos/*/issues"]}]));assert!(proposal.get("hosts").is_none());assert!(proposal.get("rate").is_none());assert!(v["asked_for"].as_str().unwrap().contains("routes POST /repos/*/issues"));let before=store_snapshot(&f).await;let audit=audit_records(&f).await;
        for extra in [json!({"grant_ttl_minutes":0}),json!({"routes":[{"methods":["FETCH"],"paths":["/x"]}]}),json!({"budget":0}),json!({"methods":"POST"})] {let mut args=extra;args["cred"]=json!("demo");args["reason"]=json!("x");assert!(control_mcp_call(&f,"vault_request_session",args,false).await.0);}
        assert_eq!(credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","reason":"x","rate":"5/fortnight"})).await.1["rule"],"policy_invalid");assert_eq!(credential_api(&f,"GET","/v1/session-requests",json!({})).await.1,pending);assert_eq!(store_snapshot(&f).await,before);assert_eq!(audit_records(&f).await,audit);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("MCP proposed session dry runs timed out");
}

#[tokio::test]
async fn control_mcp_status_shows_lifetimes_but_only_human_pending_views_receive_scrubbed_preview()
{
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut f = approval_fixture("each", &["header:authorization:Bearer"]).await;
        let original = f.token.clone();
        f.token = f
            .shared
            .run(|c| {
                use av_core::secret::ExposeSecret;
                c.vault
                    .create_session(av_store::vault::CreateSessionOptions {
                        infinite: true,
                        ..Default::default()
                    })
                    .unwrap()
                    .token
                    .expose_secret()
                    .to_string()
            })
            .await
            .unwrap();
        let (_, v) = control_mcp_call(&f, "vault_status", json!({}), true).await;
        assert_eq!(v["session"]["infinite"], true);
        assert!(v["session"]["expires_at"].is_null());
        f.token = original;
        let held = f
            .send(
                "POST",
                "/repos/x",
                vec![
                    ("authorization".into(), format!("Bearer {}", f.ph)),
                    ("content-type".into(), "application/json".into()),
                ],
                Some(json!({"title":"hello","note":format!("a pasted {SECRET}")}).to_string()),
            )
            .await;
        let id = held_id(&held);
        let (_, v) =
            control_mcp_call(&f, "vault_approval_status", json!({"approval_id":id}), true).await;
        assert!(v.get("preview").is_none());
        let (_, human) = credential_api(&f, "GET", "/v1/approvals", json!({})).await;
        let preview = &human
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()["preview"];
        assert_eq!(preview["untrusted"], true);
        assert!(!preview.to_string().contains(&f.ph));
        assert!(preview["headers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|h| !h[0].as_str().unwrap().eq_ignore_ascii_case("authorization")));
        assert!(preview["body"]["text"].as_str().unwrap().contains("hello"));
        let (_, sessions) = credential_api(&f, "GET", "/v1/session-requests", json!({})).await;
        let pending = av_store::pending::fetch_pending(|path| {
            Some(if path == "/v1/approvals" {
                human.as_array().unwrap().clone()
            } else {
                sessions.as_array().unwrap().clone()
            })
        });
        let request = pending.iter().find(|r| r.id == id).unwrap();
        assert_eq!(request.preview.as_ref(), Some(preview));
        assert!(request.narrowable.is_empty());
        f.daemon.pipeline().decide_approval(id, true).await.unwrap();
        assert_eq!(
            f.send(
                "POST",
                "/repos/x",
                vec![
                    ("authorization".into(), format!("Bearer {}", f.ph)),
                    ("content-type".into(), "application/json".into())
                ],
                Some(json!({"title":"hello","note":format!("a pasted {SECRET}")}).to_string())
            )
            .await
            .status,
            200
        );
        credential_finish(&f).await;
    })
    .await
    .expect("MCP preview separation timed out");
}

#[tokio::test]
async fn control_gate_human_window_approves_but_agent_cannot_bind_or_replace_certificate_and_socket_is_private(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        use std::os::unix::fs::PermissionsExt;
        let f=approval_fixture("each",&["header:x-key"]).await;credential_factor(&f).await;assert_eq!(std::fs::metadata(f._dir.path().join("control.sock")).unwrap().permissions().mode()&0o007,0);
        credential_presence_refused(credential_api(&f,"POST","/v1/listeners",json!({"id":"agent-added","address":"0.0.0.0:0","surfaces":["gateway","mcp"],"tls":{"managed":true}})).await);let(_,listed)=credential_api(&f,"GET","/v1/listeners",json!({})).await;assert!(!listed.as_array().unwrap().iter().any(|l|l["id"]=="agent-added"));
        let(s,first)=credential_api(&f,"POST","/v1/tls/ensure",json!({})).await;assert_eq!(s,200,"{first}");credential_presence_refused(credential_api(&f,"POST","/v1/tls/ensure",json!({"force":true})).await);assert_eq!(credential_api(&f,"POST","/v1/tls/ensure",json!({})).await.1["fingerprint"],first["fingerprint"]);
        let held=f.get().await;let id=held_id(&held);credential_presence_refused(credential_api(&f,"POST","/v1/approvals",json!({"id":id,"granted":true})).await);assert_eq!(f.get().await.status,202);assert!(f.up.hits.lock().unwrap().is_empty());credential_gate(&f,true).await;assert_eq!(credential_api(&f,"POST","/v1/approvals",json!({"id":id,"granted":true})).await.0,200);assert_eq!(f.get().await.status,200);assert!(f.up.hits.lock().unwrap().iter().any(|r|r.headers.iter().any(|(_,v)|v==SECRET)));credential_finish(&f).await;
    }).await.expect("human gate control timed out");
}

async fn control_gate_snapshot(f: &Fixture) -> Value {
    let rows = store_snapshot(f).await;
    let rest=f.shared.run(|c|json!({"settings":c.vault.get_settings().unwrap(),"templates":c.vault.list_templates().unwrap(),"notify":c.vault.notify_config().unwrap()})).await.unwrap();
    json!({"rows":rows,"rest":rest})
}

#[tokio::test]
async fn control_gate_every_widening_route_refuses_without_writing_but_reads_remain_open() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let sid=control_session_sid(&f).await;let pin=format!("sha256/{}=","A".repeat(43));let before=control_gate_snapshot(&f).await;
        for(method,path,body)in [
            ("POST","/v1/credentials",json!({"slug":"x","kind":"http","value":"v"})),("DELETE","/v1/credentials?slug=demo",json!({})),("POST","/v1/sessions",json!({"cred":"demo"})),("POST","/v1/placeholders",json!({"cred":"demo"})),("POST","/v1/placeholders/batch",json!({"sid":sid,"items":[{"cred":"demo"}]})),("POST","/v1/approvals",json!({"id":"whatever","granted":true})),("POST","/v1/listeners",json!({"id":"n","address":"127.0.0.1:0","surfaces":["mcp"]})),("POST","/v1/presence",json!({"credentialId":"c","publicKeySpki":"k"})),("POST","/v1/factors/webauthn",json!({"credential_id":"c","prf_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})),("POST","/v1/factors/webauthn",json!({"action":"remove"})),("POST","/v1/credentials/rotate",json!({"slug":"demo","value":"ROTATED-GATE-VALUE-0099887766"})),("POST","/v1/credentials/scrub",json!({"slug":"demo","pattern":"acme_[a-z0-9]{20}"})),("DELETE","/v1/credentials/scrub?slug=demo&id=sp_x",json!({})),("POST","/v1/credentials/expiry",json!({"slug":"demo","expires_at":null})),("POST","/v1/credentials/pins",json!({"slug":"demo","host":"api.example.test","pins":[pin]})),("DELETE","/v1/credentials/pins?slug=demo&host=api.example.test",json!({})),("POST","/v1/credentials/release",json!({"slug":"demo"})),("POST","/v1/tripwires",json!({"enabled":false})),("POST","/v1/tripwires",json!({"enabled":true,"rules":"defaults"})),("POST","/v1/tripwires",json!({"rules":[]})),("POST","/v1/templates",json!({"name":"gate","spec":{"cred":"demo"}})),("POST","/v1/backup/restore",json!({"bundle":{"format":"agent-vault-backup"},"recovery_passphrase":"a recovery passphrase"})),("POST","/v1/notify",json!({"webhook_url":"https://hooks.example/abc"}))
        ] {let r=credential_api(&f,method,path,body).await;assert_eq!(r.0,401,"{method} {path}: {}",r.1);assert_eq!(r.1["code"],"AV_PRESENCE_REQUIRED");}
        assert_eq!(control_gate_snapshot(&f).await,before);
        for path in ["/v1/status","/v1/lockstate","/v1/credentials","/v1/sessions","/v1/listeners","/v1/approvals","/v1/tripwires","/v1/templates","/v1/notify","/v1/audit/checkpoint","/v1/audit/export","/v1/report/access",&format!("/v1/sessions/detail?sid={sid}")] {let(s,v)=credential_api(&f,"GET",path,json!({})).await;assert_eq!(s,200,"{path}: {v}");}assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("whole widening surface timed out");
}

#[tokio::test]
async fn control_gate_narrowing_and_read_only_wave_three_routes_remain_open_with_factor_enrolled() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = approval_fixture("on-write", &["header:x-key"]).await;
        credential_factor(&f).await;
        let sid = control_session_sid(&f).await;
        assert_eq!(f.get().await.status, 200);
        for (method, path, body, want) in [
            (
                "POST",
                "/v1/sessions/narrow",
                json!({"sid":sid,"narrow":{"methods":["GET"]}}),
                200,
            ),
            ("POST", "/v1/tripwires", json!({"enabled":true}), 200),
            ("POST", "/v1/credentials/test", json!({"slug":"demo"}), 404),
            ("DELETE", "/v1/templates?name=none", json!({}), 200),
            ("DELETE", "/v1/notify", json!({}), 200),
            ("POST", "/v1/notify/test", json!({}), 404),
            (
                "POST",
                "/v1/backup/inspect",
                json!({"bundle":{"format":"other"},"recovery_passphrase":"a recovery passphrase"}),
                403,
            ),
            (
                "POST",
                "/v1/audit/verify-witness",
                json!({"checkpoints":[]}),
                200,
            ),
            (
                "POST",
                "/v1/credentials/quarantine",
                json!({"slug":"demo"}),
                200,
            ),
            ("POST", "/v1/panic", json!({}), 200),
        ] {
            let (s, v) = credential_api(&f, method, path, body).await;
            assert_eq!(s, want, "{method} {path}: {v}");
            assert_ne!(v["code"], "AV_PRESENCE_REQUIRED");
        }
        f.shared
            .run(|c| {
                assert!(c
                    .vault
                    .sessions()
                    .unwrap()
                    .iter()
                    .all(|s| s.state == av_store::model::SessionState::Revoked));
                assert!(c
                    .vault
                    .find_credential("demo")
                    .unwrap()
                    .unwrap()
                    .quarantine
                    .is_some());
            })
            .await
            .unwrap();
        credential_finish(&f).await;
    })
    .await
    .expect("open narrowing surface timed out");
}

#[tokio::test]
async fn control_gate_authenticator_alone_gates_the_socket_and_cannot_be_ransomed_by_first_passphrase(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        use base64::Engine;
        use p256::pkcs8::EncodePublicKey;
        let f = Fixture::new(&["header:x-key"]).await;
        assert_eq!(
            credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"}))
                .await
                .0,
            200
        );
        let key = p256::ecdsa::SigningKey::from_slice(&[23; 32]).unwrap();
        let spki = base64::engine::general_purpose::STANDARD
            .encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([23; 16]);
        f.shared
            .run(move |c| {
                c.vault
                    .set_presence_key(
                        &json!({"credentialId":id,"publicKeySpki":spki,"signCount":0}),
                    )
                    .unwrap()
            })
            .await
            .unwrap();
        let (s, v) = credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["code"], "AV_PRESENCE_REQUIRED");
        assert_eq!(v["factors"], json!(["authenticator"]));
        assert!(v["hint"].as_str().unwrap().contains("web UI"));
        credential_presence_refused(
            credential_api(
                &f,
                "POST",
                "/v1/passphrase",
                json!({"passphrase":"agent-chosen-ransom-phrase"}),
            )
            .await,
        );
        assert_eq!(
            credential_api(&f, "POST", "/v1/lock", json!({})).await.0,
            200
        );
        assert_eq!(
            credential_api(&f, "POST", "/v1/unlock", json!({})).await.0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("authenticator-only gate timed out");
}

#[tokio::test]
async fn control_gate_all_scrypt_routes_throttle_real_guesses_without_extending_backoff() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for (path, body) in [
            (
                "/v1/presence/window",
                json!({"passphrase":"wrong-passphrase-here"}),
            ),
            (
                "/v1/passphrase",
                json!({"passphrase":"a-new-passphrase","current":"wrong-passphrase-here"}),
            ),
        ] {
            let f = Fixture::new(&["header:x-key"]).await;
            credential_factor(&f).await;
            for _ in 0..5 {
                let (_, v) = credential_api(&f, "POST", path, body.clone()).await;
                assert_ne!(
                    v["code"], "AV_RATE_LIMITED",
                    "five free attempts should be checked"
                );
                assert_ne!(v["code"], Value::Null);
            }
            let records = audit_records(&f).await;
            let until = records
                .iter()
                .rev()
                .find(|r| r["kind"] == "presence.throttled")
                .unwrap()["until"]
                .as_str()
                .unwrap()
                .to_string();
            let end = av_daemon::util::parse_iso_ms(&until).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let (s, v) = credential_api(&f, "POST", path, body.clone()).await;
            assert_eq!(s, 429, "{v}");
            assert_eq!(v["code"], "AV_RATE_LIMITED");
            assert!(v["detail"].as_str().unwrap().contains("try again in"));
            assert_eq!(audit_records(&f).await, records);
            let wait = (end - av_daemon::util::now_ms()).max(0) as u64;
            tokio::time::sleep(std::time::Duration::from_millis(wait + 50)).await;
            credential_gate(&f, true).await;
            for _ in 0..4 {
                assert_ne!(
                    credential_api(
                        &f,
                        "POST",
                        "/v1/presence/window",
                        json!({"passphrase":"wrong again"})
                    )
                    .await
                    .1["code"],
                    "AV_RATE_LIMITED"
                );
            }
            assert_eq!(f.get().await.status, 200);
            credential_finish(&f).await;
        }
    })
    .await
    .expect("all scrypt route throttle timed out");
}

#[tokio::test]
async fn control_gate_grant_placeholder_ceiling_beats_agent_control_and_direct_issuance() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::configured(
            &["header:x-key"],
            SECRET,
            None,
            json!({"placeholder_policy":{"max_uses":1}}),
        )
        .await;
        credential_factor(&f).await;
        let sid = control_session_sid(&f).await;
        credential_gate(&f, true).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/placeholders",
            json!({"cred":"demo","sid":sid,"uses":1000000}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let direct = f.mint(Some(9999)).await;
        let gid = f.grant_id.clone();
        f.shared
            .run(move |c| {
                let rows = c.vault.list_placeholders(None).unwrap();
                assert!(rows.iter().filter(|p| p.grant_id == gid).count() >= 3);
                assert!(rows
                    .iter()
                    .filter(|p| p.grant_id == gid)
                    .all(|p| p.max_uses == 1));
            })
            .await
            .unwrap();
        let r = f
            .send("GET", "/ordinary", vec![("x-key".into(), direct)], None)
            .await;
        assert_eq!(r.status, 200);
        f.clean(&r).await;
        credential_finish(&f).await;
    })
    .await
    .expect("grant placeholder ceiling timed out");
}

fn control_template_read() -> Value {
    json!({"cred":"demo","methods":["GET"],"paths":["/repos/**"],"budget":20})
}
async fn control_template_save(f: &Fixture, name: &str, spec: Value, gated: bool) -> Value {
    if gated {
        credential_gate(f, true).await;
    }
    let (s, v) = credential_api(f, "POST", "/v1/templates", json!({"name":name,"spec":spec})).await;
    assert_eq!(s, 200, "{v}");
    if gated {
        credential_gate(f, false).await;
    }
    v
}

#[tokio::test]
async fn control_templates_validate_before_presence_and_crud_metadata_stays_open() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        credential_presence_refused(
            credential_api(
                &f,
                "POST",
                "/v1/templates",
                json!({"name":"read","spec":control_template_read()}),
            )
            .await,
        );
        assert!(f
            .shared
            .run(|c| c.vault.get_template("read").unwrap().is_none())
            .await
            .unwrap());
        for (spec, code, rule) in [
            (json!({"cred":"missing"}), "AV_NOT_FOUND", None),
            (
                json!({"cred":"demo","budget":0}),
                "AV_POLICY_DENIED",
                Some("budget"),
            ),
            (
                json!({"cred":"demo","rate":"1/fortnight"}),
                "AV_POLICY_DENIED",
                Some("policy_invalid"),
            ),
            (
                json!({"cred":"demo","template":"other"}),
                "AV_POLICY_DENIED",
                Some("session_shape"),
            ),
            (json!("demo"), "AV_POLICY_DENIED", Some("session_shape")),
        ] {
            let (_, v) =
                credential_api(&f, "POST", "/v1/templates", json!({"name":"x","spec":spec})).await;
            assert_eq!(v["code"], code);
            if let Some(rule) = rule {
                assert_eq!(v["rule"], rule);
            }
        }
        credential_gate(&f, true).await;
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/templates",
                json!({"name":"Not A Name","spec":control_template_read()})
            )
            .await
            .1["rule"],
            "template_name"
        );
        let t = control_template_save(&f, "read", control_template_read(), true).await;
        assert_eq!(t["version"], 1);
        is_hex_digest(&t["hash"]);
        assert_eq!(t["elevated"], json!([]));
        assert!(t["lint"].is_array());
        let (_, list) = credential_api(&f, "GET", "/v1/templates", json!({})).await;
        let row = &list[0];
        assert_eq!(row["name"], "read");
        assert_eq!(row["hash"], t["hash"]);
        assert_eq!(row["creds"], json!(["demo"]));
        assert!(row["summary"]
            .as_str()
            .unwrap()
            .contains("session for demo · GET"));
        assert_eq!(
            credential_api(&f, "GET", "/v1/templates?name=read", json!({}))
                .await
                .1["spec"],
            control_template_read()
        );
        assert_eq!(
            credential_api(&f, "GET", "/v1/templates?name=nope", json!({}))
                .await
                .0,
            404
        );
        assert_eq!(
            credential_api(&f, "DELETE", "/v1/templates?name=read", json!({}))
                .await
                .1,
            json!({"ok":true,"removed":true})
        );
        assert_eq!(
            credential_api(&f, "DELETE", "/v1/templates?name=read", json!({}))
                .await
                .1["removed"],
            false
        );
        let writer = control_template_save(
            &f,
            "writer",
            json!({"cred":"demo","methods":["GET","POST"],"approval":"auto"}),
            true,
        )
        .await;
        assert_eq!(writer["elevated"], json!(["approval_auto_writes"]));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("template CRUD timed out");
}

#[tokio::test]
async fn control_templates_hash_binding_detects_edits_and_overrides_only_reduce_the_saved_authority(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;let t=control_template_save(&f,"read",control_template_read(),false).await;
        assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"template":"read"})).await.1["rule"],"template_changed");let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"template":"read","template_hash":t["hash"],"label":"from template"})).await;assert_eq!(s,200,"{v}");assert_eq!(v["label"],"from template");assert_eq!(control_session_policy(&f,v["grant_id"].as_str().unwrap()).await["methods"],json!(["GET"]));let created=audit_records(&f).await.into_iter().find(|r|r["kind"]=="session.created"&&r["session_id"]==v["session_id"]).unwrap();assert_eq!(created["template"],"read");assert_eq!(created["template_version"],1);
        let mut edited=control_template_read();edited["methods"]=json!(["GET","POST"]);let current=control_template_save(&f,"read",edited,false).await;let(s,stale)=credential_api(&f,"POST","/v1/sessions",json!({"template":"read","template_hash":t["hash"]})).await;assert_eq!(s,403,"{stale}");assert_eq!(stale["rule"],"template_changed");assert!(stale["detail"].as_str().unwrap().contains("the template changed after you looked at it; review it again"));let(s,fresh)=credential_api(&f,"POST","/v1/sessions",json!({"template":"read","template_hash":current["hash"]})).await;assert_eq!(s,200,"{fresh}");let sid=fresh["session_id"].as_str().unwrap().to_owned();f.shared.run(move|c|assert_eq!(c.vault.session(&sid).unwrap().unwrap().template_version,Some(2))).await.unwrap();
        let mut spec=control_template_read();spec["approval"]=json!("on-write");spec["ttl_hours"]=json!(2);let t=control_template_save(&f,"read",spec,false).await;let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"template":"read","template_hash":t["hash"],"methods":["GET","DELETE"],"paths":["/repos/x/**","/admin/**"],"budget":500,"approval":"auto","ttl_hours":24})).await;assert_eq!(s,200,"{v}");let p=control_session_policy(&f,v["grant_id"].as_str().unwrap()).await;assert_eq!(p["methods"],json!(["GET"]));assert_eq!(p["paths"],json!(["/repos/x/**"]));assert_eq!(p["budget"]["limit"],20);assert_eq!(p["approval"],"on-write");assert!(av_daemon::util::parse_iso_ms(v["expires_at"].as_str().unwrap()).unwrap()<=av_daemon::util::now_ms()+7201000);assert_eq!(control_session_request(&f,&v,"demo","GET","/repos/x/ordinary").await.status,200);assert_ne!(control_session_request(&f,&v,"demo","DELETE","/repos/x/ordinary").await.status,200);
        let(s,n)=credential_api(&f,"POST","/v1/sessions",json!({"template":"read","template_hash":t["hash"],"budget":3,"approval":"each"})).await;assert_eq!(s,200,"{n}");let p=control_session_policy(&f,n["grant_id"].as_str().unwrap()).await;assert_eq!(p["budget"]["limit"],3);assert_eq!(p["approval"],"each");
        for extra in [json!({"hosts":["evil.example"]}),json!({"remote":true}),json!({"rate":"1/s"}),json!({"grants":[]})] {let mut b=extra;b["template"]=json!("read");b["template_hash"]=t["hash"].clone();let(s,v)=credential_api(&f,"POST","/v1/sessions",b).await;assert_eq!(s,403,"{v}");assert!([json!("template_override"),json!("session_shape")].contains(&v["rule"]));}credential_finish(&f).await;
    }).await.expect("template hash and narrowing timed out");
}

#[test]
fn control_templates_infinite_only_becomes_finite_and_budget_without_a_ceiling_requires_default() {
    use av_daemon::session_requests::resolve_template;
    let infinite = json!({"cred":"demo","infinite":true});
    let finite = resolve_template(&infinite, &json!({"ttl_hours":1}), None).unwrap();
    assert!(finite.get("infinite").is_none());
    assert_eq!(finite["ttl_hours"], 1);
    assert!(
        resolve_template(&infinite, &json!({"infinite":false}), None)
            .unwrap()
            .get("infinite")
            .is_none()
    );
    for (body, rule) in [
        (json!({"infinite":true}), "template_override"),
        (json!({"infinite":"false"}), "ttl"),
        (json!({"budget":10}), "policy_invalid"),
    ] {
        assert_eq!(
            resolve_template(&json!({"cred":"demo"}), &body, None)
                .unwrap_err()
                .extra
                .rule
                .as_deref(),
            Some(rule)
        );
    }
    let default = |_: &Value| Some(500);
    assert_eq!(
        resolve_template(
            &json!({"cred":"demo"}),
            &json!({"budget":10}),
            Some(&default)
        )
        .unwrap()["budget"],
        10
    );
    assert_eq!(
        resolve_template(
            &json!({"cred":"demo"}),
            &json!({"budget":900}),
            Some(&default)
        )
        .unwrap()["budget"],
        500
    );
}

#[tokio::test]
async fn control_templates_elevated_creation_requires_fresh_proof_and_read_only_narrowing_uses_window(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let t=control_template_save(&f,"writer",json!({"cred":"demo","methods":["GET","POST"],"approval":"auto"}),true).await;credential_gate(&f,true).await;
        let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"template":"writer","template_hash":t["hash"]})).await;assert_eq!(s,401,"{v}");assert_eq!(v["rule"],"fresh_presence");let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"template":"writer","template_hash":t["hash"],"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"template":"writer","template_hash":t["hash"],"methods":["GET"]})).await.0,200);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("elevated template gate timed out");
}

#[tokio::test]
async fn control_templates_proposal_snapshots_survive_edits_and_owner_fields_cannot_be_supplied_by_agent(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;control_template_save(&f,"read",control_template_read(),true).await;
        let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"template":"read","reason":"reading repos","budget":5})).await;assert_eq!(s,200,"{asked}");assert!(asked["summary"].as_str().unwrap().starts_with("template read v1 · session for demo · GET"));assert_eq!(asked["proposal"]["budget"],5);assert_eq!(asked["proposal"]["template_version"],1);
        let mut changed=control_template_read();changed["methods"]=json!(["GET","POST","DELETE"]);changed["budget"]=json!(999);control_template_save(&f,"read",changed,true).await;credential_gate(&f,true).await;let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":true})).await;assert_eq!(s,200,"{v}");let p=control_session_policy(&f,v["session"]["grant_id"].as_str().unwrap()).await;assert_eq!(p["methods"],json!(["GET"]));assert_eq!(p["budget"]["limit"],5);let sid=v["session"]["session_id"].as_str().unwrap().to_owned();f.shared.run(move|c|{let s=c.vault.session(&sid).unwrap().unwrap();assert_eq!(s.template.as_deref(),Some("read"));assert_eq!(s.template_version,Some(1));}).await.unwrap();
        assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"other","kind":"http","host":"api.example.test","value":"OTHER-SECRET-0099887766","sites":["header:x-key"]})).await.0,200);control_template_save(&f,"both",json!({"grants":[{"cred":"demo"},{"cred":"other"}]}),true).await;
        assert_eq!(credential_api(&f,"POST","/v1/session-requests",json!({"template":"both","reason":"x"})).await.1["rule"],"template_multi_cred");assert_eq!(credential_api(&f,"POST","/v1/session-requests",json!({"template":"nope","reason":"x"})).await.0,404);let t=control_template_save(&f,"writer",json!({"cred":"demo","methods":["GET","POST"],"approval":"auto"}),true).await;
        assert_eq!(credential_api(&f,"POST","/v1/session-requests",json!({"template":"writer","approval":"each","reason":"x"})).await.1["rule"],"owner_only_field");assert_eq!(credential_api(&f,"POST","/v1/session-requests",json!({"template":"writer","cred":"other","reason":"x"})).await.1["rule"],"session_shape");let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"template":"writer","reason":"x"})).await;assert_eq!(s,200,"{asked}");assert_eq!(asked["proposal"]["approval"],"auto");assert_eq!(asked["proposal"]["template_hash"],t["hash"]);credential_gate(&f,true).await;assert_eq!(credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":true})).await.1["rule"],"fresh_presence");let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":true,"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");assert_eq!(control_session_policy(&f,v["session"]["grant_id"].as_str().unwrap()).await["approval"],"auto");assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("template request snapshots timed out");
}

#[tokio::test]
async fn control_templates_mcp_lists_only_single_credential_templates_and_can_propose_by_name() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;control_template_save(&f,"read",control_template_read(),false).await;assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"other","kind":"http","host":"api.example.test","value":"OTHER-SECRET-0099887766","sites":["header:x-key"]})).await.0,200);control_template_save(&f,"both",json!({"grants":[{"cred":"demo"},{"cred":"other"}]}),false).await;
        let(_,v)=control_mcp_call(&f,"vault_status",json!({}),false).await;assert_eq!(v["templates"].as_array().unwrap().iter().map(|t|t["name"].as_str().unwrap()).collect::<Vec<_>>(),vec!["read"]);assert_eq!(v["templates"][0]["cred"],"demo");let(error,v)=control_mcp_call(&f,"vault_request_session",json!({"template":"read","reason":"x","grant_ttl_minutes":15}),false).await;assert!(!error,"{v}");assert_eq!(v["state"],"pending");assert!(v["asked_for"].as_str().unwrap().starts_with("template read v1"));let(_,pending)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;assert_eq!(pending.as_array().unwrap().iter().find(|r|r["id"]==v["request_id"]).unwrap()["proposal"]["grant_ttl_minutes"],15);assert_eq!(control_mcp_call(&f,"vault_request_session",json!({"template":"nope","reason":"x"}),false).await.1["code"],"AV_NOT_FOUND");assert_eq!(control_mcp_call(&f,"vault_request_session",json!({"template":"both","reason":"x"}),false).await.1["rule"],"template_multi_cred");assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("MCP template proposal timed out");
}

#[tokio::test]
async fn control_templates_signed_consent_binds_exact_template_hash_and_fresh_matching_signature_works(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let w = WidenFixture::new().await;
        let t =
            w.f.shared
                .run(|c| {
                    c.vault
                        .save_template("read", &control_template_read())
                        .unwrap()
                })
                .await
                .unwrap();
        let body = json!({"template":"read","template_hash":t.hash});
        let signature = w.proof("session.create", &body).await;
        let edited =
            w.f.shared
                .run(|c| {
                    let mut spec = control_template_read();
                    spec["methods"] = json!(["GET", "DELETE"]);
                    c.vault.save_template("read", &spec).unwrap()
                })
                .await
                .unwrap();
        let mut swapped =
            json!({"template":"read","template_hash":edited.hash,"presence":signature});
        let (s, v) = w.ctl("POST", "/v1/sessions", swapped.clone()).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["code"], "AV_PRESENCE_REQUIRED");
        swapped.as_object_mut().unwrap().remove("presence");
        let proof = w.proof("session.create", &swapped).await;
        swapped["presence"] = proof;
        let (s, v) = w.ctl("POST", "/v1/sessions", swapped).await;
        assert_eq!(s, 200, "{v}");
        w.stop().await;
    })
    .await
    .expect("signed template hash timed out");
}

#[tokio::test]
async fn control_overrides_routes_and_payload_json_create_the_narrowed_grant_instead_of_agent_proposal(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;let routes=json!([{"methods":["GET"],"paths":["/only"]}]);let payload=json!({"query":{"q":{"max_length":8}}});
        for(field,requested)in [("routes",routes),("payload",payload)] {
            let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["GET","POST"],"paths":["/**"],"routes":[{"methods":["GET","POST"],"paths":["/**"]}],"reason":"x"})).await;assert_eq!(s,200,"{asked}");
            let args=json!({field:requested.to_string()});let parsed=av_store::pending::parse_overrides(args.as_object().unwrap()).unwrap();let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":true,"overrides":parsed})).await;assert_eq!(s,200,"{v}");let stored=control_session_policy(&f,v["session"]["grant_id"].as_str().unwrap()).await;assert_eq!(stored[field],requested,"{field} narrowing was dropped");
        }
        let bad=av_store::pending::parse_overrides(json!({"routes":"[{\"methods\":"}).as_object().unwrap()).unwrap_err();assert_eq!(bad.field,"routes");assert!(bad.to_string().contains("routes"));assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("parsed JSON overrides timed out");
}

// Trust exactly this test vault's managed certificate, including its TLS
// handshake signatures. Managed certificates are CA-capable (as in Node),
// which the generic webpki end-entity chain verifier refuses.
#[derive(Debug)]
struct ExactManagedCertificate(Vec<u8>);
impl rustls::client::danger::ServerCertVerifier for ExactManagedCertificate {
    fn verify_server_cert(
        &self,
        cert: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        name: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if cert.as_ref() != self.0.as_slice() || name.to_str() != "localhost" {
            return Err(rustls::Error::General(
                "wrong disposable managed certificate".into(),
            ));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        s: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            s,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        s: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            s,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
async fn c18_tls_json(
    f: &Fixture,
    port: u16,
    path: &str,
    token: &str,
    body: Value,
) -> (u16, Value) {
    let paths = av_daemon::tls::tls_paths(f._dir.path());
    let material = av_daemon::tls::load_material(&paths.cert, &paths.key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    use base64::Engine;
    let pem = String::from_utf8(material.cert).unwrap();
    let encoded = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    let der = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    roots
        .add(rustls::pki_types::CertificateDer::from(der.clone()))
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(ExactManagedCertificate(der)));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (mut client, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn control_c18_real_tls_and_direct_tools_refuse_infinite_remote_peeks_without_mutation() {
    tokio::time::timeout(std::time::Duration::from_secs(45),async {
        let f=Fixture::new(&["header:x-key"]).await;let gid=f.grant_id.clone();let(infinite,marker)=f.shared.run(move|c|{use av_core::secret::ExposeSecret;let parent=c.vault.grant(&gid).unwrap().unwrap();let session=c.vault.create_session(av_store::vault::CreateSessionOptions{infinite:true,..Default::default()}).unwrap();let grant=c.vault.create_grant(av_store::vault::CreateGrantOptions{session_id:session.session.id,credential_id:parent.credential_id,policy:parent.policy,..Default::default()}).unwrap();let marker=c.vault.issue_placeholder(av_store::vault::IssueOptions{grant_id:grant.id,..Default::default()}).unwrap().placeholder;(session.token.expose_secret().to_string(),marker)}).await.unwrap();
        let mut ports=Vec::new();for(id,address)in [("wild","0.0.0.0:0"),("loop","127.0.0.1:0")] {let(s,v)=credential_api(&f,"POST","/v1/listeners",json!({"id":id,"address":address,"surfaces":["gateway","mcp"],"tls":{"managed":true}})).await;assert_eq!(s,200,"{v}");let entry:av_store::model::ListenerRecord=serde_json::from_value(v).unwrap();ports.push(f.daemon.bind_listener(&entry).await.unwrap().1);}
        let pre=|ph:&str|json!({"method":"GET","path":"/p/demo/x","headers":[["x-key",ph]]});let(s,v)=c18_tls_json(&f,ports[0],"/v1/preflight",&infinite,pre(&marker)).await;assert_eq!(s,403,"{v}");assert_eq!(v["code"],"AV_REMOTE_FORBIDDEN");assert_eq!(v["rule"],"infinite_remote");let(s,v)=c18_tls_json(&f,ports[0],"/v1/preflight",&f.token,pre(&f.ph)).await;assert_eq!(s,200,"{v}");assert_eq!(v["would"],"allow");assert_eq!(c18_tls_json(&f,ports[1],"/v1/preflight",&infinite,pre(&marker)).await.0,200);
        let remote=av_daemon::pipeline::ListenerInfo{id:"wild".into(),kind:"tls".into(),remote:true,advertise:vec![]};
        for(name,args)in [("vault_describe_access",json!({})),("vault_preflight",json!({"cred":"demo","method":"GET","path":"/x"}))] {
            let message=json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}});let(_,v)=c18_tls_json(&f,ports[0],"/mcp",&infinite,message.clone()).await;let v:Value=serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();assert_eq!(v["code"],"AV_REMOTE_FORBIDDEN");
            let before=store_snapshot(&f).await;let audit=audit_records(&f).await;let token=infinite.clone();let session=f.shared.run(move|c|c.vault.session_by_token(&token).unwrap()).await.unwrap();let v=f.daemon.mcp().handle(message.clone(),session,Some(infinite.clone()),Some(remote.clone())).await.unwrap();let v:Value=serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();assert_eq!(v["code"],"AV_REMOTE_FORBIDDEN");assert_eq!(v["rule"],"infinite_remote");assert_eq!(store_snapshot(&f).await,before);assert_eq!(audit_records(&f).await,audit);
            let(_,v)=c18_tls_json(&f,ports[0],"/mcp",&f.token,message.clone()).await;let v:Value=serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();if name=="vault_preflight" {assert_eq!(v["would"],"allow");} else {assert_eq!(v["session"]["id"],control_session_sid(&f).await);}
            for(token,listener)in [(f.token.clone(),Some(remote.clone())),(infinite.clone(),None)] {let is_infinite=token==infinite;let t=token.clone();let session=f.shared.run(move|c|c.vault.session_by_token(&t).unwrap()).await.unwrap();let v=f.daemon.mcp().handle(message.clone(),session,Some(token),listener).await.unwrap();let v:Value=serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();if name=="vault_preflight" {assert_eq!(v["would"],"allow");}else{assert!(v["session"]["id"].is_string());assert_eq!(v["session"]["infinite"],is_infinite);}}
        }
        assert!(f.up.hits.lock().unwrap().is_empty());assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("C18 TLS surfaces timed out");
}

struct NotifyWatch {
    status: u16,
    body: hyper::body::Incoming,
    connection: tokio::task::JoinHandle<()>,
    buffer: String,
}
impl Drop for NotifyWatch {
    fn drop(&mut self) {
        self.connection.abort();
    }
}
impl NotifyWatch {
    async fn open(f: &Fixture, headers: Vec<(String, String)>) -> Self {
        let stream = tokio::net::UnixStream::connect(f._dir.path().join("control.sock"))
            .await
            .unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut req = hyper::Request::builder()
            .uri("/v1/pending/stream")
            .header("host", "localhost");
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let response = sender
            .send_request(req.body(Full::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        Self {
            status: response.status().as_u16(),
            body: response.into_body(),
            connection,
            buffer: String::new(),
        }
    }
    async fn next(&mut self) -> (String, Value, String) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(end) = self.buffer.find("\n\n") {
                    let raw = self.buffer[..end].to_string();
                    self.buffer.drain(..end + 2);
                    if let Some(event) = raw.lines().find_map(|l| l.strip_prefix("event: ")) {
                        let data = raw.lines().find_map(|l| l.strip_prefix("data: ")).unwrap();
                        return (event.to_string(), serde_json::from_str(data).unwrap(), raw);
                    }
                }
                let frame = self
                    .body
                    .frame()
                    .await
                    .expect("notification stream ended")
                    .unwrap();
                if let Ok(bytes) = frame.into_data() {
                    self.buffer.push_str(std::str::from_utf8(&bytes).unwrap());
                }
            }
        })
        .await
        .expect("notification event timed out")
    }
}
const NOTIFY_HOOK: &str = "https://hooks.example/services/T000/B000/SECRETPATH?token=QUERYSECRET";
struct NotifyFixture {
    f: Fixture,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    status: Arc<std::sync::atomic::AtomicU16>,
    peer: tokio::task::JoinHandle<()>,
}
impl NotifyFixture {
    async fn new(each: bool) -> Self {
        use tokio::io::AsyncWriteExt;
        let mut f = if each {
            approval_fixture("each", &["header:x-key"]).await
        } else {
            Fixture::new(&["header:x-key"]).await
        };
        f.daemon.stop().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let status = Arc::new(std::sync::atomic::AtomicU16::new(200));
        let served = status.clone();
        let peer = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (_, body) = read_wire_request(&mut socket).await;
                let _: Value = serde_json::from_slice(&body).unwrap();
                let code = served.load(std::sync::atomic::Ordering::SeqCst);
                socket.write_all(format!("HTTP/1.1 {code} Fake\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
            }
        });
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let send: av_daemon::notify::Sender = Arc::new(move |url, body| {
            recorded
                .lock()
                .unwrap()
                .push((url, serde_json::from_str(&body).unwrap()));
            Box::pin(async move {
                let (s, _, _) = loopback_http(
                    port,
                    "POST",
                    "/fake-webhook",
                    vec![("content-type".into(), "application/json".into())],
                    body.into_bytes(),
                )
                .await;
                Ok(s)
            })
        });
        f.daemon = Daemon::new(
            f.shared.clone(),
            DaemonOptions {
                port: 0,
                socket_path: Some(f._dir.path().join("control.sock")),
                pipeline: PipelineOptions {
                    upstream: Some(f.up.clone()),
                    ..Default::default()
                },
                notify: av_daemon::notify::NotifierOptions { send: Some(send) },
                ..Default::default()
            },
        )
        .unwrap();
        f.daemon.start().await.unwrap();
        Self {
            f,
            calls,
            status,
            peer,
        }
    }
    async fn configure(&self, detail: av_store::model::NotifyDetail) {
        self.f
            .shared
            .run(move |c| {
                c.vault
                    .set_notify_webhook(&NOTIFY_HOOK.to_string().into(), detail)
                    .unwrap()
            })
            .await
            .unwrap();
    }
    async fn wait_calls(&self, n: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if self.calls.lock().unwrap().len() >= n {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("webhook not posted");
    }
    async fn finish(self) {
        let log = serde_json::to_string(&audit_records(&self.f).await).unwrap();
        for part in [SECRET, "SECRETPATH", "QUERYSECRET", "/services/"] {
            assert!(!log.contains(part));
        }
        credential_finish(&self.f).await;
        self.peer.abort();
        let _ = self.peer.await;
    }
}

#[tokio::test]
async fn control_notify_real_stream_snapshots_updates_and_tokens_never_touch_session_or_disclose_agent_words(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=approval_fixture("each",&["header:x-key"]).await;let first=f.send("GET","/before",vec![("x-key".into(),f.ph.clone())],None).await;let id=held_id(&first);let mut watch=NotifyWatch::open(&f,vec![]).await;assert_eq!(watch.status,200);let(event,v,_)=watch.next().await;assert_eq!(event,"snapshot");assert_eq!(v["items"].as_array().unwrap().len(),1);assert_eq!(v["items"][0]["kind"],"request");assert_eq!(f.send("GET","/later",vec![("x-key".into(),f.ph.clone()),("av-reason".into(),"<script>alert(1)</script>".into())],None).await.status,202);let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","paths":[format!("/x/{}",f.ph)],"reason":"<script>steal()</script>"})).await;assert_eq!(s,200,"{asked}");let(event,held,raw)=watch.next().await;assert_eq!(event,"pending");assert_eq!(held["kind"],"request");assert!(held["headline"].as_str().unwrap().starts_with("GET "));let(_,session,raw2)=watch.next().await;assert_eq!(session["kind"],"session");assert_eq!(session["id"],asked["id"]);let text=format!("{raw}\n{raw2}");for private in ["<script>",&f.ph,SECRET]{assert!(!text.contains(private));}assert!(session["headline"].as_str().unwrap().contains("«placeholder»"));let mut keys=session.as_object().unwrap().keys().cloned().collect::<Vec<_>>();keys.sort();assert_eq!(keys,vec!["created_at","headline","id","kind"]);drop(watch);
        let before=store_snapshot(&f).await;let audit=audit_records(&f).await;for headers in [vec![("authorization".into(),format!("Bearer {}",f.token))],vec![("av-session".into(),f.token.clone())],vec![("av-session".into(),"avs1.garbage.token".into())],vec![]] {let mut w=NotifyWatch::open(&f,headers).await;assert_eq!(w.status,200);assert_eq!(w.next().await.0,"snapshot");drop(w);}assert_eq!(store_snapshot(&f).await,before);assert_eq!(audit_records(&f).await,audit);f.daemon.pipeline().decide_approval(id,true).await.unwrap();assert_eq!(f.send("GET","/before",vec![("x-key".into(),f.ph.clone())],None).await.status,200);credential_finish(&f).await;
    }).await.expect("notification stream and C20 timed out");
}

#[tokio::test]
async fn control_notify_stream_caps_eight_watchers_and_releases_closed_slot() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let mut open = Vec::new();
        for _ in 0..8 {
            let mut w = NotifyWatch::open(&f, vec![]).await;
            assert_eq!(w.status, 200);
            w.next().await;
            open.push(w);
        }
        let ninth = NotifyWatch::open(&f, vec![]).await;
        assert_eq!(ninth.status, 429);
        drop(ninth);
        drop(open.pop());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let again = NotifyWatch::open(&f, vec![]).await;
        assert_eq!(again.status, 200);
        drop(again);
        drop(open);
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("notification watcher cap timed out");
}

#[tokio::test]
async fn control_notify_webhook_configuration_is_gated_encrypted_and_only_host_is_public() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        credential_presence_refused(
            credential_api(&f, "POST", "/v1/notify", json!({"webhook_url":NOTIFY_HOOK})).await,
        );
        assert_eq!(
            credential_api(&f, "GET", "/v1/notify", json!({})).await.1,
            json!({"webhook":null})
        );
        credential_gate(&f, true).await;
        for url in [
            json!("http://example.com/hook"),
            json!("https://user:pw@hooks.example/x"),
            json!("not a url"),
            json!(5),
        ] {
            assert_eq!(
                credential_api(&f, "POST", "/v1/notify", json!({"webhook_url":url}))
                    .await
                    .1["rule"],
                "webhook_url"
            );
        }
        let (s, v) =
            credential_api(&f, "POST", "/v1/notify", json!({"webhook_url":NOTIFY_HOOK})).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["webhook"]["host"], "hooks.example");
        assert_eq!(v["webhook"]["detail"], "minimal");
        let shown = credential_api(&f, "GET", "/v1/notify", json!({})).await.1;
        let all = json!([v, shown, audit_records(&f).await]).to_string();
        for part in ["SECRETPATH", "QUERYSECRET", "/services/"] {
            assert!(!all.contains(part));
        }
        let f = control_session_restart_with_pass(
            f,
            move |dir| {
                for file in ["vault.db", "vault.db-wal"] {
                    if let Ok(disk) = std::fs::read(dir.join(file)) {
                        for part in ["SECRETPATH", "QUERYSECRET", "/services/"] {
                            assert!(!disk.windows(part.len()).any(|w| w == part.as_bytes()));
                        }
                    }
                }
            },
            Some(WIDEN_PASS),
        )
        .await;
        credential_presence_refused(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/expiry",
                json!({"slug":"demo","expires_at":null}),
            )
            .await,
        );
        assert_eq!(
            credential_api(&f, "DELETE", "/v1/notify", json!({}))
                .await
                .1,
            json!({"ok":true,"removed":true})
        );
        assert_eq!(
            audit_records(&f)
                .await
                .iter()
                .filter(|r| r["kind"] == "notify.removed")
                .count(),
            1
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("webhook configuration timed out");
}

#[test]
fn control_notify_payloads_are_bounded_counts_or_clean_headlines_and_stored_redaction_keeps_plain_text(
) {
    use av_daemon::notify::{clean_headline, webhook_payload};
    let ph = "av1.abcdefghijklmnopqrstuvwxyz.demo_token.ABCDEFGHIJKLMNOPQRSTUVWX.ABCD";
    let items = vec![
        json!({"kind":"request","id":"ap_1","headline":"POST api.example.com/repos/x","created_at":"2026-01-01T00:00:00Z"}),
        json!({"kind":"session","id":"sr_1","headline":clean_headline(&format!("session for demo · GET · /x/{ph}\u{1b}[31m")),"created_at":"2026-01-01T00:00:01Z"}),
    ];
    let minimal = webhook_payload(&items, "minimal", "pending");
    assert!(!minimal.contains("api.example.com"));
    assert!(serde_json::from_str::<Value>(&minimal)
        .unwrap()
        .get("items")
        .is_none());
    let headline = webhook_payload(&items, "headline", "pending");
    let v: Value = serde_json::from_str(&headline).unwrap();
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(v["items"][1]["headline"], "POST api.example.com/repos/x");
    assert!(!headline.contains('\u{1b}'));
    let many=(0..50).map(|i|json!({"kind":"request","id":format!("ap_{i}"),"headline":"x".repeat(190),"created_at":format!("2026-01-01T00:00:{i:02}Z")})).collect::<Vec<_>>();
    let big = webhook_payload(&many, "headline", "pending");
    assert!(big.len() <= 2048);
    assert_eq!(serde_json::from_str::<Value>(&big).unwrap()["waiting"], 50);
    let secrets = vec![av_core::scrub::StoredSecret {
        secret: SECRET.to_string().into(),
        label: "demo".into(),
    }];
    assert_eq!(
        av_core::scrub::redact_stored("session for demo · GET · /repos/x", &secrets),
        "session for demo · GET · /repos/x"
    );
    assert_eq!(
        av_core::scrub::redact_stored(&format!("a/{SECRET}/b"), &secrets),
        "a/[[av:redacted:demo]]/b"
    );
    assert_eq!(
        av_core::scrub::redact_stored(
            "GET /abc",
            &[av_core::scrub::StoredSecret {
                secret: "abc".to_string().into(),
                label: "short".into()
            }]
        ),
        "GET /abc"
    );
}

#[tokio::test]
async fn control_notify_minimal_webhook_posts_once_per_interval_and_secret_headlines_are_scrubbed_live_and_snapshot(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let p=NotifyFixture::new(true).await;p.configure(av_store::model::NotifyDetail::Minimal).await;let held=p.f.send("GET","/a?q=QUERYTEXT",vec![("x-key".into(),p.f.ph.clone()),("av-reason".into(),"<script>x</script>".into())],None).await;let id=held_id(&held);assert_eq!(credential_api(&p.f,"POST","/v1/session-requests",json!({"cred":"demo","reason":"<script>y</script>","paths":[format!("/x/{}",p.f.ph)]})).await.0,200);p.wait_calls(1).await;tokio::time::sleep(std::time::Duration::from_millis(50)).await;let calls=p.calls.lock().unwrap().clone();assert_eq!(calls.len(),1);assert_eq!(calls[0].0,NOTIFY_HOOK);let body=&calls[0].1;let mut keys=body.as_object().unwrap().keys().cloned().collect::<Vec<_>>();keys.sort();assert_eq!(keys,vec!["event","ids","kinds","open","source","waiting"]);assert_eq!(body["event"],"pending");assert_eq!(body["kinds"]["request"],1);for part in ["<script>",&p.f.ph,"QUERYTEXT","headline","GET "] {assert!(!body.to_string().contains(part));}p.f.daemon.pipeline().decide_approval(id,true).await.unwrap();assert_eq!(p.f.send("GET","/a?q=QUERYTEXT",vec![("x-key".into(),p.f.ph.clone()),("av-reason".into(),"<script>x</script>".into())],None).await.status,200);p.finish().await;
        let p=NotifyFixture::new(false).await;p.configure(av_store::model::NotifyDetail::Headline).await;let mut watch=NotifyWatch::open(&p.f,vec![]).await;watch.next().await;assert_eq!(control(&p.f._dir.path().join("control.sock"),"/v1/session-requests",json!({"cred":"demo","paths":[format!("/{SECRET}"),"/plain/path"],"reason":"x"})).await.0,200);let(_,_,streamed)=watch.next().await;p.wait_calls(1).await;let posted=p.calls.lock().unwrap()[0].1.to_string();for text in [&streamed,&posted] {assert!(!text.contains(SECRET));assert!(!text.contains(&SECRET[..12]));assert!(text.contains("[[av:redacted:demo]]"));assert!(text.contains("/plain/path"));}let mut late=NotifyWatch::open(&p.f,vec![]).await;assert!(!late.next().await.2.contains(SECRET));drop(late);drop(watch);assert_eq!(p.f.get().await.status,200);p.finish().await;
    }).await.expect("webhook payload secrecy timed out");
}

#[tokio::test]
async fn control_notify_test_route_throttles_and_real_http_500_failures_are_audited_once() {
    tokio::time::timeout(std::time::Duration::from_secs(100), async {
        let p = NotifyFixture::new(false).await;
        assert_eq!(
            credential_api(&p.f, "POST", "/v1/notify/test", json!({}))
                .await
                .0,
            404
        );
        p.configure(av_store::model::NotifyDetail::Headline).await;
        assert_eq!(
            credential_api(&p.f, "POST", "/v1/notify/test", json!({}))
                .await
                .1,
            json!({"sent":true,"status":200})
        );
        assert_eq!(p.calls.lock().unwrap()[0].1["event"], "test");
        let (s, v) = credential_api(&p.f, "POST", "/v1/notify/test", json!({})).await;
        assert_eq!(s, 429, "{v}");
        assert_eq!(v["code"], "AV_QUOTA_EXCEEDED");
        assert_eq!(p.calls.lock().unwrap().len(), 1);
        p.status.store(500, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..2 {
            tokio::time::sleep(std::time::Duration::from_millis(
                av_daemon::notify::TEST_INTERVAL_MS + 50,
            ))
            .await;
            assert_eq!(
                credential_api(&p.f, "POST", "/v1/notify/test", json!({}))
                    .await
                    .1,
                json!({"sent":false,"status":500})
            );
        }
        let failed = audit_records(&p.f)
            .await
            .into_iter()
            .filter(|r| r["kind"] == "notify.failed")
            .collect::<Vec<_>>();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0]["host"], "hooks.example");
        assert_eq!(failed[0]["reason"], "status_500");
        assert_eq!(p.f.get().await.status, 200);
        p.finish().await;
    })
    .await
    .expect("real webhook status failure intervals timed out");
}

fn rpc_tool(name: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})
}
fn rpc_body(v: &Value) -> Value {
    serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}
async fn mcp_wire(
    f: &Fixture,
    method: &str,
    message: Value,
    token: Option<&str>,
    extra: Vec<(String, String)>,
) -> (u16, Vec<(String, String)>, Value) {
    let mut headers = vec![
        ("content-type".into(), "application/json".into()),
        (
            "accept".into(),
            "application/json, text/event-stream".into(),
        ),
    ];
    if let Some(token) = token {
        headers.push(("authorization".into(), format!("Bearer {token}")));
    }
    headers.extend(extra);
    let (s, h, body) = loopback_http(
        f.daemon.gateway_port().unwrap(),
        method,
        "/mcp",
        headers,
        serde_json::to_vec(&message).unwrap(),
    )
    .await;
    assert!(!String::from_utf8_lossy(&body).contains(SECRET));
    (
        s,
        h,
        if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        },
    )
}
#[tokio::test]
async fn mcp_transport_routing_id_never_authenticates_protocol_checks_and_batch_notification_lifetimes(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:authorization:Bearer"]).await;let(s,headers,_)=mcp_wire(&f,"POST",json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),Some(&f.token),vec![]).await;assert_eq!(s,200);let sid=headers.iter().find(|(k,_)|k.eq_ignore_ascii_case("mcp-session-id")).unwrap().1.clone();
        for(name,args)in [("vault_list_creds",json!({})),("vault_get_placeholder",json!({"cred":"demo","reason":"x"})),("vault_http",json!({"cred":"demo","method":"GET","path":"/user","reason":"x"})),("vault_approval_status",json!({"approval_id":"ap_whatever"}))] {let(_,_,v)=mcp_wire(&f,"POST",rpc_tool(name,args),None,vec![("mcp-session-id".into(),sid.clone())]).await;assert_eq!(v["result"]["isError"],true,"{name}: {v}");}
        let(s,_,v)=mcp_wire(&f,"POST",json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),Some(&f.token),vec![("mcp-session-id".into(),"not-a-real-session".into())]).await;assert_eq!(s,404);assert_eq!(v["code"],"AV_MCP_SESSION_UNKNOWN");let(s,_,v)=mcp_wire(&f,"POST",json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),Some(&f.token),vec![("mcp-protocol-version".into(),"1999-01-01".into())]).await;assert_eq!(s,400);assert_eq!(v["code"],"AV_MCP_PROTOCOL");assert!(v["supported"].is_array());
        let(s,_,v)=mcp_wire(&f,"POST",json!([{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]),Some(&f.token),vec![]).await;assert_eq!(s,200);assert_eq!(v.as_array().unwrap().len(),2);assert_eq!(v[0]["id"],1);let(s,_,v)=mcp_wire(&f,"POST",json!({"jsonrpc":"2.0","method":"notifications/initialized"}),Some(&f.token),vec![]).await;assert_eq!(s,202);assert!(v.is_null());
        assert_eq!(mcp_wire(&f,"DELETE",Value::Null,Some(&f.token),vec![("mcp-session-id".into(),sid)]).await.0,204);assert_eq!(mcp_wire(&f,"POST",json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),Some(&f.token),vec![]).await.0,200);assert_eq!(f.get().await.status,403); // its field is Authorization, not x-key
        let(_,_,v)=mcp_wire(&f,"POST",rpc_tool("vault_http",json!({"cred":"demo","method":"GET","path":"/ordinary"})),Some(&f.token),vec![]).await;assert_eq!(rpc_body(&v)["status"],200);credential_finish(&f).await;
    }).await.expect("MCP routing and transport lifetime timed out");
}
#[tokio::test]
async fn mcp_transport_direct_handler_and_http_agree_on_status_and_usage_and_share_policy_denials()
{
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::configured(
            &["header:authorization:Bearer"],
            SECRET,
            None,
            json!({"methods":["GET"]}),
        )
        .await;
        for name in ["vault_status", "vault_list_creds"] {
            let (_, direct) = control_mcp_call(&f, name, json!({}), true).await;
            let (_, _, over) = mcp_wire(
                &f,
                "POST",
                rpc_tool(name, json!({})),
                Some(&f.token),
                vec![],
            )
            .await;
            assert_eq!(direct, rpc_body(&over), "{name} transport parity");
            if name == "vault_list_creds" {
                assert_eq!(direct[0]["slug"], "demo");
                assert!(direct[0]["usage"][0]["put_placeholder_at"][0]
                    .as_str()
                    .unwrap()
                    .contains("Authorization: Bearer"));
            }
        }
        let (_, _, denied) = mcp_wire(
            &f,
            "POST",
            rpc_tool(
                "vault_http",
                json!({"cred":"demo","method":"DELETE","path":"/user","reason":"x"}),
            ),
            Some(&f.token),
            vec![],
        )
        .await;
        assert_eq!(rpc_body(&denied)["status"], 403);
        assert_eq!(rpc_body(&denied)["decision"], "deny");
        assert!(f.up.hits.lock().unwrap().is_empty());
        let (_, _, ordinary) = mcp_wire(
            &f,
            "POST",
            rpc_tool(
                "vault_http",
                json!({"cred":"demo","method":"GET","path":"/user","reason":"x"}),
            ),
            Some(&f.token),
            vec![],
        )
        .await;
        assert_eq!(rpc_body(&ordinary)["status"], 200);
        credential_finish(&f).await;
    })
    .await
    .expect("MCP parity timed out");
}

#[tokio::test]
async fn mcp_tools_grant_boundary_traversal_ungranted_credential_and_crlf_never_smuggle_upstream() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::configured(&["header:authorization:Bearer"],SECRET,None,json!({"paths":["/safe/**"]})).await;assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"ungranted","kind":"http","host":"other.example.test","value":"UNGRANTED-SECRET-0044556","sites":["header:authorization:Bearer"]})).await.0,200);
        let(_,v)=control_mcp_call(&f,"vault_http",json!({"cred":"demo","method":"GET","path":"/safe/x"}),true).await;assert_eq!(v["status"],200);{let hits=f.up.hits.lock().unwrap();assert_eq!(hits.len(),1);assert_eq!(url::Url::parse(&hits[0].url).unwrap().path(),"/safe/x");assert!(hits[0].headers.iter().any(|(k,v)|k.eq_ignore_ascii_case("authorization")&&v==&format!("Bearer {SECRET}")));}
        for path in ["/forbidden/x","/safe/../forbidden/x","/../../etc/passwd","/safe/%2e%2e/forbidden/x","/safe/./../forbidden","/safe/x\r\nX-Injected: 1"] {f.up.hits.lock().unwrap().clear();let(_,v)=control_mcp_call(&f,"vault_http",json!({"cred":"demo","method":"GET","path":path}),true).await;assert_ne!(v["status"],200,"{path}: {v}");assert!(f.up.hits.lock().unwrap().is_empty());}
        let(_,v)=control_mcp_call(&f,"vault_http",json!({"cred":"ungranted","method":"GET","path":"/safe/x"}),true).await;assert!(v.to_string().contains("no grant"));assert!(f.up.hits.lock().unwrap().is_empty());
        let(_,v)=control_mcp_call(&f,"vault_http",json!({"cred":"demo","method":"GET","path":"/safe/x","headers":{"av-session":"forged","AV-Reason":"spoofed","host":"evil.test"}}),true).await;assert_eq!(v["status"],200);{let hits=f.up.hits.lock().unwrap();assert_eq!(hits.len(),1);assert!(hits[0].headers.iter().all(|(k,_)|!k.to_ascii_lowercase().starts_with("av-")));assert!(hits[0].headers.iter().filter(|(k,_)|k.eq_ignore_ascii_case("host")).all(|(_,v)|!v.contains("evil")));}
        for(body,headers,want)in [("batch=%5B%5D",json!({"Content-Type":"application/x-www-form-urlencoded"}),"application/x-www-form-urlencoded"),("{\"a\":1}",json!({}),"application/json")] {f.up.hits.lock().unwrap().clear();let(_,v)=control_mcp_call(&f,"vault_http",json!({"cred":"demo","method":"POST","path":"/safe/x","body":body,"headers":headers}),true).await;assert_eq!(v["status"],200,"{v}");let hits=f.up.hits.lock().unwrap();assert_eq!(hits.len(),1);assert_eq!(hits[0].headers.iter().filter(|(k,_)|k.eq_ignore_ascii_case("content-type")).map(|(_,v)|v.as_str()).collect::<Vec<_>>(),vec![want]);}credential_finish(&f).await;
    }).await.expect("MCP argument attacks timed out");
}

#[tokio::test]
async fn mcp_tools_placeholder_scope_all_outputs_and_documented_names_never_expose_credentials() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:authorization:Bearer"]).await;assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"ungranted","kind":"http","host":"other.example.test","value":"UNGRANTED-SECRET-0044556","sites":["header:authorization:Bearer"]})).await.0,200);let(error,ok)=control_mcp_call(&f,"vault_get_placeholder",json!({"cred":"demo","reason":"testing"}),true).await;assert!(!error);assert!(ok["placeholder"].as_str().unwrap().starts_with("av1."));let(_,no)=control_mcp_call(&f,"vault_get_placeholder",json!({"cred":"ungranted","reason":"testing"}),true).await;assert!(no.to_string().contains("no grant"));assert!(no.get("placeholder").is_none());
        for(name,args)in [("vault_status",json!({})),("vault_list_creds",json!({})),("vault_get_placeholder",json!({"cred":"demo","reason":"x"})),("vault_http",json!({"cred":"demo","method":"GET","path":"/safe/x"})),("vault_explain_denial",json!({"request_id":"nope"}))] {let(_,v)=control_mcp_call(&f,name,args,true).await;assert!(!v.to_string().contains("UNGRANTED-SECRET-0044556"));}
        let tools=av_daemon::mcp::tools();let names=tools.as_array().unwrap().iter().map(|t|t["name"].as_str().unwrap()).collect::<std::collections::BTreeSet<_>>();assert_eq!(names,std::collections::BTreeSet::from(["vault_approval_status","vault_describe_access","vault_explain_denial","vault_get_placeholder","vault_http","vault_list_creds","vault_preflight","vault_request_session","vault_status"]));let ask=tools.as_array().unwrap().iter().find(|t|t["name"]=="vault_request_session").unwrap();assert_eq!(ask["inputSchema"]["properties"]["ttl_minutes"]["type"],"number");for field in ["cred","methods","paths","budget"]{assert!(ask["inputSchema"]["properties"].get(field).is_some());}
        let missing=control_mcp_call(&f,"vault_approval_status",json!({"approval_id":"ap_doesnotexist"}),true).await.1;assert!(missing["error"].as_str().unwrap().contains("no approval"));credential_finish(&f).await;
    }).await.expect("MCP scoped outputs and schema timed out");
}

#[test]
fn mcp_tools_every_production_error_string_tool_reference_names_an_advertised_tool() {
    fn visit(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                if p.file_name().unwrap() != "tests" {
                    visit(&p, files);
                }
            } else if p.extension().is_some_and(|s| s == "rs") {
                files.push(p);
            }
        }
    }
    let tools = av_daemon::mcp::tools();
    let names = tools
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!names.contains("vault_id"));
    let mut files = Vec::new();
    visit(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let words = av_core::jsre::compile(r"\bvault_[a-z_]+").unwrap();
    let strings = av_core::jsre::compile(r#""(?:\\.|[^"\\])*""#).unwrap();
    for file in files {
        let src = std::fs::read_to_string(&file).unwrap();
        let src = src.split("#[cfg(test)]").next().unwrap();
        for (line_no, line) in src.lines().enumerate() {
            let line = line.trim();
            if line.starts_with("//") || line.starts_with('*') {
                continue;
            }
            for text in strings.find_iter(line) {
                for word in words.find_iter(text.as_str()) {
                    assert!(
                        names.contains(word.as_str()) || word.as_str() == "vault_id",
                        "{}:{} references unknown tool {}",
                        file.display(),
                        line_no + 1,
                        word.as_str()
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn mcp_tools_session_proposals_never_issue_capability_before_human_and_batch_cannot_switch_identity(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:authorization:Bearer"]).await;let count=f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap();let before=audit_records(&f).await;assert_eq!(control_mcp_call(&f,"vault_request_session",json!({"cred":"missing","reason":"testing"}),true).await.1["code"],"AV_NOT_FOUND");assert_eq!(audit_records(&f).await,before);assert!(credential_api(&f,"GET","/v1/session-requests",json!({})).await.1.as_array().unwrap().is_empty());let(_,asked)=control_mcp_call(&f,"vault_request_session",json!({"cred":"demo","reason":"testing"}),true).await;assert_eq!(asked["state"],"pending");assert!(asked["request_id"].as_str().unwrap().starts_with("sr_"));assert!(!asked.to_string().contains("avs1."));assert_eq!(f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap(),count);let(_,poll)=control_mcp_call(&f,"vault_request_session",json!({"poll_id":asked["request_id"],"poll_secret":asked["poll_secret"],"reason":"checking"}),true).await;assert_eq!(poll["state"],"pending");assert!(poll.get("token").is_none());
        let gid=f.grant_id.clone();let high=f.shared.run(move|c|{use av_core::secret::ExposeSecret;let cred=c.vault.add_credential(av_store::vault::NewCredential{slug:"high".into(),kind:"http".into(),connector:serde_json::from_value(json!({"host":"api.example.test"})).unwrap(),fields:vec![("token".into(),"HIGH-SECRET-PRODUCTION-99999".to_string().into())],sites:std::collections::BTreeMap::from([("token".into(),vec!["header:authorization:Bearer".into()])])}).unwrap();let s=c.vault.create_session(Default::default()).unwrap();let parent=c.vault.grant(&gid).unwrap().unwrap();c.vault.create_grant(av_store::vault::CreateGrantOptions{session_id:s.session.id,credential_id:cred.id,policy:parent.policy,..Default::default()}).unwrap();s.token.expose_secret().to_string()}).await.unwrap();
        let gate=Arc::new(tokio::sync::Notify::new());*f.up.gate.lock().unwrap()=Some(gate.clone());let batch=json!([rpc_tool("vault_http",json!({"cred":"demo","method":"GET","path":"/slow"})),{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_http","arguments":{"cred":"high","method":"GET","path":"/STOLEN"}}}]);let pending=mcp_wire(&f,"POST",batch,Some(&f.token),vec![]);tokio::pin!(pending);
        tokio::select!{_= &mut pending=>panic!("slow batch unexpectedly finished"),_=async{loop{if !f.up.hits.lock().unwrap().is_empty(){break;}tokio::task::yield_now().await;}}=>{}}
        assert_eq!(mcp_wire(&f,"POST",rpc_tool("vault_status",json!({})),Some(&high),vec![]).await.0,200);gate.notify_one();let(_,_,out)=pending.await;assert!(out.to_string().contains("no grant"));assert!(!out.to_string().contains("HIGH-SECRET-PRODUCTION-99999"));assert_eq!(f.up.hits.lock().unwrap().len(),1);*f.up.gate.lock().unwrap()=None;let(_,_,allowed)=mcp_wire(&f,"POST",rpc_tool("vault_http",json!({"cred":"high","method":"GET","path":"/ordinary"})),Some(&high),vec![]).await;assert_eq!(rpc_body(&allowed)["status"],200);assert!(!allowed.to_string().contains("HIGH-SECRET-PRODUCTION-99999"));credential_finish(&f).await;
    }).await.expect("MCP proposal authority and batch race timed out");
}

#[tokio::test]
async fn mcp_tools_crlf_path_and_header_are_refused_by_real_http_transport_without_smuggling() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        use tokio::io::AsyncWriteExt;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();let received=Arc::new(Mutex::new(Vec::new()));let hits=received.clone();let peer=tokio::spawn(async move{loop{let(mut socket,_)=listener.accept().await.unwrap();let mut first=[0u8;1];if socket.peek(&mut first).await.unwrap()==0 {continue;}let(h,_)=read_wire_request(&mut socket).await;hits.lock().unwrap().push(h.clone());let reply=json!({"echo":h}).to_string();socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",reply.len()).as_bytes()).await.unwrap();}});
        let f=mcp_real_http_fixture(port).await;
        for args in [json!({"cred":"demo","method":"GET","path":"/safe/x\r\nX-Injected: 1"}),json!({"cred":"demo","method":"GET","path":"/safe/x","headers":{"X-A":"v\r\nX-Injected: 1"}})] {let(_,v)=control_mcp_call(&f,"vault_http",args,true).await;assert_ne!(v["status"],200,"{v}");assert!(received.lock().unwrap().is_empty());}
        let(_,v)=control_mcp_call(&f,"vault_http",json!({"cred":"demo","method":"GET","path":"/safe/x","headers":{"X-A":"ordinary"}}),true).await;assert_eq!(v["status"],200,"{v}");assert!(!v.to_string().contains(SECRET));let wire=received.lock().unwrap().clone();assert_eq!(wire.len(),1);assert!(wire[0].contains("ordinary"));assert!(!wire[0].contains("X-Injected"));credential_finish(&f).await;peer.abort();let _=peer.await;
    }).await.expect("MCP CRLF real wire timed out");
}

#[tokio::test]
async fn approval_verdict_nonbooleans_never_settle_even_with_window_or_matching_signature() {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let w = WidenFixture::new().await;
        let gid = w.f.grant_id.clone();
        w.f.shared
            .run(move |c| {
                c.vault
                    .narrow_grant(&gid, &json!({"approval":"on-write"}))
                    .unwrap()
            })
            .await
            .unwrap();
        let send = |path: &'static str| {
            w.f.send(
                "POST",
                path,
                vec![("authorization".into(), format!("Bearer {}", w.f.ph))],
                Some("x".into()),
            )
        };
        let id = held_id(&send("/verdict/invalid").await);
        let invalid = [
            Some(json!("false")),
            Some(json!(0)),
            Some(json!(1)),
            Some(Value::Null),
            Some(json!("true")),
            Some(json!("no")),
            None,
        ];
        for window in [false, true] {
            if window {
                credential_gate(&w.f, true).await;
            }
            for granted in &invalid {
                let mut body = json!({"id":id});
                if let Some(granted) = granted {
                    body["granted"] = granted.clone();
                }
                let (s, v) = w.ctl("POST", "/v1/approvals", body).await;
                assert_eq!(s, 403, "{v}");
                assert_eq!(v["code"], "AV_POLICY_DENIED");
                assert_eq!(v["rule"], "bulk_decision");
            }
        }
        credential_gate(&w.f, false).await;
        for granted in &invalid {
            let mut body = json!({"id":id});
            if let Some(granted) = granted {
                body["granted"] = granted.clone();
            }
            body["presence"] = w.proof("approval.approve", &body).await;
            let (s, v) = w.ctl("POST", "/v1/approvals", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "bulk_decision");
        }
        assert!(w
            .f
            .daemon
            .pipeline()
            .pending_approvals()
            .await
            .iter()
            .any(|r| r["id"] == id));
        let before = w.f.up.hits.lock().unwrap().len();
        assert_eq!(send("/verdict/invalid").await.status, 202);
        assert_eq!(w.f.up.hits.lock().unwrap().len(), before);
        for (granted, path, op, state) in [
            (true, "/verdict/yes", "approval.approve", "granted"),
            (false, "/verdict/no", "approval.deny", "denied"),
        ] {
            let id = held_id(&send(path).await);
            let mut body = json!({"id":id,"granted":granted});
            assert_eq!(w.ctl("POST", "/v1/approvals", body.clone()).await.0, 401);
            body["presence"] = w.proof(op, &body).await;
            let (s, v) = w.ctl("POST", "/v1/approvals", body).await;
            assert_eq!(s, 200, "{v}");
            assert_eq!(v["state"], state);
            if granted {
                assert_eq!(send(path).await.status, 200);
            }
        }
        w.stop().await;
    })
    .await
    .expect("strict approval verdict and signed refusals timed out");
}

async fn mcp_real_http_fixture(port: u16) -> Fixture {
    use av_core::secret::ExposeSecret;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
    let cred = vault
        .add_credential(av_store::vault::NewCredential {
            slug: "demo".into(),
            kind: "http".into(),
            connector: serde_json::from_value(
                json!({"host":format!("127.0.0.1:{port}"),"scheme":"http"}),
            )
            .unwrap(),
            fields: vec![("token".into(), SECRET.to_string().into())],
            sites: std::collections::BTreeMap::from([(
                "token".into(),
                vec!["header:authorization:Bearer".into()],
            )]),
        })
        .unwrap();
    let session = vault.create_session(Default::default()).unwrap();
    let grant=vault.create_grant(av_store::vault::CreateGrantOptions{session_id:session.session.id,credential_id:cred.id,policy:serde_json::from_value(json!({"hosts":["127.0.0.1"],"methods":["GET","POST"],"paths":["/safe/**"],"approval":"auto","budget":{"unit":"requests","limit":100}})).unwrap(),..Default::default()}).unwrap();
    let ph = vault
        .issue_placeholder(av_store::vault::IssueOptions {
            grant_id: grant.id.clone(),
            ..Default::default()
        })
        .unwrap();
    let token = session.token.expose_secret().to_string();
    let shared = Shared::new(vault);
    let daemon = Daemon::new(
        shared.clone(),
        DaemonOptions {
            port: 0,
            socket_path: Some(dir.path().join("control.sock")),
            ..Default::default()
        },
    )
    .unwrap();
    daemon.start().await.unwrap();
    Fixture {
        _dir: dir,
        shared,
        daemon,
        up: Arc::new(RecordingUpstream::default()),
        token,
        ph: ph.placeholder,
        secret: SECRET.into(),
        grant_id: grant.id,
    }
}

#[tokio::test]
async fn session_requests_presence_never_authorizes_new_hosts_denial_cannot_flip_and_flood_cannot_evict(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let (s, asked) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","methods":["GET"],"paths":["/**"]}),
        )
        .await;
        assert_eq!(s, 200, "{asked}");
        credential_gate(&f, true).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests/decide",
            json!({"id":asked["id"],"granted":true,"overrides":{"hosts":["evil.test"]}}),
        )
        .await;
        assert_eq!(s, 403, "{v}");
        assert!(v.to_string().contains("hosts"));
        assert!(!store_snapshot(&f).await["grants"]
            .to_string()
            .contains("evil.test"));
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests/decide",
            json!({"id":asked["id"],"granted":true}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let p = control_session_policy(&f, v["session"]["grant_id"].as_str().unwrap()).await;
        assert!(!p["hosts"].to_string().contains("evil.test"));
        assert!(p["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h.as_str().unwrap().contains("api.example.test")));
        credential_gate(&f, false).await;
        let (_, asked) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","methods":["GET"],"paths":["/user"]}),
        )
        .await;
        let before = store_snapshot(&f).await;
        credential_gate(&f, true).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests/decide",
            json!({"id":asked["id"],"granted":false}),
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(v["state"], "denied");
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/session-requests/decide",
                json!({"id":asked["id"],"granted":true})
            )
            .await
            .0,
            403
        );
        assert_eq!(store_snapshot(&f).await, before);
        credential_gate(&f, false).await;
        let (_, v) = credential_api(
            &f,
            "GET",
            &format!(
                "/v1/session-requests/collect?id={}&secret={}",
                asked["id"].as_str().unwrap(),
                asked["collect_secret"].as_str().unwrap()
            ),
            json!({}),
        )
        .await;
        assert_eq!(v["state"], "denied");
        assert!(v.get("token").is_none());
        let (_, first) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","methods":["GET"],"paths":["/reading"]}),
        )
        .await;
        let mut refused = 0;
        for i in 0..90 {
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/session-requests",
                json!({"cred":"demo","methods":["GET"],"paths":[format!("/u/{i}")]}),
            )
            .await;
            if s != 200 {
                refused += 1;
                assert!(v["detail"].as_str().unwrap().contains("too many"));
            }
        }
        assert!(refused > 0);
        let (_, pending) = credential_api(&f, "GET", "/v1/session-requests", json!({})).await;
        assert!(pending.as_array().unwrap().len() <= 64);
        assert!(pending
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == first["id"]));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("session request scope denial and flooding timed out");
}

#[tokio::test]
async fn session_requests_started_locked_reacquires_audit_on_every_unlock() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let Fixture {
            _dir,
            shared,
            daemon,
            up,
            token,
            ph,
            secret,
            grant_id,
        } = f;
        daemon.stop().await;
        drop(daemon);
        drop(shared);
        let mut vault = av_store::vault::Vault::open(_dir.path()).unwrap();
        vault.start_in_recorded_state(None).unwrap();
        assert!(vault.locked());
        assert!(vault.audit().is_none());
        let shared = Shared::new(vault);
        let daemon = Daemon::new(
            shared.clone(),
            DaemonOptions {
                port: 0,
                socket_path: Some(_dir.path().join("control.sock")),
                pipeline: PipelineOptions {
                    upstream: Some(up.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        daemon.start().await.unwrap();
        let f = Fixture {
            _dir,
            shared,
            daemon,
            up,
            token,
            ph,
            secret,
            grant_id,
        };
        for path in ["/user", "/repos"] {
            assert_eq!(
                credential_api(&f, "POST", "/v1/unlock", json!({"passphrase":WIDEN_PASS}))
                    .await
                    .0,
                200
            );
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/session-requests",
                json!({"cred":"demo","methods":["GET"],"paths":[path],"reason":"after an unlock"}),
            )
            .await;
            assert_eq!(s, 200, "{v}");
            assert!(audit_records(&f)
                .await
                .iter()
                .any(|r| r["kind"] == "session_request.opened" && r["request_id"] == v["id"]));
            assert_eq!(
                credential_api(&f, "POST", "/v1/lock", json!({})).await.0,
                200
            );
            f.shared
                .run(|c| assert!(c.vault.audit().is_none()))
                .await
                .unwrap();
        }
        assert_eq!(
            credential_api(&f, "POST", "/v1/unlock", json!({"passphrase":WIDEN_PASS}))
                .await
                .0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("session request locked start audit timed out");
}

#[tokio::test]
async fn notify_disconnect_monitor_preserves_two_control_requests_on_one_keep_alive_socket() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let socket = tokio::net::UnixStream::connect(f._dir.path().join("control.sock"))
            .await
            .unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        for path in ["/v1/status", "/v1/credentials"] {
            let response = sender
                .send_request(
                    hyper::Request::builder()
                        .uri(path)
                        .header("host", "localhost")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(!v.to_string().contains(SECRET));
            if path == "/v1/status" {
                assert_eq!(v["locked"], false);
            } else {
                assert_eq!(v[0]["slug"], "demo");
            }
        }
        drop(sender);
        task.abort();
        let _ = task.await;
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("control keep-alive requests timed out");
}

#[tokio::test]
async fn notify_disconnect_monitor_preserves_stream_when_another_request_is_already_pipelined() {
    tokio::time::timeout(std::time::Duration::from_secs(20),async {
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        async fn until(socket:&mut tokio::net::UnixStream,raw:&mut Vec<u8>,needle:&str) {
            tokio::time::timeout(std::time::Duration::from_secs(5),async {while !String::from_utf8_lossy(raw).contains(needle){let mut bytes=[0u8;1024];let n=socket.read(&mut bytes).await.unwrap();assert!(n>0,"pipelined request closed the notification stream");raw.extend_from_slice(&bytes[..n]);assert!(raw.len()<65536);}}).await.expect("pipelined SSE event stopped flowing");
        }
        let f=Fixture::new(&["header:x-key"]).await;let mut socket=tokio::net::UnixStream::connect(f._dir.path().join("control.sock")).await.unwrap();socket.write_all(b"GET /v1/pending/stream HTTP/1.1\r\nHost: localhost\r\n\r\nGET /v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();let mut raw=Vec::new();until(&mut socket,&mut raw,"event: snapshot").await;assert!(String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 200"));
        let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","reason":"ordinary pipelined-stream control"})).await;assert_eq!(s,200,"{asked}");until(&mut socket,&mut raw,asked["id"].as_str().unwrap()).await;let text=String::from_utf8_lossy(&raw);assert!(text.contains("event: pending"));assert_eq!(text.matches("HTTP/1.1 ").count(),1,"a later response must not be interleaved into the active SSE body");assert!(!text.contains(SECRET));drop(socket);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("notify pipelining timed out");
}

#[tokio::test]
async fn session_request_client_collection_records_only_approval_once_in_private_temp_state() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        use std::os::unix::fs::PermissionsExt;
        let f=Fixture::new(&["header:x-key"]).await;let state_path=f._dir.path().join("fake-client-state.json");
        for granted in [true,false] {
            let(s,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["GET"],"paths":[if granted{"/user"}else{"/denied"}],"reason":"to be recorded"})).await;assert_eq!(s,200);if granted{assert!(!state_path.exists());}
            let(s,answered)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":granted})).await;assert_eq!(s,200,"{answered}");let item=av_store::pending::describe(av_store::pending::PendingKind::Session,&asked);let path=if granted {state_path.clone()}else{f._dir.path().join("denied-client-state.json")};let collected=av_store::pending::collect_approved(&item,&answered,|row|{assert!(granted,"a denial must never write client state");av_store::client_state::remember_session(&av_store::client_state::RememberedSession{session_id:row["session_id"].as_str().map(str::to_owned),token:row["token"].as_str().map(str::to_owned),placeholder:row["placeholder"].as_str().map(str::to_owned),base_url:None},&path).unwrap();});
            if granted {let got=collected.unwrap();assert!(got["token"].as_str().unwrap().starts_with("avs1."));let stored:Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();assert_eq!(stored["token"],got["token"]);assert_eq!(stored["session_id"],got["session_id"]);assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode()&0o077,0);let(_,again)=credential_api(&f,"GET",&format!("/v1/session-requests/collect?id={}&secret={}",asked["id"].as_str().unwrap(),asked["collect_secret"].as_str().unwrap()),json!({})).await;assert_eq!(again["state"],"collected");assert!(again.get("token").is_none());}else{assert!(collected.is_none());assert!(!path.exists());}
        }
        assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("private client collection timed out");
}

#[tokio::test]
async fn session_request_approved_ttl_is_immutable_under_touch_and_local_remote_hard_caps_bind() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let f = Fixture::new(&["header:x-key"]).await;
        f.shared
            .run(|c| {
                let made = c
                    .vault
                    .create_session(av_store::vault::CreateSessionOptions {
                        ttl_ms: Some(30 * 60000),
                        ..Default::default()
                    })
                    .unwrap();
                let initial = made.session.expires_at.clone().unwrap();
                assert!(
                    av_daemon::util::parse_iso_ms(&initial).unwrap()
                        <= av_daemon::util::now_ms() + 1801000
                );
                for _ in 0..5 {
                    c.vault.touch_session(&made.session.id).unwrap();
                }
                let after = c.vault.session(&made.session.id).unwrap().unwrap();
                assert_eq!(after.expires_at.as_ref(), Some(&initial));
                assert!(
                    av_daemon::util::parse_iso_ms(after.max_expires_at.as_ref().unwrap()).unwrap()
                        <= av_daemon::util::parse_iso_ms(&initial).unwrap()
                );
                for (remote, cap) in [(false, 24), (true, 8)] {
                    let made = c
                        .vault
                        .create_session(av_store::vault::CreateSessionOptions {
                            ttl_ms: Some(48 * 3600000),
                            remote,
                            ..Default::default()
                        })
                        .unwrap();
                    let expiry =
                        av_daemon::util::parse_iso_ms(made.session.expires_at.as_ref().unwrap())
                            .unwrap();
                    assert!(expiry <= av_daemon::util::now_ms() + cap * 3600000 + 36000);
                    assert!(
                        expiry
                            <= av_daemon::util::parse_iso_ms(
                                made.session.max_expires_at.as_ref().unwrap()
                            )
                            .unwrap()
                    );
                }
                let plain = c.vault.create_session(Default::default()).unwrap();
                assert!(
                    av_daemon::util::parse_iso_ms(plain.session.max_expires_at.as_ref().unwrap())
                        .unwrap()
                        > av_daemon::util::parse_iso_ms(plain.session.expires_at.as_ref().unwrap())
                            .unwrap()
                );
            })
            .await
            .unwrap();
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("approved lifetime ceiling timed out");
}

#[tokio::test]
async fn session_request_bulk_rejects_hidden_approval_shapes_and_settles_live_items_through_same_narrowing(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;credential_gate(&f,true).await;
        let(_,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["GET","POST"],"paths":["/user"]})).await;let id=asked["id"].clone();
        for(decisions,detail)in [(json!([]),"nothing was selected"),(json!("not-a-list"),"must be a list"),(json!([{"id":id,"kind":"session","granted":"false"}]),"must be true or false"),(json!([{"id":id,"kind":"session","granted":true},{"id":id,"kind":"session","granted":false}]),"appears twice"),(json!([{"id":id,"kind":"elsewhere","granted":true}]),"unknown kind"),(json!([{"id":id,"kind":"session","granted":true,"presence":"smuggled"}]),"cannot carry"),(json!(vec![json!({"id":id,"kind":"session","granted":true});26]),"too many at once")] {let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":decisions})).await;assert_eq!(s,403,"{v}");assert!(v["detail"].as_str().unwrap().contains(detail),"{detail}: {v}");}
        let(_,pending)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;assert!(pending.as_array().unwrap().iter().any(|r|r["id"]==id&&r["state"]=="pending"));let before=f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap();let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":id,"kind":"session","granted":true,"overrides":{"methods":["GET"]}}]})).await;assert_eq!(s,200,"{v}");assert_eq!(v["decided"][0]["result"]["granted"]["methods"],json!(["GET"]));assert_eq!(f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap(),before+1);
        let(_,gone)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["GET"],"paths":["/gone"]})).await;let(_,live)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["GET"],"paths":["/live"]})).await;assert_eq!(credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":gone["id"],"granted":false})).await.0,200);let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":gone["id"],"kind":"session","granted":true},{"id":live["id"],"kind":"session","granted":true}]})).await;assert_eq!(s,200,"{v}");let items=v["decided"].as_array().unwrap();let skipped=items.iter().find(|r|r["id"]==gone["id"]).unwrap();assert_eq!(skipped["outcome"],"skipped");assert!(skipped["reason"].as_str().unwrap().contains("already denied"));assert_eq!(items.iter().find(|r|r["id"]==live["id"]).unwrap()["outcome"],"decided");assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("bulk session requests timed out");
}

#[tokio::test]
async fn fix_session_requests_collect_secrets_are_private_and_stolen_ids_cannot_consume_the_answer()
{
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;
        let(_,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["GET"],"paths":["/user"]})).await;let id=asked["id"].as_str().unwrap();let secret=asked["collect_secret"].as_str().unwrap();assert!(secret.len()>=20&&secret.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-'));let(_,listed)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;let listed=listed.to_string();assert!(!listed.contains(secret));assert!(!listed.contains("collect_hash"));assert!(!listed.contains("collect_secret"));assert!(!serde_json::to_string(&audit_records(&f).await).unwrap().contains(secret));
        let(_,other)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["GET"],"paths":["/other"]})).await;credential_gate(&f,true).await;assert_eq!(credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":id,"kind":"session","granted":true},{"id":other["id"],"kind":"session","granted":true}]})).await.0,200);credential_gate(&f,false).await;
        for query in [format!("id={id}"),format!("id={id}&secret="),format!("id={id}&secret={}","A".repeat(32))] {let(s,v)=credential_api(&f,"GET",&format!("/v1/session-requests/collect?{query}"),json!({})).await;assert!(s>=400,"{v}");assert!(!v.to_string().contains("avs1."));}let url=format!("/v1/session-requests/collect?id={id}&secret={secret}");let(s,mine)=credential_api(&f,"GET",&url,json!({})).await;assert_eq!(s,200,"{mine}");assert!(mine["token"].as_str().unwrap().starts_with("avs1."));assert!(credential_api(&f,"GET",&url,json!({})).await.1.get("token").is_none());
        let(_,asked)=control_mcp_call(&f,"vault_request_session",json!({"cred":"demo","reason":"test","methods":["GET"]}),false).await;assert_eq!(asked["state"],"pending");assert!(asked["poll_secret"].is_string());let(_,stranger)=control_mcp_call(&f,"vault_request_session",json!({"poll_id":asked["request_id"],"reason":"peeking"}),false).await;assert!(stranger.get("error").is_some());assert_eq!(control_mcp_call(&f,"vault_request_session",json!({"poll_id":asked["request_id"],"poll_secret":asked["poll_secret"],"reason":"checking"}),false).await.1["state"],"pending");
        let(_,asked)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","paths":["/human"]})).await;credential_gate(&f,true).await;let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["id"],"granted":true})).await;assert_eq!(s,200,"{v}");assert!(v["session"]["token"].as_str().unwrap().starts_with("avs1."));let token=v["session"]["token"].as_str().unwrap().to_owned();assert!(f.shared.run(move|c|c.vault.session_by_token(&token).unwrap().is_some()).await.unwrap());credential_gate(&f,false).await;let(_,v)=credential_api(&f,"GET",&format!("/v1/session-requests/collect?id={}&secret={}",asked["id"].as_str().unwrap(),asked["collect_secret"].as_str().unwrap()),json!({})).await;assert_eq!(v["state"],"collected");assert!(v.get("token").is_none());assert_eq!(f.get().await.status,200);credential_finish(&f).await;
    }).await.expect("private collection secret and one-time answers timed out");
}

#[tokio::test]
async fn fix_session_requests_only_pending_count_toward_cap_and_old_settled_items_are_reclaimed_after_restart(
) {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        for i in 0..av_daemon::session_requests::MAX_PENDING {
            let (s, asked) = credential_api(
                &f,
                "POST",
                "/v1/session-requests",
                json!({"cred":"demo","paths":[format!("/denied/{i}")]}),
            )
            .await;
            assert_eq!(s, 200, "{asked}");
            assert_eq!(
                credential_api(
                    &f,
                    "POST",
                    "/v1/session-requests/decide",
                    json!({"id":asked["id"],"granted":false})
                )
                .await
                .0,
                200
            );
        }
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","paths":["/next"]}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let id = v["id"].as_str().unwrap().to_owned();
        f.shared
            .run(move |c| {
                let item = c.sr.find_mut(&id).unwrap();
                item.state = "collected".into();
                item.decided_at = Some("2000-01-01T00:00:00.000Z".into());
                item.result = None;
                assert!(c.sr_get(&id).is_none());
            })
            .await
            .unwrap();
        let f = control_session_restart_after_seed(f, |_| {}).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","paths":["/after-restart"]}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        for i in 1..av_daemon::session_requests::MAX_PENDING {
            assert_eq!(
                credential_api(
                    &f,
                    "POST",
                    "/v1/session-requests",
                    json!({"cred":"demo","paths":[format!("/pending/{i}")]})
                )
                .await
                .0,
                200
            );
        }
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","paths":["/overflow"]}),
        )
        .await;
        assert_ne!(s, 200);
        assert!(v["detail"].as_str().unwrap().contains("too many"));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("session request pending cap and retention timed out");
}

#[tokio::test]
async fn fix_session_requests_mcp_anonymous_maps_and_audits_are_bounded_but_authenticated_lifetimes_are_recorded(
) {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let before = audit_records(&f).await.len();
        let mut ids = Vec::new();
        for _ in 0..600 {
            let (s, h, _) = mcp_wire(&f, "POST", init.clone(), None, vec![]).await;
            assert_eq!(s, 200);
            ids.push(
                h.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
                    .unwrap()
                    .1
                    .clone(),
            );
        }
        assert!(ids.iter().filter(|s| f.daemon.mcp().has_session(s)).count() <= 256);
        assert!(audit_records(&f).await.len() - before < 50);
        let before = audit_records(&f).await.len();
        for _ in 0..100 {
            let (s, h, _) = mcp_wire(&f, "POST", init.clone(), None, vec![]).await;
            assert_eq!(s, 200);
            let id = h
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
                .unwrap()
                .1
                .clone();
            assert_eq!(
                mcp_wire(
                    &f,
                    "DELETE",
                    Value::Null,
                    None,
                    vec![("mcp-session-id".into(), id.clone())]
                )
                .await
                .0,
                204
            );
            assert!(!f.daemon.mcp().has_session(&id));
        }
        assert!(audit_records(&f).await.len() - before < 10);
        for close_authenticated in [true, false] {
            let (s, h, _) = mcp_wire(&f, "POST", init.clone(), Some(&f.token), vec![]).await;
            assert_eq!(s, 200);
            let id = h
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
                .unwrap()
                .1
                .clone();
            assert!(f.daemon.mcp().has_session(&id));
            assert!(audit_records(&f)
                .await
                .iter()
                .any(|r| r["kind"] == "mcp.session_opened" && r["mcp_session_id"] == id));
            assert_eq!(
                mcp_wire(
                    &f,
                    "DELETE",
                    Value::Null,
                    close_authenticated.then_some(f.token.as_str()),
                    vec![("mcp-session-id".into(), id.clone())]
                )
                .await
                .0,
                204
            );
            let events = audit_records(&f)
                .await
                .into_iter()
                .filter(|r| r["mcp_session_id"] == id)
                .map(|r| r["kind"].clone())
                .collect::<Vec<_>>();
            assert_eq!(
                events,
                vec![json!("mcp.session_opened"), json!("mcp.session_closed")]
            );
        }
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("anonymous MCP transport accounting timed out");
}

#[tokio::test]
async fn fix_session_requests_placeholder_without_live_session_reports_problem_and_selects_only_live_candidate(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut f = Fixture::new(&["header:x-key"]).await;
        let sid = control_session_sid(&f).await;
        f.shared
            .run(move |c| {
                c.vault
                    .revoke_session(&sid, "fixture no live session")
                    .unwrap()
            })
            .await
            .unwrap();
        assert_eq!(
            credential_api(&f, "POST", "/v1/placeholders", json!({"cred":"demo"}))
                .await
                .1["code"],
            "AV_SESSION_REQUIRED"
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/placeholders",
                json!({"cred":"demo","sid":"nope"})
            )
            .await
            .1["code"],
            "AV_NOT_FOUND"
        );
        let (s, a) = credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
        assert_eq!(s, 200, "{a}");
        let (s, b) = credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
        assert_eq!(s, 200, "{b}");
        let dead = a["session_id"].as_str().unwrap().to_owned();
        f = control_session_restart_after_seed(f, move |dir| {
            ported_common::seed_session_expiry(dir, &dead, "2000-01-01T00:00:00.000Z")
        })
        .await;
        let (s, v) = credential_api(&f, "POST", "/v1/placeholders", json!({"cred":"demo"})).await;
        assert_eq!(s, 200, "{v}");
        assert!(v["placeholder"]
            .as_str()
            .unwrap()
            .starts_with(&format!("av1.{}.", b["session_id"].as_str().unwrap())));
        assert_eq!(
            control_session_request(&f, &b, "demo", "GET", "/ordinary")
                .await
                .status,
            200
        );
        credential_finish(&f).await;
    })
    .await
    .expect("live session selection for placeholder timed out");
}

fn ported_cli_command_names() -> Vec<String> {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../av-cli/src/lib.rs"),
    )
    .unwrap();
    let block = src
        .split("pub const COMMAND_NAMES:")
        .nth(1)
        .unwrap()
        .split("= [")
        .nth(1)
        .unwrap()
        .split("];")
        .next()
        .unwrap();
    av_core::jsre::compile(r#""[a-z][a-z-]*(?: [a-z][a-z-]*)*""#)
        .unwrap()
        .find_iter(block)
        .map(|m| m.as_str().trim_matches('"').to_string())
        .collect()
}
#[tokio::test]
async fn session_request_human_hints_and_all_daemon_error_string_commands_exist_in_cli_inventory() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let names = ported_cli_command_names();
        assert!(names.len() > 60);
        let f = Fixture::new(&["header:x-key"]).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests",
            json!({"cred":"demo","methods":["GET"],"paths":["/user"]}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let hints = v["next"]["human"].as_array().unwrap();
        assert!(!hints.is_empty());
        for hint in hints {
            let hint = hint.as_str().unwrap().strip_prefix("agent-vault ").unwrap();
            assert!(
                names
                    .iter()
                    .any(|name| hint == name || hint.starts_with(&format!("{name} "))),
                "unknown command {hint}"
            );
        }
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    if p.file_name().unwrap() != "tests" {
                        walk(&p, out);
                    }
                } else if p.extension().is_some_and(|e| e == "rs") {
                    out.push(p);
                }
            }
        }
        let first = names
            .iter()
            .map(|n| n.split_whitespace().next().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        let prose = [
            "needs",
            "under",
            "will",
            "takes",
            "notification",
            "localhost",
        ];
        let strings = av_core::jsre::compile(r#""(?:\\.|[^"\\])*""#).unwrap();
        let command = av_core::jsre::compile(r"\bagent-vault [a-z][a-z-]*").unwrap();
        let mut files = Vec::new();
        let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        for package in ["av-core", "av-store", "av-daemon", "av-cli"] {
            walk(&crates_dir.join(package).join("src"), &mut files);
        }
        for file in files {
            let src = std::fs::read_to_string(&file).unwrap();
            for (line, source) in src
                .split("#[cfg(test)]")
                .next()
                .unwrap()
                .lines()
                .enumerate()
            {
                let source = source.trim();
                if source.starts_with("//") || source.starts_with('*') {
                    continue;
                }
                for literal in strings.find_iter(source) {
                    for m in command.find_iter(literal.as_str()) {
                        let name = m.as_str().strip_prefix("agent-vault ").unwrap();
                        assert!(
                            first.contains(name) || prose.contains(&name),
                            "{}:{} unknown command {name}",
                            file.display(),
                            line + 1
                        );
                    }
                }
            }
        }
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("CLI-backed daemon hints timed out");
}

async fn probe_fixture(kind: &str, connector: Value, fields: Vec<(&str, Vec<&str>)>) -> Fixture {
    let f = Fixture::new(&["header:x-key"]).await;
    let kind = kind.to_string();
    let sites = fields
        .iter()
        .map(|(n, s)| {
            (
                n.to_string(),
                s.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        })
        .collect();
    let values = fields
        .iter()
        .map(|(n, _)| {
            (
                n.to_string(),
                if *n == "password" {
                    "FAKE-BYSTANDER-PASSWORD-0123456"
                } else {
                    SECRET
                }
                .to_string()
                .into(),
            )
        })
        .collect();
    f.shared
        .run(move |c| {
            c.vault
                .add_credential(av_store::vault::NewCredential {
                    slug: "probe".into(),
                    kind,
                    connector: serde_json::from_value(connector).unwrap(),
                    fields: values,
                    sites,
                })
                .unwrap()
        })
        .await
        .unwrap();
    f
}
async fn probe_health(f: &Fixture) -> Value {
    f.shared
        .run(|c| {
            serde_json::to_value(c.vault.find_credential("probe").unwrap().unwrap().health).unwrap()
        })
        .await
        .unwrap()
}
async fn run_public_probe(f: &Fixture) -> Result<Value, av_core::errors::VaultError> {
    av_daemon::connectors::probe::run_probe(&f.shared, "probe".into(), Some(f.up.clone())).await
}

#[tokio::test]
async fn connector_probe_fixed_methods_paths_first_header_site_and_declared_http_destination() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for (kind, host, scheme, fields, url, method, header, value) in [
            (
                "github",
                "api.github.com",
                "https",
                vec![("token", vec!["header:authorization:Bearer"])],
                "https://api.github.com/user",
                "GET",
                "authorization",
                format!("Bearer {SECRET}"),
            ),
            (
                "slack",
                "slack.com",
                "https",
                vec![("token", vec!["header:authorization:Bearer"])],
                "https://slack.com/api/auth.test",
                "POST",
                "authorization",
                format!("Bearer {SECRET}"),
            ),
            (
                "anthropic",
                "api.anthropic.com",
                "https",
                vec![
                    ("password", vec!["basic:pass"]),
                    (
                        "key",
                        vec!["header:x-api-key", "header:authorization:Bearer"],
                    ),
                ],
                "https://api.anthropic.com/v1/models",
                "GET",
                "x-api-key",
                SECRET.into(),
            ),
            (
                "github",
                "127.0.0.1:8443",
                "HTTP",
                vec![("token", vec!["header:authorization:Bearer"])],
                "http://127.0.0.1:8443/user",
                "GET",
                "authorization",
                format!("Bearer {SECRET}"),
            ),
        ] {
            let f = probe_fixture(kind, json!({"host":host,"scheme":scheme}), fields).await;
            *f.up.reply.lock().unwrap() = Some(Reply {
                streaming: false,
                status: if kind == "anthropic" { 204 } else { 200 },
                headers: vec![
                    ("x-oauth-scopes".into(), "repo, user".into()),
                    ("x-ratelimit-remaining".into(), "7".into()),
                ],
                body: vec![],
            });
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/credentials/test",
                json!({"slug":"probe","path":"/user/keys","method":"DELETE","body":"token=stolen"}),
            )
            .await;
            assert_eq!(s, 200, "{v}");
            assert_eq!(v["ok"], true);
            assert_eq!(v["status"], "ok");
            assert!(v["latency_ms"].as_u64().is_some());
            {
                let sent = f.up.hits.lock().unwrap();
                assert_eq!(sent.len(), 1);
                assert_eq!(sent[0].url, url);
                assert_eq!(sent[0].method, method);
                assert!(sent[0].body.as_ref().is_none_or(|b| b.is_empty()));
                assert!(!sent[0].url.contains(SECRET));
                assert!(sent[0]
                    .headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case(header) && v == &value));
                if kind == "anthropic" {
                    assert!(!sent[0]
                        .headers
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
                }
                if kind == "slack" {
                    assert!(sent[0]
                        .headers
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("content-type")
                            && v == "application/x-www-form-urlencoded"));
                }
                if host.contains("8443") {
                    assert_eq!(sent[0].pins.as_value(), Value::Null);
                }
            }
            let health = probe_health(&f).await;
            assert_eq!(health["source"], "probe");
            assert_eq!(health["status"], "ok");
            assert_eq!(
                health["http_status"],
                if kind == "anthropic" { 204 } else { 200 }
            );
            if kind == "github" {
                assert_eq!(v["scopes"], json!(["repo", "user"]));
                assert_eq!(v["ratelimit_remaining"], 7);
            }
            f.reply(200, "text/plain", "ordinary-traffic-control".into());
            assert_eq!(f.get().await.status, 200);
            credential_finish(&f).await;
        }
    })
    .await
    .expect("fixed profile probe destination timed out");
}

#[tokio::test]
async fn connector_probe_outputs_health_and_logs_never_return_secret_marker_or_body_and_statuses_classify(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = probe_fixture(
            "github",
            json!({"host":"api.github.com"}),
            vec![("token", vec!["header:authorization:Bearer"])],
        )
        .await;
        let body = format!("{SECRET} {} BODY_SENTINEL_do_not_return", f.ph);
        *f.up.reply.lock().unwrap() = Some(Reply {
            streaming: true,
            status: 200,
            headers: vec![
                ("x-oauth-scopes".into(), format!("repo, {SECRET}, {}", f.ph)),
                (
                    "github-authentication-token-expiration".into(),
                    "2027-01-31 00:00:00 UTC".into(),
                ),
            ],
            body: body.into_bytes(),
        });
        let result = run_public_probe(&f).await.unwrap();
        assert_eq!(result["observed_expires_at"], "2027-01-31T00:00:00.000Z");
        assert!(result["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("repo")));
        for v in [
            result,
            probe_health(&f).await,
            json!(audit_records(&f).await),
        ] {
            for private in [SECRET, &f.ph, "BODY_SENTINEL_do_not_return"] {
                assert!(!v.to_string().contains(private));
            }
        }
        credential_finish(&f).await;
        for (code, status) in [
            (401, "unauthorized"),
            (403, "forbidden"),
            (404, "error"),
            (500, "error"),
            (302, "error"),
        ] {
            let f = probe_fixture(
                "github",
                json!({"host":"api.github.com"}),
                vec![("token", vec!["header:authorization:Bearer"])],
            )
            .await;
            f.reply(code, "text/plain", "ordinary response".into());
            let v = run_public_probe(&f).await.unwrap();
            assert_eq!(v["status"], status);
            assert_eq!(v["ok"], false);
            assert_eq!(v["http_status"], code);
            let health = probe_health(&f).await;
            assert_eq!(health["status"], status);
            assert_eq!(health["source"], "probe");
            credential_finish(&f).await;
        }
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let f = probe_fixture(
            "github",
            json!({"host":format!("127.0.0.1:{port}"),"scheme":"http"}),
            vec![("token", vec!["header:authorization:Bearer"])],
        )
        .await;
        let v = av_daemon::connectors::probe::run_probe(&f.shared, "probe".into(), None)
            .await
            .unwrap();
        assert_eq!(v["status"], "unreachable");
        assert_eq!(v["ok"], false);
        assert!(v["http_status"].is_null());
        assert_eq!(probe_health(&f).await["status"], "unreachable");
        assert!(!v.to_string().contains(SECRET));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .expect("probe health result secrecy timed out");
}

#[tokio::test]
async fn connector_probe_absent_profile_header_site_and_bad_destinations_refuse_before_reading_secret(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for (kind, fields) in [
            ("http", vec![("token", vec!["header:authorization:Bearer"])]),
            ("postgres", vec![("password", vec!["basic:pass"])]),
            ("github", vec![("password", vec!["basic:pass"])]),
        ] {
            let f = probe_fixture(kind, json!({"host":"api.github.com"}), fields).await;
            credential_api(&f, "POST", "/v1/lock", json!({})).await;
            let e = run_public_probe(&f).await.unwrap_err();
            assert_eq!(e.code.as_str(), "AV_NOT_FOUND");
            assert_eq!(e.extra.rule.as_deref(), Some("no_probe"));
            if kind != "github" { assert_eq!(e.extra.hint.as_deref(),Some("This kind has no fixed read-only probe. Use vault_http on a path you know.")); }
            assert!(f.up.hits.lock().unwrap().is_empty());
            credential_api(&f, "POST", "/v1/unlock", json!({})).await;
            assert!(probe_health(&f).await.is_null());
            assert_eq!(f.get().await.status, 200);
            credential_finish(&f).await;
        }
        for (host, scheme) in [
            ("api.github.com/steal", "https"),
            ("https://evil.test", "https"),
            ("api.github.com@evil.test", "https"),
            ("api.github.com\nevil.test", "https"),
            ("api.github.com?x=1", "https"),
            ("*.github.com", "https"),
            ("file://api.github.com", "https"),
            ("api.github.com", "file"),
        ] {
            let f = probe_fixture(
                "github",
                json!({"host":host,"scheme":scheme}),
                vec![("token", vec!["header:authorization:Bearer"])],
            )
            .await;
            credential_api(&f, "POST", "/v1/lock", json!({})).await;
            let e = run_public_probe(&f).await.unwrap_err();
            assert_eq!(e.code.as_str(), "AV_POLICY_DENIED", "{host}: {e}");
            assert_eq!(e.extra.rule.as_deref(), Some("credential_host"));
            assert!(f.up.hits.lock().unwrap().is_empty());
            credential_api(&f, "POST", "/v1/unlock", json!({})).await;
            assert!(probe_health(&f).await.is_null());
            credential_finish(&f).await;
        }
    })
    .await
    .expect("probe refusal-before-secret-read timed out");
}

#[tokio::test]
async fn connector_probe_real_time_throttle_ignores_caller_now_and_expires_after_sixty_seconds() {
    tokio::time::timeout(std::time::Duration::from_secs(85), async {
        let a = probe_fixture(
            "github",
            json!({"host":"api.github.com"}),
            vec![("token", vec!["header:authorization:Bearer"])],
        )
        .await;
        let b = probe_fixture(
            "github",
            json!({"host":"api.github.com"}),
            vec![("token", vec!["header:authorization:Bearer"])],
        )
        .await;
        let began = std::time::Instant::now();
        assert_eq!(
            credential_api(&a, "POST", "/v1/credentials/test", json!({"slug":"probe"}))
                .await
                .0,
            200
        );
        assert_eq!(
            credential_api(
                &b,
                "POST",
                "/v1/credentials/test",
                json!({"slug":"probe","now":9007199254740991u64})
            )
            .await
            .0,
            200
        );
        for now in [
            av_daemon::util::now_ms() + 61000,
            av_daemon::util::now_ms() + 122000,
            av_daemon::util::now_ms() + 183000,
        ] {
            let (s, v) = credential_api(
                &a,
                "POST",
                "/v1/credentials/test",
                json!({"slug":"probe","now":now}),
            )
            .await;
            assert_eq!(s, 429, "{v}");
            assert_eq!(v["code"], "AV_QUOTA_EXCEEDED");
            assert_eq!(v["rule"], "probe_throttle");
            assert!((1..=60).contains(&v["retry_after"].as_u64().unwrap()));
        }
        assert_eq!(a.up.hits.lock().unwrap().len(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(1010).saturating_sub(began.elapsed()))
            .await;
        let (s, v) =
            credential_api(&a, "POST", "/v1/credentials/test", json!({"slug":"probe"})).await;
        assert_eq!(s, 429);
        assert!((1..=59).contains(&v["retry_after"].as_u64().unwrap()));
        tokio::time::sleep(std::time::Duration::from_millis(59100).saturating_sub(began.elapsed()))
            .await;
        let (s, v) =
            credential_api(&a, "POST", "/v1/credentials/test", json!({"slug":"probe"})).await;
        assert_eq!(s, 429);
        assert_eq!(v["retry_after"], 1);
        assert_eq!(a.up.hits.lock().unwrap().len(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(61000).saturating_sub(began.elapsed()))
            .await;
        for f in [&a, &b] {
            let (s, v) =
                credential_api(f, "POST", "/v1/credentials/test", json!({"slug":"probe"})).await;
            assert_eq!(s, 200, "{v}");
            assert_eq!(f.up.hits.lock().unwrap().len(), 2);
            assert_eq!(f.get().await.status, 200);
            credential_finish(f).await;
        }
    })
    .await
    .expect("real probe throttle interval timed out");
}

#[tokio::test]
async fn connector_probe_bounded_drain_drops_endless_fast_or_trickle_bodies_and_finishes_ordinary_short_body(
) {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for slow in [false, true] {
            let f = probe_fixture(
                "github",
                json!({"host":"api.github.com"}),
                vec![("token", vec!["header:authorization:Bearer"])],
            )
            .await;
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let producer = tokio::spawn(async move {
                loop {
                    if slow {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    if tx
                        .send(Ok(vec![b'x'; if slow { 1 } else { 16384 }]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            *f.up.source.lock().unwrap() = Some(Body::Stream(rx));
            f.reply(200, "text/plain", String::new());
            let started = std::time::Instant::now();
            let v = run_public_probe(&f).await.unwrap();
            assert_eq!(v["status"], "ok");
            assert!(
                started.elapsed()
                    < std::time::Duration::from_millis(if slow { 4000 } else { 1500 })
            );
            tokio::time::timeout(std::time::Duration::from_secs(1), producer)
                .await
                .expect("probe did not drop endless body receiver")
                .unwrap();
            credential_finish(&f).await;
        }
        let f = probe_fixture(
            "github",
            json!({"host":"api.github.com"}),
            vec![("token", vec!["header:authorization:Bearer"])],
        )
        .await;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let producer = tokio::spawn(async move {
            tx.send(Ok(vec![0; 1024])).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            tx.send(Ok(vec![0; 1024])).await.unwrap();
            tokio::task::yield_now().await;
            assert!(!tx.is_closed(), "ordinary producer was cut before EOF");
            drop(tx);
        });
        *f.up.source.lock().unwrap() = Some(Body::Stream(rx));
        f.reply(200, "text/plain", String::new());
        let started = std::time::Instant::now();
        assert_eq!(run_public_probe(&f).await.unwrap()["status"], "ok");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        producer.await.unwrap();
        credential_finish(&f).await;
    })
    .await
    .expect("bounded probe body drain timed out");
}

struct GatedRealProbe {
    ready: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl Upstream for GatedRealProbe {
    fn send(&self, req: UpstreamRequest) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        self.ready.notify_one();
        Box::pin(async move {
            self.release.notified().await;
            av_daemon::connectors::pinning::PinnedUpstream
                .send(req)
                .await
        })
    }
}
#[tokio::test]
async fn connector_probe_real_lock_during_health_write_surfaces_store_error_after_success_or_network_failure(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async {
        use tokio::io::AsyncWriteExt;
        for reachable in [true,false] {let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();let peer=if reachable{Some(tokio::spawn(async move{let(mut socket,_)=listener.accept().await.unwrap();read_wire_request(&mut socket).await;socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();}))}else{drop(listener);None};let f=probe_fixture("github",json!({"host":format!("127.0.0.1:{port}"),"scheme":"http"}),vec![("token",vec!["header:authorization:Bearer"])]).await;let ready=Arc::new(tokio::sync::Notify::new());let release=Arc::new(tokio::sync::Notify::new());let upstream=Arc::new(GatedRealProbe{ready:ready.clone(),release:release.clone()});let pending=av_daemon::connectors::probe::run_probe(&f.shared,"probe".into(),Some(upstream));tokio::pin!(pending);tokio::select!{_= &mut pending=>panic!("probe bypassed held real transport"),_=ready.notified()=>{}}
            assert_eq!(credential_api(&f,"POST","/v1/lock",json!({})).await.0,200);release.notify_one();let e=pending.await.unwrap_err();assert_eq!(e.code.as_str(),"AV_LOCKED","{e}");assert!(!e.to_string().contains(SECRET));assert_eq!(credential_api(&f,"POST","/v1/unlock",json!({})).await.0,200);assert!(probe_health(&f).await.is_null());assert!(!audit_records(&f).await.iter().any(|r|r["kind"]=="cred.tested"&&r["credential_slug"]=="probe"));if let Some(peer)=peer{peer.await.unwrap();}assert_eq!(f.get().await.status,200);credential_finish(&f).await;
        }
    }).await.expect("real store failure after probe response timed out");
}

#[tokio::test]
async fn connector_probe_joins_legacy_host_aliases_uses_url_identity_and_preserves_no_pin_controls()
{
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let pin = format!("sha256/{}=", "C".repeat(43));
        let other = format!("sha256/{}=", "E".repeat(43));
        for (host, table, want) in [
            (
                "api.github.com",
                json!({"api.github.com":[],"API.GitHub.com":[pin],"other.test":[other]}),
                json!([pin]),
            ),
            ("[0:0::1]:8443", json!({"[::1]":[pin]}), json!([pin])),
            ("[::1]:8443", json!({"[0:0::1]":[pin]}), json!([pin])),
            (
                "[::1]:8443",
                json!({"[0:0:0:0:0:0:0:1]:8443":[pin]}),
                json!([pin]),
            ),
            ("[::1]:8443", json!({"::1":[pin]}), json!([pin])),
            ("[::1]:8443", json!({" 0:0::1 ":[pin]}), json!([pin])),
            (
                "api.github.com",
                json!({"API.GitHub.com.":[pin]}),
                json!([pin]),
            ),
            (
                "api.github.com:443",
                json!({"api.github.com":[pin]}),
                json!([pin]),
            ),
            ("api.github.com", json!({}), Value::Null),
            ("api.github.com", json!({"api.github.com":[]}), Value::Null),
        ] {
            let f = probe_fixture(
                "github",
                json!({"host":host,"scheme":"https"}),
                vec![("token", vec!["header:authorization:Bearer"])],
            )
            .await;
            let f = control_session_restart_after_seed(f, move |dir| {
                ported_common::seed_credential_pins(dir, "probe", &table)
            })
            .await;
            let v = run_public_probe(&f).await.unwrap();
            assert_eq!(v["status"], "ok");
            {
                let hits = f.up.hits.lock().unwrap();
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].pins.as_value(), want, "{host}");
                assert!(hits[0].url.ends_with("/user"));
            }
            credential_finish(&f).await;
        }
    })
    .await
    .unwrap();
}

async fn requested_finish(f: &Fixture) {
    for row in audit_records(f).await {
        for secret in [
            "test-secret-requested-oai-0123456789",
            "test-secret-same-host-second-0123456789",
        ] {
            assert!(!row.to_string().contains(secret));
        }
    }
    credential_finish(f).await;
}
async fn requested_second_credential(f: &Fixture) {
    f.shared
        .run(|c| {
            c.vault
                .add_credential(av_store::vault::NewCredential {
                    slug: "oai".into(),
                    kind: "openai".into(),
                    connector: serde_json::from_value(
                        json!({"host":"api.openai.com","scheme":"https"}),
                    )
                    .unwrap(),
                    fields: Vec::from([(
                        "apikey".into(),
                        "test-secret-requested-oai-0123456789".to_owned().into(),
                    )]),
                    sites: std::collections::BTreeMap::from([(
                        "apikey".into(),
                        vec!["header:authorization:Bearer".into()],
                    )]),
                })
                .unwrap()
        })
        .await
        .unwrap();
}
#[tokio::test]
async fn requested_multicred_response_preserves_grant_order_profiles_mirrors_and_listing() {
    tokio::time::timeout(std::time::Duration::from_secs(20),async{let f=Fixture::new(&["header:x-key"]).await;requested_second_credential(&f).await;
 let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"grants":[{"cred":"demo","methods":["GET"]},{"cred":"oai","methods":["GET","POST"]}]})).await;assert_eq!(s,200,"{v}");assert_eq!(v["grants"].as_array().unwrap().iter().map(|g|g["cred"].as_str().unwrap()).collect::<Vec<_>>(),vec!["demo","oai"]);
 for g in v["grants"].as_array().unwrap(){let p=av_core::placeholder::parse_at(g["placeholder"].as_str().unwrap(),0).unwrap();assert_eq!(p.sid,v["session_id"].as_str().unwrap());assert_eq!(p.slug,g["cred"].as_str().unwrap());}
 assert_eq!(v["grants"][0]["env"],Value::Null);assert_eq!(v["grants"][1]["env"],json!({"base":"OPENAI_BASE_URL","key":"OPENAI_API_KEY"}));for k in ["grant_id","placeholder","usage","base_url","probe_path","lint"]{assert_eq!(v[k],v["grants"][0][k],"{k}");}assert_eq!(v["infinite"],false);
 let(_,listed)=credential_api(&f,"GET","/v1/sessions",json!({})).await;let row=listed.as_array().unwrap().iter().find(|r|r["id"]==v["session_id"]).unwrap();assert_eq!(row["grants"],2);assert_eq!(row["creds"].as_array().unwrap().iter().map(|r|r["slug"].as_str().unwrap()).collect::<Vec<_>>(),vec!["demo","oai"]);assert_eq!(control_session_request(&f,&v,"demo","GET","/ordinary").await.status,200);requested_finish(&f).await;}).await.unwrap();
}
#[tokio::test]
async fn requested_multicred_mixed_duplicate_empty_oversized_and_missing_are_atomic() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let f = Fixture::new(&["header:x-key"]).await;
        requested_second_credential(&f).await;
        let before = store_snapshot(&f).await;
        for body in [
            json!({"grants":[{"cred":"demo"}],"cred":"demo"}),
            json!({"grants":[{"cred":"demo"}],"methods":["GET"]}),
            json!({"grants":[{"cred":"demo"},{"cred":"demo"}]}),
            json!({"grants":[]}),
            json!({"grants":(0..17).map(|i|json!({"cred":format!("c{i}")})).collect::<Vec<_>>()}),
            json!({"grants":"demo"}),
            json!({"grants":[["demo"]]}),
            json!({"template":"x","cred":"demo"}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/sessions", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "session_shape");
            if v["detail"].as_str().unwrap_or("").contains("twice") {
                assert!(v["detail"]
                    .as_str()
                    .unwrap()
                    .contains("credential demo appears twice"));
            }
        }
        for body in [
            json!({"template":"x"}),
            json!({"grants":[{"cred":"demo"},{"cred":"nope"}]}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/sessions", body).await;
            assert_eq!(s, 404, "{v}");
            assert_eq!(v["code"], "AV_NOT_FOUND");
        }
        let (_, duplicate) = credential_api(
            &f,
            "POST",
            "/v1/sessions",
            json!({"grants":[{"cred":"demo"},{"cred":"demo"}]}),
        )
        .await;
        assert!(duplicate["detail"]
            .as_str()
            .unwrap()
            .contains("credential demo appears twice"));
        assert_eq!(store_snapshot(&f).await, before);
        assert_eq!(f.get().await.status, 200);
        requested_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn requested_batch_presence_order_ledger_ceilings_and_audit_are_exact() {
    tokio::time::timeout(std::time::Duration::from_secs(25),async{let f=Fixture::new(&["header:x-key"]).await;requested_second_credential(&f).await;credential_factor(&f).await;credential_gate(&f,true).await;let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"grants":[{"cred":"demo"},{"cred":"oai"}]})).await;assert_eq!(s,200,"{v}");credential_gate(&f,false).await;let before=store_snapshot(&f).await;let records=audit_records(&f).await;
 let body=json!({"sid":v["session_id"],"items":[{"cred":"oai"},{"cred":"demo","field":"token","uses":3}],"purpose":"env"});let(s,no)=credential_api(&f,"POST","/v1/placeholders/batch",body.clone()).await;assert_eq!(s,401,"{no}");assert_eq!(no["code"],"AV_PRESENCE_REQUIRED");assert_eq!(store_snapshot(&f).await,before);assert_eq!(audit_records(&f).await,records);credential_gate(&f,true).await;
 let(s,b)=credential_api(&f,"POST","/v1/placeholders/batch",body).await;assert_eq!(s,200,"{b}");assert_eq!(b["session_id"],v["session_id"]);assert_eq!(b["gateway_url"],format!("http://127.0.0.1:{}",f.daemon.gateway_port().unwrap()));assert_eq!(b["items"][0]["cred"],"oai");assert_eq!(b["items"][0]["field"],"apikey");assert_eq!(b["items"][0]["env"],json!({"base":"OPENAI_BASE_URL","key":"OPENAI_API_KEY"}));assert_eq!(b["items"][1]["cred"],"demo");assert_eq!(b["items"][1]["field"],"token");for item in b["items"].as_array().unwrap(){let text=item["placeholder"].as_str().unwrap();let p=av_core::placeholder::parse_at(text,0).unwrap();assert_eq!(p.text,text);assert_eq!(p.sid,v["session_id"].as_str().unwrap());}
 let gid=v["grants"][0]["grant_id"].as_str().unwrap().to_owned();f.shared.run(move|c|assert!(c.vault.list_placeholders(None).unwrap().iter().any(|r|r.grant_id==gid&&r.max_uses==3))).await.unwrap();let rows=audit_records(&f).await;let batch=rows.iter().filter(|r|r["kind"]=="placeholder.issued_batch").collect::<Vec<_>>();assert_eq!(batch.len(),1);assert_eq!(batch[0]["count"],2);assert_eq!(batch[0]["credential_slugs"],json!(["oai","demo"]));assert_eq!(batch[0]["purpose"],"env");assert!(!batch[0].to_string().contains("av1."));assert_eq!(control_session_request(&f,&v,"demo","GET","/ordinary").await.status,200);requested_finish(&f).await;}).await.unwrap();
}
#[tokio::test]
async fn requested_batch_missing_ungranted_field_session_and_bad_shapes_create_no_rows() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::new(&["header:x-key"]).await;
        requested_second_credential(&f).await;
        let (s, v) = credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
        assert_eq!(s, 200, "{v}");
        let sid = &v["session_id"];
        let before = store_snapshot(&f).await;
        let issued = audit_records(&f)
            .await
            .into_iter()
            .filter(|r| r["kind"] == "placeholder.issued")
            .count();
        for (body, status, code) in [
            (
                json!({"sid":sid,"items":[{"cred":"demo"},{"cred":"nope"}]}),
                404,
                "AV_NOT_FOUND",
            ),
            (
                json!({"sid":sid,"items":[{"cred":"demo"},{"cred":"oai"}]}),
                403,
                "AV_NO_GRANT",
            ),
            (
                json!({"sid":sid,"items":[{"cred":"demo","field":"other"}]}),
                403,
                "AV_NO_GRANT",
            ),
            (
                json!({"sid":"nosuchsession","items":[{"cred":"demo"}]}),
                404,
                "AV_NOT_FOUND",
            ),
        ] {
            let (s, r) = credential_api(&f, "POST", "/v1/placeholders/batch", body).await;
            assert_eq!(s, status, "{r}");
            assert_eq!(r["code"], code);
        }
        for body in [
            json!({"items":[{"cred":"demo"}]}),
            json!({"sid":sid,"items":[]}),
            json!({"sid":sid,"items":vec![json!({"cred":"demo"});33]}),
            json!({"sid":sid,"items":["demo"]}),
            json!({"sid":sid,"items":[{"cred":"demo"},{"cred":"demo"}]}),
            json!({"sid":sid,"items":[{"cred":"demo","uses":0}]}),
            json!({"sid":sid,"items":[{"cred":"demo","uses":1.5}]}),
            json!({"sid":sid,"items":[{"cred":"demo"}],"purpose":"curl"}),
        ] {
            let (s, r) = credential_api(&f, "POST", "/v1/placeholders/batch", body).await;
            assert_eq!(s, 403, "{r}");
            assert_eq!(r["rule"], "batch_shape");
        }
        assert_eq!(store_snapshot(&f).await, before);
        assert_eq!(
            audit_records(&f)
                .await
                .into_iter()
                .filter(|r| r["kind"] == "placeholder.issued")
                .count(),
            issued
        );
        assert_eq!(
            control_session_request(&f, &v, "demo", "GET", "/ordinary")
                .await
                .status,
            200
        );
        assert_eq!(
            credential_api(
                &f,
                "DELETE",
                &format!("/v1/sessions?sid={}", sid.as_str().unwrap()),
                json!({})
            )
            .await
            .0,
            200
        );
        let (_, r) = credential_api(
            &f,
            "POST",
            "/v1/placeholders/batch",
            json!({"sid":sid,"items":[{"cred":"demo"}]}),
        )
        .await;
        assert_eq!(r["code"], "AV_SESSION_REVOKED");
        requested_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn requested_quarantine_precedes_presence_and_single_bulk_decisions_leave_pending() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let mut ids = Vec::new();
        for _ in 0..2 {
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/session-requests",
                json!({"cred":"demo","reason":"job"}),
            )
            .await;
            assert_eq!(s, 200, "{v}");
            ids.push(v["id"].clone());
        }
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/quarantine",
                json!({"slug":"demo"})
            )
            .await
            .0,
            200
        );
        let before = store_snapshot(&f).await;
        let created = audit_records(&f)
            .await
            .into_iter()
            .filter(|r| r["kind"] == "session.created")
            .count();
        for body in [
            json!({"cred":"demo"}),
            json!({"cred":"demo","infinite":true}),
            json!({"grants":[{"cred":"demo","approval":"auto","methods":["POST"]}]}),
            json!({"cred":"demo","infinite":true,"presence":{"passphrase":WIDEN_PASS}}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/sessions", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["code"], "AV_QUARANTINED");
            assert_eq!(v["rule"], "quarantine");
        }
        credential_gate(&f, true).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/session-requests/decide",
            json!({"id":ids[0],"granted":true}),
        )
        .await;
        assert_eq!(s, 403, "{v}");
        assert_eq!(v["code"], "AV_QUARANTINED");
        assert_eq!(v["rule"], "quarantine");
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/pending/decide-many",
            json!({"decisions":[{"id":ids[1],"kind":"session","granted":true}]}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["decided"][0]["outcome"], "skipped");
        assert!(v["decided"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("quarantined"));
        let (_, pending) = credential_api(&f, "GET", "/v1/session-requests", json!({})).await;
        for id in ids {
            assert_eq!(
                pending
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["id"] == id)
                    .unwrap()["state"],
                "pending"
            );
        }
        assert_eq!(store_snapshot(&f).await, before);
        assert_eq!(
            audit_records(&f)
                .await
                .into_iter()
                .filter(|r| r["kind"] == "session.created")
                .count(),
            created
        );
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/release",
                json!({"slug":"demo"})
            )
            .await
            .0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        requested_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn requested_batch_quarantined_later_item_is_atomic_and_grant_ceiling_wins() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::configured(
            &["header:x-key"],
            SECRET,
            None,
            json!({"placeholder_policy":{"max_uses":1}}),
        )
        .await;
        requested_second_credential(&f).await;
        let sid = control_session_sid(&f).await;
        let count_before = f
            .shared
            .run(|c| c.vault.list_placeholders(None).unwrap().len())
            .await
            .unwrap();
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/placeholders/batch",
            json!({"sid":sid,"items":[{"cred":"demo","uses":40}]}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let gid = f.grant_id.clone();
        f.shared
            .run(move |c| {
                let rows = c.vault.list_placeholders(None).unwrap();
                assert_eq!(rows.len(), count_before + 1);
                assert!(rows
                    .iter()
                    .filter(|r| r.grant_id == gid)
                    .all(|r| r.max_uses == 1));
            })
            .await
            .unwrap();
        let (s, multi) = credential_api(
            &f,
            "POST",
            "/v1/sessions",
            json!({"grants":[{"cred":"demo"},{"cred":"oai"}]}),
        )
        .await;
        assert_eq!(s, 200, "{multi}");
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/credentials/quarantine",
                json!({"slug":"oai"})
            )
            .await
            .0,
            200
        );
        let before = store_snapshot(&f).await;
        let issued = audit_records(&f)
            .await
            .into_iter()
            .filter(|r| r["kind"] == "placeholder.issued")
            .count();
        for items in [
            json!([{"cred":"demo"},{"cred":"oai"}]),
            json!([{"cred":"oai"}]),
        ] {
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/placeholders/batch",
                json!({"sid":multi["session_id"],"items":items}),
            )
            .await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["code"], "AV_QUARANTINED");
            assert_eq!(v["rule"], "quarantine");
        }
        assert_eq!(store_snapshot(&f).await, before);
        assert_eq!(
            audit_records(&f)
                .await
                .into_iter()
                .filter(|r| r["kind"] == "placeholder.issued")
                .count(),
            issued
        );
        assert_eq!(f.get().await.status, 200);
        requested_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn requested_expired_grant_batch_issues_nothing_while_other_session_works() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let (s, v) = credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
        assert_eq!(s, 200, "{v}");
        let sid = v["session_id"].as_str().unwrap().to_owned();
        let gid = v["grant_id"].as_str().unwrap().to_owned();
        let seeded_sid = sid.clone();
        let f = control_session_restart_after_seed(f, move |dir| {
            ported_common::seed_gateway_rows(
                dir,
                &seeded_sid,
                &gid,
                &json!({}),
                &json!({"expires_at":"2000-01-01T00:00:00.000Z"}),
            )
        })
        .await;
        let before = store_snapshot(&f).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/placeholders/batch",
            json!({"sid":sid,"items":[{"cred":"demo"}]}),
        )
        .await;
        assert!(s >= 400, "{v}");
        assert!(v["code"].as_str().unwrap().starts_with("AV_GRANT_"));
        let after = store_snapshot(&f).await;
        assert_eq!(
            after["placeholders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].clone())
                .collect::<Vec<_>>(),
            before["placeholders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(f.get().await.status, 200);
        requested_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn requested_same_host_credentials_remain_separate_on_named_and_transparent_routes() {
    tokio::time::timeout(std::time::Duration::from_secs(20),async{let f=Fixture::new(&["header:x-key"]).await;let(s,v)=credential_api(&f,"POST","/v1/credentials",json!({"slug":"second","kind":"http","host":"api.example.test","value":"test-secret-same-host-second-0123456789","sites":["header:x-key"]})).await;assert_eq!(s,200,"{v}");let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"grants":[{"cred":"demo"},{"cred":"second"}]})).await;assert_eq!(s,200,"{v}");let req=|path:&str|GatewayRequest{method:"GET".into(),path:path.into(),headers:vec![("host".into(),"localhost".into()),("av-session".into(),v["token"].as_str().unwrap().into()),("x-key".into(),v["grants"][1]["placeholder"].as_str().unwrap().into())],..Default::default()};
 let r=f.daemon.pipeline().handle(req("/p/second/x")).await;assert_eq!(r.status,200);f.clean(&r).await;assert!(!String::from_utf8_lossy(&r.body).contains("test-secret-same-host-second-0123456789"));assert_eq!(f.up.hits.lock().unwrap().last().unwrap().headers.iter().find(|(n,_)|n.eq_ignore_ascii_case("x-key")).unwrap().1,"test-secret-same-host-second-0123456789");let r=f.daemon.pipeline().handle(req("/t/https/api.example.test/x")).await;assert_eq!(r.status,403);assert_eq!(serde_json::from_slice::<Value>(&r.body).unwrap()["code"],"AV_PH_WRONG_CONNECTOR");assert_eq!(f.up.hits.lock().unwrap().len(),1);requested_finish(&f).await;}).await.unwrap();
}

#[tokio::test]
async fn fix_mcp_stream_drains_to_eof_buffered_answer_stays_exact_and_calls_leave_no_live_capabilities(
) {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::new(&["header:authorization:Bearer"]).await;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = ended.clone();
        let producer = tokio::spawn(async move {
            tx.send(Ok(b"data: {\"n\":1}\n\n".to_vec())).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            tx.send(Ok(b"data: {\"n\":2}\n\n".to_vec())).await.unwrap();
            drop(tx);
            done.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        *f.up.source.lock().unwrap() = Some(Body::Stream(rx));
        *f.up.reply.lock().unwrap() = Some(Reply {
            streaming: true,
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body: vec![],
        });
        let (error, v) = control_mcp_call(
            &f,
            "vault_http",
            json!({"cred":"demo","method":"GET","path":"/stream","reason":"test"}),
            true,
        )
        .await;
        assert!(!error, "{v}");
        assert_eq!(v["status"], 200);
        assert_eq!(v["body"], "data: {\"n\":1}\n\ndata: {\"n\":2}\n\n");
        producer.await.unwrap();
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
        *f.up.reply.lock().unwrap() = Some(Reply {
            streaming: false,
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: b"{\"ok\":true}".to_vec(),
        });
        let (error, v) = control_mcp_call(
            &f,
            "vault_http",
            json!({"cred":"demo","method":"GET","path":"/user","reason":"test"}),
            true,
        )
        .await;
        assert!(!error, "{v}");
        assert_eq!(v["status"], 200);
        assert_eq!(v["body"], "{\"ok\":true}");
        assert_eq!(
            f.up.hits
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                .unwrap()
                .1,
            format!("Bearer {SECRET}")
        );
        let sid = control_session_sid(&f).await;
        let live = || {
            let sid = sid.clone();
            f.shared.run(move |c| {
                c.vault
                    .list_placeholders(Some(&sid))
                    .unwrap()
                    .iter()
                    .filter(|p| p.state == av_store::model::PlaceholderState::Active)
                    .count()
            })
        };
        let before = live().await.unwrap();
        for i in 0..20 {
            let (error, v) = control_mcp_call(
                &f,
                "vault_http",
                json!({"cred":"demo","method":"GET","path":format!("/n/{i}"),"reason":"test"}),
                true,
            )
            .await;
            assert!(!error, "{v}");
            assert_eq!(v["status"], 200);
        }
        assert!(live().await.unwrap() <= before);
        requested_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_mcp_query_credential_authenticates_by_session_and_proposals_preserve_ttl_and_uses() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let f = Fixture::new(&["query:api_key"]).await;
        let (error, v) = control_mcp_call(
            &f,
            "vault_http",
            json!({"cred":"demo","method":"GET","path":"/things","reason":"test"}),
            true,
        )
        .await;
        assert!(!error, "{v}");
        assert_eq!(v["status"], 200);
        assert!(f
            .up
            .hits
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .url
            .contains(&format!("api_key={SECRET}")));
        let (error, v) = control_mcp_call(
            &f,
            "vault_request_session",
            json!({"cred":"demo","reason":"short job","methods":["GET"],"ttl_minutes":15,"uses":3}),
            false,
        )
        .await;
        assert!(!error, "{v}");
        assert_eq!(v["state"], "pending");
        let (_, pending) = credential_api(&f, "GET", "/v1/session-requests", json!({})).await;
        let row = pending
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == v["request_id"])
            .unwrap();
        assert_eq!(row["proposal"]["ttl_minutes"], 15);
        assert_eq!(row["proposal"]["uses"], 3);
        assert_eq!(row["proposal"]["methods"], json!(["GET"]));
        requested_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connector_probe_malformed_persisted_pin_entries_fail_before_reading_locked_secret() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let pin = format!("sha256/{}=", "C".repeat(43));
        for list in [
            json!(["garbage"]),
            json!(["42"]),
            json!([format!(" {pin}")]),
            json!([pin, "garbage"]),
            json!((0..5)
                .map(|n| format!("sha256/{}=", char::from(b'A' + n).to_string().repeat(43)))
                .collect::<Vec<_>>()),
        ] {
            let f = probe_fixture(
                "github",
                json!({"host":"api.github.com","scheme":"https"}),
                vec![("token", vec!["header:authorization:Bearer"])],
            )
            .await;
            let table = json!({"api.github.com":list});
            let f = control_session_restart_after_seed(f, move |dir| {
                ported_common::seed_credential_pins(dir, "probe", &table)
            })
            .await;
            f.shared.run(|c| c.vault.lock().unwrap()).await.unwrap();
            let e = run_public_probe(&f).await.unwrap_err();
            assert_eq!(e.code.as_str(), "AV_PIN_MISMATCH");
            assert_eq!(e.extra.rule.as_deref(), Some("pin_format"));
            assert!(f.up.hits.lock().unwrap().is_empty());
            f.shared
                .run(|c| c.vault.unlock(None).unwrap())
                .await
                .unwrap();
            assert!(probe_health(&f).await.is_null());
            assert_eq!(f.get().await.status, 200);
            credential_finish(&f).await;
        }
        let f = probe_fixture(
            "github",
            json!({"host":"api.github.com","scheme":"https"}),
            vec![("token", vec!["header:authorization:Bearer"])],
        )
        .await;
        assert_eq!(run_public_probe(&f).await.unwrap()["status"], "ok");
        assert_eq!(probe_health(&f).await["status"], "ok");
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn r1_direct_auto_writes_require_fresh_proof_but_ordinary_creates_only_need_window() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async{
 let f=Fixture::new(&["header:x-key"]).await;let wide=json!({"cred":"demo","methods":["GET","POST"],"approval":"auto"});let before=store_snapshot(&f).await;let(s,no)=credential_api(&f,"POST","/v1/sessions",wide.clone()).await;assert_eq!(s,401,"{no}");assert_eq!(no["code"],"AV_PRESENCE_REQUIRED");assert_eq!(no["rule"],"factor_required");assert_eq!(no["factors"],json!([]));assert!(no["hint"].as_str().unwrap().contains("agent-vault passphrase set"));assert_eq!(store_snapshot(&f).await,before);
 for b in [json!({"cred":"demo","approval":"auto"}),json!({"cred":"demo","methods":["GET","POST"]})]{assert_eq!(credential_api(&f,"POST","/v1/sessions",b).await.0,200);}
 credential_factor(&f).await;credential_gate(&f,true).await;let before=store_snapshot(&f).await;let(s,no)=credential_api(&f,"POST","/v1/sessions",wide.clone()).await;assert_eq!(s,401,"{no}");assert_eq!(no["rule"],"fresh_presence");assert_eq!(no["factors"],json!(["passphrase"]));assert_eq!(store_snapshot(&f).await,before);
 let(s,ro)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","approval":"auto","methods":["GET","HEAD"]})).await;assert_eq!(s,200,"{ro}");assert!(audit_records(&f).await.iter().any(|r|r["kind"]=="presence.window_used"));let(_,listed)=credential_api(&f,"GET","/v1/sessions",json!({})).await;assert_eq!(listed.as_array().unwrap().iter().find(|r|r["id"]==ro["session_id"]).unwrap()["elevated"],json!([]));credential_gate(&f,false).await;let(s,no)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","approval":"auto"})).await;assert_eq!(s,401,"{no}");assert_eq!(no["rule"],"human_presence");
 let mut with_proof=wide;with_proof["presence"]=json!({"passphrase":WIDEN_PASS});let(s,made)=credential_api(&f,"POST","/v1/sessions",with_proof).await;assert_eq!(s,200,"{made}");let policy=control_session_policy(&f,made["grant_id"].as_str().unwrap()).await;assert_eq!(policy["approval"],"auto");assert_eq!(policy["methods"],json!(["GET","POST"]));let records=audit_records(&f).await;let proof=records.iter().rev().find(|r|r["kind"]=="presence.verified"&&r["fresh"]==true).unwrap();assert_eq!(proof["op"],"session create");assert_eq!(proof["factor"],"passphrase");let(_,listed)=credential_api(&f,"GET","/v1/sessions",json!({})).await;let row=listed.as_array().unwrap().iter().find(|r|r["id"]==made["session_id"]).unwrap();assert_eq!(row["elevated"],json!(["approval_auto_writes"]));assert_eq!(row["infinite"],false);assert_eq!(row["creds"],json!([{"slug":"demo","grant_id":made["grant_id"],"approval":"auto","methods":["GET","POST"]}]));assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await.0,401,"fresh proof must not open a window");assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn r1_failed_elevated_passphrase_is_denied_and_counted_in_real_attempt_throttle() {
    tokio::time::timeout(std::time::Duration::from_secs(20),async{let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let before=store_snapshot(&f).await;
 for n in 1..=5{let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","methods":["GET","POST"],"approval":"auto","presence":{"passphrase":"not it at all"}})).await;assert_eq!(s,403,"attempt {n}: {v}");assert_eq!(v["code"],"AV_PRESENCE_DENIED");assert_eq!(v["rule"],"fresh_presence");}
 assert_eq!(store_snapshot(&f).await,before);let rows=audit_records(&f).await;let record=rows.iter().find(|r|r["kind"]=="presence.throttled").unwrap();assert_eq!(record["consecutive_failures"],5);assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","methods":["POST"],"approval":"auto","presence":{"passphrase":"not it at all"}})).await.0,429);assert_eq!(f.get().await.status,200);credential_finish(&f).await;}).await.unwrap();
}
#[tokio::test]
async fn r1_modes_and_malformed_limits_are_refused_before_creating_any_live_session() {
    tokio::time::timeout(std::time::Duration::from_secs(25),async{let f=Fixture::new(&["header:x-key"]).await;let before=store_snapshot(&f).await;
 for approval in [json!("each-time"),json!("AUTO"),json!(""),json!(0)]{let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","approval":approval})).await;assert_eq!(s,403,"{v}");assert_eq!(v["code"],"AV_POLICY_DENIED");assert_eq!(v["rule"],"approval");assert_eq!(v["hint"],"approval is one of: each, on-write, first-use, auto");}
 for body in [json!({"cred":"demo","methods":"POST"}),json!({"cred":"demo","methods":[1]}),json!({"cred":"demo","paths":"/x"}),json!({"cred":"demo","budget":"lots"}),json!({"cred":"demo","budget":-1}),json!({"cred":"demo","uses":0}),json!({"cred":"demo","label":"x".repeat(81)})]{let(s,v)=credential_api(&f,"POST","/v1/sessions",body).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"policy_invalid");}assert_eq!(store_snapshot(&f).await,before);
 for approval in ["each","on-write","first-use","auto"]{assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","approval":approval})).await.0,200);}
 let(s,ok)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","methods":["GET"],"paths":["/a/**"],"budget":1,"uses":2,"label":"fine"})).await;assert_eq!(s,200,"{ok}");let before=store_snapshot(&f).await;let(s,v)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","budget":0})).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"budget");assert_eq!(store_snapshot(&f).await,before);assert_eq!(f.get().await.status,200);credential_finish(&f).await;}).await.unwrap();
}
#[tokio::test]
async fn r1_signed_elevated_body_works_and_read_only_signature_cannot_authorize_writes() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let w = WidenFixture::new().await;
        let wide = json!({"cred":"demo","methods":["GET","POST"],"approval":"auto"});
        let proof = w.proof("session.create", &wide).await;
        let mut made = wide.clone();
        made["presence"] = proof;
        let (s, v) = w.ctl("POST", "/v1/sessions", made).await;
        assert_eq!(s, 200, "{v}");
        assert!(audit_records(&w.f)
            .await
            .iter()
            .any(|r| r["kind"] == "presence.verified"
                && r["fresh"] == true
                && r["factor"] == "webauthn-platform"));
        let proof = w
            .proof(
                "session.create",
                &json!({"cred":"demo","methods":["GET"],"approval":"auto"}),
            )
            .await;
        let before = store_snapshot(&w.f).await;
        let mut swapped = wide;
        swapped["presence"] = proof;
        let (s, v) = w.ctl("POST", "/v1/sessions", swapped).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["rule"], "fresh_presence");
        assert_eq!(store_snapshot(&w.f).await, before);
        assert_eq!(
            w.f.send(
                "GET",
                "/ordinary",
                vec![("authorization".into(), format!("Bearer {}", w.f.ph))],
                None
            )
            .await
            .status,
            200
        );
        w.stop().await;
    })
    .await
    .unwrap();
}

async fn r1_ask(f: &Fixture, methods: Value) -> Value {
    let (s, v) = credential_api(
        f,
        "POST",
        "/v1/session-requests",
        json!({"cred":"demo","methods":methods,"reason":"job"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    v["id"].clone()
}
#[tokio::test]
async fn r1_agent_owner_fields_are_rejected_on_control_and_mcp_without_opening_or_auditing() {
    tokio::time::timeout(std::time::Duration::from_secs(25),async{let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;
 for extra in [json!({"approval":"auto"}),json!({"infinite":true}),json!({"approval":null}),json!({"infinite":false})]{let mut b=json!({"cred":"demo","methods":["POST"],"reason":"x"});for(k,v)in extra.as_object().unwrap(){b[k]=v.clone();}let(s,v)=credential_api(&f,"POST","/v1/session-requests",b).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"owner_only_field");assert!(v["hint"].as_str().unwrap().contains("Only the owner can choose"));}
 let(error,v)=control_mcp_call(&f,"vault_request_session",json!({"cred":"demo","methods":["POST"],"reason":"x","approval":"auto","infinite":true}),false).await;assert!(error,"{v}");assert_eq!(v["code"],"AV_POLICY_DENIED");assert_eq!(v["rule"],"owner_only_field");assert!(v.get("request_id").is_none());assert!(credential_api(&f,"GET","/v1/session-requests",json!({})).await.1.as_array().unwrap().is_empty());assert!(!audit_records(&f).await.iter().any(|r|r["kind"]=="session_request.opened"));
 let(s,ordinary)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","methods":["POST"],"reason":"x"})).await;assert_eq!(s,200,"{ordinary}");assert!(ordinary["proposal"].get("approval").is_none());
 let(error,ok)=control_mcp_call(&f,"vault_request_session",json!({"cred":"demo","methods":["POST"],"reason":"different ordinary job"}),false).await;assert!(!error,"{ok}");let(_,rows)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;let record=rows.as_array().unwrap().iter().find(|r|r["id"]==ok["request_id"]).unwrap();for field in ["approval","infinite"]{assert!(record["proposal"].get(field).is_none());}credential_gate(&f,true).await;let(s,approved)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":ok["request_id"],"granted":true})).await;assert_eq!(s,200,"{approved}");assert_eq!(control_session_policy(&f,approved["session"]["grant_id"].as_str().unwrap()).await["approval"],"on-write");assert_eq!(approved["session"]["infinite"],false);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn r1_gateway_mutation_paths_never_create_sessions_even_with_passphrase_in_body() {
    tokio::time::timeout(std::time::Duration::from_secs(20),async{let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let before=store_snapshot(&f).await;for path in ["/v1/sessions","/v1/session-requests/decide","/v1/pending/decide-many","/v1/placeholders/batch"]{let(s,_,body)=loopback_http(f.daemon.gateway_port().unwrap(),"POST",path,vec![("content-type".into(),"application/json".into())],json!({"cred":"demo","methods":["GET","POST"],"approval":"auto","infinite":true,"presence":{"passphrase":WIDEN_PASS}}).to_string().into_bytes()).await;assert!([401,404].contains(&s),"{path}: {s} {}",String::from_utf8_lossy(&body));}assert_eq!(store_snapshot(&f).await,before);assert_eq!(f.get().await.status,200);credential_finish(&f).await;}).await.unwrap();
}
#[tokio::test]
async fn r1_single_decisions_bind_owner_changes_and_reject_nonboolean_verdicts_before_presence() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async{let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let id=r1_ask(&f,json!(["GET","POST"])).await;credential_gate(&f,true).await;let overrides=json!({"approval":"auto","methods":["POST"]});let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":overrides})).await;assert_eq!(s,401,"{v}");assert_eq!(v["rule"],"fresh_presence");let(_,pending)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;assert_eq!(pending[0]["state"],"pending");let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":overrides,"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");assert!(v["session"]["token"].as_str().unwrap().starts_with("avs1."));assert_eq!(control_session_policy(&f,v["session"]["grant_id"].as_str().unwrap()).await["approval"],"auto");let rows=audit_records(&f).await;let row=rows.iter().find(|r|r["kind"]=="session_request.approved"&&r["request_id"]==id).unwrap();for field in ["granted","narrowed"]{assert!(row[field].as_array().unwrap().contains(&json!("approval")));}
 let id=r1_ask(&f,json!(["GET"])).await;credential_gate(&f,false).await;let before=store_snapshot(&f).await;for window in [false,true]{if window{credential_gate(&f,true).await;}for verdict in [Some(json!("false")),Some(json!(0)),Some(json!(1)),Some(Value::Null),Some(json!("true")),None]{let mut b=json!({"id":id});if let Some(v)=verdict{b["granted"]=v;}let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",b).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"bulk_decision");}}assert_eq!(store_snapshot(&f).await,before);
 let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":{"approval":"yolo"}})).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"approval");assert_eq!(credential_api(&f,"GET","/v1/session-requests",json!({})).await.1.as_array().unwrap().iter().find(|r|r["id"]==id).unwrap()["state"],"pending");
 let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":{"approval":"each"}})).await;assert_eq!(s,200,"{v}");assert_eq!(control_session_policy(&f,v["session"]["grant_id"].as_str().unwrap()).await["approval"],"each");let id=r1_ask(&f,json!(["GET"])).await;let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":false,"overrides":{"approval":"auto"}})).await;assert_eq!(s,200,"{v}");assert_eq!(f.shared.run(move|c|c.sr_get(id.as_str().unwrap()).unwrap().state).await.unwrap(),"denied");assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn r1_bulk_one_elevated_item_requires_fresh_proof_for_all_and_ordinary_batch_uses_window() {
    tokio::time::timeout(std::time::Duration::from_secs(25),async{let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let plain=r1_ask(&f,json!(["GET"])).await;let wide=r1_ask(&f,json!(["GET","POST"])).await;let decisions=json!([{"id":plain,"kind":"session","granted":true},{"id":wide,"kind":"session","granted":true,"overrides":{"approval":"auto"}}]);credential_gate(&f,true).await;let before=store_snapshot(&f).await;let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":decisions})).await;assert_eq!(s,401,"{v}");assert_eq!(v["rule"],"fresh_presence");assert_eq!(store_snapshot(&f).await,before);let(_,pending)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;for id in [&plain,&wide]{assert_eq!(pending.as_array().unwrap().iter().find(|r|r["id"]==*id).unwrap()["state"],"pending");}
 let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":decisions,"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");assert_eq!(v["decided"].as_array().unwrap().iter().map(|r|r["outcome"].as_str().unwrap()).collect::<Vec<_>>(),vec!["decided","decided"]);let a=r1_ask(&f,json!(["GET"])).await;let b=r1_ask(&f,json!(["GET"])).await;credential_gate(&f,true).await;let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":a,"kind":"session","granted":true},{"id":b,"kind":"session","granted":false,"overrides":{"approval":"auto"}}]})).await;assert_eq!(s,200,"{v}");assert_eq!(f.get().await.status,200);credential_finish(&f).await;}).await.unwrap();
}

#[tokio::test]
async fn r3_infinite_creation_validation_agent_view_implicit_selection_and_revocation() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let inf = json!({"cred":"demo","infinite":true});
        let before = store_snapshot(&f).await;
        let (s, v) = credential_api(&f, "POST", "/v1/sessions", inf.clone()).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["rule"], "factor_required");
        assert_eq!(store_snapshot(&f).await, before);
        assert_eq!(f.get().await.status, 200);
        credential_factor(&f).await;
        credential_gate(&f, true).await;
        let (s, v) = credential_api(&f, "POST", "/v1/sessions", inf.clone()).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["rule"], "fresh_presence");
        let before = store_snapshot(&f).await;
        for presence in [Value::Null, json!({"passphrase":WIDEN_PASS})] {
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/sessions",
                json!({"cred":"demo","infinite":true,"remote":true,"presence":presence}),
            )
            .await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["code"], "AV_REMOTE_FORBIDDEN");
            assert_eq!(v["rule"], "infinite_remote");
        }
        for body in [
            json!({"cred":"demo","ttl_hours":"abc"}),
            json!({"cred":"demo","ttl_hours":0}),
            json!({"cred":"demo","ttl_hours":-1}),
            json!({"cred":"demo","ttl_hours":"8"}),
            json!({"cred":"demo","infinite":true,"ttl_hours":1}),
            json!({"cred":"demo","infinite":"yes"}),
            json!({"cred":"demo","infinite":1}),
        ] {
            let (s, v) = credential_api(&f, "POST", "/v1/sessions", body).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["rule"], "ttl");
        }
        assert_eq!(store_snapshot(&f).await, before);
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/sessions",
            json!({"cred":"demo","infinite":true,"presence":{"passphrase":WIDEN_PASS}}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["infinite"], true);
        assert!(v["expires_at"].is_null());
        let (_, listed) = credential_api(&f, "GET", "/v1/sessions", json!({})).await;
        let row = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == v["session_id"])
            .unwrap();
        assert_eq!(row["elevated"], json!(["infinite"]));
        assert_eq!(row["infinite"], true);
        assert!(row["expires_at"].is_null());
        let (s, _, body) = loopback_http(
            f.daemon.gateway_port().unwrap(),
            "GET",
            "/v1/session",
            vec![(
                "authorization".into(),
                format!("Bearer {}", v["token"].as_str().unwrap()),
            )],
            vec![],
        )
        .await;
        assert_eq!(s, 200);
        let own: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(own["infinite"], true);
        assert!(own["expires_at"].is_null());
        assert!(!String::from_utf8_lossy(&body).contains(SECRET));
        let original = control_session_sid(&f).await;
        assert_eq!(
            credential_api(
                &f,
                "DELETE",
                &format!("/v1/sessions?sid={original}"),
                json!({})
            )
            .await
            .0,
            200
        );
        credential_gate(&f, true).await;
        let (s, issued) =
            credential_api(&f, "POST", "/v1/placeholders", json!({"cred":"demo"})).await;
        assert_eq!(s, 200, "{issued}");
        let parsed =
            av_core::placeholder::parse_at(issued["placeholder"].as_str().unwrap(), 0).unwrap();
        assert_eq!(parsed.sid, v["session_id"].as_str().unwrap());
        let sid = v["session_id"].as_str().unwrap().to_owned();
        assert_eq!(
            credential_api(&f, "DELETE", &format!("/v1/sessions?sid={sid}"), json!({}))
                .await
                .0,
            200
        );
        f.shared
            .run({
                let sid = sid.clone();
                move |c| {
                    let rows = c.vault.list_placeholders(Some(&sid)).unwrap();
                    assert!(!rows.is_empty());
                    for p in rows {
                        assert_eq!(p.state, av_store::model::PlaceholderState::Dead);
                        assert_eq!(p.dead_reason.as_deref(), Some("session_ended"));
                    }
                }
            })
            .await
            .unwrap();
        let (_, listed) = credential_api(&f, "GET", "/v1/sessions", json!({})).await;
        assert_eq!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == sid)
                .unwrap()["state"],
            "revoked"
        );
        let (s, control) = credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
        assert_eq!(s, 200, "{control}");
        assert_eq!(
            control_session_request(&f, &control, "demo", "GET", "/ordinary")
                .await
                .status,
            200
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn r3_explicit_finite_lifetimes_keep_their_ceiling_while_default_idle_lifetime_extends() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/sessions",
            json!({"cred":"demo","ttl_hours":1}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["infinite"], false);
        let sid = v["session_id"].as_str().unwrap().to_owned();
        f.shared
            .run(move |c| {
                let s = c.vault.session(&sid).unwrap().unwrap();
                let expires =
                    av_daemon::util::parse_iso_ms(s.expires_at.as_ref().unwrap()).unwrap();
                let left = expires - av_daemon::util::now_ms();
                assert!(left > 59 * 60000 && left <= 3600000);
                assert_eq!(s.max_expires_at, s.expires_at);
                c.vault.touch_session(&sid).unwrap();
                let after = c.vault.session(&sid).unwrap().unwrap();
                assert!(
                    av_daemon::util::parse_iso_ms(after.expires_at.as_ref().unwrap()).unwrap()
                        <= expires
                );
            })
            .await
            .unwrap();
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/sessions",
                json!({"cred":"demo","ttl_hours":0.5})
            )
            .await
            .0,
            200
        );
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/sessions",
            json!({"cred":"demo","ttl_hours":null}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let sid = v["session_id"].as_str().unwrap().to_owned();
        let seed_sid = sid.clone();
        let soon = av_daemon::util::iso_of_ms(av_daemon::util::now_ms() + 60000);
        let f = control_session_restart_after_seed(f, move |dir| {
            ported_common::seed_session_expiry(dir, &seed_sid, &soon)
        })
        .await;
        f.shared
            .run(move |c| {
                c.vault.touch_session(&sid).unwrap();
                let s = c.vault.session(&sid).unwrap().unwrap();
                let end = av_daemon::util::parse_iso_ms(s.expires_at.as_ref().unwrap()).unwrap();
                assert!(end > av_daemon::util::now_ms() + 60000);
                assert!(
                    end <= av_daemon::util::parse_iso_ms(s.max_expires_at.as_ref().unwrap())
                        .unwrap()
                );
            })
            .await
            .unwrap();
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn r3_owner_can_approve_infinite_only_with_fresh_proof_and_without_a_proposed_lifetime() {
    tokio::time::timeout(std::time::Duration::from_secs(25),async{let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let(s,timed)=credential_api(&f,"POST","/v1/session-requests",json!({"cred":"demo","ttl_minutes":30,"reason":"long job"})).await;assert_eq!(s,200,"{timed}");let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":timed["id"],"granted":true,"overrides":{"infinite":true},"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,403,"{v}");assert_eq!(v["rule"],"ttl");let id=r1_ask(&f,json!(["GET"])).await;credential_gate(&f,true).await;let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":{"infinite":true}})).await;assert_eq!(s,401,"{v}");assert_eq!(v["rule"],"fresh_presence");credential_gate(&f,false).await;let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":{"infinite":true},"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");assert_eq!(v["session"]["infinite"],true);assert!(v["session"]["expires_at"].is_null());assert_eq!(f.get().await.status,200);credential_finish(&f).await;}).await.unwrap();
}
#[tokio::test]
async fn r3_null_or_unparseable_stored_expiry_is_never_live() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        for expiry in [Value::Null, json!("garbage")] {
            let f = Fixture::new(&["header:x-key"]).await;
            let (s, made) =
                credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
            assert_eq!(s, 200, "{made}");
            let sid = made["session_id"].as_str().unwrap().to_owned();
            let gid = made["grant_id"].as_str().unwrap().to_owned();
            let seed_sid = sid.clone();
            let f = control_session_restart_after_seed(f, move |dir| {
                ported_common::seed_gateway_rows(
                    dir,
                    &seed_sid,
                    &gid,
                    &json!({"expires_at":expiry}),
                    &json!({}),
                )
            })
            .await;
            f.shared
                .run(move |c| {
                    let s = c.vault.session(&sid).unwrap().unwrap();
                    let e = c.vault.assert_session_live(Some(&s)).unwrap_err();
                    let av_store::error::Error::Vault(e) = e else {
                        panic!("vault refusal")
                    };
                    assert_eq!(e.code.as_str(), "AV_SESSION_EXPIRED");
                })
                .await
                .unwrap();
            assert_eq!(f.get().await.status, 200);
            credential_finish(&f).await;
        }
    })
    .await
    .unwrap();
}

async fn c3_created_record(f: &Fixture, sid: &Value) -> Value {
    let rows = audit_records(f)
        .await
        .into_iter()
        .filter(|r| r["kind"] == "session.created" && r["session_id"] == *sid)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "one created record per session");
    rows[0].clone()
}
#[tokio::test]
async fn c3_owner_created_sessions_record_their_own_elevation_and_expiry() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        for (mut body, want, infinite) in [
            (json!({"cred":"demo","methods":["GET"]}), json!([]), false),
            (
                json!({"cred":"demo","methods":["GET","POST"],"approval":"auto"}),
                json!(["approval_auto_writes"]),
                false,
            ),
            (
                json!({"cred":"demo","methods":["GET"],"infinite":true}),
                json!(["infinite"]),
                true,
            ),
            (
                json!({"cred":"demo","methods":["POST"],"approval":"auto","infinite":true}),
                json!(["infinite", "approval_auto_writes"]),
                true,
            ),
        ] {
            credential_gate(&f, true).await;
            body["presence"] = json!({"passphrase":WIDEN_PASS});
            let (s, v) = credential_api(&f, "POST", "/v1/sessions", body).await;
            assert_eq!(s, 200, "{v}");
            let row = c3_created_record(&f, &v["session_id"]).await;
            assert_eq!(row["elevated"], want);
            assert_eq!(row["infinite"], infinite);
            if infinite {
                assert!(row["expires_at"].is_null());
            } else {
                assert!(
                    av_daemon::util::parse_iso_ms(row["expires_at"].as_str().unwrap()).unwrap()
                        > av_daemon::util::now_ms()
                );
            }
        }
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn c3_single_and_bulk_approved_sessions_record_each_final_proposal_elevation() {
    tokio::time::timeout(std::time::Duration::from_secs(30),async{let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;
 for (methods,overrides,want) in [(json!(["GET"]),Value::Null,json!([])),(json!(["GET","POST"]),json!({"approval":"auto"}),json!(["approval_auto_writes"])),(json!(["GET"]),json!({"infinite":true}),json!(["infinite"]))]{let id=r1_ask(&f,methods).await;credential_gate(&f,true).await;let mut body=json!({"id":id,"granted":true,"presence":{"passphrase":WIDEN_PASS}});if !overrides.is_null(){body["overrides"]=overrides;}let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",body).await;assert_eq!(s,200,"{v}");assert_eq!(c3_created_record(&f,&v["session"]["session_id"]).await["elevated"],want);}
 let plain=r1_ask(&f,json!(["GET"])).await;let wide=r1_ask(&f,json!(["GET","POST"])).await;let forever=r1_ask(&f,json!(["GET"])).await;let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":plain,"kind":"session","granted":true},{"id":wide,"kind":"session","granted":true,"overrides":{"approval":"auto"}},{"id":forever,"kind":"session","granted":true,"overrides":{"infinite":true}}],"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");assert_eq!(v["decided"].as_array().unwrap().iter().map(|r|r["outcome"].as_str().unwrap()).collect::<Vec<_>>(),vec!["decided","decided","decided"]);let rows=audit_records(&f).await;for(id,want)in [(plain,json!([])),(wide,json!(["approval_auto_writes"])),(forever,json!(["infinite"]))]{let session=&rows.iter().find(|r|r["kind"]=="session_request.approved"&&r["request_id"]==id).unwrap()["session_id"];assert_eq!(c3_created_record(&f,session).await["elevated"],want);}
 assert_eq!(f.get().await.status,200);credential_finish(&f).await;}).await.unwrap();
}

#[tokio::test]
async fn c3_unknown_elevation_real_store_refusal_writes_nothing_and_valid_control_creation_works() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let before = store_snapshot(&f).await;
        let audit = audit_records(&f).await;
        for elevated in [
            vec!["root".to_owned()],
            vec!["approval_auto_writes".to_owned(), "root".to_owned()],
        ] {
            f.shared
                .run(move |c| {
                    let e = c
                        .vault
                        .create_session(av_store::vault::CreateSessionOptions {
                            elevated,
                            ..Default::default()
                        })
                        .unwrap_err();
                    let av_store::error::Error::Vault(e) = e else {
                        panic!("vault refusal")
                    };
                    assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
                    assert_eq!(e.extra.rule.as_deref(), Some("elevation_invalid"));
                })
                .await
                .unwrap();
            assert_eq!(store_snapshot(&f).await, before);
            assert_eq!(audit_records(&f).await, audit);
        }
        credential_gate(&f, true).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/sessions",
            json!({"cred":"demo","methods":["GET"]}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            control_session_request(&f, &v, "demo", "GET", "/ordinary")
                .await
                .status,
            200
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn control_notify_two_real_pending_records_queued_under_state_lock_reserve_only_one_post() {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        let p = NotifyFixture::new(false).await;
        p.configure(av_store::model::NotifyDetail::Minimal).await;
        p.f.shared
            .run(|c| {
                for reason in ["ordinary job one", "ordinary job two"] {
                    c.sr_propose(
                        json!({"cred":"demo","methods":["GET"]}),
                        Some(reason.into()),
                        false,
                    )
                    .unwrap();
                }
            })
            .await
            .unwrap();
        p.wait_calls(1).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let calls = p.calls.lock().unwrap().clone();
        assert_eq!(
            calls.len(),
            1,
            "both real pending events must share one interval reservation"
        );
        assert_eq!(calls[0].1["waiting"], 1);
        assert_eq!(calls[0].1["kinds"]["session"], 1);
        assert_eq!(p.f.shared.run(|c| c.sr_pending().len()).await.unwrap(), 2);
        assert!(!calls[0].1.to_string().contains("ordinary job"));
        assert!(!calls[0].1.to_string().contains(SECRET));
        let waiting_since = std::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_millis(av_daemon::notify::WEBHOOK_INTERVAL_MS + 5000),
            async {
                while p.calls.lock().unwrap().len() < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            },
        )
        .await
        .expect("the second event must schedule a future POST without another event");
        assert!(
            waiting_since.elapsed()
                >= std::time::Duration::from_millis(av_daemon::notify::WEBHOOK_INTERVAL_MS - 200)
        );
        let second = p.calls.lock().unwrap().clone();
        assert_eq!(second.len(), 2);
        assert_eq!(second[1].1["waiting"], 2);
        assert_eq!(second[1].1["kinds"]["session"], 2);
        assert_eq!(p.f.get().await.status, 200);
        p.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn integrate2_real_upstream_combines_repeated_list_headers_as_one_upstream_value() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let got = seen.clone();
        let peer = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let (head, body) = read_wire_request(&mut tcp).await;
                assert!(body.is_empty());
                got.lock().unwrap().push(head);
                tcp.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
            }
        });
        let f = mcp_real_http_fixture(port).await;
        for values in [vec!["a", "b"], vec!["ordinary"]] {
            let mut headers = vec![("authorization".into(), format!("Bearer {}", f.ph))];
            headers.extend(values.into_iter().map(|v| ("x-list".into(), v.into())));
            let r = f.send("GET", "/safe/list", headers, None).await;
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            f.clean(&r).await;
        }
        peer.await.unwrap();
        let heads = seen.lock().unwrap().clone();
        assert_eq!(heads.len(), 2);
        for (head, want) in heads.iter().zip(["a, b", "ordinary"]) {
            let lines = head
                .lines()
                .filter_map(|s| s.split_once(':'))
                .filter(|(n, _)| n.eq_ignore_ascii_case("x-list"))
                .collect::<Vec<_>>();
            assert_eq!(
                lines
                    .iter()
                    .map(|(_, v)| v.trim())
                    .collect::<Vec<_>>()
                    .join(", "),
                want
            );
            assert!(head.contains(&format!("Bearer {SECRET}")));
            assert!(!head.contains(&f.ph));
        }
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[derive(Clone)]
struct C12Door {
    id: String,
    port: u16,
    tls: bool,
    remote: bool,
    v6: bool,
}
struct C12World {
    f: Fixture,
    token: String,
    ph: String,
    sid: String,
    doors: Vec<C12Door>,
    seen: Arc<Mutex<Vec<String>>>,
    peer: tokio::task::JoinHandle<()>,
}
impl C12World {
    async fn new() -> Self {
        use tokio::io::AsyncWriteExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let captured = seen.clone();
        let peer = tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (head, _) = read_wire_request(&mut s).await;
                captured.lock().unwrap().push(head);
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 19\r\nconnection: close\r\n\r\nC12_UPSTREAM_MARKER").await.unwrap();
            }
        });
        let f = mcp_real_http_fixture(port).await;
        let gid = f.grant_id.clone();
        let (token, ph, sid) = f
            .shared
            .run(move |c| {
                use av_core::secret::ExposeSecret;
                let parent = c.vault.grant(&gid).unwrap().unwrap();
                let s = c
                    .vault
                    .create_session(av_store::vault::CreateSessionOptions {
                        infinite: true,
                        ..Default::default()
                    })
                    .unwrap();
                let g = c
                    .vault
                    .create_grant(av_store::vault::CreateGrantOptions {
                        session_id: s.session.id.clone(),
                        credential_id: parent.credential_id,
                        fields: Some(parent.fields),
                        policy: parent.policy,
                        ..Default::default()
                    })
                    .unwrap();
                let p = c
                    .vault
                    .issue_placeholder(av_store::vault::IssueOptions {
                        grant_id: g.id,
                        ..Default::default()
                    })
                    .unwrap();
                (
                    s.token.expose_secret().to_string(),
                    p.placeholder,
                    s.session.id,
                )
            })
            .await
            .unwrap();
        let mut doors = vec![C12Door {
            id: "builtin".into(),
            port: f.daemon.gateway_port().unwrap(),
            tls: false,
            remote: false,
            v6: false,
        }];
        for (id, address, tls, remote, v6) in [
            ("wild-v4", "0.0.0.0:0", true, true, false),
            ("wild-v6", "[::]:0", true, true, true),
            ("loop-tls", "127.0.0.1:0", true, false, false),
            ("loop-tcp", "127.0.0.1:0", false, false, false),
        ] {
            let mut spec = json!({"id":id,"address":address,"surfaces":["gateway","mcp"]});
            if tls {
                spec["tls"] = json!({"managed":true});
            }
            let (s, v) = credential_api(&f, "POST", "/v1/listeners", spec).await;
            assert_eq!(s, 200, "{v}");
            let entry = serde_json::from_value::<av_store::model::ListenerRecord>(v).unwrap();
            let port = f.daemon.bind_listener(&entry).await.unwrap().1;
            doors.push(C12Door {
                id: id.into(),
                port,
                tls,
                remote,
                v6,
            });
        }
        Self {
            f,
            token,
            ph,
            sid,
            doors,
            seen,
            peer,
        }
    }
    async fn wire(
        &self,
        d: &C12Door,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let tcp = tokio::net::TcpStream::connect((if d.v6 { "::1" } else { "127.0.0.1" }, d.port))
            .await
            .unwrap();
        let out = if d.tls {
            let material = av_daemon::tls::load_material(
                &av_daemon::tls::tls_paths(self.f._dir.path()).cert,
                &av_daemon::tls::tls_paths(self.f._dir.path()).key,
            )
            .unwrap();
            let der = av_daemon::connectors::pinning::pem_certs(
                &String::from_utf8(material.cert).unwrap(),
            )
            .remove(0);
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ExactManagedCertificate(der)))
            .with_no_client_auth();
            let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    tcp,
                )
                .await
                .unwrap();
            c12_exchange(tls, method, path, headers, body).await
        } else {
            c12_exchange(tcp, method, path, headers, body).await
        };
        assert!(
            !String::from_utf8_lossy(&out.2).contains(SECRET),
            "{} agent saw stored secret",
            d.id
        );
        out
    }
    async fn cost(&self) -> (usize, usize, usize) {
        let hits = self.seen.lock().unwrap().len();
        let rows = self
            .f
            .shared
            .run(|c| c.vault.list_placeholders(None).unwrap().len())
            .await
            .unwrap();
        let denials = audit_records(&self.f)
            .await
            .iter()
            .filter(|r| r["rule"] == "infinite_remote")
            .count();
        (hits, rows, denials)
    }
    async fn finish(self) {
        credential_finish(&self.f).await;
        self.peer.abort();
        let _ = self.peer.await;
    }
}
async fn c12_exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let (mut client, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    for (n, v) in headers {
        req = req.header(n, v);
    }
    let res = client
        .send_request(req.body(Full::new(Bytes::from(body))).unwrap())
        .await
        .unwrap();
    let status = res.status().as_u16();
    let headers = res
        .headers()
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
        .collect();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}
fn c12_rpc(name: &str, args: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap()
}
fn c12_tool(bytes: &[u8]) -> (bool, Value) {
    let v: Value = serde_json::from_slice(bytes).unwrap();
    let r = &v["result"];
    (
        r["isError"] == true,
        serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap(),
    )
}
fn c12_auth(token: &str) -> Vec<(String, String)> {
    vec![
        ("authorization".into(), format!("Bearer {token}")),
        ("content-type".into(), "application/json".into()),
        (
            "accept".into(),
            "application/json, text/event-stream".into(),
        ),
    ]
}
#[tokio::test]
async fn integrate2_c12_real_remote_listeners_refuse_infinite_on_every_surface_and_keep_finite_controls(
) {
    tokio::time::timeout(std::time::Duration::from_secs(90),async{let w=C12World::new().await;let token=w.token.clone();let untouched=w.f.shared.run(move|c|c.vault.session_by_token(&token).unwrap().unwrap().last_seen_at).await.unwrap();
 for d in w.doors.iter().filter(|d|d.remote){
  for headers in [vec![("av-session".into(),w.token.clone()),("authorization".into(),format!("Bearer {}",w.ph))],vec![("authorization".into(),format!("Bearer {}",w.token))]]{let before=w.cost().await;let(s,_,b)=w.wire(d,"GET","/p/demo/safe/x",headers,vec![]).await;let v:Value=serde_json::from_slice(&b).unwrap();assert_eq!(s,403,"{} {v}",d.id);assert_eq!(v["rule"],"infinite_remote");assert_eq!(w.cost().await,(before.0,before.1,before.2+1));}
  for (path,headers,rule) in [("/p/demo/safe/x".to_owned(),vec![("authorization".into(),format!("Bearer {}",w.ph))],Some("remote_carrier")),("/p/demo/safe/x".into(),vec![("cookie".into(),format!("av-session={}",w.token))],None),(format!("/p/demo/safe/x?access_token={}",w.token),vec![],None),("/p/demo/safe/x".into(),vec![("x-api-key".into(),w.token.clone())],None),("/p/demo/safe/x".into(),vec![("mcp-session-id".into(),w.token.clone())],None)]{let before=w.cost().await;let(s,_,b)=w.wire(d,"GET",&path,headers,vec![]).await;assert_eq!(s,401,"{} {}",d.id,String::from_utf8_lossy(&b));if let Some(rule)=rule{assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["rule"],rule);}assert_eq!(w.cost().await.0,before.0);}
  let before=w.cost().await;let(s,_,b)=w.wire(d,"GET","/p/demo/safe/x",vec![("av-session".into(),w.f.token.clone()),("authorization".into(),format!("Bearer {}",w.f.ph))],vec![]).await;assert_eq!(s,200,"{} {}",d.id,String::from_utf8_lossy(&b));assert_eq!(b,b"C12_UPSTREAM_MARKER");assert_eq!(w.cost().await.0,before.0+1);
  for carrier in ["av-session","bearer","both"]{for(name,args)in [("vault_http",json!({"cred":"demo","method":"GET","path":"/safe/x"})),("vault_get_placeholder",json!({"cred":"demo","reason":"c12"})),("vault_list_creds",json!({})),("vault_approval_status",json!({"approval_id":"apr_none"}))]{let mut headers=c12_auth(&w.token);if carrier=="av-session"{headers.retain(|(n,_)|n!="authorization");}
 if carrier!="bearer"{headers.push(("av-session".into(),w.token.clone()));}let before=w.cost().await;let(s,_,b)=w.wire(d,"POST","/mcp",headers,c12_rpc(name,args)).await;assert_eq!(s,200);let(error,v)=c12_tool(&b);assert!(error,"{v}");assert_eq!(v["code"],"AV_REMOTE_FORBIDDEN");assert_eq!(v["rule"],"infinite_remote");assert!(!String::from_utf8_lossy(&b).contains("av1."));assert_eq!(w.cost().await,(before.0,before.1,before.2+1),"{} {carrier} {name}",d.id);}}
  for headers in [c12_auth(&w.ph),vec![("content-type".into(),"application/json".into())]]{let before=w.cost().await;let(_,_,b)=w.wire(d,"POST","/mcp",headers,c12_rpc("vault_http",json!({"cred":"demo","method":"GET","path":"/safe/x"}))).await;let(error,v)=c12_tool(&b);assert!(error);assert_eq!(v["error"],"this tool needs a live session");let after=w.cost().await;assert_eq!((after.0,after.1),(before.0,before.1));}
  for(method,path,mut headers)in [("GET","/v1/session",vec![("av-session".into(),w.token.clone())]),("GET","/v1/session",c12_auth(&w.token)),("GET","/v1/credentials",c12_auth(&w.token)),("POST","/v1/placeholders?cred=demo",c12_auth(&w.token)),("GET","/v1/nope",c12_auth(&w.token))]{headers.push(("content-type".into(),"application/json".into()));let before=w.cost().await;let(s,_,b)=w.wire(d,method,path,headers,if method=="POST"{b"{}".to_vec()}else{vec![]}).await;assert_eq!(s,403,"{} {path}: {}",d.id,String::from_utf8_lossy(&b));let v:Value=serde_json::from_slice(&b).unwrap();assert_eq!(v["code"],"AV_REMOTE_FORBIDDEN");assert_eq!(v["rule"],"infinite_remote");assert!(!String::from_utf8_lossy(&b).contains(&w.sid));assert!(!String::from_utf8_lossy(&b).contains("av1."));assert_eq!(w.cost().await,(before.0,before.1,before.2+1));}
  assert_eq!(w.wire(d,"GET","/v1/status",c12_auth(&w.token),vec![]).await.0,200);
  let(s,_,b)=w.wire(d,"GET","/v1/session",c12_auth(&w.f.token),vec![]).await;assert_eq!(s,200);assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["id"],control_session_sid(&w.f).await);let(s,_,b)=w.wire(d,"GET","/v1/credentials",c12_auth(&w.f.token),vec![]).await;assert_eq!(s,200);assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()[0]["slug"],"demo");let before=w.cost().await;let(s,_,b)=w.wire(d,"POST","/v1/placeholders?cred=demo",c12_auth(&w.f.token),b"{}".to_vec()).await;assert_eq!(s,200,"{}",String::from_utf8_lossy(&b));assert!(serde_json::from_slice::<Value>(&b).unwrap()["placeholder"].as_str().unwrap().starts_with("av1."));assert_eq!(w.cost().await.1,before.1+1);
  let init=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})).unwrap();let before=w.cost().await;let(s,h,b)=w.wire(d,"POST","/mcp",c12_auth(&w.token),init.clone()).await;assert_eq!(s,200);assert!(h.iter().any(|(n,v)|n.eq_ignore_ascii_case("av-session-invalid")&&v=="1"));assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["result"]["serverInfo"]["name"],"agent-vault");assert_eq!(w.cost().await.2,before.2);let(_,_,b)=w.wire(d,"POST","/mcp",c12_auth(&w.token),c12_rpc("vault_status",json!({}))).await;let(_,v)=c12_tool(&b);assert!(v["session"].is_null());assert!(v["session_problem"].as_str().unwrap().contains("network listener"));assert_eq!(v["credentials_available"],0);assert_eq!(w.cost().await.2,before.2);let(_,_,b)=w.wire(d,"POST","/mcp",c12_auth(&w.token),c12_rpc("vault_explain_denial",json!({"request_id":"req_none"}))).await;assert!(!String::from_utf8_lossy(&b).contains(&w.sid));
  let(_,h,_)=w.wire(d,"POST","/mcp",c12_auth(&w.f.token),init).await;assert!(!h.iter().any(|(n,_)|n.eq_ignore_ascii_case("av-session-invalid")));let before=w.cost().await;let(_,_,b)=w.wire(d,"POST","/mcp",c12_auth(&w.f.token),c12_rpc("vault_http",json!({"cred":"demo","method":"GET","path":"/safe/x"}))).await;let(error,v)=c12_tool(&b);assert!(!error,"{v}");assert_eq!(v["status"],200);assert_eq!(v["body"],"C12_UPSTREAM_MARKER");assert_eq!(w.cost().await.0,before.0+1);assert!(audit_records(&w.f).await.iter().any(|r|r["request_id"]==v["request_id"]&&r["peer"]["listener_id"]==d.id));let before=w.cost().await;let(_,_,b)=w.wire(d,"POST","/mcp",c12_auth(&w.f.token),c12_rpc("vault_get_placeholder",json!({"cred":"demo","reason":"c12"}))).await;assert!(c12_tool(&b).1["placeholder"].as_str().unwrap().starts_with("av1."));assert_eq!(w.cost().await.1,before.1+1);
 }
 let token=w.token.clone();let sid=w.sid.clone();w.f.shared.run(move|c|{assert_eq!(c.vault.session_by_token(&token).unwrap().unwrap().last_seen_at,untouched);assert!(c.vault.list_placeholders(Some(&sid)).unwrap().iter().all(|p|p.uses==0));}).await.unwrap();
        let mut req=GatewayRequest{method:"GET".into(),path:"/p/demo/safe/x".into(),headers:vec![("host".into(),"localhost".into()),("av-session".into(),w.token.clone()),("authorization".into(),format!("Bearer {}",w.ph))],listener:Some(av_daemon::pipeline::ListenerInfo{id:"lan".into(),kind:"tls".into(),remote:true,advertise:vec![]}),..Default::default()};assert_eq!(w.f.daemon.pipeline().preflight(req.clone(),false).await.unwrap_err().extra.rule.as_deref(),Some("infinite_remote"));
        for listener in [Some(av_daemon::pipeline::ListenerInfo{id:"local".into(),kind:"tcp".into(),remote:false,advertise:vec![]}),None]{req.listener=listener;assert_eq!(w.f.daemon.pipeline().handle(req.clone()).await.status,200);}
        for raw in w.seen.lock().unwrap().iter(){assert!(raw.contains(&format!("Bearer {SECRET}")));}
        w.finish().await;}).await.unwrap();
}

#[tokio::test]
async fn integrate2_c12_loopback_surfaces_stdio_pipeline_defense_and_store_peek_use_contract() {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let w = C12World::new().await;
        for d in w.doors.iter().filter(|d| !d.remote) {
            let before = w.cost().await;
            let (s, _, b) = w
                .wire(
                    d,
                    "GET",
                    "/p/demo/safe/x",
                    vec![
                        ("av-session".into(), w.token.clone()),
                        ("authorization".into(), format!("Bearer {}", w.ph)),
                    ],
                    vec![],
                )
                .await;
            assert_eq!(s, 200, "{} {}", d.id, String::from_utf8_lossy(&b));
            assert_eq!(w.cost().await.0, before.0 + 1);
            let before = w.cost().await;
            let (_, _, b) = w
                .wire(
                    d,
                    "POST",
                    "/mcp",
                    c12_auth(&w.token),
                    c12_rpc(
                        "vault_http",
                        json!({"cred":"demo","method":"GET","path":"/safe/x"}),
                    ),
                )
                .await;
            let (error, v) = c12_tool(&b);
            assert!(!error, "{} {v}", d.id);
            assert_eq!(v["body"], "C12_UPSTREAM_MARKER");
            assert_eq!(w.cost().await.0, before.0 + 1);
            let before = w.cost().await;
            let (_, _, b) = w
                .wire(
                    d,
                    "POST",
                    "/mcp",
                    c12_auth(&w.token),
                    c12_rpc(
                        "vault_get_placeholder",
                        json!({"cred":"demo","reason":"c12"}),
                    ),
                )
                .await;
            assert!(c12_tool(&b).1["placeholder"]
                .as_str()
                .unwrap()
                .starts_with("av1."));
            assert_eq!(w.cost().await.1, before.1 + 1);
            let (s, _, b) = w
                .wire(
                    d,
                    "GET",
                    "/v1/session",
                    vec![("av-session".into(), w.token.clone())],
                    vec![],
                )
                .await;
            assert_eq!(s, 200);
            assert_eq!(
                serde_json::from_slice::<Value>(&b).unwrap()["infinite"],
                true
            );
            let (s, _, _) = w
                .wire(d, "GET", "/v1/credentials", c12_auth(&w.token), vec![])
                .await;
            assert_eq!(s, 200);
            let before = w.cost().await;
            let (s, _, b) = w
                .wire(
                    d,
                    "POST",
                    "/v1/placeholders?cred=demo",
                    c12_auth(&w.token),
                    b"{}".to_vec(),
                )
                .await;
            assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
            assert_eq!(w.cost().await.1, before.1 + 1);
            assert_eq!(w.cost().await.2, 0);
        }
        let token = w.token.clone();
        let session =
            w.f.shared
                .run(move |c| c.vault.session_by_token(&token).unwrap())
                .await
                .unwrap();
        let message: Value = serde_json::from_slice(&c12_rpc(
            "vault_http",
            json!({"cred":"demo","method":"GET","path":"/safe/x"}),
        ))
        .unwrap();
        let before = w.cost().await;
        let v =
            w.f.daemon
                .mcp()
                .handle(
                    message.clone(),
                    session.clone(),
                    Some(w.token.clone()),
                    None,
                )
                .await
                .unwrap();
        assert!(v["result"].get("isError").is_none());
        let body: Value =
            serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(body["body"], "C12_UPSTREAM_MARKER");
        assert_eq!(w.cost().await.0, before.0 + 1);
        let before = w.cost().await;
        let v =
            w.f.daemon
                .mcp()
                .handle(
                    message,
                    session,
                    Some(w.token.clone()),
                    Some(av_daemon::pipeline::ListenerInfo {
                        id: "wild-v4".into(),
                        kind: "tls".into(),
                        remote: true,
                        advertise: vec![],
                    }),
                )
                .await
                .unwrap();
        let body: Value =
            serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(body["status"], 403, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(body["body"].as_str().unwrap()).unwrap()["rule"],
            "infinite_remote"
        );
        assert_eq!(w.cost().await.0, before.0);
        assert!(audit_records(&w.f)
            .await
            .iter()
            .any(|r| r["request_id"] == body["request_id"]
                && r["rule"] == "infinite_remote"
                && r["peer"]["listener_id"] == "wild-v4"));
        let token = w.token.clone();
        let finite = w.f.token.clone();
        w.f.shared
            .run(move |c| {
                use av_store::vault::{ListenerContext, UsableOptions};
                let inf = c.vault.session_by_token(&token).unwrap().unwrap();
                let fin = c.vault.session_by_token(&finite).unwrap().unwrap();
                let remote = ListenerContext {
                    id: Some("lan".into()),
                    kind: Some("tls".into()),
                    remote: true,
                };
                let n = |c: &av_daemon::state::Core| {
                    c.vault
                        .audit()
                        .unwrap()
                        .read(&av_store::audit::ReadFilter {
                            limit: usize::MAX,
                            ..Default::default()
                        })
                        .unwrap()
                        .iter()
                        .filter(|r| serde_json::to_value(r).unwrap()["rule"] == "infinite_remote")
                        .count()
                };
                let before = n(c);
                let e = c
                    .vault
                    .assert_session_usable(
                        Some(&inf),
                        Some(&remote),
                        UsableOptions {
                            peek: true,
                            ..Default::default()
                        },
                    )
                    .unwrap_err();
                let av_store::error::Error::Vault(e) = e else {
                    panic!("vault refusal")
                };
                assert_eq!(e.code.as_str(), "AV_REMOTE_FORBIDDEN");
                assert_eq!(e.extra.rule.as_deref(), Some("infinite_remote"));
                assert_eq!(n(c), before);
                assert!(c
                    .vault
                    .assert_session_usable(Some(&inf), Some(&remote), Default::default())
                    .is_err());
                assert_eq!(n(c), before + 1);
                for listener in [
                    None,
                    Some(ListenerContext {
                        id: Some("local".into()),
                        kind: Some("tcp".into()),
                        remote: false,
                    }),
                ] {
                    assert_eq!(
                        c.vault
                            .assert_session_usable(
                                Some(&inf),
                                listener.as_ref(),
                                Default::default()
                            )
                            .unwrap()
                            .id,
                        inf.id
                    );
                }
                for peek in [false, true] {
                    assert_eq!(
                        c.vault
                            .assert_session_usable(
                                Some(&fin),
                                Some(&remote),
                                UsableOptions {
                                    peek,
                                    ..Default::default()
                                }
                            )
                            .unwrap()
                            .id,
                        fin.id
                    );
                }
            })
            .await
            .unwrap();
        w.finish().await;
    })
    .await
    .unwrap();
}

struct SeamWorld {
    f: Fixture,
    seen: Arc<Mutex<Vec<String>>>,
    peer: tokio::task::JoinHandle<()>,
}
impl SeamWorld {
    async fn new(reply: Reply, policy: Value, session_policy: Value) -> Self {
        use tokio::io::AsyncWriteExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let got = seen.clone();
        let peer = tokio::spawn(async move {
            while let Ok((mut tcp, _)) = l.accept().await {
                let (head, _) = read_wire_request(&mut tcp).await;
                got.lock().unwrap().push(head);
                let mut wire = format!(
                    "HTTP/1.1 {} Fake\r\ncontent-length: {}\r\nconnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (n, v) in &reply.headers {
                    wire.push_str(&format!("{n}: {v}\r\n"));
                }
                wire.push_str("\r\n");
                tcp.write_all(wire.as_bytes()).await.unwrap();
                tcp.write_all(&reply.body).await.unwrap();
            }
        });
        let mut f = mcp_real_http_fixture(port).await;
        let(token,ph,gid)=f.shared.run(move|c|{use av_core::secret::ExposeSecret;let cred=c.vault.find_credential("demo").unwrap().unwrap();let s=c.vault.create_session(av_store::vault::CreateSessionOptions{policy:serde_json::from_value(session_policy).unwrap(),..Default::default()}).unwrap();let mut base=json!({"hosts":["127.0.0.1"],"methods":["GET","POST"],"paths":["/**"],"approval":"auto","budget":{"unit":"requests","limit":100}});for(k,v)in policy.as_object().unwrap(){base[k]=v.clone();}let g=c.vault.create_grant(av_store::vault::CreateGrantOptions{session_id:s.session.id,credential_id:cred.id,policy:serde_json::from_value(base).unwrap(),..Default::default()}).unwrap();let p=c.vault.issue_placeholder(av_store::vault::IssueOptions{grant_id:g.id.clone(),..Default::default()}).unwrap();(s.token.expose_secret().to_string(),p.placeholder,g.id)}).await.unwrap();
        f.token = token;
        f.ph = ph;
        f.grant_id = gid;
        Self { f, seen, peer }
    }
    async fn get(&self) -> GatewayResponse {
        self.f
            .send(
                "GET",
                "/x",
                vec![("authorization".into(), format!("Bearer {}", self.f.ph))],
                None,
            )
            .await
    }
    async fn finish(self) {
        credential_finish(&self.f).await;
        self.peer.abort();
        let _ = self.peer.await;
    }
}
#[tokio::test]
async fn integrate2_real_redirect_hops_charge_bounded_grant_and_unit_only_session_budgets() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for (limit, grant, session) in [
            (
                2,
                json!({"budget":{"unit":"requests","limit":2},"redirects":{"max":5}}),
                json!({}),
            ),
            (
                3,
                json!({"budget":{"unit":"requests"},"redirects":{"max":5}}),
                json!({"budget":{"unit":"requests","limit":3}}),
            ),
        ] {
            let w = SeamWorld::new(redirect_reply(302, "/next"), grant, session).await;
            let r = w.get().await;
            assert_eq!(r.status, 302);
            assert_eq!(r.header("av-redirect-stopped"), Some("budget"));
            assert_eq!(w.seen.lock().unwrap().len(), limit);
            let gid = w.f.grant_id.clone();
            w.f.shared
                .run(move |c| {
                    assert_eq!(
                        c.vault.grant(&gid).unwrap().unwrap().budget_used,
                        limit as u64
                    )
                })
                .await
                .unwrap();
            w.f.clean(&r).await;
            w.finish().await;
        }
        let w = SeamWorld::new(done_reply(), json!({}), json!({})).await;
        assert_eq!(w.get().await.status, 200);
        assert_eq!(w.seen.lock().unwrap().len(), 1);
        w.finish().await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integrate2_expired_grant_is_unsent_and_stays_expired_across_repeated_attempts() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let w = SeamWorld::new(done_reply(), json!({}), json!({})).await;
        let gid = w.f.grant_id.clone();
        let sid = control_session_sid(&w.f).await;
        let seedgid = gid.clone();
        let f = control_session_restart_after_seed(w.f, move |dir| {
            ported_common::seed_gateway_rows(
                dir,
                &sid,
                &seedgid,
                &json!({}),
                &json!({"expires_at":"2000-01-01T00:00:00.000Z"}),
            )
        })
        .await;
        for _ in 0..2 {
            let r = f
                .send(
                    "GET",
                    "/x",
                    vec![("authorization".into(), format!("Bearer {}", f.ph))],
                    None,
                )
                .await;
            assert_eq!(
                serde_json::from_slice::<Value>(&r.body).unwrap()["code"],
                "AV_GRANT_EXPIRED"
            );
        }
        assert!(w.seen.lock().unwrap().is_empty());
        f.shared
            .run(move |c| {
                assert_eq!(
                    c.vault.grant(&gid).unwrap().unwrap().state,
                    av_store::model::GrantState::Expired
                )
            })
            .await
            .unwrap();
        credential_finish(&f).await;
        w.peer.abort();
        let _ = w.peer.await;
        let control = SeamWorld::new(done_reply(), json!({}), json!({})).await;
        assert_eq!(control.get().await.status, 200);
        control.finish().await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integrate2_store_quarantine_and_tripwire_both_stop_real_network_traffic() {
    tokio::time::timeout(std::time::Duration::from_secs(25),async{let w=SeamWorld::new(done_reply(),json!({}),json!({})).await;w.f.shared.run(|c|c.vault.set_quarantine("demo",Default::default()).unwrap()).await.unwrap();let r=w.get().await;assert_eq!(r.error.unwrap().code.as_str(),"AV_QUARANTINED");assert!(w.seen.lock().unwrap().is_empty());assert_eq!(grant_counters(&w.f).await.1,vec![0]);w.f.shared.run(|c|c.vault.clear_quarantine("demo").unwrap()).await.unwrap();assert_eq!(w.get().await.status,200);w.f.shared.run(|c|c.vault.update_settings(&json!({"tripwires":{"enabled":true,"rules":[{"id":"methods","codes":["AV_POLICY_DENIED"],"threshold":2,"window_s":60,"action":"quarantine_credential"}]}})).unwrap()).await.unwrap();for _ in 0..2{let r=w.f.send("DELETE","/x",vec![("authorization".into(),format!("Bearer {}",w.f.ph))],None).await;assert_eq!(r.error.unwrap().code.as_str(),"AV_POLICY_DENIED");}w.f.shared.run(|c|{let q=c.vault.find_credential("demo").unwrap().unwrap().quarantine.unwrap();assert_eq!(q.by,av_store::model::QuarantineBy::Tripwire);assert_eq!(q.rule_id.as_deref(),Some("methods"));}).await.unwrap();assert_eq!(w.get().await.error.unwrap().code.as_str(),"AV_QUARANTINED");assert_eq!(w.seen.lock().unwrap().len(),1);w.finish().await;}).await.unwrap();
}
#[tokio::test]
async fn integrate2_store_saved_scrub_pattern_is_used_and_rejected_patterns_are_never_persisted() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let w = SeamWorld::new(
            Reply {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"before acme_QWERTYUI after".to_vec(),
                streaming: false,
            },
            json!({}),
            json!({}),
        )
        .await;
        for source in [
            "acme_[A-Z]+",
            "acme_.*",
            "acme_[A-Z]{1,}",
            "abc[^Q]{0,250}[^Q]{250}Q",
        ] {
            w.f.shared
                .run(move |c| {
                    let e = c.vault.add_scrub_pattern("demo", source).unwrap_err();
                    let av_store::error::Error::Vault(e) = e else {
                        panic!("vault refusal")
                    };
                    assert_eq!(e.extra.rule.as_deref(), Some("scrub_pattern"));
                    assert!(c
                        .vault
                        .find_credential("demo")
                        .unwrap()
                        .unwrap()
                        .scrub_patterns
                        .is_empty());
                })
                .await
                .unwrap();
        }
        let ordinary = w.get().await;
        assert!(String::from_utf8_lossy(&ordinary.body).contains("acme_QWERTYUI"));
        w.f.shared
            .run(|c| c.vault.add_scrub_pattern("demo", "acme_[A-Z]{8}").unwrap())
            .await
            .unwrap();
        let r = w.get().await;
        assert_eq!(r.status, 200);
        let text = String::from_utf8(r.body).unwrap();
        assert!(!text.contains("acme_QWERTYUI"));
        assert!(text.starts_with("before ") && text.ends_with(" after"));
        w.finish().await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integrate2_held_request_is_unsent_and_store_activity_counts_it_as_held_not_allowed() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let w = SeamWorld::new(done_reply(), json!({"approval":"each"}), json!({})).await;
        let r = w.get().await;
        assert_eq!(r.status, 202);
        assert!(w.seen.lock().unwrap().is_empty());
        let rows = audit_records(&w.f).await;
        assert_eq!(
            rows.iter()
                .filter(|r| r["kind"] == "request.allowed")
                .map(|r| r["decision"].clone())
                .collect::<Vec<_>>(),
            vec![json!("held")]
        );
        let sid = control_session_sid(&w.f).await;
        let (s, v) = credential_api(
            &w.f,
            "GET",
            &format!("/v1/sessions/detail?sid={sid}"),
            json!({}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["activity"]["requests"]["held"], 1);
        assert_eq!(v["activity"]["requests"]["allowed"], 0);
        w.f.daemon
            .pipeline()
            .decide_approval(held_id(&r), true)
            .await
            .unwrap();
        assert_eq!(w.get().await.status, 200);
        assert_eq!(w.seen.lock().unwrap().len(), 1);
        w.finish().await;
    })
    .await
    .unwrap();
}

struct ForeignHostTransport;
impl Upstream for ForeignHostTransport {
    fn send(
        &self,
        mut req: UpstreamRequest,
    ) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(async move {
            req.headers.push(("Host".into(), "evil.example".into()));
            av_daemon::connectors::pinning::pinned_request(req).await
        })
    }
}
#[tokio::test]
async fn integrate2_pipeline_rebuilds_host_and_real_connector_refuses_foreign_host_with_refund() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let w = SeamWorld::new(done_reply(), json!({}), json!({})).await;
        let r =
            w.f.send(
                "GET",
                "/x",
                vec![
                    ("authorization".into(), format!("Bearer {}", w.f.ph)),
                    ("HOST".into(), "127.0.0.1".into()),
                    ("Host".into(), "localhost".into()),
                ],
                None,
            )
            .await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let raw = w.seen.lock().unwrap()[0].clone();
        let values = raw
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 1);
        let connector =
            w.f.shared
                .run(|c| {
                    c.vault.find_credential("demo").unwrap().unwrap().connector["host"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .await
                .unwrap();
        assert_eq!(values[0], connector);
        let before = grant_counters(&w.f).await;
        let pipeline = av_daemon::pipeline::Pipeline::new(
            w.f.shared.clone(),
            PipelineOptions {
                upstream: Some(Arc::new(ForeignHostTransport)),
                ..Default::default()
            },
        );
        let r = pipeline
            .handle(GatewayRequest {
                method: "GET".into(),
                path: "/p/demo/x".into(),
                headers: vec![
                    ("host".into(), "localhost".into()),
                    ("av-session".into(), w.f.token.clone()),
                    ("authorization".into(), format!("Bearer {}", w.f.ph)),
                ],
                ..Default::default()
            })
            .await;
        assert_eq!(r.status, 403);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["code"], "AV_POLICY_DENIED");
        assert_eq!(v["rule"], "host_mismatch");
        assert_eq!(v["refunded"], true);
        assert_eq!(w.seen.lock().unwrap().len(), 1);
        assert_eq!(grant_counters(&w.f).await, before);
        w.f.clean(&r).await;
        w.finish().await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integrate2_malformed_stored_pin_entries_never_mean_unpinned_or_reach_upstream() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let w = SeamWorld::new(done_reply(), json!({}), json!({})).await;
        let f = control_session_restart_after_seed(w.f, |dir| {
            ported_common::seed_credential_pins(dir, "demo", &json!({"127.0.0.1":["nope"]}))
        })
        .await;
        let pipeline = av_daemon::pipeline::Pipeline::new(f.shared.clone(), Default::default());
        let r = pipeline.handle(hop_request(&f, "GET", "/x")).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&r.body).unwrap()["code"],
            "AV_PIN_MISMATCH"
        );
        assert!(w.seen.lock().unwrap().is_empty());
        assert!(f.up.hits.lock().unwrap().is_empty());
        f.clean(&r).await;
        credential_finish(&f).await;
        w.peer.abort();
        let _ = w.peer.await;
        let normal = SeamWorld::new(done_reply(), json!({}), json!({})).await;
        assert_eq!(normal.get().await.status, 200);
        normal.finish().await;
    })
    .await
    .unwrap();
}

const C25_VALUE: &str = "ghp/PLUS+slash/001122334455667788";
const C25_AMP: &str = "abcd&efgh-ijkl-0099887766";
const C25_PIN: &str = "12345678";
fn c25_variants() -> Vec<(String, String, bool)> {
    use base64::Engine;
    let mut v = vec![("raw".into(), C25_VALUE.into(), true)];
    let mut pct = C25_VALUE.to_owned();
    for n in 1..=5 {
        pct = av_daemon::util::encode_uri_component(&pct);
        v.push((format!("percent x{n}"), pct.clone(), true));
    }
    for upper in [false, true] {
        let u = C25_VALUE
            .chars()
            .map(|c| {
                if upper {
                    format!("\\u{:04X}", c as u32)
                } else {
                    format!("\\u{:04x}", c as u32)
                }
            })
            .collect::<String>();
        v.push((format!("unicode {upper}"), u, true));
    }
    v.push((
        "partial slash".into(),
        C25_VALUE.replacen('/', "\\/", 1),
        true,
    ));
    v.push(("full slash".into(), C25_VALUE.replace('/', "\\/"), true));
    let b64 = base64::engine::general_purpose::STANDARD.encode(C25_VALUE);
    let cut = b64.len() / 2;
    v.push(("base64".into(), b64.clone(), true));
    v.push((
        "wrapped base64".into(),
        format!("{}\n{}", &b64[..cut], &b64[cut..]),
        false,
    ));
    v.push((
        "base64 of percent".into(),
        base64::engine::general_purpose::STANDARD
            .encode(av_daemon::util::encode_uri_component(C25_VALUE)),
        true,
    ));
    v.push((
        "html decimal".into(),
        C25_VALUE
            .chars()
            .map(|c| format!("&#{};", c as u32))
            .collect(),
        true,
    ));
    v.push((
        "html hex".into(),
        C25_VALUE
            .chars()
            .map(|c| format!("&#x{:x};", c as u32))
            .collect(),
        true,
    ));
    let hex = C25_VALUE
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    v.push(("hex lower".into(), hex.clone(), true));
    v.push(("hex upper".into(), hex.to_ascii_uppercase(), true));
    let mut flip = false;
    v.push((
        "hex mixed".into(),
        hex.chars()
            .map(|c| {
                if ('a'..='f').contains(&c) {
                    flip = !flip;
                    if flip {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                } else {
                    c
                }
            })
            .collect(),
        true,
    ));
    v.push(("html named".into(), C25_AMP.replace('&', "&amp;"), true));
    v
}
fn c25_greedy(numbers: bool) -> Value {
    let forms = c25_variants();
    let paths = forms
        .iter()
        .filter(|(_, _, p)| *p)
        .map(|(_, s, _)| format!("/{s}"))
        .collect::<Vec<_>>();
    let mut values = forms.iter().map(|(_, v, _)| json!(v)).collect::<Vec<_>>();
    if numbers {
        values.push(json!(12345678));
    }
    let mut p = json!({"cred":"demo","methods":["GET","POST"],"paths":paths,"routes":[{"methods":["GET","POST"],"paths":&paths[..3]}],"payload":{"json":{"/q":{"one_of":values}}},"reason":format!("forms: {} | {C25_PIN}",forms.iter().map(|(_,s,_)|s.as_str()).collect::<Vec<_>>().join(" | "))});
    if numbers {
        for(k,v)in json!({"budget":12345678,"uses":12345678,"quota":{"count":12345678,"window":"day"},"ttl_minutes":12345678,"grant_ttl_minutes":12345678}).as_object().unwrap(){p[k]=v.clone();}
    }
    p
}
async fn c25_fixture() -> Fixture {
    let f = Fixture::new(&["header:x-key"]).await;
    f.shared
        .run(|c| {
            c.vault
                .rotate_credential(
                    "demo",
                    av_store::vault::RotateOptions {
                        field: None,
                        value: C25_VALUE.to_owned().into(),
                        mode: av_store::vault::RotateMode::Keep,
                        retire_ms: 0,
                        expires_at: None,
                    },
                )
                .unwrap();
            for (slug, value) in [("amp", C25_AMP), ("pin", C25_PIN)] {
                c.vault
                    .add_credential(av_store::vault::NewCredential {
                        slug: slug.into(),
                        kind: "http".into(),
                        connector: serde_json::from_value(
                            json!({"host":"api.example.test","scheme":"https"}),
                        )
                        .unwrap(),
                        fields: vec![("token".into(), value.to_owned().into())],
                        sites: std::collections::BTreeMap::from([(
                            "token".into(),
                            vec!["header:x-key".into()],
                        )]),
                    })
                    .unwrap();
            }
        })
        .await
        .unwrap();
    credential_factor(&f).await;
    f
}
async fn c25_ask(f: &Fixture, p: Value) -> Value {
    let (s, v) = credential_api(f, "POST", "/v1/session-requests", p).await;
    assert_eq!(s, 200, "{v}");
    v["id"].clone()
}
async fn c25_decide(f: &Fixture, id: &Value, extra: Value) -> Value {
    credential_gate(f, true).await;
    let mut b = json!({"id":id,"granted":true});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    let (s, v) = credential_api(f, "POST", "/v1/session-requests/decide", b).await;
    assert_eq!(s, 200, "{v}");
    v
}
async fn c25_assert_structure_only(f: &Fixture, ids: &[Value], kinds: &[&str]) {
    let direct = json!(audit_records(f).await);
    let (s, read) = credential_api(f, "GET", "/v1/audit?limit=500", json!({})).await;
    assert_eq!(s, 200);
    let read = if read.is_array() {
        read
    } else {
        read["records"].clone()
    };
    let (s, export) = credential_api(
        f,
        "GET",
        "/v1/audit/export?since_seq=0&limit=500",
        json!({}),
    )
    .await;
    assert_eq!(s, 200, "{export}");
    let fields = av_daemon::session_requests::FIELDS
        .iter()
        .chain(av_daemon::session_requests::OWNER_FIELDS.iter())
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let variants = c25_variants();
    let b64 = variants
        .iter()
        .find(|(n, _, _)| n == "base64")
        .unwrap()
        .1
        .clone();
    let cut = b64.len() / 2;
    let mut needles = variants
        .iter()
        .map(|(_, v, _)| v.as_str())
        .collect::<Vec<_>>();
    needles.extend([
        C25_VALUE,
        C25_AMP,
        C25_PIN,
        &C25_VALUE[..12],
        "PLUS+slash",
        "001122334455667788",
        &b64[..cut],
        &b64[cut..],
    ]);
    for (where_, rows) in [
        ("store", direct),
        ("read", read),
        ("export", export["rows"].clone()),
    ] {
        let rows = rows
            .as_array()
            .unwrap_or_else(|| panic!("{where_} is not rows"));
        for kind in kinds {
            assert!(
                rows.iter().any(|r| r["kind"] == *kind),
                "{where_} lacks {kind}"
            );
        }
        for r in rows.iter().filter(|r| {
            matches!(
                r["kind"].as_str(),
                Some(
                    "session_request.opened"
                        | "session_request.approved"
                        | "session_request.denied"
                )
            )
        }) {
            let kind = r["kind"].as_str().unwrap();
            let mut allowed = vec!["seq", "ts", "kind", "prev_hash", "hash"];
            allowed.extend(match kind {
                "session_request.opened" => vec![
                    "request_id",
                    "actor",
                    "cred",
                    "template",
                    "proposed",
                    "counts",
                ],
                "session_request.approved" => vec![
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
                ],
                _ => vec!["request_id", "decision", "cred", "proposed", "actor"],
            });
            if r["actor"] == "panic" {
                allowed.push("reason");
                assert_eq!(r["reason"], "panic");
            }
            assert_eq!(
                r.as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>(),
                allowed.into_iter().collect(),
                "{where_}: {r}"
            );
            assert!(ids.contains(&r["request_id"]));
            assert!(r["cred"].is_null() || r["cred"] == "demo");
            assert!(["agent", "human", "panic"].contains(&r["actor"].as_str().unwrap()));
            for key in ["proposed", "granted", "narrowed"] {
                if let Some(v) = r.get(key) {
                    assert!(v
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|v| fields.contains(v.as_str().unwrap())));
                }
            }
            if let Some(counts) = r.get("counts") {
                for (k, n) in counts.as_object().unwrap() {
                    assert!(fields.contains(k.as_str()));
                    assert!(n.as_u64().is_some_and(|n| n < 1000));
                }
            }
            if kind == "session_request.approved" {
                assert!(r["edited"].is_boolean());
                let sid = r["session_id"].as_str().unwrap().to_owned();
                assert!(f
                    .shared
                    .run(move |c| c.vault.session(&sid).unwrap().is_some())
                    .await
                    .unwrap());
            }
            if kind != "session_request.opened" {
                assert_eq!(r["decision"], kind.split('.').nth(1).unwrap());
            }
        }
        let text = serde_json::to_string(rows).unwrap();
        for needle in &needles {
            assert!(
                !text.contains(needle),
                "{where_} audit contains input shape {needle:?}"
            );
        }
    }
}
async fn c25_assert_grant(f: &Fixture, made: &Value, numbers: bool) {
    let p = control_session_policy(f, made["grant_id"].as_str().unwrap()).await;
    for (name, v, path) in c25_variants() {
        if path {
            assert!(
                p["paths"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(format!("/{v}"))),
                "lost {name}"
            );
        }
    }
    assert!(p["payload"].to_string().contains(C25_VALUE));
    if numbers {
        assert_eq!(p["budget"]["limit"], 12345678);
        assert_eq!(p["quota"]["count"], 12345678);
    }
}
#[tokio::test]
async fn c25_all_encoded_proposal_forms_are_absent_from_all_audit_surfaces_but_limits_remain_live()
{
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = c25_fixture().await;
        let id = c25_ask(&f, c25_greedy(true)).await;
        let made = c25_decide(&f, &id, json!({})).await;
        let rows = audit_records(&f).await;
        let opened = rows
            .iter()
            .find(|r| r["kind"] == "session_request.opened")
            .unwrap();
        assert_eq!(
            opened["proposed"],
            json!([
                "cred",
                "methods",
                "paths",
                "budget",
                "uses",
                "ttl_minutes",
                "quota",
                "routes",
                "payload",
                "grant_ttl_minutes"
            ])
        );
        assert_eq!(
            opened["counts"],
            json!({"methods":2,"paths":c25_variants().len()-1,"routes":1})
        );
        assert_eq!(opened["actor"], "agent");
        assert_eq!(opened["cred"], "demo");
        let approved = rows
            .iter()
            .find(|r| r["kind"] == "session_request.approved")
            .unwrap();
        assert_eq!(approved["granted"], opened["proposed"]);
        assert_eq!(approved["narrowed"], json!([]));
        assert_eq!(approved["edited"], false);
        c25_assert_grant(&f, &made["session"], true).await;
        c25_assert_structure_only(
            &f,
            &[id],
            &["session_request.opened", "session_request.approved"],
        )
        .await;
        let sid = made["session"]["session_id"].as_str().unwrap();
        for kind in ["session.created", "grant.created"] {
            let row = rows
                .iter()
                .find(|r| r["kind"] == kind && r["session_id"] == sid)
                .unwrap();
            assert!(row["expires_at"].is_null());
            assert_eq!(row["has_expiry"], true);
        }
        let issued = rows
            .iter()
            .find(|r| r["kind"] == "placeholder.issued" && r["session_id"] == sid)
            .unwrap();
        assert!(issued.get("max_uses").is_none());
        let gid = made["session"]["grant_id"].as_str().unwrap().to_owned();
        let sid = sid.to_owned();
        f.shared
            .run(move |c| {
                assert!(c.vault.session(&sid).unwrap().unwrap().expires_at.is_some());
                assert!(c.vault.grant(&gid).unwrap().unwrap().expires_at.is_some());
                assert!(c
                    .vault
                    .list_placeholders(None)
                    .unwrap()
                    .iter()
                    .any(|p| p.grant_id == gid && p.max_uses > 0));
            })
            .await
            .unwrap();
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn c25_bulk_human_denial_and_panic_denial_keep_only_structure_and_minted_ids() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{let f=c25_fixture().await;let one=c25_ask(&f,c25_greedy(true)).await;let two=c25_ask(&f,c25_greedy(false)).await;credential_gate(&f,true).await;let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":one,"kind":"session","granted":true},{"id":two,"kind":"session","granted":false}]})).await;assert_eq!(s,200,"{v}");assert!(v["decided"].as_array().unwrap().iter().all(|r|r["outcome"]=="decided"));let rows=audit_records(&f).await;let many=rows.iter().find(|r|r["kind"]=="pending.decided_many").unwrap();assert_eq!(many["granted"],json!([one]));assert_eq!(many["denied"],json!([two]));assert_eq!(many["skipped"],json!([]));let denied=rows.iter().find(|r|r["kind"]=="session_request.denied").unwrap();assert_eq!(denied["actor"],"human");assert_eq!(denied["proposed"],json!(["cred","methods","paths","routes","payload"]));let approved=rows.iter().find(|r|r["kind"]=="session_request.approved").unwrap();let sid=approved["session_id"].as_str().unwrap().to_owned();let gid=f.shared.run(move|c|c.vault.grants_for_session(&sid).unwrap()[0].id.clone()).await.unwrap();c25_assert_grant(&f,&json!({"grant_id":gid}),true).await;c25_assert_structure_only(&f,&[one,two],&["session_request.opened","session_request.approved","session_request.denied","pending.decided_many"]).await;credential_finish(&f).await;
 let f=c25_fixture().await;let one=c25_ask(&f,c25_greedy(true)).await;credential_gate(&f,true).await;assert_eq!(credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":one,"granted":false})).await.0,200);let two=c25_ask(&f,c25_greedy(false)).await;let(s,v)=credential_api(&f,"POST","/v1/panic",json!({})).await;assert_eq!(s,200,"{v}");assert_eq!(v["denied_session_requests"],1);let rows=audit_records(&f).await;let denied=rows.iter().filter(|r|r["kind"]=="session_request.denied").collect::<Vec<_>>();assert_eq!(denied.len(),2);for(id,actor)in [(&one,"human"),(&two,"panic")]{assert!(denied.iter().any(|r|r["request_id"]==*id&&r["actor"]==actor&&r["decision"]=="denied"));}c25_assert_structure_only(&f,&[one,two],&["session_request.opened","session_request.denied"]).await;credential_finish(&f).await;
 }).await.unwrap();
}

async fn c25_rotate(f: &Fixture, value: &'static str) {
    use av_core::secret::ExposeSecret;
    f.shared
        .run(move |c| {
            c.vault
                .rotate_credential(
                    "demo",
                    av_store::vault::RotateOptions {
                        field: None,
                        value: value.to_owned().into(),
                        mode: av_store::vault::RotateMode::Keep,
                        retire_ms: 0,
                        expires_at: None,
                    },
                )
                .unwrap();
            assert!(!c
                .vault
                .all_secrets()
                .unwrap()
                .iter()
                .any(|s| s.secret.expose_secret() == C25_VALUE));
        })
        .await
        .unwrap();
}
#[tokio::test]
async fn c25_rotated_proposal_and_human_override_keep_values_in_grants_and_out_of_audits() {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        let f = c25_fixture().await;
        let id = c25_ask(&f, c25_greedy(true)).await;
        c25_rotate(&f, "ghp_NEWVALUE99887766554433221100ff").await;
        let made = c25_decide(&f, &id, json!({})).await;
        c25_assert_grant(&f, &made["session"], true).await;
        c25_assert_structure_only(
            &f,
            &[id],
            &["session_request.opened", "session_request.approved"],
        )
        .await;
        let cap = &made["session"];
        let req = |path: String| GatewayRequest {
            method: "GET".into(),
            path: format!("/p/demo{path}"),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), cap["token"].as_str().unwrap().into()),
                ("x-key".into(), cap["placeholder"].as_str().unwrap().into()),
            ],
            ..Default::default()
        };
        let r = f
            .daemon
            .pipeline()
            .handle(req(format!("/{C25_VALUE}")))
            .await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert!(f
            .up
            .hits
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .url
            .ends_with(&format!("/{C25_VALUE}")));
        assert_eq!(
            f.daemon
                .pipeline()
                .handle(req("/not-the-path".into()))
                .await
                .status,
            403
        );
        credential_finish(&f).await;
        let f = c25_fixture().await;
        let id = c25_ask(
            &f,
            json!({"cred":"demo","methods":["GET"],"paths":["/ok"],"reason":"ordinary"}),
        )
        .await;
        c25_rotate(&f, "ghp_NEWVALUE99887766554433221100ee").await;
        let pct = c25_variants()
            .into_iter()
            .find(|(n, _, _)| n == "percent x5")
            .unwrap()
            .1;
        let paths = json!([format!("/{C25_VALUE}"), format!("/{pct}")]);
        let made = c25_decide(
            &f,
            &id,
            json!({"overrides":{"paths":paths,"budget":12345678}}),
        )
        .await;
        let rows = audit_records(&f).await;
        let r = rows
            .iter()
            .find(|r| r["kind"] == "session_request.approved")
            .unwrap();
        assert_eq!(r["narrowed"], json!(["paths", "budget"]));
        assert_eq!(r["granted"], json!(["cred", "methods", "paths", "budget"]));
        assert_eq!(r["counts"], json!({"methods":1,"paths":2}));
        assert_eq!(r["edited"], true);
        let p = control_session_policy(&f, made["session"]["grant_id"].as_str().unwrap()).await;
        assert_eq!(p["paths"], paths);
        assert_eq!(p["budget"]["limit"], 12345678);
        c25_assert_structure_only(
            &f,
            &[id],
            &["session_request.opened", "session_request.approved"],
        )
        .await;
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn c25_human_expiry_stays_public_but_placeholder_use_ceiling_and_agent_expiry_do_not() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = c25_fixture().await;
        credential_gate(&f, true).await;
        let (s, made) = credential_api(
            &f,
            "POST",
            "/v1/sessions",
            json!({"cred":"demo","budget":12345678,"uses":12345678}),
        )
        .await;
        assert_eq!(s, 200, "{made}");
        let sid = made["session_id"].as_str().unwrap().to_owned();
        let gid = made["grant_id"].as_str().unwrap().to_owned();
        let rows = audit_records(&f).await;
        let r = rows
            .iter()
            .find(|r| r["kind"] == "session.created" && r["session_id"] == sid)
            .unwrap();
        assert_eq!(r["expires_at"], made["expires_at"]);
        assert!(r.get("has_expiry").is_none());
        assert!(rows
            .iter()
            .find(|r| r["kind"] == "grant.created" && r["session_id"] == sid)
            .unwrap()
            .get("has_expiry")
            .is_none());
        f.shared
            .run(move |c| {
                let row = c
                    .vault
                    .list_placeholders(None)
                    .unwrap()
                    .into_iter()
                    .find(|r| r.grant_id == gid)
                    .unwrap();
                assert_eq!(row.max_uses, 12345678);
                c.vault.consume_placeholder(&row.id).unwrap();
                c.vault.refund_placeholder(&row.id).unwrap();
            })
            .await
            .unwrap();
        let rows = audit_records(&f).await;
        assert!(rows.iter().any(|r| r["kind"] == "placeholder.refunded"));
        for r in rows
            .iter()
            .filter(|r| r["kind"] == "placeholder.issued" || r["kind"] == "placeholder.refunded")
        {
            assert!(r.get("max_uses").is_none());
            assert!(!r.to_string().contains(C25_PIN));
        }
        let id = c25_ask(
            &f,
            json!({"cred":"demo","methods":["GET"],"paths":["/inf"]}),
        )
        .await;
        let made = c25_decide(
            &f,
            &id,
            json!({"overrides":{"infinite":true},"presence":{"passphrase":WIDEN_PASS}}),
        )
        .await;
        let rows = audit_records(&f).await;
        let r = rows
            .iter()
            .find(|r| {
                r["kind"] == "session.created" && r["session_id"] == made["session"]["session_id"]
            })
            .unwrap();
        assert_eq!(
            json!([r["expires_at"], r["has_expiry"], r["infinite"]]),
            json!([null, false, true])
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
async fn c25_bystander_fixture() -> Fixture {
    let f = c25_fixture().await;
    f.shared
        .run(|c| {
            c.vault
                .add_credential(av_store::vault::NewCredential {
                    slug: "broken-health".into(),
                    kind: "http".into(),
                    connector: serde_json::from_value(json!({"host":"api.example.test"})).unwrap(),
                    fields: vec![("token".into(), "FAKE-BYSTANDER-123456789".to_owned().into())],
                    sites: std::collections::BTreeMap::from([(
                        "token".into(),
                        vec!["header:x-key".into()],
                    )]),
                })
                .unwrap();
        })
        .await
        .unwrap();
    f
}
async fn c25_unreadable_fixture() -> Fixture {
    let f = c25_bystander_fixture().await;
    let f = control_session_restart_with_pass(
        f,
        ported_common::seed_panic_side_system_failure,
        Some(WIDEN_PASS),
    )
    .await;
    assert!(f
        .shared
        .run(|c| c.vault.all_secrets().is_err())
        .await
        .unwrap());
    f
}
#[tokio::test]
async fn c25_real_secret_reader_failure_cannot_turn_shape_only_auditing_into_value_logging() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = c25_unreadable_fixture().await;
        let id = c25_ask(&f, c25_greedy(false)).await;
        c25_decide(&f, &id, json!({})).await;
        c25_assert_structure_only(
            &f,
            &[id],
            &["session_request.opened", "session_request.approved"],
        )
        .await;
        credential_finish(&f).await;
        let f = c25_fixture().await;
        let id = c25_ask(
            &f,
            json!({"cred":"demo","methods":["GET"],"paths":["/ordinary"]}),
        )
        .await;
        let made = c25_decide(&f, &id, json!({})).await;
        assert!(made["session"]["session_id"].is_string());
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integrate3_session_request_audit_records_shapes_while_human_pending_retains_secret_and_ordinary_text(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35),async {
  for broken in [false,true]{let f=if broken{c25_unreadable_fixture().await}else{c25_fixture().await};let id=c25_ask(&f,json!({"cred":"demo","paths":[format!("/{C25_VALUE}"),"/plain/path"],"reason":format!("please, my token is {C25_VALUE}")})).await;let rows=audit_records(&f).await;let row=rows.iter().find(|r|r["kind"]=="session_request.opened").unwrap();assert_eq!(row["proposed"],json!(["cred","paths"]));assert_eq!(row["counts"],json!({"paths":2}));c25_assert_structure_only(&f,std::slice::from_ref(&id),&["session_request.opened"]).await;let(s,pending)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;assert_eq!(s,200);assert!(pending.is_array());assert!(f.shared.run(move|c|c.sr_get(id.as_str().unwrap()).unwrap().summary.contains(C25_VALUE)).await.unwrap());credential_finish(&f).await;}
  let f=c25_fixture().await;let id=c25_ask(&f,json!({"cred":"demo","methods":["GET"],"paths":["/repos/**"],"reason":"read the repo list"})).await;let rows=audit_records(&f).await;let r=rows.iter().find(|r|r["kind"]=="session_request.opened").unwrap();assert_eq!(r["request_id"],id);assert_eq!(json!([r["actor"],r["cred"],r["template"]]),json!(["agent","demo",null]));assert_eq!(r["proposed"],json!(["cred","methods","paths"]));assert_eq!(r["counts"],json!({"methods":1,"paths":1}));assert!(!json!(rows).to_string().contains("/repos/**"));assert!(!json!(rows).to_string().contains("read the repo list"));let(s,p)=credential_api(&f,"GET","/v1/session-requests",json!({})).await;assert_eq!(s,200);assert!(p[0]["summary"].as_str().unwrap().contains("/repos/**"));credential_finish(&f).await;
 }).await.unwrap();
}

#[tokio::test]
async fn integrate3_c18_real_ipv4_ipv6_tls_preflight_and_description_refuse_infinite_and_keep_finite_peeks_unsent(
) {
    tokio::time::timeout(std::time::Duration::from_secs(40),async {
  let w=C12World::new().await;
  for door in w.doors.iter().filter(|d|d.remote) {
   let before=w.seen.lock().unwrap().len();
   for (token,ph,infinite) in [(&w.token,&w.ph,true),(&w.f.token,&w.f.ph,false)] {
    let body=serde_json::to_vec(&json!({"method":"GET","path":"/p/demo/safe/x","headers":[["authorization",format!("Bearer {ph}")]]})).unwrap();
    let(status,_,body)=w.wire(door,"POST","/v1/preflight",c12_auth(token),body).await;
    let value:Value=serde_json::from_slice(&body).unwrap();assert_eq!(status,if infinite{403}else{200},"{}: {value}",door.id);if infinite{assert_eq!(value["rule"],"infinite_remote");}
    for(name,args)in [("vault_describe_access",json!({})),("vault_preflight",json!({"cred":"demo","method":"GET","path":"/safe/x"}))] {
     let(status,_,body)=w.wire(door,"POST","/mcp",c12_auth(token),c12_rpc(name,args)).await;assert_eq!(status,200);let(error,value)=c12_tool(&body);if infinite{assert!(error);assert_eq!(value["rule"],"infinite_remote");}else{assert!(!error,"{} {name}: {value}",door.id);assert!(value.get("code").is_none());}assert!(!String::from_utf8_lossy(&body).contains(SECRET));
    }
   }
   assert_eq!(w.seen.lock().unwrap().len(),before,"peek reached real upstream");
  }
  w.finish().await;
 }).await.unwrap();
}

async fn integration_cap(
    f: &Fixture,
    cap: &Value,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> GatewayResponse {
    let r = f
        .daemon
        .pipeline()
        .handle(GatewayRequest {
            method: method.into(),
            path: format!("/p/demo{}", path.split_once('?').map_or(path, |p| p.0)),
            query: path.split_once('?').map_or("", |p| p.1).into(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), cap["token"].as_str().unwrap().into()),
                ("x-key".into(), cap["placeholder"].as_str().unwrap().into()),
                ("content-type".into(), "application/json".into()),
            ],
            body: body.map(|s| s.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;
    let stored = f
        .shared
        .run(|c| {
            use av_core::secret::ExposeSecret;
            c.vault
                .all_secrets()
                .unwrap()
                .iter()
                .any(|s| s.secret.expose_secret() == C25_VALUE)
        })
        .await
        .unwrap();
    if stored {
        assert!(!String::from_utf8_lossy(&r.body).contains(C25_VALUE));
    }
    r
}
async fn integration_surfaces(f: &Fixture) -> Vec<(String, Vec<Value>)> {
    let direct = audit_records(f).await;
    let (s, v) = credential_api(f, "GET", "/v1/audit?limit=5000", json!({})).await;
    assert_eq!(s, 200);
    let read = if v.is_array() {
        v
    } else {
        v["records"].clone()
    };
    let (s, v) = credential_api(
        f,
        "GET",
        "/v1/audit/export?since_seq=0&limit=5000",
        json!({}),
    )
    .await;
    assert_eq!(s, 200);
    vec![
        ("stored".into(), direct),
        ("read".into(), read.as_array().unwrap().clone()),
        ("export".into(), v["rows"].as_array().unwrap().clone()),
    ]
}
async fn integration_absent(f: &Fixture, strip_path: bool, extra: &[&str]) {
    for (name, mut rows) in integration_surfaces(f).await {
        assert!(!rows.is_empty());
        if strip_path {
            for r in &mut rows {
                if r["kind"].as_str().unwrap().starts_with("request.") && r["req"].is_object() {
                    r["req"]["path"] = Value::Null;
                }
            }
        }
        let text = json!(rows).to_string();
        for n in [C25_VALUE, "PLUS+slash", "001122334455667788"]
            .iter()
            .copied()
            .chain(extra.iter().copied())
        {
            assert!(!text.contains(n), "{name} contains {n}");
        }
    }
}
#[tokio::test]
async fn integration_c27_path_route_and_deny_rules_log_indexes_before_and_after_rotation() {
    tokio::time::timeout(std::time::Duration::from_secs(40),async{
  for routes in [false,true]{let f=c25_fixture().await;let mut proposal=json!({"cred":"demo","methods":["GET"],"paths":[format!("/{C25_VALUE}")],"reason":"job"});if routes{proposal["paths"]=json!(["/elsewhere/**",format!("/{C25_VALUE}")]);proposal["routes"]=json!([{"methods":["GET"],"paths":["/elsewhere/**"]},{"methods":["GET"],"paths":[format!("/{C25_VALUE}")]}]);}let id=c25_ask(&f,proposal).await;let made=c25_decide(&f,&id,json!({})).await;let cap=&made["session"];let policy=control_session_policy(&f,cap["grant_id"].as_str().unwrap()).await;assert!(policy["paths"].as_array().unwrap().contains(&json!(format!("/{C25_VALUE}"))));
   assert_eq!(integration_cap(&f,cap,"GET",&format!("/{C25_VALUE}"),None).await.status,200);assert!(f.up.hits.lock().unwrap().last().unwrap().url.ends_with(&format!("/{C25_VALUE}")));let rows=audit_records(&f).await;let row=rows.iter().find(|r|r["kind"]=="request.allowed").unwrap();assert_eq!(row["req"]["path_rule"],if routes{1}else{0});assert_eq!(row["req"]["route_rule"],if routes{json!(1)}else{Value::Null});assert_eq!(row["req"]["method"],"GET");assert!(row["req"].get("path_glob_matched").is_none());assert!(row["req"].get("route_matched").is_none());assert_eq!(integration_cap(&f,cap,"GET","/not-the-path",None).await.status,403);integration_absent(&f,false,&[]).await;
   if routes{c25_rotate(&f,"ghp_NEWVALUE99887766554433221100ff").await;let gid=cap["grant_id"].as_str().unwrap().to_owned();let ph=f.shared.run(move|c|c.vault.issue_placeholder(av_store::vault::IssueOptions{grant_id:gid,..Default::default()}).unwrap().placeholder).await.unwrap();let mut fresh=cap.clone();fresh["placeholder"]=json!(ph);assert_eq!(integration_cap(&f,&fresh,"GET",&format!("/{C25_VALUE}"),None).await.status,200);assert_eq!(integration_cap(&f,&fresh,"GET","/not-the-path",None).await.status,403);let rows=audit_records(&f).await;let allowed=rows.iter().filter(|r|r["kind"]=="request.allowed").collect::<Vec<_>>();assert_eq!(allowed.len(),2);assert_eq!(allowed[1]["req"]["path_rule"],1);assert_eq!(allowed[1]["req"]["route_rule"],1);integration_absent(&f,true,&[]).await;}credential_finish(&f).await;
  }
  let f=c25_fixture().await;let id=c25_ask(&f,json!({"cred":"demo","methods":["GET"],"paths":["/**"],"reason":"job"})).await;let made=c25_decide(&f,&id,json!({})).await;credential_gate(&f,false).await;let cap=&made["session"];let(s,v)=credential_api(&f,"POST","/v1/sessions/narrow",json!({"sid":cap["session_id"],"narrow":{"deny_paths":[format!("/{C25_VALUE}")]}})).await;assert_eq!(s,200,"{v}");let before=f.up.hits.lock().unwrap().len();assert_eq!(integration_cap(&f,cap,"GET",&format!("/{C25_VALUE}"),None).await.status,403);assert_eq!(f.up.hits.lock().unwrap().len(),before);let rows=audit_records(&f).await;let row=rows.iter().rev().find(|r|r["kind"]=="request.denied").unwrap();assert_eq!(row["rule"],"deny_paths:0");assert_eq!(control_session_policy(&f,cap["grant_id"].as_str().unwrap()).await["deny_paths"][0],format!("/{C25_VALUE}"));assert_eq!(integration_cap(&f,cap,"GET","/ordinary",None).await.status,200);integration_absent(&f,false,&[]).await;credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_c27_bulk_logs_only_minted_ids_and_counts_unknown_attacker_ids() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let f=c25_fixture().await;let real=c25_ask(&f,json!({"cred":"demo","methods":["GET"],"paths":["/x"],"reason":"job"})).await;credential_gate(&f,true).await;let before=f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap();let(s,r)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":real,"kind":"session","granted":true},{"id":C25_VALUE,"kind":"session","granted":true}]})).await;assert_eq!(s,200,"{r}");assert_eq!(r["decided"][0]["id"],real);assert_eq!(r["decided"][0]["outcome"],"decided");assert_eq!(r["decided"][1]["id"],C25_VALUE);assert_eq!(r["decided"][1]["outcome"],"skipped");
 for decisions in [json!([{"id":C25_PIN,"kind":"session","granted":false},{"id":format!("apr_{C25_PIN}"),"kind":"request","granted":false}]),json!([{"id":real,"kind":"session","granted":false}])]{let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":decisions})).await;assert_eq!(s,200,"{v}");}
 let rows=audit_records(&f).await;let rows=rows.iter().filter(|r|r["kind"]=="pending.decided_many").collect::<Vec<_>>();assert_eq!(rows.len(),3);for (r,expected)in rows.iter().zip([json!({"granted":[real],"denied":[],"skipped":[],"unknown":1}),json!({"granted":[],"denied":[],"skipped":[],"unknown":2}),json!({"granted":[],"denied":[real],"skipped":[real],"unknown":0})]){let mut own=(*r).clone();for k in ["seq","ts","kind","prev_hash","hash"]{own.as_object_mut().unwrap().remove(k);}assert_eq!(own,expected);}assert_eq!(f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap(),before+1);integration_absent(&f,false,&[C25_PIN]).await;credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_c26_first_use_writes_need_fresh_proof_for_create_and_decide_but_reads_use_window(
) {
    tokio::time::timeout(std::time::Duration::from_secs(40),async{
 let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;credential_gate(&f,true).await;let body=json!({"cred":"demo","methods":["GET","POST","DELETE"],"approval":"first-use"});let(s,v)=credential_api(&f,"POST","/v1/sessions",body.clone()).await;assert_eq!((s,v["rule"].as_str()),(401,Some("fresh_presence")));let mut proof=body;proof["presence"]=json!({"passphrase":WIDEN_PASS});let(s,made)=credential_api(&f,"POST","/v1/sessions",proof).await;assert_eq!(s,200,"{made}");assert_eq!(control_session_policy(&f,made["grant_id"].as_str().unwrap()).await["approval"],"first-use");let(_,listed)=credential_api(&f,"GET","/v1/sessions",json!({})).await;assert_eq!(listed.as_array().unwrap().iter().find(|r|r["id"]==made["session_id"]).unwrap()["elevated"],json!(["approval_auto_writes"]));credential_gate(&f,true).await;let(s,plain)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","methods":["GET","HEAD"],"approval":"first-use"})).await;assert_eq!(s,200,"{plain}");let(_,listed)=credential_api(&f,"GET","/v1/sessions",json!({})).await;assert_eq!(listed.as_array().unwrap().iter().find(|r|r["id"]==plain["session_id"]).unwrap()["elevated"],json!([]));
 for methods in [json!(["GET","POST"]),json!(["GET","POST","DELETE"])]{let id=c25_ask(&f,json!({"cred":"demo","methods":methods,"reason":"job"})).await;credential_gate(&f,true).await;let overrides=json!({"approval":"first-use","methods":["GET","POST"]});let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":overrides})).await;assert_eq!((s,v["rule"].as_str()),(401,Some("fresh_presence")));let rid=id.as_str().unwrap().to_owned();assert_eq!(f.shared.run(move|c|c.sr_get(&rid).unwrap().state).await.unwrap(),"pending");let extra=if methods.as_array().unwrap().len()==2{json!({"overrides":overrides,"presence":{"passphrase":WIDEN_PASS}})}else{json!({"overrides":{"approval":"first-use","methods":["GET"]}})};let made=c25_decide(&f,&id,extra).await;let p=control_session_policy(&f,made["session"]["grant_id"].as_str().unwrap()).await;assert_eq!(p["approval"],"first-use");if methods.as_array().unwrap().len()==3{assert_eq!(p["methods"],json!(["GET"]));}}
 let a=c25_ask(&f,json!({"cred":"demo","methods":["GET"]})).await;let b=c25_ask(&f,json!({"cred":"demo","methods":["GET","POST"]})).await;credential_gate(&f,true).await;let decisions=json!([{"id":a,"kind":"session","granted":true},{"id":b,"kind":"session","granted":true,"overrides":{"approval":"first-use"}}]);let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":decisions})).await;assert_eq!((s,v["rule"].as_str()),(401,Some("fresh_presence")));let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":decisions,"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");
 credential_gate(&f,true).await;let(s,made)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","methods":["GET","POST"],"approval":"on-write"})).await;assert_eq!(s,200);credential_gate(&f,false).await;let(s,v)=credential_api(&f,"POST","/v1/sessions/narrow",json!({"sid":made["session_id"],"narrow":{"approval":"first-use"}})).await;assert_eq!(s,200,"{v}");assert_eq!(control_session_policy(&f,made["grant_id"].as_str().unwrap()).await["approval"],"on-write");let(_,listed)=credential_api(&f,"GET","/v1/sessions",json!({})).await;assert_eq!(listed.as_array().unwrap().iter().find(|r|r["id"]==made["session_id"]).unwrap()["elevated"],json!([]));assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}

async fn integration_tool(
    f: &Fixture,
    token: Option<&str>,
    name: &str,
    args: Value,
) -> (bool, Value) {
    let token = token.map(str::to_owned);
    let lookup = token.clone();
    let session = f
        .shared
        .run(move |c| lookup.and_then(|s| c.vault.session_by_token(&s).unwrap()))
        .await
        .unwrap();
    let reply=f.daemon.mcp().handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),session,token,None).await.unwrap();
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains(SECRET));
    assert!(!text.contains(C25_VALUE));
    (
        reply["result"]["isError"].as_bool().unwrap_or(false),
        serde_json::from_str(text).unwrap(),
    )
}
async fn integration_create(f: &Fixture, mut spec: Value) -> Value {
    let elevated = spec["approval"] == "auto" || spec["infinite"] == true;
    let mut factor = f
        .shared
        .run(|c| c.vault.has_passphrase().unwrap())
        .await
        .unwrap();
    if elevated && !factor {
        credential_factor(f).await;
        factor = true;
    }
    if factor {
        credential_gate(f, true).await;
    }
    if elevated {
        spec["presence"] = json!({"passphrase":WIDEN_PASS});
    }
    let (s, v) = credential_api(f, "POST", "/v1/sessions", spec).await;
    assert_eq!(s, 200, "{v}");
    v
}
async fn integration_http(
    f: &Fixture,
    cap: &Value,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Value {
    let mut args = json!({"cred":"demo","method":method,"path":path,"reason":"e2e"});
    if let Some(body) = body {
        args["body"] = json!(body);
    }
    let (error, v) = integration_tool(f, cap["token"].as_str(), "vault_http", args).await;
    assert!(!error, "{v}");
    v
}
#[tokio::test]
async fn integration_e2e_rate_quota_payload_and_route_limits_are_effective_through_mcp() {
    tokio::time::timeout(std::time::Duration::from_secs(40),async{
 let f=Fixture::new(&["header:x-key"]).await;for(kind,limit)in [("rate",json!("2/min")),("quota",json!("2/day"))]{let mut spec=json!({"cred":"demo","methods":["GET"]});spec[kind]=limit;let cap=integration_create(&f,spec).await;for _ in 0..2{assert_eq!(integration_http(&f,&cap,"GET",&format!("/{kind}"),None).await["status"],200);}let before=f.up.hits.lock().unwrap().len();let r=integration_http(&f,&cap,"GET",&format!("/{kind}"),None).await;assert_eq!(r["status"],429);assert!(r.to_string().contains("AV_QUOTA_EXCEEDED"));assert!(r.to_string().contains("retry_after"));assert_eq!(f.up.hits.lock().unwrap().len(),before);}
 let plain=integration_create(&f,json!({"cred":"demo"})).await;for _ in 0..3{assert_eq!(integration_http(&f,&plain,"GET","/plain",None).await["status"],200);}assert_eq!(audit_records(&f).await.iter().filter(|r|r["kind"]=="request.throttled").count(),2);
 let cap=integration_create(&f,json!({"cred":"demo","methods":["GET","POST"],"approval":"auto","payload":{"json":{"/state":{"one_of":["open"]}}}})).await;let before=f.up.hits.lock().unwrap().len();let r=integration_http(&f,&cap,"POST","/issues",Some("{\"state\":\"closed\"}")).await;assert_eq!(r["status"],403);assert_eq!(serde_json::from_str::<Value>(r["body"].as_str().unwrap()).unwrap()["rule"],"payload:json:0:one_of");assert!(!r.to_string().contains("closed"));assert_eq!(f.up.hits.lock().unwrap().len(),before);assert_eq!(integration_http(&f,&cap,"POST","/issues",Some("{\"state\":\"open\"}")).await["status"],200);assert_eq!(f.up.hits.lock().unwrap().last().unwrap().body.as_deref(),Some(b"{\"state\":\"open\"}".as_slice()));
 let cap=integration_create(&f,json!({"cred":"demo","methods":["GET","POST"],"approval":"auto","routes":[{"methods":["GET"],"paths":["/repos/**"]},{"methods":["POST"],"paths":["/repos/*/issues"]}]})).await;let before=f.up.hits.lock().unwrap().len();for(method,path)in[("POST","/repos/a/pulls"),("GET","/user")]{assert_eq!(integration_http(&f,&cap,method,path,(method=="POST").then_some("{}")).await["status"],403);}assert_eq!(f.up.hits.lock().unwrap().len(),before);for(method,path)in[("POST","/repos/a/issues"),("GET","/repos/a/pulls")]{assert_eq!(integration_http(&f,&cap,method,path,(method=="POST").then_some("{}")).await["status"],200);}assert_eq!(f.up.hits.lock().unwrap().len(),before+2);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_e2e_mcp_concurrency_refusal_releases_its_slot_after_the_real_call() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let f=Fixture::new(&["header:x-key"]).await;let cap=integration_create(&f,json!({"cred":"demo","max_concurrent":1})).await;let release=Arc::new(tokio::sync::Notify::new());*f.up.gate.lock().unwrap()=Some(release.clone());let first=integration_http(&f,&cap,"GET","/slow",None);tokio::pin!(first);tokio::select!{_=&mut first=>panic!("upstream did not wait"),_=async{loop{if !f.up.hits.lock().unwrap().is_empty(){break;}tokio::task::yield_now().await;}}=>{}}
 let r=integration_http(&f,&cap,"GET","/second",None).await;assert_eq!(r["status"],429);assert!(r.to_string().contains("AV_QUOTA_EXCEEDED"));assert_eq!(f.up.hits.lock().unwrap().len(),1);*f.up.gate.lock().unwrap()=None;release.notify_one();assert_eq!(first.await["status"],200);assert_eq!(integration_http(&f,&cap,"GET","/second",None).await["status"],200);assert_eq!(f.up.hits.lock().unwrap().len(),2);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_e2e_redirect_policy_and_midrun_keep_rotation_are_observed_by_mcp() {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let follows = integration_create(&f, json!({"cred":"demo","redirects":1})).await;
        let never = integration_create(&f, json!({"cred":"demo"})).await;
        f.up.sequence.lock().unwrap().extend([
            Ok(redirect_reply(302, "/final")),
            Ok(done_reply()),
            Ok(redirect_reply(302, "https://elsewhere.invalid/x")),
            Ok(redirect_reply(302, "/final")),
        ]);
        let r = integration_http(&f, &follows, "GET", "/start", None).await;
        assert_eq!(r["status"], 200);
        assert_eq!(r["body"], "done");
        assert_eq!(
            f.up.hits
                .lock()
                .unwrap()
                .iter()
                .map(|r| url::Url::parse(&r.url).unwrap().path().to_owned())
                .collect::<Vec<_>>(),
            vec!["/start", "/final"]
        );
        assert_eq!(
            audit_records(&f)
                .await
                .iter()
                .filter(|r| r["kind"] == "request.redirect_followed")
                .count(),
            1
        );
        let r = integration_http(&f, &follows, "GET", "/out", None).await;
        assert_eq!(r["status"], 302);
        assert_eq!(r["headers"]["av-redirect-stopped"], "host");
        assert!(f
            .up
            .hits
            .lock()
            .unwrap()
            .iter()
            .all(|r| !r.url.contains("elsewhere.invalid")));
        assert_eq!(
            integration_http(&f, &never, "GET", "/start", None).await["status"],
            302
        );
        assert_eq!(
            f.up.hits
                .lock()
                .unwrap()
                .iter()
                .filter(|r| url::Url::parse(&r.url).unwrap().path() == "/final")
                .count(),
            1
        );
        credential_finish(&f).await;
        let f = Fixture::new(&["header:x-key"]).await;
        let cap = integration_create(&f, json!({"cred":"demo"})).await;
        f.reply(
            200,
            "application/json",
            json!({"old":SECRET,"new":CONTROL_ROTATED}).to_string(),
        );
        for i in 0..30 {
            if i == 5 {
                f.shared
                    .run(|c| {
                        c.vault
                            .rotate_credential(
                                "demo",
                                av_store::vault::RotateOptions {
                                    field: None,
                                    value: CONTROL_ROTATED.to_owned().into(),
                                    mode: av_store::vault::RotateMode::Keep,
                                    retire_ms: 3600000,
                                    expires_at: None,
                                },
                            )
                            .unwrap()
                    })
                    .await
                    .unwrap();
            }
            let r = integration_http(&f, &cap, "GET", &format!("/loop/{i}"), None).await;
            assert_eq!(r["status"], 200);
            assert!(!r.to_string().contains(SECRET));
            assert!(!r.to_string().contains(CONTROL_ROTATED));
        }
        let hits = f.up.hits.lock().unwrap().clone();
        assert_eq!(hits.len(), 30);
        for (i, r) in hits.iter().enumerate() {
            assert_eq!(
                r.headers.iter().find(|(n, _)| n == "x-key").unwrap().1,
                if i < 5 { SECRET } else { CONTROL_ROTATED }
            );
        }
        drop(hits);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn integration_e2e_auto_proof_is_fresh_without_a_window_and_mcp_write_runs_unheld() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        credential_factor(&f).await;
        let body = json!({"cred":"demo","approval":"auto","methods":["GET","POST"]});
        credential_gate(&f, true).await;
        let before = f
            .shared
            .run(|c| c.vault.sessions().unwrap().len())
            .await
            .unwrap();
        let (s, v) = credential_api(&f, "POST", "/v1/sessions", body.clone()).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(
            f.shared
                .run(|c| c.vault.sessions().unwrap().len())
                .await
                .unwrap(),
            before
        );
        let (s, _) = credential_api(&f, "POST", "/v1/sessions", json!({"cred":"demo"})).await;
        assert_eq!(s, 200);
        assert_eq!(
            f.shared
                .run(|c| c.vault.sessions().unwrap().len())
                .await
                .unwrap(),
            before + 1
        );
        credential_gate(&f, false).await;
        let rows_before = audit_records(&f).await.len();
        let mut body = body;
        body["presence"] = json!({"passphrase":WIDEN_PASS});
        let (s, cap) = credential_api(&f, "POST", "/v1/sessions", body).await;
        assert_eq!(s, 200, "{cap}");
        assert!(cap["token"].is_string() && cap["placeholder"].is_string());
        let rows = audit_records(&f).await;
        let rows = &rows[rows_before..];
        assert!(rows
            .iter()
            .any(|r| r["kind"] == "presence.verified" && r["fresh"] == true));
        assert!(!rows.iter().any(|r| r["kind"] == "presence.window_opened"));
        assert_eq!(
            rows.iter()
                .find(|r| r["kind"] == "session.created")
                .unwrap()["elevated"],
            json!(["approval_auto_writes"])
        );
        assert_eq!(
            integration_http(
                &f,
                &cap,
                "POST",
                "/repos/x/issues",
                Some("{\"title\":\"t\"}")
            )
            .await["status"],
            200
        );
        let hits = f.up.hits.lock().unwrap().clone();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].method, "POST");
        assert_eq!(
            hits[0]
                .headers
                .iter()
                .find(|(n, _)| n == "x-key")
                .unwrap()
                .1,
            SECRET
        );
        drop(hits);
        assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_e2e_model_spend_and_multicred_placeholder_handoff_reach_only_the_intended_credentials(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let f=model_fixture(json!({})).await;let cap=integration_create(&f,json!({"cred":"demo","methods":["GET","POST"],"approval":"auto","spend_tokens":200})).await;f.reply(200,"application/json",json!({"usage":{"prompt_tokens":5,"completion_tokens":7}}).to_string());let r=integration_http(&f,&cap,"POST","/v1/chat/completions",Some("{\"model\":\"gpt-4.1-mini\",\"max_tokens\":5000,\"messages\":[]}")).await;assert_eq!(r["status"],403);assert_eq!(serde_json::from_str::<Value>(r["body"].as_str().unwrap()).unwrap()["rule"],"spend");assert!(f.up.hits.lock().unwrap().is_empty());assert_eq!(integration_http(&f,&cap,"POST","/v1/chat/completions",Some("{\"model\":\"gpt-4.1-mini\",\"max_tokens\":20,\"messages\":[]}")).await["status"],200);let gid=cap["grant_id"].as_str().unwrap().to_owned();let state=f.shared.run(move|c|c.vault.grant_runtime(&gid).unwrap().unwrap().spend.unwrap()).await.unwrap();assert_eq!(state["tokens_used"],12);assert_eq!(state["reserved"],json!({}));let hits=f.up.hits.lock().unwrap().clone();assert_eq!(hits.len(),1);assert_eq!(url::Url::parse(&hits[0].url).unwrap().host_str(),Some("api.openai.com"));assert_eq!(hits[0].headers.iter().find(|(n,_)|n=="x-key").unwrap().1,SECRET);drop(hits);credential_finish(&f).await;
 let f=Fixture::new(&["header:x-key"]).await;let(s,v)=credential_api(&f,"POST","/v1/credentials",json!({"slug":"openai","kind":"openai","host":"api.openai.com","value":"OTHER-SECRET-0099887766","sites":["header:authorization:Bearer"]})).await;assert_eq!(s,200,"{v}");let cap=integration_create(&f,json!({"grants":[{"cred":"demo"},{"cred":"openai"}]})).await;let sid=cap["session_id"].as_str().unwrap().to_owned();let rows=f.shared.run(move|c|c.vault.list_placeholders(Some(&sid)).unwrap()).await.unwrap();assert!(rows.len()>=2);for g in cap["grants"].as_array().unwrap(){assert!(g["placeholder"].as_str().unwrap().starts_with("av1."));assert!(rows.iter().any(|p|p.grant_id==g["grant_id"].as_str().unwrap()));}assert_eq!(control_session_request(&f,&cap,"demo","GET","/user").await.status,200);assert_eq!(f.up.hits.lock().unwrap().last().unwrap().headers.iter().find(|(n,_)|n=="x-key").unwrap().1,SECRET);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_e2e_infinite_mcp_metadata_and_live_narrowing_take_effect_before_next_request()
{
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let cap = integration_create(
            &f,
            json!({"cred":"demo","methods":["GET","POST"],"approval":"auto"}),
        )
        .await;
        assert_eq!(
            integration_http(&f, &cap, "POST", "/w", Some("{}")).await["status"],
            200
        );
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/sessions/narrow",
            json!({"sid":cap["session_id"],"narrow":{"methods":["GET"]}}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            integration_http(&f, &cap, "POST", "/w", Some("{}")).await["status"],
            403
        );
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        assert_eq!(
            integration_http(&f, &cap, "GET", "/r", None).await["status"],
            200
        );
        let sid = cap["session_id"].as_str().unwrap().to_owned();
        assert_eq!(
            f.shared
                .run(move |c| c.vault.session(&sid).unwrap().unwrap().state)
                .await
                .unwrap(),
            av_store::model::SessionState::Active
        );
        let cap = integration_create(&f, json!({"cred":"demo","infinite":true})).await;
        assert_eq!(cap["infinite"], true);
        let (_, listed) = credential_api(&f, "GET", "/v1/sessions", json!({})).await;
        let row = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == cap["session_id"])
            .unwrap();
        assert_eq!(row["infinite"], true);
        assert!(row["expires_at"].is_null());
        let (error, status) =
            integration_tool(&f, cap["token"].as_str(), "vault_status", json!({})).await;
        assert!(!error);
        assert_eq!(status["session"]["id"], cap["session_id"]);
        assert_eq!(status["session"]["infinite"], true);
        assert_eq!(
            integration_cap(&f, &cap, "GET", "/user", None).await.status,
            200
        );
        let (s, v) = credential_api(&f, "POST", "/v1/panic", json!({})).await;
        assert_eq!(s, 200);
        assert!(v["revoked_sessions"].as_u64().unwrap() >= 1);
        let sid = cap["session_id"].as_str().unwrap().to_owned();
        assert_eq!(
            f.shared
                .run(move |c| c.vault.session(&sid).unwrap().unwrap().state)
                .await
                .unwrap(),
            av_store::model::SessionState::Revoked
        );
        let before = f.up.hits.lock().unwrap().len();
        assert_ne!(
            integration_cap(&f, &cap, "GET", "/user", None).await.status,
            200
        );
        assert_eq!(f.up.hits.lock().unwrap().len(), before);
        assert_eq!(
            audit_records(&f)
                .await
                .iter()
                .filter(|r| r["kind"] == "panic.triggered")
                .count(),
            1
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_e2e_template_snapshot_collect_and_gateway_enforce_the_version_the_agent_saw() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let t = control_template_save(
            &f,
            "reader",
            json!({"cred":"demo","methods":["GET"],"paths":["/repos/**"]}),
            false,
        )
        .await;
        assert_eq!(t["version"], 1);
        let (error, asked) = integration_tool(
            &f,
            None,
            "vault_request_session",
            json!({"template":"reader","reason":"read the repo"}),
        )
        .await;
        assert!(!error, "{asked}");
        assert_eq!(asked["state"], "pending");
        assert_eq!(
            control_template_save(
                &f,
                "reader",
                json!({"cred":"demo","methods":["GET","POST"],"paths":["/**"]}),
                false
            )
            .await["version"],
            2
        );
        let (s, made) = credential_api(
            &f,
            "POST",
            "/v1/session-requests/decide",
            json!({"id":asked["request_id"],"granted":true}),
        )
        .await;
        assert_eq!(s, 200, "{made}");
        let cap = &made["session"];
        let rows = audit_records(&f).await;
        let row = rows
            .iter()
            .rev()
            .find(|r| r["kind"] == "session.created")
            .unwrap();
        assert_eq!(row["template"], "reader");
        assert_eq!(row["template_version"], 1);
        let p = control_session_policy(&f, cap["grant_id"].as_str().unwrap()).await;
        assert_eq!(p["methods"], json!(["GET"]));
        assert_eq!(p["paths"], json!(["/repos/**"]));
        let (error, polled) = integration_tool(
            &f,
            None,
            "vault_request_session",
            json!({"poll_id":asked["request_id"],"poll_secret":asked["poll_secret"]}),
        )
        .await;
        assert!(!error, "{polled}");
        assert_eq!(polled["state"], "approved");
        assert_eq!(
            integration_http(&f, cap, "GET", "/repos/a", None).await["status"],
            200
        );
        for (method, path) in [("POST", "/repos/a"), ("GET", "/user")] {
            assert_eq!(
                integration_http(&f, cap, method, path, (method == "POST").then_some("{}")).await
                    ["status"],
                403
            );
        }
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn integration_e2e_held_preview_notifier_agent_status_and_approved_mcp_resend_execute_once() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let f=Fixture::new(&["header:authorization:Bearer"]).await;let cap=integration_create(&f,json!({"cred":"demo","methods":["GET","POST"],"approval":"on-write"})).await;let mut notices=f.shared.run(|c|c.notifier.as_ref().unwrap().subscribe(vec![]).unwrap()).await.unwrap();let _=notices.recv().await.unwrap();let args=json!({"cred":"demo","method":"POST","path":"/repos/a/issues","body":"{\"title\":\"<b>hello</b>\"}","reason":"file the bug"});let(error,r)=integration_tool(&f,cap["token"].as_str(),"vault_http",args.clone()).await;assert!(!error,"{r}");assert_eq!(r["status"],202);let held:Value=serde_json::from_str(r["body"].as_str().unwrap()).unwrap();let id=&held["approval_id"];assert!(id.is_string());assert!(f.up.hits.lock().unwrap().is_empty());let frame=notices.recv().await.unwrap();let entry=payloads(&frame).next().unwrap();assert_eq!(entry["id"],*id);assert_eq!(entry["kind"],"request");assert!(!frame.contains("av1.")&&!frame.contains(SECRET));
 let(s,listed)=credential_api(&f,"GET","/v1/approvals",json!({})).await;assert_eq!(s,200);let item=listed.as_array().unwrap().iter().find(|r|r["id"]==*id).unwrap();let preview=&item["preview"];assert_eq!(preview["method"],"POST");assert_eq!(preview["path"],"/repos/a/issues");assert!(preview["body"]["text"].as_str().unwrap().contains("hello"));assert!(!preview["headers"].as_array().unwrap().iter().any(|r|r[0].as_str().unwrap().eq_ignore_ascii_case("authorization")));assert!(preview["placeholders"].as_array().unwrap().iter().any(|r|r["label"]=="demo.token"));assert!(!listed.to_string().contains("av1."));let(_,status)=integration_tool(&f,cap["token"].as_str(),"vault_approval_status",json!({"approval_id":id})).await;assert!(status.get("preview").is_none());let(s,v)=credential_api(&f,"POST","/v1/approvals",json!({"id":id,"granted":true})).await;assert_eq!(s,200,"{v}");for replay in [false,true]{let(error,r)=integration_tool(&f,cap["token"].as_str(),"vault_http",args.clone()).await;assert!(!error);assert_eq!(r["status"],200);if replay{assert_eq!(r["headers"]["av-replayed"],"true");}assert_eq!(f.up.hits.lock().unwrap().len(),1);}let hits=f.up.hits.lock().unwrap().clone();assert_eq!(hits[0].body.as_deref(),Some(b"{\"title\":\"<b>hello</b>\"}".as_slice()));assert_eq!(hits[0].headers.iter().find(|(n,_)|n=="authorization").unwrap().1,format!("Bearer {SECRET}"));drop(hits);assert_eq!(audit_records(&f).await.iter().filter(|r|r["kind"]=="approval.replayed").count(),1);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_e2e_burned_placeholder_replay_tripwire_revokes_before_response_and_mcp_is_dead(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let cap = integration_create(&f, json!({"cred":"demo"})).await;
        let gid = cap["grant_id"].as_str().unwrap().to_owned();
        let spent = f
            .shared
            .run(move |c| {
                let p = c
                    .vault
                    .issue_placeholder(av_store::vault::IssueOptions {
                        grant_id: gid,
                        ..Default::default()
                    })
                    .unwrap();
                c.vault.burn_placeholder(&p.row.id, "spent").unwrap();
                p.placeholder
            })
            .await
            .unwrap();
        let mut dead = cap.clone();
        dead["placeholder"] = json!(spent);
        let sid = cap["session_id"].as_str().unwrap().to_owned();
        let off = integration_cap(&f, &dead, "GET", "/user", None).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&off.body).unwrap()["code"],
            "AV_PH_REPLAY"
        );
        let s = sid.clone();
        assert_eq!(
            f.shared
                .run(move |c| c.vault.session(&s).unwrap().unwrap().state)
                .await
                .unwrap(),
            av_store::model::SessionState::Active
        );
        assert!(!audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "tripwire.fired"));
        assert_eq!(
            credential_api(&f, "POST", "/v1/tripwires", json!({"enabled":true}))
                .await
                .0,
            200
        );
        let on = integration_cap(&f, &dead, "GET", "/user", None).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&on.body).unwrap()["code"],
            "AV_PH_REPLAY"
        );
        assert_eq!(
            f.shared
                .run(move |c| c.vault.session(&sid).unwrap().unwrap().state)
                .await
                .unwrap(),
            av_store::model::SessionState::Revoked
        );
        let rows = audit_records(&f).await;
        let fired = rows
            .iter()
            .filter(|r| r["kind"] == "tripwire.fired")
            .collect::<Vec<_>>();
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0]["rule_id"], "replay");
        let (error, v) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_http",
            json!({"cred":"demo","method":"GET","path":"/user","reason":"e2e"}),
        )
        .await;
        assert!(error || v["status"] != 200);
        assert!(f.up.hits.lock().unwrap().is_empty());
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_e2e_preflight_audit_only_and_activity_counts_only_the_real_request() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let cap = integration_create(&f, json!({"cred":"demo","methods":["GET","POST"]})).await;
        assert_eq!(
            integration_http(&f, &cap, "GET", "/repos/a", None).await["status"],
            200
        );
        let before = store_snapshot(&f).await;
        let rows = audit_records(&f).await;
        let (error, v) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_preflight",
            json!({"cred":"demo","method":"POST","path":"/repos/a/issues","body":"{}"}),
        )
        .await;
        assert!(!error);
        assert_eq!(v["would"], "hold");
        assert_eq!(store_snapshot(&f).await, before);
        let after = audit_records(&f).await;
        assert_eq!(after.len(), rows.len() + 1);
        assert_eq!(after.last().unwrap()["kind"], "request.preflighted");
        assert_eq!(after.last().unwrap()["would"], "hold");
        assert_eq!(after.last().unwrap()["session_id"], cap["session_id"]);
        let req = GatewayRequest {
            method: "GET".into(),
            path: "/p/demo/user".into(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), cap["token"].as_str().unwrap().into()),
                ("x-key".into(), cap["placeholder"].as_str().unwrap().into()),
            ],
            ..Default::default()
        };
        let v = f.daemon.pipeline().preflight(req, false).await.unwrap();
        assert_eq!(v["would"], "allow");
        assert_eq!(store_snapshot(&f).await, before);
        assert_eq!(audit_records(&f).await.len(), after.len() + 1);
        assert_eq!(f.up.hits.lock().unwrap().len(), 1);
        assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
        let (s, shown) = credential_api(
            &f,
            "GET",
            &format!(
                "/v1/sessions/detail?sid={}",
                cap["session_id"].as_str().unwrap()
            ),
            json!({}),
        )
        .await;
        assert_eq!(s, 200, "{shown}");
        assert_eq!(
            shown["activity"]["requests"],
            json!({"allowed":1,"denied":0,"held":0})
        );
        assert_eq!(
            shown["activity"]["paths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| json!([p["method"], p["path"], p["count"]]))
                .collect::<Vec<_>>(),
            vec![json!(["GET", "/repos/a", 1])]
        );
        assert_eq!(shown["grants"][0]["budget"]["used"], 1);
        let (s, v) = credential_api(
            &f,
            "GET",
            "/v1/audit?kind=request.preflighted&limit=10",
            json!({}),
        )
        .await;
        assert_eq!(s, 200);
        let rows = if v.is_array() {
            v
        } else {
            v["records"].clone()
        };
        assert_eq!(
            rows.as_array()
                .unwrap()
                .iter()
                .filter(|r| r["kind"] == "request.preflighted")
                .count(),
            2
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn integration_e2e_per_grant_expiry_denies_mcp_and_gateway_while_other_grant_and_session_live(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let mut f=Fixture::new(&["header:x-key"]).await;assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"other","kind":"http","host":"api.example.test","value":"OTHER-SECRET-0099887766","sites":["header:x-key"]})).await.0,200);let cap=integration_create(&f,json!({"grants":[{"cred":"demo","grant_ttl_minutes":1},{"cred":"other"}]})).await;for cred in ["demo","other"]{let(error,v)=integration_tool(&f,cap["token"].as_str(),"vault_http",json!({"cred":cred,"method":"GET","path":format!("/{cred}"),"reason":"e2e"})).await;assert!(!error);assert_eq!(v["status"],200);}assert_eq!(f.up.hits.lock().unwrap().len(),2);let sid=cap["session_id"].as_str().unwrap().to_owned();let gid=cap["grants"][0]["grant_id"].as_str().unwrap().to_owned();let s=sid.clone();f=control_session_restart_after_seed(f,move|dir|ported_common::seed_gateway_rows(dir,&s,&gid,&json!({}),&json!({"expires_at":"2000-01-01T00:00:00.000Z"}))).await;
 let(error,v)=integration_tool(&f,cap["token"].as_str(),"vault_http",json!({"cred":"demo","method":"GET","path":"/demo","reason":"e2e"})).await;assert!(error);assert_eq!(v["code"],"AV_GRANT_EXPIRED");assert_eq!(f.up.hits.lock().unwrap().len(),2);assert_ne!(control_session_request(&f,&cap,"demo","GET","/again").await.status,200);assert_eq!(f.up.hits.lock().unwrap().len(),2);let(error,v)=integration_tool(&f,cap["token"].as_str(),"vault_http",json!({"cred":"other","method":"GET","path":"/other","reason":"e2e"})).await;assert!(!error);assert_eq!(v["status"],200);let hits=f.up.hits.lock().unwrap().clone();assert_eq!(hits.len(),3);assert_eq!(hits.last().unwrap().headers.iter().find(|(n,_)|n=="x-key").unwrap().1,"OTHER-SECRET-0099887766");drop(hits);assert_eq!(f.shared.run(move|c|c.vault.session(&sid).unwrap().unwrap().state).await.unwrap(),av_store::model::SessionState::Active);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_d1_unknown_override_keys_and_nonobjects_refuse_atomically_on_single_and_bulk_routes(
) {
    tokio::time::timeout(std::time::Duration::from_secs(40),async{
 let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;
 for(overrides,named)in[(json!({"hosts":["127.0.0.1"]}),"hosts"),(json!({"deny_paths":["/admin/**"]}),"deny_paths"),(json!({"methods":["GET"],"not_a_field":1}),"not_a_field"),(json!("budget=5"),"object"),(json!(["budget"]),"object")]{let id=c25_ask(&f,json!({"cred":"demo","methods":["GET"],"paths":["/**"]})).await;let before=store_snapshot(&f).await;credential_gate(&f,true).await;for bulk in [false,true]{let(path,body)=if bulk{("/v1/pending/decide-many",json!({"decisions":[{"id":id,"kind":"session","granted":true,"overrides":overrides}]}))}else{("/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":overrides}))};let(s,v)=credential_api(&f,"POST",path,body).await;assert!((400..500).contains(&s),"{v}");if !bulk||overrides.is_object(){assert!(v.to_string().contains(named),"{v}");}else{assert_eq!(s,403);}let rid=id.as_str().unwrap().to_owned();assert_eq!(f.shared.run(move|c|c.sr_get(&rid).unwrap().state).await.unwrap(),"pending");assert_eq!(store_snapshot(&f).await,before);}}
 let(s,v)=credential_api(&f,"POST","/v1/pending/decide-many",json!({"decisions":[{"id":"apr_x","kind":"request","granted":true,"overrides":{"budget":1}}]})).await;assert!((400..500).contains(&s));assert!(v.to_string().contains("held request"));for bulk in [false,true]{let id=c25_ask(&f,json!({"cred":"demo","methods":["GET"],"paths":["/**"]})).await;credential_gate(&f,true).await;let(path,body)=if bulk{("/v1/pending/decide-many",json!({"decisions":[{"id":id,"kind":"session","granted":true,"overrides":{"budget":3}}]}))}else{("/v1/session-requests/decide",json!({"id":id,"granted":true,"overrides":{"methods":["GET"],"budget":5,"approval":"each"}}))};let(s,v)=credential_api(&f,"POST",path,body).await;assert_eq!(s,200,"{v}");}credential_finish(&f).await;
 }).await.unwrap();
}
#[test]
fn integration_d1_shared_parser_emits_only_daemon_supported_override_keys() {
    use av_daemon::session_requests::overrides_problem;
    let typed = json!({"methods":"GET","paths":"/a/**","budget":"5","uses":"2","ttl_minutes":"30","ttl-minutes":"30","grant_ttl_minutes":"5","max_concurrent":"1","redirects":"0","spend_tokens":"9","spend_usd":"1.5","rate":"60/min","quota":"1000/day","routes":"[{\"methods\":[\"GET\"],\"paths\":[\"/x\"]}]","payload":"{}","approval":"each","infinite":true});
    let read = av_store::pending::parse_overrides(typed.as_object().unwrap()).unwrap();
    assert!(overrides_problem(Some(&serde_json::to_value(read).unwrap())).is_none());
    for key in ["hosts", "deny_paths", "not_a_field"] {
        let e =
            av_store::pending::parse_overrides(json!({"budget":"1",key:"x"}).as_object().unwrap())
                .unwrap_err();
        assert_eq!(e.field, key);
    }
    let parsed =
        av_store::pending::parse_overrides(json!({"route":["GET:/x"]}).as_object().unwrap())
            .unwrap();
    assert!(overrides_problem(Some(&serde_json::to_value(parsed).unwrap())).is_none());
    let item = av_store::pending::fetch_pending(|path| {
        Some(if path == "/v1/session-requests" {
            vec![
                json!({"id":"sr_x","summary":"s","created_at":"2030-01-01T00:00:00Z","proposal":{"cred":"demo"}}),
            ]
        } else {
            vec![]
        })
    });
    let mut fields = serde_json::Map::new();
    for key in item[0]
        .narrowable
        .iter()
        .chain(item[0].owner_settable.iter())
    {
        fields.insert(key.clone(), json!(1));
    }
    assert!(overrides_problem(Some(&Value::Object(fields))).is_none());
    for k in ["hosts", "deny_paths", "cred_x"] {
        assert!(overrides_problem(Some(&json!({k:1}))).unwrap().contains(k));
    }
}

#[tokio::test]
async fn integration_c28_denials_keep_sentences_private_bounded_and_recover_codes_after_restart() {
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        let mut f = c25_fixture().await;
        let cap = integration_create(
            &f,
            json!({"cred":"demo","methods":["GET"],"deny_paths":["/admin/**"]}),
        )
        .await;
        let other = integration_create(&f, json!({"cred":"demo"})).await;
        let r = integration_http(&f, &cap, "SECRETMETHODMARKER", "/x", None).await;
        assert_eq!(r["status"], 403);
        let said: Value = serde_json::from_str(r["body"].as_str().unwrap()).unwrap();
        assert!(said["detail"]
            .as_str()
            .unwrap()
            .contains("SECRETMETHODMARKER"));
        let rows = audit_records(&f).await;
        let row = rows.iter().find(|r| r["kind"] == "request.denied").unwrap();
        assert_eq!(row["request_id"], r["request_id"]);
        assert_eq!(row["reason_code"], "AV_POLICY_DENIED");
        assert_eq!(row["req"]["method"], "OTHER");
        assert!(row.get("detail").is_none() && row.get("hint").is_none());
        integration_absent(&f, false, &["SECRETMETHODMARKER"]).await;
        let (_, explained) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_explain_denial",
            json!({"request_id":r["request_id"]}),
        )
        .await;
        assert_eq!(explained["code"], "AV_POLICY_DENIED");
        assert_eq!(explained["rule"], row["rule"]);
        assert_eq!(explained["detail"], said["detail"]);
        for token in [other["token"].as_str(), None] {
            let (_, v) = integration_tool(
                &f,
                token,
                "vault_explain_denial",
                json!({"request_id":r["request_id"]}),
            )
            .await;
            assert!(v["error"].as_str().unwrap().contains("no record"));
            assert!(!v.to_string().contains("SECRETMETHODMARKER"));
        }
        let denial = integration_http(&f, &cap, "GET", "/admin/x", None).await;
        assert_eq!(denial["status"], 403);
        let id = denial["request_id"].clone();
        for _ in 0..220 {
            let r = f
                .daemon
                .pipeline()
                .handle(GatewayRequest {
                    method: "GET".into(),
                    path: "/p/demo/x".into(),
                    ..Default::default()
                })
                .await;
            assert_eq!(r.status, 401);
        }
        let (_, v) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_explain_denial",
            json!({"request_id":id}),
        )
        .await;
        assert_eq!(v["code"], "AV_POLICY_DENIED");
        assert_eq!(v["rule"], "deny_paths:0");
        assert!(v["detail"].as_str().unwrap().contains("deny list"));
        for _ in 0..1000 {
            f.daemon
                .pipeline()
                .handle(GatewayRequest {
                    method: "GET".into(),
                    path: "/p/demo/x".into(),
                    ..Default::default()
                })
                .await;
        }
        let (_, v) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_explain_denial",
            json!({"request_id":id}),
        )
        .await;
        assert_eq!(
            json!([v["code"], v["rule"], v["detail"]]),
            json!(["AV_POLICY_DENIED", "deny_paths:0", null])
        );
        let sid = cap["session_id"].as_str().unwrap().to_owned();
        assert!(f
            .daemon
            .pipeline()
            .explain_denial(id.as_str().unwrap().to_owned(), Some(sid))
            .await
            .is_none());
        f = control_session_restart_with_pass(f, |_| {}, Some(WIDEN_PASS)).await;
        let (_, v) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_explain_denial",
            json!({"request_id":id}),
        )
        .await;
        assert_eq!(
            json!([v["code"], v["rule"], v["detail"]]),
            json!(["AV_POLICY_DENIED", "deny_paths:0", null])
        );
        let (_, v) = integration_tool(
            &f,
            other["token"].as_str(),
            "vault_explain_denial",
            json!({"request_id":id}),
        )
        .await;
        assert!(v["error"].as_str().unwrap().contains("no record"));
        assert_eq!(
            integration_http(&f, &cap, "GET", "/ordinary", None).await["status"],
            200
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_c28_payload_indexes_host_refusal_and_session_labels_keep_attacker_text_out_of_all_audits(
) {
    tokio::time::timeout(std::time::Duration::from_secs(40),async{
 let f=c25_fixture().await;let cap=integration_create(&f,json!({"cred":"demo","methods":["GET","POST"],"approval":"auto","payload":{"json":{"/ok":{},format!("/{C25_VALUE}"):{"absent":true}}}})).await;let r=integration_cap(&f,&cap,"POST","/x",Some("{\"ghp\":{\"PLUS+slash\":{\"001122334455667788\":1}}}")).await;assert_eq!(r.status,403);assert_eq!(serde_json::from_slice::<Value>(&r.body).unwrap()["rule"],"payload:json:1:absent");assert_eq!(audit_records(&f).await.iter().rev().find(|r|r["kind"]=="request.denied").unwrap()["rule"],"payload:json:1:absent");let cap=integration_create(&f,json!({"cred":"demo","payload":{"query":{"a":{}},"query_strict":true}})).await;let path=format!("/x?a=1&{}=v",av_daemon::util::encode_uri_component(C25_VALUE));let r=integration_cap(&f,&cap,"GET",&path,None).await;assert_eq!(r.status,403);assert_eq!(serde_json::from_slice::<Value>(&r.body).unwrap()["rule"],"payload:query:1:strict");assert_eq!(audit_records(&f).await.iter().rev().find(|r|r["kind"]=="request.denied").unwrap()["rule"],"payload:query:1:strict");assert!(f.up.hits.lock().unwrap().is_empty());integration_absent(&f,false,&[]).await;let cap=integration_create(&f,json!({"cred":"demo","redirects":2})).await;f.up.sequence.lock().unwrap().push_back(Ok(redirect_reply(302,"https://secretmarker99887766.evil.test/x")));assert_eq!(integration_cap(&f,&cap,"GET","/x",None).await.status,302);let rows=audit_records(&f).await;let row=rows.iter().find(|r|r["kind"]=="request.redirect_returned").unwrap();assert_eq!(row["reason"],"host");assert!(row["to_host"].is_null());integration_absent(&f,false,&["secretmarker99887766.evil.test","secretmarker"]).await;
 let cap=integration_create(&f,json!({"cred":"demo","methods":["GET"],"label":format!("job {C25_VALUE}")})).await;let sid=cap["session_id"].as_str().unwrap().to_owned();let rows=audit_records(&f).await;let row=rows.iter().find(|r|r["kind"]=="session.created"&&r["session_id"]==sid).unwrap();assert_eq!(row["has_label"],true);assert!(row.get("label").is_none());assert_eq!(f.shared.run(move|c|c.vault.session(&sid).unwrap().unwrap().label).await.unwrap(),format!("job {C25_VALUE}"));integration_absent(&f,false,&[]).await;assert_eq!(integration_http(&f,&cap,"GET","/ordinary",None).await["status"],200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_c28_presence_denials_record_closed_codes_for_real_bad_assertions_and_accept_a_valid_signature(
) {
    use base64::Engine;
    tokio::time::timeout(std::time::Duration::from_secs(60),async{
 let w=WidenFixture::new().await;let body=json!({"cred":"demo","approval":"auto","methods":["GET","POST","DELETE"]});let op=av_daemon::util::operation_for("session.create",&body).unwrap();let codes=["client_data_type","origin","malformed","malformed","malformed","malformed","malformed","size","credential","challenge","signature"];let before=w.f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap();for (i,_)in codes.iter().enumerate(){let(s,ch)=w.ctl("POST","/v1/presence/challenge",json!({"operation":op,"origins":[w.ui.origin()]})).await;assert_eq!(s,200,"{ch}");let challenge=ch["challenge"].as_str().unwrap();let mut p=w.auth.assertion(challenge,&w.ui.origin());let b64=|v:Value|json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap()));match i{0=>p["clientDataJSON"]=b64(json!({"type":C25_VALUE,"challenge":challenge,"origin":w.ui.origin()})),1=>p["clientDataJSON"]=b64(json!({"type":"webauthn.get","challenge":challenge,"origin":C25_VALUE})),2=>p["clientDataJSON"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{{\"type\":\"{C25_VALUE}"))),3=>p["clientDataJSON"]=b64(Value::Null),4=>p["clientDataJSON"]=b64(json!({"type":"webauthn.get","challenge":7,"origin":w.ui.origin()})),5=>p["authenticatorData"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&C25_VALUE.as_bytes()[..20])),6=>p["signature"]=json!({"value":C25_VALUE}),7=>p["clientDataJSON"]=b64(json!({"type":C25_VALUE.repeat(300),"challenge":challenge,"origin":w.ui.origin()})),8=>p["credentialId"]=json!(C25_VALUE),9=>p["clientDataJSON"]=b64(json!({"type":"webauthn.get","challenge":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(C25_VALUE),"origin":w.ui.origin()})),_=>p["signature"]=json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(C25_VALUE))};p["challengeId"]=ch["challengeId"].clone();let mut sent=body.clone();sent["presence"]=p;let(s,v)=w.ctl("POST","/v1/sessions",sent).await;assert_eq!(s,401,"{i}: {v}");}assert_eq!(w.f.shared.run(|c|c.vault.sessions().unwrap().len()).await.unwrap(),before);let rows=audit_records(&w.f).await;let denied=rows.iter().filter(|r|r["kind"]=="presence.denied").collect::<Vec<_>>();assert_eq!(denied.iter().map(|r|r["reason"].as_str().unwrap()).collect::<Vec<_>>(),codes);for r in denied{let keys=r.as_object().unwrap().keys().map(String::as_str).filter(|k|!["seq","ts","kind","prev_hash","hash"].contains(k)).collect::<Vec<_>>();assert_eq!(keys,vec!["reason"]);}integration_absent(&w.f,false,&[]).await;let mut sent=body.clone();sent["presence"]=w.proof("session.create",&body).await;let(s,v)=w.ctl("POST","/v1/sessions",sent).await;assert_eq!(s,200,"{v}");w.stop().await;
 }).await.unwrap();
}

#[tokio::test]
async fn integration_c28_busy_listener_audits_only_system_code_and_daemon_remains_usable() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let mut f = Fixture::new(&["header:x-key"]).await;
        let busy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = busy.local_addr().unwrap().port();
        f.daemon.stop().await;
        f.shared
            .run(move |c| {
                c.vault
                    .add_listener(av_store::vault::NewListener {
                        id: "busy".into(),
                        address: format!("127.0.0.1:{port}"),
                        surfaces: vec!["gateway".into()],
                        advertise: vec![],
                        client_auth: None,
                        allow_cidr: vec![],
                        tls: None,
                    })
                    .unwrap()
            })
            .await
            .unwrap();
        f.daemon = Daemon::new(
            f.shared.clone(),
            DaemonOptions {
                port: 0,
                socket_path: Some(f._dir.path().join("control.sock")),
                pipeline: PipelineOptions {
                    upstream: Some(f.up.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        f.daemon.start().await.unwrap();
        let rows = audit_records(&f).await;
        let row = rows
            .iter()
            .find(|r| r["kind"] == "listen.bind_failed")
            .unwrap();
        assert_eq!(row["reason"], "EADDRINUSE");
        let own = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|k| !["seq", "ts", "kind", "prev_hash", "hash"].contains(k))
            .collect::<Vec<_>>();
        assert_eq!(own, vec!["listener_id", "reason"]);
        assert!(!row.to_string().contains(&port.to_string()));
        assert_eq!(f.get().await.status, 200);
        drop(busy);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_c28_real_webhook_connection_and_protocol_failures_log_only_closed_reasons() {
    tokio::time::timeout(std::time::Duration::from_secs(40),async{
 for tls in [false,true]{let f=c25_fixture().await;credential_gate(&f,true).await;let port=if tls{let(s,v)=credential_api(&f,"POST","/v1/listeners",json!({"id":"self-signed","address":"127.0.0.1:0","surfaces":["gateway"],"tls":{"managed":true}})).await;assert_eq!(s,200,"{v}");let entry=serde_json::from_value::<av_store::model::ListenerRecord>(v).unwrap();f.daemon.bind_listener(&entry).await.unwrap().1}else{let l=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=l.local_addr().unwrap().port();drop(l);port};
 let(s,v)=credential_api(&f,"POST","/v1/notify",json!({"webhook_url":format!("{}://127.0.0.1:{port}/hook/{C25_VALUE}",if tls{"https"}else{"http"}),"detail":"minimal"})).await;assert_eq!(s,200,"{v}");let(s,v)=credential_api(&f,"POST","/v1/notify/test",json!({})).await;assert_eq!(s,200,"{v}");assert_eq!(v,json!({"sent":false,"error":if tls{"error"}else{"ECONNREFUSED"}}));let rows=audit_records(&f).await;let row=rows.iter().find(|r|r["kind"]=="notify.failed").unwrap();assert_eq!(row["reason"],v["error"]);integration_absent(&f,false,&[]).await;assert_eq!(f.get().await.status,200);credential_finish(&f).await;}
 }).await.unwrap();
}
#[tokio::test]
async fn integration_c28_untrusted_mcp_hold_and_panic_reasons_are_scrubbed_before_the_two_hundred_unit_cut(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = c25_fixture().await;
        let cap = integration_create(&f, json!({"cred":"demo"})).await;
        let reason = format!(
            "{} {} {C25_VALUE} {}",
            "r".repeat(150),
            cap["placeholder"].as_str().unwrap(),
            "z".repeat(300)
        );
        let (error, v) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_get_placeholder",
            json!({"cred":"demo","reason":reason}),
        )
        .await;
        assert!(!error, "{v}");
        let rows = audit_records(&f).await;
        let row = rows
            .iter()
            .find(|r| r["kind"] == "placeholder.issued_via_mcp")
            .unwrap();
        let text = row["agent_reason_untrusted"].as_str().unwrap();
        assert!(text.encode_utf16().count() <= 200);
        assert!(text.contains("«placeholder»"));
        assert!(!text.contains(&cap["placeholder"].as_str().unwrap()[..12]));
        let cap = integration_create(&f, json!({"cred":"demo","approval":"each"})).await;
        let r = f
            .daemon
            .pipeline()
            .handle(GatewayRequest {
                method: "GET".into(),
                path: "/p/demo/x".into(),
                headers: vec![
                    ("host".into(), "127.0.0.1".into()),
                    ("av-session".into(), cap["token"].as_str().unwrap().into()),
                    ("x-key".into(), cap["placeholder"].as_str().unwrap().into()),
                    (
                        "av-reason".into(),
                        format!("{}{C25_VALUE}{}", "h".repeat(190), "t".repeat(500)),
                    ),
                ],
                ..Default::default()
            })
            .await;
        assert_eq!(r.status, 202);
        let rows = audit_records(&f).await;
        let text = rows
            .iter()
            .find(|r| r["kind"] == "approval.requested")
            .unwrap()["agent_reason_untrusted"]
            .as_str()
            .unwrap();
        assert!(text.encode_utf16().count() <= 200);
        assert!(text.starts_with(&"h".repeat(190)));
        assert!(f.up.hits.lock().unwrap().is_empty());
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/panic",
                json!({"reason":format!("{}{C25_VALUE}","p".repeat(160))})
            )
            .await
            .0,
            200
        );
        let rows = audit_records(&f).await;
        assert_eq!(
            rows.iter()
                .find(|r| r["kind"] == "panic.triggered")
                .unwrap()["reason_untrusted"],
            format!("{}[[av:redacted:demo]]", "p".repeat(160))
        );
        integration_absent(&f, false, &["ghp/PLU"]).await;
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_c28_restored_quarantine_reason_is_cleaned_before_any_record_is_written() {
    tokio::time::timeout(std::time::Duration::from_secs(60),async{
 let f=Fixture::new(&["header:x-key"]).await;let created=av_daemon::util::iso_of_ms(av_daemon::util::now_ms());let salt=[7u8;16];let pass:av_core::secret::SecretString=CONTROL_RECOVERY.to_owned().into();let params=av_store::backup::BACKUP_KDF_V2;let key=av_store::crypto::argon2_key(&pass,&salt,&params).unwrap();let plain=json!({"credentials":[{"slug":"third","kind":"http","connector":{"host":"api.example.test","scheme":"https"},"created_at":created,"fields":[{"name":"token","value":C25_VALUE,"sites":["header:x-key"]}],"scrub_patterns":[],"pins":{},"expires_at":null,"quarantine":{"since":created,"by":"control","rule_id":null,"reason_untrusted":format!("leaked {C25_VALUE} here")}}],"templates":[]});let sealed=av_store::crypto::seal(&key,&serde_json::to_vec(&plain).unwrap(),&format!("agent-vault-backup|2|{created}")).unwrap();let bundle=serde_json::to_value(av_store::backup::BundleV2{format:"agent-vault-backup".into(),version:2,created_at:created,kdf:av_store::backup::BundleKdfV2{params,salt:{use base64::Engine;base64::engine::general_purpose::STANDARD.encode(salt)}},cipher:av_store::backup::CIPHER_V2.into(),nonce:sealed.n,ct:sealed.c}).unwrap();let(s,v)=credential_api(&f,"POST","/v1/backup/restore",json!({"bundle":bundle,"recovery_passphrase":CONTROL_RECOVERY,"on_conflict":"skip"})).await;assert_eq!(s,200,"{v}");assert!(v["restored"].as_array().unwrap().contains(&json!("third")));let rows=audit_records(&f).await;let row=rows.iter().find(|r|r["kind"]=="cred.quarantined").unwrap();assert_eq!(row["reason_untrusted"],"leaked [[av:redacted:third]] here");integration_absent(&f,false,&[]).await;assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}

#[test]
fn integration_c28_every_typed_fault_class_is_its_av_code_never_attacker_detail_or_hint() {
    use av_core::errors::{deny, DenyExtra, ErrorCode};
    for wire in [
        "AV_NO_GRANT",
        "AV_POLICY_DENIED",
        "AV_BAD_LOCATION",
        "AV_ENCODED_BODY",
        "AV_UNSCANNABLE",
        "AV_BROWSER_ORIGIN",
        "AV_PH_MALFORMED",
        "AV_PH_EXHAUSTED",
        "AV_PH_STALE",
        "AV_PH_REPLAY",
        "AV_PH_CROSS_SESSION",
        "AV_PH_WRONG_CONNECTOR",
        "AV_SESSION_EXPIRED",
        "AV_SESSION_REVOKED",
        "AV_SESSION_REQUIRED",
        "AV_LOCKED",
        "AV_REMOTE_FORBIDDEN",
        "AV_PRESENCE_REQUIRED",
        "AV_PRESENCE_DENIED",
        "AV_RATE_LIMITED",
        "AV_UPSTREAM_UNREACHABLE",
        "AV_QUOTA_EXCEEDED",
        "AV_GRANT_EXPIRED",
        "AV_QUARANTINED",
        "AV_PIN_MISMATCH",
        "AV_MCP_PROTOCOL",
        "AV_MCP_SESSION_UNKNOWN",
        "AV_NOT_FOUND",
        "AV_INTERNAL",
        "AV_TOO_MANY_REQUESTS",
        "AV_APPROVAL_PENDING",
        "AV_OWNER_ONLY",
        "AV_BAD_CURSOR",
        "AV_BAD_LIMIT",
    ] {
        let code: ErrorCode = serde_json::from_value(json!(wire)).unwrap();
        let e = deny(
            code,
            format!("forged TypeError {C25_VALUE}"),
            DenyExtra {
                hint: Some(format!("forged SyntaxError {C25_VALUE}")),
                ..Default::default()
            },
        );
        let class = av_daemon::server::error_class(&e);
        assert_eq!(class, wire);
        assert!(!class.contains(C25_VALUE));
        assert!(!class.contains("TypeError"));
        assert!(!class.contains("SyntaxError"));
    }
    assert_eq!(
        av_daemon::server::error_class(&deny(ErrorCode::Locked, C25_VALUE, Default::default())),
        "AV_LOCKED"
    );
}

#[tokio::test]
async fn integration_r6_stream_audit_media_types_are_closed_even_when_upstream_headers_contain_secrets(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = c25_fixture().await;
        for compressed in [false, true] {
            stream_reply(&f, "data: hello\n\n", compressed);
            {
                let mut reply = f.up.reply.lock().unwrap();
                let reply = reply.as_mut().unwrap();
                reply.headers.retain(|(n, _)| n != "content-type");
                reply.headers.push((
                    "content-type".into(),
                    format!("text/event-stream; note={C25_VALUE}"),
                ));
                if !compressed {
                    reply
                        .headers
                        .push(("content-encoding".into(), "identity".into()));
                }
            }
            let r = drain(f.get().await).await;
            assert_eq!(r.status, 200);
            assert!(String::from_utf8_lossy(&r.body).contains("hello"));
            assert!(!r.header("content-type").unwrap().contains(C25_VALUE));
        }
        let rows = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let rows = audit_records(&f).await;
                if rows
                    .iter()
                    .filter(|r| r["kind"] == "response.streamed")
                    .count()
                    == 2
                {
                    break rows;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            rows.iter()
                .filter(|r| r["kind"] == "response.streamed")
                .map(|r| json!([r["content_type"], r["content_encoding"]]))
                .collect::<Vec<_>>(),
            vec![
                json!(["text/event-stream", "identity"]),
                json!(["text/event-stream", "gzip"])
            ]
        );
        integration_absent(&f, false, &["note="]).await;
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_r6_no_session_denial_explains_only_code_and_rule_and_a_session_cannot_read_it()
{
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let r = f
            .daemon
            .pipeline()
            .handle(GatewayRequest {
                method: "GET".into(),
                path: "/p/demo/secret-path-marker".into(),
                ..Default::default()
            })
            .await;
        assert_eq!(r.status, 401);
        let id = r.request_id.clone().unwrap();
        assert!(f
            .daemon
            .pipeline()
            .explain_denial(id.clone(), None)
            .await
            .is_some());
        let (_, v) =
            integration_tool(&f, None, "vault_explain_denial", json!({"request_id":id})).await;
        assert_eq!(
            v["code"],
            serde_json::from_slice::<Value>(&r.body).unwrap()["code"]
        );
        assert!(v["detail"].is_null());
        assert!(v.get("hint").is_none());
        let cap = integration_create(&f, json!({"cred":"demo"})).await;
        let (_, v) = integration_tool(
            &f,
            cap["token"].as_str(),
            "vault_explain_denial",
            json!({"request_id":id}),
        )
        .await;
        assert!(v["error"].as_str().unwrap().contains("no record"));
        assert_eq!(
            integration_http(&f, &cap, "GET", "/ordinary", None).await["status"],
            200
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn integration_c28_real_malformed_metadata_failure_returns_generic_internal_and_no_error_text_in_audits(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = c25_unreadable_fixture().await;
        let (s, v) = credential_api(&f, "GET", "/v1/credentials", json!({})).await;
        assert_eq!(s, 500, "{v}");
        assert_eq!(v["code"], "AV_INTERNAL");
        assert_eq!(v["detail"], "the request could not be handled");
        for text in [
            "unreadable legacy marker",
            "invalid type",
            "Quarantine",
            "credentials",
            "SELECT",
        ] {
            assert!(!v.to_string().contains(text), "{v}");
        }
        integration_absent(
            &f,
            false,
            &["unreadable legacy marker", "invalid type", "SELECT"],
        )
        .await;
        credential_finish(&f).await;
        let f = Fixture::new(&["header:x-key"]).await;
        assert_eq!(
            credential_api(&f, "GET", "/v1/credentials", json!({}))
                .await
                .0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn integration_fix_approval_denials_require_matching_presence_and_cached_agent_responses_never_return_to_control(
) {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let w = WidenFixture::new().await;
        let gid = w.f.grant_id.clone();
        w.f.shared
            .run(move |c| {
                c.vault
                    .narrow_grant(&gid, &json!({"approval":"on-write"}))
                    .unwrap()
            })
            .await
            .unwrap();
        let ph = w.f.mint(Some(1)).await;
        let send = |path: &'static str| {
            w.f.send(
                "POST",
                path,
                vec![("authorization".into(), format!("Bearer {ph}"))],
                Some("x".into()),
            )
        };
        let id = held_id(&send("/fix-deny/no-presence").await);
        let (s, v) = w
            .ctl("POST", "/v1/approvals", json!({"id":id,"granted":false}))
            .await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["code"], "AV_PRESENCE_REQUIRED");
        assert!(w
            .f
            .daemon
            .pipeline()
            .pending_approvals()
            .await
            .iter()
            .any(|r| r["id"] == id));
        let id = held_id(&send("/fix-deny/swap").await);
        let proof = w
            .proof("approval.approve", &json!({"id":id,"granted":true}))
            .await;
        let (s, v) = w
            .ctl(
                "POST",
                "/v1/approvals",
                json!({"id":id,"granted":false,"presence":proof}),
            )
            .await;
        assert_eq!(s, 401, "{v}");
        assert!(w
            .f
            .daemon
            .pipeline()
            .pending_approvals()
            .await
            .iter()
            .any(|r| r["id"] == id));
        let id = held_id(&send("/fix-deny/signed").await);
        let proof = w
            .proof("approval.deny", &json!({"id":id,"granted":false}))
            .await;
        let (s, v) = w
            .ctl(
                "POST",
                "/v1/approvals",
                json!({"id":id,"granted":false,"presence":proof}),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["state"], "denied");
        let id = held_id(&send("/fix-deny/window").await);
        credential_gate(&w.f, true).await;
        let (s, v) = w
            .ctl("POST", "/v1/approvals", json!({"id":id,"granted":false}))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["state"], "denied");
        credential_gate(&w.f, false).await;
        assert!(w.f.up.hits.lock().unwrap().is_empty());
        let id = held_id(&send("/fix-deny/cached").await);
        let proof = w
            .proof("approval.approve", &json!({"id":id,"granted":true}))
            .await;
        assert_eq!(
            w.ctl(
                "POST",
                "/v1/approvals",
                json!({"id":id,"granted":true,"presence":proof})
            )
            .await
            .0,
            200
        );
        let r = send("/fix-deny/cached").await;
        assert_eq!(r.status, 200);
        assert_eq!(w.f.up.hits.lock().unwrap().len(), 1);
        assert!(r.header("av-placeholder-next").is_some());
        credential_gate(&w.f, true).await;
        let (_, v) = w
            .ctl("POST", "/v1/approvals", json!({"id":id,"granted":false}))
            .await;
        assert!(v.get("result").is_none());
        assert!(!v.to_string().contains("av-placeholder-next"));
        let (s, v) = w.ctl("GET", "/v1/approvals", json!({})).await;
        assert_eq!(s, 200);
        assert!(!v.to_string().contains("av-placeholder-next"));
        assert_eq!(w.f.up.hits.lock().unwrap().len(), 1);
        let fresh = w.f.mint(None).await;
        assert_eq!(
            w.f.send(
                "GET",
                "/ordinary-after-decision",
                vec![("authorization".into(), format!("Bearer {fresh}"))],
                None
            )
            .await
            .status,
            200
        );
        w.stop().await;
    })
    .await
    .unwrap();
}

fn fix_presence_record(seed: u8) -> Value {
    use base64::Engine;
    use p256::pkcs8::EncodePublicKey;
    let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    json!({"credentialId":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([seed;16]),"publicKeySpki":base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes()),"signCount":0})
}
async fn fix_presence_enroll(f: &Fixture, seed: u8) -> ported_common::FakeAuthenticator {
    credential_factor(f).await;
    let mut record = fix_presence_record(seed);
    record["presence"] = json!({"passphrase":WIDEN_PASS});
    let (s, v) = credential_api(f, "POST", "/v1/presence", record).await;
    assert_eq!(s, 200, "{v}");
    credential_gate(f, false).await;
    ported_common::FakeAuthenticator::new(seed)
}
async fn fix_presence_proof(
    f: &Fixture,
    auth: &ported_common::FakeAuthenticator,
    origin: &str,
    op: &str,
    params: &Value,
) -> Value {
    let operation = av_daemon::util::operation_for(op, params).unwrap();
    let (s, ch) = credential_api(
        f,
        "POST",
        "/v1/presence/challenge",
        json!({"operation":operation,"origins":[origin]}),
    )
    .await;
    assert_eq!(s, 200, "{ch}");
    let mut proof = auth.assertion(ch["challenge"].as_str().unwrap(), origin);
    proof["challengeId"] = ch["challengeId"].clone();
    proof
}
#[tokio::test]
async fn fix_presence_shared_window_cannot_change_factors_but_fresh_passphrase_and_assertion_can() {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        use base64::Engine;
        let f = Fixture::new(&["header:x-key"]).await;
        let human = fix_presence_enroll(&f, 31).await;
        credential_gate(&f, true).await;
        let prf = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let enroll = json!({"action":"enroll","credential_id":"fake-unlock","prf_secret":prf});
        let (s, v) = credential_api(&f, "POST", "/v1/factors/webauthn", enroll.clone()).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["rule"], "fresh_presence");
        assert_eq!(
            json!(f
                .shared
                .run(|c| c.vault.has_webauthn_unlock().unwrap())
                .await
                .unwrap()),
            false
        );
        let next = fix_presence_record(32);
        let (s, v) = credential_api(&f, "POST", "/v1/presence", next.clone()).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(
            credential_api(&f, "GET", "/v1/presence", json!({})).await.1["credentialId"],
            human.id()
        );
        let mut bad = enroll.clone();
        bad["presence"] = json!({"passphrase":"wrong fake passphrase"});
        let (s, v) = credential_api(&f, "POST", "/v1/factors/webauthn", bad).await;
        assert_eq!(s, 403, "{v}");
        assert_eq!(v["code"], "AV_PRESENCE_DENIED");
        assert_eq!(v["rule"], "fresh_presence");
        let mut good = enroll;
        good["presence"] = json!({"passphrase":WIDEN_PASS});
        assert_eq!(
            credential_api(&f, "POST", "/v1/factors/webauthn", good)
                .await
                .0,
            200
        );
        assert_eq!(
            json!(f
                .shared
                .run(|c| c.vault.has_webauthn_unlock().unwrap())
                .await
                .unwrap()),
            true
        );
        credential_gate(&f, true).await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/factors/webauthn",
            json!({"action":"remove"}),
        )
        .await;
        assert_eq!(s, 401, "{v}");
        credential_gate(&f, false).await;
        let proof = fix_presence_proof(
            &f,
            &human,
            "http://localhost:7412",
            "touchid.remove",
            &json!({}),
        )
        .await;
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/factors/webauthn",
            json!({"action":"remove","presence":proof}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            json!(f
                .shared
                .run(|c| c.vault.has_webauthn_unlock().unwrap())
                .await
                .unwrap()),
            false
        );
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/passphrase",
            json!({"action":"remove","current":WIDEN_PASS}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            credential_api(&f, "GET", "/v1/lockstate", json!({}))
                .await
                .1["has_passphrase"],
            false
        );
        assert_eq!(
            credential_api(&f, "POST", "/v1/presence", next.clone())
                .await
                .0,
            401
        );
        let proof = fix_presence_proof(
            &f,
            &human,
            "http://localhost:7412",
            "presence.enroll",
            &next,
        )
        .await;
        let mut sent = next.clone();
        sent["presence"] = proof;
        let (s, v) = credential_api(&f, "POST", "/v1/presence", sent).await;
        assert_eq!(s, 200, "{v}");
        let (_, stored) = credential_api(&f, "GET", "/v1/presence", json!({})).await;
        assert_eq!(stored["credentialId"], next["credentialId"]);
        assert!(stored.get("presence").is_none());
        assert_eq!(
            stored
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["credentialId", "enrolledAt", "publicKeySpki", "signCount"]
                .into_iter()
                .collect()
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_presence_one_window_records_each_ordinary_step_and_lock_and_fresh_proofs_never_leave_it_open(
) {
    tokio::time::timeout(std::time::Duration::from_secs(45),async{
 let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;credential_gate(&f,true).await;let(s,v)=credential_api(&f,"POST","/v1/credentials",json!({"slug":"second","kind":"http","host":"api.other.test","value":"test-secret-second-fake-123456789","sites":["header:x-key"]})).await;assert_eq!(s,200,"{v}");let(s,cap)=credential_api(&f,"POST","/v1/sessions",json!({"cred":"second"})).await;assert_eq!(s,200,"{cap}");assert_eq!(credential_api(&f,"POST","/v1/placeholders",json!({"cred":"second","sid":cap["session_id"]})).await.0,200);assert_eq!(audit_records(&f).await.iter().filter(|r|r["kind"]=="presence.window_used").map(|r|r["op"].as_str().unwrap().to_owned()).collect::<Vec<_>>(),vec!["cred add","session create","placeholder issue"]);credential_gate(&f,false).await;assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await.0,401);
 let(s,v)=credential_api(&f,"POST","/v1/ui/origins",json!({"origin":"http://localhost:9125","presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,200,"{v}");assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await.0,401);assert!(audit_records(&f).await.iter().any(|r|r["kind"]=="presence.verified"&&r["fresh"]==true&&r["factor"]=="passphrase"));assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 let f=Fixture::new(&["header:x-key"]).await;let(s,v)=credential_api(&f,"POST","/v1/ui/origins",json!({"origin":"http://localhost:9124"})).await;assert_eq!(s,401,"{v}");assert_eq!(v["rule"],"factor_required");assert_eq!(v["factors"],json!([]));assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await.0,200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn fix_presence_caller_origins_do_not_grant_trust_but_default_and_freshly_authorized_origins_work(
) {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let auth = fix_presence_enroll(&f, 33).await;
        let body = json!({"cred":"demo","methods":["GET"]});
        let proof =
            fix_presence_proof(&f, &auth, "http://localhost:6666", "session.create", &body).await;
        let mut sent = body.clone();
        sent["presence"] = proof;
        assert_eq!(
            credential_api(&f, "POST", "/v1/sessions", sent).await.0,
            401
        );
        let proof =
            fix_presence_proof(&f, &auth, "http://localhost:7412", "session.create", &body).await;
        let mut sent = body.clone();
        sent["presence"] = proof;
        let (s, v) = credential_api(&f, "POST", "/v1/sessions", sent).await;
        assert_eq!(s, 200, "{v}");
        let (s, ui) = credential_api(&f, "GET", "/v1/ui", json!({})).await;
        assert_eq!(s, 200);
        assert_eq!(ui["port"], 7412);
        assert_eq!(ui["origins"], json!(["http://localhost:7412"]));
        credential_gate(&f, true).await;
        assert_eq!(
            credential_api(
                &f,
                "POST",
                "/v1/ui/origins",
                json!({"origin":"http://localhost:9123"})
            )
            .await
            .0,
            401
        );
        credential_gate(&f, false).await;
        for origin in [
            "http://evil.example:9123",
            "https://localhost:9123",
            "http://localhost",
            "http://localhost:99999",
            "http://localhost:9123/x",
        ] {
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/ui/origins",
                json!({"origin":origin,"presence":{"passphrase":WIDEN_PASS}}),
            )
            .await;
            assert!(s >= 400, "{v}");
        }
        let (s, v) = credential_api(
            &f,
            "POST",
            "/v1/ui/origins",
            json!({"origin":"http://localhost:9123","presence":{"passphrase":WIDEN_PASS}}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        assert!(audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "ui.origin_added"));
        let proof =
            fix_presence_proof(&f, &auth, "http://localhost:9123", "session.create", &body).await;
        let mut sent = body;
        sent["presence"] = proof;
        assert_eq!(
            credential_api(&f, "POST", "/v1/sessions", sent).await.0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_ledger_mcp_native_requests_bound_live_rows_keep_unrotated_rows_and_refuse_rotated_rows(
) {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let cap =
            integration_create(&f, json!({"cred":"demo","methods":["GET"],"budget":100})).await;
        let get = || {
            integration_tool(
                &f,
                cap["token"].as_str(),
                "vault_get_placeholder",
                json!({"cred":"demo","reason":"native client"}),
            )
        };
        let (_, v) = get().await;
        let mut first = cap.clone();
        first["placeholder"] = v["placeholder"].clone();
        assert_eq!(
            integration_cap(&f, &first, "GET", "/user", None)
                .await
                .status,
            200
        );
        for _ in 0..6 {
            assert!(get().await.1["placeholder"]
                .as_str()
                .unwrap()
                .starts_with("av1."));
        }
        for i in 0..5 {
            assert_eq!(
                integration_cap(&f, &first, "GET", &format!("/again/{i}"), None)
                    .await
                    .status,
                200
            );
        }
        let mut newest = first.clone();
        for i in 0..12 {
            let (_, v) = get().await;
            newest["placeholder"] = v["placeholder"].clone();
            assert_eq!(
                integration_cap(&f, &newest, "GET", &format!("/n/{i}"), None)
                    .await
                    .status,
                200
            );
        }
        let sid = cap["session_id"].as_str().unwrap().to_owned();
        let gid = cap["grant_id"].as_str().unwrap().to_owned();
        assert!(
            f.shared
                .run(move |c| c
                    .vault
                    .list_placeholders(Some(&sid))
                    .unwrap()
                    .iter()
                    .filter(|p| p.grant_id == gid
                        && p.state == av_store::model::PlaceholderState::Active)
                    .count())
                .await
                .unwrap()
                <= 8
        );
        let stale = integration_cap(&f, &first, "GET", "/user", None).await;
        assert_ne!(stale.status, 200);
        assert!(String::from_utf8_lossy(&stale.body).contains("AV_PH_STALE"));
        assert_eq!(
            integration_cap(&f, &newest, "GET", "/newest", None)
                .await
                .status,
            200
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fix_factors_last_passphrase_refusals_preserve_gating_across_unlock_and_touchid_removal() {
    tokio::time::timeout(std::time::Duration::from_secs(50),async{
 let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let unsigned=||credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo","methods":["GET"],"paths":["/**"]}));assert_eq!(unsigned().await.0,401);let before=f.shared.run(|c|c.vault.factors().unwrap()).await.unwrap();let(s,v)=credential_api(&f,"POST","/v1/passphrase",json!({"action":"remove","current":WIDEN_PASS})).await;assert_eq!(s,403,"{v}");assert_eq!(v["code"],"AV_POLICY_DENIED");assert_eq!(v["rule"],"last_factor");assert!(v["hint"].as_str().unwrap().contains("presence authenticator"));assert_eq!(v["next"],"agent-vault ui");assert_eq!(f.shared.run(|c|c.vault.factors().unwrap()).await.unwrap(),before);assert_eq!(unsigned().await.0,401);assert_eq!(credential_api(&f,"POST","/v1/lock",json!({})).await.0,200);assert_eq!(credential_api(&f,"POST","/v1/unlock",json!({})).await.0,423);assert_eq!(credential_api(&f,"POST","/v1/unlock",json!({"passphrase":WIDEN_PASS})).await.0,200);assert_eq!(unsigned().await.0,401);
 let prf=av_core::secret::SecretBytes::from(vec![9u8;32]);f.shared.run(move|c|c.vault.add_webauthn_unlock("fake-c",&prf).unwrap()).await.unwrap();let(s,v)=credential_api(&f,"POST","/v1/passphrase",json!({"action":"remove","current":WIDEN_PASS})).await;assert_eq!(s,403);assert_eq!(v["rule"],"last_factor");assert!(v["detail"].as_str().unwrap().contains("remove Touch ID unlock first"));f.shared.run(|c|c.vault.remove_webauthn_unlock().unwrap()).await.unwrap();let(s,v)=credential_api(&f,"POST","/v1/passphrase",json!({"action":"remove","current":WIDEN_PASS})).await;assert_eq!(s,403);assert_eq!(v["rule"],"last_factor");assert!(f.shared.run(|c|c.vault.has_passphrase().unwrap()).await.unwrap());assert_eq!(unsigned().await.0,401);assert_eq!(credential_api(&f,"POST","/v1/passphrase",json!({"action":"remove","current":"not the passphrase"})).await.1["code"],"AV_LOCKED");assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 let f=Fixture::new(&["header:x-key"]).await;fix_presence_enroll(&f,36).await;let(s,v)=credential_api(&f,"POST","/v1/passphrase",json!({"action":"remove","current":WIDEN_PASS})).await;assert_eq!(s,200,"{v}");assert!(!f.shared.run(|c|c.vault.has_passphrase().unwrap()).await.unwrap());assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await.0,401);let(s,v)=credential_api(&f,"POST","/v1/presence/window",json!({})).await;assert_eq!(s,200);assert_eq!(v["granted"],false);assert_eq!(v["ungated"],false);assert_eq!(v["factors"],json!(["authenticator"]));assert!(v["detail"].as_str().unwrap().contains("authenticator"));assert!(!v["detail"].as_str().unwrap().contains("nothing is gated"));assert!(v["next"].as_str().unwrap().contains("agent-vault ui"));assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await.0,401);credential_finish(&f).await;
 let f=Fixture::new(&["header:x-key"]).await;let(s,v)=credential_api(&f,"POST","/v1/presence/window",json!({})).await;assert_eq!(s,200);assert_eq!(v["granted"],false);assert_eq!(v["ungated"],true);assert_eq!(v["next"],"agent-vault passphrase set");assert_eq!(credential_api(&f,"POST","/v1/sessions",json!({"cred":"demo"})).await.0,200);credential_factor(&f).await;let(s,v)=credential_api(&f,"POST","/v1/passphrase",json!({"action":"set","passphrase":"test-brand-new-fake-passphrase","current":WIDEN_PASS})).await;assert_eq!(s,200,"{v}");f.shared.run(|c|{assert!(c.vault.verify_passphrase(&"test-brand-new-fake-passphrase".to_owned().into()).unwrap());assert!(!c.vault.verify_passphrase(&WIDEN_PASS.to_owned().into()).unwrap());}).await.unwrap();credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn fix_factors_invalid_presence_replacements_are_atomic_and_clean_valid_replacements_still_sign(
) {
    use base64::Engine;
    tokio::time::timeout(std::time::Duration::from_secs(60),async{
 let f=Fixture::new(&["header:x-key"]).await;let auth=fix_presence_enroll(&f,37).await;assert_eq!(credential_api(&f,"POST","/v1/passphrase",json!({"action":"remove","current":WIDEN_PASS})).await.0,200);let original=credential_api(&f,"GET","/v1/presence",json!({})).await.1;let valid=fix_presence_record(38);let mut malformed=valid.clone();malformed["publicKeySpki"]=json!(base64::engine::general_purpose::STANDARD.encode([0u8;91]));let mut ed=valid.clone();ed["publicKeySpki"]=json!("MCowBQYDK2VwAyEANKHnyqArQEggFNewEh0DeGGhdkEXN6EqPRccdq5NGPY=");let mut p384=valid.clone();p384["publicKeySpki"]=json!("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUdowsFF/At70p0OS5B1WmL45lPct9GSkIcvVrL/GRlJ3jz0rjHLUbBYWYJyKbK6CEeepfbOjPjsSQjUHyHp9ALK/p+0t7CQQNnzuMIWczU7Kox8hFtzHiEdWrYq/lsyo");let mut short=valid.clone();short["credentialId"]=json!("aGVsbG8");let mut negative=valid.clone();negative["signCount"]=json!(-1);let mut big=valid.clone();big["signCount"]=json!(1u64<<40);
 for body in [json!({}),json!({"credentialId":"broken","publicKeySpki":"not-a-public-key","signCount":0}),json!({"credentialId":valid["credentialId"],"signCount":0}),malformed,ed,p384,short,negative,big]{let proof=fix_presence_proof(&f,&auth,"http://localhost:7412","presence.enroll",&body).await;let mut sent=body;sent["presence"]=proof;let(s,v)=credential_api(&f,"POST","/v1/presence",sent).await;assert_eq!(s,403,"{v}");assert_eq!(v["code"],"AV_POLICY_DENIED");assert_eq!(v["rule"],"presence_key");assert_eq!(credential_api(&f,"GET","/v1/presence",json!({})).await.1,original);assert_eq!(f.shared.run(|c|serde_json::to_value(c.vault.presence_key().unwrap().unwrap()).unwrap()).await.unwrap(),original);}
 let mut body=valid.clone();body["attestation"]=json!("x".repeat(64));body["extra"]=json!({"anything":true});let proof=fix_presence_proof(&f,&auth,"http://localhost:7412","presence.enroll",&body).await;body["presence"]=proof;let(s,v)=credential_api(&f,"POST","/v1/presence",body).await;assert_eq!(s,200,"{v}");assert_eq!(v["replaced"],true);let stored=credential_api(&f,"GET","/v1/presence",json!({})).await.1;assert_eq!(stored["credentialId"],valid["credentialId"]);assert_eq!(stored.as_object().unwrap().keys().map(String::as_str).collect::<std::collections::BTreeSet<_>>(),["credentialId","enrolledAt","publicKeySpki","signCount"].into_iter().collect());let body=json!({"cred":"demo","methods":["GET"],"paths":["/**"]});let proof=fix_presence_proof(&f,&ported_common::FakeAuthenticator::new(38),"http://localhost:7412","session.create",&body).await;let mut sent=body;sent["presence"]=proof;assert_eq!(credential_api(&f,"POST","/v1/sessions",sent).await.0,200);credential_finish(&f).await;
 let f=Fixture::new(&["header:x-key"]).await;credential_factor(&f).await;let(s,v)=credential_api(&f,"POST","/v1/presence",json!({"credentialId":"broken","publicKeySpki":"not-a-public-key","signCount":0,"presence":{"passphrase":WIDEN_PASS}})).await;assert_eq!(s,403);assert_eq!(v["rule"],"presence_key");assert!(f.shared.run(|c|c.vault.presence_key().unwrap().is_none()).await.unwrap());credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn fix_factors_real_sqlite_contention_cannot_replace_the_existing_presence_key() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        fix_presence_enroll(&f, 39).await;
        let original = f
            .shared
            .run(|c| serde_json::to_value(c.vault.presence_key().unwrap().unwrap()).unwrap())
            .await
            .unwrap();
        let lock = ported_common::TempWriteLock::acquire(f._dir.path());
        let next = fix_presence_record(40);
        let failed = f
            .shared
            .run(move |c| c.vault.set_presence_key(&next).is_err())
            .await
            .unwrap();
        assert!(failed);
        drop(lock);
        assert_eq!(
            f.shared
                .run(|c| serde_json::to_value(c.vault.presence_key().unwrap().unwrap()).unwrap())
                .await
                .unwrap(),
            original
        );
        f.shared
            .run(|c| c.vault.set_presence_key(&fix_presence_record(40)).unwrap())
            .await
            .unwrap();
        assert_eq!(
            credential_api(&f, "GET", "/v1/presence", json!({})).await.1["credentialId"],
            fix_presence_record(40)["credentialId"]
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_locked_reads_report_locked_unknown_audit_count_and_unlock_restores_records() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_eq!(
            credential_api(&f, "POST", "/v1/lock", json!({})).await.0,
            200
        );
        let (s, v) = credential_api(&f, "GET", "/v1/audit?limit=10", json!({})).await;
        assert_eq!(s, 423);
        assert_eq!(v["code"], "AV_LOCKED");
        assert!(v["detail"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("unlock"));
        let (s, v) = credential_api(&f, "GET", "/v1/audit/verify", json!({})).await;
        assert_eq!(s, 423);
        assert_eq!(v["code"], "AV_LOCKED");
        for path in ["/v1/status", "/v1/lockstate"] {
            let (s, v) = credential_api(&f, "GET", path, json!({})).await;
            assert_eq!(s, 200);
            assert_eq!(v["locked"], true);
            if path == "/v1/status" {
                assert!(v["audit_records"].is_null());
                assert_eq!(v["credentials"], 1);
            }
        }
        assert_eq!(
            credential_api(&f, "POST", "/v1/unlock", json!({})).await.0,
            200
        );
        let (s, v) = credential_api(&f, "GET", "/v1/audit?limit=10", json!({})).await;
        assert_eq!(s, 200);
        assert!(v
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "vault.lock"));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_remote_carriers_real_upstream_listener_refusals_and_shorter_session_ceilings() {
    tokio::time::timeout(std::time::Duration::from_secs(45),async{
 let w=SeamWorld::new(done_reply(),json!({}),json!({})).await;for(remote,token,expected)in[(false,false,200),(true,false,401),(true,true,200)]{let before=w.seen.lock().unwrap().len();let mut headers=vec![("host".into(),"127.0.0.1".into()),("authorization".into(),format!("Bearer {}",w.f.ph))];if token{headers.push(("av-session".into(),w.f.token.clone()));}let r=w.f.daemon.pipeline().handle(GatewayRequest{method:"GET".into(),path:"/p/demo/x".into(),headers,listener:Some(av_daemon::pipeline::ListenerInfo{id:if remote{"lan"}else{"local"}.into(),kind:if remote{"tls"}else{"loopback"}.into(),remote,advertise:vec![]}),..Default::default()}).await;assert_eq!(r.status,expected);assert!(!String::from_utf8_lossy(&r.body).contains(SECRET));if expected==401{let v:Value=serde_json::from_slice(&r.body).unwrap();assert_eq!(v["code"],"AV_SESSION_REQUIRED");assert_eq!(v["rule"],"remote_carrier");assert!(v["hint"].as_str().unwrap().contains("session token"));assert_eq!(w.seen.lock().unwrap().len(),before);}else{assert_eq!(w.seen.lock().unwrap().len(),before+1);assert!(w.seen.lock().unwrap().last().unwrap().contains(&format!("Bearer {SECRET}")));}}
 w.f.shared.run(|c|{for surface in ["control","approver","l4"]{let e=c.vault.add_listener(serde_json::from_value(json!({"id":format!("bad-{surface}"),"address":"0.0.0.0:9999","surfaces":[surface]})).unwrap()).unwrap_err();assert_eq!(e.as_vault().unwrap().code.as_str(),"AV_REMOTE_FORBIDDEN");}let ok=c.vault.add_listener(serde_json::from_value(json!({"id":"loopback-control","address":"127.0.0.1:9998","surfaces":["control"]})).unwrap()).unwrap();assert_eq!(ok.id,"loopback-control");c.vault.remove_listener("loopback-control").unwrap();let local=c.vault.create_session(Default::default()).unwrap().session;let remote=c.vault.create_session(av_store::vault::CreateSessionOptions{remote:true,..Default::default()}).unwrap().session;assert!(remote.remote);assert!(remote.max_expires_at<local.max_expires_at);assert!(remote.idle_timeout_ms<local.idle_timeout_ms);}).await.unwrap();assert!(audit_records(&w.f).await.iter().any(|r|r["kind"]=="listen.refused"));w.finish().await;
 }).await.unwrap();
}

#[test]
fn fix_factor_factory_refuses_prf_only_before_writing_and_keeps_passphrase_and_none_controls() {
    use av_store::model::FactorClass;
    use av_store::vault::{CreateOptions, Vault};
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let target = dir.path().join("refused");
    let e = Vault::create(
        &target,
        CreateOptions {
            factor: FactorClass::WebauthnPrf,
            passphrase: Some("test-fake-prf-not-a-recovery-factor".to_owned().into()),
        },
    )
    .err()
    .unwrap();
    let e = e.as_vault().unwrap();
    assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(e.extra.rule.as_deref(), Some("factor_order"));
    assert_eq!(e.extra.next.as_ref().unwrap(), "agent-vault passphrase set");
    assert!(!target.join("vault.db").exists());
    assert!(!target.join("device.key").exists());
    assert!(serde_json::from_value::<FactorClass>(json!("webauthn")).is_err());
    let target = dir.path().join("passphrase");
    let pass: av_core::secret::SecretString = WIDEN_PASS.to_owned().into();
    let mut v = Vault::create(
        &target,
        CreateOptions {
            factor: FactorClass::Passphrase,
            passphrase: Some(pass.clone()),
        },
    )
    .unwrap();
    assert_eq!(v.factors().unwrap(), vec![FactorClass::Passphrase]);
    v.lock().unwrap();
    drop(v);
    let mut v = Vault::open(&target).unwrap();
    assert_eq!(
        v.unlock(None)
            .unwrap_err()
            .as_vault()
            .unwrap()
            .code
            .as_str(),
        "AV_LOCKED"
    );
    assert!(v.unlock(Some(&pass)).unwrap());
    v.lock().unwrap();
    drop(v);
    let target = dir.path().join("none");
    let mut v = Vault::create(&target, CreateOptions::default()).unwrap();
    assert_eq!(v.factors().unwrap(), vec![FactorClass::None]);
    assert!(!v.remove_webauthn_unlock().unwrap());
    assert!(!v
        .remove_passphrase(&"anything fake".to_owned().into())
        .unwrap());
    v.lock().unwrap();
    drop(v);
    assert!(Vault::open(&target).unwrap().unlock(None).unwrap());
}

#[tokio::test]
async fn legacy_health_shape_is_absent_on_public_credential_listing_and_does_not_fail_secret_reads()
{
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = c25_bystander_fixture().await;
        let f = control_session_restart_with_pass(
            f,
            ported_common::seed_legacy_health_shape,
            Some(WIDEN_PASS),
        )
        .await;
        let (s, v) = credential_api(&f, "GET", "/v1/credentials", json!({})).await;
        assert_eq!(s, 200, "{v}");
        let row = v
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["slug"] == "broken-health")
            .unwrap();
        assert!(row["health"].is_null());
        assert!(f
            .shared
            .run(|c| c.vault.all_secrets().is_ok())
            .await
            .unwrap());
        assert!(!v.to_string().contains("legacy health shape"));
        assert!(!v.to_string().contains(C25_VALUE));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

async fn listener_bind_public(f: &Fixture, id: &str, extra: Value) -> C12Door {
    let mut spec = json!({"id":id,"address":"127.0.0.1:0","surfaces":["gateway"]});
    for (k, v) in extra.as_object().unwrap() {
        spec[k] = v.clone();
    }
    let (s, v) = credential_api(f, "POST", "/v1/listeners", spec).await;
    assert_eq!(s, 200, "{v}");
    let entry: av_store::model::ListenerRecord = serde_json::from_value(v).unwrap();
    let port = f.daemon.bind_listener(&entry).await.unwrap().1;
    C12Door {
        id: id.into(),
        port,
        tls: extra.get("tls").is_some(),
        remote: false,
        v6: false,
    }
}
async fn listener_tcp_answers(port: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
            return false;
        };
        if s.write_all(b"GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .is_err()
        {
            return false;
        }
        let mut b = [0u8; 128];
        s.read(&mut b)
            .await
            .is_ok_and(|n| n > 0 && b[..n].starts_with(b"HTTP/1.1 "))
    })
    .await
    .unwrap_or(false)
}
async fn listener_tls_connect(
    f: &Fixture,
    port: u16,
    trust: bool,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap();
    let config = if trust {
        let pem = std::fs::read_to_string(av_daemon::tls::tls_paths(f._dir.path()).cert).unwrap();
        let der = av_daemon::connectors::pinning::pem_certs(&pem).remove(0);
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ExactManagedCertificate(der)))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    };
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .map_err(|e| e.to_string())
}
#[tokio::test]
async fn fix_listeners_removal_cidr_and_invalid_configuration_have_live_socket_controls() {
    tokio::time::timeout(std::time::Duration::from_secs(45),async{
 let f=Fixture::new(&["header:x-key"]).await;let gone=listener_bind_public(&f,"gone",json!({})).await;let kept=listener_bind_public(&f,"kept",json!({})).await;assert!(listener_tcp_answers(gone.port).await);assert_eq!(credential_api(&f,"DELETE","/v1/listeners?id=gone",json!({})).await.0,200);assert!(!listener_tcp_answers(gone.port).await);assert!(listener_tcp_answers(kept.port).await);assert!(audit_records(&f).await.iter().any(|r|r["kind"]=="listen.unbound"&&r["listener_id"]=="gone"));let(_,listed)=credential_api(&f,"GET","/v1/listeners",json!({})).await;assert!(!listed.as_array().unwrap().iter().any(|r|r["id"]=="gone"));f.shared.run(|c|c.vault.add_listener(serde_json::from_value(json!({"id":"later","address":"127.0.0.1:0","surfaces":["mcp"]})).unwrap()).unwrap()).await.unwrap();assert_eq!(credential_api(&f,"DELETE","/v1/listeners?id=later",json!({})).await.0,200);
 let d=listener_bind_public(&f,"tailnet",json!({"allow_cidr":["100.64.0.0/10"]})).await;assert!(!listener_tcp_answers(d.port).await);assert!(audit_records(&f).await.iter().any(|r|r["kind"]=="listen.peer_refused"&&r["listener_id"]=="tailnet"));for(id,cidrs)in[("mine",json!(["10.0.0.0/8","127.0.0.0/8"])),("v6",json!(["::1/128","127.0.0.1/32"])),("open",json!([]))]{let d=listener_bind_public(&f,id,json!({"allow_cidr":cidrs})).await;assert!(listener_tcp_answers(d.port).await);assert!(!audit_records(&f).await.iter().any(|r|r["kind"]=="listen.peer_refused"&&r["listener_id"]==id));}
 for bad in [json!(["10.0.0.0/33"]),json!(["not-a-cidr"]),json!(["10.0.0.0"]),json!(["1.2.3.4/8x"]),json!("a-string")]{let(s,v)=credential_api(&f,"POST","/v1/listeners",json!({"id":"bad","address":"127.0.0.1:0","surfaces":["mcp"],"allow_cidr":bad})).await;assert!(s>=400,"{v}");assert!(!credential_api(&f,"GET","/v1/listeners",json!({})).await.1.as_array().unwrap().iter().any(|r|r["id"]=="bad"));}assert_eq!(credential_api(&f,"POST","/v1/listeners",json!({"id":"good","address":"127.0.0.1:0","surfaces":["mcp"],"allow_cidr":["100.64.0.0/10","fd7a:115c:a1e0::/48"]})).await.0,200);assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn fix_listeners_silent_and_established_tls_peers_are_dropped_on_removal_while_another_listener_works(
) {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let gone = listener_bind_public(&f, "tls", json!({"tls":{"managed":true}})).await;
        let kept = listener_bind_public(&f, "kept", json!({"tls":{"managed":true}})).await;
        let mut silent = tokio::net::TcpStream::connect(("127.0.0.1", gone.port))
            .await
            .unwrap();
        assert_eq!(
            credential_api(&f, "DELETE", "/v1/listeners?id=tls", json!({}))
                .await
                .0,
            200
        );
        let mut byte = [0];
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), silent.read(&mut byte))
                .await
                .unwrap()
                .is_ok_and(|n| n == 0)
        );
        let tls = listener_tls_connect(&f, kept.port, true).await.unwrap();
        assert_eq!(
            c12_exchange(tls, "GET", "/v1/status", vec![], vec![])
                .await
                .0,
            200
        );
        let d = listener_bind_public(&f, "established", json!({"tls":{"managed":true}})).await;
        assert_eq!(
            c12_exchange(
                listener_tls_connect(&f, d.port, true).await.unwrap(),
                "GET",
                "/v1/status",
                vec![],
                vec![]
            )
            .await
            .0,
            200
        );
        let mut tls = listener_tls_connect(&f, d.port, true).await.unwrap();
        assert_eq!(
            credential_api(&f, "DELETE", "/v1/listeners?id=established", json!({}))
                .await
                .0,
            200
        );
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), tls.read(&mut byte))
            .await
            .unwrap();
        assert!(closed.is_err() || closed.is_ok_and(|n| n == 0));
        assert!(listener_tls_connect(&f, d.port, true).await.is_err());
        assert_eq!(
            c12_exchange(
                listener_tls_connect(&f, kept.port, true).await.unwrap(),
                "GET",
                "/v1/status",
                vec![],
                vec![]
            )
            .await
            .0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn listeners_certificate_names_surface_isolation_trust_and_pipeline_peer_are_real() {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let info = av_daemon::tls::ensure_certificate(f._dir.path(), false).unwrap();
        assert!(info.created);
        assert!(info.pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(av_core::jsre::compile(r"^[0-9A-F]{2}(:[0-9A-F]{2})+$")
            .unwrap()
            .is_match(&info.fingerprint));
        let der = av_daemon::connectors::pinning::pem_certs(&info.pem).remove(0);
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        assert!(cert.is_ca());
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(san.value.general_names.iter().any(|n| matches!(
            n,
            x509_parser::extensions::GeneralName::DNSName("localhost")
        )));
        assert!(san.value.general_names.iter().any(
            |n| matches!(n,x509_parser::extensions::GeneralName::IPAddress(b) if *b==[127,0,0,1])
        ));
        let d = listener_bind_public(
            &f,
            "mcp-only",
            json!({"surfaces":["mcp"],"tls":{"managed":true}}),
        )
        .await;
        let init =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}))
                .unwrap();
        assert!(
            c12_exchange(
                listener_tls_connect(&f, d.port, true).await.unwrap(),
                "POST",
                "/mcp",
                vec![("content-type".into(), "application/json".into())],
                init
            )
            .await
            .0 < 500
        );
        let (s, _, b) = c12_exchange(
            listener_tls_connect(&f, d.port, true).await.unwrap(),
            "GET",
            "/p/demo/user",
            vec![],
            vec![],
        )
        .await;
        assert_eq!(s, 404);
        assert!(serde_json::from_slice::<Value>(&b).unwrap()["detail"]
            .as_str()
            .unwrap()
            .contains("does not serve the gateway surface"));
        assert!(listener_tls_connect(&f, d.port, false).await.is_err());
        let d = listener_bind_public(&f, "peer-test", json!({"tls":{"managed":true}})).await;
        let before = audit_records(&f).await.len();
        let _ = c12_exchange(
            listener_tls_connect(&f, d.port, true).await.unwrap(),
            "GET",
            "/p/nope/whatever",
            vec![("host".into(), "127.0.0.1".into())],
            vec![],
        )
        .await;
        let rows = audit_records(&f).await;
        let row = rows[before..]
            .iter()
            .find(|r| r["peer"].is_object())
            .unwrap();
        assert_eq!(row["peer"]["listener_id"], "peer-test");
        assert_eq!(row["peer"]["kind"], "tls");
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fix_audit_valid_json_but_malformed_last_records_never_lock_out_owner_and_stay_reported() {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        for bad in [
            "{}",
            r#"{"seq":"6","ts":"x","kind":"k","hash":"00","prev_hash":"00"}"#,
            r#"{"seq":6,"ts":"x","kind":"k"}"#,
        ] {
            let f = Fixture::new(&["header:x-key"]).await;
            let at = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let captured = at.clone();
            let f = control_session_restart_after_seed(f, move |dir| {
                captured.store(
                    ported_common::seed_audit_tail(dir, bad).unwrap(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            })
            .await;
            let (s, v) = credential_api(&f, "GET", "/v1/lockstate", json!({})).await;
            assert_eq!(s, 200);
            assert_eq!(v["locked"], false);
            let (s, v) = credential_api(&f, "GET", "/v1/audit/verify", json!({})).await;
            assert_eq!(s, 200, "{v}");
            assert_eq!(v["ok"], false);
            assert_eq!(v["brokenAt"], at.load(std::sync::atomic::Ordering::SeqCst));
            assert!(audit_records(&f)
                .await
                .iter()
                .any(|r| r["kind"] == "audit.corruption_detected"));
            let record = f
                .shared
                .run(|c| {
                    c.vault
                        .audit_mut()
                        .unwrap()
                        .write("fixture.after", serde_json::Map::new())
                        .unwrap()
                })
                .await
                .unwrap();
            assert!(record.seq >= at.load(std::sync::atomic::Ordering::SeqCst));
            let f = control_session_restart_after_seed(f, |_| {}).await;
            assert_eq!(
                credential_api(&f, "GET", "/v1/lockstate", json!({}))
                    .await
                    .1["locked"],
                false
            );
            assert_eq!(f.get().await.status, 200);
            credential_finish(&f).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_audit_sqlite_rows_survive_two_restarts_and_incomplete_json_cannot_be_written() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let f = control_session_restart_after_seed(f, |dir| {
            assert!(ported_common::seed_audit_tail(dir, r#"{"seq":99,"ts":"20"#).is_err());
        })
        .await;
        for _ in 0..2 {
            assert_eq!(
                credential_api(&f, "GET", "/v1/audit/verify", json!({}))
                    .await
                    .1["ok"],
                true
            );
            assert_eq!(f.get().await.status, 200);
        }
        let f = control_session_restart_after_seed(f, |_| {}).await;
        assert_eq!(
            credential_api(&f, "GET", "/v1/audit/verify", json!({}))
                .await
                .1["ok"],
            true
        );
        assert!(!audit_records(&f)
            .await
            .iter()
            .any(|r| r["kind"] == "audit.corruption_detected"));
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_audit_nonstring_session_reason_is_stored_without_putting_agent_words_in_audits() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        for reason in [json!(1.5), json!("reading issues")] {
            let (s, v) = credential_api(
                &f,
                "POST",
                "/v1/session-requests",
                json!({"cred":"demo","reason":reason}),
            )
            .await;
            assert_eq!(s, 200, "{v}");
            let id = v["id"].as_str().unwrap().to_owned();
            assert!(f
                .shared
                .run(move |c| c.sr_get(&id).is_some())
                .await
                .unwrap());
        }
        let rows = audit_records(&f).await;
        let opened = rows
            .iter()
            .filter(|r| r["kind"] == "session_request.opened")
            .collect::<Vec<_>>();
        assert_eq!(opened.len(), 2);
        assert_eq!(opened[1]["cred"], "demo");
        assert!(opened
            .iter()
            .all(|r| r.get("agent_reason_untrusted").is_none()));
        assert!(!json!(rows).to_string().contains("reading issues"));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fix_process_ordinary_daemon_run_and_stop_emit_no_process_global_uncaught_records() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let f = Fixture::new(&["header:x-key"]).await;
        assert_eq!(
            credential_api(&f, "GET", "/v1/status", json!({})).await.0,
            200
        );
        assert_eq!(f.get().await.status, 200);
        f.daemon.stop().await;
        let rows = audit_records(&f).await;
        assert!(rows.iter().any(|r| r["kind"] == "daemon.stop"));
        assert!(!rows
            .iter()
            .any(|r| r["kind"] == "daemon.uncaught" || r["kind"] == "daemon.handler_error"));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn integration_r6_tripwire_defaults_are_read_only_edits_keep_other_rules_and_enable_keeps_edits(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let (s, shown) = credential_api(&f, "GET", "/v1/tripwires", json!({})).await;
        assert_eq!(s, 200);
        assert_eq!(shown["rules_saved"], false);
        assert_eq!(shown["rules"], av_daemon::tripwire::default_rules_json());
        assert!(f
            .shared
            .run(|c| c.vault.get_settings().unwrap().get("tripwires").is_none())
            .await
            .unwrap());
        let mut rules = shown["rules"].clone();
        for r in rules.as_array_mut().unwrap() {
            if r["id"] == "replay" {
                r["threshold"] = json!(3);
            }
        }
        assert_eq!(
            credential_api(&f, "POST", "/v1/tripwires", json!({"rules":rules}))
                .await
                .0,
            200
        );
        let (_, after) = credential_api(&f, "GET", "/v1/tripwires", json!({})).await;
        assert_eq!(after["rules_saved"], true);
        assert_eq!(after["rules"], rules);
        assert_eq!(after["enabled"], false);
        assert_eq!(
            after["rules"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].as_str().unwrap())
                .collect::<std::collections::BTreeSet<_>>(),
            ["bad_location", "cross_session", "deny_paths", "replay"]
                .into_iter()
                .collect()
        );
        assert_eq!(
            credential_api(&f, "POST", "/v1/tripwires", json!({"enabled":true}))
                .await
                .0,
            200
        );
        let (_, after) = credential_api(&f, "GET", "/v1/tripwires", json!({})).await;
        assert_eq!(after["enabled"], true);
        assert_eq!(after["rules"], rules);
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_r6_preflight_assumption_is_explicit_boolean_and_never_hides_a_misplaced_placeholder(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let cap = integration_create(
            &f,
            json!({"cred":"demo","methods":["GET","POST"],"paths":["/repos/**"]}),
        )
        .await;
        let before = store_snapshot(&f).await;
        let at = audit_records(&f).await.len();
        for (method, path, headers, would) in [
            ("GET", "/p/demo/repos/my-org/x", json!([]), "allow"),
            (
                "GET",
                "/p/demo/repos/my-org/x",
                json!([["content-type", "application/json"]]),
                "allow",
            ),
            (
                "POST",
                "/p/demo/repos/my-org/x/issues",
                json!([["content-type", "application/json"]]),
                "hold",
            ),
            ("GET", "/p/demo/admin", json!([]), "deny"),
            (
                "GET",
                "/p/demo/repos/my-org/x",
                json!([["x-note", cap["placeholder"]]]),
                "deny",
            ),
        ] {
            let (s, v) = control_mcp_preflight_http(
                &f,
                "POST",
                json!({"method":method,"path":path,"headers":headers,"assume_placeholder":true})
                    .to_string(),
                vec![("av-session".into(), cap["token"].as_str().unwrap().into())],
            )
            .await;
            assert_eq!(s, 200, "{v}");
            assert_eq!(v["would"], would);
            if would == "deny" {
                assert!(v["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|c| c["rule"] != "no_placeholder"));
            }
            if headers.to_string().contains("x-note") {
                assert_eq!(
                    v["checks"].as_array().unwrap().last().unwrap()["code"],
                    "AV_BAD_LOCATION"
                );
            }
        }
        assert_eq!(store_snapshot(&f).await, before);
        let rows = audit_records(&f).await;
        assert_eq!(rows.len(), at + 5);
        assert!(rows[at..]
            .iter()
            .all(|r| r["kind"] == "request.preflighted"));
        assert!(f.up.hits.lock().unwrap().is_empty());
        assert!(f.daemon.pipeline().pending_approvals().await.is_empty());
        let auth = vec![("av-session".into(), cap["token"].as_str().unwrap().into())];
        let (s, v) = control_mcp_preflight_http(
            &f,
            "POST",
            json!({"method":"GET","path":"/p/demo/repos/my-org/x"}).to_string(),
            auth.clone(),
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(v["would"], "deny");
        assert_eq!(
            v["checks"].as_array().unwrap().last().unwrap()["rule"],
            "no_placeholder"
        );
        assert_eq!(
            control_mcp_preflight_http(
                &f,
                "POST",
                json!({"method":"GET","path":"/p/demo/repos/my-org/x","assume_placeholder":true})
                    .to_string(),
                auth.clone()
            )
            .await
            .1["would"],
            "allow"
        );
        for value in [json!("yes"), json!(1), Value::Null] {
            let (s, v) = control_mcp_preflight_http(
                &f,
                "POST",
                json!({"method":"GET","path":"/p/demo/repos/my-org/x","assume_placeholder":value})
                    .to_string(),
                auth.clone(),
            )
            .await;
            assert_eq!(s, 403);
            assert_eq!(v["rule"], "preflight_shape");
        }
        assert_eq!(
            integration_http(&f, &cap, "GET", "/repos/ordinary", None).await["status"],
            200
        );
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_r6_approved_request_returns_granted_shape_and_probe_all_preserves_no_probe_and_real_failures(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let f=Fixture::new(&["header:x-key"]).await;let(error,asked)=integration_tool(&f,None,"vault_request_session",json!({"cred":"demo","methods":["GET","POST"],"paths":["/user"],"budget":5,"reason":"read me"})).await;assert!(!error);assert_eq!(asked["state"],"pending");let(s,v)=credential_api(&f,"POST","/v1/session-requests/decide",json!({"id":asked["request_id"],"granted":true,"overrides":{"methods":["GET"],"paths":["/user"],"grant_ttl_minutes":10}})).await;assert_eq!(s,200,"{v}");assert_eq!(v["granted"]["methods"],json!(["GET"]));assert_eq!(v["granted"]["paths"],json!(["/user"]));assert_eq!(v["granted"]["budget"],5);assert_eq!(v["granted"]["grant_ttl_minutes"],10);let p=control_session_policy(&f,v["session"]["grant_id"].as_str().unwrap()).await;assert_eq!(p["methods"],json!(["GET"]));
 let(s,v)=credential_api(&f,"POST","/v1/credentials/test",json!({"slug":"demo"})).await;assert_eq!(s,404);assert_eq!(v["code"],"AV_NOT_FOUND");assert_eq!(v["rule"],"no_probe");assert_eq!(credential_api(&f,"POST","/v1/credentials",json!({"slug":"openai","kind":"openai","host":"api.openai.com","value":"test-secret-quarantined-probe-123456789","sites":["header:authorization:Bearer"]})).await.0,200);assert_eq!(credential_api(&f,"POST","/v1/credentials/quarantine",json!({"slug":"openai"})).await.0,200);let(s,v)=credential_api(&f,"POST","/v1/credentials/test",json!({"all":true})).await;assert_eq!(s,200);let rows=v["results"].as_array().unwrap();assert_eq!(rows.iter().find(|r|r["slug"]=="openai").unwrap()["error"],"AV_QUARANTINED");assert_eq!(rows.iter().find(|r|r["slug"]=="demo").unwrap()["rule"],"no_probe");assert_eq!(credential_api(&f,"DELETE","/v1/credentials?slug=openai",json!({})).await.0,200);let(s,v)=credential_api(&f,"POST","/v1/credentials/test",json!({"all":true})).await;assert_eq!(s,200);assert!(v["results"].as_array().unwrap().iter().all(|r|r["rule"]=="no_probe"));assert!(f.up.hits.lock().unwrap().is_empty());assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_r6_bidi_reason_request_and_held_write_keep_the_daemon_protocol_and_safe_headline(
) {
    tokio::time::timeout(std::time::Duration::from_secs(30),async{
 let f=Fixture::new(&["header:x-key"]).await;let reason="fix\u{202e}evil\u{2066}x\u{2069}\u{2028}y\u{2029}\u{1b}[31mred";let(error,v)=integration_tool(&f,None,"vault_request_session",json!({"cred":"demo","methods":["GET"],"reason":reason})).await;assert!(!error);assert_eq!(v["state"],"pending");let cap=integration_create(&f,json!({"cred":"demo","methods":["GET","POST"]})).await;let r=integration_http(&f,&cap,"POST","/a\u{202e}/b",Some("{\"t\":\"\u{202e}x\"}")).await;assert_eq!(r["status"],202);assert!(f.up.hits.lock().unwrap().is_empty());assert_eq!(av_daemon::notify::clean_headline("a\u{202a}b\u{202b}c\u{202c}d\u{202d}e\u{202e}f\u{2066}g\u{2067}h\u{2068}i\u{2069}j\u{2028}k\u{2029}l"),"abcdefghij k l");assert_eq!(integration_http(&f,&cap,"GET","/ordinary",None).await["status"],200);credential_finish(&f).await;
 }).await.unwrap();
}
#[tokio::test]
async fn touchid_daemon_bare_enrollment_and_missing_recovery_factor_have_actionable_refusals() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 use base64::Engine;let body=json!({"action":"enroll","credential_id":"fake-credential","prf_secret":base64::engine::general_purpose::STANDARD.encode([7u8;32])});let f=Fixture::new(&["header:x-key"]).await;let(s,v)=credential_api(&f,"POST","/v1/factors/webauthn",body.clone()).await;assert_eq!(s,403,"{v}");assert_eq!(v["code"],"AV_POLICY_DENIED");assert_eq!(v["rule"],"factor_order");assert_eq!(v["next"],"agent-vault passphrase set");assert!(v["hint"].as_str().unwrap().contains("agent-vault passphrase set"));assert!(v["hint"].as_str().unwrap().contains("recovery")||v["hint"].as_str().unwrap().contains("fall back"));assert!(!f.shared.run(|c|c.vault.has_webauthn_unlock().unwrap()).await.unwrap());let(s,v)=credential_api(&f,"POST","/v1/presence",fix_presence_record(41)).await;assert_eq!(s,403);assert_eq!(v["rule"],"factor_order");assert_eq!(v["next"],"agent-vault passphrase set");assert!(f.shared.run(|c|c.vault.presence_key().unwrap().is_none()).await.unwrap());credential_factor(&f).await;let(s,v)=credential_api(&f,"POST","/v1/factors/webauthn",body).await;assert_eq!(s,401);assert_eq!(v["code"],"AV_PRESENCE_REQUIRED");assert_eq!(f.get().await.status,200);credential_finish(&f).await;
 }).await.unwrap();
}

struct UiContractFixture {
    _dir: tempfile::TempDir,
    ui: av_daemon::ui::server::UiServer,
    cookie: String,
    auth: ported_common::FakeAuthenticator,
    replies: Arc<Mutex<std::collections::HashMap<String, (u16, Value)>>>,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    peer: tokio::task::JoinHandle<()>,
    queries: Arc<Mutex<Vec<(String, String)>>>,
    token: String,
    ph: String,
}
impl UiContractFixture {
    async fn new(idle_ms: u64) -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let socket = dir.path().join("stub.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let replies: Arc<Mutex<std::collections::HashMap<String, (u16, Value)>>> = Arc::default();
        let calls: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
        let queries: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let captured_queries = queries.clone();
        let responses = replies.clone();
        let observed = calls.clone();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let peer = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let captured_queries = captured_queries.clone();
                let responses = responses.clone();
                let observed = observed.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let captured_queries = captured_queries.clone();
                            let responses = responses.clone();
                            let observed = observed.clone();
                            let counter = counter.clone();
                            async move {
                                use base64::Engine;
                                let key = format!("{} {}", req.method(), req.uri().path());
                                captured_queries
                                    .lock()
                                    .unwrap()
                                    .push((key.clone(), req.uri().query().unwrap_or("").into()));
                                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                                let body =
                                    serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
                                let (status, value) = if key == "GET /v1/presence" {
                                    (200, {
                                        let mut v = fix_presence_record(42);
                                        v["enrolledAt"] = json!("2026-10-27T00:00:00Z");
                                        v
                                    })
                                } else if key == "POST /v1/presence/challenge" {
                                    let n =
                                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    (
                                        200,
                                        json!({"challengeId":format!("fixture-challenge-{n}"),"challenge":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([n as u8;32]),"allowCredentials":[{"id":fix_presence_record(42)["credentialId"],"type":"public-key"}],"rpId":"localhost"}),
                                    )
                                } else {
                                    observed.lock().unwrap().push((key.clone(), body));
                                    responses
                                        .lock()
                                        .unwrap()
                                        .get(&key)
                                        .cloned()
                                        .unwrap_or((200, json!({"ok":true})))
                                };
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(status)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from(
                                            serde_json::to_vec(&value).unwrap(),
                                        )))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let dist = dir.path().join("dist");
        std::fs::create_dir(&dist).unwrap();
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><title>fake contract UI</title>",
        )
        .unwrap();
        let ui = av_daemon::ui::server::UiServer::start(
            &socket,
            av_daemon::ui::server::UiServerOptions {
                port: 0,
                idle_ms: Some(idle_ms),
                dist_dir: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let url = url::Url::parse(&ui.url()).unwrap();
        let (s, h, _) = loopback_http_host(
            ui.bound_port(),
            "localhost",
            "GET",
            &format!("{}?{}", url.path(), url.query().unwrap()),
            vec![],
            vec![],
        )
        .await;
        assert_eq!(s, 302);
        let cookie = h
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let token = "avs1.AAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        let ph = av_core::placeholder::mint(&av_core::placeholder::MintInput {
            k_ph: &av_core::secret::Key32::from_bytes([7u8; 32]),
            sid: "aaaaaaaaaaaa",
            slug: "demo",
            field: "token",
        })
        .unwrap()
        .text;
        Self {
            _dir: dir,
            ui,
            cookie,
            auth: ported_common::FakeAuthenticator::new(42),
            replies,
            calls,
            peer,
            queries,
            token,
            ph,
        }
    }
    fn set(&self, key: &str, status: u16, body: Value) {
        self.replies
            .lock()
            .unwrap()
            .insert(key.into(), (status, body));
    }
    async fn wire(
        &self,
        method: &str,
        path: &str,
        body: Value,
        authenticated: bool,
    ) -> (u16, Vec<(String, String)>, Value) {
        let mut h = vec![
            ("x-av-ui".into(), "1".into()),
            ("content-type".into(), "application/json".into()),
        ];
        if authenticated {
            h.push(("cookie".into(), self.cookie.clone()));
        }
        let (s, h, b) = loopback_http_host(
            self.ui.bound_port(),
            "localhost",
            method,
            &format!("/api/{path}"),
            h,
            serde_json::to_vec(&body).unwrap(),
        )
        .await;
        (s, h, serde_json::from_slice(&b).unwrap())
    }
    async fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (s, _, v) = self.wire(method, path, body, true).await;
        (s, v)
    }
    async fn proof(&self, op: &str, params: &Value) -> Value {
        let op = av_daemon::util::operation_for(op, params).unwrap();
        let (s, ch) = self
            .api("POST", "presence/challenge", json!({"operation":op}))
            .await;
        assert_eq!(s, 200, "{ch}");
        let mut p = self
            .auth
            .assertion(ch["challenge"].as_str().unwrap(), &self.ui.origin());
        p["challengeId"] = ch["challengeId"].clone();
        p
    }
    async fn stop(&self) {
        self.ui.stop().await;
        self.peer.abort();
    }
}

#[tokio::test]
async fn ui_guard_leaked_capabilities_are_scrubbed_on_reads_and_errors_but_created_cards_work() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let u=UiContractFixture::new(60000).await;
 u.set("GET /v1/sessions/detail",200,json!({"session":{"id":"s_1","label":format!("pasted {} by mistake",u.token),"state":"active"},"token":u.token,"grants":[{"cred":"demo","placeholders":[{"id":"ph_01","field":"token","uses":1,"placeholder":u.ph}],"note":format!("the agent sent {} to /repos",u.ph)}],"activity":{"complete":true,"paths":[{"method":"GET","path":"/repos/av1.example/x","count":2}]}}));
 let(s,v)=u.api("GET","sessions/detail?sid=s_1",json!({})).await;assert_eq!(s,200);assert!(!v.to_string().contains(&u.ph));assert!(!v.to_string().contains("avs1."));assert_eq!(v["grants"][0]["placeholders"][0]["id"],"ph_01");assert_eq!(v["grants"][0]["note"],"the agent sent «placeholder» to /repos");assert_eq!(v["session"]["label"],"pasted «token» by mistake");assert_eq!(v["session"]["state"],"active");assert_eq!(v["activity"]["paths"][0]["path"],"/repos/av1.example/x");
 let normal=json!({"a":[1,true,null,"x"],"b":{"c":"GET /user"}});assert_eq!(av_daemon::ui::server::toward_page(&normal,0),normal);
 u.set("GET /v1/approvals",200,json!([{"id":"ap_1","summary":format!("POST api.example.com/x?ph={}",u.ph),"created_at":"2026-10-27T00:00:00Z"}]));u.set("GET /v1/session-requests",200,json!([]));u.set("GET /v1/notify",200,json!({"webhook":{"host":"hooks.example","detail":"minimal","configured_at":"x"},"webhook_url":"https://hooks.example/T0/B0/fake-secret"}));u.set("GET /v1/templates",404,json!({"code":"AV_NOT_FOUND","detail":format!("no template; you sent {}",u.ph)}));
 let(s,v)=u.api("GET","pending",json!({})).await;assert_eq!(s,200,"{v}");assert!(!v.to_string().contains(&u.ph));assert!(v.to_string().contains("«placeholder»"));assert_eq!(u.api("GET","notify",json!({})).await.1,json!({"webhook":{"host":"hooks.example","detail":"minimal","configured_at":"x"}}));let(s,v)=u.api("GET","templates?name=x",json!({})).await;assert_eq!(s,404);assert!(!v.to_string().contains(&u.ph));
 u.set("POST /v1/sessions",200,json!({"session_id":"s_2","token":u.token,"placeholder":u.ph,"grants":[{"cred":"demo","placeholder":u.ph}]}));let mut b=json!({"cred":"demo","methods":["GET"]});b["presence"]=u.proof("session.create",&b).await;let(s,v)=u.api("POST","sessions",b).await;assert_eq!(s,200,"{v}");assert_eq!(v["token"],u.token);assert_eq!(v["grants"][0]["placeholder"],u.ph);u.stop().await;
 }).await.unwrap();
}
#[tokio::test]
async fn ui_handoff_errors_never_copy_secrets_and_success_only_copies_card_fields() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let u=UiContractFixture::new(60000).await;let hook="https://hooks.example/fake-secret-XYZ";let value="fake-secret-value-XYZ";let pass="fake-recovery-passphrase-XYZ";let bundle="fake-bundle-secret-XYZ";
 for error in [true,false]{let body=json!({"session_id":"s_2","token":u.token,"placeholder":u.ph,"usage":[format!("header Authorization: Bearer {}",u.ph)],"label":"ci","expires_at":"2026-10-28T00:00:00Z","infinite":false,"code":"AV_POLICY_DENIED","detail":"no","webhook_url":hook,"value":value,"bundle":{"sealed":bundle},"recovery_passphrase":pass,"grants":[{"cred":"demo","grant_id":"g_1","placeholder":u.ph,"usage":[format!("header Authorization: Bearer {}",u.ph)],"base_url":"http://127.0.0.1:7777/p/demo","probe_path":"/user","env":{"key":"DEMO_TOKEN"},"lint":[],"value":value,"webhook_url":hook,"Bundle":bundle}]});u.set("POST /v1/sessions",if error{400}else{200},body);let mut b=json!({"cred":"demo","methods":["GET"]});b["presence"]=u.proof("session.create",&b).await;let(s,v)=u.api("POST","sessions",b).await;assert_eq!(s,if error{400}else{200},"{v}");for secret in [hook,value,pass,bundle]{assert!(!v.to_string().contains(secret));}if error{assert!(!v.to_string().contains(&u.token));assert!(!v.to_string().contains(&u.ph));assert_eq!(v["detail"]["code"],"AV_POLICY_DENIED");assert_eq!(v["detail"]["grants"][0]["cred"],"demo");}else{assert_eq!(v["token"],u.token);assert_eq!(v["placeholder"],u.ph);assert_eq!(v["session_id"],"s_2");assert_eq!(v["label"],"ci");assert_eq!(v["expires_at"],"2026-10-28T00:00:00Z");assert_eq!(v["infinite"],false);let g=&v["grants"][0];assert_eq!(g["placeholder"],u.ph);assert_eq!(g["usage"],json!([format!("header Authorization: Bearer {}",u.ph)]));assert_eq!(g["base_url"],"http://127.0.0.1:7777/p/demo");assert_eq!(g["cred"],"demo");assert_eq!(g["env"]["key"],"DEMO_TOKEN");assert_eq!(g["probe_path"],"/user");assert_eq!(v["usage"],g["usage"]);}}
 let b=json!({"slug":"demo","kind":"github","value":value});let presence=u.proof("cred.add",&b).await;let n=u.calls.lock().unwrap().iter().filter(|(k,_)|k=="POST /v1/credentials").count();let mut b=b;b["op"]=json!("cred.remove");b["presence"]=presence;let(s,v)=u.api("POST","credentials",b).await;assert_eq!(s,403);assert_eq!(v["detail"]["rule"],"reserved_operation_field");assert!(!v.to_string().contains(value));assert_eq!(u.calls.lock().unwrap().iter().filter(|(k,_)|k=="POST /v1/credentials").count(),n);u.stop().await;
 }).await.unwrap();
}
#[test]
fn ui_handoff_scalar_copy_and_recursive_key_folding_leave_ordinary_fields_untouched() {
    use av_daemon::ui::server::{handoff_toward_page, toward_page};
    let ph = av_core::placeholder::mint(&av_core::placeholder::MintInput {
        k_ph: &av_core::secret::Key32::from_bytes([7u8; 32]),
        sid: "aaaaaaaaaaaa",
        slug: "demo",
        field: "token",
    })
    .unwrap()
    .text;
    let token = "avs1.AAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let hook = "https://hooks.example/fake-secret";
    let out = handoff_toward_page(
        &json!({"token":{"value":"fake-value"},"label":[hook,{"webhook_url":hook}],"grants":[{"cred":"demo","placeholder":ph,"usage":[{"value":"fake-value"}],"sites":["header:Authorization:Bearer"]}]}),
    );
    assert!(out.get("token").is_none());
    assert_eq!(out["grants"][0]["placeholder"], ph);
    assert_eq!(out["grants"][0]["usage"], json!([{}]));
    assert_eq!(
        out["grants"][0]["sites"],
        json!(["header:Authorization:Bearer"])
    );
    assert_eq!(out["label"], json!([hook, {}]));
    assert_eq!(
        handoff_toward_page(&json!({"token":token,"placeholder":ph,"value":"fake-value"})),
        json!({"token":token,"placeholder":ph})
    );
    assert_eq!(handoff_toward_page(&json!([token])), json!(["«token»"]));
    assert_eq!(
        toward_page(
            &json!({"session":{"id":"s_1","state":"active","Webhook_URL":hook,"webhook-url":hook},"VALUE":"fake-value","Recovery-Passphrase":"fake-pass","Bundle":{"sealed":"fake-bundle"},"nested":{"deeper":{"Token":token,"PLACE-HOLDER":"not withheld","Placeholder":ph}},"items":[{"Value":"fake-value","label":"kept"},[{"WEBHOOK-URL":hook,"recovery_PASSPHRASE":"fake-pass"}]],"token_hash":"kept, not a withheld name"}),
            0
        ),
        json!({"session":{"id":"s_1","state":"active"},"nested":{"deeper":{"PLACE-HOLDER":"not withheld"}},"items":[{"label":"kept"},[{}]],"token_hash":"kept, not a withheld name"})
    );
    assert_eq!(
        toward_page(
            &json!({"Webhook_URL":hook,"webhook-url":hook,"VALUE":"fake-value","Recovery-Passphrase":"fake-pass","PRF-Secret":"x","keep":1}),
            0
        ),
        json!({"keep":1})
    );
    let normal = json!([[{"a":{"token-hash":"t","Tokens":2,"values":[1]}}]]);
    assert_eq!(toward_page(&normal, 0), normal);
}
#[tokio::test]
async fn ui_default_serves_exact_shipped_index_and_asset_bytes_with_strict_policy() {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let u = UiContractFixture::new(60000).await;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/ui/dist");
        let mut files = vec![("/".to_owned(), root.join("index.html"))];
        for e in std::fs::read_dir(root.join("assets")).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_file() {
                files.push((
                    format!("/assets/{}", e.file_name().to_str().unwrap()),
                    e.path(),
                ));
            }
        }
        assert!(files.len() > 1);
        for (path, file) in files {
            let (s, h, b) = loopback_http_host(
                u.ui.bound_port(),
                "localhost",
                "GET",
                &path,
                vec![("cookie".into(), u.cookie.clone())],
                vec![],
            )
            .await;
            assert_eq!(s, 200, "{path}");
            assert_eq!(b, std::fs::read(&file).unwrap(), "{}", file.display());
            assert_eq!(
                h.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
                    .unwrap()
                    .1,
                av_daemon::ui::server::STRICT_CSP
            );
            assert_eq!(
                h.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
                    .unwrap()
                    .1,
                "no-store"
            );
        }
        u.stop().await;
    })
    .await
    .unwrap();
}
#[test]
fn ui_guard_passphrase_spellings_and_separator_runs_are_withheld_at_every_depth() {
    use av_daemon::ui::server::toward_page;
    assert_eq!(
        toward_page(
            &json!({"passphrase":"fake-secret","PassPhrase":"fake-secret","pass-phrase":"fake-secret","PASS_PHRASE":"fake-secret","nested":[{"passphrase":"fake-secret","label":"kept"}],"has_passphrase":true,"passphrase_set_at":"x","note":"kept"}),
            0
        ),
        json!({"nested":[{"label":"kept"}],"has_passphrase":true,"passphrase_set_at":"x","note":"kept"})
    );
    assert_eq!(
        toward_page(
            &json!({"pass--phrase":"fake-secret","pass__phrase":"fake-secret","pass phrase":"fake-secret","Pass -_ Phrase":"fake-secret","nested":[{"recovery pass phrase":"fake-secret","recovery--passphrase":"fake-secret","webhook--url":"https://hooks.example/fake-secret"}],"pass phrase note":"kept","has_passphrase":true}),
            0
        ),
        json!({"nested":[{}],"pass phrase note":"kept","has_passphrase":true})
    );
}
#[test]
fn ui_operation_secrets_are_canonical_digests_and_request_fields_cannot_overwrite_them() {
    use av_daemon::util::operation_for;
    use sha2::{Digest, Sha256};
    let sha = |s: &str| {
        use std::fmt::Write;
        let mut out = String::new();
        for byte in Sha256::digest(s.as_bytes()) {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    };
    let bundle = json!({"format":"agent-vault-backup","version":1,"created_at":"2026-10-27T00:00:00.000Z","nonce":"bm9uY2U","ct":"Y2lwaGVy"});
    let params = json!({"value":"fake_SECRETVALUE","prf_secret":"cHJmc2VjcmV0","recovery_passphrase":"a fake recovery passphrase","bundle":bundle,"webhook_url":"https://hooks.example/fake-secret"});
    let op = operation_for("x", &params).unwrap();
    let text = serde_json::to_string(&op).unwrap();
    for (k, v) in params.as_object().unwrap() {
        assert!(op.get(k).is_none());
        let digest = op[format!("{k}_sha256")].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        if let Some(s) = v.as_str() {
            assert!(!text.contains(s));
        }
    }
    assert!(!text.contains("Y2lwaGVy"));
    for (op, key, value) in [
        ("cred.add", "value", json!("v")),
        ("touchid.enroll", "prf_secret", json!("p")),
        ("notify.set", "webhook_url", json!("https://h/x")),
        ("x", "value", Value::Null),
    ] {
        let mut p = json!({});
        p[key] = value.clone();
        let got = operation_for(op, &p).unwrap();
        assert_eq!(
            got[format!("{key}_sha256")],
            sha(value.as_str().unwrap_or("null"))
        );
    }
    let a = operation_for("backup.restore", &json!({"bundle":bundle})).unwrap();
    let mut changed = bundle.clone();
    changed["ct"] = json!("b3RoZXI");
    let b = operation_for("backup.restore", &json!({"bundle":changed})).unwrap();
    assert_ne!(a["bundle_sha256"], b["bundle_sha256"]);
    assert_ne!(a["bundle_sha256"], sha("[object Object]"));
    let reordered: serde_json::Map<String, Value> = bundle
        .as_object()
        .unwrap()
        .iter()
        .rev()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert_eq!(
        a,
        operation_for("backup.restore", &json!({"bundle":reordered})).unwrap()
    );
    let fields = json!({"cred":"demo","methods":["GET"],"paths":["/only"]});
    let shown = operation_for("session.create", &fields).unwrap();
    let mut swapped = fields.clone();
    swapped["op"] = json!("session.create");
    assert!(operation_for("placeholder.issue", &swapped).is_err());
    assert_eq!(shown["op"], "session.create");
    for (name, key) in [("touchid.enroll", "prf_secret"), ("cred.add", "value")] {
        let mut human = json!({"credential_id":"c","slug":"s"});
        human[key] = json!("HUMAN");
        let signed = operation_for(name, &human).unwrap();
        let mut attack = human;
        attack[key] = json!("ATTACKER");
        attack[format!("{key}_sha256")] = json!(sha("HUMAN"));
        assert!(operation_for(name, &attack).is_err());
        assert_eq!(signed[format!("{key}_sha256")], sha("HUMAN"));
    }
    assert_eq!(
        operation_for(
            "cred.add",
            &json!({"slug":"s","kind":"http","value":"v","presence":{"x":1}})
        )
        .unwrap(),
        json!({"op":"cred.add","slug":"s","kind":"http","value_sha256":sha("v")})
    );
}

#[tokio::test]
async fn ui_route_signature_matrix_rejects_unsigned_swapped_fields_and_wrong_ops_and_forwards_exact_proofs(
) {
    tokio::time::timeout(std::time::Duration::from_secs(50),async{
 use av_daemon::ui::server::{GATED,DAEMON_VERIFIED};
 let u=UiContractFixture::new(60000).await;
 let changes=vec![
 ("POST","sessions/narrow","session.narrow",false,json!({"sid":"s_1","narrow":{"methods":["GET","HEAD"]}}),None),
 ("POST","credentials/rotate","cred.rotate",true,json!({"slug":"demo","value":"test-fake-rotated-value-0011223344556677","mode":"keep","retire_hours":24}),None),
 ("POST","credentials/scrub","cred.scrub_add",true,json!({"slug":"demo","pattern":"acme_[A-Za-z0-9]{20}","sample":"token acme_abcdefghijklmnopqrst"}),None),
 ("DELETE","credentials/scrub?slug=demo&id=sp_01","cred.scrub_remove",true,json!({}),Some(json!({"slug":"demo","id":"sp_01"}))),
 ("POST","credentials/expiry","cred.expiry_set",true,json!({"slug":"demo","expires_at":"2027-01-31T00:00:00.000Z"}),None),
 ("POST","credentials/release","cred.release",true,json!({"slug":"demo"}),None),
 ("POST","tripwires","tripwires.set",true,json!({"enabled":false}),None),
 ("POST","templates","template.save",true,json!({"name":"gh-read","spec":{"cred":"demo","methods":["GET"],"spend_usd":1.5}}),None),
 ("DELETE","templates?name=gh-read","template.delete",false,json!({}),Some(json!({"name":"gh-read"}))),
 ];
 for(method,path,op,verified,body,bind)in changes{let route=path.split('?').next().unwrap();let key=format!("{method} {route}");let target=format!("{method} /v1/{route}");assert!(GATED.contains(&key.as_str()));assert_eq!(DAEMON_VERIFIED.contains(&key.as_str()),verified);let bound=bind.as_ref().unwrap_or(&body);let count=||u.calls.lock().unwrap().iter().filter(|(k,_)|k==&target).count();let n=count();assert_eq!(u.api(method,path,body.clone()).await.0,401,"{key}");assert_eq!(count(),n);
 let mut other=bound.clone();let first=other.as_object().unwrap().keys().next().unwrap().clone();other[&first]=json!(format!("{}-other",other[&first]));let mut swapped=body.clone();swapped["presence"]=u.proof(op,&other).await;assert_eq!(u.api(method,path,swapped).await.0,409,"{key}");assert_eq!(count(),n);
 let proof=u.proof(op,bound).await;let mut valid=body.clone();valid["presence"]=proof.clone();let(s,v)=u.api(method,path,valid).await;assert_eq!(s,200,"{key}: {v}");let got=u.calls.lock().unwrap().iter().rev().find(|(k,_)|k==&target).unwrap().1.clone();if verified{assert_eq!(got["presence"],proof,"{key}");}else{assert!(got.get("presence").is_none(),"{key}");}let forwarded=if bind.is_some(){let q=u.queries.lock().unwrap().iter().rev().find(|(k,_)|k==&target).unwrap().1.clone();let map:serde_json::Map<String,Value>=url::form_urlencoded::parse(q.as_bytes()).map(|(k,v)|(k.into_owned(),Value::String(v.into_owned()))).collect();Value::Object(map)}else{got};assert_eq!(av_daemon::util::operation_for(op,&forwarded).unwrap(),av_daemon::util::operation_for(op,bound).unwrap(),"{key}");}
 for key in ["POST credentials/test","POST credentials/quarantine","POST panic"]{assert!(!GATED.contains(&key));assert!(!DAEMON_VERIFIED.contains(&key));}
 let mut b=json!({"slug":"demo"});b["presence"]=u.proof("cred.quarantine",&b).await;assert_eq!(u.api("POST","credentials/release",b).await.0,409);let op=av_daemon::util::operation_for("cred.rotate",&json!({"slug":"demo","value":"test-fake-rotated-value-0011223344556677"})).unwrap();assert!(!op.to_string().contains("test-fake-rotated"));assert_eq!(op["value_sha256"].as_str().unwrap().len(),64);assert!(op["value_sha256"].as_str().unwrap().bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()));assert_eq!(u.api("GET","tripwires",json!({})).await.0,200);u.stop().await;
 }).await.unwrap();
}
#[tokio::test]
async fn ui_open_route_whitelists_and_read_queries_audit_filter_do_not_allow_agent_steering() {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let u=UiContractFixture::new(60000).await;let last=|target:&str|u.calls.lock().unwrap().iter().rev().find(|(k,_)|k==target).unwrap().1.clone();
 for(body,expected)in[(json!({"slug":"demo","path":"/admin","method":"DELETE","body":"x"}),json!({"slug":"demo"})),(json!({"all":true}),json!({"all":true})),(json!({"all":"true","slug":"demo"}),json!({"slug":"demo"}))]{assert_eq!(u.api("POST","credentials/test",body).await.0,200);assert_eq!(last("POST /v1/credentials/test"),expected);}
 assert_eq!(u.api("POST","credentials/quarantine",json!({"slug":"demo","reason":"odd traffic","by":"tripwire"})).await.0,200);assert_eq!(last("POST /v1/credentials/quarantine"),json!({"slug":"demo","reason":"odd traffic"}));
 for(body,expected)in[(json!({"lock":true,"reason":"agent went wild"}),json!({"lock":true,"reason":"agent went wild"})),(json!({}),json!({"lock":false}))]{assert_eq!(u.api("POST","panic",body).await.0,200);assert_eq!(last("POST /v1/panic"),expected);}for lock in [json!("false"),json!("true"),json!(1),Value::Null]{let n=u.calls.lock().unwrap().iter().filter(|(k,_)|k=="POST /v1/panic").count();assert_eq!(u.api("POST","panic",json!({"lock":lock})).await.0,400);assert_eq!(u.calls.lock().unwrap().iter().filter(|(k,_)|k=="POST /v1/panic").count(),n);}
 for(path,target,expected)in[("sessions/detail?sid=s_1","/v1/sessions/detail",json!({"sid":"s_1"})),("report/access","/v1/report/access",json!({"since":"7d"})),("report/access?since=24h","/v1/report/access",json!({"since":"24h"})),("tripwires","/v1/tripwires",json!({})),("templates","/v1/templates",json!({})),("templates?name=gh-read","/v1/templates",json!({"name":"gh-read"})),("notify","/v1/notify",json!({})),("audit/checkpoint","/v1/audit/checkpoint",json!({}))]{assert_eq!(u.api("GET",path,json!({})).await.0,200,"{path}");let key=format!("GET {target}");let q=u.queries.lock().unwrap().iter().rev().find(|(k,_)|k==&key).unwrap().1.clone();let query:serde_json::Map<String,Value>=url::form_urlencoded::parse(q.as_bytes()).map(|(k,v)|(k.into_owned(),Value::String(v.into_owned()))).collect();assert_eq!(Value::Object(query),expected,"{path}");}
 u.set("GET /v1/audit",200,json!([{"seq":1,"kind":"session.created"},{"seq":2,"kind":"tripwire.fired","rule_id":"replay"},{"seq":3,"kind":"request.denied"},{"seq":4,"kind":"tripwire.fired","rule_id":"deny_paths"}]));let(s,v)=u.api("GET","audit?kind=tripwire.fired&limit=5",json!({})).await;assert_eq!(s,200,"{v}");assert_eq!(v.as_array().unwrap().iter().map(|r|r["seq"].clone()).collect::<Vec<_>>(),vec![json!(2),json!(4)]);assert_eq!(u.api("GET","audit?limit=5",json!({})).await.1.as_array().unwrap().len(),4);assert_eq!(u.api("GET","audit?kind=../../v1/credentials",json!({})).await.0,400);u.stop().await;
 }).await.unwrap();
}
#[tokio::test]
async fn serving_refuses_network_control_database_atomically_audits_and_allows_only_networkable_surfaces(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let f = Fixture::new(&["header:x-key"]).await;
        f.shared
            .run(|c| {
                use av_store::vault::{is_loopback_spec, NewListener};
                let before = c.vault.list_listeners().unwrap().len();
                for (id, address, surfaces) in [
                    ("bad-control", "eth0:7411", vec!["gateway", "control"]),
                    ("bad-db", "10.0.0.5:7411", vec!["l4"]),
                    ("bad-audited", "tailscale0:7411", vec!["control"]),
                ] {
                    let e = c
                        .vault
                        .add_listener(NewListener {
                            id: id.into(),
                            address: address.into(),
                            surfaces: surfaces.iter().map(|s| (*s).into()).collect(),
                            ..Default::default()
                        })
                        .unwrap_err();
                    let v = e.as_vault().unwrap();
                    assert_eq!(v.code.as_str(), "AV_REMOTE_FORBIDDEN");
                    if id == "bad-control" {
                        assert!(v.detail.contains("control"));
                    }
                    assert_eq!(c.vault.list_listeners().unwrap().len(), before);
                }
                let local = c
                    .vault
                    .add_listener(NewListener {
                        id: "local-extra".into(),
                        address: "unix:/tmp/fake-av-extra.sock".into(),
                        surfaces: vec!["control".into(), "l4".into()],
                        ..Default::default()
                    })
                    .unwrap();
                assert_eq!(local.id, "local-extra");
                let network = c
                    .vault
                    .add_listener(NewListener {
                        id: "tailnet".into(),
                        address: "tailscale0:7411".into(),
                        surfaces: vec!["gateway".into(), "mcp".into()],
                        client_auth: Some("bearer".into()),
                        allow_cidr: vec!["100.64.0.0/10".into()],
                        ..Default::default()
                    })
                    .unwrap();
                assert_eq!(network.surfaces, vec!["gateway", "mcp"]);
                assert_eq!(network.client_auth.as_deref(), Some("bearer"));
                for ok in [
                    "unix:/run/av.sock",
                    "127.0.0.1:7411",
                    "[::1]:7411",
                    "localhost:7411",
                ] {
                    assert!(is_loopback_spec(ok), "{ok}");
                }
                for bad in [
                    "0.0.0.0:7411",
                    "eth0:7411",
                    "10.0.0.5:7411",
                    "tailscale0:7411",
                ] {
                    assert!(!is_loopback_spec(bad), "{bad}");
                }
                c.vault.remove_listener("tailnet").unwrap();
                assert!(!c
                    .vault
                    .list_listeners()
                    .unwrap()
                    .iter()
                    .any(|l| l.id == "tailnet"));
            })
            .await
            .unwrap();
        let rows = audit_records(&f).await;
        for kind in ["listen.refused", "listen.removed"] {
            assert!(rows.iter().any(|r| r["kind"] == kind), "{kind}");
        }
        assert!(!serde_json::to_string(&rows).unwrap().contains(SECRET));
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn serving_control_socket_is_private_and_default_gateway_has_no_tcp_control_surface() {
    use std::os::unix::fs::PermissionsExt;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let f = Fixture::new(&["header:x-key"]).await;
        let socket = f._dir.path().join("control.sock");
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(f._dir.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(DaemonOptions::default().host, "127.0.0.1");
        assert_eq!(
            credential_api(&f, "GET", "/v1/listeners", json!({}))
                .await
                .0,
            200
        );
        let (s, _, b) = loopback_http_host(
            f.daemon.gateway_port().unwrap(),
            "127.0.0.1",
            "GET",
            "/v1/listeners",
            vec![("authorization".into(), format!("Bearer {}", f.token))],
            vec![],
        )
        .await;
        assert_eq!(s, 404);
        assert!(!String::from_utf8_lossy(&b).contains(SECRET));
        let local = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if local.connect("192.0.2.1:9").is_ok() {
            let address = local.local_addr().unwrap().ip();
            if !address.is_loopback() && !address.is_unspecified() {
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        tokio::net::TcpStream::connect((address, f.daemon.gateway_port().unwrap()))
                    )
                    .await
                    .is_ok_and(|r| r.is_err()),
                    "gateway unexpectedly accepts a non-loopback connection"
                );
            }
        }
        assert_eq!(f.get().await.status, 200);
        credential_finish(&f).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn ui_invalid_verdicts_never_spend_a_signature_or_settle_pending_and_real_denials_work() {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let w = WidenFixture::new().await;
        let gid = w.f.grant_id.clone();
        w.f.shared
            .run(move |c| {
                c.vault
                    .narrow_grant(&gid, &json!({"approval":"on-write"}))
                    .unwrap()
            })
            .await
            .unwrap();
        let hold =
            w.f.send(
                "POST",
                "/held-ui-verdict",
                vec![("authorization".into(), format!("Bearer {}", w.f.ph))],
                Some("fake request body".into()),
            )
            .await;
        let id = held_id(&hold);
        let not_verdict = [
            Some(Value::Null),
            Some(json!(0)),
            Some(json!(1)),
            Some(json!("false")),
            Some(json!("true")),
            Some(json!("no")),
            None,
        ];
        for granted in &not_verdict {
            let mut b = json!({"id":id});
            if let Some(g) = granted {
                b["granted"] = g.clone();
            }
            b["presence"] = w.proof("approval.approve", &b).await;
            let (s, v) = w.api("POST", "approvals", b).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["detail"]["rule"], "bulk_decision");
        }
        assert!(w
            .f
            .daemon
            .pipeline()
            .pending_approvals()
            .await
            .iter()
            .any(|r| r["id"] == id));
        assert!(w.f.up.hits.lock().unwrap().is_empty());
        let b = json!({"id":id,"granted":false});
        let proof = w.proof("approval.deny", &b).await;
        let (s, v) = w
            .api(
                "POST",
                "approvals",
                json!({"id":id,"granted":false,"presence":proof}),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        assert!(!w
            .f
            .daemon
            .pipeline()
            .pending_approvals()
            .await
            .iter()
            .any(|r| r["id"] == id));
        let (s, asked) = w
            .ctl(
                "POST",
                "/v1/session-requests",
                json!({"cred":"demo","methods":["GET"],"reason":"job"}),
            )
            .await;
        assert_eq!(s, 200, "{asked}");
        let id = asked["id"].clone();
        let before = w.ctl("GET", "/v1/sessions", json!({})).await.1;
        for granted in &not_verdict {
            let proof = w
                .proof("session_request.decide", &json!({"id":id,"granted":true}))
                .await;
            let mut b = json!({"id":id,"presence":proof});
            if let Some(g) = granted {
                b["granted"] = g.clone();
            }
            let (s, v) = w.api("POST", "session-requests/decide", b).await;
            assert_eq!(s, 403, "{v}");
            assert_eq!(v["detail"]["rule"], "bulk_decision");
        }
        assert_eq!(w.ctl("GET", "/v1/sessions", json!({})).await.1, before);
        let (s, pending) = w.ctl("GET", "/v1/session-requests", json!({})).await;
        assert_eq!(s, 200);
        assert!(pending
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == id && r["state"] == "pending"));
        let proof = w
            .proof("session_request.decide", &json!({"id":id,"granted":false}))
            .await;
        assert_eq!(
            w.api(
                "POST",
                "session-requests/decide",
                json!({"id":id,"granted":false,"presence":proof})
            )
            .await
            .0,
            200
        );
        assert_eq!(
            w.f.send(
                "GET",
                "/ordinary",
                vec![("authorization".into(), format!("Bearer {}", w.f.ph))],
                None
            )
            .await
            .status,
            200
        );
        w.stop().await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn ui_session_request_single_and_batch_record_for_local_clients_without_returning_tokens() {
    tokio::time::timeout(std::time::Duration::from_secs(40),async{
 let w=WidenFixture::new().await;for batch in [false,true]{let(s,asked)=w.ctl("POST","/v1/session-requests",json!({"cred":"demo","methods":["GET"],"paths":[if batch{"/ui-two"}else{"/ui-one"}],"reason":"read a fake resource"})).await;assert_eq!(s,200,"{asked}");let id=asked["id"].clone();let (path,mut b,op)=if batch{("pending/decide-many",json!({"decisions":[{"id":id,"kind":"session","granted":true}]}),"pending.decide_many")}else{("session-requests/decide",json!({"id":id,"granted":true}),"session_request.decide")};b["presence"]=w.proof(op,&b).await;let(s,v)=w.api("POST",path,b).await;assert_eq!(s,200,"{v}");assert!(!v.to_string().contains("avs1."));assert!(!v.to_string().contains("av1."));assert!(!v.to_string().contains(SECRET));if batch{assert_eq!(v["recorded"],id);}else{assert!(v["recorded"]["session_id"].is_string());}}
 assert_eq!(w.f.send("GET","/ordinary",vec![("authorization".into(),format!("Bearer {}",w.f.ph))],None).await.status,200);w.stop().await;
 }).await.unwrap();
}
#[tokio::test]
async fn signed_placeholder_issue_cannot_borrow_a_narrow_session_signature_but_the_real_operation_works(
) {
    tokio::time::timeout(std::time::Duration::from_secs(35),async{
 let w=WidenFixture::new().await;let fields=json!({"cred":"demo","methods":["GET"],"paths":["/only"]});let proof=w.proof("session.create",&fields).await;let before=w.f.shared.run(|c|c.vault.list_placeholders(None).unwrap().len()).await.unwrap();let(s,v)=w.ctl("POST","/v1/placeholders",json!({"cred":"demo","methods":["GET"],"paths":["/only"],"op":"session.create","presence":proof})).await;assert_ne!(s,200,"{v}");assert!(v["placeholder"].is_null());assert_eq!(w.f.shared.run(|c|c.vault.list_placeholders(None).unwrap().len()).await.unwrap(),before);let b=json!({"cred":"demo"});let proof=w.proof("placeholder.issue",&b).await;let(s,v)=w.ctl("POST","/v1/placeholders",json!({"cred":"demo","presence":proof})).await;assert_eq!(s,200,"{v}");assert!(v["placeholder"].as_str().unwrap().starts_with("av1."));assert_eq!(w.f.send("GET","/ordinary",vec![("authorization".into(),format!("Bearer {}",w.f.ph))],None).await.status,200);w.stop().await;
 }).await.unwrap();
}
#[test]
fn serving_new_vault_directory_is_private_before_any_daemon_runs() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!vault.locked());
    vault.lock().unwrap();
}
#[tokio::test]
async fn integration_c22_pin_removal_binds_explicit_null_or_exact_spki_at_both_ui_and_daemon() {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        let w = WidenFixture::new().await;
        let pins = vec![
            format!("sha256/{}=", "A".repeat(43)),
            format!("sha256/{}=", "B".repeat(43)),
        ];
        let expected = pins.clone();
        w.f.shared
            .run(move |c| c.vault.set_pins("demo", "api.example.test", &pins).unwrap())
            .await
            .unwrap();
        let url = "credentials/pins?slug=demo&host=api.example.test";
        for params in [
            json!({"slug":"demo","host":"api.example.test"}),
            json!({"slug":"demo","host":"api.example.test","spki":expected[0]}),
        ] {
            let proof = w.proof("cred.pins_remove", &params).await;
            assert_eq!(w.api("DELETE", url, json!({"presence":proof})).await.0, 409);
            let proof = w.proof("cred.pins_remove", &params).await;
            let (s, v) = w
                .ctl("DELETE", &format!("/v1/{url}"), json!({"presence":proof}))
                .await;
            assert_eq!(s, 401, "{v}");
            assert_eq!(v["code"], "AV_PRESENCE_REQUIRED");
            assert_eq!(
                w.f.shared
                    .run(|c| serde_json::to_value(
                        c.vault.find_credential("demo").unwrap().unwrap()
                    )
                    .unwrap()["pins"]["api.example.test"]
                        .clone())
                    .await
                    .unwrap(),
                json!(expected)
            );
        }
        let proof = w
            .proof(
                "cred.pins_remove",
                &json!({"slug":"demo","host":"api.example.test","spki":null}),
            )
            .await;
        let (s, v) = w.api("DELETE", url, json!({"presence":proof})).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            w.f.send(
                "GET",
                "/ordinary",
                vec![("authorization".into(), format!("Bearer {}", w.f.ph))],
                None
            )
            .await
            .status,
            200
        );
        w.stop().await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn integration_c19_backup_restore_binds_canonical_bundle_digest_and_refuses_a_different_bundle(
) {
    tokio::time::timeout(std::time::Duration::from_secs(45),async{
 let w=WidenFixture::new().await;let recovery="test fake integration recovery words";let proof=w.proof("backup.export",&json!({"recovery_passphrase":recovery})).await;let(s,exported)=w.ctl("POST","/v1/backup/export",json!({"recovery_passphrase":recovery,"presence":proof})).await;assert_eq!(s,200,"{exported}");let bundle=exported.get("bundle").unwrap_or(&exported).clone();assert!(bundle.is_object());let mut other=bundle.clone();other["integration_fixture"]=json!("not this one");let proof=w.proof("backup.restore",&json!({"bundle":other,"recovery_passphrase":recovery,"on_conflict":"rename"})).await;let(s,v)=w.ctl("POST","/v1/backup/restore",json!({"bundle":bundle,"recovery_passphrase":recovery,"on_conflict":"rename","presence":proof})).await;assert_eq!(s,401,"{v}");assert_eq!(v["code"],"AV_PRESENCE_REQUIRED");let reversed:serde_json::Map<String,Value>=bundle.as_object().unwrap().iter().rev().map(|(k,v)|(k.clone(),v.clone())).collect();let proof=w.proof("backup.restore",&json!({"bundle":reversed,"recovery_passphrase":recovery,"on_conflict":"rename"})).await;let(s,v)=w.ctl("POST","/v1/backup/restore",json!({"bundle":bundle,"recovery_passphrase":recovery,"on_conflict":"rename","presence":proof})).await;assert_eq!(s,200,"{v}");assert!(!v.to_string().contains(SECRET));assert!(!serde_json::to_string(&audit_records(&w.f).await).unwrap().contains(recovery));assert_eq!(w.f.send("GET","/ordinary",vec![("authorization".into(),format!("Bearer {}",w.f.ph))],None).await.status,200);w.stop().await;
 }).await.unwrap();
}
#[tokio::test]
async fn integration_c19_webhook_configuration_binds_url_digest_and_never_logs_the_secret_path() {
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let w = WidenFixture::new().await;
        let url = "https://hooks.example.test/services/test-fake-secret";
        let params = json!({"webhook_url":url,"detail":"minimal"});
        let proof = w
            .proof(
                "notify.set",
                &json!({"webhook_url":"https://hooks.example.test/other","detail":"minimal"}),
            )
            .await;
        let (s, v) = w
            .ctl(
                "POST",
                "/v1/notify",
                json!({"webhook_url":url,"detail":"minimal","presence":proof}),
            )
            .await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["code"], "AV_PRESENCE_REQUIRED");
        let op = av_daemon::util::operation_for("notify.set", &params).unwrap();
        assert!(!op.to_string().contains("test-fake-secret"));
        let proof = w.proof("notify.set", &params).await;
        let (s, v) = w
            .ctl(
                "POST",
                "/v1/notify",
                json!({"webhook_url":url,"detail":"minimal","presence":proof}),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        assert!(!v.to_string().contains("test-fake-secret"));
        assert!(!serde_json::to_string(&audit_records(&w.f).await)
            .unwrap()
            .contains("test-fake-secret"));
        assert_eq!(
            w.f.send(
                "GET",
                "/ordinary",
                vec![("authorization".into(), format!("Bearer {}", w.f.ph))],
                None
            )
            .await
            .status,
            200
        );
        w.stop().await;
    })
    .await
    .unwrap();
}
