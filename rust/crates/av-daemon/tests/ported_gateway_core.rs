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
                "2027-01-01T00:00:00.000Z".into(),
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
            assert_eq!(health["observed_expires_at"], "2027-01-01T00:00:00.000Z");
        })
        .await
        .unwrap();
    f.clean(&executed).await;
    f.reply(200, "application/json", "{}".into());
    let ordinary = f.get().await;
    assert_eq!(ordinary.status, 200);
    f.clean(&ordinary).await;
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
    assert!(denied[0] < *revoked.iter().min().unwrap());
    assert!(*revoked.iter().max().unwrap() < *requests.iter().min().unwrap());
    assert!(*requests.iter().max().unwrap() < panic[0]);
    assert!(!serde_json::to_string(&rows).unwrap().contains(SECRET));
    assert!(f.up.hits.lock().unwrap().is_empty());
    let ordinary = Fixture::new(&["header:x-key"]).await;
    let response = ordinary.get().await;
    assert_eq!(response.status, 200);
    ordinary.clean(&response).await;
}

#[tokio::test]
async fn real_session_request_metadata_failure_does_not_prevent_panic_revocation_and_partial_record(
) {
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
            assert!(!serde_json::to_string(&audit).unwrap().contains(SECRET));
        })
        .await
        .unwrap();
    let ordinary = SeededGateway::new(json!({}), json!({}));
    let clean = ordinary.pipeline.panic(None, false).await.unwrap();
    assert_eq!(clean["revoked_sessions"], 1);
    assert_eq!(clean["denied_session_requests"], 0);
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
