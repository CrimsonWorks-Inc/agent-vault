//! Credential-bearing TLS requests: decisions precede application bytes.
#![forbid(unsafe_code)]
use av_daemon::connectors::pinning::{fetch_chain_pins, pinned_request, spki_of};
use av_daemon::upstream::{Body, Pins, UpstreamRequest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const SECRET: &str = "test-secret-ported-pinning-0123456789";
fn cert(name: &str, days: (i64, i64)) -> (Vec<u8>, Vec<u8>) {
    let k = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now + time::Duration::days(days.0);
    p.not_after = now + time::Duration::days(days.1);
    (p.self_signed(&k).unwrap().der().to_vec(), k.serialize_der())
}
type Handshakes = Arc<Mutex<Vec<(Option<String>, bool)>>>;
struct Peer {
    handshakes: Handshakes,
    port: u16,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Debug)]
struct OneCert(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for OneCert {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}
async fn peer(chain: Vec<Vec<u8>>, key: Vec<u8>) -> Peer {
    peer_on(chain, key, "127.0.0.1:0", None).await
}
async fn peer_on(
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
    address: &str,
    response: Option<Vec<u8>>,
) -> Peer {
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(key),
    ))
    .unwrap();
    let certified = rustls::sign::CertifiedKey::new(
        chain.into_iter().map(CertificateDer::from).collect(),
        signing,
    );
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(OneCert(Arc::new(certified))));
    let accept = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind(address).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let s = seen.clone();
    let handshakes = Arc::new(Mutex::new(Vec::new()));
    let hs = handshakes.clone();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = connections.clone();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let a = accept.clone();
            let s = s.clone();
            let response = response.clone();
            let hs = hs.clone();
            tokio::spawn(async move {
                if let Ok(Ok(mut tls)) =
                    tokio::time::timeout(Duration::from_secs(3), a.accept(tcp)).await
                {
                    hs.lock().unwrap().push((
                        tls.get_ref().1.server_name().map(str::to_owned),
                        matches!(
                            tls.get_ref().1.handshake_kind(),
                            Some(rustls::HandshakeKind::Resumed)
                        ),
                    ));
                    let mut all = Vec::new();
                    let mut b = [0; 4096];
                    while let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), tls.read(&mut b)).await
                    {
                        if n == 0 {
                            break;
                        }
                        all.extend_from_slice(&b[..n]);
                        if let Some(end) = all.windows(4).position(|w| w == b"\r\n\r\n") {
                            let length = String::from_utf8_lossy(&all[..end])
                                .lines()
                                .filter_map(|l| l.split_once(':'))
                                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if all.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    if !all.is_empty() {
                        s.lock().unwrap().push(all);
                        let reply=response.as_deref().unwrap_or(b"HTTP/1.1 200 OK\r\nx-ok: 1\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello");
                        let _ = tls.write_all(reply).await;
                    }
                }
            });
        }
    });
    Peer {
        handshakes,
        port,
        seen,
        connections,
        task,
    }
}
fn request(port: u16, pins: Pins) -> UpstreamRequest {
    UpstreamRequest {
        url: format!("https://127.0.0.1:{port}/user"),
        method: "POST".into(),
        headers: vec![("authorization".into(), format!("Bearer {SECRET}"))],
        body: Some(b"SENTINEL".to_vec()),
        pins,
    }
}
fn pins(v: &[String]) -> Pins {
    Pins::List(v.iter().map(|s| json!(s)).collect())
}
async fn success(r: UpstreamRequest) {
    let out = pinned_request(r).await.unwrap();
    assert_eq!(out.status, 200);
    assert_eq!(
        out.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("x-ok"))
            .map(|(_, v)| v.as_str()),
        Some("1")
    );
    let mut b = Vec::new();
    match out.body {
        Body::Full(v) => b = v,
        Body::Stream(mut rx) => {
            while let Some(v) = rx.recv().await {
                b.extend(v.unwrap());
            }
        }
    }
    assert_eq!(b, b"hello");
    assert!(!String::from_utf8_lossy(&b).contains(SECRET));
}
#[tokio::test]
async fn leaf_pin_controls_refuse_wrong_identity_untrusted_pin_and_out_of_date_before_http() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (der, key) = cert("127.0.0.1", (-1, 2));
        let pin = spki_of(&der).unwrap();
        let s = peer(vec![der], key).await;
        for p in [
            Pins::None,
            Pins::List(vec![]),
            pins(&[format!("sha256/{}=", "A".repeat(43))]),
        ] {
            let e = pinned_request(request(s.port, p)).await.err().unwrap();
            assert_eq!(e.code, "DEPTH_ZERO_SELF_SIGNED_CERT");
            assert!(!format!("{e:?}").contains(SECRET));
        }
        let c = chain();
        for pinset in [
            vec![spki_of(c.leaf.der()).unwrap()],
            vec![
                spki_of(c.inter.der()).unwrap(),
                spki_of(c.root.der()).unwrap(),
            ],
        ] {
            let e = pinned_request(request(s.port, pins(&pinset)))
                .await
                .err()
                .unwrap();
            assert_eq!(e.code, "DEPTH_ZERO_SELF_SIGNED_CERT");
        }
        assert!(s.seen.lock().unwrap().is_empty());
        success(request(
            s.port,
            pins(&[format!("sha256/{}=", "A".repeat(43)), pin]),
        ))
        .await;
        assert_eq!(s.seen.lock().unwrap().len(), 1);
        for (label, name, days, code, reason) in [
            (
                "wrong SAN",
                "elsewhere.test",
                (-1, 2),
                "ERR_TLS_CERT_ALTNAME_INVALID",
                None,
            ),
            (
                "expired",
                "127.0.0.1",
                (-3, -2),
                "AV_PIN_MISMATCH",
                Some("leaf_expired"),
            ),
            (
                "future",
                "127.0.0.1",
                (2, 3),
                "AV_PIN_MISMATCH",
                Some("leaf_not_yet_valid"),
            ),
        ] {
            let (d, k) = cert(name, days);
            let pin = spki_of(&d).unwrap();
            let p = peer(vec![d], k).await;
            let e = pinned_request(request(p.port, pins(std::slice::from_ref(&pin))))
                .await
                .err()
                .unwrap();
            assert_eq!(e.code, code, "{label}");
            assert_eq!(e.reason.as_deref(), reason, "{label}");
            if reason.is_some() {
                assert!(e.presented.contains(&pin));
            }
            assert!(p.seen.lock().unwrap().is_empty(), "{label}");
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn malformed_pin_tables_and_plaintext_pins_never_connect_with_valid_tls_control() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (d, k) = cert("127.0.0.1", (-1, 2));
        let pin = spki_of(&d).unwrap();
        let p = peer(vec![d], k).await;
        let bad = vec![
            Pins::Unreadable,
            Pins::List(vec![json!("garbage")]),
            Pins::List(vec![Value::Null]),
            Pins::List(vec![json!(42)]),
            Pins::List(vec![json!(format!(" {pin}"))]),
            Pins::List(vec![json!(pin), json!("garbage")]),
            Pins::List(vec![json!(pin); 5]),
        ];
        for pins in bad {
            for scheme in ["http", "https"] {
                let mut r = request(p.port, pins.clone());
                r.url = format!("{scheme}://127.0.0.1:{}/user", p.port);
                let e = pinned_request(r).await.err().unwrap();
                assert_eq!(e.code, "AV_PIN_MISMATCH");
                assert_eq!(e.reason.as_deref(), Some("pin_format"));
                assert!(e.presented.is_empty());
            }
        }
        let mut r = request(p.port, pins(std::slice::from_ref(&pin)));
        r.url = r.url.replace("https:", "http:");
        let e = pinned_request(r).await.err().unwrap();
        assert_eq!(e.reason.as_deref(), Some("plaintext"));
        assert!(e.presented.is_empty());
        assert!(p.seen.lock().unwrap().is_empty());
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(p.connections.load(std::sync::atomic::Ordering::SeqCst), 0);
        success(request(p.port, pins(&[pin]))).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn host_alias_port_list_and_repeated_foreign_fields_refuse_with_matching_control() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (d, k) = cert("127.0.0.1", (-1, 2));
        let pin = spki_of(&d).unwrap();
        let p = peer(vec![d], k).await;
        for host in [
            "127.0.0.1".to_owned(),
            format!("127.0.0.1:{}x", p.port),
            format!(" 127.0.0.1:{}", p.port),
            "Elsewhere.TEST".into(),
            format!("localhost:{}", p.port),
            format!("127.0.0.1:{}", if p.port == 65535 { 1 } else { p.port + 1 }),
        ] {
            for pinset in [Pins::None, pins(std::slice::from_ref(&pin))] {
                for scheme in ["http", "https"] {
                    let mut r = request(p.port, pinset.clone());
                    r.url = r.url.replace("https:", &format!("{scheme}:"));
                    r.headers.push(("HOST".into(), host.clone()));
                    let e = pinned_request(r).await.err().unwrap();
                    assert_eq!(
                        e.vault.unwrap().extra.rule.as_deref(),
                        Some("host_mismatch")
                    );
                }
            }
        }
        let mut r = request(p.port, pins(std::slice::from_ref(&pin)));
        r.headers.extend([
            ("host".into(), format!("127.0.0.1:{}", p.port)),
            ("Host".into(), "elsewhere.test".into()),
        ]);
        let e = pinned_request(r).await.err().unwrap();
        assert_eq!(
            e.vault.unwrap().extra.rule.as_deref(),
            Some("host_mismatch")
        );
        assert!(p.seen.lock().unwrap().is_empty());
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(p.connections.load(std::sync::atomic::Ordering::SeqCst), 0);
        let mut r = request(p.port, pins(&[pin]));
        r.headers
            .push(("host".into(), format!("127.0.0.1:{}", p.port)));
        success(r).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fetch_chain_describes_certificates_without_application_bytes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (d, k) = cert("127.0.0.1", (-1, 2));
        let pin = spki_of(&d).unwrap();
        let p = peer(vec![d], k).await;
        let rows = fetch_chain_pins("127.0.0.1", p.port).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["spki"], pin);
        assert!(rows[0]["not_after"].as_str().unwrap().contains('T'));
        assert!(p.seen.lock().unwrap().is_empty());
        success(request(p.port, pins(&[pin]))).await;
    })
    .await
    .unwrap();
}

// A fresh process reads its private CA once, exactly as the production client does.
#[tokio::test]
async fn pinning_child_client() {
    let Ok(input) = std::env::var("AV_PORTED_PIN_CALLS") else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(20),async {
 let mut out=Vec::new();
 for call in serde_json::from_str::<Vec<Value>>(&input).unwrap(){
 if call["probe"]==true {out.push(child_probe(&call).await);continue;}
 let r=UpstreamRequest{url:call["url"].as_str().unwrap().into(),method:"POST".into(),headers:call.get("headers").map(|v|serde_json::from_value(v.clone()).unwrap()).unwrap_or_else(||vec![("authorization".into(),format!("Bearer {SECRET}"))]),body:Some(b"SENTINEL".to_vec()),pins:match &call["pins"]{Value::Array(v)=>Pins::List(v.clone()),_=>Pins::None}};
 out.push(match pinned_request(r).await{Ok(r)=>{let mut b=Vec::new();match r.body{Body::Full(v)=>b=v,Body::Stream(mut rx)=>while let Some(v)=rx.recv().await{b.extend(v.unwrap());}}json!({"ok":true,"status":r.status,"headers":r.headers,"body":String::from_utf8(b).unwrap()})},Err(e)=>json!({"ok":false,"code":e.code,"reason":e.reason,"presented":e.presented,"rule":e.vault.map(|v|v.extra.rule)})});
 }
 std::fs::write(std::env::var("AV_PORTED_PIN_OUTPUT").unwrap(),serde_json::to_vec(&out).unwrap()).unwrap();
 }).await.unwrap();
}
async fn trusted(root: &str, calls: Vec<Value>) -> Vec<Value> {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let ca = dir.path().join("ca.pem");
    let result = dir.path().join("result.json");
    std::fs::write(&ca, root).unwrap();
    let mut cmd = tokio::process::Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "pinning_child_client", "--nocapture"])
        .env("NODE_EXTRA_CA_CERTS", ca)
        .env(
            "AV_PORTED_PIN_CALLS",
            serde_json::to_string(&calls).unwrap(),
        )
        .env("AV_PORTED_PIN_OUTPUT", &result)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(25), cmd.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(result).unwrap()).unwrap()
}
struct Chain {
    root: rcgen::Certificate,
    inter: rcgen::Certificate,
    leaf: rcgen::Certificate,
    key: Vec<u8>,
    rotated: rcgen::Certificate,
    rotated_key: Vec<u8>,
    other: rcgen::Certificate,
    other_key: Vec<u8>,
    evil: rcgen::Certificate,
    evil_key: Vec<u8>,
}
fn ca(name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair) {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, name);
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    if name == "TestIntermediate" {
        p.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(vec![0x42; 20]);
    }
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    (p, rcgen::KeyPair::generate().unwrap())
}
fn chain() -> Chain {
    let (rp, rk) = ca("TestRoot");
    let root = rp.self_signed(&rk).unwrap();
    let ri = rcgen::Issuer::new(rp, rk);
    let (ip, ik) = ca("TestIntermediate");
    let inter = ip.signed_by(&ik, &ri).unwrap();
    let ii = rcgen::Issuer::new(ip, ik);
    let make = |names: Vec<String>, issuer: &rcgen::Issuer<'_, rcgen::KeyPair>| {
        let mut p = rcgen::CertificateParams::new(names).unwrap();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        p.use_authority_key_identifier_extension = true;
        let k = rcgen::KeyPair::generate().unwrap();
        (p.signed_by(&k, issuer).unwrap(), k.serialize_der())
    };
    let (leaf, key) = make(vec!["localhost".into(), "127.0.0.1".into()], &ii);
    let (rotated, rotated_key) = make(vec!["localhost".into(), "127.0.0.1".into()], &ii);
    let (other, other_key) = make(vec!["elsewhere.test".into()], &ii);
    let (fp, fk) = ca("TestIntermediate");
    let fi = rcgen::Issuer::new(fp, fk);
    let (evil, evil_key) = make(vec!["127.0.0.1".into()], &fi);
    Chain {
        root,
        inter,
        leaf,
        key,
        rotated,
        rotated_key,
        other,
        other_key,
        evil,
        evil_key,
    }
}
fn call(port: u16, pins: Value) -> Value {
    json!({"url":format!("https://127.0.0.1:{port}/user"),"pins":pins})
}
fn pin(c: &rcgen::Certificate) -> String {
    spki_of(c.der()).unwrap()
}
#[tokio::test]
async fn trusted_chain_leaf_intermediate_root_and_rotation_are_proven_before_secret_send() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let c = chain();
        let p = peer(
            vec![c.leaf.der().to_vec(), c.inter.der().to_vec()],
            c.key.clone(),
        )
        .await;
        let wrong = format!("sha256/{}=", "A".repeat(43));
        let root = c.root.pem();
        let out = trusted(
            &root,
            vec![
                call(p.port, json!([pin(&c.leaf)])),
                call(p.port, json!([wrong, pin(&c.inter)])),
                call(p.port, json!([pin(&c.root)])),
                call(p.port, json!([wrong])),
                call(p.port, Value::Null),
                call(p.port, json!([])),
            ],
        )
        .await;
        for i in [0, 1, 2, 4, 5] {
            assert_eq!(out[i]["ok"], true, "{}", out[i]);
            assert_eq!(out[i]["body"], "hello");
            assert_eq!(out[i]["status"], 200);
            assert!(out[i]["headers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|pair| pair[0] == "x-ok" && pair[1] == "1"));
        }
        assert_eq!(out[3]["code"], "AV_PIN_MISMATCH");
        assert_eq!(out[3]["reason"], Value::Null);
        for present in [pin(&c.leaf), pin(&c.inter)] {
            assert!(out[3]["presented"]
                .as_array()
                .unwrap()
                .contains(&json!(present)));
        }
        assert!(!out[3]["presented"]
            .as_array()
            .unwrap()
            .contains(&json!(wrong)));
        assert_eq!(p.seen.lock().unwrap().len(), 5);
        for b in p.seen.lock().unwrap().iter() {
            let text = String::from_utf8_lossy(b);
            assert!(text.contains(SECRET));
            assert!(text.starts_with("POST /user "));
            assert!(text.ends_with("SENTINEL"));
        }
        let rotated = peer(
            vec![c.rotated.der().to_vec(), c.inter.der().to_vec()],
            c.rotated_key.clone(),
        )
        .await;
        let out = trusted(
            &root,
            vec![
                call(rotated.port, json!([pin(&c.leaf)])),
                call(rotated.port, json!([pin(&c.leaf), pin(&c.inter)])),
            ],
        )
        .await;
        assert_eq!(out[0]["code"], "AV_PIN_MISMATCH");
        assert!(out[0]["presented"]
            .as_array()
            .unwrap()
            .contains(&json!(pin(&c.rotated))));
        assert!(!out[0]["presented"]
            .as_array()
            .unwrap()
            .contains(&json!(pin(&c.leaf))));
        assert_eq!(out[1]["ok"], true);
        assert_eq!(rotated.seen.lock().unwrap().len(), 1);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn nonleaf_pins_cannot_replace_ca_trust_or_admit_forged_and_unlinked_certificates() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let c = chain();
        let root = c.root.pem();
        let genuine = peer(
            vec![c.leaf.der().to_vec(), c.inter.der().to_vec()],
            c.key.clone(),
        )
        .await;
        for pinset in [
            vec![pin(&c.inter)],
            vec![pin(&c.root)],
            vec![pin(&c.inter), pin(&c.root)],
        ] {
            let e = pinned_request(request(genuine.port, pins(&pinset)))
                .await
                .err()
                .unwrap();
            assert_eq!(e.code, "UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
        }
        assert!(genuine.seen.lock().unwrap().is_empty());
        success(request(genuine.port, pins(&[pin(&c.leaf)]))).await;
        let (s, k) = cert("127.0.0.1", (-1, 2));
        let selfpin = spki_of(&s).unwrap();
        for (label, chain, key, pinset) in [
            (
                "forged intermediate",
                vec![c.evil.der().to_vec(), c.inter.der().to_vec()],
                c.evil_key.clone(),
                vec![pin(&c.inter)],
            ),
            (
                "forged root",
                vec![
                    c.evil.der().to_vec(),
                    c.inter.der().to_vec(),
                    c.root.der().to_vec(),
                ],
                c.evil_key.clone(),
                vec![pin(&c.root)],
            ),
            (
                "unlinked self leaf",
                vec![s, c.inter.der().to_vec()],
                k,
                vec![pin(&c.inter)],
            ),
        ] {
            let p = peer(chain, key).await;
            let e = pinned_request(request(p.port, pins(&pinset)))
                .await
                .err()
                .unwrap();
            assert!(!e.code.is_empty());
            let out = trusted(&root, vec![call(p.port, json!(pinset))]).await;
            assert_eq!(out[0]["ok"], false, "{label}");
            assert!(p.seen.lock().unwrap().is_empty(), "{label}");
        }
        let other = peer(
            vec![c.other.der().to_vec(), c.inter.der().to_vec()],
            c.other_key.clone(),
        )
        .await;
        let out = trusted(
            &root,
            vec![
                call(other.port, json!([pin(&c.other)])),
                call(other.port, json!([pin(&c.inter)])),
                call(other.port, Value::Null),
            ],
        )
        .await;
        for v in out {
            assert_eq!(v["code"], "ERR_TLS_CERT_ALTNAME_INVALID");
        }
        assert!(other.seen.lock().unwrap().is_empty());
        assert!(!selfpin.is_empty());
    })
    .await
    .unwrap();
}
#[test]
fn spki_hash_matches_independent_key_der_and_host_header_identity_table() {
    use base64::Engine;
    use sha2::Digest;
    let key = rcgen::KeyPair::generate().unwrap();
    let p = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let c = p.self_signed(&key).unwrap();
    let expected = format!(
        "sha256/{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(
            base64::engine::general_purpose::STANDARD
                .decode(
                    key.public_key_pem()
                        .lines()
                        .filter(|l| !l.starts_with('-'))
                        .collect::<String>()
                )
                .unwrap()
        ))
    );
    assert_eq!(spki_of(c.der()).unwrap(), expected);
    assert_eq!(expected.len(), 51);
    assert!(spki_of(b"not-a-cert").is_none());
    use av_daemon::connectors::pinning::host_header_matches;
    for (url, good, bad) in [
        (
            "https://API.github.com/user",
            vec!["api.github.com", "API.GITHUB.COM", "api.github.com:443"],
            vec![
                "api.github.com:80",
                "api.github.com:8443",
                "api.github.com.",
                "evil.example",
                "api.github.com:443:443",
                "",
            ],
        ),
        (
            "http://example.test/",
            vec!["example.test:80"],
            vec!["example.test:443"],
        ),
        (
            "https://example.test:8443/",
            vec!["example.test:8443"],
            vec!["example.test", "example.test:443"],
        ),
        ("https://[::1]:8443/", vec!["[::1]:8443"], vec!["::1"]),
    ] {
        let u = url::Url::parse(url).unwrap();
        for h in good {
            assert!(host_header_matches(h, &u), "{url} {h}");
        }
        for h in bad {
            assert!(!host_header_matches(h, &u), "{url} {h}");
        }
    }
}
#[tokio::test]
async fn fetch_chain_returns_leaf_and_intermediate_and_never_sends_http() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let c = chain();
        let p = peer(
            vec![c.leaf.der().to_vec(), c.inter.der().to_vec()],
            c.key.clone(),
        )
        .await;
        let rows = fetch_chain_pins("127.0.0.1", p.port).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["spki"], pin(&c.leaf));
        assert_eq!(rows[1]["spki"], pin(&c.inter));
        assert!(rows[0]["subject"].as_str().unwrap().contains("localhost"));
        assert!(rows[1]["subject"]
            .as_str()
            .unwrap()
            .contains("TestIntermediate"));
        assert!(rows[0]["not_after"].as_str().unwrap().contains('T'));
        assert!(p.seen.lock().unwrap().is_empty());
        success(request(p.port, pins(&[pin(&c.leaf)]))).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn absent_or_empty_pins_preserve_plain_http_method_path_body_and_response() {
    tokio::time::timeout(Duration::from_secs(10),async {
 let l=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=l.local_addr().unwrap().port();
 let task=tokio::spawn(async move {for _ in 0..3 {let(mut tcp,_)=l.accept().await.unwrap();let mut all=Vec::new();let mut b=[0;4096];loop{let n=tcp.read(&mut b).await.unwrap();if n==0{panic!("request ended early");}all.extend_from_slice(&b[..n]);if all.ends_with(b"abc"){break;}}let text=String::from_utf8(all).unwrap();assert!(text.starts_with("POST /user?q=1 HTTP/1.1\r\n"));assert!(text.ends_with("abc"));tcp.write_all(b"HTTP/1.1 201 Created\r\nx-plain: yes\r\ncontent-length: 5\r\nconnection: close\r\n\r\nplain").await.unwrap();}});
 for pins in [Pins::None,Pins::None,Pins::List(vec![])] {let r=pinned_request(UpstreamRequest{url:format!("http://127.0.0.1:{port}/user?q=1"),method:"POST".into(),headers:vec![("content-type".into(),"text/plain".into())],body:Some(b"abc".to_vec()),pins}).await.unwrap();assert_eq!(r.status,201);assert!(r.headers.iter().any(|(n,v)|n=="x-plain"&&v=="yes"));let Body::Stream(mut rx)=r.body else{panic!("stream")};let mut body=Vec::new();while let Some(b)=rx.recv().await{body.extend(b.unwrap());}assert_eq!(body,b"plain");}task.await.unwrap();
 }).await.unwrap();
}
#[tokio::test]
async fn host_named_by_foreign_certificate_never_overrides_url_identity() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let c = chain();
        let p = peer(
            vec![c.other.der().to_vec(), c.inter.der().to_vec()],
            c.other_key.clone(),
        )
        .await;
        let mut calls = Vec::new();
        for name in ["127.0.0.1", "localhost"] {
            for pinset in [
                json!([pin(&c.leaf)]),
                json!([pin(&c.other)]),
                json!([pin(&c.inter)]),
                json!([pin(&c.root)]),
                Value::Null,
            ] {
                let mut call = call(p.port, pinset);
                call["url"] = json!(format!("https://{name}:{}/user", p.port));
                call["headers"] = json!([
                    ["authorization", format!("Bearer {SECRET}")],
                    ["Host", "elsewhere.test"]
                ]);
                calls.push(call);
            }
        }
        let out = trusted(&c.root.pem(), calls).await;
        for r in out {
            assert_eq!(r["rule"], "host_mismatch");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(p.connections.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(p.seen.lock().unwrap().is_empty());
        let out = trusted(
            &c.root.pem(),
            vec![
                call(p.port, json!([pin(&c.other)])),
                call(p.port, json!([pin(&c.inter)])),
            ],
        )
        .await;
        for r in out {
            assert_eq!(r["code"], "ERR_TLS_CERT_ALTNAME_INVALID");
        }
        assert!(p.seen.lock().unwrap().is_empty());
        let good = peer(
            vec![c.leaf.der().to_vec(), c.inter.der().to_vec()],
            c.key.clone(),
        )
        .await;
        success(request(good.port, pins(&[pin(&c.leaf)]))).await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn fresh_tls_handshake_per_request_and_redirect_is_returned_without_following() {
    tokio::time::timeout(Duration::from_secs(40),async{let c=chain();let destination=peer(vec![c.leaf.der().to_vec(),c.inter.der().to_vec()],c.key.clone()).await;let response=format!("HTTP/1.1 302 Found\r\nlocation: https://127.0.0.1:{}/steal\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",destination.port).into_bytes();let p=peer_on(vec![c.leaf.der().to_vec(),c.inter.der().to_vec()],c.key.clone(),"127.0.0.1:0",Some(response)).await;let wrong=format!("sha256/{}=","A".repeat(43));let out=trusted(&c.root.pem(),vec![call(p.port,json!([pin(&c.leaf)])),call(p.port,json!([wrong])),call(p.port,json!([pin(&c.leaf)]))]).await;assert_eq!(out[0]["status"],302);assert_eq!(out[1]["code"],"AV_PIN_MISMATCH");assert_eq!(out[2]["status"],302);assert_eq!(p.connections.load(std::sync::atomic::Ordering::SeqCst),3);assert_eq!(p.seen.lock().unwrap().len(),2);assert_eq!(p.handshakes.lock().unwrap().len(),3);assert!(p.handshakes.lock().unwrap().iter().all(|(_,resumed)| !resumed));assert_eq!(destination.connections.load(std::sync::atomic::Ordering::SeqCst),0);assert!(destination.seen.lock().unwrap().is_empty());}).await.unwrap();
}
#[tokio::test]
async fn matching_or_absent_host_is_sent_and_sni_is_only_the_url_dns_name() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let c = chain();
        let p = peer(
            vec![c.leaf.der().to_vec(), c.inter.der().to_vec()],
            c.key.clone(),
        )
        .await;
        let host = format!("127.0.0.1:{}", p.port);
        let mut calls = Vec::new();
        for pinset in [
            json!([pin(&c.inter)]),
            json!([pin(&c.root)]),
            json!([pin(&c.leaf)]),
            Value::Null,
        ] {
            for with_host in [false, true] {
                let mut r = call(p.port, pinset.clone());
                if with_host {
                    r["headers"] = json!([
                        ["authorization", format!("Bearer {SECRET}")],
                        ["host", host]
                    ]);
                }
                calls.push(r);
            }
        }
        for out in trusted(&c.root.pem(), calls).await {
            assert_eq!(out["ok"], true);
            assert_eq!(out["body"], "hello");
        }
        assert_eq!(p.seen.lock().unwrap().len(), 8);
        for b in p.seen.lock().unwrap().iter() {
            let text = String::from_utf8_lossy(b);
            assert!(text.to_lowercase().contains(&format!("host: {host}\r\n")));
            assert!(text.contains(SECRET));
        }
        assert!(p
            .handshakes
            .lock()
            .unwrap()
            .iter()
            .all(|(sni, resumed)| sni.is_none() && !resumed));
        let (d, k) = cert("localhost", (-1, 2));
        let pin = spki_of(&d).unwrap();
        let local = peer(vec![d], k).await;
        for h in [Some(format!("LocalHost:{}", local.port)), None] {
            let mut r = request(local.port, pins(std::slice::from_ref(&pin)));
            r.url = format!("https://localhost:{}/user", local.port);
            if let Some(h) = h {
                r.headers.push(("hOsT".into(), h));
            }
            success(r).await;
        }
        assert_eq!(
            local
                .handshakes
                .lock()
                .unwrap()
                .iter()
                .map(|(n, _)| n.clone())
                .collect::<Vec<_>>(),
            vec![Some("localhost".into()); 2]
        );
        let seen = local.seen.lock().unwrap();
        assert!(String::from_utf8_lossy(&seen[0]).contains(&format!("LocalHost:{}", local.port)));
        assert!(String::from_utf8_lossy(&seen[1]).contains(&format!("localhost:{}", local.port)));
    })
    .await
    .unwrap();
}

struct PublicOnly(Vec<u8>);
impl rcgen::PublicKeyData for PublicOnly {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
#[tokio::test]
#[ignore = "pending daemon fix: pinning leaf issuer classification"]
async fn copied_intermediate_public_key_cannot_sign_the_handshake_or_authorize_an_appended_leaf() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let c = chain();
        let (_, parsed) = x509_parser::parse_x509_certificate(c.inter.der()).unwrap();
        let copied_key = PublicOnly(parsed.public_key().subject_public_key.data.to_vec());
        let p = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        let (signer_params, signer) = ca("attacker");
        let private = signer.serialize_der();
        let issuer = rcgen::Issuer::new(signer_params, signer);
        let copied = p.signed_by(&copied_key, &issuer).unwrap();
        assert_eq!(pin(&copied), pin(&c.inter));
        let bad = peer(vec![copied.der().to_vec()], private).await;
        let e = pinned_request(request(bad.port, pins(&[pin(&c.inter)])))
            .await
            .err()
            .unwrap();
        assert_ne!(e.code, "AV_PIN_MISMATCH");
        assert!(!e.code.is_empty());
        let out = trusted(&c.root.pem(), vec![call(bad.port, json!([pin(&c.inter)]))]).await;
        assert_eq!(out[0]["ok"], false);
        assert_ne!(out[0]["code"], "AV_PIN_MISMATCH");
        assert!(bad.seen.lock().unwrap().is_empty());
        let (d, k) = cert("127.0.0.1", (-1, 2));
        let goodpin = spki_of(&d).unwrap();
        let behind = peer(vec![d, copied.der().to_vec()], k).await;
        let e = pinned_request(request(behind.port, pins(&[pin(&c.inter)])))
            .await
            .err()
            .unwrap();
        assert_eq!(e.code, "DEPTH_ZERO_SELF_SIGNED_CERT");
        assert!(behind.seen.lock().unwrap().is_empty());
        success(request(behind.port, pins(&[goodpin]))).await;
    })
    .await
    .unwrap();
}
#[test]
fn only_cryptographically_proven_issuers_can_match_pins_and_duplicate_presentations_are_bounded() {
    use av_daemon::connectors::pinning::{describe_cert, verdict_with};
    use rustls::pki_types::ServerName;
    let c = chain();
    let a = webpki::anchor_from_trusted_cert(c.root.der())
        .unwrap()
        .to_owned();
    let anchors = [a];
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let chain = vec![
        c.leaf.der().to_vec(),
        c.inter.der().to_vec(),
        c.root.der().to_vec(),
    ];
    for p in [pin(&c.leaf), pin(&c.inter), pin(&c.root)] {
        assert!(verdict_with(&chain, &name, Some(&[p]), &anchors).is_none());
    }
    let forged = vec![
        c.evil.der().to_vec(),
        c.inter.der().to_vec(),
        c.root.der().to_vec(),
    ];
    for p in [pin(&c.inter), pin(&c.root)] {
        assert!(verdict_with(&forged, &name, Some(&[p]), &anchors).is_some());
    }
    assert!(verdict_with(&forged, &name, Some(&[pin(&c.evil)]), &anchors).is_none());
    let mut repeated = chain.clone();
    repeated.extend(chain.clone());
    let wrong = format!("sha256/{}=", "A".repeat(43));
    let e = verdict_with(&repeated, &name, Some(&[wrong]), &anchors).unwrap();
    assert_eq!(e.code, "AV_PIN_MISMATCH");
    assert_eq!(e.presented.len(), 3);
    assert_eq!(
        e.presented
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert!(describe_cert(b"not-a-cert").is_none());
    assert!(spki_of(b"not-a-cert").is_none());
}
#[tokio::test]
async fn owned_header_snapshot_is_exact_on_wire_and_foreign_first_value_never_connects() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (d, k) = cert("127.0.0.1", (-1, 2));
        let pin = spki_of(&d).unwrap();
        let p = peer(vec![d], k).await;
        let good = format!("127.0.0.1:{}", p.port);
        let mut backing = vec![
            ("authorization".to_owned(), format!("Bearer {SECRET}")),
            ("Host".to_owned(), good.clone()),
            ("x-declared".to_owned(), "ordinary".to_owned()),
        ];
        let mut r = request(p.port, pins(std::slice::from_ref(&pin)));
        r.headers = backing.clone();
        let pending = pinned_request(r);
        backing[0].1 = "Bearer test-secret-unapproved-0099".into();
        backing[1].1 = "evil.example".into();
        backing.push(("x-undeclared".into(), "hostile".into()));
        let response = pending.await.unwrap();
        assert_eq!(response.status, 200);
        drop(response);
        let raw = p.seen.lock().unwrap()[0].clone();
        let text = String::from_utf8(raw).unwrap();
        assert!(!text.contains("evil.example"));
        assert!(!text.contains("unapproved"));
        assert!(!text.contains("x-undeclared"));
        let mut headers = text
            .split("\r\n")
            .skip(1)
            .take_while(|s| !s.is_empty())
            .map(|s| {
                let (n, v) = s.split_once(':').unwrap();
                (n.to_ascii_lowercase(), v.trim().to_owned())
            })
            .collect::<Vec<_>>();
        headers.sort();
        let mut expected = vec![
            ("authorization".to_owned(), format!("Bearer {SECRET}")),
            ("host".to_owned(), good),
            ("x-declared".to_owned(), "ordinary".into()),
            ("content-length".to_owned(), "8".into()),
        ];
        expected.sort();
        assert_eq!(headers, expected);
        let before = p.connections.load(std::sync::atomic::Ordering::SeqCst);
        let mut r = request(p.port, pins(&[pin]));
        r.headers = backing;
        let e = pinned_request(r).await.err().unwrap();
        assert_eq!(
            e.vault.unwrap().extra.rule.as_deref(),
            Some("host_mismatch")
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            p.connections.load(std::sync::atomic::Ordering::SeqCst),
            before
        );
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn ipv6_uses_ip_san_without_sni_and_still_checks_pins_and_host_before_http() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let (rp, rk) = ca("IPv6 Test Root");
        let root = rp.self_signed(&rk).unwrap();
        let issuer = rcgen::Issuer::new(rp, rk);
        let p = rcgen::CertificateParams::new(vec!["::1".into()]).unwrap();
        let k = rcgen::KeyPair::generate().unwrap();
        let leaf = p.signed_by(&k, &issuer).unwrap();
        let genuine = peer_on(
            vec![leaf.der().to_vec(), root.der().to_vec()],
            k.serialize_der(),
            "[::1]:0",
            None,
        )
        .await;
        let (d, k) = cert("::1", (-1, 2));
        let selfpin = spki_of(&d).unwrap();
        let local = peer_on(vec![d], k, "[::1]:0", None).await;
        for host in [None, Some(format!("[::1]:{}", local.port))] {
            let mut r = request(local.port, pins(std::slice::from_ref(&selfpin)));
            r.url = format!("https://[::1]:{}/user", local.port);
            if let Some(h) = host {
                r.headers.push(("host".into(), h));
            }
            success(r).await;
        }
        assert_eq!(local.seen.lock().unwrap().len(), 2);
        for b in local.seen.lock().unwrap().iter() {
            let s = String::from_utf8_lossy(b);
            assert!(s.contains(&format!("[::1]:{}", local.port)));
            assert!(s.contains(SECRET));
        }
        assert!(local
            .handshakes
            .lock()
            .unwrap()
            .iter()
            .all(|(sni, _)| sni.is_none()));
        let mut calls = Vec::new();
        for pinset in [
            json!([pin(&root)]),
            Value::Null,
            json!([format!("sha256/{}=", "A".repeat(43))]),
        ] {
            let mut r = call(genuine.port, pinset);
            r["url"] = json!(format!("https://[::1]:{}/user", genuine.port));
            calls.push(r);
        }
        let out = trusted(&root.pem(), calls).await;
        assert_eq!(out[0]["ok"], true);
        assert_eq!(out[1]["ok"], true);
        assert_eq!(out[2]["code"], "AV_PIN_MISMATCH");
        assert_eq!(genuine.seen.lock().unwrap().len(), 2);
        let (d, k) = cert("127.0.0.1", (-1, 2));
        let wrongpin = spki_of(&d).unwrap();
        let wrong = peer_on(vec![d], k, "[::1]:0", None).await;
        let mut r = request(wrong.port, pins(&[wrongpin]));
        r.url = format!("https://[::1]:{}/user", wrong.port);
        let e = pinned_request(r).await.err().unwrap();
        assert_eq!(e.code, "ERR_TLS_CERT_ALTNAME_INVALID");
        assert!(wrong.seen.lock().unwrap().is_empty());
        let before = local.connections.load(std::sync::atomic::Ordering::SeqCst);
        for h in [
            "::1".to_owned(),
            "evil.example".into(),
            format!("127.0.0.1:{}", local.port),
        ] {
            let mut r = request(local.port, pins(std::slice::from_ref(&selfpin)));
            r.url = format!("https://[::1]:{}/user", local.port);
            r.headers.push(("host".into(), h));
            assert_eq!(
                pinned_request(r)
                    .await
                    .err()
                    .unwrap()
                    .vault
                    .unwrap()
                    .extra
                    .rule
                    .as_deref(),
                Some("host_mismatch")
            );
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            local.connections.load(std::sync::atomic::Ordering::SeqCst),
            before
        );
    })
    .await
    .unwrap();
}
async fn child_probe(call: &Value) -> Value {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
    let url = url::Url::parse(call["url"].as_str().unwrap()).unwrap();
    let host = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
    vault
        .add_credential(av_store::vault::NewCredential {
            slug: "probe".into(),
            kind: "github".into(),
            connector: serde_json::from_value(json!({"host":host,"scheme":"https"})).unwrap(),
            fields: vec![("token".into(), SECRET.to_owned().into())],
            sites: std::collections::BTreeMap::from([(
                "token".into(),
                vec!["header:authorization:Bearer".into()],
            )]),
        })
        .unwrap();
    if let Some(p) = call["pins"].as_array() {
        let pins = p
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        vault.set_pins("probe", "127.0.0.1", &pins).unwrap();
    }
    let shared = av_daemon::state::Shared::new(vault);
    let result = av_daemon::connectors::probe::run_probe(&shared, "probe".into(), None).await;
    let health = shared
        .run(|c| {
            serde_json::to_value(c.vault.find_credential("probe").unwrap().unwrap().health).unwrap()
        })
        .await
        .unwrap();
    let audit = shared
        .run(|c| {
            serde_json::to_value(
                c.vault
                    .audit()
                    .unwrap()
                    .read(&av_store::audit::ReadFilter {
                        limit: 1000,
                        ..Default::default()
                    })
                    .unwrap(),
            )
            .unwrap()
        })
        .await
        .unwrap();
    assert!(!audit.to_string().contains(SECRET));
    match result {
        Ok(v) => json!({"result":v,"health":health}),
        Err(e) => json!({"error":{"code":e.code.as_str(),"rule":e.extra.rule},"health":health}),
    }
}
#[tokio::test]
async fn real_probe_root_pin_needs_ca_trust_refuses_mismatch_and_persists_scrubbed_health() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let c = chain();
        let body = format!("{SECRET} test-marker-probe-body-0123456");
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let p = peer_on(
            vec![
                c.leaf.der().to_vec(),
                c.inter.der().to_vec(),
                c.root.der().to_vec(),
            ],
            c.key.clone(),
            "127.0.0.1:0",
            Some(reply),
        )
        .await;
        let mut wrong = call(p.port, json!([format!("sha256/{}=", "D".repeat(43))]));
        wrong["probe"] = json!(true);
        let bad = trusted(&c.root.pem(), vec![wrong]).await;
        assert_eq!(bad[0]["error"]["code"], "AV_PIN_MISMATCH");
        assert_eq!(bad[0]["health"]["status"], "error");
        assert_eq!(bad[0]["health"]["source"], "probe");
        let mut normal = call(p.port, json!([pin(&c.root)]));
        normal["probe"] = json!(true);
        let untrusted = trusted("", vec![normal.clone()]).await;
        assert_eq!(untrusted[0]["result"]["status"], "unreachable");
        assert!(p.seen.lock().unwrap().is_empty());
        let ok = trusted(&c.root.pem(), vec![normal]).await;
        assert_eq!(ok[0]["result"]["status"], "ok");
        assert_eq!(ok[0]["health"]["status"], "ok");
        assert_eq!(ok[0]["health"]["source"], "probe");
        assert_eq!(ok[0]["health"]["http_status"], 200);
        assert!(!ok
            .to_owned()
            .iter()
            .any(|v| v.to_string().contains(SECRET)
                || v.to_string().contains("test-marker-probe-body")));
        assert_eq!(p.seen.lock().unwrap().len(), 1);
        let raw = p.seen.lock().unwrap()[0].clone();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.starts_with("GET /user HTTP/1.1\r\n"));
        assert!(text.contains(&format!("Bearer {SECRET}")));
        assert!(!text.contains("pwned"));
    })
    .await
    .unwrap();
}
