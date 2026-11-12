//! Tests for the src/connectors/pinning.js, probe.js and profiles.js entries
//! of mutations.toml, against real local TLS and TCP servers. Each names the
//! protection (the `what` of test/mutation-check.js) it holds.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::connectors::pinning::{pinned_request, spki_of};
use crate::upstream::{Pins, UpstreamRequest};

type Got = Arc<Mutex<Vec<u8>>>;

fn self_signed(name: &str) -> (Vec<u8>, Vec<u8>) {
    let kp = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    (cert.der().to_vec(), kp.serialize_der())
}

async fn answer<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S, got: Got) {
    let mut buf = vec![0u8; 4096];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1500), s.read(&mut buf)).await
    {
        if n == 0 {
            return;
        }
        got.lock().unwrap().extend_from_slice(&buf[..n]);
        if got.lock().unwrap().windows(4).any(|w| w == b"\r\n\r\n") {
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await;
            let _ = s.flush().await;
            return;
        }
    }
}

/// A TLS server on 127.0.0.1 presenting `cert`; records every byte it reads.
async fn tls_server(cert: Vec<u8>, key: Vec<u8>) -> (u16, Got) {
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
    )
    .unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let got: Got = Arc::default();
    let g = got.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let (acc, g) = (acc.clone(), g.clone());
            tokio::spawn(async move {
                if let Ok(s) = acc.accept(tcp).await {
                    answer(s, g).await;
                }
            });
        }
    });
    (port, got)
}

fn req(url: String, headers: Vec<(String, String)>, pins: Pins) -> UpstreamRequest {
    UpstreamRequest {
        url,
        method: "GET".into(),
        headers,
        body: None,
        pins,
    }
}

/// 'the request is ended before the certificate pin is checked'.
#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_written_to_a_server_whose_certificate_is_refused() {
    let (cert, key) = self_signed("127.0.0.1");
    let (port, got) = tls_server(cert, key).await;
    let e = pinned_request(req(
        format!("https://127.0.0.1:{port}/x"),
        vec![("authorization".into(), format!("Bearer {SECRET}"))],
        Pins::None,
    ))
    .await
    .err()
    .expect("an untrusted certificate is refused");
    assert!(e.message.contains("not trusted"), "{e:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(got.lock().unwrap().is_empty(), "not a byte of the request");
}

/// 'the certificate identity check reads the Host header' and 'a Host
/// header naming another host is sent instead of refused'.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_header_naming_another_host_is_refused_before_connecting() {
    let (cert, key) = self_signed("localhost");
    let pin = spki_of(&cert).unwrap();
    let (port, got) = tls_server(cert, key).await;
    let e = pinned_request(req(
        format!("https://127.0.0.1:{port}/x"),
        vec![("host".into(), format!("localhost:{port}"))],
        Pins::List(vec![json!(pin)]),
    ))
    .await
    .err()
    .expect("refused");
    assert_eq!(
        e.vault.map(|v| v.extra.rule),
        Some(Some("host_mismatch".into()))
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(got.lock().unwrap().is_empty());
}

/// 'a Host header under another spelling of the name is not checked'.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_header_is_checked_whatever_its_case() {
    for name in ["Host", "HOST", "hOsT"] {
        let e = pinned_request(req(
            "https://127.0.0.1:1/x".into(),
            vec![(name.into(), "evil.test".into())],
            Pins::None,
        ))
        .await
        .err()
        .unwrap();
        assert_eq!(
            e.vault.and_then(|v| v.extra.rule).as_deref(),
            Some("host_mismatch"),
            "{name}"
        );
    }
}

/// 'pinnedRequest connects to the bracketed IPv6 host'.
#[tokio::test(flavor = "multi_thread")]
async fn an_ipv6_url_connects_to_the_bare_address() {
    let l = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let got: Got = Arc::default();
    let g = got.clone();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = l.accept().await {
            answer(tcp, g).await;
        }
    });
    let r = pinned_request(req(format!("http://[::1]:{port}/x"), vec![], Pins::None))
        .await
        .expect("sent");
    assert_eq!(r.status, 200);
}

/// 'a pin list with a malformed entry is used anyway', 'any Host header
/// value passes as the URL host', 'a probe pin entry of the wrong shape is
/// skipped', 'probe pin keys that are a bare IPv6 address are not read as a
/// host' (the av-core halves the daemon calls).
#[test]
fn the_pin_helpers_the_daemon_calls_fail_closed() {
    use av_core::pins::{host_header_matches, pin_list_state, pins_for, PinListState, PinLookup};
    let pin = format!("sha256/{}=", "A".repeat(43));
    assert_eq!(
        pin_list_state(Some(&json!([pin.clone(), "nope"]))),
        PinListState::Invalid
    );
    let u = url::Url::parse("https://api.example.test/x").unwrap();
    assert!(host_header_matches("API.example.test:443", &u));
    assert!(!host_header_matches("evil.test", &u));
    assert!(!host_header_matches("api.example.test:8443", &u));
    assert!(matches!(
        pins_for(Some(&json!({"api.example.test": "x"})), "api.example.test"),
        PinLookup::Malformed
    ));
    assert!(matches!(
        pins_for(Some(&json!({"::1": [pin.clone()]})), "::1"),
        PinLookup::Found(_)
    ));
}

/// 'an unparseable expiry header is kept as the observed expiry' and 'an
/// expiry offset outside +-14:00 is applied'.
#[test]
fn an_expiry_header_is_kept_only_when_it_parses() {
    let gh = av_core::profiles::get_profile("github").ok();
    let at = |v: &str| {
        av_core::profiles::extract_health(
            gh,
            &[(
                "github-authentication-token-expiration".into(),
                v.to_string(),
            )],
        )
        .and_then(|h| h.observed_expires_at)
    };
    assert_eq!(
        at("2030-01-02T03:04:05+01:00").as_deref(),
        Some("2030-01-02T02:04:05.000Z")
    );
    assert_eq!(at("next tuesday, probably"), None);
    assert_eq!(at("2030-01-02T03:04:05+15:00"), None);
    assert_eq!(at("2030-01-02T03:04:05+14:30"), None);
}

/// A github credential `gh` in a fresh world, and its record.
async fn gh() -> (World, av_store::model::CredentialRecord) {
    crate::connectors::probe::reset_probe_throttle();
    let w = World::bare().await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "gh", "kind": "github", "value": SECRET}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let c = w
        .shared
        .run(|core| core.vault.find_credential("gh").unwrap().unwrap())
        .await
        .unwrap();
    (w, c)
}

/// 'a probe host that is not a hostname is used anyway', 'a probe accepts
/// a scheme other than http or https', 'probe pins are looked up by the
/// declared host, not the URL host', 'probe pin keys that are a bare IPv6
/// address are not read as a host'.
#[tokio::test(flavor = "multi_thread")]
async fn the_probe_reads_its_destination_and_pins_as_the_js_does() {
    let (_w, base) = gh().await;
    let pin = format!("sha256/{}=", "B".repeat(43));
    let with = |connector: Value, pins: Value| {
        let mut c = base.clone();
        c.connector = connector.as_object().unwrap().clone();
        c.pins = serde_json::from_value(pins).unwrap();
        c.id = format!("cr_{}", av_core::placeholder::new_sid());
        c
    };
    let secret = |_: &str, _: &str| Ok(av_core::secret::SecretString::from("x".to_string()));
    for host in [
        "api.github.com/steal",
        "https://evil.test",
        "api.github.com@evil.test",
        "api.github.com\nevil.test",
        "api.github.com?x=1",
        "*.github.com",
        "file://api.github.com",
    ] {
        let c = with(json!({"host": host, "scheme": "https"}), json!({}));
        let e = crate::connectors::probe::prepare_for_test(&c, secret)
            .err()
            .unwrap_or_else(|| panic!("{host:?} is not a host"));
        assert_eq!(e.extra.rule.as_deref(), Some("credential_host"), "{host:?}");
    }
    let c = with(json!({"host": "api.github.com", "scheme": "file"}), json!({}));
    let e = crate::connectors::probe::prepare_for_test(&c, secret)
        .err()
        .expect("file is not a scheme a probe uses");
    assert_eq!(e.extra.rule.as_deref(), Some("credential_host"));
    for (host, pins) in [
        ("[::1]:8443", json!({"::1": [pin]})),
        ("[::1]:8443", json!({" 0:0::1 ": [pin]})),
        ("api.github.com", json!({"API.GitHub.com.": [pin]})),
        ("api.github.com:443", json!({"api.github.com": [pin]})),
    ] {
        let c = with(json!({"host": host, "scheme": "https"}), pins.clone());
        let p = crate::connectors::probe::prepare_for_test(&c, secret).unwrap();
        assert_eq!(p, json!([pin]), "{host} {pins}");
    }
}

struct Odd {
    dir: std::path::PathBuf,
    mode: &'static str,
}

impl Upstream for Odd {
    fn send(&self, _req: UpstreamRequest) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            match self.mode {
                "failwrite" => {
                    // Any later write of a credential row now fails.
                    let c = rusqlite::Connection::open(self.dir.join("vault.db")).unwrap();
                    c.execute_batch(
                        "CREATE TRIGGER t_fail BEFORE UPDATE ON credentials BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
                    )
                    .unwrap();
                    return Ok(json_response(200, &json!({})));
                }
                "endless" => {
                    tokio::spawn(async move {
                        while tx.send(Ok(vec![b'x'; 8192])).await.is_ok() {}
                    });
                }
                _ => {
                    // Never ends and never sends.
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        drop(tx);
                    });
                }
            }
            Ok(UpstreamResponse {
                status: 200,
                headers: vec![],
                body: Body::Stream(rx),
            })
        })
    }
}

/// 'a recordHealth failure is swallowed'.
#[tokio::test(flavor = "multi_thread")]
async fn a_probe_whose_health_cannot_be_recorded_fails() {
    let (w, _) = gh().await;
    let up = Arc::new(Odd {
        dir: w._dir.path().to_path_buf(),
        mode: "failwrite",
    });
    let r = crate::connectors::probe::run_probe(&w.shared, "gh".into(), Some(up)).await;
    assert!(r.is_err(), "{r:?}");
}

/// 'a probe body past the drain bound is left open'.
#[tokio::test(flavor = "multi_thread")]
async fn a_probe_stops_reading_past_the_drain_bound() {
    let (w, _) = gh().await;
    let up = Arc::new(Odd {
        dir: w._dir.path().to_path_buf(),
        mode: "endless",
    });
    let t = Instant::now();
    let r = crate::connectors::probe::run_probe(&w.shared, "gh".into(), Some(up)).await;
    assert!(r.is_ok(), "{r:?}");
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
}

/// 'a probe body that never ends holds the probe open'.
#[tokio::test(flavor = "multi_thread")]
async fn a_probe_gives_up_on_a_body_that_never_ends() {
    let (w, _) = gh().await;
    let up = Arc::new(Odd {
        dir: w._dir.path().to_path_buf(),
        mode: "silent",
    });
    let r = tokio::time::timeout(
        Duration::from_secs(6),
        crate::connectors::probe::run_probe(&w.shared, "gh".into(), Some(up)),
    )
    .await
    .expect("the drain is bounded in time");
    assert!(r.is_ok(), "{r:?}");
}
