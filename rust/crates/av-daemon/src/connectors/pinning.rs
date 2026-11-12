//! SPKI pins for one credential's hosts, and the upstream HTTP client every
//! credential-bearing request goes through. Ports the network and TLS parts
//! of `src/connectors/pinning.js` (`pinnedRequest`, `pinVerdict`,
//! `chainPins`, `verifiedChainPins`, `fetchChainPins`); the pure parts
//! (`PIN_RE`, `pinListState`, `urlHostOf`, `hostHeaderMatches`, `pinsFor`)
//! are `av_core::pins`, re-exported here.
//!
//! The order is the whole protection, as in the JS: the TLS handshake runs
//! to the end, the verdict is made, and only then is the first byte of the
//! request (which carries the substituted secret) written. The certificate
//! verifier given to rustls records what the peer presented and accepts it;
//! the decision is [`verdict`]'s, made before anything is sent:
//!
//! - no pins: the chain must verify to the trust store (the Mozilla roots,
//!   as Node bundles them, plus `NODE_EXTRA_CA_CERTS`) and name the host;
//! - an exact leaf pin stands in for CA trust, but the certificate must still
//!   name the host and be inside its validity window;
//! - any other pin needs a verified chain, and matches only a certificate in
//!   that verified path (the leaf, each proven intermediate, the trust
//!   anchor), never one the server merely appended.
//!
//! The handshake signature is always verified, so the server proved it holds
//! the leaf's key.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use http_body_util::BodyExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::err::{dr, C};
use crate::upstream::{Body, BoxFuture, Pins, Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

pub use av_core::pins::{host_header_matches, pin_list_state, pins_for, url_host_of, url_identity, PinListState, PIN_PATTERN};

/// Idle timeout on an upstream request. Ports `UPSTREAM_TIMEOUT_MS`.
pub const UPSTREAM_TIMEOUT_MS: u64 = 30_000;
/// Longest chain walked. Ports `CHAIN_HOPS`.
pub const CHAIN_HOPS: usize = 16;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The trust store: the Mozilla roots Node bundles, plus every certificate
/// in the file `NODE_EXTRA_CA_CERTS` names, read once, as Node reads it.
pub fn trust_anchors() -> &'static [TrustAnchor<'static>] {
    static ROOTS: OnceLock<Vec<TrustAnchor<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut out: Vec<TrustAnchor<'static>> = webpki_roots::TLS_SERVER_ROOTS.to_vec();
        if let Some(path) = std::env::var_os("NODE_EXTRA_CA_CERTS").filter(|p| !p.is_empty()) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                for der in pem_certs(&text) {
                    let der = CertificateDer::from(der);
                    if let Ok(a) = webpki::anchor_from_trusted_cert(&der) {
                        out.push(a.to_owned());
                    }
                }
            }
        }
        out
    })
}

/// Every `CERTIFICATE` block in a PEM text, as DER.
pub fn pem_certs(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            body = Some(String::new());
        } else if l == "-----END CERTIFICATE-----" {
            if let Some(b) = body.take() {
                out.push(crate::util::b64_lenient(&b));
            }
        } else if let Some(b) = body.as_mut() {
            b.push_str(l);
        }
    }
    out
}

/// `'sha256/<base64>'` of a certificate's SubjectPublicKeyInfo. Ports `spkiOf`.
pub fn spki_of(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(spki_pin(cert.tbs_certificate.subject_pki.raw))
}

fn spki_pin(spki: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256/{}", crate::util::b64(&sha2::Sha256::digest(spki)))
}

fn wrap_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// What the handshake presented, recorded by the verifier.
#[derive(Debug, Default, Clone)]
struct Seen {
    chain: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct Recorder {
    seen: Mutex<Seen>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut s = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        s.chain = std::iter::once(end_entity.to_vec()).chain(intermediates.iter().map(|c| c.to_vec())).collect();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The outcome of verifying a presented chain against the trust store.
struct ChainCheck {
    /// Node's `socket.authorized`: chain, time and name all good.
    authorized: Result<(), String>,
    /// Pins of the verified path: leaf, proven intermediates, anchor.
    verified: Vec<String>,
}

/// The Node error code for a webpki failure.
fn node_code(e: &webpki::Error, chain: &[Vec<u8>]) -> String {
    use webpki::Error as E;
    match e {
        E::CertExpired { .. } => "CERT_HAS_EXPIRED".into(),
        E::CertNotValidYet { .. } => "CERT_NOT_YET_VALID".into(),
        E::CertNotValidForName(_) => "ERR_TLS_CERT_ALTNAME_INVALID".into(),
        E::UnknownIssuer => {
            let self_signed = |der: &[u8]| {
                x509_parser::parse_x509_certificate(der).is_ok_and(|(_, c)| c.tbs_certificate.issuer.as_raw() == c.tbs_certificate.subject.as_raw())
            };
            if chain.len() == 1 && self_signed(&chain[0]) {
                "DEPTH_ZERO_SELF_SIGNED_CERT".into()
            } else if chain.len() == 1 {
                "UNABLE_TO_VERIFY_LEAF_SIGNATURE".into()
            } else if chain.last().is_some_and(|c| self_signed(c)) {
                "SELF_SIGNED_CERT_IN_CHAIN".into()
            } else {
                "UNABLE_TO_GET_ISSUER_CERT_LOCALLY".into()
            }
        }
        E::CertRevoked => "CERT_REVOKED".into(),
        _ => "UNABLE_TO_VERIFY_LEAF_SIGNATURE".into(),
    }
}

fn check_chain(chain: &[Vec<u8>], name: &ServerName<'_>, anchors: &[TrustAnchor<'_>]) -> ChainCheck {
    let Some(leaf) = chain.first() else {
        return ChainCheck { authorized: Err("UNABLE_TO_VERIFY_LEAF_SIGNATURE".into()), verified: Vec::new() };
    };
    let leaf_der = CertificateDer::from(leaf.as_slice());
    let inter: Vec<CertificateDer<'_>> = chain[1..].iter().take(CHAIN_HOPS).map(|c| CertificateDer::from(c.as_slice())).collect();
    let Ok(ee) = webpki::EndEntityCert::try_from(&leaf_der) else {
        return ChainCheck { authorized: Err("UNABLE_TO_VERIFY_LEAF_SIGNATURE".into()), verified: Vec::new() };
    };
    let algs = provider().signature_verification_algorithms;
    let now = UnixTime::now();
    match ee.verify_for_usage(algs.all, anchors, &inter, now, webpki::KeyUsage::server_auth(), None, None) {
        Err(e) => match anchor_leaf(leaf, anchors) {
            // OpenSSL accepts a leaf that is itself in the trust store (a
            // self-signed certificate trusted through NODE_EXTRA_CA_CERTS),
            // CA flag or not; webpki will not build a path from it. Such a
            // leaf is authorized when it is in date and names the host, and
            // its own key is the only pin it proves.
            Some(pin) => {
                let named = ee.verify_is_valid_for_subject_name(name).map_err(|e| node_code(&e, chain));
                let dated = in_date(leaf).map_err(|_| "CERT_HAS_EXPIRED".to_string());
                ChainCheck { authorized: dated.and(named), verified: vec![pin] }
            }
            None => ChainCheck { authorized: Err(node_code(&e, chain)), verified: Vec::new() },
        },
        Ok(path) => {
            let mut verified = Vec::new();
            let mut push = |p: String| {
                if !verified.contains(&p) {
                    verified.push(p);
                }
            };
            if let Some(p) = spki_of(leaf) {
                push(p);
            }
            for c in path.intermediate_certificates() {
                push(spki_pin(c.subject_public_key_info().as_ref()));
            }
            push(spki_pin(&wrap_sequence(path.anchor().subject_public_key_info.as_ref())));
            let named = ee.verify_is_valid_for_subject_name(name).map_err(|e| node_code(&e, chain));
            ChainCheck { authorized: named, verified }
        }
    }
}

/// The leaf's pin when the leaf is itself a trust anchor: the same subject
/// and the same key as one in the store, and signed by that key.
fn anchor_leaf(leaf: &[u8], anchors: &[TrustAnchor<'_>]) -> Option<String> {
    let (_, c) = x509_parser::parse_x509_certificate(leaf).ok()?;
    let subject = c.tbs_certificate.subject.as_raw();
    let spki = c.tbs_certificate.subject_pki.raw;
    let found = anchors.iter().any(|a| wrap_sequence(a.subject.as_ref()) == subject && wrap_sequence(a.subject_public_key_info.as_ref()) == spki);
    if !found || c.tbs_certificate.issuer.as_raw() != subject {
        return None;
    }
    Some(spki_pin(spki))
}

/// Whether a certificate is inside its validity window now.
fn in_date(der: &[u8]) -> Result<(), ()> {
    let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|_| ())?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    if now < c.validity().not_before.timestamp() || now > c.validity().not_after.timestamp() {
        return Err(());
    }
    Ok(())
}

/// `chainPins(socket)`: every presented certificate's pin, leaf first.
fn chain_pins(chain: &[Vec<u8>], extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in chain.iter().take(CHAIN_HOPS) {
        if let Some(p) = spki_of(c) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    for p in extra {
        if !out.contains(p) {
            out.push(p.clone());
        }
    }
    out
}

fn pin_error(presented: Vec<String>, reason: Option<&str>) -> UpstreamError {
    UpstreamError {
        code: "AV_PIN_MISMATCH".into(),
        message: "certificate pin mismatch".into(),
        reason: reason.map(str::to_string),
        presented,
        vault: None,
    }
}

/// `pinVerdict(socket, hostname, pinList)`: `None` to send.
fn verdict(chain: &[Vec<u8>], name: &ServerName<'_>, pins: Option<&[String]>) -> Option<UpstreamError> {
    let check = check_chain(chain, name, trust_anchors());
    let Some(pins) = pins else {
        return check.authorized.err().map(|code| UpstreamError::new(&code, format!("upstream certificate not trusted: {code}")));
    };
    if check.authorized.is_ok() {
        if check.verified.iter().any(|p| pins.contains(p)) {
            return None;
        }
        return Some(pin_error(chain_pins(chain, &check.verified), None));
    }
    let leaf = chain.first()?;
    let leaf_pin = spki_of(leaf);
    let leaf_pinned = leaf_pin.as_ref().is_some_and(|p| pins.contains(p));
    if !leaf_pinned {
        let code = check.authorized.err().unwrap_or_else(|| "UNABLE_TO_VERIFY_LEAF_SIGNATURE".into());
        return Some(UpstreamError::new(&code, format!("upstream certificate not trusted: {code}")));
    }
    let leaf_der = CertificateDer::from(leaf.as_slice());
    let named = webpki::EndEntityCert::try_from(&leaf_der).map_err(|e| node_code(&e, chain)).and_then(|ee| ee.verify_is_valid_for_subject_name(name).map_err(|e| node_code(&e, chain)));
    if let Err(code) = named {
        return Some(UpstreamError::new(&code, format!("upstream certificate does not name the host: {code}")));
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let validity = x509_parser::parse_x509_certificate(leaf).ok().map(|(_, c)| (c.validity().not_before.timestamp(), c.validity().not_after.timestamp()));
    match validity {
        Some((_, not_after)) if now > not_after => Some(pin_error(chain_pins(chain, &[]), Some("leaf_expired"))),
        Some((not_before, _)) if now < not_before => Some(pin_error(chain_pins(chain, &[]), Some("leaf_not_yet_valid"))),
        None => Some(pin_error(chain_pins(chain, &[]), Some("leaf_expired"))),
        _ => None,
    }
}

/// The URL host a certificate names: no IPv6 brackets.
fn identity_of(url: &url::Url) -> String {
    av_core::pins::url_identity(url)
}

fn io_code(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => "ECONNREFUSED",
        K::ConnectionReset => "ECONNRESET",
        K::TimedOut => "ETIMEDOUT",
        K::AddrNotAvailable => "EADDRNOTAVAIL",
        K::HostUnreachable => "EHOSTUNREACH",
        K::NetworkUnreachable => "ENETUNREACH",
        K::BrokenPipe => "EPIPE",
        _ => "ECONNRESET",
    }
}

/// The default upstream: `pinnedRequest`. Redirects are never followed.
#[derive(Debug, Default, Clone)]
pub struct PinnedUpstream;

impl Upstream for PinnedUpstream {
    fn send(&self, req: UpstreamRequest) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(pinned_request(req))
    }
}

/// `pinnedRequest({ url, method, headers, body, pins })`.
pub async fn pinned_request(req: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
    let url = url::Url::parse(&req.url).map_err(|_| UpstreamError::new("ERR_INVALID_URL", "Invalid URL"))?;
    // The caller's headers, read once.
    let mut sent: Vec<(String, String)> = Vec::new();
    for (n, v) in &req.headers {
        if sent.iter().any(|(k, _)| k == n) {
            return Err(UpstreamError { vault: Some(dr(C::PolicyDenied, "headers must be names with string values, each read once", "header_format")), ..Default::default() });
        }
        sent.push((n.clone(), v.clone()));
    }
    let identity = identity_of(&url);
    if !sent.iter().filter(|(n, _)| n.eq_ignore_ascii_case("host")).all(|(_, v)| host_header_matches(v, &url)) {
        return Err(UpstreamError { vault: Some(dr(C::PolicyDenied, "the Host header names a different host than the URL", "host_mismatch")), ..Default::default() });
    }
    let state = pin_list_state(Some(&req.pins.as_value()));
    if state == PinListState::Invalid {
        return Err(pin_error(Vec::new(), Some("pin_format")));
    }
    let pin_list: Option<Vec<String>> = (state == PinListState::Pinned).then(|| match &req.pins {
        Pins::List(v) => v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    });
    let https = url.scheme() == "https";
    if pin_list.is_some() && !https {
        return Err(pin_error(Vec::new(), Some("plaintext")));
    }
    let port = url.port_or_known_default().unwrap_or(if https { 443 } else { 80 });
    let timeout = Duration::from_millis(UPSTREAM_TIMEOUT_MS);

    let connect = async {
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((identity.as_str(), port))
            .await
            .map_err(|_| UpstreamError::new("ENOTFOUND", format!("getaddrinfo ENOTFOUND {identity}")))?
            .collect();
        if addrs.is_empty() {
            return Err(UpstreamError::new("ENOTFOUND", format!("getaddrinfo ENOTFOUND {identity}")));
        }
        let mut last = None;
        for a in &addrs {
            match tokio::net::TcpStream::connect(a).await {
                Ok(s) => return Ok(s),
                Err(e) => last = Some((e, *a)),
            }
        }
        let (e, a) = last.expect("an address");
        let code = io_code(&e);
        Err(UpstreamError::new(code, format!("connect {code} {a}")))
    };
    let tcp = tokio::time::timeout(timeout, connect).await.map_err(|_| UpstreamError::new("", "upstream timeout"))??;
    let _ = tcp.set_nodelay(true);

    let path = format!("{}{}", url.path(), url.query().map(|q| format!("?{q}")).unwrap_or_default());
    if https {
        let recorder = Arc::new(Recorder { seen: Mutex::new(Seen::default()), algs: provider().signature_verification_algorithms });
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| UpstreamError::new("ERR_SSL", e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(recorder.clone())
            .with_no_client_auth();
        let name: ServerName<'static> = match identity.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(identity.clone()).map_err(|_| UpstreamError::new("ERR_INVALID_URL", "Invalid URL"))?,
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tls = tokio::time::timeout(timeout, connector.connect(name.clone(), tcp))
            .await
            .map_err(|_| UpstreamError::new("", "upstream timeout"))?
            .map_err(|e| UpstreamError::new("ECONNRESET", format!("Client network socket disconnected before secure TLS connection was established: {e}")))?;
        let chain = recorder.seen.lock().unwrap_or_else(|p| p.into_inner()).chain.clone();
        // The decision, before a byte of the request is written.
        if let Some(err) = verdict(&chain, &name, pin_list.as_deref()) {
            drop(tls);
            return Err(err);
        }
        exchange(tls, &req.method, &path, &sent, req.body, &url).await
    } else {
        exchange(tcp, &req.method, &path, &sent, req.body, &url).await
    }
}

async fn exchange<S>(io: S, method: &str, path: &str, headers: &[(String, String)], body: Option<Vec<u8>>, url: &url::Url) -> Result<UpstreamResponse, UpstreamError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let timeout = Duration::from_millis(UPSTREAM_TIMEOUT_MS);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake::<_, http_body_util::Full<hyper::body::Bytes>>(hyper_util::rt::TokioIo::new(io))
        .await
        .map_err(|e| UpstreamError::new("ECONNRESET", e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut b = hyper::Request::builder().method(method).uri(if path.is_empty() { "/" } else { path });
    let mut has_host = false;
    for (n, v) in headers {
        if n.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        b = b.header(n.as_str(), hyper::header::HeaderValue::from_bytes(&crate::util::latin1_bytes(v)).map_err(|_| UpstreamError {
            vault: Some(dr(C::PolicyDenied, "headers must be names with string values, each read once", "header_format")),
            ..Default::default()
        })?);
    }
    if !has_host {
        let h = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or("")),
            None => url.host_str().unwrap_or("").to_string(),
        };
        b = b.header("host", h);
    }
    let request = b
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body.unwrap_or_default())))
        .map_err(|e| UpstreamError::new("ERR_INVALID_HTTP_TOKEN", e.to_string()))?;
    let res = tokio::time::timeout(timeout, sender.send_request(request))
        .await
        .map_err(|_| UpstreamError::new("", "upstream timeout"))?
        .map_err(|e| UpstreamError::new("ECONNRESET", format!("socket hang up: {e}")))?;
    let status = res.status().as_u16();
    let headers = crate::util::node_headers(res.headers());
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, String>>(16);
    let mut body = res.into_body();
    tokio::spawn(async move {
        loop {
            match tokio::time::timeout(timeout, body.frame()).await {
                Err(_) => {
                    let _ = tx.send(Err("upstream timeout".into())).await;
                    return;
                }
                Ok(None) => return,
                Ok(Some(Err(e))) => {
                    let _ = tx.send(Err(e.to_string())).await;
                    return;
                }
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        if tx.send(Ok(data.to_vec())).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });
    Ok(UpstreamResponse { status, headers, body: Body::Stream(rx) })
}

/// One certificate as `fetchChainPins` describes it.
pub fn describe_cert(der: &[u8]) -> Option<Value> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    let not_after = c.validity().not_after.timestamp();
    Some(serde_json::json!({
        "subject": c.subject().to_string(),
        "issuer": c.issuer().to_string(),
        "spki": spki_pin(c.tbs_certificate.subject_pki.raw),
        "not_after": crate::util::iso_of_ms(not_after * 1000),
    }))
}

/// The certificates a host presents, for the human to read before pinning.
/// Sends no credential and no HTTP request. Ports `fetchChainPins(host, port)`.
pub async fn fetch_chain_pins(host: &str, port: u16) -> Result<Vec<Value>, UpstreamError> {
    let timeout = Duration::from_millis(UPSTREAM_TIMEOUT_MS);
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect((bare.as_str(), port)))
        .await
        .map_err(|_| UpstreamError::new("", "upstream timeout"))?
        .map_err(|e| UpstreamError::new(io_code(&e), e.to_string()))?;
    let recorder = Arc::new(Recorder { seen: Mutex::new(Seen::default()), algs: provider().signature_verification_algorithms });
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| UpstreamError::new("ERR_SSL", e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let name: ServerName<'static> = match bare.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(bare.clone()).map_err(|_| UpstreamError::new("ERR_INVALID_URL", "Invalid host"))?,
    };
    let tls = tokio::time::timeout(timeout, tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp))
        .await
        .map_err(|_| UpstreamError::new("", "upstream timeout"))?
        .map_err(|e| UpstreamError::new("ECONNRESET", e.to_string()))?;
    drop(tls);
    let chain = recorder.seen.lock().unwrap_or_else(|p| p.into_inner()).chain.clone();
    Ok(chain.iter().take(CHAIN_HOPS).filter_map(|c| describe_cert(c)).collect())
}
