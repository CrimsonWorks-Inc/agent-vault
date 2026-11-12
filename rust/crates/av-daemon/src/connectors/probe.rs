//! F12: a credential's read-only probe. Ports `src/connectors/probe.js`,
//! together with the error mapping `Daemon.#probe` applies to its refusals.
//!
//! The probe sends the profile's own method and path, nothing a caller
//! chose, with the secret in the first header site the credential declares,
//! through the same pinned request the gateway uses. Once a minute per
//! credential. Everything it returns is scrubbed of the secret it held.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use av_core::errors::VaultError;
use av_core::scrub::{ScrubEntry, Scrubber, ScrubberOptions};
use av_core::secret::{ExposeSecret, SecretString};
use av_store::model::CredentialRecord;
use serde_json::{json, Value};

use crate::err::{d, dr, DenyExt, C};
use crate::state::{StoreResult, VaultRef};
use crate::upstream::{Body, Pins, Upstream, UpstreamRequest};
use crate::util::{iso_now, now_ms};

/// One probe per credential per this long. Ports `PROBE_WINDOW_MS`.
pub const PROBE_WINDOW_MS: u64 = 60_000;
/// Most of a probe's answer drained. Ports `DRAIN_LIMIT_BYTES`.
pub const DRAIN_LIMIT_BYTES: usize = 64 * 1024;
/// Longest drain. Ports `DRAIN_TIMEOUT_MS`.
pub const DRAIN_TIMEOUT_MS: u64 = 2_000;

fn clock() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1_000_000
}

fn probe_at() -> &'static Mutex<HashMap<String, u64>> {
    static AT: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    AT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Forget the throttle (tests).
pub fn reset_probe_throttle() {
    probe_at().lock().unwrap_or_else(|p| p.into_inner()).clear();
}

/// `takeProbeSlot(credId, now)`.
fn take_slot(cred_id: &str, now: u64) -> Result<(), VaultError> {
    let mut at = probe_at().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(prev) = at.get(cred_id) {
        if now.saturating_sub(*prev) < PROBE_WINDOW_MS {
            let elapsed = now.saturating_sub(*prev);
            let retry = ((PROBE_WINDOW_MS - elapsed) as f64 / 1000.0).ceil() as u64;
            return Err(dr(C::QuotaExceeded, "this credential was already probed in the last minute", "probe_throttle").retry(if retry > 0 { retry } else { 60 }));
        }
    }
    at.insert(cred_id.to_string(), now);
    Ok(())
}

fn classify(status: Option<u16>) -> &'static str {
    match status {
        None => "error",
        Some(s) if (200..300).contains(&s) => "ok",
        Some(401) => "unauthorized",
        Some(403) => "forbidden",
        _ => "error",
    }
}

fn is_probe_path(p: &str) -> bool {
    p.starts_with('/') && !p.contains("://") && !p.chars().any(|c| c.is_whitespace() || "?#\\".contains(c))
}

/// `splitHostPort(raw)` / `usable` / `isHost`.
fn split_host_port(raw: &str) -> Option<(String, Option<u16>)> {
    let s = raw.trim().to_lowercase();
    if s.is_empty() || s.chars().any(|c| c.is_whitespace() || "/\\?#@".contains(c)) {
        return None;
    }
    let usable = |host: String, port: Option<u64>| -> Option<(String, Option<u16>)> {
        if !is_host(&host) {
            return None;
        }
        match port {
            Some(p) if !(1..=65535).contains(&p) => None,
            Some(p) => Some((host, Some(p as u16))),
            None => Some((host, None)),
        }
    };
    if s.starts_with('[') {
        let end = s.find(']')?;
        if end < 2 {
            return None;
        }
        let host = s[..=end].to_string();
        let rest = &s[end + 1..];
        if rest.is_empty() {
            return usable(host, None);
        }
        let port = rest.strip_prefix(':').filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))?;
        return usable(host, port.parse().ok());
    }
    match s.rfind(':') {
        None => usable(s.trim_end_matches('.').to_string(), None),
        Some(colon) => {
            let host = s[..colon].trim_end_matches('.').to_string();
            let p = &s[colon + 1..];
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            usable(host, Some(p.parse().unwrap_or(0)))
        }
    }
}

fn is_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else { return false };
        return inner.contains(':') && inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    }
    if host.starts_with(|c: char| c.is_ascii_digit()) {
        let parts: Vec<&str> = host.split('.').collect();
        return parts.len() == 4
            && parts.iter().all(|p| (*p == "0" || (!p.starts_with('0') && !p.is_empty() && p.len() <= 3)) && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().is_ok_and(|n| n <= 255));
    }
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|l| {
        let b = l.as_bytes();
        !b.is_empty() && b.len() <= 63 && b[0].is_ascii_alphanumeric() && b[b.len() - 1].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    })
}

fn scrub_text(text: &str, scrubber: &mut Scrubber) -> String {
    let out = scrubber.scrub(text).text;
    let ph = av_core::jsre::compile(av_core::placeholder::SCANNER_PATTERN).expect("scanner");
    let out = ph.replace_all(&out, "[[av:redacted]]").into_owned();
    let tok = av_core::jsre::compile(r"avs1\.[0-9a-z]{12}\.[A-Za-z0-9_-]{20,}").expect("token");
    tok.replace_all(&out, "[[av:redacted]]").into_owned()
}

/// What the lock half returns: the request, its scrubber, the cred id.
struct Prepared {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    pins: Pins,
    cred_id: String,
    scrubber_secret: SecretString,
    slug: String,
    kind: String,
}

fn prepare(cred: &CredentialRecord, secret_of: impl FnOnce(&str, &str) -> Result<SecretString, VaultError>) -> Result<Prepared, VaultError> {
    let profile = av_core::profiles::get_profile(&cred.connector_kind).ok();
    let probe = profile.and_then(|p| p.probe).filter(|p| !p.method.is_empty() && is_probe_path(p.path));
    let Some(probe) = probe else {
        return Err(dr(C::NotFound, "this connector has no probe", "no_probe").hinted("This kind has no fixed read-only probe. Use vault_http on a path you know."));
    };
    // probeDestination
    let declared = cred
        .connector
        .get("host")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| profile.and_then(|p| p.hosts.first()).map(|s| s.to_string()));
    let credential_host = || dr(C::PolicyDenied, "host is outside what this credential permits", "credential_host");
    let Some(declared) = declared.filter(|d| !d.trim().is_empty()) else {
        return Err(dr(C::PolicyDenied, "this credential declares no host it may reach", "credential_host"));
    };
    let (raw_host, port) = split_host_port(&declared).ok_or_else(credential_host)?;
    let host = av_core::policy::host_only(&raw_host);
    let hosts: Vec<String> = profile.map(|p| p.hosts.iter().map(|s| s.to_string()).collect()).unwrap_or_default();
    let ceiling = av_core::policy::credential_host_ceiling(cred.connector.get("host").and_then(Value::as_str), &hosts);
    if host.is_empty() || !ceiling.iter().any(|e| av_core::policy::match_host(e, &host)) {
        return Err(credential_host());
    }
    let scheme = cred.connector.get("scheme").and_then(Value::as_str).unwrap_or("https").to_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(credential_host());
    }
    let authority = match port {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    // firstHeaderSite
    let mut header = None;
    'f: for f in &cred.fields {
        for spec in &f.sites {
            if let Ok(site) = av_core::sites::parse_site(spec) {
                if site.kind == av_core::sites::SiteKind::Header {
                    header = Some((f.name.clone(), site));
                    break 'f;
                }
            }
        }
    }
    let Some((field, site)) = header else {
        return Err(dr(C::NotFound, "this credential has no header site a probe can authenticate with", "no_probe")
            .hinted("A probe sends the secret only in a header site declared on the credential."));
    };
    let url = format!("{scheme}://{authority}{}", probe.path);
    let pins = url::Url::parse(&url)
        .map(|u| {
            let table = serde_json::to_value(&cred.pins).ok().filter(|t| t.as_object().is_some_and(|m| !m.is_empty()));
            Pins::from_lookup(av_core::pins::pins_for(table.as_ref(), &av_core::pins::url_identity(&u)))
        })
        .unwrap_or(Pins::None);
    if av_core::pins::pin_list_state(Some(&pins.as_value())) == av_core::pins::PinListState::Invalid {
        return Err(dr(C::PinMismatch, "certificate pin mismatch", "pin_format"));
    }
    take_slot(&cred.id, clock())?;
    let secret = secret_of(&cred.id, &field)?;
    let name = site.name.clone().unwrap_or_default();
    let value = match &site.scheme {
        Some(s) => format!("{s} {}", secret.expose_secret()),
        None => secret.expose_secret().to_string(),
    };
    let mut headers = vec![(name, value)];
    let mut body = None;
    if probe.method == "POST" {
        headers.push(("content-type".into(), "application/x-www-form-urlencoded".into()));
        body = Some(Vec::new());
    }
    Ok(Prepared {
        url,
        method: probe.method.to_string(),
        headers,
        body,
        pins,
        cred_id: cred.id.clone(),
        scrubber_secret: secret,
        slug: cred.slug.clone(),
        kind: cred.connector_kind.clone(),
    })
}

/// Run a credential's probe. Ports `runProbe` plus `Daemon.#probe`'s
/// mapping of its refusals and the `cred.tested` record.
pub async fn run_probe(shared: &VaultRef, slug: String, upstream: Option<Arc<dyn Upstream>>) -> Result<Value, VaultError> {
    let p = shared
        .run(move |core| -> Result<Prepared, VaultError> {
            let cred = core.vault.find_credential(&slug).v()?.ok_or_else(|| d(C::NotFound, format!("no credential {slug}")))?;
            if cred.quarantine.is_some() {
                return Err(crate::server::quarantined(&cred.slug));
            }
            prepare(&cred, |id, field| core.vault.reveal_field(id, field).v())
        })
        .await??;
    let mut scrubber = Scrubber::new(
        &[ScrubEntry { secret: p.scrubber_secret.clone(), label: if p.slug.is_empty() { "cred".into() } else { p.slug.clone() }, replacement: None, always: true }],
        &ScrubberOptions::default(),
    )?;
    let send: Arc<dyn Upstream> = upstream.unwrap_or_else(|| Arc::new(crate::connectors::pinning::PinnedUpstream));
    let started = now_ms();
    let sent = send
        .send(UpstreamRequest { url: p.url.clone(), method: p.method.clone(), headers: p.headers.clone(), body: p.body.clone(), pins: p.pins.clone() })
        .await;
    let (status, http_status, health, answered) = match sent {
        Err(e) if e.code == "AV_PIN_MISMATCH" => {
            finish(shared, &p, "error", None, None, started, None).await?;
            let rule = match e.reason.as_deref() {
                Some("plaintext") => "pin_plaintext",
                Some("pin_format") => "pin_format",
                _ => "spki_pin",
            };
            return Err(dr(C::PinMismatch, scrub_text(&e.message, &mut scrubber), rule));
        }
        Err(e) if e.vault.is_some() => {
            let v = e.vault.expect("vault");
            let mut out = d(v.code, scrub_text(&v.detail, &mut scrubber));
            out.extra.rule = v.extra.rule.clone();
            if let Some(h) = &v.extra.hint {
                out.extra.hint = Some(scrub_text(h, &mut scrubber));
            }
            out.extra.retry_after = v.extra.retry_after;
            return Err(out);
        }
        Err(_) => ("unreachable", None, None, None),
        Ok(res) => {
            let answered = now_ms();
            let health = av_core::profiles::get_profile(&p.kind).ok().and_then(|pr| av_core::profiles::extract_health(Some(pr), &res.headers));
            if let Body::Stream(mut rx) = res.body {
                let drain = async {
                    let mut n = 0usize;
                    while let Some(Ok(c)) = rx.recv().await {
                        n += c.len();
                        if n > DRAIN_LIMIT_BYTES {
                            break;
                        }
                    }
                };
                let _ = tokio::time::timeout(std::time::Duration::from_millis(DRAIN_TIMEOUT_MS), drain).await;
            }
            (classify(Some(res.status)), Some(res.status), health, Some(answered))
        }
    };
    let health_v = health.map(|h| serde_json::to_value(h).unwrap_or(Value::Null));
    let scopes = health_v
        .as_ref()
        .and_then(|h| h.get("scopes"))
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .map(|a| Value::Array(a.iter().map(|x| Value::from(scrub_text(&crate::util::js_string(x), &mut scrubber))).collect()))
        .unwrap_or(Value::Null);
    let observed = health_v
        .as_ref()
        .and_then(|h| h.get("observed_expires_at"))
        .and_then(Value::as_str)
        .map(|s| Value::from(scrub_text(s, &mut scrubber)))
        .unwrap_or(Value::Null);
    let ratelimit = health_v.as_ref().and_then(|h| h.get("ratelimit_remaining")).filter(|v| v.is_u64()).cloned().unwrap_or(Value::Null);
    finish(shared, &p, status, http_status, Some((scopes, observed, ratelimit)), started, answered).await
}

async fn finish(shared: &VaultRef, p: &Prepared, status: &str, http_status: Option<u16>, extracted: Option<(Value, Value, Value)>, started: i64, answered: Option<i64>) -> Result<Value, VaultError> {
    let (scopes, observed, ratelimit) = extracted.unwrap_or((Value::Null, Value::Null, Value::Null));
    let checked_at = iso_now();
    let latency = (answered.unwrap_or_else(now_ms) - started).max(0);
    let patch = json!({"status": status, "http_status": http_status, "checked_at": checked_at, "source": "probe", "observed_expires_at": observed, "scopes": scopes});
    let (id, slug) = (p.cred_id.clone(), p.slug.clone());
    let result = json!({
        "ok": status == "ok", "status": status, "http_status": http_status, "latency_ms": latency,
        "scopes": scopes, "ratelimit_remaining": ratelimit, "observed_expires_at": observed, "checked_at": checked_at,
    });
    let out = result.clone();
    let record = status != "error" || http_status.is_some() || answered.is_some();
    let _ = record;
    shared
        .run(move |core| -> Result<(), VaultError> {
            core.vault.record_health(&id, &patch).v()?;
            Ok(())
        })
        .await??;
    if status == "error" && http_status.is_none() && answered.is_none() {
        // A pin refusal: the caller throws; `cred.tested` is not written.
        return Ok(out);
    }
    shared
        .run(move |core| core.audit("cred.tested", json!({"credential_slug": slug, "status": result["status"], "http_status": result["http_status"], "latency_ms": result["latency_ms"]})))
        .await??;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_grammar() {
        assert_eq!(split_host_port("api.github.com"), Some(("api.github.com".into(), None)));
        assert_eq!(split_host_port("API.example.com.:8443"), Some(("api.example.com".into(), Some(8443))));
        assert_eq!(split_host_port("[::1]:9"), Some(("[::1]".into(), Some(9))));
        assert!(split_host_port("a b").is_none());
        assert!(split_host_port("user@host").is_none());
        assert!(split_host_port("256.1.1.1").is_none());
        assert!(split_host_port("host:0").is_none());
    }

    #[test]
    fn throttle_is_once_a_minute() {
        take_slot("cr_test_throttle", 10_000_000).unwrap();
        let e = take_slot("cr_test_throttle", 10_000_500).unwrap_err();
        assert_eq!(e.code, C::QuotaExceeded);
        assert_eq!(e.extra.retry_after, Some(60));
        take_slot("cr_test_throttle", 10_060_000).unwrap();
    }
}
