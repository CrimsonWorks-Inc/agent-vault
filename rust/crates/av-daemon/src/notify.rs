//! The "something is waiting" signal: the SSE stream the CLI's `watch` reads
//! and the optional webhook. Ports `src/daemon/notify.js`.
//!
//! `redactStored`, which the JS re-exports from here, lives in
//! `av_core::scrub` and is not re-declared.

use std::sync::{Arc, Mutex, Weak};

use av_core::errors::VaultError;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::err::{d, dr, DenyExt, C};
use crate::state::{Core, Shared};
use crate::upstream::BoxFuture;
use crate::util::{js_stringify, now_ms};

/// Stream subscribers held at once. Ports `MAX_SUBSCRIBERS`.
pub const MAX_SUBSCRIBERS: usize = 8;
/// SSE keep-alive comment interval. Ports `KEEPALIVE_MS`.
pub const KEEPALIVE_MS: u64 = 15_000;
/// Least time between webhook posts. Ports `WEBHOOK_INTERVAL_MS`.
pub const WEBHOOK_INTERVAL_MS: u64 = 30_000;
/// Least time between `notify test` posts. Ports `TEST_INTERVAL_MS`.
pub const TEST_INTERVAL_MS: u64 = 30_000;
/// Least time between audit records of webhook failures. Ports `FAILURE_RECORD_MS`.
pub const FAILURE_RECORD_MS: u64 = 5 * 60_000;
/// Webhook request timeout. Ports `WEBHOOK_TIMEOUT_MS`.
pub const WEBHOOK_TIMEOUT_MS: u64 = 5_000;
/// Largest webhook body. Ports `MAX_PAYLOAD_BYTES`.
pub const MAX_PAYLOAD_BYTES: usize = 2048;
/// Most item ids in one webhook body. Ports `MAX_IDS`.
pub const MAX_IDS: usize = 10;
/// Longest headline sent. Ports `MAX_HEADLINE`.
pub const MAX_HEADLINE: usize = 200;
/// Item kinds the stream carries. Ports `KINDS`.
pub const KINDS: [&str; 2] = ["request", "session"];

/// `cleanHeadline(text)`.
pub fn clean_headline(text: &str) -> String {
    let mut s = text.to_string();
    for hit in av_core::placeholder::find_all(text).into_iter().rev() {
        s = format!("{}«placeholder»{}", &s[..hit.offset], &s[hit.end..]);
    }
    let s: String = s
        .chars()
        .filter_map(|c| match c as u32 {
            0x00..=0x1f | 0x7f..=0x9f | 0x2028 | 0x2029 => Some(' '),
            0x202a..=0x202e | 0x2066..=0x2069 => None,
            _ => Some(c),
        })
        .collect();
    let units: Vec<u16> = s.encode_utf16().collect();
    if units.len() > MAX_HEADLINE {
        format!("{}…", String::from_utf16_lossy(&units[..MAX_HEADLINE - 1]))
    } else {
        s
    }
}

fn is_item(e: &Value) -> bool {
    e.get("kind")
        .and_then(Value::as_str)
        .is_some_and(|k| KINDS.contains(&k))
        && e.get("id")
            .and_then(Value::as_str)
            .is_some_and(|i| !i.is_empty())
}

fn cut16(s: &str, n: usize) -> String {
    let u: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&u)
}

/// `itemOf(event, secrets)`.
fn item_of(e: &Value, secrets: Option<&[av_core::scrub::StoredSecret]>) -> Option<Value> {
    if !is_item(e) {
        return None;
    }
    let headline = match secrets {
        Some(s) => clean_headline(&av_core::scrub::redact_stored(
            e.get("headline").and_then(Value::as_str).unwrap_or(""),
            s,
        )),
        None => String::new(),
    };
    Some(json!({
        "kind": e["kind"],
        "id": cut16(e["id"].as_str().unwrap_or(""), 64),
        "headline": headline,
        "created_at": e.get("created_at").and_then(Value::as_str).map(|c| cut16(c, 40)),
    }))
}

/// `webhookPayload(items, detail, { event })`: the JSON text.
pub fn webhook_payload(items: &[Value], detail: &str, event: &str) -> String {
    let mut kinds = json!({"request": 0, "session": 0});
    for i in items {
        if let Some(k) = i["kind"].as_str() {
            kinds[k] = json!(kinds[k].as_u64().unwrap_or(0) + 1);
        }
    }
    let mut newest = items.to_vec();
    newest.sort_by(|a, b| {
        let s = |v: &Value| crate::util::js_string(&v["created_at"]);
        s(b).encode_utf16().cmp(s(a).encode_utf16())
    });
    newest.truncate(MAX_IDS);
    let mut ids: Vec<Value> = newest.iter().map(|i| i["id"].clone()).collect();
    let mut its: Option<Vec<Value>> = (detail == "headline").then(|| {
        newest
            .iter()
            .map(|i| json!({"kind": i["kind"], "id": i["id"], "headline": i["headline"]}))
            .collect()
    });
    let body = |ids: &[Value], its: &Option<Vec<Value>>| {
        let mut b = json!({
            "source": "agent-vault", "event": event, "waiting": items.len(), "kinds": kinds,
            "ids": ids, "open": "agent-vault approvals",
        });
        if let Some(x) = its {
            b["items"] = Value::Array(x.clone());
        }
        js_stringify(&b)
    };
    let mut text = body(&ids, &its);
    while text.len() > MAX_PAYLOAD_BYTES
        && (its.as_ref().is_some_and(|x| !x.is_empty()) || !ids.is_empty())
    {
        if let Some(x) = its.as_mut().filter(|x| !x.is_empty()) {
            x.pop();
        } else {
            ids.pop();
        }
        text = body(&ids, &its);
    }
    text
}

/// The webhook sender: `(url, body) → status`, or an error code. Ports
/// `defaultSend` / the `fetchImpl` option.
pub type Sender =
    Arc<dyn Fn(String, String) -> BoxFuture<'static, Result<u16, String>> + Send + Sync>;

/// Options for [`Notifier::new`]. Ports `{ fetchImpl }`.
#[derive(Default, Clone)]
pub struct NotifierOptions {
    /// Replaces the network.
    pub send: Option<Sender>,
}

#[derive(Default)]
struct Inner {
    subscribers: Vec<mpsc::UnboundedSender<String>>,
    last_sent: i64,
    last_test: i64,
    last_failure_recorded: i64,
    timer: bool,
    closed: bool,
}

/// A webhook POST whose interval slot is already taken.
struct Pending {
    url: String,
    host: String,
    body: String,
    count: usize,
}

/// The pending-item notifier. Ports `class Notifier`.
pub struct Notifier {
    inner: Mutex<Inner>,
    shared: Mutex<Weak<Shared>>,
    send: Sender,
}

fn secrets_of(core: &Core) -> Option<Vec<av_core::scrub::StoredSecret>> {
    core.vault.all_secrets().ok().map(|v| {
        v.into_iter()
            .map(|s| av_core::scrub::StoredSecret {
                secret: s.secret,
                label: s.label,
            })
            .collect()
    })
}

impl Notifier {
    /// Ports `new Notifier(vault, opts)`.
    pub fn new(opts: NotifierOptions) -> Arc<Notifier> {
        Arc::new(Notifier {
            inner: Mutex::new(Inner::default()),
            shared: Mutex::new(Weak::new()),
            send: opts.send.unwrap_or_else(default_sender),
        })
    }

    /// Bind to the daemon's state (for the webhook, which reads the vault).
    pub fn bind(&self, shared: &Arc<Shared>) {
        *self.shared.lock().unwrap_or_else(|p| p.into_inner()) = Arc::downgrade(shared);
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `#waiting()`: what is waiting now, cleaned.
    pub fn waiting(core: &mut Core) -> Vec<Value> {
        let rows = core.dm_waiting_items();
        let secrets = if rows.is_empty() {
            None
        } else {
            secrets_of(core)
        };
        rows.iter()
            .filter_map(|r| item_of(r, secrets.as_deref()))
            .collect()
    }

    /// `Notifier.pending(event)`: tell every subscriber, schedule the
    /// webhook. Called under the lock; never fails.
    pub fn pending(self: &Arc<Self>, core: &mut Core, event: &Value) {
        if self.inner().closed || !is_item(event) {
            return;
        }
        let has_subs = !self.inner().subscribers.is_empty();
        if has_subs {
            let secrets = secrets_of(core);
            let frame = format!(
                "event: pending\ndata: {}\n\n",
                js_stringify(&item_of(event, secrets.as_deref()).unwrap_or(Value::Null))
            );
            self.inner()
                .subscribers
                .retain(|s| s.send(frame.clone()).is_ok());
        }
        self.schedule(core);
    }

    /// `#scheduleWebhook()`: at most one POST per interval. Runs under the
    /// lock, so the slot is taken before the next event can look at it.
    fn schedule(self: &Arc<Self>, core: &mut Core) {
        let configured = core.vault.notify_config().ok().flatten().is_some();
        let wait = {
            let mut i = self.inner();
            if i.timer || !configured {
                return;
            }
            let wait = (i.last_sent + WEBHOOK_INTERVAL_MS as i64 - now_ms()).max(0);
            if wait > 0 {
                i.timer = true;
            }
            wait
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            if wait > 0 {
                self.inner().timer = false;
            }
            return;
        };
        let me = Arc::clone(self);
        if wait == 0 {
            if let Some(send) = self.take_slot(core) {
                rt.spawn(async move { me.send_webhook(send).await });
            }
            return;
        }
        rt.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(wait as u64)).await;
            let Some(shared) = me
                .shared
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .upgrade()
            else {
                me.inner().timer = false;
                return;
            };
            let m2 = Arc::clone(&me);
            let send = shared
                .run(move |core| {
                    m2.inner().timer = false;
                    m2.take_slot(core)
                })
                .await
                .ok()
                .flatten();
            if let Some(send) = send {
                me.send_webhook(send).await;
            }
        });
    }

    /// The synchronous half of `#sendWebhook()`: the hook and what is
    /// waiting, with `lastSent` reserved at once. Runs under the lock.
    fn take_slot(&self, core: &mut Core) -> Option<Pending> {
        let (url, host, detail) = webhook_of(core)?;
        if self.inner().closed {
            return None;
        }
        let items = Notifier::waiting(core);
        if items.is_empty() {
            return None;
        }
        self.inner().last_sent = now_ms();
        Some(Pending {
            url,
            host,
            body: webhook_payload(&items, &detail, "pending"),
            count: items.len(),
        })
    }

    async fn send_webhook(self: &Arc<Self>, p: Pending) {
        let Some(shared) = self
            .shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .upgrade()
        else {
            return;
        };
        let _ = self.post(&shared, p.url, p.host, p.body, p.count).await;
    }

    async fn post(
        self: &Arc<Self>,
        shared: &Arc<Shared>,
        url: String,
        host: String,
        body: String,
        count: usize,
    ) -> Value {
        let res = (self.send)(url, body).await;
        match res {
            Ok(status) if (200..300).contains(&status) => {
                let h = host.clone();
                let _ = shared
                    .run(move |core| {
                        record(core, "notify.sent", json!({"host": h, "items": count}))
                    })
                    .await;
                json!({"sent": true, "status": status})
            }
            Ok(status) => {
                self.failed(shared, host, format!("status_{status}")).await;
                json!({"sent": false, "status": status})
            }
            Err(code) => {
                let ok = code.starts_with('E')
                    && code.len() <= 40
                    && code.len() >= 2
                    && code[1..]
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
                let reason = if ok { code } else { "error".into() };
                self.failed(shared, host, reason.clone()).await;
                json!({"sent": false, "error": reason})
            }
        }
    }

    async fn failed(self: &Arc<Self>, shared: &Arc<Shared>, host: String, reason: String) {
        {
            let mut i = self.inner();
            let now = now_ms();
            if now - i.last_failure_recorded < FAILURE_RECORD_MS as i64 {
                return;
            }
            i.last_failure_recorded = now;
        }
        let _ = shared
            .run(move |core| {
                record(
                    core,
                    "notify.failed",
                    json!({"host": host, "reason": reason}),
                )
            })
            .await;
    }

    /// `Notifier.subscribe(res)`: the receiver yields SSE frames, snapshot
    /// first, with a keep-alive comment every [`KEEPALIVE_MS`].
    pub fn subscribe(
        &self,
        snapshot: Vec<Value>,
    ) -> Result<mpsc::UnboundedReceiver<String>, VaultError> {
        let mut i = self.inner();
        if i.closed {
            return Err(d(C::NotFound, "the daemon is stopping"));
        }
        i.subscribers.retain(|s| !s.is_closed());
        if i.subscribers.len() >= MAX_SUBSCRIBERS {
            return Err(dr(
                C::QuotaExceeded,
                format!("at most {MAX_SUBSCRIBERS} watchers at once"),
                "stream_limit",
            )
            .retry(30));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = tx.send(format!(
            "event: snapshot\ndata: {}\n\n",
            js_stringify(&json!({"items": snapshot}))
        ));
        i.subscribers.push(tx.clone());
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(KEEPALIVE_MS)).await;
                    if tx.send(": ping\n\n".into()).is_err() {
                        return;
                    }
                }
            });
        }
        Ok(rx)
    }

    /// Whether a later item waits for the next slot (`notifier.timer`).
    #[cfg(test)]
    pub(crate) fn timer_set(&self) -> bool {
        self.inner().timer
    }

    /// `Notifier.test()`.
    pub async fn test(self: &Arc<Self>) -> Result<Value, VaultError> {
        let Some(shared) = self
            .shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .upgrade()
        else {
            return Err(d(C::NotFound, "no webhook is configured"));
        };
        let (hook, items) = shared
            .run(|core| {
                if core.vault.locked() {
                    return Err(d(C::Locked, "unlock the vault to use the webhook"));
                }
                let hook =
                    webhook_of(core).ok_or_else(|| d(C::NotFound, "no webhook is configured"))?;
                Ok((hook, Notifier::waiting(core)))
            })
            .await??;
        {
            let mut i = self.inner();
            let now = now_ms();
            if now - i.last_test < TEST_INTERVAL_MS as i64 {
                let wait = ((i.last_test + TEST_INTERVAL_MS as i64 - now) as f64 / 1000.0)
                    .ceil()
                    .max(1.0) as u64;
                return Err(d(
                    C::QuotaExceeded,
                    "a test notification was sent less than 30 seconds ago",
                )
                .retry(wait));
            }
            i.last_test = now;
        }
        let (url, host, detail) = hook;
        let body = webhook_payload(&items, &detail, "test");
        Ok(self.post(&shared, url, host, body, items.len()).await)
    }

    /// `Notifier.close()`.
    pub fn close(&self) {
        let mut i = self.inner();
        i.closed = true;
        i.timer = false;
        i.subscribers.clear();
    }
}

fn record(core: &mut Core, kind: &str, fields: Value) {
    if !core.vault.locked() {
        core.audit_opt(kind, fields);
    }
}

/// `#webhook()`: `(url, host, detail)`, or nothing.
fn webhook_of(core: &Core) -> Option<(String, String, String)> {
    if core.vault.locked() || core.vault.notify_config().ok().flatten().is_none() {
        return None;
    }
    let hook = core.vault.get_notify_webhook().ok().flatten()?;
    let detail = serde_json::to_value(hook.detail)
        .ok()
        .and_then(|d| d.as_str().map(str::to_string))
        .unwrap_or_else(|| "minimal".into());
    let url = hook_url(&hook)?;
    Some((url, hook.host.clone(), detail))
}

fn hook_url(hook: &av_store::vault::NotifyWebhook) -> Option<String> {
    use av_core::secret::ExposeSecret;
    Some(hook.url.expose_secret().to_string())
}

/// `defaultSend`: one POST, no redirect, the answer drained unread, given up
/// after [`WEBHOOK_TIMEOUT_MS`].
pub fn default_sender() -> Sender {
    Arc::new(|url: String, body: String| {
        Box::pin(async move {
            use crate::upstream::{Pins, Upstream, UpstreamRequest};
            let up = crate::connectors::pinning::PinnedUpstream;
            let req = UpstreamRequest {
                url,
                method: "POST".into(),
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("content-length".into(), body.len().to_string()),
                    ("user-agent".into(), "agent-vault".into()),
                ],
                body: Some(body.into_bytes()),
                pins: Pins::None,
            };
            let fut = up.send(req);
            match tokio::time::timeout(std::time::Duration::from_millis(WEBHOOK_TIMEOUT_MS), fut)
                .await
            {
                Err(_) => Err("timeout".into()),
                Ok(Err(e)) => Err(if e.code.is_empty() {
                    "error".into()
                } else {
                    e.code
                }),
                Ok(Ok(res)) => {
                    let status = res.status;
                    if let crate::upstream::Body::Stream(mut rx) = res.body {
                        let drain = async { while rx.recv().await.is_some() {} };
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_millis(WEBHOOK_TIMEOUT_MS),
                            drain,
                        )
                        .await;
                    }
                    Ok(status)
                }
            }
        }) as BoxFuture<'static, Result<u16, String>>
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headline_strips_controls_bidi_and_placeholders() {
        assert_eq!(clean_headline("a\u{1b}[31mb\u{202e}c"), "a [31mbc");
        let long = "x".repeat(300);
        assert_eq!(clean_headline(&long).encode_utf16().count(), 200);
    }

    #[test]
    fn payload_is_bounded_by_dropping_items_never_cutting_json() {
        let items: Vec<Value> = (0..20)
            .map(|i| json!({"kind": "request", "id": format!("ap_{i:02}"), "headline": "h".repeat(190), "created_at": format!("2026-01-01T00:00:{i:02}.000Z")}))
            .collect();
        let text = webhook_payload(&items, "headline", "pending");
        assert!(text.len() <= MAX_PAYLOAD_BYTES);
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["waiting"], 20);
        assert_eq!(v["ids"].as_array().unwrap().len(), 10);
        assert_eq!(v["ids"][0], "ap_19");
    }

    /// "a notification headline keeps a stored secret an agent put in a
    /// path (F14)" and "a notification headline keeps placeholder text".
    #[test]
    fn a_headline_carries_no_stored_secret_and_no_placeholder() {
        let secret = "s3cr3t-value-in-a-path-0123456789";
        let secrets = vec![av_core::scrub::StoredSecret {
            secret: secret.to_string().into(),
            label: "gh".into(),
        }];
        let e = json!({"kind": "request", "id": "ap_1", "headline": format!("GET /x/{secret}")});
        let item = item_of(&e, Some(&secrets)).unwrap();
        let h = item["headline"].as_str().unwrap();
        assert!(!h.contains(secret), "{h}");
        assert!(h.starts_with("GET /x/"), "{h}");
        let k = av_core::secret::Key32::from_bytes([7; 32]);
        let sid = av_core::placeholder::new_sid();
        let ph = av_core::placeholder::mint(&av_core::placeholder::MintInput {
            k_ph: &k,
            sid: &sid,
            slug: "gh",
            field: "token",
        })
        .unwrap()
        .text;
        let h = clean_headline(&format!("GET /y?k={ph}"));
        assert!(!h.contains(&ph), "{h}");
        assert!(h.contains("«placeholder»"), "{h}");
    }
}
