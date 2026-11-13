//! `agent-vault watch`: follow the daemon's pending stream and notify.
//! Ports `src/cli/watch.js`.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use av_core::errors::Exit;

use crate::prompt::Colors;
use crate::CliError;

/// Strip C0 (including tab and newline), C1, bidi and line separators.
/// Ports `clean` in `src/cli/watch.js` (not `cleanText`, which keeps tab
/// and newline).
pub(crate) fn watch_clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            let u = *c as u32;
            !((u <= 0x1f)
                || (0x7f..=0x9f).contains(&u)
                || (0x202a..=0x202e).contains(&u)
                || (0x2066..=0x2069).contains(&u)
                || u == 0x2028
                || u == 0x2029)
        })
        .collect()
}

fn is_placeholder_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-'
}

/// Replace `av1.<token>` and drop `?query` runs. Hand scans, no regex.
fn scrub_headline(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"av1.") {
            let mut j = i + 4;
            let start = j;
            while j < bytes.len() && is_placeholder_char(bytes[j]) {
                j += 1;
            }
            if j > start {
                out.push_str("[placeholder]");
                i = j;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\u{fffd}');
        if ch == '?' {
            i += ch.len_utf8();
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                let next = input[i..].chars().next().unwrap_or('\u{fffd}');
                i += next.len_utf8();
            }
            continue;
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The four display fields of one stream entry, cleaned (controls stripped,
/// placeholders replaced, query strings dropped from the headline); `None`
/// for an entry that is not one. Never the agent's reason or body. Ports
/// `safeEntry(entry)` in `src/cli/watch.js`.
pub fn safe_entry(entry: &Value) -> Option<Value> {
    let obj = entry.as_object()?;
    let kind = obj.get("kind").and_then(|v| v.as_str())?;
    if kind != "request" && kind != "session" {
        return None;
    }
    let id = obj.get("id").and_then(|v| v.as_str())?;
    let headline = scrub_headline(&watch_clean(
        obj.get("headline").and_then(|v| v.as_str()).unwrap_or(""),
    ));
    let mut out = Map::new();
    out.insert("kind".into(), Value::from(kind));
    out.insert("id".into(), Value::from(watch_clean(id)));
    out.insert("headline".into(), Value::from(headline));
    match obj.get("created_at") {
        Some(Value::Number(n)) if n.as_f64().is_some_and(|f| f.is_finite()) => {
            out.insert("created_at".into(), Value::Number(n.clone()));
        }
        Some(Value::String(s)) => {
            out.insert("created_at".into(), Value::from(watch_clean(s)));
        }
        _ => {}
    }
    Some(Value::Object(out))
}

/// Options for [`watch_approvals`]. Ports the options of
/// `watchApprovals({ socketPath, json, notify, open, onEvent, quiet, deps })`
/// in `src/cli/watch.js` (`deps` is the test seam; the CLI worker chooses the
/// Rust equivalent).
#[derive(Debug, Clone, Default)]
pub struct WatchOptions {
    /// The control socket.
    pub socket_path: PathBuf,
    /// One JSON line per item.
    pub json: bool,
    /// Desktop notification per item.
    pub notify: bool,
    /// Open the UI on the first item.
    pub open: bool,
    /// Less output.
    pub quiet: bool,
}

const FRAME_CAP: usize = 262_144;

fn fail(message: impl Into<String>, exit: Exit) -> CliError {
    CliError {
        message: message.into(),
        exit,
        next: None,
        problem: None,
        skew: false,
    }
}

async fn http_get_stream(path: &PathBuf) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(path).await?;
    let req = b"GET /v1/pending/stream HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n";
    stream.write_all(req).await?;
    stream.flush().await?;
    Ok(stream)
}

struct Head {
    status: u16,
    body_start: Vec<u8>,
}

fn split_head(buf: &[u8]) -> Option<(Head, usize)> {
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = &buf[..sep];
    let rest = buf[sep + 4..].to_vec();
    let text = String::from_utf8_lossy(head);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((
        Head {
            status,
            body_start: rest,
        },
        sep + 4,
    ))
}

/// Reconnect delay, capped at 30 seconds. Ports the backoff in `src/cli/watch.js`.
pub(crate) fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(Duration::from_secs(30))
}

/// A 404 with no control route is an old daemon. Other statuses keep the
/// registered exit for the error code.
pub(crate) fn stream_refusal(status: u16, problem: &Value) -> CliError {
    let detail = problem.get("detail").and_then(|v| v.as_str()).unwrap_or("");
    if status == 404 && detail.contains("no control route") {
        return CliError {
            message: "the running daemon is older than this command".into(),
            exit: Exit::VersionSkew,
            next: Some("restart the daemon you started with: agent-vault daemon".into()),
            problem: Some(Box::new(problem.clone())),
            skew: true,
        };
    }
    let code = problem.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let exit = av_core::errors::ErrorCode::parse(code)
        .map(|c| c.spec().exit)
        .unwrap_or(Exit::Failure);
    let message = if detail.is_empty() {
        format!("approval stream returned HTTP {status}")
    } else {
        detail.to_string()
    };
    CliError {
        message,
        exit,
        next: None,
        problem: Some(Box::new(problem.clone())),
        skew: false,
    }
}

/// osascript that shows `argv`'s first item. The notification text is an
/// argument, never interpolated into the script. Ports the `osascript`
/// invocation in `src/cli/watch.js`. Only macOS runs it; the unit test runs
/// everywhere.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn macos_notify_script() -> &'static [&'static str] {
    &[
        "-e",
        "on run argv",
        "-e",
        "display notification (item 1 of argv) with title \"agent-vault\"",
        "-e",
        "end run",
        "--",
    ]
}

fn notify_desktop(text: &str) {
    let text = text.to_string();
    std::thread::spawn(move || {
        #[cfg(target_os = "macos")]
        let result = {
            let mut args: Vec<&str> = macos_notify_script().to_vec();
            args.push(&text);
            std::process::Command::new("osascript").args(&args).output()
        };
        #[cfg(target_os = "linux")]
        let result = std::process::Command::new("notify-send")
            .args(["agent-vault", &text])
            .output();
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let result: std::io::Result<std::process::Output> = Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no notifier",
        ));
        if result.is_err() || result.ok().is_some_and(|o| !o.status.success()) {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr().lock(),
                b"note desktop notifications are unavailable\n",
            );
        }
    });
}

fn open_ui() {
    let bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-vault"));
    let _ = std::process::Command::new(bin)
        .arg("ui")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Watch the local approval stream until SIGINT, reconnecting with backoff.
/// Ports `watchApprovals(...)` in `src/cli/watch.js`.
pub async fn watch_approvals(opts: WatchOptions) -> Result<(), CliError> {
    let mut stopped = false;
    let mut connected = false;
    let mut backoff = Duration::from_secs(1);
    let mut opened = false;
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut pending_notes: Vec<Value> = Vec::new();
    let mut cooling = false;
    let mut cool_until = std::time::Instant::now();
    let colors = Colors::detect();
    let sigint = tokio::signal::ctrl_c();
    tokio::pin!(sigint);

    while !stopped {
        let connect = http_get_stream(&opts.socket_path);
        tokio::pin!(connect);
        let stream = tokio::select! {
            _ = &mut sigint => {
                break;
            }
            result = &mut connect => result,
        };
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                if !connected {
                    return Err(fail(
                        format!("the daemon cannot be reached: {e}"),
                        Exit::DaemonUnreachable,
                    ));
                }
                tokio::select! {
                    _ = &mut sigint => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head = loop {
            let n = tokio::select! {
                _ = &mut sigint => { stopped = true; break None; }
                n = stream.read(&mut tmp) => n,
            };
            match n {
                Ok(0) | Err(_) => break None,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some((head, _)) = split_head(&buf) {
                        break Some(head);
                    }
                    if buf.len() > FRAME_CAP {
                        break None;
                    }
                }
            }
        };
        let Some(head) = head else {
            if stopped {
                break;
            }
            if !connected {
                return Err(fail(
                    "the daemon cannot be reached",
                    Exit::DaemonUnreachable,
                ));
            }
            tokio::time::sleep(backoff).await;
            backoff = next_backoff(backoff);
            continue;
        };
        if head.status != 200 {
            let mut body = head.body_start;
            let mut tmp = [0u8; 4096];
            while body.len() < 65536 {
                match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                }
            }
            let problem: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            return Err(stream_refusal(head.status, &problem));
        }
        connected = true;
        backoff = Duration::from_secs(1);
        // The snapshot often arrives in the same read as the headers
        // (chunked). Parse that before blocking on the next read, or a
        // client waiting for the first line sits through the keep-alive.
        let mut carry = head.body_start;
        let mut name = "message".to_string();
        let mut lines: Vec<String> = Vec::new();
        let mut frame_bytes = 0usize;
        loop {
            if cooling && std::time::Instant::now() >= cool_until && !pending_notes.is_empty() {
                let batch = std::mem::take(&mut pending_notes);
                desktop_batch(&batch);
                cooling = true;
                cool_until = std::time::Instant::now() + Duration::from_secs(10);
            }
            let mut oversize = false;
            while let Some(at) = carry.iter().position(|b| *b == b'\n') {
                let raw = carry.drain(..=at).collect::<Vec<_>>();
                let line = sse_line(&raw);
                if line.is_empty() {
                    if !lines.is_empty() {
                        if let Ok(data) = serde_json::from_str::<Value>(&lines.join("\n")) {
                            if data.is_object() {
                                handle_event(
                                    &name,
                                    &data,
                                    &opts,
                                    &colors,
                                    &mut seen,
                                    &mut pending_notes,
                                    &mut cooling,
                                    &mut cool_until,
                                    &mut opened,
                                );
                            }
                        }
                    }
                    name = "message".into();
                    lines.clear();
                    frame_bytes = 0;
                    continue;
                }
                // A chunk-size line (`24`) is not an SSE field.
                if let Some(rest) = line.strip_prefix("event:") {
                    name = rest.strip_prefix(' ').unwrap_or(rest).to_string();
                } else if let Some(rest) = line.strip_prefix("data:") {
                    let data = rest.strip_prefix(' ').unwrap_or(rest).to_string();
                    frame_bytes += data.len();
                    if frame_bytes > FRAME_CAP {
                        oversize = true;
                        break;
                    }
                    lines.push(data);
                }
            }
            if oversize || carry.len() > FRAME_CAP {
                break;
            }
            let mut tmp = [0u8; 4096];
            let n = tokio::select! {
                _ = &mut sigint => { stopped = true; break; }
                n = stream.read(&mut tmp) => n,
            };
            match n {
                Ok(0) | Err(_) => break,
                Ok(n) => carry.extend_from_slice(&tmp[..n]),
            }
        }
        if stopped {
            break;
        }
        tokio::select! {
            _ = &mut sigint => break,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = next_backoff(backoff);
    }
    Ok(())
}

fn desktop_batch(items: &[Value]) {
    let Some(first) = items.first() else {
        return;
    };
    let kind = first.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let headline = first.get("headline").and_then(|v| v.as_str()).unwrap_or("");
    let suffix = if items.len() > 1 {
        format!(" and {} more", items.len() - 1)
    } else {
        String::new()
    };
    let prefix = if kind == "request" {
        "Held request"
    } else {
        "Session requested"
    };
    let text = watch_clean(&format!("{prefix}: {headline}"));
    let room = 120usize.saturating_sub(suffix.len());
    let cut: String = text.chars().take(room).collect();
    notify_desktop(&format!("{cut}{suffix}"));
}

/// One SSE line, with the trailing LF or CRLF removed. The bytes are
/// decoded only after the newline has arrived, so a character split across
/// reads is whole by the time this runs.
pub(crate) fn sse_line(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .trim_end_matches(['\n', '\r'])
        .to_string()
}

/// `true` the first time `id` is shown. An empty id is never shown, and a
/// repeat is not shown again. Ports the `seen` set in `src/cli/watch.js`.
pub(crate) fn first_time(seen: &mut std::collections::BTreeSet<String>, id: &str) -> bool {
    !id.is_empty() && seen.insert(id.to_string())
}

/// The display object for one SSE event: cleaned fields only, never the
/// raw frame. Ports the `data: { ...data, event }` write in `src/cli/watch.js`.
pub(crate) fn event_data(name: &str, raw: &Value) -> Option<Value> {
    if name == "snapshot" {
        let items = raw
            .get("items")
            .and_then(|v| v.as_array())
            .map(|items| items.iter().filter_map(safe_entry).collect::<Vec<_>>())?;
        let mut map = Map::new();
        map.insert("items".into(), Value::from(items));
        Some(Value::Object(map))
    } else if name == "pending" {
        safe_entry(raw)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    name: &str,
    raw: &Value,
    opts: &WatchOptions,
    colors: &Colors,
    seen: &mut std::collections::BTreeSet<String>,
    pending_notes: &mut Vec<Value>,
    cooling: &mut bool,
    cool_until: &mut std::time::Instant,
    opened: &mut bool,
) {
    let Some(data) = event_data(name, raw) else {
        return;
    };
    if opts.json {
        let mut envelope_data = data.as_object().cloned().unwrap_or_default();
        envelope_data.insert("event".into(), Value::from(name));
        let mut env = Map::new();
        env.insert("ok".into(), Value::Bool(true));
        env.insert("data".into(), Value::Object(envelope_data));
        println!(
            "{}",
            serde_json::to_string(&Value::Object(env)).unwrap_or_else(|_| "{}".into())
        );
        // Piped stdout is block-buffered. A watcher that waits for the
        // snapshot line never sees it if the process is killed first.
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    let mut show = |safe: &Value| {
        let id = safe.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if !first_time(seen, id) {
            return;
        }
        let headline = safe.get("headline").and_then(|v| v.as_str()).unwrap_or("");
        let kind = safe.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if !opts.json && !opts.quiet {
            let label = if kind == "request" {
                "held"
            } else {
                "session requested"
            };
            let colored = if colors.enabled {
                colors.yellow(label)
            } else {
                label.to_string()
            };
            println!("{colored} {id}  {headline}");
        }
        if !opts.json && opts.notify {
            if *cooling && std::time::Instant::now() < *cool_until {
                pending_notes.push(safe.clone());
            } else {
                desktop_batch(std::slice::from_ref(safe));
                *cooling = true;
                *cool_until = std::time::Instant::now() + Duration::from_secs(10);
            }
        }
        if !opts.json && opts.open && !*opened {
            *opened = true;
            open_ui();
        }
    };
    if name == "snapshot" {
        if let Some(items) = data.get("items").and_then(|v| v.as_array()) {
            for item in items {
                show(item);
            }
        }
    } else {
        show(&data);
    }
}
