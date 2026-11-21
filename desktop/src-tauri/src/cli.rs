//! Running the installed agent-vault CLI and reading its `--json` output.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const TIMEOUT: Duration = Duration::from_secs(20);

/// The root-owned CLI the vault's installer puts in place. The companion
/// never looks the CLI up on PATH: an agent can put a fake `agent-vault`
/// earlier on PATH, and a companion that ran it would show whatever it chose.
fn install_path() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        Some(PathBuf::from("/var/db/agent-vault/app/bin/agent-vault"))
    } else if cfg!(target_os = "linux") {
        Some(PathBuf::from("/usr/libexec/agent-vault/app/bin/agent-vault"))
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct Cli {
    path: PathBuf,
}

impl Cli {
    pub fn locate() -> Result<Cli, String> {
        let Some(path) = install_path() else {
            return Err("agent-vault does not run on this operating system yet".into());
        };
        if !path.exists() {
            return Err("run `agent-vault setup` to install it".into());
        }
        check_root_owned(&path)?;
        if let Some(dir) = path.parent() {
            check_root_owned(dir)?;
        }
        Ok(Cli { path })
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.path);
        cmd.args(args)
            .arg("--json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        clean_env(&mut cmd);
        cmd
    }

    /// Run one command to completion and return the envelope's `data`.
    pub fn run(&self, args: &[&str]) -> Result<Value, String> {
        let mut child = self
            .command(args)
            .spawn()
            .map_err(|e| format!("could not start agent-vault: {e}"))?;
        let out = drain(child.stdout.take());
        let err = drain(child.stderr.take());
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() > TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("agent-vault {} timed out", args.join(" ")));
                }
                Ok(None) => thread::sleep(Duration::from_millis(40)),
                Err(e) => return Err(e.to_string()),
            }
        }
        let stdout = out.join().unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        parse_envelope(&stdout).or_else(|e| {
            let stderr = stderr.trim();
            Err(if stderr.is_empty() { e } else { first_line(stderr) })
        })
    }

    /// `agent-vault watch --json --no-notify`: a long-lived stream of
    /// pending-approval events. The caller reads stdout line by line.
    pub fn watch(&self) -> std::io::Result<Child> {
        let mut cmd = self.command(&["watch", "--no-notify"]);
        cmd.stderr(Stdio::null());
        cmd.spawn()
    }

    /// Start `agent-vault ui --json --no-open` and wait for its single-use
    /// link. Returns the process (which serves the UI until it idles out or is
    /// killed) and the link.
    pub fn ui(&self) -> Result<(Child, String), String> {
        let mut child = self
            .command(&["ui", "--no-open"])
            .spawn()
            .map_err(|e| format!("could not start the vault UI: {e}"))?;
        let stdout = child.stdout.take();
        let stderr = drain(child.stderr.take());
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let Some(stdout) = stdout else { return };
            let mut reader = BufReader::new(stdout);
            let mut json = JsonLines::default();
            let mut sent = false;
            // Keep reading after the link so a full pipe never stalls the server.
            while let Ok(Some(line)) = read_line_capped(&mut reader, LINE_CAP) {
                if !sent {
                    if let Some(v) = json.push(&line) {
                        let _ = tx.send(v);
                        sent = true;
                    }
                }
            }
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(v) => {
                let url = v
                    .get("data")
                    .and_then(|d| d.get("url"))
                    .or_else(|| v.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let checked = checked_ui_url(url)
                    .ok_or_else(|| {
                        envelope_error(&v).unwrap_or_else(|| "the vault UI gave an unexpected link".into())
                    })
                    .and_then(|url| {
                        only_listener(ui_port(&url).unwrap_or_default(), child.id()).map(|()| url)
                    });
                match checked {
                    Ok(url) => Ok((child, url)),
                    Err(why) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        Err(why)
                    }
                }
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let why = stderr.join().unwrap_or_default();
                let why = first_line(why.trim());
                Err(if why.is_empty() { "the vault UI did not start".into() } else { why })
            }
        }
    }
}

/// Child processes get a fixed, minimal environment. Anything else could be
/// steering: `AGENT_VAULT_DIR`, for one, points the CLI at a different control
/// socket, and the companion may have been started from a shell an agent set up.
fn clean_env(cmd: &mut Command) {
    cmd.env_clear();
    for key in ["HOME", "USER", "LOGNAME", "LANG", "TMPDIR"] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
}

/// Lines longer than this are skipped whole: the vault's own JSON lines are far
/// shorter, and nothing should be able to make the companion hold an
/// unbounded line in memory.
pub const LINE_CAP: usize = 64 * 1024;

/// Read one line of at most `cap` bytes, without its newline. A longer line is
/// consumed and returned as an empty string. `Ok(None)` at end of stream.
pub fn read_line_capped<R: BufRead>(r: &mut R, cap: usize) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut overflow = false;
    let mut any = false;
    loop {
        let (used, done) = {
            let avail = r.fill_buf()?;
            if avail.is_empty() {
                if !any {
                    return Ok(None);
                }
                break;
            }
            any = true;
            let (n, done) = match avail.iter().position(|&b| b == b'\n') {
                Some(i) => (i, true),
                None => (avail.len(), false),
            };
            if !overflow {
                if buf.len() + n > cap {
                    overflow = true;
                    buf = Vec::new();
                } else {
                    buf.extend_from_slice(&avail[..n]);
                }
            }
            (if done { n + 1 } else { n }, done)
        };
        r.consume(used);
        if done {
            break;
        }
    }
    Ok(Some(if overflow {
        String::new()
    } else {
        String::from_utf8_lossy(&buf).into_owned()
    }))
}

/// Gathers lines until they form one JSON value: the CLI prints some
/// envelopes on one line and some pretty-printed over several.
#[derive(Default)]
pub struct JsonLines {
    buf: String,
}

impl JsonLines {
    pub fn push(&mut self, line: &str) -> Option<Value> {
        if line.is_empty() && self.buf.is_empty() {
            return None;
        }
        self.buf.push_str(line);
        self.buf.push('\n');
        if let Ok(v) = serde_json::from_str::<Value>(&self.buf) {
            self.buf.clear();
            return Some(v);
        }
        if self.buf.len() > LINE_CAP {
            self.buf.clear();
        }
        None
    }
}

fn ui_port(url: &str) -> Option<u16> {
    url.strip_prefix("http://localhost:")?
        .split_once('/')?
        .0
        .parse()
        .ok()
}

/// The browser resolves `localhost` to IPv6 as well as IPv4, and the vault's
/// UI server quietly skips IPv6 when that port is taken. So before opening a
/// single-use link, make sure every listener on the port is the UI process the
/// companion just started; anything else could receive the link.
fn only_listener(port: u16, ours: u32) -> Result<(), String> {
    if port == 0 {
        return Err("the vault UI gave an unexpected link".into());
    }
    let lsof = ["/usr/sbin/lsof", "/usr/bin/lsof"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or("cannot check who is listening on the vault UI's port (lsof is missing)")?;
    let mut cmd = Command::new(lsof);
    cmd.args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fp"])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    clean_env(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("cannot check the vault UI's port: {e}"))?;
    let pids: Vec<u32> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix('p')?.parse().ok())
        .collect();
    if pids.is_empty() {
        return Err("the vault UI is not listening".into());
    }
    if pids.iter().any(|p| *p != ours) {
        return Err(format!(
            "another program is listening on the vault UI's port {port}, so the link was not opened. Check what holds it: lsof -nP -iTCP:{port}"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn check_root_owned(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(p).map_err(|e| format!("cannot inspect {}: {e}", p.display()))?;
    if m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is not a root-owned install, so the companion will not run it",
            p.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_root_owned(_p: &Path) -> Result<(), String> {
    Err("agent-vault does not run on this operating system yet".into())
}

fn drain<R: Read + Send + 'static>(r: Option<R>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut r) = r {
            let _ = r.read_to_string(&mut s);
        }
        s
    })
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or_default().chars().take(200).collect()
}

fn envelope_error(v: &Value) -> Option<String> {
    let e = v.get("error")?;
    let msg = e
        .as_str()
        .or_else(|| e.get("message").and_then(Value::as_str))
        .or_else(|| e.get("detail").and_then(Value::as_str))?;
    Some(first_line(msg))
}

/// `{"ok":true,"data":…}` → data; anything else → a readable error.
pub fn parse_envelope(stdout: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(stdout.trim())
        .map_err(|_| "agent-vault gave no readable answer".to_string())?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(v.get("data").cloned().unwrap_or(Value::Null))
    } else {
        Err(envelope_error(&v).unwrap_or_else(|| "agent-vault refused".into()))
    }
}

/// Only a loopback link to the vault's own UI is opened.
pub fn checked_ui_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://localhost:")?;
    let (port, tail) = rest.split_once('/')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let token = tail.strip_prefix("?t=")?;
    if token.is_empty()
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'~'))
    {
        return None;
    }
    Some(url.to_string())
}

/// Open a URL in the default browser.
pub fn open_in_browser(url: &str) -> Result<(), String> {
    let result = if cfg!(target_os = "macos") {
        Command::new("/usr/bin/open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).status()
    } else {
        Command::new("/usr/bin/xdg-open").arg(url).status()
    };
    match result {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("the browser did not open ({s})")),
        Err(e) => Err(format!("the browser did not open: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_yield_data_or_the_error_message() {
        assert_eq!(parse_envelope(r#"{"ok":true,"data":[1]}"#).unwrap(), serde_json::json!([1]));
        assert_eq!(
            parse_envelope(r#"{"ok":false,"error":{"code":"AV_LOCKED","message":"the vault is locked"}}"#).unwrap_err(),
            "the vault is locked"
        );
        assert!(parse_envelope("not json").is_err());
    }

    #[test]
    fn long_lines_are_skipped_not_held() {
        let data = format!("short\n{}\nafter\nlast", "x".repeat(200));
        let mut r = std::io::BufReader::with_capacity(16, data.as_bytes());
        let mut got = Vec::new();
        while let Some(line) = read_line_capped(&mut r, 50).unwrap() {
            got.push(line);
        }
        assert_eq!(got, ["short", "", "after", "last"]);
    }

    #[test]
    fn json_is_gathered_across_pretty_printed_lines() {
        let mut j = JsonLines::default();
        assert_eq!(j.push("{"), None);
        assert_eq!(j.push(r#"  "ok": true"#), None);
        assert_eq!(j.push("}"), Some(serde_json::json!({"ok": true})));
        assert_eq!(j.push(r#"{"ok":true,"data":{"event":"pending"}}"#).unwrap()["data"]["event"], "pending");
    }

    #[test]
    fn the_port_is_read_from_the_link() {
        assert_eq!(ui_port("http://localhost:7412/?t=abc"), Some(7412));
        assert_eq!(ui_port("http://localhost:/?t=abc"), None);
    }

    #[test]
    fn only_the_vaults_own_loopback_link_is_opened() {
        assert!(checked_ui_url("http://localhost:7412/?t=abc_DEF-123").is_some());
        for bad in [
            "https://localhost:7412/?t=abc",
            "http://127.0.0.1:7412/?t=abc",
            "http://localhost.evil.com:7412/?t=abc",
            "http://localhost:7412/?t=",
            "http://localhost:7412/?t=abc&next=http://evil",
            "http://localhost:/?t=abc",
            "file:///etc/passwd",
        ] {
            assert!(checked_ui_url(bad).is_none(), "{bad}");
        }
    }
}
