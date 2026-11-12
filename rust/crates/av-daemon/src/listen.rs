//! Binding and serving: the loopback gateway, the control socket (mode,
//! group and ACL as in `#secureSocket`, plus a peer-credential check), and
//! configured listeners (`#bindListener`): TLS, surfaces, `allow_cidr` on
//! the raw connection before TLS or HTTP see a byte, and revocation that
//! drops every connection, mid-handshake ones included.

use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::json;

use crate::http::{read_body, Resp};
use crate::pipeline::ListenerInfo;
use crate::server::{
    is_loopback_host, parse_address, parse_allow_cidr, Bound, Daemon, Incoming, MAX_BODY,
};
use crate::state::VaultRef;

async fn incoming(req: hyper::Request<hyper::body::Incoming>) -> Result<Incoming, Box<Resp>> {
    let (parts, body) = req.into_parts();
    let target = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.to_string(), |p| p.as_str().to_string());
    let target = if parts.uri.scheme().is_some() {
        parts.uri.to_string()
    } else {
        target
    };
    let headers = crate::util::node_headers(&parts.headers);
    let body = read_body(body, MAX_BODY).await?;
    Ok(Incoming {
        method: parts.method.as_str().to_string(),
        target,
        headers,
        body,
    })
}

/// The future a guarded handler returns.
type Answer =
    std::pin::Pin<Box<dyn Future<Output = Result<Resp, std::convert::Infallible>> + Send>>;

/// Watches the connection a handler answers for the client going away.
pub trait ConnWatch: Send + Sync {
    /// Ready once the client's side of the connection has closed.
    fn poll_closed(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()>;
}

tokio::task_local! {
    static CONN: Arc<dyn ConnWatch>;
}

/// Ready once the connection the current handler answers has closed; None
/// outside a served connection (in-process calls).
pub fn conn_closed() -> Option<crate::http::Closed> {
    let w = CONN.try_with(Clone::clone).ok()?;
    Some(Box::pin(std::future::poll_fn(move |cx| w.poll_closed(cx))))
}

/// The most a watcher stashes for hyper before it stops reading ahead.
const STASH_LIMIT: usize = 64 * 1024;

struct Conn<IO> {
    io: IO,
    /// Bytes read ahead by a watcher, handed to hyper first.
    stash: Vec<u8>,
    /// The client's side ended (end of input or a read error).
    ended: bool,
}

/// The connection's IO, shared between hyper and a stream that watches for
/// the client going away. hyper (with `half_close`, which a client that
/// half-closes before reading needs) does not read while it writes a
/// response, so an endless event stream reads ahead itself: what it reads
/// is kept for hyper, and the end of input closes the stream at once, as
/// `res.on('close')` does in Node.
struct Shared<IO>(Arc<std::sync::Mutex<Conn<IO>>>);

impl<IO> Shared<IO> {
    fn lock(&self) -> std::sync::MutexGuard<'_, Conn<IO>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl<IO: tokio::io::AsyncRead + Unpin + Send> ConnWatch for std::sync::Mutex<Conn<IO>> {
    fn poll_closed(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let mut c = self.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if c.ended {
                return std::task::Poll::Ready(());
            }
            if c.stash.len() >= STASH_LIMIT {
                return std::task::Poll::Pending;
            }
            let mut chunk = [0u8; 4096];
            let mut buf = tokio::io::ReadBuf::new(&mut chunk);
            match std::pin::Pin::new(&mut c.io).poll_read(cx, &mut buf) {
                std::task::Poll::Ready(Ok(())) if buf.filled().is_empty() => c.ended = true,
                std::task::Poll::Ready(Ok(())) => {
                    let got = buf.filled().to_vec();
                    c.stash.extend_from_slice(&got);
                }
                std::task::Poll::Ready(Err(_)) => c.ended = true,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl<IO: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Shared<IO> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut c = self.lock();
        if !c.stash.is_empty() {
            let n = c.stash.len().min(buf.remaining());
            buf.put_slice(&c.stash[..n]);
            c.stash.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }
        if c.ended {
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut c.io).poll_read(cx, buf)
    }
}

impl<IO: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Shared<IO> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.lock().io).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.lock().io).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.lock().io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.lock().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.lock().io.is_write_vectored()
    }
}

/// `#guard`: a handler that panics answers 500, never ends the daemon.
fn guarded<F, Fut>(
    f: F,
    conn: Arc<dyn ConnWatch>,
) -> impl Fn(hyper::Request<hyper::body::Incoming>) -> Answer + Clone
where
    F: Fn(Incoming) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    move |req| {
        let f = f.clone();
        let conn = conn.clone();
        Box::pin(async move {
            let inc = match incoming(req).await {
                Ok(i) => i,
                Err(r) => return Ok(*r),
            };
            let task = tokio::spawn(CONN.scope(conn, f(inc)));
            Ok(match task.await {
                Ok(r) => r,
                Err(_) => crate::http::response(
                    500,
                    &[("content-type".into(), "application/problem+json".into())],
                    crate::util::js_stringify(&json!({"code": "AV_INTERNAL", "detail": "the request could not be handled"})).into_bytes(),
                ),
            })
        })
    }
}

fn serve_conn<IO, F, Fut>(io: IO, handler: F) -> impl Future<Output = ()>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Fn(Incoming) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    let conn = Arc::new(std::sync::Mutex::new(Conn {
        io,
        stash: Vec::new(),
        ended: false,
    }));
    let svc = guarded(handler, conn.clone());
    let io = Shared(conn);
    async move {
        let _ = hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .half_close(true)
            .serve_connection(TokioIo::new(io), service_fn(svc))
            .await;
    }
}

/// Serve HTTP on a TCP listener.
pub async fn serve_tcp<F, Fut>(
    listener: tokio::net::TcpListener,
    _info: Option<ListenerInfo>,
    handler: F,
) where
    F: Fn(Incoming, Option<String>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let h = handler.clone();
        let peer_s = peer.ip().to_string();
        tokio::spawn(serve_conn(stream, move |inc| h(inc, Some(peer_s.clone()))));
    }
}

/// Bind the control socket with a narrow umask, so it is never connectable
/// by anyone else between the bind and the chmod.
pub fn bind_unix(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    crate::peercred::with_umask(0o077, || tokio::net::UnixListener::bind(path))
}

/// Serve the control API. With an enrolled uid, a peer that is not this
/// process's uid, the enrolled uid or root is refused before a byte is read.
pub fn serve_unix<F, Fut>(
    listener: tokio::net::UnixListener,
    enrolled: Option<u32>,
    handler: F,
) -> impl Future<Output = ()> + Send
where
    F: Fn(Incoming) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    let me = crate::peercred::effective_uid();
    async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            if let Some(uid) = enrolled {
                match crate::peercred::peer_cred(&stream) {
                    Ok(c) if c.uid == me || c.uid == uid || c.uid == 0 => {}
                    Ok(c) => {
                        eprintln!(
                            "agent-vault: refused a control connection from uid {}",
                            c.uid
                        );
                        continue;
                    }
                    Err(_) => continue,
                }
            }
            tokio::spawn(serve_conn(stream, handler.clone()));
        }
    }
}

/// `#secureSocket()`.
pub async fn secure_socket(
    shared: &VaultRef,
    path: &Path,
    group: Option<&str>,
    enrolled: Option<u32>,
) {
    let audit = |kind: &'static str, fields: serde_json::Value| {
        let s = shared.clone();
        async move {
            let _ = s.run(move |core| core.audit_opt(kind, fields)).await;
        }
    };
    let Some(group) = group else {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        return;
    };
    let gid = lookup_gid(group);
    let Some(gid) = gid else {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        audit(
            "daemon.socket_group_failed",
            json!({"group": group, "reason": "group not found"}),
        )
        .await;
        eprintln!("agent-vault: group {group} does not exist; the socket is 0600 and only this user can connect");
        return;
    };
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::metadata(path).map(|m| m.gid()).unwrap_or(u32::MAX);
    if current != gid {
        if let Err(e) =
            std::os::unix::fs::chown(path, Some(crate::peercred::effective_uid()), Some(gid))
        {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            let code = e.raw_os_error().map(errno_name).unwrap_or("EPERM");
            audit(
                "daemon.socket_group_failed",
                json!({"group": group, "reason": code}),
            )
            .await;
            eprintln!("agent-vault: cannot set the socket group to {group} ({code}).\n  The socket is 0600, so the CLI cannot reach it. Re-run the installer to repair group membership.");
            return;
        }
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
    if let Some(uid) = enrolled {
        let p = path.display().to_string();
        let ok = if cfg!(target_os = "macos") {
            std::process::Command::new("chmod")
                .args(["+a", &format!("user:{uid} allow read,write"), &p])
                .status()
        } else {
            std::process::Command::new("setfacl")
                .args(["-m", &format!("u:{uid}:rw"), &p])
                .status()
        };
        if !ok.is_ok_and(|s| s.success()) {
            audit("daemon.socket_acl_failed", json!({"uid": uid})).await;
        }
    }
}

fn errno_name(n: i32) -> &'static str {
    match n {
        1 => "EPERM",
        2 => "ENOENT",
        13 => "EACCES",
        _ => "EPERM",
    }
}

/// The group's gid, as `getent group` (or `dscl` on macOS) reports it.
fn lookup_gid(group: &str) -> Option<u32> {
    let out = std::process::Command::new("getent")
        .args(["group", group])
        .output()
        .ok()
        .filter(|o| o.status.success());
    if let Some(o) = out {
        return String::from_utf8_lossy(&o.stdout)
            .split(':')
            .nth(2)
            .and_then(|g| g.trim().parse().ok());
    }
    let o = std::process::Command::new("dscl")
        .args([".", "-read", &format!("/Groups/{group}"), "PrimaryGroupID"])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    String::from_utf8_lossy(&o.stdout)
        .split(':')
        .next_back()
        .and_then(|g| g.trim().parse().ok())
}

/// A bind failure: the system code for the audit log, and the message.
pub struct BindError(pub String, pub String);

fn tls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Result<tokio_rustls::TlsAcceptor, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .filter_map(Result::ok)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("tls key: {e}"))?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| e.to_string())?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// `#bindListener(entry)`.
pub(crate) async fn bind_listener(
    daemon: &Arc<Daemon>,
    entry: &av_store::model::ListenerRecord,
) -> Result<Bound, BindError> {
    let other = |m: String| BindError("other".into(), m);
    let (host, port) = parse_address(&entry.address).map_err(other)?;
    let surfaces = entry.surfaces.clone();
    let remote = !is_loopback_host(&host);
    let allow_v = serde_json::to_value(&entry.allow_cidr)
        .ok()
        .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()));
    let allow = parse_allow_cidr(allow_v.as_ref()).map_err(other)?;
    let acceptor = match &entry.tls {
        Some(t) => {
            let material = if t.managed == Some(true) {
                let info = crate::tls::ensure_certificate(daemon.shared.dir(), false)
                    .map_err(|e| other(e.to_string()))?;
                crate::tls::load_material(&info.cert, &info.key)
            } else {
                crate::tls::load_material(
                    Path::new(t.cert.as_deref().unwrap_or("")),
                    Path::new(t.key.as_deref().unwrap_or("")),
                )
            }
            .map_err(|e| other(e.to_string()))?;
            use av_core::secret::ExposeSecret;
            Some(tls_acceptor(&material.cert, material.key.expose_secret()).map_err(other)?)
        }
        None => {
            if remote {
                return Err(other(
                    "a listener on a network address must configure TLS".into(),
                ));
            }
            None
        }
    };
    let bind_host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let listener = tokio::net::TcpListener::bind((bind_host.as_str(), port))
        .await
        .map_err(|e| {
            let code = match e.kind() {
                std::io::ErrorKind::AddrInUse => "EADDRINUSE",
                std::io::ErrorKind::PermissionDenied => "EACCES",
                std::io::ErrorKind::AddrNotAvailable => "EADDRNOTAVAIL",
                _ => "other",
            };
            BindError(code.into(), e.to_string())
        })?;
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let info = ListenerInfo {
        id: entry.id.clone(),
        kind: if entry.tls.is_some() {
            "tls".into()
        } else {
            "tcp".into()
        },
        remote,
        advertise: entry.advertise.clone(),
    };
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let d = daemon.clone();
    let id = entry.id.clone();
    let task = tokio::spawn(async move {
        let mut conns = tokio::task::JoinSet::new();
        let mut stop = stop_rx.clone();
        loop {
            let accepted = tokio::select! {
                a = listener.accept() => a,
                _ = stop.changed() => break,
            };
            let Ok((stream, peer)) = accepted else {
                continue;
            };
            let addr = peer.ip().to_string();
            if let Some(allow) = &allow {
                if !allow.allows(&addr) {
                    let (d2, id2) = (d.clone(), id.clone());
                    tokio::spawn(async move { d2.peer_refused(&id2, &addr).await });
                    drop(stream);
                    continue;
                }
            }
            let (d2, info2, surfaces2, acceptor2) =
                (d.clone(), info.clone(), surfaces.clone(), acceptor.clone());
            let mut revoked = stop_rx.clone();
            conns.spawn(async move {
                let handler = move |inc: Incoming| {
                    let (d3, info3, surfaces3) = (d2.clone(), info2.clone(), surfaces2.clone());
                    async move { on_listener(&d3, inc, info3, &surfaces3).await }
                };
                let work = async move {
                    match acceptor2 {
                        Some(a) => {
                            if let Ok(tls) = a.accept(stream).await {
                                serve_conn(tls, handler).await;
                            }
                        }
                        None => serve_conn(stream, handler).await,
                    }
                };
                tokio::select! {
                    _ = work => {}
                    _ = revoked.changed() => {}
                }
            });
            while conns.try_join_next().is_some() {}
        }
        conns.abort_all();
    });
    let surf = entry.surfaces.clone();
    let (lid, tls, addr) = (
        entry.id.clone(),
        entry.tls.is_some(),
        format!("{host}:{bound_port}"),
    );
    let s2 = surf.clone();
    daemon
        .shared
        .run(move |core| {
            core.audit_opt(
                "listen.bound",
                json!({"listener_id": lid, "address": addr, "tls": tls, "surfaces": s2}),
            )
        })
        .await
        .ok();
    Ok(Bound {
        id: entry.id.clone(),
        host,
        port: bound_port,

        stop: stop_tx,
        task,
    })
}

/// The handler of a configured listener: only the surfaces it declares.
async fn on_listener(
    d: &Arc<Daemon>,
    inc: Incoming,
    info: ListenerInfo,
    surfaces: &[String],
) -> Resp {
    let path = crate::http::parse_target(&inc.target, "http://placeholder")
        .map(|(p, _)| p)
        .unwrap_or_default();
    let wanted = if path == "/mcp" { "mcp" } else { "gateway" };
    if !surfaces.iter().any(|s| s == wanted) {
        let list = if surfaces.is_empty() {
            "nothing".to_string()
        } else {
            surfaces.join(", ")
        };
        return crate::http::json_compact(
            404,
            &json!({"code": "AV_NOT_FOUND", "detail": format!("listener {} does not serve the {wanted} surface", info.id), "hint": format!("it serves: {list}")}),
        );
    }
    d.on_gateway(inc, Some(info), None).await
}
