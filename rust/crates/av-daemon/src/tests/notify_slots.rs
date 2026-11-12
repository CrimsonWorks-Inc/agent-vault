//! A watcher that goes away frees its slot on the notify stream at once,
//! not at the next frame (`res.on('close')` in `Notifier.subscribe`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::notify::{Notifier, NotifierOptions, MAX_SUBSCRIBERS};

/// Opens the stream and reads to the end of its status line.
async fn watch(path: &std::path::Path) -> (UnixStream, u16) {
    let mut s = UnixStream::connect(path).await.unwrap();
    s.write_all(b"GET /v1/pending/stream HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    while !got.windows(2).any(|w| w == b"\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("the stream answers")
            .unwrap();
        assert!(n > 0, "the stream closed before answering");
        got.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&got);
    let status = line.split(' ').nth(1).unwrap().parse().unwrap();
    (s, status)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_watcher_that_disconnects_frees_its_slot_while_the_stream_is_idle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    let n = Notifier::new(NotifierOptions::default());
    let listener = crate::listen::bind_unix(&path).unwrap();
    let nn: Arc<Notifier> = n.clone();
    tokio::spawn(crate::listen::serve_unix(listener, None, move |_inc| {
        let nn = nn.clone();
        async move {
            match nn.subscribe(Vec::new()) {
                Ok(rx) => crate::http::streamed(
                    200,
                    &[("content-type".into(), "text/event-stream".into())],
                    crate::http::text_stream(rx),
                ),
                Err(e) => crate::http::json_compact(e.http(), &e.to_problem()),
            }
        }
    }));
    let mut held = Vec::new();
    for _ in 0..MAX_SUBSCRIBERS {
        let (s, st) = watch(&path).await;
        assert_eq!(st, 200);
        held.push(s);
    }
    let (_, st) = watch(&path).await;
    assert_eq!(st, 429, "a ninth watcher is refused");
    drop(held.pop());
    let t0 = Instant::now();
    loop {
        let (s, st) = watch(&path).await;
        if st == 200 {
            held.push(s);
            break;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "the closed watcher's slot was never freed"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Serves the notify stream on a fresh control socket.
fn serve_watchers(path: &std::path::Path) -> Arc<Notifier> {
    let n = Notifier::new(NotifierOptions::default());
    let listener = crate::listen::bind_unix(path).unwrap();
    let nn: Arc<Notifier> = n.clone();
    tokio::spawn(crate::listen::serve_unix(listener, None, move |_inc| {
        let nn = nn.clone();
        async move {
            match nn.subscribe(Vec::new()) {
                Ok(rx) => crate::http::streamed(
                    200,
                    &[("content-type".into(), "text/event-stream".into())],
                    crate::http::text_stream(rx),
                ),
                Err(e) => crate::http::json_compact(e.http(), &e.to_problem()),
            }
        }
    }));
    n
}

/// Opens watchers until one is let in, for up to two seconds.
async fn slot_frees_within(path: &std::path::Path, held: &mut Vec<UnixStream>) -> bool {
    let t0 = Instant::now();
    loop {
        let (s, st) = watch(path).await;
        if st == 200 {
            held.push(s);
            return true;
        }
        if t0.elapsed() >= Duration::from_secs(2) {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Keeps reading a stream so hyper is never stuck writing, without
/// dropping the read half (that would be a full close).
fn drain<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut rd: R,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok(n) = rd.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    })
}

/// Ordinary control: a watcher that half-closes with no extra bytes frees
/// its slot while the stream is otherwise idle.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_closed_watcher_frees_its_notify_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    let _n = serve_watchers(&path);
    let mut held = Vec::new();
    for _ in 0..MAX_SUBSCRIBERS {
        let (s, st) = watch(&path).await;
        assert_eq!(st, 200);
        held.push(s);
    }
    held.pop().unwrap().shutdown().await.unwrap();
    assert!(
        slot_frees_within(&path, &mut held).await,
        "a half-close with no pipelined bytes never freed the slot"
    );
}

/// A watcher that writes past the 64 KiB read-ahead stash and then
/// half-closes still frees its slot: a full stash keeps reading, sees the
/// end of input, and the bytes past the limit fail closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_watcher_that_fills_the_read_ahead_stash_and_half_closes_frees_its_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    let _n = serve_watchers(&path);
    let mut readers = Vec::new();
    let mut writes = Vec::new();
    let payload = vec![b'A'; 64 * 1024 + 4096];
    for _ in 0..MAX_SUBSCRIBERS {
        let (s, st) = watch(&path).await;
        assert_eq!(st, 200);
        let (rd, mut wr) = s.into_split();
        readers.push(drain(rd));
        let wrote = tokio::time::timeout(Duration::from_secs(2), async {
            wr.write_all(&payload).await.unwrap();
            wr.shutdown().await.unwrap();
            wr
        })
        .await
        .expect("the pipelined write was accepted");
        // Hold the shut write half so the read half stays open.
        writes.push(wrote);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut held = Vec::new();
    assert!(
        slot_frees_within(&path, &mut held).await,
        "filling the 64 KiB read-ahead and half-closing left every notify slot taken"
    );
    drop(writes);
    drop(readers);
}

/// The MCP GET event stream has no slot cap, so a client that fills the
/// read-ahead stash and half-closes must still end its connection task;
/// otherwise each one is held until the process exits. The daemon ends
/// the connection, so the client's read half sees the end of input.
#[tokio::test(flavor = "multi_thread")]
async fn an_mcp_event_stream_that_fills_the_read_ahead_and_half_closes_ends_its_connection() {
    let w = super::World::bare().await;
    let port = w.daemon.gateway_port().unwrap();
    let sid = w.daemon.mcp.open_session(false).await;
    for overfill in [false, true] {
        let s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let (mut rd, mut wr) = s.into_split();
        wr.write_all(
            format!(
                "GET /mcp HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\naccept: text/event-stream\r\nmcp-session-id: {sid}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 4096];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut buf))
                .await
                .expect("the event stream answers")
                .unwrap();
            assert!(n > 0, "the event stream closed before answering");
            head.extend_from_slice(&buf[..n]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        let reader = drain(rd);
        if overfill {
            tokio::time::timeout(
                Duration::from_secs(2),
                wr.write_all(&vec![b'A'; 64 * 1024 + 4096]),
            )
            .await
            .expect("the pipelined write was accepted")
            .unwrap();
        }
        wr.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), reader)
                .await
                .is_ok(),
            "a half-closed MCP event stream (overfilled: {overfill}) kept its connection"
        );
        drop(wr);
    }
}

/// Bytes past a full read-ahead stash fail closed: the watcher that sends
/// them loses its slot even though its side of the connection stays open,
/// and the stash never grows past the limit to keep it.
#[tokio::test(flavor = "multi_thread")]
async fn a_watcher_that_writes_past_the_read_ahead_stash_loses_its_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    let _n = serve_watchers(&path);
    let mut readers = Vec::new();
    let mut writes = Vec::new();
    let payload = vec![b'A'; 64 * 1024 + 4096];
    for _ in 0..MAX_SUBSCRIBERS {
        let (s, st) = watch(&path).await;
        assert_eq!(st, 200);
        let (rd, mut wr) = s.into_split();
        readers.push(drain(rd));
        tokio::time::timeout(Duration::from_secs(2), wr.write_all(&payload))
            .await
            .expect("the pipelined write was accepted")
            .unwrap();
        // The write half stays open: no end of input is ever sent.
        writes.push(wr);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut held = Vec::new();
    assert!(
        slot_frees_within(&path, &mut held).await,
        "a watcher that overran the read-ahead stash kept its notify slot"
    );
    drop(writes);
    drop(readers);
}
