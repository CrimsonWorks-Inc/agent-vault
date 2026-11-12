//! Read-ahead stash edges, adopted from the review-daemon-2 probes:
//! pipelining, keep-alive, late bodies, body limits, half-close, a TCP reset
//! as a read error, and gateway frames that stay off the read-ahead path.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};

use std::os::unix::io::AsRawFd;

use crate::http::AvBody;
use crate::notify::{Notifier, NotifierOptions, MAX_SUBSCRIBERS};

fn echo_or_stream(inc: crate::server::Incoming, hold: bool) -> crate::http::Resp {
    if inc.target.starts_with("/stream") {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = tx.send("event: hi\ndata: 1\n\n".into());
        tokio::spawn(async move {
            if hold {
                std::future::pending::<()>().await;
            } else {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            drop(tx);
        });
        return crate::http::streamed(
            200,
            &[("content-type".into(), "text/event-stream".into())],
            crate::http::text_stream(rx),
        );
    }
    if inc.target.starts_with("/frames") {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx.send(b"one\n".to_vec()).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = tx.send(b"two\n".to_vec()).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = tx.send(b"three\n".to_vec()).await;
        });
        return crate::http::streamed(
            200,
            &[("content-type".into(), "text/plain".into())],
            AvBody::Frames(rx),
        );
    }
    if inc.target.starts_with("/late") {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = tx.send("one\n".into());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let _ = tx.send("two\n".into());
        });
        return crate::http::streamed(
            200,
            &[("content-type".into(), "text/plain".into())],
            crate::http::text_stream(rx),
        );
    }
    crate::http::response(
        200,
        &[("content-type".into(), "text/plain".into())],
        inc.body,
    )
}

fn serve_unix_app(path: &std::path::Path, hold_stream: bool) {
    let listener = crate::listen::bind_unix(path).unwrap();
    tokio::spawn(crate::listen::serve_unix(listener, None, move |inc| {
        let hold_stream = hold_stream;
        async move { echo_or_stream(inc, hold_stream) }
    }));
}

async fn read_headers(rd: &mut (impl AsyncReadExt + Unpin)) -> (String, Vec<u8>) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut buf))
            .await
            .expect("headers")
            .unwrap();
        assert!(n > 0, "closed before headers");
        raw.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let idx = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body = raw[idx..].to_vec();
    (text, body)
}

#[allow(unsafe_code)]
fn reset(stream: TcpStream) {
    let std_stream = stream.into_std().unwrap();
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let rc = unsafe {
        libc::setsockopt(
            std_stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "SO_LINGER");
    drop(std_stream);
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        if n.eq_ignore_ascii_case("content-length") {
            v.trim().parse().ok()
        } else {
            None
        }
    })
}

async fn read_full(rd: &mut (impl AsyncReadExt + Unpin), headers: &str, already: &[u8]) -> Vec<u8> {
    let need = content_length(headers).expect("content-length");
    let mut body = already.to_vec();
    let mut buf = [0u8; 8192];
    while body.len() < need {
        let n = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut buf))
            .await
            .expect("body")
            .unwrap();
        assert!(n > 0, "body ended early");
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(need);
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_stashed_during_a_text_stream_reaches_hyper_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    serve_unix_app(&path, false);
    let mut s = UnixStream::connect(&path).await.unwrap();
    s.write_all(b"GET /stream HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&raw).contains("event: hi") {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("stream")
            .unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&buf[..n]);
    }
    let req = b"POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: 13\r\n\r\nhello-stashed";
    s.write_all(req).await.unwrap();
    while !String::from_utf8_lossy(&raw).contains("hello-stashed") {
        let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf))
            .await
            .expect("the stashed request was not answered")
            .unwrap();
        assert!(n > 0, "connection closed before the stashed body came back");
        raw.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("HTTP/1.1 200"));
    assert!(text.contains("hello-stashed"));
    assert!(!text.contains("hello-stashed-EXTRA"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_request_past_a_full_stash_ends_the_stream_and_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    serve_unix_app(&path, true);
    let mut s = UnixStream::connect(&path).await.unwrap();
    s.write_all(b"GET /stream HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&raw).contains("event: hi") {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&buf[..n]);
    }
    let mut big =
        b"POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: 70000\r\n\r\n".to_vec();
    big.extend(std::iter::repeat_n(b'B', 70000));
    let write = tokio::time::timeout(Duration::from_secs(3), s.write_all(&big)).await;
    // The server fail-closes once the stash is full, so the write may be cut.
    let _ = write;
    let rest = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    assert!(
        rest.is_ok(),
        "a request past the full stash left the text stream open"
    );
    let text = String::from_utf8_lossy(&raw);
    assert!(
        !text.contains(&"B".repeat(70000)),
        "the tail past the stash was served"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exactly_64kib_then_a_later_half_close_frees_the_watcher() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    let n = Notifier::new(NotifierOptions::default());
    let listener = crate::listen::bind_unix(&path).unwrap();
    let nn = n.clone();
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
        let mut s = UnixStream::connect(&path).await.unwrap();
        s.write_all(b"GET /v1/pending/stream HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(2).any(|w| w == b"\r\n") {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert!(String::from_utf8_lossy(&got).contains(" 200 "));
        held.push(s);
    }
    let victim = held.pop().unwrap();
    let (mut rd, mut wr) = victim.into_split();
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok(n) = rd.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(2), wr.write_all(&vec![b'A'; 64 * 1024]))
        .await
        .expect("64 KiB was not accepted")
        .unwrap();
    // Parked on a full stash: the half-close is not in the buffer yet.
    tokio::time::sleep(Duration::from_millis(200)).await;
    wr.shutdown().await.unwrap();
    let t0 = std::time::Instant::now();
    let mut freed = false;
    while t0.elapsed() < Duration::from_secs(2) {
        let mut s = UnixStream::connect(&path).await.unwrap();
        s.write_all(b"GET /v1/pending/stream HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while !got.windows(2).any(|w| w == b"\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
                .await
                .expect("status")
                .unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        if String::from_utf8_lossy(&got).contains(" 200 ") {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        freed,
        "EOF behind an already-full stash never woke the watcher"
    );
    drop(held);
    drop(wr);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_arrives_after_the_headers_is_unchanged_and_over_16mib_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    serve_unix_app(&path, false);
    let mut s = UnixStream::connect(&path).await.unwrap();
    let n = 100_000;
    s.write_all(
        format!("POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: {n}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let payload = vec![b'C'; n];
    s.write_all(&payload).await.unwrap();
    let (headers, already) = read_headers(&mut s).await;
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    let body = read_full(&mut s, &headers, &already).await;
    assert_eq!(body, payload);

    let s = UnixStream::connect(&path).await.unwrap();
    let (mut rd, mut wr) = s.into_split();
    let over = crate::server::MAX_BODY + 1;
    wr.write_all(
        format!("POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: {over}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let reader = tokio::spawn(async move {
        let (headers, already) = read_headers(&mut rd).await;
        let body = read_full(&mut rd, &headers, &already).await;
        (headers, body)
    });
    let writer = tokio::spawn(async move {
        let chunk = vec![b'D'; 64 * 1024];
        let mut sent = 0usize;
        while sent < over {
            let m = chunk.len().min(over - sent);
            if wr.write_all(&chunk[..m]).await.is_err() {
                break;
            }
            sent += m;
        }
    });
    let (headers, body) = tokio::time::timeout(Duration::from_secs(15), reader)
        .await
        .expect("413")
        .unwrap();
    writer.abort();
    let msg = headers + &String::from_utf8_lossy(&body);
    assert!(msg.starts_with("HTTP/1.1 413"), "{msg}");
    assert!(msg.contains("body exceeds 16 MiB"), "{msg}");
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_alive_serves_a_second_plain_request_after_the_first_response() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    serve_unix_app(&path, false);
    let mut s = UnixStream::connect(&path).await.unwrap();
    for body in ["one", "two"] {
        let req = format!(
            "POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let (headers, already) = read_headers(&mut s).await;
        assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
        let got = read_full(&mut s, &headers, &already).await;
        assert_eq!(got, body.as_bytes());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_frames_keep_going_after_extra_bytes_and_a_half_close() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    serve_unix_app(&path, false);
    let s = UnixStream::connect(&path).await.unwrap();
    let (mut rd, mut wr) = s.into_split();
    wr.write_all(b"GET /frames HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !raw.windows(4).any(|w| w == b"one\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut buf))
            .await
            .expect("frame one")
            .unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&buf[..n]);
    }
    wr.write_all(&[b'Z'; 64]).await.unwrap();
    wr.shutdown().await.unwrap();
    while !raw.windows(6).any(|w| w == b"three\n") {
        let n = tokio::time::timeout(Duration::from_secs(3), rd.read(&mut buf))
            .await
            .expect("frames ended when the client half-closed")
            .unwrap();
        assert!(n > 0, "frames closed before three");
        raw.extend_from_slice(&buf[..n]);
    }
    assert!(raw.windows(4).any(|w| w == b"two\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_text_stream_ends_on_half_close_before_a_later_frame() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctl.sock");
    serve_unix_app(&path, false);
    let s = UnixStream::connect(&path).await.unwrap();
    let (mut rd, mut wr) = s.into_split();
    wr.write_all(b"GET /late HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !raw.windows(4).any(|w| w == b"one\n") {
        let n = rd.read(&mut buf).await.unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&buf[..n]);
    }
    wr.shutdown().await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let n = rd.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
    })
    .await;
    assert!(ended.is_ok(), "half-close did not end the text stream");
    assert!(
        !raw.windows(4).any(|w| w == b"two\n"),
        "a frame after the half-close was still written"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_reset_is_a_read_error_and_ends_the_text_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let reset_task = tokio::spawn(async move {
        reset(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    });
    let (mut srv, _) = listener.accept().await.unwrap();
    reset_task.await.unwrap();
    let mut buf = [0u8; 16];
    let err = srv
        .read(&mut buf)
        .await
        .expect_err("reset was not a read error");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset,
        "raw {} kind {:?}",
        err.raw_os_error().unwrap_or(0),
        err.kind()
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (gone_tx, gone_rx) = tokio::sync::oneshot::channel::<()>();
    let gone = std::sync::Arc::new(std::sync::Mutex::new(Some(gone_tx)));
    tokio::spawn(crate::listen::serve_tcp(
        listener,
        None,
        move |inc, _peer| {
            let gone = gone.clone();
            async move {
                if inc.target.starts_with("/stream") {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                    let _ = tx.send("event: hi\ndata: 1\n\n".into());
                    // No further writes. The body ends only when poll_closed
                    // sees the reset, which drops this sender.
                    tokio::spawn(async move {
                        tx.closed().await;
                        if let Some(tx) = gone.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    });
                    crate::http::streamed(
                        200,
                        &[("content-type".into(), "text/event-stream".into())],
                        crate::http::text_stream(rx),
                    )
                } else {
                    crate::http::response(404, &[], Vec::new())
                }
            }
        },
    ));
    let mut cli = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    cli.write_all(b"GET /stream HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&raw).contains("event: hi") {
        let n = cli.read(&mut buf).await.unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&buf[..n]);
    }
    reset(cli);
    tokio::time::timeout(Duration::from_secs(2), gone_rx)
        .await
        .expect("a reset did not end the text stream")
        .unwrap();
}
