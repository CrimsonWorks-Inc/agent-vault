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
