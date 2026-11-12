//! HTTP plumbing shared by the gateway, the control socket and the UI
//! server: a response body that is either whole or a stream of frames, a
//! bounded body reader (`readBody`), and the URL reading Node does
//! (`new URL(req.url, base)`, which normalises dot segments and encodes the
//! way WHATWG says).

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame, Incoming};
use serde_json::Value;
use tokio::sync::mpsc;

/// A response body: whole, or frames from a channel until it closes.
pub enum AvBody {
    /// Whole.
    Full(Option<Bytes>),
    /// Streamed bytes.
    Frames(mpsc::Receiver<Vec<u8>>),
    /// Streamed text (the notifier's).
    Text(mpsc::UnboundedReceiver<String>),
}

impl hyper::body::Body for AvBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            AvBody::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            AvBody::Frames(rx) => rx.poll_recv(cx).map(|o| o.map(|v| Ok(Frame::data(Bytes::from(v))))),
            AvBody::Text(rx) => rx.poll_recv(cx).map(|o| o.map(|v| Ok(Frame::data(Bytes::from(v))))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, AvBody::Full(None))
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            AvBody::Full(Some(b)) => hyper::body::SizeHint::with_exact(b.len() as u64),
            AvBody::Full(None) => hyper::body::SizeHint::with_exact(0),
            _ => hyper::body::SizeHint::default(),
        }
    }
}

/// A response.
pub type Resp = hyper::Response<AvBody>;

/// A whole response.
pub fn response(status: u16, headers: &[(String, String)], body: Vec<u8>) -> Resp {
    let mut r = hyper::Response::new(AvBody::Full(Some(Bytes::from(body))));
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    for (n, v) in headers {
        if let (Ok(n), Ok(v)) = (hyper::header::HeaderName::from_bytes(n.as_bytes()), hyper::header::HeaderValue::from_bytes(&crate::util::latin1_bytes(v))) {
            r.headers_mut().append(n, v);
        }
    }
    r
}

/// A streamed response.
pub fn streamed(status: u16, headers: &[(String, String)], body: AvBody) -> Resp {
    let mut r = response(status, headers, Vec::new());
    *r.body_mut() = body;
    r
}

/// `json(status, obj)` with `JSON.stringify(obj, null, 2)` and extra headers.
pub fn json_pretty(status: u16, obj: &Value, extra: &[(String, String)]) -> Resp {
    let mut h = vec![("content-type".to_string(), "application/json".to_string())];
    for (n, v) in extra {
        h.retain(|(k, _)| k != n);
        h.push((n.clone(), v.clone()));
    }
    response(status, &h, crate::util::js_pretty(obj).into_bytes())
}

/// `readBody(req, res)`: the body, or the 413 to answer with past `max`.
pub async fn read_body(body: Incoming, max: usize) -> Result<Vec<u8>, Resp> {
    let mut body = body;
    let mut out = Vec::new();
    loop {
        match body.frame().await {
            None => return Ok(out),
            Some(Err(_)) => return Err(response(400, &[], Vec::new())),
            Some(Ok(f)) => {
                if let Ok(d) = f.into_data() {
                    out.extend_from_slice(&d);
                    if out.len() > max {
                        return Err(json_compact(413, &serde_json::json!({"code": "AV_UNSCANNABLE", "detail": "body exceeds 16 MiB"})));
                    }
                }
            }
        }
    }
}

/// `res.end(JSON.stringify(obj))` with `content-type: application/json`.
pub fn json_compact(status: u16, obj: &Value) -> Resp {
    response(status, &[("content-type".into(), "application/json".into())], crate::util::js_stringify(obj).into_bytes())
}

/// `new URL(req.url, base)`: `(pathname, search without '?')`, or `None`
/// where Node's parser throws.
pub fn parse_target(raw: &str, base: &str) -> Option<(String, String)> {
    let base = url::Url::parse(base).ok()?;
    let u = base.join(raw).ok()?;
    Some((u.path().to_string(), u.query().unwrap_or("").to_string()))
}
