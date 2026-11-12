//! What the pipeline sends upstream and gets back, and the seam a test uses
//! to replace the network (the JS `fetchImpl` option of `new Pipeline`).
//! The default is [`crate::connectors::pinning::PinnedUpstream`].

use std::future::Future;
use std::pin::Pin;

use av_core::errors::VaultError;
use serde_json::Value;
use tokio::sync::mpsc;

/// A boxed future, as the trait returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The `pins` argument: `pinsFor`'s `null` (none), `false` (a table that
/// cannot be read, which is pinned, never unpinned) or a list.
#[derive(Debug, Clone, PartialEq)]
pub enum Pins {
    /// No pins for this host.
    None,
    /// A table or entry of the wrong shape; refused as `pin_format`.
    Unreadable,
    /// The stored list, as stored (checked by `pinListState`).
    List(Vec<Value>),
}

impl Pins {
    /// From av-core's lookup.
    pub fn from_lookup(l: av_core::pins::PinLookup) -> Pins {
        match l {
            av_core::pins::PinLookup::NoPins => Pins::None,
            av_core::pins::PinLookup::Malformed => Pins::Unreadable,
            av_core::pins::PinLookup::Found(v) => Pins::List(v),
        }
    }

    /// Whether `pinsFor` returned something other than `null`.
    pub fn is_some(&self) -> bool {
        !matches!(self, Pins::None)
    }

    /// As the JSON value `pinListState` reads.
    pub fn as_value(&self) -> Value {
        match self {
            Pins::None => Value::Null,
            Pins::Unreadable => Value::Bool(false),
            Pins::List(v) => Value::Array(v.clone()),
        }
    }
}

/// One outbound request. Each header is one line (`pinnedRequest` refuses a
/// non-string value).
#[derive(Clone)]
pub struct UpstreamRequest {
    /// The full URL.
    pub url: String,
    /// Method.
    pub method: String,
    /// Headers, one value each, names as written.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Option<Vec<u8>>,
    /// Pins for the URL host.
    pub pins: Pins,
}

impl std::fmt::Debug for UpstreamRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Headers and body carry the substituted secret.
        f.debug_struct("UpstreamRequest")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// A response body: whole, or streamed in chunks (an error ends it).
pub enum Body {
    /// Already buffered (the JS `res.body`).
    Full(Vec<u8>),
    /// A stream (the JS `res.res`). Dropping it closes the connection.
    Stream(mpsc::Receiver<Result<Vec<u8>, String>>),
}

impl Body {
    /// A stream from chunks, for tests.
    pub fn chunks(chunks: Vec<Result<Vec<u8>, String>>) -> Body {
        let (tx, rx) = mpsc::channel(chunks.len().max(1));
        for c in chunks {
            let _ = tx.try_send(c);
        }
        Body::Stream(rx)
    }
}

/// One upstream answer. Header names are lower-cased; repeats are joined
/// with `, ` as Node's `res.headers` does (`set-cookie` likewise; the
/// pipeline drops it).
pub struct UpstreamResponse {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Body,
}

impl UpstreamResponse {
    /// The first header named `name` (lower-case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// Why an upstream request failed. `code` is the Node error code the JS
/// reads (`ENOTFOUND`, `ECONNREFUSED`, `CERT_HAS_EXPIRED`, `AV_PIN_MISMATCH`,
/// ...); `vault` carries a `VaultError` the connector raised itself
/// (`host_mismatch`, `header_format`).
#[derive(Debug, Clone, Default)]
pub struct UpstreamError {
    /// Node-style error code.
    pub code: String,
    /// Message (never contains a header value).
    pub message: String,
    /// Pin refusals: `plaintext`, `pin_format`, `leaf_expired`, ...
    pub reason: Option<String>,
    /// Pin refusals: the SPKI pins the peer presented.
    pub presented: Vec<String>,
    /// A refusal the connector made before connecting.
    pub vault: Option<VaultError>,
}

impl UpstreamError {
    /// An error with a code and message.
    pub fn new(code: &str, message: impl Into<String>) -> UpstreamError {
        UpstreamError {
            code: code.into(),
            message: message.into(),
            ..Default::default()
        }
    }
}

/// The network, replaceable.
pub trait Upstream: Send + Sync {
    /// Send one request; redirects are never followed here.
    fn send(&self, req: UpstreamRequest) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>>;
}
