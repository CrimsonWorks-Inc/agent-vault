//! Model token metering and spend estimates for the metered connector kinds.
//! Ports `src/core/model-usage.js`.
//!
//! Prices are standard first-party list prices in USD microdollars per million
//! tokens. Estimates exclude provider-specific tool fees, caching discounts
//! and tiers.

use serde::{Deserialize, Serialize};

use crate::errors::Result;

/// Version label of the [`PRICES`] table. Ports `PRICES_VERSION` in
/// `src/core/model-usage.js`.
pub const PRICES_VERSION: &str = "2026-10-25";

/// One price row: model prefix, input and output USD micros per million
/// tokens. Ports the `[prefix, input, output]` rows of `PRICES` in
/// `src/core/model-usage.js`.
pub type PriceRow = (&'static str, u64, u64);

/// Per-kind price rows, verbatim. Ports `PRICES` in
/// `src/core/model-usage.js`.
pub const PRICES: &[(&str, &[PriceRow])] = &[
    // https://developers.openai.com/api/docs/models/gpt-4.1-mini
    ("openai", &[("gpt-4.1-mini", 400_000, 1_600_000)]),
    // https://platform.claude.com/docs/en/about-claude/pricing
    (
        "anthropic",
        &[
            ("claude-sonnet-4-5", 3_000_000, 15_000_000),
            ("claude-sonnet-4-0", 3_000_000, 15_000_000),
            ("claude-sonnet-4", 3_000_000, 15_000_000),
        ],
    ),
    // https://ai.google.dev/gemini-api/docs/pricing (standard text input/output)
    (
        "google-genai",
        &[
            ("gemini-2.5-flash-lite", 100_000, 400_000),
            ("gemini-2.5-flash", 300_000, 2_500_000),
        ],
    ),
];

/// Output tokens reserved when a request names no maximum. Ports
/// `DEFAULT_OUTPUT` in `src/core/model-usage.js`.
pub const DEFAULT_OUTPUT: &[(&str, u64)] = &[
    ("anthropic", 4096),
    ("openai", 16384),
    ("google-genai", 8192),
];

/// The connector kinds a spend limit applies to; everything else ignores it.
/// Ports `METERED_KINDS` in `src/core/model-usage.js`.
pub const METERED_KINDS: &[&str] = &["anthropic", "openai", "google-genai"];

/// A model's price. Ports the object returned by `priceOf` in
/// `src/core/model-usage.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Price {
    /// USD micros per million input tokens.
    pub input_micros_per_mtok: u64,
    /// USD micros per million output tokens.
    pub output_micros_per_mtok: u64,
}

/// The price for `kind`/`model`: an exact prefix match or a dated snapshot of
/// the longest known prefix (`-YYYYMMDD` or `-YYYY-MM-DD`); `None` for unknown
/// kinds and unpriced models. Ports `priceOf` in `src/core/model-usage.js`.
pub fn price_of(kind: &str, model: Option<&str>) -> Option<Price> {
    todo!()
}

/// The original request bytes to meter, before credentials are injected.
/// Ports the `{ method, path, contentType, body }` argument of `meterRequest`
/// in `src/core/model-usage.js`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MeterInput<'a> {
    /// Request method.
    pub method: Option<&'a str>,
    /// Path, possibly with a query.
    pub path: Option<&'a str>,
    /// Content-Type header value.
    pub content_type: Option<&'a str>,
    /// Request body bytes.
    pub body: Option<&'a [u8]>,
}

/// What a request will cost at most. Ports the object returned by
/// `meterRequest` in `src/core/model-usage.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Meter {
    /// A metered generation endpoint.
    pub metered: bool,
    /// A request that cannot spend tokens (safe methods, count-tokens).
    pub free: bool,
    /// The model named, if any.
    pub model: Option<String>,
    /// Output tokens reserved.
    pub max_output: u64,
    /// Input tokens estimated as `ceil(body bytes / 3)`.
    pub input_estimate: u64,
    /// A request to a metered kind on an endpoint this module does not model.
    pub unmodeled: bool,
}

/// Inspect a request to a metered kind. Refuses (`AV_POLICY_DENIED`, rule
/// `spend_unparseable`) a metered request without a readable JSON object
/// body. Ports `meterRequest` in `src/core/model-usage.js`.
pub fn meter_request(kind: &str, input: &MeterInput<'_>) -> Result<Meter> {
    todo!()
}

/// Token counters reported by a provider. Ports the
/// `{ input_tokens, output_tokens }` objects of `src/core/model-usage.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Input tokens (including cache creation and reads for Anthropic).
    pub input_tokens: u64,
    /// Output tokens (including thinking tokens for Google).
    pub output_tokens: u64,
}

/// Usage from a complete response body, or `None` for absent, partial or
/// malformed usage. Ports `usageFromBody` in `src/core/model-usage.js`.
pub fn usage_from_body(kind: &str, json: &serde_json::Value) -> Option<Usage> {
    todo!()
}

/// One SSE `data:` payload, as text or already parsed. Ports the `eventData`
/// argument of `usageFromEvent` in `src/core/model-usage.js`.
#[derive(Debug, Clone, Copy)]
pub enum SseEventData<'a> {
    /// JSON text (a string or Buffer in the JS).
    Raw(&'a [u8]),
    /// An already-parsed value.
    Parsed(&'a serde_json::Value),
}

/// Fold one SSE event into the running usage. Counters are cumulative and
/// never added twice; an unreadable event returns `acc` unchanged. Ports
/// `usageFromEvent` in `src/core/model-usage.js`.
pub fn usage_from_event(kind: &str, event: SseEventData<'_>, acc: Option<Usage>) -> Option<Usage> {
    todo!()
}

/// A token and USD amount (reserved or charged). Ports the
/// `{ tokens, usd_micros }` objects of `src/core/model-usage.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Charge {
    /// Input plus output tokens.
    pub tokens: u64,
    /// USD micros, rounded up; 0 for an unpriced model.
    pub usd_micros: u64,
}

/// Options for [`reservation_for`]. Ports the `{ usd = false }` argument of
/// `reservationFor` in `src/core/model-usage.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReservationOptions {
    /// A USD limit applies, so an unpriced model is refused.
    pub usd: bool,
}

/// The amount to reserve before sending. Zero for an unmetered request;
/// refuses `spend_unpriced` when `usd` is set and the model has no price, and
/// `spend_unparseable` when counters overflow the safe integer range. Ports
/// `reservationFor` in `src/core/model-usage.js`.
pub fn reservation_for(kind: &str, meter: &Meter, opts: ReservationOptions) -> Result<Charge> {
    todo!()
}

/// The amount to charge after the response: the reservation when `usage` is
/// absent or unreadable (an aborted stream must pass `None`), else the actual
/// usage priced. Ports `chargeFor` in `src/core/model-usage.js`.
pub fn charge_for(
    kind: &str,
    meter: &Meter,
    reservation: &Charge,
    usage: Option<&Usage>,
) -> Result<Charge> {
    todo!()
}
