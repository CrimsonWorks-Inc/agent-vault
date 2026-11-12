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
    let model = model?;
    let rows = PRICES.iter().find(|(k, _)| *k == kind)?.1;
    let re = crate::jsre::compile(r"^(?:\d{8}|\d{4}-\d{2}-\d{2})$").expect("snapshot");
    rows.iter()
        .filter(|(prefix, _, _)| {
            model == *prefix
                || model
                    .strip_prefix(&format!("{prefix}-"))
                    .is_some_and(|s| re.is_match(s))
        })
        .max_by_key(|(prefix, _, _)| prefix.len())
        .map(|(_, input, output)| Price {
            input_micros_per_mtok: *input,
            output_micros_per_mtok: *output,
        })
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
    let result = Meter::default();
    let Some((_, default_output)) = DEFAULT_OUTPUT.iter().find(|(k, _)| *k == kind) else {
        return Ok(result);
    };
    let verb = input.method.unwrap_or("").to_uppercase();
    let path = input.path.unwrap_or("").split('?').next().unwrap_or("");
    let re = crate::jsre::compile(
        r"^/v1(?:beta)?/models/([^/:]+):(generateContent|streamGenerateContent|countTokens)$",
    )
    .expect("Google endpoint");
    let google = re.captures(path);
    if ["GET", "HEAD", "OPTIONS"].contains(&verb.as_str())
        || (verb == "POST"
            && ((kind == "anthropic" && path == "/v1/messages/count_tokens")
                || (kind == "google-genai"
                    && google.as_ref().is_some_and(|g| &g[2] == "countTokens"))))
    {
        return Ok(Meter {
            free: true,
            ..result
        });
    }
    let metered = verb == "POST"
        && ((kind == "anthropic" && path == "/v1/messages")
            || (kind == "openai"
                && [
                    "/v1/chat/completions",
                    "/v1/responses",
                    "/v1/completions",
                    "/v1/embeddings",
                ]
                .contains(&path))
            || (kind == "google-genai" && google.as_ref().is_some_and(|g| &g[2] != "countTokens")));
    if !metered {
        return Ok(Meter {
            unmodeled: true,
            ..result
        });
    }
    let unreadable = || {
        meter_fail(
            "spend_unparseable",
            "A metered request needs a readable JSON object body.",
        )
    };
    let ct = input.content_type.ok_or_else(unreadable)?;
    if !crate::jsre::compile(r"(?i)^application/(?:json|[\w.+-]+\+json)(?:\s*;|\s*$)")
        .expect("JSON content type")
        .is_match(ct)
    {
        return Err(unreadable());
    }
    let bytes = input.body.ok_or_else(unreadable)?;
    let text = std::str::from_utf8(bytes).map_err(|_| unreadable())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let json = crate::payload::parse_strict_json(text).map_err(|_| unreadable())?;
    if !json.is_object() {
        return Err(unreadable());
    }
    let model = if kind == "google-genai" {
        google.map(|g| g[1].into())
    } else {
        json["model"].as_str().map(str::to_owned)
    };
    let proposed = match kind {
        "anthropic" => &json["max_tokens"],
        "openai" => ["max_completion_tokens", "max_tokens", "max_output_tokens"]
            .into_iter()
            .find_map(|k| json.get(k).filter(|v| !v.is_null()))
            .unwrap_or(&serde_json::Value::Null),
        _ => &json["generationConfig"]["maxOutputTokens"],
    };
    let max_output = if path == "/v1/embeddings" {
        0
    } else {
        counter(proposed)
            .filter(|n| *n > 0)
            .unwrap_or(*default_output)
    };
    Ok(Meter {
        metered: true,
        model,
        max_output,
        input_estimate: (bytes.len() as u64).div_ceil(3),
        ..result
    })
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
    usage_body(kind, json)
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
    let parsed;
    let event = match event {
        SseEventData::Raw(bytes) => {
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
                return acc;
            };
            parsed = v;
            &parsed
        }
        SseEventData::Parsed(v) => v,
    };
    if !event.is_object() {
        return acc;
    }
    let mut usage = usage_from_body(kind, event);
    if kind == "openai" && event.get("response").is_some() {
        usage = usage_from_body(kind, &event["response"]);
    }
    if kind == "anthropic" {
        if event["type"] == "message_start" {
            usage = usage_from_body(kind, &event["message"]);
        }
        if event["type"] == "message_delta" {
            if let (Some(acc), Some(output)) = (acc, counter(&event["usage"]["output_tokens"])) {
                usage = Some(Usage {
                    input_tokens: acc.input_tokens,
                    output_tokens: output,
                });
            }
        }
    }
    usage
        .map(|u| Usage {
            input_tokens: acc.map_or(0, |a| a.input_tokens).max(u.input_tokens),
            output_tokens: acc.map_or(0, |a| a.output_tokens).max(u.output_tokens),
        })
        .or(acc)
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
    if !meter.metered {
        return Ok(Charge::default());
    }
    let price = price_of(kind, meter.model.as_deref());
    if opts.usd && price.is_none() {
        return Err(meter_fail(
            "spend_unpriced",
            "This model has no checked USD price; use a token budget or a priced model.",
        ));
    }
    amount(meter.input_estimate, meter.max_output, price)
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
    let Some(usage) = usage.filter(|u| {
        u.input_tokens <= crate::policy::MAX_SAFE_INTEGER
            && u.output_tokens <= crate::policy::MAX_SAFE_INTEGER
    }) else {
        return Ok(*reservation);
    };
    amount(
        usage.input_tokens,
        usage.output_tokens,
        price_of(kind, meter.model.as_deref()),
    )
}

fn meter_fail(rule: &str, detail: &str) -> crate::errors::VaultError {
    crate::errors::deny(
        crate::errors::ErrorCode::PolicyDenied,
        detail,
        crate::errors::DenyExtra {
            rule: Some(rule.into()),
            ..Default::default()
        },
    )
}
fn counter(v: &serde_json::Value) -> Option<u64> {
    crate::policy::budget_integer(v).filter(|_| v.is_number())
}
fn optional_counter(v: &serde_json::Value) -> Option<u64> {
    if v.is_null() {
        Some(0)
    } else {
        counter(v)
    }
}
fn usage_body(kind: &str, json: &serde_json::Value) -> Option<Usage> {
    if !json.is_object() {
        return None;
    }
    let (input, output) = match kind {
        "anthropic" => {
            let u = &json["usage"];
            let input = counter(&u["input_tokens"])?;
            let output = counter(&u["output_tokens"])?;
            let creation = optional_counter(&u["cache_creation_input_tokens"])?;
            let read = optional_counter(&u["cache_read_input_tokens"])?;
            (input.checked_add(creation)?.checked_add(read)?, output)
        }
        "openai" => {
            let u = &json["usage"];
            let input = counter(
                u.get("prompt_tokens")
                    .filter(|v| !v.is_null())
                    .unwrap_or(&u["input_tokens"]),
            )?;
            let out = u
                .get("completion_tokens")
                .filter(|v| !v.is_null())
                .or_else(|| u.get("output_tokens"));
            let output = if out.is_none() && counter(&u["total_tokens"]) == Some(input) {
                0
            } else {
                counter(out?)?
            };
            (input, output)
        }
        "google-genai" => {
            let u = &json["usageMetadata"];
            let input = counter(&u["promptTokenCount"])?;
            let thoughts = optional_counter(&u["thoughtsTokenCount"])?;
            let output = if u.get("candidatesTokenCount").is_none() && thoughts > 0 {
                0
            } else {
                counter(&u["candidatesTokenCount"])?
            };
            (input, output.checked_add(thoughts)?)
        }
        _ => return None,
    };
    (input <= crate::policy::MAX_SAFE_INTEGER && output <= crate::policy::MAX_SAFE_INTEGER)
        .then_some(Usage {
            input_tokens: input,
            output_tokens: output,
        })
}
fn amount(input: u64, output: u64, price: Option<Price>) -> Result<Charge> {
    let max = crate::policy::MAX_SAFE_INTEGER;
    if input > max || output > max || input.checked_add(output).is_none_or(|n| n > max) {
        return Err(meter_fail(
            "spend_unparseable",
            "Model token counters exceed the supported integer range.",
        ));
    }
    let micros = price.map_or(0, |p| {
        (u128::from(input) * u128::from(p.input_micros_per_mtok)
            + u128::from(output) * u128::from(p.output_micros_per_mtok))
        .div_ceil(1_000_000)
    });
    if micros > u128::from(max) {
        return Err(meter_fail(
            "spend_unparseable",
            "Model price exceeds the supported integer range.",
        ));
    }
    Ok(Charge {
        tokens: input + output,
        usd_micros: micros as u64,
    })
}
