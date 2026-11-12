//! Canonical serialization for anything that gets hashed: presence operation
//! hashes, approval request hashes and the audit chain. Ports
//! `src/core/canon.js`.
//!
//! Object keys are sorted by their UTF-8 bytes, floats are refused, arrays keep
//! their order. Two structurally equal values produce identical bytes.

use crate::secret::Key32;

/// Why a value cannot be canonicalized. Ports the `Error('canon: …')` throws
/// in `canonicalize` in `src/core/canon.js`. (`serde_json::Value` cannot hold
/// a non-finite number or `undefined`, so only the float case remains.)
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    /// `canon: floats are not canonicalizable`
    #[error("canon: floats are not canonicalizable")]
    Float,
}

/// The canonical JSON text of `value`. Ports `canonicalize` in
/// `src/core/canon.js`.
pub fn canonicalize(value: &serde_json::Value) -> Result<String, CanonError> {
    use serde_json::Value;
    Ok(match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            let v = n.as_f64().ok_or(CanonError::Float)?;
            if v.fract() != 0.0 {
                return Err(CanonError::Float);
            }
            if v == 0.0 {
                "0".into()
            } else if v.abs() < 1e21 {
                v.to_string()
            } else {
                let mut s = format!("{v:e}");
                if !s.contains("e-") {
                    s = s.replace('e', "e+");
                }
                s
            }
        }
        Value::String(s) => serde_json::to_string(s).expect("string serialization"),
        Value::Array(a) => format!(
            "[{}]",
            a.iter()
                .map(canonicalize)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        ),
        Value::Object(o) => {
            let mut keys: Vec<_> = o.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|k| Ok(format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("string serialization"),
                        canonicalize(&o[k])?
                    )))
                    .collect::<Result<Vec<_>, CanonError>>()?
                    .join(",")
            )
        }
    })
}

/// Lowercase hex SHA-256 of `canonicalize(value)`. Ports `hash` in
/// `src/core/canon.js`.
pub fn hash(value: &serde_json::Value) -> Result<String, CanonError> {
    Ok(sha256(canonicalize(value)?.as_bytes()))
}

/// Lowercase hex HMAC-SHA256 under `key` of `canonicalize(value)`. Ports
/// `hmac` in `src/core/canon.js`. Comparing two of these must be constant
/// time.
pub fn hmac(key: &Key32, value: &serde_json::Value) -> Result<String, CanonError> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.expose()).expect("HMAC accepts every key length");
    mac.update(canonicalize(value)?.as_bytes());
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Input to [`request_hash`]. Ports the destructured argument
/// `{ method, host, path, query, bodySha256, credentials, headers }` of
/// `requestHash` in `src/core/canon.js`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestHashInput<'a> {
    /// Request method; uppercased (`''` when absent).
    pub method: Option<&'a str>,
    /// Destination host; lowercased (`''` when absent).
    pub host: Option<&'a str>,
    /// Decided path (`'/'` when absent).
    pub path: Option<&'a str>,
    /// Query without `?` (`''` when absent).
    pub query: Option<&'a str>,
    /// Hex SHA-256 of the body (`bodySha256`, `''` when absent).
    pub body_sha256: Option<&'a str>,
    /// `<grant>:<field>` of every injected credential field; sorted.
    pub credentials: &'a [String],
    /// The headers that will be forwarded, in order; names lowercased and
    /// stably sorted by name only.
    pub headers: &'a [(String, String)],
}

/// The approval and idempotency key for a proxied request: lowercase hex
/// SHA-256 of the canonical `{method, host, path, query, body, credentials,
/// headers}` object. Ports `requestHash` in `src/core/canon.js`.
pub fn request_hash(input: &RequestHashInput<'_>) -> String {
    let mut credentials = input.credentials.to_vec();
    credentials.sort_by_key(|s| s.encode_utf16().collect::<Vec<_>>());
    let mut headers: Vec<_> = input
        .headers
        .iter()
        .map(|(n, v)| (n.to_lowercase(), v.clone()))
        .collect();
    headers.sort_by_key(|(name, _)| name.encode_utf16().collect::<Vec<_>>());
    hash(&serde_json::json!({"method":input.method.unwrap_or("").to_uppercase(),"host":input.host.unwrap_or("").to_lowercase(),"path":input.path.filter(|s| !s.is_empty()).unwrap_or("/"),"query":input.query.unwrap_or(""),"body":input.body_sha256.unwrap_or(""),"credentials":credentials,"headers":headers})).expect("request has canonical values")
}

/// Lowercase hex SHA-256 of `buf`. Ports `sha256` in `src/core/canon.js`.
pub fn sha256(buf: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(buf)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// JS JSON numbers use binary64 even when the input token spells an integer.
// Normalize before typed deserialization so 1.0 and 1 have the same meaning.
pub(crate) fn js_numbers(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value as V;
    match value {
        V::Number(n) => {
            if let Some(v) = n.as_f64() {
                if v.fract() == 0.0 {
                    if v >= 0.0 && v < (u64::MAX as f64) {
                        return V::from(v as u64);
                    }
                    if v < 0.0 && v >= i64::MIN as f64 {
                        return V::from(v as i64);
                    }
                }
            }
            V::Number(n)
        }
        V::Array(a) => V::Array(a.into_iter().map(js_numbers).collect()),
        V::Object(o) => V::Object(o.into_iter().map(|(k, v)| (k, js_numbers(v))).collect()),
        v => v,
    }
}

pub(crate) fn js_number_text(n: &serde_json::Number) -> String {
    let v = n.as_f64().expect("finite JSON number");
    if v == 0.0 {
        return "0".into();
    }
    if v.abs() >= 1e21 || v.abs() < 1e-6 {
        let mut s = format!("{v:e}");
        if !s.contains("e-") {
            s = s.replace('e', "e+");
        }
        s
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_hash_binds_headers_preserving_repeat_order() {
        assert_eq!(
            canonicalize(&serde_json::json!({"z":0,"a":[true,null]})).unwrap(),
            "{\"a\":[true,null],\"z\":0}"
        );
        assert!(canonicalize(&serde_json::json!(0.5)).is_err());
        let h = vec![
            ("X-HTTP-Method-Override".into(), "POST".into()),
            ("X-HTTP-Method-Override".into(), "DELETE".into()),
        ];
        let mut reversed = h.clone();
        reversed.reverse();
        let a = request_hash(&RequestHashInput {
            headers: &h,
            ..Default::default()
        });
        assert_ne!(
            a,
            request_hash(&RequestHashInput {
                headers: &reversed,
                ..Default::default()
            })
        );
        assert_ne!(a, request_hash(&Default::default()));
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hmac(
                &Key32::from_bytes([42; 32]),
                &serde_json::json!({"b":2,"a":1})
            )
            .unwrap(),
            hmac(
                &Key32::from_bytes([42; 32]),
                &serde_json::json!({"a":1,"b":2})
            )
            .unwrap()
        );
    }
}
