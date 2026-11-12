//! Small helpers the daemon modules share: JavaScript-compatible JSON text,
//! latin1 byte strings, clocks and random ids. Nothing here has a JS module
//! of its own; each helper says which JS expression it reproduces.

use serde_json::{Map, Value};

/// `Date.now()`.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `new Date(ms).toISOString()`: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso_of_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            millis
        ),
        Err(_) => "1970-01-01T00:00:00.000Z".into(),
    }
}

/// `new Date().toISOString()`.
pub fn iso_now() -> String {
    iso_of_ms(now_ms())
}

/// `Date.parse(text)` for the ISO forms the daemon writes and accepts:
/// milliseconds since the epoch, or `None` where JS would give `NaN`.
pub fn parse_iso_ms(text: &str) -> Option<i64> {
    let t = text.trim();
    // Date-only: midnight UTC, as JS reads `YYYY-MM-DD`.
    if t.len() == 10 && t.as_bytes()[4] == b'-' && t.as_bytes()[7] == b'-' {
        let d = time::Date::parse(t, time::macros::format_description!("[year]-[month]-[day]")).ok()?;
        return Some(d.midnight().assume_utc().unix_timestamp() * 1000);
    }
    let parsed = time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
        .or_else(|_| {
            // JS also takes `YYYY-MM-DDTHH:MM[:SS[.mmm]]` with no zone as
            // local time; the daemon never writes that, and treating it as
            // UTC is the only reading that does not depend on the host.
            time::PrimitiveDateTime::parse(
                t,
                time::macros::format_description!(
                    version = 2,
                    "[year]-[month]-[day]T[hour]:[minute][optional [:[second][optional [.[subsecond]]]]]"
                ),
            )
            .map(|p| p.assume_utc())
        })
        .ok()?;
    Some((parsed.unix_timestamp_nanos() / 1_000_000) as i64)
}

/// `randomBytes(n).toString('base64url')`.
pub fn random_b64url(n: usize) -> String {
    use base64::Engine;
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("the OS random source is available");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}

/// Random bytes from the OS.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the OS random source is available");
    buf
}

/// `Buffer.from(bytes).toString('latin1')`: one char per byte.
pub fn latin1_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// `Buffer.from(text, 'latin1')`: each char's low byte, as Node writes it.
pub fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars().map(|c| (c as u32 & 0xff) as u8).collect()
}

/// `Buffer.from(text, 'utf8').toString('base64')`-style helpers.
pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Node's lenient `Buffer.from(text, 'base64')`: characters outside the
/// alphabet are skipped, `-`/`_` are read as `+`/`/`, padding is optional,
/// and decoding stops at the first `=`.
pub fn b64_lenient(text: &str) -> Vec<u8> {
    let mut vals = Vec::with_capacity(text.len());
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        vals.push(v);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let n = chunk.len();
        let mut acc = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            acc |= (*v as u32) << (18 - 6 * i);
        }
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
    }
    out
}

/// `Buffer.from(text, 'base64url')` (Node's reader is the lenient one).
pub fn b64url_lenient(text: &str) -> Vec<u8> {
    b64_lenient(text)
}

/// `Buffer.from(bytes).toString('base64url')`.
pub fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hex.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(data))
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

/// Constant-time equality of two byte strings of any length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ------------------------------------------------------------------ JSON

/// `JSON.stringify(value)`.
pub fn js_stringify(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, None, 0);
    out
}

/// `JSON.stringify(value, null, 2)`.
pub fn js_pretty(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, Some(2), 0);
    out
}

/// `JSON.stringify(value, keys)` with an array replacer: only these keys,
/// in this order, at every depth (arrays keep every element).
pub fn js_stringify_keys(value: &Value, keys: &[String]) -> String {
    fn go(out: &mut String, v: &Value, keys: &[String]) {
        match v {
            Value::Object(m) => {
                out.push('{');
                let mut first = true;
                for k in keys {
                    if let Some(x) = m.get(k) {
                        if !first {
                            out.push(',');
                        }
                        first = false;
                        write_string(out, k);
                        out.push(':');
                        go(out, x, keys);
                    }
                }
                out.push('}');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    go(out, x, keys);
                }
                out.push(']');
            }
            other => write_value(out, other, None, 0),
        }
    }
    let mut out = String::new();
    go(&mut out, value, keys);
    out
}

fn write_value(out: &mut String, v: &Value, indent: Option<usize>, depth: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&js_number(n)),
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                write_value(out, x, indent, depth + 1);
            }
            newline(out, indent, depth);
            out.push(']');
        }
        Value::Object(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                write_string(out, k);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_value(out, x, indent, depth + 1);
            }
            newline(out, indent, depth);
            out.push('}');
        }
    }
}

fn newline(out: &mut String, indent: Option<usize>, depth: usize) {
    if let Some(n) = indent {
        out.push('\n');
        for _ in 0..n * depth {
            out.push(' ');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A number as JavaScript's `String(n)` writes it.
pub fn js_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    js_f64(n.as_f64().unwrap_or(f64::NAN))
}

/// `String(x)` for a double.
pub fn js_f64(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if x == 0.0 {
        return "0".into();
    }
    // Shortest round-trip digits and exponent, then JS's layout rules.
    let e = format!("{:e}", x.abs());
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    let k = digits.len() as i32;
    let n = exp + 1;
    let sign = if x < 0.0 { "-" } else { "" };
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let es = if e >= 0 { format!("+{e}") } else { e.to_string() };
        if k == 1 {
            format!("{digits}e{es}")
        } else {
            format!("{}.{}e{es}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

/// A whole-number JSON value from an `f64` the way JS holds numbers: an
/// integer when it is one, else a double.
pub fn num(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() < 9.007_199_254_740_992e15 {
        Value::from(x as i64)
    } else {
        serde_json::Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// `typeof v === 'number' && Number.isInteger(v)` and in u64 range, as u64.
pub fn as_whole(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f <= 9.007_199_254_740_991e15)
                .map(|f| f as u64)
        }),
        _ => None,
    }
}

/// `Number.isInteger(v)` (any sign) as i64.
pub fn as_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64()
                .filter(|f| f.fract() == 0.0 && f.abs() <= 9.007_199_254_740_991e15)
                .map(|f| f as i64)
        }),
        _ => None,
    }
}

/// `typeof v === 'number' && Number.isFinite(v)`.
pub fn as_finite(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

/// `v !== undefined && v !== null` for an optional field.
pub fn present(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

/// A JSON object from pairs, in order (insertion order, like a JS literal).
pub fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// `v !== null && typeof v === 'object' && !Array.isArray(v)`.
pub fn is_object(v: &Value) -> bool {
    v.is_object()
}

/// Truthiness of a JSON value, as JavaScript reads it.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// `String(v)` for a JSON value (objects as `[object Object]`, arrays
/// joined with `,`).
pub fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number(n),
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .map(|x| if x.is_null() { String::new() } else { js_string(x) })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b);
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `URLSearchParams.get(name)` over a raw query string (no leading `?`):
/// the first value, `+` read as space, percent-decoded leniently.
pub fn search_param(query: &str, name: &str) -> Option<String> {
    search_params(query).into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Every `(name, value)` of a raw query string, as `URLSearchParams` reads it.
pub fn search_params(query: &str) -> Vec<(String, String)> {
    let q = query.strip_prefix('?').unwrap_or(query);
    url::form_urlencoded::parse(q.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// `URLSearchParams.getAll(name)`.
pub fn search_all(query: &str, name: &str) -> Vec<String> {
    search_params(query).into_iter().filter(|(k, _)| k == name).map(|(_, v)| v).collect()
}

/// `URLSearchParams.toString()` for pairs.
pub fn search_string(pairs: &[(String, String)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbers_print_as_javascript_prints_them() {
        assert_eq!(js_f64(1.0), "1");
        assert_eq!(js_f64(0.5), "0.5");
        assert_eq!(js_f64(1e21), "1e+21");
        assert_eq!(js_f64(1.5e-7), "1.5e-7");
        assert_eq!(js_f64(123456.789), "123456.789");
        assert_eq!(js_f64(-0.000001), "-0.000001");
        assert_eq!(js_pretty(&json!({"a":[1,{}],"b":[]})), "{\n  \"a\": [\n    1,\n    {}\n  ],\n  \"b\": []\n}");
    }

    #[test]
    fn array_replacer_filters_every_depth() {
        let v = json!({"b":{"a":1,"z":2},"a":[{"b":1,"q":2}]});
        let keys = vec!["a".to_string(), "b".to_string()];
        assert_eq!(js_stringify_keys(&v, &keys), r#"{"a":[{"b":1}],"b":{"a":1}}"#);
    }

    #[test]
    fn iso_round_trips() {
        let ms = 1_700_000_000_123;
        assert_eq!(parse_iso_ms(&iso_of_ms(ms)), Some(ms));
        assert_eq!(parse_iso_ms("not a date"), None);
        assert_eq!(parse_iso_ms("2026-01-02"), Some(1_767_312_000_000));
    }

    #[test]
    fn lenient_base64_matches_node() {
        assert_eq!(b64_lenient("aGk="), b"hi");
        assert_eq!(b64_lenient("aGk"), b"hi");
        assert_eq!(b64_lenient("a-_"), vec![0x6b, 0xef]);
    }
}
