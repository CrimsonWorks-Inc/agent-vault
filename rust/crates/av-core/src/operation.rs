//! The operation a WebAuthn presence proof binds to: the pure parts of
//! `src/ui/webauthn.js`. Signature verification stays in av-daemon.

use crate::errors::Result;

/// Request fields that carry a secret and are bound by SHA-256 digest
/// (`<key>_sha256`) rather than in clear. Ports `DIGESTED` in
/// `src/ui/webauthn.js`.
pub const DIGESTED: &[&str] = &[
    "value",
    "prf_secret",
    "recovery_passphrase",
    "bundle",
    "webhook_url",
];

/// The operation object a presence proof signs: `params` with keys sorted,
/// `presence` and undefined values dropped, [`DIGESTED`] fields replaced by
/// `<key>_sha256` (hex of the string's bytes, or of the canonical form of a
/// non-string), then `op`. Refuses (`AV_POLICY_DENIED`, rule
/// `reserved_operation_field`) a param named `op` that differs from `op`, or
/// any `*_sha256`. `params` may hold secrets; the result does not. Ports
/// `operationFor` in `src/ui/webauthn.js`.
pub fn operation_for(
    op: &str,
    params: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    use crate::errors::{deny, DenyExtra, ErrorCode};
    let mut out = serde_json::Map::new();
    for (key, v) in params {
        if key == "presence" || (key == "op" && v.as_str() == Some(op)) {
            continue;
        }
        if key == "op" || key.ends_with("_sha256") {
            return Err(deny(
                ErrorCode::PolicyDenied,
                format!(
                    "a request cannot carry a field named {}",
                    serde_json::to_string(key).expect("key")
                ),
                DenyExtra {
                    rule: Some("reserved_operation_field".into()),
                    ..Default::default()
                },
            ));
        }
        if DIGESTED.contains(&key.as_str()) {
            let text = v
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| canonical_operation(v));
            out.insert(
                format!("{key}_sha256"),
                crate::canon::sha256(text.as_bytes()).into(),
            );
        } else {
            out.insert(key.clone(), v.clone());
        }
    }
    out.insert("op".into(), op.into());
    Ok(out)
}

/// Stable-key-order JSON text of an operation, so the signed and executed
/// operations compare exactly (`null` for null). Ports `canonicalOperation`
/// in `src/ui/webauthn.js`.
pub fn canonical_operation(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(o) => {
            let mut keys: Vec<_> = o.keys().collect();
            keys.sort_by_key(|s| s.encode_utf16().collect::<Vec<_>>());
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|k| format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("key"),
                        canonical_operation(&o[k])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        serde_json::Value::Array(a) => format!(
            "[{}]",
            a.iter()
                .map(canonical_operation)
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Number(n) => crate::canon::js_number_text(n),
        _ => serde_json::to_string(value).expect("JSON value"),
    }
}

/// The WebAuthn challenge for an operation: SHA-256 of `nonce` followed by
/// the UTF-8 of `canonical_operation(operation)`. Ports
/// `challengeForOperation` in `src/ui/webauthn.js`.
pub fn challenge_for_operation(nonce: &[u8], operation: &serde_json::Value) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(canonical_operation(operation).as_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;
    #[test]
    fn reserved_fields_and_secret_digests() {
        let params =
            json!({"op":"cred.add","value":"test-secret-fake","presence":{},"slug":"test"});
        let op = operation_for("cred.add", params.as_object().unwrap()).unwrap();
        assert!(!op.contains_key("value"));
        assert!(!op.contains_key("presence"));
        assert_eq!(
            op["value_sha256"],
            crate::canon::sha256(b"test-secret-fake")
        );
        assert_eq!(op["op"], "cred.add");
        for p in [
            json!({"op":"session.create"}),
            json!({"value_sha256":"fake"}),
        ] {
            assert_eq!(
                operation_for("cred.add", p.as_object().unwrap())
                    .unwrap_err()
                    .extra
                    .rule
                    .as_deref(),
                Some("reserved_operation_field")
            );
        }
        let a = json!({"op":"x","methods":["GET","POST"]});
        let b = json!({"methods":["POST","GET"],"op":"x"});
        assert_ne!(canonical_operation(&a), canonical_operation(&b));
        assert_ne!(
            challenge_for_operation(b"fake-nonce", &a),
            challenge_for_operation(b"fake-nonce", &b)
        );
        assert_eq!(
            canonical_operation(&json!({"b":1,"a":null})),
            "{\"a\":null,\"b\":1}"
        );
    }
    proptest! {
        #[test] fn distinct_operations_bind_differently(a in "[a-z]{0,30}",b in "[a-z]{0,30}") {prop_assume!(a!=b);prop_assert_ne!(canonical_operation(&json!({"op":"cred.add","slug":a})),canonical_operation(&json!({"slug":b,"op":"cred.add"})));}
    }
}
