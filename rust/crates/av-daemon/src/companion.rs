//! The companion's presence factor: a P-256 key in one Mac's Secure Enclave,
//! usable only after Touch ID. The daemon mints a single-use challenge for
//! one exact operation (`POST /v1/presence/companion/challenge`); the
//! companion asks for Touch ID, naming that operation, and signs
//! [`signed_message`]; the request then carries `challengeId` and
//! `companionSignature` as its presence, and the daemon checks both before it
//! widens anything. A signature proves a human touched the sensor for that
//! one operation, exactly as a WebAuthn assertion does in the web UI.

use base64::Engine as _;

/// What the companion signs: a fixed, versioned prefix, then the 32 raw
/// bytes of the challenge. The prefix keeps a companion signature from ever
/// standing for anything else the same key could be asked to sign.
pub const SIGNED_PREFIX: &[u8] = b"agent-vault companion presence v1\n";

/// The bytes a companion signature covers for `challenge`.
pub fn signed_message(challenge: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNED_PREFIX.len() + challenge.len());
    m.extend_from_slice(SIGNED_PREFIX);
    m.extend_from_slice(challenge);
    m
}

/// Whether `signature` (base64url, unpadded, of a DER ECDSA signature) is
/// the enrolled key's (`spki`, canonical base64 DER) over `challenge`.
/// Anything malformed is simply not a valid signature.
/// Whether `secret` is the shape of the companion's unlock secret: 32
/// bytes, base64url without padding (43 characters). The wrap is made over
/// the text itself, as the browser's PRF secret is, since `/v1/unlock`
/// takes either one as `prf_secret`.
pub fn plain_unlock_secret(secret: &str) -> bool {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret)
        .is_ok_and(|raw| raw.len() == 32)
}

pub fn verify(spki: &str, challenge: &[u8; 32], signature: &str) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(spki) else {
        return false;
    };
    let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(&der) else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_der(&raw) else {
        return false;
    };
    // The Secure Enclave may give either of a signature's two equal forms.
    let sig = sig.normalize_s();
    key.verify(&signed_message(challenge), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::EncodePublicKey;

    fn key(seed: u8) -> (p256::ecdsa::SigningKey, String) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        (
            sk,
            base64::engine::general_purpose::STANDARD.encode(spki.as_bytes()),
        )
    }

    fn sign(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> String {
        let sig: p256::ecdsa::Signature = sk.sign(msg);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes())
    }

    #[test]
    fn only_the_enrolled_keys_signature_over_this_challenge_verifies() {
        let (sk, spki) = key(7);
        let challenge = [9u8; 32];
        let good = sign(&sk, &signed_message(&challenge));
        assert!(verify(&spki, &challenge, &good));
        // Another challenge, another key, or the challenge without the
        // prefix: none of them verify.
        assert!(!verify(&spki, &[8u8; 32], &good));
        let (other, other_spki) = key(8);
        assert!(!verify(&other_spki, &challenge, &good));
        assert!(!verify(
            &spki,
            &challenge,
            &sign(&other, &signed_message(&challenge))
        ));
        assert!(!verify(&spki, &challenge, &sign(&sk, &challenge)));
        // Malformed input is refused, not a panic.
        for bad in ["", "not base64!", "AAAA", &good[..good.len() - 4]] {
            assert!(!verify(&spki, &challenge, bad), "{bad}");
        }
        assert!(!verify("", &challenge, &good));
        assert!(!verify("bm90IGEga2V5", &challenge, &good));
    }

    #[test]
    fn the_high_s_form_of_a_signature_verifies_too() {
        let (sk, spki) = key(7);
        let challenge = [3u8; 32];
        let sig: p256::ecdsa::Signature = sk.sign(&signed_message(&challenge));
        let (r, s) = sig.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s).unwrap();
        let text =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(high.to_der().as_bytes());
        assert!(verify(&spki, &challenge, &text));
    }
}
