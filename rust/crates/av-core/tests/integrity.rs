use av_core::{base32, canon, placeholder as ph, secret::Key32};
use proptest::prelude::*;
fn minted(slug: &str, field: &str) -> ph::Minted {
    ph::mint(&ph::MintInput {
        k_ph: &Key32::from_bytes([42; 32]),
        sid: "0123456789ab",
        slug,
        field,
    })
    .unwrap()
}
#[test]
fn grammar_constants() {
    assert_eq!(ph::PH_MIN_LEN, 54);
    assert_eq!(ph::PH_MAX_LEN, 92);
    assert_eq!(ph::B64_MIN_RUN, 72);
    assert_eq!(ph::SCAN_OVERLAP, 278);
}
#[test]
fn mint_roundtrip_and_longest_label() {
    for (slug, field) in [
        ("gh-frozencrow", "token"),
        ("aaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"),
    ] {
        let p = minted(slug, field);
        let parsed = ph::parse_at(&p.text, 0).unwrap();
        assert_eq!(parsed.slug, slug);
        assert_eq!(parsed.field, field);
        assert_eq!(parsed.sid, p.sid);
        assert!(ph::verify(&Key32::from_bytes([42; 32]), &parsed));
        assert!((ph::PH_MIN_LEN..=ph::PH_MAX_LEN).contains(&p.text.len()));
        if slug.len() == 24 {
            assert_eq!(p.text.len(), ph::PH_MAX_LEN);
        }
    }
}
#[test]
fn transport_safe_and_scanner_pattern() {
    let re = regex::Regex::new(ph::SCANNER_PATTERN).unwrap();
    for _ in 0..50 {
        let p = minted("test-fake", "token");
        assert!(p
            .text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
        assert_eq!(
            serde_json::from_str::<String>(&serde_json::to_string(&p.text).unwrap()).unwrap(),
            p.text
        );
        assert_eq!(p.text, p.text.to_lowercase());
        assert!(re.is_match(&p.text));
        let x = ph::parse_at(&p.text, 0).unwrap();
        for g in [&x.sid, &x.nonce, &x.chk] {
            assert!(!g.contains(['i', 'l', 'o', 'u']));
        }
    }
}
#[test]
fn entropy_unique() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2000 {
        let p = minted("test-fake", "token");
        assert_eq!(p.nonce.len(), 26);
        assert!(seen.insert(p.nonce));
    }
}
#[test]
fn diagnose_and_find() {
    let a = minted("test-fake", "token").text;
    let b = minted("pg-prod", "password").text;
    assert!(ph::diagnose(&a.replace("av1.", "av2.")).contains("does not start"));
    assert!(ph::diagnose(&(a.clone() + "zz")).contains("expected groups of 12/26/6"));
    assert!(ph::diagnose(a.rsplit_once('.').unwrap().0).contains("expected 5 dot-separated groups"));
    assert_eq!(
        ph::find_all(&format!("Bearer {a}\nav1.notreal\npg={b};"))
            .iter()
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>(),
        vec![a.as_str(), b.as_str()]
    );
    assert!(ph::find_all(&(a.clone() + "abcd")).is_empty());
    assert_eq!(ph::find_all(&(a + "-abcd")).len(), 1);
}
#[test]
fn js_golden_vectors() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/placeholder-vectors.json")).unwrap();
    check_vectors(&v);
}
fn check_vectors(v: &serde_json::Value) {
    for p in v["vectors"].as_array().unwrap() {
        let parsed = ph::parse_at(p["text"].as_str().unwrap(), 0).unwrap();
        assert!(ph::verify(&Key32::from_bytes([42; 32]), &parsed));
        assert_eq!(ph::hash_nonce(&parsed.nonce), p["nonceHash"]);
    }
    assert_eq!(
        ph::hash_nonce("0123456789abcdefghjkmnpqrs0"),
        v["nonceHash"]
    );
    assert_eq!(
        canon::canonicalize(&serde_json::json!({"é":1,"a":[true,null,"fake"]})).unwrap(),
        v["canon"]
    );
    let creds = vec!["b:token".into(), "a:token".into()];
    let headers = vec![
        ("Z".into(), "a".into()),
        ("X".into(), "2".into()),
        ("X".into(), "1".into()),
    ];
    assert_eq!(
        canon::request_hash(&canon::RequestHashInput {
            method: Some("post"),
            host: Some("EXAMPLE.COM"),
            path: Some("/x"),
            credentials: &creds,
            headers: &headers,
            ..Default::default()
        }),
        v["requestHash"]
    );
}
#[test]
fn live_js_golden_vectors() {
    // The mutation runner copies only rust/; checked-in JS vectors remain tested there.
    if !std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/core/placeholder.js"
    ))
    .exists()
    {
        return;
    }
    let out = std::process::Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/placeholder-vectors.mjs"
        ))
        .output()
        .expect("node available for JS parity");
    assert!(out.status.success());
    check_vectors(&serde_json::from_slice(&out.stdout).unwrap());
}
#[test]
fn request_hash_binds_headers_and_repeat_order() {
    let headers = vec![
        ("X-HTTP-Method-Override".into(), "POST".into()),
        ("X-HTTP-Method-Override".into(), "DELETE".into()),
    ];
    let mut reverse = headers.clone();
    reverse.reverse();
    let first = canon::request_hash(&canon::RequestHashInput {
        headers: &headers,
        ..Default::default()
    });
    assert_ne!(
        first,
        canon::request_hash(&canon::RequestHashInput {
            headers: &reverse,
            ..Default::default()
        })
    );
    assert_ne!(first, canon::request_hash(&Default::default()));
    assert_eq!(
        first,
        canon::request_hash(&canon::RequestHashInput {
            headers: &headers,
            ..Default::default()
        })
    );
}
#[test]
fn canonical_values() {
    assert_eq!(
        canon::canonicalize(&serde_json::json!({"z":0,"a":[true,null,"fake"]})).unwrap(),
        "{\"a\":[true,null,\"fake\"],\"z\":0}"
    );
    assert!(canon::canonicalize(&serde_json::json!(1.5)).is_err());
}
proptest! {
 #[test] fn base32_roundtrip(bytes in any::<[u8;16]>()) {let s=base32::encode(&bytes,26);prop_assert_eq!(s.len(),26);prop_assert!(base32::is_base32(&s));prop_assert_eq!(base32::decode(&s,16).unwrap(),bytes.to_vec());}
 #[test] fn minted_always_verifies(slug in "[a-z0-9-]{1,24}",field in "[a-z0-9]{1,16}") {let p=minted(&slug,&field);prop_assert!(ph::verify(&Key32::from_bytes([42;32]),&ph::parse_at(&p.text,0).unwrap()));}
 #[test] fn checksum_single_character_change(at in 0usize..92,replacement in 0u8..32) {let p=minted("test-fake","token");let at=at%p.text.len();let mut text=p.text.into_bytes();let r=base32::ALPHABET.as_bytes()[replacement as usize];if text[at]!=r {text[at]=r;let text=String::from_utf8(text).unwrap();if let Some(parsed)=ph::parse_at(&text,0){prop_assert!(!ph::verify(&Key32::from_bytes([42;32]),&parsed));}}}
 #[test] fn wrong_key_never_verifies(key in any::<[u8;32]>()) {prop_assume!(key!=[42;32]);let p=minted("test-fake","token");prop_assert!(!ph::verify(&Key32::from_bytes(key),&ph::parse_at(&p.text,0).unwrap()));}
 #[test] fn random_text_never_verifies(s in "[av1.0-9a-hjkmnp-tv-z_-]{40,100}") {if let Some(parsed)=ph::parse_at(&format!("av1.{s}"),0){prop_assert!(!ph::verify(&Key32::from_bytes([42;32]),&parsed));}}
}
proptest! {
    #[test]
    fn operation_shapes_canonicalize_injectively(op1 in 0usize..5,op2 in 0usize..5,cred1 in "[a-z0-9-]{0,12}",cred2 in "[a-z0-9-]{0,12}",methods1 in prop::collection::vec(0usize..4,0..5),methods2 in prop::collection::vec(0usize..4,0..5),paths1 in prop::collection::vec(0usize..4,0..5),paths2 in prop::collection::vec(0usize..4,0..5)){
        let ops=["session.create","cred.add","cred.remove","approval.approve","listener.add"];let methods=["GET","POST","DELETE","HEAD"];let paths=["/**","/v1/**","/user","/repos/*"];
        let a=serde_json::json!({"op":ops[op1],"cred":cred1,"methods":methods1.iter().map(|i|methods[*i]).collect::<Vec<_>>(),"paths":paths1.iter().map(|i|paths[*i]).collect::<Vec<_>>()});let b=serde_json::json!({"paths":paths2.iter().map(|i|paths[*i]).collect::<Vec<_>>(),"methods":methods2.iter().map(|i|methods[*i]).collect::<Vec<_>>(),"cred":cred2,"op":ops[op2]});
        prop_assert_eq!(av_core::operation::canonical_operation(&a)==av_core::operation::canonical_operation(&b),a==b);
    }
}
#[test]
fn js_number_canonical_vectors() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/number-vectors.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let value: serde_json::Value = serde_json::from_str(row["raw"].as_str().unwrap()).unwrap();
        assert_eq!(
            av_core::operation::canonical_operation(&value),
            row["operation"],
            "{row}"
        );
        assert_eq!(
            serde_json::json!(canon::canonicalize(&value).ok()),
            row["canon"],
            "{row}"
        );
    }
}
