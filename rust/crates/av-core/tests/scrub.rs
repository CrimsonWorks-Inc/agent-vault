use av_core::{
    scrub::*,
    secret::{ExposeSecret, SecretString},
};
use serde_json::Value;
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/scrub-vectors.json")).unwrap()
}
fn entries(v: &Value) -> Vec<ScrubEntry> {
    v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| ScrubEntry {
            secret: SecretString::from(e["secret"].as_str().unwrap().to_owned()),
            label: e["label"].as_str().unwrap().into(),
            replacement: e["replacement"].as_str().map(str::to_owned),
            always: e["always"].as_bool().unwrap_or(false),
        })
        .collect()
}
#[test]
fn js_scrub_encoding_and_nested_vectors() {
    let v = fixture();
    let entries = entries(&v);
    for (i, c) in v["cases"].as_array().unwrap().iter().enumerate() {
        let r = Scrubber::new(&entries, &Default::default())
            .unwrap()
            .scrub(c["text"].as_str().unwrap());
        assert_eq!(r.text, c["result"]["text"], "case {i}: {c}");
        assert_eq!(
            r.redactions,
            c["result"]["redactions"].as_u64().unwrap() as usize,
            "case {i}: {c}"
        );
        assert_eq!(
            r.unscannable,
            c["result"]["unscannable"].as_bool().unwrap_or(false)
        );
    }
}
#[test]
fn js_scrub_pattern_grammar() {
    for c in fixture()["compiled"].as_array().unwrap() {
        let r = compile_scrub_pattern(c["source"].as_str().unwrap());
        assert_eq!(r.is_ok(), c["ok"].as_bool().unwrap(), "{c}");
        if let Err(e) = r {
            assert_eq!(e.detail, c["detail"], "{c}");
        }
    }
}
#[test]
fn js_encoding_sets() {
    for e in fixture()["encodings"].as_array().unwrap() {
        let secret = SecretString::from(e["secret"].as_str().unwrap().to_owned());
        let plain = |v: Vec<SecretString>| {
            v.iter()
                .map(|s| s.expose_secret().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            serde_json::json!(plain(encodings(&secret, 1))),
            e["encodings"]
        );
        assert_eq!(
            serde_json::json!(plain(blob_encodings(&secret))),
            e["blobs"]
        );
    }
}
#[test]
fn streaming_every_encoding_all_chunk_sizes() {
    let v = fixture();
    let entries = entries(&v);
    for c in v["cases"].as_array().unwrap() {
        let text = c["text"].as_str().unwrap();
        if !text.is_ascii() {
            continue;
        }
        for size in [1, 2, 3, 7, 31, 64, 100] {
            let mut scrub = Scrubber::new(&entries, &Default::default()).unwrap();
            let mut stream = scrub.stream();
            let mut output = String::new();
            for chunk in text.as_bytes().chunks(size) {
                output += &stream.push(std::str::from_utf8(chunk).unwrap());
            }
            output += &stream.flush();
            assert_eq!(output, c["result"]["text"], "size {size}: {c}");
        }
    }
}
#[test]
fn pathological_pattern_and_ordinary_controls() {
    assert!(compile_scrub_pattern("abc[^Q]{0,256}[^Q]{256}Q").is_err());
    let p = compile_scrub_pattern("abc[^Q]{0,256}Q").unwrap();
    let start = std::time::Instant::now();
    assert!(!p.regex.is_match(&" abc".repeat(16384)));
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
    for line in SCRUB_PATTERN_CORPUS {
        assert_eq!(
            Scrubber::new(&[], &Default::default())
                .unwrap()
                .scrub(line)
                .text,
            *line
        );
    }
}
#[test]
fn floor_and_untrusted_redaction_before_cut() {
    let secrets = [
        StoredSecret {
            secret: SecretString::from("test-secret-fake".to_owned()),
            label: "fake".into(),
        },
        StoredSecret {
            secret: SecretString::from("tiny".to_owned()),
            label: "short".into(),
        },
    ];
    assert_eq!(
        redact_stored("tiny test-secret-fake", &secrets),
        "tiny [[av:redacted:fake]]"
    );
    assert_eq!(
        untrusted_text(Some("prefix test-secret-fake suffix"), &secrets, 15).unwrap(),
        "prefix [[av:red"
    );
    assert_eq!(untrusted_text(None, &[], 200), None);
}
#[test]
fn nested_budget_fails_closed_with_control() {
    let e = [ScrubEntry {
        secret: SecretString::from("test-secret-fake".to_owned()),
        label: "fake".into(),
        replacement: None,
        always: false,
    }];
    let mut s = Scrubber::new(
        &e,
        &ScrubberOptions {
            nested_views: Some(0),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!s.scrub("ordinary response").unscannable);
    let nested = av_core::secret::SecretString::from("test-secret-fake".to_owned());
    use base64::Engine;
    let base = base64::engine::general_purpose::STANDARD.encode(nested.expose_secret());
    let percent = base
        .bytes()
        .map(|b| format!("%{b:02x}"))
        .collect::<String>();
    assert!(s.scrub(&percent).unscannable);
}
use proptest::prelude::*;
proptest! {
    #[test]
    fn secret_never_survives_stream(secret in "test-secret-[a-zA-Z0-9]{8,30}",size in 1usize..80){let entry=[ScrubEntry{secret:secret.clone().into(),label:"fake".into(),replacement:Some("<REDACTED>".into()),always:false}];for encoded in encodings(&secret.clone().into(),8){let text=format!("ordinary {} tail",encoded.expose_secret());let mut scrub=Scrubber::new(&entry,&Default::default()).unwrap();let whole=scrub.scrub(&text).text;let mut stream=scrub.stream();let mut out=String::new();for c in text.as_bytes().chunks(size){out+=&stream.push(std::str::from_utf8(c).unwrap());}out+=&stream.flush();prop_assert!(!out.contains(&secret));prop_assert_eq!(out,whole);}}
}
