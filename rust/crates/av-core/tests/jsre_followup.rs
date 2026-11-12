use av_core::{canon::*, jsre, scrub::compile_scrub_pattern};
use serde_json::Value;
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/jsre-followup-vectors.json")).unwrap()
}
#[test]
fn js_dot_classes_and_flag_refusals() {
    for row in vectors()["probes"].as_array().unwrap() {
        let source = row["source"].as_str().unwrap();
        let pattern = if row["flags"] == "i" {
            format!("(?i){source}")
        } else {
            source.into()
        };
        let re = jsre::compile(&pattern);
        if row["refuse"] == true {
            assert!(re.is_err(), "{row}");
        } else if row["scalarException"] == true {
            assert!(re.unwrap().is_match(row["text"].as_str().unwrap()));
            assert_eq!(row["js"], false);
        } else {
            assert_eq!(
                re.unwrap().is_match(row["text"].as_str().unwrap()),
                row["js"].as_bool().unwrap(),
                "{row}"
            );
        }
    }
}
#[test]
fn js_scrub_non_bmp_repetitions_refuse_with_invalid_pattern_problem() {
    let vectors = vectors();
    assert_eq!(vectors["counted"][0]["match"], "abcXY");
    assert_eq!(vectors["counted"][1]["match"], "abc😀");
    assert!(vectors["counted"][2]["match"].is_null());
    for row in vectors["scrub"].as_array().unwrap() {
        let compiled = compile_scrub_pattern(row["source"].as_str().unwrap());
        if row["refuse"] == true {
            assert_eq!(
                compiled.unwrap_err().to_problem(),
                vectors["invalidProblem"],
                "{row}"
            );
        } else if row["ok"] == false {
            assert_eq!(compiled.unwrap_err().to_problem(), row["problem"], "{row}");
        } else {
            assert!(compiled.is_ok(), "{row}");
        }
    }
}
#[test]
fn js_request_hash_utf16_names_credentials_and_ascii_control() {
    assert_eq!(
        vectors()["requests"][2]["hash"],
        "f9eb2734ea7f1c885e34e8b00b426fcac1b294f6f774b3f98d539b0ab66609f3"
    );
    for row in vectors()["requests"].as_array().unwrap() {
        let input = &row["input"];
        let headers =
            serde_json::from_value::<Vec<(String, String)>>(input["headers"].clone()).unwrap();
        let credentials =
            serde_json::from_value::<Vec<String>>(input["credentials"].clone()).unwrap();
        assert_eq!(
            request_hash(&RequestHashInput {
                method: input["method"].as_str(),
                host: input["host"].as_str(),
                headers: &headers,
                credentials: &credentials,
                ..Default::default()
            }),
            row["hash"]
        );
    }
}
#[test]
fn followup_vectors_regenerate_from_node() {
    if !std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../legacy/js/src/core/scrub.js"
    ))
    .exists()
    {
        return;
    }
    let out = std::process::Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/jsre-followup-vectors.mjs"
        ))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap(),
        vectors()
    );
}
