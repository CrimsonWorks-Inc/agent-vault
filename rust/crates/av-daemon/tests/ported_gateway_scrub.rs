//! gateway-w2-scrub.test.js: custom-pattern grammar and stream regressions.
#![forbid(unsafe_code)]
use av_core::scrub::*;
fn custom(source: &str) -> Scrubber {
    Scrubber::new(
        &[],
        &ScrubberOptions {
            extra_patterns: vec![ExtraPattern {
                name: "acme".into(),
                source: source.into(),
            }],
            ..Default::default()
        },
    )
    .unwrap()
}
const SOURCE: &str = "acme_[A-Za-z0-9]{20,80}";
fn token() -> String {
    format!("acme_{}", "Z".repeat(40))
}
#[test]
fn restricted_custom_pattern_grammar_rejects_dangerous_and_broad_expressions() {
    for source in [
        "(a+)+b",
        ".*",
        "a",
        "[a-z]+",
        "abc.*def+",
        r"abc\1",
        "abc(?=x)",
        "abc$",
        "abc[A-Z]{257}",
        "abc|",
        "abc|xy",
        "disk-usage_by_repository_over_time",
        "abc[[]",
    ] {
        let e = compile_scrub_pattern(source).unwrap_err();
        assert_eq!(e.extra.rule.as_deref(), Some("scrub_pattern"), "{source}");
    }
    for source in [
        "abc_[0-9]{1,64}",
        r"abc\d{2,20}",
        r"abc\.xyz|def_[A-Z]{0,40}",
        SOURCE,
    ] {
        compile_scrub_pattern(source).unwrap();
    }
}
#[test]
fn custom_patterns_are_additive_to_stored_and_derived_secret_protection() {
    let mut scrub = Scrubber::new(
        &[ScrubEntry {
            secret: "test-secret-fixture-value".to_string().into(),
            label: "fixture".into(),
            replacement: None,
            always: false,
        }],
        &ScrubberOptions {
            extra_patterns: vec![ExtraPattern {
                name: "acme".into(),
                source: SOURCE.into(),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let token = token();
    let github = format!("ghp_{}", "Q".repeat(30));
    let r = scrub.scrub(&format!("{token} test-secret-fixture-value {github}"));
    assert_eq!(r.redactions, 3);
    for secret in [&token, &github, &"test-secret-fixture-value".to_string()] {
        assert!(!r.text.contains(secret));
    }
    assert!(scrub.derived_seen().contains("acme"));
    assert!(scrub.derived_seen().contains("github"));
    for text in SCRUB_PATTERN_CORPUS {
        assert_eq!(scrub.scrub(text).text, *text);
    }
}
#[test]
fn custom_token_is_redacted_at_every_two_chunk_cut_and_every_odd_chunk_width() {
    let token = token();
    for cut in 0..=token.len() {
        let mut scrub = custom(SOURCE);
        let mut stream = scrub.stream();
        let mut out = stream.push(&format!("prefix {}", &token[..cut]));
        out += &stream.push(&format!("{} suffix {}", &token[cut..], ".".repeat(150)));
        out += &stream.flush();
        assert!(!out.contains(&token), "cut {cut}");
        assert_eq!(stream.redactions(), 1);
        drop(stream);
        assert!(scrub.derived_seen().contains("acme"));
    }
    let body = format!("before {token} middle {token} after");
    for width in (1..=23).step_by(2) {
        let mut scrub = custom(SOURCE);
        let mut stream = scrub.stream();
        let mut out = String::new();
        for chunk in body.as_bytes().chunks(width) {
            out += &stream.push(std::str::from_utf8(chunk).unwrap());
        }
        out += &stream.flush();
        assert!(!out.contains("acme_Z"), "width {width}");
        assert_eq!(stream.redactions(), 2);
    }
    let ordinary = "we use acme_ tooling here";
    assert_eq!(custom(SOURCE).scrub(ordinary).text, ordinary);
}
#[test]
fn long_bounded_tokens_and_escaped_prefixes_are_redacted_across_single_character_chunks() {
    for (source, text) in [
        ("long_[A-Z]{200}", format!("long_{}", "Z".repeat(200))),
        (r"ab\|_[A-Z]{20,80}", format!("ab|_{}", "Q".repeat(30))),
    ] {
        let mut scrub = custom(source);
        let mut stream = scrub.stream();
        let mut out = String::new();
        for c in text.chars() {
            out += &stream.push(&c.to_string());
        }
        out += &stream.flush();
        assert_eq!(out, "[[av:derived]]");
        let ordinary = "ordinary text with no token";
        assert_eq!(custom(source).scrub(ordinary).text, ordinary);
    }
}
#[test]
fn ordinary_prefix_traffic_keeps_flowing_with_bounded_holdback() {
    let mut scrub = custom(SOURCE);
    let mut stream = scrub.stream();
    let mut out = String::new();
    let mut pushed = 0;
    let mut most = 0;
    for text in std::iter::once("we use acme_ tooling here; ").chain(std::iter::repeat_n(
        "ordinary text that goes on and on. ",
        2000,
    )) {
        pushed += text.len();
        out += &stream.push(text);
        most = most.max(pushed - out.len());
    }
    assert!(out.len() > 60000);
    assert!(most < 4096, "held {most}");
    out += &stream.flush();
    assert!(out.starts_with("we use acme_ tooling here; "));
    assert_eq!(stream.redactions(), 0);
}
#[test]
fn corrupt_persisted_pattern_source_fails_closed_before_any_output() {
    let e = Scrubber::new(
        &[],
        &ScrubberOptions {
            extra_patterns: vec![ExtraPattern {
                name: "bad".into(),
                source: "(a+)+".into(),
            }],
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.code.as_str(), "AV_UNSCANNABLE");
    assert_eq!(e.extra.rule.as_deref(), Some("scrub_pattern_invalid"));
    assert_eq!(
        custom(SOURCE).scrub("ordinary traffic").text,
        "ordinary traffic"
    );
}

fn scan_under_50_ms(pattern: &CompiledScrubPattern, input: &str) {
    // Wall time below 50 ms also bounds CPU time below the JS contract's
    // 50 ms; retry scheduler interruptions just as the JS meter retries.
    let mut fastest = std::time::Duration::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        std::hint::black_box(pattern.regex.is_match(input));
        fastest = fastest.min(start.elapsed());
        if fastest < std::time::Duration::from_millis(50) {
            break;
        }
    }
    assert!(
        fastest < std::time::Duration::from_millis(50),
        "{} scan took {fastest:?}",
        pattern.source
    );
}
#[test]
fn bounded_grammar_refuses_combinatorial_repetition_and_scans_realistic_shapes_promptly() {
    let refused = vec![
        "abc[a-z]{0,256}[a-z]{0,256}Z".into(),
        format!("abc{}Z", "a?".repeat(20)),
        format!("abc{}Z", "[a]{0,20}a".repeat(10)),
        "abc[A-Z]+".into(),
        "abc[A-Z]*".into(),
        "abc[A-Z]{1,}".into(),
        "abc[A-Z]{1,2}?".into(),
        "abc[A-Z]{257}".into(),
        "abc\n[A-Z]{4}".into(),
        "abc[A-Z]{3,1}".into(),
        "abc[^Q]{0,256}[^Q]{256}Q".into(),
        "abc[a-z]{0,256}[a-z]{256}Q".into(),
        "abc[0-9]{1,5}[A-Z]{3}".into(),
        r"abc[0-9]{0,5}\d".into(),
        "abc[A-Z]{256}x[B-Z]{256}x".into(),
        "abc[A-Z]{2,9}x?".into(),
    ];
    for source in refused {
        assert_eq!(
            compile_scrub_pattern(&source)
                .unwrap_err()
                .extra
                .rule
                .as_deref(),
            Some("scrub_pattern"),
            "{source}"
        );
    }
    let input = format!("abc{}", "a".repeat(64 * 1024));
    for source in [
        "acme_[A-Za-z0-9]{32,40}",
        "sk-live-[0-9a-f]{24}",
        r"tok\.[A-Z]{4}-[0-9]{6}",
        "abc[a-z]{0,256}Z",
        "abc_[0-9]{1,64}",
        r"abc\d{2,20}",
        r"abc\.xyz|def_[A-Z]{0,40}",
        r"ab\|_[A-Z]{20,80}",
        "long_[A-Z]{200}",
        "abc[A-Z]{250}x[B-Z]{250}x",
        "tok_[A-Z]{4}-[0-9]{6,8}",
        "abc_[a-z]{0,10}_end",
    ] {
        let compiled = compile_scrub_pattern(source).unwrap();
        scan_under_50_ms(&compiled, &input);
    }
}
#[test]
fn hostile_input_scans_meet_bound_and_non_bmp_repetitions_are_refused_as_planned() {
    let accepted = [
        "acme_[A-Za-z0-9]{32,40}",
        "sk-live-[0-9a-f]{24}",
        "tok_[A-Z]{4}-[0-9]{6,8}",
        "abc_[a-z]{0,10}_end",
    ];
    let refused=["abc[^Q]{252}[^Q]{0,256}Q","abc[^Q]{128}[^Q]{128}[^Q]{0,249}QQQQ","abc[^Q]{0,256}QQQQQQQQQQQQQQQQ",r"abc\S{253}\S{0,256}","abc[^ ]{0,256}Q|abd[^ ]{0,256}Q|abe[^ ]{0,256}Q|abf[^ ]{0,256}Q|abg[^ ]{0,256}Q|abh[^ ]{0,256}Q","abc[^Q]{250}[^Q]{250}[^Q]{9}"];
    // Intended difference approved in rust/PLAN.md: UTF-16 vs scalar counts.
    for source in refused {
        let e = compile_scrub_pattern(source).unwrap_err();
        assert_eq!(e.http(), 403);
        assert_eq!(
            e.to_problem(),
            serde_json::json!({"type":"https://agent-vault.dev/errors/AV_POLICY_DENIED","code":"AV_POLICY_DENIED","detail":"scrub pattern refused: it is not a valid expression","hint":"The grant exists but this method or path is outside it.","rule":"scrub_pattern"})
        );
    }
    for source in ["abc[^Q]{0,250}[^Q]{250}Q", "abc[^Q]{0,128}[^Q]{128}Q"] {
        assert_eq!(
            compile_scrub_pattern(source)
                .unwrap_err()
                .extra
                .rule
                .as_deref(),
            Some("scrub_pattern")
        );
    }
    let fill =
        |unit: &str| unit.repeat((64 * 1024usize).div_ceil(unit.len()))[..64 * 1024].to_string();
    for source in accepted {
        let compiled = compile_scrub_pattern(source).unwrap();
        let prefix = &source[..3];
        let mut hostile = vec![
            "x".repeat(64 * 1024),
            fill(&format!(" {prefix}")),
            fill(&format!(" {prefix}-")),
        ];
        for run in [100, 300, 520, 1100] {
            hostile.push(fill(&format!(" {prefix}{}", "a".repeat(run))));
        }
        for run in [100, 300, 520] {
            hostile.push(fill(&format!(" {prefix}{}QQQ", "q".repeat(run))));
        }
        for input in hostile {
            scan_under_50_ms(&compiled, &input);
        }
    }
}
