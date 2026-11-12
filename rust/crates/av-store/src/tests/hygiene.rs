//! Source checks over this crate: SQL is never built with `format!` (every
//! statement is prepared, with bound parameters), and `unsafe` appears only
//! in the `mlock` module.

const SOURCES: &[(&str, &str)] = &[
    ("activity.rs", include_str!("../activity.rs")),
    ("audit.rs", include_str!("../audit.rs")),
    ("backup.rs", include_str!("../backup.rs")),
    ("client_state.rs", include_str!("../client_state.rs")),
    ("crypto.rs", include_str!("../crypto.rs")),
    ("db.rs", include_str!("../db.rs")),
    ("error.rs", include_str!("../error.rs")),
    ("ids.rs", include_str!("../ids.rs")),
    ("lib.rs", include_str!("../lib.rs")),
    ("migrate.rs", include_str!("../migrate.rs")),
    ("mlock.rs", include_str!("../mlock.rs")),
    ("model.rs", include_str!("../model.rs")),
    ("pending.rs", include_str!("../pending.rs")),
    ("rows.rs", include_str!("../rows.rs")),
    ("schema.rs", include_str!("../schema.rs")),
    ("util.rs", include_str!("../util.rs")),
    ("vault.rs", include_str!("../vault.rs")),
];

const SQL_WORDS: &[&str] = &[
    "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "PRAGMA ", "CREATE ", "DROP ", "ALTER ", " WHERE ",
    " VALUES", " FROM ",
];

/// The text of every `format!(...)` call in `src` (its argument list), by
/// parenthesis matching.
fn format_calls(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for marker in ["format!(", "format_args!(", "write!(", "concat!("] {
        let mut from = 0;
        while let Some(i) = src[from..].find(marker) {
            let start = from + i + marker.len();
            let mut depth = 1;
            let mut end = start;
            for (j, ch) in src[start..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = start + j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push(src[start..end].to_string());
            from = start;
        }
    }
    out
}

fn sql_in_format(src: &str) -> Vec<String> {
    format_calls(src)
        .into_iter()
        .filter(|call| SQL_WORDS.iter().any(|w| call.contains(w)))
        .collect()
}

#[test]
fn no_sql_is_built_with_format() {
    let mut calls = 0;
    let mut bad = Vec::new();
    for (name, src) in SOURCES {
        calls += format_calls(src).len();
        for c in sql_in_format(src) {
            bad.push(format!("{name}: format!({c})"));
        }
    }
    assert!(
        calls > 50,
        "found only {calls} format! calls; the scan has stopped reading the source"
    );
    assert!(bad.is_empty(), "SQL built with format!: {bad:#?}");
}

#[test]
fn the_sql_scan_itself_catches_a_formatted_statement() {
    let probe = r#"let sql = format!("SELECT * FROM credentials WHERE slug = '{slug}'");"#;
    assert_eq!(sql_in_format(probe).len(), 1);
    let ordinary = r#"let m = format!("no vault at {}; run: agent-vault setup", d);"#;
    assert!(sql_in_format(ordinary).is_empty());
}

#[test]
fn unsafe_appears_only_in_the_mlock_module() {
    for (name, src) in SOURCES {
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let has =
            code.contains("unsafe {") || code.contains("unsafe fn") || code.contains("unsafe impl");
        if *name == "mlock.rs" {
            assert!(has, "mlock.rs lost its unsafe block; update this test");
        } else {
            assert!(!has, "{name} uses unsafe");
        }
    }
    assert!(SOURCES
        .iter()
        .any(|(n, s)| *n == "lib.rs" && s.contains("#![deny(unsafe_code)]")));
}

#[test]
fn every_regex_goes_through_av_core_jsre() {
    // rust/PLAN.md: a pattern is compiled only through av_core::jsre, which
    // gives JavaScript semantics. av-store compiles none of its own; its
    // shape checks are written by hand.
    for (name, src) in SOURCES {
        for banned in ["Regex::new", "RegexBuilder", "regex::"] {
            assert!(
                !src.contains(banned),
                "{name} compiles a regex directly ({banned}); use av_core::jsre"
            );
        }
    }
    assert!(
        !include_str!("../../Cargo.toml").contains("regex"),
        "av-store depends on regex directly"
    );
}
