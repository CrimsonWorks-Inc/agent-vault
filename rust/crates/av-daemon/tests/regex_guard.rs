//! Every pattern in av-daemon goes through `av_core::jsre`, which gives
//! JavaScript semantics (rust/PLAN.md, "Regexes use JavaScript semantics"),
//! and none uses syntax that helper does not translate.

fn bypasses_jsre(source: &str) -> bool {
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    [
        ["regex", "::"].concat(),
        ["use", "regex"].concat(),
        ["externcrate", "regex"].concat(),
        ["Regex", "::new"].concat(),
        ["RegexBuilder", "::new"].concat(),
        ["RegexSet", "::new"].concat(),
    ]
    .iter()
    .any(|s| compact.contains(s))
}

fn unsupported(line: &str) -> bool {
    line.contains("jsre::compile")
        && ["(?m)", "(?s)", "(?x)", "(?=", "(?!", "(?<", "(?u)"].iter().any(|f| line.contains(f))
}

fn visit(dir: &std::path::Path, bad: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            visit(&path, bad);
        } else if path.extension().is_some_and(|e| e == "rs") && path.file_name().unwrap() != "regex_guard.rs" {
            let text = std::fs::read_to_string(&path).unwrap();
            if bypasses_jsre(&text) {
                bad.push(format!("{} bypasses jsre", path.display()));
            }
            for (i, l) in text.lines().enumerate() {
                if unsupported(l) {
                    bad.push(format!("{}:{} uses a flag or lookaround jsre does not translate", path.display(), i + 1));
                }
            }
        }
    }
}

#[test]
fn every_daemon_regex_uses_the_javascript_compiler() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut bad = Vec::new();
    visit(&root.join("src"), &mut bad);
    visit(&root.join("tests"), &mut bad);
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn the_guard_catches_a_direct_constructor() {
    assert!(bypasses_jsre(&["let r = Regex", "::new(\"a\");"].concat()));
    assert!(!bypasses_jsre("let r = av_core::jsre::compile(\"a\");"));
    assert!(unsupported(&["jsre::compile(r\"", "(?m)^x\")"].concat()));
}
