//! Every regex in av-cli goes through `av_core::jsre`. This file must not
//! contain a contiguous `regex` path: the detector strings are split.

fn bypasses_jsre(source: &str) -> bool {
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    [
        ["regex", "::"].concat(),
        ["use", "regex"].concat(),
        ["regex", "as"].concat(),
        ["externcrate", "regex"].concat(),
        ["Regex", "::new"].concat(),
        ["Regex", "as"].concat(),
        ["RegexBuilder", "as"].concat(),
        ["RegexSet", "as"].concat(),
        ["RegexSetBuilder", "as"].concat(),
        ["RegexBuilder", "::new"].concat(),
        ["RegexSet", "::new"].concat(),
        ["RegexSetBuilder", "::new"].concat(),
    ]
    .iter()
    .any(|s| compact.contains(s))
}

#[test]
fn every_cli_regex_uses_javascript_compiler() {
    fn visit(dir: &std::path::Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source = std::fs::read_to_string(&path).unwrap();
                assert!(!bypasses_jsre(&source), "{} bypasses jsre", path.display());
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    visit(&root.join("src"));
    visit(&root.join("tests"));
}
