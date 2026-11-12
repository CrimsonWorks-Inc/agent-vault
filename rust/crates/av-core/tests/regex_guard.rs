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
fn every_core_regex_uses_javascript_compiler() {
    fn visit(dir: &std::path::Path) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().unwrap() != "jsre.rs"
            {
                assert!(
                    !bypasses_jsre(&std::fs::read_to_string(&path).unwrap()),
                    "{} bypasses jsre",
                    path.display()
                );
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    visit(&root.join("src"));
    visit(&root.join("tests"));
}

#[test]
fn guard_rejects_sets_bytes_aliases_and_split_constructors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/jsre-followup-vectors.json")).unwrap();
    for row in vectors["guard"].as_array().unwrap() {
        assert_eq!(
            bypasses_jsre(row["source"].as_str().unwrap()),
            row["bypass"].as_bool().unwrap(),
            "{row}"
        );
    }
}
