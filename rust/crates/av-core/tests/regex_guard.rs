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
                let text = std::fs::read_to_string(&path).unwrap();
                for forbidden in [
                    ["Regex", "::new"].concat(),
                    ["RegexBuilder", "::new"].concat(),
                ] {
                    assert!(
                        !text.contains(&forbidden),
                        "{} bypasses jsre",
                        path.display()
                    );
                }
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    visit(&root.join("src"));
    visit(&root.join("tests"));
}
