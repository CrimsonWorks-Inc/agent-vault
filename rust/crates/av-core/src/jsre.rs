//! Linear-time compilation of the JavaScript (non-`u`) regex subset used by
//! the port. Shorthand classes and word boundaries retain ECMAScript semantics.
//! A leading `(?i)` enables legacy case folding, including BMP literals, without
//! Unicode folds such as Kelvin sign / ASCII K or long s / ASCII S.
//! Matching and repetition count Unicode scalars, not UTF-16 units. In
//! particular dot matches one scalar; custom scrub patterns refuse repetitions
//! of atoms that can consume non-BMP text until a UTF-16 matcher exists.
pub use regex::{Captures, Regex};

const SPACE: &str =
    r"\x09-\x0d\x20\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}";

fn canonical(c: char) -> char {
    let mut upper = c.to_uppercase();
    let first = upper.next().unwrap();
    if upper.next().is_some() || (!c.is_ascii() && first.is_ascii()) {
        c
    } else {
        first
    }
}

fn folds(c: char) -> String {
    use std::{collections::HashMap, sync::OnceLock};
    static FOLDS: OnceLock<HashMap<char, String>> = OnceLock::new();
    let table = FOLDS.get_or_init(|| {
        let mut table: HashMap<char, String> = HashMap::new();
        for c in (0..=0xffff).filter_map(char::from_u32) {
            table.entry(canonical(c)).or_default().push(c);
        }
        table
    });
    table
        .get(&canonical(c))
        .cloned()
        .unwrap_or_else(|| c.to_string())
}

/// Translate the supported JavaScript regex syntax to Rust regex syntax.
/// Escaped backslashes are consumed as pairs, so `\\s` remains literal text.
pub fn translate(pattern: &str) -> String {
    if validate(pattern).is_err() {
        // Preserve this public String signature while emitting syntax that the
        // linear engine refuses, rather than passing divergent syntax through.
        return "(?!)".into();
    }
    let (insensitive, pattern) = pattern
        .strip_prefix("(?i)")
        .map_or((false, pattern), |p| (true, p));
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut bracket = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c == '\\' {
            let Some(&e) = chars.get(i) else {
                out.push(c);
                break;
            };
            i += 1;
            match e {
                's' => out.push_str(&format!("[{SPACE}]")),
                'S' => out.push_str(&format!("[^{SPACE}]")),
                'w' => out.push_str("[A-Za-z0-9_]"),
                'W' => out.push_str("[^A-Za-z0-9_]"),
                'd' => out.push_str("[0-9]"),
                'D' => out.push_str("[^0-9]"),
                'b' if bracket => out.push_str(r"\x08"),
                'B' if bracket => out.push('B'),
                'b' => out.push_str(r"(?-u:\b)"),
                'B' => out.push_str(r"(?-u:\B)"),
                '/' => out.push('/'),
                _ => {
                    out.push('\\');
                    out.push(e);
                }
            }
        } else if c == '[' {
            bracket = true;
            out.push(c);
        } else if c == ']' {
            bracket = false;
            out.push(c);
        } else if c == '.' && !bracket {
            out.push_str(r"[^\n\r\x{2028}\x{2029}]");
        } else if bracket && matches!(c, '&' | '~') {
            out.push('\\');
            out.push(c);
        } else if insensitive && c.is_alphabetic() {
            // Expand ranges before literals, preserving complement classes.
            if bracket
                && chars.get(i) == Some(&'-')
                && chars
                    .get(i + 1)
                    .is_some_and(|end| end.is_alphabetic() && *end >= c)
            {
                let end = chars[i + 1];
                i += 2;
                for x in (u32::from(c)..=u32::from(end)).filter_map(char::from_u32) {
                    out.push_str(&regex::escape(&folds(x)));
                }
            } else {
                let alternatives = regex::escape(&folds(c));
                if !bracket {
                    out.push('[');
                }
                out.push_str(&alternatives);
                if !bracket {
                    out.push(']');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn validate(pattern: &str) -> Result<(), regex::Error> {
    let pattern = pattern.strip_prefix("(?i)").unwrap_or(pattern);
    let chars: Vec<_> = pattern.chars().collect();
    let mut bracket = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            i += 2;
            continue;
        }
        if c == '[' {
            bracket = true;
        } else if c == ']' {
            bracket = false;
        } else if bracket && c == '-' && chars.get(i + 1) == Some(&'-') {
            return Err(regex::Error::Syntax(
                "JavaScript class cannot contain --".into(),
            ));
        } else if !bracket
            && c == '('
            && chars.get(i + 1) == Some(&'?')
            && chars.get(i + 2) != Some(&':')
        {
            return Err(regex::Error::Syntax(
                "only one leading (?i) flag is supported".into(),
            ));
        }
        i += 1;
    }
    Ok(())
}

/// Compile a JavaScript pattern using the linear-time `regex` engine.
/// A leading `(?i)` corresponds to JavaScript's `i` flag (without `u`).
pub fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    validate(pattern)?;
    Regex::new(&translate(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn javascript_classes_inside_and_outside_brackets() {
        for (class, yes, no) in [
            (r"\s", "\u{feff}", "\u{85}"),
            (r"\S", "\u{85}", "\u{feff}"),
            (r"\w", "a", "é"),
            (r"\W", "é", "a"),
            (r"\d", "5", "٥"),
            (r"\D", "٥", "5"),
        ] {
            for pattern in [format!("^{class}$"), format!("^[{class}]$")] {
                let re = compile(&pattern).unwrap();
                assert!(re.is_match(yes), "{pattern}");
                assert!(!re.is_match(no), "{pattern}");
            }
            let escaped = format!(r"^\{class}$");
            assert!(compile(&escaped).unwrap().is_match(class));
        }
        assert!(compile(r"\bé\B").unwrap().is_match("aé!"));
        assert!(!compile(r"\bé").unwrap().is_match(" é"));
        assert!(compile(r"[\b]").unwrap().is_match("\x08"));
        assert!(compile(r"[\B]").unwrap().is_match("B"));
        assert_eq!(translate(r"\\s\\w\\d\\b\\B"), r"\\s\\w\\d\\b\\B");
    }

    #[test]
    fn legacy_case_folding_does_not_introduce_unicode_ascii_equivalents() {
        for pattern in ["(?i)^[a-z]+$", "(?i)^k[s]+$", r"(?i)^\w+$"] {
            let re = compile(pattern).unwrap();
            assert!(re.is_match("Ks"));
            assert!(!re.is_match("Kſ"));
        }
        let re = compile("(?i)^éμ$").unwrap();
        assert!(re.is_match("ÉΜ"));
        assert!(re.is_match("éµ"));
    }
}
