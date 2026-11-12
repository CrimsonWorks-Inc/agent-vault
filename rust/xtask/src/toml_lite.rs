//! A tiny reader for the subset of TOML that `mutations.toml` uses: an array
//! of tables (`[[mutation]]`) whose values are strings. It supports basic
//! (`"…"`), literal (`'…'`) and multi-line (`"""…"""`, `'''…'''`) strings and
//! `#` comments. Anything else is an error naming the line, so a typo can never
//! silently drop an entry. (A full TOML crate is not on the approved list.)

use std::collections::BTreeMap;

/// One `[[<table>]]` entry: key -> string value, plus the line it started on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub line: usize,
    pub fields: BTreeMap<String, String>,
}

/// Parse `src`, returning the entries of every `[[table]]` block. Keys outside
/// a `[[table]]` block are an error.
pub fn parse_tables(src: &str, table: &str) -> Result<Vec<Entry>, String> {
    let mut p = Parser {
        s: src.as_bytes(),
        i: 0,
        line: 1,
    };
    let mut out: Vec<Entry> = Vec::new();
    let header = format!("[[{table}]]");
    loop {
        p.skip_ws_and_comments();
        if p.eof() {
            return Ok(out);
        }
        if p.peek() == Some(b'[') {
            let start = p.line;
            let rest = p.take_line();
            let h = strip_comment(rest).trim();
            if h != header {
                return Err(format!("line {start}: expected `{header}`, found `{h}`"));
            }
            out.push(Entry {
                line: start,
                fields: BTreeMap::new(),
            });
            continue;
        }
        let line = p.line;
        let key = p.key().map_err(|e| format!("line {line}: {e}"))?;
        p.skip_inline_ws();
        if p.bump() != Some(b'=') {
            return Err(format!("line {line}: expected `=` after `{key}`"));
        }
        p.skip_inline_ws();
        let value = p.string().map_err(|e| format!("line {line}: {e}"))?;
        p.end_of_line().map_err(|e| format!("line {line}: {e}"))?;
        let Some(entry) = out.last_mut() else {
            return Err(format!("line {line}: `{key}` outside a `{header}` block"));
        };
        if entry.fields.insert(key.clone(), value).is_some() {
            return Err(format!("line {line}: duplicate key `{key}`"));
        }
    }
}

fn strip_comment(s: &str) -> &str {
    match s.find('#') {
        Some(i) => &s[..i],
        None => s,
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    line: usize,
}

impl<'a> Parser<'a> {
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn starts_with(&self, pat: &[u8]) -> bool {
        self.s[self.i..].starts_with(pat)
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        if c == b'\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn take_line(&mut self) -> &'a str {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b'\n' {
                break;
            }
            self.i += 1;
        }
        std::str::from_utf8(&self.s[start..self.i]).unwrap_or("")
    }

    fn skip_inline_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.bump();
                }
                Some(b'#') => {
                    self.take_line();
                }
                _ => return,
            }
        }
    }

    fn end_of_line(&mut self) -> Result<(), String> {
        self.skip_inline_ws();
        match self.peek() {
            None | Some(b'\n') => Ok(()),
            Some(b'\r') if self.s.get(self.i + 1) == Some(&b'\n') => Ok(()),
            Some(b'#') => {
                self.take_line();
                Ok(())
            }
            Some(c) => Err(format!("unexpected `{}` after value", c as char)),
        }
    }

    fn key(&mut self) -> Result<String, String> {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
                self.i += 1;
            } else {
                break;
            }
        }
        if self.i == start {
            return Err("expected a bare key".into());
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn string(&mut self) -> Result<String, String> {
        if self.starts_with(b"\"\"\"") {
            self.i += 3;
            self.skip_first_newline();
            self.basic_until(b"\"\"\"")
        } else if self.starts_with(b"'''") {
            self.i += 3;
            self.skip_first_newline();
            self.literal_until(b"'''")
        } else if self.peek() == Some(b'"') {
            self.i += 1;
            self.basic_until(b"\"")
        } else if self.peek() == Some(b'\'') {
            self.i += 1;
            self.literal_until(b"'")
        } else {
            Err("only string values are supported".into())
        }
    }

    fn skip_first_newline(&mut self) {
        if self.starts_with(b"\r\n") {
            self.i += 1;
        }
        if self.peek() == Some(b'\n') {
            self.bump();
        }
    }

    fn literal_until(&mut self, close: &[u8]) -> Result<String, String> {
        let start = self.i;
        while !self.eof() {
            if self.starts_with(close) {
                let v = std::str::from_utf8(&self.s[start..self.i])
                    .map_err(|_| "string is not UTF-8".to_string())?
                    .to_string();
                if close.len() == 1 && v.contains('\n') {
                    return Err("newline in a single-line string".into());
                }
                self.i += close.len();
                return Ok(v);
            }
            self.bump();
        }
        Err("unterminated string".into())
    }

    fn basic_until(&mut self, close: &[u8]) -> Result<String, String> {
        let mut out: Vec<u8> = Vec::new();
        while !self.eof() {
            if self.starts_with(close) {
                self.i += close.len();
                return String::from_utf8(out).map_err(|_| "string is not UTF-8".to_string());
            }
            let c = self.bump().unwrap_or(0);
            if c == b'\n' && close.len() == 1 {
                return Err("newline in a single-line string".into());
            }
            if c != b'\\' {
                out.push(c);
                continue;
            }
            match self.bump() {
                Some(b'"') => out.push(b'"'),
                Some(b'\\') => out.push(b'\\'),
                Some(b'n') => out.push(b'\n'),
                Some(b't') => out.push(b'\t'),
                Some(b'r') => out.push(b'\r'),
                Some(b'b') => out.push(0x08),
                Some(b'f') => out.push(0x0c),
                Some(u @ (b'u' | b'U')) => {
                    let n = if u == b'u' { 4 } else { 8 };
                    let hex = self
                        .s
                        .get(self.i..self.i + n)
                        .and_then(|h| std::str::from_utf8(h).ok())
                        .ok_or("short unicode escape")?;
                    let cp = u32::from_str_radix(hex, 16).map_err(|_| "bad unicode escape")?;
                    let ch = char::from_u32(cp).ok_or("bad unicode scalar")?;
                    self.i += n;
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                // Line-ending backslash in a multi-line basic string trims the
                // newline and the leading whitespace that follows.
                Some(b'\n') if close.len() == 3 => {
                    while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                        self.bump();
                    }
                }
                Some(c) => return Err(format!("unknown escape `\\{}`", c as char)),
                None => return Err("unterminated string".into()),
            }
        }
        Err("unterminated string".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_string_form() {
        let src = r#"
# a comment
[[mutation]]
name = "basic \"quoted\" é"   # trailing comment
file = 'src/lib.rs'
from = """
line one
line two"""
to = '''raw \n stays'''
"#;
        let got = parse_tables(src, "mutation").unwrap();
        assert_eq!(got.len(), 1);
        let f = &got[0].fields;
        assert_eq!(f["name"], "basic \"quoted\" \u{e9}");
        assert_eq!(f["file"], "src/lib.rs");
        assert_eq!(f["from"], "line one\nline two");
        assert_eq!(f["to"], "raw \\n stays");
    }

    #[test]
    fn rejects_what_it_does_not_understand() {
        assert!(parse_tables("[[mutation]]\nname = 3\n", "mutation").is_err());
        assert!(parse_tables("name = \"x\"\n", "mutation").is_err());
        assert!(parse_tables("[other]\n", "mutation").is_err());
        assert!(parse_tables("[[mutation]]\na = \"1\"\na = \"2\"\n", "mutation").is_err());
        assert!(parse_tables("[[mutation]]\na = \"open\n", "mutation").is_err());
    }

    #[test]
    fn several_entries() {
        let src = "[[mutation]]\nname = \"a\"\n\n[[mutation]]\nname = \"b\"\n";
        let got = parse_tables(src, "mutation").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].fields["name"], "b");
        assert_eq!(got[1].line, 4);
    }
}
