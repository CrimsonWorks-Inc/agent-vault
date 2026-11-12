//! Scrubbing a server-sent event stream. Ports `scrubEventStream`,
//! `parseEventJson`, `jsonStringsByPath`, `gatheringsOf` and `eventRuns` in
//! `src/daemon/pipeline.js`, whose comments explain each step: the bytes go
//! through the scrubber's own stream (a secret across a chunk boundary), the
//! `data:` payloads are joined and watched (a secret across events), and each
//! JSON payload's strings are gathered by key path and index the way client
//! SDKs put them back together (a secret across application fields). Any of
//! these finding a secret cuts the stream.
//!
//! Text here is latin1: one char per byte, so binary survives and offsets
//! match the JS, which reads the stream as `latin1` too.

use std::collections::HashMap;

use av_core::scrub::{ScrubStream, Scrubber};
use serde_json::Value;

use crate::pipeline::{MAX_EVENT_BYTES, MAX_SSE_INDEXES, MAX_SSE_PATHS};
use crate::util::{js_stringify, latin1_bytes, latin1_string};

/// Why a stream was cut, with the sentence the agent is sent.
pub fn why(reason: &str) -> String {
    match reason {
        "credential_split_across_events" => {
            "the upstream split a credential across events; the stream was cut".into()
        }
        "too_many_paths" => format!(
            "the upstream stream used more than {MAX_SSE_PATHS} JSON key paths, more than can be tracked for a credential split across events; the stream was cut"
        ),
        "too_many_indexes" => format!(
            "the upstream stream put more than {MAX_SSE_INDEXES} index fields over one value, more than can be tracked for a credential split across events; the stream was cut"
        ),
        "response_unscannable" => "the upstream nested encodings deeper than could be decoded within budget, so an event could not be fully scrubbed; the stream was cut".into(),
        _ => "the upstream stream failed before it finished; the stream was cut".into(),
    }
}

/// The closing error event.
pub fn cut_frame(detail: &str) -> Vec<u8> {
    let body = crate::util::obj([
        ("code", Value::from("AV_UNSCANNABLE")),
        ("detail", Value::from(detail)),
    ]);
    latin1_bytes(&format!("event: error\ndata: {}\n\n", js_stringify(&body)))
}

/// What the stream scrubber does with each input.
pub enum Step {
    /// Frames to send, in order.
    Frames(Vec<Vec<u8>>),
    /// Frames to send, then the stream ends with this cut (`reason`, frame).
    Cut(Vec<Vec<u8>>, String, Vec<u8>),
}

/// The scrubber of one event stream.
pub struct EventScrub {
    check: Scrubber,
    pending: String,
    scanned: usize,
    carry: String,
    assembled: String,
    total: usize,
    keep: usize,
    max_bytes: usize,
    runs: Runs,
}

impl EventScrub {
    /// `check` searches the reassemblies; the bytes are framed by a
    /// [`ScrubStream`] over a second scrubber with the same secrets, passed
    /// to each call (see [`run`]). The JS uses one object for both; the only
    /// state a scrubber keeps is a record of which derived patterns it has
    /// seen, which neither use reads.
    pub fn new(check: Scrubber, max_bytes: usize) -> EventScrub {
        let keep = check.overlap() * 4;
        EventScrub {
            check,
            pending: String::new(),
            scanned: 0,
            carry: String::new(),
            assembled: String::new(),
            total: 0,
            keep,
            max_bytes,
            runs: Runs::new(keep),
        }
    }

    fn lf(&mut self, text: String) -> String {
        let mut t = std::mem::take(&mut self.carry) + &text;
        if t.ends_with('\r') {
            self.carry = "\r".into();
            t.pop();
        }
        t.replace("\r\n", "\n").replace('\r', "\n")
    }

    fn events(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let from = self.scanned.min(self.pending.len());
            let Some(rel) = self.pending[from..].find("\n\n") else {
                break;
            };
            let boundary = from + rel;
            let rest = self.pending.split_off(boundary + 2);
            out.push(std::mem::replace(&mut self.pending, rest));
            self.scanned = 0;
        }
        self.scanned = self.pending.len().saturating_sub(1);
        out
    }

    fn leaked(&mut self, text: &str) -> Option<&'static str> {
        let crude: String = text
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "_-+/=".contains(*c))
            .collect();
        for v in [text.to_string(), json_values(text), crude] {
            if v.is_empty() {
                continue;
            }
            let r = self.check.scrub(&v);
            if r.redactions > 0 {
                return Some("credential_split_across_events");
            }
            if r.unscannable {
                return Some("response_unscannable");
            }
        }
        None
    }

    fn leaks(&mut self, event: &str) -> Option<&'static str> {
        let data = data_of(event);
        let joined = self.assembled.clone() + &data.concat();
        self.assembled = tail(&joined, self.keep);
        if let Some(r) = self.leaked(&joined) {
            return Some(r);
        }
        if data.is_empty() {
            return None;
        }
        match parse_event_json(&data.join("\n")) {
            Parsed::Value(v) => self.runs.add(&v, &mut self.check),
            Parsed::TooDeep => Some("response_unscannable"),
            Parsed::No => None,
        }
    }

    fn cut(&self, frames: Vec<Vec<u8>>, reason: &str, detail: String) -> Step {
        Step::Cut(frames, reason.to_string(), cut_frame(&detail))
    }

    /// One decoded chunk from the upstream.
    pub fn push(&mut self, frame: &mut ScrubStream<'_>, chunk: &[u8]) -> Step {
        self.total += chunk.len();
        if self.total > self.max_bytes {
            let mib = (self.max_bytes as f64 / 1024.0 / 1024.0).round();
            return self.cut(
                Vec::new(),
                "stream_too_large",
                format!("the upstream stream decoded to more than {mib} MiB; the stream was cut"),
            );
        }
        let framed = frame.push(&latin1_string(chunk));
        let text = self.lf(framed);
        self.pending.push_str(&text);
        let mut frames = Vec::new();
        for event in self.events() {
            if let Some(reason) = self.leaks(&event) {
                return self.cut(frames, reason, why(reason));
            }
            frames.push(latin1_bytes(&event));
        }
        if self.pending.len() > MAX_EVENT_BYTES {
            let mib = (MAX_EVENT_BYTES as f64 / 1024.0 / 1024.0).round();
            return self.cut(
                frames,
                "event_too_large",
                format!("one event grew past {mib} MiB without ending; the stream was cut"),
            );
        }
        Step::Frames(frames)
    }

    /// The upstream failed part way.
    pub fn fail(&mut self) -> Step {
        self.cut(Vec::new(), "upstream_failed", why("upstream_failed"))
    }

    /// The upstream ended.
    pub fn finish(&mut self, frame: &mut ScrubStream<'_>) -> Step {
        let flushed = frame.flush();
        let mut text = self.lf(flushed);
        if !self.carry.is_empty() {
            text.push('\n');
            self.carry.clear();
        }
        self.pending.push_str(&text);
        let mut all = self.events();
        all.push(std::mem::take(&mut self.pending));
        let mut frames = Vec::new();
        for event in all.into_iter().filter(|e| !e.is_empty()) {
            if let Some(reason) = self.leaks(&event) {
                return self.cut(frames, reason, why(reason));
            }
            frames.push(latin1_bytes(&event));
        }
        Step::Frames(frames)
    }
}

/// What the stream driver reads from the upstream side.
pub enum Input {
    /// Decoded bytes.
    Chunk(Vec<u8>),
    /// The upstream failed part way.
    Failed,
    /// The upstream ended.
    End,
}

/// Run one stream to its end: read with `next`, send each frame with `emit`
/// (false when the agent has gone), and report a cut with `on_cut`. Returns
/// whether the stream completed (the JS `closeAware` `complete`): false when
/// it was cut, failed, or the agent stopped reading.
pub fn run(
    framing: Scrubber,
    check: Scrubber,
    max_bytes: usize,
    mut next: impl FnMut() -> Input,
    mut emit: impl FnMut(Vec<u8>) -> bool,
    mut on_cut: impl FnMut(&str),
) -> bool {
    let mut framing = framing;
    let mut frame = framing.stream();
    let mut st = EventScrub::new(check, max_bytes);
    loop {
        let step = match next() {
            Input::Chunk(c) => st.push(&mut frame, &c),
            Input::Failed => st.fail(),
            Input::End => {
                let last = st.finish(&mut frame);
                return match last {
                    Step::Frames(f) => f.into_iter().all(&mut emit),
                    Step::Cut(f, reason, cut) => {
                        let _ = f.into_iter().all(&mut emit);
                        on_cut(&reason);
                        let _ = emit(cut);
                        false
                    }
                };
            }
        };
        match step {
            Step::Frames(f) => {
                for x in f {
                    if !emit(x) {
                        return false;
                    }
                }
            }
            Step::Cut(f, reason, cut) => {
                let _ = f.into_iter().all(&mut emit);
                on_cut(&reason);
                let _ = emit(cut);
                return false;
            }
        }
    }
}

/// `dataOf(event)`.
fn data_of(event: &str) -> Vec<String> {
    event
        .split('\n')
        .filter(|l| l.starts_with("data:"))
        .map(|l| {
            let v = &l[5..];
            v.strip_prefix(' ').unwrap_or(v).to_string()
        })
        .collect()
}

/// The last `keep` characters.
fn tail(s: &str, keep: usize) -> String {
    let n = s.chars().count();
    if n <= keep {
        s.to_string()
    } else {
        s.chars().skip(n - keep).collect()
    }
}

/// `jsonValues(text)`: every JSON string literal that is not a key, joined.
fn json_values(text: &str) -> String {
    let re =
        av_core::jsre::compile(r#""((?:[^"\\]|\\[^\n\r])*)"(\s*:)?"#).expect("literal pattern");
    let mut out = String::new();
    for caps in re.captures_iter(text) {
        if caps.get(2).is_some() {
            continue;
        }
        let inner = caps.get(1).map_or("", |m| m.as_str());
        out.push_str(&inner.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    out
}

enum Parsed {
    Value(Value),
    TooDeep,
    No,
}

/// `parseEventJson(payload)`: JSON, or JSON with Python's `NaN`/`Infinity`
/// read as null. Lone surrogate escapes (JS reads them, serde does not) are
/// read as U+FFFD, and nesting past serde's limit is refused, so neither can
/// hide a payload from the per-path reassembly.
fn parse_event_json(payload: &str) -> Parsed {
    match parse_js_json(payload) {
        Ok(v) => return Parsed::Value(v),
        Err(deep) if deep => return Parsed::TooDeep,
        Err(_) => {}
    }
    let chars: Vec<char> = payload.chars().collect();
    let mut swapped = String::new();
    let mut from = 0;
    let mut in_string = false;
    let mut i = 0;
    let starts = |i: usize, w: &str| chars[i..].iter().take(w.len()).copied().eq(w.chars());
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            if c == '\\' {
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
            i += 1;
            continue;
        }
        let word = if starts(i, "NaN") {
            3
        } else if starts(i, "Infinity") {
            8
        } else {
            0
        };
        if word == 0 {
            i += 1;
            continue;
        }
        let end = if i > 0 && chars[i - 1] == '-' {
            i - 1
        } else {
            i
        };
        swapped.extend(&chars[from..end.max(from)]);
        swapped.push_str("null");
        i += word;
        from = i;
    }
    if from == 0 {
        return Parsed::No;
    }
    swapped.extend(&chars[from..]);
    match parse_js_json(&swapped) {
        Ok(v) => Parsed::Value(v),
        Err(deep) if deep => Parsed::TooDeep,
        Err(_) => Parsed::No,
    }
}

/// JSON as `JSON.parse` reads it; `Err(true)` when only the nesting depth
/// stopped it.
fn parse_js_json(text: &str) -> Result<Value, bool> {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("recursion limit") {
                return Err(true);
            }
            if msg.contains("surrogate") {
                return serde_json::from_str::<Value>(&fix_surrogates(text))
                    .map_err(|e| e.to_string().contains("recursion limit"));
            }
            Err(false)
        }
    }
}

/// Every `\uD800`–`\uDFFF` escape as `�`.
fn fix_surrogates(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut last = 0;
    while i + 5 < b.len() && i + 6 <= b.len() {
        if b[i] == b'\\' {
            if b[i + 1] == b'u' {
                let hex = &text[i + 2..i + 6];
                if let Ok(n) = u16::from_str_radix(hex, 16) {
                    if (0xD800..=0xDFFF).contains(&n) {
                        out.push_str(&text[last..i]);
                        out.push_str("\\uFFFD");
                        i += 6;
                        last = i;
                        continue;
                    }
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    out.push_str(&text[last..]);
    out
}

/// `INDEX_FIELD`: `index`, or `<something>_index` not starting `start_`/`end_`.
fn index_field(k: &str) -> bool {
    k == "index"
        || (k.len() > "_index".len()
            && k.ends_with("_index")
            && !k.starts_with("start_")
            && !k.starts_with("end_"))
}

/// A key-path segment: an array position or an object key.
#[derive(Clone, Debug, PartialEq)]
enum Seg {
    I(usize),
    K(String),
}

fn seg_json(s: &Seg) -> Value {
    match s {
        Seg::I(i) => Value::from(*i as u64),
        Seg::K(k) => Value::from(k.clone()),
    }
}

/// `[depth, key, value]` of an index field over a string.
type Slot = (usize, String, Value);

/// Object keys in the order `Object.entries` gives them: array-index keys
/// first, ascending, then the rest in insertion order.
pub fn js_key_order(m: &serde_json::Map<String, Value>) -> Vec<(&String, &Value)> {
    let is_index = |k: &str| {
        !k.is_empty()
            && (k == "0" || !k.starts_with('0'))
            && k.bytes().all(|b| b.is_ascii_digit())
            && k.parse::<u64>().is_ok_and(|n| n < u32::MAX as u64)
    };
    let mut idx: Vec<_> = m.iter().filter(|(k, _)| is_index(k)).collect();
    idx.sort_by_key(|(k, _)| k.parse::<u64>().unwrap_or(0));
    idx.extend(m.iter().filter(|(k, _)| !is_index(k)));
    idx
}

/// `jsonStringsByPath(value)`.
fn strings_by_path(
    value: &Value,
    path: &mut Vec<Seg>,
    indexes: &[Slot],
    out: &mut Vec<(Vec<Seg>, Vec<Slot>, String)>,
) {
    match value {
        Value::String(s) => out.push((path.clone(), indexes.to_vec(), s.clone())),
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                path.push(Seg::I(i));
                strings_by_path(v, path, indexes, out);
                path.pop();
            }
        }
        Value::Object(m) => {
            let entries = js_key_order(m);
            let here: Vec<Slot> = entries
                .iter()
                .filter(|(k, v)| index_field(k) && (v.is_number() || v.is_string()))
                .map(|(k, v)| (path.len(), (*k).clone(), (*v).clone()))
                .collect();
            let inner: Vec<Slot> = if here.is_empty() {
                indexes.to_vec()
            } else {
                indexes.iter().cloned().chain(here).collect()
            };
            for (k, v) in entries {
                path.push(Seg::K(k.clone()));
                strings_by_path(v, path, &inner, out);
                path.pop();
            }
        }
        _ => {}
    }
}

const APPENDED: &[&str] = &[
    "text",
    "content",
    "delta",
    "arguments",
    "partial_json",
    "thinking",
    "refusal",
    "reasoning",
    "reasoning_content",
];

/// A CONTINUES pattern segment.
enum P {
    K(&'static str),
    At(&'static str),
}

/// `CONTINUES`.
const CONTINUES: &[(&str, &[P], &str)] = &[
    (
        "content_block_start",
        &[P::K("content_block"), P::K("text")],
        "text",
    ),
    (
        "content_block_start",
        &[P::K("content_block"), P::K("thinking")],
        "thinking",
    ),
    (
        "content_block_delta",
        &[P::K("delta"), P::K("text")],
        "text",
    ),
    (
        "content_block_delta",
        &[P::K("delta"), P::K("thinking")],
        "thinking",
    ),
    (
        "response.output_item.added",
        &[
            P::K("item"),
            P::K("content"),
            P::At("content_index"),
            P::K("text"),
        ],
        "output_text",
    ),
    (
        "response.content_part.added",
        &[P::K("part"), P::K("text")],
        "output_text",
    ),
    (
        "response.output_text.delta",
        &[P::K("delta")],
        "output_text",
    ),
    (
        "response.output_item.added",
        &[
            P::K("item"),
            P::K("content"),
            P::At("content_index"),
            P::K("refusal"),
        ],
        "refusal",
    ),
    (
        "response.content_part.added",
        &[P::K("part"), P::K("refusal")],
        "refusal",
    ),
    ("response.refusal.delta", &[P::K("delta")], "refusal"),
    (
        "response.output_item.added",
        &[P::K("item"), P::K("arguments")],
        "arguments",
    ),
    (
        "response.function_call_arguments.delta",
        &[P::K("delta")],
        "arguments",
    ),
    (
        "response.output_item.added",
        &[
            P::K("item"),
            P::K("summary"),
            P::At("summary_index"),
            P::K("text"),
        ],
        "summary",
    ),
    (
        "response.reasoning_summary_part.added",
        &[P::K("part"), P::K("text")],
        "summary",
    ),
    (
        "response.reasoning_summary_text.delta",
        &[P::K("delta")],
        "summary",
    ),
];

struct Way {
    gathering: String,
    indexes: Vec<Slot>,
    appended: bool,
}

/// `gatheringsOf({ path, indexes }, type)`.
fn gatherings_of(path: &[Seg], indexes: &[Slot], ty: Option<&str>) -> Vec<Way> {
    let appended = matches!(path.last(), Some(Seg::K(k)) if APPENDED.contains(&k.as_str()));
    let path_json = Value::Array(path.iter().map(seg_json).collect());
    let mut out = vec![Way {
        gathering: js_stringify(&path_json),
        indexes: indexes.to_vec(),
        appended,
    }];
    if path.iter().any(|s| matches!(s, Seg::I(_))) {
        let nulled = Value::Array(
            path.iter()
                .map(|s| match s {
                    Seg::I(_) => Value::Null,
                    k => seg_json(k),
                })
                .collect(),
        );
        out.push(Way {
            gathering: js_stringify(&nulled),
            indexes: indexes.to_vec(),
            appended,
        });
    }
    for (event_type, pattern, continued) in CONTINUES {
        if Some(*event_type) != ty || pattern.len() != path.len() {
            continue;
        }
        let mut positions: Vec<Slot> = Vec::new();
        let matches = pattern.iter().zip(path).all(|(p, s)| match (p, s) {
            (P::K(k), Seg::K(sk)) => k == sk,
            (P::K(_), Seg::I(_)) => false,
            (P::At(at), Seg::I(i)) => {
                positions.push((0, at.to_string(), Value::from(*i as u64)));
                true
            }
            (P::At(_), Seg::K(_)) => false,
        });
        if !matches {
            continue;
        }
        let own: Vec<Slot> = indexes
            .iter()
            .filter(|(depth, key, _)| !positions.iter().any(|p| *depth == 0 && &p.1 == key))
            .cloned()
            .collect();
        out.push(Way {
            gathering: format!("#{continued}"),
            indexes: own.into_iter().chain(positions).collect(),
            appended: true,
        });
    }
    out
}

/// JS string comparison (UTF-16 code units).
fn js_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn by_slot(a: &Slot, b: &Slot) -> std::cmp::Ordering {
    a.0.cmp(&b.0).then_with(|| js_cmp(&a.1, &b.1))
}

/// `valuesOf(v)`: a numeric-looking string is also its number.
fn values_of(v: &Value) -> Vec<Value> {
    if let Value::String(s) = v {
        let numeric = s == "0"
            || (!s.is_empty()
                && s.len() <= 16
                && s.as_bytes()[0] != b'0'
                && s.bytes().all(|b| b.is_ascii_digit()));
        if numeric {
            if let Ok(n) = s.parse::<u64>() {
                return vec![v.clone(), Value::from(n)];
            }
        }
    }
    vec![v.clone()]
}

const MISSING: [Value; 2] = [Value::Null, Value::Null];

fn missing() -> Vec<Value> {
    let _ = MISSING;
    vec![Value::from(0u64), Value::Null]
}

#[derive(Default)]
struct Seen {
    fields: Vec<(String, (usize, String))>,
    runs: Vec<(String, Vec<Slot>)>,
}

/// `eventRuns(scrubber, keep)`.
struct Runs {
    runs: HashMap<String, String>,
    seen: HashMap<String, Seen>,
    keep: usize,
}

impl Runs {
    fn new(keep: usize) -> Runs {
        Runs {
            runs: HashMap::new(),
            seen: HashMap::new(),
            keep,
        }
    }

    fn key_of(gathering: &str, chosen: &[Slot]) -> String {
        let arr = Value::Array(vec![
            Value::from(gathering),
            Value::Array(
                chosen
                    .iter()
                    .map(|(d, k, v)| {
                        Value::Array(vec![
                            Value::from(*d as u64),
                            Value::from(k.clone()),
                            v.clone(),
                        ])
                    })
                    .collect(),
            ),
        ]);
        let key = js_stringify(&arr);
        if key.encode_utf16().count() > 256 {
            format!("#{}", av_core::canon::sha256(key.as_bytes()))
        } else {
            key
        }
    }

    fn room(&self, key: &str) -> Option<&'static str> {
        if self.runs.contains_key(key) || self.runs.len() < MAX_SSE_PATHS {
            None
        } else {
            Some("too_many_paths")
        }
    }

    fn gather(&mut self, way: &Way, value: &str, scrubber: &mut Scrubber) -> Option<&'static str> {
        let mut fields_here: Vec<(usize, String)> = Vec::new();
        if way.appended {
            self.seen.entry(way.gathering.clone()).or_default();
            for (depth, key, _) in &way.indexes {
                let id = js_stringify(&Value::Array(vec![
                    Value::from(*depth as u64),
                    Value::from(key.clone()),
                ]));
                let here = self.seen.get(&way.gathering).expect("seen");
                if here.fields.iter().any(|(i, _)| *i == id) {
                    continue;
                }
                let existing: Vec<(String, Vec<Slot>)> = here.runs.clone();
                for (from, chosen) in existing {
                    for m in missing() {
                        let mut choice = chosen.clone();
                        choice.push((*depth, key.clone(), m));
                        choice.sort_by(by_slot);
                        let to = Self::key_of(&way.gathering, &choice);
                        if self.runs.contains_key(&to) {
                            continue;
                        }
                        if let Some(full) = self.room(&to) {
                            return Some(full);
                        }
                        let text = self.runs.get(&from).cloned().unwrap_or_default();
                        self.runs.insert(to.clone(), text);
                        let here = self.seen.get_mut(&way.gathering).expect("seen");
                        set_run(&mut here.runs, to, choice);
                    }
                }
                let here = self.seen.get_mut(&way.gathering).expect("seen");
                here.fields.push((id, (*depth, key.clone())));
            }
            fields_here = self
                .seen
                .get(&way.gathering)
                .map(|h| h.fields.iter().map(|(_, f)| f.clone()).collect())
                .unwrap_or_default();
        }
        let mut slots: Vec<(usize, String, Vec<Value>)> = way
            .indexes
            .iter()
            .map(|(d, k, v)| (*d, k.clone(), values_of(v)))
            .collect();
        for (depth, key) in fields_here {
            if !way.indexes.iter().any(|(d, k, _)| *d == depth && *k == key) {
                slots.push((depth, key, missing()));
            }
        }
        if slots.len() > MAX_SSE_INDEXES {
            return Some("too_many_indexes");
        }
        slots.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| js_cmp(&a.1, &b.1)));
        let mut choices: Vec<Vec<Slot>> = vec![Vec::new()];
        for (depth, key, values) in &slots {
            let mut next = Vec::new();
            for c in choices {
                next.push(c.clone());
                for v in values {
                    let mut x = c.clone();
                    x.push((*depth, key.clone(), v.clone()));
                    next.push(x);
                }
            }
            choices = next;
        }
        for chosen in choices {
            let key = Self::key_of(&way.gathering, &chosen);
            if let Some(full) = self.room(&key) {
                return Some(full);
            }
            let run = self.runs.get(&key).cloned().unwrap_or_default() + value;
            let r = scrubber.scrub(&run);
            if r.redactions > 0 {
                return Some("credential_split_across_events");
            }
            if r.unscannable {
                return Some("response_unscannable");
            }
            self.runs.insert(key.clone(), tail(&run, self.keep));
            if way.appended {
                if let Some(here) = self.seen.get_mut(&way.gathering) {
                    set_run(&mut here.runs, key, chosen);
                }
            }
        }
        None
    }

    fn add(&mut self, payload: &Value, scrubber: &mut Scrubber) -> Option<&'static str> {
        let ty = payload
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut strings = Vec::new();
        strings_by_path(payload, &mut Vec::new(), &[], &mut strings);
        for (path, indexes, value) in strings {
            for way in gatherings_of(&path, &indexes, ty.as_deref()) {
                if let Some(reason) = self.gather(&way, &value, scrubber) {
                    return Some(reason);
                }
            }
        }
        None
    }
}

/// `Map.set` on an ordered list: replace in place, or append.
fn set_run(runs: &mut Vec<(String, Vec<Slot>)>, key: String, chosen: Vec<Slot>) {
    if let Some(e) = runs.iter_mut().find(|(k, _)| *k == key) {
        e.1 = chosen;
    } else {
        runs.push((key, chosen));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::scrub::{ScrubEntry, ScrubberOptions};

    const SECRET: &str = "test-secret-conform-0123456789abcdef";

    fn scrubber() -> Scrubber {
        Scrubber::new(
            &[ScrubEntry {
                secret: av_core::secret::SecretString::from(SECRET.to_string()),
                label: "demo".into(),
                replacement: None,
                always: true,
            }],
            &ScrubberOptions::default(),
        )
        .unwrap()
    }

    fn drive(chunks: &[&str]) -> (String, Vec<String>, bool) {
        let mut input: Vec<Input> = chunks
            .iter()
            .map(|c| Input::Chunk(c.as_bytes().to_vec()))
            .collect();
        input.push(Input::End);
        let mut it = input.into_iter();
        let mut out = Vec::new();
        let mut cuts = Vec::new();
        let complete = run(
            scrubber(),
            scrubber(),
            usize::MAX,
            || it.next().unwrap_or(Input::End),
            |f| {
                out.extend(f);
                true
            },
            |r| cuts.push(r.to_string()),
        );
        (String::from_utf8_lossy(&out).into_owned(), cuts, complete)
    }

    #[test]
    fn hardening_a_secret_split_across_events_cuts_the_stream_and_ordinary_events_survive() {
        let (a, b) = SECRET.split_at(16);
        let (text, cuts, complete) = drive(&[
            "data: ordinary-traffic-control\n\n",
            "data: lookalike\n\n",
            &format!("data: {a}\n\n"),
            &format!("data: {b}\n\n"),
            "data: after-cut-marker\n\n",
        ]);
        assert!(text.contains("ordinary-traffic-control"), "{text}");
        assert!(text.contains("lookalike"), "{text}");
        assert!(!text.contains("after-cut-marker"), "{text}");
        assert!(text.contains("AV_UNSCANNABLE"), "{text}");
        assert!(!text.contains(SECRET));
        assert_eq!(cuts, vec!["credential_split_across_events"]);
        assert!(!complete);
        // Control: an ordinary stream goes through whole.
        let (text, cuts, complete) = drive(&["data: one\n\n", "data: two\n\n"]);
        assert_eq!(text, "data: one\n\ndata: two\n\n");
        assert!(cuts.is_empty() && complete);
    }

    #[test]
    fn hardening_a_secret_split_across_json_fields_cuts_the_stream() {
        let (a, b) = SECRET.split_at(10);
        let (text, cuts, _) = drive(&[
            &format!("data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"text\":\"{a}\"}}}}\n\n"),
            "data: {\"type\":\"ping\",\"meta\":\"content_block_delta\"}\n\n",
            &format!("data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"text\":\"{b}\"}}}}\n\n"),
        ]);
        assert!(!text.contains(b) || !text.contains(a));
        assert_eq!(cuts, vec!["credential_split_across_events"]);
    }

    #[test]
    fn crlf_framing_is_split_too() {
        let (text, _, complete) = drive(&["data: one\r\n\r\ndata: tw", "o\r\n\r\n"]);
        assert_eq!(text, "data: one\n\ndata: two\n\n");
        assert!(complete);
    }
}
