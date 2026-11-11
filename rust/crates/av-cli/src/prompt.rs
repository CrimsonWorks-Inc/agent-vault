//! Interactive terminal prompts for the guided flows. Ports
//! `src/cli/prompt.js`.

use crate::CliError;

/// Ctrl-C in a prompt: an ordinary outcome, nothing committed. Ports
/// `class Cancelled` in `src/cli/prompt.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cancelled")]
pub struct Cancelled;

/// Refuse with `<what> needs a terminal` (the `noTty` error the runner turns
/// into a usage failure) unless stdin and stdout are TTYs. Ports
/// `requireTty(what)` in `src/cli/prompt.js`.
pub fn require_tty(what: &str) -> Result<(), CliError> {
    todo!()
}

/// ANSI styling, identity when stdout is not a TTY or `NO_COLOR` is set.
/// Ports `colors` (`C`) in `src/cli/prompt.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colors {
    /// Whether to emit escapes.
    pub enabled: bool,
}

impl Colors {
    /// For this process's stdout and environment. Ports the TTY and
    /// `NO_COLOR` test that builds `C` in `src/cli/prompt.js`.
    pub fn detect() -> Self {
        todo!()
    }
    /// Ports `C.dim` in `src/cli/prompt.js`.
    pub fn dim(&self, s: &str) -> String {
        todo!()
    }
    /// Ports `C.bold` in `src/cli/prompt.js`.
    pub fn bold(&self, s: &str) -> String {
        todo!()
    }
    /// Ports `C.cyan` in `src/cli/prompt.js`.
    pub fn cyan(&self, s: &str) -> String {
        todo!()
    }
    /// Ports `C.green` in `src/cli/prompt.js`.
    pub fn green(&self, s: &str) -> String {
        todo!()
    }
    /// Ports `C.red` in `src/cli/prompt.js`.
    pub fn red(&self, s: &str) -> String {
        todo!()
    }
    /// Ports `C.yellow` in `src/cli/prompt.js`.
    pub fn yellow(&self, s: &str) -> String {
        todo!()
    }
    /// Ports `C.inverse` in `src/cli/prompt.js`.
    pub fn inverse(&self, s: &str) -> String {
        todo!()
    }
}

/// One choice in [`select`]. Ports the `{ value, label, hint }` choices in
/// `src/cli/prompt.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice<T> {
    /// What choosing it returns.
    pub value: T,
    /// Shown text.
    pub label: String,
    /// Dim text after the label.
    pub hint: Option<String>,
}

/// Arrow-key menu; returns the chosen value. Ports
/// `select(question, choices, { initial })` in `src/cli/prompt.js`.
pub fn select<T: Clone>(
    question: &str,
    choices: &[Choice<T>],
    initial: usize,
) -> Result<T, CliError> {
    todo!()
}

/// A validator: an error message to ask again, or `None` to accept. Ports
/// the `validate` option of `text` in `src/cli/prompt.js`.
pub type Validate<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Options for [`text`]. Ports the options of
/// `text(question, { placeholder, defaultValue, validate, allowEmpty })` in
/// `src/cli/prompt.js`.
#[derive(Default)]
pub struct TextOptions<'a> {
    /// Dim example shown in the input.
    pub placeholder: Option<&'a str>,
    /// Used when the answer is empty.
    pub default_value: Option<&'a str>,
    /// Returns an error message to ask again.
    pub validate: Option<Validate<'a>>,
    /// Accept an empty answer.
    pub allow_empty: bool,
}

/// Ask for a line of text. Ports `text(question, opts)` in
/// `src/cli/prompt.js`.
pub fn text(question: &str, opts: TextOptions<'_>) -> Result<String, CliError> {
    todo!()
}

/// Yes/no. Ports `confirm(question, { defaultYes })` in
/// `src/cli/prompt.js`.
pub fn confirm(question: &str, default_yes: bool) -> Result<bool, CliError> {
    todo!()
}

/// A secret with echo off. Ports `secret(question)` in
/// `src/cli/prompt.js`.
pub fn secret(question: &str) -> Result<av_core::secret::SecretString, CliError> {
    todo!()
}

/// `[n/total] title`. Ports `step(n, total, title)` in `src/cli/prompt.js`.
pub fn step(n: usize, total: usize, title: &str) {
    todo!()
}

/// Dim indented lines. Ports `note(lines)` in `src/cli/prompt.js`.
pub fn note(lines: &[&str]) {
    todo!()
}

/// An empty line. Ports `blank()` in `src/cli/prompt.js`.
pub fn blank() {
    todo!()
}

/// A titled two-column summary. Ports `summary(title, rows)` in
/// `src/cli/prompt.js`.
pub fn summary(title: &str, rows: &[(&str, &str)]) {
    todo!()
}
