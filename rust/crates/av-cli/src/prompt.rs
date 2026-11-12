//! Interactive terminal prompts for the guided flows. Ports
//! `src/cli/prompt.js`.
//!
//! Menus are numbered. Arrow-key raw mode needs a terminal discipline this
//! crate cannot set without `unsafe`; a number on a line chooses the same
//! value, and tests of the pure wizard decisions never reach a prompt.

use std::io::{BufRead, Write};

use av_core::errors::Exit;
use av_core::secret::SecretString;

use crate::CliError;

/// Ctrl-C in a prompt: an ordinary outcome, nothing committed. Ports
/// `class Cancelled` in `src/cli/prompt.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cancelled")]
pub struct Cancelled;

/// The error the wizard runner turns into exit 0 and the cancelled line.
pub fn cancelled() -> CliError {
    CliError {
        message: "cancelled".into(),
        exit: Exit::Ok,
        next: None,
        problem: None,
        skew: false,
    }
}

fn tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::io::IsTerminal::is_terminal(&std::io::stdout())
}

/// Refuse with `<what> needs a terminal` (the `noTty` error the runner turns
/// into a usage failure) unless stdin and stdout are TTYs. Ports
/// `requireTty(what)` in `src/cli/prompt.js`.
pub fn require_tty(what: &str) -> Result<(), CliError> {
    if tty() {
        return Ok(());
    }
    Err(CliError {
        message: format!("{what} needs a terminal"),
        exit: Exit::Usage,
        next: Some("agent-vault help   (pass the options as flags instead)".into()),
        problem: None,
        skew: false,
    })
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
        Self {
            enabled: std::io::IsTerminal::is_terminal(&std::io::stdout())
                && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    /// Ports `C.dim` in `src/cli/prompt.js`.
    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    /// Ports `C.bold` in `src/cli/prompt.js`.
    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    /// Ports `C.cyan` in `src/cli/prompt.js`.
    pub fn cyan(&self, s: &str) -> String {
        self.paint("36", s)
    }
    /// Ports `C.green` in `src/cli/prompt.js`.
    pub fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }
    /// Ports `C.red` in `src/cli/prompt.js`.
    pub fn red(&self, s: &str) -> String {
        self.paint("31", s)
    }
    /// Ports `C.yellow` in `src/cli/prompt.js`.
    pub fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }
    /// Ports `C.inverse` in `src/cli/prompt.js`.
    pub fn inverse(&self, s: &str) -> String {
        self.paint("7", s)
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

fn read_line() -> Result<String, CliError> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => Err(cancelled()),
        Ok(_) => {
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            }
            Ok(line)
        }
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Err(cancelled()),
        Err(e) => Err(CliError {
            message: e.to_string(),
            exit: Exit::Failure,
            next: None,
            problem: None,
            skew: false,
        }),
    }
}

/// Numbered menu; returns the chosen value. Ports
/// `select(question, choices, { initial })` in `src/cli/prompt.js`.
pub fn select<T: Clone>(
    question: &str,
    choices: &[Choice<T>],
    initial: usize,
) -> Result<T, CliError> {
    require_tty("this question")?;
    if choices.is_empty() {
        return Err(CliError {
            message: "nothing to choose".into(),
            exit: Exit::Usage,
            next: None,
            problem: None,
            skew: false,
        });
    }
    let c = Colors::detect();
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{} {question}", c.bold("?"));
    for (i, choice) in choices.iter().enumerate() {
        let marker = if i == initial {
            c.cyan(">")
        } else {
            " ".into()
        };
        let hint = choice
            .hint
            .as_deref()
            .map(|h| format!(" {}", c.dim(h)))
            .unwrap_or_default();
        let label = if i == initial {
            c.cyan(&choice.label)
        } else {
            choice.label.clone()
        };
        let _ = writeln!(stdout, "  {marker} {}. {label}{hint}", i + 1);
    }
    let _ = writeln!(stdout, "{}", c.dim("  enter a number"));
    let _ = stdout.flush();
    loop {
        let line = read_line()?;
        let trimmed = line.trim();
        if let Ok(n) = trimmed.parse::<usize>() {
            if (1..=choices.len()).contains(&n) {
                let chosen = &choices[n - 1];
                let _ = writeln!(
                    stdout,
                    "{} {question} {}",
                    c.green("ok"),
                    c.cyan(&chosen.label)
                );
                return Ok(chosen.value.clone());
            }
        }
        let _ = writeln!(stdout, "{}", c.red("  enter one of the numbers"));
    }
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
    require_tty("this question")?;
    let c = Colors::detect();
    let mut stdout = std::io::stdout();
    loop {
        let suffix = if let Some(default) = opts.default_value {
            c.dim(&format!(" ({default})"))
        } else if let Some(placeholder) = opts.placeholder {
            c.dim(&format!(" ({placeholder})"))
        } else {
            String::new()
        };
        let _ = write!(stdout, "{} {question}{suffix} ", c.bold("?"));
        let _ = stdout.flush();
        let answer = read_line()?;
        let value = {
            let trimmed = answer.trim();
            if trimmed.is_empty() {
                opts.default_value.unwrap_or("").to_string()
            } else {
                trimmed.to_string()
            }
        };
        if value.is_empty() && !opts.allow_empty {
            let _ = writeln!(stdout, "{}", c.red("  a value is required"));
            continue;
        }
        if let Some(validate) = opts.validate {
            if let Some(problem) = validate(&value) {
                let _ = writeln!(stdout, "{}", c.red(&format!("  {problem}")));
                continue;
            }
        }
        return Ok(value);
    }
}

/// Yes/no. Ports `confirm(question, { defaultYes })` in
/// `src/cli/prompt.js`.
pub fn confirm(question: &str, default_yes: bool) -> Result<bool, CliError> {
    require_tty("this question")?;
    let c = Colors::detect();
    let hint = if default_yes { "Y/n" } else { "y/N" };
    let mut stdout = std::io::stdout();
    let _ = write!(
        stdout,
        "{} {question} {} ",
        c.bold("?"),
        c.dim(&format!("[{hint}]"))
    );
    let _ = stdout.flush();
    let answer = read_line()?;
    let t = answer.trim().to_ascii_lowercase();
    if t.is_empty() {
        return Ok(default_yes);
    }
    Ok(t == "y" || t == "yes")
}

/// A secret with echo off. Ports `secret(question)` in
/// `src/cli/prompt.js`.
pub fn secret(question: &str) -> Result<SecretString, CliError> {
    require_tty("entering a credential value")?;
    let c = Colors::detect();
    let value = rpassword::prompt_password(format!("{} {question} ", c.bold("?")))
        .map_err(|_| cancelled())?;
    Ok(SecretString::from(value))
}

/// `[n/total] title`. Ports `step(n, total, title)` in `src/cli/prompt.js`.
pub fn step(n: usize, total: usize, title: &str) {
    let c = Colors::detect();
    println!(
        "\n{}  {}",
        c.dim(&format!("step {n}/{total}")),
        c.bold(title)
    );
}

/// Dim indented lines. Ports `note(lines)` in `src/cli/prompt.js`.
pub fn note(lines: &[&str]) {
    let c = Colors::detect();
    for line in lines {
        println!("  {}", c.dim(line));
    }
}

/// An empty line. Ports `blank()` in `src/cli/prompt.js`.
pub fn blank() {
    println!();
}

/// A titled two-column summary. Ports `summary(title, rows)` in
/// `src/cli/prompt.js`.
pub fn summary(title: &str, rows: &[(&str, &str)]) {
    let c = Colors::detect();
    println!("\n  {}", c.bold(title));
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in rows {
        println!("    {}  {v}", c.dim(&format!("{k:<width$}")));
    }
    println!();
}
