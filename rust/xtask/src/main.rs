//! Workspace tasks. Run from `rust/` as `cargo xtask <task>`.
//!
//! `cargo xtask mutation` checks the tests against themselves, like
//! `test/mutation-check.js` does for the JavaScript (rust/PLAN.md, "Tests and
//! the regression net"). Each entry in `crates/*/mutations.toml` breaks one
//! protection by a literal string swap; the tests must then fail. A mutation
//! that survives means the protection it broke is not really tested.
//!
//! The swaps are applied to a temporary copy of the `rust/` tree, never in
//! place, so an interrupted run cannot leave a protection removed in the
//! working tree.
#![forbid(unsafe_code)]

mod mutation;
mod toml_lite;

use std::process::ExitCode;

const USAGE: &str = "\
usage: cargo xtask <task>

tasks:
  mutation [--only <name>] [--keep]
      Apply each entry of crates/*/mutations.toml to a temporary copy of the
      rust/ tree and require `cargo test` to fail. Exits non-zero if any
      mutation survives or no longer applies.
        --only <name>   run just the named mutation (repeatable)
        --keep          keep the temporary copy for inspection
      Environment: MUTATION_TIMEOUT_SECS (default 600) bounds one test run; a
      run that times out counts as caught, as in test/mutation-check.js.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("mutation") => match mutation::Options::parse(&args[1..]) {
            Ok(opts) => mutation::run(&opts),
            Err(e) => {
                eprintln!("error: {e}\n\n{USAGE}");
                ExitCode::from(2)
            }
        },
        Some("-h") | Some("--help") | Some("help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown task `{other}`\n\n{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
