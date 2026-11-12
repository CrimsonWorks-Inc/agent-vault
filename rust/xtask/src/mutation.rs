//! `cargo xtask mutation`: the Rust counterpart of `test/mutation-check.js`.
//!
//! Each `crates/<crate>/mutations.toml` holds entries like:
//!
//! ```toml
//! [[mutation]]
//! name = "secure_delete is switched off"   # what the swap breaks
//! file = "src/db.rs"                       # relative to the crate directory
//! from = "secure_delete = ON"              # must appear exactly once
//! to   = "secure_delete = OFF"
//! test = "pragmas"                         # optional `cargo test` name filter
//! ```
//!
//! For every entry the swap is made in a temporary copy of `rust/` (plus the
//! repo inputs the tests read: `src/`, `bin/`, `package.json`, `web/src`,
//! `README.md`), then
//! `cargo test --workspace` runs there. The mutant must compile (a swap that
//! breaks the build proves nothing) and the tests must fail. A test run that
//! outlives the timeout counts as caught, as in the JS check. The working tree
//! is never modified.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::toml_lite;

/// Command-line options for `cargo xtask mutation`.
#[derive(Debug, Default)]
pub struct Options {
    only: Vec<String>,
    keep: bool,
    scoped: bool,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut o = Options::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--keep" => o.keep = true,
                "--scoped" => o.scoped = true,
                "--only" => o.only.push(it.next().ok_or("--only needs a name")?.clone()),
                s if s.starts_with("--only=") => o.only.push(s["--only=".len()..].to_string()),
                other => return Err(format!("unknown option `{other}`")),
            }
        }
        Ok(o)
    }
}

/// One validated `[[mutation]]` entry.
#[derive(Debug, Clone)]
struct Mutation {
    crate_name: String,
    name: String,
    /// Path relative to `rust/`.
    rel_file: PathBuf,
    from: String,
    to: String,
    test: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Caught,
    CaughtTimeout,
    Missed,
    DoesNotCompile,
}

fn workspace_root() -> PathBuf {
    // xtask lives at rust/xtask, so its parent is the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}

pub fn run(opts: &Options) -> ExitCode {
    match run_inner(opts) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("mutation: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_inner(opts: &Options) -> Result<bool, String> {
    let root = workspace_root();
    let mut mutations = load_all(&root)?;
    if !opts.only.is_empty() {
        let known: BTreeSet<&str> = mutations.iter().map(|m| m.name.as_str()).collect();
        for n in &opts.only {
            if !known.contains(n.as_str()) {
                return Err(format!("no mutation named `{n}`"));
            }
        }
        mutations.retain(|m| opts.only.contains(&m.name));
    }
    if mutations.is_empty() {
        println!("mutation: no entries in crates/*/mutations.toml");
        return Ok(true);
    }

    let timeout = std::env::var("MUTATION_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(600));

    let copy = TempTree::new(opts.keep)?;
    let tree = copy.path.join("rust");
    copy_tree(&root, &tree).map_err(|e| format!("copying {}: {e}", root.display()))?;
    copy_repo_inputs(&root, &copy.path)?;
    // A target dir of its own, so the copy never fights the working tree's
    // build for the lock, and later runs reuse what was compiled.
    let target = root.join("target").join("mutation");
    let logs = copy.path.join("logs");
    fs::create_dir_all(&logs).map_err(|e| e.to_string())?;

    println!(
        "mutation: {} entr{} on a copy at {}",
        mutations.len(),
        if mutations.len() == 1 { "y" } else { "ies" },
        tree.display()
    );

    // The unmutated tree has to be green, or every mutant looks caught.
    let base_log = logs.join("baseline.log");
    match cargo_test(&tree, &target, None, None, timeout, &base_log)? {
        Outcome::Missed => {} // tests passed: the baseline is green
        other => {
            return Err(format!(
                "the unmutated tests are not green ({other:?}); fix them first. Log: {}",
                base_log.display()
            ))
        }
    }

    let mut bad = 0usize;
    for (i, m) in mutations.iter().enumerate() {
        let path = tree.join(&m.rel_file);
        let original = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mutated = original.replacen(&m.from, &m.to, 1);
        fs::write(&path, &mutated).map_err(|e| format!("{}: {e}", path.display()))?;
        let log = logs.join(format!("{i:03}.log"));
        let started = Instant::now();
        let package = opts.scoped.then_some(m.crate_name.as_str());
        let result = cargo_test(&tree, &target, package, m.test.as_deref(), timeout, &log);
        // Restore before anything else, even if the run itself errored.
        fs::write(&path, &original).map_err(|e| format!("{}: {e}", path.display()))?;
        let outcome = result?;
        let secs = started.elapsed().as_secs();
        let label = match outcome {
            Outcome::Caught => "caught".to_string(),
            Outcome::CaughtTimeout => format!("caught (timed out after {}s)", timeout.as_secs()),
            Outcome::Missed => {
                bad += 1;
                format!("MISSED  (log: {})", log.display())
            }
            Outcome::DoesNotCompile => {
                bad += 1;
                format!(
                    "INVALID: the mutant does not compile (log: {})",
                    log.display()
                )
            }
        };
        println!("  [{}] {}: {label}  ({secs}s)", m.crate_name, m.name);
    }

    let caught = mutations.len() - bad;
    println!(
        "mutation: {caught} caught, {bad} not caught, of {}",
        mutations.len()
    );
    if bad > 0 && !opts.keep {
        println!("mutation: rerun with --keep to inspect the logs");
    }
    Ok(bad == 0)
}

/// Read and validate every `crates/*/mutations.toml`.
fn load_all(root: &Path) -> Result<Vec<Mutation>, String> {
    let crates = root.join("crates");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&crates)
        .map_err(|e| format!("{}: {e}", crates.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("mutations.toml").is_file())
        .collect();
    dirs.sort();
    let mut out = Vec::new();
    let mut names = BTreeSet::new();
    for dir in dirs {
        let crate_name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let toml_path = dir.join("mutations.toml");
        let src =
            fs::read_to_string(&toml_path).map_err(|e| format!("{}: {e}", toml_path.display()))?;
        let entries = toml_lite::parse_tables(&src, "mutation")
            .map_err(|e| format!("{}: {e}", toml_path.display()))?;
        for entry in entries {
            let at = format!("{}:{}", toml_path.display(), entry.line);
            let get = |k: &str| -> Result<String, String> {
                entry
                    .fields
                    .get(k)
                    .cloned()
                    .ok_or_else(|| format!("{at}: missing `{k}`"))
            };
            for k in entry.fields.keys() {
                if !matches!(k.as_str(), "name" | "file" | "from" | "to" | "test") {
                    return Err(format!("{at}: unknown key `{k}`"));
                }
            }
            let m = Mutation {
                crate_name: crate_name.clone(),
                name: get("name")?,
                rel_file: Path::new("crates").join(&crate_name).join(get("file")?),
                from: get("from")?,
                to: get("to")?,
                test: entry.fields.get("test").cloned(),
            };
            if m.from.is_empty() || m.from == m.to {
                return Err(format!(
                    "{at}: `from` must be non-empty and differ from `to`"
                ));
            }
            if !names.insert(m.name.clone()) {
                return Err(format!("{at}: duplicate mutation name `{}`", m.name));
            }
            let file = root.join(&m.rel_file);
            let text =
                fs::read_to_string(&file).map_err(|e| format!("{at}: {}: {e}", file.display()))?;
            let n = text.matches(m.from.as_str()).count();
            if n != 1 {
                return Err(format!(
                    "{at}: `from` must appear exactly once in {}, found {n}; the entry is stale",
                    m.rel_file.display()
                ));
            }
            out.push(m);
        }
    }
    Ok(out)
}

// Keep the integration gate's whole-workspace behavior as the default.
// The opt-in scoped mode still compiles and runs all tests in the owner crate.
fn cargo_test_args(package: Option<&str>, no_run: bool) -> Vec<String> {
    let mut args = vec!["test".to_owned()];
    if let Some(package) = package {
        args.extend(["--package".to_owned(), package.to_owned()]);
    } else {
        args.extend([
            "--workspace".to_owned(),
            "--exclude".to_owned(),
            "xtask".to_owned(),
        ]);
    }
    if no_run {
        args.push("--no-run".into());
    }
    args.push("--quiet".into());
    args
}

/// Build the tests, then run them. `Missed` means they all passed.
fn cargo_test(
    tree: &Path,
    target: &Path,
    package: Option<&str>,
    filter: Option<&str>,
    timeout: Duration,
    log: &Path,
) -> Result<Outcome, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let jobs = std::env::var("CARGO_BUILD_JOBS").unwrap_or_else(|_| "2".into());
    let logf = || -> Result<(Stdio, Stdio), String> {
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(|e| format!("{}: {e}", log.display()))?;
        let g = f.try_clone().map_err(|e| e.to_string())?;
        Ok((Stdio::from(f), Stdio::from(g)))
    };

    let (o, e) = logf()?;
    let built = Command::new(&cargo)
        .args(cargo_test_args(package, true))
        .current_dir(tree)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_JOBS", &jobs)
        .stdout(o)
        .stderr(e)
        .status()
        .map_err(|e| format!("running {cargo}: {e}"))?;
    if !built.success() {
        return Ok(Outcome::DoesNotCompile);
    }

    let (o, e) = logf()?;
    let mut cmd = Command::new(&cargo);
    cmd.args(cargo_test_args(package, false));
    if let Some(f) = filter {
        cmd.args(["--", f]);
    }
    let mut child = cmd
        .current_dir(tree)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_JOBS", &jobs)
        .stdout(o)
        .stderr(e)
        .spawn()
        .map_err(|e| format!("running {cargo}: {e}"))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(if status.success() {
                Outcome::Missed
            } else {
                Outcome::Caught
            });
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Outcome::CaughtTimeout);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Files outside `rust/` that the tests read through `../../../`: the JS
/// reference sources and the built UI (`src/`), the JS entry points and
/// package manifest (`bin/`, `package.json`; contract tests start the JS
/// daemon), the UI sources (`web/src`) and the README. They are copied beside the `rust/` copy so the copy's
/// tests see the same tree the working copy's tests do. A missing input is
/// skipped; the baseline run then fails and names it.
const REPO_INPUTS: &[&str] = &["src", "legacy", "package.json", "web/src", "README.md"];

fn copy_repo_inputs(root: &Path, dest: &Path) -> Result<(), String> {
    let Some(repo) = root.parent() else {
        return Ok(());
    };
    for rel in REPO_INPUTS {
        let from = repo.join(rel);
        let to = dest.join(rel);
        let res = if from.is_dir() {
            copy_tree(&from, &to)
        } else if from.is_file() {
            to.parent()
                .map_or(Ok(()), fs::create_dir_all)
                .and_then(|()| fs::copy(&from, &to).map(|_| ()))
        } else {
            continue;
        };
        res.map_err(|e| format!("copying {}: {e}", from.display()))?;
    }
    Ok(())
}

/// Copy `from` to `to`, skipping build output and VCS metadata.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        let ty = entry.file_type()?;
        let dest = to.join(&name);
        if ty.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), &dest)?;
            // fs::copy keeps the source's mtime. The mutation target dir is
            // shared between runs, so a restored file that looks older than
            // the last mutant's build would be skipped by cargo and the stale
            // mutant tested as the baseline. Stamp every copy with now.
            fs::File::options()
                .write(true)
                .open(&dest)?
                .set_modified(SystemTime::now())?;
        }
        // Symlinks are skipped: the workspace has none, and following one
        // could copy something outside the tree.
    }
    Ok(())
}

/// A temporary directory removed on drop unless `keep` is set.
struct TempTree {
    path: PathBuf,
    keep: bool,
}

impl TempTree {
    fn new(keep: bool) -> Result<Self, String> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("av-mutation-{}-{nanos}", std::process::id()));
        fs::create_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(TempTree { path, keep })
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.keep {
            println!("mutation: kept {}", self.path.display());
        } else {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_tree_skips_target_and_git() {
        let base = std::env::temp_dir().join(format!("av-xtask-copy-{}", std::process::id()));
        let src = base.join("src");
        fs::create_dir_all(src.join("target/debug")).unwrap();
        fs::create_dir_all(src.join("crates/a/src")).unwrap();
        fs::write(src.join("crates/a/src/lib.rs"), "x").unwrap();
        fs::write(src.join("target/debug/junk"), "y").unwrap();
        let dst = base.join("dst");
        copy_tree(&src, &dst).unwrap();
        assert!(dst.join("crates/a/src/lib.rs").is_file());
        assert!(!dst.join("target").exists());
        let age = fs::metadata(dst.join("crates/a/src/lib.rs"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            age.elapsed().unwrap() < Duration::from_secs(60),
            "copies are stamped with now"
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn repo_inputs_are_copied_beside_the_rust_copy() {
        let base = std::env::temp_dir().join(format!("av-xtask-inputs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let repo = base.join("repo");
        fs::create_dir_all(repo.join("rust")).unwrap();
        fs::create_dir_all(repo.join("src/ui/dist")).unwrap();
        fs::create_dir_all(repo.join("web/src")).unwrap();
        fs::write(repo.join("src/ui/dist/index.html"), "ui").unwrap();
        fs::write(repo.join("web/src/app.jsx"), "app").unwrap();
        fs::write(repo.join("README.md"), "readme").unwrap();
        fs::write(repo.join("secret.txt"), "not an input").unwrap();
        let dest = base.join("copy");
        copy_repo_inputs(&repo.join("rust"), &dest).unwrap();
        assert_eq!(
            fs::read_to_string(dest.join("src/ui/dist/index.html")).unwrap(),
            "ui"
        );
        assert_eq!(
            fs::read_to_string(dest.join("web/src/app.jsx")).unwrap(),
            "app"
        );
        assert_eq!(
            fs::read_to_string(dest.join("README.md")).unwrap(),
            "readme"
        );
        assert!(!dest.join("secret.txt").exists(), "only the named inputs");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn options_parse() {
        let o = Options::parse(&[
            "--only".into(),
            "a".into(),
            "--only=b".into(),
            "--keep".into(),
        ])
        .unwrap();
        assert_eq!(o.only, vec!["a".to_string(), "b".to_string()]);
        assert!(o.keep);
        assert!(Options::parse(&["--bogus".into()]).is_err());
    }

    #[test]
    fn scoped_mode_is_opt_in_and_retains_build_and_test_modes() {
        assert!(!Options::parse(&[]).unwrap().scoped);
        assert!(Options::parse(&["--scoped".into()]).unwrap().scoped);
        assert_eq!(
            cargo_test_args(None, true),
            [
                "test",
                "--workspace",
                "--exclude",
                "xtask",
                "--no-run",
                "--quiet"
            ]
        );
        assert_eq!(
            cargo_test_args(None, false),
            ["test", "--workspace", "--exclude", "xtask", "--quiet"]
        );
        assert_eq!(
            cargo_test_args(Some("av-core"), true),
            ["test", "--package", "av-core", "--no-run", "--quiet"]
        );
        assert_eq!(
            cargo_test_args(Some("av-store"), false),
            ["test", "--package", "av-store", "--quiet"]
        );
    }

    #[test]
    fn the_checked_in_entries_are_valid() {
        // Every entry parses, names a real file, and its `from` appears once.
        let all = load_all(&workspace_root()).unwrap();
        assert!(!all.is_empty(), "at least the sample entry exists");
    }
}
