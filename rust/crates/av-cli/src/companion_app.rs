//! `companion install | upgrade | open`: the macOS companion app, from the
//! release this CLI belongs to. New in the port; no JS source.
//!
//! The app comes from this CLI's own GitHub release (the same version, so
//! the app and the CLI it runs agree), fetched with the system's curl,
//! checked against the release's `SHA256SUMS` (and, when the GitHub CLI is
//! installed, against the build provenance GitHub recorded for it), then
//! copied out of the `.dmg` and checked again: its bundle id, its version
//! and its code signature. Only then does it replace an installed copy,
//! in one rename, so a failure part way leaves the old app as it was.
//!
//! Gatekeeper checks an app the first time it opens only if a browser (or
//! another app that marks its downloads) put the quarantine mark on it.
//! curl does not, so a copy installed here opens without macOS's "cannot
//! be checked" dialog. The checksum and the provenance are what vouch for
//! it instead, as they do for the CLI's own archive in `install.sh`.

use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

use av_core::errors::Exit;

use crate::{CliError, Context, Outcome};

/// The app bundle's name, in `/Applications` or `~/Applications`.
pub const APP: &str = "agent-vault companion.app";
/// The app's bundle id (`desktop/Resources/Info.plist`).
pub const BUNDLE_ID: &str = "com.iolitelabs.agentvault.companion";
/// The repository whose releases carry the app.
const REPO: &str = "CrimsonWorks-Inc/agent-vault";
/// This CLI's version: the app it installs is the same one.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The release's `.dmg` is a few megabytes; anything near this is not it.
const MAX_DMG: u64 = 256 * 1024 * 1024;
/// `SHA256SUMS` lists a handful of files.
const MAX_SUMS: u64 = 64 * 1024;

fn fail(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        exit: Exit::Failure,
        next: None,
        problem: None,
        skew: false,
    }
}

fn fail_next(message: impl Into<String>, exit: Exit, next: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        exit,
        next: Some(next.into()),
        problem: None,
        skew: false,
    }
}

/// The `.dmg` a release carries for `version`.
pub(crate) fn dmg_name(version: &str) -> String {
    format!("agent-vault-companion-{version}.dmg")
}

/// Where a release's file is downloaded from.
pub(crate) fn release_url(version: &str, file: &str) -> String {
    format!("https://github.com/{REPO}/releases/download/v{version}/{file}")
}

/// The digest `SHA256SUMS` lists for exactly `name`: 64 lowercase hex
/// digits on one line. A name listed twice, or a digest of another shape,
/// is no answer at all.
pub(crate) fn listed_digest(sums: &str, name: &str) -> Option<String> {
    let mut found = None;
    for line in sums.lines() {
        let mut parts = line.split_whitespace();
        let (Some(digest), Some(file), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if file.strip_prefix('*').unwrap_or(file) != name {
            continue;
        }
        let plain = digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if found.is_some() || !plain {
            return None;
        }
        found = Some(digest.to_string());
    }
    found
}

/// Whether `bytes` are the file `SHA256SUMS` lists as `name`.
pub(crate) fn check_download(bytes: &[u8], sums: &str, name: &str) -> Result<(), CliError> {
    let Some(expected) = listed_digest(sums, name) else {
        return Err(fail(format!(
            "the release's SHA256SUMS does not list {name}; refusing to install"
        )));
    };
    if av_core::canon::sha256(bytes) != expected {
        return Err(fail(format!(
            "checksum mismatch for {name}: refusing to install"
        )));
    }
    Ok(())
}

/// What an app bundle's `Info.plist` says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppInfo {
    /// `CFBundleIdentifier`.
    pub id: String,
    /// `CFBundleShortVersionString`.
    pub version: String,
}

/// Whether the app copied out of the `.dmg` is the companion, at `version`.
pub(crate) fn check_app(info: &AppInfo, version: &str) -> Result<(), CliError> {
    if info.id != BUNDLE_ID {
        return Err(fail(format!(
            "the .dmg holds an app with the id {:?}, not the companion's; refusing to install",
            info.id
        )));
    }
    if info.version != version {
        return Err(fail(format!(
            "the .dmg holds companion {}, not {version}; refusing to install",
            info.version
        )));
    }
    Ok(())
}

/// A dotted version's numbers, or `None` for anything else.
fn numbers(version: &str) -> Option<Vec<u64>> {
    version.split('.').map(|n| n.parse().ok()).collect()
}

/// Whether the installed app is newer than this CLI's.
pub(crate) fn is_newer(installed: &str, ours: &str) -> bool {
    match (numbers(installed), numbers(ours)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// What `install` and `upgrade` do about the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    /// None is installed: install this CLI's release.
    Install,
    /// This CLI's release is installed, and macOS will open it.
    Keep,
    /// A newer one is installed: never go back a version.
    KeepNewer,
    /// Another version, an unreadable one, or one macOS marked as
    /// downloaded (a browser's or the Homebrew cask's copy, which macOS
    /// will not open until it is notarized): replace it with a checked
    /// copy of this CLI's release.
    Replace,
}

/// The plan for an installed app (`installed`, its `version` if readable,
/// whether macOS `marked` it as downloaded) against this CLI's `ours`.
pub(crate) fn plan(installed: bool, version: Option<&str>, marked: bool, ours: &str) -> Plan {
    match version {
        _ if !installed => Plan::Install,
        Some(v) if is_newer(v, ours) => Plan::KeepNewer,
        Some(v) if v == ours && !marked => Plan::Keep,
        _ => Plan::Replace,
    }
}

/// Whether macOS has marked the app as downloaded (`com.apple.quarantine`),
/// so that Gatekeeper checks it, and refuses an app that is not notarized.
fn quarantined(app: &Path) -> bool {
    run_quiet(
        "/usr/bin/xattr",
        &[
            "-p".as_ref(),
            "com.apple.quarantine".as_ref(),
            app.as_os_str(),
        ],
    )
}

/// Where the app can be: the system's Applications folder, then the user's.
pub(crate) fn app_dirs(home: &Path) -> [PathBuf; 2] {
    [PathBuf::from("/Applications"), home.join("Applications")]
}

/// The installed copy: the first of `dirs` that has one.
pub(crate) fn installed_in(dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter()
        .map(|d| d.join(APP))
        .find(|p| p.symlink_metadata().is_ok_and(|m| m.is_dir()))
}

/// Where to put the app: over the installed copy, else in the first of
/// `dirs` this user can write to, else the last (the user's own folder,
/// made if it is missing).
pub(crate) fn destination(
    dirs: &[PathBuf],
    existing: Option<&Path>,
    writable: impl Fn(&Path) -> bool,
) -> PathBuf {
    if let Some(app) = existing {
        return app.to_path_buf();
    }
    let dir = dirs
        .iter()
        .find(|d| writable(d))
        .or(dirs.last())
        .cloned()
        .unwrap_or_default();
    dir.join(APP)
}

/// Whether this user can make a folder in `dir` (a probe, removed again).
fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".agent-vault-probe-{}", std::process::id()));
    match fs::create_dir(&probe) {
        Ok(()) => {
            let _ = fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

/// The app's id and version, read from its `Info.plist` by `plutil`.
fn read_info(app: &Path) -> Option<AppInfo> {
    let plist = app.join("Contents/Info.plist");
    let key = |k: &str| {
        let out = Command::new("/usr/bin/plutil")
            .args(["-extract", k, "raw", "-o", "-"])
            .arg(&plist)
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    Some(AppInfo {
        id: key("CFBundleIdentifier")?,
        version: key("CFBundleShortVersionString")?,
    })
}

fn run_quiet(program: &str, args: &[&OsStr]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The `pgrep -f` pattern for the companion running from `app`, and from
/// no other copy: its executable's whole path, from the start of the
/// command line. (The process name alone is cut to 16 characters.)
pub(crate) fn running_pattern(app: &Path) -> String {
    let mut pattern = String::from("^");
    for c in app.to_string_lossy().chars() {
        if r"\.^$|?*+()[]{}".contains(c) {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push_str(r"/Contents/MacOS/agent-vault-companion( |$)");
    pattern
}

/// Run `pgrep` or `pkill` over this user's companion running from `app`.
fn run_matching(program: &str, signal: Option<&str>, app: &Path) -> bool {
    let mut args: Vec<String> = signal.map(String::from).into_iter().collect();
    if let Some(uid) = crate::own_uid() {
        args.extend(["-U".into(), uid.to_string()]);
    }
    args.extend(["-f".into(), running_pattern(app)]);
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    run_quiet(program, &args)
}

/// The companion is running from `app`.
fn running(app: &Path) -> bool {
    run_matching("/usr/bin/pgrep", None, app)
}

/// Ask the companion running from `app` to quit (it quits cleanly on
/// SIGTERM, taking its `watch` and `ui` processes with it), and wait for it.
fn stop_running(app: &Path) -> bool {
    run_matching("/usr/bin/pkill", Some("-TERM"), app);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if !running(app) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn open_app(app: &Path) -> Result<(), CliError> {
    if run_quiet("/usr/bin/open", &[app.as_os_str()]) {
        Ok(())
    } else {
        Err(fail(format!("macOS could not open {}", app.display())))
    }
}

/// A folder of this process's own, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, CliError> {
        let base = std::env::temp_dir();
        for n in 0..32u32 {
            let path = base.join(format!("agent-vault-companion-{}-{n}", std::process::id()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(fail(format!("could not make a temporary folder: {e}"))),
            }
        }
        Err(fail("could not make a temporary folder"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The `.dmg`, attached read-only at a mount point of ours; detached when
/// dropped.
struct Mounted(PathBuf);

impl Mounted {
    fn attach(dmg: &Path, at: &Path) -> Result<Self, CliError> {
        fs::create_dir(at).map_err(|e| fail(format!("could not make a mount point: {e}")))?;
        let ok = run_quiet(
            "/usr/bin/hdiutil",
            &[
                "attach".as_ref(),
                "-nobrowse".as_ref(),
                "-readonly".as_ref(),
                "-noautoopen".as_ref(),
                "-quiet".as_ref(),
                "-mountpoint".as_ref(),
                at.as_os_str(),
                dmg.as_os_str(),
            ],
        );
        if ok {
            Ok(Self(at.to_path_buf()))
        } else {
            Err(fail(
                "macOS could not open the .dmg (hdiutil attach failed)",
            ))
        }
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let at = self.0.as_os_str();
        if !run_quiet(
            "/usr/bin/hdiutil",
            &["detach".as_ref(), "-quiet".as_ref(), at],
        ) {
            run_quiet(
                "/usr/bin/hdiutil",
                &["detach".as_ref(), "-force".as_ref(), "-quiet".as_ref(), at],
            );
        }
    }
}

/// A copy of the app beside its destination, removed if it is never moved
/// into place.
struct Staged(PathBuf);

impl Drop for Staged {
    fn drop(&mut self) {
        if self.0.symlink_metadata().is_ok() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn sibling(dest: &Path, tag: &str) -> PathBuf {
    dest.with_file_name(format!(".{APP}.{tag}-{}", std::process::id()))
}

/// Put `staged` at `dest` in one rename, moving an installed copy aside
/// first and back if the rename fails.
fn swap_in(staged: &Path, dest: &Path) -> std::io::Result<()> {
    if dest.symlink_metadata().is_err() {
        return fs::rename(staged, dest);
    }
    let old = sibling(dest, "old");
    fs::rename(dest, &old)?;
    if let Err(e) = fs::rename(staged, dest) {
        let _ = fs::rename(&old, dest);
        return Err(e);
    }
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

/// Download one file of the release with the system's curl: HTTPS only,
/// redirects included, and no `~/.curlrc` (`-q`).
fn fetch(url: &str, to: &Path, max: u64) -> bool {
    let max = max.to_string();
    run_quiet(
        "/usr/bin/curl",
        &[
            "-q".as_ref(),
            "-fsSL".as_ref(),
            "--proto".as_ref(),
            "=https".as_ref(),
            "--proto-redir".as_ref(),
            "=https".as_ref(),
            "--tlsv1.2".as_ref(),
            "--max-filesize".as_ref(),
            max.as_ref(),
            "-o".as_ref(),
            to.as_os_str(),
            url.as_ref(),
        ],
    )
}

fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, CliError> {
    let file = fs::File::open(path)
        .map_err(|e| fail(format!("could not read {}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| fail(format!("could not read {}: {e}", path.display())))?;
    if bytes.len() as u64 > max {
        return Err(fail(format!("{} is too large", path.display())));
    }
    Ok(bytes)
}

/// What `gh attestation verify` said about the `.dmg`: `None` when the
/// GitHub CLI is not installed.
fn provenance(dmg: &Path) -> Option<bool> {
    match Command::new("gh")
        .args(["attestation", "verify"])
        .arg(dmg)
        .args(["--repo", REPO])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) => Some(s.success()),
        Err(_) => None,
    }
}

fn macos_only() -> Result<(), CliError> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(fail_next(
            "the companion app is for macOS",
            Exit::Usage,
            "agent-vault ui   (the web UI does the same things)",
        ))
    }
}

/// Download this CLI's release of the app and install it at `dest`.
/// Returns whether a running companion was stopped for it.
fn install_at(dest: &Path, say: &dyn Fn(&str)) -> Result<bool, CliError> {
    let name = dmg_name(VERSION);
    let scratch = Scratch::new()?;
    let dmg = scratch.0.join(&name);
    let sums = scratch.0.join("SHA256SUMS");
    say(&format!("  downloading {}", release_url(VERSION, &name)));
    if !fetch(&release_url(VERSION, &name), &dmg, MAX_DMG) {
        return Err(fail_next(
            format!("could not download {name}: release v{VERSION} has no companion app, or GitHub could not be reached"),
            Exit::Failure,
            format!("https://github.com/{REPO}/releases/tag/v{VERSION}"),
        ));
    }
    if !fetch(&release_url(VERSION, "SHA256SUMS"), &sums, MAX_SUMS) {
        return Err(fail(format!(
            "could not download release v{VERSION}'s SHA256SUMS"
        )));
    }
    let sums_text = String::from_utf8_lossy(&read_capped(&sums, MAX_SUMS)?).into_owned();
    install_from(&dmg, &sums_text, dest, say, &provenance)
}

/// Check a downloaded `.dmg` and install its app at `dest`, replacing what
/// is there only once every check has passed: the checksum, the build
/// provenance (when `gh` can say), and the app's id, version and code
/// signature. Returns whether a running companion was stopped for it.
fn install_from(
    dmg: &Path,
    sums_text: &str,
    dest: &Path,
    say: &dyn Fn(&str),
    provenance: &dyn Fn(&Path) -> Option<bool>,
) -> Result<bool, CliError> {
    let name = dmg_name(VERSION);
    check_download(&read_capped(dmg, MAX_DMG)?, sums_text, &name)?;
    say("  checksum ok");
    let built_here = provenance(dmg);
    if built_here == Some(false) {
        return Err(fail_next(
            format!("gh attestation verify failed for {name}: refusing to install"),
            Exit::Failure,
            "gh auth status   (the check needs gh signed in)",
        ));
    }
    if built_here == Some(true) {
        say(&format!(
            "  build provenance ok (built by {REPO}'s release workflow)"
        ));
    } else {
        say("  (install the GitHub CLI, gh, to also verify where this .dmg was built)");
    }

    let scratch = Scratch::new()?;
    let mounted = Mounted::attach(dmg, &scratch.0.join("mnt"))?;
    let source = mounted.0.join(APP);
    if !source.symlink_metadata().is_ok_and(|m| m.is_dir()) {
        return Err(fail(format!("the .dmg has no {APP}")));
    }
    let parent = dest.parent().unwrap_or(Path::new("/"));
    fs::create_dir_all(parent)
        .map_err(|e| fail(format!("could not make {}: {e}", parent.display())))?;
    let staged = Staged(sibling(dest, "new"));
    if staged.0.symlink_metadata().is_ok() {
        let _ = fs::remove_dir_all(&staged.0);
    }
    if !run_quiet(
        "/usr/bin/ditto",
        &[source.as_os_str(), staged.0.as_os_str()],
    ) {
        return Err(fail_next(
            format!("could not copy the app into {}", parent.display()),
            Exit::Failure,
            "check that you can write there",
        ));
    }
    drop(mounted);
    let Some(info) = read_info(&staged.0) else {
        return Err(fail("the app in the .dmg has no readable Info.plist"));
    };
    check_app(&info, VERSION)?;
    if !run_quiet(
        "/usr/bin/codesign",
        &[
            "--verify".as_ref(),
            "--strict".as_ref(),
            staged.0.as_os_str(),
        ],
    ) {
        return Err(fail(
            "the app's code signature does not verify: refusing to install",
        ));
    }
    say("  app checked (id, version, signature)");

    let was_running = running(dest);
    if was_running {
        say("  quitting the running companion");
        if !stop_running(dest) {
            return Err(fail_next(
                "the running companion did not quit",
                Exit::Failure,
                "quit it from its menu, then run this again",
            ));
        }
    }
    swap_in(&staged.0, dest).map_err(|e| {
        fail_next(
            format!("could not put the app at {}: {e}", dest.display()),
            Exit::Failure,
            "check that you can write there",
        )
    })?;
    Ok(was_running)
}

/// `companion install` and `companion upgrade`.
pub fn install(ctx: &Context, upgrade: bool, no_open: bool) -> Outcome {
    macos_only()?;
    let dirs = app_dirs(&crate::home_dir());
    let existing = installed_in(&dirs);
    let previous = existing.as_deref().and_then(read_info).map(|i| i.version);
    let say = |line: &str| {
        if !ctx.json {
            println!("{line}");
        }
    };
    if upgrade && existing.is_none() {
        return Err(fail_next(
            "the companion app is not installed",
            Exit::NotFound,
            "agent-vault companion install",
        ));
    }
    let marked = existing.as_deref().is_some_and(quarantined);
    let step = plan(existing.is_some(), previous.as_deref(), marked, VERSION);
    if let (Some(app), Plan::Keep | Plan::KeepNewer) = (&existing, step) {
        let opened = !no_open && open_app(app).is_ok();
        let version = previous.clone().unwrap_or_default();
        let human = if step == Plan::KeepNewer {
            format!(
                "companion {version} is installed at {}, newer than this CLI ({VERSION}); left as it is",
                app.display()
            )
        } else {
            format!("companion {version} is installed at {}", app.display())
        };
        ctx.out(
            Some(&human),
            &json!({ "app": app, "version": version, "changed": false, "opened": opened }),
        );
        return Ok(0);
    }
    let dest = destination(&dirs, existing.as_deref(), writable);
    say(&format!("agent-vault companion {VERSION}"));
    if marked && previous.as_deref() == Some(VERSION) {
        say("  the installed copy is marked as downloaded, so macOS would ask about it; replacing it with a checked one");
    }
    let was_running = install_at(&dest, &say)?;
    let opened = (!no_open || was_running) && open_app(&dest).is_ok();
    let verb = match previous.as_deref() {
        None if existing.is_none() => "installed",
        Some(VERSION) => "replaced",
        _ => "upgraded",
    };
    let human = format!(
        "{} companion {VERSION} at {}{}",
        ctx.paint("32", verb),
        dest.display(),
        if opened { "; it is open" } else { "" }
    );
    ctx.out(
        Some(&human),
        &json!({
            "app": dest,
            "version": VERSION,
            "previous": previous,
            "changed": true,
            "opened": opened,
        }),
    );
    Ok(0)
}

/// `companion open`.
pub fn open(ctx: &Context) -> Outcome {
    macos_only()?;
    let Some(app) = installed_in(&app_dirs(&crate::home_dir())) else {
        return Err(fail_next(
            "the companion app is not installed",
            Exit::NotFound,
            "agent-vault companion install",
        ));
    };
    open_app(&app)?;
    let version = read_info(&app).map(|i| i.version);
    let behind = version
        .as_deref()
        .is_some_and(|v| v != VERSION && !is_newer(v, VERSION));
    let mut human = format!("opened {}", app.display());
    if behind {
        human.push_str(&format!(
            "\n{} it is companion {}; this CLI is {VERSION}: agent-vault companion upgrade",
            ctx.paint("2", "note:"),
            version.as_deref().unwrap_or("")
        ));
    }
    ctx.out(
        Some(&human),
        &json!({ "app": app, "version": version, "opened": true }),
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_release_names_and_urls_are_this_version() {
        assert_eq!(dmg_name("0.5.3"), "agent-vault-companion-0.5.3.dmg");
        assert_eq!(
            release_url("0.5.3", "SHA256SUMS"),
            "https://github.com/CrimsonWorks-Inc/agent-vault/releases/download/v0.5.3/SHA256SUMS"
        );
    }

    #[test]
    fn sha256sums_gives_the_digest_of_exactly_that_file() {
        let name = "agent-vault-companion-0.5.3.dmg";
        let other = "1".repeat(64);
        let sums =
            format!("{other}  agent-vault-0.5.3-aarch64-apple-darwin.tar.gz\n{DIGEST}  {name}\n");
        assert_eq!(listed_digest(&sums, name).as_deref(), Some(DIGEST));
        // The binary-mode marker sha256sum -b writes.
        assert_eq!(
            listed_digest(&format!("{DIGEST} *{name}\n"), name).as_deref(),
            Some(DIGEST)
        );
        // Another file's line, a prefix or a suffix of the name, is not it.
        assert_eq!(listed_digest(&format!("{DIGEST}  x{name}\n"), name), None);
        assert_eq!(
            listed_digest(&format!("{DIGEST}  {name}.sig\n"), name),
            None
        );
        assert_eq!(
            listed_digest(&format!("{other}  agent-vault-companion-0.5.2.dmg\n"), name),
            None
        );
        // Listed twice, even with the same digest: no answer.
        assert_eq!(
            listed_digest(&format!("{DIGEST}  {name}\n{DIGEST}  {name}\n"), name),
            None
        );
        // A digest of another shape.
        assert_eq!(
            listed_digest(&format!("{}  {name}\n", &DIGEST[1..]), name),
            None
        );
        assert_eq!(
            listed_digest(&format!("{}  {name}\n", DIGEST.to_uppercase()), name),
            None
        );
        assert_eq!(
            listed_digest(&format!("{DIGEST}  {name} extra\n"), name),
            None
        );
    }

    #[test]
    fn a_download_is_installed_only_if_its_checksum_is_listed_for_it() {
        let name = "agent-vault-companion-0.5.3.dmg";
        let bytes = b"the dmg";
        let good = av_core::canon::sha256(bytes);
        let sums = format!("{good}  {name}\n");
        assert!(check_download(bytes, &sums, name).is_ok());
        let tampered = check_download(b"the dmh", &sums, name).unwrap_err();
        assert!(
            tampered.message.contains("checksum mismatch"),
            "{}",
            tampered.message
        );
        let unlisted = check_download(bytes, &format!("{good}  other.dmg\n"), name).unwrap_err();
        assert!(
            unlisted.message.contains("does not list"),
            "{}",
            unlisted.message
        );
    }

    #[test]
    fn only_the_companion_at_this_version_is_installed() {
        let app = |id: &str, version: &str| AppInfo {
            id: id.into(),
            version: version.into(),
        };
        assert!(check_app(&app(BUNDLE_ID, "0.5.3"), "0.5.3").is_ok());
        assert!(check_app(&app("com.example.other", "0.5.3"), "0.5.3").is_err());
        assert!(check_app(&app(BUNDLE_ID, "0.5.2"), "0.5.3").is_err());
        assert!(check_app(&app(&format!("{BUNDLE_ID}.x"), "0.5.3"), "0.5.3").is_err());
    }

    #[test]
    fn upgrade_never_goes_back_a_version() {
        assert!(is_newer("0.5.10", "0.5.9"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.5.2", "0.5.3"));
        assert!(!is_newer("0.5.3", "0.5.3"));
        assert!(!is_newer("garbage", "0.5.3"));
    }

    #[test]
    fn a_copy_macos_would_block_is_replaced_but_never_with_an_older_one() {
        assert_eq!(plan(false, None, false, "0.5.3"), Plan::Install);
        assert_eq!(plan(true, Some("0.5.3"), false, "0.5.3"), Plan::Keep);
        // The cask's copy of the same version: macOS will not open it.
        assert_eq!(plan(true, Some("0.5.3"), true, "0.5.3"), Plan::Replace);
        assert_eq!(plan(true, Some("0.5.2"), false, "0.5.3"), Plan::Replace);
        assert_eq!(plan(true, None, false, "0.5.3"), Plan::Replace);
        // Newer stays, marked or not.
        assert_eq!(plan(true, Some("0.5.4"), false, "0.5.3"), Plan::KeepNewer);
        assert_eq!(plan(true, Some("0.5.4"), true, "0.5.3"), Plan::KeepNewer);
    }

    /// The mark a browser or the Homebrew cask leaves is read off the app.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_quarantine_mark_is_seen() {
        let scratch = Scratch::new().unwrap();
        let app = scratch.0.join(APP);
        fs::create_dir_all(&app).unwrap();
        assert!(!quarantined(&app));
        let mark: [&OsStr; 4] = [
            "-w".as_ref(),
            "com.apple.quarantine".as_ref(),
            "0081;00000000;Test;".as_ref(),
            app.as_os_str(),
        ];
        assert!(run_quiet("/usr/bin/xattr", &mark));
        assert!(quarantined(&app));
    }

    #[test]
    fn the_app_goes_over_the_installed_copy_else_where_this_user_can_write() {
        let home = PathBuf::from("/Users/someone");
        let dirs = app_dirs(&home);
        let user = home.join("Applications").join(APP);
        let system = PathBuf::from("/Applications").join(APP);
        assert_eq!(destination(&dirs, Some(&user), |_| true), user);
        assert_eq!(destination(&dirs, None, |_| true), system);
        assert_eq!(
            destination(&dirs, None, |d| d != Path::new("/Applications")),
            user
        );
        assert_eq!(destination(&dirs, None, |_| false), user);
    }

    #[test]
    fn the_installed_copy_is_found_in_either_applications_folder() {
        let root = std::env::temp_dir().join(format!("av-companion-find-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let system = root.join("system");
        let user = root.join("user");
        fs::create_dir_all(&system).unwrap();
        fs::create_dir_all(user.join(APP)).unwrap();
        let dirs = [system.clone(), user.clone()];
        assert_eq!(installed_in(&dirs), Some(user.join(APP)));
        fs::create_dir_all(system.join(APP)).unwrap();
        assert_eq!(installed_in(&dirs), Some(system.join(APP)));
        // A file of that name is not an app.
        fs::remove_dir_all(system.join(APP)).unwrap();
        fs::write(system.join(APP), b"").unwrap();
        assert_eq!(installed_in(&dirs), Some(user.join(APP)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_swap_puts_the_installed_copy_back() {
        let root = std::env::temp_dir().join(format!("av-companion-swap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let dest = root.join(APP);
        fs::create_dir_all(dest.join("old")).unwrap();
        // Nothing staged: the rename fails, and the old copy is back.
        assert!(swap_in(&root.join("missing"), &dest).is_err());
        assert!(dest.join("old").is_dir());
        // Staged: it replaces the old copy, which is gone.
        let staged = root.join("staged");
        fs::create_dir_all(staged.join("new")).unwrap();
        swap_in(&staged, &dest).unwrap();
        assert!(dest.join("new").is_dir());
        assert!(!dest.join("old").exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    /// A stand-in companion packed in a .dmg the way the release packs it:
    /// `/usr/bin/true` as its executable, signed ad hoc, and changed after
    /// signing when `tamper` is set.
    #[cfg(target_os = "macos")]
    fn fake_dmg(dir: &Path, id: &str, version: &str, tamper: bool) -> PathBuf {
        let stage = dir.join(format!("stage-{id}-{version}-{tamper}"));
        let app = stage.join(APP);
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::copy(
            "/usr/bin/true",
            app.join("Contents/MacOS/agent-vault-companion"),
        )
        .unwrap();
        fs::write(
            app.join("Contents/Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>agent-vault-companion</string>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>"#
            ),
        )
        .unwrap();
        let sign: [&OsStr; 4] = [
            "--force".as_ref(),
            "--sign".as_ref(),
            "-".as_ref(),
            app.as_os_str(),
        ];
        assert!(run_quiet("/usr/bin/codesign", &sign));
        if tamper {
            let exe = app.join("Contents/MacOS/agent-vault-companion");
            let mut bytes = fs::read(&exe).unwrap();
            bytes.push(0);
            fs::write(&exe, bytes).unwrap();
        }
        let dmg = dir.join(format!("{id}-{version}-{tamper}.dmg"));
        let create: [&OsStr; 7] = [
            "create".as_ref(),
            "-quiet".as_ref(),
            "-srcfolder".as_ref(),
            stage.as_os_str(),
            "-format".as_ref(),
            "UDZO".as_ref(),
            dmg.as_os_str(),
        ];
        assert!(run_quiet("/usr/bin/hdiutil", &create));
        dmg
    }

    /// The install after the download, on real .dmgs: every refusal leaves
    /// the installed copy exactly as it was, and a good one replaces it with
    /// nothing left beside it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_dmg_is_installed_only_once_every_check_passes() {
        let scratch = Scratch::new().unwrap();
        let good = fake_dmg(&scratch.0, BUNDLE_ID, VERSION, false);
        let older = fake_dmg(&scratch.0, BUNDLE_ID, "0.0.1", false);
        let other = fake_dmg(&scratch.0, "com.example.other", VERSION, false);
        let tampered = fake_dmg(&scratch.0, BUNDLE_ID, VERSION, true);
        let name = dmg_name(VERSION);
        let listed = |dmg: &Path| {
            format!(
                "{}  {name}\n",
                av_core::canon::sha256(&fs::read(dmg).unwrap())
            )
        };
        let apps = scratch.0.join("Applications");
        let dest = apps.join(APP);
        fs::create_dir_all(dest.join("Contents/installed")).unwrap();
        let untouched = || {
            assert!(
                dest.join("Contents/installed").is_dir(),
                "the installed copy is as it was"
            );
            assert_eq!(
                fs::read_dir(&apps).unwrap().count(),
                1,
                "nothing left beside it"
            );
        };
        let quiet = |_: &str| {};
        let unknown = |_: &Path| None;

        // The checksum listed is another file's.
        let refused = install_from(&good, &listed(&older), &dest, &quiet, &unknown).unwrap_err();
        assert!(
            refused.message.contains("checksum mismatch"),
            "{}",
            refused.message
        );
        untouched();
        // gh says the .dmg was not built by the release workflow.
        let refused =
            install_from(&good, &listed(&good), &dest, &quiet, &|_| Some(false)).unwrap_err();
        assert!(
            refused.message.contains("attestation"),
            "{}",
            refused.message
        );
        untouched();
        // The .dmg holds another version, or another app.
        let refused = install_from(&older, &listed(&older), &dest, &quiet, &unknown).unwrap_err();
        assert!(
            refused.message.contains("holds companion 0.0.1"),
            "{}",
            refused.message
        );
        untouched();
        // The app was changed after it was signed.
        let refused =
            install_from(&tampered, &listed(&tampered), &dest, &quiet, &unknown).unwrap_err();
        assert!(
            refused.message.contains("code signature"),
            "{}",
            refused.message
        );
        untouched();
        let refused = install_from(&other, &listed(&other), &dest, &quiet, &unknown).unwrap_err();
        assert!(
            refused.message.contains("com.example.other"),
            "{}",
            refused.message
        );
        untouched();

        let stopped = install_from(&good, &listed(&good), &dest, &quiet, &|_| Some(true)).unwrap();
        assert!(!stopped, "nothing was running from the scratch folder");
        assert_eq!(
            read_info(&dest),
            Some(AppInfo {
                id: BUNDLE_ID.into(),
                version: VERSION.into()
            })
        );
        assert!(
            !dest.join("Contents/installed").exists(),
            "the old copy is gone"
        );
        assert_eq!(
            fs::read_dir(&apps).unwrap().count(),
            1,
            "only the app is left"
        );
        let verify: [&OsStr; 3] = ["--verify".as_ref(), "--strict".as_ref(), dest.as_os_str()];
        assert!(run_quiet("/usr/bin/codesign", &verify));
    }

    #[test]
    fn only_the_copy_being_replaced_is_quit() {
        assert_eq!(
            running_pattern(Path::new("/Applications/agent-vault companion.app")),
            r"^/Applications/agent-vault companion\.app/Contents/MacOS/agent-vault-companion( |$)"
        );
        // The pattern is a regular expression; the path's own characters
        // match only themselves.
        assert_eq!(
            running_pattern(Path::new("/x/a+b (1)/[c]")),
            r"^/x/a\+b \(1\)/\[c\]/Contents/MacOS/agent-vault-companion( |$)"
        );
    }

    /// pgrep reads the pattern the way the escaping assumes: a copy in
    /// another folder, or a path that differs only where the pattern has a
    /// dot, is not this one.
    #[cfg(target_os = "macos")]
    #[test]
    fn pgrep_finds_the_copy_at_that_path_only() {
        use std::os::unix::process::CommandExt;
        let scratch = Scratch::new().unwrap();
        // Runs from ".../agent-vault companionXapp": an unescaped dot in
        // the pattern for ".../agent-vault companion.app" would match it.
        let app = scratch.0.join("Apps").join("agent-vault companionXapp");
        let exe = app.join("Contents/MacOS/agent-vault-companion");
        // `sleep` itself, with the companion's path as its argv[0], which is
        // what `pgrep -f` reads. (A copied executable would be checked by
        // macOS before its first run, which is slow on a busy machine.)
        let mut child = Command::new("/bin/sleep")
            .arg0(&exe)
            .arg("30")
            .spawn()
            .unwrap();
        let found = (0..100).any(|_| {
            std::thread::sleep(Duration::from_millis(50));
            running(&app)
        });
        let elsewhere = running(&scratch.0.join("Apps").join(APP))
            || running(&scratch.0.join("Other").join("agent-vault companionXapp"));
        assert!(stop_running(&app), "SIGTERM reached it");
        let _ = child.kill();
        let _ = child.wait();
        assert!(found, "pgrep found the copy at that path");
        assert!(!elsewhere, "and no other");
    }
}
