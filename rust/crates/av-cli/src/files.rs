//! Writing files a human asked for without following links or clobbering
//! anything, and the last check before an env file is written. Ports
//! `src/cli/files.js`.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use av_core::placeholder::parse_at;

/// A variable name an env file may carry. Ports `ENV_NAME` in
/// `src/cli/files.js` (a regex there; the pattern text here).
pub const ENV_NAME: &str = "^[A-Za-z_][A-Za-z0-9_]*$";

/// Every value an env file may carry is made of these. Ports `SAFE_VALUE`
/// (module-private) in `src/cli/files.js`.
pub const SAFE_VALUE: &str = "^[A-Za-z0-9._:/-]+$";

/// Why a file was not written. Ports the `code` values (`EEXIST`,
/// `ENOTREGULAR`, `ELOOP`, `NOT_PLACEHOLDER`) the JS attaches to its errors
/// in `src/cli/files.js`.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// The path exists (a symlink, even a dangling one, counts) and `force`
    /// was not set. `EEXIST`.
    #[error("{0} exists")]
    Exists(String),
    /// Not a regular file owned by this user, or the path was swapped during
    /// the write. The string is the JS message (`ENOTREGULAR`).
    #[error("{0}")]
    NotRegular(String),
    /// A symlink where none may be. `ELOOP`.
    #[error("{0} is a symbolic link")]
    Symlink(String),
    /// A value that is not a placeholder for this session. `NOT_PLACEHOLDER`.
    #[error("refusing to write a value that is not a placeholder")]
    NotPlaceholder,
    /// Any other I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The effective uid, from `/usr/bin/id -u` (no `unsafe`). A failure is not
/// root and matches no file owner, so a forced replace is refused.
pub(crate) fn euid() -> u32 {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(u32::MAX)
}

fn os_eq(err: &std::io::Error, code: i32) -> bool {
    err.raw_os_error() == Some(code)
}

fn write_all_mode(file: &mut std::fs::File, text: &str, mode: u32) -> Result<(), FileError> {
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(mode);
    file.set_permissions(perms)?;
    Ok(())
}

fn dev_ino(meta: &std::fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

/// Whether `path` is, right now, the regular file `st` describes. Opened
/// with `O_NOFOLLOW` and `O_NONBLOCK`. Ports `isFile` in `src/cli/files.js`.
fn is_same_file(path: &Path, st: (u64, u64)) -> bool {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path);
    let Ok(file) = opened else {
        return false;
    };
    let Ok(now) = file.metadata() else {
        return false;
    };
    now.file_type().is_file() && dev_ino(&now) == st
}

/// Write `text` to `path` (mode `mode`, default 0600), which must not exist
/// unless `force`; returns whether an existing file was replaced. Ports
/// `writeFileExclusive(path, text, { force, mode })` in `src/cli/files.js`.
pub fn write_file_exclusive(
    path: &Path,
    text: &str,
    force: bool,
    mode: u32,
) -> Result<bool, FileError> {
    let shown = path.display().to_string();
    if !force {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                if os_eq(&e, libc::EEXIST) {
                    FileError::Exists(shown.clone())
                } else if os_eq(&e, libc::ELOOP) {
                    FileError::Symlink(shown.clone())
                } else {
                    FileError::Io(e)
                }
            })?;
        write_all_mode(&mut file, text, mode)?;
        return Ok(false);
    }

    let mut replaced = false;
    match std::fs::symlink_metadata(path) {
        Ok(st) => {
            if !st.file_type().is_file() || st.uid() != euid() {
                return Err(FileError::NotRegular(format!(
                    "{shown} is not a regular file you own"
                )));
            }
            replaced = true;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(FileError::Io(e)),
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ u64::from(std::process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let tmp = dir.join(format!(".{base}.av-{nonce:08x}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let written = (|| -> Result<(u64, u64), FileError> {
        write_all_mode(&mut file, text, mode)?;
        Ok(dev_ino(&file.metadata()?))
    })();
    drop(file);
    let written = match written {
        Ok(st) => st,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(FileError::Io(e));
    }
    if !is_same_file(path, written) {
        let _ = std::fs::remove_file(path);
        return Err(FileError::NotRegular(format!(
            "{shown} was replaced while it was being written; nothing was left there"
        )));
    }
    if let Ok(dir_file) = std::fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(replaced)
}

/// Append one line to a regular file this user owns (creating it 0600),
/// refusing symlinks, fifos and anything not regular. Ports
/// `appendLineExclusive(path, line)` in `src/cli/files.js`.
pub fn append_line_exclusive(path: &Path, line: &str) -> Result<(), FileError> {
    let shown = path.display().to_string();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if os_eq(&e, libc::ELOOP) || os_eq(&e, libc::ENXIO) {
                FileError::NotRegular(format!("{shown} is not a regular file"))
            } else {
                FileError::Io(e)
            }
        })?;
    if !file.metadata()?.file_type().is_file() {
        return Err(FileError::NotRegular(format!(
            "{shown} is not a regular file"
        )));
    }
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o600);
    file.set_permissions(perms)?;
    let text = if line.ends_with('\n') {
        line.to_string()
    } else {
        format!("{line}\n")
    };
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// One env-file entry. Ports the `{ name, value, cred }` entries of
/// `assertPlaceholderOnly` in `src/cli/files.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    /// Variable name.
    pub name: String,
    /// Placeholder or gateway URL.
    pub value: String,
    /// The credential the entry is for.
    pub cred: String,
}

fn env_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn safe_value_ok(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
}

/// Every value is a placeholder for this session and the entry's own
/// credential, or exactly a loopback gateway URL for this session's port;
/// otherwise [`FileError::NotPlaceholder`], naming no value. Ports
/// `assertPlaceholderOnly(entries, { sid, port, slugs })` in
/// `src/cli/files.js`.
pub fn assert_placeholder_only(
    entries: &[EnvEntry],
    sid: &str,
    port: u16,
    slugs: &[String],
) -> Result<(), FileError> {
    if sid.is_empty() {
        return Err(FileError::NotPlaceholder);
    }
    let urls: Vec<String> = std::iter::once(format!("http://127.0.0.1:{port}"))
        .chain(
            slugs
                .iter()
                .map(|slug| format!("http://127.0.0.1:{port}/p/{slug}")),
        )
        .collect();
    for entry in entries {
        if !env_name_ok(&entry.name) || !safe_value_ok(&entry.value) {
            return Err(FileError::NotPlaceholder);
        }
        let parsed = parse_at(&entry.value, 0);
        let is_placeholder = parsed.is_some_and(|p| {
            p.text == entry.value
                && p.sid == sid
                && p.slug == entry.cred
                && slugs.iter().any(|s| s == &entry.cred)
        });
        if !is_placeholder && !urls.iter().any(|u| u == &entry.value) {
            return Err(FileError::NotPlaceholder);
        }
    }
    Ok(())
}
