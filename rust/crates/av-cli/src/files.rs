//! Writing files a human asked for without following links or clobbering
//! anything, and the last check before an env file is written. Ports
//! `src/cli/files.js`.

use std::path::Path;

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
    /// Not a regular file owned by this user. `ENOTREGULAR`.
    #[error("{0} is not a regular file you own")]
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

/// Write `text` to `path` (mode `mode`, default 0600), which must not exist
/// unless `force`; returns whether an existing file was replaced. Ports
/// `writeFileExclusive(path, text, { force, mode })` in `src/cli/files.js`.
pub fn write_file_exclusive(
    path: &Path,
    text: &str,
    force: bool,
    mode: u32,
) -> Result<bool, FileError> {
    todo!()
}

/// Append one line to a regular file this user owns (creating it 0600),
/// refusing symlinks, fifos and anything not regular. Ports
/// `appendLineExclusive(path, line)` in `src/cli/files.js`.
pub fn append_line_exclusive(path: &Path, line: &str) -> Result<(), FileError> {
    todo!()
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
    todo!()
}
