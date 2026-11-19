//! Credential folders: the shape of a folder path, and how one path sits
//! inside another. Folders only organize; nothing that grants or injects a
//! credential reads them. New with SQLite schema 2; no JS source.

/// Deepest folder path: `a/b/c/d`.
pub const MAX_DEPTH: usize = 4;
/// Longest single folder name.
pub const MAX_NAME: usize = 40;

/// Why a folder path was refused, said so a person can fix it.
pub fn folder_problem(path: &str) -> Option<String> {
    if path.is_empty() {
        return Some("a folder path is empty; give a name like clients/acme, or none".into());
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_DEPTH {
        return Some(format!(
            "a folder path is at most {MAX_DEPTH} levels deep, like a/b/c/d"
        ));
    }
    for part in parts {
        if part.is_empty() {
            return Some(
                "a folder path has an empty name; drop the leading, trailing or doubled /".into(),
            );
        }
        if part.chars().count() > MAX_NAME {
            return Some(format!("each folder name is at most {MAX_NAME} characters"));
        }
        if part == "." || part == ".." {
            return Some("a folder can't be named . or ..".into());
        }
        if part.starts_with(' ') || part.ends_with(' ') {
            return Some("a folder name can't start or end with a space".into());
        }
        if !part
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '-' | '_' | '.'))
        {
            return Some(
                "folder names use letters, digits, spaces, and - _ . only, with / between levels"
                    .into(),
            );
        }
    }
    None
}

/// Whether `path` is `folder` itself or somewhere beneath it.
pub fn is_within(path: &str, folder: &str) -> bool {
    path == folder
        || (path.len() > folder.len()
            && path.starts_with(folder)
            && path.as_bytes()[folder.len()] == b'/')
}

/// `path` moved from under `from` to under `to`, if it is within `from`.
pub fn renamed(path: &str, from: &str, to: &str) -> Option<String> {
    if !is_within(path, from) {
        return None;
    }
    Some(format!("{to}{}", &path[from.len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn good_paths_pass_and_each_bad_shape_says_why() {
        for ok in ["clients", "clients/acme", "a/b/c/d", "Prod Keys/v1.2_x-y"] {
            assert_eq!(folder_problem(ok), None, "{ok}");
        }
        let forty = "x".repeat(MAX_NAME);
        assert_eq!(folder_problem(&forty), None);
        for (bad, says) in [
            ("", "empty"),
            ("/a", "empty name"),
            ("a/", "empty name"),
            ("a//b", "empty name"),
            ("a/b/c/d/e", "4 levels"),
            ("a/..", ". or .."),
            (".", ". or .."),
            (" a", "space"),
            ("a ", "space"),
            ("a\\b", "letters"),
            ("a\u{202e}b", "letters"),
            ("café", "letters"),
            ("a\nb", "letters"),
        ] {
            let why = folder_problem(bad).unwrap_or_else(|| panic!("{bad:?} passed"));
            assert!(why.contains(says), "{bad:?}: {why}");
        }
        assert!(folder_problem(&"x".repeat(MAX_NAME + 1))
            .unwrap()
            .contains("40"));
    }

    #[test]
    fn within_means_the_folder_or_beneath_it_never_a_name_that_starts_the_same() {
        assert!(is_within("clients", "clients"));
        assert!(is_within("clients/acme", "clients"));
        assert!(!is_within("clients-old", "clients"));
        assert!(!is_within("client", "clients"));
        assert!(!is_within("x/clients", "clients"));
        assert_eq!(
            renamed("clients/acme", "clients", "customers").as_deref(),
            Some("customers/acme")
        );
        assert_eq!(renamed("clients", "clients", "a/b").as_deref(), Some("a/b"));
        assert_eq!(renamed("clients-old", "clients", "x"), None);
    }
}
