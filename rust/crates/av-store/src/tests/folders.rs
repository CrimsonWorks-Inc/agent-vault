//! Credential folders (schema 2): the migration from a v1 database, filing
//! and unfiling, renaming a folder all or none, and the audit trail. New with
//! SQLite; no JS source.

use serde_json::json;

use super::helpers::*;

fn v1_database_with_a_credential() -> rusqlite::Connection {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch(crate::schema::SCHEMA_SQL).unwrap();
    c.execute(
        "INSERT INTO schema_version (id, version, migrated_at) VALUES (1, 1, '2026-01-01T00:00:00.000Z')",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO credentials (id, slug, connector_kind, connector, created_at)
         VALUES ('cred_1', 'demo', 'http', '{}', '2026-01-01T00:00:00.000Z')",
        [],
    )
    .unwrap();
    c
}

#[test]
fn a_v1_database_gains_folders_and_keeps_its_credentials_unfiled() {
    let c = v1_database_with_a_credential();
    crate::db::migrate(&c).unwrap();
    assert_eq!(crate::db::schema_version(&c).unwrap(), 2);
    let (slug, folder): (String, Option<String>) = c
        .query_row("SELECT slug, folder FROM credentials", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((slug.as_str(), folder), ("demo", None));
    // Running it again is a no-op, not a second ALTER.
    crate::db::migrate(&c).unwrap();
    assert_eq!(crate::db::schema_version(&c).unwrap(), 2);
}

#[test]
fn the_column_refuses_a_malformed_path_even_past_the_daemon() {
    let c = v1_database_with_a_credential();
    crate::db::migrate(&c).unwrap();
    for bad in ["", "/a", "a/", "a//b"] {
        let r = c.execute("UPDATE credentials SET folder = ?1", [bad]);
        assert!(r.is_err(), "{bad:?} was stored");
    }
    c.execute("UPDATE credentials SET folder = 'clients/acme'", [])
        .unwrap();
}

#[test]
fn filing_a_credential_shows_its_folder_and_is_audited_once_per_change() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let c = v
        .set_credential_folder("demo", Some("clients/acme"))
        .unwrap();
    assert_eq!(c.folder.as_deref(), Some("clients/acme"));
    assert_eq!(serde_json::to_value(&c).unwrap()["folder"], "clients/acme");
    let listed = v.list_credentials().unwrap();
    let demo = listed.iter().find(|c| c.slug == "demo").unwrap();
    let other = listed.iter().find(|c| c.slug == "other").unwrap();
    assert_eq!(demo.folder.as_deref(), Some("clients/acme"));
    assert_eq!(other.folder, None);
    // Unfiled credentials keep their old public shape: no folder key.
    assert!(serde_json::to_value(other).unwrap().get("folder").is_none());

    // Filing it where it already is records nothing more.
    v.set_credential_folder("demo", Some("clients/acme"))
        .unwrap();
    let set = records(v, "cred.folder_set");
    assert_eq!(set.len(), 1);
    assert_eq!(field(&set[0], "credential_slug"), &json!("demo"));
    assert_eq!(field(&set[0], "from"), &json!(null));
    assert_eq!(field(&set[0], "to"), &json!("clients/acme"));

    let c = v.set_credential_folder("demo", None).unwrap();
    assert_eq!(c.folder, None);
    let set = records(v, "cred.folder_set");
    assert_eq!(set.len(), 2);
    assert_eq!(field(&set[1], "from"), &json!("clients/acme"));
    assert_eq!(field(&set[1], "to"), &json!(null));
}

#[test]
fn a_bad_folder_or_an_unknown_credential_changes_nothing() {
    let mut fx = fresh();
    refused_cleanly(
        &mut fx.vault,
        |v| v.set_credential_folder("demo", Some("a//b")),
        ("AV_POLICY_DENIED", Some("folder")),
    );
    refused_cleanly(
        &mut fx.vault,
        |v| v.set_credential_folder("nope", Some("a")),
        ("AV_NOT_FOUND", None),
    );
}

#[test]
fn renaming_a_folder_moves_it_and_everything_beneath_it_and_nothing_that_only_starts_the_same() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.add_credential(new_cred(
        "third",
        "http",
        "api.third.example",
        &[("token", "t-value-three")],
    ))
    .unwrap();
    v.set_credential_folder("demo", Some("clients")).unwrap();
    v.set_credential_folder("other", Some("clients/acme"))
        .unwrap();
    v.set_credential_folder("third", Some("clients-old"))
        .unwrap();
    let moved = v.rename_folder("clients", "customers/active").unwrap();
    assert_eq!(moved, vec!["demo".to_string(), "other".to_string()]);
    let folder = |v: &crate::vault::Vault, s: &str| {
        v.list_credentials()
            .unwrap()
            .into_iter()
            .find(|c| c.slug == s)
            .unwrap()
            .folder
    };
    assert_eq!(folder(v, "demo").as_deref(), Some("customers/active"));
    assert_eq!(folder(v, "other").as_deref(), Some("customers/active/acme"));
    assert_eq!(folder(v, "third").as_deref(), Some("clients-old"));
    let r = records(v, "cred.folder_renamed");
    assert_eq!(r.len(), 1);
    assert_eq!(field(&r[0], "from"), &json!("clients"));
    assert_eq!(field(&r[0], "to"), &json!("customers/active"));
    assert_eq!(field(&r[0], "credential_slugs"), &json!(["demo", "other"]));
}

#[test]
fn a_rename_that_would_go_too_deep_moves_nothing_and_an_empty_folder_is_not_found() {
    let mut fx = fresh();
    fx.vault.set_credential_folder("demo", Some("a")).unwrap();
    fx.vault
        .set_credential_folder("other", Some("a/b/c"))
        .unwrap();
    // demo would be fine at w/x/y; other would be w/x/y/b/c, five deep.
    refused_cleanly(
        &mut fx.vault,
        |v| v.rename_folder("a", "w/x/y"),
        ("AV_POLICY_DENIED", Some("folder")),
    );
    refused_cleanly(
        &mut fx.vault,
        |v| v.rename_folder("nothing-here", "b"),
        ("AV_NOT_FOUND", None),
    );
    refused_cleanly(
        &mut fx.vault,
        |v| v.rename_folder("a", "bad//path"),
        ("AV_POLICY_DENIED", Some("folder")),
    );
}
