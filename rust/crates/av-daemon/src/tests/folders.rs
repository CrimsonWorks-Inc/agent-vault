//! Credential folders through the daemon: the control routes, that a folder
//! changes nothing an agent can do, and the credentials page's folder tree,
//! filters and orders. New with SQLite schema 2; no JS source.

use serde_json::{json, Value};

use super::ui::Ui;
use super::*;

async fn add(w: &World, slug: &str, kind: &str) {
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": slug, "kind": kind, "host": format!("{slug}.example.test"), "value": format!("{slug}-value-0123456789"), "sites": ["header:authorization:Bearer"]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
}

async fn move_to(w: &World, slug: &str, folder: Value) -> (u16, Value) {
    w.control(
        "POST",
        "/v1/credentials/folder",
        json!({"slug": slug, "folder": folder}),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_filed_credential_works_exactly_as_before_and_the_move_is_audited() {
    let w = World::seeded(json!({})).await;
    let (s, v) = move_to(&w, "demo", json!("clients/acme")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["folder"], "clients/acme");
    let r = w.get("/user").await;
    assert_eq!(r.status, 200, "{:?}", r.error);
    assert_eq!(w.up.count(), 1);
    let (_, list) = w.control("GET", "/v1/credentials", json!({})).await;
    assert_eq!(list[0]["folder"], "clients/acme");
    let audit = w.audit().await;
    let set: Vec<_> = audit
        .iter()
        .filter(|r| r["kind"] == "cred.folder_set")
        .collect();
    assert_eq!(set.len(), 1);
    assert_eq!(set[0]["to"], "clients/acme");
    let (s, v) = move_to(&w, "demo", Value::Null).await;
    assert_eq!((s, v.get("folder")), (200, None), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_control_routes_refuse_a_wrong_shape_and_a_bad_path() {
    let w = World::seeded(json!({})).await;
    for folder in [json!(3), json!(["a"]), json!("a//b"), json!("../x")] {
        let (s, v) = move_to(&w, "demo", folder.clone()).await;
        assert_eq!(
            (s, v["code"].as_str(), v["rule"].as_str()),
            (403, Some("AV_POLICY_DENIED"), Some("folder")),
            "{folder}: {v}"
        );
    }
    let (s, v) = move_to(&w, "nope", json!("a")).await;
    assert_eq!(v["code"], "AV_NOT_FOUND", "{s} {v}");
    for body in [
        json!({"from": "a"}),
        json!({"from": "a", "to": 1}),
        json!({"to": "b"}),
    ] {
        let (_, v) = w
            .control("POST", "/v1/credentials/folder/rename", body.clone())
            .await;
        assert_eq!(v["rule"], "folder", "{body}: {v}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn renaming_a_folder_through_control_moves_everything_beneath_it() {
    let w = World::seeded(json!({})).await;
    add(&w, "beta", "http").await;
    move_to(&w, "demo", json!("clients")).await;
    move_to(&w, "beta", json!("clients/acme")).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/folder/rename",
            json!({"from": "clients", "to": "customers"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["moved"], json!(["beta", "demo"]));
    let (_, list) = w.control("GET", "/v1/credentials", json!({})).await;
    let folders: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["slug"].clone(), c["folder"].clone()))
        .collect();
    assert!(
        folders.contains(&(json!("demo"), json!("customers"))),
        "{folders:?}"
    );
    assert!(
        folders.contains(&(json!("beta"), json!("customers/acme"))),
        "{folders:?}"
    );
}

async fn page_ui() -> Ui {
    let mut u = Ui::start().await;
    u.claim().await;
    for (slug, kind) in [
        ("alpha", "github"),
        ("beta", "http"),
        ("gamma", "github"),
        ("delta", "http"),
    ] {
        add(&u._w, slug, kind).await;
    }
    for (slug, folder) in [
        ("alpha", "clients/acme"),
        ("beta", "clients"),
        ("gamma", "clients-old"),
        ("delta", "infra/aws"),
    ] {
        let (s, v) = move_to(&u._w, slug, json!(folder)).await;
        assert_eq!(s, 200, "{v}");
    }
    u
}

fn slugs(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no items: {v}"))
        .iter()
        .map(|c| c["slug"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_lists_a_folder_and_beneath_it_never_a_name_that_only_starts_the_same() {
    let u = page_ui().await;
    let r = u
        .api("GET", "credentials?paged=1&folder=clients", json!({}))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(slugs(&r.json()), vec!["alpha", "beta"]);
    assert_eq!(r.json()["total"], 2);
    let r = u
        .api("GET", "credentials?paged=1&unfiled=1", json!({}))
        .await;
    assert_eq!(slugs(&r.json()), vec!["demo"]);
    let r = u
        .api("GET", "credentials?paged=1&kind=github", json!({}))
        .await;
    assert_eq!(slugs(&r.json()), vec!["alpha", "gamma"]);
    let r = u.api("GET", "credentials?paged=1&q=infra", json!({})).await;
    assert_eq!(slugs(&r.json()), vec!["delta"], "search reaches the folder");
    let r = u
        .api("GET", "credentials?paged=1&q=gamma.example", json!({}))
        .await;
    assert_eq!(slugs(&r.json()), vec!["gamma"], "search reaches the host");
    let r = u
        .api("GET", "credentials?paged=1&status=untested", json!({}))
        .await;
    assert_eq!(slugs(&r.json()).len(), 5);
    let r = u
        .api("GET", "credentials?paged=1&status=quarantined", json!({}))
        .await;
    assert_eq!(slugs(&r.json()), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_orders_by_folder_and_a_cursor_from_one_order_or_filter_is_refused_by_another() {
    let u = page_ui().await;
    let r = u
        .api("GET", "credentials?paged=1&sort=folder", json!({}))
        .await;
    assert_eq!(
        slugs(&r.json()),
        vec!["demo", "beta", "alpha", "gamma", "delta"]
    );
    let r = u.api("GET", "credentials?paged=1&limit=2", json!({})).await;
    let cursor = r.json()["next_cursor"].as_str().unwrap().to_string();
    let other = u
        .api(
            "GET",
            &format!("credentials?paged=1&limit=2&sort=folder&cursor={cursor}"),
            json!({}),
        )
        .await;
    assert_eq!(
        (other.status, other.json()["code"].as_str()),
        (400, Some("AV_BAD_CURSOR")),
        "{}",
        other.body
    );
    let other = u
        .api(
            "GET",
            &format!("credentials?paged=1&limit=2&kind=http&cursor={cursor}"),
            json!({}),
        )
        .await;
    assert_eq!(
        (other.status, other.json()["code"].as_str()),
        (400, Some("AV_BAD_CURSOR")),
        "{}",
        other.body
    );
    let same = u
        .api(
            "GET",
            &format!("credentials?paged=1&limit=2&cursor={cursor}"),
            json!({}),
        )
        .await;
    assert_eq!(same.status, 200, "{}", same.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_refuses_a_filter_it_does_not_know() {
    let u = page_ui().await;
    for q in [
        "status=broken",
        "sort=random",
        "folder=a//b",
        "unfiled=yes",
        "folder=clients&unfiled=1",
        "folder=a&folder=b",
    ] {
        let r = u
            .api("GET", &format!("credentials?paged=1&{q}"), json!({}))
            .await;
        assert_eq!(
            (r.status, r.json()["code"].as_str()),
            (400, Some("AV_BAD_FILTER")),
            "{q}: {}",
            r.body
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_folder_tree_counts_each_folder_and_beneath_it_and_moves_need_no_signature() {
    let u = page_ui().await;
    let r = u.api("GET", "credentials/folders", json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let t = r.json();
    assert_eq!(
        (t["total"].clone(), t["unfiled"].clone()),
        (json!(5), json!(1))
    );
    assert_eq!(
        t["folders"],
        json!([
            {"path": "clients", "direct": 1, "total": 2},
            {"path": "clients-old", "direct": 1, "total": 1},
            {"path": "clients/acme", "direct": 1, "total": 1},
            {"path": "infra", "direct": 0, "total": 1},
            {"path": "infra/aws", "direct": 1, "total": 1},
        ])
    );
    assert_eq!(
        t["kinds"],
        json!([{"kind": "github", "count": 2}, {"kind": "http", "count": 3}])
    );

    let r = u
        .api(
            "POST",
            "credentials/folder",
            json!({"slug": "demo", "folder": "infra"}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = u
        .api(
            "POST",
            "credentials/folder/rename",
            json!({"from": "infra", "to": "platform"}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["moved"], json!(["delta", "demo"]));
    let r = u
        .api(
            "POST",
            "credentials/folder",
            json!({"slug": "demo", "folder": ""}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(
        r.json().get("folder").is_none(),
        "an empty folder unfiles it: {}",
        r.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_folder_named_like_a_token_is_withheld_and_a_search_cannot_test_it() {
    let mut u = Ui::start().await;
    u.claim().await;
    let fake = "avs1.abcdefghijkl.ABCDEFGHIJKLMNOPQRSTUV";
    let (s, v) = move_to(&u._w, "demo", json!(fake)).await;
    assert_eq!(s, 200, "{v}");
    for q in ["avs1", "abcdefghijkl"] {
        let r = u
            .api("GET", &format!("credentials?paged=1&q={q}"), json!({}))
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(
            slugs(&r.json()),
            Vec::<String>::new(),
            "q={q} tested the withheld folder"
        );
    }
    let r = u.api("GET", "credentials?paged=1", json!({})).await;
    assert!(!r.body.contains(fake), "{}", r.body);
    let r = u.api("GET", "credentials/folders", json!({})).await;
    assert!(!r.body.contains(fake), "{}", r.body);
}
