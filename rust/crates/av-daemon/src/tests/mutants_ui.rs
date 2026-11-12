//! Tests for the src/ui/server.js entries of mutations.toml, over real HTTP
//! against a daemon's control socket. Each names the protection (the `what`
//! of test/mutation-check.js) it holds.

use serde_json::{json, Value};

use super::ui::{dist, raw, Reply, Ui};
use crate::ui::server::{literal_path, toward_page, UiServer, DAEMON_VERIFIED};
use crate::ui::webauthn::testkit::SoftKey;

const PASS: &str = "test-passphrase-123";

fn pin(c: char) -> String {
    format!("sha256/{}=", c.to_string().repeat(43))
}

/// A UI over a daemon with two pins and a scrub pattern on `demo`, a
/// passphrase and an enrolled software authenticator, claimed.
async fn signed_ui() -> (Ui, SoftKey, String) {
    let mut u = Ui::start().await;
    let w = &u._w;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/pins",
            json!({"slug": "demo", "host": "api.example.test", "pins": [pin('A'), pin('B')]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/scrub",
            json!({"slug": "demo", "pattern": "zz-[0-9]{6}"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (_, cred) = w.control("GET", "/v1/credentials", json!({})).await;
    let scrub_id = crate::util::js_stringify(&cred)
        .split("\"id\":\"")
        .find_map(|x| {
            x.split('"')
                .next()
                .filter(|i| i.starts_with("sp_"))
                .map(str::to_string)
        })
        .unwrap_or_default();
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let o = format!("http://localhost:{}", u.port());
    let (s, v) = w
        .control(
            "POST",
            "/v1/ui/origins",
            json!({"origin": o, "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let k = SoftKey::new();
    let mut rec = k.record();
    rec["presence"] = json!({"passphrase": PASS});
    let (s, v) = w.control("POST", "/v1/presence", rec).await;
    assert_eq!(s, 200, "{v}");
    u.claim().await;
    (u, k, scrub_id)
}

fn origin(u: &Ui) -> String {
    format!("http://localhost:{}", u.port())
}

/// A gated call, signed the way the page signs it.
async fn signed(
    u: &Ui,
    k: &mut SoftKey,
    method: &str,
    route: &str,
    query: &str,
    mut body: Value,
) -> Reply {
    let key = format!("{method} {route}");
    let op = UiServer::operation_of(&key, query, &body).expect("an operation");
    let ch = u
        .api("POST", "presence/challenge", json!({"operation": op}))
        .await
        .json();
    let challenge = crate::util::b64url_lenient(ch["challenge"].as_str().expect("a challenge"));
    let mut pres = k.assert(&challenge, &origin(u));
    pres["challengeId"] = ch["challengeId"].clone();
    body["presence"] = pres;
    let path = if query.is_empty() {
        route.to_string()
    } else {
        format!("{route}?{query}")
    };
    u.api(method, &path, body).await
}

/// 'credential-record writes, tripwire rules and templates go through the
/// UI unsigned' and 'removing a pin from the UI needs no signature (C22(4))'.
#[tokio::test(flavor = "multi_thread")]
async fn every_record_write_needs_a_signature_at_the_ui() {
    let mut u = Ui::start().await;
    u.claim().await;
    for (m, route) in [
        ("POST", "credentials/rotate"),
        ("POST", "credentials/scrub"),
        ("DELETE", "credentials/scrub?slug=demo&id=x"),
        ("POST", "credentials/expiry"),
        ("POST", "credentials/release"),
        ("POST", "tripwires"),
        ("POST", "templates"),
        ("DELETE", "templates?name=t"),
        ("DELETE", "credentials/pins?slug=demo&host=api.example.test"),
    ] {
        let r = u.api(m, route, json!({"slug": "demo"})).await;
        assert_eq!(r.status, 412, "{m} {route}: {}", r.body);
    }
}

/// 'the UI treats the daemon-verified pin removal as its own check only'.
#[tokio::test(flavor = "multi_thread")]
async fn the_daemon_checks_a_pin_removal_itself() {
    assert!(DAEMON_VERIFIED.contains(&"DELETE credentials/pins"));
    let (u, _k, _) = signed_ui().await;
    let (s, v) =
        u._w.control(
            "DELETE",
            "/v1/credentials/pins?slug=demo&host=api.example.test",
            json!({}),
        )
        .await;
    assert_eq!(s, 401, "{v}");
}

/// 'Touch ID changes from the UI drop the proof on the way to the daemon',
/// 'removing a scrub pattern drops the proof on the way to the daemon', 'the
/// UI forwards a single-pin removal without the pin'.
#[tokio::test(flavor = "multi_thread")]
async fn a_signed_change_reaches_the_daemon_with_its_proof_and_its_arguments() {
    let (u, mut k, scrub) = signed_ui().await;
    let r = signed(&u, &mut k, "POST", "touchid/remove", "", json!({})).await;
    assert_ne!(r.status, 401, "{}", r.body);
    assert_ne!(r.json()["code"], "AV_PRESENCE_REQUIRED", "{}", r.body);
    let r = signed(
        &u,
        &mut k,
        "DELETE",
        "credentials/scrub",
        &format!("slug=demo&id={scrub}"),
        json!({}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = signed(
        &u,
        &mut k,
        "DELETE",
        "credentials/pins",
        &format!(
            "slug=demo&host=api.example.test&spki={}",
            crate::util::encode_uri_component(&pin('A'))
        ),
        json!({}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["remaining"], 1, "only the one pin: {}", r.body);
}

/// 'the UI binds a pin removal with spki omitted rather than null (C22(4))'.
#[test]
fn a_pin_removal_binds_a_missing_spki_as_null() {
    let op = UiServer::operation_of(
        "DELETE credentials/pins",
        "slug=demo&host=api.example.test",
        &json!({}),
    )
    .unwrap();
    assert_eq!(op["spki"], Value::Null);
    assert!(op.as_object().unwrap().contains_key("spki"), "{op}");
}

/// 'a replacement authenticator other than the one just registered is
/// accepted by the UI'.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_key_just_registered_can_replace_the_authenticator() {
    let (u, _k, _) = signed_ui().await;
    let begun = u.api("POST", "presence/rotate/begin", json!({})).await;
    assert_eq!(begun.status, 200, "{}", begun.body);
    let ch = crate::util::b64url_lenient(begun.json()["challenge"].as_str().unwrap());
    let next = SoftKey::new();
    let reg = u
        .api(
            "POST",
            "presence/rotate/register",
            next.attestation(&ch, &origin(&u)),
        )
        .await;
    assert_eq!(reg.status, 200, "{}", reg.body);
    let mut other = reg.json()["credential"].clone();
    other["credentialId"] = json!(SoftKey::new().id);
    let r = u.api("POST", "presence/rotate", other).await;
    assert_eq!(r.status, 409, "{}", r.body);
}

/// 'the page can steer the credential probe'.
#[tokio::test(flavor = "multi_thread")]
async fn the_page_sends_the_probe_only_a_slug_or_all() {
    let mut u = Ui::start().await;
    u.claim().await;
    let r = u
        .api(
            "POST",
            "credentials/test",
            json!({"slug": "demo", "all": "yes"}),
        )
        .await;
    assert_ne!(r.json()["detail"]["rule"], "policy_invalid", "{}", r.body);
    assert_eq!(r.json()["detail"]["rule"], "no_probe", "{}", r.body);
}

/// 'the audit kind filter takes any text into the daemon path'.
#[tokio::test(flavor = "multi_thread")]
async fn an_audit_kind_that_is_not_a_record_kind_is_refused() {
    let mut u = Ui::start().await;
    u.claim().await;
    for k in ["Bad", "a..b", "x%26limit%3D1", "a.", "a-b"] {
        let r = u
            .get(&format!("/api/audit?kind={k}"), "X-AV-UI: 1\r\n")
            .await;
        assert_eq!(r.status, 400, "{k}: {}", r.body);
    }
    let r = u
        .get("/api/audit?kind=session.created", "X-AV-UI: 1\r\n")
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
}

/// 'U3 fix4: the page's old kind read passes its own limit to the daemon'.
#[tokio::test(flavor = "multi_thread")]
async fn the_old_kind_read_asks_the_daemon_for_a_batch() {
    let mut u = Ui::start().await;
    u.claim().await;
    for l in ["abc", "1000", "0"] {
        let r = u
            .get(
                &format!("/api/audit?kind=session.created&limit={l}"),
                "X-AV-UI: 1\r\n",
            )
            .await;
        assert_eq!(r.status, 200, "limit {l}: {}", r.body);
    }
}

/// "a hand-off card field is copied back with whatever is nested in it",
/// 'the session hand-off carries the whole daemon answer, not only the
/// card fields', 'an error from POST sessions reaches the page as a
/// hand-off, unfiltered'.
#[tokio::test(flavor = "multi_thread")]
async fn the_session_hand_off_is_the_card_and_errors_are_filtered() {
    let (u, mut k, _) = signed_ui().await;
    let body = json!({"cred": "demo", "label": "ui", "methods": ["GET"], "ttl_hours": 1});
    let r = signed(&u, &mut k, "POST", "sessions", "", body).await;
    assert_eq!(r.status, 200, "{}", r.body);
    eprintln!("HANDOFF {}", r.body);
    let v = r.json();
    assert!(v["token"].as_str().unwrap().starts_with("avs1."), "{v}");
    let ph = u._w.placeholder.clone();
    let bad = json!({"cred": ph, "label": "ui", "methods": ["GET"], "ttl_hours": 1});
    let r = signed(&u, &mut k, "POST", "sessions", "", bad).await;
    eprintln!("ERR {}", r.body);
    assert!(r.status >= 400);
    assert!(!r.body.contains("av1."), "{}", r.body);
}

/// 'towardPage sends a passphrase to the page', 'a hyphenated withheld key
/// reaches the page', 'towardPage sends a pass-phrase or pass_phrase to the
/// page', 'towardPage keeps pass--phrase, pass__phrase and "pass phrase":
/// separator runs are not folded'.
#[test]
fn withheld_keys_are_dropped_under_every_spelling() {
    let v = json!({
        "passphrase": 1, "pass-phrase": 2, "pass_phrase": 3, "Pass-Phrase": 4,
        "pass--phrase": 5, "pass__phrase": 6, "pass phrase": 7, "prf-secret": 8,
        "Recovery-Passphrase": 9, "webhook-url": 10, "kept": 11,
    });
    let out = toward_page(&v, 0);
    assert_eq!(out, json!({"kept": 11}));
}

/// 'U2: a server with no built bundle starts anyway', 'U2 fix3: a dist
/// directory that is a symlink is followed', 'U2 fix3: an index.html that is
/// a symlink is followed', 'U2 fix3: an assets directory that is a symlink is
/// read through'.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_linked_bundle_is_refused() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("empty")).unwrap();
    let sock = d.path().join("none.sock");
    let r = UiServer::start(
        &sock,
        crate::ui::server::UiServerOptions {
            port: 0,
            dist_dir: Some(d.path().join("empty")),
            state_path: Some(d.path().join("state.json")),
            ..Default::default()
        },
    )
    .await;
    assert!(r.is_err(), "no index.html, no server");
    dist(&d.path().join("real"));
    std::fs::remove_file(d.path().join("real/assets/link.js")).unwrap();
    assert!(crate::ui::server::load_dist(&d.path().join("real")).is_ok());
    // index.html as a link
    dist(&d.path().join("ix"));
    std::fs::remove_file(d.path().join("ix/assets/link.js")).unwrap();
    std::fs::remove_file(d.path().join("ix/index.html")).unwrap();
    std::os::unix::fs::symlink(
        d.path().join("real/index.html"),
        d.path().join("ix/index.html"),
    )
    .unwrap();
    let e = crate::ui::server::load_dist(&d.path().join("ix")).unwrap_err();
    assert!(e.to_string().contains("index.html is a symlink"), "{e}");
    // assets as a link
    std::fs::create_dir_all(d.path().join("as")).unwrap();
    std::fs::write(d.path().join("as/index.html"), "x").unwrap();
    std::os::unix::fs::symlink(d.path().join("real/assets"), d.path().join("as/assets")).unwrap();
    let e = crate::ui::server::load_dist(&d.path().join("as")).unwrap_err();
    assert!(
        e.to_string().contains("the assets directory is a symlink"),
        "{e}"
    );
    // dist itself as a link
    std::os::unix::fs::symlink(d.path().join("real"), d.path().join("ln")).unwrap();
    let e = crate::ui::server::load_dist(&d.path().join("ln")).unwrap_err();
    assert!(
        e.to_string().contains("the dist directory is a symlink"),
        "{e}"
    );
}

/// 'U2 fix2: a path the parser changed counts as literal', 'U2 fix2:
/// encoded separators and backslashes count as literal', 'U2 fix2: dot and
/// empty segments count as literal'.
#[test]
fn a_literal_path_is_exactly_what_arrived() {
    assert!(literal_path("/", "/"));
    assert!(literal_path("/assets/app-1.js?x=1", "/assets/app-1.js"));
    assert!(!literal_path("/a/../b", "/b"));
    assert!(!literal_path("/\u{e9}", "/%C3%A9"), "the parser changed it");
    assert!(!literal_path("/a b", "/a%20b"), "the parser changed it");
    assert!(!literal_path("/assets/%2e%2e/x", "/assets/%2e%2e/x"));
    assert!(!literal_path("/assets/%2F/x", "/assets/%2F/x"));
    assert!(!literal_path("/a\\b", "/a\\b"));
    assert!(!literal_path("/a/./b", "/a/./b"));
    assert!(!literal_path("/a/../b", "/a/../b"));
    assert!(!literal_path("/a//b", "/a//b"));
}

/// 'U2 fix2: the raw path is not checked before routing'.
#[tokio::test(flavor = "multi_thread")]
async fn a_path_that_normalises_to_the_page_is_not_served() {
    let mut u = Ui::start().await;
    u.claim().await;
    for p in ["/x/../", "/./", "/assets/..", "/api/../"] {
        let r = u.get(p, "").await;
        assert_eq!(r.status, 404, "{p}: {}", r.status);
    }
}

/// 'U2 fix2: a request target the URL parser refuses is thrown, not
/// answered'.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_the_parser_refuses_is_answered_404() {
    let mut u = Ui::start().await;
    u.claim().await;
    for t in ["//[bad/", "//%zz@/", "//a:99999/"] {
        let r = raw(
            u.port(),
            &format!("GET {t} HTTP/1.1\r\nHost: localhost:{}\r\n", u.port()),
            "",
        )
        .await;
        eprintln!("TARGET {t} -> {}", r.status);
        assert!(r.status == 404 || r.status == 400, "{t}: {}", r.status);
    }
}

/// 'the UI login cookie never slides'.
#[tokio::test(flavor = "multi_thread")]
async fn every_api_answer_slides_the_cookie() {
    let mut u = Ui::start().await;
    u.claim().await;
    let r = u.api("GET", "status", json!({})).await;
    let c = r.header("set-cookie").unwrap_or("");
    assert!(c.starts_with("av_ui=") && c.contains("Max-Age="), "{c}");
}

/// 'a VaultError refusal from the UI is reported as a crash'.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_refusal_keeps_its_status() {
    let (u, _k, _) = signed_ui().await;
    let ch = u
        .api(
            "POST",
            "presence/challenge",
            json!({"operation": {"op": "cred.add"}}),
        )
        .await
        .json();
    let r = u
        .api(
            "POST",
            "credentials",
            json!({"slug": "x", "op": "evil", "presence": {"challengeId": ch["challengeId"]}}),
        )
        .await;
    assert_eq!(r.status, 403, "{}", r.body);
}

/// 'the UI server checks the narrowing of an approval only, so a denial
/// carrying an unreadable one is not a 400'.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_narrowing_is_refused_on_a_denial_too() {
    let mut u = Ui::start().await;
    u.claim().await;
    let r = u
        .api(
            "POST",
            "session-requests/decide",
            json!({"id": "sr_x", "granted": false, "overrides": {"routes": "[bad"}}),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.body);
}

/// 'U3: a paged search matches the answer before towardPage, so q can test
/// a withheld value' and 'U3: an audit search matches rows before
/// towardPage'.
#[tokio::test(flavor = "multi_thread")]
async fn a_search_cannot_test_a_withheld_value() {
    let mut u = Ui::start().await;
    let fake = "avs1.abcdefghijkl.ABCDEFGHIJKLMNOPQRSTUV";
    let (s, v) =
        u._w.control(
            "POST",
            "/v1/sessions",
            json!({"cred": "demo", "label": fake, "methods": ["GET"], "ttl_hours": 1}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    // An audit row that carries the same text: the agent's reason.
    let sess =
        u._w.shared
            .run({
                let t = u._w.token.clone();
                move |c| c.vault.session_by_token(&t).unwrap()
            })
            .await
            .unwrap();
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "vault_get_placeholder", "arguments": {"cred": "demo", "reason": format!("see {fake}")}}});
    u._w.daemon
        .mcp
        .handle(msg, sess, Some(u._w.token.clone()), None)
        .await
        .unwrap();
    // And one with it in a field the search reads.
    u._w.shared
        .run(move |c| {
            c.audit(
                "test.planted",
                json!({"rule": format!("see {fake}"), "credential_slug": "demo"}),
            )
        })
        .await
        .unwrap();
    assert!(
        u._w.audit_text().await.contains("avs1."),
        "the row holds it"
    );
    u.claim().await;
    for list in ["sessions", "audit"] {
        let r = u
            .get(&format!("/api/{list}?paged=1&q=avs1"), "X-AV-UI: 1\r\n")
            .await;
        assert_eq!(r.status, 200, "{list}: {}", r.body);
        assert!(!r.body.contains("avs1."), "{list}: {}", r.body);
        assert_eq!(r.json()["items"], json!([]), "{list}: {}", r.body);
    }
    // A search that does match the row hands it over as the page sees it.
    let r = u
        .get("/api/audit?paged=1&q=demo&limit=200", "X-AV-UI: 1\r\n")
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(
        r.body.contains("\u{ab}token\u{bb}"),
        "the matched row is there, its token withheld: {}",
        r.body
    );
    assert!(!r.body.contains("avs1."), "{}", r.body);
}

async fn audit_page(u: &Ui, q: &str) -> Value {
    let r = u
        .get(&format!("/api/audit?paged=1&{q}"), "X-AV-UI: 1\r\n")
        .await;
    assert_eq!(r.status, 200, "{q}: {}", r.body);
    r.json()
}

fn seqs(v: &Value) -> Vec<i64> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["seq"].as_i64().unwrap())
        .collect()
}

/// 'U3: the audit page ignores where the last page ended and rereads the
/// newest rows', 'U3 fix1: Prev with less than a page above it starts again
/// from the newest row', 'U3 fix1: a short Prev page still offers a Prev'.
#[tokio::test(flavor = "multi_thread")]
async fn audit_pages_walk_from_their_cursor() {
    let mut u = Ui::start().await;
    for _ in 0..8 {
        u._w.send("DELETE", "/x", vec![], None).await;
    }
    u.claim().await;
    let p1 = audit_page(&u, "limit=2").await;
    let next = p1["next_cursor"].as_str().unwrap().to_string();
    let p2 = audit_page(&u, &format!("limit=2&cursor={next}")).await;
    let (a, b) = (seqs(&p1), seqs(&p2));
    assert_eq!(b.len(), 2, "{p2}");
    assert!(b[0] < a[1], "page two is older: {a:?} {b:?}");
    // From page one's top row, Prev has nothing above a page's worth.
    let top = audit_page(&u, "limit=1").await;
    let n1 = top["next_cursor"].as_str().unwrap().to_string();
    let second = audit_page(&u, &format!("limit=1&cursor={n1}")).await;
    let prev = second["prev_cursor"].as_str().unwrap().to_string();
    let back = audit_page(&u, &format!("limit=3&cursor={prev}")).await;
    assert_eq!(
        seqs(&back),
        seqs(&top),
        "a short page, not the newest three"
    );
    assert_eq!(back["prev_cursor"], Value::Null, "{back}");
}

type Canned = std::sync::Arc<std::sync::Mutex<(u16, Value)>>;

/// [`signed_ui`] whose control socket answers POST /v1/sessions with
/// whatever `canned` holds and passes everything else to the daemon.
async fn stubbed_ui() -> (Ui, SoftKey, Canned) {
    let (base, k, _) = signed_ui().await;
    let canned: Canned = std::sync::Arc::new(std::sync::Mutex::new((200, json!({}))));
    let sockdir = tempfile::Builder::new()
        .prefix("avs")
        .tempdir_in("/tmp")
        .unwrap();
    let sock = sockdir.path().join("c.sock");
    let listener = crate::listen::bind_unix(&sock).unwrap();
    let d = base._w.daemon.clone();
    let c2 = canned.clone();
    tokio::spawn(crate::listen::serve_unix(listener, None, move |req| {
        let (d, c) = (d.clone(), c2.clone());
        async move {
            if req.method == "POST" && req.target == "/v1/sessions" {
                let (s, v) = c.lock().unwrap().clone();
                return crate::http::response(
                    s,
                    &[("content-type".into(), "application/json".into())],
                    crate::util::js_stringify(&v).into_bytes(),
                );
            }
            d.on_control(req).await
        }
    }));
    let distdir = tempfile::tempdir().unwrap();
    dist(distdir.path());
    std::fs::remove_file(distdir.path().join("assets/link.js")).unwrap();
    // The same port as the UI the origin was registered for is not needed:
    // register this one too.
    let ui = UiServer::start(
        &sock,
        crate::ui::server::UiServerOptions {
            port: 0,
            dist_dir: Some(distdir.path().to_path_buf()),
            state_path: Some(sockdir.path().join("state.json")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (s, v) = base
        ._w
        .control(
            "POST",
            "/v1/ui/origins",
            json!({"origin": format!("http://localhost:{}", ui.bound_port()), "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let Ui { _w, .. } = base;
    let mut u = Ui {
        _sock: sockdir,
        _w,
        _dist: distdir,
        ui,
        cookie: None,
    };
    u.claim().await;
    (u, k, canned)
}

const TOKEN: &str = "avs1.abcdefghijkl.ABCDEFGHIJKLMNOPQRSTUVWX";

/// 'an error from POST sessions reaches the page as a hand-off, unfiltered',
/// 'the session hand-off carries the whole daemon answer, not only the card
/// fields', 'a hand-off card field is copied back with whatever is nested in
/// it'.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_card_of_a_created_session_reaches_the_page() {
    let (u, mut k, canned) = stubbed_ui().await;
    let ph = u._w.placeholder.clone();
    let body = json!({"cred": "demo", "methods": ["GET"]});
    *canned.lock().unwrap() = (
        400,
        json!({"code": "AV_POLICY_DENIED", "detail": "no", "token": TOKEN, "placeholder": ph,
               "value": "super-secret-value-XYZ", "grants": [{"cred": "demo", "placeholder": ph}]}),
    );
    let r = signed(&u, &mut k, "POST", "sessions", "", body.clone()).await;
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(
        !r.body.contains(TOKEN) && !r.body.contains(&ph),
        "{}",
        r.body
    );
    assert!(!r.body.contains("super-secret-value-XYZ"), "{}", r.body);
    *canned.lock().unwrap() = (
        200,
        json!({"token": TOKEN, "session_id": "s_1", "label": "x", "note": format!("export AV_SESSION={TOKEN}"),
               "grants": [{"cred": "demo", "placeholder": ph, "usage": [format!("Bearer {ph}")],
                           "probe": {"nested": {"token": TOKEN, "kept": 1}}}]}),
    );
    let r = signed(&u, &mut k, "POST", "sessions", "", body).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["token"], TOKEN, "the card carries the token");
    assert_eq!(v["grants"][0]["placeholder"], json!(ph));
    assert!(!v["note"].as_str().unwrap().contains(TOKEN), "{v}");
    assert_eq!(
        v["grants"][0]["probe"],
        json!({"nested": {"kept": 1}}),
        "{v}"
    );
}
