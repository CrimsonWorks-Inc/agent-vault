//! Credential proposals: an agent describes a credential over MCP, never the
//! key; a human confirms the hosts the key would be sent to and types the
//! key. New with credential proposals; no JS source.

use serde_json::{json, Value};

use super::*;

async fn mcp(w: &World, args: Value) -> Value {
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "vault_propose_credential", "arguments": args}});
    let r = w.daemon.mcp.handle(msg, None, None, None).await.unwrap();
    serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

fn linear() -> Value {
    json!({"slug": "linear", "kind": "http", "host": "api.linear.app", "sites": ["header:authorization"], "reason": "to read the open issues"})
}

/// A key the shape check reads as Anthropic's, built at run time.
fn anthropic_shaped() -> String {
    ["sk", "ant", &"q".repeat(30)].join("-")
}

async fn decide(w: &World, body: Value) -> (u16, Value) {
    w.control("POST", "/v1/cred-proposals/decide", body).await
}

async fn has_credential(w: &World, slug: &str) -> bool {
    let slug = slug.to_string();
    w.shared
        .run(move |c| c.vault.find_credential(&slug).unwrap().is_some())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_proposes_without_a_session_and_a_human_finishes_with_the_key() {
    let w = World::bare().await;
    let asked = mcp(&w, linear()).await;
    assert_eq!(asked["state"], "pending", "{asked}");
    assert_eq!(asked["hosts"], json!(["api.linear.app"]));
    let id = asked["request_id"].as_str().unwrap().to_string();
    assert!(id.starts_with("cp_"));
    let poll = json!({"poll_id": id, "poll_secret": asked["poll_secret"]});
    assert_eq!(mcp(&w, poll.clone()).await["state"], "pending");

    // What a human is shown: the hosts, the claim, the kind of decision.
    let (s, listed) = w.control("GET", "/v1/cred-proposals", json!({})).await;
    assert_eq!(s, 200);
    assert_eq!(listed[0]["hosts"], json!(["api.linear.app"]));
    assert_eq!(
        listed[0]["agent_reason_untrusted"],
        "to read the open issues"
    );
    assert_eq!(
        listed[0]["proposal"]["sites"],
        json!(["header:authorization"])
    );
    let item = av_store::pending::describe(av_store::pending::PendingKind::Credential, &listed[0]);
    assert_eq!(
        item.hosts.as_deref(),
        Some(&["api.linear.app".to_string()][..])
    );
    assert_eq!(item.decide.path, "/v1/cred-proposals/decide");
    let waiting = w.shared.run(|c| c.dm_waiting_items()).await.unwrap();
    assert_eq!(waiting[0]["kind"], "credential");

    let (s, v) = decide(
        &w,
        json!({"id": id, "granted": true, "hosts": ["api.linear.app"], "value": SECRET}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["state"], "approved");
    assert_eq!(v["credential"]["slug"], "linear");
    assert_eq!(v["credential"]["connector"]["host"], "api.linear.app");
    assert!(!leaks(&v.to_string()));
    assert!(has_credential(&w, "linear").await);

    let polled = mcp(&w, poll).await;
    assert_eq!(
        (polled["state"].as_str(), polled["cred"].as_str()),
        (Some("approved"), Some("linear"))
    );
    let audit = w.audit_text().await;
    for kind in [
        "cred_proposal.opened",
        "cred.added",
        "cred_proposal.approved",
    ] {
        assert!(audit.contains(kind), "{kind}");
    }
    assert!(!leaks(&audit));
    // Settled: nothing waiting, and it cannot be answered twice.
    let (_, listed) = w.control("GET", "/v1/cred-proposals", json!({})).await;
    assert_eq!(listed, json!([]));
    let (s, v) = decide(&w, json!({"id": id, "granted": false})).await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("cred_proposals")),
        "{v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proposal_never_widens_where_a_key_can_go() {
    let w = World::bare().await;
    let refused = |v: &Value, rule: &str| {
        assert_eq!(v["code"], "AV_POLICY_DENIED", "{v}");
        assert_eq!(v["rule"], rule, "{v}");
    };
    // A profile's hosts are fixed: a host beside them would join the ceiling.
    refused(
        &mcp(
            &w,
            json!({"slug": "gh", "kind": "github", "host": "evil.example"}),
        )
        .await,
        "proposal_host",
    );
    let gh = mcp(&w, json!({"slug": "gh", "kind": "github"})).await;
    assert_eq!(
        gh["hosts"],
        json!(["api.github.com", "uploads.github.com", "github.com"]),
        "{gh}"
    );
    refused(
        &mcp(
            &w,
            json!({"slug": "gh2", "kind": "github", "sites": ["query:token"]}),
        )
        .await,
        "proposal_sites",
    );
    // A generic credential names one host a human can read back.
    for host in [
        None,
        Some("https://api.x.example/v1"),
        Some("203.0.113.9"),
        Some("localhost"),
        Some("a b.example"),
    ] {
        let mut p = json!({"slug": "x1", "kind": "http"});
        if let Some(h) = host {
            p["host"] = h.into();
        }
        refused(&mcp(&w, p).await, "proposal_host");
    }
    // Read back as the gateway enforces it: lowercase, no port, no final dot.
    let ok = mcp(&w, json!({"slug": "x1", "host": "API.Example.COM:8443"})).await;
    assert_eq!(ok["hosts"], json!(["api.example.com"]), "{ok}");
    let dot = mcp(&w, json!({"slug": "x3", "host": "api.example.org."})).await;
    assert_eq!(dot["hosts"], json!(["api.example.org"]), "{dot}");
    refused(
        &mcp(
            &w,
            json!({"slug": "x2", "host": "api.example.com", "sites": ["proxy:userinfo"]}),
        )
        .await,
        "proposal_sites",
    );
    refused(
        &mcp(
            &w,
            json!({"slug": "x2", "host": "api.example.com", "scheme": "http"}),
        )
        .await,
        "proposal_shape",
    );
    refused(
        &mcp(
            &w,
            json!({"slug": "x2", "kind": "postgres", "host": "db.example.com"}),
        )
        .await,
        "proposal_kind",
    );
    // Only new names, and one proposal per name at a time.
    refused(
        &mcp(&w, json!({"slug": "x1", "host": "api.example.com"})).await,
        "proposal_slug",
    );
    refused(
        &mcp(&w, json!({"slug": "Not A Slug", "host": "api.example.com"})).await,
        "proposal_slug",
    );
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "taken", "kind": "http", "host": "api.example.test", "value": SECRET}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    refused(
        &mcp(&w, json!({"slug": "taken", "host": "api.example.com"})).await,
        "proposal_slug",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proposal_carrying_a_key_is_refused_and_nothing_of_it_is_kept() {
    let w = World::bare().await;
    let key = anthropic_shaped();
    for p in [
        json!({"slug": "a1", "host": "api.example.com", "value": SECRET}),
        json!({"slug": "a1", "host": "api.example.com", "api_key": SECRET}),
        json!({"slug": "a1", "host": "api.example.com", "reason": format!("the key is {key}")}),
        json!({"slug": "a1", "host": "api.example.com", "field": key.clone()}),
    ] {
        let v = mcp(&w, p).await;
        assert_eq!(v["rule"], "proposal_secret", "{v}");
    }
    let (_, listed) = w.control("GET", "/v1/cred-proposals", json!({})).await;
    assert_eq!(listed, json!([]));
    let kept = w
        .shared
        .run(|c| c.vault.cred_proposals().unwrap())
        .await
        .unwrap();
    assert!(!kept.to_string().contains(&key) && !leaks(&kept.to_string()));
    let audit = w.audit_text().await;
    assert!(!audit.contains(&key) && !leaks(&audit));
}

#[tokio::test(flavor = "multi_thread")]
async fn approving_takes_exactly_the_hosts_shown_and_a_key_whose_shape_fits_them() {
    let w = World::bare().await;
    let asked = mcp(&w, linear()).await;
    let id = asked["request_id"].clone();
    for hosts in [
        json!(null),
        json!([]),
        json!(["api.linear.app", "evil.example"]),
        json!(["evil.example"]),
    ] {
        let mut b = json!({"id": id, "granted": true, "value": SECRET});
        if !hosts.is_null() {
            b["hosts"] = hosts;
        }
        let (s, v) = decide(&w, b).await;
        assert_eq!(
            (s, v["rule"].as_str()),
            (403, Some("proposal_hosts")),
            "{v}"
        );
    }
    // A key that says it is Anthropic's, bound for a host that is not.
    let (s, v) = decide(&w, json!({"id": id, "granted": true, "hosts": ["api.linear.app"], "value": anthropic_shaped()})).await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("proposal_key_host")),
        "{v}"
    );
    assert!(v["detail"].as_str().unwrap().contains("an Anthropic key"));
    let (s, v) = decide(
        &w,
        json!({"id": id, "granted": true, "hosts": ["api.linear.app"], "value": "  "}),
    )
    .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("proposal_value")),
        "{v}"
    );
    let (s, v) = decide(&w, json!({"id": id, "granted": true, "hosts": ["api.linear.app"], "value": SECRET, "kind": "github"})).await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("proposal_decision")),
        "{v}"
    );
    // Nothing was made, and the proposal still waits.
    assert!(!has_credential(&w, "linear").await);
    let (_, listed) = w.control("GET", "/v1/cred-proposals", json!({})).await;
    assert_eq!(listed[0]["state"], "pending");
    // A name that only ends in the provider's is not the provider's.
    let lookalike = mcp(&w, json!({"slug": "nota", "host": "api.notanthropic.com"})).await;
    let (s, v) = decide(&w, json!({"id": lookalike["request_id"], "granted": true, "hosts": ["api.notanthropic.com"], "value": anthropic_shaped()})).await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("proposal_key_host")),
        "{v}"
    );
    // The same key shape is fine where it belongs.
    let a = mcp(&w, json!({"slug": "claude", "kind": "anthropic"})).await;
    let (s, v) = decide(&w, json!({"id": a["request_id"], "granted": true, "hosts": ["api.anthropic.com"], "value": anthropic_shaped()})).await;
    assert_eq!(s, 200, "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denial_carries_no_key_and_only_the_proposer_can_poll() {
    let w = World::bare().await;
    let asked = mcp(&w, linear()).await;
    let id = asked["request_id"].clone();
    let wrong = mcp(&w, json!({"poll_id": id, "poll_secret": "not-it"})).await;
    assert!(wrong["error"]
        .as_str()
        .unwrap()
        .contains("only the agent that proposed it"));
    let (s, v) = decide(&w, json!({"id": id, "granted": false, "value": SECRET})).await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("proposal_decision")),
        "{v}"
    );
    let (s, v) = decide(&w, json!({"id": id, "granted": false})).await;
    assert_eq!((s, v["state"].as_str()), (200, Some("denied")), "{v}");
    let polled = mcp(
        &w,
        json!({"poll_id": id, "poll_secret": asked["poll_secret"]}),
    )
    .await;
    assert_eq!(polled["state"], "denied");
    assert!(!has_credential(&w, "linear").await);
    assert!(w.audit_text().await.contains("cred_proposal.denied"));
}

#[tokio::test(flavor = "multi_thread")]
async fn proposals_are_kept_across_a_restart_expire_unanswered_and_a_panic_denies_them() {
    let w = World::bare().await;
    let asked = mcp(&w, linear()).await;
    let id = asked["request_id"].as_str().unwrap().to_string();
    // A new core reads back what the last one saved.
    let back = w
        .shared
        .run({
            let id = id.clone();
            move |c| {
                c.cp = crate::cred_proposals::CredProposalStore::load(&c.vault);
                c.cp_get(&id).map(|r| r.state)
            }
        })
        .await
        .unwrap();
    assert_eq!(back.as_deref(), Some("pending"));
    // Unanswered past its time: expired, and the agent is told so.
    w.shared
        .run(|c| {
            let mut rows = c.vault.cred_proposals().unwrap();
            rows[0]["created_at"] = "2020-01-01T00:00:00.000Z".into();
            c.vault.save_cred_proposals(&rows).unwrap();
            c.cp = crate::cred_proposals::CredProposalStore::load(&c.vault);
        })
        .await
        .unwrap();
    let polled = mcp(
        &w,
        json!({"poll_id": id, "poll_secret": asked["poll_secret"]}),
    )
    .await;
    assert_eq!(polled["state"], "expired", "{polled}");
    let (s, v) = decide(
        &w,
        json!({"id": id, "granted": true, "hosts": ["api.linear.app"], "value": SECRET}),
    )
    .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("cred_proposals")),
        "{v}"
    );
    // A panic leaves nothing that could be finished.
    let again = mcp(&w, json!({"slug": "linear2", "host": "api.linear.app"})).await;
    let (s, v) = w.control("POST", "/v1/panic", json!({})).await;
    assert_eq!(s, 200, "{v}");
    let polled = mcp(
        &w,
        json!({"poll_id": again["request_id"], "poll_secret": again["poll_secret"]}),
    )
    .await;
    assert_eq!(polled["state"], "denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_goes_in_whatever_header_the_service_names_and_nowhere_unusable() {
    let mut w = World::bare().await;
    // ElevenLabs reads its key from xi-api-key, not Authorization.
    let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "eleven", "kind": "http", "host": "api.elevenlabs.test", "value": SECRET, "sites": ["header:xi-api-key"]})).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "eleven", "methods": ["GET"], "ttl_hours": 1}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    w.slug = "eleven".into();
    w.token = v["token"].as_str().unwrap().into();
    let ph = v["placeholder"].as_str().unwrap().to_string();
    let r = w
        .send("GET", "/v1/voices", vec![("xi-api-key".into(), ph)], None)
        .await;
    assert_eq!(r.status, 200);
    let sent = w.up.hits.lock().unwrap().last().unwrap().headers.clone();
    assert!(
        sent.iter().any(|(n, v)| n == "xi-api-key" && v == SECRET),
        "{sent:?}"
    );
    assert!(!sent
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("authorization")));
    // A site that could never be used is refused when it is stored.
    for site in ["header:xi api key", "header:", "nonsense:x"] {
        let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "bad", "kind": "http", "host": "api.example.test", "value": SECRET, "sites": [site]})).await;
        assert_eq!((s, v["rule"].as_str()), (403, Some("site")), "{site}: {v}");
    }
    // An agent may propose a named header, never a framing one.
    let ok = mcp(
        &w,
        json!({"slug": "eleven2", "host": "api.elevenlabs.io", "sites": ["header:xi-api-key"]}),
    )
    .await;
    assert_eq!(ok["state"], "pending", "{ok}");
    let framing = mcp(
        &w,
        json!({"slug": "eleven3", "host": "api.elevenlabs.io", "sites": ["header:host"]}),
    )
    .await;
    assert_eq!(framing["rule"], "proposal_sites", "{framing}");
}
