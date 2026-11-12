//! MCP: the handshake without a session, tools that check for themselves,
//! vault_http through the same pipeline, explain-denial scoping, transport
//! sessions. Ports the internal parts of test/security/mcp.test.js,
//! mcp-tools.test.js, control-api-mcp.test.js and fix-control-mcp.test.js
//! (see PORTED.md).

use serde_json::{json, Value};

use super::*;

async fn call(w: &World, name: &str, args: Value, with_session: bool) -> Value {
    let s = if with_session {
        w.shared
            .run({
                let t = w.token.clone();
                move |c| c.vault.session_by_token(&t).unwrap()
            })
            .await
            .unwrap()
    } else {
        None
    };
    let tok = if with_session {
        Some(w.token.clone())
    } else {
        None
    };
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
    w.daemon.mcp.handle(msg, s, tok, None).await.unwrap()["result"].clone()
}

fn text_of(r: &Value) -> Value {
    serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap_or(Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_handshake_and_the_ungated_tools_work_without_a_session() {
    let w = World::seeded(json!({})).await;
    let init = w.daemon.mcp.handle(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}), None, None, None).await.unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init["result"]["instructions"], crate::mcp::INSTRUCTIONS);
    assert_eq!(init["result"]["serverInfo"]["name"], "agent-vault");
    // Over HTTP the transport also issues a session id.
    let r = w
        .daemon
        .on_gateway(
            crate::server::Incoming {
                method: "POST".into(),
                target: "/mcp".into(),
                headers: vec![("host".into(), "127.0.0.1".into())],
                body: crate::util::js_stringify(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})).into_bytes(),
            },
            None,
            None,
        )
        .await;
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()
            .get("mcp-session-id")
            .is_some_and(|v| !v.is_empty()),
        "a transport session id is issued"
    );
    let list = w
        .daemon
        .mcp
        .handle(
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "vault_status",
            "vault_list_creds",
            "vault_get_placeholder",
            "vault_request_session",
            "vault_approval_status",
            "vault_http",
            "vault_explain_denial",
            "vault_describe_access",
            "vault_preflight"
        ]
    );
    let st = text_of(&call(&w, "vault_status", json!({}), false).await);
    assert_eq!(st["session"], Value::Null);
    assert_eq!(
        st["session_problem"],
        "no session token was sent with this connection"
    );
    assert!(w
        .daemon
        .mcp
        .handle(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            None,
            None,
            None
        )
        .await
        .is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_every_tool_that_spends_capability_checks_for_a_session() {
    let w = World::seeded(json!({})).await;
    for tool in [
        "vault_list_creds",
        "vault_get_placeholder",
        "vault_http",
        "vault_describe_access",
        "vault_preflight",
        "vault_approval_status",
    ] {
        let r = call(
            &w,
            tool,
            json!({"cred": "demo", "method": "GET", "path": "/user", "reason": "r"}),
            false,
        )
        .await;
        assert_eq!(r["isError"], true, "{tool}");
        assert_eq!(
            text_of(&r)["error"],
            "this tool needs a live session",
            "{tool}"
        );
    }
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_http_runs_the_pipeline_sends_the_token_and_burns_its_placeholder() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| {
        Ok(json_response(
            200,
            &json!({"echo": SECRET, "ordinary": "ok"}),
        ))
    }));
    let r = text_of(
        &call(
            &w,
            "vault_http",
            json!({"cred": "demo", "method": "GET", "path": "/user", "reason": "look"}),
            true,
        )
        .await,
    );
    assert_eq!(r["status"], 200, "{r}");
    assert_eq!(r["decision"], "allow");
    let body = r["body"].as_str().unwrap();
    assert!(!leaks(body), "{body}");
    assert_eq!(
        w.up.last_auth().as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );
    let live = w
        .shared
        .run({
            let sid = w.session_id.clone();
            move |c| {
                c.vault
                    .list_placeholders(Some(&sid))
                    .unwrap()
                    .into_iter()
                    .filter(|p| p.state == av_store::model::PlaceholderState::Active)
                    .count()
            }
        })
        .await
        .unwrap();
    assert_eq!(live, 1, "only the session's own placeholder is left live");
}

#[tokio::test(flavor = "multi_thread")]
async fn explain_denial_answers_only_about_the_callers_own_requests() {
    let w = World::seeded(json!({})).await;
    let r = text_of(
        &call(
            &w,
            "vault_http",
            json!({"cred": "demo", "method": "DELETE", "path": "/x", "reason": "r"}),
            true,
        )
        .await,
    );
    let rid = r["request_id"].as_str().unwrap().to_string();
    let mine = text_of(&call(&w, "vault_explain_denial", json!({"request_id": rid}), true).await);
    assert_eq!(mine["decision"], "deny");
    assert_eq!(mine["rule"], "methods");
    assert!(mine["detail"].as_str().is_some());
    let theirs = text_of(
        &call(
            &w,
            "vault_explain_denial",
            json!({"request_id": rid}),
            false,
        )
        .await,
    );
    assert!(
        theirs["error"]
            .as_str()
            .unwrap()
            .starts_with("no record of request"),
        "{theirs}"
    );
}

/// integrate3-r5.test.js:140-147: past DENIAL_TTL_MS the sentence is
/// forgotten, but vault_explain_denial still answers with the code and rule.
#[tokio::test(flavor = "multi_thread")]
async fn explain_denial_keeps_code_and_rule_after_the_sentence_ages_out() {
    let w = World::seeded(json!({})).await;
    let r = text_of(
        &call(
            &w,
            "vault_http",
            json!({"cred": "demo", "method": "DELETE", "path": "/x", "reason": "r"}),
            true,
        )
        .await,
    );
    let rid = r["request_id"].as_str().unwrap().to_string();
    let fresh = text_of(&call(&w, "vault_explain_denial", json!({"request_id": rid}), true).await);
    assert_eq!(fresh["code"], "AV_POLICY_DENIED", "{fresh}");
    assert!(fresh["detail"].as_str().is_some(), "{fresh}");
    w.shared
        .run(|core| core.pl_age_denials(crate::pipeline::DENIAL_TTL_MS as i64 + 1))
        .await
        .unwrap();
    let late = text_of(&call(&w, "vault_explain_denial", json!({"request_id": rid}), true).await);
    assert_eq!(late["code"], "AV_POLICY_DENIED", "{late}");
    assert_eq!(late["rule"], fresh["rule"], "{late}");
    assert_eq!(late["rule"], "methods", "{late}");
    assert!(
        late.get("detail").is_some(),
        "detail is present, as null: {late}"
    );
    assert_eq!(late["detail"], Value::Null, "{late}");
}

#[tokio::test(flavor = "multi_thread")]
async fn request_session_is_the_proposer_and_polls_with_the_secret_only() {
    let w = World::seeded(json!({})).await;
    let r = text_of(
        &call(
            &w,
            "vault_request_session",
            json!({"cred": "demo", "reason": "need", "approval": "auto"}),
            false,
        )
        .await,
    );
    assert_eq!(r["code"], "AV_POLICY_DENIED");
    assert_eq!(r["rule"], "owner_only_field");
    let r = text_of(
        &call(
            &w,
            "vault_request_session",
            json!({"cred": "demo", "reason": "need", "methods": ["GET"]}),
            false,
        )
        .await,
    );
    assert_eq!(r["state"], "pending", "{r}");
    let id = r["request_id"].as_str().unwrap().to_string();
    let secret = r["poll_secret"].as_str().unwrap().to_string();
    let p = text_of(
        &call(
            &w,
            "vault_request_session",
            json!({"poll_id": id, "poll_secret": "nope", "reason": "x"}),
            false,
        )
        .await,
    );
    assert!(p["error"]
        .as_str()
        .unwrap()
        .contains("poll_secret does not match"));
    let p = text_of(
        &call(
            &w,
            "vault_request_session",
            json!({"poll_id": id, "poll_secret": secret, "reason": "x"}),
            false,
        )
        .await,
    );
    assert_eq!(p["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn describe_access_and_preflight_report_without_spending() {
    let w = World::seeded(json!({"budget": 7})).await;
    let d = text_of(&call(&w, "vault_describe_access", json!({}), true).await);
    assert_eq!(d["grants"][0]["budget_remaining"], 7, "{d}");
    assert!(
        !crate::util::js_stringify(&d).contains(&w.placeholder),
        "never a placeholder"
    );
    let p = text_of(
        &call(
            &w,
            "vault_preflight",
            json!({"cred": "demo", "method": "GET", "path": "/user"}),
            true,
        )
        .await,
    );
    assert_eq!(p["would"], "allow", "{p}");
    let p = text_of(
        &call(
            &w,
            "vault_preflight",
            json!({"cred": "demo", "method": "G E T", "path": "/user"}),
            true,
        )
        .await,
    );
    assert_eq!(p["rule"], "preflight_shape");
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_anonymous_transport_sessions_are_bounded_and_unrecorded() {
    let w = World::bare().await;
    let mut first = String::new();
    for i in 0..(crate::mcp::MAX_MCP_SESSIONS + 5) {
        let sid = w.daemon.mcp.open_session(false).await;
        if i == 0 {
            first = sid;
        }
    }
    assert!(!w.daemon.mcp.has_session(&first), "the oldest is evicted");
    assert!(!w.daemon.mcp.close_session(&first, false).await);
    assert!(!w.audit_text().await.contains("mcp.session_opened"));
}

#[tokio::test(flavor = "multi_thread")]
async fn get_placeholder_records_the_reason_cleaned_and_never_the_secret() {
    let w = World::seeded(json!({})).await;
    let r = text_of(
        &call(
            &w,
            "vault_get_placeholder",
            json!({"cred": "demo", "reason": format!("paste {SECRET}")}),
            true,
        )
        .await,
    );
    assert!(
        r["placeholder"].as_str().unwrap().starts_with("av1."),
        "{r}"
    );
    let audit = w.audit_text().await;
    assert!(audit.contains("placeholder.issued_via_mcp"));
    assert!(!leaks(&audit), "{audit}");
}
