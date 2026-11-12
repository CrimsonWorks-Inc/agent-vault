//! Tests for the src/daemon/mcp.js entries of mutations.toml. Each names
//! the protection (the `what` of test/mutation-check.js) it holds.

use serde_json::{json, Value};

use super::*;
use crate::pipeline::ListenerInfo;

async fn call_on(
    w: &World,
    name: &str,
    args: Value,
    token: Option<&str>,
    listener: Option<ListenerInfo>,
) -> Value {
    let s = match token {
        Some(t) => {
            let t = t.to_string();
            w.shared
                .run(move |c| c.vault.session_by_token(&t).unwrap())
                .await
                .unwrap()
        }
        None => None,
    };
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
    let r = w
        .daemon
        .mcp
        .handle(msg, s, token.map(str::to_string), listener)
        .await
        .unwrap();
    let t = r["result"]["content"][0]["text"].as_str().unwrap_or("null");
    serde_json::from_str(t).unwrap_or(Value::Null)
}

fn remote() -> Option<ListenerInfo> {
    Some(ListenerInfo {
        id: "ls_test".into(),
        kind: "tls".into(),
        remote: true,
        advertise: vec![],
    })
}

/// 'vault_http does not hand its listener to the pipeline', 'vault_describe
/// access checks the session without its listener (C18)' and
/// 'vault_preflight does not hand its listener to the pipeline (C18)': an
/// unlimited session is refused on a network listener by every tool.
#[tokio::test(flavor = "multi_thread")]
async fn every_tool_asks_about_the_listener_the_call_arrived_on() {
    let w = World::seeded(json!({})).await;
    let pass = "test-passphrase-123";
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": pass}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "demo", "label": "forever", "methods": ["GET"], "infinite": true, "presence": {"passphrase": pass}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let tok = v["token"].as_str().unwrap().to_string();
    let args = json!({"cred": "demo", "method": "GET", "path": "/user"});
    for tool in ["vault_http", "vault_describe_access", "vault_preflight"] {
        let local = call_on(&w, tool, args.clone(), Some(&tok), None).await;
        assert!(
            !local.to_string().contains("infinite_remote"),
            "{tool} on loopback: {local}"
        );
        let far = call_on(&w, tool, args.clone(), Some(&tok), remote()).await;
        assert!(
            far.to_string().contains("infinite_remote"),
            "{tool} on a network listener: {far}"
        );
    }
}

/// 'every MCP transport close is audited, anonymous ones included'.
#[tokio::test(flavor = "multi_thread")]
async fn an_anonymous_transport_close_is_not_recorded() {
    let w = World::bare().await;
    let sid = w.daemon.mcp.open_session(false).await;
    assert!(w.daemon.mcp.close_session(&sid, false).await);
    assert!(!w.audit_text().await.contains("mcp.session_closed"));
    let sid = w.daemon.mcp.open_session(true).await;
    assert!(w.daemon.mcp.close_session(&sid, false).await);
    assert!(w.audit_text().await.contains("mcp.session_closed"));
}

/// 'vault_request_session drops an owner field instead of refusing it (R3)'.
#[tokio::test(flavor = "multi_thread")]
async fn request_session_refuses_an_owner_field() {
    let w = World::seeded(json!({})).await;
    for f in [json!({"approval": "auto"}), json!({"infinite": true})] {
        let mut args = json!({"cred": "demo", "reason": "r"});
        for (k, v) in f.as_object().unwrap() {
            args[k] = v.clone();
        }
        let r = call_on(&w, "vault_request_session", args, None, None).await;
        assert_eq!(r["rule"], "owner_only_field", "{r}");
    }
}

/// 'r6 F2 (Grok): explain-denial looks only at the last 200 audit rows'.
#[tokio::test(flavor = "multi_thread")]
async fn explain_denial_finds_a_denial_however_much_came_after_it() {
    let w = World::seeded(json!({})).await;
    let tok = w.token.clone();
    let r = call_on(
        &w,
        "vault_http",
        json!({"cred": "demo", "method": "DELETE", "path": "/x"}),
        Some(&tok),
        None,
    )
    .await;
    let rid = r["request_id"].as_str().unwrap().to_string();
    for _ in 0..220 {
        w.send("DELETE", "/y", vec![], None).await;
    }
    assert!(w.audit().await.len() > 220);
    let e = call_on(
        &w,
        "vault_explain_denial",
        json!({"request_id": rid}),
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(e["decision"], "deny", "{e}");
    assert_eq!(e["rule"], "methods", "{e}");
}

/// 'r6 F2 (Grok): a caller with no session gets the sentence of any
/// no-session denial'.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_with_no_session_gets_no_sentence() {
    let w = World::seeded(json!({})).await;
    let r = w
        .daemon
        .pipeline
        .handle(crate::pipeline::GatewayRequest {
            method: "GET".into(),
            path: "/p/demo/user".into(),
            query: String::new(),
            headers: vec![("host".into(), "127.0.0.1".into())],
            body: None,
            listener: None,
        })
        .await;
    assert_eq!(r.status, 401);
    let rid = r.request_id.clone().expect("a request id");
    let e = call_on(&w, "vault_explain_denial", json!({"request_id": rid}), None, None).await;
    assert_eq!(e["detail"], Value::Null, "{e}");
}
