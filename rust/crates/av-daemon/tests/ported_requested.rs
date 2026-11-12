//! Requested integration policy tables through the public daemon helpers.
#![forbid(unsafe_code)]
use av_daemon::session_requests::{elevation_of, overrides_of, OWNER_FIELDS};
use serde_json::{json, Value};
#[test]
fn r1_elevation_names_only_auto_writes_and_infinite_with_ordinary_controls() {
    for (shape, want) in [
        (
            json!({"cred":"demo","approval":"auto","methods":["GET","POST"]}),
            vec!["approval_auto_writes"],
        ),
        (
            json!({"cred":"demo","approval":"auto","methods":["get","patch"]}),
            vec!["approval_auto_writes"],
        ),
        (
            json!({"grants":[{"cred":"a"},{"cred":"b","approval":"auto","methods":["POST"]}]}),
            vec!["approval_auto_writes"],
        ),
        (json!({"cred":"demo","infinite":true}), vec!["infinite"]),
        (
            json!({"cred":"demo","approval":"auto","methods":["POST"],"infinite":true}),
            vec!["infinite", "approval_auto_writes"],
        ),
        (
            json!({"cred":"demo","approval":"auto","routes":[{"methods":["DELETE"],"paths":["/x"]}]}),
            vec!["approval_auto_writes"],
        ),
        (json!({"cred":"demo"}), vec![]),
        (json!({"cred":"demo","approval":"auto"}), vec![]),
        (
            json!({"cred":"demo","approval":"auto","methods":["GET","HEAD","OPTIONS"]}),
            vec![],
        ),
        (
            json!({"cred":"demo","approval":"on-write","methods":["GET","POST","DELETE"]}),
            vec![],
        ),
        (
            json!({"cred":"demo","approval":"each","methods":["POST"]}),
            vec![],
        ),
        (json!({"cred":"demo","infinite":false}), vec![]),
    ] {
        assert_eq!(elevation_of(&shape), want, "{shape}");
    }
}
#[test]
fn r1_unreadable_specs_and_lists_elevate_independently_of_approval_mode() {
    for shape in [
        Value::Null,
        json!([]),
        json!("auto"),
        json!(7),
        json!({"cred":"demo","approval":"auto","methods":"POST"}),
        json!({"cred":"demo","approval":"auto","methods":[7]}),
        json!({"cred":"demo","approval":"auto","routes":"GET:/x"}),
        json!({"grants":"demo"}),
        json!({"grants":[null]}),
        json!({"cred":"demo","methods":"POST"}),
        json!({"cred":"demo","methods":7}),
        json!({"cred":"demo","approval":"on-write","methods":"POST"}),
        json!({"cred":"demo","approval":"each","methods":["GET",7]}),
        json!({"cred":"demo","routes":"POST /x"}),
        json!({"cred":"demo","approval":"each","routes":[{"methods":"DELETE","paths":["/x"]}]}),
        json!({"cred":"demo","routes":[null]}),
        json!({"grants":[{"cred":"a","methods":["GET"]},{"cred":"b","methods":"POST"}]}),
        json!({"grants":[{"cred":"a"},{"cred":"b","approval":"first-use","routes":"GET:/x"}],"infinite":false}),
    ] {
        assert_eq!(
            elevation_of(&shape),
            vec!["approval_auto_writes"],
            "{shape}"
        );
    }
    assert_eq!(
        elevation_of(&json!({"cred":"demo","methods":"POST","infinite":true})),
        vec!["infinite", "approval_auto_writes"]
    );
    for shape in [
        json!({"cred":"demo","methods":null,"routes":null}),
        json!({"cred":"demo","approval":"each","methods":["POST"],"routes":[{"methods":["DELETE"],"paths":["/x"]}]}),
        json!({"grants":[{"cred":"a","methods":["GET"]},{"cred":"b","approval":"on-write","methods":["POST"]}]}),
        json!({"cred":"demo","approval":"auto","routes":[{"methods":["GET"],"paths":["/x"]}]}),
        json!({"cred":"demo","approval":"yolo","methods":["POST"]}),
    ] {
        assert!(elevation_of(&shape).is_empty(), "{shape}");
    }
}
#[test]
fn r1_owner_options_share_parser_and_direct_request_store_never_accepts_them() {
    assert_eq!(OWNER_FIELDS, ["approval", "infinite"]);
    assert_eq!(
        overrides_of(&json!({"methods":["GET"],"approval":"auto","infinite":true,"junk":1})),
        json!({"methods":["GET"],"approval":"auto","infinite":true})
    );
    for (input, want) in [
        (
            json!({"approval":"auto","infinite":true}),
            json!({"approval":"auto","infinite":true}),
        ),
        (json!({"infinite":"true"}), json!({"infinite":true})),
        (json!({"infinite":"yes","approval":""}), json!({})),
    ] {
        let parsed = av_store::pending::parse_overrides(input.as_object().unwrap()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), want);
    }
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
    let mut core = av_daemon::state::Core::new(vault);
    for p in [
        json!({"cred":"demo","approval":"auto"}),
        json!({"cred":"demo","infinite":true}),
    ] {
        let e = core.sr_propose(p, Some("x".into()), false).unwrap_err();
        assert_eq!(e.code.as_str(), "AV_OWNER_ONLY");
        assert!(core.sr_pending().is_empty());
    }
    let (record, secret) = core
        .sr_propose(json!({"cred":"demo"}), Some("x".into()), false)
        .unwrap();
    assert_eq!(record.state, "pending");
    assert!(!secret.is_empty());
}
