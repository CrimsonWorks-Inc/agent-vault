use av_core::policy::*;
use serde_json::{json, Value as V};
fn p(v: &V) -> Policy {
    serde_json::from_value(v.clone()).unwrap()
}
fn serial(v: impl serde::Serialize) -> V {
    serde_json::to_value(v).unwrap()
}
#[test]
fn js_policy_reference_vectors() {
    let cases: V = serde_json::from_str(include_str!("fixtures/policy-vectors.json")).unwrap();
    for (i, c) in cases.as_array().unwrap().iter().enumerate() {
        let a = c["args"].as_array().unwrap();
        let s = |i: usize| a[i].as_str().unwrap();
        let result: Result<V, av_core::VaultError> = match c["fn"].as_str().unwrap() {
            "validate" => Ok(serial(validate_json(&a[0], &Default::default()))),
            "intersect" => {
                let layers: Vec<_> = a[0].as_array().unwrap().iter().map(p).collect();
                Ok(serial(intersect(
                    &layers.iter().map(Some).collect::<Vec<_>>(),
                )))
            }
            "normalizeHost" => normalize_host(s(0)).map(V::from),
            "normalizePath" => normalize_path(s(0)).map(V::from),
            "matchPath" => Ok(json!(match_path(s(0), s(1)))),
            "matchHost" => Ok(json!(match_host(s(0), s(1)))),
            "confineHosts" => {
                let requested: Option<Vec<String>> = serde_json::from_value(a[0].clone()).unwrap();
                let ceiling: Vec<String> = serde_json::from_value(a[1].clone()).unwrap();
                confine_hosts(requested.as_deref(), &ceiling).map(serial)
            }
            "evaluateHttp" => evaluate_http(
                &p(&a[0]),
                &HttpTarget {
                    method: a[1]["method"].as_str(),
                    path: a[1]["path"].as_str().unwrap_or(""),
                    host: a[1]["host"].as_str().unwrap_or(""),
                },
            )
            .map(serial),
            "needsApproval" => Ok(json!(needs_approval(
                &p(&a[0]),
                &ApprovalQuery {
                    method: a[1]["method"].as_str(),
                    first_use: a[1]["firstUse"].as_bool().unwrap_or(false)
                }
            ))),
            "budgetInteger" => Ok(json!(budget_integer(&a[0]))),
            "budgetLimit" => {
                let b: Checked<Budget> = serde_json::from_value(a[0].clone()).unwrap();
                Ok(match budget_limit(Some(&b)) {
                    BudgetLimit::Unlimited | BudgetLimit::Unreadable => V::Null,
                    BudgetLimit::Limit(n) => n.into(),
                })
            }
            "lint" => Ok(serial(lint_json(&a[0], &Default::default()))),
            "grantPolicyFromInput" => grant_policy_from_input(
                &a[0],
                &GrantPolicyOptions {
                    ceiling: GrantCeiling::Hosts(vec!["api.example.test".into()]),
                    defaults: a[1]["defaults"].as_bool().unwrap(),
                    profile: None,
                },
            )
            .map(serial),
            x => panic!("unknown {x}"),
        };
        if c["ok"] == true {
            let mut actual = result.unwrap_or_else(|e| panic!("case {i} {c}: {e}"));
            if c["fn"] == "intersect" {
                // JS undefined keys disappear, null list fields remain.
                for key in ["hosts", "methods", "paths", "databases", "rcpt", "commands"] {
                    if actual.get(key).is_none() {
                        actual[key] = V::Null;
                    }
                }
            }
            assert_eq!(actual, c["result"], "case {i}: {c}");
        } else {
            assert_eq!(
                result.unwrap_err().to_problem(),
                c["error"],
                "case {i}: {c}"
            );
        }
    }
}
#[test]
fn host_ceiling_and_wire_path() {
    assert_eq!(
        credential_host_ceiling(Some("127.0.0.1:9931"), &[]),
        vec!["127.0.0.1"]
    );
    assert_eq!(host_only("[::1]:8443"), "[::1]");
    assert_eq!(host_only("API.Example.com."), "api.example.com");
    assert_eq!(
        encode_path_for_wire("/v1beta/models/gemini-pro:generateContent"),
        "/v1beta/models/gemini-pro:generateContent"
    );
    assert_eq!(encode_path_segment("é ?#%"), "%C3%A9%20%3F%23%25");
}
use proptest::prelude::*;
proptest! {
    #[test]
    fn randomized_intersections_only_narrow(a in 1u64..1025,b in 1u64..1025,ta in 0u64..100000,tb in 0u64..100000) {
        let a=p(&json!({"max_concurrent":a,"budget":{"limit":ta},"spend":{"tokens":ta},"hosts":["*.example.test"],"paths":["/repos/**/pulls"]}));
        let b=p(&json!({"max_concurrent":b,"budget":{"limit":tb},"spend":{"tokens":tb},"hosts":["api.example.test"],"paths":["/repos/anything-at-all"]}));
        let c=intersect(&[Some(&a),Some(&b)]);prop_assert!(validate(&c,&Default::default()).is_empty());
        prop_assert_eq!(c.max_concurrent.clone(),Some(Checked::Valid(match (a.max_concurrent,b.max_concurrent){(Some(Checked::Valid(a)),Some(Checked::Valid(b)))=>a.min(b),_=>unreachable!()})));
        prop_assert_eq!(budget_limit(c.budget.as_ref()),BudgetLimit::Limit(ta.min(tb)));prop_assert_eq!(c.paths.clone(),Some(Checked::Valid(vec![])));
        prop_assert_eq!(c.clone(),intersect(&[Some(&c)]));
    }
}
#[test]
fn hardening_path_shapes_with_ordinary_control() {
    assert_eq!(
        normalize_path("/repos/o/r/hooks").unwrap(),
        "/repos/o/r/hooks"
    );
    for x in [
        "/repos/o/r/hooks\t",
        "/repos/o/r/hooks%00",
        "/a%252fb",
        "/a%255c",
        "/a%252520c",
        "/a%25u002e",
    ] {
        assert!(normalize_path(x).is_err(), "{x}");
    }
    let start = std::time::Instant::now();
    assert!(!match_path(
        &format!("{}missing", "/**".repeat(100)),
        &format!("{}/end", "/x".repeat(200))
    ));
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
}
