use av_core::{model_usage::*, payload::*, policy::Checked, request_view::*};
use serde_json::{json, Value as V};
#[test]
fn js_payload_and_model_reference_vectors() {
    let cases: V =
        serde_json::from_str(include_str!("fixtures/payload-model-vectors.json")).unwrap();
    for (i, c) in cases.as_array().unwrap().iter().enumerate() {
        let a = c["args"].as_array().unwrap();
        let s = |i: usize| a[i].as_str().unwrap();
        let result: Result<V, av_core::VaultError> = match c["fn"].as_str().unwrap() {
            "parseStrictJson" => parse_strict_json(s(0)),
            "scanGraphQL" => {
                scan_graphql(s(0), &serde_json::from_value(a[1].clone()).unwrap()).map(|_| V::Null)
            }
            "evaluatePayload" => {
                let input = &a[1];
                let view = request_view(&RequestInput {
                    query: input["query"].as_str(),
                    method: input["method"].as_str(),
                    content_type: input["contentType"].as_str(),
                    body: input["body"].as_str().map(str::as_bytes),
                    ..Default::default()
                });
                let sets: Checked<Vec<PayloadRuleSet>> =
                    serde_json::from_value(a[0].clone()).unwrap();
                evaluate_payload(
                    Some(&sets),
                    &PayloadInput {
                        view: &view,
                        path: input["path"].as_str().unwrap_or(""),
                    },
                )
                .map(|_| V::Null)
            }
            "meterRequest" => {
                let input = &a[1];
                meter_request(
                    s(0),
                    &MeterInput {
                        method: input["method"].as_str(),
                        path: input["path"].as_str(),
                        content_type: input["contentType"].as_str(),
                        body: input["body"].as_str().map(str::as_bytes),
                    },
                )
                .map(|m| json!(m))
            }
            "priceOf" => Ok(json!(price_of(s(0), a[1].as_str()))),
            "usageFromBody" => Ok(json!(usage_from_body(s(0), &a[1]))),
            "reservationFor" => reservation_for(
                s(0),
                &serde_json::from_value(a[1].clone()).unwrap(),
                ReservationOptions {
                    usd: a[2]["usd"].as_bool().unwrap(),
                },
            )
            .map(|m| json!(m)),
            "chargeFor" => {
                let usage: Option<Usage> = serde_json::from_value(a[3].clone()).unwrap();
                charge_for(
                    s(0),
                    &serde_json::from_value(a[1].clone()).unwrap(),
                    &serde_json::from_value(a[2].clone()).unwrap(),
                    usage.as_ref(),
                )
                .map(|m| json!(m))
            }
            "usageFromEvent" => {
                let event = if let Some(s) = a[1].as_str() {
                    SseEventData::Raw(s.as_bytes())
                } else {
                    SseEventData::Parsed(&a[1])
                };
                Ok(json!(usage_from_event(
                    s(0),
                    event,
                    serde_json::from_value(a[2].clone()).unwrap()
                )))
            }
            x => panic!("unknown {x}"),
        };
        if c["ok"] == true {
            assert_eq!(
                result.unwrap_or_else(|e| panic!("case {i}: {c}: {e}")),
                c["result"],
                "case {i}: {c}"
            );
        } else {
            assert_eq!(
                result.unwrap_err().to_problem(),
                c["error"],
                "case {i}: {c}"
            );
        }
    }
}
