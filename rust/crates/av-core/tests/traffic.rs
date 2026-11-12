use av_core::{detect::*, request_view::*, sites::*, substitute::*};
use serde_json::{json, Value as V};
fn fixture() -> V {
    serde_json::from_str(include_str!("fixtures/traffic-vectors.json")).unwrap()
}
fn request(v: &V) -> ProxyRequest {
    ProxyRequest {
        method: v["method"].as_str().unwrap_or("GET").into(),
        path: v["path"].as_str().unwrap_or("").into(),
        query: v["query"].as_str().unwrap_or("").into(),
        headers: serde_json::from_value(v["headers"].clone()).unwrap(),
        body: v["body"].as_str().map(|s| s.as_bytes().to_vec()),
    }
}
fn serial_req(r: &ProxyRequest) -> V {
    json!({"method":r.method,"path":r.path,"query":r.query,"headers":r.headers,"body":r.body.as_ref().map(|b|String::from_utf8_lossy(b).into_owned())})
}
#[test]
fn js_detector_vectors() {
    for c in fixture()["detect"].as_array().unwrap() {
        let hits = detect_all(c["text"].as_str().unwrap());
        let actual: Vec<_> = hits
            .iter()
            .map(|h| json!({"text":h.parsed.text,"encoding":h.encoding.as_str()}))
            .collect();
        assert_eq!(json!(actual), c["hits"], "{c}");
        assert_eq!(
            has_encoded_hit(&hits),
            hits.iter().any(|h| h.encoding != HitEncoding::Raw)
        );
    }
}
#[test]
fn js_substitution_vectors() {
    for c in fixture()["substitute"].as_array().unwrap() {
        let req = request(&c["req"]);
        let found = locate(&req);
        let actual: Vec<_> = found
            .occurrences
            .iter()
            .map(|o| {
                let mut loc = serde_json::to_value(&o.location).unwrap();
                if o.location.region == Region::Header
                    && !loc.as_object().unwrap().contains_key("scheme")
                {
                    loc["scheme"] = V::Null;
                }
                json!({"text":o.text,"location":loc})
            })
            .collect();
        assert_eq!(json!(actual), c["occurrences"], "{}", c["req"]);
        for a in c["applied"].as_array().unwrap() {
            let loc = serde_json::from_value(a["location"].clone()).unwrap();
            let out = apply(
                &req,
                &loc,
                fixture()["ph"].as_str().unwrap(),
                &"test-secret-FAKE/+é".to_owned().into(),
            )
            .unwrap();
            assert_eq!(serial_req(&out), a["out"], "{a}");
        }
        assert_eq!(serial_req(&req), c["req"]);
    }
}
#[test]
fn js_request_view_vectors() {
    for c in fixture()["views"].as_array().unwrap() {
        let r = request(&c["input"]);
        let v = request_view(&RequestInput {
            method: Some(&r.method),
            query: Some(&r.query),
            headers: &r.headers,
            body: r.body.as_deref(),
            content_type: None,
        });
        let params: Vec<_> = v
            .params
            .iter()
            .map(|p| json!({"rawName":p.raw_name,"name":p.name,"value":p.value}))
            .collect();
        let actual = json!({"method":v.method,"query":v.query,"params":params,"semicolon":v.semicolon,"unsendable":v.unsendable,"strayName":v.stray_name,"headers":v.headers,"body":v.body.map(|b|String::from_utf8_lossy(b).into_owned()),"contentType":v.content_type,"mediaType":v.media_type,"overrides":{"headers":v.overrides.headers,"fields":v.overrides.fields}});
        assert_eq!(actual, c["out"], "{c}");
    }
    for n in fixture()["names"].as_array().unwrap() {
        let s = n["name"].as_str().unwrap();
        assert_eq!(json!(folded_names(s)), n["folded"]);
        assert_eq!(json!(list_base(s)), n["base"]);
        assert_eq!(is_override_field(s), n["override"].as_bool().unwrap());
        assert_eq!(is_stray_key(s), n["strayKey"].as_bool().unwrap());
        assert_eq!(is_stray_name(s), n["strayName"].as_bool().unwrap());
    }
}
#[test]
fn encoded_locations_refuse_and_raw_controls_match() {
    let ph = fixture()["ph"].as_str().unwrap().to_owned();
    let req = ProxyRequest {
        headers: vec![("X-Api-Key".into(), ph)],
        ..Default::default()
    };
    let hit = locate(&req).occurrences.remove(0);
    let site = parse_site("header:x-api-key").unwrap();
    assert!(matches_site(&hit.location, &site));
    for encoding in [
        HitEncoding::Percent,
        HitEncoding::PercentDouble,
        HitEncoding::JsonEscape,
        HitEncoding::Base64,
    ] {
        let mut loc = hit.location.clone();
        loc.encoding = encoding;
        assert!(!matches_site(&loc, &site));
    }
    assert!(unsubstituted(&req, &[hit.parsed.nonce.clone()]).is_some());
    let out = apply(
        &req,
        &hit.location,
        &hit.text,
        &"test-secret-fake".to_owned().into(),
    )
    .unwrap();
    assert!(unsubstituted(&out, &[hit.parsed.nonce]).is_none());
}
use proptest::prelude::*;
proptest! {
 #[test]fn detector_encodings_at_every_alignment(pad in 0usize..20,width in 1usize..80){use base64::Engine;let p=fixture()["ph"].as_str().unwrap().to_owned();let encoded=base64::engine::general_purpose::STANDARD.encode(format!("{}{p}","x".repeat(pad)));let wrapped=encoded.as_bytes().chunks(width).map(|c|std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");prop_assert!(detect_all(&wrapped).iter().any(|h|h.parsed.text==p&&h.encoding==HitEncoding::Base64));}
}
#[test]
fn detector_pathological_input_linear_bound() {
    let s = format!("{}{}", "av1.".repeat(20000), "a".repeat(200000));
    let start = std::time::Instant::now();
    assert!(detect_all(&s).is_empty());
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
}
#[test]
fn substitution_sites_and_ordinary_controls() {
    let ph = fixture()["ph"].as_str().unwrap().to_owned();
    let site = parse_site("header:authorization:Bearer").unwrap();
    for scheme in ["bearer ", "BEARER   ", "Bearer\t"] {
        let req = ProxyRequest {
            headers: vec![("Authorization".into(), format!("{scheme}{ph}"))],
            ..Default::default()
        };
        let hit = locate(&req).occurrences.remove(0);
        assert!(matches_site(&hit.location, &site));
        assert!(describe_location(&hit.location).contains("authorization"));
    }
    let req = ProxyRequest {
        body: Some(vec![b' '; MAX_BUFFERED_BODY + 1]),
        ..Default::default()
    };
    assert!(locate(&req).unscannable.unwrap().contains("16 MiB"));
    let utf16: String = ph
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .map(char::from)
        .collect();
    assert!(detect_all(&utf16).is_empty());
    for (content_type, body) in [
        ("application/json", "{\"ordinary\":\"hello\"}"),
        ("text/plain", "ordinary prose"),
        ("application/x-www-form-urlencoded", "a=1&b=2"),
    ] {
        let req = ProxyRequest {
            headers: vec![("content-type".into(), content_type.into())],
            body: Some(body.as_bytes().to_vec()),
            ..Default::default()
        };
        assert!(locate(&req).occurrences.is_empty());
    }
    let req = ProxyRequest {
        path: format!("/p/{ph}"),
        ..Default::default()
    };
    let hit = locate(&req).occurrences.remove(0);
    for spec in [
        "header:authorization:Bearer",
        "basic:pass",
        "json:/auth/key",
        "query:key",
        "form:token",
    ] {
        assert!(!matches_site(&hit.location, &parse_site(spec).unwrap()));
    }
}
proptest! {
    #[test]
    fn detector_is_structural_superset_for_all_encodings(slug in "[a-z0-9-]{1,24}",field in "[a-z0-9]{1,16}",pad in 0usize..3){use base64::Engine;let key=av_core::secret::Key32::from_bytes([42;32]);let minted=av_core::placeholder::mint(&av_core::placeholder::MintInput{k_ph:&key,sid:"0123456789ab",slug:&slug,field:&field}).unwrap();let ph=&minted.text;let pct=ph.replace('.',"%2e");let twice=pct.replace('%',"%25");let unicode=ph.bytes().map(|b|format!("\\u{b:04x}")).collect::<String>();let blob=base64::engine::general_purpose::STANDARD.encode(format!("{}{ph}-suffix","x".repeat(pad)));for encoded in [ph.clone(),pct,twice,unicode,blob.clone(),blob.replace('+',"-").replace('/',"_")]{let hits=detect_all(&format!("before ! {encoded} ! after"));prop_assert!(hits.iter().any(|h|h.parsed.nonce==minted.nonce));}let req=ProxyRequest{headers:vec![("Authorization".into(),format!("Bearer {ph}"))],..Default::default()};prop_assert!(locate(&req).occurrences.iter().any(|o|o.parsed.nonce==minted.nonce));prop_assert!(detect_all(&(ph.to_owned()+"x")).is_empty());
    }
}
