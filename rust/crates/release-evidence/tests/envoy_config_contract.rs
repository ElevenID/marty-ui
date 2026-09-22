use marty_release_evidence::envoy_config::{
    encode, parse, render, DESCRIPTOR, HTTP_PATH, NATIVE_CLUSTER, RPC_PATH,
};
use serde_json::{json, Value};

const BASE: &[u8] = include_bytes!("../../../../config/envoy/envoy.yaml");
const ROUTES: &str = "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config/route_config/virtual_hosts/0/routes";

fn mutated(change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut model = parse(BASE).unwrap();
    change(&mut model);
    encode(&model).unwrap().into_bytes()
}

#[test]
fn complete_native_model_is_validated_without_rewriting() {
    let original = parse(BASE).unwrap();
    assert_eq!(render(BASE, DESCRIPTOR).unwrap(), original);
}

#[test]
fn historical_legacy_model_upgrades_both_complete_prefixes() {
    let input = mutated(|model| {
        let clusters = model["static_resources"]["clusters"]
            .as_array_mut()
            .unwrap();
        let native = clusters
            .iter_mut()
            .find(|cluster| cluster["name"] == NATIVE_CLUSTER)
            .unwrap();
        native["name"] = json!("issuance_grpc");
        native["load_assignment"]["cluster_name"] = json!("issuance_grpc");
        native["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
            ["socket_address"]["address"] = json!("issuance");
        for route in model.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap() {
            if route["route"]["cluster"] == NATIVE_CLUSTER {
                route["route"]["cluster"] = json!("issuance_grpc");
            }
        }
    });

    let upgraded = render(&input, DESCRIPTOR).unwrap();
    let routes = upgraded.pointer(ROUTES).unwrap().as_array().unwrap();
    for prefix in ["/marty.ui.issuance.v1.IssuanceService/", "/v1/issuance/"] {
        let selected: Vec<_> = routes
            .iter()
            .filter(|route| route["match"]["prefix"] == prefix)
            .collect();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0]["route"]["cluster"], NATIVE_CLUSTER);
    }
    assert!(routes.iter().all(|route| {
        route["match"]["path"] != RPC_PATH && route["match"]["path"] != HTTP_PATH
    }));
}

#[test]
fn selected_model_roundtrips_and_unrelated_values_are_preserved() {
    let input =
        mutated(|m| m["admin"]["access_log_path"] = json!("/tmp/synthetic-admin-access.log"));
    let value = render(&input, DESCRIPTOR).unwrap();
    assert_eq!(
        value["admin"]["access_log_path"],
        "/tmp/synthetic-admin-access.log"
    );
    assert_eq!(parse(encode(&value).unwrap().as_bytes()).unwrap(), value);
    assert_eq!(
        render(encode(&value).unwrap().as_bytes(), DESCRIPTOR).unwrap(),
        value,
        "Native validation must be idempotent"
    );
}

#[test]
fn descriptor_and_ambiguous_or_incompatible_topology_fail_closed() {
    assert!(render(BASE, &[]).is_err());
    let mut corrupted = DESCRIPTOR.to_vec();
    corrupted[0] ^= 1;
    assert!(render(BASE, &corrupted).is_err());
    for kind in 0..11 {
        let input = mutated(|m| match kind {
            0 => {
                m["static_resources"]["listeners"][0]["name"] = json!("other");
            }
            1 => {
                m["static_resources"]["clusters"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name":NATIVE_CLUSTER}));
            }
            2 => {
                let c = m["static_resources"]["clusters"].as_array_mut().unwrap();
                c.retain(|v| v["name"] != NATIVE_CLUSTER);
            }
            3 => {
                let c = m["static_resources"]["clusters"].as_array_mut().unwrap();
                let owned = c.iter_mut().find(|v| v["name"] == NATIVE_CLUSTER).unwrap();
                owned["typed_extension_protocol_options"] = json!({});
            }
            4 => {
                let r = m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap();
                let owned = r
                    .iter()
                    .find(|v| v["match"]["prefix"] == "/v1/issuance/")
                    .unwrap()
                    .clone();
                r.push(owned);
            }
            5 => {
                m.pointer_mut(ROUTES)
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .insert(
                        0,
                        json!({"match":{"prefix":"/"},"route":{"cluster":NATIVE_CLUSTER}}),
                    );
            }
            6 => {
                m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap().insert(0,json!({"match":{"safe_regex":{"regex":".*"}},"route":{"cluster":NATIVE_CLUSTER}}));
            }
            7 => {
                m.pointer_mut(ROUTES)
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .insert(
                        0,
                        json!({"match":{"path":HTTP_PATH},"route":{"cluster":NATIVE_CLUSTER}}),
                    );
            }
            8 => {
                let r = m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap();
                let owned = r
                    .iter_mut()
                    .find(|v| v["match"]["prefix"] == "/v1/issuance/")
                    .unwrap();
                owned["route"]["cluster"] = json!("auth_grpc");
            }
            9 => {
                m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap().insert(0,json!({"match":{"prefix":"/V1/ISSUANCE/","case_sensitive":false},"route":{"cluster":NATIVE_CLUSTER}}));
            }
            10 => {
                m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap().insert(0,json!({"match":{"path":"/V1/ISSUANCE/INITIATE","case_sensitive":false},"route":{"cluster":NATIVE_CLUSTER}}));
            }
            _ => unreachable!(),
        });
        assert!(
            render(&input, DESCRIPTOR).is_err(),
            "negative topology {kind}"
        );
    }
}

#[test]
fn duplicate_mappings_and_oversized_input_are_rejected_without_values_in_errors() {
    assert!(parse(b"secret: synthetic-one\nsecret: synthetic-two\n").is_err());
    let error = parse(&vec![b' '; 1024 * 1024 + 1]).unwrap_err();
    assert_eq!(error, "Envoy configuration size is invalid");
    assert!(encode(&json!({"value":"x".repeat(1024*1024)})).is_err());
    let alias = format!(
        "first: &repeated {}\nrest: [{}]\n",
        "x".repeat(4096),
        vec!["*repeated"; 300].join(",")
    );
    assert!(alias.len() < 1024 * 1024);
    let expanded = parse(alias.as_bytes()).unwrap();
    assert!(
        encode(&expanded).is_err(),
        "Compact YAML aliases cannot bypass encoded output size bound"
    );
}
