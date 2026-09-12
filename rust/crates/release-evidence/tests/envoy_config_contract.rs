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
fn complete_model_changes_only_two_routes_and_one_derived_cluster() {
    let original = parse(BASE).unwrap();
    let mut candidate = render(BASE, DESCRIPTOR).unwrap();
    let routes = candidate
        .pointer_mut(ROUTES)
        .unwrap()
        .as_array_mut()
        .unwrap();
    for (path, prefix) in [
        (RPC_PATH, "/marty.ui.issuance.v1.IssuanceService/"),
        (HTTP_PATH, "/v1/issuance/"),
    ] {
        let index = routes
            .iter()
            .position(|r| r["match"]["path"] == path)
            .unwrap();
        assert_eq!(
            routes[index],
            json!({"match":{"path":path,"headers":[{"name":":method","string_match":{"exact":"POST"}}]},"route":{"cluster":"issuance_native_grpc","timeout":"60s"}})
        );
        assert_eq!(routes[index + 1]["match"]["prefix"], prefix);
        routes.remove(index);
    }
    let clusters = candidate["static_resources"]["clusters"]
        .as_array_mut()
        .unwrap();
    let mut added = clusters.pop().unwrap();
    assert_eq!(added["name"], NATIVE_CLUSTER);
    assert_eq!(added["load_assignment"]["cluster_name"], NATIVE_CLUSTER);
    assert_eq!(
        added["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
            ["socket_address"]["address"],
        "issuance-native"
    );
    added["name"] = json!("issuance_grpc");
    added["load_assignment"]["cluster_name"] = json!("issuance_grpc");
    added["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
        ["socket_address"]["address"] = json!("issuance");
    assert_eq!(
        added,
        *clusters
            .iter()
            .find(|c| c["name"] == "issuance_grpc")
            .unwrap()
    );
    assert_eq!(candidate, original, "Every other route, filter, auth setting, cluster, health check and listener must be unchanged");
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
    assert!(
        render(encode(&value).unwrap().as_bytes(), DESCRIPTOR).is_err(),
        "Double activation must not duplicate selectors"
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
                c.retain(|v| v["name"] != "issuance_grpc");
            }
            3 => {
                let c = m["static_resources"]["clusters"].as_array_mut().unwrap();
                let owned = c.iter_mut().find(|v| v["name"] == "issuance_grpc").unwrap();
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
                        json!({"match":{"prefix":"/"},"route":{"cluster":"issuance_grpc"}}),
                    );
            }
            6 => {
                m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap().insert(0,json!({"match":{"safe_regex":{"regex":".*"}},"route":{"cluster":"issuance_grpc"}}));
            }
            7 => {
                m.pointer_mut(ROUTES)
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .insert(
                        0,
                        json!({"match":{"path":HTTP_PATH},"route":{"cluster":"issuance_grpc"}}),
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
                m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap().insert(0,json!({"match":{"prefix":"/V1/ISSUANCE/","case_sensitive":false},"route":{"cluster":"issuance_grpc"}}));
            }
            10 => {
                m.pointer_mut(ROUTES).unwrap().as_array_mut().unwrap().insert(0,json!({"match":{"path":"/V1/ISSUANCE/INITIATE","case_sensitive":false},"route":{"cluster":"issuance_grpc"}}));
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
