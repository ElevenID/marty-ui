//! Closed opt-in Envoy delta. This is configuration generation, not release
//! attestation or runtime qualification. The canonical legacy owner stays intact.
use serde_json::{json, Value};
use std::io::{self, Write};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const SERVICE: &str = "marty.ui.issuance.v1.IssuanceService";
pub const RPC_PATH: &str = "/marty.ui.issuance.v1.IssuanceService/InitiateIssuance";
pub const HTTP_PATH: &str = "/v1/issuance/initiate";
pub const NATIVE_CLUSTER: &str = "issuance_native_grpc";
pub const DESCRIPTOR: &[u8] = include_bytes!("../../../../config/envoy/proto_descriptor.pb");
const RPC_PREFIX: &str = "/marty.ui.issuance.v1.IssuanceService/";
const HTTP_PREFIX: &str = "/v1/issuance/";
const HCM: &str = "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config";
const ROUTES: &str = "/route_config/virtual_hosts/0/routes";
const PROTOCOL: &str = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions";

fn require(ok: bool, detail: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(detail)
    }
}

/// Parsing rejects duplicate mappings before conversion into the JSON model.
/// Errors deliberately omit arbitrary configuration values and file paths.
pub fn parse(bytes: &[u8]) -> Result<Value, &'static str> {
    require(
        !bytes.is_empty() && bytes.len() <= MAX_CONFIG_BYTES,
        "Envoy configuration size is invalid",
    )?;
    let yaml: serde_yaml::Value =
        serde_yaml::from_slice(bytes).map_err(|_| "Envoy YAML is invalid")?;
    serde_json::to_value(yaml).map_err(|_| "Envoy configuration is not a JSON-compatible mapping")
}

pub fn render(bytes: &[u8], descriptor: &[u8]) -> Result<Value, &'static str> {
    // Bind to the descriptor shipped with this source/tooling, not any arbitrary
    // descriptor containing a similarly named method. Envoy itself validates it
    // in the required executable gate; this byte check is not semantic proof.
    require(
        descriptor == DESCRIPTOR,
        "Envoy descriptor differs from this renderer's source",
    )?;
    let mut model = parse(bytes)?;
    let listeners = model
        .pointer("/static_resources/listeners")
        .and_then(Value::as_array)
        .ok_or("Envoy listeners are missing")?;
    require(
        listeners.len() == 1 && listeners[0]["name"] == "grpc_listener",
        "Envoy listener topology changed",
    )?;
    require(
        listeners[0]["filter_chains"]
            .as_array()
            .is_some_and(|v| v.len() == 1)
            && listeners[0]["filter_chains"][0]["filters"]
                .as_array()
                .is_some_and(|v| v.len() == 1),
        "Envoy listener filter topology changed",
    )?;
    let hcm = model
        .pointer(HCM)
        .ok_or("Envoy connection manager is missing")?;
    require(hcm["@type"] == "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", "Envoy connection manager type changed")?;
    require(
        hcm["route_config"]["virtual_hosts"]
            .as_array()
            .is_some_and(|v| v.len() == 1),
        "Envoy virtual host topology changed",
    )?;
    let filters = hcm["http_filters"]
        .as_array()
        .ok_or("Envoy HTTP filters are missing")?;
    let transcoders: Vec<_> = filters
        .iter()
        .filter(|v| v["name"] == "envoy.filters.http.grpc_json_transcoder")
        .collect();
    require(
        transcoders.len() == 1,
        "Envoy transcoder ownership is ambiguous",
    )?;
    let transcoder = &transcoders[0]["typed_config"];
    require(
        transcoder["match_incoming_request_route"] == true
            && transcoder["proto_descriptor"] == "/etc/envoy/proto_descriptor.pb"
            && transcoder["services"]
                .as_array()
                .is_some_and(|v| v.iter().filter(|s| **s == SERVICE).count() == 1),
        "Envoy issuance transcoder contract changed",
    )?;
    let clusters = model
        .pointer_mut("/static_resources/clusters")
        .and_then(Value::as_array_mut)
        .ok_or("Envoy clusters are missing")?;
    require(
        !clusters.iter().any(|v| v["name"] == NATIVE_CLUSTER),
        "Envoy native cluster already exists",
    )?;
    let legacy: Vec<_> = clusters
        .iter()
        .filter(|v| v["name"] == "issuance_grpc")
        .collect();
    require(
        legacy.len() == 1,
        "Envoy legacy issuance cluster is ambiguous",
    )?;
    let mut native = legacy[0].clone();
    require(
        native["typed_extension_protocol_options"][PROTOCOL]["explicit_http_config"]
            ["http2_protocol_options"]
            == json!({}),
        "Envoy issuance requires explicit HTTP2",
    )?;
    require(
        native["load_assignment"]
            == json!({"cluster_name":"issuance_grpc","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"issuance","port_value":9005}}}}]}]}),
        "Envoy legacy issuance endpoint changed",
    )?;
    require(
        native["health_checks"]
            .as_array()
            .is_some_and(|v| v.len() == 1 && v[0]["grpc_health_check"]["service_name"] == SERVICE),
        "Envoy issuance health contract changed",
    )?;
    native["name"] = json!(NATIVE_CLUSTER);
    native["load_assignment"]["cluster_name"] = json!(NATIVE_CLUSTER);
    native["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
        ["socket_address"]["address"] = json!("issuance-native");
    clusters.push(native);
    let routes = model
        .pointer_mut(&format!("{HCM}{ROUTES}"))
        .and_then(Value::as_array_mut)
        .ok_or("Envoy routes are missing")?;
    require(
        !routes.iter().any(|r| {
            r["route"]["cluster"] == NATIVE_CLUSTER
                || [RPC_PATH, HTTP_PATH]
                    .iter()
                    .any(|p| r["match"]["path"] == *p)
        }),
        "Envoy native route already exists",
    )?;
    for (prefix, path) in [(RPC_PREFIX, RPC_PATH), (HTTP_PREFIX, HTTP_PATH)] {
        let matches: Vec<_> = routes
            .iter()
            .enumerate()
            .filter(|(_, r)| r["match"]["prefix"] == prefix)
            .map(|(i, _)| i)
            .collect();
        require(
            matches.len() == 1,
            "Envoy legacy issuance prefix is ambiguous",
        )?;
        let index = matches[0];
        require(
            routes[index]
                == json!({"match":{"prefix":prefix},"route":{"cluster":"issuance_grpc","timeout":"60s"}}),
            "Envoy legacy issuance route changed",
        )?;
        for previous in &routes[..index] {
            // A new matcher could shadow the selected operation. Fail closed
            // rather than try to duplicate Envoy's complete matching engine.
            let matcher = previous["match"]
                .as_object()
                .ok_or("Envoy preceding route matcher is invalid")?;
            require(
                matcher
                    .get("case_sensitive")
                    .is_none_or(|value| *value == true),
                "Envoy preceding case-insensitive matcher requires review",
            )?;
            let unrelated = if let Some(other) = matcher.get("prefix").and_then(Value::as_str) {
                !path.starts_with(other)
            } else if let Some(other) = matcher.get("path").and_then(Value::as_str) {
                path != other
            } else {
                false
            };
            require(unrelated, "Envoy selected operation may be shadowed")?;
        }
        routes.insert(index, json!({"match":{"path":path,"headers":[{"name":":method","string_match":{"exact":"POST"}}]},"route":{"cluster":NATIVE_CLUSTER,"timeout":"60s"}}));
    }
    Ok(model)
}

/// Emit bounded JSON-compatible YAML. Use the JSON serializer itself so
/// feature-unified arbitrary-precision numbers remain scalar numbers, never
/// serde_json's private cross-serializer representation.
pub fn encode(model: &Value) -> Result<String, &'static str> {
    struct BoundedOutput(Vec<u8>);
    impl Write for BoundedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_CONFIG_BYTES.saturating_sub(self.0.len()) {
                return Err(io::Error::other("Envoy encoded output exceeds size limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = BoundedOutput(Vec::new());
    serde_json::to_writer(&mut output, model)
        .map_err(|_| "Cannot encode bounded Envoy configuration")?;
    String::from_utf8(output.0).map_err(|_| "Cannot encode Envoy configuration")
}
