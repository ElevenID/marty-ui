//! Shared expansion and iterative structural witness for the frozen depth cases.
use marty_issuance_service::lossless_json_tree::{JsonNode, JsonTree};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn scenarios() -> Value {
    let spec: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-json-depth-scenarios.json"
    ))
    .unwrap();
    assert_eq!(spec["schema"], "marty.canvas-json-depth-scenarios/v1");
    assert_eq!(spec["leaf_json"], "0");
    assert_eq!(spec["shapes"], json!(["array", "object"]));
    assert_eq!(spec["statuses"], json!([200, 403]));
    let mut validation = Vec::new();
    let mut provider = Vec::new();
    for shape in ["array", "object"] {
        let (open, close) = if shape == "array" {
            ("[", "]")
        } else {
            ("{\"nested\":", "}")
        };
        for depth in spec["depths"].as_array().unwrap() {
            let depth = usize::try_from(depth.as_u64().unwrap()).unwrap();
            assert!((1..=1600).contains(&depth));
            let bytes = format!("{}0{}", open.repeat(depth), close.repeat(depth));
            for status in [200, 403] {
                let common = json!({"name":format!("json_depth_{shape}_{depth}_{status}"),
                    "response_status":status,"response_content_type":"application/json; charset=latin1",
                    "response_hex":hex::encode(bytes.as_bytes())});
                let mut case = common.clone();
                case["provider"] = json!("badgr_api");
                case["direct"] = json!("synthetic-direct");
                validation.push(case);
                let mut case = common;
                case["provider"] = json!("bridge");
                case["action"] = json!("suspend");
                provider.push(case);
            }
        }
    }
    json!({"validation":validation,"provider":provider})
}

pub fn oracle() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-json-depth-oracle.json"
    ))
    .unwrap()
}

pub fn witness_bytes(bytes: &[u8]) -> Value {
    let tree = JsonTree::from_response_bytes(bytes).expect("actual scalar JSON response");
    witness(&tree)
}

pub fn witness(tree: &JsonTree) -> Value {
    let mut hash = Sha256::new();
    hash.update(b"marty.json-tree/v1\n");
    let mut pending = vec![(tree.root(), 0)];
    let mut count = 0;
    let mut maximum = 0;
    while let Some((id, parent)) = pending.pop() {
        count += 1;
        let token = match tree.node(id) {
            JsonNode::Array(children) => {
                maximum = maximum.max(parent + 1);
                pending.extend(children.iter().rev().map(|id| (*id, parent + 1)));
                json!(["array", children.len()])
            }
            JsonNode::Object(entries) => {
                let mut sorted: Vec<_> = entries.iter().collect();
                sorted.sort_by(|a, b| a.0.codepoints().cmp(b.0.codepoints()));
                maximum = maximum.max(parent + 1);
                pending.extend(sorted.iter().rev().map(|(_, id)| (*id, parent + 1)));
                json!([
                    "object",
                    sorted
                        .iter()
                        .map(|(key, _)| key.codepoints().collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                ])
            }
            JsonNode::Text(text) => json!(["text", text.codepoints().collect::<Vec<_>>()]),
            JsonNode::Float(value) => float_token(*value),
            JsonNode::Scalar(value) => match value {
                Value::Null => json!(["null"]),
                Value::Bool(value) => json!(["bool", value]),
                Value::Number(number) => {
                    let token = number.to_string();
                    if token.contains(['.', 'e', 'E']) {
                        float_token(number.as_f64().unwrap())
                    } else {
                        json!(["integer", token])
                    }
                }
                _ => panic!("parser scalar nodes must be primitive"),
            },
        };
        hash.update(serde_json::to_vec(&token).unwrap());
        hash.update(b"\n");
    }
    json!({"representation":"marty.json-tree/v1","sha256":hex::encode(hash.finalize()),
        "nodes":count,"container_depth":maximum})
}

fn float_token(value: f64) -> Value {
    json!([
        "float",
        if value.is_nan() {
            "nan".into()
        } else {
            format!("{:016x}", value.to_bits())
        }
    ])
}

#[test]
fn witness_agrees_with_explicit_typed_python_token_vector() {
    let tokens = b"marty.json-tree/v1\n[\"object\",[[97],[98]]]\n[\"array\",2]\n[\"integer\",\"0\"]\n[\"bool\",false]\n[\"text\",[55296]]\n";
    let actual = witness_bytes(br#"{"b":"\ud800","a":[0,false]}"#);
    assert_eq!(actual["sha256"], hex::encode(Sha256::digest(tokens)));
    assert_eq!(actual["nodes"], 5);
    assert_eq!(actual["container_depth"], 2);
}
