//! Shared issuance and admission contract for eight-hour renewal leaves.
use serde_json::{json, Value};

pub fn request(policy: &str) -> Value {
    json!({"policies":[policy], "no_default_policy":true,
        "ttl":"8h", "explicit_max_ttl":"8h"})
}

/// A role's configured maximum is not proof of the issued token's hard cap.
pub fn bounded_metadata(data: &Value) -> bool {
    let Some(ttl) = data["ttl"].as_u64() else {
        return false;
    };
    let Some(created) = data["creation_ttl"].as_u64() else {
        return false;
    };
    data["type"] == "service"
        && data["num_uses"] == 0
        && data["explicit_max_ttl"] == 28800
        && (1..=28800).contains(&created)
        && (1..=created).contains(&ttl)
        && data
            .get("identity_policies")
            .is_none_or(|v| v.is_null() || v == &json!([]))
        && data
            .get("token_policies")
            .is_none_or(|v| v == &data["policies"])
        && ["period", "token_period"]
            .iter()
            .all(|name| data.get(*name).is_none_or(|v| v.is_null() || v == 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encodes_a_hard_cap_without_changing_scope() {
        let value = request("synthetic-reviewed-leaf");
        assert_eq!(
            value,
            json!({"policies":["synthetic-reviewed-leaf"],
            "no_default_policy":true,"ttl":"8h","explicit_max_ttl":"8h"})
        );
        assert!(!value.as_object().unwrap().contains_key("period"));
    }

    #[test]
    fn role_maximum_does_not_replace_an_issued_token_cap() {
        let valid = json!({"type":"service","num_uses":0,"explicit_max_ttl":28800,
            "creation_ttl":28800,"ttl":28799,"policies":["synthetic-reviewed-leaf"]});
        assert!(bounded_metadata(&valid));
        for (name, value) in [
            ("explicit_max_ttl", json!(0)),
            ("explicit_max_ttl", json!(86400)),
            ("ttl", json!(0)),
            ("ttl", json!(28801)),
            ("creation_ttl", json!(28801)),
            ("num_uses", json!(1)),
            ("type", json!("batch")),
            ("period", json!(28800)),
            ("token_period", json!(28800)),
            ("identity_policies", json!(["extra"])),
            ("token_policies", json!(["extra"])),
        ] {
            let mut changed = valid.clone();
            changed[name] = value;
            assert!(!bounded_metadata(&changed), "{name}");
        }
        for name in [
            "type",
            "num_uses",
            "explicit_max_ttl",
            "creation_ttl",
            "ttl",
        ] {
            let mut changed = valid.clone();
            changed.as_object_mut().unwrap().remove(name);
            assert!(!bounded_metadata(&changed), "{name}");
        }
    }
}
