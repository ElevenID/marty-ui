use serde_json::Value;

/// Account only for migration 0009's nullable extension to legacy credentials.
/// The caller separately proves and incorporates the bounded token lifetime.
/// Keep every other field, row and collection in the exact snapshot comparison.
pub(super) fn assert_migrated_legacy_snapshot(mut expected: Value, actual: &Value) {
    for credential in expected["credentials"]
        .as_array_mut()
        .expect("legacy credential collection")
    {
        let fields = credential.as_object_mut().expect("legacy credential row");
        if let Some(reference) = fields.get("mdoc_status_reference") {
            assert!(
                reference.is_null(),
                "Do not overwrite an existing credential status binding"
            );
        } else {
            fields.insert("mdoc_status_reference".into(), Value::Null);
        }
    }
    assert_eq!(
        actual, &expected,
        "startup migration changed seeded renewal domain state"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn legacy() -> Value {
        json!({
            "transaction": {"id":"owned", "status":"issued", "access_token_expires_at":"bounded-by-caller"},
            "credentials": [{"id":"credential", "status":"active", "credential_hash":"original"}],
            "events": [], "deliveries": []
        })
    }

    fn migrated() -> Value {
        let mut value = legacy();
        value["credentials"][0]["mdoc_status_reference"] = Value::Null;
        value
    }

    #[test]
    fn nullable_schema_extension_preserves_the_entire_legacy_domain_snapshot() {
        assert_migrated_legacy_snapshot(legacy(), &migrated());
        assert_migrated_legacy_snapshot(migrated(), &migrated());
    }

    #[test]
    fn absent_or_invented_status_binding_is_not_an_accepted_migration() {
        assert!(
            std::panic::catch_unwind(|| assert_migrated_legacy_snapshot(legacy(), &legacy()))
                .is_err()
        );
        let mut invented = migrated();
        invented["credentials"][0]["mdoc_status_reference"] = json!("invented");
        assert!(
            std::panic::catch_unwind(|| assert_migrated_legacy_snapshot(legacy(), &invented))
                .is_err()
        );
        assert!(std::panic::catch_unwind(|| assert_migrated_legacy_snapshot(
            invented,
            &migrated()
        ))
        .is_err());
    }

    #[test]
    fn domain_fields_rows_and_unknown_schema_changes_still_fail_the_full_comparison() {
        for mutation in 0..6 {
            let mut changed = migrated();
            match mutation {
                0 => changed["credentials"][0]["status"] = json!("revoked"),
                1 => changed["credentials"][0]["credential_hash"] = json!("changed"),
                2 => changed["transaction"]["access_token_expires_at"] = json!("unbounded"),
                3 => changed["events"] = json!([{"unexpected":"event"}]),
                4 => changed["deliveries"] = json!([{"unexpected":"delivery"}]),
                _ => changed["credentials"][0]["unexpected_column"] = Value::Null,
            }
            assert!(std::panic::catch_unwind(|| assert_migrated_legacy_snapshot(
                legacy(),
                &changed
            ))
            .is_err());
        }
    }
}
