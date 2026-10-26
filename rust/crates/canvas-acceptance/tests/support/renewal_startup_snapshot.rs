use serde_json::Value;

/// Account only for migration 0009's nullable extension to legacy credentials.
/// The caller separately proves and incorporates the bounded token lifetime.
/// Keep every other field, row and collection in the exact snapshot comparison.
pub(super) fn legacy_snapshot_with_nullable_mdoc_reference(mut expected: Value) -> Value {
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
    expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn legacy() -> Value {
        json!({
            "transaction": {"id":"owned", "status":"issued", "access_token_expires_at":"bounded-by-caller"},
            "credentials": [
                {"id":"credential", "status":"active", "credential_hash":"original"},
                {"id":"other", "status":"suspended", "existing_optional":null}
            ],
            "events": [{"id":"history"}], "deliveries": [{"id":"delivery"}]
        })
    }

    fn migrated() -> Value {
        let mut value = legacy();
        value["credentials"][0]["mdoc_status_reference"] = Value::Null;
        value["credentials"][1]["mdoc_status_reference"] = Value::Null;
        value
    }

    #[test]
    fn nullable_schema_extension_preserves_the_entire_legacy_domain_snapshot() {
        assert_eq!(
            legacy_snapshot_with_nullable_mdoc_reference(legacy()),
            migrated()
        );
        assert_eq!(
            legacy_snapshot_with_nullable_mdoc_reference(migrated()),
            migrated()
        );
    }

    #[test]
    fn existing_status_binding_is_never_overwritten_or_fabricated() {
        let mut bound = migrated();
        bound["credentials"][0]["mdoc_status_reference"] =
            json!("existing-authenticated-reference");
        assert!(
            std::panic::catch_unwind(|| legacy_snapshot_with_nullable_mdoc_reference(bound))
                .is_err()
        );
        let actual = legacy_snapshot_with_nullable_mdoc_reference(legacy());
        assert!(actual["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row.get("mdoc_status_reference") == Some(&Value::Null)));
    }

    #[test]
    fn malformed_legacy_collections_and_rows_fail_closed() {
        for invalid in [
            json!({}),
            json!({"credentials":null}),
            json!({"credentials":{}}),
            json!({"credentials":[null]}),
        ] {
            assert!(
                std::panic::catch_unwind(|| legacy_snapshot_with_nullable_mdoc_reference(invalid))
                    .is_err()
            );
        }
    }
}
