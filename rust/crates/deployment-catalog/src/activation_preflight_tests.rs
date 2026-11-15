use super::*;

#[test]
fn recovery_tokens_reject_normalized_reuse_and_cross_role_duplicates() {
    let old = vec![b"old-a".to_vec(), b"old-b\n".to_vec()];
    assert!(recovery_tokens_are_new(&old, &[b"new-a".to_vec(), b"new-b".to_vec()]).is_ok());
    for new in [
        vec![b"old-a\n".to_vec(), b"new-b".to_vec()],
        vec![b"new-a".to_vec(), b" old-b \r\n".to_vec()],
        vec![b"new-a".to_vec(), b"new-a\n".to_vec()],
        vec![b"new-a".to_vec(), b" \n".to_vec()],
    ] {
        assert!(recovery_tokens_are_new(&old, &new).is_err());
    }
}

#[test]
fn recovery_candidate_requires_distinct_generations_and_closed_admission() {
    let valid = json!({"token":"PUBLIC_SYNTHETIC","old":"/proof/old","new":"/proof/new","minimum_ttl":3600});
    assert!(recovery_candidate_context(&valid).is_ok());
    for (field, value) in [
        ("new", json!("/proof/old")),
        ("old", json!(null)),
        ("minimum_ttl", json!(3599)),
        ("minimum_ttl", json!(28801)),
        ("minimum_ttl", json!(3600.0)),
        ("require_orphan_new", json!(false)),
        ("require_closed_new_metadata", json!(false)),
        ("replacement", json!(null)),
        ("retiring", json!(false)),
        ("allow_expired_new", json!(true)),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        assert!(recovery_candidate_context(&changed).is_err(), "{field}");
    }
}

#[test]
fn retained_certificate_evidence_refuses_activation_options_and_weak_ttl() {
    let valid =
        json!({"token":"PUBLIC_SYNTHETIC", "generation":"/proof/retained", "minimum_ttl":3600});
    assert!(retained_certificate_context(&valid).is_ok());
    for ttl in [0, 3599, 28801] {
        let mut changed = valid.clone();
        changed["minimum_ttl"] = json!(ttl);
        assert!(retained_certificate_context(&changed).is_err());
    }
    for field in ["replacement", "retiring", "old", "new", "allow_expired"] {
        let mut changed = valid.clone();
        changed[field] = json!(false);
        assert!(retained_certificate_context(&changed).is_err());
    }
    for field in ["token", "generation", "minimum_ttl"] {
        let mut changed = valid.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(retained_certificate_context(&changed).is_err());
    }
}

#[test]
fn closed_new_leaf_metadata_rejects_identity_grants_and_lifetime_expansion() {
    let original = json!({"type":"service","policies":["one-exact-policy"],"num_uses":0,
        "identity_policies":[],"period":0,"token_period":0,"ttl":28000,
        "creation_ttl":28800,"explicit_max_ttl":28800,"renewable":true});
    assert!(closed_new_token_metadata(&original).is_ok());
    // Existing producers do not request non-renewability. Both variants remain
    // acceptable under the original absolute eight-hour role lifetime cap.
    let mut nonrenewable = original.clone();
    nonrenewable["renewable"] = json!(false);
    assert!(closed_new_token_metadata(&nonrenewable).is_ok());
    for (field, value) in [
        ("type", json!("batch")),
        ("num_uses", json!(1)),
        ("identity_policies", json!(["unexpected-identity-grant"])),
        ("token_policies", json!(["unexpected-token-grant"])),
        ("period", json!(28800)),
        ("token_period", json!(28800)),
        ("explicit_max_ttl", json!(0)),
        ("explicit_max_ttl", json!(86400)),
        ("creation_ttl", json!(86400)),
        ("creation_ttl", json!(1)),
        ("ttl", json!(0)),
        ("ttl", json!(28801)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(closed_new_token_metadata(&changed).is_err(), "{field}");
    }
    for field in ["type", "num_uses", "creation_ttl", "explicit_max_ttl"] {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(
            closed_new_token_metadata(&changed).is_err(),
            "missing {field}"
        );
    }
}

#[test]
fn closed_new_metadata_is_explicit_and_preserves_existing_callers() {
    assert_eq!(closed_new_metadata_requested(&json!({})), Ok(false));
    assert_eq!(
        closed_new_metadata_requested(&json!({"require_closed_new_metadata":false})),
        Ok(false)
    );
    assert_eq!(
        closed_new_metadata_requested(&json!({"require_closed_new_metadata":true})),
        Ok(true)
    );
    for value in [json!(null), json!(1), json!("true")] {
        assert!(
            closed_new_metadata_requested(&json!({"require_closed_new_metadata":value})).is_err()
        );
    }
}

fn native_policy_orders() -> (Vec<String>, Vec<String>) {
    const PROJECT: &str = "marty-selfhost-disposable-enrollment-test";
    const NONCE: &str = "0123456789ab";
    const INGRESS: &str = "installer-ingress-0123456789abcdef0123456789abcdef";

    // Keep the validator's real token-file traversal. Policy names follow the
    // native workload producer and keycloak::mint, not the filenames' order.
    let observed: Vec<String> = token_scopes()
        .into_iter()
        .map(|(file, key)| match key {
            Some(key) => format!("{PROJECT}-{key}"),
            None if file == "keycloak_signing_kms_token" => {
                format!("selfhost-keycloak-sign-{NONCE}")
            }
            None => {
                let parts: Vec<_> = file.split('_').collect();
                assert_eq!(parts.len(), 4);
                assert!(keycloak::REALMS.contains(&parts[1]));
                assert!(keycloak::PURPOSES.contains(&parts[2]));
                format!("selfhost-keycloak-{}-{}-{NONCE}", parts[1], parts[2])
            }
        })
        .collect();

    // approle::bootstrap sorts names when retaining the enrollment. The public
    // generation caller removes its separately validated ingress signer.
    let mut enrolled = observed.clone();
    enrolled.push(INGRESS.into());
    enrolled.sort();
    enrolled.retain(|name| name != INGRESS);
    (observed, enrolled)
}

#[test]
fn enrolled_policies_accept_native_producer_order() {
    let (observed, enrolled) = native_policy_orders();
    assert_eq!(observed.len(), 21);
    assert_eq!(enrolled.len(), 21);
    assert_eq!(
        observed.iter().collect::<std::collections::BTreeSet<_>>(),
        enrolled.iter().collect::<std::collections::BTreeSet<_>>()
    );
    assert_ne!(observed, enrolled);
    assert!(observed[0].ends_with("workload-tls-auth-server"));
    assert!(enrolled[0].ends_with("workload-tls-auth-client"));
    assert!(same_enrolled_policies(observed, &enrolled));
}

#[test]
fn enrolled_policies_reject_missing_extra_duplicate_or_substituted_scopes() {
    let (observed, enrolled) = native_policy_orders();
    let mut missing = observed.clone();
    missing.pop();
    let mut extra = observed.clone();
    extra.push("unrelated-extra-policy".into());
    let mut duplicate = observed.clone();
    duplicate[1] = duplicate[0].clone();
    let mut substituted = observed.clone();
    substituted[0] = "unrelated-substituted-policy".into();
    for (case, changed) in [
        ("missing", missing),
        ("extra", extra),
        ("duplicate", duplicate),
        ("substituted", substituted),
    ] {
        assert!(
            !same_enrolled_policies(changed.clone(), &enrolled),
            "changed live inventory: {case}"
        );
        assert!(
            !same_enrolled_policies(enrolled.clone(), &changed),
            "changed enrollment inventory: {case}"
        );
    }
}
