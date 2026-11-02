use super::*;

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
