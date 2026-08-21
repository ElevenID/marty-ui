use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use marty_flow::{
    canonical_template_signing_format, template_key_purpose, validate_definition_references,
    CredentialTemplateProvider, CredentialTemplateReference, FlowDefinitionReferenceSet,
    FlowProviderError, FlowProviderRegistry, FlowReference, FlowReferenceKind,
    FlowReferenceProvider, PresentationEvaluationRequest, PresentationEvaluationResult,
    PresentationPolicyProvider, PresentationPolicyReference, SigningIdentity,
    SigningIdentityProvider, SigningRequest, SigningResult,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    draft_status_behavior: String,
    activation_status_behavior: String,
    identity_behavior: String,
    delivery_destination_tenant_exception: String,
    presentation_policy_behavior: String,
    template_issuer_behavior: String,
    template_cache_behavior: String,
    catalog_active_statuses: Vec<String>,
    credential_active_statuses: Vec<String>,
    issuer_format_aliases: BTreeMap<String, String>,
    failure_behavior: String,
}

#[derive(Clone)]
struct Templates {
    status: &'static str,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CredentialTemplateReference {
            id: template_id.into(),
            organization_id: "org-1".into(),
            status: self.status.into(),
            credential_type: "ExampleCredential".into(),
            vct: String::new(),
            doctype: String::new(),
            supported_formats: vec!["vc+sd-jwt".into()],
            claims: Vec::new(),
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "jwt_vc".into(),
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }
}

#[derive(Clone)]
struct Policies {
    status: &'static str,
}

#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: policy_id.into(),
            organization_id: "org-1".into(),
            status: self.status.into(),
            credential_requirements: vec![json!({"credential_template_id": "template-1"})],
        })
    }

    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!("reference validation never evaluates a presentation")
    }
}

#[derive(Clone)]
struct Signing {
    wrong_tenant: bool,
}

#[async_trait]
impl SigningIdentityProvider for Signing {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        key_purpose: &str,
        credential_format: &str,
        _algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        Ok(SigningIdentity {
            organization_id: if self.wrong_tenant {
                "org-2"
            } else {
                organization_id
            }
            .into(),
            issuer_did: issuer_did.into(),
            verification_method_id: format!("{issuer_did}#key-1"),
            public_jwk: BTreeMap::from([
                ("kty".into(), Value::String("EC".into())),
                ("crv".into(), Value::String("P-256".into())),
                ("x".into(), Value::String("x".into())),
                ("y".into(), Value::String("y".into())),
            ]),
            key_purpose: key_purpose.into(),
            credential_format: credential_format.into(),
            algorithm: "ES256".into(),
        })
    }

    async fn sign(&self, _request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        unreachable!("reference validation never signs")
    }
}

#[derive(Clone)]
struct Catalog {
    status: &'static str,
    wrong_tenant: Option<FlowReferenceKind>,
}

#[async_trait]
impl FlowReferenceProvider for Catalog {
    async fn resolve(
        &self,
        kind: FlowReferenceKind,
        reference_id: &str,
        _principal_id: &str,
    ) -> Result<FlowReference, FlowProviderError> {
        let system_owned = kind == FlowReferenceKind::DeliveryDestination;
        let organization_id = if system_owned {
            None
        } else if self.wrong_tenant == Some(kind) {
            Some("org-2".into())
        } else {
            Some("org-1".into())
        };
        Ok(FlowReference {
            kind,
            id: reference_id.into(),
            organization_id,
            status: self.status.into(),
            system_owned,
        })
    }
}

fn references() -> FlowDefinitionReferenceSet {
    FlowDefinitionReferenceSet {
        credential_template_id: Some("template-1".into()),
        application_template_id: Some("application-1".into()),
        presentation_policy_id: Some("policy-1".into()),
        delivery_destination_profile_id: Some("delivery-1".into()),
        deployment_profile_ids: vec!["deployment-1".into(), "deployment-1".into()],
        trust_profile_id: Some("trust-1".into()),
    }
}

fn registry(
    credential_status: &'static str,
    catalog_status: &'static str,
    wrong_tenant: Option<FlowReferenceKind>,
    wrong_signing_tenant: bool,
) -> (FlowProviderRegistry, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        FlowProviderRegistry {
            credential_template: Some(Arc::new(Templates {
                status: credential_status,
                calls: calls.clone(),
            })),
            presentation_policy: Some(Arc::new(Policies {
                status: credential_status,
            })),
            signing_identity: Some(Arc::new(Signing {
                wrong_tenant: wrong_signing_tenant,
            })),
            reference_catalog: Some(Arc::new(Catalog {
                status: catalog_status,
                wrong_tenant,
            })),
            ..FlowProviderRegistry::default()
        },
        calls,
    )
}

#[tokio::test]
async fn language_neutral_reference_contract_is_executable() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-reference-validation-behavior.json"
    ))
    .expect("reference contract");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(
        contract.draft_status_behavior,
        "existence_and_tenant_binding_required"
    );
    assert_eq!(contract.activation_status_behavior, "all_references_active");
    assert_eq!(contract.identity_behavior, "exact_id_kind_and_tenant");
    assert_eq!(
        contract.delivery_destination_tenant_exception,
        "system_owned_only"
    );
    assert_eq!(
        contract.presentation_policy_behavior,
        "validate_each_direct_credential_template_requirement"
    );
    assert_eq!(
        contract.template_issuer_behavior,
        "public_did_format_purpose_algorithm_and_key_bound"
    );
    assert_eq!(
        contract.template_cache_behavior,
        "resolve_each_template_once_per_validation"
    );
    assert_eq!(contract.catalog_active_statuses, ["active", "enabled"]);
    assert_eq!(contract.credential_active_statuses, ["active"]);
    for (alias, canonical) in &contract.issuer_format_aliases {
        assert_eq!(canonical_template_signing_format(alias), canonical);
    }
    assert_eq!(template_key_purpose("mso_mdoc"), "mdoc_dsc");
    assert_eq!(template_key_purpose("vds_nc"), "vdsnc_signing");
    assert_eq!(template_key_purpose("jwt_vc_json"), "vc_jwt_issuer");
    assert_eq!(contract.failure_behavior, "fail_closed");

    let (draft_registry, calls) = registry("draft", "disabled", None, false);
    validate_definition_references(&draft_registry, "user-1", "org-1", &references(), false)
        .await
        .expect("inactive references remain editable in draft");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "nested reference is cached"
    );

    assert!(validate_definition_references(
        &draft_registry,
        "user-1",
        "org-1",
        &references(),
        true,
    )
    .await
    .is_err());

    let (active_registry, _) = registry("active", "enabled", None, false);
    validate_definition_references(&active_registry, "user-1", "org-1", &references(), true)
        .await
        .expect("active tenant-bound references");
}

#[tokio::test]
async fn reference_identity_and_signing_mismatches_fail_closed() {
    let (wrong_reference, _) = registry(
        "active",
        "active",
        Some(FlowReferenceKind::TrustProfile),
        false,
    );
    assert!(validate_definition_references(
        &wrong_reference,
        "user-1",
        "org-1",
        &references(),
        true,
    )
    .await
    .is_err());

    let (wrong_signer, _) = registry("active", "active", None, true);
    assert!(
        validate_definition_references(&wrong_signer, "user-1", "org-1", &references(), true,)
            .await
            .is_err()
    );
}
