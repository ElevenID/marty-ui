use async_trait::async_trait;
use marty_oid4vci::verifier::{VerificationCheckStatus, VerificationEngine};
use marty_verification::{
    verification::{verify_vds_nc_jwk_json, VerificationProcessingStatus},
    SignatureVerificationStatus,
};
use serde_json::{Map, Value};

use super::{
    AdapterFacts, CredentialStatus, GovernanceSnapshot, IssuerKeyRequest, IssuerKeyResolver,
    PresentationDefinition,
};

#[async_trait]
pub trait CredentialVerificationKernel: Send + Sync {
    async fn verify_jwt_vp(
        &self,
        presentation: &str,
        expected_audience: &str,
        expected_nonce: Option<&str>,
    ) -> AdapterFacts;

    async fn verify_structured_presentation(
        &self,
        presentation: &Map<String, Value>,
        definition: &PresentationDefinition,
        verifier_did: &str,
        governance: &GovernanceSnapshot,
        issuer_resolver: &dyn IssuerKeyResolver,
    ) -> AdapterFacts;

    async fn verify_vds_nc(&self, barcode: &str, issuer_jwk: &Value) -> AdapterFacts;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeCredentialVerificationKernel;

#[async_trait]
impl CredentialVerificationKernel for NativeCredentialVerificationKernel {
    async fn verify_jwt_vp(
        &self,
        presentation: &str,
        expected_audience: &str,
        expected_nonce: Option<&str>,
    ) -> AdapterFacts {
        let result = VerificationEngine::new(expected_audience, expected_audience)
            .verify_vp_token(presentation, expected_nonce.unwrap_or_default());
        AdapterFacts {
            processing_status: VerificationProcessingStatus::Completed,
            presentation_structure_valid: None,
            presentation_proof_valid: fact(result.evidence.presentation_proof),
            credential_proofs_valid: fact(result.evidence.credential_issuer_proofs),
            trust_chain_valid: None,
            holder_binding_valid: fact(result.evidence.holder_binding),
            transaction_binding_valid: fact(result.evidence.transaction_binding),
            presentation_constraints_valid: fact(result.evidence.presentation_constraints),
            revocation_checked: None,
            revocation_status: None,
        }
    }

    async fn verify_structured_presentation(
        &self,
        presentation: &Map<String, Value>,
        definition: &PresentationDefinition,
        verifier_did: &str,
        governance: &GovernanceSnapshot,
        issuer_resolver: &dyn IssuerKeyResolver,
    ) -> AdapterFacts {
        verify_structured(
            presentation,
            definition,
            verifier_did,
            governance,
            issuer_resolver,
        )
        .await
    }

    async fn verify_vds_nc(&self, barcode: &str, issuer_jwk: &Value) -> AdapterFacts {
        let result = serde_json::to_string(issuer_jwk)
            .ok()
            .and_then(|jwk| verify_vds_nc_jwk_json(barcode, &jwk).ok());
        let verified = result.as_ref().is_some_and(|result| {
            result.verified && result.signature_status == SignatureVerificationStatus::Valid
        });
        AdapterFacts {
            processing_status: VerificationProcessingStatus::Completed,
            presentation_structure_valid: None,
            presentation_proof_valid: None,
            credential_proofs_valid: Some(verified),
            trust_chain_valid: Some(true),
            holder_binding_valid: None,
            transaction_binding_valid: None,
            presentation_constraints_valid: None,
            revocation_checked: None,
            revocation_status: Some(CredentialStatus::Unknown),
        }
    }
}

async fn verify_structured(
    presentation: &Map<String, Value>,
    definition: &PresentationDefinition,
    verifier_did: &str,
    governance: &GovernanceSnapshot,
    issuer_resolver: &dyn IssuerKeyResolver,
) -> AdapterFacts {
    let credentials = match presentation.get("verifiableCredential") {
        Some(Value::Array(credentials)) if !credentials.is_empty() => credentials.clone(),
        Some(credential) if !credential.is_null() => vec![credential.clone()],
        _ => return structured_failure(Some(false), None, None),
    };
    if definition.input_descriptors.is_empty() {
        return structured_failure(None, Some(false), None);
    }
    let Some(submission) = presentation.get("presentation_submission") else {
        return structured_failure(None, Some(false), None);
    };
    for credential in credentials {
        let Some(credential) = credential.as_object() else {
            return structured_failure(Some(false), None, None);
        };
        if !verify_credential(credential, governance, issuer_resolver).await {
            return structured_failure(Some(false), None, Some(false));
        }
    }
    let definition = serde_json::to_value(definition)
        .ok()
        .and_then(|value| serde_json::from_value(value).ok());
    let submission = serde_json::from_value(submission.clone()).ok();
    let structure_valid = definition
        .zip(submission)
        .is_some_and(|(definition, submission)| {
            let result = VerificationEngine::new(verifier_did, verifier_did)
                .verify_presentation_structure(&definition, &submission);
            result.check_valid
                && result.evidence.presentation_structure == VerificationCheckStatus::Passed
        });
    if !structure_valid {
        return structured_failure(Some(true), Some(false), Some(true));
    }
    AdapterFacts {
        processing_status: VerificationProcessingStatus::Completed,
        presentation_structure_valid: Some(true),
        presentation_proof_valid: None,
        credential_proofs_valid: Some(true),
        trust_chain_valid: Some(true),
        holder_binding_valid: None,
        transaction_binding_valid: None,
        presentation_constraints_valid: None,
        revocation_checked: Some(false),
        revocation_status: None,
    }
}

async fn verify_credential(
    credential: &Map<String, Value>,
    governance: &GovernanceSnapshot,
    issuer_resolver: &dyn IssuerKeyResolver,
) -> bool {
    if !credential.get("proof").is_some_and(Value::is_object) {
        return false;
    }
    let issuer = match credential.get("issuer") {
        Some(Value::String(issuer)) => issuer.as_str(),
        Some(Value::Object(issuer)) => issuer.get("id").and_then(Value::as_str).unwrap_or_default(),
        _ => "",
    };
    if issuer.is_empty() {
        return false;
    }
    let method_id = credential
        .get("proof")
        .and_then(Value::as_object)
        .and_then(|proof| {
            ["verificationMethod", "verification_method", "kid"]
                .into_iter()
                .find_map(|field| proof.get(field).and_then(Value::as_str))
        });
    let Ok(key) = issuer_resolver
        .resolve(
            governance,
            IssuerKeyRequest {
                issuer_did: issuer,
                verification_method_id: method_id,
                credential_format: "vcdm",
                key_purpose: "assertion",
                algorithm: None,
            },
        )
        .await
    else {
        return false;
    };
    let response = marty_verification::vcdm::verify_vcdm_data_integrity_json(
        &serde_json::json!({
            "document": credential,
            "resolved_verification_methods": [{
                "id": key.verification_method_id(),
                "controller": issuer,
                "public_jwk": key.public_jwk(),
            }],
        })
        .to_string(),
    );
    serde_json::from_str::<Value>(&response)
        .ok()
        .is_some_and(|result| {
            result.get("valid") == Some(&Value::Bool(true))
                && result.get("kind").and_then(Value::as_str) == Some("credential")
                && result.get("verified_credentials").and_then(Value::as_u64) == Some(1)
        })
}

const fn structured_failure(
    credential_proofs_valid: Option<bool>,
    presentation_structure_valid: Option<bool>,
    trust_chain_valid: Option<bool>,
) -> AdapterFacts {
    AdapterFacts {
        processing_status: VerificationProcessingStatus::Completed,
        presentation_structure_valid,
        presentation_proof_valid: None,
        credential_proofs_valid,
        trust_chain_valid,
        holder_binding_valid: None,
        transaction_binding_valid: None,
        presentation_constraints_valid: None,
        revocation_checked: None,
        revocation_status: None,
    }
}

const fn fact(status: VerificationCheckStatus) -> Option<bool> {
    match status {
        VerificationCheckStatus::Passed => Some(true),
        VerificationCheckStatus::Failed => Some(false),
        VerificationCheckStatus::NotChecked | VerificationCheckStatus::Unsupported => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials_compat::{
        GovernanceEngine, GovernancePurpose, IssuerResolutionError, ResolvedIssuerKey,
    };

    struct RejectingResolver;

    #[async_trait]
    impl IssuerKeyResolver for RejectingResolver {
        async fn resolve(
            &self,
            _governance: &GovernanceSnapshot,
            _request: IssuerKeyRequest<'_>,
        ) -> Result<ResolvedIssuerKey, IssuerResolutionError> {
            Err(IssuerResolutionError::Invalid)
        }
    }

    fn governed_direct() -> (GovernanceSnapshot, PresentationDefinition) {
        let fixture: Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        let governance = GovernanceEngine::new(&fixture["governance"].to_string())
            .unwrap()
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap();
        let definition = serde_json::from_value(fixture["definition"].clone()).unwrap();
        (governance, definition)
    }

    #[tokio::test]
    async fn malformed_jwt_and_vds_inputs_fail_closed_without_panicking() {
        let kernel = NativeCredentialVerificationKernel;
        let jwt = kernel
            .verify_jwt_vp("not-a-jwt", "did:web:verifier.example", Some("nonce"))
            .await;
        assert_ne!(jwt.presentation_proof_valid, Some(true));
        assert_ne!(jwt.transaction_binding_valid, Some(true));

        let vds = kernel
            .verify_vds_nc("malformed", &serde_json::json!({"kty":"oct","k":"secret"}))
            .await;
        assert_eq!(vds.credential_proofs_valid, Some(false));
    }

    #[tokio::test]
    async fn structured_verification_preserves_validation_order_and_fails_closed() {
        let kernel = NativeCredentialVerificationKernel;
        let (governance, definition) = governed_direct();
        let empty = Map::new();
        let facts = kernel
            .verify_structured_presentation(
                &empty,
                &definition,
                "did:web:verifier.example",
                &governance,
                &RejectingResolver,
            )
            .await;
        assert_eq!(facts.credential_proofs_valid, Some(false));

        let mut no_descriptors = definition.clone();
        no_descriptors.input_descriptors.clear();
        let presentation = serde_json::json!({
            "verifiableCredential": [{"issuer":"did:web:issuer.example","proof":{}}],
            "presentation_submission": {}
        });
        let facts = kernel
            .verify_structured_presentation(
                presentation.as_object().unwrap(),
                &no_descriptors,
                "did:web:verifier.example",
                &governance,
                &RejectingResolver,
            )
            .await;
        assert_eq!(facts.presentation_structure_valid, Some(false));
        assert_eq!(facts.credential_proofs_valid, None);

        let no_submission = serde_json::json!({
            "verifiableCredential": [{"issuer":"did:web:issuer.example","proof":{}}]
        });
        let facts = kernel
            .verify_structured_presentation(
                no_submission.as_object().unwrap(),
                &definition,
                "did:web:verifier.example",
                &governance,
                &RejectingResolver,
            )
            .await;
        assert_eq!(facts.presentation_structure_valid, Some(false));
        assert_eq!(facts.credential_proofs_valid, None);

        let facts = kernel
            .verify_structured_presentation(
                presentation.as_object().unwrap(),
                &definition,
                "did:web:verifier.example",
                &governance,
                &RejectingResolver,
            )
            .await;
        assert_eq!(facts.credential_proofs_valid, Some(false));
        assert_eq!(facts.trust_chain_valid, Some(false));
    }
}
