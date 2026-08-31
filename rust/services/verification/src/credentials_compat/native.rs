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
        _ => return structured_failure(VerificationProcessingStatus::Completed, Some(false), None),
    };
    if definition.input_descriptors.is_empty() {
        return structured_failure(VerificationProcessingStatus::Completed, None, Some(false));
    }
    let Some(submission) = presentation
        .get("presentation_submission")
        .filter(|submission| submission.is_object())
    else {
        return structured_failure(VerificationProcessingStatus::Completed, None, Some(false));
    };
    for credential in credentials {
        let Some(credential) = credential.as_object() else {
            return structured_failure(
                VerificationProcessingStatus::Unsupported,
                Some(false),
                None,
            );
        };
        if !verify_credential(credential, governance, issuer_resolver).await {
            return structured_failure(VerificationProcessingStatus::Completed, Some(false), None);
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
        return structured_failure(VerificationProcessingStatus::Completed, None, Some(false));
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
                credential_format: None,
                key_purpose: None,
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
    processing_status: VerificationProcessingStatus,
    credential_proofs_valid: Option<bool>,
    presentation_structure_valid: Option<bool>,
) -> AdapterFacts {
    AdapterFacts {
        processing_status,
        presentation_structure_valid,
        presentation_proof_valid: None,
        credential_proofs_valid,
        trust_chain_valid: None,
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
    use std::sync::{Arc, Mutex};

    use axum::{extract::State, http::Uri, routing::get, Json, Router};
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;

    use super::*;
    use crate::credentials_compat::{
        build_canonical_decision, GovernanceEngine, GovernancePurpose, IssuerResolutionError,
        OrganizationIssuerKeyResolver, Presented, ResolvedIssuerKey,
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

    fn canonical(facts: &AdapterFacts, governance: &GovernanceSnapshot) -> Value {
        serde_json::to_value(
            build_canonical_decision(
                governance,
                "verification:test",
                "transaction:test",
                Presented::String("test-presentation"),
                facts,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn check_code<'a>(canonical: &'a Value, check_id: &str) -> &'a str {
        canonical["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["check_id"] == check_id)
            .and_then(|check| check["code"].as_str())
            .unwrap()
    }

    #[derive(Clone)]
    struct ResolverFixture {
        response: Value,
        query: Arc<Mutex<Option<String>>>,
    }

    async fn resolve_fixture(State(state): State<ResolverFixture>, uri: Uri) -> Json<Value> {
        *state.query.lock().unwrap() = uri.query().map(str::to_owned);
        Json(state.response)
    }

    async fn signed_credential_and_org_resolver() -> (
        Value,
        OrganizationIssuerKeyResolver,
        Arc<Mutex<Option<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let issuer = "did:web:issuer.example";
        let method = "did:web:issuer.example#key-1";
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_jwk = serde_json::json!({
            "kty":"OKP",
            "crv":"Ed25519",
            "x":URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
            "kid":method,
            "alg":"EdDSA"
        });
        let prepared: Value = serde_json::from_str(
            &marty_verification::vcdm::prepare_vcdm_data_integrity_credential_json(
                &serde_json::json!({
                    "credential": {
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "id": "urn:uuid:org-resolved-vcdm",
                        "type": ["VerifiableCredential"],
                        "issuer": issuer,
                        "validFrom": "2026-08-31T00:00:00Z",
                        "credentialSubject": {"id":"did:example:holder"}
                    },
                    "issuer_did": issuer,
                    "verification_method_id": method,
                    "public_jwk": public_jwk
                })
                .to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        let signing_input = URL_SAFE_NO_PAD
            .decode(prepared["signing_input_b64"].as_str().unwrap())
            .unwrap();
        let signature = signing_key.sign(&signing_input);
        let credential: Value = serde_json::from_str(
            &marty_verification::vcdm::complete_vcdm_data_integrity_credential_json(
                &serde_json::json!({
                    "prepared": prepared,
                    "signature_b64": URL_SAFE_NO_PAD.encode(signature.to_bytes())
                })
                .to_string(),
            )
            .unwrap(),
        )
        .unwrap();

        let query = Arc::new(Mutex::new(None));
        let fixture = ResolverFixture {
            response: serde_json::json!({
                "ok":true,
                "organization_id":"123e4567-e89b-42d3-a456-426614174000",
                "issuer_did":issuer,
                "verification_method_id":method,
                "public_jwk":public_jwk,
                "did_document":{
                    "id":issuer,
                    "verificationMethod":[{"id":method,"controller":issuer}],
                    "assertionMethod":[method]
                },
                "verification_method":{"id":method,"controller":issuer},
                "resolver":{"type":"organization_issuer_profile","public_fallback_used":false}
            }),
            query: query.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/resolve-issuer-did", get(resolve_fixture))
                    .with_state(fixture),
            )
            .await
            .unwrap();
        });
        let resolver = OrganizationIssuerKeyResolver::new(
            format!("http://{address}"),
            "test-key".into(),
            std::time::Duration::from_secs(2),
            Vec::new(),
        )
        .unwrap();
        (credential, resolver, query, server)
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

    #[test]
    fn structured_failure_preserves_every_frozen_processing_state() {
        for status in [
            VerificationProcessingStatus::Completed,
            VerificationProcessingStatus::Error,
            VerificationProcessingStatus::Unavailable,
            VerificationProcessingStatus::Unsupported,
        ] {
            assert_eq!(
                structured_failure(status, Some(false), None).processing_status,
                status
            );
        }
    }

    #[tokio::test]
    async fn valid_signed_vds_nc_projects_a_verified_credential_proof() {
        let signing_key = P256SigningKey::from_slice(&[9_u8; 32]).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let public_jwk = serde_json::json!({
            "kty":"EC",
            "crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y":URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            "alg":"ES256"
        });
        let claims = serde_json::from_value(serde_json::json!({
            "docType":"CMC",
            "issuingCountry":"AUS",
            "documentNumber":"X123456",
            "surname":"EXAMPLE",
            "givenNames":"ADA",
            "dateOfBirth":"19900102",
            "nationality":"AUS",
            "gender":"F",
            "dateOfIssue":"20260101",
            "dateOfExpiry":"20300101"
        }))
        .unwrap();
        let payload = marty_oid4vci::formats::vds_nc_profile::build_profile_payload(
            &claims,
            "CMC",
            "issuer-1",
            "issuer-1#key-1",
            "ES256",
        )
        .unwrap()
        .0;
        let signing_input = format!("DC03AUS~{payload}");
        let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        let barcode = format!("{signing_input}~{}", STANDARD.encode(signature.to_bytes()));

        let facts = NativeCredentialVerificationKernel
            .verify_vds_nc(&barcode, &public_jwk)
            .await;
        assert_eq!(facts.credential_proofs_valid, Some(true));
        assert_eq!(facts.trust_chain_valid, Some(true));
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
        assert_eq!(facts.trust_chain_valid, None);
        let outcome = canonical(&facts, &governance);
        assert_eq!(
            check_code(&outcome, "credential.proof"),
            "CREDENTIAL_PROOFS_INVALID"
        );
        assert_eq!(
            check_code(&outcome, "issuer.trust"),
            "ISSUER_TRUST_NOT_PERFORMED"
        );

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
        assert_eq!(facts.trust_chain_valid, None);
    }

    #[tokio::test]
    async fn structured_contract_preserves_unsupported_and_org_resolved_signed_vcdm_paths() {
        let kernel = NativeCredentialVerificationKernel;
        let (governance, definition) = governed_direct();
        let unsupported = serde_json::json!({
            "verifiableCredential":["compact-but-unsupported"],
            "presentation_submission":{}
        });
        let facts = kernel
            .verify_structured_presentation(
                unsupported.as_object().unwrap(),
                &definition,
                "did:web:verifier.example",
                &governance,
                &RejectingResolver,
            )
            .await;
        assert_eq!(
            facts.processing_status,
            VerificationProcessingStatus::Unsupported
        );
        let outcome = canonical(&facts, &governance);
        assert_eq!(outcome["processing_status"], "UNSUPPORTED");
        assert_eq!(
            check_code(&outcome, "credential.proof"),
            "CREDENTIAL_PROOFS_INVALID"
        );
        assert_eq!(
            check_code(&outcome, "issuer.trust"),
            "ISSUER_TRUST_NOT_PERFORMED"
        );

        let (credential, resolver, query, server) = signed_credential_and_org_resolver().await;
        let invalid_structure = serde_json::json!({
            "verifiableCredential":[credential.clone()],
            "presentation_submission":{}
        });
        let facts = kernel
            .verify_structured_presentation(
                invalid_structure.as_object().unwrap(),
                &definition,
                "did:web:verifier.example",
                &governance,
                &resolver,
            )
            .await;
        assert_eq!(facts.presentation_structure_valid, Some(false));
        assert_eq!(facts.credential_proofs_valid, None);
        assert_eq!(facts.trust_chain_valid, None);
        let outcome = canonical(&facts, &governance);
        assert_eq!(
            check_code(&outcome, "presentation.structure"),
            "PRESENTATION_STRUCTURE_INVALID"
        );
        assert_eq!(
            check_code(&outcome, "credential.proof"),
            "CREDENTIAL_PROOF_NOT_PERFORMED"
        );
        assert_eq!(
            check_code(&outcome, "issuer.trust"),
            "ISSUER_TRUST_NOT_PERFORMED"
        );

        let valid_structure = serde_json::json!({
            "verifiableCredential":[credential],
            "presentation_submission":{
                "id":"submission-1",
                "definition_id":"pd-1",
                "descriptor_map":[{
                    "id":"employee",
                    "format":"ldp_vc",
                    "path":"$"
                }]
            }
        });
        let mut valid_definition = definition.clone();
        valid_definition.input_descriptors[0]
            .insert("constraints".into(), serde_json::json!({"fields":[]}));
        let core_definition =
            serde_json::from_value(serde_json::to_value(&valid_definition).unwrap()).unwrap();
        let core_submission =
            serde_json::from_value(valid_structure["presentation_submission"].clone()).unwrap();
        let structural =
            VerificationEngine::new("did:web:verifier.example", "did:web:verifier.example")
                .verify_presentation_structure(&core_definition, &core_submission);
        assert!(structural.check_valid, "{:?}", structural.errors);
        let facts = kernel
            .verify_structured_presentation(
                valid_structure.as_object().unwrap(),
                &valid_definition,
                "did:web:verifier.example",
                &governance,
                &resolver,
            )
            .await;
        server.abort();
        assert_eq!(facts.credential_proofs_valid, Some(true));
        assert_eq!(facts.presentation_structure_valid, Some(true));
        assert_eq!(facts.trust_chain_valid, Some(true));
        let query = query.lock().unwrap().clone().unwrap();
        assert!(query.contains("verification_method_id="));
        assert!(!query.contains("credential_format="));
        assert!(!query.contains("key_purpose="));
    }
}
