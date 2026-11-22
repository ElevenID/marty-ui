//! Ephemeral signing fixtures. No production constructor selects these keys.
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_delegated_authority::{
    DelegatedDecisionReceiptSigner, DelegatedReceiptSigningError, DelegatedReceiptSigningKey,
    DelegatedReceiptSigningRequest, Principal, DELEGATED_DECISION_JWS_PURPOSE,
};
use marty_flow::{
    CredentialTemplateProvider, CredentialTemplateReference, FlowProviderError,
    FlowProviderRegistry, FlowReference, FlowReferenceKind, FlowReferenceProvider,
    PresentationEvaluationRequest, PresentationEvaluationResult, PresentationPolicyProvider,
    PresentationPolicyReference, SigningIdentity, SigningIdentityProvider, SigningRequest,
    SigningResult,
};
use marty_oid4vp_contract::{jwt_vc_profile::JwtVcSecuringProfile, FrozenPolicyIdentity};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use uuid::Uuid;

pub const REQUEST_ISSUER: &str = "did:web:delegated-host.example.test";
pub const REQUEST_KEY: &str = "fixture-managed-request-key";
pub const RECEIPT_ISSUER: &str = "did:web:receipt.delegated-host.example.test";
pub const RECEIPT_KEY: &str = "did:web:receipt.delegated-host.example.test#receipt";
pub const PRESENTATION_POLICY: &str = "host-machine-presentation";
pub const CREDENTIAL_TEMPLATE: &str = "host-machine-template";

pub fn signing_key() -> SigningKey {
    loop {
        let mut seed = [0_u8; 32];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut seed)
            .unwrap();
        if let Ok(key) = SigningKey::from_slice(&seed) {
            return key;
        }
    }
}

pub fn public_jwk(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_sec1_point(false);
    json!({
        "kty":"EC","crv":"P-256",
        "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())
    })
}

pub fn compact_jws(key: &SigningKey, header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.normalize_s().to_bytes())
    )
}

/// The remote presentation/template/reference responses are test-owned frozen
/// inputs. These ports never produce a delegated authorization decision.
pub struct FlowPorts {
    pub organization: Uuid,
    pub principal_id: String,
    pub credential_issuer: String,
    pub credential_public_jwk: Value,
    pub key: SigningKey,
    pub calls: AtomicUsize,
}

impl FlowPorts {
    pub fn registry(self: &Arc<Self>) -> FlowProviderRegistry {
        FlowProviderRegistry {
            presentation_policy: Some(self.clone()),
            credential_template: Some(self.clone()),
            signing_identity: Some(self.clone()),
            reference_catalog: Some(self.clone()),
            ..Default::default()
        }
    }
    fn unavailable(provider: &'static str) -> FlowProviderError {
        FlowProviderError::Unavailable { provider }
    }
}

#[async_trait]
impl PresentationPolicyProvider for FlowPorts {
    async fn configuration_digest(&self, id: &str) -> Result<String, FlowProviderError> {
        if id != PRESENTATION_POLICY {
            return Err(Self::unavailable("presentation_policy"));
        }
        Ok(format!("sha256:{}", "93".repeat(32)))
    }

    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        if id != PRESENTATION_POLICY {
            return Err(Self::unavailable("presentation_policy"));
        }
        Ok(PresentationPolicyReference {
            id: id.into(),
            organization_id: self.organization.to_string(),
            status: "active".into(),
            holder_binding_required: true,
            prerequisite_evidence_profile: None,
            credential_authority: None,
            policy_revision: FrozenPolicyIdentity {
                id: id.into(),
                version: 1,
                content_digest: format!("sha256:{}", "93".repeat(32)),
            },
            credential_requirements: vec![json!({
                "id":"machine", "credential_template_id":CREDENTIAL_TEMPLATE,
                "expected_securing_profile":JwtVcSecuringProfile::MartyNestedVc2JwtV1,
                "credential_payload_format":"VC_JWT",
                "required":true,"requested_claims":[]
            })],
        })
    }

    async fn evaluate(
        &self,
        _: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        panic!("the real delegated machine and Cedar owners must evaluate this operation")
    }
}

#[async_trait]
impl CredentialTemplateProvider for FlowPorts {
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        if id != CREDENTIAL_TEMPLATE {
            return Err(Self::unavailable("credential_template"));
        }
        Ok(CredentialTemplateReference {
            id: id.into(),
            organization_id: self.organization.to_string(),
            status: "active".into(),
            credential_type: "MachineCredential".into(),
            vct: String::new(),
            doctype: String::new(),
            supported_formats: vec!["VC_JWT".into()],
            claims: vec![],
            issuer_did: self.credential_issuer.clone(),
            credential_format: "jwt_vc".into(),
            jwt_vc_profile: None,
            issuance_protocol: "OID4VCI_PRE_AUTH".into(),
            wallet_configurations: vec![],
            issuer_algorithm: Some("ES256".into()),
        })
    }

    async fn wallet_formats(&self, organization: &str) -> Result<Vec<String>, FlowProviderError> {
        if organization != self.organization.to_string() {
            return Err(Self::unavailable("credential_template"));
        }
        Ok(vec!["VC_JWT".into()])
    }
}

#[async_trait]
impl SigningIdentityProvider for FlowPorts {
    async fn resolve(
        &self,
        organization: &str,
        issuer: &str,
        purpose: &str,
        format: &str,
        algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        if organization != self.organization.to_string()
            || algorithm.is_some_and(|value| value != "ES256")
        {
            return Err(Self::unavailable("signing_identity"));
        }
        if issuer == self.credential_issuer && purpose == "vc_jwt_issuer" && format == "jwt_vc_json"
        {
            // Flow validates the referenced credential template's public key
            // selection. This fixture exposes its real bootstrap public key
            // only; the serving path cannot sign a new machine credential.
            return Ok(SigningIdentity {
                organization_id: organization.into(),
                issuer_did: issuer.into(),
                verification_method_id: format!("{issuer}#credential"),
                signing_key_reference: "fixture-credential-public-selection-only".into(),
                public_jwk: serde_json::from_value(self.credential_public_jwk.clone()).unwrap(),
                key_purpose: purpose.into(),
                credential_format: format.into(),
                algorithm: "ES256".into(),
            });
        }
        if issuer != REQUEST_ISSUER
            || purpose != "oid4vp_request_signing"
            || format != "oauth-authz-req+jwt"
        {
            return Err(Self::unavailable("signing_identity"));
        }
        Ok(SigningIdentity {
            organization_id: organization.into(),
            issuer_did: issuer.into(),
            verification_method_id: format!("{issuer}#request"),
            signing_key_reference: REQUEST_KEY.into(),
            public_jwk: serde_json::from_value::<BTreeMap<_, _>>(public_jwk(&self.key)).unwrap(),
            key_purpose: purpose.into(),
            credential_format: format.into(),
            algorithm: "ES256".into(),
        })
    }

    async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        let identity = SigningIdentityProvider::resolve(
            self,
            &request.organization_id,
            &request.issuer_did,
            &request.key_purpose,
            &request.credential_format,
            Some(&request.algorithm),
        )
        .await?;
        if request.verification_method_id != identity.verification_method_id
            || request.signing_key_reference != REQUEST_KEY
            || Uuid::parse_str(&request.operation_id).is_err()
        {
            return Err(Self::unavailable("signing_identity"));
        }
        let input = URL_SAFE_NO_PAD
            .decode(&request.payload_b64url)
            .map_err(|_| Self::unavailable("signing_identity"))?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let signature: Signature = self.key.sign(&input);
        Ok(SigningResult {
            issuer_did: identity.issuer_did,
            verification_method_id: identity.verification_method_id,
            algorithm: identity.algorithm,
            signature_raw_b64url: URL_SAFE_NO_PAD.encode(signature.normalize_s().to_bytes()),
        })
    }
}

#[async_trait]
impl FlowReferenceProvider for FlowPorts {
    async fn resolve(
        &self,
        kind: FlowReferenceKind,
        id: &str,
        principal: &str,
        organization: &str,
    ) -> Result<FlowReference, FlowProviderError> {
        if organization != self.organization.to_string()
            || principal != self.principal_id
            || !matches!(id, PRESENTATION_POLICY | CREDENTIAL_TEMPLATE)
        {
            return Err(Self::unavailable("reference_catalog"));
        }
        Ok(FlowReference {
            kind,
            id: id.into(),
            organization_id: Some(organization.into()),
            status: "active".into(),
            system_owned: false,
        })
    }
}

pub struct ReceiptSigner {
    pub organization: Uuid,
    pub issuer: Principal,
    pub key: SigningKey,
    pub calls: AtomicUsize,
}

#[async_trait]
impl DelegatedDecisionReceiptSigner for ReceiptSigner {
    async fn resolve_key(
        &self,
        organization: Uuid,
        issuer: &Principal,
        purpose: &'static str,
    ) -> Result<DelegatedReceiptSigningKey, DelegatedReceiptSigningError> {
        if organization != self.organization
            || issuer != &self.issuer
            || purpose != DELEGATED_DECISION_JWS_PURPOSE
        {
            return Err(DelegatedReceiptSigningError);
        }
        Ok(DelegatedReceiptSigningKey {
            issuer: issuer.clone(),
            purpose: purpose.into(),
            key_id: RECEIPT_KEY.into(),
            algorithm: "ES256".into(),
        })
    }

    async fn sign(
        &self,
        request: DelegatedReceiptSigningRequest,
    ) -> Result<Vec<u8>, DelegatedReceiptSigningError> {
        if request.organization_id != self.organization
            || request.key.issuer != self.issuer
            || request.key.purpose != DELEGATED_DECISION_JWS_PURPOSE
            || request.key.key_id != RECEIPT_KEY
            || request.key.algorithm != "ES256"
        {
            return Err(DelegatedReceiptSigningError);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let signature: Signature = self.key.sign(&request.signing_input);
        Ok(signature.normalize_s().to_bytes().to_vec())
    }
}
