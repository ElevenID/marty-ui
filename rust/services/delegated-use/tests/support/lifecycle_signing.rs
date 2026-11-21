//! Three purpose-separated managed keys behind the actual Signing Keys HTTPS
//! owner. Registry credentials use the existing remote envelope; grants use
//! real per-origin OpenBao HMACs and the Redis one-use verifier.
use std::{fs, path::PathBuf};

use marty_credential_template::CredentialTemplate;
use marty_signing_grant::{
    delegated_decision::{KEY_PURPOSE, PROFILE_FORMAT, WIRE_FORMAT},
    replay::RedisGrantReplayStore,
    verifier::GrantVerifier,
};
use marty_signing_keys::{
    documents::{DidVerificationRelationship, DocumentStore, PublishDidRequest},
    kms::{public_key, ProviderRequest},
    profiles::ProfileStore,
    registry::RegistryStore,
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use uuid::Uuid;

use super::live_support::{setting, Server, READ_KEY, SIGN_KEY};
use crate::support::{crypto::REQUEST_ISSUER, TestResult};

#[path = "../../../signing-keys/tests/support/disposable_backends.rs"]
mod disposable_backends;
#[path = "lifecycle_issuance.rs"]
mod issuance;
pub use issuance::IssuedMachineCredential;

pub struct KeyIdentity {
    pub issuer: String,
    pub kid: String,
    pub key: String,
    pub jwk: Value,
    pub service_id: String,
}

/// The receipt fields deliberately match the startup-only fixture so the same
/// production host environment assembly can be used by both qualifications.
pub struct SigningKeys {
    pub server: Server,
    pub issuer: String,
    pub kid: String,
    pub key: String,
    pub jwk: Value,
    pub request: KeyIdentity,
    pub credential: KeyIdentity,
}

struct KeyConfiguration {
    identity: KeyIdentity,
    service: Value,
    purpose: &'static str,
    profile_format: &'static str,
    domain: &'static str,
    fragment: &'static str,
}

impl SigningKeys {
    pub async fn start(organization: Uuid) -> TestResult<Self> {
        if setting("MARTY_TEST_DELEGATED_USE_LIFECYCLE") != "true" {
            return Err("isolated lifecycle custody is required".into());
        }
        let redis = disposable_backends::disposable_redis_url().await;
        let envelope = disposable_backends::disposable_openbao_envelope().await;
        let endpoint = setting("MARTY_TEST_OPENBAO_URL");
        let request = KeyConfiguration::load(
            "request",
            REQUEST_ISSUER.to_owned(),
            "delegated-host.example.test",
            "request-key",
            "MARTY_TEST_LIFECYCLE_REQUEST_KEY",
            "MARTY_TEST_LIFECYCLE_REQUEST_SIGNER_TOKEN_FILE",
            "oid4vp_request_signing",
            "VC_JWT",
            "oauth-authz-req+jwt",
            &endpoint,
        )
        .await?;
        let credential = KeyConfiguration::load(
            "machine",
            format!(
                "did:web:machine-issuer.example.test:orgs:{}",
                organization.simple()
            ),
            "machine-issuer.example.test",
            "machine-key",
            "MARTY_TEST_LIFECYCLE_CREDENTIAL_KEY",
            "MARTY_TEST_LIFECYCLE_CREDENTIAL_SIGNER_TOKEN_FILE",
            "vc_jwt_issuer",
            "VC_JWT",
            "jwt_vc_json",
            &endpoint,
        )
        .await?;
        let receipt = KeyConfiguration::load(
            "receipt",
            format!("did:web:receipt.example:orgs:{}", organization.simple()),
            "receipt.example",
            "receipt-key",
            "MARTY_TEST_RECEIPT_ES256_KEY",
            "MARTY_TEST_RECEIPT_SIGNER_TOKEN_FILE",
            KEY_PURPOSE,
            PROFILE_FORMAT,
            WIRE_FORMAT,
            &endpoint,
        )
        .await?;
        assert_ne!(request.identity.key, receipt.identity.key);
        assert_ne!(request.identity.key, credential.identity.key);
        assert_ne!(receipt.identity.key, credential.identity.key);
        assert_ne!(request.identity.jwk, receipt.identity.jwk);
        assert_ne!(request.identity.jwk, credential.identity.jwk);
        assert_ne!(receipt.identity.jwk, credential.identity.jwk);

        let registry = RegistryStore::connect(&redis)
            .await?
            .with_auth_envelopes(Some(envelope));
        let mut key_purposes = Map::new();
        for selected in [&request, &credential, &receipt] {
            key_purposes.insert(
                selected.identity.service_id.clone(),
                json!({(selected.identity.key.clone()): [selected.purpose]}),
            );
        }
        registry
            .save(
                &organization.to_string(),
                &json!({
                    "services":[request.service,credential.service,receipt.service],
                    "default_service_id":credential.identity.service_id,
                    "key_reference_purposes":key_purposes
                }),
            )
            .await?;
        let profiles = ProfileStore::from_connection(registry.connection());
        let documents = DocumentStore::from_connection(registry.connection());
        for selected in [&request, &credential, &receipt] {
            selected
                .publish(organization, &profiles, &documents)
                .await?;
        }
        let verifier = GrantVerifier::for_managed_openbao_with_delegated_decisions(
            &endpoint,
            PathBuf::from(setting("MARTY_TEST_LIFECYCLE_VERIFY_TOKEN_FILE")),
            RedisGrantReplayStore::new(registry.connection()),
            true,
        )?;
        let router = marty_signing_keys::http::router_with_all_keys_and_grants(
            READ_KEY.into(),
            None,
            Some(SIGN_KEY.into()),
            None,
            None,
            None,
            false,
            Some(registry),
            Some(documents),
            None,
            Some(profiles),
            None,
            None,
            Some(verifier),
        );
        Ok(Self {
            server: Server::https(router).await?,
            issuer: receipt.identity.issuer,
            kid: receipt.identity.kid,
            key: receipt.identity.key,
            jwk: receipt.identity.jwk,
            request: request.identity,
            credential: credential.identity,
        })
    }

    pub async fn issue_machine_credential(
        &self,
        pool: &PgPool,
        organization: Uuid,
        template: &CredentialTemplate,
        subject: &str,
        machine_key: &SigningKey,
    ) -> TestResult<IssuedMachineCredential> {
        issuance::issue(self, pool, organization, template, subject, machine_key).await
    }
}

impl KeyConfiguration {
    #[allow(clippy::too_many_arguments)]
    async fn load(
        name: &str,
        issuer: String,
        domain: &'static str,
        fragment: &'static str,
        key_setting: &str,
        token_setting: &str,
        purpose: &'static str,
        profile_format: &'static str,
        wire_format: &'static str,
        endpoint: &str,
    ) -> TestResult<Self> {
        let key = setting(key_setting);
        let service_id = format!("lifecycle-{name}-custody");
        let service = json!({
            "id":service_id,"name":service_id,"service_type":"custom-transit-compatible",
            "provider":"openbao","endpoint":endpoint,"ca_cert_file":setting("BAO_CACERT"),
            "mount":"transit","auth_mode":"token",
            "auth_reference":fs::read_to_string(setting(token_setting))?,
            "key_reference":key,"algorithm":"ES256","algorithms":["ES256"],
            "key_purposes":[purpose],"credential_formats":[wire_format]
        });
        let metadata = public_key(ProviderRequest {
            service_config: service.clone(),
        })
        .await?;
        let mut jwk = metadata.get("public_jwk").unwrap_or(&metadata).clone();
        jwk.as_object_mut()
            .ok_or("provider public JWK missing")?
            .retain(|name, _| matches!(name.as_str(), "kty" | "crv" | "x" | "y"));
        if jwk["kty"] != "EC"
            || jwk["crv"] != "P-256"
            || jwk["x"].as_str().is_none()
            || jwk["y"].as_str().is_none()
        {
            return Err("custody returned an unexpected mathematical key".into());
        }
        Ok(Self {
            identity: KeyIdentity {
                kid: format!("{issuer}#{fragment}"),
                issuer,
                key,
                jwk,
                service_id,
            },
            service,
            purpose,
            profile_format,
            domain,
            fragment,
        })
    }

    async fn publish(
        &self,
        organization: Uuid,
        profiles: &ProfileStore,
        documents: &DocumentStore,
    ) -> TestResult<()> {
        let selected = &self.identity;
        let profile = format!("{}-profile", selected.service_id);
        profiles
            .put(
                &organization.to_string(),
                &profile,
                json!({
                    "id":profile,"organization_id":organization,"status":"active",
                    "issuer_did":selected.issuer,"verification_method_id":selected.kid,
                    "signing_service_id":selected.service_id,"signing_key_reference":selected.key,
                    "credential_format":self.profile_format,"key_purpose":self.purpose,
                    "algorithm":"ES256","issuer_mode":"org_managed"
                }),
            )
            .await?;
        documents
            .publish_did(
                &organization.to_string(),
                &selected.service_id,
                PublishDidRequest {
                    jwk: selected.jwk.clone(),
                    public_domain: self.domain.into(),
                    did_id: Some(selected.issuer.clone()),
                    org_slug: None,
                    fragment: Some(self.fragment.into()),
                    key_reference: Some(selected.key.clone()),
                    cert_pem: None,
                    cert_chain_pem: None,
                    relationship: DidVerificationRelationship::AssertionMethod,
                },
            )
            .await?;
        Ok(())
    }
}
