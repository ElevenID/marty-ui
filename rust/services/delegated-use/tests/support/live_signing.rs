//! Actual Signing Keys registry, document/profile owners, grant verifier and
//! remote provider adapter, served over real keyless HTTPS. This gate only
//! resolves the receipt key; it deliberately does not claim a signing workflow.
use std::{fs, path::PathBuf};

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
use serde_json::{json, Value};
use uuid::Uuid;

use super::live_support::{setting, Server, READ_KEY, SIGN_KEY};
use crate::support::TestResult;

#[path = "../../../signing-keys/tests/support/disposable_backends.rs"]
mod disposable_backends;

pub struct SigningKeys {
    pub server: Server,
    pub issuer: String,
    pub kid: String,
    pub key: String,
    pub jwk: Value,
}

impl SigningKeys {
    pub async fn start(organization: Uuid) -> TestResult<Self> {
        let redis = disposable_backends::disposable_redis_url().await;
        let envelope = disposable_backends::disposable_openbao_envelope().await;
        let endpoint = setting("MARTY_TEST_OPENBAO_URL");
        let key = setting("MARTY_TEST_RECEIPT_ES256_KEY");
        let issuer = format!("did:web:receipt.example:orgs:{}", organization.simple());
        let kid = format!("{issuer}#receipt-key");
        let service_id = "live-startup-receipt-custody";
        let service = json!({
            "id":service_id,"name":service_id,"service_type":"custom-transit-compatible",
            "provider":"openbao","endpoint":endpoint,"ca_cert_file":setting("BAO_CACERT"),
            "mount":"transit","auth_mode":"token",
            "auth_reference":fs::read_to_string(setting("MARTY_TEST_RECEIPT_SIGNER_TOKEN_FILE"))?,
            "key_reference":key,"algorithm":"ES256","algorithms":["ES256"],
            "key_purposes":[KEY_PURPOSE],"credential_formats":[WIRE_FORMAT]
        });
        let metadata = public_key(ProviderRequest {
            service_config: service.clone(),
        })
        .await?;
        let mut jwk = metadata.get("public_jwk").unwrap_or(&metadata).clone();
        // The host selects a closed mathematical public key, not resolver metadata.
        jwk.as_object_mut()
            .ok_or("provider public JWK missing")?
            .retain(|name, _| matches!(name.as_str(), "kty" | "crv" | "x" | "y"));
        let registry = RegistryStore::connect(&redis)
            .await?
            .with_auth_envelopes(Some(envelope));
        registry
            .save(
                &organization.to_string(),
                &json!({
                    "services":[service],"default_service_id":service_id,
                    "key_reference_purposes":{(service_id):{(key.clone()):[KEY_PURPOSE]}}
                }),
            )
            .await?;
        let profiles = ProfileStore::from_connection(registry.connection());
        profiles.put(&organization.to_string(), "receipt-profile", json!({
            "id":"receipt-profile","organization_id":organization,"status":"active",
            "issuer_did":issuer,"verification_method_id":kid,"signing_service_id":service_id,
            "signing_key_reference":key,"credential_format":PROFILE_FORMAT,"key_purpose":KEY_PURPOSE,
            "algorithm":"ES256","issuer_mode":"org_managed"
        })).await?;
        let documents = DocumentStore::from_connection(registry.connection());
        documents
            .publish_did(
                &organization.to_string(),
                service_id,
                PublishDidRequest {
                    jwk: jwk.clone(),
                    public_domain: "receipt.example".into(),
                    did_id: Some(issuer.clone()),
                    org_slug: None,
                    fragment: Some("receipt-key".into()),
                    key_reference: Some(key.clone()),
                    cert_pem: None,
                    cert_chain_pem: None,
                    relationship: DidVerificationRelationship::AssertionMethod,
                },
            )
            .await?;
        let verifier = GrantVerifier::for_managed_openbao_with_delegated_decisions(
            &endpoint,
            PathBuf::from(setting("MARTY_TEST_RECEIPT_VERIFY_TOKEN_FILE")),
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
            issuer,
            kid,
            key,
            jwk,
        })
    }
}
