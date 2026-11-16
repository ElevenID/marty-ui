//! Explicit managed producer authority and exact, fresh owner request evidence.
//! A producer base is an identity check, never a callback-prefix permission.
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    ComplianceStatus, TrustProfile, TrustProfileApplicationError, TrustProfileStatus, TrustPurpose,
    TrustSource, TrustSourceType,
};

pub mod transport;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFlowVerifier {
    /// Selects an operator-configured fixed owner transport; never an URL.
    pub producer_id: String,
    pub public_base_url: String,
    pub verifier_did: String,
    pub request_key_id: String,
    pub public_jwk: Value,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// Deserialized only from the fixed workload-authenticated Flow owner response.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FlowOwnerRequest {
    contract: String,
    organization_id: String,
    instance_id: String,
    request_uri: String,
    client_id: String,
    request_key_id: String,
    public_jwk: Value,
    compact_request_jws: String,
    request_jws_sha256: String,
    response_uri: String,
    nonce: String,
    request_issued_at: DateTime<Utc>,
    request_expires_at: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

fn invalid() -> TrustProfileApplicationError {
    TrustProfileApplicationError::Invalid("managed_flow_verifier")
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn canonical_base(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    text(value)
        && !value.contains('*')
        && url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !value.ends_with('/')
        && url.as_str().trim_end_matches('/') == value
}

pub(crate) fn registration(
    source: &TrustSource,
) -> Result<ManagedFlowVerifier, TrustProfileApplicationError> {
    if source.source_type != TrustSourceType::ManagedFlowVerifier
        || source.id.is_nil()
        || source.purposes.as_deref() != Some(&[TrustPurpose::PresentationVerifier])
        || source.url.is_some()
        || source.certificate_pem.is_some()
        || source.issuer_did.is_some()
        || !source.pinned_certificates.is_empty()
        || source.registry_sync.is_some()
        || source.registry_sync_token.is_some()
        || source.registry_sequence != 0
        || !source.registry_entries.is_empty()
        || source.registry_last_synced_at.is_some()
        || source.extensions.len() != 1
    {
        return Err(invalid());
    }
    let value = source
        .extensions
        .get("managed_flow_verifier")
        .ok_or_else(invalid)?;
    crate::reject_private_custody_metadata(value)?;
    let value: ManagedFlowVerifier =
        serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if !text(&value.producer_id)
        || value.producer_id.len() > 128
        || !value
            .producer_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || !canonical_base(&value.public_base_url)
        || !text(&value.verifier_did)
        || !["did:web:", "did:jwk:", "did:key:"].iter().any(|prefix| {
            value
                .verifier_did
                .strip_prefix(prefix)
                .is_some_and(|value| !value.is_empty())
        })
        || value
            .verifier_did
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '?' | '#' | '/'))
        || !text(&value.request_key_id)
        || value
            .request_key_id
            .strip_prefix(&format!("{}#", value.verifier_did))
            .is_none_or(str::is_empty)
        || value.valid_until <= value.valid_from
        || value.valid_from.timestamp_subsec_nanos() != 0
        || value.valid_until.timestamp_subsec_nanos() != 0
    {
        return Err(invalid());
    }
    crate::registered_verifier::validate_public_request_key(
        &value.public_jwk,
        &value.request_key_id,
    )?;
    Ok(value)
}

/// Select only an explicitly active managed source. Registered plain clients,
/// credential issuers and machine-identity sources cannot supply this authority.
pub(crate) fn select(
    profile: &TrustProfile,
    organization_id: &str,
    client_id: &str,
    now: DateTime<Utc>,
) -> Result<(uuid::Uuid, ManagedFlowVerifier), TrustProfileApplicationError> {
    crate::registered_verifier::validate_profile_policy(profile)?;
    if profile.id.is_nil()
        || profile.organization_id != organization_id
        || !text(organization_id)
        || profile.status != TrustProfileStatus::Active
        || profile.compliance_status != ComplianceStatus::Compliant
        || !profile
            .trust_purposes
            .as_ref()
            .is_some_and(|p| p.contains(&TrustPurpose::PresentationVerifier))
    {
        return Err(invalid());
    }
    let mut clients = std::collections::BTreeSet::new();
    let mut selected = None;
    for source in profile
        .trust_sources
        .iter()
        .filter(|s| s.source_type == TrustSourceType::ManagedFlowVerifier)
    {
        let value = registration(source)?;
        let client = format!("decentralized_identifier:{}", value.verifier_did);
        if !clients.insert(client.clone()) {
            return Err(invalid());
        }
        if source.enabled
            && client == client_id
            && value.valid_from <= now
            && now < value.valid_until
        {
            selected = Some((source.id, value));
        }
    }
    selected.ok_or_else(invalid)
}

/// Locator parsing is selection only. Its complete canonical value must equal
/// the server-derived request URI before any owner call or authority projection.
pub(crate) fn instance_for_locator(
    registration: &ManagedFlowVerifier,
    locator: &str,
) -> Result<String, TrustProfileApplicationError> {
    let prefix = format!("{}/v1/flows/instances/", registration.public_base_url);
    let instance = locator
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix("/request"))
        .ok_or_else(invalid)?;
    let id = uuid::Uuid::parse_str(instance).map_err(|_| invalid())?;
    if id.is_nil() || id.to_string() != instance {
        return Err(invalid());
    }
    Ok(instance.to_owned())
}

pub(crate) fn project(
    profile: &TrustProfile,
    organization_id: &str,
    client_id: &str,
    locator: &str,
    request: FlowOwnerRequest,
    now: DateTime<Utc>,
) -> Result<Value, TrustProfileApplicationError> {
    let (source_id, registration) = select(profile, organization_id, client_id, now)?;
    let instance_id = instance_for_locator(&registration, locator)?;
    let response_uri = format!(
        "{}/v1/flows/instances/{instance_id}/submit",
        registration.public_base_url
    );
    if request.contract != "marty.flow/wallet-verifier-request/v1"
        || request.organization_id != organization_id
        || request.instance_id != instance_id
        || request.request_uri != locator
        || request.client_id != client_id
        || request.request_key_id != registration.request_key_id
        || request.public_jwk != registration.public_jwk
        || request.response_uri != response_uri
        || !text(&request.nonce)
        || request.compact_request_jws.len() > 65536
        || request.request_jws_sha256
            != format!(
                "{:x}",
                Sha256::digest(request.compact_request_jws.as_bytes())
            )
        || request.observed_at > now
        || request.expires_at <= now
        || request.expires_at <= request.observed_at
        || request
            .observed_at
            .checked_add_signed(Duration::seconds(60))
            .is_none_or(|end| request.expires_at > end)
        || request.expires_at > request.request_expires_at
        || request.request_issued_at > now + Duration::seconds(30)
        || request.request_expires_at <= now
        || request.request_expires_at <= request.request_issued_at
        || request
            .request_issued_at
            .checked_add_signed(Duration::seconds(900))
            .is_none_or(|end| request.request_expires_at > end)
        || request.request_issued_at < registration.valid_from
        || request.request_expires_at > registration.valid_until
    {
        return Err(invalid());
    }
    // Verify the owner evidence's original bytes against the explicitly pinned
    // public key too. The wallet must still independently resolve the DID and
    // authenticate the full supported request semantics with Core.
    let verified = marty_oid4vci::jose::verify_compact_jwt_with_public_jwk(
        &request.compact_request_jws,
        &registration.public_jwk.to_string(),
        "ES256",
    )
    .map_err(|_| invalid())?;
    let claims = &verified.claims;
    if verified.header["kid"].as_str() != Some(registration.request_key_id.as_str())
        || verified.header["typ"].as_str() != Some("oauth-authz-req+jwt")
        || claims["client_id"].as_str() != Some(client_id)
        || claims["iss"].as_str() != Some(client_id)
        || claims["response_uri"].as_str() != Some(response_uri.as_str())
        || claims["nonce"].as_str() != Some(request.nonce.as_str())
        || claims["state"].as_str() != Some(instance_id.as_str())
        || claims["iat"].as_i64() != Some(request.request_issued_at.timestamp())
        || claims["exp"].as_i64() != Some(request.request_expires_at.timestamp())
        || request.request_issued_at.timestamp_subsec_nanos() != 0
        || request.request_expires_at.timestamp_subsec_nanos() != 0
    {
        return Err(invalid());
    }
    let revision = marty_oid4vp_contract::digest_domain_json(
        "marty.trust/managed-flow-verifier-authority/v2",
        &json!({
            "organization_id":profile.organization_id,"profile_id":profile.id,
            "profile_updated_at":profile.updated_at,"profile_status":profile.status,
            "compliance_status":profile.compliance_status,"trust_purposes":profile.trust_purposes,
            "validation_rules":profile.validation_rules,"trusted_assertion_formats":profile.trusted_assertion_formats,
            "time_policy":profile.time_policy,"source_id": source_id, "registration": registration,
            "instance_id": instance_id, "request_jws_sha256": request.request_jws_sha256,
            "response_uri": response_uri,
        }),
    )
    .map_err(|_| invalid())?;
    let expires_at = request
        .expires_at
        .min(registration.valid_until)
        .min(now + Duration::seconds(60));
    let result = json!({
        "contract":"marty.wallet/verifier-authority/v2", "organization_id":organization_id,
        "trust_profile_id":profile.id, "observed_at":now, "expires_at":expires_at,
        "authority": {
            "authority_id":format!("{}/{source_id}",profile.id), "revision":revision,
            "key_purpose":"oid4vp_request_signing", "algorithm":"ES256",
            "request_clock_skew_seconds":30,"max_request_lifetime_seconds":900,
            "registration": {"client_id":client_id,"request_key_id":registration.request_key_id,
                "public_jwk":registration.public_jwk,"response_uris":[response_uri],
                "valid_from":registration.valid_from,"valid_until":registration.valid_until},
        },
        "request": {"producer_id":registration.producer_id,"instance_id":instance_id,
            "request_uri":request.request_uri,"response_uri":request.response_uri,"nonce":request.nonce,
            "compact_request_jws":request.compact_request_jws,"request_jws_sha256":request.request_jws_sha256,
            "request_issued_at":request.request_issued_at,"request_expires_at":request.request_expires_at},
    });
    if serde_json::to_vec(&result).map_err(|_| invalid())?.len() > 65536 {
        return Err(invalid());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(now: DateTime<Utc>) -> TrustSource {
        let registered: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/registered-verifier-source.json"
        ))
        .unwrap();
        serde_json::from_value(json!({
            "id":uuid::Uuid::from_u128(3),"name":"Managed verifier","source_type":"MANAGED_FLOW_VERIFIER",
            "url":null,"certificate_pem":null,"issuer_did":null,"purposes":["PRESENTATION_VERIFIER"],
            "description":null,"pinned_certificates":[],"refresh_interval_hours":0,"enabled":true,
            "registry_sync":null,"registry_sync_token":null,"registry_sequence":0,"registry_entries":{},"registry_last_synced_at":null,
            "managed_flow_verifier":{"producer_id":"flow-primary","public_base_url":"https://verifier.example",
                "verifier_did":"did:web:verifier.example","request_key_id":"did:web:verifier.example#key-1",
                "public_jwk":registered["registered_verifier"]["public_jwk"],
                "valid_from":DateTime::from_timestamp(now.timestamp()-60,0).unwrap(),
                "valid_until":DateTime::from_timestamp(now.timestamp()+3600,0).unwrap()},
        })).unwrap()
    }

    fn profile(now: DateTime<Utc>) -> TrustProfile {
        TrustProfile {
            id: uuid::Uuid::from_u128(2),
            organization_id: "org-1".into(),
            name: "Managed verifiers".into(),
            description: None,
            status: TrustProfileStatus::Active,
            profile_type: crate::TrustProfileType::Custom,
            compliance_status: ComplianceStatus::Compliant,
            trust_purposes: Some(vec![TrustPurpose::PresentationVerifier]),
            trust_sources: vec![source(now)],
            validation_rules: Default::default(),
            allowed_issuers: None,
            denied_issuers: None,
            system_issuer_overrides: Default::default(),
            compatible_compliance_codes: vec![],
            verification_policy_set_id: None,
            auto_generated: false,
            revocation_policy: Default::default(),
            revocation_profile_id: None,
            time_policy: Default::default(),
            supported_formats: vec![],
            trusted_assertion_formats: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn managed_source_never_inherits_issuer_registration_or_prefix_permissions() {
        let now = Utc::now();
        let p = profile(now);
        let client = "decentralized_identifier:did:web:verifier.example";
        let (_, registered) = select(&p, "org-1", client, now).unwrap();
        let good = "https://verifier.example/v1/flows/instances/11111111-2222-4333-8444-555555555555/request";
        assert_eq!(
            instance_for_locator(&registered, good).unwrap(),
            "11111111-2222-4333-8444-555555555555"
        );
        for uri in [
            format!("{good}?next=https://attacker.example"),
            format!("{good}#fragment"),
            good.replace("verifier.example/", "verifier.example.attacker/"),
            good.replace("https:", "http:"),
            good.replace("/request", "/request/extra"),
            good.replace("11111111-2222-4333-8444-555555555555", "../other"),
            good.replace(
                "11111111-2222-4333-8444-555555555555",
                "00000000-0000-0000-0000-000000000000",
            ),
        ] {
            assert!(instance_for_locator(&registered, &uri).is_err(), "{uri}");
        }
        assert!(select(&p, "other-org", client, now).is_err());
        assert!(select(&p, "org-1", "registered-client", now).is_err());
        for field in [
            "disabled",
            "draft",
            "noncompliant",
            "issuer-purpose",
            "expired",
            "duplicate",
        ] {
            let mut p = p.clone();
            match field {
                "disabled" => p.trust_sources[0].enabled = false,
                "draft" => p.status = TrustProfileStatus::Draft,
                "noncompliant" => p.compliance_status = ComplianceStatus::NeedsAttention,
                "issuer-purpose" => p.trust_purposes = Some(vec![TrustPurpose::CredentialIssuer]),
                "expired" => {
                    p.trust_sources[0].extensions["managed_flow_verifier"]["valid_until"] =
                        json!(DateTime::from_timestamp(now.timestamp() - 1, 0).unwrap())
                }
                "duplicate" => p.trust_sources.push(p.trust_sources[0].clone()),
                _ => unreachable!(),
            }
            assert!(select(&p, "org-1", client, now).is_err(), "{field}");
        }
        for (field, value) in [
            ("producer_id", json!("https://attacker.example")),
            ("public_base_url", json!("http://verifier.example")),
            ("public_base_url", json!("https://verifier.example/*")),
            ("verifier_did", json!("registered-client")),
            ("request_key_id", json!("did:web:attacker.example#key-1")),
            ("response_uris", json!(["https://attacker.example"])),
        ] {
            let mut s = source(now);
            s.extensions["managed_flow_verifier"][field] = value;
            assert!(registration(&s).is_err(), "{field}");
        }
        let mut s = source(now);
        s.extensions["managed_flow_verifier"]["public_jwk"]["d"] = json!("private");
        assert!(registration(&s).is_err());
        let mut s = source(now);
        s.url = Some("https://attacker.example".into());
        assert!(registration(&s).is_err());
    }

    #[tokio::test]
    #[ignore = "requires the guarded real Flow HTTP/TLS-OpenBao proof"]
    async fn actual_flow_signed_proof_projects_only_exact_fresh_request_authority() {
        let nonce = std::env::var("MARTY_TEST_WALLET_REQUEST_FIXTURE_NONCE").unwrap();
        assert!(nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit()));
        let path = std::path::PathBuf::from(
            std::env::var("MARTY_TEST_WALLET_REQUEST_PROOF_FILE").unwrap(),
        );
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!("flow-owner-{nonce}.json")
        );
        let bytes = std::fs::read(path).unwrap();
        assert!(bytes.len() <= 65536);
        let proof: FlowOwnerRequest = serde_json::from_slice(&bytes).unwrap();
        let now = Utc::now();
        let mut p = profile(now);
        p.trust_sources[0].extensions["managed_flow_verifier"]["public_jwk"] =
            proof.public_jwk.clone();
        let result = project(
            &p,
            "org-1",
            &proof.client_id,
            &proof.request_uri,
            proof.clone(),
            now,
        )
        .unwrap();
        assert_eq!(result["contract"], "marty.wallet/verifier-authority/v2");
        assert_eq!(
            result["authority"]["registration"]["response_uris"],
            json!([proof.response_uri])
        );
        assert_eq!(
            result["request"]["compact_request_jws"],
            proof.compact_request_jws
        );
        let next = project(
            &p,
            "org-1",
            &proof.client_id,
            &proof.request_uri,
            proof.clone(),
            now + Duration::milliseconds(1),
        )
        .unwrap();
        assert_eq!(
            result["authority"]["revision"],
            next["authority"]["revision"]
        );
        qualify_fixed_owner_transport_and_http_races(&p, &proof, &nonce).await;
        for change in [
            "tenant",
            "instance",
            "callback",
            "key",
            "digest",
            "bytes",
            "nonce",
            "expired",
            "future",
            "clock-overflow",
        ] {
            let mut changed = proof.clone();
            match change {
                "tenant" => changed.organization_id = "other-org".into(),
                "instance" => changed.instance_id = "11111111-2222-4333-8444-555555555556".into(),
                "callback" => changed.response_uri.push_str("/attacker"),
                "key" => changed.public_jwk["x"] = json!("invalid"),
                "digest" => changed.request_jws_sha256 = "0".repeat(64),
                "bytes" => {
                    changed.compact_request_jws.push('x');
                    changed.request_jws_sha256 = format!(
                        "{:x}",
                        Sha256::digest(changed.compact_request_jws.as_bytes())
                    );
                }
                "nonce" => changed.nonce = "substituted-nonce".into(),
                "expired" => changed.expires_at = now - Duration::seconds(1),
                "future" => changed.observed_at = now + Duration::seconds(1),
                "clock-overflow" => changed.request_issued_at = DateTime::<Utc>::MAX_UTC,
                _ => unreachable!(),
            }
            assert!(
                project(
                    &p,
                    "org-1",
                    &proof.client_id,
                    &proof.request_uri,
                    changed,
                    now
                )
                .is_err(),
                "{change}"
            );
        }
        p.trust_sources[0].enabled = false;
        assert!(project(
            &p,
            "org-1",
            &proof.client_id,
            &proof.request_uri,
            proof.clone(),
            now
        )
        .is_err());
    }

    struct FixtureControlPlane(std::sync::atomic::AtomicBool);
    #[async_trait::async_trait]
    impl crate::TrustProfileControlPlane for FixtureControlPlane {
        async fn require_permission(
            &self,
            user: &str,
            organization: &str,
            _resource: &'static str,
            _action: &'static str,
        ) -> Result<(), crate::TrustAuthorizationError> {
            assert_eq!(user, "user-1");
            assert_eq!(organization, "org-1");
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                Err(crate::TrustAuthorizationError::MembershipRequired)
            } else {
                Ok(())
            }
        }
    }
    struct FixtureSynchronizer;
    #[async_trait::async_trait]
    impl crate::TrustRegistrySynchronizer for FixtureSynchronizer {
        async fn synchronize(
            &self,
            _profile: TrustProfile,
        ) -> Result<Value, crate::TrustRegistrySyncError> {
            panic!("managed verifier lookup must never synchronize issuer registries")
        }
    }

    async fn qualify_fixed_owner_transport_and_http_races(
        p: &TrustProfile,
        proof: &FlowOwnerRequest,
        nonce: &str,
    ) {
        use super::transport::FlowOwnerClient;
        use crate::TrustProfileRepository;
        use axum::{
            body::{to_bytes, Body},
            http::Request,
        };
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use tower::ServiceExt;
        let origin = std::env::var("MARTY_TEST_WALLET_FLOW_OWNER_ORIGIN").unwrap();
        let url = url::Url::parse(&origin).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(
            url.port().is_some()
                && url.path() == "/"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        );
        let token = std::env::var("MARTY_TEST_WALLET_FLOW_OWNER_TOKEN").unwrap();
        let ca = std::fs::read(std::env::var("MARTY_TEST_WALLET_FLOW_OWNER_CA").unwrap()).unwrap();
        let control = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(3))
            .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
            .build()
            .unwrap();
        let operation = |name: &str| format!("{origin}/fixture/{nonce}/{name}");
        let guard: Value = control
            .get(operation("guard"))
            .header("x-fixture-token", &token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(guard["nonce"], nonce);
        let client = FlowOwnerClient::new("flow-primary", &origin, &token, Some(&ca)).unwrap();
        let received = client
            .fetch("flow-primary", &proof.instance_id)
            .await
            .unwrap();
        assert_eq!(received.compact_request_jws, proof.compact_request_jws);
        assert!(client
            .fetch("another-producer", &proof.instance_id)
            .await
            .is_err());
        for index in 1..=6 {
            let id = format!("00000000-0000-4000-8000-{index:012}");
            assert!(
                client.fetch("flow-primary", &id).await.is_err(),
                "negative TLS response vector {index}"
            );
        }
        assert!(
            FlowOwnerClient::new("flow-primary", &origin, &"w".repeat(32), Some(&ca))
                .unwrap()
                .fetch("flow-primary", &proof.instance_id)
                .await
                .is_err()
        );
        assert!(FlowOwnerClient::new("flow-primary", &origin, &token, None)
            .unwrap()
            .fetch("flow-primary", &proof.instance_id)
            .await
            .is_err());
        assert!(FlowOwnerClient::new(
            "flow-primary",
            &origin.replace("127.0.0.1", "localhost"),
            &token,
            Some(&ca)
        )
        .unwrap()
        .fetch("flow-primary", &proof.instance_id)
        .await
        .is_err());
        let repository = Arc::new(crate::MemoryTrustProfileRepository::default());
        repository.save_profile(p, None).await.unwrap();
        let permissions = Arc::new(FixtureControlPlane(AtomicBool::new(false)));
        let service_token = uuid::Uuid::new_v4().to_string();
        let app = crate::trust_credential_authority_router(crate::TrustProfileHttpState {
            flow_owner: Some(Arc::new(client)),
            repository: repository.clone(),
            application: Arc::new(crate::TrustProfileApplication::new(
                repository.clone(),
                permissions.clone(),
            )),
            service_authenticator: Arc::new(
                mmf_security::ServiceTokenAuthenticator::new(Some(service_token.clone()), true)
                    .unwrap(),
            ),
            internal_api_key: None,
            registry_synchronizer: Arc::new(FixtureSynchronizer),
        });
        let mut route = url::Url::parse("https://fixture.invalid").unwrap();
        route.set_path(&format!(
            "/internal/v1/trust-profiles/{}/wallet-managed-verifier-authority",
            p.id
        ));
        route
            .query_pairs_mut()
            .append_pair("organization_id", "org-1")
            .append_pair("client_id", &proof.client_id)
            .append_pair("request_uri", &proof.request_uri);
        let route = format!("{}?{}", route.path(), route.query().unwrap());
        let request = || {
            Request::get(&route)
                .header("x-service-token", &service_token)
                .header("x-user-id", "user-1")
                .body(Body::empty())
                .unwrap()
        };
        let success = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(success.status(), 200);
        assert_eq!(success.headers()["cache-control"], "no-store");
        let response: Value =
            serde_json::from_slice(&to_bytes(success.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(
            response["request"]["compact_request_jws"],
            proof.compact_request_jws
        );
        for change in ["producer", "disabled", "membership"] {
            repository.save_profile(p, None).await.unwrap();
            permissions.0.store(false, Ordering::SeqCst);
            control
                .get(operation("arm"))
                .header("x-fixture-token", &token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
            let pending = tokio::spawn(app.clone().oneshot(request()));
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let state: Value = control
                    .get(operation("pending"))
                    .header("x-fixture-token", &token)
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if state["pending"] == true {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "owned owner never received pending lookup"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            let mut changed = p.clone();
            changed.updated_at = Utc::now();
            let status = match change {
                "producer" => {
                    changed.trust_sources[0].extensions["managed_flow_verifier"]["producer_id"] =
                        json!("replacement-producer");
                    409
                }
                "disabled" => {
                    changed.trust_sources[0].enabled = false;
                    422
                }
                "membership" => {
                    permissions.0.store(true, Ordering::SeqCst);
                    403
                }
                _ => unreachable!(),
            };
            repository.save_profile(&changed, None).await.unwrap();
            control
                .get(operation("release"))
                .header("x-fixture-token", &token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
            let denied = tokio::time::timeout(std::time::Duration::from_secs(15), pending)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(denied.status().as_u16(), status, "{change}");
            let bytes = to_bytes(denied.into_body(), 65536).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(&proof.compact_request_jws));
        }
    }
}
