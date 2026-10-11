//! Atomic one-use consumption for an OpenBao-verified signing grant.

use redis::aio::ConnectionManager;
use thiserror::Error;

use crate::{bound_input, payload_digest, GrantBinding, GrantClaims, SigningOrigin, VerifiedGrant};

const KEY_PREFIX: &str = "marty:issuer-signing-grant:used:v1:";
const MAX_REPLAY_TTL_SECONDS: i128 = 66;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReplayError {
    #[error("signing grant has expired")]
    Expired,
    #[error("signing grant was already used")]
    AlreadyUsed,
    #[error("signing grant replay store is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct RedisGrantReplayStore {
    connection: ConnectionManager,
}

/// Created only after OpenBao verification and atomic one-use consumption.
/// Move this value into the KMS signing kernel; it cannot be cloned or forged.
pub struct ConsumedGrant {
    claims: GrantClaims,
}

/// The operation actually submitted to a remote signing provider. The origin
/// and operation ID come from the consumed grant, never from this input.
#[derive(Clone, Copy)]
pub struct FinalSignBinding<'a> {
    pub organization_id: &'a str,
    pub route: &'a str,
    pub service_id: Option<&'a str>,
    pub issuer_did: Option<&'a str>,
    pub key_reference: Option<&'a str>,
    pub key_purpose: &'a str,
    pub algorithm: &'a str,
    pub payload: &'a [u8],
}

/// A CSR signing operation approved from one consumed Gateway grant after
/// deriving the exact CSR bytes from the selected remote public key.
pub struct ApprovedServiceCsrSign {
    organization_id: String,
    route: String,
    service_id: String,
    key_reference: String,
    algorithm: String,
    payload_sha256_b64: String,
    expires_at: i64,
}

/// Move-only authority for a managed issuer CSR. Gateway authorizes the
/// public identity; Signing Keys selects and binds the actual remote key.
pub struct ApprovedIssuerCsrSign {
    organization_id: String,
    route: String,
    issuer_did: String,
    key_reference: String,
    key_purpose: String,
    algorithm: String,
    payload_sha256_b64: String,
    expires_at: i64,
}

impl ApprovedIssuerCsrSign {
    pub fn authorizes(self, actual: &FinalSignBinding<'_>) -> bool {
        chrono::Utc::now().timestamp() <= self.expires_at
            && self.organization_id == actual.organization_id
            && self.route == actual.route
            && actual.service_id.is_none()
            && Some(self.issuer_did.as_str()) == actual.issuer_did
            && Some(self.key_reference.as_str()) == actual.key_reference
            && self.key_purpose == actual.key_purpose
            && self.algorithm == actual.algorithm
            && self.payload_sha256_b64 == payload_digest(actual.payload)
    }
}

impl ApprovedServiceCsrSign {
    pub fn authorizes(self, actual: &FinalSignBinding<'_>) -> bool {
        chrono::Utc::now().timestamp() <= self.expires_at
            && self.organization_id == actual.organization_id
            && self.route == actual.route
            && Some(self.service_id.as_str()) == actual.service_id
            && actual.issuer_did.is_none()
            && Some(self.key_reference.as_str()) == actual.key_reference
            && actual.key_purpose == "x509_csr"
            && self.algorithm == actual.algorithm
            && self.payload_sha256_b64 == payload_digest(actual.payload)
    }
}

impl ConsumedGrant {
    /// Recheck the exact operation at the point of KMS use, including expiry.
    /// Consuming the proof prevents a caller from using one grant for two signs.
    pub fn authorizes(self, binding: &GrantBinding<'_>) -> bool {
        bound_input(&self.claims, binding, chrono::Utc::now().timestamp()).is_ok()
    }

    /// Consume the proof at the provider boundary after key and algorithm
    /// resolution, so a route-level check cannot authorize changed bytes.
    pub fn authorizes_final(self, actual: &FinalSignBinding<'_>) -> bool {
        let binding = GrantBinding {
            origin: self.claims.origin,
            operation_id: &self.claims.operation_id,
            organization_id: actual.organization_id,
            route: actual.route,
            service_id: actual.service_id,
            issuer_did: actual.issuer_did,
            key_reference: actual.key_reference,
            key_purpose: actual.key_purpose,
            algorithm: actual.algorithm,
            payload: actual.payload,
        };
        bound_input(&self.claims, &binding, chrono::Utc::now().timestamp()).is_ok()
    }

    pub fn approve_service_csr(
        self,
        intent: &GrantBinding<'_>,
        actual: &FinalSignBinding<'_>,
    ) -> Option<ApprovedServiceCsrSign> {
        if self.claims.origin != SigningOrigin::GatewayService
            || !intent.route.ends_with("/certificate-csr")
            || intent.key_purpose != "x509_csr"
            || bound_input(&self.claims, intent, chrono::Utc::now().timestamp()).is_err()
            || actual.organization_id != intent.organization_id
            || actual.route != intent.route
            || actual.service_id != intent.service_id
            || actual.issuer_did.is_some()
            || actual.key_reference != intent.key_reference
            || actual.key_purpose != "x509_csr"
            || actual.algorithm != intent.algorithm
        {
            return None;
        }
        Some(ApprovedServiceCsrSign {
            organization_id: actual.organization_id.to_owned(),
            route: actual.route.to_owned(),
            service_id: actual.service_id?.to_owned(),
            key_reference: actual.key_reference?.to_owned(),
            algorithm: actual.algorithm.to_owned(),
            payload_sha256_b64: payload_digest(actual.payload),
            expires_at: self.claims.expires_at,
        })
    }

    pub fn approve_issuer_csr(
        self,
        intent: &GrantBinding<'_>,
        actual: &FinalSignBinding<'_>,
    ) -> Option<ApprovedIssuerCsrSign> {
        if self.claims.origin != SigningOrigin::GatewayIssuerDid
            || intent.route != "/v1/signing-keys/issuer-identities/certificate-csr"
            || intent.service_id.is_some()
            || intent.key_reference.is_some()
            || !matches!(intent.key_purpose, "csca" | "x509_doc_signer")
            || bound_input(&self.claims, intent, chrono::Utc::now().timestamp()).is_err()
            || actual.organization_id != intent.organization_id
            || actual.route != intent.route
            || actual.service_id.is_some()
            || actual.issuer_did != intent.issuer_did
            || actual.key_reference.is_none()
            || actual.key_purpose != intent.key_purpose
            || actual.algorithm != intent.algorithm
        {
            return None;
        }
        Some(ApprovedIssuerCsrSign {
            organization_id: actual.organization_id.to_owned(),
            route: actual.route.to_owned(),
            issuer_did: actual.issuer_did?.to_owned(),
            key_reference: actual.key_reference?.to_owned(),
            key_purpose: actual.key_purpose.to_owned(),
            algorithm: actual.algorithm.to_owned(),
            payload_sha256_b64: payload_digest(actual.payload),
            expires_at: self.claims.expires_at,
        })
    }
}

impl RedisGrantReplayStore {
    pub fn new(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    /// Atomically records the grant before KMS signing. A failed sign still
    /// consumes the grant; the authorized origin must start a new operation.
    pub async fn consume(&self, verified: &VerifiedGrant) -> Result<ConsumedGrant, ReplayError> {
        self.consume_at(verified, chrono::Utc::now().timestamp())
            .await
    }

    async fn consume_at(
        &self,
        verified: &VerifiedGrant,
        now_seconds: i64,
    ) -> Result<ConsumedGrant, ReplayError> {
        let ttl = i128::from(verified.expires_at()) - i128::from(now_seconds) + 1;
        if !(1..=MAX_REPLAY_TTL_SECONDS).contains(&ttl) {
            return Err(ReplayError::Expired);
        }
        let mut connection = self.connection.clone();
        let result: Option<String> = redis::cmd("SET")
            .arg(format!("{KEY_PREFIX}{}", verified.nonce()))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl as u64)
            .query_async(&mut connection)
            .await
            .map_err(|_| ReplayError::Unavailable)?;
        match result.as_deref() {
            Some("OK") => Ok(ConsumedGrant {
                claims: verified.claims.clone(),
            }),
            None => Err(ReplayError::AlreadyUsed),
            _ => Err(ReplayError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::{IssuerCsrIntent, ServiceCsrIntent};

    #[test]
    fn issuer_csr_approval_binds_resolved_key_and_generated_bytes() {
        let now = chrono::Utc::now().timestamp();
        let csr: IssuerCsrIntent = serde_json::from_str(
            r#"{"issuer_did":"did:web:example.test:issuer","key_purpose":"csca","credential_format":"MDOC","algorithm":"ES256","country":"US","organization":"Example","common_name":"Issuer"}"#,
        )
        .unwrap();
        let payload = csr.bound_payload();
        let route = "/v1/signing-keys/issuer-identities/certificate-csr";
        let claims = GrantClaims {
            version: 1,
            origin: SigningOrigin::GatewayIssuerDid,
            operation_id: "gateway-csr-1".into(),
            organization_id: "tenant-1".into(),
            route: route.into(),
            service_id: None,
            issuer_did: Some(csr.issuer_did.clone()),
            key_reference: None,
            key_purpose: csr.key_purpose.clone(),
            algorithm: csr.algorithm.clone(),
            payload_sha256_b64: payload_digest(&payload),
            issued_at: now,
            expires_at: now + 30,
            nonce: "0123456789abcdef0123456789abcdef".into(),
        };
        let intent = GrantBinding {
            origin: SigningOrigin::GatewayIssuerDid,
            operation_id: "gateway-csr-1",
            organization_id: "tenant-1",
            route,
            service_id: None,
            issuer_did: Some(&csr.issuer_did),
            key_reference: None,
            key_purpose: &csr.key_purpose,
            algorithm: &csr.algorithm,
            payload: &payload,
        };
        let actual = FinalSignBinding {
            organization_id: "tenant-1",
            route,
            service_id: None,
            issuer_did: Some(&csr.issuer_did),
            key_reference: Some("resolved-remote-key"),
            key_purpose: "csca",
            algorithm: "ES256",
            payload: b"generated CSR signing bytes",
        };
        let approved = ConsumedGrant {
            claims: claims.clone(),
        }
        .approve_issuer_csr(&intent, &actual)
        .unwrap();
        assert!(approved.authorizes(&actual));
        let approved = ConsumedGrant {
            claims: claims.clone(),
        }
        .approve_issuer_csr(&intent, &actual)
        .unwrap();
        assert!(!approved.authorizes(&FinalSignBinding {
            payload: b"changed CSR bytes",
            ..actual
        }));
        assert!(ConsumedGrant { claims }
            .approve_issuer_csr(
                &intent,
                &FinalSignBinding {
                    issuer_did: Some("did:web:other.test:issuer"),
                    ..actual
                }
            )
            .is_none());
    }

    #[test]
    fn csr_approval_rechecks_generated_bytes_at_final_sign() {
        let now = chrono::Utc::now().timestamp();
        let csr: ServiceCsrIntent = serde_json::from_str(
            r#"{"country":"US","organization":"Example","common_name":"example.invalid","key_reference":"key-1","algorithm":"ES256"}"#,
        )
        .unwrap();
        let bound_payload = csr.bound_payload();
        let route = "/v1/signing-keys/services/service-1/certificate-csr";
        let claims = GrantClaims {
            version: 1,
            origin: SigningOrigin::GatewayService,
            operation_id: "gateway-request-1".into(),
            organization_id: "tenant-1".into(),
            route: route.into(),
            service_id: Some("service-1".into()),
            issuer_did: None,
            key_reference: Some("key-1".into()),
            key_purpose: "x509_csr".into(),
            algorithm: "ES256".into(),
            payload_sha256_b64: payload_digest(&bound_payload),
            issued_at: now,
            expires_at: now + 30,
            nonce: "0123456789abcdef0123456789abcdef".into(),
        };
        let intent = GrantBinding {
            origin: SigningOrigin::GatewayService,
            operation_id: "gateway-request-1",
            organization_id: "tenant-1",
            route,
            service_id: Some("service-1"),
            issuer_did: None,
            key_reference: Some("key-1"),
            key_purpose: "x509_csr",
            algorithm: "ES256",
            payload: &bound_payload,
        };
        let final_sign = FinalSignBinding {
            organization_id: "tenant-1",
            route,
            service_id: Some("service-1"),
            issuer_did: None,
            key_reference: Some("key-1"),
            key_purpose: "x509_csr",
            algorithm: "ES256",
            payload: b"generated CSR signing bytes",
        };
        let approved = ConsumedGrant {
            claims: claims.clone(),
        }
        .approve_service_csr(&intent, &final_sign)
        .unwrap();
        assert!(approved.authorizes(&final_sign));
        let approved = ConsumedGrant {
            claims: claims.clone(),
        }
        .approve_service_csr(&intent, &final_sign)
        .unwrap();
        assert!(!approved.authorizes(&FinalSignBinding {
            payload: b"different CSR bytes",
            ..final_sign
        }));
        assert!(ConsumedGrant { claims }
            .approve_service_csr(
                &intent,
                &FinalSignBinding {
                    key_reference: Some("other-key"),
                    ..final_sign
                }
            )
            .is_none());
    }

    #[test]
    fn final_sign_rechecks_resolved_key_and_actual_bytes() {
        let now = chrono::Utc::now().timestamp();
        let claims = GrantClaims {
            version: 1,
            origin: SigningOrigin::GatewayService,
            operation_id: "operation-1".into(),
            organization_id: "tenant-1".into(),
            route: "/v1/signing-keys/services/managed-openbao-transit/sign".into(),
            service_id: Some("managed-openbao-transit".into()),
            issuer_did: None,
            key_reference: Some("tenant-key-1".into()),
            key_purpose: "vc_jwt_issuer".into(),
            algorithm: "ES256".into(),
            payload_sha256_b64: payload_digest(b"exact payload"),
            issued_at: now,
            expires_at: now + 30,
            nonce: "0123456789abcdef0123456789abcdef".into(),
        };
        let actual = FinalSignBinding {
            organization_id: "tenant-1",
            route: "/v1/signing-keys/services/managed-openbao-transit/sign",
            service_id: Some("managed-openbao-transit"),
            issuer_did: None,
            key_reference: Some("tenant-key-1"),
            key_purpose: "vc_jwt_issuer",
            algorithm: "ES256",
            payload: b"exact payload",
        };
        assert!(ConsumedGrant {
            claims: claims.clone()
        }
        .authorizes_final(&actual));
        for changed in [
            FinalSignBinding {
                key_reference: Some("tenant-key-2"),
                ..actual
            },
            FinalSignBinding {
                payload: b"different payload",
                ..actual
            },
            FinalSignBinding {
                organization_id: "tenant-2",
                ..actual
            },
            FinalSignBinding {
                algorithm: "ES384",
                ..actual
            },
        ] {
            assert!(!ConsumedGrant {
                claims: claims.clone()
            }
            .authorizes_final(&changed));
        }
    }

    #[test]
    fn final_issuer_sign_rejects_a_different_did_or_purpose() {
        let now = chrono::Utc::now().timestamp();
        let claims = GrantClaims {
            version: 1,
            origin: SigningOrigin::FlowWalletRequest,
            operation_id: "wallet-request-1".into(),
            organization_id: "tenant-1".into(),
            route: "/internal/compat/issuer-dids/sign".into(),
            service_id: None,
            issuer_did: Some("did:web:issuer.example".into()),
            key_reference: Some("issuer-key-1".into()),
            key_purpose: "oid4vp_request_signing".into(),
            algorithm: "ES256".into(),
            payload_sha256_b64: payload_digest(b"request object"),
            issued_at: now,
            expires_at: now + 30,
            nonce: "0123456789abcdef0123456789abcdef".into(),
        };
        let actual = FinalSignBinding {
            organization_id: "tenant-1",
            route: "/internal/compat/issuer-dids/sign",
            service_id: None,
            issuer_did: Some("did:web:issuer.example"),
            key_reference: Some("issuer-key-1"),
            key_purpose: "oid4vp_request_signing",
            algorithm: "ES256",
            payload: b"request object",
        };
        assert!(ConsumedGrant {
            claims: claims.clone()
        }
        .authorizes_final(&actual));
        assert!(!ConsumedGrant {
            claims: claims.clone()
        }
        .authorizes_final(&FinalSignBinding {
            issuer_did: Some("did:web:other.example"),
            ..actual
        }));
        assert!(
            !ConsumedGrant { claims }.authorizes_final(&FinalSignBinding {
                key_purpose: "vc_jwt_issuer",
                ..actual
            })
        );
    }

    #[tokio::test]
    #[ignore = "requires marked disposable loopback Redis DB 13 or higher"]
    async fn concurrent_consumers_cannot_both_reach_kms() {
        let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
        let parsed = reqwest::Url::parse(&url).expect("Redis URL");
        assert!(matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "::1")
        ));
        assert!(parsed
            .path()
            .trim_start_matches('/')
            .parse::<u8>()
            .is_ok_and(|db| db >= 13));
        let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE").expect("guard nonce");
        assert!(nonce.len() >= 16);
        let client = redis::Client::open(url.as_str()).expect("Redis URL");
        let mut connection = client
            .get_connection_manager()
            .await
            .expect("disposable Redis connection");
        let observed: Option<String> = redis::cmd("GET")
            .arg("marty:tests:disposable-guard")
            .query_async(&mut connection)
            .await
            .expect("disposable marker");
        assert_eq!(observed.as_deref(), Some(nonce.as_str()));
        let store = RedisGrantReplayStore::new(connection);
        let grant = VerifiedGrant {
            claims: GrantClaims {
                version: 1,
                origin: SigningOrigin::GatewayService,
                operation_id: "disposable-operation".into(),
                organization_id: "disposable-org".into(),
                route: "/v1/signing-keys/services/service-1/sign".into(),
                service_id: Some("service-1".into()),
                issuer_did: None,
                key_reference: None,
                key_purpose: "vc_jwt_issuer".into(),
                algorithm: "ES256".into(),
                payload_sha256_b64: payload_digest(b"exact.payload"),
                issued_at: 1_700_000_000,
                expires_at: 1_700_000_030,
                nonce,
            },
        };
        let now = 1_700_000_000;
        let (a, b) = tokio::join!(store.consume_at(&grant, now), store.consume_at(&grant, now));
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(
            matches!(a, Err(ReplayError::AlreadyUsed))
                || matches!(b, Err(ReplayError::AlreadyUsed))
        );
        assert!(matches!(
            store.consume_at(&grant, now).await,
            Err(ReplayError::AlreadyUsed)
        ));
        assert!(matches!(
            store.consume_at(&grant, 1_700_000_031).await,
            Err(ReplayError::Expired)
        ));
    }
}
