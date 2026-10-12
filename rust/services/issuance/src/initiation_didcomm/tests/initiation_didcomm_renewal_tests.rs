// A fast composition proof for renewal admission through the real DIDComm
// policy, resolution, endpoint and envelope owners. Process/SQL/HTTP delivery
// remain the responsibility of the published Canvas acceptance cases.
use super::*;
use crate::{
    credential_renewal::{
        CredentialRenewalService, RenewalRepository, RenewalRepositoryError, RenewalSource,
    },
    initiation::{
        IdempotencyBinding, InitiationApplicationClaimsResolver, InitiationClientRepository,
        InitiationClock, InitiationDependencyError, InitiationOrganizationValidator,
        InitiationPorts, InitiationRegisteredClient, InitiationRelatedResourceValidator,
        InitiationRepository, InitiationRepositoryError, InitiationReservation,
        InitiationRevocationProfileValidator, InitiationSeed, InitiationSeedGenerator,
        InitiationService, InitiationTemplate, InitiationTemplateResolver, OrganizationValidation,
    },
    initiation_http::InitiationHttpService,
    initiation_response::InitiationOfferProjector,
};
use axum::http::{HeaderMap, HeaderValue};
use chrono::DateTime;

const SOURCE_ID: &str = "renewal-source-credential";
const TEMPLATE_ID: &str = "template-a";
const ENDPOINT: &str = "https://127.0.0.1/didcomm";

struct RenewalGraphPorts {
    source: RenewalSource,
    source_transaction: CredentialTransaction,
    reserved: Mutex<Option<CredentialTransaction>>,
    issuer_did: String,
    now: DateTime<Utc>,
}

#[async_trait]
impl RenewalRepository for RenewalGraphPorts {
    async fn source(&self, id: &str) -> Result<Option<RenewalSource>, RenewalRepositoryError> {
        assert_eq!(id, SOURCE_ID);
        Ok(Some(self.source.clone()))
    }

    async fn source_transaction(
        &self,
        source: &RenewalSource,
    ) -> Result<Option<CredentialTransaction>, RenewalRepositoryError> {
        assert_eq!(source, &self.source);
        Ok(Some(self.source_transaction.clone()))
    }

    async fn bind_reservation(
        &self,
        transaction: &CredentialTransaction,
        source: &RenewalSource,
        application_id: Option<&str>,
    ) -> Result<CredentialTransaction, RenewalRepositoryError> {
        assert_eq!(source, &self.source);
        assert_eq!(application_id, None);
        assert_eq!(self.reserved.lock().unwrap().as_ref(), Some(transaction));
        let mut bound = transaction.clone();
        bound.renewal_of_credential_id = Some(SOURCE_ID.to_owned());
        *self.reserved.lock().unwrap() = Some(bound.clone());
        Ok(bound)
    }
}

#[async_trait]
impl InitiationRepository for RenewalGraphPorts {
    async fn recover_idempotently(
        &self,
        _: &str,
        _: &IdempotencyBinding,
    ) -> Result<Option<CredentialTransaction>, InitiationRepositoryError> {
        Ok(None)
    }

    async fn reserve_idempotently(
        &self,
        transaction: &CredentialTransaction,
    ) -> Result<InitiationReservation, InitiationRepositoryError> {
        assert!(self.reserved.lock().unwrap().is_none());
        *self.reserved.lock().unwrap() = Some(transaction.clone());
        Ok(InitiationReservation {
            transaction: transaction.clone(),
            created: true,
        })
    }
}

#[async_trait]
impl InitiationOrganizationValidator for RenewalGraphPorts {
    async fn validate(&self, organization: &str) -> OrganizationValidation {
        assert_eq!(organization, "org-a");
        OrganizationValidation::Found
    }
}

#[async_trait]
impl InitiationClientRepository for RenewalGraphPorts {
    async fn get(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
        panic!("renewal must not resolve a client")
    }
}

#[async_trait]
impl InitiationTemplateResolver for RenewalGraphPorts {
    async fn resolve(&self, id: &str) -> Result<InitiationTemplate, InitiationDependencyError> {
        assert_eq!(id, TEMPLATE_ID);
        Ok(InitiationTemplate {
            credential_type: "EmployeeCredential".to_owned(),
            issuer_did: Some(self.issuer_did.clone()),
            issuer_algorithm: Some("ES256".to_owned()),
            wallet_configs: vec![json!({
                "wallet_id": "didcomm",
                "format_variant": "didcomm_v2"
            })],
            renewable: true,
            renewal_window_days: 7,
            ..InitiationTemplate::default()
        })
    }
}

#[async_trait]
impl InitiationRevocationProfileValidator for RenewalGraphPorts {
    async fn validate_active(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        Ok(())
    }
}

#[async_trait]
impl InitiationApplicationClaimsResolver for RenewalGraphPorts {
    async fn resolve(&self, _: &str) -> Result<Option<Map<String, Value>>, ()> {
        panic!("renewal must not resolve application claims")
    }
}

#[async_trait]
impl InitiationRelatedResourceValidator for RenewalGraphPorts {
    async fn validate(&self, _: &Value) -> Result<(), InitiationDependencyError> {
        panic!("renewal has no related document")
    }
}

impl InitiationSeedGenerator for RenewalGraphPorts {
    fn generate(&self) -> InitiationSeed {
        InitiationSeed {
            transaction_id: "00000000-0000-0000-0000-000000000013".to_owned(),
            pre_authorized_code: "renewal-code".to_owned(),
        }
    }
}

impl InitiationClock for RenewalGraphPorts {
    fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

#[async_trait]
impl IssuerContextResolver for RenewalGraphPorts {
    async fn resolve(
        &self,
        _: &CredentialTransaction,
        _: &str,
        _: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        Ok(IssuerContext {
            issuer_did: self.issuer_did.clone(),
            verification_method_id: Some(format!("{}#signing-1", self.issuer_did)),
            ..issuer()
        })
    }
}

struct RenewalGraphLifecycle {
    delivery: Arc<Mutex<Option<InitiationDidcommDeliveryState>>>,
    completed: AtomicUsize,
}

#[async_trait]
impl CredentialLifecycle for RenewalGraphLifecycle {
    async fn ensure_ready(
        &self,
        _: &CredentialTransaction,
        _: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        Ok(())
    }

    async fn allocate_status(
        &self,
        _: &CredentialTransaction,
        _: &str,
        _: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        Ok(AllocatedCredentialStatus::default())
    }

    async fn after_issued(
        &self,
        _: &CredentialTransaction,
        _: &IssuedCredential,
        _: &str,
    ) -> Result<(), CredentialIssuanceError> {
        panic!("DIDComm delivery must not use OID4VCI lifecycle")
    }

    async fn after_didcomm_issued(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        endpoint: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        assert_eq!(endpoint, ENDPOINT);
        assert!(!message_id.is_empty());
        assert_eq!(
            transaction.renewal_of_credential_id.as_deref(),
            Some(SOURCE_ID)
        );
        assert_eq!(credential.transaction_id, transaction.id);
        let mut delivery = self.delivery.lock().unwrap();
        let Some(InitiationDidcommDeliveryState::Pending(pending)) = delivery.as_ref() else {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        };
        assert!(pending.transported);
        *delivery = Some(InitiationDidcommDeliveryState::Delivered(
            DeliveredInitiationDidcommDelivery {
                transaction_id: transaction.id.clone(),
                organization_id: transaction.organization_id.clone(),
                credential_id: credential.id.clone(),
                holder_did: pending.delivery.holder_did.clone(),
                service_endpoint: endpoint.to_owned(),
                message_id: message_id.to_owned(),
            },
        ));
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct RenewalGraphTransport {
    messages: Mutex<Vec<String>>,
}

#[async_trait]
impl DidcommTransportPort for RenewalGraphTransport {
    async fn deliver(
        &self,
        endpoint: &ValidatedDidcommEndpoint,
        encrypted_message: String,
    ) -> DidcommTransportOutcome {
        assert_eq!(endpoint.as_str(), ENDPOINT);
        self.messages.lock().unwrap().push(encrypted_message);
        DidcommTransportOutcome::Delivered
    }
}

#[tokio::test]
async fn renewal_private_ip_matrix_composes_real_didcomm_policy_and_crypto() {
    // Real ingress/DB/Redis and HTTP transport are retained by the Canvas
    // published-schema cases. The remote-less authcrypt branch must refuse
    // issuance; packaged Canvas and live OpenBao prove positive authcrypt.
    for authenticated in [false, true] {
        for allow_private_ips in [false, true] {
            let sender = shared_fixtures::document_with_public(
                "did:web:issuer.example",
                &URL_SAFE_NO_PAD.encode([1_u8; 32]),
            );
            let (_, recipient_secret) = shared_fixtures::holder_with_id("did:example:holder");
            let policy_directory = tempfile::tempdir().unwrap();
            let policy_path = policy_directory
                .path()
                .join("didcomm-encryption-policy.json");
            let key_reference = format!("didcomm/keys/org-a/sender/versions/{}", "a".repeat(32));
            let mode = if authenticated {
                json!({"mode":"authcrypt","sender_key_ref":key_reference})
            } else {
                json!({"mode":"anoncrypt"})
            };
            std::fs::write(
                &policy_path,
                json!({"version":1,"issuers":{(sender.id.clone()):mode}}).to_string(),
            )
            .unwrap();
            let policy_file = policy_path.to_str().unwrap();
            assert_eq!(
                matches!(
                    load_active_policy(Some(&policy_path), &sender.id).unwrap(),
                    ActiveEncryptionPolicy::Authcrypt(_)
                ),
                authenticated
            );
            let service = json!({
                "id": "#didcomm-1",
                "type": "DIDCommMessaging",
                "serviceEndpoint": ENDPOINT,
            });
            let holder_did = format!(
                "did:peer:2.E{SYNTHETIC_RECIPIENT_MULTIBASE}.S{}",
                URL_SAFE_NO_PAD.encode(service.to_string())
            );
            let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
            let mut source_transaction = transaction();
            source_transaction.renewable = true;
            source_transaction.renewal_window_days = 7;
            source_transaction.issuer_did = Some(sender.id.clone());
            source_transaction.subject_did = Some(holder_did.clone());
            source_transaction.delivery_mode = "wallet_only".to_owned();
            let source = RenewalSource {
                id: SOURCE_ID.to_owned(),
                organization_id: source_transaction.organization_id.clone(),
                transaction_id: source_transaction.id.clone(),
                credential_template_id: TEMPLATE_ID.to_owned(),
                applicant_id: None,
                subject_did: Some(holder_did.clone()),
                status: "active".to_owned(),
                renewed_to_credential_id: None,
                expires_at: Some(now + chrono::Duration::days(1)),
            };
            let graph = Arc::new(RenewalGraphPorts {
                source,
                source_transaction,
                reserved: Mutex::new(None),
                issuer_did: sender.id.clone(),
                now,
            });

            let order = Arc::new(Mutex::new(Vec::new()));
            let native_repository = Arc::new(HarnessRepository::new(order.clone()));
            let lifecycle = Arc::new(RenewalGraphLifecycle {
                delivery: native_repository.delivery.clone(),
                completed: AtomicUsize::new(0),
            });
            let transport = Arc::new(RenewalGraphTransport::default());
            let envelope = NativeDidcommEnvelope::new(None, None, Some(policy_file));
            let delivery = Arc::new(
                NativeInitiationDidcommDelivery::new(
                    NativeInitiationDidcommPorts {
                        repository: native_repository.clone(),
                        issuer_resolver: graph.clone(),
                        builder: Arc::new(HarnessBuilder {
                            order: order.clone(),
                            fail: false,
                        }),
                        lifecycle: lifecycle.clone(),
                        envelope: Arc::new(envelope),
                        endpoints: Arc::new(DidcommEndpointValidator::new(allow_private_ips)),
                        transport: transport.clone(),
                    },
                    "https://issuer.example",
                )
                .unwrap(),
            );
            let initiation = InitiationService::new(
                InitiationPorts {
                    repository: graph.clone(),
                    organizations: graph.clone(),
                    clients: graph.clone(),
                    templates: graph.clone(),
                    revocation_profiles: graph.clone(),
                    applications: graph.clone(),
                    related_resources: graph.clone(),
                    issuer_resolver: graph.clone(),
                    seeds: graph.clone(),
                    clock: graph.clone(),
                },
                "https://issuer.example",
            )
            .unwrap();
            let renewal = CredentialRenewalService::new(
                graph.clone(),
                InitiationHttpService::new(
                    initiation,
                    InitiationOfferProjector::new("https://issuer.example", delivery).unwrap(),
                    Some("renewal-key"),
                ),
                Some("renewal-key"),
                graph.clone(),
            );
            let mut headers = HeaderMap::new();
            headers.insert("X-API-Key", HeaderValue::from_static("renewal-key"));
            headers.insert("X-Organization-ID", HeaderValue::from_static("org-a"));
            let response = renewal.renew(&headers, SOURCE_ID).await.unwrap();
            assert_eq!(response.source_credential_id, SOURCE_ID);
            // Renewal admission persists its reservation in all four cases;
            // private-IP refusal must stop only irreversible native issuance
            // and delivery, while returning the existing pending offer.
            assert_eq!(
                graph
                    .reserved
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .renewal_of_credential_id
                    .as_deref(),
                Some(SOURCE_ID)
            );
            let messages = transport.messages.lock().unwrap().clone();
            if allow_private_ips && !authenticated {
                assert_eq!(
                    response.credential_offer_uris["didcomm"],
                    format!("didcomm://{ENDPOINT}")
                );
                assert_eq!(messages.len(), 1, "exactly one native transport call");
                assert_eq!(lifecycle.completed.load(Ordering::SeqCst), 1);
                assert_eq!(native_repository.finalizations.load(Ordering::SeqCst), 1);
                assert!(matches!(
                    native_repository.delivery.lock().unwrap().as_ref(),
                    Some(InitiationDidcommDeliveryState::Delivered(_))
                ));
                let plaintext =
                    shared_fixtures::holder_decrypt_anoncrypt(&messages[0], &recipient_secret);
                let packed: Value = serde_json::from_str(&plaintext).unwrap();
                assert_eq!(packed["to"], json!([holder_did]));
                assert_eq!(packed["from"], sender.id);
                assert!(order.lock().unwrap().contains(&"build"));
            } else {
                assert_eq!(
                    response.credential_offer_uris["didcomm"],
                    format!(
                        "didcomm://pending?transaction_id={}",
                        response.transaction_id
                    )
                );
                assert!(messages.is_empty());
                assert!(
                    order.lock().unwrap().is_empty(),
                    "denied delivery precedes claim/materialization"
                );
                assert_eq!(lifecycle.completed.load(Ordering::SeqCst), 0);
                assert_eq!(native_repository.finalizations.load(Ordering::SeqCst), 0);
                assert!(native_repository.delivery.lock().unwrap().is_none());
                assert_eq!(
                    *native_repository.transport_claim.lock().unwrap(),
                    HarnessTransportClaimState::Idle,
                    "private-IP or missing remote KMS must not acquire a send fence"
                );
            }
        }
    }
}
