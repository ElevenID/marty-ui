use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mmf_security::constant_time_secret_eq;
use rand::RngCore;
use serde_json::{json, Map, Value};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use tracing::error;
use uuid::Uuid;

use crate::{
    credential::{
        CredentialAuthorizationSession, CredentialIssuanceError, CredentialRepository,
        CredentialTransaction, CredentialTransactionStatus, ExistingCredential, IssuedCredential,
    },
    credential_lifecycle::delivery_record_id,
    initiation::{
        IdempotencyBinding, InitiationRepository, InitiationRepositoryError, InitiationReservation,
    },
    initiation_didcomm::{
        DeliveredInitiationDidcommDelivery, InitiationDidcommClaim, InitiationDidcommDeliveryState,
        InitiationDidcommRepository, PendingInitiationDidcommDelivery,
        StagedInitiationDidcommDelivery,
    },
    token_postgres::hash_access_token,
};

macro_rules! transaction_columns {
    () => {
        "id, organization_id, credential_template_id, revocation_profile_id,
     renewal_of_credential_id, applicant_id, application_id, subject_did,
     idempotency_key_hash, idempotency_request_hash, status,
     pre_auth_code, c_nonce, claims, credential_type, selective_disclosure_claims,
     zk_predicate_claims, credential_payload_format, wallet_configs, validity_days,
     renewable, renewal_window_days, delivery_mode, issuer_profile_id,
     issuer_mode, issuer_did_override, issuer_algorithm, signing_service_id,
     reserved_credential_id, oid4vci_client_id, created_at, expires_at"
    };
}

macro_rules! transaction_query {
    ($condition:literal) => {
        concat!(
            "SELECT ",
            transaction_columns!(),
            " FROM issuance_service.issuance_transactions WHERE ",
            $condition
        )
    };
}

const TRANSACTION_BY_ACCESS_TOKEN: &str = transaction_query!("access_token = $1");
const TRANSACTION_BY_PRE_AUTH_CODE: &str = transaction_query!("pre_auth_code = $1");
const TRANSACTION_BY_ID: &str = transaction_query!("id = $1");
const TRANSACTION_BY_ID_AND_ORGANIZATION: &str =
    transaction_query!("id = $1 AND organization_id = $2");
const TRANSACTION_BY_IDEMPOTENCY: &str =
    transaction_query!("organization_id = $1 AND idempotency_key_hash = $2");
const CLAIM_FOR_SIGNING: &str = concat!(
    "UPDATE issuance_service.issuance_transactions
     SET status = 'signing', reserved_credential_id = $2, credential_type = $3,
         issuer_profile_id = $4, issuer_mode = $5, issuer_did_override = $6,
         issuer_algorithm = $7, signing_service_id = $8
     WHERE id = $1 AND status = 'authorized'
     RETURNING ",
    transaction_columns!()
);

const CLAIM_FOR_DIDCOMM: &str = concat!(
    "UPDATE issuance_service.issuance_transactions
     SET status = 'signing', reserved_credential_id = $2, credential_type = $3,
         issuer_profile_id = $4, issuer_mode = $5, issuer_did_override = $6,
         issuer_algorithm = $7, signing_service_id = $8
     WHERE id = $1 AND organization_id = $9 AND status = $10
     RETURNING ",
    transaction_columns!()
);

const RESERVE_INITIATION: &str = concat!(
    "INSERT INTO issuance_service.issuance_transactions
         (id, organization_id, credential_template_id, revocation_profile_id,
          renewal_of_credential_id, applicant_id, application_id, subject_did,
          idempotency_key_hash, idempotency_request_hash, status, pre_auth_code,
          c_nonce, claims, credential_type, selective_disclosure_claims,
          zk_predicate_claims, credential_payload_format, wallet_configs,
          validity_days, renewable, renewal_window_days, delivery_mode,
          issuer_profile_id, issuer_mode, issuer_did_override, issuer_algorithm,
          signing_service_id, reserved_credential_id, oid4vci_client_id,
          created_at, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
             $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25,
             $26, $27, $28, $29, $30, $31, $32)
     ON CONFLICT (organization_id, idempotency_key_hash) DO NOTHING
     RETURNING ",
    transaction_columns!()
);

#[derive(Clone)]
pub struct PostgresCredentialRepository {
    pool: PgPool,
    token_hmac_key: Arc<[u8]>,
}

impl std::fmt::Debug for PostgresCredentialRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCredentialRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresCredentialRepository {
    #[must_use]
    pub fn new(pool: PgPool, token_hmac_key: impl AsRef<[u8]>) -> Self {
        Self {
            pool,
            token_hmac_key: Arc::from(token_hmac_key.as_ref()),
        }
    }

    async fn transaction_by_query(
        &self,
        query: &'static str,
        value: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        sqlx::query(query)
            .bind(value)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()
    }

    async fn active_issuer_identity(
        &self,
        organization_id: &str,
        credential_type: &str,
    ) -> Result<(String, String), CredentialIssuanceError> {
        let row = sqlx::query(
            "SELECT issuer_did, issuer_algorithm
             FROM credential_template_service.credential_templates
             WHERE organization_id = $1
               AND status IN ('active', 'draft')
               AND credential_type = $2
             ORDER BY CASE WHEN status = 'active' THEN 0 ELSE 1 END, updated_at DESC
             LIMIT 1",
        )
        .bind(organization_id)
        .bind(credential_type)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .ok_or_else(|| missing_issuer_identity(credential_type))?;
        let issuer_did = get::<Option<String>>(&row, "issuer_did")?
            .unwrap_or_default()
            .trim()
            .to_owned();
        let algorithm = get::<Option<String>>(&row, "issuer_algorithm")?
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !issuer_did.starts_with("did:")
            || !matches!(algorithm.as_str(), "ES256" | "ES384" | "RS256" | "EdDSA")
        {
            return Err(missing_issuer_identity(credential_type));
        }
        Ok((issuer_did, algorithm))
    }
}

#[async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn transaction_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        self.transaction_by_query(
            TRANSACTION_BY_ACCESS_TOKEN,
            &hash_access_token(&self.token_hmac_key, access_token),
        )
        .await
    }

    async fn authorization_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<CredentialAuthorizationSession>, CredentialIssuanceError> {
        let row = sqlx::query(
            "SELECT id, organization_id, issuer_state, credential_configuration_ids, dpop_jkt
             FROM issuance_service.authorization_sessions
             WHERE access_token = $1",
        )
        .bind(hash_access_token(&self.token_hmac_key, access_token))
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?;
        row.map(authorization_row).transpose()
    }

    async fn ensure_authorization_transaction(
        &self,
        session: &CredentialAuthorizationSession,
        access_token: &str,
    ) -> Result<CredentialTransaction, CredentialIssuanceError> {
        if let Some(issuer_state) = session.issuer_state.as_deref() {
            if let Some(transaction) = self
                .transaction_by_query(TRANSACTION_BY_PRE_AUTH_CODE, issuer_state)
                .await?
            {
                return Ok(transaction);
            }
        }
        let selected = session
            .credential_configuration_ids
            .first()
            .map(String::as_str)
            .unwrap_or("default");
        let credential_type = selected.split('#').next().unwrap_or("default");
        let (issuer_did, algorithm) = self
            .active_issuer_identity(&session.organization_id, credential_type)
            .await?;
        let transaction_id = authorization_transaction_id(&session.id);
        let claims = session
            .dpop_jkt
            .as_ref()
            .map_or_else(|| json!({}), |jkt| json!({"_dpop_jkt": jkt}));
        sqlx::query(
            "INSERT INTO issuance_service.issuance_transactions
                 (id, organization_id, credential_template_id, status, pre_auth_code,
                  access_token, c_nonce, claims, credential_type, issuer_mode,
                  issuer_did_override, issuer_algorithm, credential_payload_format,
                  selective_disclosure_claims, wallet_configs, validity_days,
                  created_at, expires_at)
             VALUES ($1, $2, '', 'authorized', $3, $4, NULL, $5, $6, 'org_managed',
                     $7, $8, 'w3c_vcdm_v2_sd_jwt', '[]'::jsonb, '[]'::jsonb, 365,
                     clock_timestamp(), clock_timestamp() + interval '15 minutes')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&transaction_id)
        .bind(&session.organization_id)
        .bind(random_capability())
        .bind(hash_access_token(&self.token_hmac_key, access_token))
        .bind(claims)
        .bind(credential_type)
        .bind(issuer_did)
        .bind(algorithm)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        let transaction = self
            .transaction_by_id(&transaction_id)
            .await?
            .ok_or(CredentialIssuanceError::RepositoryUnavailable)?;
        if transaction.organization_id != session.organization_id {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        }
        Ok(transaction)
    }

    async fn credential_by_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ExistingCredential>, CredentialIssuanceError> {
        sqlx::query(
            "SELECT id, credential_jwt FROM issuance_service.issued_credentials
             WHERE transaction_id = $1",
        )
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(|row| {
            Ok(ExistingCredential {
                id: get(&row, "id")?,
                credential: get(&row, "credential_jwt")?,
            })
        })
        .transpose()
    }

    async fn transaction_by_id(
        &self,
        transaction_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        self.transaction_by_query(TRANSACTION_BY_ID, transaction_id)
            .await
    }

    async fn claim_for_signing(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        sqlx::query(CLAIM_FOR_SIGNING)
            .bind(&transaction.id)
            .bind(credential_id)
            .bind(&transaction.credential_type)
            .bind(&transaction.issuer_profile_id)
            .bind(&transaction.issuer_mode)
            .bind(&transaction.issuer_did)
            .bind(&transaction.issuer_algorithm)
            .bind(&transaction.signing_service_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()
    }

    async fn finalize(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError> {
        let mut database = self.pool.begin().await.map_err(repository_error)?;
        finalize_credential(&mut database, transaction, credential).await?;
        database.commit().await.map_err(repository_error)
    }

    async fn mark_failed_if_signing(
        &self,
        transaction_id: &str,
        _reason: &str,
    ) -> Result<(), CredentialIssuanceError> {
        sqlx::query(
            "UPDATE issuance_service.issuance_transactions SET status = 'failed'
             WHERE id = $1 AND status = 'signing'",
        )
        .bind(transaction_id)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }
}

impl PostgresCredentialRepository {
    async fn load_didcomm_delivery_state(
        &self,
        organization_id: &str,
        transaction_id: &str,
        include_delivered: bool,
    ) -> Result<Option<InitiationDidcommDeliveryState>, CredentialIssuanceError> {
        let Some(transaction) = self.transaction_by_id(transaction_id).await? else {
            return Ok(None);
        };
        if transaction.organization_id != organization_id
            || transaction.status != CredentialTransactionStatus::Issued
        {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT credential.id, credential.transaction_id, credential.organization_id,
                    credential.credential_template_id, credential.applicant_id,
                    credential.subject_did, credential.issuer_did,
                    credential.revocation_profile_id, credential.renewed_from_credential_id,
                    credential.status_list_entries, credential.credential_jwt,
                    credential.credential_hash, credential.issued_at, credential.expires_at,
                    delivery.status AS delivery_status, delivery.metadata
             FROM issuance_service.issued_credentials AS credential
             JOIN issuance_service.credential_delivery_records AS delivery
               ON delivery.credential_id = credential.id
              AND delivery.transaction_id = credential.transaction_id
              AND delivery.organization_id = credential.organization_id
             WHERE credential.transaction_id = $1
               AND credential.organization_id = $2
               AND delivery.delivery_target = 'didcomm_v2'
               AND (delivery.status IN ('pending', 'failed', 'transported')
                    OR ($3 AND delivery.status = 'delivered'))",
        )
        .bind(transaction_id)
        .bind(organization_id)
        .bind(include_delivered)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let metadata = get::<Value>(&row, "metadata")?;
        let metadata_text = |name: &str| {
            metadata
                .get(name)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(CredentialIssuanceError::RepositoryUnavailable)
        };
        let delivery_status = get::<String>(&row, "delivery_status")?;
        if delivery_status == "delivered" {
            return Ok(Some(InitiationDidcommDeliveryState::Delivered(
                DeliveredInitiationDidcommDelivery {
                    transaction_id: transaction.id,
                    organization_id: transaction.organization_id,
                    credential_id: get(&row, "id")?,
                    holder_did: metadata_text("holder_did")?,
                    service_endpoint: metadata_text("service_endpoint")?,
                    message_id: metadata_text("didcomm_message_id")?,
                },
            )));
        }
        Ok(Some(InitiationDidcommDeliveryState::Pending(Box::new(
            PendingInitiationDidcommDelivery {
                transaction,
                credential: IssuedCredential {
                    id: get(&row, "id")?,
                    transaction_id: get(&row, "transaction_id")?,
                    organization_id: get(&row, "organization_id")?,
                    credential_template_id: get(&row, "credential_template_id")?,
                    applicant_id: get(&row, "applicant_id")?,
                    subject_did: get(&row, "subject_did")?,
                    issuer_did: get(&row, "issuer_did")?,
                    revocation_profile_id: get(&row, "revocation_profile_id")?,
                    renewed_from_credential_id: get(&row, "renewed_from_credential_id")?,
                    status_list_entries: json_vec(&row, "status_list_entries")?,
                    credential: get(&row, "credential_jwt")?,
                    credential_hash: get(&row, "credential_hash")?,
                    issued_at: get(&row, "issued_at")?,
                    expires_at: get(&row, "expires_at")?,
                },
                delivery: StagedInitiationDidcommDelivery {
                    holder_did: metadata_text("holder_did")?,
                    service_endpoint: metadata_text("service_endpoint")?,
                    message_id: metadata_text("didcomm_message_id")?,
                    encrypted_message: metadata_text("encrypted_message")?,
                },
                transported: delivery_status == "transported",
            },
        ))))
    }
}

#[async_trait]
impl InitiationDidcommRepository for PostgresCredentialRepository {
    async fn pending_delivery(
        &self,
        organization_id: &str,
        transaction_id: &str,
    ) -> Result<Option<PendingInitiationDidcommDelivery>, CredentialIssuanceError> {
        self.load_didcomm_delivery_state(organization_id, transaction_id, false)
            .await
            .map(|state| match state {
                Some(InitiationDidcommDeliveryState::Pending(pending)) => Some(*pending),
                Some(InitiationDidcommDeliveryState::Delivered(_)) | None => None,
            })
    }

    async fn delivery_state(
        &self,
        organization_id: &str,
        transaction_id: &str,
    ) -> Result<Option<InitiationDidcommDeliveryState>, CredentialIssuanceError> {
        self.load_didcomm_delivery_state(organization_id, transaction_id, true)
            .await
    }

    async fn transaction_for_delivery(
        &self,
        organization_id: &str,
        transaction_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        sqlx::query(TRANSACTION_BY_ID_AND_ORGANIZATION)
            .bind(transaction_id)
            .bind(organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()
    }

    async fn claim_retryably(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
    ) -> Result<Option<InitiationDidcommClaim>, CredentialIssuanceError> {
        if !matches!(
            transaction.status,
            CredentialTransactionStatus::Pending | CredentialTransactionStatus::Authorized
        ) {
            return Ok(None);
        }
        let previous_status = transaction.status;
        let claimed = sqlx::query(CLAIM_FOR_DIDCOMM)
            .bind(&transaction.id)
            .bind(credential_id)
            .bind(&transaction.credential_type)
            .bind(&transaction.issuer_profile_id)
            .bind(&transaction.issuer_mode)
            .bind(&transaction.issuer_did)
            .bind(&transaction.issuer_algorithm)
            .bind(&transaction.signing_service_id)
            .bind(&transaction.organization_id)
            .bind(transaction_status(transaction.status))
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()?;
        Ok(claimed.map(|transaction| InitiationDidcommClaim {
            transaction,
            previous_status,
        }))
    }

    async fn release_retryably(
        &self,
        claim: &InitiationDidcommClaim,
    ) -> Result<(), CredentialIssuanceError> {
        let released = sqlx::query(
            "UPDATE issuance_service.issuance_transactions
             SET status = $1, reserved_credential_id = NULL
             WHERE id = $2 AND organization_id = $3 AND status = 'signing'
               AND reserved_credential_id = $4",
        )
        .bind(transaction_status(claim.previous_status))
        .bind(&claim.transaction.id)
        .bind(&claim.transaction.organization_id)
        .bind(&claim.transaction.reserved_credential_id)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        if released.rows_affected() != 1 {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        }
        Ok(())
    }

    async fn finalize_delivered(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError> {
        CredentialRepository::finalize(self, transaction, credential).await
    }

    async fn stage_delivery(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        delivery: &StagedInitiationDidcommDelivery,
    ) -> Result<(), CredentialIssuanceError> {
        let mut database = self.pool.begin().await.map_err(repository_error)?;
        finalize_credential(&mut database, transaction, credential).await?;
        sqlx::query(
            "INSERT INTO issuance_service.credential_delivery_records
                 (id, credential_id, transaction_id, organization_id, delivery_target,
                  delivery_mode, status, canvas_account_id, last_error, metadata,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'didcomm_v2', $5, 'pending', NULL, NULL, $6,
                     clock_timestamp(), clock_timestamp())",
        )
        .bind(delivery_record_id(&credential.id, "didcomm_v2", None))
        .bind(&credential.id)
        .bind(&transaction.id)
        .bind(&transaction.organization_id)
        .bind(&transaction.delivery_mode)
        .bind(json!({
            "protocol": "didcomm_v2",
            "holder_did": delivery.holder_did,
            "service_endpoint": delivery.service_endpoint,
            "didcomm_message_id": delivery.message_id,
            "encrypted_message": delivery.encrypted_message,
        }))
        .execute(&mut *database)
        .await
        .map_err(repository_error)?;
        database.commit().await.map_err(repository_error)
    }

    async fn mark_transport_delivered(
        &self,
        transaction_id: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        update_didcomm_delivery_status(&self.pool, transaction_id, message_id, "transported", None)
            .await
    }

    async fn mark_transport_failed(
        &self,
        transaction_id: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        update_didcomm_delivery_status(
            &self.pool,
            transaction_id,
            message_id,
            "failed",
            Some("didcomm_delivery_failed"),
        )
        .await
    }
}

#[derive(Debug)]
struct CanvasProjection {
    application_id: String,
    organization_id: String,
    candidate_id: Option<String>,
}

fn authorization_transaction_id(session_id: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("marty:oid4vci:authorization-session:{session_id}").as_bytes(),
    )
    .to_string()
}

fn random_capability() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn missing_issuer_identity(credential_type: &str) -> CredentialIssuanceError {
    CredentialIssuanceError::IssuerUnavailable(format!(
        "The selected credential configuration '{credential_type}' has no active DID-mediated issuer identity."
    ))
}

const fn transaction_status(status: CredentialTransactionStatus) -> &'static str {
    match status {
        CredentialTransactionStatus::Pending => "pending",
        CredentialTransactionStatus::Authorized => "authorized",
        CredentialTransactionStatus::Signing => "signing",
        CredentialTransactionStatus::Issued => "issued",
        CredentialTransactionStatus::Failed => "failed",
        CredentialTransactionStatus::Expired => "expired",
        CredentialTransactionStatus::Revoked => "revoked",
    }
}

fn validate_idempotent_recovery(
    existing: Option<CredentialTransaction>,
    request_hash: &str,
) -> Result<Option<CredentialTransaction>, InitiationRepositoryError> {
    let Some(existing) = existing else {
        return Ok(None);
    };
    if !constant_time_secret_eq(
        existing
            .idempotency_request_hash
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
        request_hash.as_bytes(),
    ) {
        return Err(InitiationRepositoryError::IdempotencyConflict);
    }
    Ok(Some(existing))
}

fn transaction_row(row: PgRow) -> Result<CredentialTransaction, CredentialIssuanceError> {
    let status = get::<String>(&row, "status")?;
    Ok(CredentialTransaction {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        credential_template_id: get(&row, "credential_template_id")?,
        revocation_profile_id: get(&row, "revocation_profile_id")?,
        renewal_of_credential_id: get(&row, "renewal_of_credential_id")?,
        applicant_id: get(&row, "applicant_id")?,
        application_id: get(&row, "application_id")?,
        subject_did: get(&row, "subject_did")?,
        idempotency_key_hash: get(&row, "idempotency_key_hash")?,
        idempotency_request_hash: get(&row, "idempotency_request_hash")?,
        status: CredentialTransactionStatus::try_from(status.as_str())?,
        pre_authorized_code: get(&row, "pre_auth_code")?,
        nonce: get(&row, "c_nonce")?,
        claims: json_map(&row, "claims")?,
        credential_type: get(&row, "credential_type")?,
        selective_disclosure_claims: json_vec(&row, "selective_disclosure_claims")?,
        zk_predicate_claims: json_vec(&row, "zk_predicate_claims")?,
        credential_payload_format: get(&row, "credential_payload_format")?,
        wallet_configs: json_vec(&row, "wallet_configs")?,
        validity_days: i64::from(get::<i32>(&row, "validity_days")?),
        renewable: get(&row, "renewable")?,
        renewal_window_days: i64::from(get::<i32>(&row, "renewal_window_days")?),
        delivery_mode: get(&row, "delivery_mode")?,
        issuer_profile_id: get(&row, "issuer_profile_id")?,
        issuer_mode: get(&row, "issuer_mode")?,
        issuer_did: get(&row, "issuer_did_override")?,
        issuer_algorithm: get(&row, "issuer_algorithm")?,
        signing_service_id: get(&row, "signing_service_id")?,
        reserved_credential_id: get(&row, "reserved_credential_id")?,
        oid4vci_client_id: get(&row, "oid4vci_client_id")?,
        created_at: get(&row, "created_at")?,
        expires_at: get(&row, "expires_at")?,
    })
}

#[async_trait]
impl InitiationRepository for PostgresCredentialRepository {
    async fn recover_idempotently(
        &self,
        organization_id: &str,
        binding: &IdempotencyBinding,
    ) -> Result<Option<CredentialTransaction>, InitiationRepositoryError> {
        let existing = sqlx::query(TRANSACTION_BY_IDEMPOTENCY)
            .bind(organization_id)
            .bind(&binding.key_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| InitiationRepositoryError::Unavailable)?
            .map(transaction_row)
            .transpose()
            .map_err(|_| InitiationRepositoryError::Unavailable)?;
        validate_idempotent_recovery(existing, &binding.request_hash)
    }

    async fn reserve_idempotently(
        &self,
        transaction: &CredentialTransaction,
    ) -> Result<InitiationReservation, InitiationRepositoryError> {
        match (
            transaction.idempotency_key_hash.as_deref(),
            transaction.idempotency_request_hash.as_deref(),
        ) {
            (None, None) | (Some(_), Some(_)) => {}
            _ => return Err(InitiationRepositoryError::IncompleteIdempotencyBinding),
        }
        let validity_days = i32::try_from(transaction.validity_days)
            .map_err(|_| InitiationRepositoryError::Unavailable)?;
        let renewal_window_days = i32::try_from(transaction.renewal_window_days)
            .map_err(|_| InitiationRepositoryError::Unavailable)?;
        let created = sqlx::query(RESERVE_INITIATION)
            .bind(&transaction.id)
            .bind(&transaction.organization_id)
            .bind(&transaction.credential_template_id)
            .bind(&transaction.revocation_profile_id)
            .bind(&transaction.renewal_of_credential_id)
            .bind(&transaction.applicant_id)
            .bind(&transaction.application_id)
            .bind(&transaction.subject_did)
            .bind(&transaction.idempotency_key_hash)
            .bind(&transaction.idempotency_request_hash)
            .bind(transaction_status(transaction.status))
            .bind(&transaction.pre_authorized_code)
            .bind(&transaction.nonce)
            .bind(Value::Object(transaction.claims.clone()))
            .bind(&transaction.credential_type)
            .bind(json!(transaction.selective_disclosure_claims))
            .bind(json!(transaction.zk_predicate_claims))
            .bind(&transaction.credential_payload_format)
            .bind(Value::Array(transaction.wallet_configs.clone()))
            .bind(validity_days)
            .bind(transaction.renewable)
            .bind(renewal_window_days)
            .bind(&transaction.delivery_mode)
            .bind(&transaction.issuer_profile_id)
            .bind(&transaction.issuer_mode)
            .bind(&transaction.issuer_did)
            .bind(&transaction.issuer_algorithm)
            .bind(&transaction.signing_service_id)
            .bind(&transaction.reserved_credential_id)
            .bind(&transaction.oid4vci_client_id)
            .bind(transaction.created_at)
            .bind(transaction.expires_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| InitiationRepositoryError::Unavailable)?
            .map(transaction_row)
            .transpose()
            .map_err(|_| InitiationRepositoryError::Unavailable)?;
        if let Some(transaction) = created {
            return Ok(InitiationReservation {
                transaction,
                created: true,
            });
        }
        let (Some(key_hash), Some(request_hash)) = (
            transaction.idempotency_key_hash.as_deref(),
            transaction.idempotency_request_hash.as_deref(),
        ) else {
            return Err(InitiationRepositoryError::Unavailable);
        };
        let existing = sqlx::query(TRANSACTION_BY_IDEMPOTENCY)
            .bind(&transaction.organization_id)
            .bind(key_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| InitiationRepositoryError::Unavailable)?
            .map(transaction_row)
            .transpose()
            .map_err(|_| InitiationRepositoryError::Unavailable)?;
        let transaction = validate_idempotent_recovery(existing, request_hash)?
            .ok_or(InitiationRepositoryError::Unavailable)?;
        Ok(InitiationReservation {
            transaction,
            created: false,
        })
    }
}

fn authorization_row(
    row: PgRow,
) -> Result<CredentialAuthorizationSession, CredentialIssuanceError> {
    let organization_id = get::<Option<String>>(&row, "organization_id")?
        .filter(|value| !value.is_empty())
        .ok_or(CredentialIssuanceError::RepositoryUnavailable)?;
    Ok(CredentialAuthorizationSession {
        id: get(&row, "id")?,
        organization_id,
        issuer_state: get(&row, "issuer_state")?,
        credential_configuration_ids: json_vec(&row, "credential_configuration_ids")?,
        dpop_jkt: get(&row, "dpop_jkt")?,
    })
}

fn validate_finalization_input(
    transaction: &CredentialTransaction,
    credential: &IssuedCredential,
) -> Result<(), CredentialIssuanceError> {
    if transaction.status != CredentialTransactionStatus::Signing
        || transaction.reserved_credential_id.as_deref() != Some(&credential.id)
        || credential.transaction_id != transaction.id
        || credential.organization_id != transaction.organization_id
        || credential.credential_template_id != transaction.credential_template_id
    {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    Ok(())
}

async fn finalize_credential(
    database: &mut Transaction<'_, Postgres>,
    transaction: &CredentialTransaction,
    credential: &IssuedCredential,
) -> Result<(), CredentialIssuanceError> {
    validate_finalization_input(transaction, credential)?;
    let authoritative = sqlx::query(
        "SELECT organization_id, credential_template_id, application_id, status,
                reserved_credential_id
         FROM issuance_service.issuance_transactions WHERE id = $1 FOR UPDATE",
    )
    .bind(&transaction.id)
    .fetch_optional(&mut **database)
    .await
    .map_err(repository_error)?
    .ok_or(CredentialIssuanceError::RepositoryUnavailable)?;
    validate_authoritative_finalization(&authoritative, credential)?;
    if credential_exists(database, &transaction.id).await? {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    let canvas = prepare_canvas_projection(
        database,
        get::<Option<String>>(&authoritative, "application_id")?.as_deref(),
        &credential.organization_id,
        &credential.id,
    )
    .await?;
    insert_credential(database, credential).await?;
    apply_canvas_projection(database, canvas.as_ref(), credential).await?;
    let finalized = sqlx::query(
        "UPDATE issuance_service.issuance_transactions
         SET status = 'issued', c_nonce = NULL, issued_at = $3
         WHERE id = $1 AND status = 'signing' AND reserved_credential_id = $2",
    )
    .bind(&transaction.id)
    .bind(&credential.id)
    .bind(credential.issued_at)
    .execute(&mut **database)
    .await
    .map_err(repository_error)?;
    if finalized.rows_affected() != 1 {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    Ok(())
}

fn validate_authoritative_finalization(
    row: &PgRow,
    credential: &IssuedCredential,
) -> Result<(), CredentialIssuanceError> {
    if get::<String>(row, "status")? != "signing"
        || get::<String>(row, "organization_id")? != credential.organization_id
        || get::<String>(row, "credential_template_id")? != credential.credential_template_id
        || get::<Option<String>>(row, "reserved_credential_id")?.as_deref() != Some(&credential.id)
    {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    Ok(())
}

async fn credential_exists(
    database: &mut Transaction<'_, Postgres>,
    transaction_id: &str,
) -> Result<bool, CredentialIssuanceError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM issuance_service.issued_credentials WHERE transaction_id = $1",
    )
    .bind(transaction_id)
    .fetch_one(&mut **database)
    .await
    .map_err(repository_error)?
        != 0)
}

async fn insert_credential(
    database: &mut Transaction<'_, Postgres>,
    credential: &IssuedCredential,
) -> Result<(), CredentialIssuanceError> {
    sqlx::query(
        "INSERT INTO issuance_service.issued_credentials
             (id, transaction_id, organization_id, credential_template_id, applicant_id,
              subject_did, issuer_did, revocation_profile_id, renewed_from_credential_id,
              status_list_entries, credential_jwt, credential_hash, status, status_updated_at,
              revoked, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 'active', $13, false, $13, $14)",
    )
    .bind(&credential.id)
    .bind(&credential.transaction_id)
    .bind(&credential.organization_id)
    .bind(&credential.credential_template_id)
    .bind(&credential.applicant_id)
    .bind(&credential.subject_did)
    .bind(&credential.issuer_did)
    .bind(&credential.revocation_profile_id)
    .bind(&credential.renewed_from_credential_id)
    .bind(json!(credential.status_list_entries))
    .bind(&credential.credential)
    .bind(&credential.credential_hash)
    .bind(credential.issued_at)
    .bind(credential.expires_at)
    .execute(&mut **database)
    .await
    .map_err(repository_error)?;
    Ok(())
}

async fn update_didcomm_delivery_status(
    pool: &PgPool,
    transaction_id: &str,
    message_id: &str,
    status: &str,
    last_error: Option<&str>,
) -> Result<(), CredentialIssuanceError> {
    let updated = sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET status = $3, last_error = $4, updated_at = clock_timestamp()
         WHERE transaction_id = $1
           AND delivery_target = 'didcomm_v2'
           AND metadata ->> 'didcomm_message_id' = $2
           AND status IN ('pending', 'failed')",
    )
    .bind(transaction_id)
    .bind(message_id)
    .bind(status)
    .bind(last_error)
    .execute(pool)
    .await
    .map_err(repository_error)?;
    if updated.rows_affected() != 1 {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    Ok(())
}

async fn prepare_canvas_projection(
    database: &mut Transaction<'_, Postgres>,
    application_id: Option<&str>,
    organization_id: &str,
    credential_id: &str,
) -> Result<Option<CanvasProjection>, CredentialIssuanceError> {
    let Some(application_id) = application_id.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let application = sqlx::query(
        "SELECT id, organization_id, credential_id, integration_context
         FROM issuance_service.applications
         WHERE id = $1 AND organization_id = $2 FOR UPDATE",
    )
    .bind(application_id)
    .bind(organization_id)
    .fetch_optional(&mut **database)
    .await
    .map_err(repository_error)?;
    let Some(application) = application else {
        return Ok(None);
    };
    let integration = get::<Value>(&application, "integration_context")?;
    let Some(canvas) = canvas_context(&integration) else {
        return Ok(None);
    };
    let current_credential = get::<Option<String>>(&application, "credential_id")?;
    if current_credential
        .as_deref()
        .is_some_and(|value| value != credential_id)
    {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    let candidate_id = canvas
        .get("canvas_award_candidate_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if let Some(candidate_id) = candidate_id.as_deref() {
        let candidate = sqlx::query(
            "SELECT id, application_id, binding_id, platform_id, claimed_credential_id
             FROM issuance_service.canvas_award_candidates
             WHERE id = $1 AND organization_id = $2 FOR UPDATE",
        )
        .bind(candidate_id)
        .bind(organization_id)
        .fetch_optional(&mut **database)
        .await
        .map_err(repository_error)?;
        if let Some(candidate) = candidate {
            let expected_binding = canvas_string(canvas, "canvas_program_binding_id");
            let expected_platform = canvas_string(canvas, "canvas_platform_id");
            let claimed = get::<Option<String>>(&candidate, "claimed_credential_id")?;
            if get::<Option<String>>(&candidate, "application_id")?.as_deref()
                != Some(application_id)
                || (!expected_binding.is_empty()
                    && get::<String>(&candidate, "binding_id")? != expected_binding)
                || (!expected_platform.is_empty()
                    && get::<String>(&candidate, "platform_id")? != expected_platform)
                || claimed
                    .as_deref()
                    .is_some_and(|value| value != credential_id)
            {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            }
        } else {
            return Ok(Some(CanvasProjection {
                application_id: application_id.to_owned(),
                organization_id: organization_id.to_owned(),
                candidate_id: None,
            }));
        }
    }
    Ok(Some(CanvasProjection {
        application_id: application_id.to_owned(),
        organization_id: organization_id.to_owned(),
        candidate_id,
    }))
}

async fn apply_canvas_projection(
    database: &mut Transaction<'_, Postgres>,
    projection: Option<&CanvasProjection>,
    credential: &IssuedCredential,
) -> Result<(), CredentialIssuanceError> {
    let Some(projection) = projection else {
        return Ok(());
    };
    let application = sqlx::query(
        "UPDATE issuance_service.applications SET credential_id = $3, updated_at = $4
         WHERE id = $1 AND organization_id = $2
           AND (credential_id IS NULL OR credential_id = $3)",
    )
    .bind(&projection.application_id)
    .bind(&projection.organization_id)
    .bind(&credential.id)
    .bind(credential.issued_at)
    .execute(&mut **database)
    .await
    .map_err(repository_error)?;
    if application.rows_affected() != 1 {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    if let Some(candidate_id) = projection.candidate_id.as_deref() {
        let candidate = sqlx::query(
            "UPDATE issuance_service.canvas_award_candidates
             SET state = 'claimed', claimed_credential_id = $3, updated_at = $4
             WHERE id = $1 AND organization_id = $2
               AND (claimed_credential_id IS NULL OR claimed_credential_id = $3)",
        )
        .bind(candidate_id)
        .bind(&projection.organization_id)
        .bind(&credential.id)
        .bind(credential.issued_at)
        .execute(&mut **database)
        .await
        .map_err(repository_error)?;
        if candidate.rows_affected() != 1 {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        }
    }
    Ok(())
}

fn canvas_context(integration: &Value) -> Option<&Map<String, Value>> {
    let canvas = integration.get("canvas")?.as_object()?;
    let source = canvas_string(canvas, "source").to_ascii_lowercase();
    [
        "canvas_platform_id",
        "canvas_program_binding_id",
        "canvas_account_id",
    ]
    .iter()
    .any(|name| !canvas_string(canvas, name).is_empty())
    .then_some(canvas)
    .or_else(|| source.starts_with("canvas").then_some(canvas))
}

fn canvas_string(canvas: &Map<String, Value>, name: &str) -> String {
    canvas
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned()
}

fn json_map(row: &PgRow, name: &str) -> Result<Map<String, Value>, CredentialIssuanceError> {
    get::<Value>(row, name)?
        .as_object()
        .cloned()
        .ok_or(CredentialIssuanceError::RepositoryUnavailable)
}

fn json_vec<T>(row: &PgRow, name: &str) -> Result<Vec<T>, CredentialIssuanceError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(get::<Option<Value>>(row, name)?.unwrap_or_else(|| json!([])))
        .map_err(|cause| row_conversion_error(name, cause))
}

fn get<'row, T>(row: &'row PgRow, name: &str) -> Result<T, CredentialIssuanceError>
where
    T: sqlx::Decode<'row, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(name).map_err(|cause| {
        error!(%cause, column = name, "credential repository row is invalid");
        CredentialIssuanceError::RepositoryUnavailable
    })
}

fn row_conversion_error(name: &str, cause: serde_json::Error) -> CredentialIssuanceError {
    error!(%cause, column = name, "credential repository JSON is invalid");
    CredentialIssuanceError::RepositoryUnavailable
}

fn repository_error(cause: sqlx::Error) -> CredentialIssuanceError {
    error!(%cause, "credential repository query failed");
    CredentialIssuanceError::RepositoryUnavailable
}

#[cfg(test)]
mod tests {
    use super::{authorization_transaction_id, canvas_context};
    use serde_json::json;

    #[test]
    fn authorization_transaction_identity_matches_the_python_contract() {
        assert_eq!(
            authorization_transaction_id("authorization-session-race"),
            "dca62a6b-abc0-590d-906b-2582303615e5"
        );
    }

    #[test]
    fn canvas_projection_requires_a_real_canvas_context() {
        assert!(canvas_context(&json!({"canvas": {"source": "canvas-lti"}})).is_some());
        assert!(canvas_context(&json!({"canvas": {"source": "other"}})).is_none());
    }
}
