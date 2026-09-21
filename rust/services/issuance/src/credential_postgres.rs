use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use mmf_security::constant_time_secret_eq;
use rand::RngCore;
use serde_json::{json, Map, Value};
use sqlx::{postgres::PgRow, Executor, PgPool, Postgres, Row, Transaction};
use tracing::error;
use uuid::Uuid;

use crate::oid4vci_authorization::Oid4vciAuthorizationRepository;
use crate::oid4vci_authorization_postgres::PostgresOid4vciAuthorizationRepository;
use crate::{
    credential::{
        reserved_credential_id, CredentialAccessTokenGrant, CredentialAuthorizationSession,
        CredentialIssuanceError, CredentialRepository, CredentialTransaction,
        CredentialTransactionStatus, ExistingCredential, IssuedCredential,
    },
    credential_lifecycle::delivery_record_id,
    credential_renewal::{RenewalRepository, RenewalRepositoryError, RenewalSource},
    initiation::{
        IdempotencyBinding, InitiationRepository, InitiationRepositoryError, InitiationReservation,
    },
    initiation_didcomm::{
        DeliveredInitiationDidcommDelivery, InitiationDidcommClaim, InitiationDidcommDeliveryState,
        InitiationDidcommRepository, InitiationDidcommTransportClaim,
        InitiationDidcommTransportClaimOutcome, PendingInitiationDidcommDelivery,
        StagedInitiationDidcommDelivery, DIDCOMM_TRANSPORT_CLAIM_LEASE_SECONDS,
        DIDCOMM_TRANSPORT_READY_STATUS, DIDCOMM_TRANSPORT_RETRYABLE_STATUS,
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

const BIND_RENEWAL_RESERVATION: &str = concat!(
    "UPDATE issuance_service.issuance_transactions AS candidate
     SET renewal_of_credential_id = $3, application_id = $4
     WHERE id = $1 AND organization_id = $2
       AND ((renewal_of_credential_id = $3 AND application_id IS NOT DISTINCT FROM $4)
            OR (renewal_of_credential_id IS NULL AND application_id IS NULL
                AND status = 'pending' AND reserved_credential_id IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM issuance_service.issued_credentials issued
                    WHERE issued.transaction_id = candidate.id)
                AND NOT EXISTS (
                    SELECT 1 FROM issuance_service.credential_delivery_records delivery
                    WHERE delivery.transaction_id = candidate.id)))
       AND idempotency_key_hash IS NOT DISTINCT FROM $5
       AND idempotency_request_hash IS NOT DISTINCT FROM $6
     RETURNING ",
    transaction_columns!()
);

const TRANSACTION_BY_ACCESS_TOKEN: &str =
    transaction_query!("access_token = $1 AND access_token_expires_at > clock_timestamp()");
const BIND_AUTHORIZATION_TRANSACTION: &str = concat!(
    "UPDATE issuance_service.issuance_transactions
     SET oid4vci_client_id = COALESCE(oid4vci_client_id, $3),
         access_token = $5,
         access_token_expires_at = $6,
         claims = CASE
             WHEN $4::text IS NULL THEN claims::jsonb
             ELSE jsonb_set(COALESCE(claims::jsonb, '{}'::jsonb),
                            '{_dpop_jkt}', to_jsonb($4::text), true)
         END,
         status = CASE WHEN status = 'pending' THEN 'authorized' ELSE status END
     WHERE pre_auth_code = $1
       AND organization_id = $2
       AND (oid4vci_client_id IS NULL OR oid4vci_client_id = $3)
       AND ((access_token IS NULL AND access_token_expires_at IS NULL)
            OR (access_token = $5 AND access_token_expires_at = $6))
       AND ((claims::jsonb ->> '_dpop_jkt') IS NULL
            OR (claims::jsonb ->> '_dpop_jkt') = $4)
     RETURNING ",
    transaction_columns!()
);
const TRANSACTION_BY_PRE_AUTH_CODE: &str = transaction_query!("pre_auth_code = $1");
const TRANSACTION_BY_ID: &str = transaction_query!("id = $1");
const TRANSACTION_BY_AUTHORIZATION_SESSION: &str = transaction_query!(
    "id = $1
     AND organization_id = $2
     AND oid4vci_client_id = $3
     AND access_token = $4
     AND access_token_expires_at = $5
     AND (claims::jsonb ->> '_dpop_jkt') IS NOT DISTINCT FROM $6
     AND credential_type = $7"
);
const TRANSACTION_BY_ID_AND_ORGANIZATION: &str =
    transaction_query!("id = $1 AND organization_id = $2");
const TRANSACTION_BY_ID_AND_ORGANIZATION_FOR_UPDATE: &str = concat!(
    "SELECT ",
    transaction_columns!(),
    " FROM issuance_service.issuance_transactions
      WHERE id = $1 AND organization_id = $2 FOR UPDATE"
);
const TRANSACTION_BY_IDEMPOTENCY: &str =
    transaction_query!("organization_id = $1 AND idempotency_key_hash = $2");
const TRANSACTION_BY_IDEMPOTENCY_FOR_UPDATE: &str = concat!(
    "SELECT ",
    transaction_columns!(),
    " FROM issuance_service.issuance_transactions
      WHERE organization_id = $1 AND idempotency_key_hash = $2 FOR UPDATE"
);
const REFRESH_PENDING_APPLICATION_OFFER: &str = concat!(
    "UPDATE issuance_service.issuance_transactions
     SET delivery_mode = $3, revocation_profile_id = $4,
         issuer_profile_id = $5, issuer_mode = $6, issuer_did_override = $7,
         issuer_algorithm = $8, signing_service_id = $9
     WHERE id = $1 AND organization_id = $2 AND application_id = $10
       AND status = 'pending'
     RETURNING ",
    transaction_columns!()
);
const REFRESH_PENDING_CANVAS_APPLICATION_OFFER: &str = concat!(
    "UPDATE issuance_service.issuance_transactions
     SET delivery_mode = $3, revocation_profile_id = $4,
         issuer_profile_id = $5, issuer_mode = $6, issuer_did_override = $7,
         issuer_algorithm = $8, signing_service_id = $9,
         credential_template_id = $10, claims = $11,
         credential_type = $12, credential_payload_format = $13,
         wallet_configs = $14, selective_disclosure_claims = $15,
         zk_predicate_claims = $16, validity_days = $17, renewable = $18,
         renewal_window_days = $19
     WHERE id = $1 AND organization_id = $2 AND application_id = $20
       AND status = 'pending'
     RETURNING ",
    transaction_columns!()
);
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

/// Insert the canonical issuance-transaction shape through either a pool or an
/// existing database transaction. Application approval uses the latter so the
/// application lifecycle transition and transaction reservation commit as one
/// write set.
pub(crate) async fn insert_issuance_transaction<'executor, E>(
    executor: E,
    transaction: &CredentialTransaction,
) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>
where
    E: Executor<'executor, Database = Postgres>,
{
    let validity_days = i32::try_from(transaction.validity_days)
        .map_err(|_| CredentialIssuanceError::RepositoryUnavailable)?;
    let renewal_window_days = i32::try_from(transaction.renewal_window_days)
        .map_err(|_| CredentialIssuanceError::RepositoryUnavailable)?;
    sqlx::query(RESERVE_INITIATION)
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
        .fetch_optional(executor)
        .await
        .map_err(|_| CredentialIssuanceError::RepositoryUnavailable)?
        .map(transaction_row)
        .transpose()
}

pub(crate) async fn issuance_transaction_by_id<'executor, E>(
    executor: E,
    transaction_id: &str,
    organization_id: &str,
) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>
where
    E: Executor<'executor, Database = Postgres>,
{
    sqlx::query(TRANSACTION_BY_ID_AND_ORGANIZATION)
        .bind(transaction_id)
        .bind(organization_id)
        .fetch_optional(executor)
        .await
        .map_err(repository_error)?
        .map(transaction_row)
        .transpose()
}

pub(crate) async fn lock_issuance_transaction_by_id<'executor, E>(
    executor: E,
    transaction_id: &str,
    organization_id: &str,
) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>
where
    E: Executor<'executor, Database = Postgres>,
{
    sqlx::query(TRANSACTION_BY_ID_AND_ORGANIZATION_FOR_UPDATE)
        .bind(transaction_id)
        .bind(organization_id)
        .fetch_optional(executor)
        .await
        .map_err(repository_error)?
        .map(transaction_row)
        .transpose()
}

pub(crate) async fn lock_issuance_transaction_by_idempotency<'executor, E>(
    executor: E,
    organization_id: &str,
    key_hash: &str,
) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>
where
    E: Executor<'executor, Database = Postgres>,
{
    sqlx::query(TRANSACTION_BY_IDEMPOTENCY_FOR_UPDATE)
        .bind(organization_id)
        .bind(key_hash)
        .fetch_optional(executor)
        .await
        .map_err(repository_error)?
        .map(transaction_row)
        .transpose()
}

pub(crate) async fn refresh_pending_application_offer<'executor, E>(
    executor: E,
    current: &CredentialTransaction,
    prepared: &CredentialTransaction,
    refresh_canvas_context: bool,
) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>
where
    E: Executor<'executor, Database = Postgres>,
{
    let Some(application_id) = current.application_id.as_deref() else {
        return Ok(None);
    };
    let query = if refresh_canvas_context {
        let validity_days = i32::try_from(prepared.validity_days)
            .map_err(|_| CredentialIssuanceError::RepositoryUnavailable)?;
        let renewal_window_days = i32::try_from(prepared.renewal_window_days)
            .map_err(|_| CredentialIssuanceError::RepositoryUnavailable)?;
        sqlx::query(REFRESH_PENDING_CANVAS_APPLICATION_OFFER)
            .bind(&current.id)
            .bind(&current.organization_id)
            .bind(&prepared.delivery_mode)
            .bind(&prepared.revocation_profile_id)
            .bind(&prepared.issuer_profile_id)
            .bind(&prepared.issuer_mode)
            .bind(&prepared.issuer_did)
            .bind(&prepared.issuer_algorithm)
            .bind(&prepared.signing_service_id)
            .bind(&prepared.credential_template_id)
            .bind(Value::Object(prepared.claims.clone()))
            .bind(&prepared.credential_type)
            .bind(&prepared.credential_payload_format)
            .bind(Value::Array(prepared.wallet_configs.clone()))
            .bind(json!(prepared.selective_disclosure_claims))
            .bind(json!(prepared.zk_predicate_claims))
            .bind(validity_days)
            .bind(prepared.renewable)
            .bind(renewal_window_days)
            .bind(application_id)
    } else {
        sqlx::query(REFRESH_PENDING_APPLICATION_OFFER)
            .bind(&current.id)
            .bind(&current.organization_id)
            .bind(&prepared.delivery_mode)
            .bind(&prepared.revocation_profile_id)
            .bind(&prepared.issuer_profile_id)
            .bind(&prepared.issuer_mode)
            .bind(&prepared.issuer_did)
            .bind(&prepared.issuer_algorithm)
            .bind(&prepared.signing_service_id)
            .bind(application_id)
    };
    query
        .fetch_optional(executor)
        .await
        .map_err(repository_error)?
        .map(transaction_row)
        .transpose()
}

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
    async fn resolve_access_token_grant(
        &self,
        access_token: &str,
    ) -> Result<CredentialAccessTokenGrant, CredentialIssuanceError> {
        let resolver = PostgresOid4vciAuthorizationRepository::new(
            self.pool.clone(),
            self.token_hmac_key.as_ref(),
        );
        let Some(_) = resolver
            .access_token_grant(access_token)
            .await
            .map_err(|_| CredentialIssuanceError::RepositoryUnavailable)?
        else {
            return Ok(CredentialAccessTokenGrant::Missing);
        };
        if let Some(transaction) = self.transaction_by_access_token(access_token).await? {
            return Ok(CredentialAccessTokenGrant::Transaction(Box::new(
                transaction,
            )));
        }
        self.authorization_by_access_token(access_token)
            .await
            .map(|session| {
                session.map_or(CredentialAccessTokenGrant::Missing, |session| {
                    CredentialAccessTokenGrant::Authorization(session)
                })
            })
    }

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
            "SELECT id, client_id, organization_id, issuer_state,
                    credential_configuration_ids, dpop_jkt,
                    access_token_expires_at
             FROM issuance_service.authorization_sessions
             WHERE access_token = $1
               AND access_token_expires_at > clock_timestamp()",
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
            if let Some(transaction) = sqlx::query(BIND_AUTHORIZATION_TRANSACTION)
                .bind(issuer_state)
                .bind(&session.organization_id)
                .bind(&session.client_id)
                .bind(&session.dpop_jkt)
                .bind(hash_access_token(&self.token_hmac_key, access_token))
                .bind(session.access_token_expires_at)
                .fetch_optional(&self.pool)
                .await
                .map_err(repository_error)?
                .map(transaction_row)
                .transpose()?
            {
                return Ok(transaction);
            }
            if self
                .transaction_by_query(TRANSACTION_BY_PRE_AUTH_CODE, issuer_state)
                .await?
                .is_some()
            {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
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
        let access_token_digest = hash_access_token(&self.token_hmac_key, access_token);
        let claims = session
            .dpop_jkt
            .as_ref()
            .map_or_else(|| json!({}), |jkt| json!({"_dpop_jkt": jkt}));
        sqlx::query(
            "INSERT INTO issuance_service.issuance_transactions
                 (id, organization_id, credential_template_id, status, pre_auth_code,
                  access_token, access_token_expires_at, c_nonce, claims, credential_type, issuer_mode,
                  issuer_did_override, issuer_algorithm, credential_payload_format,
                  selective_disclosure_claims, wallet_configs, validity_days,
                  oid4vci_client_id,
                  created_at, expires_at)
             VALUES ($1, $2, '', 'authorized', $3, $4, $5, NULL, $6, $7, 'org_managed',
                     $8, $9, 'w3c_vcdm_v2_sd_jwt', '[]'::jsonb, '[]'::jsonb, 365, $10,
                     clock_timestamp(), clock_timestamp() + interval '15 minutes')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&transaction_id)
        .bind(&session.organization_id)
        .bind(random_capability())
        .bind(&access_token_digest)
        .bind(session.access_token_expires_at)
        .bind(claims)
        .bind(credential_type)
        .bind(issuer_did)
        .bind(algorithm)
        .bind(&session.client_id)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        sqlx::query(TRANSACTION_BY_AUTHORIZATION_SESSION)
            .bind(&transaction_id)
            .bind(&session.organization_id)
            .bind(&session.client_id)
            .bind(access_token_digest)
            .bind(session.access_token_expires_at)
            .bind(&session.dpop_jkt)
            .bind(credential_type)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()?
            .ok_or(CredentialIssuanceError::RepositoryUnavailable)
    }

    async fn credential_by_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ExistingCredential>, CredentialIssuanceError> {
        let row = sqlx::query(
            "SELECT credential.id, credential.transaction_id, credential.credential_jwt,
                    transaction.organization_id AS binding_organization_id,
                    transaction.application_id AS binding_authoritative_application_id,
                    binding.application_id AS notification_binding_application_id,
                    binding.metadata AS notification_binding
             FROM issuance_service.issued_credentials AS credential
             JOIN issuance_service.issuance_transactions AS transaction
               ON transaction.id = credential.transaction_id
              AND transaction.organization_id = credential.organization_id
             LEFT JOIN LATERAL (
                 SELECT event.application_id, event.metadata
                 FROM issuance_service.issuance_events AS event
                 WHERE event.id = $2
                   AND event.transaction_id = credential.transaction_id
                   AND event.event_type = 'oid4vci_notification_binding'
                 LIMIT 1
             ) AS binding ON TRUE
             WHERE credential.transaction_id = $1",
        )
        .bind(transaction_id)
        .bind(notification_binding_event_id(transaction_id))
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let credential_id = get::<String>(&row, "id")?;
        let transaction_id = get::<String>(&row, "transaction_id")?;
        let organization_id = get::<String>(&row, "binding_organization_id")?;
        let application_id = get::<Option<String>>(&row, "binding_authoritative_application_id")?;
        let notification_id = match get::<Option<Value>>(&row, "notification_binding")? {
            Some(binding) => {
                let notification_id = binding
                    .get("notification_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or(CredentialIssuanceError::RepositoryUnavailable)?;
                if binding.get("credential_id").and_then(Value::as_str)
                    != Some(credential_id.as_str())
                    || binding.get("organization_id").and_then(Value::as_str)
                        != Some(organization_id.as_str())
                    || get::<Option<String>>(&row, "notification_binding_application_id")?
                        != application_id
                {
                    return Err(CredentialIssuanceError::RepositoryUnavailable);
                }
                notification_id.to_owned()
            }
            None => {
                let notification_id = legacy_notification_id(&transaction_id);
                insert_notification_binding_record(
                    &self.pool,
                    &transaction_id,
                    &credential_id,
                    &notification_id,
                )
                .await?
            }
        };
        Ok(Some(ExistingCredential {
            id: credential_id,
            credential: get(&row, "credential_jwt")?,
            notification_id,
        }))
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
        notification_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        let mut database = self.pool.begin().await.map_err(repository_error)?;
        finalize_credential(
            &mut database,
            transaction,
            credential,
            Some(notification_id),
        )
        .await?;
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
               AND (delivery.status IN ($3, $4, 'transported')
                    OR ($5 AND delivery.status = 'delivered'))",
        )
        .bind(transaction_id)
        .bind(organization_id)
        .bind(DIDCOMM_TRANSPORT_READY_STATUS)
        .bind(DIDCOMM_TRANSPORT_RETRYABLE_STATUS)
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

    async fn claim_transport(
        &self,
        organization_id: &str,
        transaction_id: &str,
        holder_did: &str,
    ) -> Result<InitiationDidcommTransportClaimOutcome, CredentialIssuanceError> {
        let mut database = self.pool.begin().await.map_err(repository_error)?;
        let mut delivery_rows = sqlx::query(
            "SELECT id, credential_id, transaction_id, organization_id, status, metadata,
                    clock_timestamp() AS database_now
             FROM issuance_service.credential_delivery_records
             WHERE transaction_id = $1
               AND organization_id = $2
               AND delivery_target = 'didcomm_v2'
             FOR UPDATE",
        )
        .bind(transaction_id)
        .bind(organization_id)
        .fetch_all(&mut *database)
        .await
        .map_err(repository_error)?;
        if delivery_rows.is_empty() {
            database.commit().await.map_err(repository_error)?;
            return Ok(InitiationDidcommTransportClaimOutcome::Absent);
        }
        if delivery_rows.len() != 1 {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        }
        let delivery_row = delivery_rows
            .pop()
            .ok_or(CredentialIssuanceError::RepositoryUnavailable)?;
        let delivery_id = get::<String>(&delivery_row, "id")?;
        let credential_id = get::<String>(&delivery_row, "credential_id")?;
        let bound_transaction_id = get::<String>(&delivery_row, "transaction_id")?;
        let bound_organization_id = get::<String>(&delivery_row, "organization_id")?;
        let delivery_status = get::<String>(&delivery_row, "status")?;
        let metadata = get::<Value>(&delivery_row, "metadata")?;
        let database_now = get::<DateTime<Utc>>(&delivery_row, "database_now")?;

        let holder = metadata_required_text(&metadata, "holder_did")?;
        let service_endpoint = metadata_required_text(&metadata, "service_endpoint")?;
        let message_id = metadata_required_text(&metadata, "didcomm_message_id")?;
        if bound_transaction_id != transaction_id
            || bound_organization_id != organization_id
            || holder != holder_did
        {
            database.commit().await.map_err(repository_error)?;
            return Ok(InitiationDidcommTransportClaimOutcome::BindingMismatch);
        }

        let transaction = sqlx::query(TRANSACTION_BY_ID_AND_ORGANIZATION)
            .bind(transaction_id)
            .bind(organization_id)
            .fetch_optional(&mut *database)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()?;
        let credential_row = sqlx::query(
            "SELECT id, transaction_id, organization_id, credential_template_id, applicant_id,
                    subject_did, issuer_did, revocation_profile_id,
                    renewed_from_credential_id, status_list_entries, credential_jwt,
                    credential_hash, issued_at, expires_at
             FROM issuance_service.issued_credentials
             WHERE id = $1 AND transaction_id = $2 AND organization_id = $3",
        )
        .bind(&credential_id)
        .bind(transaction_id)
        .bind(organization_id)
        .fetch_optional(&mut *database)
        .await
        .map_err(repository_error)?;
        let (Some(transaction), Some(credential_row)) = (transaction, credential_row) else {
            database.commit().await.map_err(repository_error)?;
            return Ok(InitiationDidcommTransportClaimOutcome::BindingMismatch);
        };
        let credential = issued_credential_row(&credential_row)?;
        if transaction.status != CredentialTransactionStatus::Issued
            || credential.id != credential_id
            || delivery_id != delivery_record_id(&credential.id, "didcomm_v2", None)
            || credential.id != reserved_credential_id(&transaction)
            || credential.transaction_id != transaction.id
            || credential.organization_id != transaction.organization_id
        {
            database.commit().await.map_err(repository_error)?;
            return Ok(InitiationDidcommTransportClaimOutcome::BindingMismatch);
        }

        if delivery_status == "delivered" {
            database.commit().await.map_err(repository_error)?;
            return Ok(InitiationDidcommTransportClaimOutcome::Delivered(
                DeliveredInitiationDidcommDelivery {
                    transaction_id: transaction.id,
                    organization_id: transaction.organization_id,
                    credential_id,
                    holder_did: holder,
                    service_endpoint,
                    message_id,
                },
            ));
        }

        let encrypted_message = metadata_required_text(&metadata, "encrypted_message")?;
        let pending = PendingInitiationDidcommDelivery {
            transaction,
            credential,
            delivery: StagedInitiationDidcommDelivery {
                holder_did: holder,
                service_endpoint,
                message_id,
                encrypted_message,
            },
            transported: delivery_status == "transported",
        };
        match delivery_status.as_str() {
            "pending" | "failed" => {
                mark_locked_didcomm_outcome_unknown(&mut database, &delivery_id).await?;
                database.commit().await.map_err(repository_error)?;
                Ok(InitiationDidcommTransportClaimOutcome::OutcomeUnknown)
            }
            "transported" => {
                database.commit().await.map_err(repository_error)?;
                Ok(InitiationDidcommTransportClaimOutcome::Transported(
                    Box::new(pending),
                ))
            }
            "delivery_unknown" => {
                database.commit().await.map_err(repository_error)?;
                Ok(InitiationDidcommTransportClaimOutcome::OutcomeUnknown)
            }
            "transporting" => {
                let attempt_id = metadata
                    .get("didcomm_transport_attempt_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| Uuid::parse_str(value).is_ok());
                let deadline = metadata
                    .get("didcomm_transport_lease_expires_at")
                    .and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .map(|value| value.with_timezone(&Utc));
                if attempt_id.is_some() && deadline.is_some_and(|value| value > database_now) {
                    database.commit().await.map_err(repository_error)?;
                    return Ok(InitiationDidcommTransportClaimOutcome::Busy);
                }
                mark_locked_didcomm_outcome_unknown(&mut database, &delivery_id).await?;
                database.commit().await.map_err(repository_error)?;
                Ok(InitiationDidcommTransportClaimOutcome::OutcomeUnknown)
            }
            DIDCOMM_TRANSPORT_READY_STATUS | DIDCOMM_TRANSPORT_RETRYABLE_STATUS => {
                let attempt_id = Uuid::new_v4().to_string();
                let claimed = sqlx::query(
                    "UPDATE issuance_service.credential_delivery_records
                     SET status = 'transporting', last_error = NULL,
                         metadata = (metadata
                             - 'didcomm_transport_attempt_id'
                             - 'didcomm_transport_lease_expires_at')
                             || jsonb_build_object(
                                 'didcomm_transport_attempt_id', $10::text,
                                 'didcomm_transport_lease_expires_at',
                                 clock_timestamp() + $11::integer * INTERVAL '1 second'),
                         updated_at = clock_timestamp()
                     WHERE id = $1
                       AND credential_id = $2
                       AND transaction_id = $3
                       AND organization_id = $4
                       AND delivery_target = 'didcomm_v2'
                       AND status = $5
                       AND metadata ->> 'holder_did' = $6
                       AND metadata ->> 'service_endpoint' = $7
                       AND metadata ->> 'didcomm_message_id' = $8
                       AND metadata ->> 'encrypted_message' = $9",
                )
                .bind(&delivery_id)
                .bind(&pending.credential.id)
                .bind(&pending.transaction.id)
                .bind(&pending.transaction.organization_id)
                .bind(&delivery_status)
                .bind(&pending.delivery.holder_did)
                .bind(&pending.delivery.service_endpoint)
                .bind(&pending.delivery.message_id)
                .bind(&pending.delivery.encrypted_message)
                .bind(&attempt_id)
                .bind(DIDCOMM_TRANSPORT_CLAIM_LEASE_SECONDS)
                .execute(&mut *database)
                .await
                .map_err(repository_error)?;
                if claimed.rows_affected() != 1 {
                    return Err(CredentialIssuanceError::RepositoryUnavailable);
                }
                database.commit().await.map_err(repository_error)?;
                Ok(InitiationDidcommTransportClaimOutcome::Claimed(
                    InitiationDidcommTransportClaim::new(pending, delivery_id, attempt_id),
                ))
            }
            _ => Err(CredentialIssuanceError::RepositoryUnavailable),
        }
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
        let mut database = self.pool.begin().await.map_err(repository_error)?;
        finalize_credential(&mut database, transaction, credential, None).await?;
        database.commit().await.map_err(repository_error)
    }

    async fn stage_delivery(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        delivery: &StagedInitiationDidcommDelivery,
    ) -> Result<(), CredentialIssuanceError> {
        let mut database = self.pool.begin().await.map_err(repository_error)?;
        finalize_credential(&mut database, transaction, credential, None).await?;
        sqlx::query(
            "INSERT INTO issuance_service.credential_delivery_records
                 (id, credential_id, transaction_id, organization_id, delivery_target,
                  delivery_mode, status, canvas_account_id, last_error, metadata,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'didcomm_v2', $5, $6, NULL, NULL, $7,
                     clock_timestamp(), clock_timestamp())",
        )
        .bind(delivery_record_id(&credential.id, "didcomm_v2", None))
        .bind(&credential.id)
        .bind(&transaction.id)
        .bind(&transaction.organization_id)
        .bind(&transaction.delivery_mode)
        .bind(DIDCOMM_TRANSPORT_READY_STATUS)
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

    async fn mark_transport_succeeded(
        &self,
        claim: &InitiationDidcommTransportClaim,
    ) -> Result<(), CredentialIssuanceError> {
        finish_didcomm_transport_claim(&self.pool, claim, "transported", None).await
    }

    async fn mark_transport_unattempted(
        &self,
        claim: &InitiationDidcommTransportClaim,
    ) -> Result<(), CredentialIssuanceError> {
        finish_didcomm_transport_claim(
            &self.pool,
            claim,
            DIDCOMM_TRANSPORT_RETRYABLE_STATUS,
            Some("didcomm_delivery_failed"),
        )
        .await
    }

    async fn mark_transport_outcome_unknown(
        &self,
        claim: &InitiationDidcommTransportClaim,
    ) -> Result<(), CredentialIssuanceError> {
        finish_didcomm_transport_claim(
            &self.pool,
            claim,
            "delivery_unknown",
            Some("didcomm_delivery_outcome_unknown"),
        )
        .await
    }
}

#[derive(Debug)]
struct CanvasProjection {
    application_id: String,
    organization_id: String,
    candidate_id: Option<String>,
    renewal_source: Option<String>,
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

pub(crate) fn transaction_row(
    row: PgRow,
) -> Result<CredentialTransaction, CredentialIssuanceError> {
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
impl RenewalRepository for PostgresCredentialRepository {
    async fn source(&self, id: &str) -> Result<Option<RenewalSource>, RenewalRepositoryError> {
        let row = sqlx::query(
            "SELECT id, organization_id, transaction_id, credential_template_id,
                    applicant_id, subject_did, status, renewed_to_credential_id, expires_at
             FROM issuance_service.issued_credentials WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RenewalRepositoryError::Unavailable)?;
        row.map(|row| {
            Ok(RenewalSource {
                id: row.try_get("id")?,
                organization_id: row.try_get("organization_id")?,
                transaction_id: row.try_get("transaction_id")?,
                credential_template_id: row.try_get("credential_template_id")?,
                applicant_id: row.try_get("applicant_id")?,
                subject_did: row.try_get("subject_did")?,
                status: row.try_get("status")?,
                renewed_to_credential_id: row.try_get("renewed_to_credential_id")?,
                expires_at: row.try_get("expires_at")?,
            })
        })
        .transpose()
        .map_err(|_: sqlx::Error| RenewalRepositoryError::Unavailable)
    }

    async fn source_transaction(
        &self,
        source: &RenewalSource,
    ) -> Result<Option<CredentialTransaction>, RenewalRepositoryError> {
        sqlx::query(TRANSACTION_BY_ID_AND_ORGANIZATION)
            .bind(&source.transaction_id)
            .bind(&source.organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| RenewalRepositoryError::Unavailable)?
            .map(transaction_row)
            .transpose()
            .map_err(|_| RenewalRepositoryError::Unavailable)
    }

    async fn bind_reservation(
        &self,
        transaction: &CredentialTransaction,
        source: &RenewalSource,
        application_id: Option<&str>,
    ) -> Result<CredentialTransaction, RenewalRepositoryError> {
        if transaction.organization_id != source.organization_id {
            return Err(RenewalRepositoryError::BindingConflict);
        }
        let mut database = self
            .pool
            .begin()
            .await
            .map_err(|_| RenewalRepositoryError::Unavailable)?;
        let bound = sqlx::query(BIND_RENEWAL_RESERVATION)
            .bind(&transaction.id)
            .bind(&source.organization_id)
            .bind(&source.id)
            .bind(application_id)
            .bind(&transaction.idempotency_key_hash)
            .bind(&transaction.idempotency_request_hash)
            .fetch_optional(&mut *database)
            .await
            .map_err(|_| RenewalRepositoryError::Unavailable)?
            .map(transaction_row)
            .transpose()
            .map_err(|_| RenewalRepositoryError::Unavailable)?;
        if let Some(bound) = bound {
            bind_canvas_renewal_application(&mut database, &bound, source, application_id).await?;
            database
                .commit()
                .await
                .map_err(|_| RenewalRepositoryError::Unavailable)?;
            return Ok(bound);
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM issuance_service.issuance_transactions
             WHERE id = $1 AND organization_id = $2)",
        )
        .bind(&transaction.id)
        .bind(&source.organization_id)
        .fetch_one(&mut *database)
        .await
        .map_err(|_| RenewalRepositoryError::Unavailable)?;
        Err(if exists {
            RenewalRepositoryError::BindingConflict
        } else {
            RenewalRepositoryError::ReservationMissing
        })
    }
}

/// Only actual Canvas-marked applications need their approved current
/// transaction moved. Generic applications and absent historical IDs retain
/// existing behavior. Candidate links and this association commit together.
async fn bind_canvas_renewal_application(
    database: &mut Transaction<'_, Postgres>,
    candidate: &CredentialTransaction,
    source: &RenewalSource,
    application_id: Option<&str>,
) -> Result<(), RenewalRepositoryError> {
    let Some(application_id) = application_id else {
        return Ok(());
    };
    let application: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(app) FROM issuance_service.applications app WHERE id=$1 FOR UPDATE",
    )
    .bind(application_id)
    .fetch_optional(&mut **database)
    .await
    .map_err(|_| RenewalRepositoryError::Unavailable)?;
    let Some(application) = application else {
        return Ok(());
    };
    if !application["integration_context"]["canvas"]
        .as_object()
        .is_some_and(crate::canvas_issuance_guard::has_canvas_marker)
    {
        return Ok(());
    }
    let source_bound: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM issuance_service.issued_credentials source
         JOIN issuance_service.issuance_transactions original
           ON original.id=source.transaction_id AND original.organization_id=source.organization_id
         WHERE source.id=$1 AND source.organization_id=$2 AND source.transaction_id=$3
           AND original.application_id=$4
           AND (source.status='active' AND (source.renewed_to_credential_id IS NULL OR source.renewed_to_credential_id='')
                OR source.status='revoked' AND source.revoked=true AND EXISTS(
                  SELECT 1 FROM issuance_service.issued_credentials successor
                  WHERE successor.id=source.renewed_to_credential_id AND successor.transaction_id=$5
                    AND successor.organization_id=$2 AND successor.renewed_from_credential_id=source.id)))",
    ).bind(&source.id).bind(&source.organization_id).bind(&source.transaction_id)
      .bind(application_id).bind(&candidate.id).fetch_one(&mut **database).await
      .map_err(|_| RenewalRepositoryError::Unavailable)?;
    let current = application["issuance_transaction_id"].as_str();
    if !source_bound
        || application["organization_id"] != source.organization_id
        || !application["status"]
            .as_str()
            .is_some_and(|status| status.eq_ignore_ascii_case("approved"))
        || !matches!(current, Some(id) if id == source.transaction_id || id == candidate.id)
    {
        return Err(RenewalRepositoryError::BindingConflict);
    }
    if let Some(current_credential) = application["credential_id"].as_str() {
        if current_credential != source.id {
            let successor: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM issuance_service.issued_credentials
                 WHERE id=$1 AND transaction_id=$2 AND organization_id=$3 AND renewed_from_credential_id=$4)",
            ).bind(current_credential).bind(&candidate.id).bind(&source.organization_id).bind(&source.id)
              .fetch_one(&mut **database).await.map_err(|_| RenewalRepositoryError::Unavailable)?;
            if !successor {
                return Err(RenewalRepositoryError::BindingConflict);
            }
        }
    }
    if current == Some(candidate.id.as_str()) {
        return Ok(());
    }
    // Do not clear the source credential or award-candidate claim. Their current
    // pointers advance only with successful credential finalization.
    let updated = sqlx::query(
        "UPDATE issuance_service.applications SET issuance_transaction_id=$3
         WHERE id=$1 AND organization_id=$2 AND issuance_transaction_id=$4
           AND lower(status)='approved' AND (credential_id IS NULL OR credential_id=$5)",
    )
    .bind(application_id)
    .bind(&source.organization_id)
    .bind(&candidate.id)
    .bind(&source.transaction_id)
    .bind(&source.id)
    .execute(&mut **database)
    .await
    .map_err(|_| RenewalRepositoryError::Unavailable)?;
    if updated.rows_affected() != 1 {
        return Err(RenewalRepositoryError::BindingConflict);
    }
    Ok(())
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
        let created = insert_issuance_transaction(&self.pool, transaction)
            .await
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
        client_id: get(&row, "client_id")?,
        organization_id,
        issuer_state: get(&row, "issuer_state")?,
        credential_configuration_ids: json_vec(&row, "credential_configuration_ids")?,
        dpop_jkt: get(&row, "dpop_jkt")?,
        access_token_expires_at: get(&row, "access_token_expires_at")?,
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
    notification_id: Option<&str>,
) -> Result<(), CredentialIssuanceError> {
    validate_finalization_input(transaction, credential)?;
    let authoritative = sqlx::query(
        "SELECT organization_id, credential_template_id, application_id, renewal_of_credential_id, status,
                reserved_credential_id
         FROM issuance_service.issuance_transactions WHERE id = $1 FOR UPDATE",
    )
    .bind(&transaction.id)
    .fetch_optional(&mut **database)
    .await
    .map_err(repository_error)?
    .ok_or(CredentialIssuanceError::RepositoryUnavailable)?;
    validate_authoritative_finalization(&authoritative, credential)?;
    if renewal_source_id(
        get::<Option<String>>(&authoritative, "renewal_of_credential_id")?.as_deref(),
    ) != renewal_source_id(credential.renewed_from_credential_id.as_deref())
    {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    if credential_exists(database, &transaction.id).await? {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    let canvas = prepare_canvas_projection(
        database,
        get::<Option<String>>(&authoritative, "application_id")?.as_deref(),
        &credential.organization_id,
        &credential.id,
        &transaction.id,
        get::<Option<String>>(&authoritative, "renewal_of_credential_id")?.as_deref(),
    )
    .await?;
    insert_credential(database, credential).await?;
    if let Some(notification_id) = notification_id {
        insert_notification_binding(database, transaction, credential, notification_id).await?;
    }
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

async fn insert_notification_binding(
    database: &mut Transaction<'_, Postgres>,
    transaction: &CredentialTransaction,
    credential: &IssuedCredential,
    notification_id: &str,
) -> Result<(), CredentialIssuanceError> {
    if notification_id.trim().is_empty() {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    sqlx::query(INSERT_NOTIFICATION_BINDING)
        .bind(notification_binding_event_id(&transaction.id))
        .bind(&transaction.id)
        .bind(&credential.id)
        .bind(notification_id)
        .execute(&mut **database)
        .await
        .map_err(repository_error)?;
    let rows = sqlx::query(
        "SELECT id, transaction_id, application_id, event_type, metadata
         FROM issuance_service.issuance_events
         WHERE id = $1
            OR (event_type = 'oid4vci_notification_binding'
                AND metadata ->> 'notification_id' = $2)
         FOR UPDATE",
    )
    .bind(notification_binding_event_id(&transaction.id))
    .bind(notification_id)
    .fetch_all(&mut **database)
    .await
    .map_err(repository_error)?;
    if rows.len() != 1 {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    validate_notification_binding(
        &rows[0],
        &transaction.id,
        &credential.id,
        &transaction.organization_id,
        transaction.application_id.as_deref(),
        notification_id,
    )?;
    Ok(())
}

const INSERT_NOTIFICATION_BINDING: &str = "INSERT INTO issuance_service.issuance_events
         (id, transaction_id, application_id, event_type, metadata, created_at)
     SELECT $1, transaction.id, transaction.application_id,
            'oid4vci_notification_binding',
            jsonb_build_object(
                'notification_id', $4::text,
                'credential_id', credential.id,
                'organization_id', transaction.organization_id
            ),
            clock_timestamp()
     FROM issuance_service.issuance_transactions AS transaction
     JOIN issuance_service.issued_credentials AS credential
       ON credential.transaction_id = transaction.id
      AND credential.id = $3
      AND credential.organization_id = transaction.organization_id
     WHERE transaction.id = $2
     ON CONFLICT DO NOTHING";

async fn insert_notification_binding_record(
    pool: &PgPool,
    transaction_id: &str,
    credential_id: &str,
    notification_id: &str,
) -> Result<String, CredentialIssuanceError> {
    let event_id = notification_binding_event_id(transaction_id);
    let authority = sqlx::query(
        "SELECT transaction.organization_id, transaction.application_id
         FROM issuance_service.issuance_transactions AS transaction
         JOIN issuance_service.issued_credentials AS credential
           ON credential.transaction_id = transaction.id
          AND credential.id = $2
          AND credential.organization_id = transaction.organization_id
         WHERE transaction.id = $1",
    )
    .bind(transaction_id)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(repository_error)?
    .ok_or(CredentialIssuanceError::RepositoryUnavailable)?;
    let organization_id = get::<String>(&authority, "organization_id")?;
    let application_id = get::<Option<String>>(&authority, "application_id")?;
    sqlx::query(INSERT_NOTIFICATION_BINDING)
        .bind(&event_id)
        .bind(transaction_id)
        .bind(credential_id)
        .bind(notification_id)
        .execute(pool)
        .await
        .map_err(repository_error)?;
    let rows = sqlx::query(
        "SELECT id, transaction_id, application_id, event_type, metadata
         FROM issuance_service.issuance_events
         WHERE id = $1
            OR (event_type = 'oid4vci_notification_binding'
                AND metadata ->> 'notification_id' = $2)",
    )
    .bind(&event_id)
    .bind(notification_id)
    .fetch_all(pool)
    .await
    .map_err(repository_error)?;
    if rows.len() != 1 {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    validate_notification_binding(
        &rows[0],
        transaction_id,
        credential_id,
        &organization_id,
        application_id.as_deref(),
        notification_id,
    )?;
    Ok(notification_id.to_owned())
}

fn validate_notification_binding(
    row: &PgRow,
    transaction_id: &str,
    credential_id: &str,
    organization_id: &str,
    application_id: Option<&str>,
    notification_id: &str,
) -> Result<(), CredentialIssuanceError> {
    let metadata = get::<Value>(row, "metadata")?;
    if get::<Option<String>>(row, "transaction_id")?.as_deref() != Some(transaction_id)
        || get::<String>(row, "event_type")? != "oid4vci_notification_binding"
        || get::<Option<String>>(row, "application_id")?.as_deref() != application_id
        || metadata.get("notification_id").and_then(Value::as_str) != Some(notification_id)
        || metadata.get("credential_id").and_then(Value::as_str) != Some(credential_id)
        || metadata.get("organization_id").and_then(Value::as_str) != Some(organization_id)
    {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    Ok(())
}

fn notification_binding_event_id(transaction_id: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("marty:oid4vci:notification-binding:{transaction_id}").as_bytes(),
    )
    .to_string()
}

fn legacy_notification_id(transaction_id: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("marty:oid4vci:legacy-notification:{transaction_id}").as_bytes(),
    )
    .to_string()
}

fn metadata_required_text(metadata: &Value, name: &str) -> Result<String, CredentialIssuanceError> {
    metadata
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(CredentialIssuanceError::RepositoryUnavailable)
}

fn issued_credential_row(row: &PgRow) -> Result<IssuedCredential, CredentialIssuanceError> {
    Ok(IssuedCredential {
        id: get(row, "id")?,
        transaction_id: get(row, "transaction_id")?,
        organization_id: get(row, "organization_id")?,
        credential_template_id: get(row, "credential_template_id")?,
        applicant_id: get(row, "applicant_id")?,
        subject_did: get(row, "subject_did")?,
        issuer_did: get(row, "issuer_did")?,
        revocation_profile_id: get(row, "revocation_profile_id")?,
        renewed_from_credential_id: get(row, "renewed_from_credential_id")?,
        status_list_entries: json_vec(row, "status_list_entries")?,
        credential: get(row, "credential_jwt")?,
        credential_hash: get(row, "credential_hash")?,
        issued_at: get(row, "issued_at")?,
        expires_at: get(row, "expires_at")?,
    })
}

async fn mark_locked_didcomm_outcome_unknown(
    database: &mut Transaction<'_, Postgres>,
    delivery_id: &str,
) -> Result<(), CredentialIssuanceError> {
    let updated = sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET status = 'delivery_unknown',
             last_error = 'didcomm_delivery_outcome_unknown',
             metadata = metadata
                 - 'didcomm_transport_attempt_id'
                 - 'didcomm_transport_lease_expires_at',
             updated_at = clock_timestamp()
         WHERE id = $1
           AND delivery_target = 'didcomm_v2'
           AND status IN ('transporting', 'pending', 'failed')",
    )
    .bind(delivery_id)
    .execute(&mut **database)
    .await
    .map_err(repository_error)?;
    if updated.rows_affected() != 1 {
        return Err(CredentialIssuanceError::RepositoryUnavailable);
    }
    Ok(())
}

async fn finish_didcomm_transport_claim(
    pool: &PgPool,
    claim: &InitiationDidcommTransportClaim,
    status: &str,
    last_error: Option<&str>,
) -> Result<(), CredentialIssuanceError> {
    let pending = claim.pending();
    let updated = sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET status = $1, last_error = $2,
             metadata = metadata
                 - 'didcomm_transport_attempt_id'
                 - 'didcomm_transport_lease_expires_at',
             updated_at = clock_timestamp()
         WHERE id = $3
           AND credential_id = $4
           AND transaction_id = $5
           AND organization_id = $6
           AND delivery_target = 'didcomm_v2'
           AND status = 'transporting'
           AND metadata ->> 'didcomm_transport_attempt_id' = $7
           AND metadata ->> 'holder_did' = $8
           AND metadata ->> 'service_endpoint' = $9
           AND metadata ->> 'didcomm_message_id' = $10
           AND metadata ->> 'encrypted_message' = $11",
    )
    .bind(status)
    .bind(last_error)
    .bind(claim.delivery_id())
    .bind(&pending.credential.id)
    .bind(&pending.transaction.id)
    .bind(&pending.transaction.organization_id)
    .bind(claim.attempt_id())
    .bind(&pending.delivery.holder_did)
    .bind(&pending.delivery.service_endpoint)
    .bind(&pending.delivery.message_id)
    .bind(&pending.delivery.encrypted_message)
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
    transaction_id: &str,
    renewal_source: Option<&str>,
) -> Result<Option<CanvasProjection>, CredentialIssuanceError> {
    let renewal_source = renewal_source_id(renewal_source);
    let Some(application_id) = application_id.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let application = sqlx::query(
        "SELECT id, organization_id, credential_id, integration_context, issuance_transaction_id
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
    if let Some(source_id) = renewal_source {
        let lineage: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM issuance_service.issued_credentials source
             JOIN issuance_service.issuance_transactions original
               ON original.id=source.transaction_id AND original.organization_id=source.organization_id
             JOIN issuance_service.issuance_transactions successor
               ON successor.id=$3 AND successor.organization_id=source.organization_id
              AND successor.renewal_of_credential_id=source.id AND successor.application_id=$4
             WHERE source.id=$1 AND source.organization_id=$2 AND original.application_id=$4)",
        ).bind(source_id).bind(organization_id).bind(transaction_id).bind(application_id)
          .fetch_one(&mut **database).await.map_err(repository_error)?;
        if !lineage
            || get::<Option<String>>(&application, "issuance_transaction_id")?.as_deref()
                != Some(transaction_id)
        {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        }
    }
    let current_credential = get::<Option<String>>(&application, "credential_id")?;
    if current_credential
        .as_deref()
        .is_some_and(|value| value != credential_id && Some(value) != renewal_source)
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
                    .is_some_and(|value| value != credential_id && Some(value) != renewal_source)
            {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            }
        } else {
            return Ok(Some(CanvasProjection {
                application_id: application_id.to_owned(),
                organization_id: organization_id.to_owned(),
                candidate_id: None,
                renewal_source: renewal_source.map(str::to_owned),
            }));
        }
    }
    Ok(Some(CanvasProjection {
        application_id: application_id.to_owned(),
        organization_id: organization_id.to_owned(),
        candidate_id,
        renewal_source: renewal_source.map(str::to_owned),
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
           AND (credential_id IS NULL OR credential_id = $3 OR credential_id = $5)",
    )
    .bind(&projection.application_id)
    .bind(&projection.organization_id)
    .bind(&credential.id)
    .bind(credential.issued_at)
    .bind(&projection.renewal_source)
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
               AND (claimed_credential_id IS NULL OR claimed_credential_id = $3 OR claimed_credential_id = $5)",
        )
        .bind(candidate_id)
        .bind(&projection.organization_id)
        .bind(&credential.id)
        .bind(credential.issued_at)
        .bind(&projection.renewal_source)
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

fn renewal_source_id(value: Option<&str>) -> Option<&str> {
    // Historical ordinary rows can contain blank links. Meaningful identity
    // bytes are not trimmed or otherwise rewritten by this consistency guard.
    value.filter(|id| !id.trim().is_empty())
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
    use super::{authorization_transaction_id, canvas_context, renewal_source_id};
    use serde_json::json;

    #[test]
    fn renewal_lineage_treats_only_absent_or_blank_links_as_absent() {
        for value in [None, Some(""), Some(" \t\n")] {
            assert_eq!(renewal_source_id(value), None);
        }
        for value in ["source", " source", "source ", "other-source"] {
            assert_eq!(renewal_source_id(Some(value)), Some(value));
        }
        assert_ne!(
            renewal_source_id(Some(" source")),
            renewal_source_id(Some("source"))
        );
    }

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
