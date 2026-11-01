//! Bounded, installation-owned initial ACME enrolment.
//! Uses the maintained protocol, retained OpenBao keys and real HTTP-01 projection.
//! Successful issuance produces an admitted candidate, never an active generation.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme_certificates::{
        self as certificates, RetainedIngressKey, ValidatedCertificate, ValidatedCsr,
    },
    installer_acme_configuration::{AcmeEnvironment, BoundAcmeConfiguration},
    installer_acme_custody::AccountKeyBinding,
    installer_acme_state::{
        self as ledger, require, AuthorizationRecord, Binding, CertificateRecord, Ledger,
        OrderRecord, Projection, Retry, Stage, REFUSED,
    },
    installer_host_fs,
    installer_state::{ExecutionScope, InstallerState, LockedInspection, LockedMaintenance, Phase},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_acme_client::{
    protocol::{
        Account, AuthorizationStatus, ChallengeStatus, ChallengeType, Error as ProtocolError,
        ExternalAccountSigner, HttpClient, Identifier, NewAccount, NewOrder, Order, OrderStatus,
        ResponseMetadata,
    },
    AcmeHttps, OpenBaoAccountSigner, WorkloadCredentials,
};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::acme_http01::{
    AllowedIdentifiers, Challenge, Snapshot, MAX_LIFETIME_SECONDS, SNAPSHOT_BASENAME,
    SNAPSHOT_SCHEMA,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const HTTP01_DIRECTORY: &str = "acme-http01";
const WORK_DEADLINE: Duration = Duration::from_secs(90);
const SHORTLIVED_MAXIMUM_SECONDS: u64 = 160 * 3600;

/// Every value is validated against the held installation before network work.
/// The CSR is already signed remotely and admitted by the certificate boundary.
pub struct EnrolmentInputs<'a> {
    pub installation: &'a Path,
    pub configuration: &'a BoundAcmeConfiguration,
    pub account_key: &'a AccountKeyBinding,
    pub ingress_key: &'a RetainedIngressKey,
    pub csr: &'a ValidatedCsr,
    /// Explicit staging-only anchors. Production must supply None.
    pub staging_roots_pem: Option<&'a [u8]>,
}

/// Public certificate material with exact custody/order provenance. There is no
/// conversion to an active private-CA generation or installation Ready state.
#[derive(Clone, Debug, Serialize)]
pub struct AcmeCandidate {
    environment: AcmeEnvironment,
    installation_id: uuid::Uuid,
    enrolment_receipt_sha256: String,
    order_url: String,
    csr_sha256: String,
    fullchain_pem: String,
    metadata: Value,
}
impl AcmeCandidate {
    pub fn environment(&self) -> AcmeEnvironment {
        self.environment
    }
    pub fn fullchain_pem(&self) -> &str {
        &self.fullchain_pem
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
    pub fn enrolment_receipt_sha256(&self) -> &str {
        &self.enrolment_receipt_sha256
    }
}

#[derive(Debug, Serialize)]
pub struct EnrolmentOutcome {
    pub report: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<AcmeCandidate>,
}

fn now() -> Result<u64> {
    #[cfg(test)]
    if let Some(value) = TEST_TIME.with(std::cell::Cell::get) {
        return Ok(value);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| REFUSED.into())
}

#[cfg(test)]
thread_local! { static TEST_TIME: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }

/// First-install caller retains its original exclusive lock and phase.
/// This entry point never chooses an origin, accepts terms, creates a key,
/// starts a service, advances installer phase, or activates the returned chain.
pub fn run_for_install(
    state: &mut InstallerState,
    inputs: &EnrolmentInputs<'_>,
    bao: OpenBaoHttp,
    credentials: Arc<dyn WorkloadCredentials>,
) -> Result<EnrolmentOutcome> {
    state.require_live_phase(Phase::Provisioning)?;
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err("ACME enrolment requires a synchronous installer caller".into());
    }
    state.with_maintenance(|state| run_locked(state, inputs, bao, credentials))
}

pub(crate) fn run_locked(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    bao: OpenBaoHttp,
    credentials: Arc<dyn WorkloadCredentials>,
) -> Result<EnrolmentOutcome> {
    require(
        matches!(
            state.journal().execution_scope(),
            ExecutionScope::Unclassified
        ) && state.journal().phase() == Phase::Provisioning
            && state.journal().runtime().is_some_and(|runtime| {
                runtime.profile == crate::installer_state::RuntimeProfile::Rootless
            }),
    )?;
    state.journal().runtime().ok_or(REFUSED)?.validate()?;
    let binding = bind_inputs(state.inspection(), inputs)?;
    let signer = Arc::new(
        OpenBaoAccountSigner::new(
            bao,
            credentials,
            inputs.account_key.transit_key_name().into(),
            inputs
                .account_key
                .key_version()
                .try_into()
                .map_err(|_| REFUSED)?,
            inputs
                .account_key
                .public_sec1()
                .try_into()
                .map_err(|_| REFUSED)?,
        )
        .map_err(|_| REFUSED)?,
    );
    let http = Box::new(
        AcmeHttps::new(inputs.configuration.parameters().directory_url()).map_err(|_| REFUSED)?,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED)?;
    runtime.block_on(async {
        tokio::time::timeout(WORK_DEADLINE, drive(state, inputs, binding, signer, http))
            .await
            .map_err(|_| REFUSED)?
    })
}

/// Read-only evidence. Account/order existence, public reachability and current
/// certificate freshness are not re-observed by this status call.
pub fn status(state: &LockedInspection) -> Result<Value> {
    let mut environments = Vec::new();
    for environment in [AcmeEnvironment::Staging, AcmeEnvironment::Production] {
        if let Some(ledger) = Ledger::load(state, environment)? {
            environments.push(ledger.report());
        }
    }
    Ok(
        json!({"schema":"elevenid.installer-acme-status/v1","installation_id":state.journal().installation_id(),
        "configured":!environments.is_empty(),"environments":environments,"read_only":true,
        "activation_performed":false,"installation_ready":false,"automatic_renewal":false,
        "load_characterized":false,"functional_recovery_qualified":false}),
    )
}

/// Recover the exact CSR already bound to an enrolment, before requesting a new
/// remote signature. A known order always finalizes the original DER bytes.
pub fn retained_csr(
    state: &LockedInspection,
    configuration: &BoundAcmeConfiguration,
    ingress_key: &RetainedIngressKey,
) -> Result<Option<ValidatedCsr>> {
    let Some(saved) = Ledger::load(state, configuration.parameters().environment())? else {
        return Ok(None);
    };
    require(
        saved.binding.configuration == serde_json::to_value(configuration).map_err(|_| REFUSED)?
            && saved.binding.ingress_key_name == ingress_key.transit_key_name()
            && saved.binding.ingress_key_version == ingress_key.key_version()
            && saved.binding.ingress_spki_base64 == STANDARD.encode(ingress_key.public_spki_der()),
    )?;
    let csr = certificates::validate_signed_csr(
        saved.binding.csr_pem.as_bytes(),
        &configuration.certificate_identity()?,
        ingress_key,
    )?;
    require(
        STANDARD.encode(csr.der()) == saved.binding.csr_der_base64
            && ledger::hash(csr.der()) == saved.binding.csr_sha256
            && *csr.metadata() == saved.binding.csr_metadata,
    )?;
    Ok(Some(csr))
}

fn bind_inputs(state: &LockedInspection, inputs: &EnrolmentInputs<'_>) -> Result<Binding> {
    state.require_path_binding(inputs.installation)?;
    let expected = BoundAcmeConfiguration::bind(state, inputs.configuration.parameters().clone())?;
    require(
        expected == *inputs.configuration
            && inputs.account_key.installation_id() == state.journal().installation_id()
            && inputs.account_key.environment() == expected.parameters().environment()
            && inputs.account_key.public_spki_der() != inputs.ingress_key.public_spki_der(),
    )?;
    let identity = expected.certificate_identity()?;
    let csr = certificates::validate_signed_csr(
        inputs.csr.pem().as_bytes(),
        &identity,
        inputs.ingress_key,
    )?;
    require(csr.der() == inputs.csr.der() && csr.metadata() == inputs.csr.metadata())?;
    require(
        inputs.staging_roots_pem.is_some()
            == (expected.parameters().environment() == AcmeEnvironment::Staging),
    )?;
    if let Some(roots) = inputs.staging_roots_pem {
        require(!roots.is_empty() && roots.len() <= 64 * 1024)?;
    }
    projection_directory(state, inputs.installation)?;
    let binding = Binding {
        installation_id: state.journal().installation_id(),
        environment: expected.parameters().environment(),
        configuration: serde_json::to_value(&expected).map_err(|_| REFUSED)?,
        release: serde_json::to_value(state.journal().identity()).map_err(|_| REFUSED)?,
        runtime: serde_json::to_value(state.journal().runtime()).map_err(|_| REFUSED)?,
        account_key: inputs.account_key.binding_metadata(),
        ingress_key_name: inputs.ingress_key.transit_key_name().into(),
        ingress_key_version: inputs.ingress_key.key_version(),
        ingress_spki_base64: STANDARD.encode(inputs.ingress_key.public_spki_der()),
        csr_pem: csr.pem().into(),
        csr_der_base64: STANDARD.encode(csr.der()),
        csr_sha256: ledger::hash(csr.der()),
        csr_metadata: csr.metadata().clone(),
        staging_roots_sha256: inputs.staging_roots_pem.map(ledger::hash),
    };
    binding.configuration(state)?;
    Ok(binding)
}

fn parameters<'a>(
    inputs: &'a EnrolmentInputs<'_>,
) -> &'a crate::installer_acme_configuration::AcmeParameters {
    inputs.configuration.parameters()
}

fn expected_identifiers(inputs: &EnrolmentInputs<'_>) -> Result<Vec<Identifier>> {
    let identity = inputs.configuration.certificate_identity()?;
    let mut values = vec![Identifier::Dns(identity.dns_name().into())];
    if let Some(ip) = identity.ip_address() {
        values.push(Identifier::Ip(ip));
    }
    Ok(values)
}

fn expires(text: Option<&str>) -> Result<u64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(text.ok_or(REFUSED)?).map_err(|_| REFUSED)?;
    parsed.timestamp().try_into().map_err(|_| REFUSED.into())
}

fn deadline(hints: Option<ResponseMetadata>, now: u64, fallback: u64) -> u64 {
    hints
        .and_then(|value| value.retry_after)
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_secs())
        .unwrap_or_else(|| now.saturating_add(fallback))
        .max(now.saturating_add(1))
}

fn observe_order(
    order: &mut Order,
    inputs: &EnrolmentInputs<'_>,
    retained: Option<&OrderRecord>,
) -> Result<OrderRecord> {
    let url = order.url().to_owned();
    ledger::same_origin_url(parameters(inputs).directory_url(), &url)?;
    let state = order.state();
    let identifiers = state.identifiers.as_ref().ok_or(REFUSED)?;
    let mut expected = expected_identifiers(inputs)?;
    let canonical =
        |value: &Identifier| serde_json::to_string(value).map_err(|_| REFUSED.to_owned());
    let mut actual = identifiers
        .iter()
        .map(canonical)
        .collect::<Result<Vec<_>>>()?;
    let mut expected_text = expected.iter().map(canonical).collect::<Result<Vec<_>>>()?;
    actual.sort();
    expected_text.sort();
    require(
        actual == expected_text
            && state.profile.as_deref() == Some(parameters(inputs).profile())
            && state.replaces.is_none(),
    )?;
    ledger::same_origin_url(parameters(inputs).directory_url(), &state.finalize)?;
    let mut authorization_urls: Vec<_> = state
        .authorizations
        .iter()
        .map(|value| value.url.clone())
        .collect();
    authorization_urls.sort();
    require(
        authorization_urls.len() == identifiers.len()
            && authorization_urls.iter().collect::<BTreeSet<_>>().len() == authorization_urls.len(),
    )?;
    for url in &authorization_urls {
        ledger::same_origin_url(parameters(inputs).directory_url(), url)?;
    }
    if let Some(certificate) = &state.certificate {
        ledger::same_origin_url(parameters(inputs).directory_url(), certificate)?;
    }
    let reported_expiry = state
        .expires
        .as_deref()
        .map(|value| expires(Some(value)))
        .transpose()?;
    if matches!(state.status, OrderStatus::Pending | OrderStatus::Valid) {
        require(reported_expiry.is_some())?;
    }
    // RFC 8555 section 7.1.3 pins identifiers/authorization URLs, not expires.
    // A completed order may have a different CA retention deadline. Preserve
    // our original invalidation deadline; certificate admission checks the
    // issued leaf's current validity independently. An active order cannot
    // silently acquire a later local deadline through a changed response.
    let expires_at = match (retained, state.status) {
        (Some(retained), OrderStatus::Valid) => retained.expires_at,
        (Some(retained), _) => reported_expiry.unwrap_or(retained.expires_at),
        (None, _) => reported_expiry.ok_or(REFUSED)?,
    };
    expected.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
    let observed = OrderRecord {
        url,
        finalize_url: state.finalize.clone(),
        authorization_urls,
        expires_at,
        identifiers: serde_json::to_value(expected).map_err(|_| REFUSED)?,
        profile: parameters(inputs).profile().into(),
    };
    if let Some(retained) = retained {
        require(*retained == observed)?;
    }
    Ok(observed)
}

fn outcome(saved: &Ledger, candidate: Option<ValidatedCertificate>) -> EnrolmentOutcome {
    let candidate = candidate.map(|certificate| AcmeCandidate {
        environment: saved.binding.environment,
        installation_id: saved.binding.installation_id,
        enrolment_receipt_sha256: saved.digest.clone(),
        order_url: saved
            .state
            .order
            .as_ref()
            .expect("admitted order")
            .url
            .clone(),
        csr_sha256: saved.binding.csr_sha256.clone(),
        fullchain_pem: certificate.fullchain_pem().into(),
        metadata: certificate.metadata().clone(),
    });
    EnrolmentOutcome {
        report: saved.report(),
        candidate,
    }
}

fn admitted(inputs: &EnrolmentInputs<'_>, pem: &[u8]) -> Result<ValidatedCertificate> {
    let identity = inputs.configuration.certificate_identity()?;
    let value = match parameters(inputs).environment() {
        AcmeEnvironment::Production => {
            certificates::admit_production(pem, &identity, inputs.ingress_key)?
        }
        AcmeEnvironment::Staging => certificates::admit_staging_test(
            pem,
            inputs.staging_roots_pem.ok_or(REFUSED)?,
            &identity,
            inputs.ingress_key,
        )?,
    };
    let metadata = value.metadata();
    let before = metadata["not_before"].as_u64().ok_or(REFUSED)?;
    let after = metadata["not_after"].as_u64().ok_or(REFUSED)?;
    require(
        after
            .checked_sub(before)
            .is_some_and(|life| life <= SHORTLIVED_MAXIMUM_SECONDS)
            && metadata["trust_class"]
                == if parameters(inputs).environment() == AcmeEnvironment::Production {
                    "production_public"
                } else {
                    "staging_test"
                },
    )?;
    Ok(value)
}

fn retry(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    saved: &mut Ledger,
    error: &ProtocolError,
    observed: u64,
) -> Result<()> {
    let failures = saved
        .state
        .retry
        .as_ref()
        .map_or(1, |retry| retry.failures + 1);
    if failures > 32 {
        return terminal(state, inputs, saved, "retry_limit").map(|_| ());
    }
    let (category, metadata) = match error {
        ProtocolError::Api(problem) => {
            let category = match problem.r#type.as_deref() {
                Some("urn:ietf:params:acme:error:rateLimited") => "rate_limited",
                Some("urn:ietf:params:acme:error:badNonce") => "bad_nonce",
                _ => "temporary",
            };
            (category, problem.response_metadata)
        }
        _ => ("temporary", None),
    };
    let exponential = 5u64.saturating_mul(1u64 << failures.min(6)).min(300);
    // Draw once and persist. Restarting a worker never redraws this deadline.
    let jitter = u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % (exponential / 4 + 1);
    let next_attempt_at = deadline(metadata, observed, exponential + jitter)
        .max(observed.saturating_add(exponential + jitter));
    let mut next = saved.state.clone();
    next.retry = Some(Retry {
        failures,
        next_attempt_at,
        category: category.into(),
        http_status: metadata.map(|value| value.status),
    });
    saved.append(state, next, observed)
}

fn terminal(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    saved: &mut Ledger,
    code: &str,
) -> Result<EnrolmentOutcome> {
    let mut next = saved.state.clone();
    next.stage = Stage::Terminal;
    next.failure = Some(code.into());
    next.retry = None;
    next.next_poll_at = None;
    next.pending_challenge = None;
    saved.append(state, next, now()?)?;
    withdraw(state, inputs, saved)?;
    Ok(outcome(saved, None))
}

async fn drive(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    binding: Binding,
    signer: Arc<dyn ExternalAccountSigner>,
    http: Box<dyn HttpClient>,
) -> Result<EnrolmentOutcome> {
    let observed = now()?;
    let mut saved = match Ledger::load(state.inspection(), binding.environment)? {
        Some(value) => {
            require(value.binding == binding)?;
            value
        }
        None => Ledger::begin(state, binding, observed)?,
    };
    require(signer.public_key() == inputs.account_key.public_sec1())?;
    require(observed.saturating_add(120) >= saved.observed_at)?;
    let other_environment = if saved.binding.environment == AcmeEnvironment::Staging {
        AcmeEnvironment::Production
    } else {
        AcmeEnvironment::Staging
    };
    if let Some(other) = Ledger::load(state.inspection(), other_environment)? {
        require(
            other.state.projection.is_none()
                || matches!(other.state.stage, Stage::Complete | Stage::Terminal),
        )?;
    }
    if saved.state.stage == Stage::OrderPending {
        // No URL is available to reconcile. No directory GET, signing or CA POST.
        return Ok(outcome(&saved, None));
    }
    if saved.state.stage == Stage::Terminal {
        withdraw(state, inputs, &mut saved)?;
        return Ok(outcome(&saved, None));
    }
    if matches!(
        saved.state.stage,
        Stage::CertificateAdmitted | Stage::Complete
    ) {
        let certificate = admitted(
            inputs,
            saved
                .state
                .certificate
                .as_ref()
                .ok_or(REFUSED)?
                .fullchain_pem
                .as_bytes(),
        )?;
        withdraw(state, inputs, &mut saved)?;
        if saved.state.stage != Stage::Complete {
            let mut next = saved.state.clone();
            next.stage = Stage::Complete;
            saved.append(state, next, now()?)?;
        }
        return Ok(outcome(&saved, Some(certificate)));
    }
    if saved
        .state
        .retry
        .as_ref()
        .is_some_and(|retry| retry.next_attempt_at > observed)
        || saved
            .state
            .next_poll_at
            .is_some_and(|deadline| deadline > observed)
    {
        if saved
            .state
            .order
            .as_ref()
            .is_some_and(|order| order.expires_at <= observed)
            && saved.state.stage != Stage::CertificatePending
        {
            return terminal(state, inputs, &mut saved, "order_expired");
        }
        return Ok(outcome(&saved, None));
    }
    if saved.state.stage == Stage::PublicationPending {
        // Complete exactly the retained publication before constructing another
        // projection. A lost rename result may already have published these bytes.
        publish(
            state.inspection(),
            inputs.installation,
            saved.state.projection.as_ref().ok_or(REFUSED)?,
        )?;
        let mut next = saved.state.clone();
        next.stage = Stage::ChallengesPublished;
        saved.append(state, next, now()?)?;
    }
    let prepared = match Account::builder_with_http(http)
        .prepare_with_signer(signer, parameters(inputs).directory_url().into())
        .await
    {
        Ok(value) => value,
        Err(error) => {
            retry(state, inputs, &mut saved, &error, now()?)?;
            return Ok(outcome(&saved, None));
        }
    };
    parameters(inputs).require_directory_terms(prepared.terms_of_service_url())?;
    prepared
        .require_terms_and_profile(parameters(inputs).terms_url(), parameters(inputs).profile())
        .map_err(|_| REFUSED)?;
    let account = if let Some(url) = &saved.state.account_url {
        prepared.restore(url.clone())
    } else {
        let recovering = saved.state.stage == Stage::AccountPending;
        if !recovering {
            let mut next = saved.state.clone();
            next.stage = Stage::AccountPending;
            next.retry = None;
            saved.append(state, next, now()?)?;
        }
        let contacts: Vec<_> = parameters(inputs).contact().into_iter().collect();
        let registration = NewAccount {
            contact: &contacts,
            terms_of_service_agreed: true,
            only_return_existing: recovering,
        };
        match prepared
            .register(
                &registration,
                None,
                parameters(inputs).terms_url(),
                parameters(inputs).profile(),
            )
            .await
        {
            Ok(account) => {
                ledger::same_origin_url(parameters(inputs).directory_url(), account.id())?;
                let mut next = saved.state.clone();
                next.account_url = Some(account.id().into());
                next.stage = Stage::AccountBound;
                next.retry = None;
                saved.append(state, next, now()?)?;
                account
            }
            Err(error) => {
                if recovering
                    && matches!(&error,ProtocolError::Api(problem)
                    if problem.response_metadata.is_some_and(|metadata|metadata.status==400)
                    && problem.r#type.as_deref()==Some("urn:ietf:params:acme:error:accountDoesNotExist"))
                {
                    // The CA has confirmed the same pinned key has no account.
                    // A later invocation may register it after a new durable intent.
                    let mut next = saved.state.clone();
                    next.stage = Stage::AccountAbsent;
                    next.retry = None;
                    saved.append(state, next, now()?)?;
                    return Ok(outcome(&saved, None));
                }
                if matches!(&error,ProtocolError::Api(problem)
                    if problem.response_metadata.is_some_and(|metadata|(400..500).contains(&metadata.status)&&metadata.status!=429)
                    && problem.r#type.as_deref()!=Some("urn:ietf:params:acme:error:badNonce"))
                {
                    return terminal(state, inputs, &mut saved, "account_unavailable");
                }
                retry(state, inputs, &mut saved, &error, now()?)?;
                return Ok(outcome(&saved, None));
            }
        }
    };
    let mut order = if let Some(retained) = &saved.state.order {
        match account.order(retained.url.clone()).await {
            Ok(value) => value,
            Err(error) => {
                retry(state, inputs, &mut saved, &error, now()?)?;
                return Ok(outcome(&saved, None));
            }
        }
    } else {
        require(matches!(
            saved.state.stage,
            Stage::AccountBound | Stage::OrderRejected
        ))?;
        let mut next = saved.state.clone();
        next.stage = Stage::OrderPending;
        next.failure = None;
        saved.append(state, next, now()?)?;
        match account
            .new_order(
                &NewOrder::new(&expected_identifiers(inputs)?)
                    .profile(parameters(inputs).profile()),
            )
            .await
        {
            Ok(mut value) => {
                let retained = observe_order(&mut value, inputs, None)?;
                let mut next = saved.state.clone();
                next.stage = Stage::OrderBound;
                next.order = Some(retained);
                next.retry = None;
                saved.append(state, next, now()?)?;
                value
            }
            Err(error) => {
                let definitely_rejected = matches!(&error,ProtocolError::Api(problem)
                    if problem.response_metadata.is_some_and(|meta|meta.status==429 || meta.status==400)
                    && matches!(problem.r#type.as_deref(),Some("urn:ietf:params:acme:error:rateLimited"|"urn:ietf:params:acme:error:badNonce")));
                if definitely_rejected {
                    let mut next = saved.state.clone();
                    next.stage = Stage::OrderRejected;
                    saved.append(state, next, now()?)?;
                    retry(state, inputs, &mut saved, &error, now()?)?;
                } else {
                    let mut next = saved.state.clone();
                    next.failure = Some("order_outcome_unknown".into());
                    saved.append(state, next, now()?)?;
                }
                return Ok(outcome(&saved, None));
            }
        }
    };
    observe_order(&mut order, inputs, saved.state.order.as_ref())?;
    let observed = now()?;
    let status = order.state().status;
    if status == OrderStatus::Invalid {
        return terminal(state, inputs, &mut saved, "order_invalid");
    }
    if status != OrderStatus::Valid
        && saved.state.order.as_ref().ok_or(REFUSED)?.expires_at <= observed
    {
        return terminal(state, inputs, &mut saved, "order_expired");
    }
    if status == OrderStatus::Pending {
        return pending_authorizations(state, inputs, &mut saved, &mut order).await;
    }
    if status == OrderStatus::Ready {
        let mut next = saved.state.clone();
        next.stage = Stage::FinalizePending;
        next.next_poll_at = None;
        saved.append(state, next, now()?)?;
        if let Err(error) = order.finalize_csr(inputs.csr.der()).await {
            retry(state, inputs, &mut saved, &error, now()?)?;
            return Ok(outcome(&saved, None));
        }
        observe_order(&mut order, inputs, saved.state.order.as_ref())?;
    }
    if order.state().status == OrderStatus::Invalid {
        return terminal(state, inputs, &mut saved, "order_invalid");
    }
    if saved.state.stage != Stage::CertificatePending {
        let mut next = saved.state.clone();
        next.stage = Stage::CertificatePending;
        next.retry = None;
        next.next_poll_at = None;
        saved.append(state, next, now()?)?;
    }
    if order.state().status != OrderStatus::Valid {
        let mut next = saved.state.clone();
        next.next_poll_at = Some(deadline(order.state().response_metadata, now()?, 5));
        saved.append(state, next, now()?)?;
        return Ok(outcome(&saved, None));
    }
    let pem = match order.certificate().await {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(outcome(&saved, None)),
        Err(error) => {
            retry(state, inputs, &mut saved, &error, now()?)?;
            return Ok(outcome(&saved, None));
        }
    };
    let certificate = match admitted(inputs, pem.as_bytes()) {
        Ok(value) => value,
        Err(_) => return terminal(state, inputs, &mut saved, "certificate_refused"),
    };
    let mut next = saved.state.clone();
    next.stage = Stage::CertificateAdmitted;
    next.retry = None;
    next.next_poll_at = None;
    next.certificate = Some(CertificateRecord {
        fullchain_pem: certificate.fullchain_pem().into(),
        metadata: certificate.metadata().clone(),
    });
    saved.append(state, next, now()?)?;
    withdraw(state, inputs, &mut saved)?;
    let mut next = saved.state.clone();
    next.stage = Stage::Complete;
    saved.append(state, next, now()?)?;
    Ok(outcome(&saved, Some(certificate)))
}

async fn pending_authorizations(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    saved: &mut Ledger,
    order: &mut Order,
) -> Result<EnrolmentOutcome> {
    let mut records = Vec::new();
    let mut terminal_reason = None;
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = match result {
                Ok(value) => value,
                Err(error) => {
                    retry(state, inputs, saved, &error, now()?)?;
                    return Ok(outcome(saved, None));
                }
            };
            let identifier = authorization.identifier().to_string();
            let url = authorization.url().to_owned();
            let expires_at = expires(authorization.expires.as_deref())?;
            if expires_at <= now()? {
                terminal_reason = Some("authorization_expired");
                break;
            }
            if !matches!(
                authorization.status,
                AuthorizationStatus::Pending | AuthorizationStatus::Valid
            ) {
                terminal_reason = Some("authorization_invalid");
                break;
            }
            let prior = saved
                .state
                .authorizations
                .iter()
                .find(|prior| prior.url == url);
            let mut record = AuthorizationRecord {
                identifier,
                url,
                expires_at,
                status: if authorization.status == AuthorizationStatus::Valid {
                    "valid"
                } else {
                    "pending"
                }
                .into(),
                challenge_url: None,
                token: None,
                key_authorization: None,
                ready_observed: authorization.status == AuthorizationStatus::Valid,
            };
            if authorization.status == AuthorizationStatus::Pending {
                let challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or(REFUSED)?;
                ledger::same_origin_url(parameters(inputs).directory_url(), &challenge.url)?;
                require(matches!(
                    challenge.status,
                    ChallengeStatus::Pending | ChallengeStatus::Processing | ChallengeStatus::Valid
                ))?;
                record.challenge_url = Some(challenge.url.clone());
                record.token = Some(challenge.token.clone());
                record.key_authorization = Some(challenge.key_authorization().as_str().into());
                record.ready_observed = challenge.status != ChallengeStatus::Pending
                    || prior.is_some_and(|prior| prior.ready_observed);
                if let Some(prior) = prior {
                    require(
                        prior.identifier == record.identifier
                            && prior.expires_at == record.expires_at
                            && prior.challenge_url == record.challenge_url
                            && prior.token == record.token
                            && prior.key_authorization == record.key_authorization,
                    )?;
                }
            }
            records.push(record);
        }
    }
    if let Some(reason) = terminal_reason {
        return terminal(state, inputs, saved, reason);
    }
    records.sort_by(|left, right| left.identifier.cmp(&right.identifier));
    let identity = inputs.configuration.certificate_identity()?;
    let expected: BTreeSet<_> = std::iter::once(identity.dns_name().to_owned())
        .chain(identity.ip_address().map(|ip| ip.to_string()))
        .collect();
    require(
        records.len() == expected.len()
            && records
                .iter()
                .map(|record| record.identifier.clone())
                .collect::<BTreeSet<_>>()
                == expected,
    )?;
    let projection = projection_for(
        inputs,
        &records,
        saved.state.order.as_ref().ok_or(REFUSED)?.expires_at,
        saved.state.projection.as_ref(),
        false,
    )?;
    let mut next = saved.state.clone();
    next.authorizations = records;
    next.stage = Stage::PublicationPending;
    next.projection = Some(projection);
    next.pending_challenge = None;
    next.next_poll_at = None;
    saved.append(state, next, now()?)?;
    publish(
        state.inspection(),
        inputs.installation,
        saved.state.projection.as_ref().ok_or(REFUSED)?,
    )?;
    let mut next = saved.state.clone();
    next.stage = Stage::ChallengesPublished;
    saved.append(state, next, now()?)?;
    let pending = saved
        .state
        .authorizations
        .iter()
        .find(|record| record.status == "pending" && !record.ready_observed)
        .map(|record| record.url.clone());
    if let Some(pending) = pending {
        let mut next = saved.state.clone();
        next.stage = Stage::ChallengeReadyPending;
        next.pending_challenge = Some(pending.clone());
        saved.append(state, next, now()?)?;
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result.map_err(|_| REFUSED)?;
            if authorization.url() != pending {
                continue;
            }
            // authorizations() caches the first observation. Refresh the exact
            // target before the mutation, then recheck the published identity
            // and challenge. Never post readiness for a changed or completed
            // challenge merely because its authorization URL still matches.
            if let Err(error) = authorization.refresh().await {
                retry(state, inputs, saved, &error, now()?)?;
                return Ok(outcome(saved, None));
            }
            let retained = saved
                .state
                .authorizations
                .iter()
                .find(|record| record.url == pending)
                .ok_or(REFUSED)?;
            let observed = now()?;
            let current_expiry = expires(authorization.expires.as_deref())?;
            require(
                authorization.url() == retained.url
                    && authorization.identifier().to_string() == retained.identifier
                    && current_expiry > observed
                    && matches!(
                        authorization.status,
                        AuthorizationStatus::Pending | AuthorizationStatus::Valid
                    )
                    && (authorization.status == AuthorizationStatus::Valid
                        || current_expiry == retained.expires_at),
            )?;
            let authorization_valid = authorization.status == AuthorizationStatus::Valid;
            let observed_hints = authorization.response_metadata;
            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or(REFUSED)?;
            require(
                Some(challenge.url.as_str()) == retained.challenge_url.as_deref()
                    && Some(challenge.token.as_str()) == retained.token.as_deref()
                    && Some(challenge.key_authorization().as_str())
                        == retained.key_authorization.as_deref()
                    && matches!(
                        challenge.status,
                        ChallengeStatus::Pending
                            | ChallengeStatus::Processing
                            | ChallengeStatus::Valid
                    )
                    && (!authorization_valid || challenge.status == ChallengeStatus::Valid),
            )?;
            let response = if challenge.status == ChallengeStatus::Pending {
                challenge.set_ready_with_response().await.map(Some)
            } else {
                Ok(observed_hints)
            };
            match response {
                Ok(hints) => {
                    let mut next = saved.state.clone();
                    next.authorizations
                        .iter_mut()
                        .find(|record| record.url == pending)
                        .ok_or(REFUSED)?
                        .ready_observed = true;
                    next.stage = Stage::AwaitingOrder;
                    next.pending_challenge = None;
                    next.retry = None;
                    next.next_poll_at = Some(deadline(hints, now()?, 5));
                    saved.append(state, next, now()?)?;
                }
                Err(error) => retry(state, inputs, saved, &error, now()?)?,
            }
            return Ok(outcome(saved, None));
        }
        return Err(REFUSED.into());
    }
    let mut next = saved.state.clone();
    next.stage = Stage::AwaitingOrder;
    next.next_poll_at = Some(deadline(order.state().response_metadata, now()?, 5));
    saved.append(state, next, now()?)?;
    Ok(outcome(saved, None))
}

fn projection_for(
    inputs: &EnrolmentInputs<'_>,
    authorizations: &[AuthorizationRecord],
    order_expiry: u64,
    previous: Option<&Projection>,
    empty: bool,
) -> Result<Projection> {
    let observed = now()?;
    let challenges = if empty {
        Vec::new()
    } else {
        authorizations
            .iter()
            .filter(|record| record.status == "pending")
            .map(|record| {
                Ok(Challenge {
                    identifier: record.identifier.clone(),
                    token: record.token.clone().ok_or(REFUSED)?,
                    key_authorization: record.key_authorization.clone().ok_or(REFUSED)?,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };
    let expires_at = if empty {
        observed.checked_add(60).ok_or(REFUSED)?
    } else {
        authorizations
            .iter()
            .map(|record| record.expires_at)
            .chain([order_expiry, observed.saturating_add(MAX_LIFETIME_SECONDS)])
            .min()
            .ok_or(REFUSED)?
    };
    let snapshot = Snapshot {
        schema: SNAPSHOT_SCHEMA.into(),
        created_at: observed,
        expires_at,
        challenges,
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|_| REFUSED)?;
    let allowed = AllowedIdentifiers::from_origins(
        inputs.configuration.canonical_origin(),
        inputs.configuration.public_entry_origin(),
    )
    .map_err(|_| REFUSED)?;
    Snapshot::parse(&bytes, &allowed, observed).map_err(|_| REFUSED)?;
    Ok(Projection {
        snapshot: String::from_utf8(bytes).map_err(|_| REFUSED)?,
        sha256: ledger::hash(&serde_json::to_vec(&snapshot).map_err(|_| REFUSED)?),
        previous_sha256: previous.map(|value| value.sha256.clone()),
    })
}

fn withdraw(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    saved: &mut Ledger,
) -> Result<()> {
    if saved.state.projection.is_none() {
        return Ok(());
    }
    let current = saved.state.projection.as_ref().ok_or(REFUSED)?;
    let snapshot: Snapshot =
        serde_json::from_slice(current.snapshot.as_bytes()).map_err(|_| REFUSED)?;
    if snapshot.challenges.is_empty() {
        return publish(state.inspection(), inputs.installation, current);
    }
    let projection = projection_for(
        inputs,
        &saved.state.authorizations,
        0,
        saved.state.projection.as_ref(),
        true,
    )?;
    let mut next = saved.state.clone();
    next.projection = Some(projection);
    saved.append(state, next, now()?)?;
    publish(
        state.inspection(),
        inputs.installation,
        saved.state.projection.as_ref().ok_or(REFUSED)?,
    )
}

fn projection_directory(state: &LockedInspection, installation: &Path) -> Result<File> {
    state.require_path_binding(installation)?;
    let directory = installer_host_fs::open_child(
        state.installation_directory(),
        HTTP01_DIRECTORY,
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let metadata = directory.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o755,
    )?;
    require_projection_directory(state, installation, &directory)?;
    Ok(directory)
}

fn require_projection_directory(
    state: &LockedInspection,
    installation: &Path,
    held: &File,
) -> Result<()> {
    state.require_path_binding(installation)?;
    let current = installer_host_fs::open_child(
        state.installation_directory(),
        HTTP01_DIRECTORY,
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let old = held.metadata().map_err(|_| REFUSED)?;
    let current = current.metadata().map_err(|_| REFUSED)?;
    require(
        current.is_dir()
            && current.uid() == unsafe { libc::geteuid() }
            && current.mode() & 0o7777 == 0o755
            && (old.dev(), old.ino(), old.uid(), old.gid(), old.mode())
                == (
                    current.dev(),
                    current.ino(),
                    current.uid(),
                    current.gid(),
                    current.mode(),
                ),
    )
}

fn read_projection(directory: &File) -> Result<Option<Vec<u8>>> {
    let name = CString::new(SNAPSHOT_BASENAME).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(REFUSED.into())
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o444
            && metadata.nlink() == 1,
    )?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(!bytes.is_empty() && bytes.len() <= 4096)?;
    Ok(Some(bytes))
}

fn publish(state: &LockedInspection, installation: &Path, projection: &Projection) -> Result<()> {
    let directory = projection_directory(state, installation)?;
    if let Some(existing) = read_projection(&directory)? {
        let digest = ledger::hash(&existing);
        if digest == projection.sha256 {
            return Ok(());
        }
        if projection.previous_sha256.as_deref() != Some(digest.as_str()) {
            // The other environment may have completed and withdrawn its projection.
            let mut withdrawn_owner = false;
            for environment in [AcmeEnvironment::Staging, AcmeEnvironment::Production] {
                if let Some(other) = Ledger::load(state, environment)? {
                    if matches!(other.state.stage, Stage::Complete | Stage::Terminal)
                        && other
                            .state
                            .projection
                            .as_ref()
                            .is_some_and(|value| value.sha256 == digest)
                    {
                        let snapshot: Snapshot =
                            serde_json::from_slice(&existing).map_err(|_| REFUSED)?;
                        withdrawn_owner = snapshot.challenges.is_empty();
                    }
                }
            }
            require(withdrawn_owner)?;
        }
    } else {
        require(projection.previous_sha256.is_none())?;
    }
    require(ledger::hash(projection.snapshot.as_bytes()) == projection.sha256)?;
    let temporary =
        CString::new(format!(".acme-{}.tmp", uuid::Uuid::new_v4())).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(projection.snapshot.as_bytes())
        .map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
    file.sync_all().map_err(|_| REFUSED)?;
    require_projection_directory(state, installation, &directory)?;
    let active = CString::new(SNAPSHOT_BASENAME).map_err(|_| REFUSED)?;
    require(
        unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                active.as_ptr(),
            )
        } == 0,
    )?;
    directory.sync_all().map_err(|_| REFUSED)?;
    require(read_projection(&directory)?.as_deref() == Some(projection.snapshot.as_bytes()))?;
    state.require_unchanged()
}

#[cfg(test)]
#[path = "installer_acme_tests.rs"]
mod tests;
