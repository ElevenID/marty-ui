use std::{fmt, sync::Arc, time::Duration};

use reqwest::{header, Client, Response};
use serde::de::DeserializeOwned;
use serde_json::json;
use uuid::Uuid;

use crate::{
    model::ReceiptWire, strict, CallerVerifiedRequest, ClientError, CommandResponse, CommandResult,
    FinalizedUse, PreparedFinalize, PreparedStart, ProofSubmission, ReceiptArtifact, Result,
    StartedUse, UnverifiedRequestArtifact, COMMAND_RESPONSE_PROFILE, EVIDENCE_SEMANTICS,
    MAX_COMPACT_RECEIPT_BYTES, MAX_FORM_BYTES, MAX_PROOF_BYTES, MAX_REQUEST_ARTIFACT_BYTES,
    REQUEST_LINK_RELATION,
};

const MAX_COMMAND_RESPONSE_BYTES: usize = 65_536;
const MAX_RECEIPT_RESPONSE_BYTES: usize = 131_072;
const MAX_SUBMISSION_RESPONSE_BYTES: usize = 4_096;

/// Only these roots are trusted. The resolver may use remote custody; the
/// client never requests or exports its private key and does not add OS roots.
pub struct MtlsConfig {
    pub roots: rustls::RootCertStore,
    pub client_certificate: Arc<dyn rustls::client::ResolvesClientCert>,
}
impl fmt::Debug for MtlsConfig {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("MtlsConfig { <explicit trust and client certificate> }")
    }
}

/// A canonical HTTPS origin without a trailing slash, one organization and a
/// bounded whole-request timeout. No per-call override can replace the origin,
/// TLS verifier, authentication, proxy, redirect or retry policy.
pub struct ClientConfig {
    pub origin: String,
    pub organization: Uuid,
    pub tls: MtlsConfig,
    pub timeout: Duration,
}
impl fmt::Debug for ClientConfig {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("ClientConfig { <configured organization and mTLS host> }")
    }
}

pub struct DelegatedUseClient {
    http: Client,
    origin: String,
    organization: Uuid,
}
impl fmt::Debug for DelegatedUseClient {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("DelegatedUseClient { <configured organization and mTLS host> }")
    }
}

impl DelegatedUseClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let origin =
            url::Url::parse(&config.origin).map_err(|_| ClientError::InvalidConfiguration)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.origin().ascii_serialization() != config.origin
            || config.organization.is_nil()
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(300)
            || config.tls.roots.is_empty()
            || !config.tls.client_certificate.has_certs()
        {
            return Err(ClientError::InvalidConfiguration);
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| ClientError::InvalidConfiguration)?
        .with_root_certificates(config.tls.roots)
        .with_client_cert_resolver(config.tls.client_certificate);
        let http = Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(config.timeout.min(Duration::from_secs(10)))
            .timeout(config.timeout)
            .build()
            .map_err(|_| ClientError::InvalidConfiguration)?;
        Ok(Self {
            http,
            origin: config.origin,
            organization: config.organization,
        })
    }

    pub async fn start(&self, command: &PreparedStart) -> Result<StartedUse> {
        self.start_bytes(command, command.bytes(), false).await
    }

    /// Read the original command's retained result. A missing result or a
    /// transport error never permits replacing the original command identity.
    pub async fn recover_start(&self, command: &PreparedStart) -> Result<StartedUse> {
        self.start_bytes(command, &command.recovery_bytes(), true)
            .await
    }

    async fn start_bytes(
        &self,
        command: &PreparedStart,
        bytes: &[u8],
        recovery: bool,
    ) -> Result<StartedUse> {
        let response = self.post_command(bytes).await?;
        let link = single_header(response.headers(), header::LINK)?.to_owned();
        let response: CommandResponse = read_json(response, MAX_COMMAND_RESPONSE_BYTES).await?;
        correlate(
            &response,
            command.command_id(),
            command.command_digest(),
            recovery,
        )?;
        let CommandResult::Challenge {
            challenge_id,
            grant,
            operation,
            created_at,
            expires_at,
        } = &response.result
        else {
            return Err(ClientError::CorrelationMismatch);
        };
        if grant != &command.grant || operation != &command.operation || created_at >= expires_at {
            return Err(ClientError::CorrelationMismatch);
        }
        let challenge_id = *challenge_id;
        let request_uri = self.wallet_uri(challenge_id, "request");
        if link != format!("<{request_uri}>; rel=\"{REQUEST_LINK_RELATION}\"") {
            return Err(ClientError::InvalidDestination);
        }
        Ok(StartedUse {
            response,
            request_uri,
            organization: self.organization,
            challenge_id,
        })
    }

    pub async fn finalize(&self, command: &PreparedFinalize) -> Result<FinalizedUse> {
        self.finalize_bytes(command, command.bytes(), false).await
    }

    pub async fn recover_final(&self, command: &PreparedFinalize) -> Result<FinalizedUse> {
        self.finalize_bytes(command, &command.recovery_bytes(), true)
            .await
    }

    async fn finalize_bytes(
        &self,
        command: &PreparedFinalize,
        bytes: &[u8],
        recovery: bool,
    ) -> Result<FinalizedUse> {
        let response = self.post_command(bytes).await?;
        if response.headers().contains_key(header::LINK) {
            return Err(ClientError::InvalidResponse);
        }
        let response: CommandResponse = read_json(response, MAX_COMMAND_RESPONSE_BYTES).await?;
        correlate_final(&response, command, recovery)?;
        Ok(FinalizedUse { response })
    }

    pub async fn fetch_request(&self, started: &StartedUse) -> Result<UnverifiedRequestArtifact> {
        self.check_started(started)?;
        let response = self
            .http
            .get(&started.request_uri)
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        check_response(&response, "application/oauth-authz-req+jwt")?;
        let bytes = read_body(response, MAX_REQUEST_ARTIFACT_BYTES).await?;
        let compact = String::from_utf8(bytes).map_err(|_| ClientError::InvalidResponse)?;
        if !strict::compact_jws(&compact) {
            return Err(ClientError::InvalidResponse);
        }
        Ok(UnverifiedRequestArtifact(compact))
    }

    /// The caller must independently verify the request before creating
    /// `CallerVerifiedRequest`. This method only constrains the destination and
    /// binds returned proof retention to the exact submitted compact bytes.
    pub async fn submit_direct_post(
        &self,
        started: &StartedUse,
        verified: &CallerVerifiedRequest,
        compact_vp: &str,
    ) -> Result<ProofSubmission> {
        self.check_started(started)?;
        if verified.response_uri != self.wallet_uri(started.challenge_id, "submit")
            || verified.state != started.challenge_id.to_string()
            || verified.query_id.is_empty()
            || verified.query_id.len() > 128
            || !verified
                .query_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(ClientError::InvalidDestination);
        }
        if compact_vp.len() > MAX_PROOF_BYTES {
            return Err(ClientError::TooLarge);
        }
        if !strict::compact_jws(compact_vp) {
            return Err(ClientError::InvalidCommand);
        }
        let vp_token = json!({ &verified.query_id: [compact_vp] }).to_string();
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &verified.state)
            .append_pair("vp_token", &vp_token)
            .finish();
        if form.len() > MAX_FORM_BYTES {
            return Err(ClientError::TooLarge);
        }
        let response = self
            .http
            .post(&verified.response_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        check_response(&response, "application/json")?;
        let submitted: ProofSubmission = read_json(response, MAX_SUBMISSION_RESPONSE_BYTES).await?;
        let CommandResult::Challenge {
            created_at,
            expires_at,
            ..
        } = &started.response.result
        else {
            return Err(ClientError::CorrelationMismatch);
        };
        if submitted.challenge_id != started.challenge_id
            || submitted.proof_digest != strict::digest(compact_vp.as_bytes())
            || submitted.received_at < *created_at
            || submitted.received_at >= *expires_at
        {
            return Err(ClientError::CorrelationMismatch);
        }
        Ok(submitted)
    }

    /// Returns original evidence for one independently retained finalization.
    /// Historical expiry is preserved; fresh authorization is not inferred.
    pub async fn recover_receipt(&self, command: &PreparedFinalize) -> Result<ReceiptArtifact> {
        let response = self
            .http
            .post(format!(
                "{}/v1/organizations/{}/delegated-use/receipts/recover",
                self.origin, self.organization,
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .body(command.recovery_bytes())
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        check_response(&response, "application/json")?;
        let wire: ReceiptWire = read_json(response, MAX_RECEIPT_RESPONSE_BYTES).await?;
        correlate_final(&wire.original_response, command, true)?;
        let CommandResult::FinalUse {
            receipt_ref,
            receipt_digest,
            ..
        } = &wire.original_response.result
        else {
            return Err(ClientError::CorrelationMismatch);
        };
        if wire.compact_jws.len() > MAX_COMPACT_RECEIPT_BYTES {
            return Err(ClientError::TooLarge);
        }
        if !strict::compact_jws(&wire.compact_jws)
            || wire.semantics != EVIDENCE_SEMANTICS
            || wire.receipt_ref != *receipt_ref
            || wire.receipt_digest != *receipt_digest
            || wire.receipt_digest != strict::digest(wire.compact_jws.as_bytes())
        {
            return Err(ClientError::CorrelationMismatch);
        }
        Ok(ReceiptArtifact { wire })
    }

    fn wallet_uri(&self, challenge_id: Uuid, operation: &str) -> String {
        format!(
            "{}/v1/flows/instances/{challenge_id}/{operation}",
            self.origin
        )
    }

    fn check_started(&self, started: &StartedUse) -> Result<()> {
        if started.organization != self.organization
            || started.request_uri != self.wallet_uri(started.challenge_id, "request")
        {
            return Err(ClientError::InvalidDestination);
        }
        Ok(())
    }

    async fn post_command(&self, bytes: &[u8]) -> Result<Response> {
        let response = self
            .http
            .post(format!(
                "{}/v1/organizations/{}/delegated-use-commands",
                self.origin, self.organization,
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        check_response(&response, "application/json")?;
        Ok(response)
    }
}

fn correlate(response: &CommandResponse, id: Uuid, digest: &str, recovery: bool) -> Result<()> {
    if response.profile != COMMAND_RESPONSE_PROFILE
        || response.original_command_id != id
        || response.command_digest != digest
        || (recovery && !response.recovered)
    {
        return Err(ClientError::CorrelationMismatch);
    }
    Ok(())
}

fn correlate_final(
    response: &CommandResponse,
    command: &PreparedFinalize,
    recovery: bool,
) -> Result<()> {
    correlate(
        response,
        command.command_id(),
        command.command_digest(),
        recovery,
    )?;
    let CommandResult::FinalUse {
        challenge_id,
        decision,
        receipt_ref,
        receipt_digest,
        recorded_at,
        authorization_expires_at,
        semantics,
    } = &response.result
    else {
        return Err(ClientError::CorrelationMismatch);
    };
    if *challenge_id != command.challenge_id
        || !matches!(decision.as_str(), "PERMIT" | "DENY")
        || receipt_ref
            .strip_prefix("urn:marty:delegated-receipt:")
            .and_then(strict::canonical_uuid)
            .is_none()
        || !strict::valid_digest(receipt_digest)
        || recorded_at >= authorization_expires_at
        || semantics != EVIDENCE_SEMANTICS
    {
        return Err(ClientError::CorrelationMismatch);
    }
    Ok(())
}

fn single_header(headers: &header::HeaderMap, name: header::HeaderName) -> Result<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(ClientError::InvalidResponse)?;
    if values.next().is_some() {
        return Err(ClientError::InvalidResponse);
    }
    value.to_str().map_err(|_| ClientError::InvalidResponse)
}

fn check_response(response: &Response, content_type: &str) -> Result<()> {
    if response.status() != reqwest::StatusCode::OK {
        return Err(ClientError::Http(response.status().as_u16()));
    }
    for (name, expected) in [
        (header::CONTENT_TYPE, content_type),
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ] {
        if single_header(response.headers(), name)? != expected {
            return Err(ClientError::InvalidResponse);
        }
    }
    if response.headers().contains_key(header::CONTENT_ENCODING) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

async fn read_json<T: DeserializeOwned>(response: Response, maximum: usize) -> Result<T> {
    strict::json(&read_body(response, maximum).await?)
}

async fn read_body(mut response: Response, maximum: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(ClientError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ClientError::Transport)? {
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(ClientError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
