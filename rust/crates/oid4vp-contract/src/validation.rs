use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose, Engine as _};
use percent_encoding::percent_decode_str;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::{
    digest_audience, digest_frozen_request, digest_nonce, digest_query_document, digest_replay_key,
    digest_response_item, digest_wallet_submission, AuthenticatedDecisionAction,
    AuthenticatedResult, CredentialStatusMode, CredentialStatusState, EvidenceCheckOutcome,
    EvidenceFact, EvidenceProcessingStatus, FrozenCredentialRequirement, FrozenOid4vpRequestV1,
    FrozenPolicyIdentity, Oid4vpCheckId, Oid4vpEvidenceProjectionV1, PresentationDescriptor,
    QueryKind, VpToken, WalletSubmissionV1, MAX_CLAIMS_PER_CREDENTIAL, MAX_CLAIM_VALUE_BYTES,
    MAX_CODE_BYTES, MAX_CREDENTIALS, MAX_DESCRIPTOR_DEPTH, MAX_EVIDENCE_LIST_ITEMS,
    MAX_EVIDENCE_PROJECTION_BYTES, MAX_FROZEN_REQUEST_BYTES, MAX_IDENTIFIER_BYTES, MAX_JSON_DEPTH,
    MAX_PRIVACY_BASE64_DECODE_LAYERS, MAX_PRIVACY_PERCENT_DECODE_LAYERS, MAX_QUERY_DOCUMENT_BYTES,
    MAX_QUERY_REQUIREMENTS, MAX_REQUEST_LIFETIME_SECONDS, MAX_STATUS_VALIDITY_SECONDS, MAX_TOKENS,
    MAX_TOKEN_BYTES, MAX_WALLET_SUBMISSION_BYTES, MIN_NONCE_BYTES, MIN_TOKEN_BYTES,
    REQUIRED_OID4VP_CHECKS,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Oid4vpContractError {
    #[error("OID4VP contract JSON could not be serialized")]
    Serialization,
    #[error("OID4VP contract JSON could not be deserialized")]
    Deserialization,
    #[error("OID4VP contract exceeds its byte limit: {0}")]
    SizeLimit(&'static str),
    #[error("OID4VP contract field is invalid or unbounded: {0}")]
    InvalidField(&'static str),
    #[error("invalid sha256 digest: {0}")]
    InvalidDigest(&'static str),
    #[error("frozen query document and typed requirements disagree")]
    InvalidQueryDocument,
    #[error("frozen query digest does not match its document")]
    QueryDigestMismatch,
    #[error("frozen request time window is invalid")]
    InvalidLifetime,
    #[error("wallet state does not match the server-owned frozen state")]
    StateMismatch,
    #[error("wallet response does not exactly cover the frozen query identifiers")]
    QueryCoverageMismatch,
    #[error("presentation_submission does not exactly match the frozen definition")]
    PresentationDefinitionMismatch,
    #[error("authenticated evidence is not bound to the frozen request")]
    RequestDigestMismatch,
    #[error("authenticated evidence is not bound to the wallet submission")]
    ResponseDigestMismatch,
    #[error("authenticated evidence does not contain the exact canonical check inventory")]
    CheckInventoryMismatch,
    #[error("authenticated evidence contains an inconsistent check record")]
    CheckEvidenceMismatch,
    #[error("authenticated binding evidence is inconsistent")]
    BindingMismatch,
    #[error("credential evidence is not exactly bound to query and response tokens")]
    CredentialBindingMismatch,
    #[error("credential trust evidence is inconsistent with frozen authority")]
    TrustEvidenceMismatch,
    #[error("credential status evidence is inconsistent with frozen policy")]
    StatusEvidenceMismatch,
    #[error("authenticated policy and final decision projections are inconsistent")]
    DecisionMismatch,
    #[error("authenticated evidence contains raw wallet material")]
    PrivacyViolation,
}

impl WalletSubmissionV1 {
    pub fn from_json(value: &str) -> Result<Self, Oid4vpContractError> {
        let submission: Self =
            parse_bounded(value, MAX_WALLET_SUBMISSION_BYTES, "wallet_submission")?;
        submission.validate()?;
        Ok(submission)
    }

    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        validate_serialized_size(self, MAX_WALLET_SUBMISSION_BYTES, "wallet_submission")?;
        let mut unique_tokens = BTreeSet::new();
        let token_count = match &self.vp_token {
            VpToken::Single(token) => {
                require_token(token, "vp_token")?;
                unique_tokens.insert(token.as_str());
                1
            }
            VpToken::ByQuery(tokens) => {
                if tokens.is_empty() || tokens.len() > MAX_QUERY_REQUIREMENTS {
                    return Err(Oid4vpContractError::InvalidField("vp_token"));
                }
                let mut count = 0usize;
                for (query_id, values) in tokens {
                    require_identifier(query_id, "vp_token.query_id")?;
                    if values.is_empty() {
                        return Err(Oid4vpContractError::InvalidField("vp_token.query_tokens"));
                    }
                    for value in values {
                        require_token(value, "vp_token.query_token")?;
                        if !unique_tokens.insert(value.as_str()) {
                            return Err(Oid4vpContractError::InvalidField(
                                "vp_token.duplicate_token",
                            ));
                        }
                        count = count.saturating_add(1);
                    }
                }
                count
            }
        };
        if token_count > MAX_TOKENS {
            return Err(Oid4vpContractError::InvalidField("vp_token.count"));
        }
        if let Some(state) = &self.state {
            require_identifier(state, "state")?;
        }
        if let Some(submission) = &self.presentation_submission {
            require_identifier(&submission.id, "presentation_submission.id")?;
            require_identifier(
                &submission.definition_id,
                "presentation_submission.definition_id",
            )?;
            if submission.descriptor_map.is_empty()
                || submission.descriptor_map.len() > MAX_QUERY_REQUIREMENTS
            {
                return Err(Oid4vpContractError::InvalidField(
                    "presentation_submission.descriptor_map",
                ));
            }
            for descriptor in &submission.descriptor_map {
                validate_descriptor(descriptor, 1)?;
            }
        }
        Ok(())
    }

    fn raw_tokens(&self) -> Vec<&str> {
        match &self.vp_token {
            VpToken::Single(token) => vec![token],
            VpToken::ByQuery(tokens) => tokens
                .values()
                .flat_map(|values| values.iter().map(String::as_str))
                .collect(),
        }
    }
}

impl FrozenOid4vpRequestV1 {
    pub fn from_json(value: &str) -> Result<Self, Oid4vpContractError> {
        let request: Self = parse_bounded(value, MAX_FROZEN_REQUEST_BYTES, "frozen_request")?;
        request.validate_structure()?;
        Ok(request)
    }

    pub fn validate_at(&self, now_epoch_seconds: i64) -> Result<(), Oid4vpContractError> {
        self.validate_structure()?;
        if now_epoch_seconds < self.issued_at_epoch_seconds
            || now_epoch_seconds > self.expires_at_epoch_seconds
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        Ok(())
    }

    pub fn validate_submission_at(
        &self,
        submission: &WalletSubmissionV1,
        now_epoch_seconds: i64,
    ) -> Result<(), Oid4vpContractError> {
        self.validate_at(now_epoch_seconds)?;
        submission.validate()?;
        if submission.state.as_deref() != Some(self.expected_state.as_str()) {
            return Err(Oid4vpContractError::StateMismatch);
        }

        let expected_ids = self.query_ids();
        match self.query.kind {
            QueryKind::Dcql => {
                if submission.presentation_submission.is_some() {
                    return Err(Oid4vpContractError::PresentationDefinitionMismatch);
                }
                match &submission.vp_token {
                    VpToken::Single(_) if expected_ids.len() == 1 => {}
                    VpToken::ByQuery(tokens)
                        if tokens.keys().cloned().collect::<BTreeSet<_>>() == expected_ids => {}
                    VpToken::Single(_) | VpToken::ByQuery(_) => {
                        return Err(Oid4vpContractError::QueryCoverageMismatch);
                    }
                }
            }
            QueryKind::PresentationExchange => {
                if !matches!(submission.vp_token, VpToken::Single(_)) {
                    return Err(Oid4vpContractError::QueryCoverageMismatch);
                }
                let presentation = submission
                    .presentation_submission
                    .as_ref()
                    .ok_or(Oid4vpContractError::PresentationDefinitionMismatch)?;
                let definition_id = self
                    .query
                    .document
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
                let descriptor_ids = presentation
                    .descriptor_map
                    .iter()
                    .map(|descriptor| descriptor.id.clone())
                    .collect::<BTreeSet<_>>();
                if presentation.definition_id != definition_id
                    || descriptor_ids.len() != presentation.descriptor_map.len()
                    || descriptor_ids != expected_ids
                {
                    return Err(Oid4vpContractError::PresentationDefinitionMismatch);
                }
                for descriptor in &presentation.descriptor_map {
                    let requirement = self
                        .query
                        .requirements
                        .iter()
                        .find(|requirement| requirement.id == descriptor.id)
                        .ok_or(Oid4vpContractError::PresentationDefinitionMismatch)?;
                    pe_descriptor_selector(descriptor, requirement)?;
                }
            }
        }
        self.validate_token_cardinality(submission)
    }

    fn validate_structure(&self) -> Result<(), Oid4vpContractError> {
        validate_serialized_size(self, MAX_FROZEN_REQUEST_BYTES, "frozen_request")?;
        for (value, name) in [
            (&self.session_id, "session_id"),
            (&self.organization_id, "organization_id"),
            (&self.initiating_principal_id, "initiating_principal_id"),
            (&self.policy.id, "policy.id"),
            (&self.verifier.client_id, "verifier.client_id"),
            (&self.expected_state, "expected_state"),
        ] {
            require_identifier(value, name)?;
        }
        require_text(&self.nonce, "nonce", MAX_IDENTIFIER_BYTES)?;
        if self.nonce.len() < MIN_NONCE_BYTES {
            return Err(Oid4vpContractError::InvalidField("nonce"));
        }
        require_text(
            &self.verifier.response_uri,
            "verifier.response_uri",
            MAX_IDENTIFIER_BYTES,
        )?;
        let response_uri = Url::parse(&self.verifier.response_uri)
            .map_err(|_| Oid4vpContractError::InvalidField("verifier.response_uri"))?;
        if response_uri.scheme() != "https" || response_uri.host_str().is_none() {
            return Err(Oid4vpContractError::InvalidField("verifier.response_uri"));
        }
        validate_policy_reference(self)?;
        let lifetime = self
            .expires_at_epoch_seconds
            .checked_sub(self.issued_at_epoch_seconds)
            .ok_or(Oid4vpContractError::InvalidLifetime)?;
        if self.issued_at_epoch_seconds <= 0
            || lifetime <= 0
            || lifetime > MAX_REQUEST_LIFETIME_SECONDS
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        validate_bounded_value(
            &self.query.document,
            "query.document",
            MAX_QUERY_DOCUMENT_BYTES,
        )?;
        validate_digest(&self.query.document_digest, "query.document_digest")?;
        if digest_query_document(&self.query.document)? != self.query.document_digest {
            return Err(Oid4vpContractError::QueryDigestMismatch);
        }
        self.validate_requirements()
    }

    fn validate_requirements(&self) -> Result<(), Oid4vpContractError> {
        if self.query.requirements.is_empty()
            || self.query.requirements.len() > MAX_QUERY_REQUIREMENTS
            || self
                .query
                .requirements
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        let mut ids = BTreeSet::new();
        for requirement in &self.query.requirements {
            validate_requirement(requirement)?;
            if !ids.insert(requirement.id.clone()) {
                return Err(Oid4vpContractError::InvalidQueryDocument);
            }
        }
        let document_ids = validate_query_document_semantics(
            self.query.kind,
            &self.query.document,
            &self.query.requirements,
        )?;
        if ids != document_ids {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        if self.query.kind == QueryKind::PresentationExchange
            && self.query.requirements.iter().any(|requirement| {
                requirement.min_credentials != 1 || requirement.max_credentials != 1
            })
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        Ok(())
    }

    fn validate_token_cardinality(
        &self,
        submission: &WalletSubmissionV1,
    ) -> Result<(), Oid4vpContractError> {
        if self.query.kind == QueryKind::PresentationExchange {
            return Ok(());
        }
        match &submission.vp_token {
            VpToken::Single(_) => {
                let requirement = self
                    .query
                    .requirements
                    .first()
                    .ok_or(Oid4vpContractError::QueryCoverageMismatch)?;
                if !(requirement.min_credentials..=requirement.max_credentials).contains(&1) {
                    return Err(Oid4vpContractError::QueryCoverageMismatch);
                }
            }
            VpToken::ByQuery(tokens) => {
                for requirement in &self.query.requirements {
                    let count = u16::try_from(
                        tokens
                            .get(&requirement.id)
                            .ok_or(Oid4vpContractError::QueryCoverageMismatch)?
                            .len(),
                    )
                    .map_err(|_| Oid4vpContractError::QueryCoverageMismatch)?;
                    if !(requirement.min_credentials..=requirement.max_credentials).contains(&count)
                    {
                        return Err(Oid4vpContractError::QueryCoverageMismatch);
                    }
                }
            }
        }
        Ok(())
    }

    fn query_ids(&self) -> BTreeSet<String> {
        self.query
            .requirements
            .iter()
            .map(|requirement| requirement.id.clone())
            .collect()
    }
}

impl Oid4vpEvidenceProjectionV1 {
    pub fn from_json(value: &str) -> Result<Self, Oid4vpContractError> {
        parse_bounded(value, MAX_EVIDENCE_PROJECTION_BYTES, "evidence_projection")
    }

    pub fn validate_against_at(
        &self,
        request: &FrozenOid4vpRequestV1,
        submission: &WalletSubmissionV1,
        now_epoch_seconds: i64,
    ) -> Result<(), Oid4vpContractError> {
        validate_serialized_size(self, MAX_EVIDENCE_PROJECTION_BYTES, "evidence_projection")?;
        request.validate_submission_at(submission, now_epoch_seconds)?;
        let request_digest = digest_frozen_request(request)?;
        let response_digest = digest_wallet_submission(submission)?;
        if self.request_digest != request_digest {
            return Err(Oid4vpContractError::RequestDigestMismatch);
        }
        if self.response_digest != response_digest {
            return Err(Oid4vpContractError::ResponseDigestMismatch);
        }
        validate_digest(&self.request_digest, "request_digest")?;
        validate_digest(&self.response_digest, "response_digest")?;
        self.validate_supporting_facts(request, now_epoch_seconds)?;
        let credential_state = self.validate_credentials(request, submission, now_epoch_seconds)?;
        self.validate_bindings(request, now_epoch_seconds)?;
        self.validate_checks(&credential_state)?;
        self.validate_decision(request, &credential_state, now_epoch_seconds)?;
        self.validate_privacy(submission)?;
        Ok(())
    }

    fn validate_supporting_facts(
        &self,
        request: &FrozenOid4vpRequestV1,
        now: i64,
    ) -> Result<(), Oid4vpContractError> {
        validate_fact(
            &self.presentation.structure,
            FactKind::PresentationStructure,
            request,
            now,
        )?;
        validate_fact(
            &self.presentation.proof,
            FactKind::PresentationProof,
            request,
            now,
        )?;
        Ok(())
    }

    fn validate_credentials(
        &self,
        request: &FrozenOid4vpRequestV1,
        submission: &WalletSubmissionV1,
        now: i64,
    ) -> Result<CredentialValidationState, Oid4vpContractError> {
        if self.credentials.is_empty() || self.credentials.len() > MAX_CREDENTIALS {
            return Err(Oid4vpContractError::CredentialBindingMismatch);
        }
        if self
            .credentials
            .windows(2)
            .any(|pair| pair[0].credential_id >= pair[1].credential_id)
        {
            return Err(Oid4vpContractError::CredentialBindingMismatch);
        }
        let mut credential_ids = BTreeSet::new();
        let mut response_item_digests = BTreeSet::new();
        let mut by_query: BTreeMap<&str, Vec<&crate::AuthenticatedCredentialEvidence>> =
            BTreeMap::new();
        for credential in &self.credentials {
            require_identifier(&credential.credential_id, "credentials.credential_id")?;
            require_identifier(&credential.query_id, "credentials.query_id")?;
            require_identifier(&credential.format, "credentials.format")?;
            require_identifier(&credential.issuer_id, "credentials.issuer_id")?;
            require_identifier(&credential.proof_algorithm, "credentials.proof_algorithm")?;
            if !credential_ids.insert(credential.credential_id.clone()) {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            }
            let requirement = request
                .query
                .requirements
                .iter()
                .find(|requirement| requirement.id == credential.query_id)
                .ok_or(Oid4vpContractError::CredentialBindingMismatch)?;
            validate_digest(
                &credential.response_token_digest,
                "credentials.response_token_digest",
            )?;
            if !response_item_digests.insert(credential.response_token_digest.clone()) {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            }
            validate_string_list(
                &credential.authenticated_type_or_vct,
                "credentials.authenticated_type_or_vct",
                false,
            )?;
            validate_string_list(&credential.status_ids, "credentials.status_ids", true)?;
            if credential.claims.len() > MAX_CLAIMS_PER_CREDENTIAL {
                return Err(Oid4vpContractError::InvalidField("credentials.claims"));
            }
            for (name, value) in &credential.claims {
                require_identifier(name, "credentials.claims.name")?;
                validate_bounded_value(value, "credentials.claims.value", MAX_CLAIM_VALUE_BYTES)?;
            }
            if credential.issued_at_epoch_seconds <= 0 || credential.issued_at_epoch_seconds > now {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            }
            validate_fact(&credential.proof, FactKind::CredentialProof, request, now)?;
            validate_trust(credential, request, now)?;
            validate_status(credential, requirement, request, now)?;
            by_query
                .entry(credential.query_id.as_str())
                .or_default()
                .push(credential);
        }

        validate_credential_token_binding(request, submission, &by_query)?;

        let mut requirement_satisfaction = BTreeMap::new();
        let mut claim_outcomes = Vec::new();
        for requirement in &request.query.requirements {
            let credentials = by_query
                .get(requirement.id.as_str())
                .ok_or(Oid4vpContractError::CredentialBindingMismatch)?;
            let count = u16::try_from(credentials.len())
                .map_err(|_| Oid4vpContractError::CredentialBindingMismatch)?;
            if !(requirement.min_credentials..=requirement.max_credentials).contains(&count) {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            }
            let metadata_satisfied = credentials
                .iter()
                .all(|credential| credential_matches_requirement(credential, requirement));
            claim_outcomes.push(if metadata_satisfied {
                EvidenceCheckOutcome::Passed
            } else {
                EvidenceCheckOutcome::Failed
            });
            let fully_satisfied = metadata_satisfied
                && credentials.iter().all(|credential| {
                    credential.proof.outcome == EvidenceCheckOutcome::Passed
                        && credential.trust.outcome == EvidenceCheckOutcome::Passed
                        && credential.status.outcome == EvidenceCheckOutcome::Passed
                });
            requirement_satisfaction.insert(requirement.id.clone(), fully_satisfied);
        }

        Ok(CredentialValidationState {
            credential_proof: aggregate_outcomes(
                self.credentials
                    .iter()
                    .map(|credential| credential.proof.outcome),
            ),
            trust: aggregate_outcomes(
                self.credentials
                    .iter()
                    .map(|credential| credential.trust.outcome),
            ),
            status: aggregate_outcomes(
                self.credentials
                    .iter()
                    .map(|credential| credential.status.outcome),
            ),
            claims: aggregate_outcomes(claim_outcomes),
            credential_ids,
            requirement_satisfaction,
        })
    }

    fn validate_bindings(
        &self,
        request: &FrozenOid4vpRequestV1,
        now: i64,
    ) -> Result<(), Oid4vpContractError> {
        validate_digest_binding(
            &self.binding.challenge,
            &digest_nonce(&request.nonce)?,
            DigestBindingKind::Challenge,
            "binding.challenge",
        )?;
        validate_digest_binding(
            &self.binding.audience,
            &digest_audience(&request.verifier.client_id)?,
            DigestBindingKind::Audience,
            "binding.audience",
        )?;
        let holder = &self.binding.holder;
        if holder.code != expected_holder_code(holder.outcome) {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        match holder.outcome {
            EvidenceCheckOutcome::Passed => {
                require_identifier(
                    holder
                        .method
                        .as_deref()
                        .ok_or(Oid4vpContractError::BindingMismatch)?,
                    "binding.holder.method",
                )?;
                require_identifier(
                    holder
                        .proof_profile
                        .as_deref()
                        .ok_or(Oid4vpContractError::BindingMismatch)?,
                    "binding.holder.proof_profile",
                )?;
                validate_digest(
                    holder
                        .evidence_digest
                        .as_deref()
                        .ok_or(Oid4vpContractError::BindingMismatch)?,
                    "binding.holder.evidence_digest",
                )?;
                validate_checked_at(
                    holder
                        .checked_at_epoch_seconds
                        .ok_or(Oid4vpContractError::BindingMismatch)?,
                    request,
                    now,
                )?;
            }
            EvidenceCheckOutcome::Failed | EvidenceCheckOutcome::Indeterminate => {
                if holder.method.is_some()
                    || holder.proof_profile.is_some()
                    || holder.evidence_digest.is_some()
                    || holder.checked_at_epoch_seconds.is_some()
                {
                    return Err(Oid4vpContractError::BindingMismatch);
                }
            }
        }
        let replay = &self.binding.replay;
        if replay.code != expected_replay_code(replay.outcome) {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        validate_digest(
            &replay.replay_key_digest,
            "binding.replay.replay_key_digest",
        )?;
        if replay.replay_key_digest
            != digest_replay_key(&self.request_digest, &self.response_digest)?
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        match replay.outcome {
            EvidenceCheckOutcome::Passed => {
                if replay.consumed_at_epoch_seconds != Some(now) {
                    return Err(Oid4vpContractError::BindingMismatch);
                }
                validate_digest(
                    replay
                        .receipt_digest
                        .as_deref()
                        .ok_or(Oid4vpContractError::BindingMismatch)?,
                    "binding.replay.receipt_digest",
                )?;
            }
            EvidenceCheckOutcome::Failed | EvidenceCheckOutcome::Indeterminate => {
                if replay.consumed_at_epoch_seconds.is_some() || replay.receipt_digest.is_some() {
                    return Err(Oid4vpContractError::BindingMismatch);
                }
            }
        }
        Ok(())
    }

    fn validate_checks(
        &self,
        credential_state: &CredentialValidationState,
    ) -> Result<(), Oid4vpContractError> {
        if self.checks.len() != REQUIRED_OID4VP_CHECKS.len()
            || self
                .checks
                .iter()
                .map(|check| check.check_id)
                .ne(REQUIRED_OID4VP_CHECKS)
        {
            return Err(Oid4vpContractError::CheckInventoryMismatch);
        }
        let expected = [
            self.presentation.structure.outcome,
            self.presentation.proof.outcome,
            credential_state.credential_proof,
            credential_state.trust,
            credential_state.status,
            self.binding.holder.outcome,
            aggregate_outcomes([
                self.binding.challenge.outcome,
                self.binding.audience.outcome,
                self.binding.replay.outcome,
            ]),
            credential_state.claims,
        ];
        for (check, expected_outcome) in self.checks.iter().zip(expected) {
            if check.outcome != expected_outcome
                || check.code != expected_check_code(check.check_id, expected_outcome)
            {
                return Err(Oid4vpContractError::CheckEvidenceMismatch);
            }
        }
        let expected_processing = if expected.contains(&EvidenceCheckOutcome::Indeterminate) {
            EvidenceProcessingStatus::Incomplete
        } else {
            EvidenceProcessingStatus::Complete
        };
        if self.processing_status != expected_processing {
            return Err(Oid4vpContractError::CheckEvidenceMismatch);
        }
        Ok(())
    }

    fn validate_decision(
        &self,
        request: &FrozenOid4vpRequestV1,
        credential_state: &CredentialValidationState,
        now: i64,
    ) -> Result<(), Oid4vpContractError> {
        let expected_identity = FrozenPolicyIdentity {
            id: request.policy.id.clone(),
            version: request.policy.version,
            content_digest: request.policy.content_digest.clone(),
        };
        let parity_counts = policy_parity_counts(
            request,
            credential_state,
            self.presentation.proof.outcome == EvidenceCheckOutcome::Passed,
        )?;
        if self.policy_result.policy != expected_identity
            || self.policy_result.evaluation_time_epoch_seconds != now
            || self.policy_result.total_requirements != parity_counts.total
            || self.policy_result.satisfied_requirements != parity_counts.satisfied
            || self.policy_result.required_total != parity_counts.required_total
            || self.policy_result.required_satisfied != parity_counts.required_satisfied
            || self.policy_result.evaluated_credential_ids
                != credential_state
                    .credential_ids
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        require_code(&self.policy_result.reason_code, "policy_result.reason_code")?;
        require_code(&self.decision.reason_code, "decision.reason_code")?;
        if self.policy_result.violation_codes.len() > MAX_EVIDENCE_LIST_ITEMS {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        validate_string_list(
            &self.policy_result.violation_codes,
            "policy_result.violation_codes",
            true,
        )?;

        let any_indeterminate = self
            .checks
            .iter()
            .any(|check| check.outcome == EvidenceCheckOutcome::Indeterminate);
        let global_failure = [0usize, 1, 5, 6]
            .into_iter()
            .any(|index| self.checks[index].outcome == EvidenceCheckOutcome::Failed);
        let fully_satisfied = parity_counts.required_satisfied == parity_counts.required_total
            && !global_failure
            && !any_indeterminate;
        let partial = parity_counts.satisfied_credential_obligations > 0
            && !global_failure
            && !any_indeterminate;
        let expected = if fully_satisfied {
            (
                AuthenticatedResult::Passed,
                AuthenticatedDecisionAction::Allow,
            )
        } else if partial {
            (
                AuthenticatedResult::Partial,
                AuthenticatedDecisionAction::ManualReview,
            )
        } else if any_indeterminate {
            (
                AuthenticatedResult::Indeterminate,
                AuthenticatedDecisionAction::Deny,
            )
        } else {
            (
                AuthenticatedResult::Failed,
                AuthenticatedDecisionAction::Deny,
            )
        };
        if (self.policy_result.result, self.policy_result.decision) != expected
            || (self.decision.result, self.decision.decision) != expected
            || self.policy_result.reason_code != self.decision.reason_code
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }

        if fully_satisfied {
            if self.policy_result.satisfied_requirements != self.policy_result.total_requirements
                || !self.policy_result.violation_codes.is_empty()
                || self.policy_result.reason_code != "OID4VP_AND_POLICY_PASSED"
                || self.policy_result.verified_claims != merged_verified_claims(&self.credentials)?
            {
                return Err(Oid4vpContractError::DecisionMismatch);
            }
        } else {
            let first_violation = self
                .policy_result
                .violation_codes
                .first()
                .ok_or(Oid4vpContractError::DecisionMismatch)?;
            if !self.policy_result.verified_claims.is_empty()
                || &self.policy_result.reason_code != first_violation
                || (partial && self.policy_result.reason_code != "OID4VP_POLICY_PARTIAL")
            {
                return Err(Oid4vpContractError::DecisionMismatch);
            }
        }
        Ok(())
    }

    fn validate_privacy(&self, submission: &WalletSubmissionV1) -> Result<(), Oid4vpContractError> {
        let value = serde_json::to_value(self).map_err(|_| Oid4vpContractError::Serialization)?;
        let raw_tokens = submission.raw_tokens();
        let sensitive_patterns = sensitive_token_patterns(&raw_tokens);
        if contains_sensitive_string(&value, &sensitive_patterns) || contains_forbidden_key(&value)
        {
            return Err(Oid4vpContractError::PrivacyViolation);
        }
        Ok(())
    }
}

struct CredentialValidationState {
    credential_proof: EvidenceCheckOutcome,
    trust: EvidenceCheckOutcome,
    status: EvidenceCheckOutcome,
    claims: EvidenceCheckOutcome,
    credential_ids: BTreeSet<String>,
    requirement_satisfaction: BTreeMap<String, bool>,
}

struct PolicyParityCounts {
    total: u16,
    satisfied: u16,
    required_total: u16,
    required_satisfied: u16,
    satisfied_credential_obligations: u16,
}

fn policy_parity_counts(
    request: &FrozenOid4vpRequestV1,
    credential_state: &CredentialValidationState,
    presentation_proof_satisfied: bool,
) -> Result<PolicyParityCounts, Oid4vpContractError> {
    let grouped_ids = request
        .policy
        .alternative_requirement_groups
        .iter()
        .flat_map(|group| group.requirement_ids.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let direct = request
        .query
        .requirements
        .iter()
        .filter(|requirement| !grouped_ids.contains(requirement.id.as_str()))
        .collect::<Vec<_>>();
    let is_satisfied = |id: &str| {
        credential_state
            .requirement_satisfaction
            .get(id)
            .copied()
            .unwrap_or(false)
    };
    let direct_satisfied = direct
        .iter()
        .filter(|requirement| is_satisfied(&requirement.id))
        .count();
    let required_direct = direct
        .iter()
        .filter(|requirement| requirement.required)
        .copied()
        .collect::<Vec<_>>();
    let required_direct_satisfied = required_direct
        .iter()
        .filter(|requirement| is_satisfied(&requirement.id))
        .count();
    let satisfied_groups = request
        .policy
        .alternative_requirement_groups
        .iter()
        .filter(|group| {
            group
                .requirement_ids
                .iter()
                .filter(|id| is_satisfied(id))
                .count()
                >= usize::from(group.min_satisfied)
        })
        .count();
    let proof_unit = usize::from(request.policy.presentation_proof_required);
    let proof_satisfied =
        usize::from(request.policy.presentation_proof_required && presentation_proof_satisfied);
    let total = direct.len() + request.policy.alternative_requirement_groups.len() + proof_unit;
    let satisfied = direct_satisfied + satisfied_groups + proof_satisfied;
    let required_total =
        required_direct.len() + request.policy.alternative_requirement_groups.len() + proof_unit;
    let required_satisfied = required_direct_satisfied + satisfied_groups + proof_satisfied;
    Ok(PolicyParityCounts {
        total: u16::try_from(total).map_err(|_| Oid4vpContractError::DecisionMismatch)?,
        satisfied: u16::try_from(satisfied).map_err(|_| Oid4vpContractError::DecisionMismatch)?,
        required_total: u16::try_from(required_total)
            .map_err(|_| Oid4vpContractError::DecisionMismatch)?,
        required_satisfied: u16::try_from(required_satisfied)
            .map_err(|_| Oid4vpContractError::DecisionMismatch)?,
        satisfied_credential_obligations: u16::try_from(
            required_direct_satisfied + satisfied_groups,
        )
        .map_err(|_| Oid4vpContractError::DecisionMismatch)?,
    })
}

fn validate_policy_reference(request: &FrozenOid4vpRequestV1) -> Result<(), Oid4vpContractError> {
    if request.policy.version == 0
        || request.policy.max_trust_age_seconds == 0
        || i64::from(request.policy.max_trust_age_seconds) > MAX_REQUEST_LIFETIME_SECONDS
    {
        return Err(Oid4vpContractError::InvalidField("policy"));
    }
    validate_digest(&request.policy.content_digest, "policy.content_digest")?;
    validate_profile(&request.policy.trust_profile)?;

    let requirement_ids = request
        .query
        .requirements
        .iter()
        .map(|requirement| requirement.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut grouped_ids = BTreeSet::new();
    let mut previous_group_id: Option<&str> = None;
    for group in &request.policy.alternative_requirement_groups {
        require_identifier(&group.id, "policy.alternative_group.id")?;
        if previous_group_id.is_some_and(|previous| previous >= group.id.as_str())
            || group.requirement_ids.is_empty()
            || group.requirement_ids.len() > MAX_QUERY_REQUIREMENTS
            || group
                .requirement_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || group.min_satisfied == 0
            || usize::from(group.min_satisfied) > group.requirement_ids.len()
        {
            return Err(Oid4vpContractError::InvalidField(
                "policy.alternative_requirement_groups",
            ));
        }
        previous_group_id = Some(&group.id);
        for requirement_id in &group.requirement_ids {
            require_identifier(requirement_id, "policy.alternative_group.requirement_id")?;
            if !requirement_ids.contains(requirement_id.as_str())
                || !grouped_ids.insert(requirement_id.as_str())
            {
                return Err(Oid4vpContractError::InvalidField(
                    "policy.alternative_requirement_groups",
                ));
            }
        }
    }
    if request
        .query
        .requirements
        .iter()
        .any(|requirement| grouped_ids.contains(requirement.id.as_str()) && requirement.required)
    {
        return Err(Oid4vpContractError::InvalidField(
            "policy.alternative_requirement_groups",
        ));
    }
    if !request.policy.presentation_proof_required
        && !request
            .query
            .requirements
            .iter()
            .any(|requirement| requirement.required)
        && request.policy.alternative_requirement_groups.is_empty()
    {
        return Err(Oid4vpContractError::InvalidField("policy.obligations"));
    }
    Ok(())
}

fn validate_profile(profile: &crate::EvidenceProfileReference) -> Result<(), Oid4vpContractError> {
    require_identifier(&profile.id, "trust.profile.id")?;
    if profile.version == 0 {
        return Err(Oid4vpContractError::TrustEvidenceMismatch);
    }
    validate_digest(&profile.content_digest, "trust.profile.content_digest")
}

fn validate_requirement(
    requirement: &FrozenCredentialRequirement,
) -> Result<(), Oid4vpContractError> {
    require_identifier(&requirement.id, "query.requirements.id")?;
    validate_string_list(
        &requirement.accepted_formats,
        "query.requirements.accepted_formats",
        false,
    )?;
    validate_type_sets(&requirement.accepted_type_sets)?;
    validate_string_list(
        &requirement.required_claims,
        "query.requirements.required_claims",
        true,
    )?;
    validate_string_list(
        &requirement.allowed_claims,
        "query.requirements.allowed_claims",
        true,
    )?;
    validate_string_list(
        &requirement.retained_claims,
        "query.requirements.retained_claims",
        true,
    )?;
    if !requirement
        .retained_claims
        .iter()
        .all(|claim| requirement.allowed_claims.binary_search(claim).is_ok())
    {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    validate_accepted_algorithms(requirement)?;
    if !requirement
        .required_claims
        .iter()
        .all(|claim| requirement.allowed_claims.binary_search(claim).is_ok())
        || requirement.min_credentials == 0
        || requirement.max_credentials < requirement.min_credentials
        || usize::from(requirement.max_credentials) > MAX_CREDENTIALS
        || requirement.status.max_age_seconds == 0
        || i64::from(requirement.status.max_age_seconds) > MAX_REQUEST_LIFETIME_SECONDS
    {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    Ok(())
}

fn validate_accepted_algorithms(
    requirement: &FrozenCredentialRequirement,
) -> Result<(), Oid4vpContractError> {
    if requirement
        .accepted_algorithms
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        != requirement.accepted_formats
    {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    for algorithms in requirement.accepted_algorithms.values() {
        validate_string_list(algorithms, "query.requirements.accepted_algorithms", false)?;
        if algorithms
            .iter()
            .any(|algorithm| algorithm.eq_ignore_ascii_case("none"))
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
    }
    Ok(())
}

fn validate_type_sets(type_sets: &[Vec<String>]) -> Result<(), Oid4vpContractError> {
    if type_sets.is_empty()
        || type_sets.len() > MAX_EVIDENCE_LIST_ITEMS
        || type_sets.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    for type_set in type_sets {
        validate_string_list(type_set, "query.requirements.accepted_type_sets", false)?;
    }
    Ok(())
}

fn validate_query_document_semantics(
    kind: QueryKind,
    document: &Value,
    requirements: &[FrozenCredentialRequirement],
) -> Result<BTreeSet<String>, Oid4vpContractError> {
    match kind {
        QueryKind::Dcql => validate_dcql_document(document, requirements),
        QueryKind::PresentationExchange => validate_pe_document(document, requirements),
    }
}

fn validate_dcql_document(
    document: &Value,
    requirements: &[FrozenCredentialRequirement],
) -> Result<BTreeSet<String>, Oid4vpContractError> {
    let object = exact_object(document, &["credentials"], &[])?;
    let entries = object["credentials"]
        .as_array()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    let mut ids = BTreeSet::new();
    for entry in entries {
        let object = exact_object(entry, &["format", "id", "meta"], &["claims"])?;
        let id = object["id"]
            .as_str()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        require_identifier(id, "query.document.id")?;
        if !ids.insert(id.to_owned()) {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        let requirement = requirement_by_id(requirements, id)?;
        let format = object["format"]
            .as_str()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        if requirement.accepted_formats != [format] {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        if !requirement.format_options.is_empty() {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        if requirement.accepted_type_sets != extract_dcql_meta(&object["meta"])? {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        let claim_entries = object.get("claims").map_or(Ok(&[][..]), |claims| {
            claims
                .as_array()
                .map(Vec::as_slice)
                .ok_or(Oid4vpContractError::InvalidQueryDocument)
        })?;
        let (claims, retained_claims) = extract_dcql_claims(claim_entries, requirement)?;
        if requirement.required_claims != claims
            || requirement.allowed_claims != claims
            || requirement.retained_claims != retained_claims
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
    }
    if ids.is_empty() || ids.len() != entries.len() {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    Ok(ids)
}

fn validate_pe_document(
    document: &Value,
    requirements: &[FrozenCredentialRequirement],
) -> Result<BTreeSet<String>, Oid4vpContractError> {
    let object = exact_object(document, &["format", "id", "input_descriptors"], &[])?;
    require_identifier(
        object["id"]
            .as_str()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?,
        "query.document.definition_id",
    )?;
    let top_formats = object["format"]
        .as_object()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    let expected_top_formats = expected_pe_top_formats(requirements)?;
    if top_formats != &expected_top_formats {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    let entries = object["input_descriptors"]
        .as_array()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    let mut ids = BTreeSet::new();
    for entry in entries {
        let descriptor = exact_object(
            entry,
            &["constraints", "format", "id", "name", "purpose"],
            &[],
        )?;
        let id = descriptor["id"]
            .as_str()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        require_identifier(id, "query.document.id")?;
        if !ids.insert(id.to_owned()) {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        for (value, field) in [
            (&descriptor["name"], "query.document.descriptor.name"),
            (&descriptor["purpose"], "query.document.descriptor.purpose"),
        ] {
            require_text(
                value
                    .as_str()
                    .ok_or(Oid4vpContractError::InvalidQueryDocument)?,
                field,
                MAX_IDENTIFIER_BYTES,
            )?;
        }
        let requirement = requirement_by_id(requirements, id)?;
        let format_object = descriptor["format"]
            .as_object()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        let expected_descriptor_formats = requirement
            .format_options
            .iter()
            .map(|(format, options)| (format.clone(), options.clone()))
            .collect::<serde_json::Map<_, _>>();
        if format_object != &expected_descriptor_formats {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        validate_pe_format_options(requirement)?;
        validate_pe_constraints(&descriptor["constraints"], requirement)?;
    }
    if ids.is_empty() || ids.len() != entries.len() {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    Ok(ids)
}

fn expected_pe_top_formats(
    requirements: &[FrozenCredentialRequirement],
) -> Result<serde_json::Map<String, Value>, Oid4vpContractError> {
    let mut formats = serde_json::Map::new();
    for requirement in requirements {
        if requirement
            .format_options
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            != requirement.accepted_formats
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        for (format, options) in &requirement.format_options {
            if formats
                .insert(format.clone(), options.clone())
                .is_some_and(|previous| previous != *options)
            {
                return Err(Oid4vpContractError::InvalidQueryDocument);
            }
        }
    }
    Ok(formats)
}

fn validate_pe_format_options(
    requirement: &FrozenCredentialRequirement,
) -> Result<(), Oid4vpContractError> {
    const ALGORITHM_KEYS: [&str; 4] = [
        "alg",
        "proof_type",
        "sd-jwt_alg_values",
        "kb-jwt_alg_values",
    ];
    for (format, options) in &requirement.format_options {
        let object = options
            .as_object()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        if object.is_empty()
            || object
                .keys()
                .any(|key| !ALGORITHM_KEYS.contains(&key.as_str()))
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        for values in object.values() {
            for algorithm in string_array(values, "query.document.format.algorithms")? {
                if algorithm.eq_ignore_ascii_case("none") {
                    return Err(Oid4vpContractError::InvalidQueryDocument);
                }
            }
        }
        let primary = ["alg", "proof_type", "sd-jwt_alg_values"]
            .into_iter()
            .find_map(|key| object.get(key))
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        let primary_values = string_array(primary, "query.document.format.primary_algorithms")?;
        let primary_algorithm_set = primary_values.iter().cloned().collect::<BTreeSet<_>>();
        if primary_algorithm_set.len() != primary_values.len() {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        let primary_algorithms = primary_algorithm_set.into_iter().collect::<Vec<_>>();
        if primary_algorithms != requirement.accepted_algorithms[format] {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
    }
    Ok(())
}

fn validate_pe_constraints(
    constraints: &Value,
    requirement: &FrozenCredentialRequirement,
) -> Result<(), Oid4vpContractError> {
    let object = exact_object(constraints, &["fields"], &["limit_disclosure"])?;
    if object
        .get("limit_disclosure")
        .is_some_and(|value| value.as_str() != Some("required"))
    {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    let fields = object["fields"]
        .as_array()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    let mut types = BTreeSet::new();
    let mut allowed_claims = BTreeSet::new();
    let mut required_claims = BTreeSet::new();
    let mut retained_claims = BTreeSet::new();
    for field in fields {
        let field = exact_object(
            field,
            &["path"],
            &["filter", "intent_to_retain", "name", "optional", "purpose"],
        )?;
        let paths = string_array(&field["path"], "query.document.field.path")?;
        if let Some(claim) = pe_claim_name(&paths) {
            require_identifier(&claim, "query.document.claim")?;
            if !allowed_claims.insert(claim.clone()) {
                return Err(Oid4vpContractError::InvalidQueryDocument);
            }
            let optional = field
                .get("optional")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or(Oid4vpContractError::InvalidQueryDocument)
                })
                .transpose()?
                .unwrap_or(false);
            if !optional {
                required_claims.insert(claim.clone());
            }
            if field
                .get("intent_to_retain")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or(Oid4vpContractError::InvalidQueryDocument)
                })
                .transpose()?
                .unwrap_or(false)
            {
                retained_claims.insert(claim);
            }
            continue;
        }
        let filter = field
            .get("filter")
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        for value in pe_selector_values(&paths, filter)? {
            types.insert(value);
        }
    }
    let selector_type_sets = types
        .into_iter()
        .map(|value| vec![value])
        .collect::<Vec<_>>();
    if selector_type_sets != requirement.accepted_type_sets
        || allowed_claims.into_iter().collect::<Vec<_>>() != requirement.allowed_claims
        || required_claims.into_iter().collect::<Vec<_>>() != requirement.required_claims
        || retained_claims.into_iter().collect::<Vec<_>>() != requirement.retained_claims
    {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    Ok(())
}

fn extract_dcql_meta(meta: &Value) -> Result<Vec<Vec<String>>, Oid4vpContractError> {
    let object = meta
        .as_object()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    if object.len() != 1 {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    let mut values = match object.iter().next() {
        Some((key, value)) if key == "vct_values" => string_array(value, "query.document.meta")?
            .into_iter()
            .map(|value| vec![value])
            .collect(),
        Some((key, value)) if key == "doctype_value" => vec![vec![value
            .as_str()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?
            .to_owned()]],
        Some((key, value)) if key == "type_values" => {
            let alternatives = value
                .as_array()
                .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
            let mut canonical_type_sets = BTreeSet::new();
            for entry in alternatives {
                let values = string_array(entry, "query.document.meta.type_values")?;
                let mut alternative = values.iter().cloned().collect::<BTreeSet<_>>();
                if alternative.len() != values.len() {
                    return Err(Oid4vpContractError::InvalidQueryDocument);
                }
                alternative.remove("VerifiableCredential");
                if alternative.is_empty() {
                    return Err(Oid4vpContractError::InvalidQueryDocument);
                }
                if !canonical_type_sets.insert(alternative.into_iter().collect::<Vec<_>>()) {
                    return Err(Oid4vpContractError::InvalidQueryDocument);
                }
            }
            canonical_type_sets.into_iter().collect()
        }
        _ => return Err(Oid4vpContractError::InvalidQueryDocument),
    };
    values.sort();
    values.dedup();
    if values.is_empty() {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    Ok(values)
}

fn extract_dcql_claims(
    entries: &[Value],
    requirement: &FrozenCredentialRequirement,
) -> Result<(Vec<String>, Vec<String>), Oid4vpContractError> {
    let mut claims = BTreeSet::new();
    let mut retained_claims = BTreeSet::new();
    for entry in entries {
        let object = exact_object(entry, &["id", "path"], &["intent_to_retain"])?;
        let id = object["id"]
            .as_str()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        require_identifier(id, "query.document.claim.id")?;
        let path = string_array(&object["path"], "query.document.claim.path")?;
        let claim = if (1..=2).contains(&path.len()) {
            path.join(".")
        } else {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        };
        let intent_to_retain = object
            .get("intent_to_retain")
            .map(|value| {
                value
                    .as_bool()
                    .ok_or(Oid4vpContractError::InvalidQueryDocument)
            })
            .transpose()?
            .unwrap_or(false);
        if canonical_claim_id(&claim) != id
            || requirement.allowed_claims.binary_search(&claim).is_err()
            || !claims.insert(claim.clone())
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        if intent_to_retain {
            retained_claims.insert(claim);
        }
    }
    Ok((
        claims.into_iter().collect(),
        retained_claims.into_iter().collect(),
    ))
}

fn pe_claim_name(paths: &[String]) -> Option<String> {
    if paths.len() != 3 {
        return None;
    }
    let claim = paths[2].strip_prefix("$.")?;
    let expected = [
        format!("$.vc.credentialSubject.{claim}"),
        format!("$.credentialSubject.{claim}"),
        format!("$.{claim}"),
    ];
    (paths == expected).then(|| claim.to_owned())
}

fn pe_selector_values(
    paths: &[String],
    filter: &Value,
) -> Result<Vec<String>, Oid4vpContractError> {
    if paths == ["$.vct"] || paths == ["$.mdoc.docType", "$.docType"] {
        let object = exact_object(filter, &["type"], &["const", "enum"])?;
        if object["type"].as_str() != Some("string") {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        return match (object.get("const"), object.get("enum")) {
            (Some(value), None) => Ok(vec![value
                .as_str()
                .ok_or(Oid4vpContractError::InvalidQueryDocument)?
                .to_owned()]),
            (None, Some(values)) => string_array(values, "query.document.selector.enum"),
            _ => Err(Oid4vpContractError::InvalidQueryDocument),
        };
    }
    if paths == ["$.vc.type", "$.type"] {
        let object = exact_object(filter, &["anyOf"], &[])?;
        let alternatives = object["anyOf"]
            .as_array()
            .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
        let mut values = BTreeSet::new();
        for alternative in alternatives {
            collect_const_strings(alternative, &mut values)?;
        }
        values.remove("VerifiableCredential");
        if values.is_empty() {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        return Ok(values.into_iter().collect());
    }
    Err(Oid4vpContractError::InvalidQueryDocument)
}

fn collect_const_strings(
    value: &Value,
    output: &mut BTreeSet<String>,
) -> Result<(), Oid4vpContractError> {
    let object = value
        .as_object()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    if let Some(value) = object.get("const") {
        if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("string") {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        output.insert(
            value
                .as_str()
                .ok_or(Oid4vpContractError::InvalidQueryDocument)?
                .to_owned(),
        );
        return Ok(());
    }
    if let Some(contains) = object.get("contains") {
        if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("array") {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        return collect_const_strings(contains, output);
    }
    Err(Oid4vpContractError::InvalidQueryDocument)
}

fn exact_object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, Oid4vpContractError> {
    let object = value
        .as_object()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    Ok(object)
}

fn requirement_by_id<'a>(
    requirements: &'a [FrozenCredentialRequirement],
    id: &str,
) -> Result<&'a FrozenCredentialRequirement, Oid4vpContractError> {
    requirements
        .iter()
        .find(|requirement| requirement.id == id)
        .ok_or(Oid4vpContractError::InvalidQueryDocument)
}

fn string_array(value: &Value, field: &'static str) -> Result<Vec<String>, Oid4vpContractError> {
    let values = value
        .as_array()
        .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
    if values.is_empty() || values.len() > MAX_EVIDENCE_LIST_ITEMS {
        return Err(Oid4vpContractError::InvalidQueryDocument);
    }
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or(Oid4vpContractError::InvalidQueryDocument)?;
            require_text(value, field, MAX_IDENTIFIER_BYTES)?;
            Ok(value.to_owned())
        })
        .collect()
}

fn canonical_claim_id(value: &str) -> String {
    format!(
        "claim_{}",
        value
            .chars()
            .map(|character| match character {
                '-' | '.' => '_',
                other => other,
            })
            .collect::<String>()
    )
}

fn pe_descriptor_selector(
    descriptor: &PresentationDescriptor,
    requirement: &FrozenCredentialRequirement,
) -> Result<String, Oid4vpContractError> {
    match &descriptor.path_nested {
        None => {
            if requirement
                .accepted_formats
                .binary_search(&descriptor.format)
                .is_err()
                || !matches!(descriptor.path.as_str(), "$" | "$[0]")
            {
                return Err(Oid4vpContractError::PresentationDefinitionMismatch);
            }
            Ok(descriptor.path.clone())
        }
        Some(nested) => {
            if !matches!(descriptor.format.as_str(), "jwt_vp" | "ldp_vp")
                || descriptor.path != "$"
                || nested.path_nested.is_some()
                || requirement
                    .accepted_formats
                    .binary_search(&nested.format)
                    .is_err()
                || !is_supported_nested_credential_path(&nested.path)
            {
                return Err(Oid4vpContractError::PresentationDefinitionMismatch);
            }
            Ok(format!("{}|{}", descriptor.path, nested.path))
        }
    }
}

fn is_supported_nested_credential_path(path: &str) -> bool {
    ["$[", "$.verifiableCredential["].iter().any(|prefix| {
        path.strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(']'))
            .is_some_and(|index| {
                !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
            })
    })
}

fn validate_descriptor(
    descriptor: &PresentationDescriptor,
    depth: usize,
) -> Result<(), Oid4vpContractError> {
    if depth > MAX_DESCRIPTOR_DEPTH {
        return Err(Oid4vpContractError::InvalidField(
            "presentation_submission.descriptor_depth",
        ));
    }
    require_identifier(&descriptor.id, "presentation_submission.descriptor.id")?;
    require_identifier(
        &descriptor.format,
        "presentation_submission.descriptor.format",
    )?;
    require_text(
        &descriptor.path,
        "presentation_submission.descriptor.path",
        MAX_IDENTIFIER_BYTES,
    )?;
    if let Some(nested) = &descriptor.path_nested {
        validate_descriptor(nested, depth + 1)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FactKind {
    PresentationStructure,
    PresentationProof,
    CredentialProof,
}

fn validate_fact(
    fact: &EvidenceFact,
    kind: FactKind,
    request: &FrozenOid4vpRequestV1,
    now: i64,
) -> Result<(), Oid4vpContractError> {
    if fact.code != expected_fact_code(kind, fact.outcome) {
        return Err(Oid4vpContractError::CheckEvidenceMismatch);
    }
    validate_digest(&fact.evidence_digest, "evidence_fact.evidence_digest")?;
    validate_checked_at(fact.checked_at_epoch_seconds, request, now)
}

fn expected_fact_code(kind: FactKind, outcome: EvidenceCheckOutcome) -> &'static str {
    match (kind, outcome) {
        (FactKind::PresentationStructure, EvidenceCheckOutcome::Passed) => {
            "OID4VP_PRESENTATION_PARSED"
        }
        (FactKind::PresentationStructure, EvidenceCheckOutcome::Failed) => {
            "OID4VP_PRESENTATION_MALFORMED"
        }
        (FactKind::PresentationStructure, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_PRESENTATION_STRUCTURE_UNAVAILABLE"
        }
        (FactKind::PresentationProof, EvidenceCheckOutcome::Passed) => {
            "OID4VP_PRESENTATION_SIGNATURE_VERIFIED"
        }
        (FactKind::PresentationProof, EvidenceCheckOutcome::Failed) => {
            "OID4VP_PRESENTATION_SIGNATURE_INVALID"
        }
        (FactKind::PresentationProof, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_PRESENTATION_SIGNATURE_UNAVAILABLE"
        }
        (FactKind::CredentialProof, EvidenceCheckOutcome::Passed) => {
            "OID4VP_CREDENTIAL_SIGNATURE_VERIFIED"
        }
        (FactKind::CredentialProof, EvidenceCheckOutcome::Failed) => {
            "OID4VP_CREDENTIAL_SIGNATURE_INVALID"
        }
        (FactKind::CredentialProof, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_CREDENTIAL_SIGNATURE_UNAVAILABLE"
        }
    }
}

fn validate_checked_at(
    checked_at: i64,
    request: &FrozenOid4vpRequestV1,
    now: i64,
) -> Result<(), Oid4vpContractError> {
    if checked_at < request.issued_at_epoch_seconds || checked_at > now {
        return Err(Oid4vpContractError::InvalidLifetime);
    }
    Ok(())
}

fn validate_trust(
    credential: &crate::AuthenticatedCredentialEvidence,
    request: &FrozenOid4vpRequestV1,
    now: i64,
) -> Result<(), Oid4vpContractError> {
    validate_profile(&credential.trust.profile)?;
    if credential.trust.profile != request.policy.trust_profile {
        return Err(Oid4vpContractError::TrustEvidenceMismatch);
    }
    validate_string_list(
        &credential.trust.trust_levels,
        "credentials.trust.trust_levels",
        credential.trust.outcome != EvidenceCheckOutcome::Passed,
    )?;
    validate_string_list(
        &credential.trust.compliance_statuses,
        "credentials.trust.compliance_statuses",
        true,
    )?;
    validate_string_list(
        &credential.trust.accreditations,
        "credentials.trust.accreditations",
        true,
    )?;
    validate_digest(
        &credential.trust.evidence_digest,
        "credentials.trust.evidence_digest",
    )?;
    validate_checked_at(credential.trust.checked_at_epoch_seconds, request, now)?;
    if now - credential.trust.checked_at_epoch_seconds
        > i64::from(request.policy.max_trust_age_seconds)
    {
        return Err(Oid4vpContractError::TrustEvidenceMismatch);
    }
    Ok(())
}

fn validate_status(
    credential: &crate::AuthenticatedCredentialEvidence,
    requirement: &FrozenCredentialRequirement,
    request: &FrozenOid4vpRequestV1,
    now: i64,
) -> Result<(), Oid4vpContractError> {
    let status = &credential.status;
    let valid = match status.state {
        CredentialStatusState::NotPresent => {
            credential.status_ids.is_empty()
                && requirement.status.mode == CredentialStatusMode::AllowAbsent
                && status.outcome == EvidenceCheckOutcome::Passed
                && status.checked_at_epoch_seconds.is_none()
                && status.valid_until_epoch_seconds.is_none()
                && status.evidence_digest.is_none()
        }
        CredentialStatusState::Active => {
            !credential.status_ids.is_empty()
                && status.outcome == EvidenceCheckOutcome::Passed
                && status
                    .valid_until_epoch_seconds
                    .is_some_and(|value| value >= now)
                && status.checked_at_epoch_seconds.is_some()
                && status.evidence_digest.is_some()
        }
        CredentialStatusState::Revoked => {
            !credential.status_ids.is_empty()
                && status.outcome == EvidenceCheckOutcome::Failed
                && status.checked_at_epoch_seconds.is_some()
                && status.evidence_digest.is_some()
        }
        CredentialStatusState::Unknown => {
            !credential.status_ids.is_empty()
                && status.outcome == EvidenceCheckOutcome::Indeterminate
                && status.valid_until_epoch_seconds.is_none()
        }
        CredentialStatusState::Stale => {
            !credential.status_ids.is_empty()
                && status.outcome == EvidenceCheckOutcome::Failed
                && status
                    .valid_until_epoch_seconds
                    .is_some_and(|value| value < now)
                && status.checked_at_epoch_seconds.is_some()
                && status.evidence_digest.is_some()
        }
    };
    if !valid {
        return Err(Oid4vpContractError::StatusEvidenceMismatch);
    }
    if let Some(checked_at) = status.checked_at_epoch_seconds {
        validate_checked_at(checked_at, request, now)?;
        if now - checked_at > i64::from(requirement.status.max_age_seconds) {
            return Err(Oid4vpContractError::StatusEvidenceMismatch);
        }
    }
    if let (Some(checked_at), Some(valid_until)) = (
        status.checked_at_epoch_seconds,
        status.valid_until_epoch_seconds,
    ) {
        let validity = valid_until
            .checked_sub(checked_at)
            .ok_or(Oid4vpContractError::StatusEvidenceMismatch)?;
        if !(0..=MAX_STATUS_VALIDITY_SECONDS).contains(&validity) {
            return Err(Oid4vpContractError::StatusEvidenceMismatch);
        }
    }
    if let Some(digest) = &status.evidence_digest {
        validate_digest(digest, "credentials.status.evidence_digest")?;
    }
    Ok(())
}

fn validate_credential_token_binding(
    request: &FrozenOid4vpRequestV1,
    submission: &WalletSubmissionV1,
    credentials: &BTreeMap<&str, Vec<&crate::AuthenticatedCredentialEvidence>>,
) -> Result<(), Oid4vpContractError> {
    match (&request.query.kind, &submission.vp_token) {
        (QueryKind::Dcql, VpToken::Single(token)) => {
            let query_id = &request.query.requirements[0].id;
            let expected = digest_response_item(token, query_id, "0")?;
            let actual = credentials
                .values()
                .flatten()
                .map(|credential| credential.response_token_digest.as_str())
                .collect::<Vec<_>>();
            if actual != [expected.as_str()] {
                return Err(Oid4vpContractError::CredentialBindingMismatch);
            }
        }
        (QueryKind::Dcql, VpToken::ByQuery(tokens)) => {
            for (query_id, values) in tokens {
                let mut expected = values
                    .iter()
                    .enumerate()
                    .map(|(index, token)| digest_response_item(token, query_id, &index.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut actual = credentials
                    .get(query_id.as_str())
                    .ok_or(Oid4vpContractError::CredentialBindingMismatch)?
                    .iter()
                    .map(|credential| credential.response_token_digest.clone())
                    .collect::<Vec<_>>();
                expected.sort();
                actual.sort();
                if actual != expected {
                    return Err(Oid4vpContractError::CredentialBindingMismatch);
                }
            }
        }
        (QueryKind::PresentationExchange, VpToken::Single(token)) => {
            let presentation = submission
                .presentation_submission
                .as_ref()
                .ok_or(Oid4vpContractError::CredentialBindingMismatch)?;
            for descriptor in &presentation.descriptor_map {
                let requirement = requirement_by_id(&request.query.requirements, &descriptor.id)?;
                let selector = pe_descriptor_selector(descriptor, requirement)?;
                let expected = digest_response_item(token, &descriptor.id, &selector)?;
                let query_credentials = credentials
                    .get(descriptor.id.as_str())
                    .ok_or(Oid4vpContractError::CredentialBindingMismatch)?;
                if query_credentials.len() != 1
                    || query_credentials[0].response_token_digest != expected
                {
                    return Err(Oid4vpContractError::CredentialBindingMismatch);
                }
            }
        }
        (QueryKind::PresentationExchange, VpToken::ByQuery(_)) => {
            return Err(Oid4vpContractError::CredentialBindingMismatch);
        }
    }
    Ok(())
}

fn credential_matches_requirement(
    credential: &crate::AuthenticatedCredentialEvidence,
    requirement: &FrozenCredentialRequirement,
) -> bool {
    requirement
        .accepted_formats
        .binary_search(&credential.format)
        .is_ok()
        && requirement
            .accepted_type_sets
            .binary_search(&credential.authenticated_type_or_vct)
            .is_ok()
        && requirement
            .accepted_algorithms
            .get(&credential.format)
            .is_some_and(|algorithms| {
                !credential.proof_algorithm.eq_ignore_ascii_case("none")
                    && algorithms
                        .binary_search(&credential.proof_algorithm)
                        .is_ok()
            })
        && requirement
            .required_claims
            .iter()
            .all(|claim| credential.claims.contains_key(claim))
        && credential
            .claims
            .keys()
            .all(|claim| requirement.allowed_claims.binary_search(claim).is_ok())
}

#[derive(Clone, Copy)]
enum DigestBindingKind {
    Challenge,
    Audience,
}

fn validate_digest_binding(
    binding: &crate::DigestBindingEvidence,
    authoritative_expected: &str,
    kind: DigestBindingKind,
    field: &'static str,
) -> Result<(), Oid4vpContractError> {
    validate_digest(binding.expected_digest.as_str(), field)?;
    if let Some(observed) = &binding.observed_digest {
        validate_digest(observed, field)?;
    }
    if binding.code != expected_digest_binding_code(kind, binding.outcome) {
        return Err(Oid4vpContractError::BindingMismatch);
    }
    let outcome_matches = match binding.outcome {
        EvidenceCheckOutcome::Passed => {
            binding.observed_digest.as_deref() == Some(binding.expected_digest.as_str())
        }
        EvidenceCheckOutcome::Failed => binding
            .observed_digest
            .as_ref()
            .is_some_and(|observed| observed != &binding.expected_digest),
        EvidenceCheckOutcome::Indeterminate => binding.observed_digest.is_none(),
    };
    if binding.expected_digest != authoritative_expected || !outcome_matches {
        return Err(Oid4vpContractError::BindingMismatch);
    }
    Ok(())
}

fn expected_digest_binding_code(
    kind: DigestBindingKind,
    outcome: EvidenceCheckOutcome,
) -> &'static str {
    match (kind, outcome) {
        (DigestBindingKind::Challenge, EvidenceCheckOutcome::Passed) => "OID4VP_NONCE_MATCHED",
        (DigestBindingKind::Challenge, EvidenceCheckOutcome::Failed) => "OID4VP_NONCE_MISMATCH",
        (DigestBindingKind::Challenge, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_NONCE_UNAVAILABLE"
        }
        (DigestBindingKind::Audience, EvidenceCheckOutcome::Passed) => "OID4VP_AUDIENCE_MATCHED",
        (DigestBindingKind::Audience, EvidenceCheckOutcome::Failed) => "OID4VP_AUDIENCE_MISMATCH",
        (DigestBindingKind::Audience, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_AUDIENCE_UNAVAILABLE"
        }
    }
}

fn expected_holder_code(outcome: EvidenceCheckOutcome) -> &'static str {
    match outcome {
        EvidenceCheckOutcome::Passed => "OID4VP_HOLDER_KEY_BOUND",
        EvidenceCheckOutcome::Failed => "OID4VP_HOLDER_BINDING_FAILED",
        EvidenceCheckOutcome::Indeterminate => "OID4VP_HOLDER_BINDING_UNAVAILABLE",
    }
}

fn expected_replay_code(outcome: EvidenceCheckOutcome) -> &'static str {
    match outcome {
        EvidenceCheckOutcome::Passed => "OID4VP_REPLAY_CAS_CONSUMED",
        EvidenceCheckOutcome::Failed => "OID4VP_REPLAY_DETECTED",
        EvidenceCheckOutcome::Indeterminate => "OID4VP_REPLAY_UNAVAILABLE",
    }
}

fn merged_verified_claims(
    credentials: &[crate::AuthenticatedCredentialEvidence],
) -> Result<BTreeMap<String, Value>, Oid4vpContractError> {
    let mut merged = BTreeMap::new();
    for credential in credentials {
        for (name, value) in &credential.claims {
            if merged
                .insert(name.clone(), value.clone())
                .is_some_and(|previous| previous != *value)
            {
                return Err(Oid4vpContractError::DecisionMismatch);
            }
        }
    }
    Ok(merged)
}

fn expected_check_code(check: Oid4vpCheckId, outcome: EvidenceCheckOutcome) -> &'static str {
    match (check, outcome) {
        (Oid4vpCheckId::PresentationStructure, EvidenceCheckOutcome::Passed) => {
            "OID4VP_PRESENTATION_STRUCTURE_PASSED"
        }
        (Oid4vpCheckId::PresentationStructure, EvidenceCheckOutcome::Failed) => {
            "OID4VP_PRESENTATION_STRUCTURE_FAILED"
        }
        (Oid4vpCheckId::PresentationStructure, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_PRESENTATION_STRUCTURE_INDETERMINATE"
        }
        (Oid4vpCheckId::PresentationProof, EvidenceCheckOutcome::Passed) => {
            "OID4VP_PRESENTATION_PROOF_PASSED"
        }
        (Oid4vpCheckId::PresentationProof, EvidenceCheckOutcome::Failed) => {
            "OID4VP_PRESENTATION_PROOF_FAILED"
        }
        (Oid4vpCheckId::PresentationProof, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_PRESENTATION_PROOF_INDETERMINATE"
        }
        (Oid4vpCheckId::CredentialProof, EvidenceCheckOutcome::Passed) => {
            "OID4VP_CREDENTIAL_PROOF_PASSED"
        }
        (Oid4vpCheckId::CredentialProof, EvidenceCheckOutcome::Failed) => {
            "OID4VP_CREDENTIAL_PROOF_FAILED"
        }
        (Oid4vpCheckId::CredentialProof, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_CREDENTIAL_PROOF_INDETERMINATE"
        }
        (Oid4vpCheckId::IssuerTrust, EvidenceCheckOutcome::Passed) => "OID4VP_ISSUER_TRUST_PASSED",
        (Oid4vpCheckId::IssuerTrust, EvidenceCheckOutcome::Failed) => "OID4VP_ISSUER_TRUST_FAILED",
        (Oid4vpCheckId::IssuerTrust, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_ISSUER_TRUST_INDETERMINATE"
        }
        (Oid4vpCheckId::CredentialStatus, EvidenceCheckOutcome::Passed) => {
            "OID4VP_CREDENTIAL_STATUS_PASSED"
        }
        (Oid4vpCheckId::CredentialStatus, EvidenceCheckOutcome::Failed) => {
            "OID4VP_CREDENTIAL_STATUS_FAILED"
        }
        (Oid4vpCheckId::CredentialStatus, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_CREDENTIAL_STATUS_INDETERMINATE"
        }
        (Oid4vpCheckId::HolderBinding, EvidenceCheckOutcome::Passed) => {
            "OID4VP_HOLDER_BINDING_PASSED"
        }
        (Oid4vpCheckId::HolderBinding, EvidenceCheckOutcome::Failed) => {
            "OID4VP_HOLDER_BINDING_FAILED"
        }
        (Oid4vpCheckId::HolderBinding, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_HOLDER_BINDING_INDETERMINATE"
        }
        (Oid4vpCheckId::TransactionBinding, EvidenceCheckOutcome::Passed) => {
            "OID4VP_TRANSACTION_BINDING_PASSED"
        }
        (Oid4vpCheckId::TransactionBinding, EvidenceCheckOutcome::Failed) => {
            "OID4VP_TRANSACTION_BINDING_FAILED"
        }
        (Oid4vpCheckId::TransactionBinding, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_TRANSACTION_BINDING_INDETERMINATE"
        }
        (Oid4vpCheckId::ClaimConstraints, EvidenceCheckOutcome::Passed) => {
            "OID4VP_CLAIM_CONSTRAINTS_PASSED"
        }
        (Oid4vpCheckId::ClaimConstraints, EvidenceCheckOutcome::Failed) => {
            "OID4VP_CLAIM_CONSTRAINTS_FAILED"
        }
        (Oid4vpCheckId::ClaimConstraints, EvidenceCheckOutcome::Indeterminate) => {
            "OID4VP_CLAIM_CONSTRAINTS_INDETERMINATE"
        }
    }
}

fn aggregate_outcomes(
    outcomes: impl IntoIterator<Item = EvidenceCheckOutcome>,
) -> EvidenceCheckOutcome {
    let mut any = false;
    let mut indeterminate = false;
    for outcome in outcomes {
        any = true;
        match outcome {
            EvidenceCheckOutcome::Failed => return EvidenceCheckOutcome::Failed,
            EvidenceCheckOutcome::Indeterminate => indeterminate = true,
            EvidenceCheckOutcome::Passed => {}
        }
    }
    if !any || indeterminate {
        EvidenceCheckOutcome::Indeterminate
    } else {
        EvidenceCheckOutcome::Passed
    }
}

fn validate_bounded_value(
    value: &Value,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), Oid4vpContractError> {
    if serde_json::to_vec(value)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        > max_bytes
        || json_depth(value, 1) > MAX_JSON_DEPTH
    {
        return Err(Oid4vpContractError::InvalidField(field));
    }
    Ok(())
}

fn json_depth(value: &Value, depth: usize) -> usize {
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| json_depth(value, depth + 1))
            .max()
            .unwrap_or(depth),
        Value::Object(values) => values
            .values()
            .map(|value| json_depth(value, depth + 1))
            .max()
            .unwrap_or(depth),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => depth,
    }
}

fn sensitive_token_patterns(raw_tokens: &[&str]) -> Vec<String> {
    let mut patterns = raw_tokens
        .iter()
        .map(|token| (*token).to_owned())
        .filter(|pattern| pattern.len() <= MAX_CLAIM_VALUE_BYTES)
        .collect::<BTreeSet<_>>();
    let mut frontier = patterns.clone();
    // Freeze the accepted normalization budget plus one fail-closed sentinel
    // layer. The decoder below also rejects exact values that remain decodable.
    for _ in 0..=MAX_PRIVACY_BASE64_DECODE_LAYERS {
        let next = frontier
            .iter()
            .flat_map(|value| encode_base64_variants(value.as_bytes()))
            .filter(|pattern| pattern.len() <= MAX_CLAIM_VALUE_BYTES)
            .collect::<BTreeSet<_>>();
        patterns.extend(next.iter().cloned());
        frontier = next;
    }
    patterns.into_iter().collect()
}

fn encode_base64_variants(value: &[u8]) -> [String; 4] {
    [
        general_purpose::STANDARD.encode(value),
        general_purpose::STANDARD_NO_PAD.encode(value),
        general_purpose::URL_SAFE.encode(value),
        general_purpose::URL_SAFE_NO_PAD.encode(value),
    ]
}

fn contains_sensitive_string(value: &Value, sensitive_patterns: &[String]) -> bool {
    match value {
        Value::String(value) => string_contains_sensitive_pattern(value, sensitive_patterns),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_sensitive_string(value, sensitive_patterns)),
        Value::Object(values) => values.iter().any(|(key, value)| {
            string_contains_sensitive_pattern(key, sensitive_patterns)
                || contains_sensitive_string(value, sensitive_patterns)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn string_contains_sensitive_pattern(value: &str, sensitive_patterns: &[String]) -> bool {
    let contains_pattern = |candidate: &str| {
        sensitive_patterns
            .iter()
            .any(|pattern| candidate.contains(pattern))
    };
    let mut candidates = vec![value.to_owned()];
    for _ in 0..MAX_PRIVACY_PERCENT_DECODE_LAYERS {
        let candidate = candidates.last().expect("candidate is initialized");
        let decoded = percent_decode_str(candidate)
            .decode_utf8_lossy()
            .into_owned();
        if decoded == *candidate {
            break;
        }
        candidates.push(decoded);
    }
    let last = candidates.last().expect("candidate is initialized");
    if percent_decode_str(last).decode_utf8_lossy() != *last {
        return true;
    }
    candidates.into_iter().any(|candidate| {
        contains_pattern(&candidate)
            || base64_normalization_contains_sensitive(&candidate, sensitive_patterns)
    })
}

fn base64_normalization_contains_sensitive(value: &str, sensitive_patterns: &[String]) -> bool {
    if value.len() < MIN_TOKEN_BYTES {
        return false;
    }
    let contains_pattern = |candidate: &str| {
        sensitive_patterns
            .iter()
            .any(|pattern| candidate.contains(pattern))
    };
    let mut frontier = BTreeSet::from([value.to_owned()]);
    for _ in 0..MAX_PRIVACY_BASE64_DECODE_LAYERS {
        let next = frontier
            .iter()
            .flat_map(|candidate| decode_base64_utf8_variants(candidate))
            .collect::<BTreeSet<_>>();
        if next.iter().any(|candidate| contains_pattern(candidate)) {
            return true;
        }
        if next.is_empty() {
            return false;
        }
        frontier = next;
    }
    // A value that remains canonically decodable after the frozen budget is an
    // opaque nested encoding and is rejected instead of partially normalized.
    frontier
        .iter()
        .any(|candidate| !decode_base64_utf8_variants(candidate).is_empty())
}

fn decode_base64_utf8_variants(value: &str) -> Vec<String> {
    if value.len() < MIN_TOKEN_BYTES {
        return Vec::new();
    }
    [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ]
    .into_iter()
    .filter_map(|engine| engine.decode(value).ok())
    .filter_map(|bytes| String::from_utf8(bytes).ok())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

fn contains_forbidden_key(value: &Value) -> bool {
    const FORBIDDEN_KEYS: [&str; 4] = [
        "presentationsubmission",
        "rawcredential",
        "rawtoken",
        "vptoken",
    ];
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            let normalized_key = key
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect::<String>();
            FORBIDDEN_KEYS
                .iter()
                .any(|forbidden| normalized_key.contains(forbidden))
                || contains_forbidden_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_key),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn validate_serialized_size<T: Serialize>(
    value: &T,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), Oid4vpContractError> {
    if serde_json::to_vec(value)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        > max_bytes
    {
        return Err(Oid4vpContractError::SizeLimit(field));
    }
    Ok(())
}

fn validate_string_list(
    values: &[String],
    field: &'static str,
    allow_empty: bool,
) -> Result<(), Oid4vpContractError> {
    if (!allow_empty && values.is_empty())
        || values.len() > MAX_EVIDENCE_LIST_ITEMS
        || values
            .iter()
            .any(|value| require_identifier(value, field).is_err())
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(Oid4vpContractError::InvalidField(field));
    }
    Ok(())
}

fn require_identifier(value: &str, field: &'static str) -> Result<(), Oid4vpContractError> {
    require_text(value, field, MAX_IDENTIFIER_BYTES)
}

fn require_token(value: &str, field: &'static str) -> Result<(), Oid4vpContractError> {
    require_text(value, field, MAX_TOKEN_BYTES)?;
    if value.len() < MIN_TOKEN_BYTES {
        return Err(Oid4vpContractError::InvalidField(field));
    }
    Ok(())
}

fn require_code(value: &str, field: &'static str) -> Result<(), Oid4vpContractError> {
    require_text(value, field, MAX_CODE_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(Oid4vpContractError::InvalidField(field));
    }
    Ok(())
}

fn require_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), Oid4vpContractError> {
    if value.is_empty() || value.trim() != value || value.len() > max_bytes {
        Err(Oid4vpContractError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), Oid4vpContractError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(Oid4vpContractError::InvalidDigest(field));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Oid4vpContractError::InvalidDigest(field));
    }
    Ok(())
}

fn parse_bounded<T: DeserializeOwned>(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<T, Oid4vpContractError> {
    if value.len() > max_bytes {
        return Err(Oid4vpContractError::SizeLimit(field));
    }
    serde_json::from_str(value).map_err(|_| Oid4vpContractError::Deserialization)
}
