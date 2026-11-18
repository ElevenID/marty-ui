use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const GRANT_PROFILE: &str = "urn:marty:delegation-grant:v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub id: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalType { User, Organization, ServiceAccount, MachineIdentity, External }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingMethod { Key, Session }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub method: BindingMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub establishment_evidence_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityMode { Managed, External }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub mode: AuthorityMode,
    pub issuer: Principal,
    pub status_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConstraintMode { ExactOperation, ExternalProfile }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    pub mode: ConstraintMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluator: Option<Principal>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTerms {
    pub grantor: Principal,
    pub subject: Principal,
    pub delegate: Principal,
    pub binding: Binding,
    pub actions: Vec<String>,
    pub audiences: Vec<String>,
    pub resources: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub subdelegation_allowed: bool,
    pub constraints: Constraints,
}
impl GrantTerms {
    pub fn validate(&self) -> Result<(), GrantValidationError> {
        validate_principal(&self.grantor)?;
        validate_principal(&self.subject)?;
        validate_principal(&self.delegate)?;
        if self.grantor.id == self.delegate.id || self.subject.id == self.delegate.id {
            return Err(GrantValidationError::DelegateMustBeDistinct);
        }
        if self.subdelegation_allowed { return Err(GrantValidationError::SubdelegationUnsupported); }
        if self.valid_until <= self.valid_from { return Err(GrantValidationError::InvalidValidity); }
        for set in [&self.actions, &self.audiences, &self.resources] {
            if set.is_empty() || set.len() > 64 { return Err(GrantValidationError::InvalidScopeSet); }
            let mut unique = std::collections::BTreeSet::new();
            if set.iter().any(|v| v.trim().is_empty() || v.contains('*') || !unique.insert(v)) {
                return Err(GrantValidationError::InvalidScopeSet);
            }
        }
        match self.binding.method {
            BindingMethod::Key if valid_digest(self.binding.key_thumbprint.as_deref())
                && self.binding.session_ref.is_none()
                && self.binding.establishment_evidence_ref.is_none() => {}
            BindingMethod::Session if self.binding.key_thumbprint.is_none()
                && valid_uri(self.binding.session_ref.as_deref())
                && valid_uri(self.binding.establishment_evidence_ref.as_deref()) => {}
            _ => return Err(GrantValidationError::InvalidBinding),
        }
        match self.constraints.mode {
            ConstraintMode::ExactOperation => {
                if !valid_uri(self.constraints.request_profile.as_deref())
                    || !valid_digest(self.constraints.request_digest.as_deref())
                    || self.constraints.profile.is_some() || self.constraints.document_ref.is_some()
                    || self.constraints.document_digest.is_some() || self.constraints.evaluator.is_some() {
                    return Err(GrantValidationError::InvalidConstraints);
                }
            }
            ConstraintMode::ExternalProfile => {
                if !valid_uri(self.constraints.profile.as_deref())
                    || !valid_uri(self.constraints.document_ref.as_deref())
                    || !valid_digest(self.constraints.document_digest.as_deref())
                    || self.constraints.evaluator.as_ref().is_none_or(|p| validate_principal(p).is_err())
                    || self.constraints.request_profile.is_some() || self.constraints.request_digest.is_some() {
                    return Err(GrantValidationError::InvalidConstraints);
                }
            }
        }
        Ok(())
    }
}
fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, GrantValidationError> {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut out = Vec::from(b"{".as_slice());
            for (index, key) in keys.iter().enumerate() {
                if index > 0 { out.push(b','); }
                out.extend(serde_json::to_string(key).map_err(|_| GrantValidationError::TermsSerialization)?.as_bytes());
                out.push(b':');
                out.extend(canonical_json(&map[*key])?);
            }
            out.push(b'}');
            Ok(out)
        }
        Value::Array(values) => {
            let mut out = Vec::from(b"[".as_slice());
            for (index, item) in values.iter().enumerate() {
                if index > 0 { out.push(b','); }
                out.extend(canonical_json(item)?);
            }
            out.push(b']');
            Ok(out)
        }
        Value::String(value) => Ok(serde_json::to_string(value)
            .map_err(|_| GrantValidationError::TermsSerialization)?.into_bytes()),
        Value::Bool(value) => Ok(if *value { b"true".to_vec() } else { b"false".to_vec() }),
        Value::Null => Ok(b"null".to_vec()),
        Value::Number(_) => Err(GrantValidationError::UnsupportedCanonicalNumber),
    }
}
fn validate_principal(p: &Principal) -> Result<(), GrantValidationError> {
    if valid_uri(Some(&p.id)) { Ok(()) } else { Err(GrantValidationError::InvalidPrincipal) }
}
fn valid_uri(value: Option<&str>) -> bool {
    value.is_some_and(|v| !v.trim().is_empty() && v.len() <= 1024 && !v.contains('*')
        && v.split_once(':').is_some_and(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty()
            && !scheme.chars().any(char::is_whitespace)))
}
fn valid_digest(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.len() == 71 && v.starts_with("sha256:")
        && v[7..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantStatus { Pending, Active, Suspended, Revoked, Expired }
impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Active => "ACTIVE",
            Self::Suspended => "SUSPENDED",
            Self::Revoked => "REVOKED",
            Self::Expired => "EXPIRED",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantApproval {
    pub profile: String,
    pub grant_id: Uuid,
    pub approver: Principal,
    pub evidence_ref: String,
    pub authority_evidence_ref: String,
    pub terms_digest: String,
    pub approved_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationGrant {
    pub profile: String,
    pub id: Uuid,
    pub organization_id: Uuid,
    pub authority: Authority,
    pub terms: GrantTerms,
    pub terms_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<GrantApproval>,
    pub status: GrantStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl DelegationGrant {
    pub fn pending(organization_id: Uuid, authority: Authority, terms: GrantTerms, now: DateTime<Utc>)
        -> Result<Self, GrantValidationError> {
        terms.validate()?;
        if terms.valid_until <= now { return Err(GrantValidationError::AlreadyExpired); }
        validate_authority(&authority)?;
        if authority.mode == AuthorityMode::External
            && authority.source_expires_at.is_none_or(|expiry| terms.valid_until > expiry) {
            return Err(GrantValidationError::InvalidAuthority);
        }
        let id = Uuid::new_v4();
        let mut grant = Self { profile: GRANT_PROFILE.into(), id, organization_id,
            authority, terms, terms_digest: String::new(), approval: None,
            status: GrantStatus::Pending, revision: 1, created_at: now, updated_at: now };
        grant.terms_digest = grant.calculate_terms_digest()?;
        Ok(grant)
    }
    pub fn validate(&self) -> Result<(), GrantValidationError> {
        if self.profile != GRANT_PROFILE || self.revision == 0 {
            return Err(GrantValidationError::InvalidEnvelope);
        }
        self.terms.validate()?;
        validate_authority(&self.authority)?;
        if self.authority.mode == AuthorityMode::External
            && self.authority.source_expires_at.is_none_or(|expiry| self.terms.valid_until > expiry) {
            return Err(GrantValidationError::InvalidAuthority);
        }
        if self.calculate_terms_digest()? != self.terms_digest { return Err(GrantValidationError::TermsDigestMismatch); }
        if self.created_at > self.updated_at { return Err(GrantValidationError::InvalidTemporalOrdering); }
        if matches!(self.status, GrantStatus::Active | GrantStatus::Suspended) && self.approval.is_none() {
            return Err(GrantValidationError::ApprovalRequired);
        }
        if let Some(a) = &self.approval {
            if a.grant_id != self.id || a.terms_digest != self.terms_digest
                || a.approver != self.terms.grantor
                || !valid_uri(Some(&a.profile))
                || !valid_uri(Some(&a.evidence_ref)) || !valid_uri(Some(&a.authority_evidence_ref))
                || a.approved_at < self.created_at || a.approved_at > self.updated_at
                || a.approved_at >= self.terms.valid_until {
                return Err(GrantValidationError::InvalidApproval);
            }
        }
        if self.status == GrantStatus::Active
            && !(self.terms.valid_from <= self.updated_at && self.updated_at < self.terms.valid_until) {
            return Err(GrantValidationError::InvalidActivationTime);
        }
        if self.status == GrantStatus::Expired && self.updated_at < self.terms.valid_until {
            return Err(GrantValidationError::PrematureExpiration);
        }
        Ok(())
    }
    pub fn calculate_terms_digest(&self) -> Result<String, GrantValidationError> {
        let projection = serde_json::json!({
            "profile": self.profile,
            "id": self.id,
            "organization_id": self.organization_id,
            "authority": self.authority,
            "terms": self.terms
        });
        let canonical = canonical_json(&projection)?;
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }
    pub fn current_status(&self, now: DateTime<Utc>) -> GrantStatus {
        if matches!(self.status, GrantStatus::Pending | GrantStatus::Active | GrantStatus::Suspended)
            && (self.terms.valid_until <= now || self.authority.source_expires_at.is_some_and(|expiry| expiry <= now)) { GrantStatus::Expired } else { self.status }
    }
}
fn validate_authority(a: &Authority) -> Result<(), GrantValidationError> {
    validate_principal(&a.issuer)?;
    if !a.status_ref.starts_with("https://") || !valid_uri(Some(&a.status_ref)) {
        return Err(GrantValidationError::InvalidAuthority);
    }
    match a.mode {
        AuthorityMode::Managed if a.source_profile.is_none() && a.source_evidence_ref.is_none()
            && a.source_evidence_digest.is_none() && a.source_expires_at.is_none() => Ok(()),
        AuthorityMode::External if valid_uri(a.source_profile.as_deref())
            && valid_uri(a.source_evidence_ref.as_deref())
            && valid_digest(a.source_evidence_digest.as_deref())
            && a.source_expires_at.is_some() => Ok(()),
        _ => Err(GrantValidationError::InvalidAuthority),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GrantValidationError {
    #[error("delegation grant envelope is invalid")] InvalidEnvelope,
    #[error("principal identifier is invalid")] InvalidPrincipal,
    #[error("delegate must be distinct from grantor and subject")] DelegateMustBeDistinct,
    #[error("subdelegation is not supported by profile v1")] SubdelegationUnsupported,
    #[error("grant validity interval is invalid")] InvalidValidity,
    #[error("grant is already expired")] AlreadyExpired,
    #[error("scope sets must contain unique, non-wildcard values")] InvalidScopeSet,
    #[error("agent binding is invalid")] InvalidBinding,
    #[error("constraint profile is invalid or ambiguous")] InvalidConstraints,
    #[error("authority source is invalid or expired")] InvalidAuthority,
    #[error("terms serialization failed")] TermsSerialization,
    #[error("numeric values are not supported in Delegated Authority v1 canonical projections")] UnsupportedCanonicalNumber,
    #[error("terms digest does not match immutable terms")] TermsDigestMismatch,
    #[error("active or suspended grant requires approval")] ApprovalRequired,
    #[error("approval evidence is invalid")] InvalidApproval,
    #[error("grant creation/update timestamps are inconsistent")] InvalidTemporalOrdering,
    #[error("activation timestamp is outside the grant validity interval")] InvalidActivationTime,
    #[error("grant was marked expired before its validity ended")] PrematureExpiration,
}
