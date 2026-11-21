use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const GRANT_PROFILE: &str = "urn:marty:delegation-grant:v1";
/// Largest exactly interoperable JSON integer permitted by the v1 schema.
pub const MAX_GRANT_REVISION: u64 = 9_007_199_254_740_991;
pub const MAX_GRANT_DOCUMENT_BYTES: usize = 65_536;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub id: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalType {
    User,
    Organization,
    ServiceAccount,
    MachineIdentity,
    External,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingMethod {
    Key,
    Session,
}
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
pub enum AuthorityMode {
    Managed,
    External,
}
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
pub enum ConstraintMode {
    ExactOperation,
    ExternalProfile,
}
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
        validate_time(self.valid_from)?;
        validate_time(self.valid_until)?;
        if self.subdelegation_allowed {
            return Err(GrantValidationError::SubdelegationUnsupported);
        }
        if self.valid_until <= self.valid_from {
            return Err(GrantValidationError::InvalidValidity);
        }
        for set in [&self.actions, &self.audiences, &self.resources] {
            if set.is_empty() || set.len() > 64 {
                return Err(GrantValidationError::InvalidScopeSet);
            }
            let mut unique = std::collections::BTreeSet::new();
            if set
                .iter()
                .any(|v| !valid_uri(Some(v)) || v.contains('*') || !unique.insert(v))
            {
                return Err(GrantValidationError::InvalidScopeSet);
            }
        }
        match self.binding.method {
            BindingMethod::Key
                if valid_key_thumbprint(self.binding.key_thumbprint.as_deref())
                    && self.binding.session_ref.is_none()
                    && self.binding.establishment_evidence_ref.is_none() => {}
            BindingMethod::Session
                if self.binding.key_thumbprint.is_none()
                    && valid_uri(self.binding.session_ref.as_deref())
                    && valid_uri(self.binding.establishment_evidence_ref.as_deref()) => {}
            _ => return Err(GrantValidationError::InvalidBinding),
        }
        match self.constraints.mode {
            ConstraintMode::ExactOperation => {
                if !valid_uri(self.constraints.request_profile.as_deref())
                    || !valid_digest(self.constraints.request_digest.as_deref())
                    || self.constraints.profile.is_some()
                    || self.constraints.document_ref.is_some()
                    || self.constraints.document_digest.is_some()
                    || self.constraints.evaluator.is_some()
                {
                    return Err(GrantValidationError::InvalidConstraints);
                }
            }
            ConstraintMode::ExternalProfile => {
                if !valid_uri(self.constraints.profile.as_deref())
                    || !valid_uri(self.constraints.document_ref.as_deref())
                    || !valid_digest(self.constraints.document_digest.as_deref())
                    || self
                        .constraints
                        .evaluator
                        .as_ref()
                        .is_none_or(|p| validate_principal(p).is_err())
                    || self.constraints.request_profile.is_some()
                    || self.constraints.request_digest.is_some()
                {
                    return Err(GrantValidationError::InvalidConstraints);
                }
            }
        }
        Ok(())
    }
}
pub(crate) fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, GrantValidationError> {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut out = Vec::from(b"{".as_slice());
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(
                    serde_json::to_string(key)
                        .map_err(|_| GrantValidationError::TermsSerialization)?
                        .as_bytes(),
                );
                out.push(b':');
                out.extend(canonical_json(&map[*key])?);
            }
            out.push(b'}');
            Ok(out)
        }
        Value::Array(values) => {
            let mut out = Vec::from(b"[".as_slice());
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(canonical_json(item)?);
            }
            out.push(b']');
            Ok(out)
        }
        Value::String(value) => Ok(serde_json::to_string(value)
            .map_err(|_| GrantValidationError::TermsSerialization)?
            .into_bytes()),
        Value::Bool(value) => Ok(if *value {
            b"true".to_vec()
        } else {
            b"false".to_vec()
        }),
        Value::Null => Ok(b"null".to_vec()),
        Value::Number(_) => Err(GrantValidationError::UnsupportedCanonicalNumber),
    }
}
fn validate_principal(p: &Principal) -> Result<(), GrantValidationError> {
    if valid_uri(Some(&p.id)) {
        Ok(())
    } else {
        Err(GrantValidationError::InvalidPrincipal)
    }
}
fn validate_time(time: DateTime<Utc>) -> Result<(), GrantValidationError> {
    // Chrono can represent leap seconds that PostgreSQL normalizes to the next
    // minute. The managed adapter rejects them to preserve exact ordering.
    if !(1..=9999).contains(&time.year()) || time.timestamp_subsec_nanos() >= 1_000_000_000 {
        return Err(GrantValidationError::InvalidTimestamp);
    }
    Ok(())
}
pub(crate) fn valid_uri(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    if value.is_empty() || value.len() > 1024 || !value.is_ascii() {
        return false;
    }
    // Validate the spelling before URL parsing, which otherwise repairs spaces,
    // backslashes and malformed scheme/host input. References are identifiers;
    // this validation never fetches them or grants authority to their origin.
    if value
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && !b"-._~:/?#[]@!$&'()+,;=%".contains(&b))
        || value.bytes().filter(|byte| *byte == b'#').count() > 1
    {
        return false;
    }
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return false;
    }
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return false;
        }
    }
    let authority_parts = rest.strip_prefix("//").map(|hierarchical| {
        let authority_end = hierarchical
            .find(['/', '?', '#'])
            .unwrap_or(hierarchical.len());
        hierarchical.split_at(authority_end)
    });
    if authority_parts
        .is_some_and(|(authority, _)| authority.bytes().filter(|byte| *byte == b'@').count() > 1)
    {
        return false;
    }
    // An HTTP(S) URI must contain a host in its original authority. The URL
    // parser otherwise repairs inputs such as https:///host or https:host.
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        let Some((authority, _)) = authority_parts else {
            return false;
        };
        let host_port = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if host_port.is_empty() || host_port.starts_with(':') {
            return false;
        }
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    // WHATWG URL parsing accepts literal brackets in paths and userinfo, but
    // RFC3986 reserves them for an IP-literal host. Preserve URI semantics
    // instead of accepting the parser's repaired/percent-encoded spelling.
    if value.bytes().any(|byte| matches!(byte, b'[' | b']')) {
        let Some((authority, suffix)) = authority_parts else {
            return false;
        };
        if suffix.bytes().any(|byte| matches!(byte, b'[' | b']')) {
            return false;
        }
        let host_port = if let Some((userinfo, host_port)) = authority.rsplit_once('@') {
            if userinfo
                .bytes()
                .any(|byte| matches!(byte, b'[' | b']' | b'@'))
            {
                return false;
            }
            host_port
        } else {
            authority
        };
        let Some(literal) = host_port.strip_prefix('[') else {
            return false;
        };
        let Some((address, port)) = literal.split_once(']') else {
            return false;
        };
        if address.parse::<std::net::Ipv6Addr>().is_err()
            || !matches!(parsed.host(), Some(url::Host::Ipv6(_)))
            || !(port.is_empty()
                || port
                    .strip_prefix(':')
                    .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit())))
        {
            return false;
        }
    }
    true
}
fn valid_key_thumbprint(value: Option<&str>) -> bool {
    valid_digest(value)
}

pub(crate) fn valid_digest(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        v.len() == 71
            && v.starts_with("sha256:")
            && v[7..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}
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
    pub fn pending(
        organization_id: Uuid,
        authority: Authority,
        terms: GrantTerms,
        now: DateTime<Utc>,
    ) -> Result<Self, GrantValidationError> {
        terms.validate()?;
        if terms.valid_until <= now {
            return Err(GrantValidationError::AlreadyExpired);
        }
        validate_authority(&authority)?;
        if authority.mode == AuthorityMode::External
            && authority
                .source_expires_at
                .is_none_or(|expiry| terms.valid_until > expiry)
        {
            return Err(GrantValidationError::InvalidAuthority);
        }
        let id = Uuid::new_v4();
        let mut grant = Self {
            profile: GRANT_PROFILE.into(),
            id,
            organization_id,
            authority,
            terms,
            terms_digest: String::new(),
            approval: None,
            status: GrantStatus::Pending,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        grant.terms_digest = grant.calculate_terms_digest()?;
        grant.validate()?;
        Ok(grant)
    }
    pub fn validate(&self) -> Result<(), GrantValidationError> {
        if self.profile != GRANT_PROFILE || !(1..=MAX_GRANT_REVISION).contains(&self.revision) {
            return Err(GrantValidationError::InvalidEnvelope);
        }
        self.terms.validate()?;
        validate_time(self.created_at)?;
        validate_time(self.updated_at)?;
        validate_authority(&self.authority)?;
        if self.authority.mode == AuthorityMode::External
            && self
                .authority
                .source_expires_at
                .is_none_or(|expiry| self.terms.valid_until > expiry)
        {
            return Err(GrantValidationError::InvalidAuthority);
        }
        if self.calculate_terms_digest()? != self.terms_digest {
            return Err(GrantValidationError::TermsDigestMismatch);
        }
        if self.created_at > self.updated_at {
            return Err(GrantValidationError::InvalidTemporalOrdering);
        }
        if matches!(self.status, GrantStatus::Active | GrantStatus::Suspended)
            && self.approval.is_none()
        {
            return Err(GrantValidationError::ApprovalRequired);
        }
        if let Some(a) = &self.approval {
            validate_time(a.approved_at)?;
            if a.grant_id != self.id
                || a.terms_digest != self.terms_digest
                || a.approver != self.terms.grantor
                || !valid_uri(Some(&a.profile))
                || !valid_uri(Some(&a.evidence_ref))
                || !valid_uri(Some(&a.authority_evidence_ref))
                || a.approved_at < self.created_at
                || a.approved_at > self.updated_at
                || a.approved_at >= self.terms.valid_until
            {
                return Err(GrantValidationError::InvalidApproval);
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| GrantValidationError::TermsSerialization)?
            .len()
            > MAX_GRANT_DOCUMENT_BYTES
        {
            return Err(GrantValidationError::DocumentTooLarge);
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
        if matches!(
            self.status,
            GrantStatus::Pending | GrantStatus::Active | GrantStatus::Suspended
        ) && (self.terms.valid_until <= now
            || self
                .authority
                .source_expires_at
                .is_some_and(|expiry| expiry <= now))
        {
            GrantStatus::Expired
        } else {
            self.status
        }
    }
}
pub fn validate_transition(
    previous: &DelegationGrant,
    current: &DelegationGrant,
) -> Result<(), GrantValidationError> {
    previous.validate()?;
    current.validate()?;
    if previous.authority.mode != AuthorityMode::Managed {
        return Err(GrantValidationError::ExternalAuthorityReadOnly);
    }
    let immutable_changed = previous.profile != current.profile
        || previous.id != current.id
        || previous.organization_id != current.organization_id
        || previous.authority != current.authority
        || previous.terms != current.terms
        || previous.terms_digest != current.terms_digest
        || previous.created_at != current.created_at
        || previous
            .approval
            .as_ref()
            .is_some_and(|approval| current.approval.as_ref() != Some(approval));
    if immutable_changed {
        return Err(GrantValidationError::ImmutableGrantDataChanged);
    }
    if current.revision
        != previous
            .revision
            .checked_add(1)
            .ok_or(GrantValidationError::RevisionOverflow)?
    {
        return Err(GrantValidationError::InvalidRevision);
    }
    if current.updated_at <= previous.updated_at {
        return Err(GrantValidationError::TransitionTimeDidNotAdvance);
    }
    if current.status == GrantStatus::Active
        && !(current.terms.valid_from <= current.updated_at
            && current.updated_at < current.terms.valid_until)
    {
        return Err(GrantValidationError::InvalidActivationTime);
    }
    if current.status == GrantStatus::Expired && current.updated_at < current.terms.valid_until {
        return Err(GrantValidationError::PrematureExpiration);
    }
    let allowed = match previous.status {
        GrantStatus::Pending => matches!(
            current.status,
            GrantStatus::Active | GrantStatus::Revoked | GrantStatus::Expired
        ),
        GrantStatus::Active => matches!(
            current.status,
            GrantStatus::Suspended | GrantStatus::Revoked | GrantStatus::Expired
        ),
        GrantStatus::Suspended => matches!(
            current.status,
            GrantStatus::Active | GrantStatus::Revoked | GrantStatus::Expired
        ),
        GrantStatus::Revoked | GrantStatus::Expired => false,
    };
    if !allowed {
        return Err(GrantValidationError::InvalidStatusTransition);
    }
    Ok(())
}

pub(crate) fn validate_authority(a: &Authority) -> Result<(), GrantValidationError> {
    validate_principal(&a.issuer)?;
    if let Some(expiry) = a.source_expires_at {
        validate_time(expiry)?;
    }
    if !a.status_ref.starts_with("https://") || !valid_uri(Some(&a.status_ref)) {
        return Err(GrantValidationError::InvalidAuthority);
    }
    match a.mode {
        AuthorityMode::Managed
            if a.source_profile.is_none()
                && a.source_evidence_ref.is_none()
                && a.source_evidence_digest.is_none()
                && a.source_expires_at.is_none() =>
        {
            Ok(())
        }
        AuthorityMode::External
            if valid_uri(a.source_profile.as_deref())
                && valid_uri(a.source_evidence_ref.as_deref())
                && valid_digest(a.source_evidence_digest.as_deref())
                && a.source_expires_at.is_some() =>
        {
            Ok(())
        }
        _ => Err(GrantValidationError::InvalidAuthority),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GrantValidationError {
    #[error("delegation grant envelope is invalid")]
    InvalidEnvelope,
    #[error("principal identifier is invalid")]
    InvalidPrincipal,
    #[error("external authority snapshots cannot be changed by the managed lifecycle")]
    ExternalAuthorityReadOnly,
    #[error("subdelegation is not supported by profile v1")]
    SubdelegationUnsupported,
    #[error("grant validity interval is invalid")]
    InvalidValidity,
    #[error("grant timestamp is outside the supported RFC3339 subset")]
    InvalidTimestamp,
    #[error("delegation grant document exceeds the byte limit")]
    DocumentTooLarge,
    #[error("grant is already expired")]
    AlreadyExpired,
    #[error("scope sets must contain unique, non-wildcard values")]
    InvalidScopeSet,
    #[error("agent binding is invalid")]
    InvalidBinding,
    #[error("constraint profile is invalid or ambiguous")]
    InvalidConstraints,
    #[error("authority source is invalid or expired")]
    InvalidAuthority,
    #[error("terms serialization failed")]
    TermsSerialization,
    #[error("numeric values are not supported in Delegated Authority v1 canonical projections")]
    UnsupportedCanonicalNumber,
    #[error("terms digest does not match immutable terms")]
    TermsDigestMismatch,
    #[error("active or suspended grant requires approval")]
    ApprovalRequired,
    #[error("approval evidence is invalid")]
    InvalidApproval,
    #[error("grant creation/update timestamps are inconsistent")]
    InvalidTemporalOrdering,
    #[error("activation timestamp is outside the grant validity interval")]
    InvalidActivationTime,
    #[error("grant was marked expired before its validity ended")]
    PrematureExpiration,
    #[error("immutable grant identity, authority, terms, or approval changed")]
    ImmutableGrantDataChanged,
    #[error("grant revision did not advance exactly once")]
    InvalidRevision,
    #[error("grant lifecycle transition timestamp did not advance")]
    TransitionTimeDidNotAdvance,
    #[error("grant lifecycle status transition is not permitted")]
    InvalidStatusTransition,
    #[error("grant revision overflow")]
    RevisionOverflow,
}
