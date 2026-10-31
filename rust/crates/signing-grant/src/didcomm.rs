//! Exact request binding for the existing Issuance credential authority.
//! Sender private-key operations remain owned by the registered KMS extension.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{bounded, GrantBinding, GrantError, SigningOrigin};

pub const RESOLVE_ROUTE: &str = "/internal/compat/issuer-dids/didcomm/resolve";
pub const PACK_ROUTE: &str = "/internal/compat/issuer-dids/didcomm/pack";
pub const KEY_PURPOSE: &str = "didcomm_authcrypt";
pub const ALGORITHM: &str = "ECDH-1PU+A256KW";
pub const MAX_JWE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidcommKeyReference {
    tenant: String,
    name: String,
    version: String,
}

impl DidcommKeyReference {
    pub fn parse(value: &str) -> Result<Self, GrantError> {
        let parts: Vec<_> = value.split('/').collect();
        if parts.len() != 6 || parts[0] != "didcomm" || parts[1] != "keys" || parts[4] != "versions"
        {
            return Err(GrantError::Malformed);
        }
        let (tenant, name, version) = (parts[2], parts[3], parts[5]);
        let name_is_valid = |value: &str| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        };
        if !name_is_valid(tenant) || !name_is_valid(name) || !lower_hex(version, 32) {
            return Err(GrantError::Malformed);
        }
        Ok(Self {
            tenant: tenant.into(),
            name: name.into(),
            version: version.into(),
        })
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn public_path(&self) -> String {
        format!(
            "v1/didcomm/keys/{}/{}/versions/{}",
            self.tenant, self.name, self.version
        )
    }

    pub fn pack_path(&self) -> String {
        format!(
            "v1/didcomm/pack/{}/{}/{}",
            self.tenant, self.name, self.version
        )
    }
}

impl std::fmt::Display for DidcommKeyReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "didcomm/keys/{}/{}/versions/{}",
            self.tenant, self.name, self.version
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DidcommOperationBinding {
    pub service_id: String,
    pub service_config_sha256: String,
    pub key_reference: String,
    pub sender_key_id: String,
    pub public_key: String,
}

impl DidcommOperationBinding {
    pub fn validate(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<DidcommKeyReference, GrantError> {
        let reference = DidcommKeyReference::parse(&self.key_reference)?;
        if reference.tenant() != organization_id
            || !bounded(&self.service_id, 128)
            || !lower_hex(&self.service_config_sha256, 64)
            || !bounded(issuer_did, 512)
            || !issuer_did.starts_with("did:")
            || !self.sender_key_id.starts_with(&format!("{issuer_did}#"))
            || !bounded(&self.sender_key_id, 1024)
        {
            return Err(GrantError::BindingMismatch);
        }
        public_key_bytes(&self.public_key)?;
        Ok(reference)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteRecipientPublic {
    pub kid: String,
    pub public_key: String,
}

impl RemoteRecipientPublic {
    pub fn new(kid: String, public_key: &[u8; 32]) -> Self {
        Self {
            kid,
            public_key: URL_SAFE_NO_PAD.encode(public_key),
        }
    }
}

pub fn public_key_bytes(value: &str) -> Result<[u8; 32], GrantError> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| GrantError::Malformed)?
        .try_into()
        .map_err(|_| GrantError::Malformed)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(GrantError::Malformed);
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DidcommResolveRequest {
    pub organization_id: String,
    pub issuer_did: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DidcommPackPhase {
    Preflight,
    Delivery,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DidcommPackRequest {
    pub organization_id: String,
    pub issuer_did: String,
    pub operation_id: String,
    pub phase: DidcommPackPhase,
    pub binding: DidcommOperationBinding,
    pub recipient_did: String,
    pub recipients: Vec<RemoteRecipientPublic>,
    pub plaintext: String,
}

impl DidcommPackRequest {
    /// Serialize the complete typed request, including phase, both DID identities,
    /// the selected custody binding, every recipient key and exact plaintext.
    pub fn bound_payload(&self) -> Result<Vec<u8>, GrantError> {
        self.binding
            .validate(&self.organization_id, &self.issuer_did)?;
        if !bounded(&self.organization_id, 128)
            || !bounded(&self.operation_id, 128)
            || !bounded(&self.recipient_did, 512)
            || !self.recipient_did.starts_with("did:")
            || self.recipients.is_empty()
            || self.recipients.len() > 32
            || self.plaintext.is_empty()
            || self.plaintext.len() > 1 << 20
        {
            return Err(GrantError::Malformed);
        }
        let mut kids = std::collections::BTreeSet::new();
        for recipient in &self.recipients {
            if !bounded(&recipient.kid, 1024)
                || !recipient
                    .kid
                    .starts_with(&format!("{}#", self.recipient_did))
                || !kids.insert(&recipient.kid)
            {
                return Err(GrantError::Malformed);
            }
            public_key_bytes(&recipient.public_key)?;
        }
        serde_json::to_vec(self).map_err(|_| GrantError::Malformed)
    }

    pub fn grant_binding<'a>(&'a self, payload: &'a [u8]) -> GrantBinding<'a> {
        GrantBinding {
            origin: SigningOrigin::IssuanceCredential,
            operation_id: &self.operation_id,
            organization_id: &self.organization_id,
            route: PACK_ROUTE,
            service_id: Some(&self.binding.service_id),
            issuer_did: Some(&self.issuer_did),
            key_reference: Some(&self.binding.key_reference),
            key_purpose: KEY_PURPOSE,
            algorithm: ALGORITHM,
            payload,
        }
    }
}

pub(crate) fn authorizes_route_shape(claims: &crate::GrantClaims) -> bool {
    claims.route == PACK_ROUTE
        && claims.key_purpose == KEY_PURPOSE
        && claims.algorithm == ALGORITHM
        && claims
            .service_id
            .as_deref()
            .is_some_and(|id| bounded(id, 128))
        && claims
            .issuer_did
            .as_deref()
            .is_some_and(|did| did.starts_with("did:"))
        && claims
            .key_reference
            .as_deref()
            .and_then(|reference| DidcommKeyReference::parse(reference).ok())
            .is_some_and(|reference| reference.tenant() == claims.organization_id)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bound_input, payload_digest, GrantClaims};

    fn request() -> DidcommPackRequest {
        DidcommPackRequest {
            organization_id: "org-a".into(),
            issuer_did: "did:example:issuer".into(),
            operation_id: "transaction-1".into(),
            phase: DidcommPackPhase::Preflight,
            binding: DidcommOperationBinding {
                service_id: "service-a".into(),
                service_config_sha256: "a".repeat(64),
                key_reference: format!("didcomm/keys/org-a/sender/versions/{}", "b".repeat(32)),
                sender_key_id: "did:example:issuer#sender".into(),
                public_key: URL_SAFE_NO_PAD.encode([1; 32]),
            },
            recipient_did: "did:example:holder".into(),
            recipients: vec![RemoteRecipientPublic::new(
                "did:example:holder#key".into(),
                &[2; 32],
            )],
            plaintext: "credential plaintext".into(),
        }
    }

    #[test]
    fn authcrypt_grant_binds_phase_plaintext_recipients_and_immutable_provider() {
        let request = request();
        let payload = request.bound_payload().unwrap();
        let binding = request.grant_binding(&payload);
        let claims = GrantClaims {
            version: 1,
            origin: binding.origin,
            operation_id: binding.operation_id.into(),
            organization_id: binding.organization_id.into(),
            route: binding.route.into(),
            service_id: binding.service_id.map(Into::into),
            issuer_did: binding.issuer_did.map(Into::into),
            key_reference: binding.key_reference.map(Into::into),
            key_purpose: binding.key_purpose.into(),
            algorithm: binding.algorithm.into(),
            payload_sha256_b64: payload_digest(&payload),
            issued_at: 100,
            expires_at: 130,
            nonce: "a".repeat(32),
        };
        assert!(bound_input(&claims, &binding, 101).is_ok());
        for mutate in [
            |r: &mut DidcommPackRequest| r.phase = DidcommPackPhase::Delivery,
            |r: &mut DidcommPackRequest| r.plaintext.push('!'),
            |r: &mut DidcommPackRequest| r.binding.service_id.push('x'),
            |r: &mut DidcommPackRequest| {
                r.binding.key_reference = r.binding.key_reference.replace('b', "c")
            },
            |r: &mut DidcommPackRequest| {
                r.recipients[0].public_key = URL_SAFE_NO_PAD.encode([3; 32])
            },
            |r: &mut DidcommPackRequest| r.recipients[0].kid.push('x'),
            |r: &mut DidcommPackRequest| r.operation_id.push('x'),
            |r: &mut DidcommPackRequest| r.binding.service_config_sha256 = "d".repeat(64),
        ] {
            let mut changed = request.clone();
            mutate(&mut changed);
            let bytes = changed.bound_payload().unwrap();
            assert_eq!(
                bound_input(&claims, &changed.grant_binding(&bytes), 101),
                Err(GrantError::BindingMismatch)
            );
        }
        let mut foreign = claims.clone();
        foreign.origin = SigningOrigin::IssuanceCanvas;
        assert_eq!(
            bound_input(&foreign, &binding, 101),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn authcrypt_contract_rejects_cross_tenant_and_unversioned_keys() {
        let mut request = request();
        request.organization_id = "other".into();
        assert!(request.bound_payload().is_err());
        for reference in [
            "didcomm/keys/org/sender/versions/1",
            "didcomm/keys/../sender/versions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "didcomm/keys/org/sender/versions/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(DidcommKeyReference::parse(reference).is_err());
        }
    }
}
