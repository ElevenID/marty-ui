//! Wallet issuance-service grants, separate from generic credential trust.
use crate::{IssuerEntity, TrustProfile, TrustProfileIssuer, TrustProfileRepositoryError};
use chrono::{DateTime, Utc};
use marty_oid4vp_contract::{
    digest_domain_json,
    trust_authority::{CredentialAuthorityBasisV1, CredentialAuthoritySnapshotV1},
    EvidenceProfileReference,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub use marty_oid4vp_contract::wallet_issuance::{IssuanceAuthorization, METADATA_KEY};
pub fn authorizations(
    metadata: &Value,
) -> Result<Vec<IssuanceAuthorization>, TrustProfileRepositoryError> {
    marty_oid4vp_contract::wallet_issuance::authorizations(metadata).map_err(|_| invalid())
}
fn invalid() -> TrustProfileRepositoryError {
    TrustProfileRepositoryError::InvalidData("wallet_issuer_authority.issuance_authorizations")
}

pub type IssuerBindings = BTreeMap<String, Vec<IssuanceAuthorization>>;

/// Coherent owner observation. Its wallet revision has a separate namespace,
/// so generic credential-authority v1 revisions/wire schemas stay unchanged.
#[derive(Clone, Debug, PartialEq)]
pub struct WalletIssuerAuthoritySnapshot {
    pub credential_authority: CredentialAuthoritySnapshotV1,
    pub issuance_authorizations: IssuerBindings,
    pub revision: EvidenceProfileReference,
}

pub(crate) fn basis(
    profile: &TrustProfile,
    relationships: Vec<(TrustProfileIssuer, IssuerEntity)>,
) -> Result<(CredentialAuthorityBasisV1, IssuerBindings), TrustProfileRepositoryError> {
    let mut bindings = IssuerBindings::new();
    for (relationship, issuer) in &relationships {
        let grants = authorizations(&relationship.metadata)?;
        if !grants.is_empty() && bindings.insert(issuer.issuer_id.clone(), grants).is_some() {
            return Err(invalid());
        }
    }
    Ok((
        crate::credential_authority::authority_basis(profile, relationships)?,
        bindings,
    ))
}
pub(crate) fn digest(
    basis: &CredentialAuthorityBasisV1,
    bindings: &IssuerBindings,
) -> Result<String, TrustProfileRepositoryError> {
    digest_domain_json(
        "marty.wallet/issuer-authority-basis/v2",
        &json!({
            "credential_authority_basis":basis,"issuance_authorizations":bindings,
        }),
    )
    .map_err(|_| invalid())
}
pub(crate) fn snapshot(
    basis: CredentialAuthorityBasisV1,
    bindings: IssuerBindings,
    version: u32,
) -> Result<WalletIssuerAuthoritySnapshot, TrustProfileRepositoryError> {
    if version == 0 {
        return Err(invalid());
    }
    let revision = EvidenceProfileReference {
        id: basis.id.clone(),
        version,
        content_digest: digest(&basis, &bindings)?,
    };
    Ok(WalletIssuerAuthoritySnapshot {
        credential_authority: crate::credential_authority::authority_snapshot(basis, 1)?,
        issuance_authorizations: bindings,
        revision,
    })
}
pub fn project(
    snapshot: &WalletIssuerAuthoritySnapshot,
    now: DateTime<Utc>,
) -> Result<Value, crate::credential_authority::CredentialAuthorityError> {
    use crate::credential_authority::CredentialAuthorityError;
    if snapshot.revision.id != snapshot.credential_authority.profile.id
        || snapshot.revision.version == 0
        || digest(
            &snapshot.credential_authority.basis,
            &snapshot.issuance_authorizations,
        )
        .map_err(|_| CredentialAuthorityError::Unavailable)?
            != snapshot.revision.content_digest
    {
        return Err(CredentialAuthorityError::Unavailable);
    }
    let mut projection =
        crate::credential_authority::wallet_issuer_authority(&snapshot.credential_authority, now)?;
    projection["revision"] = serde_json::to_value(&snapshot.revision)
        .map_err(|_| CredentialAuthorityError::Unavailable)?;
    for key in projection["issuer_keys"]
        .as_array_mut()
        .ok_or(CredentialAuthorityError::Unavailable)?
    {
        let issuer = key["issuer"]
            .as_str()
            .ok_or(CredentialAuthorityError::Unavailable)?;
        let grants = snapshot
            .issuance_authorizations
            .get(issuer)
            .cloned()
            .unwrap_or_default();
        let accepted = grants
            .into_iter()
            .filter(|grant| {
                key["credential_authorizations"]
                    .as_array()
                    .is_some_and(|types| {
                        types
                            .iter()
                            .any(|rule| rule["format"] == "SD_JWT_VC" && rule["vct"] == grant.vct)
                    })
            })
            .collect::<Vec<_>>();
        key["issuance_authorizations"] =
            serde_json::to_value(accepted).map_err(|_| CredentialAuthorityError::Unavailable)?;
    }
    if serde_json::to_vec(&projection)
        .map_err(|_| CredentialAuthorityError::Unavailable)?
        .len()
        > 256 * 1024
    {
        return Err(CredentialAuthorityError::Unavailable);
    }
    Ok(projection)
}
