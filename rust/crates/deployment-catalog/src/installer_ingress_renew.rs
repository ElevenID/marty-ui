//! Ingress leaf renewal inside the existing scoped generation transaction.
//! No root credential, new key, issuer replacement, activation or readiness claim.
use super::*;
use crate::installer_ingress_outputs::IngressMetadata;
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "installer_ingress_renew_tests.rs"]
mod tests;

pub(crate) struct RenewedIngress {
    pub files: BTreeMap<String, Vec<u8>>,
    pub metadata: IngressMetadata,
}

fn input<'a>(values: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a str> {
    std::str::from_utf8(values.get(name).ok_or(REFUSED)?).map_err(|_| REFUSED.into())
}

/// Bind the old public leaf to the retained CA and the current remote key.
/// An expired leaf may be replaced; neither expiration nor an unavailable old
/// signer token authorizes changing its issuer, identity, SPKI, or key version.
fn old_identity(
    ca: &str,
    leaf: &str,
    public: &str,
    name: &str,
    identity: &IngressIdentity,
) -> Result<()> {
    validate_retained_private_identity_at(
        ca,
        leaf,
        public,
        name,
        identity,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| REFUSED)?
            .as_secs(),
    )
}

/// Historical source authentication for a public generation transition. This
/// keeps the private issuer/leaf profile checks intact and does not require an
/// obsolete private CA to remain live when inspecting an immutable receipt.
pub(crate) fn validate_retained_private_identity_at(
    ca: &str,
    leaf: &str,
    public: &str,
    name: &str,
    identity: &IngressIdentity,
    observed: u64,
) -> Result<()> {
    let issuer = certificate(ca)?;
    let leaf = certificate(leaf)?;
    p256(&issuer)?;
    check_self_signature(&issuer)?;
    check_leaf_profile(&leaf, identity)?;
    check_certificate_signature(&leaf, &issuer)?;
    require(
        issuer.tbs_certificate.subject.to_string()
            == format!(
                "CN=Marty local CA {}",
                name.strip_prefix("installer-ingress-").ok_or(REFUSED)?
            ),
    )?;
    let remote = spki::SubjectPublicKeyInfoOwned::from_pem(public).map_err(|_| REFUSED)?;
    require(leaf.tbs_certificate.subject_public_key_info == remote)?;
    require(
        check_lifetime_at(ca.as_bytes(), TTL, Duration::from_secs(observed))
            .map_err(|_| REFUSED)?,
    )
}

async fn custody(
    bao: &OpenBaoHttp,
    authority: &str,
    owner: &str,
    current: &BTreeMap<String, Vec<u8>>,
    identity: &IngressIdentity,
) -> Result<(String, String)> {
    let name = resource_name(owner)?;
    let key = request(
        bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    version_one_custody(&key["data"], "ecdsa-p256").map_err(|_| REFUSED)?;
    let public = text(&key["data"]["keys"]["1"], "public_key")?.to_owned();
    let ca = request(
        bao,
        Method::GET,
        &format!("{name}/cert/ca"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(
        text(&ca["data"], "certificate")?.trim_end() == input(current, OUTPUTS[0])?.trim_end(),
    )?;
    old_identity(
        input(current, OUTPUTS[0])?,
        input(current, OUTPUTS[1])?,
        &public,
        &name,
        identity,
    )?;
    let policy = request(
        bao,
        Method::GET,
        &format!("sys/policies/acl/{name}"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(text(&policy["data"], "policy")? == signer_policy(&name)?)?;
    let role = request(
        bao,
        Method::GET,
        &format!("{name}/roles/localhost"),
        None,
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    let expected = identity.role_body();
    for (key, value) in expected.as_object().ok_or(REFUSED)? {
        if key == "max_ttl" {
            require(role["data"][key] == TTL)?;
        } else {
            require(role["data"][key] == *value)?;
        }
    }
    Ok((name, public))
}

/// Root-owned bootstrap validates the existing ingress before extending the
/// one renewal AppRole's reviewed leaf-policy inventory.
pub(crate) async fn renewal_inventory(
    bao: &OpenBaoHttp,
    authority: &str,
    owner: &str,
    current: &BTreeMap<String, Vec<u8>>,
    identity: &IngressIdentity,
) -> Result<String> {
    let (name, public) = custody(bao, authority, owner, current, identity).await?;
    let token = input(current, OUTPUTS[2])?;
    let lookup = request(
        bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    check_token(&lookup["data"], &name)?;
    let signed = request(
        bao,
        Method::POST,
        &format!("transit/sign/{name}"),
        Some(&sign_body()),
        Some(token),
    )
    .await
    .map_err(|_| REFUSED)?;
    verify_signing_proof(&public, text(&signed["data"], "signature")?)?;
    Ok(name)
}

pub(crate) fn validate_replacement(
    owner: &str,
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
    metadata: &IngressMetadata,
    identity: &IngressIdentity,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    validate_at(owner, before, after, metadata, identity, now)
}

/// Verify a retained, hash-bound receipt at its recorded observation time.
/// Current freshness is a separate admission check; historical evidence must
/// remain inspectable after the leaf or token reaches its scheduled expiry.
pub(crate) fn validate_recorded_replacement(
    owner: &str,
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
    metadata: &IngressMetadata,
    identity: &IngressIdentity,
) -> Result<()> {
    validate_at(
        owner,
        before,
        after,
        metadata,
        identity,
        metadata.token_observed_at,
    )
}

fn validate_at(
    owner: &str,
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
    metadata: &IngressMetadata,
    identity: &IngressIdentity,
    now: u64,
) -> Result<()> {
    require(metadata.schema == "elevenid.installer-ingress/v2")?;
    require(
        before.get(OUTPUTS[0]) == after.get(OUTPUTS[0])
            && before.get(OUTPUTS[1]) != after.get(OUTPUTS[1])
            && before.get(OUTPUTS[2]) != after.get(OUTPUTS[2]),
    )?;
    let bytes = serde_json::to_vec(metadata).map_err(|_| REFUSED)?;
    crate::installer_ingress_outputs::metadata_for_identity(&bytes, owner, now, identity)?;
    let leaf = certificate(input(after, OUTPUTS[1])?)?;
    let old = certificate(input(before, OUTPUTS[1])?)?;
    require(
        leaf.tbs_certificate.subject_public_key_info == old.tbs_certificate.subject_public_key_info,
    )?;
    use spki::der::EncodePem;
    let public = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_pem(spki::der::pem::LineEnding::LF)
        .map_err(|_| REFUSED)?;
    let expiry = check_certificates_for(
        input(after, OUTPUTS[0])?,
        input(after, OUTPUTS[1])?,
        &public,
        &resource_name(owner)?,
        now,
        identity,
    )?;
    require(expiry == (metadata.ca_expires_at, metadata.certificate_expires_at))?;
    let ca_der = certificate(input(after, OUTPUTS[0])?)?
        .to_der()
        .map_err(|_| REFUSED)?;
    let leaf_der = leaf.to_der().map_err(|_| REFUSED)?;
    for (expected, value) in [
        (
            &metadata.ca_pem_sha256,
            after.get(OUTPUTS[0]).ok_or(REFUSED)?.as_slice(),
        ),
        (
            &metadata.certificate_pem_sha256,
            after.get(OUTPUTS[1]).ok_or(REFUSED)?.as_slice(),
        ),
        (&metadata.ca_der_sha256, ca_der.as_slice()),
        (&metadata.certificate_der_sha256, leaf_der.as_slice()),
    ] {
        require(*expected == format!("{:x}", Sha256::digest(value)))?;
    }
    Ok(())
}

pub(crate) struct MintedTlsSigner {
    pub token: String,
    pub ttl_seconds: u64,
    pub observed_at: u64,
}

/// Shared exact TLS-token mint and proof. It has no CSR or issuer operation.
pub(crate) async fn mint_tls_signer(
    bao: &OpenBaoHttp,
    authority: &str,
    name: &str,
    public: &str,
    previous_token: &str,
) -> Result<MintedTlsSigner> {
    signer_policy(name)?;
    let minted = request(bao, Method::POST, "auth/token/create/selfhost-renew-leaf", Some(&json!({
        "policies":[name],"no_default_policy":true,"renewable":false,"ttl":"8h","explicit_max_ttl":"8h"
    })), Some(authority)).await.map_err(|_| REFUSED)?;
    let token = text(&minted["auth"], "client_token")?;
    require(
        (20..=4096).contains(&token.len())
            && token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            && token != authority
            && token != previous_token,
    )?;
    let looked_up = request(
        bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    let data = &looked_up["data"];
    let ttl = data["ttl"].as_u64().ok_or(REFUSED)?;
    require(
        data["policies"] == json!([name])
            && data["orphan"] == true
            && data["renewable"] == false
            && data["path"] == "auth/token/create/selfhost-renew-leaf"
            && data["explicit_max_ttl"] == TTL
            && (3600..=TTL).contains(&ttl),
    )?;
    let signed = request(
        bao,
        Method::POST,
        &format!("transit/sign/{name}"),
        Some(&sign_body()),
        Some(token),
    )
    .await
    .map_err(|_| REFUSED)?;
    verify_signing_proof(public, text(&signed["data"], "signature")?)?;
    for path in [
        format!("transit/keys/{name}/rotate"),
        "auth/token/create".into(),
        format!("{name}/root/generate/internal"),
    ] {
        denial(bao, token, Method::POST, &path, Some(sign_body()))
            .await
            .map_err(|_| REFUSED)?;
    }
    denial(
        bao,
        token,
        Method::GET,
        &format!("transit/export/signing-key/{name}"),
        None,
    )
    .await
    .map_err(|_| REFUSED)?;
    Ok(MintedTlsSigner {
        token: token.into(),
        ttl_seconds: ttl,
        observed_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| REFUSED)?
            .as_secs(),
    })
}

pub(crate) async fn prove_retained_tls_signer(
    bao: &OpenBaoHttp,
    authority: &str,
    name: &str,
    spki: &[u8],
    token: &str,
) -> Result<()> {
    signer_policy(name)?;
    let observed = request(
        bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    let data = &observed["data"];
    require(
        data["policies"] == json!([name])
            && data["orphan"] == true
            && data["renewable"] == false
            && data["explicit_max_ttl"] == TTL
            && data["ttl"]
                .as_u64()
                .is_some_and(|ttl| (3600..=TTL).contains(&ttl))
            && [
                "auth/token/create-orphan",
                "auth/token/create/selfhost-renew-leaf",
            ]
            .contains(&data["path"].as_str().ok_or(REFUSED)?),
    )?;
    let public = spki::SubjectPublicKeyInfoOwned::from_der(spki).map_err(|_| REFUSED)?;
    let public = spki::der::EncodePem::to_pem(&public, spki::der::pem::LineEnding::LF)
        .map_err(|_| REFUSED)?;
    let signed = request(
        bao,
        Method::POST,
        &format!("transit/sign/{name}"),
        Some(&sign_body()),
        Some(token),
    )
    .await
    .map_err(|_| REFUSED)?;
    verify_signing_proof(&public, text(&signed["data"], "signature")?)
}

/// Called once after the containing generation has persisted its pending
/// receipt. A lost CSR/sign/token response remains an uncertain transaction.
pub(crate) async fn renew(
    bao: &OpenBaoHttp,
    authority: &str,
    owner: &str,
    current: &BTreeMap<String, Vec<u8>>,
    identity: &IngressIdentity,
) -> Result<RenewedIngress> {
    crate::activation_preflight::authority(bao, authority, false)
        .await
        .map_err(|_| REFUSED)?;
    let (name, public) = custody(bao, authority, owner, current, identity).await?;
    let csr = request(
        bao,
        Method::POST,
        &format!("transit/keys/{name}/csr"),
        Some(&json!({"version":1})),
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    let issued = request(
        bao,
        Method::POST,
        &format!("{name}/sign/localhost"),
        Some(&identity.signing_request(text(&csr["data"], "csr")?)),
        Some(authority),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(issued["data"].get("private_key").is_none())?;
    let leaf = text(&issued["data"], "certificate")?;
    let ca = input(current, OUTPUTS[0])?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let (ca_expires_at, certificate_expires_at) =
        check_certificates_for(ca, leaf, &public, &name, now, identity)?;
    let minted =
        mint_tls_signer(bao, authority, &name, &public, input(current, OUTPUTS[2])?).await?;
    let token = minted.token.as_str();
    let metadata = IngressMetadata {
        schema: "elevenid.installer-ingress/v2".into(),
        installation_id: owner.into(),
        key_name: name.clone(),
        key_version: 1,
        pki_mount: name,
        dns_names: identity.dns_names(),
        ip_addresses: identity.ip_addresses(),
        ca_der_sha256: format!(
            "{:x}",
            Sha256::digest(certificate(ca)?.to_der().map_err(|_| REFUSED)?)
        ),
        certificate_der_sha256: format!(
            "{:x}",
            Sha256::digest(certificate(leaf)?.to_der().map_err(|_| REFUSED)?)
        ),
        ca_pem_sha256: format!("{:x}", Sha256::digest(ca.as_bytes())),
        certificate_pem_sha256: format!("{:x}", Sha256::digest(leaf.as_bytes())),
        ca_expires_at,
        certificate_expires_at,
        token_ttl_seconds: minted.ttl_seconds,
        token_observed_at: minted.observed_at,
        trust_installed: false,
        installation_ready: false,
    };
    let files = [
        (OUTPUTS[0].into(), ca.as_bytes().to_vec()),
        (OUTPUTS[1].into(), leaf.as_bytes().to_vec()),
        (OUTPUTS[2].into(), token.as_bytes().to_vec()),
    ]
    .into();
    validate_replacement(owner, current, &files, &metadata, identity)?;
    Ok(RenewedIngress { files, metadata })
}
