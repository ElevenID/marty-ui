//! Explicit assembly-only transport and remote custody fixtures. The production
//! executable is separately tested to require its real keyless TLS constructor.
use std::{collections::BTreeMap, time::Duration as Timeout};

use axum::{body::Body, http::Request};
use chrono::{Duration, SecondsFormat};
use marty_delegated_authority::{
    use_http::{AuthenticatedDelegationUseContext, DelegationUseHttpAuthenticator},
    use_mtls::{DelegatedUseWorkloadBinding, DelegatedUseWorkloadBindings},
    ManagedDelegatedReceiptKey,
};
use marty_delegated_use::config::{
    DelegatedUseHostConfig, ReceiptSigningConfig, RequestSigningConfig,
};
use marty_service_runtime::{RemoteTlsIdentityFiles, TlsIdentityNames, WorkloadTlsFiles};

use super::{
    crypto::{public_jwk, RECEIPT_KEY},
    database::Database,
    owned::{now, Owned, PUBLIC_BASE},
    TestResult,
};

pub fn configuration(owned: &Owned, db: &Database) -> TestResult<DelegatedUseHostConfig> {
    // These configuration paths are never read by assemble; they deliberately
    // cannot supply a local production key or an alternate serving mode.
    let tls_values: BTreeMap<String, String> = [
        ("CERT_FILE", "/fixture/public-chain.pem"),
        ("KMS_PROVIDER", "openbao-transit"),
        ("KMS_ADDR", "https://custody.example.test"),
        ("KMS_CA_CERT_FILE", "/fixture/custody-ca.pem"),
        ("KMS_TOKEN_FILE", "/fixture/custody-token"),
        ("KMS_KEY_NAME", "fixture-tls-provider-key"),
        ("KMS_KEY_VERSION", "1"),
    ]
    .into_iter()
    .map(|(suffix, value)| (format!("TEST_TLS_{suffix}"), value.to_owned()))
    .collect();
    let tls_identity = RemoteTlsIdentityFiles::from_values(
        |name| tls_values.get(name).map(String::as_str),
        TlsIdentityNames::files("TEST_TLS"),
        Timeout::from_secs(5),
        4,
    )?
    .ok_or("fixture remote identity selection is absent")?;
    let workload_bindings =
        DelegatedUseWorkloadBindings::new(vec![DelegatedUseWorkloadBinding::new(
            format!("spiffe://host.example.test/machine/{}", owned.machine_id),
            format!("sha256:{}", "ab".repeat(32)),
            owned.principal.id.clone(),
        )?])?;
    let receipt_key = ManagedDelegatedReceiptKey::new(
        owned.organization,
        owned.receipts.issuer.clone(),
        "ES256".into(),
        RECEIPT_KEY.into(),
        "fixture-receipt-provider-key".into(),
        public_jwk(&owned.receipts.key),
    )?;
    Ok(DelegatedUseHostConfig {
        listen_addr: "127.0.0.1:0".parse()?,
        health_addr: None,
        public_caller_enabled: false,
        pool_max_connections: 1,
        organization_id: owned.organization,
        deployment_profile_id: owned.deployment,
        delegation_policy_id: owned.delegated_policy,
        database_urls: db.urls.clone(),
        approval_configuration: owned.approval.clone(),
        authority: owned.authority.clone(),
        flow_start: owned.flow.clone(),
        request_options: owned.flow.options.request_object.clone(),
        public_base_url: PUBLIC_BASE.into(),
        challenge_lifetime_seconds: 120,
        receipt_lifetime_seconds: 120,
        credential_template_grpc_target: "https://template.example.test:9005".into(),
        presentation_policy_grpc_target: "https://policy.example.test:9006".into(),
        workload_client_tls: WorkloadTlsFiles {
            ca_certificate: "/fixture/peer-ca.pem".into(),
            identity: tls_identity.clone(),
        },
        service_token: "fixture-service-token-for-remote-read-owner-only".into(),
        issuance_native_url: "https://issuance.example.test".into(),
        issuance_api_key: "fixture-issuance-read-credential-only".into(),
        credential_template_url: "https://template.example.test".into(),
        trust_profile_url: "https://trust.example.test".into(),
        deployment_profile_url: "https://deployment.example.test".into(),
        request_signing: RequestSigningConfig {
            origin: "https://signing.example.test".into(),
            read_credential: "fixture-request-key-read-credential-only".into(),
            sign_credential: "fixture-request-signing-credential-only".into(),
            grant_openbao_origin: "https://custody.example.test".into(),
            mint_token_file: "/fixture/request-mint-token".into(),
        },
        receipt_signing: ReceiptSigningConfig {
            origin: "https://signing.example.test".into(),
            read_credential: "fixture-receipt-key-read-credential-only".into(),
            sign_credential: "fixture-receipt-signing-credential-only".into(),
            grant_openbao_origin: "https://custody.example.test".into(),
            mint_token_file: "/fixture/receipt-mint-token".into(),
            key: receipt_key,
            issuer: owned.receipts.issuer.clone(),
        },
        tls_identity,
        // assemble constructs the mandatory certificate authenticator; parsing
        // an actual trust anchor occurs only when the executable binds TLS.
        client_ca_der: vec![vec![0x30, 1, 0]],
        workload_bindings,
    })
}

/// Human-independent fixture for a pre-authenticated machine workload. It does
/// not substitute the runtime router's authenticator (which remains mTLS-only).
pub fn context(owned: &Owned) -> TestResult<AuthenticatedDelegationUseContext> {
    const TOKEN: &str = "explicit-assembly-test-forwarder-token-32-bytes";
    let authenticator =
        DelegationUseHttpAuthenticator::trusted_forwarder(TOKEN.into(), owned.organization)?;
    let time = now();
    let request = Request::builder()
        .header("x-service-token", TOKEN)
        .header(
            "x-marty-use-organization-id",
            owned.organization.to_string(),
        )
        .header("x-marty-use-principal-type", "MACHINE_IDENTITY")
        .header("x-marty-use-principal-id", &owned.principal.id)
        .header(
            "x-marty-use-observed-at",
            time.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        )
        .header(
            "x-marty-use-valid-until",
            (time + Duration::seconds(25)).to_rfc3339_opts(SecondsFormat::AutoSi, true),
        )
        .body(Body::empty())?;
    authenticator
        .authenticate(&owned.organization.to_string(), &request)
        .map_err(|_| "fixture workload authentication rejected".into())
}
