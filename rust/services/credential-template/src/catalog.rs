use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::{
    CredentialTemplateRepositoryError, DeliveryDestinationEntry, MergeStrategy,
    PostgresCredentialTemplateStore, WalletRegistryEntry,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CatalogSeedSummary {
    pub wallets_inserted: usize,
    pub wallets_reconciled: usize,
    pub destinations_inserted: usize,
    pub destinations_reconciled: usize,
}

pub fn system_wallet_catalog(now: DateTime<Utc>) -> Vec<WalletRegistryEntry> {
    vec![
        WalletRegistryEntry {
            logo_url: Some("https://spruceid.com/favicon.ico".to_owned()),
            supported_formats: strings(&["dc+sd-jwt", "mso_mdoc"]),
            platforms: strings(&["ios", "android"]),
            routing_templates: string_map(&[
                ("generic", "openid-credential-offer://?{credential_offer_param}={offer_encoded}"),
                ("ios", "openid-credential-offer://?{credential_offer_param}={offer_encoded}"),
                ("android", "intent://?{credential_offer_param}={offer_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end"),
            ]),
            install_urls: string_map(&[
                ("ios", "https://apps.apple.com/search?term=SpruceKit"),
                ("android", "https://play.google.com/store/search?q=SpruceKit&c=apps"),
            ]),
            docs_url: Some("https://spruceid.com/products/sprucekit".to_owned()),
            ..wallet(
                "wr-spruce-001",
                "SpruceKit",
                "SpruceID mobile wallet for OID4VCI delivery.",
                &["SpruceKit"],
                &["OID4VCI"],
                now,
            )
        },
        WalletRegistryEntry {
            supported_formats: strings(&["dc+sd-jwt", "mso_mdoc"]),
            platforms: strings(&["ios", "android"]),
            routing_templates: string_map(&[
                ("generic", "marty-authenticator://open?inner={inner_uri_encoded}"),
                ("ios", "marty-authenticator://open?inner={inner_uri_encoded}"),
                ("android", "marty-authenticator://open?inner={inner_uri_encoded}"),
            ]),
            ios_scheme: Some("marty-authenticator".to_owned()),
            ..wallet(
                "wr-marty-001",
                "Marty Authenticator",
                "Marty-branded authenticator wallet.",
                &["Marty Authenticator"],
                &["OID4VCI"],
                now,
            )
        },
        WalletRegistryEntry {
            description: Some("Generic OID4VCI handoff for configured and tested SD-JWT VC or JWT VC wallets; this entry does not assert compatibility with every wallet or mdoc profile.".to_owned()),
            supported_formats: strings(&["sd_jwt_vc", "jwt_vc"]),
            platforms: strings(&["ios", "android", "web"]),
            ..wallet(
                "wr-default",
                "Any OID4VCI Wallet",
                "Generic OID4VCI-compatible wallet entry.",
                &["Any OID4VCI Wallet"],
                &["OID4VCI"],
                now,
            )
        },
        WalletRegistryEntry {
            logo_url: Some("https://lissi.id/favicon.ico".to_owned()),
            supported_formats: strings(&["sd_jwt_vc", "jwt_vc"]),
            platforms: strings(&["ios", "android"]),
            docs_url: Some("https://lissi.id".to_owned()),
            ..wallet(
                "wr-lissi-001",
                "LISSI Wallet",
                "LISSI mobile wallet.",
                &["LISSI Wallet"],
                &["OID4VCI"],
                now,
            )
        },
        WalletRegistryEntry {
            logo_url: Some("https://walt.id/favicon.ico".to_owned()),
            deep_link_template:
                "openid-credential-offer://?{credential_offer_param}={offer_encoded}".to_owned(),
            routing_templates: string_map(&[
                ("generic", "openid-credential-offer://?{credential_offer_param}={offer_encoded}"),
                ("web", "https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}"),
                ("desktop", "https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}"),
            ]),
            supported_formats: strings(&["sd_jwt_vc", "jwt_vc", "mdoc"]),
            platforms: strings(&["ios", "android", "web"]),
            docs_url: Some("https://docs.walt.id".to_owned()),
            is_active: false,
            ..wallet(
                "wr-waltid-001",
                "walt.id Wallet",
                "walt.id community wallet retained for interoperability tracking.",
                &["walt.id Wallet"],
                &["OID4VCI", "OID4VP"],
                now,
            )
        },
        WalletRegistryEntry {
            logo_url: Some("https://sphereon.com/favicon.ico".to_owned()),
            supported_formats: strings(&["sd_jwt_vc", "jwt_vc"]),
            platforms: strings(&["ios", "android"]),
            docs_url: Some("https://sphereon.com".to_owned()),
            ..wallet(
                "wr-sphereon-001",
                "Sphereon Wallet",
                "Sphereon mobile wallet.",
                &["Sphereon Wallet"],
                &["OID4VCI"],
                now,
            )
        },
        WalletRegistryEntry {
            supported_formats: strings(&["sd_jwt_vc", "mdoc"]),
            platforms: strings(&["ios", "android"]),
            ..wallet(
                "wr-dc4eu-001",
                "DC4EU Wallet",
                "DC4EU and EUDI ecosystem wallet.",
                &["DC4EU Wallet"],
                &["OID4VCI", "eIDAS"],
                now,
            )
        },
        WalletRegistryEntry {
            logo_url: Some("https://wallet.google/favicon.ico".to_owned()),
            supported_formats: strings(&["dc+sd-jwt"]),
            supported_protocols: strings(&["CREDENTIAL_MANAGER"]),
            platforms: strings(&["android"]),
            deep_link_template: "openid-credential-offer://?credential_offer={offer}".to_owned(),
            routing_templates: string_map(&[
                ("generic", "openid-credential-offer://?credential_offer={offer_encoded}"),
                ("android", "openid-credential-offer://?credential_offer={offer_encoded}"),
            ]),
            android_package: Some("com.google.android.gms".to_owned()),
            supports_digital_credentials: true,
            docs_url: Some(
                "https://developer.android.com/identity/digital-credentials".to_owned(),
            ),
            ..wallet(
                "wr-google-001",
                "Google Wallet",
                "Google Wallet via Android CredentialManager API.",
                &["Google Wallet"],
                &["OID4VCI", "CredentialManager"],
                now,
            )
        },
        WalletRegistryEntry {
            logo_url: Some("https://www.apple.com/favicon.ico".to_owned()),
            supported_formats: strings(&["mso_mdoc"]),
            specifications: strings(&["ISO 18013-5", "Verify with Wallet"]),
            supported_protocols: strings(&["APPLE_WALLET"]),
            platforms: strings(&["ios"]),
            deep_link_template: String::new(),
            routing_templates: BTreeMap::new(),
            supports_deeplink: false,
            supports_digital_credentials: true,
            is_active: false,
            description: Some("Inactive compatibility placeholder. Apple Wallet identity provisioning and Verify with Wallet presentation are program-specific paths and are not generic OID4VCI compatibility.".to_owned()),
            docs_url: Some("https://developer.apple.com/documentation/passkit/wallet".to_owned()),
            ..wallet(
                "wr-apple-001",
                "Apple Wallet",
                "Apple Wallet via Verify with Wallet / ISO 18013-5 issuance.",
                &["Apple Wallet"],
                &["OID4VCI", "ISO 18013-5"],
                now,
            )
        },
        WalletRegistryEntry {
            supported_formats: strings(&["sd_jwt_vc", "jwt_vc", "mso_mdoc"]),
            supported_protocols: strings(&["DIDCOMM_V2"]),
            platforms: strings(&["any"]),
            supports_qr: false,
            supports_deeplink: false,
            deep_link_template: String::new(),
            docs_url: Some(
                "https://identity.foundation/didcomm-messaging/spec/v2.1/".to_owned(),
            ),
            ..wallet(
                "wr-didcomm-001",
                "DIDComm V2 Agent",
                "Push credential delivery via DIDComm v2 messaging. Resolves holder DID to find service endpoint.",
                &["DIDComm V2 Agent"],
                &["DIDComm v2", "DIF DIDComm Messaging"],
                now,
            )
        },
    ]
}

pub fn system_delivery_destination_catalog(now: DateTime<Utc>) -> Vec<DeliveryDestinationEntry> {
    vec![
        DeliveryDestinationEntry {
            wallet_profile_id: Some("wr-marty-001".to_owned()),
            issuance_protocol: Some("OID4VCI_PRE_AUTH".to_owned()),
            claim_projection_policy: json!({"mode":"full_credential_reference"}),
            capabilities: bool_map(&[
                ("holder_wallet", true),
                ("oid4vci", true),
                ("post_issuance_publish", false),
            ]),
            ..destination(
                "dd-elevenid-wallet",
                "ElevenID Wallet",
                "Add the credential to the holder's ElevenID-compatible wallet using OID4VCI.",
                "elevenid_wallet",
                "holder_wallet",
                "learner",
                "wallet",
                now,
            )
        },
        DeliveryDestinationEntry {
            wallet_profile_id: Some("wr-default".to_owned()),
            issuance_protocol: Some("OID4VCI_PRE_AUTH".to_owned()),
            claim_projection_policy: json!({"mode":"full_credential_reference"}),
            capabilities: bool_map(&[
                ("holder_wallet", true),
                ("oid4vci", true),
                ("post_issuance_publish", false),
            ]),
            ..destination(
                "dd-oid4vci-compatible-wallet",
                "Compatible Wallet",
                "Open the standards-based credential offer in any compatible OID4VCI wallet.",
                "oid4vci_wallet",
                "holder_wallet",
                "learner",
                "wallet",
                now,
            )
        },
        DeliveryDestinationEntry {
            credential_format: Some("VC_JWT".to_owned()),
            issuance_protocol: Some("DIRECT".to_owned()),
            compliance_profile_code: Some("OB3_JWT".to_owned()),
            connector_type: Some("canvas_platform".to_owned()),
            requires_consent: true,
            claim_projection_policy: json!({
                "mode":"public_badge",
                "allowed_claims":["achievement","result","learning_context","issuer","credentialSubject","credentialStatus","provenance"]
            }),
            setup_requirements: strings(&[
                "Canvas Credentials issuer/API access configured by an organization admin",
                "Canvas Credentials API token referenced from an org-scoped secret or issuance secret layer",
                "Canvas Credentials badgeclass/entity ID mapped to the credential template, program binding, or delivery destination",
                "Canvas program binding enabled for Canvas mirror delivery",
            ]),
            capabilities: bool_map(&[
                ("holder_wallet", false),
                ("org_managed", true),
                ("post_issuance_publish", true),
                ("status_sync", true),
                ("provenance", true),
                ("badgr_api", true),
            ]),
            docs_url: Some(
                "https://developerdocs.instructure.com/services/credentials".to_owned(),
            ),
            ..destination(
                "dd-canvas-credentials-institutional",
                "Canvas Credentials",
                "Publish a public Open Badge view to Canvas Credentials after canonical ElevenID issuance. Requires organization-managed Canvas Credentials setup.",
                "canvas_credentials",
                "organization_mirror",
                "org_admin",
                "canvas_credentials",
                now,
            )
        },
        DeliveryDestinationEntry {
            connector_type: Some("canvas_credentials_oauth".to_owned()),
            requires_consent: true,
            claim_projection_policy: json!({"mode":"public_badge"}),
            setup_requirements: strings(&[
                "Learner authorizes their own backpack account",
                "Organization enables backpack import as an allowed destination",
            ]),
            capabilities: bool_map(&[
                ("holder_wallet", false),
                ("learner_owned", true),
                ("oauth_required", true),
                ("post_issuance_publish", true),
            ]),
            docs_url: Some(
                "https://developerdocs.instructure.com/services/credentials".to_owned(),
            ),
            ..destination(
                "dd-canvas-credentials-backpack",
                "Canvas Credentials Backpack",
                "Let a learner connect a personal Canvas/Parchment backpack when OAuth setup is available.",
                "canvas_credentials_backpack",
                "learner_backpack",
                "learner",
                "external_api",
                now,
            )
        },
    ]
}

pub async fn seed_system_catalog(
    store: &PostgresCredentialTemplateStore,
    now: DateTime<Utc>,
) -> Result<CatalogSeedSummary, CredentialTemplateRepositoryError> {
    let mut summary = CatalogSeedSummary::default();
    for wallet in system_wallet_catalog(now) {
        if store.wallet_by_id(&wallet.id).await?.is_none() {
            summary.wallets_inserted += 1;
        } else {
            summary.wallets_reconciled += 1;
        }
        store.save_wallet(&wallet).await?;
    }
    for destination in system_delivery_destination_catalog(now) {
        if store.destination_by_id(&destination.id).await?.is_none() {
            summary.destinations_inserted += 1;
        } else {
            summary.destinations_reconciled += 1;
        }
        store.save_destination(&destination).await?;
    }
    Ok(summary)
}

fn wallet(
    id: &str,
    name: &str,
    description: &str,
    wallet_apps: &[&str],
    specifications: &[&str],
    now: DateTime<Utc>,
) -> WalletRegistryEntry {
    WalletRegistryEntry {
        id: id.to_owned(),
        organization_id: None,
        is_override: false,
        override_precedence: 50,
        merge_strategy: MergeStrategy::Append,
        credential_format: None,
        issuance_protocol: None,
        compliance_profile_code: None,
        name: name.to_owned(),
        description: Some(description.to_owned()),
        wallet_apps: strings(wallet_apps),
        specifications: strings(specifications),
        logo_url: None,
        deep_link_template: "openid-credential-offer://?credential_offer_uri={offer_uri}"
            .to_owned(),
        routing_templates: BTreeMap::new(),
        install_urls: BTreeMap::new(),
        ios_scheme: None,
        universal_link_template: None,
        android_package: None,
        supported_formats: Vec::new(),
        supported_protocols: strings(&["OID4VCI_PRE_AUTH"]),
        platforms: Vec::new(),
        supports_qr: true,
        supports_deeplink: true,
        supports_digital_credentials: false,
        supports_haip: false,
        docs_url: None,
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

#[allow(clippy::too_many_arguments)]
fn destination(
    id: &str,
    name: &str,
    description: &str,
    provider: &str,
    mode: &str,
    setup_actor: &str,
    delivery_target: &str,
    now: DateTime<Utc>,
) -> DeliveryDestinationEntry {
    DeliveryDestinationEntry {
        id: id.to_owned(),
        organization_id: None,
        is_system: true,
        name: name.to_owned(),
        description: Some(description.to_owned()),
        provider: provider.to_owned(),
        mode: mode.to_owned(),
        setup_actor: setup_actor.to_owned(),
        delivery_target: delivery_target.to_owned(),
        wallet_profile_id: None,
        credential_format: None,
        issuance_protocol: None,
        compliance_profile_code: None,
        connector_type: None,
        connector_id: None,
        requires_consent: false,
        claim_projection_policy: json!({}),
        setup_requirements: Vec::new(),
        capabilities: BTreeMap::new(),
        docs_url: None,
        is_enabled: true,
        created_at: now,
        updated_at: now,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn string_map(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn bool_map(values: &[(&str, bool)]) -> BTreeMap<String, bool> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), *value))
        .collect()
}
