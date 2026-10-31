//! Shared opt-in fixture for real registry-bound DIDComm operations. Callers
//! own the disposable Redis/OpenBao resources and the token directory; this
//! helper reuses production registries, public publication, HTTPS routes and
//! distinct remote mint/verify policies without a test cryptographic adapter.

use async_trait::async_trait;
use axum::Router;
use marty_didcomm::DidDocument;
use marty_issuance_service::didcomm_kms::RegisteredDidcommKms;
use marty_signing_grant::{
    minter::{GrantMinter, GrantMinting},
    replay::RedisGrantReplayStore,
    verifier::GrantVerifier,
    GrantBinding, GrantEnvelope, GrantError, SigningOrigin,
};
use marty_signing_keys::{
    documents::{DidVerificationRelationship, DocumentStore, LoadDidRequest, PublishDidRequest},
    flow_envelope::OpenBaoEnvelopeProvider,
    kms::{public_key_existing, ProviderRequest},
    profiles::ProfileStore,
    registry::RegistryStore,
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub struct SenderInputs<'a> {
    pub client: &'a reqwest::Client,
    pub base: &'a str,
    pub root_token: &'a str,
    pub kms_ca: &'a Path,
    pub redis_url: &'a str,
    pub directory: &'a Path,
    pub tenant: &'a str,
    pub sender_did: &'a str,
    pub issuer_api_key: &'a str,
    pub integration_secret_api_key: Option<&'a str>,
}

pub struct RegisteredSenderFixture {
    pub registry: RegistryStore,
    pub name: String,
    pub sender_kid: String,
    pub version: String,
    pub sender_public: String,
    pub reference: String,
    pub policy_name: String,
    pub extension_policy: String,
    pub scoped_token: String,
    pub mint_file: PathBuf,
    pub url: reqwest::Url,
    pub ca_pem: String,
    pub ca_file: PathBuf,
    pub https: reqwest::Client,
    pub publication: Value,
    pub publication_url: String,
    pub sender_document: DidDocument,
    pub recording: RecordingMinter,
    pub kms: RegisteredDidcommKms,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for RegisteredSenderFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[derive(Clone)]
pub struct RecordingMinter {
    pub inner: GrantMinter,
    pub issued: Arc<Mutex<Vec<(String, String)>>>,
}
#[async_trait]
impl GrantMinting for RecordingMinter {
    async fn mint(&self, binding: &GrantBinding<'_>) -> Result<GrantEnvelope, GrantError> {
        let grant = self.inner.mint(binding).await?;
        let request: Value = serde_json::from_slice(binding.payload).unwrap();
        self.issued.lock().unwrap().push((
            request["phase"].as_str().unwrap().into(),
            grant.claims.nonce.clone(),
        ));
        Ok(grant)
    }
}

pub async fn write(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    path: &str,
    value: Value,
) -> Value {
    let response = client
        .post(format!("{base}/v1/{path}"))
        .header("X-Vault-Token", token)
        .json(&value)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        json!({})
    } else {
        response.json().await.unwrap()
    }
}
pub async fn policy(client: &reqwest::Client, base: &str, root: &str, name: &str, text: &str) {
    client
        .put(format!("{base}/v1/sys/policies/acl/{name}"))
        .header("X-Vault-Token", root)
        .json(&json!({"policy":text}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}
async fn token(client: &reqwest::Client, base: &str, root: &str, name: &str, text: &str) -> String {
    policy(client, base, root, name, text).await;
    write(
        client,
        base,
        root,
        "auth/token/create",
        json!({"policies":[name],"no_default_policy":true,"ttl":"10m"}),
    )
    .await["auth"]["client_token"]
        .as_str()
        .unwrap()
        .into()
}

impl RegisteredSenderFixture {
    pub fn shutdown(&self) {
        self.server.abort();
    }

    pub async fn create(input: SenderInputs<'_>) -> Self {
        let SenderInputs {
            client,
            base,
            root_token,
            kms_ca,
            redis_url,
            directory,
            tenant,
            sender_did,
            issuer_api_key,
            integration_secret_api_key,
        } = input;
        assert_eq!(std::env::var("BAO_ADDR").as_deref(), Ok(base));
        assert_eq!(
            std::env::var("BAO_CACERT").as_deref(),
            Ok(kms_ca.to_str().unwrap())
        );
        assert!(directory.is_absolute() && directory.is_dir());
        let parts: Vec<_> = sender_did.split(':').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(&parts[..2], &["did", "web"]);
        assert_eq!(parts[3], "orgs");
        let public_domain = parts[2].to_owned();
        let slug = parts[4].to_owned();
        let sender_did = sender_did.to_owned();
        let mounts: Value = client
            .get(format!("{base}/v1/sys/mounts"))
            .header("X-Vault-Token", root_token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        if mounts
            .get("data")
            .and_then(|data| data.get("transit/"))
            .is_none()
        {
            write(
                client,
                base,
                root_token,
                "sys/mounts/transit",
                json!({"type":"transit"}),
            )
            .await;
        }
        let sender_kid = format!("{sender_did}#key-1");
        let fixture_id = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("sender_{fixture_id}");
        let create = write(
            client,
            base,
            root_token,
            &format!("didcomm/keys/{tenant}/{name}"),
            json!({"sender_did":sender_did,"sender_key_id":sender_kid}),
        )
        .await;
        let version = create["data"]["version"].as_str().unwrap().to_owned();
        let sender_public = create["data"]["public_key"].as_str().unwrap().to_owned();
        let reference = format!("didcomm/keys/{tenant}/{name}/versions/{version}");
        let signing_key = format!("sender-signing-{fixture_id}");
        let grant_key = SigningOrigin::IssuanceCredential.transit_key_name();
        let envelope_key = "integration-secret-envelope-marty-aes256";
        for (key, kind) in [
            (&signing_key[..], "ecdsa-p256"),
            (grant_key, "hmac"),
            (envelope_key, "aes256-gcm96"),
        ] {
            let mut request =
                json!({"type":kind,"exportable":false,"allow_plaintext_backup":false});
            if kind == "hmac" {
                request["key_size"] = json!(32);
            }
            write(
                client,
                base,
                root_token,
                &format!("transit/keys/{key}"),
                request,
            )
            .await;
        }
        let extension_policy = format!("path \"didcomm/keys/{tenant}/{name}/versions/{version}\" {{ capabilities = [\"read\"] }}\npath \"didcomm/pack/{tenant}/{name}/{version}\" {{ capabilities = [\"update\"] }}\npath \"transit/keys/{signing_key}\" {{ capabilities = [\"read\"] }}\npath \"transit/sign/{signing_key}\" {{ capabilities = [\"update\"] }}");
        let policy_name = format!("sender-extension-{fixture_id}");
        let scoped_token = token(client, base, root_token, &policy_name, &extension_policy).await;
        let mint_token = token(
            client,
            base,
            root_token,
            &format!("sender-mint-{fixture_id}"),
            &format!(
                "path \"transit/hmac/{grant_key}/sha2-256\" {{ capabilities = [\"update\"] }}"
            ),
        )
        .await;
        let verify_token = token(
            client,
            base,
            root_token,
            &format!("sender-verify-{fixture_id}"),
            &format!(
                "path \"transit/verify/{grant_key}/sha2-256\" {{ capabilities = [\"update\"] }}"
            ),
        )
        .await;
        let envelope_token = token(client, base, root_token, &format!("sender-envelope-{fixture_id}"), &format!("path \"transit/keys/{envelope_key}\" {{ capabilities = [\"read\"] }}\npath \"transit/encrypt/{envelope_key}\" {{ capabilities = [\"update\"] }}\npath \"transit/decrypt/{envelope_key}\" {{ capabilities = [\"update\"] }}")).await;
        let mint_file = directory.join("credential-grant-openbao-token");
        let verify_file = directory.join("didcomm-grant-verify.token");
        std::fs::write(&mint_file, mint_token).unwrap();
        std::fs::write(&verify_file, verify_token).unwrap();
        let envelope_provider =
            OpenBaoEnvelopeProvider::new_with_ca(base, envelope_token, Some(kms_ca)).unwrap();
        let registry = RegistryStore::connect(redis_url)
            .await
            .unwrap()
            .with_auth_envelopes(Some(envelope_provider.clone()));
        let profiles = ProfileStore::from_connection(registry.connection());
        let documents = DocumentStore::from_connection(registry.connection());
        let service = json!({"id":"svc-a","name":"Existing issuer KMS","service_type":"openbao-transit","provider":"openbao","protocol":"vault-transit",
        "endpoint":base,"mount":"transit","auth_mode":"token","auth_reference":scoped_token,"ca_cert_file":kms_ca,
        "key_reference":signing_key,"credential_formats":["dc+sd-jwt"],"key_purposes":["vc_jwt_issuer"],"algorithms":["ES256"]});
        registry
            .save(
                tenant,
                &json!({"services":[service.clone()],"default_service_id":"svc-a"}),
            )
            .await
            .unwrap();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../signing-keys/tests/fixtures/issuer_profile_vectors.json"
        ))
        .unwrap();
        let mut profile = fixture["normalize"]["expected"].clone();
        profile["organization_id"] = json!(tenant);
        profile["issuer_did"] = json!(sender_did);
        profile["signing_key_reference"] = json!(signing_key);
        profiles.put(tenant, "ip-vector", profile).await.unwrap();
        let signing_jwk = public_key_existing(ProviderRequest {
            service_config: service.clone(),
        })
        .await
        .unwrap();
        documents
            .publish_did(
                tenant,
                "svc-a",
                PublishDidRequest {
                    jwk: signing_jwk,
                    public_domain: public_domain.clone(),
                    did_id: Some(sender_did.clone()),
                    org_slug: Some(slug.clone()),
                    fragment: Some("signing-1".into()),
                    key_reference: None,
                    cert_pem: None,
                    cert_chain_pem: None,
                    relationship: DidVerificationRelationship::AssertionMethod,
                },
            )
            .await
            .unwrap();
        let verifier = GrantVerifier::for_managed_openbao(
            base,
            verify_file,
            RedisGrantReplayStore::new(registry.connection()),
        )
        .unwrap();
        let app = marty_signing_keys::http::router_with_all_keys_and_grants(
            "test-internal-key".into(),
            None,
            Some(issuer_api_key.into()),
            integration_secret_api_key.map(str::to_owned),
            None,
            None,
            false,
            Some(registry.clone()),
            Some(documents.clone()),
            None,
            Some(profiles),
            Some(envelope_provider),
            Some(public_domain),
            Some(verifier),
        );
        let (url, ca_pem, server) = serve_signing_keys(app).await;
        let https = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let publication = json!({"organization_id":tenant,"issuer_did":sender_did,"key_purpose":"vc_jwt_issuer","credential_format":"SD_JWT_VC","algorithm":"ES256",
        "service_id":"svc-a","key_reference":reference,"public_jwk":{"kty":"OKP","crv":"X25519","x":sender_public}});
        let publication_url = format!(
            "{}/v1/signing-keys/issuer-identities/didcomm-key-agreement?organization_id={tenant}",
            url.origin().ascii_serialization()
        );
        let response = https
            .put(&publication_url)
            .json(&publication)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "publication status {}",
            response.status()
        );
        let response: Value = response.json().await.unwrap();
        assert_eq!(response["key_agreement_method_id"], sender_kid);
        let persisted = documents
            .load_did(
                tenant,
                LoadDidRequest {
                    did_id: Some(sender_did.clone()),
                    fallback_did: None,
                },
            )
            .await
            .unwrap();
        let sender_document: DidDocument =
            serde_json::from_value(persisted.document.clone()).unwrap();
        assert!(persisted.document["keyAgreement"]
            .as_array()
            .unwrap()
            .contains(&json!(sender_kid)));
        assert!(!persisted.document.to_string().contains(&reference));
        let sealed: String = registry
            .connection()
            .get(marty_signing_keys::registry::storage_key(tenant))
            .await
            .unwrap();
        assert!(!sealed.contains(&scoped_token));

        let recording = RecordingMinter {
            inner: GrantMinter::for_managed_openbao(
                base,
                SigningOrigin::IssuanceCredential,
                mint_file.clone(),
            )
            .unwrap(),
            issued: Arc::new(Mutex::new(Vec::new())),
        };
        let kms = RegisteredDidcommKms::new(
            url.clone(),
            Some(ca_pem.as_bytes()),
            issuer_api_key,
            Arc::new(recording.clone()),
        )
        .unwrap();
        let ca_file = directory.join("registered-signing-keys-ca.pem");
        std::fs::write(&ca_file, &ca_pem).unwrap();
        Self {
            registry,
            name,
            sender_kid,
            version,
            sender_public,
            reference,
            policy_name,
            extension_policy,
            scoped_token,
            mint_file,
            url,
            ca_pem,
            ca_file,
            https,
            publication,
            publication_url,
            sender_document,
            recording,
            kms,
            server,
        }
    }
}

async fn serve_signing_keys(app: Router) -> (reqwest::Url, String, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let ca = cert.cert.pem();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        ca.as_bytes().to_vec(),
        cert.signing_key.serialize_pem().into_bytes(),
    )
    .await
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    (
        reqwest::Url::parse(&format!("https://{address}/internal")).unwrap(),
        ca,
        server,
    )
}
