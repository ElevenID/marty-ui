//! Canvas adapter for the shared real Signing Keys DIDComm acceptance fixture.
//! Redis remains exact-owned by the existing disposable runtime owner.
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_issuance_service::didcomm_kms::RegisteredDidcommKms;
use redis::AsyncCommands;

#[allow(dead_code)]
#[path = "../../../../services/issuance/tests/support/registered_didcomm_sender.rs"]
mod registered_didcomm_sender;
use registered_didcomm_sender::{RegisteredSenderFixture, SenderInputs};

pub(super) struct RemoteSenderFixture {
    pub(super) base_url: String,
    pub(super) ca_file: PathBuf,
    pub(super) public_key: String,
    pub(super) registered: RegisteredSenderFixture,
    redis: Option<super::base_runtime_redis::OwnedRedis>,
}

impl RemoteSenderFixture {
    pub(super) async fn create(directory: &Path, issuer_did: &str, tenant: &str) -> Self {
        Self::create_with_redis(directory, issuer_did, tenant, None).await
    }

    pub(super) async fn create_with_redis(
        directory: &Path,
        issuer_did: &str,
        tenant: &str,
        namespace_redis: Option<&str>,
    ) -> Self {
        let base_url = std::env::var("MARTY_CANVAS_OPENBAO_URL")
            .expect("Canvas DIDComm requires disposable plugin OpenBao URL");
        let url = url::Url::parse(&base_url).expect("OpenBao URL");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.port().is_some());
        assert_eq!(url.path(), "/");
        assert!(url.username().is_empty() && url.password().is_none());
        assert!(url.query().is_none() && url.fragment().is_none());
        let root = std::env::var("MARTY_CANVAS_OPENBAO_ROOT_TOKEN")
            .expect("Canvas DIDComm requires disposable plugin OpenBao root token");
        let ca_file = PathBuf::from(
            std::env::var("MARTY_CANVAS_OPENBAO_CA_CERT_FILE")
                .expect("Canvas DIDComm requires the disposable OpenBao public CA"),
        );
        let client = super::issuance_named_peers::canvas_openbao_client(&ca_file);
        let (redis, redis_url, nonce) = if let Some(base) = namespace_redis {
            assert_eq!(
                std::env::var("MARTY_BASE_RUNTIME_CHILD").as_deref(),
                Ok("1")
            );
            assert_eq!(
                std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
                Ok("1")
            );
            assert_eq!(base, "redis://127.0.0.1:6379");
            let nonce = std::env::var("MARTY_CANVAS_SIGNING_REDIS_NONCE")
                .expect("parent-owned namespace Redis sentinel");
            assert!(nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()));
            (None, format!("{base}/13"), nonce)
        } else {
            assert_ne!(
                std::env::var("MARTY_BASE_RUNTIME_CHILD").as_deref(),
                Ok("1"),
                "isolated child must reuse its parent's owned Redis"
            );
            let owned = super::base_runtime_redis::OwnedRedis::start()
                .await
                .unwrap();
            let nonce = owned.prepare_signing_keys_database().unwrap();
            let url = format!("{}/13", owned.url());
            (Some(owned), url, nonce)
        };
        let mut connection = redis::Client::open(redis_url.as_str())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let observed: String = connection
            .get("marty:tests:disposable-guard")
            .await
            .unwrap();
        assert_eq!(observed, nonce);
        let registered = RegisteredSenderFixture::create(SenderInputs {
            client: &client,
            base: &base_url,
            root_token: &root,
            kms_ca: &ca_file,
            redis_url: &redis_url,
            directory,
            tenant,
            sender_did: issuer_did,
            issuer_api_key: super::issuance_named_peers::ISSUER_SIGN_KEY,
            integration_secret_api_key: Some(super::issuance_named_peers::ENVELOPE_KEY),
        })
        .await;
        let public_key = registered.sender_public.clone();
        assert_eq!(URL_SAFE_NO_PAD.decode(&public_key).unwrap().len(), 32);
        Self {
            base_url,
            ca_file,
            public_key,
            registered,
            redis,
        }
    }

    pub(super) fn client(&self) -> RegisteredDidcommKms {
        self.registered.kms.clone()
    }
}

impl Drop for RemoteSenderFixture {
    fn drop(&mut self) {
        self.registered.shutdown();
        if let Some(redis) = self.redis.take() {
            if let Err(error) = redis.close_verified() {
                if std::thread::panicking() {
                    eprintln!("Canvas registered sender Redis cleanup failed: {error}");
                } else {
                    panic!("Canvas registered sender Redis cleanup failed: {error}");
                }
            }
        }
    }
}
