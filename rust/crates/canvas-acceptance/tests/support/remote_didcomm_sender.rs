//! Disposable OpenBao sender custody shared by Canvas DIDComm acceptance paths.
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_issuance_service::didcomm_remote_kms::{DidcommKeyReference, RemoteDidcommKms};
use serde_json::{json, Value};

pub(super) struct RemoteSenderFixture {
    pub(super) base_url: String,
    pub(super) token_file: PathBuf,
    pub(super) reference: String,
    pub(super) public_key: String,
}

impl RemoteSenderFixture {
    pub(super) async fn create(directory: &Path, issuer_did: &str, tenant: &str) -> Self {
        let base_url = std::env::var("MARTY_CANVAS_OPENBAO_URL")
            .expect("Canvas DIDComm requires disposable plugin OpenBao URL");
        let url = url::Url::parse(&base_url).expect("OpenBao URL");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.port().is_some());
        assert_eq!(url.path(), "/");
        assert!(url.username().is_empty() && url.password().is_none());
        assert!(url.query().is_none() && url.fragment().is_none());
        let root = std::env::var("MARTY_CANVAS_OPENBAO_ROOT_TOKEN")
            .expect("Canvas DIDComm requires disposable plugin OpenBao root token");
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let name = format!("canvas_{}", uuid::Uuid::new_v4().simple());
        let sender_key_id = format!("{issuer_did}#key-1");
        let created: Value = client
            .post(format!("{base_url}/v1/didcomm/keys/{tenant}/{name}"))
            .header("X-Vault-Token", &root)
            .json(&json!({"sender_did":issuer_did,"sender_key_id":sender_key_id}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let version = created["data"]["version"].as_str().unwrap();
        let public_key = created["data"]["public_key"].as_str().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(public_key).unwrap().len(), 32);
        let reference = format!("didcomm/keys/{tenant}/{name}/versions/{version}");
        DidcommKeyReference::parse(&reference).unwrap();
        let policy_name = format!("canvas-didcomm-{}", uuid::Uuid::new_v4().simple());
        let policy = format!(
            "path \"didcomm/keys/{tenant}/{name}/versions/{version}\" {{ capabilities = [\"read\"] }}\n\
             path \"didcomm/pack/{tenant}/{name}/{version}\" {{ capabilities = [\"update\"] }}"
        );
        client
            .put(format!("{base_url}/v1/sys/policies/acl/{policy_name}"))
            .header("X-Vault-Token", &root)
            .json(&json!({"policy":policy}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let issued: Value = client
            .post(format!("{base_url}/v1/auth/token/create"))
            .header("X-Vault-Token", &root)
            .json(&json!({"policies":[policy_name],"no_default_policy":true,"ttl":"1h"}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = issued["auth"]["client_token"].as_str().unwrap();
        let token_file = directory.join("didcomm-openbao-token");
        std::fs::write(&token_file, token).unwrap();
        Self {
            base_url,
            token_file,
            reference,
            public_key: public_key.to_owned(),
        }
    }

    pub(super) fn client(&self) -> RemoteDidcommKms {
        RemoteDidcommKms::new(&self.base_url, self.token_file.clone()).unwrap()
    }
}
