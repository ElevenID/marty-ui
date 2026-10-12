//! OpenBao DIDComm authcrypt client. The issuer receives only public key
//! metadata and complete JWEs; sender private keys remain in the plugin.

use std::{fmt, fs::File, io::Read, path::PathBuf, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::{redirect::Policy, Client, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

const MAX_TOKEN_BYTES: u64 = 4_096;
const MAX_JWE_BYTES: usize = 2 * 1024 * 1024;
const MAX_METADATA_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_PACK_RESPONSE_BYTES: usize = MAX_JWE_BYTES + 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidcommKeyReference {
    tenant: String,
    name: String,
    version: String,
}

impl DidcommKeyReference {
    pub fn parse(value: &str) -> Result<Self, RemoteDidcommKmsError> {
        let parts: Vec<_> = value.split('/').collect();
        if parts.len() != 6 || parts[0] != "didcomm" || parts[1] != "keys" || parts[4] != "versions"
        {
            return Err(RemoteDidcommKmsError::InvalidReference);
        }
        let (tenant, name, version) = (parts[2], parts[3], parts[5]);
        if !valid_name(tenant) || !valid_name(name) || !valid_version(version) {
            return Err(RemoteDidcommKmsError::InvalidReference);
        }
        Ok(Self {
            tenant: tenant.to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
        })
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    fn public_path(&self) -> String {
        format!(
            "v1/didcomm/keys/{}/{}/versions/{}",
            self.tenant, self.name, self.version
        )
    }

    fn pack_path(&self) -> String {
        format!(
            "v1/didcomm/pack/{}/{}/{}",
            self.tenant, self.name, self.version
        )
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_version(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone)]
pub struct RemoteDidcommKms {
    base_url: Url,
    token_file: PathBuf,
    client: Client,
}

impl fmt::Debug for RemoteDidcommKms {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteDidcommKms")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum RemoteDidcommKmsError {
    #[error("invalid DIDComm KMS reference")]
    InvalidReference,
    #[error("invalid DIDComm KMS configuration")]
    InvalidConfiguration,
    #[error("DIDComm KMS token is unavailable")]
    TokenUnavailable,
    #[error("DIDComm KMS operation failed")]
    OperationFailed,
    #[error("DIDComm KMS returned mismatched key metadata")]
    BindingMismatch,
}

#[derive(Deserialize)]
struct BaoResponse<T> {
    data: T,
}

#[derive(Deserialize)]
struct PublicMetadata {
    tenant: String,
    name: String,
    version: String,
    sender_did: String,
    sender_key_id: String,
    public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSenderPublic {
    pub sender_key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Serialize)]
struct PackRequest<'a> {
    recipient_did: &'a str,
    recipients: String,
    plaintext_base64: String,
}

#[derive(Deserialize)]
struct PackResponse {
    jwe: String,
    version: String,
    sender_key_id: String,
}

async fn bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<T, RemoteDidcommKmsError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RemoteDidcommKmsError::OperationFailed)?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| RemoteDidcommKmsError::OperationFailed)
}

impl RemoteDidcommKms {
    pub fn new(base_url: &str, token_file: PathBuf) -> Result<Self, RemoteDidcommKmsError> {
        let url = Url::parse(base_url).map_err(|_| RemoteDidcommKmsError::InvalidConfiguration)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(RemoteDidcommKmsError::InvalidConfiguration);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| RemoteDidcommKmsError::InvalidConfiguration)?;
        Ok(Self {
            base_url: url,
            token_file,
            client,
        })
    }

    fn token(&self) -> Result<String, RemoteDidcommKmsError> {
        let file =
            File::open(&self.token_file).map_err(|_| RemoteDidcommKmsError::TokenUnavailable)?;
        let mut data = Vec::new();
        file.take(MAX_TOKEN_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| RemoteDidcommKmsError::TokenUnavailable)?;
        if data.is_empty() || data.len() as u64 > MAX_TOKEN_BYTES {
            return Err(RemoteDidcommKmsError::TokenUnavailable);
        }
        let token = String::from_utf8(data).map_err(|_| RemoteDidcommKmsError::TokenUnavailable)?;
        let token = token.trim_end_matches(['\r', '\n']);
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(RemoteDidcommKmsError::TokenUnavailable);
        }
        Ok(token.to_owned())
    }

    pub async fn public_key(
        &self,
        reference: &DidcommKeyReference,
        expected_sender_did: &str,
    ) -> Result<RemoteSenderPublic, RemoteDidcommKmsError> {
        let url = self
            .base_url
            .join(&reference.public_path())
            .map_err(|_| RemoteDidcommKmsError::InvalidReference)?;
        let response = self
            .client
            .get(url)
            .header("X-Vault-Token", self.token()?)
            .send()
            .await
            .map_err(|_| RemoteDidcommKmsError::OperationFailed)?;
        if !response.status().is_success() {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        let metadata: BaoResponse<PublicMetadata> =
            bounded_json(response, MAX_METADATA_RESPONSE_BYTES).await?;
        let data = metadata.data;
        let public = URL_SAFE_NO_PAD
            .decode(&data.public_key)
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        let public_key: [u8; 32] = public
            .try_into()
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        if data.tenant != reference.tenant
            || data.name != reference.name
            || data.version != reference.version
            || data.sender_did != expected_sender_did
            || !data
                .sender_key_id
                .starts_with(&format!("{expected_sender_did}#"))
        {
            return Err(RemoteDidcommKmsError::BindingMismatch);
        }
        Ok(RemoteSenderPublic {
            sender_key_id: data.sender_key_id,
            public_key,
        })
    }

    pub async fn pack(
        &self,
        reference: &DidcommKeyReference,
        sender_key_id: &str,
        recipient_did: &str,
        recipients: &[RemoteRecipientPublic],
        plaintext: &str,
    ) -> Result<String, RemoteDidcommKmsError> {
        if recipients.is_empty() || recipients.len() > 32 || plaintext.len() > 1 << 20 {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        let url = self
            .base_url
            .join(&reference.pack_path())
            .map_err(|_| RemoteDidcommKmsError::InvalidReference)?;
        let request = PackRequest {
            recipient_did,
            recipients: serde_json::to_string(recipients)
                .map_err(|_| RemoteDidcommKmsError::OperationFailed)?,
            plaintext_base64: base64::engine::general_purpose::STANDARD.encode(plaintext),
        };
        let response = self
            .client
            .post(url)
            .header("X-Vault-Token", self.token()?)
            .json(&request)
            .send()
            .await
            .map_err(|_| RemoteDidcommKmsError::OperationFailed)?;
        if !response.status().is_success() {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        let body: BaoResponse<PackResponse> =
            bounded_json(response, MAX_PACK_RESPONSE_BYTES).await?;
        if body.data.version != reference.version
            || body.data.sender_key_id != sender_key_id
            || body.data.jwe.is_empty()
            || body.data.jwe.len() > MAX_JWE_BYTES
        {
            return Err(RemoteDidcommKmsError::BindingMismatch);
        }
        Ok(body.data.jwe)
    }
}

#[cfg(test)]
mod tests {
    use super::{DidcommKeyReference, RemoteDidcommKms};

    #[test]
    fn reference_requires_exact_tenant_name_and_opaque_version() {
        let valid = "didcomm/keys/organization-1/sender/versions/0123456789abcdef0123456789abcdef";
        let reference = DidcommKeyReference::parse(valid).unwrap();
        assert_eq!(reference.tenant(), "organization-1");
        assert_eq!(reference.version(), "0123456789abcdef0123456789abcdef");
        for invalid in [
            "didcomm/keys/../sender/versions/0123456789abcdef0123456789abcdef",
            "didcomm/keys/org/sender/versions/1",
            "didcomm/keys/org/sender/versions/0123456789ABCDEF0123456789ABCDEF",
            "didcomm/keys/org/sender/versions/0123456789abcdef0123456789abcdef/extra",
            "transit/keys/org/sender/versions/0123456789abcdef0123456789abcdef",
        ] {
            assert!(DidcommKeyReference::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn kms_url_rejects_credentials_paths_and_redirect_targets() {
        let token_file = std::path::PathBuf::from("/not-read-in-constructor");
        for url in [
            "http://user:password@localhost:8200",
            "https://example.org/other/path",
            "https://example.org/?query=1",
            "file:///tmp/openbao",
        ] {
            assert!(RemoteDidcommKms::new(url, token_file.clone()).is_err());
        }
    }
}
