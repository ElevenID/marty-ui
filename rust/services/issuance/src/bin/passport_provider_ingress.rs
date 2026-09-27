//! Default-off physical personalization-bureau ingress.

use std::{env, fs, net::SocketAddr, time::Duration};

use marty_issuance_service::{
    passport_provider_ingress::{router, ProviderIngressState},
    passport_repository::PostgresPassportRepository,
};
use reqwest::{redirect::Policy, Client, Url};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

struct Config {
    listen: SocketAddr,
    database_url: String,
    provider_profile_id: String,
    webhook_secret: Vec<u8>,
    signing_base_url: Url,
    signing_api_key: String,
    native_callback_url: Url,
}

impl Config {
    fn from_env() -> Result<Self, &'static str> {
        if env::var("PASSPORT_PROVIDER_INGRESS_ENABLED").as_deref() != Ok("true") {
            return Err("passport provider ingress must be explicitly enabled");
        }
        let provider_profile_id = required("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID")?;
        if provider_profile_id.len() > 128 || provider_profile_id.trim() != provider_profile_id {
            return Err("invalid bureau provider profile ID");
        }
        let webhook_secret = read_secret("PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE")?;
        std::str::from_utf8(&webhook_secret).map_err(|_| "bureau webhook secret must be UTF-8")?;
        let signing_api_key =
            normalize_signer_key(read_secret("PASSPORT_PROVIDER_SIGNER_API_KEY_FILE")?)?;
        validate_credential_separation(&webhook_secret, &signing_api_key)?;
        let signing_base_url = private_url(
            "PASSPORT_PROVIDER_SIGNER_URL",
            "passport-callback-signer",
            "/internal/documents",
        )?;
        let native_callback_url = private_url(
            "PASSPORT_PROVIDER_NATIVE_CALLBACK_URL",
            "issuance-native",
            "/v1/passport/webhooks/personalization",
        )?;
        let database_url =
            required("DATABASE_URL")?.replacen("postgresql+asyncpg://", "postgresql://", 1);
        let listen = env::var("PASSPORT_PROVIDER_INGRESS_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:8021".into())
            .parse()
            .map_err(|_| "invalid provider ingress listen address")?;
        Ok(Self {
            listen,
            database_url,
            provider_profile_id,
            webhook_secret,
            signing_base_url,
            signing_api_key,
            native_callback_url,
        })
    }
}

fn required(name: &str) -> Result<String, &'static str> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or("provider ingress configuration is incomplete")
}

fn read_secret(name: &str) -> Result<Vec<u8>, &'static str> {
    let path = required(name)?;
    let bytes = fs::read(path).map_err(|_| "provider ingress secret file is unavailable")?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("provider ingress secret file is invalid");
    }
    Ok(bytes)
}

fn normalize_signer_key(bytes: Vec<u8>) -> Result<String, &'static str> {
    let value = String::from_utf8(bytes).map_err(|_| "signer API key must be UTF-8")?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.len() < 32
        || value.starts_with("dev-")
        || value.starts_with("CHANGE_ME")
        || value.trim() != value
    {
        return Err("signer API key is invalid");
    }
    Ok(value.to_owned())
}

fn validate_credential_separation(
    webhook_secret: &[u8],
    signing_api_key: &str,
) -> Result<(), &'static str> {
    let provider_secret =
        std::str::from_utf8(webhook_secret).map_err(|_| "bureau webhook secret must be UTF-8")?;
    if provider_secret.trim_end_matches(['\r', '\n']) == signing_api_key {
        return Err("provider webhook secret and signer API key must differ");
    }
    Ok(())
}

fn private_url(name: &str, service: &str, path: &str) -> Result<Url, &'static str> {
    let value = required(name)?;
    private_url_from(&value, service, path)
}

fn private_url_from(value: &str, service: &str, path: &str) -> Result<Url, &'static str> {
    let url = Url::parse(&value).map_err(|_| "invalid private passport URL")?;
    let host = url.host_str().ok_or("invalid private passport URL")?;
    let private_host = host == service
        || host == format!("{service}.marty-prod.svc.cluster.local")
        || matches!(host, "127.0.0.1" | "localhost" | "::1");
    if !matches!(url.scheme(), "http" | "https")
        || !private_host
        || url.path() != path
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid private passport URL");
    }
    Ok(url)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    let http = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .build()?;
    let state = ProviderIngressState {
        provider_profile_id: config.provider_profile_id,
        webhook_secret: config.webhook_secret,
        repository: PostgresPassportRepository::new(pool),
        signing_base_url: config.signing_base_url,
        signing_api_key: config.signing_api_key,
        native_callback_url: config.native_callback_url,
        http,
    };
    let listener = TcpListener::bind(config.listen).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_callback_urls_reject_public_signer_and_wrong_route() {
        assert!(private_url_from(
            "http://passport-callback-signer:8018/internal/documents",
            "passport-callback-signer",
            "/internal/documents"
        )
        .is_ok());
        assert!(private_url_from(
            "https://passport-callback-signer.marty-prod.svc.cluster.local/internal/documents",
            "passport-callback-signer",
            "/internal/documents"
        )
        .is_ok());
        assert!(private_url_from(
            "https://public.example/internal/documents",
            "passport-callback-signer",
            "/internal/documents"
        )
        .is_err());
        assert!(private_url_from(
            "https://passport-callback-signer.foreign.svc.cluster.local/internal/documents",
            "passport-callback-signer",
            "/internal/documents"
        )
        .is_err());
        assert!(private_url_from(
            "http://passport-callback-signer:8018/public",
            "passport-callback-signer",
            "/internal/documents"
        )
        .is_err());
    }

    #[test]
    fn signer_credential_is_normalized_and_separate_from_provider_secret() {
        let key = "dedicated-ingress-signing-key-00000001";
        assert_eq!(
            normalize_signer_key(format!("{key}\r\n").into_bytes()).unwrap(),
            key
        );
        assert!(validate_credential_separation(key.as_bytes(), key).is_err());
        assert!(validate_credential_separation(format!("{key}\n").as_bytes(), key).is_err());
        assert!(validate_credential_separation(b"different-provider-secret", key).is_ok());
        assert!(normalize_signer_key(b"short-key".to_vec()).is_err());
    }
}
