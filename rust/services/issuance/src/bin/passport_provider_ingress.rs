//! Default-off physical personalization-bureau ingress.

use std::{env, fs, net::SocketAddr, time::Duration};

use marty_issuance_service::{
    passport_provider_ingress::{router, ProviderIngressState},
    passport_repository::PostgresPassportRepository,
};
use marty_passport_auth::valid_provider_profile_id;
use reqwest::{redirect::Policy, Client, Url};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

struct Config {
    listen: SocketAddr,
    database_url: String,
    provider_profile_id: String,
    provider_hmac_key_version: u32,
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
        if !valid_provider_profile_id(&provider_profile_id) {
            return Err("invalid bureau provider profile ID");
        }
        if env::var_os("PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE").is_some()
            || env::var_os("PASSPORT_PROVIDER_WEBHOOK_SECRET").is_some()
            || env::var_os("PASSPORT_PROVIDER_HMAC_SOURCE_FILE").is_some()
        {
            return Err("local provider webhook-secret configuration is forbidden");
        }
        let provider_hmac_key_version = required("PASSPORT_PROVIDER_HMAC_KEY_VERSION")?
            .parse::<u32>()
            .map_err(|_| "provider HMAC key version is invalid")?;
        if provider_hmac_key_version == 0 {
            return Err("provider HMAC key version is invalid");
        }
        let signing_api_key =
            normalize_signer_key(read_secret("PASSPORT_PROVIDER_SIGNER_API_KEY_FILE")?)?;
        let signing_base_url = private_url(
            "PASSPORT_PROVIDER_SIGNER_URL",
            "passport-callback-signer-supported",
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
            provider_hmac_key_version,
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

fn private_url(name: &str, service: &str, path: &str) -> Result<Url, &'static str> {
    let value = required(name)?;
    private_url_from(&value, service, path)
}

fn private_url_from(value: &str, service: &str, path: &str) -> Result<Url, &'static str> {
    let url = Url::parse(value).map_err(|_| "invalid private passport URL")?;
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
        provider_hmac_key_version: config.provider_hmac_key_version,
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
            "http://passport-callback-signer-supported:8018/internal/documents",
            "passport-callback-signer-supported",
            "/internal/documents"
        )
        .is_ok());
        assert!(private_url_from(
            "https://passport-callback-signer-supported.marty-prod.svc.cluster.local/internal/documents",
            "passport-callback-signer-supported",
            "/internal/documents"
        )
        .is_ok());
        assert!(private_url_from(
            "https://public.example/internal/documents",
            "passport-callback-signer-supported",
            "/internal/documents"
        )
        .is_err());
        assert!(private_url_from(
            "https://passport-callback-signer-supported.foreign.svc.cluster.local/internal/documents",
            "passport-callback-signer-supported",
            "/internal/documents"
        )
        .is_err());
        assert!(private_url_from(
            "http://passport-callback-signer-supported:8018/public",
            "passport-callback-signer-supported",
            "/internal/documents"
        )
        .is_err());
        assert!(private_url_from(
            "http://passport-callback-signer:8018/internal/documents",
            "passport-callback-signer-supported",
            "/internal/documents"
        )
        .is_err());
    }

    #[test]
    fn signer_credential_is_normalized() {
        let key = "dedicated-ingress-signing-key-00000001";
        assert_eq!(
            normalize_signer_key(format!("{key}\r\n").into_bytes()).unwrap(),
            key
        );
        assert!(normalize_signer_key(b"short-key".to_vec()).is_err());
    }
}
