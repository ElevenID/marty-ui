//! Isolated production-mode callback MAC service for a trusted provider ingress.
//! The beta signer has a separate binary and retains its beta-only startup guard.

use std::{env, fs, net::SocketAddr};

use marty_signing_keys::{
    flow_envelope::OpenBaoEnvelopeProvider,
    passport_callback_hmac::isolated_supported_signer_router,
};
use tokio::net::TcpListener;

fn required_file(name: &str) -> Result<String, String> {
    let path = env::var(format!("{name}_FILE")).map_err(|_| format!("{name}_FILE is required"))?;
    if path.is_empty() || env::var_os(name).is_some() {
        return Err(format!("{name} must be supplied only by file"));
    }
    let value = fs::read_to_string(path)
        .map_err(|_| format!("{name}_FILE is not a readable UTF-8 file"))?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.starts_with("dev-") || value.starts_with("CHANGE_ME") {
        return Err(format!("{name}_FILE contains an invalid credential"));
    }
    Ok(value.to_owned())
}

fn required_configuration() -> Result<(SocketAddr, String, String, String), String> {
    if env::var("ENVIRONMENT").as_deref() != Ok("production")
        || env::var("PASSPORT_SUPPORTED_CALLBACK_SIGNER_ENABLED").as_deref() != Ok("true")
    {
        return Err("supported callback signer is production-mode and default-off".into());
    }
    if env::var_os("BAO_TOKEN").is_some()
        || env::var_os("BAO_TOKEN_FILE").is_some()
        || env::var_os("OPENBAO_SERVICE_TOKEN").is_some()
        || env::var_os("OPENBAO_SERVICE_TOKEN_FILE").is_some()
    {
        return Err("ordinary OpenBao service credentials are forbidden".into());
    }
    let key = required_file("PASSPORT_CALLBACK_SIGNER_API_KEY")?;
    if key.len() < 32 {
        return Err(
            "PASSPORT_CALLBACK_SIGNER_API_KEY_FILE must contain at least 32 characters".into(),
        );
    }
    let token = required_file("PASSPORT_CALLBACK_SIGNER_BAO_TOKEN")?;
    if token == key {
        return Err("callback signer API key and OpenBao token must differ".into());
    }
    for ordinary_key in [
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        "ISSUANCE_API_KEY",
        "ISSUANCE_API_KEY_FILE",
        "PASSPORT_PROVIDER_WEBHOOK_SECRET",
        "PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE",
        "PASSPORT_PROVIDER_HMAC_SOURCE_FILE",
    ] {
        if env::var_os(ordinary_key).is_some() {
            return Err("ordinary service credentials are forbidden on callback signer".into());
        }
    }
    let addr = env::var("PASSPORT_CALLBACK_SIGNER_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8018".into())
        .parse::<SocketAddr>()
        .map_err(|_| "PASSPORT_CALLBACK_SIGNER_BIND is invalid".to_string())?;
    let bao_addr = env::var("BAO_ADDR").map_err(|_| "BAO_ADDR is required".to_string())?;
    Ok((addr, bao_addr, token, key))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (addr, bao_addr, token, key) = required_configuration()?;
    let provider = OpenBaoEnvelopeProvider::new(bao_addr, token)?;
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, isolated_supported_signer_router(provider, key)).await?;
    Ok(())
}
