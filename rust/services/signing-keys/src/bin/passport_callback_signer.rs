use std::{env, fs, net::SocketAddr, path::Path};

use marty_signing_keys::{
    flow_envelope::OpenBaoEnvelopeProvider, passport_callback_hmac::isolated_signer_router,
};
use tokio::net::TcpListener;

fn required_configuration() -> Result<(SocketAddr, String, String, String), String> {
    if env::var("ENVIRONMENT").as_deref() != Ok("beta")
        || env::var("PASSPORT_CALLBACK_SIGNER_ENABLED").as_deref() != Ok("true")
    {
        return Err("isolated passport callback signer is beta-only and default-off".into());
    }
    if [
        "BAO_TOKEN",
        "OPENBAO_SERVICE_TOKEN",
        "OPENBAO_SERVICE_TOKEN_FILE",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some())
    {
        return Err("inline or shared OpenBao credentials are forbidden".into());
    }
    let key = env::var("SIGNING_KEYS_INTERNAL_API_KEY")
        .map_err(|_| "SIGNING_KEYS_INTERNAL_API_KEY is required")?;
    if key.starts_with("dev-") || key.len() < 16 {
        return Err("a non-development internal signing credential is required".into());
    }
    let token_path = env::var("BAO_TOKEN_FILE").map_err(|_| "BAO_TOKEN_FILE is required")?;
    if !Path::new(&token_path).is_absolute() {
        return Err("BAO_TOKEN_FILE must be absolute".into());
    }
    let token = fs::read_to_string(&token_path)
        .map_err(|_| "BAO_TOKEN_FILE is not a readable UTF-8 file")?;
    let token = token.trim_end_matches(['\r', '\n']).to_owned();
    if token.is_empty() || token == key {
        return Err("BAO_TOKEN_FILE contains an invalid scoped token".into());
    }
    let addr = env::var("BAO_ADDR").map_err(|_| "BAO_ADDR is required")?;
    let port = env::var("SIGNING_KEYS_SERVICE_PORT")
        .map_err(|_| "SIGNING_KEYS_SERVICE_PORT is required")?
        .parse::<u16>()
        .map_err(|_| "SIGNING_KEYS_SERVICE_PORT is invalid")?;
    if port == 0 {
        return Err("SIGNING_KEYS_SERVICE_PORT is invalid".into());
    }
    Ok((SocketAddr::from(([0, 0, 0, 0], port)), addr, token, key))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (addr, bao_addr, token, key) = required_configuration()?;
    let provider = OpenBaoEnvelopeProvider::new(bao_addr, token)?;
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, isolated_signer_router(provider, key)).await?;
    Ok(())
}
