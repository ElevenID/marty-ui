use marty_signing_keys::{
    config::Config, flow_envelope::OpenBaoEnvelopeProvider,
    passport_callback_hmac::isolated_signer_router,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("ENVIRONMENT").as_deref() != Ok("beta")
        || std::env::var("PASSPORT_CALLBACK_SIGNER_ENABLED").as_deref() != Ok("true")
    {
        return Err("isolated passport callback signer is beta-only and default-off".into());
    }
    let config = Config::from_env()?;
    if config.internal_api_key.starts_with("dev-") || config.internal_api_key.len() < 16 {
        return Err("a non-development internal signing credential is required".into());
    }
    let provider = OpenBaoEnvelopeProvider::new(
        config.bao_addr.ok_or("BAO_ADDR is required")?,
        config.bao_token.ok_or("BAO_TOKEN is required")?,
    )?;
    let listener = TcpListener::bind(config.http_addr).await?;
    axum::serve(
        listener,
        isolated_signer_router(provider, config.internal_api_key),
    )
    .await?;
    Ok(())
}
