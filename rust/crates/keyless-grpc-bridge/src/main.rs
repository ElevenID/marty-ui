#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    marty_service_runtime::install_tls_crypto_provider();
    marty_keyless_grpc_bridge::run_from_environment().await
}
