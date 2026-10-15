#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    marty_keyless_grpc_bridge::run_from_environment().await
}
