//! Shared schema and issuer-profile bootstrap before the notification migration.

#[tokio::main]
async fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments == ["--reference-json"] {
        use std::io::Read;
        let mut request = String::new();
        if let Err(error) = std::io::stdin().read_to_string(&mut request) {
            eprintln!("invalid reference input: {error}");
            std::process::exit(2);
        }
        let result = match serde_json::from_str(&request) {
            Ok(invocation) => marty_signing_keys::bootstrap_simulation::replay(&invocation).await,
            Err(error) => Err(error.to_string()),
        };
        match result {
            Ok(result) => {
                println!("{result}");
                return;
            }
            Err(error) => {
                eprintln!("invalid reference input: {error}");
                std::process::exit(2);
            }
        }
    }
    if arguments.iter().any(|argument| argument != "--verify-only") || arguments.len() > 1 {
        eprintln!("usage: marty-migration-bootstrap [--verify-only | --reference-json]");
        std::process::exit(2);
    }
    let verify_only = !arguments.is_empty();
    if let Err(error) = marty_signing_keys::bootstrap_runtime::run(verify_only).await {
        eprintln!("Marty migration bootstrap failed: {error}");
        std::process::exit(1);
    }
}
