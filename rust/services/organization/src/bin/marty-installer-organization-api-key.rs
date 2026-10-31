//! Internal installer setup-job entrypoint. No HTTP endpoint or secret stdout.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [command] = arguments.as_slice() else {
        eprintln!("usage: marty-installer-organization-api-key issue|revoke");
        std::process::exit(2);
    };
    match marty_organization::installer_bootstrap::run(command).await {
        Ok(receipt) => match serde_json::to_string(&receipt) {
            Ok(public) => println!("{public}"),
            Err(_) => {
                eprintln!("installer organization credential receipt unavailable");
                std::process::exit(1);
            }
        },
        Err(error) => {
            // BootstrapError contains fixed classifications only.
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("installer organization credential setup requires Linux");
    std::process::exit(2);
}
