use marty_demo_vendor_seed::{
    database_url, normalize_profile, persistent_profile, seed, ORGANIZATION_ID,
};
use std::{env, fs, path::Path};

fn load_env_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if !key.is_empty() && env::var_os(key).is_none() {
                env::set_var(key, value.trim().trim_matches(['\'', '"']));
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let mut args = env::args().skip(1);
    let mut env_file = String::from(".env.tunnel.beta.local");
    let mut force = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--env-file" => match args.next() {
                Some(value) => env_file = value,
                None => {
                    eprintln!("--env-file requires a path");
                    std::process::exit(2);
                }
            },
            "--force" => force = true,
            "-h" | "--help" => {
                println!("Seed reset-friendly demo vendor org/catalog/template fixtures\nUsage: marty-demo-vendor-seed [--env-file PATH] [--force]");
                return;
            }
            _ => {
                eprintln!("unexpected argument: {arg}");
                std::process::exit(2);
            }
        }
    }
    if let Err(error) = load_env_file(Path::new(&env_file)) {
        eprintln!("ERROR: cannot read seed environment: {error}");
        std::process::exit(2);
    }
    let profile = normalize_profile(&env::var("MARTY_MIGRATION_PROFILE").unwrap_or_default());
    if persistent_profile(&profile) && !force {
        eprintln!("ERROR: demo vendor fixtures are intended for reset-friendly profiles only. Refusing to run against persistent profile '{profile}'. Use --force to override.");
        std::process::exit(2);
    }
    println!("==> Seeding demo vendor fixtures (profile: {profile})");
    let url = match database_url() {
        Ok(url) => url,
        Err(error) => {
            eprintln!("ERROR: demo vendor seed failed: {error}");
            std::process::exit(1);
        }
    };
    match seed(&url).await {
        Ok(summary) => {
            println!("  ✓ Organization upserted: {ORGANIZATION_ID}");
            println!(
                "  ✓ Credential types seeded: {}",
                summary.credential_types_seeded
            );
            println!(
                "  ✓ Credential templates seeded: {}",
                summary.credential_templates_seeded
            );
            println!(
                "  ✓ Wallet configs applied: {}",
                if summary.wallet_configs_applied {
                    "True"
                } else {
                    "False"
                }
            );
            println!("Done.");
        }
        Err(error) => {
            eprintln!("ERROR: demo vendor seed failed: {error}");
            std::process::exit(1);
        }
    }
}
