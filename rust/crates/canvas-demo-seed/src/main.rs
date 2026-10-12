use marty_canvas_demo_seed::{build_run_config, run_seed, transition_display_lines};
use std::{collections::HashMap, env, fs, path::Path};

fn load_env_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.is_empty() && env::var_os(key).is_none() {
            env::set_var(key, value.trim().trim_matches(['\'', '"']));
        }
    }
    Ok(())
}

fn usage() {
    println!("Seed real Canvas LMS + ElevenID Canvas platform\nUsage: marty-canvas-demo-seed [--env-file PATH] [--skip-canvas-lms-seed] [--probe-after-upsert]");
}

#[tokio::main]
async fn main() {
    let mut args = env::args().skip(1);
    let mut env_file = String::from(".env.tunnel.beta.local");
    let mut skip_canvas_lms_seed = false;
    let mut probe_after_upsert = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--env-file" => match args.next() {
                Some(value) => env_file = value,
                None => {
                    eprintln!("--env-file requires a path");
                    std::process::exit(2)
                }
            },
            "--skip-canvas-lms-seed" => skip_canvas_lms_seed = true,
            "--probe-after-upsert" => probe_after_upsert = true,
            "-h" | "--help" => {
                usage();
                return;
            }
            _ => {
                eprintln!("unexpected argument: {arg}");
                std::process::exit(2)
            }
        }
    }
    if let Err(error) = load_env_file(Path::new(&env_file)) {
        eprintln!("ERROR: cannot read Canvas seed environment: {error}");
        std::process::exit(2);
    }
    let variables: HashMap<String, String> = env::vars().collect();
    let config = match build_run_config(&variables, skip_canvas_lms_seed, probe_after_upsert) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::exit(2)
        }
    };
    let database_url = match marty_demo_vendor_seed::database_url() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("ERROR: Canvas database configuration failed: {error}");
            std::process::exit(2)
        }
    };
    match run_seed(&config, &variables, &database_url).await {
        Ok(report) => {
            println!("Canvas platform: {}", report["platform"]["id"]);
            if report["canvas_lms"].is_object() {
                println!("Canvas course: {}", report["canvas_lms"]["course"]["id"]);
                println!("Canvas learner: {}", report["canvas_lms"]["learner"]["id"]);
            }
            if report["binding"].is_object() {
                println!("Program binding: {}", report["binding"]["id"]);
            }
            if report["application"].is_object() {
                println!("Demo application: {}", report["application"]["id"]);
            }
            if report["wallet"].is_object() {
                println!(
                    "OID4VCI credential claimed for transaction: {}",
                    report["wallet"]["transaction_id"]
                );
            }
            if report["mirror"].is_object() {
                println!(
                    "Canvas mirror cycle: {} processed",
                    report["mirror"]["processed_count"]
                );
            }
            if report["transition"].is_object() {
                for line in
                    transition_display_lines(&report["transition"], &config.connector, &variables)
                {
                    println!("{line}");
                }
            }
            if let Some(warnings) = report["warnings"].as_array() {
                for warning in warnings {
                    eprintln!("WARN: {}", warning.as_str().unwrap_or("unknown warning"));
                }
            }
        }
        Err(error) => {
            eprintln!("ERROR: Canvas seed failed: {error}");
            std::process::exit(3)
        }
    }
}
