use marty_canvas_demo_seed::{build_run_config, run_seed, transition_display_lines};
use serde_json::Value;
use std::{collections::HashMap, env, fs, path::Path};

fn show(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "None".into(),
        other => other.to_string(),
    }
}

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
            println!("Canvas LTI 1.3 setup summary");
            println!("Canvas platform: {}", show(&report["platform"]["id"]));
            println!(
                "  account: {}",
                show(&report["platform"]["canvas_account_id"])
            );
            println!("  issuer: {}", show(&report["platform"]["lti_issuer"]));
            println!(
                "  organization: {}",
                show(&report["platform"]["organization_id"])
            );
            println!(
                "  Canvas base URL: {}",
                show(&report["platform"]["canvas_base_url"])
            );
            println!(
                "  LTI client ID: {}",
                show(&report["platform"]["lti_client_id"])
            );
            println!(
                "  LTI deployment ID: {}",
                show(&report["platform"]["lti_deployment_id"])
            );
            println!("  JWKS refreshed: {}", show(&report["jwks_refreshed"]));
            println!("  JWKS URL: {}", show(&report["platform"]["lti_jwks_url"]));
            println!(
                "  JWKS key count: {}",
                report["platform"]["lti_jwks_json"]["keys"]
                    .as_array()
                    .map_or(0, Vec::len)
            );
            if report["canvas_lms"].is_object() {
                let lms = &report["canvas_lms"];
                println!("Canvas LMS configured:");
                println!(
                    "  public domain: {} ({})",
                    show(&lms["public_domain"]["domain"]),
                    show(&lms["public_domain"]["action"])
                );
                println!(
                    "  developer key: {} ({})",
                    show(&lms["developer_key"]["id"]),
                    show(&lms["developer_key"]["action"])
                );
                println!("  client ID: {}", show(&lms["developer_key"]["client_id"]));
                println!(
                    "  developer key name: {}",
                    show(&lms["developer_key"]["name"])
                );
                println!(
                    "  owner binding: {} ({})",
                    show(&lms["developer_key"]["owner_binding_account_id"]),
                    show(&lms["developer_key"]["owner_binding_workflow_state"])
                );
                println!(
                    "  account binding: {} ({})",
                    show(&lms["developer_key"]["requested_binding_account_id"]),
                    show(&lms["developer_key"]["requested_binding_workflow_state"])
                );
                println!(
                    "  course: {} ({})",
                    show(&lms["course"]["name"]),
                    show(&lms["course"]["id"])
                );
                println!(
                    "  learner: {} ({})",
                    show(&lms["learner"]["name"]),
                    show(&lms["learner"]["id"])
                );
                println!(
                    "  external tool: {} ({})",
                    show(&lms["external_tool"]["id"]),
                    show(&lms["external_tool"]["action"])
                );
                println!(
                    "  tool deployment ID: {}",
                    show(&lms["external_tool"]["deployment_id"])
                );
                if lms["launch_surface"].is_object() {
                    println!(
                        "  launch module: {} ({})",
                        show(&lms["launch_surface"]["module"]["name"]),
                        show(&lms["launch_surface"]["module"]["id"])
                    );
                    println!(
                        "  launch item: {} ({})",
                        show(&lms["launch_surface"]["module_item"]["title"]),
                        show(&lms["launch_surface"]["module_item"]["id"])
                    );
                    if lms["launch_surface"]["assignment"].is_object() {
                        println!(
                            "  assignment: {} ({})",
                            show(&lms["launch_surface"]["assignment"]["name"]),
                            show(&lms["launch_surface"]["assignment"]["id"])
                        );
                    } else if lms["launch_surface"]["assignment_error"].is_string() {
                        println!(
                            "  assignment: {}",
                            show(&lms["launch_surface"]["assignment_error"])
                        );
                    }
                }
                if lms["quiz"].is_object() {
                    println!(
                        "  quiz: {} ({})",
                        show(&lms["quiz"]["title"]),
                        show(&lms["quiz"]["id"])
                    );
                    if lms["quiz"]["error"].is_string() {
                        println!("  quiz warning: {}", show(&lms["quiz"]["error"]));
                    }
                }
                println!(
                    "Next: log into {}, open '{}', and launch '{}'.",
                    config.canvas.browser_base_url,
                    config.canvas.course_name,
                    config.canvas.launch_item_title
                );
            } else if config.canvas.enabled {
                println!("WARN: Canvas LMS seeding did not complete; fix the warning and rerun.");
            } else {
                println!("Canvas LMS seeding skipped; rerun without --skip-canvas-lms-seed to bootstrap Canvas.");
            }
            if report["binding"].is_object() {
                println!("Program binding: {}", show(&report["binding"]["id"]));
                println!(
                    "  delivery mode: {}",
                    show(&report["binding"]["delivery_mode"])
                );
                println!("  evidence scope: {}", report["canvas_scope"]);
                println!(
                    "  application template: {}",
                    show(&report["binding"]["application_template_id"])
                );
                println!(
                    "  credential template: {}",
                    show(&report["binding"]["credential_template_id"])
                );
                println!(
                    "  evidence type: {}",
                    config.connector.program_binding_evidence_type
                );
            }
            if report["issuer_context"].is_object() {
                println!(
                    "Issuer profile: {}",
                    show(&report["issuer_context"]["issuer_profile_id"])
                );
                println!("  DID: {}", show(&report["issuer_context"]["issuer_did"]));
                println!(
                    "  signing service: {}",
                    show(&report["issuer_context"]["signing_service_id"])
                );
                println!(
                    "  signing key reference: {}",
                    show(&report["issuer_context"]["signing_key_reference"])
                );
            }
            if report["application"].is_object() {
                println!(
                    "Demo application: {} ({})",
                    show(&report["application"]["id"]),
                    show(&report["application"]["status"])
                );
            }
            if report["evidence"].is_object() {
                println!(
                    "Canvas AGS evidence: {}",
                    show(&report["evidence"]["application_status"])
                );
                println!(
                    "  policy allowed: {}",
                    show(&report["evidence"]["policy_decision"]["allowed"])
                );
            }
            if report["wallet"].is_object() {
                println!(
                    "OID4VCI credential claimed for transaction: {}",
                    show(&report["wallet"]["transaction_id"])
                );
                println!(
                    "  credential format: {}",
                    show(&report["wallet"]["credential_format"])
                );
                println!(
                    "  credential size: {}",
                    show(&report["wallet"]["credential_size"])
                );
                println!(
                    "  credential SHA-256: {}",
                    show(&report["wallet"]["credential_hash"])
                );
            }
            if report["mirror"].is_object() {
                println!(
                    "Canvas mirror cycle: {} processed",
                    show(&report["mirror"]["processed_count"])
                );
                let publish = if report["mirror"]["publish"].is_object() {
                    &report["mirror"]["publish"]
                } else {
                    &report["mirror"]
                };
                println!("  delivered: {}", show(&publish["delivered_count"]));
                println!("  failed: {}", show(&report["mirror"]["failed_count"]));
                println!("  blocked: {}", show(&report["mirror"]["blocked_count"]));
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
