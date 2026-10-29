use marty_deployment_catalog::Catalog;
use serde_json::Value;
use std::env;
use std::path::PathBuf;

fn value_strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn value_string<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn root_from_executable() -> Result<PathBuf, String> {
    if let Ok(root) = env::var("MARTY_REPO_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    for parent in exe.ancestors() {
        if parent.join("deploy-config/catalog/services.json").exists() {
            return Ok(parent.to_path_buf());
        }
    }
    Err("Cannot find repository root; pass --repo-root".to_owned())
}

fn positional<'a>(args: &'a [String], options_with_value: &[&str]) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if options_with_value.contains(&arg.as_str()) {
            skip = true;
            continue;
        }
        if !arg.starts_with('-') {
            result.push(arg.as_str());
        }
    }
    result
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut result = None;
    for (index, arg) in args.iter().enumerate() {
        if arg == name {
            result = args.get(index + 1).map(String::as_str);
        } else if let Some(value) = arg
            .strip_prefix(name)
            .and_then(|tail| tail.strip_prefix('='))
        {
            result = Some(value);
        }
    }
    result
}

fn required<'a>(args: &'a [&str], position: usize, label: &str) -> Result<&'a str, String> {
    args.get(position)
        .copied()
        .ok_or_else(|| format!("{label} is required"))
}

const TOP_USAGE: &str = "usage: marty-deploy.py [-h] [--repo-root REPO_ROOT]\n                       {validate,plan,services,secrets,compose-command,bundle-assets}\n                       ...\n";
const SERVICE_FIELDS: &[&str] = &[
    "id",
    "compose_service",
    "k8s_deployment",
    "image_name",
    "service_name_env",
    "group",
    "lifecycle",
];
const SECRET_FIELDS: &[&str] = &[
    "id",
    "env",
    "file_env",
    "compose_secret",
    "no_log",
    "allow_empty",
    "required_for",
];

fn usage_error(usage: &str, context: &str, message: &str) -> String {
    format!("__USAGE__{usage}{context}: error: {message}\n")
}

fn frozen_help(command: &str) -> String {
    let help: Value = serde_json::from_str(include_str!(
        "../../../../contracts/deployment-catalog-cli-help.json"
    ))
    .expect("frozen deployment CLI help must be valid JSON");
    help.get(command)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn command_usage(command: &str) -> String {
    format!(
        "{}\n",
        frozen_help(command)
            .split("\n\n")
            .next()
            .unwrap_or_default()
    )
}

fn check_options(command: &str, params: &[String]) -> Result<(), String> {
    let (flags, valued): (&[&str], &[&str]) = match command {
        "validate" | "bundle-assets" => (&[], &[]),
        "plan" | "compose-command" => (&["--json"], &[]),
        "services" => (
            &["--running-only", "--include-optional"],
            &["--group", "--field"],
        ),
        "secrets" => (&[], &["--field"]),
        _ => (&[], &[]),
    };
    let mut unknown = Vec::new();
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < params.len() {
        let arg = &params[index];
        if valued.contains(&arg.as_str()) {
            if index + 1 == params.len() || params[index + 1].starts_with('-') {
                return Err(usage_error(
                    &command_usage(command),
                    &format!("marty-deploy.py {command}"),
                    &format!("argument {arg}: expected one argument"),
                ));
            }
            index += 2;
            continue;
        }
        if let Some((name, _value)) = arg.split_once('=') {
            if valued.contains(&name) {
                index += 1;
                continue;
            }
        }
        if arg.starts_with('-') && !flags.contains(&arg.as_str()) {
            unknown.push(arg.clone());
        } else if !arg.starts_with('-') {
            positionals.push(arg.clone());
        }
        index += 1;
    }
    let maximum = match command {
        "validate" => 0,
        "compose-command" => 2,
        "plan" | "services" | "secrets" | "bundle-assets" => 1,
        _ => 0,
    };
    unknown.extend(positionals.iter().skip(maximum).cloned());
    if !unknown.is_empty() {
        return Err(usage_error(
            TOP_USAGE,
            "marty-deploy.py",
            &format!("unrecognized arguments: {}", unknown.join(" ")),
        ));
    }
    let required = match command {
        "plan" | "secrets" => &["stack"][..],
        "compose-command" => &["stack", "operation"][..],
        "bundle-assets" => &["bundle"][..],
        _ => &[][..],
    };
    if positionals.len() < required.len() {
        return Err(usage_error(
            &command_usage(command),
            &format!("marty-deploy.py {command}"),
            &format!(
                "the following arguments are required: {}",
                required[positionals.len()..].join(", ")
            ),
        ));
    }
    if let Some(field) = option(params, "--field") {
        let (choices, usage, context) = match command {
            "services" => (SERVICE_FIELDS, "usage: marty-deploy.py services [-h] [--group GROUP] [--running-only]\n                                [--include-optional]\n                                [--field {id,compose_service,k8s_deployment,image_name,service_name_env,group,lifecycle}]\n                                [stack]\n", "marty-deploy.py services"),
            "secrets" => (SECRET_FIELDS, "usage: marty-deploy.py secrets [-h]\n                               [--field {id,env,file_env,compose_secret,no_log,allow_empty,required_for}]\n                               stack\n", "marty-deploy.py secrets"),
            _ => return Ok(()),
        };
        if !choices.contains(&field) {
            return Err(usage_error(
                usage,
                context,
                &format!(
                    "argument --field: invalid choice: '{field}' (choose from {})",
                    choices.join(", ")
                ),
            ));
        }
    }
    Ok(())
}

fn print_plan(plan: &Value) {
    println!("Stack: {}", value_string(plan, "name"));
    if !value_string(plan, "description").is_empty() {
        println!("Description: {}", value_string(plan, "description"));
    }
    println!("Env file: {}", value_string(plan, "env_file"));
    println!(
        "Compose files: {}",
        value_strings(plan, "compose_files").join(", ")
    );
    let profiles = value_strings(plan, "compose_profiles");
    println!(
        "Compose profiles: {}",
        if profiles.is_empty() {
            "<none>".to_owned()
        } else {
            profiles.join(", ")
        }
    );
    println!("Domains: {}", value_strings(plan, "domains").join(", "));
    println!(
        "Artifact profile: {}",
        value_string(plan, "artifact_profile")
    );
    println!(
        "Deployment targets: {}",
        value_strings(plan, "deployment_targets").join(", ")
    );
    for (label, key) in [
        ("Required services:", "required_services"),
        ("Running services checked for health:", "running_services"),
        (
            "Required secret names (values redacted):",
            "required_secret_names",
        ),
    ] {
        println!("{label}");
        for value in value_strings(plan, key) {
            println!("  - {value}");
        }
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg == "installer-rootless-canary-helper")
    {
        #[cfg(target_os = "linux")]
        return marty_deployment_catalog::installer_rootless_canary_helper::run(&args[1..]);
        #[cfg(not(target_os = "linux"))]
        return Err("internal rootless canary helper requires Linux".into());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "restore-rootless-canary")
    {
        if args.len() != 5 || args[1] != "--installation" || args[3] != "--docker-bin" {
            return Err(
                "rootless canary restore requires exact installation and Docker executable".into(),
            );
        }
        #[cfg(target_os = "linux")]
        return marty_deployment_catalog::installer_rootless_storage_canary::restore_interrupted(
            &PathBuf::from(&args[2]),
            &PathBuf::from(&args[4]),
        );
        #[cfg(not(target_os = "linux"))]
        return Err("rootless canary restore requires Linux".into());
    }
    if args.first().is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "installer-generation-provision" | "installer-generation-provision-transfer"
        )
    }) {
        if args.len() != 3 || args[1] != "--installation-id" {
            return Err(
                "internal generation provisioning requires an owned container invocation".into(),
            );
        }
        #[cfg(target_os = "linux")]
        {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|_| "cannot start generation provisioning runtime")?;
            let count = if args[0] == "installer-generation-provision-transfer" {
                runtime.block_on(
                    marty_deployment_catalog::installer_generation::provision_transfer(&args[2]),
                )?
            } else {
                runtime.block_on(marty_deployment_catalog::installer_generation::provision(
                    &args[2],
                ))?
            };
            println!("{}", serde_json::json!({"outputs_written":count}));
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("internal generation provisioning requires Linux".into());
    }
    if args.first().is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "installer-renewal-bootstrap" | "installer-renewal-bootstrap-transfer"
        )
    }) {
        if args.len() != 3 || args[1] != "--installation-id" {
            return Err("internal renewal bootstrap requires an owned container invocation".into());
        }
        #[cfg(target_os = "linux")]
        {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|_| "cannot start renewal bootstrap runtime")?;
            let count = if args[0] == "installer-renewal-bootstrap-transfer" {
                runtime.block_on(
                    marty_deployment_catalog::installer_renewal_bootstrap::bootstrap_transfer(
                        &args[2],
                    ),
                )?
            } else {
                runtime.block_on(
                    marty_deployment_catalog::installer_renewal_bootstrap::bootstrap(&args[2]),
                )?
            };
            println!("{}", serde_json::json!({"outputs_written":count}));
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("internal renewal bootstrap requires Linux".into());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "installer-ingress-provision")
    {
        if args.len() != 3 || args[1] != "--installation-id" {
            return Err(
                "internal ingress provisioner requires an owned container invocation".into(),
            );
        }
        #[cfg(target_os = "linux")]
        {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|_| "cannot start ingress provisioning runtime")?;
            let count = runtime.block_on(
                marty_deployment_catalog::installer_ingress_provision::provision(&args[2]),
            )?;
            println!("{}", serde_json::json!({"outputs_written":count}));
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("internal ingress provisioner requires Linux".into());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "installer-tls-finalize")
    {
        if args.len() != 1 {
            return Err("internal TLS finalizer accepts no arguments".into());
        }
        #[cfg(target_os = "linux")]
        {
            let count = marty_deployment_catalog::installer_tls_outputs::finalize()?;
            println!("{}", serde_json::json!({"outputs_validated":count}));
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("internal TLS finalizer requires Linux".into());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "installer-keycloak-bridge")
    {
        if args.len() != 3 || args[1] != "--nonce" {
            return Err("internal Keycloak bridge requires an owned container invocation".into());
        }
        #[cfg(target_os = "linux")]
        {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|_| "cannot start Keycloak bridge runtime")?;
            let count = runtime.block_on(
                marty_deployment_catalog::installer_keycloak_bridge::provision(&args[2]),
            )?;
            println!("{}", serde_json::json!({"outputs_written":count}));
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("internal Keycloak bridge requires Linux".into());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "fetch-published-candidate")
    {
        #[cfg(target_os = "linux")]
        return marty_deployment_catalog::installer_candidate_command::fetch_published(
            &args[1..],
            env!("MARTY_DEPLOY_BUILD_IDENTITY"),
        );
        #[cfg(not(target_os = "linux"))]
        return Err("acceptance-only public acquisition requires Linux amd64".into());
    }
    if args.first().is_some_and(|arg| arg == "install-candidate") {
        #[cfg(target_os = "linux")]
        return marty_deployment_catalog::installer_candidate_command::install(
            &args[1..],
            env!("MARTY_DEPLOY_BUILD_IDENTITY"),
        );
        #[cfg(not(target_os = "linux"))]
        return Err("acceptance-only candidate execution requires Linux amd64".into());
    }
    if args.first().is_some_and(|arg| arg == "install") {
        #[cfg(target_os = "linux")]
        return marty_deployment_catalog::installer_command::install(
            &args[1..],
            env!("MARTY_DEPLOY_BUILD_IDENTITY"),
        );
        #[cfg(not(target_os = "linux"))]
        return Err("installer currently requires Linux amd64".into());
    }
    if args.first().is_some_and(|arg| arg == "candidate-test") {
        #[cfg(target_os = "linux")]
        return marty_deployment_catalog::installer_command::candidate_test(
            &args[1..],
            env!("MARTY_DEPLOY_BUILD_IDENTITY"),
        );
        #[cfg(not(target_os = "linux"))]
        return Err("candidate testing requires Linux amd64".into());
    }
    if args == ["--build-identity"] {
        println!("{}", env!("MARTY_DEPLOY_BUILD_IDENTITY"));
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "trust-info") {
        if args.len() != 3 || args[1] != "--install-dir" {
            return Err("usage: marty-deploy trust-info --install-dir ABSOLUTE_PATH".into());
        }
        #[cfg(target_os = "linux")]
        {
            let report =
                marty_deployment_catalog::installer_trust::inspect(std::path::Path::new(&args[2]))?;
            println!(
                "{}",
                serde_json::to_string(&report)
                    .map_err(|_| "cannot encode public trust information")?
            );
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("installer trust information currently requires Linux".into());
    }
    if args.first().is_some_and(|arg| arg == "status") {
        if args.len() != 3 || args[1] != "--install-dir" {
            return Err("usage: marty-deploy status --install-dir ABSOLUTE_PATH".into());
        }
        #[cfg(target_os = "linux")]
        {
            let inspection = marty_deployment_catalog::installer_state::LockedInspection::open(
                std::path::Path::new(&args[2]),
            )?;
            let journal = inspection.journal();
            let cleanup = inspection.cleanup_status()?;
            inspection.require_unchanged()?;
            println!(
                "{}",
                serde_json::json!({
                    "scope": "installation-journal", "runtime_observed": false, "journal": journal,
                    "cleanup": cleanup,
                })
            );
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("installer status currently requires Linux".into());
    }
    if args.first().is_some_and(|arg| arg == "validate")
        && args.iter().any(|arg| {
            arg == "--install-dir" || arg.starts_with("--install-dir=") || arg == "--docker-bin"
        })
    {
        if !matches!(args.len(), 3 | 5)
            || args[1] != "--install-dir"
            || (args.len() == 5 && args[3] != "--docker-bin")
        {
            return Err("usage: marty-deploy validate --install-dir ABSOLUTE_PATH [--docker-bin ABSOLUTE_PATH]".into());
        }
        #[cfg(target_os = "linux")]
        return marty_deployment_catalog::installer_validation::run(
            std::path::Path::new(&args[2]),
            std::path::Path::new(args.get(4).map(String::as_str).unwrap_or("/usr/bin/docker")),
        );
        #[cfg(not(target_os = "linux"))]
        return Err("deployment validation currently requires Linux".into());
    }
    if args.first().is_some_and(|arg| arg == "doctor") {
        if !matches!(args.len(), 3 | 5)
            || args[1] != "--install-dir"
            || (args.len() == 5 && args[3] != "--docker-bin")
        {
            return Err("usage: marty-deploy doctor --install-dir ABSOLUTE_PATH [--docker-bin ABSOLUTE_PATH]".into());
        }
        #[cfg(target_os = "linux")]
        {
            let directory = std::path::Path::new(&args[2]);
            let inspection =
                marty_deployment_catalog::installer_state::LockedInspection::open(directory)?;
            let journal = inspection.journal();
            let runtime = journal.runtime().ok_or(
                "installation has no recorded Docker binding; automatic adoption is refused",
            )?;
            let docker =
                std::path::Path::new(args.get(4).map(String::as_str).unwrap_or("/usr/bin/docker"));
            let runner = marty_deployment_catalog::installer_runtime::DockerRunner::from_binding(
                docker, runtime, directory,
            )?;
            let observation = runner.preflight()?;
            let cleanup = inspection.cleanup_status()?;
            let services = marty_deployment_catalog::installer_doctor::services(
                &inspection,
                directory,
                &runner,
            )?;
            inspection.require_unchanged()?;
            println!(
                "{}",
                serde_json::json!({
                    "scope": "installation-host", "installation_id": journal.installation_id(),
                    "compose_project": journal.compose_project(), "docker": observation,
                    "services_observed": services["services_observed"], "installation_ready": false,
                    "service_inspection": services,
                    "cleanup": cleanup,
                })
            );
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("installer doctor currently requires Linux".into());
    }
    if args.first().is_some_and(|arg| arg == "logs") {
        #[cfg(target_os = "linux")]
        {
            let report = marty_deployment_catalog::installer_logs::logs(&args[1..])?;
            println!("{report}");
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("installer logs currently requires Linux".into());
    }
    if args.first().is_some_and(|arg| arg == "uninstall") {
        #[cfg(target_os = "linux")]
        {
            let report = if args.get(1).is_some_and(|arg| arg == "plan") {
                marty_deployment_catalog::installer_uninstall::plan(&args[2..])?
            } else {
                marty_deployment_catalog::installer_uninstall::uninstall(&args[1..])?
            };
            println!("{report}");
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("installer uninstall currently requires Linux".into());
    }
    // KMS operator commands do not read the catalog or require a source checkout.
    if args.first().is_some_and(|a| a == "operator") {
        use marty_deployment_catalog::operator::{self, REFUSAL};
        use std::io::{Read, Write};
        let result = match args.get(1).map(String::as_str) {
            Some("beta-rehearsal") if args.len() == 2 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let result = marty_deployment_catalog::beta_rehearsal::run(context)?;
                serde_json::to_writer(std::io::stdout(), &result).map_err(|_| REFUSAL)?;
                Ok(())
            }
            Some("beta-runtime-config") if args.len() == 4 => {
                let value = marty_deployment_catalog::beta_runtime_config::stage(
                    std::path::Path::new(&args[2]),
                    &args[3],
                )?;
                serde_json::to_writer(std::io::stdout(), &value).map_err(|_| REFUSAL)?;
                Ok(())
            }
            Some("passport-model") if args.len() == 3 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(16 * 1024 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 16 * 1024 * 1024 {
                    return Err(REFUSAL.into());
                }
                let value: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let result = marty_deployment_catalog::passport_model::evaluate(&args[2], &value);
                serde_json::to_writer(std::io::stdout(), &result).map_err(|_| REFUSAL)?;
                Ok(())
            }

            Some(
                "ca-issuer"
                | "activation-certificates"
                | "activation-tokens"
                | "authority-check"
                | "renewal-inventory"
                | "leaf-check",
            ) if args.len() == 4 => {
                use marty_deployment_catalog::{activation_preflight as preflight, ca_issuer};
                use std::{io::IsTerminal, path::Path, time::Duration};
                if std::io::stdout().is_terminal() {
                    return Err(REFUSAL.into());
                }
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let bao = marty_openbao_http::OpenBaoHttp::connect(
                    &args[2],
                    Some(Path::new(&args[3])),
                    Duration::from_secs(10),
                )
                .map_err(|_| REFUSAL)?;
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| REFUSAL)?
                    .block_on(async {
                        match args[1].as_str() {
                            "ca-issuer" => ca_issuer::stage(&bao, &context).await,
                            "leaf-check" => {
                                marty_deployment_catalog::leaf_tokens::check(&bao, &context)
                                    .await
                                    .map(|_| Value::Null)
                            }
                            "activation-certificates" => preflight::certificates(&bao, &context)
                                .await
                                .map(|_| Value::Null),
                            "activation-tokens" => {
                                preflight::tokens(&bao, &context).await.map(|_| Value::Null)
                            }
                            "renewal-inventory" => preflight::renewal_inventory(&bao, &context)
                                .await
                                .map(|names| serde_json::json!(names)),
                            _ => preflight::authority(
                                &bao,
                                context["token"].as_str().ok_or(REFUSAL)?,
                                context["rotation"].as_bool().ok_or(REFUSAL)?,
                            )
                            .await
                            .map(|_| Value::Null),
                        }
                    });
                let value = match result {
                    Ok(value) => serde_json::json!({"value":value}),
                    Err(error) if error == ca_issuer::RECOVERY => return Err(error.into()),
                    Err(error) => serde_json::json!({"error":error}),
                };
                let refusal = if args[1] == "ca-issuer" {
                    ca_issuer::RECOVERY
                } else {
                    REFUSAL
                };
                let mut output = std::io::stdout().lock();
                serde_json::to_writer(&mut output, &value).map_err(|_| refusal)?;
                output.flush().map_err(|_| refusal)
            }
            Some("generation") if args.len() == 2 => {
                use marty_deployment_catalog::generation;
                use std::io::IsTerminal;
                if std::io::stdout().is_terminal() {
                    return Err(REFUSAL.into());
                }
                let mut input = Vec::new();
                std::io::stdin()
                    .take(512 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 512 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let value = match generation::operation(&context) {
                    Ok(value) => serde_json::json!({"value":value}),
                    Err(error) => serde_json::json!({"error":error}),
                };
                let mut output = std::io::stdout().lock();
                serde_json::to_writer(&mut output, &value).map_err(|_| REFUSAL)?;
                output.flush().map_err(|_| REFUSAL)
            }
            Some("keycloak-policy" | "keycloak-token" | "keycloak-provision") => {
                use marty_deployment_catalog::keycloak;
                use std::{io::IsTerminal, path::Path, time::Duration};
                let mint = args[1] != "keycloak-policy";
                if args.len() != if mint { 4 } else { 2 }
                    || (mint && std::io::stdout().is_terminal())
                {
                    return Err(REFUSAL.into());
                }
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let value = if mint {
                    let bao = marty_openbao_http::OpenBaoHttp::connect(
                        &args[2],
                        Some(Path::new(&args[3])),
                        Duration::from_secs(10),
                    )
                    .map_err(|_| REFUSAL)?;
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| REFUSAL)?
                        .block_on(async {
                            if args[1] == "keycloak-provision" {
                                marty_deployment_catalog::keycloak_provision::provision(
                                    &bao, &context,
                                )
                                .await
                            } else {
                                keycloak::mint(&bao, &context).await.map(Value::String)
                            }
                        })
                        .map_err(str::to_owned)?
                } else {
                    Value::String(keycloak::policy(&context)?)
                };
                let refusal = if mint { keycloak::RECOVERY } else { REFUSAL };
                let mut output = std::io::stdout().lock();
                serde_json::to_writer(&mut output, &value).map_err(|_| refusal)?;
                output.flush().map_err(|_| refusal)
            }
            Some("certificate-lifetime" | "certificate-expiry") if args.len() == 3 => {
                let ttl: u64 = args[2].parse().map_err(|_| REFUSAL)?;
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                let check = if args[1] == "certificate-expiry" {
                    marty_deployment_catalog::operator_certificates::check_expiry
                } else {
                    marty_deployment_catalog::operator_certificates::check_lifetime
                };
                let valid = check(&input, ttl)?;
                serde_json::to_writer(std::io::stdout().lock(), &valid).map_err(|_| REFUSAL)
            }
            Some("replacement-ca") if args.len() == 4 => {
                let version = args[3].parse().map_err(|_| REFUSAL)?;
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                marty_deployment_catalog::operator_certificates::check_replacement_ca(
                    &input, &args[2], version,
                )
            }
            Some("certificate-chain") if args.len() == 2 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(256 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 256 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let certificate = context["certificate"].as_str().ok_or(REFUSAL)?;
                let issuer = context["issuer"].as_str().ok_or(REFUSAL)?;
                marty_deployment_catalog::operator_certificates::check_chain(
                    certificate.as_bytes(),
                    issuer.as_bytes(),
                )
            }
            Some("leaf-metadata") if args.len() == 2 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                marty_deployment_catalog::leaf_tokens::metadata(
                    &context["metadata"],
                    "selfhost-qualification-custody-signer",
                    true,
                    None,
                )
            }
            Some("managed-reference") if args.len() == 2 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let reference = marty_managed_key_reference::selfhost_reference(
                    context["org"].as_str().ok_or(REFUSAL)?,
                    context["purpose"].as_str().ok_or(REFUSAL)?,
                )
                .ok_or(REFUSAL)?;
                serde_json::to_writer(std::io::stdout(), &reference).map_err(|_| REFUSAL)
            }
            Some("custody-signer") if args.len() == 2 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let (version, public_pem) = operator::custody_signer(
                    &context["metadata"],
                    context["version_one"].as_bool().ok_or(REFUSAL)?,
                )?;
                serde_json::to_writer(
                    std::io::stdout(),
                    &serde_json::json!({"version":version,"public_pem":public_pem}),
                )
                .map_err(|_| REFUSAL)
            }
            Some("ed25519-pem") if args.len() == 2 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL)?;
                let pem = operator::ed25519_pem(std::str::from_utf8(&input).map_err(|_| REFUSAL)?)?;
                std::io::stdout()
                    .write_all(pem.as_bytes())
                    .map_err(|_| REFUSAL)
            }
            Some("public-spki" | "certificate-spki" | "ed25519-spki") if args.len() == 2 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL.to_owned())?;
                let der = if args[1] == "ed25519-spki" {
                    operator::ed25519_spki(std::str::from_utf8(&input).map_err(|_| REFUSAL)?)
                } else {
                    operator::public_spki(&input, args[1] == "certificate-spki")
                }
                .map_err(str::to_owned)?;
                std::io::stdout().write_all(&der).map_err(|_| REFUSAL)
            }
            Some("leaf-refresh") if args.len() == 4 => {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL.to_owned())?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value = serde_json::from_slice(&input).map_err(|_| REFUSAL)?;
                let bao = marty_openbao_http::OpenBaoHttp::connect(
                    &args[2],
                    Some(std::path::Path::new(&args[3])),
                    std::time::Duration::from_secs(10),
                )
                .map_err(|_| REFUSAL)?;
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| REFUSAL)?
                    .block_on(marty_deployment_catalog::approle::refresh_leaf(
                        &bao, &context,
                    ))
            }
            Some(
                "approle-policy" | "approle-login" | "approle-bootstrap" | "approle-mint"
                | "approle-rotate" | "approle-retire",
            ) => {
                use marty_deployment_catalog::approle::{self, Role};
                use std::{io::IsTerminal, path::Path, time::Duration};
                let operation = &args[1];
                if args.len() != if operation == "approle-policy" { 3 } else { 6 } {
                    return Err(REFUSAL.into());
                }
                let role = Role::parse(&args[2]).map_err(str::to_owned)?;
                let mut input = Vec::new();
                std::io::stdin()
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut input)
                    .map_err(|_| REFUSAL.to_owned())?;
                if input.len() > 64 * 1024 {
                    return Err(REFUSAL.into());
                }
                let context: Value =
                    serde_json::from_slice(&input).map_err(|_| REFUSAL.to_owned())?;
                if !context.is_object() {
                    return Err(REFUSAL.into());
                }
                let output = if operation == "approle-policy" {
                    Value::String(approle::policy(role, &context).map_err(str::to_owned)?)
                } else {
                    if ["approle-login", "approle-mint"].contains(&operation.as_str())
                        && std::io::stdout().is_terminal()
                    {
                        return Err(REFUSAL.into());
                    }
                    let bao = marty_openbao_http::OpenBaoHttp::connect(
                        &args[3],
                        Some(Path::new(&args[4])),
                        Duration::from_secs(10),
                    )
                    .map_err(|_| REFUSAL.to_owned())?;
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| REFUSAL.to_owned())?;
                    runtime
                        .block_on(async {
                            match operation.as_str() {
                                "approle-login" => {
                                    approle::login(&bao, role, Path::new(&args[5]), &context).await
                                }
                                "approle-mint" => {
                                    approle::mint(&bao, role, Path::new(&args[5]), &context)
                                        .await
                                        .map(Value::String)
                                }
                                "approle-rotate" | "approle-retire" => approle::rotate(
                                    &bao,
                                    role,
                                    Path::new(&args[5]),
                                    &context,
                                    operation == "approle-retire",
                                )
                                .await
                                .map(|_| serde_json::json!({"ready":true})),
                                _ => approle::bootstrap(&bao, role, Path::new(&args[5]), &context)
                                    .await
                                    .map(|_| serde_json::json!({"ready":true})),
                            }
                        })
                        .map_err(str::to_owned)?
                };
                serde_json::to_writer(std::io::stdout().lock(), &output).map_err(|_| REFUSAL)
            }
            Some("export-snapshot") if args.len() == 7 => {
                use std::path::Path;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| REFUSAL.to_owned())?;
                let archive = runtime
                    .block_on(marty_deployment_catalog::snapshot::export(
                        Path::new(&args[2]),
                        Path::new(&args[3]),
                        Path::new(&args[4]),
                        &args[5],
                        Path::new(&args[6]),
                    ))
                    .map_err(str::to_owned)?;
                println!("{}", archive.display());
                Ok(())
            }
            Some("check-snapshot") if args.len() == 3 => {
                let source = std::fs::File::open(&args[2]).map_err(|_| REFUSAL.to_owned())?;
                operator::check_snapshot(source)
            }
            _ => Err(REFUSAL),
        };
        return result.map_err(str::to_owned);
    }
    let root = if let Some(index) = args.iter().position(|arg| arg == "--repo-root") {
        if index + 1 >= args.len() {
            return Err("--repo-root requires a path".to_owned());
        }
        let path = PathBuf::from(args.remove(index + 1));
        args.remove(index);
        Some(path)
    } else {
        args.iter()
            .position(|arg| arg.starts_with("--repo-root="))
            .map(|index| PathBuf::from(args.remove(index).trim_start_matches("--repo-root=")))
    };
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        print!("{}", frozen_help("root"));
        return Ok(());
    }
    let command = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| "command is required".to_owned())?;
    let params = &args[1..];
    if params.iter().any(|arg| arg == "--help" || arg == "-h") {
        if command == "kubernetes-secrets" {
            println!(
                "usage: marty-deploy kubernetes-secrets STACK NAMESPACE [CAPTURED_REQUIRED_NAMES]"
            );
            return Ok(());
        }
        print!("{}", frozen_help(command));
        return Ok(());
    }
    if command != "kubernetes-secrets" {
        check_options(command, params)?;
    }
    let root = match root {
        Some(path) => path,
        None => root_from_executable()?,
    };
    let catalog = Catalog::load(root)?;
    match command {
        "kubernetes-secrets" if matches!(params.len(), 2 | 3) => {
            marty_deployment_catalog::kubernetes_secrets::apply(
                &catalog,
                &params[0],
                &params[1],
                params.get(2).map(String::as_str),
            )?;
        }
        "validate" => {
            println!("Deployment catalog validation passed.");
            println!(
                "stacks={} services={} secrets={} bundles={}",
                catalog.stacks.len(),
                catalog.services.len(),
                catalog.input_specs.len(),
                catalog.bundles.len()
            );
        }
        "plan" => {
            let positionals = positional(params, &[]);
            let plan = catalog.plan(required(&positionals, 0, "stack")?)?;
            if params.iter().any(|a| a == "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?
                );
            } else {
                print_plan(&plan);
            }
        }
        "services" => {
            let positionals = positional(params, &["--group", "--field"]);
            let group = option(params, "--group");
            let include_optional = params.iter().any(|a| a == "--include-optional");
            let field = option(params, "--field").unwrap_or("id");
            let ids = if let Some(group) = group {
                catalog.group_services(group)?
            } else if let Some(stack) = positionals.first() {
                if params.iter().any(|a| a == "--running-only") {
                    catalog.running_services(stack, include_optional)?
                } else {
                    catalog.expanded_services(stack, include_optional)?
                }
            } else {
                return Err("services requires either a stack argument or --group.".to_owned());
            };
            for id in ids {
                println!("{}", catalog.service_field(&id, field)?);
            }
        }
        "secrets" => {
            let positionals = positional(params, &["--field"]);
            let field = option(params, "--field").unwrap_or("id");
            for id in catalog.required_input_ids(required(&positionals, 0, "stack")?)? {
                println!("{}", catalog.public_input_field(&id, field)?);
            }
        }
        "compose-command" => {
            let positionals = positional(params, &[]);
            let argv = catalog.compose_command(
                required(&positionals, 0, "stack")?,
                required(&positionals, 1, "operation")?,
            )?;
            if params.iter().any(|a| a == "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&argv).map_err(|e| e.to_string())?
                );
            } else if cfg!(windows) {
                println!(
                    "{}",
                    argv.iter()
                        .map(|a| if a.is_empty() || a.chars().any(char::is_whitespace) {
                            format!("'{}'", a.replace('\'', "''"))
                        } else {
                            a.clone()
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            } else {
                println!(
                    "{}",
                    argv.iter()
                        .map(|a| posix_shell_quote(a))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
        "bundle-assets" => {
            let positionals = positional(params, &[]);
            for path in catalog.bundle_assets(required(&positionals, 0, "bundle")?)? {
                println!("{}", path.display());
            }
        }
        _ => return Err(format!("unknown command: {command}")),
    }
    Ok(())
}

fn posix_shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || "_/@%+=:,.-".contains(c)
                || ('\u{7f}'..='\u{ff}').contains(&c)
        })
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

fn main() {
    if let Err(error) = run() {
        if let Some(usage) = error.strip_prefix("__USAGE__") {
            eprint!("{usage}");
            std::process::exit(2);
        }
        eprintln!("{error}");
        if [
            marty_deployment_catalog::approle::CLEANUP_BOOTSTRAP,
            marty_deployment_catalog::approle::CLEANUP_LEAF,
            marty_deployment_catalog::approle::CLEANUP_ROTATION,
            marty_deployment_catalog::approle::CLEANUP_REFRESH,
            marty_deployment_catalog::keycloak::RECOVERY,
            marty_deployment_catalog::ca_issuer::RECOVERY,
            marty_deployment_catalog::beta_rehearsal::RECOVERY,
        ]
        .contains(&error.as_str())
        {
            std::process::exit(3);
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::posix_shell_quote;

    #[test]
    fn compose_preview_quotes_posix_shell_metacharacters() {
        for value in ["a;b", "a&b", "a|b", "a<b", "a>b", "a*b", "a#b"] {
            assert_eq!(posix_shell_quote(value), format!("'{value}'"));
        }
        assert_eq!(posix_shell_quote(""), "''");
        assert_eq!(posix_shell_quote("a'b"), "'a'\"'\"'b'");
        assert_eq!(posix_shell_quote("safe/path-1"), "safe/path-1");
    }
}
