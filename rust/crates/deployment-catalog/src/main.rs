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
    if args == ["--build-identity"] {
        println!("{}", env!("MARTY_DEPLOY_BUILD_IDENTITY"));
        return Ok(());
    }
    // KMS operator commands do not read the catalog or require a source checkout.
    if args.first().is_some_and(|a| a == "operator") {
        use marty_deployment_catalog::operator::{self, REFUSAL};
        use std::io::{Read, Write};
        let result = match args.get(1).map(String::as_str) {
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
            Some("approle-policy" | "approle-login" | "approle-bootstrap" | "approle-mint") => {
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
        print!("{}", frozen_help(command));
        return Ok(());
    }
    check_options(command, params)?;
    let root = match root {
        Some(path) => path,
        None => root_from_executable()?,
    };
    let catalog = Catalog::load(root)?;
    match command {
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
