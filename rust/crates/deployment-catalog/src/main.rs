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
    args.windows(2)
        .find(|parts| parts[0] == name)
        .map(|parts| parts[1].as_str())
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
    let mut index = 0;
    while index < params.len() {
        let arg = &params[index];
        if valued.contains(&arg.as_str()) {
            index += 2;
            continue;
        }
        if arg.starts_with('-') && !flags.contains(&arg.as_str()) {
            unknown.push(arg.clone());
        }
        index += 1;
    }
    if !unknown.is_empty() {
        return Err(usage_error(
            TOP_USAGE,
            "marty-deploy.py",
            &format!("unrecognized arguments: {}", unknown.join(" ")),
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
    let root = if let Some(index) = args.iter().position(|arg| arg == "--repo-root") {
        if index + 1 >= args.len() {
            return Err("--repo-root requires a path".to_owned());
        }
        let path = PathBuf::from(args.remove(index + 1));
        args.remove(index);
        path
    } else {
        root_from_executable()?
    };
    let command = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| "command is required".to_owned())?;
    let params = &args[1..];
    check_options(command, params)?;
    let catalog = Catalog::load(root)?;
    match command {
        "validate" => {
            println!("Deployment catalog validation passed.");
            println!(
                "stacks={} services={} secrets={} bundles={}",
                catalog.stacks.len(),
                catalog.services.len(),
                catalog.secrets.len(),
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
            for id in catalog.required_secrets(required(&positionals, 0, "stack")?)? {
                println!("{}", catalog.secret_field(&id, field)?);
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
                        .map(|a| {
                            if a.is_empty()
                                || a.chars()
                                    .any(|c| c.is_whitespace() || "'\"\\$`".contains(c))
                            {
                                format!("'{}'", a.replace('\'', "'\"'\"'"))
                            } else {
                                a.clone()
                            }
                        })
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

fn main() {
    if let Err(error) = run() {
        if let Some(usage) = error.strip_prefix("__USAGE__") {
            eprint!("{usage}");
            std::process::exit(2);
        }
        eprintln!("{error}");
        std::process::exit(1);
    }
}
