use std::{collections::BTreeMap, path::PathBuf};

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let mut paths = BTreeMap::new();
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            println!("Read-only, no-start declaration validation; does not qualify a release.\nUsage: check-selfhost-secret-closure --compose YAML --catalog JSON --stack JSON --example-dir DIR");
            return Ok(());
        }
        let key = arg.to_str().ok_or("invalid argument")?.to_owned();
        if !["--compose", "--catalog", "--stack", "--example-dir"].contains(&key.as_str()) {
            return Err("unknown argument; use --help".into());
        }
        let path = PathBuf::from(args.next().ok_or("argument needs a path")?);
        if paths.insert(key, path).is_some() {
            return Err("duplicate argument".into());
        }
    }
    let get = |key: &str| {
        paths
            .get(key)
            .map(PathBuf::as_path)
            .ok_or_else(|| format!("missing {key}"))
    };
    let receipt = marty_selfhost_bundle::secret_closure::validate(
        get("--compose")?,
        get("--catalog")?,
        get("--stack")?,
        get("--example-dir")?,
    )?;
    println!("{receipt}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Secret closure rejected: {error}");
        std::process::exit(1);
    }
}
