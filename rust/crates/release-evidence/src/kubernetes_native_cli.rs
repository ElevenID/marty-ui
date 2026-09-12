use marty_release_evidence::kubernetes_native::{
    self as native, Environment, Result, MAX_BYTES, REFUSAL,
};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

fn bounded(mut source: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source
        .by_ref()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSAL)?;
    if bytes.len() > MAX_BYTES {
        return Err(REFUSAL);
    }
    Ok(bytes)
}
fn read(path: &Path) -> Result<Vec<u8>> {
    bounded(File::open(path).map_err(|_| REFUSAL)?)
}

fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let operation = args.next().ok_or(REFUSAL)?;
    let mut repo = None;
    let mut manifests = None;
    let mut namespace = None;
    while let Some(argument) = args.next() {
        let value = args.next().ok_or(REFUSAL)?;
        if argument == "--repo-root" && repo.is_none() {
            repo = Some(PathBuf::from(value));
        } else if argument == "--manifest-dir" && manifests.is_none() {
            manifests = Some(PathBuf::from(value));
        } else if argument == "--namespace" && namespace.is_none() {
            namespace = Some(value.into_string().map_err(|_| REFUSAL)?);
        } else {
            return Err(REFUSAL);
        }
    }
    let values: Environment = native::capture_environment(|name| std::env::var_os(name))?;
    let enabled = native::selected(&values)?;
    if operation == "validate" {
        if repo.is_some() || manifests.is_some() || namespace.is_some() {
            return Err(REFUSAL);
        }
        if enabled {
            native::services_image(values.get("MARTY_SERVICES_IMAGE").ok_or(REFUSAL)?)?;
            native::configuration(&values)?;
        }
        return Ok(());
    }
    if !enabled || (operation != "render" && operation != "check-update") {
        return Err(REFUSAL);
    }
    let repo = repo.ok_or(REFUSAL)?;
    let manifests = manifests.ok_or(REFUSAL)?;
    let mut template = native::documents(&read(&manifests.join("07a-issuance-native.yaml"))?)?;
    template.extend(native::documents(&read(
        &manifests.join("07b-signing-keys.yaml"),
    )?)?);
    let source = String::from_utf8(read(&repo.join("rust/services/gateway/src/config.rs"))?)
        .map_err(|_| REFUSAL)?;
    let ready = native::readiness_from_source(&source)?;
    if operation == "render" {
        if namespace.is_some() {
            return Err(REFUSAL);
        }
        let original = native::documents(&bounded(io::stdin().lock())?)?;
        let model = native::compose(&original, &template, &ready, &values)?;
        let bytes = serde_json::to_vec(&model).map_err(|_| REFUSAL)?;
        let mut output = io::stdout().lock();
        output
            .write_all(&bytes)
            .and_then(|_| output.write_all(b"\n"))
            .map_err(|_| REFUSAL)?;
    } else {
        let namespace = namespace.ok_or(REFUSAL)?;
        let original = native::documents(&read(&manifests.join("07-microservices.yaml"))?)?;
        let expected = native::compose(&original, &template, &ready, &values)?;
        let bytes = bounded(io::stdin().lock())?;
        let parsed: serde_yaml::Value = serde_yaml::from_slice(&bytes).map_err(|_| REFUSAL)?;
        let actual = serde_json::to_value(parsed).map_err(|_| REFUSAL)?;
        native::check_update(&actual, &expected, &namespace)?;
    }
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("{REFUSAL}");
        std::process::exit(1);
    }
}
