use marty_release_evidence::envoy_config::{encode, render, MAX_CONFIG_BYTES};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> Result<Vec<u8>, &'static str> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "Required Envoy input is unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Envoy inputs must be regular files");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "Cannot open Envoy input")?
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read Envoy input")?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err("Envoy input exceeds size limit");
    }
    Ok(bytes)
}

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err(
            "usage: render-envoy-native-issuance BASE_YAML PROTO_DESCRIPTOR > candidate.yaml",
        );
    }
    let model = render(&read(Path::new(&args[0]))?, &read(Path::new(&args[1]))?)?;
    let output = encode(&model)?;
    io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(|_| "Cannot write Envoy configuration")
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Envoy configuration rejected: {error}");
        std::process::exit(1);
    }
}
