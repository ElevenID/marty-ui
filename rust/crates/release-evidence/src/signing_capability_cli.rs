use marty_release_evidence::{
    deployment_bundle::read_bounded,
    signing_capability::{
        prepare_signing_capability, verify_signing_capability, SigningCapabilityInput,
        MAX_PROBE_BYTES, SCHEMA,
    },
};

fn run() -> Result<String, &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--version"] {
        return Ok(SCHEMA.into());
    }
    if args.len() != 1 || !matches!(args[0].as_str(), "prepare" | "verify") {
        return Err(
            "usage: validate-signing-capability prepare|verify < bounded-public-probe.json",
        );
    }
    let bytes = read_bounded(std::io::stdin().lock(), MAX_PROBE_BYTES)?;
    let input: SigningCapabilityInput =
        serde_json::from_slice(&bytes).map_err(|_| "invalid bounded signing-capability input")?;
    let receipt = if args[0] == "prepare" {
        prepare_signing_capability(&input)?
    } else {
        verify_signing_capability(&input)?
    };
    serde_json::to_string(&receipt).map_err(|_| "cannot serialize signing-capability receipt")
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("Signing capability rejected: {error}");
            std::process::exit(1);
        }
    }
}
