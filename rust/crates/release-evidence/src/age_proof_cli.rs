use marty_release_evidence::{
    age_proof::{validate_age_proof, AgeProofInput, MAX_INPUT_BYTES, SCHEMA},
    deployment_bundle::read_bounded,
};

fn run() -> Result<String, &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--version"] {
        return Ok(SCHEMA.into());
    }
    if args.len() != 1 {
        return Err("usage: validate-age-proof-demo inputs|prepare|issued|request|allowed|denied|cleanup < bounded-run-input.json");
    }
    let bytes = read_bounded(std::io::stdin().lock(), MAX_INPUT_BYTES)?;
    let input: AgeProofInput =
        serde_json::from_slice(&bytes).map_err(|_| "invalid age-proof input")?;
    let receipt = validate_age_proof(&args[0], &input)?;
    serde_json::to_string(&receipt).map_err(|_| "cannot serialize age-proof receipt")
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("Age proof rejected: {error}");
            std::process::exit(1);
        }
    }
}
