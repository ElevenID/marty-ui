use std::io::{self, Read};

use marty_release_evidence::{validate_release_run, MAX_RUN_BYTES};

fn run() -> Result<String, &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(2..=3).contains(&args.len()) {
        return Err(
            "usage: validate-stack-release-run RUN_ID VERSION [EXPECTED_SOURCE] < run.json",
        );
    }
    let run_id = args[0].parse::<u64>().map_err(|_| "invalid run ID")?;
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_RUN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read release run response")?;
    validate_release_run(&bytes, run_id, &args[1], args.get(2).map(String::as_str))
}

fn main() {
    match run() {
        Ok(source) => println!("{source}"),
        Err(error) => {
            eprintln!("Release run rejected: {error}");
            std::process::exit(1);
        }
    }
}
