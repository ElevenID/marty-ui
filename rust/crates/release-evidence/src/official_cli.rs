use std::{fs::File, path::Path};

use marty_release_evidence::{
    deployment_bundle::read_bounded,
    official::{validate_official_suite, LANES, MAX_MANIFEST_BYTES, MAX_SUMMARY_BYTES},
};

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "cannot inspect official evidence")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("official evidence must be a bounded regular file");
    }
    read_bounded(
        File::open(path).map_err(|_| "cannot open official evidence")?,
        limit,
    )
}

fn run() -> Result<String, &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 6 {
        return Err("usage: validate-official-suite MANIFEST SOURCE_SHA HARNESS_SHA RUN_ID RUN_ATTEMPT SUMMARY_DIRECTORY");
    }
    let run_id = args[3]
        .parse::<u64>()
        .map_err(|_| "invalid official run ID")?;
    let attempt = args[4]
        .parse::<u64>()
        .map_err(|_| "invalid official run attempt")?;
    if attempt == 0 {
        return Err("invalid official run attempt");
    }
    let manifest = read(Path::new(&args[0]), MAX_MANIFEST_BYTES)?;
    let summaries = LANES
        .iter()
        .map(|lane| {
            let directory = format!("official-{lane}-{run_id}-{attempt}");
            read(
                &Path::new(&args[5]).join(directory).join("summary.json"),
                MAX_SUMMARY_BYTES,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let receipt = validate_official_suite(&manifest, &summaries, &args[1], &args[2], run_id)?;
    serde_json::to_string(&receipt).map_err(|_| "cannot serialize official gate receipt")
}

fn main() {
    match run() {
        Ok(receipt) => println!("{receipt}"),
        Err(error) => {
            eprintln!("Official conformance gate rejected: {error}");
            std::process::exit(1);
        }
    }
}
