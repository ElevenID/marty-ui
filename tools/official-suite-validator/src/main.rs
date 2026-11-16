//! Validate an already authenticated released stack and same-run summaries.

use std::{fs::File, io::Read, path::Path};

use marty_official_suite_validator::{
    official::{LANES, MAX_MANIFEST_BYTES, MAX_SUMMARY_BYTES},
    official_automation::validate_automated_released_official_suite,
    official_review::prepare_released_official_review,
};

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "cannot inspect official evidence")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("official evidence must be a bounded regular file");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "cannot open official evidence")?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read official evidence")?;
    if bytes.len() > limit {
        return Err("official evidence exceeds its size limit");
    }
    Ok(bytes)
}

fn run() -> Result<String, &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--list-lanes"] {
        return serde_json::to_string(&LANES).map_err(|_| "cannot serialize official lanes");
    }
    if args.len() != 7
        || !matches!(
            args[0].as_str(),
            "--prepare-released" | "--automated-released"
        )
    {
        return Err("usage: marty-official-suite-validator [--prepare-released | --automated-released] MANIFEST SOURCE_SHA HARNESS_SHA RUN_ID RUN_ATTEMPT SUMMARY_DIRECTORY");
    }
    let run_id = args[4]
        .parse::<u64>()
        .map_err(|_| "invalid official run ID")?;
    let attempt = args[5]
        .parse::<u64>()
        .map_err(|_| "invalid official run attempt")?;
    if run_id == 0 || attempt != 1 {
        return Err("released qualification requires the original official run attempt");
    }
    let manifest = read(Path::new(&args[1]), MAX_MANIFEST_BYTES)?;
    let summaries = LANES
        .iter()
        .map(|lane| {
            let directory = format!("official-{lane}-{run_id}-{attempt}");
            read(
                &Path::new(&args[6]).join(directory).join("summary.json"),
                MAX_SUMMARY_BYTES,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if args[0] == "--prepare-released" {
        let plan = prepare_released_official_review(
            &manifest, &summaries, &args[2], &args[3], run_id, attempt,
        )?;
        String::from_utf8(plan.bytes()?).map_err(|_| "cannot encode released official review plan")
    } else {
        let receipt = validate_automated_released_official_suite(
            &manifest, &summaries, &args[2], &args[3], run_id, attempt,
        )?;
        serde_json::to_string(&receipt)
            .map_err(|_| "cannot serialize released official gate receipt")
    }
}

fn main() {
    match run() {
        Ok(value) => print!("{value}"),
        Err(error) => {
            eprintln!("Official conformance gate rejected: {error}");
            std::process::exit(1);
        }
    }
}
