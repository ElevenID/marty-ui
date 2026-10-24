use std::{fs::File, path::Path};

use marty_release_evidence::{
    deployment_bundle::read_bounded,
    official::{validate_official_suite, LANES, MAX_MANIFEST_BYTES, MAX_SUMMARY_BYTES},
    official_review::{
        prepare_official_review, validate_official_suite_with_review, MAX_DISPOSITION_BYTES,
    },
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
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--list-lanes"] {
        return serde_json::to_string(&LANES).map_err(|_| "cannot serialize official lanes");
    }
    let prepare = args
        .first()
        .is_some_and(|value| value == "--prepare-review");
    if prepare {
        args.remove(0);
    }
    let main_review = if args
        .first()
        .is_some_and(|value| value == "--with-main-review")
    {
        if args.len() < 3 || prepare {
            return Err("official review arguments are invalid");
        }
        let values = args.drain(..3).collect::<Vec<_>>();
        Some((values[1].clone(), values[2].clone()))
    } else {
        None
    };
    if args.len() != 6 {
        return Err("usage: validate-official-suite [--prepare-review | --with-main-review RECORD MAIN_COMMIT] MANIFEST SOURCE_SHA HARNESS_SHA RUN_ID RUN_ATTEMPT SUMMARY_DIRECTORY");
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
    if prepare {
        let plan =
            prepare_official_review(&manifest, &summaries, &args[1], &args[2], run_id, attempt)?;
        return String::from_utf8(plan.bytes()?).map_err(|_| "cannot encode official review plan");
    }
    let receipt = if let Some((record, main_commit)) = main_review {
        let bytes = read(Path::new(&record), MAX_DISPOSITION_BYTES)?;
        validate_official_suite_with_review(
            &manifest,
            &summaries,
            &args[1],
            &args[2],
            run_id,
            attempt,
            &bytes,
            &main_commit,
        )?
    } else {
        validate_official_suite(&manifest, &summaries, &args[1], &args[2], run_id)?
    };
    serde_json::to_string(&receipt).map_err(|_| "cannot serialize official gate receipt")
}

fn main() {
    match run() {
        // Exact review-plan bytes are the approval subject; do not add a newline.
        Ok(receipt) => print!("{receipt}"),
        Err(error) => {
            eprintln!("Official conformance gate rejected: {error}");
            std::process::exit(1);
        }
    }
}
