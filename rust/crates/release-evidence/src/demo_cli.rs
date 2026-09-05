use std::fs::File;

use marty_release_evidence::{
    demo_qualification::{validate_demo_qualification, ExpectedQualification, MAX_REPORT_BYTES},
    deployment_bundle::read_bounded,
    MAX_RUN_BYTES,
};

fn read_file(path: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "cannot inspect evidence file")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("evidence must be a bounded regular file");
    }
    read_bounded(
        File::open(path).map_err(|_| "cannot open evidence file")?,
        limit,
    )
}

fn run() -> Result<String, &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 9 {
        return Err("usage: validate-demo-qualification RUN_FILE REPORT_FILE RUN_ID RECORDER_SHA VERSION UI_SHA SOURCE_ID DEPLOYMENT_SHA256 STACK_SHA256");
    }
    let expected = ExpectedQualification {
        run_id: args[2]
            .parse()
            .map_err(|_| "invalid qualification run ID")?,
        recorder_sha: &args[3],
        release_version: &args[4],
        ui_sha: &args[5],
        source_id: &args[6],
        deployment_sha256: &args[7],
        stack_sha256: &args[8],
    };
    let run = read_file(&args[0], MAX_RUN_BYTES)?;
    let report = read_file(&args[1], MAX_REPORT_BYTES)?;
    let verified = validate_demo_qualification(&run, &report, &expected)?;
    serde_json::to_string(&verified).map_err(|_| "cannot serialize verified qualification")
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("Demo qualification rejected: {error}");
            std::process::exit(1);
        }
    }
}
