use marty_selfhost_bundle::{Options, Result};
use std::path::PathBuf;
mod user_path;

fn run() -> Result<()> {
    let mut repo = std::env::current_dir().map_err(|_| "Cannot determine repository root")?;
    let mut output = None;
    let mut archive = None;
    let mut compose = None;
    let mut replace = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            println!("Stage the image-based self-host customer bundle.\nUsage: package-selfhost-bundle [--repo-root DIR] [--output-dir DIR] [--archive ZIP_BASENAME] [--replace] [--compose-executable PATH]\nExisting outputs are preserved unless --replace verifies an unchanged owned bundle. ZIP paths must always be new.");
            return Ok(());
        } else if arg == "--replace" {
            replace = true;
        } else if arg == "--repo-root" {
            repo = PathBuf::from(args.next().ok_or("--repo-root needs a directory")?);
        } else if arg == "--output-dir" {
            output = Some(PathBuf::from(
                args.next().ok_or("--output-dir needs a directory")?,
            ));
        } else if arg == "--archive" {
            let base = args.next().ok_or("--archive needs a basename")?;
            if !base.is_empty() {
                archive = Some(PathBuf::from(base));
            }
        } else if arg == "--compose-executable" {
            compose = Some(args.next().ok_or("--compose-executable needs a path")?);
        } else {
            return Err("Unknown argument; use --help".into());
        }
    }
    let output = match output {
        Some(path) => user_path::expand(path)?,
        None => marty_selfhost_bundle::default_output(&repo)?,
    };
    let options = Options {
        repo,
        output,
        archive: archive.map(user_path::archive).transpose()?,
        replace,
    };
    let published = marty_selfhost_bundle::package(&options, |dir, args| {
        marty_selfhost_bundle::process::compose(dir, args, compose.as_ref())
    })?;
    println!("Staged self-host bundle at {}", published.output.display());
    if let Some(path) = published.archive {
        println!("Created archive {}", path.display());
    }
    if let Some(path) = published.backup {
        println!(
            "Previous bundle retained for recovery at {}",
            path.display()
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Self-host bundle rejected: {error}");
        std::process::exit(1);
    }
}
