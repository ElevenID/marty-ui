use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};

use marty_release_evidence::deployment_bundle::{
    decode, decode_dispatch_event, encode, read_bounded, DeploymentBundle, FILENAMES,
    MAX_DOCUMENT_BYTES, MAX_EVENT_BYTES, MAX_TRANSPORT_BYTES,
};

fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "cannot inspect evidence file")?;
    if !metadata.file_type().is_file() {
        return Err("evidence input must be a regular non-symlink file");
    }
    read_bounded(
        File::open(path).map_err(|_| "cannot open evidence file")?,
        limit,
    )
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "cannot create new evidence output; existing files are never overwritten")?;
    file.write_all(bytes)
        .map_err(|_| "cannot write evidence output")
}

fn run() -> Result<&'static str, &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: beta-evidence-bundle pack INPUT_DIR NEW_FILE | unpack|unpack-event FILE_OR_- NEW_DIR",
        );
    }
    let input = Path::new(&args[1]);
    let output = Path::new(&args[2]);
    if args[0] == "pack" {
        let mut documents = [Vec::new(), Vec::new(), Vec::new()];
        for (document, name) in documents.iter_mut().zip(FILENAMES) {
            *document = read_file(&input.join(name), MAX_DOCUMENT_BYTES)?;
        }
        let transport = encode(&DeploymentBundle(documents))?;
        write_new(output, &transport)?;
        Ok("Deployment evidence packed; original files unchanged")
    } else if args[0] == "unpack" || args[0] == "unpack-event" {
        let event = args[0] == "unpack-event";
        let limit = if event {
            MAX_EVENT_BYTES
        } else {
            MAX_TRANSPORT_BYTES
        };
        let transport = if args[1] == "-" {
            read_bounded(io::stdin().lock(), limit)?
        } else {
            read_file(input, limit)?
        };
        let bundle = if event {
            decode_dispatch_event(&transport)?
        } else {
            decode(&transport)?
        };
        fs::create_dir(output)
            .map_err(|_| "cannot create new evidence directory; existing paths are never reused")?;
        for (name, bytes) in FILENAMES.iter().zip(bundle.0) {
            write_new(&output.join(name), &bytes)?;
        }
        Ok("Deployment evidence unpacked; all three original files preserved")
    } else {
        Err("unknown evidence transport command")
    }
}

fn main() {
    match run() {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("Deployment evidence rejected: {error}");
            std::process::exit(1);
        }
    }
}
