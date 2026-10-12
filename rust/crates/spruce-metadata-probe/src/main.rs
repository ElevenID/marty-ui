use std::path::PathBuf;

#[tokio::main]
async fn main() {
    if let Err(message) = run().await {
        eprintln!("Spruce metadata probe failed: {message}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut base = "https://beta.elevenidllc.com".to_owned();
    let mut org_id = "00000000-0000-0000-0000-000000000001".to_owned();
    let mut output: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            println!("usage: marty-spruce-metadata-probe [--base BASE] [--org-id ORG_ID] [--output OUTPUT]");
            return Ok(());
        }
        if let Some(value) = arg.strip_prefix("--base=") {
            base = value.to_owned();
            continue;
        }
        if let Some(value) = arg.strip_prefix("--org-id=") {
            org_id = value.to_owned();
            continue;
        }
        if let Some(value) = arg.strip_prefix("--output=") {
            output = Some(PathBuf::from(value));
            continue;
        }
        match arg.as_str() {
            "--base" => base = args.next().ok_or("--base requires a value")?,
            "--org-id" => org_id = args.next().ok_or("--org-id requires a value")?,
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a value")?,
                ))
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    let result = marty_spruce_metadata_probe::probe(&base, &org_id).await?;
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
    );
    if let Some(path) = output {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, &rendered).map_err(|e| e.to_string())?;
    }
    print!("{rendered}");
    Ok(())
}
