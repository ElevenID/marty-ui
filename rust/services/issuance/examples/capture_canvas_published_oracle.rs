//! Offline reference capture, not a qualification gate or deployment command.
//! Reuses the exact-owned disposable published-image/database fixture.
#[allow(dead_code)]
#[path = "../tests/support/canvas_published_database.rs"]
mod canvas_published_database;

#[tokio::main]
async fn main() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (scenario, output) = match arguments.as_slice() {
        [scenario] => (scenario, None),
        [scenario, flag, path] if flag == "--output" => {
            let path = std::path::PathBuf::from(path);
            if !path.is_absolute() {
                return Err("capture output must be an absolute new file path".into());
            }
            (scenario, Some(path))
        }
        _ => return Err("expected scenario [--output ABSOLUTE_NEW_FILE]".into()),
    };
    use canvas_published_database::PublishedDatabase;
    let owned = match scenario.as_str() {
        "validation-boundary" => PublishedDatabase::start_with_validation_boundary().await?,
        "status-provider" => PublishedDatabase::start_with_status_provider().await?,
        "utf7-consumer" => PublishedDatabase::start_with_utf7_consumer().await?,
        "json-consumer" => PublishedDatabase::start_with_json_consumer().await?,
        "json-depth" => PublishedDatabase::start_with_json_depth().await?,
        "worker-startup" => PublishedDatabase::start_with_worker_startup().await?,
        _ => {
            return Err(
                "expected validation-boundary, status-provider, utf7-consumer, json-consumer, json-depth or worker-startup"
                    .into(),
            )
        }
    };
    let observation = owned
        .oracle
        .as_ref()
        .ok_or("published fixture did not return an oracle")?;
    let capture = if let Some(path) = output {
        // Generated evidence can exceed terminal transport limits. Exclusive
        // creation never overwrites earlier captures or an existing reference.
        capture_file(observation, &path).map(|()| {
            println!("CANVAS_PUBLISHED_ORACLE_FILE={}", path.display());
        })
    } else {
        println!("CANVAS_PUBLISHED_ORACLE={observation}");
        Ok(())
    };
    let cleanup = owned.close();
    capture?;
    cleanup
}

fn capture_file(observation: &serde_json::Value, path: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut file, observation).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn large_capture_is_complete_and_existing_evidence_cannot_be_overwritten() {
        let directory =
            std::env::temp_dir().join(format!("canvas-capture-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("observation.json");
        let expected = serde_json::json!({"payload":"a".repeat(1_100_000),"float":0.0,
            "negative_zero":-0.0,"integer":serde_json::from_str::<serde_json::Value>(&"9".repeat(4300)).unwrap()});
        super::capture_file(&expected, &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 1_100_000);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            expected
        );
        assert!(super::capture_file(&serde_json::json!({}), &path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
