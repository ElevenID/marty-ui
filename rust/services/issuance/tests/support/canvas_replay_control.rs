//! Mechanical parent/child coordination only. Scenarios own paths, names,
//! liveness policy, timeout budgets, symlink checks, and outcome assertions.
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) fn control_directory(environment: &str) -> PathBuf {
    let directory = PathBuf::from(std::env::var(environment).unwrap())
        .canonicalize()
        .unwrap();
    assert!(directory.is_dir());
    assert_eq!(directory.file_name().unwrap(), "native-control");
    let certificate = PathBuf::from(std::env::var("SSL_CERT_FILE").unwrap())
        .canonicalize()
        .unwrap();
    // The Python owner must keep control files alive after closing HTTPS.
    assert!(!directory.starts_with(certificate.parent().unwrap()));
    directory
}

pub(super) async fn wait_for_marker<E>(
    path: &Path,
    seconds: u64,
    mut check_alive: impl FnMut() -> Result<(), E>,
) -> Result<Result<(), E>, tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        while !path.is_file() {
            check_alive()?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        check_alive()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn already_published_marker_still_checks_child() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            wait_for_marker(file.path(), 1, || Err("child exited"))
                .await
                .unwrap(),
            Err("child exited")
        );
    }
    #[tokio::test]
    async fn missing_marker_propagates_liveness_failure() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            wait_for_marker(&directory.path().join("missing"), 1, || Err("child exited"))
                .await
                .unwrap(),
            Err("child exited")
        );
    }
    #[tokio::test]
    async fn missing_marker_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            wait_for_marker(&directory.path().join("missing"), 0, || Ok::<_, ()>(()))
                .await
                .is_err()
        );
    }
}
