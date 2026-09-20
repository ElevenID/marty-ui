//! One lazy fixed-operator secret owner for Canvas validation and delivery.
//! Tenant metadata never supplies the path; required non-Canvas startup secrets
//! retain their existing, separate fail-closed configuration policy.
use async_trait::async_trait;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanvasOperatorSecretError {
    #[error("Canvas Credentials operator token file is not valid UTF-8")]
    InvalidUtf8,
}

#[async_trait]
pub trait CanvasOperatorSecretReader: Send + Sync {
    async fn read(&self, operator_path: &str) -> Result<Vec<u8>, std::io::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FileCanvasOperatorSecretReader;

#[async_trait]
impl CanvasOperatorSecretReader for FileCanvasOperatorSecretReader {
    async fn read(&self, operator_path: &str) -> Result<Vec<u8>, std::io::Error> {
        tokio::fs::read(operator_path).await
    }
}

pub async fn resolve_canvas_operator_token(
    direct: Option<&str>,
    operator_path: Option<&str>,
    reader: &dyn CanvasOperatorSecretReader,
) -> Result<Option<String>, CanvasOperatorSecretError> {
    if let Some(direct) = direct.filter(|value| !value.is_empty()) {
        return Ok(Some(direct.to_owned()));
    }
    let Some(path) = operator_path.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    // Published optional fallback catches file I/O errors, but not invalid UTF-8.
    let Ok(bytes) = reader.read(path).await else {
        return Ok(None);
    };
    let decoded = String::from_utf8(bytes).map_err(|_| CanvasOperatorSecretError::InvalidUtf8)?;
    // Python open(..., encoding="utf-8") uses universal newline translation.
    // Direct environment and tenant values deliberately bypass this conversion.
    let decoded = decoded.replace("\r\n", "\n").replace('\r', "\n");
    let token = crate::python_value::strip(&decoded);
    Ok((!token.is_empty()).then(|| token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OwnedFile {
        directory: std::path::PathBuf,
        file: std::path::PathBuf,
    }
    impl Drop for OwnedFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.file);
            let _ = std::fs::remove_dir(&self.directory);
        }
    }

    #[tokio::test]
    async fn real_reader_observes_rotation_and_preserves_optional_io_vs_utf8_errors() {
        let directory = std::env::temp_dir().join(format!(
            "canvas-operator-secret-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        let owned = OwnedFile {
            file: directory.join("synthetic-token"),
            directory,
        };
        let path = owned.file.to_str().unwrap();
        let reader = FileCanvasOperatorSecretReader;
        tokio::fs::write(&owned.file, b" synthetic-first\n")
            .await
            .unwrap();
        let first = resolve_canvas_operator_token(None, Some(path), &reader).await;
        tokio::fs::write(&owned.file, b"synthetic-second")
            .await
            .unwrap();
        let second = resolve_canvas_operator_token(None, Some(path), &reader).await;
        tokio::fs::write(&owned.file, b" synthetic-first\r\nsecond\rthird\n ")
            .await
            .unwrap();
        let newlines = resolve_canvas_operator_token(None, Some(path), &reader).await;
        tokio::fs::write(&owned.file, [0xff]).await.unwrap();
        let invalid = resolve_canvas_operator_token(None, Some(path), &reader).await;
        let direct =
            resolve_canvas_operator_token(Some(" synthetic-direct "), Some(path), &reader).await;
        tokio::fs::remove_file(&owned.file).await.unwrap();
        let missing = resolve_canvas_operator_token(None, Some(path), &reader).await;
        let directory =
            resolve_canvas_operator_token(None, owned.directory.to_str(), &reader).await;
        drop(owned);
        assert_eq!(first.unwrap().as_deref(), Some("synthetic-first"));
        assert_eq!(second.unwrap().as_deref(), Some("synthetic-second"));
        assert_eq!(
            newlines.unwrap().as_deref(),
            Some("synthetic-first\nsecond\nthird")
        );
        assert_eq!(invalid, Err(CanvasOperatorSecretError::InvalidUtf8));
        assert_eq!(direct.unwrap().as_deref(), Some(" synthetic-direct "));
        assert_eq!(missing.unwrap(), None);
        assert_eq!(directory.unwrap(), None);
    }
}
