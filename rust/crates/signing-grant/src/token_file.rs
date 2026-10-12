//! Bounded runtime reads for rotated OpenBao grant tokens.

use std::path::Path;

use tokio::io::AsyncReadExt as _;

const MAX_TOKEN_BYTES: u64 = 4096;

pub(crate) async fn read_token_file(path: &Path) -> Result<String, ()> {
    let file = tokio::fs::File::open(path).await.map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ())?;
    if bytes.len() > MAX_TOKEN_BYTES as usize {
        return Err(());
    }
    let text = String::from_utf8(bytes).map_err(|_| ())?;
    let token = text.trim_end_matches(['\r', '\n']);
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(());
    }
    Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek as _, Write as _};

    #[tokio::test]
    async fn rejects_oversized_and_multiline_grant_tokens() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&vec![b'x'; MAX_TOKEN_BYTES as usize + 1])
            .unwrap();
        assert!(read_token_file(file.path()).await.is_err());
        file.as_file_mut().set_len(0).unwrap();
        file.as_file_mut().rewind().unwrap();
        file.write_all(b"valid\nembedded\n").unwrap();
        assert!(read_token_file(file.path()).await.is_err());
        file.as_file_mut().set_len(0).unwrap();
        file.as_file_mut().rewind().unwrap();
        file.write_all(b"valid-token\r\n").unwrap();
        assert_eq!(read_token_file(file.path()).await.unwrap(), "valid-token");
    }
}
