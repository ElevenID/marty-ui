//! Outgoing request mechanics; admission and metadata validation stay at callers.

use std::time::Duration;
use tonic::{metadata::AsciiMetadataValue, Request};

/// Build a fresh request with a caller-selected timeout and prevalidated token.
pub fn with_service_token<T>(
    body: T,
    timeout: Duration,
    service_token: Option<&AsciiMetadataValue>,
) -> Request<T> {
    let mut request = Request::new(body);
    request.set_timeout(timeout);
    if let Some(token) = service_token {
        request
            .metadata_mut()
            .insert("x-service-token", token.clone());
    }
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_keeps_body_and_wire_timeout_without_inventing_credentials() {
        let request = with_service_token(vec![1, 2, 3], Duration::from_secs(3), None);
        assert_eq!(request.get_ref(), &[1, 2, 3]);
        assert_eq!(request.metadata().get("grpc-timeout").unwrap(), "3000000u");
        assert!(!request.metadata().contains_key("x-service-token"));
    }

    #[test]
    fn requests_clone_prevalidated_metadata_without_sharing_mutations() {
        let token: AsciiMetadataValue = "caller-service-token".parse().unwrap();
        let mut first = with_service_token("first", Duration::from_secs(1), Some(&token));
        first
            .metadata_mut()
            .insert("x-service-token", "replaced".parse().unwrap());
        first
            .metadata_mut()
            .insert("x-request-id", "first-only".parse().unwrap());
        let second = with_service_token("second", Duration::from_secs(2), Some(&token));
        assert_eq!(second.get_ref(), &"second");
        assert_eq!(
            second.metadata().get("x-service-token").unwrap(),
            "caller-service-token"
        );
        assert_eq!(second.metadata().get("grpc-timeout").unwrap(), "2000000u");
        assert!(!second.metadata().contains_key("x-request-id"));
        assert_eq!(token, "caller-service-token");
    }
}
