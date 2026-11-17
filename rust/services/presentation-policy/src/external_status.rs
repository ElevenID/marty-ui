//! Credential status is authenticated independently of issuer trust and managed
//! lifecycle identity. Only the native verifier calls this with verified claims.
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::{Decompress, FlushDecompress, Status};
use mmf_platform::OutboundDestinationPolicy;
use serde_json::{Map, Value};
use url::Url;

use crate::{CredentialStatusEvidence, ResolvedIssuerKey};

const MAX_TOKEN_BYTES: usize = 2 * 1024 * 1024;
const MAX_LIST_BYTES: usize = 1024 * 1024;
const MAX_AGE_SECONDS: u64 = 300;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Deployment-owned, exact-origin exception for isolated HTTPS qualification.
/// Public destinations never inherit this CA or private-address permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalStatusFixtureTransport {
    origin: String,
    ca_pem: Vec<u8>,
}

impl ExternalStatusFixtureTransport {
    pub fn new(origin: &str, ca_pem: Vec<u8>) -> Result<Self, &'static str> {
        let url = Url::parse(origin).map_err(|_| "invalid fixture origin")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.origin().ascii_serialization() != origin
            || ca_pem.is_empty()
            || ca_pem.len() > 256 * 1024
        {
            return Err("invalid fixture origin or CA");
        }
        let roots =
            reqwest::Certificate::from_pem_bundle(&ca_pem).map_err(|_| "invalid fixture CA")?;
        if roots.is_empty() {
            return Err("missing fixture CA");
        }
        Ok(Self {
            origin: origin.into(),
            ca_pem,
        })
    }

    fn matches(&self, url: &Url) -> bool {
        url.origin().ascii_serialization() == self.origin
    }
}

#[derive(Clone, PartialEq)]
struct StatusReference {
    uri: String,
    index: u64,
}

// Missing status is distinct from a declared but malformed/unsupported status.
fn reference(
    claims: &Map<String, Value>,
    fixture: Option<&ExternalStatusFixtureTransport>,
) -> Result<Option<StatusReference>, ()> {
    let Some(status) = claims.get("status") else {
        return Ok(None);
    };
    let status = status.as_object().ok_or(())?;
    if status.len() != 1 {
        return Err(());
    }
    let list = status
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or(())?;
    if list.len() != 2 {
        return Err(());
    }
    let uri = list
        .get("uri")
        .and_then(Value::as_str)
        .filter(|s| s.len() <= 4096)
        .ok_or(())?;
    let url = Url::parse(uri).map_err(|_| ())?;
    // A nonstandard port is admitted only for the exact deployment-owned origin.
    if url.scheme() != "https"
        || url.host_str().is_none()
        || (url.port().is_some() && !fixture.is_some_and(|f| f.matches(&url)))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(());
    }
    let index = list.get("idx").and_then(Value::as_u64).ok_or(())?;
    if index >= (MAX_LIST_BYTES as u64) * 8 {
        return Err(());
    }
    Ok(Some(StatusReference {
        uri: uri.into(),
        index,
    }))
}

async fn fetch(uri: &str, fixture: Option<&ExternalStatusFixtureTransport>) -> Result<String, ()> {
    String::from_utf8(fetch_bytes(uri, &["application/statuslist+jwt"], fixture).await?)
        .map_err(|_| ())
}

pub(crate) async fn fetch_bytes(
    uri: &str,
    content_types: &[&str],
    fixture: Option<&ExternalStatusFixtureTransport>,
) -> Result<Vec<u8>, ()> {
    // The timeout includes DNS resolution, connection, TLS and streamed body.
    tokio::time::timeout(TIMEOUT, async {
        if uri.len() > 4096 {
            return Err(());
        }
        let url = Url::parse(uri).map_err(|_| ())?;
        let fixture = fixture.filter(|fixture| fixture.matches(&url));
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || (url.port().is_some() && fixture.is_none())
        {
            return Err(());
        }
        let host = url.host_str().ok_or(())?;
        let addresses: Vec<_> =
            tokio::net::lookup_host((host, url.port_or_known_default().ok_or(())?))
                .await
                .map_err(|_| ())?
                .collect();
        let mut policy = OutboundDestinationPolicy::public_https();
        let mut validation_url = url.clone();
        if fixture.is_some() {
            policy.allowed_non_public_hosts.insert(host.into());
            // MMF's public URL validator rejects custom ports. This exact
            // configured origin alone uses its explicitly bound HTTPS port.
            validation_url.set_port(None).map_err(|_| ())?;
        }
        policy
            .validate_resolved(&validation_url, &addresses)
            .map_err(|_| ())?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .resolve_to_addrs(host, &addresses);
        if let Some(fixture) = fixture {
            // Do not mix system roots or this private CA into public requests.
            builder = builder.tls_certs_only(
                reqwest::Certificate::from_pem_bundle(&fixture.ca_pem).map_err(|_| ())?,
            );
        }
        let client = builder.build().map_err(|_| ())?;
        // No workload token, cookies, service credentials or caller headers.
        let mut response = client
            .get(url)
            .header("Accept", content_types.first().copied().ok_or(())?)
            .send()
            .await
            .map_err(|_| ())?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .is_none_or(|v| !content_types.contains(&v.trim()))
            || response
                .content_length()
                .is_some_and(|n| n > MAX_TOKEN_BYTES as u64)
        {
            return Err(());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|n| n > MAX_TOKEN_BYTES)
            {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    })
    .await
    .map_err(|_| ())?
}

// The credential issuer's previously governed key is the sole JWT authority.
// A status token's embedded JWK/x5c/jku never supplies or expands authority.
fn verify_token(
    token: &str,
    reference: &StatusReference,
    key: &Value,
    algorithm: &str,
    now: u64,
) -> Result<(u8, u64), ()> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(());
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|s| s.is_empty()) || parts[0].len() > 32768 {
        return Err(());
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| ())?)
        .map_err(|_| ())?;
    if header.get("typ").and_then(Value::as_str) != Some("statuslist+jwt")
        || header.get("alg").and_then(Value::as_str) != Some(algorithm)
        || !matches!(algorithm, "ES256" | "ES384" | "EdDSA" | "RS256")
        || header.get("crit").is_some()
        || header.get("b64").is_some()
    {
        return Err(());
    }
    let payload = if algorithm == "RS256" {
        if key.get("kty").and_then(Value::as_str) != Some("RSA") {
            return Err(());
        }
        let n = key
            .get("n")
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 1400)
            .ok_or(())?;
        let e = key
            .get("e")
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 12)
            .ok_or(())?;
        let n = URL_SAFE_NO_PAD.decode(n).map_err(|_| ())?;
        let e = URL_SAFE_NO_PAD.decode(e).map_err(|_| ())?;
        if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 8 {
            return Err(());
        }
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| ())?;
        let input = format!("{}.{}", parts[0], parts[1]);
        ring::signature::RsaPublicKeyComponents {
            n: n.as_slice(),
            e: e.as_slice(),
        }
        .verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            input.as_bytes(),
            &signature,
        )
        .map_err(|_| ())?;
        URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| ())?
    } else {
        let key: ssi_jwk::JWK = serde_json::from_value(key.clone()).map_err(|_| ())?;
        ssi_jws::decode_verify(token, &key).map_err(|_| ())?.1
    };
    let claims: Value = serde_json::from_slice(&payload).map_err(|_| ())?;
    let claims = claims.as_object().ok_or(())?;
    if claims.get("sub").and_then(Value::as_str) != Some(reference.uri.as_str()) {
        return Err(());
    }
    let iat = claims.get("iat").and_then(Value::as_u64).ok_or(())?;
    let mut valid_until = iat.checked_add(MAX_AGE_SECONDS).ok_or(())?;
    if iat > now || now >= valid_until {
        return Err(());
    }
    if let Some(exp) = claims.get("exp") {
        valid_until = valid_until.min(exp.as_u64().ok_or(())?);
    }
    if now >= valid_until {
        return Err(());
    }
    if claims
        .get("nbf")
        .is_some_and(|value| value.as_u64().is_none_or(|nbf| nbf > now))
    {
        return Err(());
    }
    if claims
        .get("ttl")
        .is_some_and(|v| v.as_u64().is_none_or(|n| n == 0))
    {
        return Err(());
    }
    let list = claims
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or(())?;
    let bits = list
        .get("bits")
        .and_then(Value::as_u64)
        .filter(|n| [1, 2, 4, 8].contains(n))
        .ok_or(())?;
    let compressed = URL_SAFE_NO_PAD
        .decode(list.get("lst").and_then(Value::as_str).ok_or(())?)
        .map_err(|_| ())?;
    let mut decoder = Decompress::new(true);
    let mut bytes = vec![0; MAX_LIST_BYTES + 1];
    let state = decoder
        .decompress(&compressed, &mut bytes, FlushDecompress::Finish)
        .map_err(|_| ())?;
    if state != Status::StreamEnd
        || decoder.total_out() > MAX_LIST_BYTES as u64
        || decoder.total_in() != compressed.len() as u64
    {
        return Err(());
    }
    bytes.truncate(decoder.total_out() as usize);
    let bit_index = reference.index.checked_mul(bits).ok_or(())?;
    let byte = bytes
        .get(usize::try_from(bit_index / 8).map_err(|_| ())?)
        .ok_or(())?;
    let mask = u8::MAX >> (8 - bits);
    Ok(((byte >> (bit_index % 8)) & mask, valid_until))
}

pub(crate) async fn sd_jwt_status(
    claims: &Map<String, Value>,
    key: &ResolvedIssuerKey,
    algorithm: &str,
    fixture: Option<&ExternalStatusFixtureTransport>,
) -> (CredentialStatusEvidence, Option<u64>) {
    let selected = reference(claims, fixture);
    if matches!(selected, Ok(None)) {
        return (CredentialStatusEvidence::default(), None);
    }
    let checked_at = chrono::Utc::now().timestamp().max(0) as u64;
    let result = match selected {
        Ok(Some(reference)) => match fetch(&reference.uri, fixture).await {
            Ok(token) => verify_token(
                &token,
                &reference,
                &key.public_jwk,
                algorithm,
                chrono::Utc::now().timestamp().max(0) as u64,
            ),
            Err(()) => Err(()),
        },
        _ => Err(()),
    };
    let (not_revoked, status, warnings, until) = match result {
        Ok((0, until)) => (Some(true), "VALID", Vec::new(), Some(until)),
        Ok((1, until)) => (Some(false), "REVOKED", Vec::new(), Some(until)),
        Ok((2, until)) => (Some(false), "SUSPENDED", Vec::new(), Some(until)),
        _ => (
            None,
            "UNKNOWN",
            vec!["External credential status is unavailable or invalid".into()],
            None,
        ),
    };
    (
        CredentialStatusEvidence {
            checked_at_epoch_seconds: Some(checked_at),
            not_revoked,
            credential_status: Some(status.into()),
            warnings,
        },
        until,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use flate2::{write::ZlibEncoder, Compression};
    use serde_json::json;
    use std::io::Write;

    fn fixture() -> (StatusReference, Value, Value) {
        let reference = StatusReference {
            uri: "https://status.example/list".into(),
            index: 3,
        };
        let key = SigningKey::from_bytes(&[7; 32]); // Deterministic public test fixture only.
        let jwk = json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())});
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[0b0100_0000]).unwrap(); // Two-bit entry 3 is REVOKED.
        let claims = json!({"sub": reference.uri, "iat":1000, "exp":1200, "ttl":60,
            "status_list":{"bits":2,"lst":URL_SAFE_NO_PAD.encode(encoder.finish().unwrap())}});
        (reference, jwk, claims)
    }

    fn signed(claims: &Value, mut header: Value, seed: u8) -> String {
        if header.is_null() {
            header = json!({"typ":"statuslist+jwt", "alg":"EdDSA"});
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        let signature = SigningKey::from_bytes(&[seed; 32]).sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn verifies_rsa_without_ssi_rsa_feature_or_private_key_import() {
        let fixture: Value =
            serde_json::from_str(include_str!("external_status_rsa_public_fixture.json")).unwrap();
        let reference = StatusReference {
            uri: "https://status.example/list".into(),
            index: 0,
        };
        let token = fixture["token"].as_str().unwrap();
        assert_eq!(
            verify_token(token, &reference, &fixture["public_jwk"], "RS256", 1100),
            Ok((0, 1200))
        );
        let mut changed = fixture["public_jwk"].clone();
        changed["e"] = json!("Aw");
        assert!(verify_token(token, &reference, &changed, "RS256", 1100).is_err());
    }

    #[test]
    fn verifies_issuer_signature_and_exact_status_index() {
        let (reference, key, claims) = fixture();
        assert_eq!(
            verify_token(
                &signed(&claims, Value::Null, 7),
                &reference,
                &key,
                "EdDSA",
                1100
            ),
            Ok((1, 1200))
        );
        let reference = StatusReference {
            index: 0,
            ..reference
        };
        assert_eq!(
            verify_token(
                &signed(&claims, Value::Null, 7),
                &reference,
                &key,
                "EdDSA",
                1100
            ),
            Ok((0, 1200))
        );
    }

    #[test]
    fn rejects_other_signer_even_with_embedded_key() {
        let (reference, key, claims) = fixture();
        let attacker = SigningKey::from_bytes(&[8; 32]);
        let header = json!({"typ":"statuslist+jwt","alg":"EdDSA","jwk":
            {"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(attacker.verifying_key().as_bytes())}});
        assert!(
            verify_token(&signed(&claims, header, 8), &reference, &key, "EdDSA", 1100).is_err()
        );
    }

    #[test]
    fn rejects_wrong_type_critical_header_or_algorithm() {
        let (reference, key, claims) = fixture();
        for header in [
            json!({"typ":"JWT","alg":"EdDSA"}),
            json!({"typ":"statuslist+jwt","alg":"none"}),
            json!({"typ":"statuslist+jwt","alg":"EdDSA","crit":["custom"]}),
            json!({"typ":"statuslist+jwt","alg":"EdDSA","b64":true}),
        ] {
            assert!(
                verify_token(&signed(&claims, header, 7), &reference, &key, "EdDSA", 1100).is_err()
            );
        }
        assert!(verify_token(
            &signed(&claims, Value::Null, 7),
            &reference,
            &key,
            "ES256",
            1100
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_subject_future_stale_expired_and_invalid_ttl() {
        let (reference, key, claims) = fixture();
        for (field, value) in [
            ("sub", json!("https://other.example/list")),
            ("iat", json!(1101)),
            ("iat", json!(800)),
            ("iat", json!(-1)),
            ("exp", json!(1100)),
            ("exp", json!("1200")),
            ("nbf", json!(1101)),
            ("nbf", json!("1000")),
            ("ttl", json!(0)),
            ("ttl", json!(-1)),
        ] {
            let mut changed = claims.clone();
            changed[field] = value;
            assert!(
                verify_token(
                    &signed(&changed, Value::Null, 7),
                    &reference,
                    &key,
                    "EdDSA",
                    1100
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn bounds_index_and_rejects_corrupt_or_trailing_compressed_payload() {
        let (reference, key, claims) = fixture();
        let out_of_bounds = StatusReference {
            index: 4,
            ..reference.clone()
        };
        assert!(verify_token(
            &signed(&claims, Value::Null, 7),
            &out_of_bounds,
            &key,
            "EdDSA",
            1100
        )
        .is_err());
        for bytes in [vec![1, 2, 3], {
            let mut bytes = URL_SAFE_NO_PAD
                .decode(claims["status_list"]["lst"].as_str().unwrap())
                .unwrap();
            bytes.push(0);
            bytes
        }] {
            let mut changed = claims.clone();
            changed["status_list"]["lst"] = json!(URL_SAFE_NO_PAD.encode(bytes));
            assert!(verify_token(
                &signed(&changed, Value::Null, 7),
                &reference,
                &key,
                "EdDSA",
                1100
            )
            .is_err());
        }
    }

    #[test]
    fn requires_complete_zlib_stream_even_when_status_byte_exists() {
        let (reference, key, claims) = fixture();
        assert!(verify_token(
            &signed(&claims, Value::Null, 7),
            &reference,
            &key,
            "EdDSA",
            1100
        )
        .is_ok());
        let original = URL_SAFE_NO_PAD
            .decode(claims["status_list"]["lst"].as_str().unwrap())
            .unwrap();
        for removed in [1, 4] {
            let mut changed = claims.clone();
            changed["status_list"]["lst"] =
                json!(URL_SAFE_NO_PAD.encode(&original[..original.len() - removed]));
            assert!(
                verify_token(
                    &signed(&changed, Value::Null, 7),
                    &reference,
                    &key,
                    "EdDSA",
                    1100
                )
                .is_err(),
                "a missing zlib checksum/end marker cannot supply status"
            );
        }
    }

    #[test]
    fn rejects_decompression_bomb() {
        let (reference, key, mut claims) = fixture();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&vec![0; MAX_LIST_BYTES + 1]).unwrap();
        claims["status_list"]["lst"] = json!(URL_SAFE_NO_PAD.encode(encoder.finish().unwrap()));
        assert!(verify_token(
            &signed(&claims, Value::Null, 7),
            &reference,
            &key,
            "EdDSA",
            1100
        )
        .is_err());
    }

    #[test]
    fn distinguishes_missing_from_malformed_status_and_rejects_url_authority_changes() {
        assert!(matches!(reference(&Map::new(), None), Ok(None)));
        for status in [
            Value::Null,
            json!({}),
            json!({"status_list":{"idx":"3","uri":"https://status.example/list"}}),
        ] {
            assert!(reference(json!({"status":status}).as_object().unwrap(), None).is_err());
        }
        for uri in [
            "http://status.example/list",
            "https://u:p@status.example/list",
            "https://status.example:8443/list",
            "https://status.example/list#x",
            "https://status.example/list?q=1",
        ] {
            assert!(reference(
                json!({"status":{"status_list":{"idx":3,"uri":uri}}})
                    .as_object()
                    .unwrap(),
                None
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn transport_rejects_local_metadata_without_network_access() {
        assert!(fetch("https://127.0.0.1/list", None).await.is_err());
        assert!(fetch("https://169.254.169.254/latest/meta-data", None)
            .await
            .is_err());
    }
    #[test]
    fn fixture_transport_requires_an_exact_origin_and_real_certificates() {
        let public: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/mdoc_presentation_signed_public.json"
        ))
        .unwrap();
        let pem = public["certificate_pem"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        for origin in [
            "http://localhost",
            "https://localhost/",
            "https://u:p@localhost",
            "https://localhost/path",
            "https://localhost?q=1",
            "https://localhost#x",
        ] {
            assert!(ExternalStatusFixtureTransport::new(origin, pem.clone()).is_err());
        }
        assert!(ExternalStatusFixtureTransport::new("https://localhost:8443", Vec::new()).is_err());
        assert!(
            ExternalStatusFixtureTransport::new("https://localhost:8443", b"not PEM".to_vec())
                .is_err()
        );
        let transport = ExternalStatusFixtureTransport::new("https://localhost:8443", pem).unwrap();
        for (uri, allowed) in [
            ("https://localhost:8443/list", true),
            ("https://localhost:8444/list", false),
            ("https://other:8443/list", false),
        ] {
            assert_eq!(
                reference(
                    json!({"status":{"status_list":{"idx":3,"uri":uri}}})
                        .as_object()
                        .unwrap(),
                    Some(&transport)
                )
                .is_ok(),
                allowed
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires an owned loopback HTTPS fixture and generated ephemeral certificates"]
    async fn live_fixture_https_transport_and_signed_status() {
        let origin = std::env::var("STATUS_HTTPS_TEST_ORIGIN").unwrap();
        let pem = std::fs::read(std::env::var("STATUS_HTTPS_TEST_CA").unwrap()).unwrap();
        let transport = ExternalStatusFixtureTransport::new(&origin, pem).unwrap();
        let (_, key, _) = fixture();
        let now = chrono::Utc::now().timestamp() as u64;
        for (path, expected) in [("valid", 0), ("revoked", 1)] {
            let uri = format!("{origin}/{path}");
            assert!(
                fetch(&uri, None).await.is_err(),
                "default must deny private address"
            );
            let token = fetch(&uri, Some(&transport)).await.unwrap();
            let reference = StatusReference { uri, index: 3 };
            assert_eq!(
                verify_token(&token, &reference, &key, "EdDSA", now)
                    .unwrap()
                    .0,
                expected
            );
        }
        for path in ["redirect", "wrong-content", "oversized"] {
            assert!(fetch(&format!("{origin}/{path}"), Some(&transport))
                .await
                .is_err());
        }
        for path in ["expired", "bad-signature"] {
            let uri = format!("{origin}/{path}");
            let token = fetch(&uri, Some(&transport)).await.unwrap();
            assert!(verify_token(
                &token,
                &StatusReference { uri, index: 3 },
                &key,
                "EdDSA",
                now
            )
            .is_err());
        }
        let wrong_ca = ExternalStatusFixtureTransport::new(
            &origin,
            std::fs::read(std::env::var("STATUS_HTTPS_TEST_WRONG_CA").unwrap()).unwrap(),
        )
        .unwrap();
        assert!(
            fetch(&format!("{origin}/valid"), Some(&wrong_ca))
                .await
                .is_err(),
            "wrong TLS root must fail"
        );
        let wrong_host = origin.replace("localhost", "127.0.0.1");
        let wrong_host_transport =
            ExternalStatusFixtureTransport::new(&wrong_host, transport.ca_pem.clone()).unwrap();
        assert!(
            fetch(&format!("{wrong_host}/valid"), Some(&wrong_host_transport))
                .await
                .is_err(),
            "TLS hostname must be checked"
        );
        let values = |origin: &str, ca: &str| {
            [
                ("ENVIRONMENT".into(), "test".into()),
                ("DATABASE_URL".into(), "postgres://localhost/test".into()),
                (
                    "PRESENTATION_POLICY_STATUS_FIXTURE_ORIGIN".into(),
                    origin.into(),
                ),
                (
                    "PRESENTATION_POLICY_STATUS_FIXTURE_CA_FILE".into(),
                    ca.into(),
                ),
            ]
        };
        let ca = std::env::var("STATUS_HTTPS_TEST_CA").unwrap();
        let config =
            crate::PresentationPolicyServiceConfig::from_values(values(&origin, &ca)).unwrap();
        assert_eq!(config.external_status_fixture_transport, Some(transport));
        assert!(crate::PresentationPolicyServiceConfig::from_values(values(
            &origin,
            "/missing-ca"
        ))
        .is_err());
    }
}
