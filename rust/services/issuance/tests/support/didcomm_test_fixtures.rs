// Shared synthetic DID documents only; production crypto remains in pinned Core.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_didcomm::{
    types::{Jwk, VerificationMethod},
    DidDocument,
};
use serde_json::json;

pub fn recipient_document() -> DidDocument {
    let did = "did:example:holder";
    let key_id = format!("{did}#key-1");
    DidDocument {
        id: did.to_owned(),
        context: serde_json::Value::Null,
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        key_agreement: vec![json!(key_id)],
        verification_method: vec![VerificationMethod {
            id: key_id,
            r#type: "JsonWebKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_jwk: Some(Jwk {
                kty: "OKP".to_owned(),
                crv: Some("X25519".to_owned()),
                x: Some(URL_SAFE_NO_PAD.encode([7_u8; 32])),
                y: None,
                d: None,
                kid: None,
                additional_properties: serde_json::Map::new(),
            }),
            public_key_multibase: None,
            public_key_base58: None,
            additional_properties: serde_json::Map::new(),
        }],
        service: Vec::new(),
        additional_properties: serde_json::Map::new(),
    }
}

pub fn authcrypt_parties() -> (DidDocument, [u8; 32], DidDocument, [u8; 32]) {
    authcrypt_parties_with_ids("did:web:issuer.example", "did:example:holder")
}

pub fn authcrypt_parties_with_ids(
    sender: &str,
    recipient: &str,
) -> (DidDocument, [u8; 32], DidDocument, [u8; 32]) {
    // Public values independently derived from the synthetic repeated-byte
    // secrets. Production envelope/key binding remains entirely in Core.
    let document = |did: &str, public_hex: &str| {
        let mut document = recipient_document();
        document.id = did.to_owned();
        let key_id = format!("{did}#key-1");
        document.key_agreement = vec![json!(key_id)];
        document.verification_method[0].id = key_id;
        document.verification_method[0].controller = did.to_owned();
        document.verification_method[0]
            .public_key_jwk
            .as_mut()
            .unwrap()
            .x = Some(URL_SAFE_NO_PAD.encode(hex::decode(public_hex).unwrap()));
        // The managed resolver also requires an authentication/assertion
        // relationship; use a separate synthetic signing key, not X25519.
        let mut signing_method = document.verification_method[0].clone();
        signing_method.id = format!("{did}#signing-1");
        let signing_jwk = signing_method.public_key_jwk.as_mut().unwrap();
        signing_jwk.crv = Some("Ed25519".to_owned());
        signing_jwk.x = Some(
            URL_SAFE_NO_PAD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        );
        document.assertion_method = vec![json!(signing_method.id)];
        document.verification_method.push(signing_method);
        document
    };
    (
        document(
            sender,
            "57db4b359f23ae5e146e4e2512056704722506348c150c14753d0c933d04d421",
        ),
        [9_u8; 32],
        document(
            recipient,
            "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d",
        ),
        [7_u8; 32],
    )
}

// Base58btc of the X25519 multicodec prefix EC01 and authcrypt_parties'
// synthetic recipient public key. Both tests verify its decoded key through
// canonical Core; no local multibase/resolver implementation is introduced.
pub const SYNTHETIC_RECIPIENT_MULTIBASE: &str = "z6LSd1FDxqS6PDoWwxco3fnM3DGEuXyse6pr7uRRYamJDqit";

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn synthetic_documents_preserve_executed_pre_extraction_bytes() {
        // Captured by executing the old builders at source aa33eff6f9e971459758191fde4728fbb494421d,
        // initiation_didcomm.rs Git blob 2ced767c1ae23b71abb4d44f6fdf385fbb93254c.
        // Before deleting them, shared_synthetic_documents_preserve_pre_extraction_bytes
        // compared every serialized byte with these shared builders and passed.
        // These are hashes of serde_json::to_vec(DidDocument), not checkout hashes.
        let (sender, sender_secret, recipient, recipient_secret) = authcrypt_parties();
        for (document, expected) in [
            (
                recipient_document(),
                "e8dd4098b7424f579d91cd257c21b18168ff0293d950310a7b3bb9598c2f568b",
            ),
            (
                sender,
                "2513212613df6ae7232858d5af2cac85c69a2419cfab4e4181cc4fce3f2c3b28",
            ),
            (
                recipient,
                "e5952ead4e34ac2bc1c12643f3574f5364c0a6138c818aa26b20b53340ccf83a",
            ),
        ] {
            assert_eq!(
                hex::encode(sha2::Sha256::digest(serde_json::to_vec(&document).unwrap())),
                expected
            );
        }
        assert_eq!(sender_secret, [9_u8; 32]);
        assert_eq!(recipient_secret, [7_u8; 32]);
        assert_eq!(
            SYNTHETIC_RECIPIENT_MULTIBASE,
            "z6LSd1FDxqS6PDoWwxco3fnM3DGEuXyse6pr7uRRYamJDqit"
        );
    }

    #[test]
    fn parameterized_parties_change_only_document_identifiers() {
        let (old_sender, old_sender_secret, old_recipient, old_recipient_secret) =
            authcrypt_parties();
        let (sender, sender_secret, recipient, recipient_secret) =
            authcrypt_parties_with_ids("did:web:sender.test", "did:web:recipient.test");
        for (old, new) in [(old_sender, sender), (old_recipient, recipient)] {
            let expected = serde_json::to_string(&old)
                .unwrap()
                .replace(&old.id, &new.id);
            assert_eq!(serde_json::to_vec(&new).unwrap(), expected.as_bytes());
        }
        assert_eq!(sender_secret, old_sender_secret);
        assert_eq!(recipient_secret, old_recipient_secret);
    }
}
