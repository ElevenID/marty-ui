// Shared synthetic public DID documents and independent holder test support.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_didcomm::{
    types::{Jwk, VerificationMethod},
    DidDocument,
};
use serde_json::json;

pub const SYNTHETIC_SIGNING_PUBLIC_X: &str = "Zr5-Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo";
pub const SYNTHETIC_SENDER_X25519_PUBLIC_X: &str = "V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE";

pub fn recipient_document() -> DidDocument {
    let did = "did:example:holder";
    let key_id = format!("{did}#key-1");
    let mut document = DidDocument::new(did);
    document.set_key_agreements(vec![json!(key_id)]).unwrap();
    let mut method = VerificationMethod::new(key_id, "JsonWebKey2020", did);
    method.public_key_jwk = Some(Jwk::new_public(
        "OKP",
        Some("X25519".to_owned()),
        Some(URL_SAFE_NO_PAD.encode([7_u8; 32])),
        None,
        None,
    ));
    document.verification_method = vec![method];
    document
}

pub fn holder_with_id(recipient: &str) -> (DidDocument, [u8; 32]) {
    (
        document_with_public(
            recipient,
            &URL_SAFE_NO_PAD.encode(
                hex::decode("13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d")
                    .unwrap(),
            ),
        ),
        [7_u8; 32],
    )
}

pub fn document_with_public(did: &str, public_x: &str) -> DidDocument {
    document_with_public_and_signing(did, public_x, SYNTHETIC_SIGNING_PUBLIC_X)
}

pub fn document_with_public_and_signing(did: &str, public_x: &str, signing_x: &str) -> DidDocument {
    assert_eq!(URL_SAFE_NO_PAD.decode(public_x).unwrap().len(), 32);
    assert_eq!(URL_SAFE_NO_PAD.decode(signing_x).unwrap().len(), 32);
    let mut document = recipient_document();
    document.id = did.to_owned();
    let key_id = format!("{did}#key-1");
    document.set_key_agreements(vec![json!(key_id)]).unwrap();
    document.verification_method[0].id = key_id;
    document.verification_method[0].controller = did.to_owned();
    document.verification_method[0]
        .public_key_jwk
        .as_mut()
        .unwrap()
        .x = Some(public_x.to_owned());
    // The managed resolver requires a distinct signing relationship.
    let mut signing_method = document.verification_method[0].clone();
    signing_method.id = format!("{did}#signing-1");
    let signing_jwk = signing_method.public_key_jwk.as_mut().unwrap();
    signing_jwk.crv = Some("Ed25519".to_owned());
    signing_jwk.x = Some(signing_x.to_owned());
    document
        .set_assertion_methods(vec![json!(signing_method.id)])
        .unwrap();
    document.verification_method.push(signing_method);
    document
}

// Base58btc of the X25519 multicodec prefix EC01 and the synthetic holder
// public key. Tests verify its decoded key through canonical Core.
pub const SYNTHETIC_RECIPIENT_MULTIBASE: &str = "z6LSd1FDxqS6PDoWwxco3fnM3DGEuXyse6pr7uRRYamJDqit";

// Holder-side interoperability checks use an independent DIDComm implementation.
// This is test support only; production Core is built without local key operations.
#[allow(dead_code)] // This shared file is included by tests with different holder paths.
pub struct HolderDecryption {
    pub plaintext: String,
    pub sender_kid: String,
    pub recipient_kid: String,
}

#[allow(dead_code)]
pub fn holder_decrypt_anoncrypt(jwe: &str, recipient_secret: &[u8; 32]) -> String {
    use affinidi_messaging_didcomm::{
        crypto::key_agreement::{Curve, PrivateKeyAgreement},
        jwe::decrypt,
    };
    let recipient_private = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, recipient_secret)
        .expect("holder X25519 secret");
    let value: serde_json::Value = serde_json::from_str(jwe).expect("DIDComm JWE");
    let recipients = value["recipients"].as_array().expect("JWE recipients");
    let decrypted = recipients
        .iter()
        .filter_map(|recipient| {
            recipient
                .pointer("/header/kid")
                .and_then(|kid| kid.as_str())
        })
        .find_map(|kid| decrypt::decrypt(jwe, kid, &recipient_private, None).ok())
        .expect("holder can open anoncrypt JWE");
    assert!(!decrypted.authenticated);
    String::from_utf8(decrypted.plaintext).expect("UTF-8 DIDComm plaintext")
}

#[allow(dead_code)]
pub fn holder_decrypt_authcrypt(
    jwe: &str,
    recipient_secret: &[u8; 32],
    recipient_document: &DidDocument,
    sender_document: &DidDocument,
) -> HolderDecryption {
    use affinidi_messaging_didcomm::{
        crypto::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement},
        jwe::decrypt,
    };
    let recipient_private = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, recipient_secret)
        .expect("holder X25519 secret");
    let PublicKeyAgreement::X25519(recipient_public) = recipient_private.public_key() else {
        unreachable!("holder key is X25519")
    };
    let recipient_kid = recipient_document
        .x25519_key_agreement_methods()
        .expect("valid holder DID document")
        .into_iter()
        .find_map(|(kid, public)| (public == recipient_public).then_some(kid))
        .expect("holder secret authorized by DID document");
    let value: serde_json::Value = serde_json::from_str(jwe).expect("DIDComm JWE");
    let header_bytes = URL_SAFE_NO_PAD
        .decode(value["protected"].as_str().expect("protected header"))
        .expect("base64url protected header");
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).expect("protected header JSON");
    let sender_kid = header["skid"].as_str().expect("authenticated sender kid");
    let sender_public = sender_document
        .x25519_key_agreement_methods()
        .expect("valid sender DID document")
        .into_iter()
        .find_map(|(kid, public)| (kid == sender_kid).then_some(public))
        .expect("sender kid authorized by DID document");
    let sender_public = PublicKeyAgreement::from_raw_bytes(Curve::X25519, &sender_public)
        .expect("sender X25519 public key");
    let decrypted = decrypt::decrypt(
        jwe,
        &recipient_kid,
        &recipient_private,
        Some(&sender_public),
    )
    .expect("holder can open authcrypt JWE");
    assert!(decrypted.authenticated && !decrypted.legacy_kek_used);
    assert_eq!(decrypted.sender_kid.as_deref(), Some(sender_kid));
    HolderDecryption {
        plaintext: String::from_utf8(decrypted.plaintext).expect("UTF-8 DIDComm plaintext"),
        sender_kid: sender_kid.to_owned(),
        recipient_kid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synthetic_documents_round_trip_as_public_did_documents() {
        let sender =
            document_with_public("did:web:issuer.example", SYNTHETIC_SENDER_X25519_PUBLIC_X);
        let (recipient, recipient_secret) = holder_with_id("did:example:holder");
        for document in [recipient_document(), sender, recipient] {
            let value = serde_json::to_value(&document).unwrap();
            assert!(value["verificationMethod"]
                .as_array()
                .unwrap()
                .iter()
                .all(|method| method["publicKeyJwk"].get("d").is_none()));
            let round_trip: DidDocument = serde_json::from_value(value).unwrap();
            assert_eq!(
                round_trip.x25519_key_agreement_methods().unwrap(),
                document.x25519_key_agreement_methods().unwrap()
            );
        }
        assert_eq!(recipient_secret, [7_u8; 32]);
        assert_eq!(
            SYNTHETIC_RECIPIENT_MULTIBASE,
            "z6LSd1FDxqS6PDoWwxco3fnM3DGEuXyse6pr7uRRYamJDqit"
        );
    }

    #[test]
    fn parameterized_parties_change_only_document_identifiers() {
        let old_sender =
            document_with_public("did:web:issuer.example", SYNTHETIC_SENDER_X25519_PUBLIC_X);
        let (old_recipient, old_recipient_secret) = holder_with_id("did:example:holder");
        let sender = document_with_public("did:web:sender.test", SYNTHETIC_SENDER_X25519_PUBLIC_X);
        let (recipient, recipient_secret) = holder_with_id("did:web:recipient.test");
        for (old, new) in [(old_sender, sender), (old_recipient, recipient)] {
            let expected = serde_json::to_string(&old)
                .unwrap()
                .replace(&old.id, &new.id);
            assert_eq!(serde_json::to_vec(&new).unwrap(), expected.as_bytes());
        }
        assert_eq!(recipient_secret, old_recipient_secret);
    }
}
