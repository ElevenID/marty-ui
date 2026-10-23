//! Real HTTP registry lookup followed by native JWT signature verification.
use async_trait::async_trait;
use axum::{http::HeaderMap, routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use marty_issuer_key_resolution::{
    registry::HttpOrganizationIssuerResolver, IssuerKeyResolution, IssuerKeyResolutionError,
    IssuerKeyResolver,
};
use marty_presentation_policy::{
    CredentialVerificationContext, CredentialVerificationKernel, ResolvedTrustProfile,
    ResolvingCredentialKernel,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Map, Value};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const DID: &str = "did:web:issuer.example";
const KID: &str = "did:web:issuer.example#assertion";

struct NoPublic;
#[async_trait]
impl IssuerKeyResolver for NoPublic {
    async fn resolve(&self, _: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
        panic!("a scoped identity must not use ambient public resolution")
    }
}

fn token(key: &SigningKey, sd_jwt: bool) -> String {
    let now = chrono::Utc::now();
    let header = URL_SAFE_NO_PAD.encode(
        json!({"alg":"EdDSA", "typ":if sd_jwt {"vc+sd-jwt"} else {"JWT"}, "kid":KID}).to_string(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss":DID,"sub":"did:example:holder","jti":"urn:uuid:registry-issued-credential",
            "nbf":now.timestamp()-60,"iat":now.timestamp()-60,"exp":now.timestamp()+3600,
            "_sd_alg":"sha-256","_sd":[],"vct":"urn:example:member",
        "vc":{"@context":["https://www.w3.org/ns/credentials/v2"],
                "id":"urn:uuid:registry-issued-credential","type":["VerifiableCredential"],
            "issuer":DID,"validFrom":(now-chrono::Duration::seconds(60)).to_rfc3339(),
                "credentialSubject":{"id":"did:example:holder","role":"member"}}
        })
        .to_string(),
    );
    let input = format!("{header}.{payload}");
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    )
}

fn registry_response(key: &SigningKey) -> Value {
    let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())});
    json!({"ok":true, "organization_id":"org-1","issuer_did":DID,"algorithm":"EdDSA", "key_purpose":"vc_jwt_issuer",
        "verification_method_id":KID,
        "issuer_profile":{"organization_id":"org-1","issuer_did":DID,"status":"active","credential_format":"VC_JWT","algorithm":"EdDSA","key_purpose":"vc_jwt_issuer"},
        "did_document":{"id":DID,"verificationMethod":[{"id":KID,"controller":DID,"type":"JsonWebKey2020","publicKeyJwk":jwk}],"assertionMethod":[KID]},
        "resolver":{"public_fallback_used":false,"resolved_at":chrono::Utc::now().to_rfc3339()}
    })
}

#[tokio::test]
async fn registry_bound_signature_verifies_and_context_or_method_mutations_fail_closed() {
    // Test-only key material; deployment qualification separately requires KMS custody.
    let key = SigningKey::from_bytes(&[42; 32]);
    let signed = token(&key, false);
    let mut public_key =
        registry_response(&key)["did_document"]["verificationMethod"][0]["publicKeyJwk"].clone();
    public_key["kid"] = json!(KID);
    let raw = marty_verification::vcdm::verify_vcdm_jwt_json_async(
        &json!({"token":signed,"issuer_public_jwk":public_key}).to_string(),
    )
    .await;
    let native: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        native["valid"],
        json!(true),
        "test credential must satisfy the canonical verifier: {raw}"
    );
    exercise_registry(&key, json!(signed), DetectedCredentialFormat::W3cVc).await;
}

#[tokio::test]
async fn sd_jwt_registry_bound_signature_and_mutations_follow_the_same_policy() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let signed = format!("{}~", token(&key, true));
    exercise_registry(&key, json!(signed), DetectedCredentialFormat::SdJwt).await;
}

#[tokio::test]
async fn data_integrity_registry_binding_and_assertion_method_pins_are_enforced() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let public =
        registry_response(&key)["did_document"]["verificationMethod"][0]["publicKeyJwk"].clone();
    let prepared = marty_verification::vcdm::prepare_vcdm_data_integrity_credential_json_async(&json!({
        "credential":{"@context":["https://www.w3.org/ns/credentials/v2"],
            "id":"urn:uuid:2f2e1a96-3f33-4be7-90d9-fca583d23a8b","type":["VerifiableCredential"],
            "issuer":DID,"validFrom":(chrono::Utc::now()-chrono::Duration::seconds(60)).to_rfc3339(),
            "credentialSubject":{"id":"did:example:holder"}},
        "issuer_did":DID,"verification_method_id":KID,"public_jwk":public
    }).to_string()).await.unwrap();
    let prepared: Value = serde_json::from_str(&prepared).unwrap();
    let input = URL_SAFE_NO_PAD
        .decode(prepared["signing_input_b64"].as_str().unwrap())
        .unwrap();
    let credential = marty_verification::vcdm::complete_vcdm_data_integrity_credential_json_async(
        &json!({
            "prepared":prepared,"signature_b64":URL_SAFE_NO_PAD.encode(key.sign(&input).to_bytes())
        })
        .to_string(),
    )
    .await
    .unwrap();
    exercise_registry(
        &key,
        serde_json::from_str(&credential).unwrap(),
        DetectedCredentialFormat::W3cVcdmDi,
    )
    .await;
}

async fn exercise_registry(key: &SigningKey, signed: Value, format: DetectedCredentialFormat) {
    let wire_format = match format {
        DetectedCredentialFormat::SdJwt => "SD_JWT_VC",
        DetectedCredentialFormat::W3cVcdmDi => "JSON_LD",
        _ => "VC_JWT",
    };
    for case in [
        "valid",
        "wrong-tenant",
        "inactive",
        "wrong-pin",
        "unauthorized-method",
        "wrong-signature",
    ] {
        let mut response = registry_response(key);
        match case {
            "wrong-tenant" => response["issuer_profile"]["organization_id"] = json!("org-2"),
            "inactive" => response["issuer_profile"]["status"] = json!("revoked"),
            "unauthorized-method" => response["did_document"]["assertionMethod"] = json!([]),
            "wrong-signature" => response = registry_response(&SigningKey::from_bytes(&[43; 32])),
            _ => {}
        }
        response["issuer_profile"]["credential_format"] = json!(wire_format);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route("/internal/compat/resolve-issuer-did",post(move |headers:HeaderMap,Json(request):Json<Value>|{
            let response=response.clone();
            async move {
                assert_eq!(headers["x-api-key"],"test-internal-credential");
                assert_eq!(request,json!({"organization_id":"org-1","issuer_did":DID,"credential_format":wire_format,"key_purpose":"vc_jwt_issuer","algorithm":"EdDSA"}));
                Json(response)
            }
        }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let registry = HttpOrganizationIssuerResolver::new(
            &base,
            "test-internal-credential",
            Duration::from_secs(2),
        )
        .unwrap();
        let kernel =
            ResolvingCredentialKernel::new(Arc::new(NoPublic)).with_registry(Arc::new(registry));
        let context = CredentialVerificationContext {
            resolved_issuer_public_jwk: None,
            format,
            token: signed.clone(),
            nonce: None,
            audience: None,
            verifier_context: Map::new(),
            trust_profile: Some(ResolvedTrustProfile {
                id: Uuid::new_v4(),
                organization_id: Uuid::new_v4(),
                document: json!({
                    "status":"active","trust_sources":[{"issuer_did":DID,"organization_id":"org-1",
                        "verification_method_ids":[if case=="wrong-pin" {"did:web:issuer.example#other"} else {KID}],
                        "did_resolution":{"allow_public_fallback":true,"cache_ttl_seconds":0}}]
                }),
            }),
        };
        let evidence = kernel.verify(&context).await.unwrap();
        server.abort();
        assert_eq!(
            evidence.verified,
            case == "valid",
            "{case}: {:?}",
            evidence.failure_reason
        );
        if case == "valid" {
            assert_eq!(evidence.issuer_id.as_deref(), Some(DID));
            if format == DetectedCredentialFormat::W3cVcdmDi {
                assert_eq!(
                    evidence.claims.get("id"),
                    Some(&json!("did:example:holder"))
                );
            } else {
                assert_eq!(evidence.claims.get("role"), Some(&json!("member")));
            }
        } else {
            assert!(evidence.claims.is_empty(), "{case}");
            assert!(evidence.issuer_id.is_none(), "{case}");
        }
    }
}
