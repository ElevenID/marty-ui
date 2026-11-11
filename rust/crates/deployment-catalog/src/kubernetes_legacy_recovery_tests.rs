use super::*;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use spki::{
    der::{asn1::BitString, DecodePem, EncodePem},
    AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    str::FromStr,
    sync::Mutex,
};
use x509_cert::{
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        AsExtension,
    },
    name::Name,
};

const ROOT: &str = "synthetic-retained-root-token-for-local-tests";
const NAMESPACE: &str = "marty-ux";
const NAMESPACE_UID: &str = "50ab59c0-045b-4b42-96ca-82e63ef02ac3";
const CLUSTER: &str = "a290aeec-d21d-4a72-99fa-17e2e9a59d4c";
const ISSUER: &str = "ac11aa00-c8c6-441a-933f-204549235c87";
const KEY: &str = "a1aab800-3464-4ae0-99ab-1c6e1bebdc2f";
const NONCE: &str = "012345abcdef";
// Existing public-only fixture from signing-keys/managed_key_create_mock_contract.
const RSA_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxZrSKXzXy4gpAp6iFW/B\nXWnIOL377WmFDT/H3IpLN7rg9rIS/FKyBtWFUICfDVwfoCMElc3nz+Pedl2Dw2b4\nFLomW89q2op6RVfuXK1QTgVfrvfF/30feNti6iemScKBibXkPLfCLZL0k8DU+PIC\nIHASwNCjmv3OTFIlv4am7/DemiOHqezP8JAK3Yc2n3kWZFeMnFomq3jFzjKABNHX\nN10EwkWLy7PFxhmdoZnRF4chIgIqT+YRyFt5r1f9n9OtW9uoQ0P+lBP3y3sv67Ng\nlAqxySz2siHm2Q87ZLAgMJztoncChb7ea6VRamaPR0qcfGmoeK5HPhPUZRBptMFF\nTwIDAQAB\n-----END PUBLIC KEY-----\n";

fn pem(certificate: &Certificate) -> Vec<u8> {
    certificate
        .to_pem(spki::der::pem::LineEnding::LF)
        .unwrap()
        .into_bytes()
}

fn sign(mut certificate: Certificate, key: &EcdsaKeyPair) -> Certificate {
    certificate.signature_algorithm = AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        parameters: None,
    };
    certificate.tbs_certificate.signature = certificate.signature_algorithm.clone();
    certificate.signature = BitString::from_bytes(
        key.sign(
            &SystemRandom::new(),
            &certificate.tbs_certificate.to_der().unwrap(),
        )
        .unwrap()
        .as_ref(),
    )
    .unwrap();
    certificate
}

struct Certificates {
    key: EcdsaKeyPair,
    ca: Certificate,
    ec: Certificate,
    rsa: Certificate,
    now: u64,
}

impl Certificates {
    fn new() -> Self {
        let random = SystemRandom::new();
        let private =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private.as_ref(), &random)
                .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut ca = Certificate::from_pem(include_bytes!(
            "../../../../tests/fixtures/selfhost_ca_issuer_public.pem"
        ))
        .unwrap();
        ca.tbs_certificate.subject = Name::from_str("CN=Local recovery test issuer").unwrap();
        ca.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
        ca.tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(key.public_key().as_ref()).unwrap();
        ca.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(now - 86_400))
            .try_into()
            .unwrap();
        ca.tbs_certificate.validity.not_after = (UNIX_EPOCH
            + Duration::from_secs(now + 7 * 86_400))
        .try_into()
        .unwrap();
        ca.tbs_certificate.extensions = Some(vec![
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_extension(&ca.tbs_certificate.subject, &[])
            .unwrap(),
            KeyUsage(KeyUsages::KeyCertSign.into())
                .to_extension(&ca.tbs_certificate.subject, &[])
                .unwrap(),
        ]);
        let ca = sign(ca, &key);
        let mut ec = Certificate::from_pem(include_bytes!(
            "../../../../tests/fixtures/acme/le-first-shortlived-leaf.pem"
        ))
        .unwrap();
        ec.tbs_certificate.subject = Name::from_str("CN=legacy-retained-workload").unwrap();
        ec.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
        ec.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(now - 43_200))
            .try_into()
            .unwrap();
        ec.tbs_certificate.validity.not_after = (UNIX_EPOCH + Duration::from_secs(now - 14_400))
            .try_into()
            .unwrap();
        ec.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|extension| {
                ["2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.37"]
                    .contains(&extension.extn_id.to_string().as_str())
            });
        let ec = sign(ec, &key);
        let mut rsa = ec.clone();
        rsa.tbs_certificate.subject_public_key_info =
            SubjectPublicKeyInfoOwned::from_pem(RSA_PUBLIC).unwrap();
        let rsa = sign(rsa, &key);
        Self {
            key,
            ca,
            ec,
            rsa,
            now,
        }
    }

    fn issuer(&self) -> Value {
        json!({"data":{"issuer_id":ISSUER, "key_id":KEY, "certificate":String::from_utf8(pem(&self.ca)).unwrap(),
            "revoked":false, "usage":"crl-signing,issuing-certificates,ocsp-signing,read-only"}})
    }
}

struct Reads {
    responses: BTreeMap<String, Value>,
    calls: Mutex<Vec<(String, bool)>>,
    change_on_final_health: Option<PathBuf>,
}

#[async_trait]
impl ReadApi for Reads {
    async fn read(&self, path: &str, token: Option<&str>) -> Result<Value> {
        let mut calls = self.calls.lock().unwrap();
        if path == "sys/health" {
            assert!(
                token.is_none(),
                "health must precede authenticated admission"
            );
            if calls.iter().any(|(old, _)| old == path) {
                if let Some(path) = &self.change_on_final_health {
                    fs::write(path, b"concurrent-input-change").unwrap();
                }
            }
        } else {
            assert_eq!(token, Some(ROOT));
        }
        calls.push((path.into(), token.is_some()));
        self.responses.get(path).cloned().ok_or(REFUSAL)
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    context: Context,
    reads: Reads,
    certificates: Certificates,
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let current = directory.path().join("current");
        fs::create_dir(&current).unwrap();
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
        let root_token_file = directory.path().join("root-token");
        write(&root_token_file, ROOT.as_bytes(), 0o400);
        let project = format!("marty-selfhost-disposable-k8s-{NONCE}");
        let requests: Vec<_> = specifications().iter().map(|spec| json!({
            "input":spec.input, "requestedPolicies":spec.policies,
            "requestedTtl":if spec.input == "OPENBAO_BOOTSTRAP_TOKEN" {"2h"} else {"8h"},
            "requestedRenewable":false,"requestedOrphan":true,"requestedNoDefaultPolicy":true,
        })).collect();
        let bootstrap = json!({"bootstrapId":"23627ef5-47fb-4305-985b-69e52b1f489e",
            "namespace":NAMESPACE,"openbaoClusterId":CLUSTER,"runtimeSourceSha":LEGACY_RUNTIME,
            "chartSourceSha":"25a71a7c557599a07939ba48a9a511caed7fbc29",
            "status":"openbao-and-application-credentials-ready","credentialLifetimeHours":8,
            "migrationBootstrapLifetimeHours":2,"credentialLifecycle":{
                "schema":"marty.kubernetes-credential-lifecycle/v1","namespaceUid":NAMESPACE_UID,
                "producerNonce":NONCE,"workloadProject":project,"ordinaryTokens":requests}});
        let context = Context {
            schema: SCHEMA.into(),
            initialize_request: json!({
            "bootstrapId":bootstrap["bootstrapId"],"namespace":NAMESPACE,"namespaceUid":NAMESPACE_UID,
            "producerNonce":NONCE,"workloadProject":project,"operation":"bao operator init",
            "recoveryShares":1,"recoveryThreshold":1}),
            bootstrap,
            tls_key_metadata: json!({"schema":"marty.selfhost-disposable-tls-keys/v1",
                "roles":SELFHOST_ROLES.iter().map(|role| json!({"role":role.name,"key_name":role.key_name,"version":1})).collect::<Vec<_>>() }),
            namespace_observation: NamespaceObservation {
                name: NAMESPACE.into(),
                uid: NAMESPACE_UID.into(),
            },
            current,
            root_token_file,
            retained_root_sha256: sha256(ROOT.as_bytes()),
        };
        let certificates = Certificates::new();
        let ec_pem = pem(&certificates.ec);
        let rsa_pem = pem(&certificates.rsa);
        let ec_public = certificates
            .ec
            .tbs_certificate
            .subject_public_key_info
            .to_pem(spki::der::pem::LineEnding::LF)
            .unwrap();
        let mut responses = BTreeMap::from([
            (
                "sys/health".into(),
                json!({"initialized":true,"sealed":false,"standby":false,"cluster_id":CLUSTER,"version":LEGACY_OPENBAO_VERSION}),
            ),
            (
                "auth/token/lookup-self".into(),
                json!({"data":{"policies":["root"],"ttl":0,"orphan":true,"path":"auth/token/root"}}),
            ),
            (
                "sys/auth".into(),
                json!({"data":{"token/":{"type":"token"}}}),
            ),
            (
                "sys/mounts".into(),
                json!({"data":{"transit/":{"type":"transit"},"didcomm/":{"type":"openbao-didcomm-authcrypt"},
                "workload-pki/":{"type":"pki"},"keycloak-pki/":{"type":"pki"}}}),
            ),
        ]);
        for mount in ["workload-pki", "keycloak-pki"] {
            responses.insert(format!("{mount}/issuer/default"), certificates.issuer());
            responses.insert(format!("{mount}/issuer/{ISSUER}"), certificates.issuer());
        }
        write(
            &context.current.join("workload_identity_ca_cert"),
            &pem(&certificates.ca),
            0o644,
        );
        write(
            &context.current.join("openbao_tls_ca_cert"),
            &pem(&certificates.ca),
            0o644,
        );
        for spec in specifications() {
            write(
                &context.current.join(spec.file),
                b"synthetic-expired-ordinary-token",
                0o600,
            );
        }
        for role in SELFHOST_ROLES {
            write(&context.current.join(role.cert_file), &ec_pem, 0o644);
            write(
                &context.current.join(role.token_file),
                b"synthetic-expired-tls-token",
                0o600,
            );
            responses.insert(format!("transit/keys/{}",role.key_name), json!({"data":{
                "type":"ecdsa-p256","latest_version":1,"exportable":false,"allow_plaintext_backup":false,
                "keys":{"1":{"public_key":ec_public}}}}));
            let profile = WORKLOAD_TLS_ROLES
                .iter()
                .find(|item| item.name == role.name)
                .unwrap();
            responses.insert(format!("workload-pki/roles/{}",role.name), json!({"data":{
                "allow_any_name":true,"allow_localhost":true,"allow_ip_sans":true,"server_flag":profile.server,"client_flag":profile.client,
                "key_type":"ec","key_bits":256,"max_ttl":86400,"use_csr_common_name":false,"use_csr_sans":false,
                "allowed_uri_sans":profile.uri_sans.split(',').filter(|part| !part.is_empty()).collect::<Vec<_>>(),"issuer_ref":ISSUER}}));
            let name = format!("{project}-{}", role.key_name);
            responses.insert(format!("sys/policies/acl/{name}"),json!({"data":{"policy":format!(
                "path \"transit/keys/{}\" {{ capabilities = [\"read\"] }}\npath \"transit/sign/{}\" {{ capabilities = [\"update\"] }}",role.key_name,role.key_name)}}));
        }
        responses.insert("keycloak-pki/roles/rs256".into(),json!({"data":{"key_type":"rsa","key_bits":2048,"allow_any_name":true,
            "max_ttl":28800,"use_csr_common_name":false,"use_csr_sans":false,"issuer_ref":"default"}}));
        write(
            &context.current.join("keycloak_signing_kms_token"),
            b"synthetic-expired-keycloak-signing-token",
            0o600,
        );
        for realm in keycloak::REALMS {
            write(
                &context.current.join(format!("keycloak_{realm}_rs256_cert")),
                &rsa_pem,
                0o644,
            );
            for (suffix, kind) in [("rs256", "rsa-2048"), ("hs512", "hmac")] {
                responses.insert(format!("transit/keys/keycloak-{realm}-{suffix}"),json!({"data":{
                    "type":kind,"latest_version":1,"exportable":false,"allow_plaintext_backup":false,"keys":{"1":{"public_key":RSA_PUBLIC}}}}));
            }
            for purpose in keycloak::PURPOSES {
                write(
                    &context
                        .current
                        .join(format!("keycloak_{realm}_{purpose}_token")),
                    b"synthetic-expired-keycloak-jwe-token",
                    0o600,
                );
                responses.insert(
                    format!("didcomm/keycloak/keys/{realm}/{purpose}"),
                    json!({"data":{"version":"v1","value":"never-retain-symmetric-material"}}),
                );
                let body = keycloak::policy(
                    &json!({"scope":"jwe","realm":realm,"purpose":purpose,"version":"v1"}),
                )
                .unwrap();
                responses.insert(
                    format!("sys/policies/acl/selfhost-keycloak-{realm}-{purpose}-{NONCE}"),
                    json!({"data":{"policy":body}}),
                );
            }
        }
        responses.insert(
            format!("sys/policies/acl/selfhost-keycloak-sign-{NONCE}"),
            json!({"data":{"policy":keycloak::policy(&json!({"scope":"signing"})).unwrap()}}),
        );
        for (name, body) in compiled_initializer_policies().unwrap() {
            responses.insert(
                format!("sys/policies/acl/{name}"),
                json!({"data":{"policy":body}}),
            );
        }
        Self {
            _directory: directory,
            context,
            certificates,
            reads: Reads {
                responses,
                calls: Mutex::new(vec![]),
                change_on_final_health: None,
            },
        }
    }
}

#[tokio::test]
async fn expired_legacy_fixture_inspects_without_issuance_or_secret_output() {
    let fixture = Fixture::new();
    let report = inspect_with(&fixture.reads, &fixture.context)
        .await
        .unwrap();
    assert_eq!(report["status"], "inspected-not-staged");
    assert_eq!(report["mutationAvailable"], false);
    assert_eq!(report["observed"]["keys"].as_object().unwrap().len(), 20);
    let encoded = serde_json::to_string(&report).unwrap();
    for forbidden in [
        ROOT,
        "synthetic-expired-",
        "never-retain-symmetric-material",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    assert_eq!(
        fixture.reads.calls.lock().unwrap().first(),
        Some(&("sys/health".into(), false))
    );
    assert_eq!(
        fixture.reads.calls.lock().unwrap().last(),
        Some(&("sys/health".into(), false))
    );
    assert!(
        crate::operator_certificates::check_chain(
            &pem(&fixture.certificates.ec),
            &pem(&fixture.certificates.ca)
        )
        .is_err(),
        "normal live certificate validation must still reject the expired leaf"
    );
}

#[tokio::test]
async fn source_namespace_and_root_input_mismatch_fail_before_network() {
    for case in 0..5 {
        let mut fixture = Fixture::new();
        match case {
            0 => fixture.context.bootstrap["runtimeSourceSha"] = json!("a".repeat(40)),
            1 => fixture.context.namespace_observation.uid = KEY.into(),
            2 => fixture.context.bootstrap["applicationAuthority"] = json!({}),
            3 => fixture.context.retained_root_sha256 = "0".repeat(64),
            // Root metadata would look identical for a later generate-root token.
            // The trusted retained-input binding, not lookup metadata, rejects it.
            _ => {
                fs::set_permissions(
                    &fixture.context.root_token_file,
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                write(
                    &fixture.context.root_token_file,
                    b"synthetic-generated-root-lookalike",
                    0o400,
                );
            }
        }
        assert!(
            inspect_with(&fixture.reads, &fixture.context)
                .await
                .is_err(),
            "case {case}"
        );
        assert!(fixture.reads.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn wrong_cluster_is_refused_before_sending_root() {
    let mut fixture = Fixture::new();
    fixture.reads.responses.get_mut("sys/health").unwrap()["cluster_id"] = json!(KEY);
    assert!(inspect_with(&fixture.reads, &fixture.context)
        .await
        .is_err());
    assert_eq!(
        *fixture.reads.calls.lock().unwrap(),
        vec![("sys/health".into(), false)]
    );
}

#[tokio::test]
async fn unexpected_server_version_is_refused_before_sending_root() {
    let mut fixture = Fixture::new();
    fixture.reads.responses.get_mut("sys/health").unwrap()["version"] = json!("2.7.2");
    assert!(inspect_with(&fixture.reads, &fixture.context)
        .await
        .is_err());
    assert_eq!(
        *fixture.reads.calls.lock().unwrap(),
        vec![("sys/health".into(), false)]
    );
}

#[test]
fn inspection_boundary_rejects_duplicate_nested_records() {
    let fixture = Fixture::new();
    let encoded = serde_json::to_string(&fixture.context).unwrap();
    assert!(decode_context(encoded.as_bytes()).is_ok());
    let duplicate = encoded.replace(
        "\"bootstrapId\":",
        "\"bootstrapId\":\"discarded-value\",\"bootstrapId\":",
    );
    assert!(decode_context(duplicate.as_bytes()).is_err());
}

#[tokio::test]
async fn existing_authority_key_custody_and_policy_drift_are_refused() {
    for case in 0..7 {
        let mut fixture = Fixture::new();
        let key = format!("transit/keys/{}", SELFHOST_ROLES[0].key_name);
        match case {
            0 => {
                fixture.reads.responses.get_mut("sys/auth").unwrap()["data"]["selfhost-renew/"] =
                    json!({"type":"approle"})
            }
            1 => {
                fixture.reads.responses.get_mut(&key).unwrap()["data"]["latest_version"] = json!(2)
            }
            2 => fixture.reads.responses.get_mut(&key).unwrap()["data"]["exportable"] = json!(true),
            3 => {
                fixture.reads.responses.get_mut(&key).unwrap()["data"]["allow_plaintext_backup"] =
                    json!(true)
            }
            4 => {
                fixture
                    .reads
                    .responses
                    .get_mut("sys/policies/acl/credential-service")
                    .unwrap()["data"]["policy"] = json!("path \"*\" { capabilities = [\"sudo\"] }")
            }
            5 => {
                fixture
                    .reads
                    .responses
                    .get_mut("keycloak-pki/roles/rs256")
                    .unwrap()["data"]["max_ttl"] = json!(86400)
            }
            _ => {
                fixture.reads.responses.get_mut(&key).unwrap()["data"]["keys"]["1"]["public_key"] =
                    json!(RSA_PUBLIC)
            }
        }
        assert!(
            inspect_with(&fixture.reads, &fixture.context)
                .await
                .is_err(),
            "case {case}"
        );
    }
}

#[tokio::test]
async fn roles_must_resolve_to_the_observed_issuer_not_just_mount_default() {
    let mut fixture = Fixture::new();
    let path = format!("workload-pki/roles/{}", SELFHOST_ROLES[0].name);
    fixture.reads.responses.get_mut(&path).unwrap()["data"]["issuer_ref"] = json!("alternate");
    let mut alternate = fixture.certificates.issuer();
    alternate["data"]["issuer_id"] = json!(KEY);
    fixture
        .reads
        .responses
        .insert("workload-pki/issuer/alternate".into(), alternate);
    assert!(inspect_with(&fixture.reads, &fixture.context)
        .await
        .is_err());
    assert!(fixture
        .reads
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|(path, _)| path == "workload-pki/issuer/alternate"));
}

#[tokio::test]
async fn issuer_usage_matches_the_pinned_openbao_string_contract() {
    for usage in [
        json!(["issuing-certificates"]),
        json!("read-only"),
        json!("issuing-certificates,unknown:16"),
        json!("issuing-certificates,issuing-certificates"),
        json!("issuing-certificates,"),
        Value::Null,
    ] {
        let mut fixture = Fixture::new();
        fixture
            .reads
            .responses
            .get_mut("workload-pki/issuer/default")
            .unwrap()["data"]["usage"] = usage;
        assert!(inspect_with(&fixture.reads, &fixture.context)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn retained_input_change_during_inspection_is_refused() {
    let mut fixture = Fixture::new();
    fixture.reads.change_on_final_health =
        Some(fixture.context.current.join(SELFHOST_ROLES[0].token_file));
    assert!(inspect_with(&fixture.reads, &fixture.context)
        .await
        .is_err());
}

#[tokio::test]
async fn future_or_short_lived_current_issuer_is_refused() {
    for future in [true, false] {
        let mut fixture = Fixture::new();
        let mut ca = fixture.certificates.ca.clone();
        if future {
            ca.tbs_certificate.validity.not_before = (UNIX_EPOCH
                + Duration::from_secs(fixture.certificates.now + 60))
            .try_into()
            .unwrap();
        } else {
            ca.tbs_certificate.validity.not_after = (UNIX_EPOCH
                + Duration::from_secs(fixture.certificates.now + TTL - 60))
            .try_into()
            .unwrap();
        }
        let replacement = pem(&sign(ca, &fixture.certificates.key));
        fixture
            .reads
            .responses
            .get_mut("keycloak-pki/issuer/default")
            .unwrap()["data"]["certificate"] = json!(String::from_utf8(replacement).unwrap());
        assert!(inspect_with(&fixture.reads, &fixture.context)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn private_input_custody_rejects_links_and_unsafe_modes() {
    for case in 0..4 {
        let fixture = Fixture::new();
        let input = fixture.context.current.join(SELFHOST_ROLES[0].token_file);
        match case {
            0 => {
                fs::remove_file(&input).unwrap();
                symlink(&fixture.context.root_token_file, &input).unwrap();
            }
            1 => fs::hard_link(&input, fixture._directory.path().join("other-link")).unwrap(),
            2 => fs::set_permissions(&input, fs::Permissions::from_mode(0o666)).unwrap(),
            _ => fs::set_permissions(&fixture.context.current, fs::Permissions::from_mode(0o755))
                .unwrap(),
        }
        assert!(
            inspect_with(&fixture.reads, &fixture.context)
                .await
                .is_err(),
            "case {case}"
        );
        assert!(fixture.reads.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn retained_leaf_signature_checks_issuer_time_constraints_and_real_signature() {
    let fixture = Certificates::new();
    let leaf = pem(&fixture.ec);
    let now = Duration::from_secs(fixture.now);
    assert!(retained_leaf_signature(&leaf, &pem(&fixture.ca), now).is_ok());
    let other = Certificates::new();
    assert!(retained_leaf_signature(&leaf, &pem(&other.ca), now).is_err());
    for case in 0..3 {
        let mut ca = fixture.ca.clone();
        match case {
            0 => {
                ca.tbs_certificate.validity.not_before =
                    (UNIX_EPOCH + now + Duration::from_secs(60))
                        .try_into()
                        .unwrap()
            }
            1 => {
                ca.tbs_certificate.validity.not_after = (UNIX_EPOCH + now - Duration::from_secs(60))
                    .try_into()
                    .unwrap()
            }
            _ => ca.tbs_certificate.extensions = None,
        }
        assert!(
            retained_leaf_signature(&leaf, &pem(&sign(ca, &fixture.key)), now).is_err(),
            "case {case}"
        );
    }
    let mut future = fixture.ec.clone();
    future.tbs_certificate.validity.not_before = (UNIX_EPOCH + now + Duration::from_secs(60))
        .try_into()
        .unwrap();
    future.tbs_certificate.validity.not_after = (UNIX_EPOCH + now + Duration::from_secs(600))
        .try_into()
        .unwrap();
    assert!(
        retained_leaf_signature(&pem(&sign(future, &fixture.key)), &pem(&fixture.ca), now).is_err()
    );
    let mut current_ca = fixture.ca.clone();
    current_ca.tbs_certificate.validity.not_before = (UNIX_EPOCH + now - Duration::from_secs(60))
        .try_into()
        .unwrap();
    assert!(
        retained_leaf_signature(&leaf, &pem(&sign(current_ca, &fixture.key)), now).is_ok(),
        "current same-key issuer need not pretend to be the historical certificate bytes"
    );
}

#[test]
fn authority_shape_does_not_claim_original_token_lineage() {
    let fixture = Fixture::new();
    let contract = contract();
    assert_eq!(contract["readOnly"], true);
    assert_eq!(contract["migrationTokenReplacement"], false);
    assert_eq!(contract["ordinaryRuntimeTokens"], 12);
    let mut namespace = fixture.context.namespace_observation.clone();
    namespace.name = "kube-system".into();
    let unknown = json!({"name":namespace.name,"uid":namespace.uid,"invented":"receipt"});
    assert!(serde_json::from_value::<NamespaceObservation>(unknown).is_err());
}

#[path = "kubernetes_legacy_recovery_stage_tests.rs"]
mod staging_tests;
