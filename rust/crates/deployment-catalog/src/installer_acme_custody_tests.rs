use super::*;
use crate::{
    installer_acme_certificates::validate_signed_csr,
    installer_acme_configuration::AcmeParameters,
    installer_hosting,
    installer_state::{Identity, InstallerState, Phase},
    operator_http::denial,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use spki::der::{pem::LineEnding, DecodePem, Encode, EncodePem};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};

const OWNER: &str = "b0aef1cc-14a3-4474-9b35-6d710eb6b516";
const PUBLIC_ROOT: &[u8] =
    include_bytes!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");

fn public() -> Vec<u8> {
    x509_cert::Certificate::from_pem(PUBLIC_ROOT)
        .unwrap()
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap()
}
fn key_metadata(name: &str, public: &[u8]) -> Value {
    json!({"name":name, "type":"ecdsa-p256", "derived":false,"imported_key":false,
        "exportable":false,"allow_plaintext_backup":false,"supports_signing":true,
        "deletion_allowed":false,"soft_deleted":false,"auto_rotate_period":0,"latest_version":1,
        "keys":{"1":{"public_key":SubjectPublicKeyInfoOwned::from_der(public).unwrap().to_pem(LineEnding::LF).unwrap()}}})
}
fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn parameters(environment: AcmeEnvironment) -> AcmeParameters {
    AcmeParameters::parse(&serde_json::to_vec(&json!({
        "environment":environment,"directory_url":environment.directory_url(),"profile":"shortlived",
        "terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf","terms_agreed":true
    })).unwrap()).unwrap()
}
pub(super) fn fixture() -> (tempfile::TempDir, LockedMaintenance, BoundAcmeConfiguration) {
    fixture_for(AcmeEnvironment::Staging)
}
fn fixture_for(
    environment: AcmeEnvironment,
) -> (tempfile::TempDir, LockedMaintenance, BoundAcmeConfiguration) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let installation = root.path().join("installation");
    let mut state = InstallerState::create(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    let input = root.path().join("hosting.json");
    write(
        &input,
        &serde_json::to_vec(
            &json!({"schema":"elevenid.installation-hosting/v1","mode":"direct",
        "public_origin":"https://login.example.com","public_entry_origin":"https://198.51.100.7",
        "listener":{"bind_address":"0.0.0.0","port":8443},
        "tls":{"termination":"marty-keyless","certificate_source":"acme",
            "acme":parameters(environment),"http01_host_port":18080}}),
        )
        .unwrap(),
    );
    installer_hosting::select(
        installer_hosting::prepare(Some(&input), None).unwrap(),
        &mut state,
    )
    .unwrap();
    drop(state);
    let state = LockedMaintenance::open(&installation).unwrap();
    let config = BoundAcmeConfiguration::from_selection(state.inspection()).unwrap();
    (root, state, config)
}
pub(super) fn fixture_ingress(configuration: &BoundAcmeConfiguration) -> RetainedIngressKey {
    let owner = configuration.installation_id().to_string();
    let name = crate::installer_ingress_provision::resource_name(&owner).unwrap();
    RetainedIngressKey::bind(&owner, 1, &public(), &key_metadata(&name, &public())).unwrap()
}

#[test]
fn account_binding_refuses_foreign_environment_versions_and_weakened_custody() {
    let environment = AcmeEnvironment::Staging;
    let name = account_resource_name(OWNER, environment).unwrap();
    let metadata = key_metadata(&name, &public());
    let held = AccountKeyBinding::bind(OWNER, environment, 1, &public(), &metadata).unwrap();
    assert_eq!(held.public_sec1().len(), 65);
    assert_eq!(held.environment(), environment);
    assert_eq!(held.installation_id().to_string(), OWNER);
    assert_ne!(
        name,
        account_resource_name(OWNER, AcmeEnvironment::Production).unwrap()
    );
    assert!(
        AccountKeyBinding::bind(OWNER, AcmeEnvironment::Production, 1, &public(), &metadata)
            .is_err()
    );
    assert!(AccountKeyBinding::bind(OWNER, environment, 2, &public(), &metadata).is_err());
    assert!(account_resource_name("not-an-installation", environment).is_err());
    for (field, wrong) in [
        ("type", json!("ecdsa-p384")),
        ("name", json!("foreign-key")),
        ("latest_version", json!(2)),
        ("exportable", json!(true)),
        ("allow_plaintext_backup", json!(true)),
        ("derived", json!(true)),
        ("imported_key", json!(true)),
        ("supports_signing", json!(false)),
        ("deletion_allowed", json!(true)),
        ("soft_deleted", json!(true)),
        ("auto_rotate_period", json!(86400)),
    ] {
        let mut bad = metadata.clone();
        bad[field] = wrong;
        assert!(held.require_metadata(&bad).is_err(), "{field}");
        bad.as_object_mut().unwrap().remove(field);
        assert!(held.require_metadata(&bad).is_err(), "missing {field}");
    }
    let mut altered = public();
    *altered.last_mut().unwrap() ^= 1;
    assert!(AccountKeyBinding::bind(OWNER, environment, 1, &altered, &metadata).is_err());
}

#[test]
fn policies_separate_account_signing_exact_csr_and_existing_tls_signing() {
    let (_root, _state, config) = fixture();
    let leaf = fixture_ingress(&config);
    let account = account_signer_policy(
        &config.installation_id().to_string(),
        AcmeEnvironment::Staging,
    )
    .unwrap();
    assert!(!account.contains("transit/keys/"));
    assert!(!account.contains(leaf.transit_key_name()));
    assert!(account.contains("\"prehashed\" = [false]"));
    assert!(account.contains("\"marshaling_algorithm\" = [\"jws\"]"));
    let csr = ingress_csr_policy(&config, &leaf).unwrap();
    assert!(!csr.contains("transit/sign/"));
    let template = csr_template(&config.certificate_identity().unwrap(), &leaf).unwrap();
    assert!(csr.contains(&serde_json::to_string(&template).unwrap()));
    assert!(csr.contains("required_parameters = [\"version\", \"csr\"]"));
    assert_ne!(
        csr_policy_name(
            &config.installation_id().to_string(),
            AcmeEnvironment::Staging
        )
        .unwrap(),
        csr_policy_name(
            &config.installation_id().to_string(),
            AcmeEnvironment::Production
        )
        .unwrap()
    );
    let edge = crate::installer_ingress_provision::signer_policy(leaf.transit_key_name()).unwrap();
    assert!(!edge.contains("/csr"));
    assert!(edge.contains("\"prehashed\" = [true]"));
    assert!(edge.contains("\"marshaling_algorithm\" = [\"asn1\"]"));
}

#[tokio::test]
async fn pending_custody_intent_never_replays_or_contacts_openbao() {
    let (_root, mut state, config) = fixture();
    let leaf = fixture_ingress(&config);
    let marker = "acme-custody-staging-intent.json";
    state
        .write_evidence_exclusive(marker, b"{\"uncertain\":true}")
        .unwrap();
    let bao =
        OpenBaoHttp::connect("https://127.0.0.1:18443", None, Duration::from_millis(1)).unwrap();
    let result = provision_initial(
        &mut state,
        &config,
        &leaf,
        &bao,
        "test-only-authority-value",
    )
    .await;
    assert!(matches!(result, Err(ref error) if error == RECOVERY));
    assert_eq!(
        state.read_evidence(marker).unwrap().as_deref(),
        Some(b"{\"uncertain\":true}".as_slice())
    );
    assert!(state
        .read_evidence("acme-custody-staging-result.json")
        .unwrap()
        .is_none());
}

#[test]
fn public_wrapper_requires_live_provisioning_without_advancing_phase() {
    let (root, state, configuration) = fixture();
    let leaf = fixture_ingress(&configuration);
    let identity = state.journal().identity().clone();
    drop(state);
    let installation = root.path().join("installation");
    let mut state = InstallerState::resume(&installation, &identity).unwrap();
    let before = state.journal().clone();
    let bao =
        OpenBaoHttp::connect("https://127.0.0.1:18443", None, Duration::from_millis(1)).unwrap();
    assert!(provision_for_install(
        &mut state,
        &configuration,
        &leaf,
        &bao,
        "test-only-authority-value"
    )
    .is_err());
    assert_eq!(state.journal(), &before);
    assert!(!installation
        .join("evidence/acme-custody-staging-intent.json")
        .exists());
}

struct Server {
    child: std::process::Child,
    files: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
async fn server() -> (Server, OpenBaoHttp, String) {
    use std::{
        net::TcpListener,
        process::{Command, Stdio},
        time::Instant,
    };
    let executable = std::env::var("MARTY_TEST_OPENBAO_EXECUTABLE")
        .expect("set the verified official OpenBao 2.5.5 executable");
    let files = tempfile::tempdir().unwrap();
    fs::set_permissions(files.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let root = format!("test-only-{}", uuid::Uuid::new_v4());
    let child = Command::new(executable)
        .args(["server", "-dev", "-dev-tls", "-dev-no-store-token"])
        .arg(format!("-dev-listen-address={address}"))
        .arg(format!("-dev-tls-cert-dir={}", files.path().display()))
        .env("BAO_DEV_ROOT_TOKEN_ID", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server { child, files };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "test OpenBao exited"
        );
        assert!(Instant::now() < deadline, "test OpenBao startup timeout");
        if let Ok(bao) = OpenBaoHttp::connect(
            &format!("https://{address}"),
            Some(&server.files.path().join("vault-ca.pem")),
            Duration::from_secs(5),
        ) {
            if request(&bao, Method::GET, "sys/health", None, None)
                .await
                .is_ok()
            {
                return (server, bao, root);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
async fn mint(bao: &OpenBaoHttp, root: &str, policy: &str) -> String {
    request(bao, Method::POST, "auth/token/create-orphan", Some(&json!({"policies":[policy],"no_default_policy":true,"renewable":false,"ttl":"5m","explicit_max_ttl":"5m"})), Some(root)).await.unwrap()
        ["auth"]["client_token"].as_str().unwrap().to_owned()
}
async fn create_leaf(
    bao: &OpenBaoHttp,
    root: &str,
    config: &BoundAcmeConfiguration,
) -> RetainedIngressKey {
    let owner = config.installation_id().to_string();
    let name = crate::installer_ingress_provision::resource_name(&owner).unwrap();
    request(
        bao,
        Method::POST,
        &format!("transit/keys/{name}"),
        Some(&json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false})),
        Some(root),
    )
    .await
    .unwrap();
    let data = metadata(bao, root, &name).await.unwrap();
    RetainedIngressKey::bind(&owner, 1, &metadata_spki(&data).unwrap(), &data).unwrap()
}

#[tokio::test]
#[ignore = "requires the verified official OpenBao 2.5.5 binary and loopback TLS; no live CA"]
async fn official_openbao_proves_environment_scoped_custody_and_three_separate_authorities() {
    use marty_acme_client::{
        protocol::ExternalAccountSigner, OpenBaoAccountSigner, WorkloadCredentials,
    };
    use reqwest::header::HeaderValue;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED};
    use std::sync::Arc;
    struct Credential(HeaderValue);
    #[async_trait::async_trait]
    impl WorkloadCredentials for Credential {
        async fn token(
            &self,
        ) -> std::result::Result<HeaderValue, marty_acme_client::protocol::Error> {
            Ok(self.0.clone())
        }
    }
    let (_server, bao, root) = server().await;
    request(
        &bao,
        Method::POST,
        "sys/mounts/transit",
        Some(&json!({"type":"transit"})),
        Some(&root),
    )
    .await
    .unwrap();
    let (_files, mut state, config) = fixture();
    let leaf = create_leaf(&bao, &root, &config).await;
    let held = provision_initial(&mut state, &config, &leaf, &bao, &root)
        .await
        .unwrap();
    assert_ne!(held.account_key().public_spki_der(), leaf.public_spki_der());
    assert_eq!(held.account_key().environment(), AcmeEnvironment::Staging);
    let before = state
        .read_evidence("acme-custody-staging-result.json")
        .unwrap()
        .unwrap();
    let restored = provision_initial(&mut state, &config, &leaf, &bao, &root)
        .await
        .unwrap();
    assert_eq!(restored.account_key(), held.account_key());
    assert_eq!(
        state
            .read_evidence("acme-custody-staging-result.json")
            .unwrap()
            .unwrap(),
        before
    );
    let account_token = mint(&bao, &root, held.account_policy_name()).await;
    let csr_token = mint(&bao, &root, held.csr_policy_name()).await;
    let edge_policy =
        crate::installer_ingress_provision::signer_policy(leaf.transit_key_name()).unwrap();
    request(
        &bao,
        Method::PUT,
        &format!("sys/policies/acl/{}", leaf.transit_key_name()),
        Some(&json!({"policy":edge_policy})),
        Some(&root),
    )
    .await
    .unwrap();
    let edge_token = mint(&bao, &root, leaf.transit_key_name()).await;
    let signer = OpenBaoAccountSigner::new(
        bao.clone(),
        Arc::new(Credential(account_token.parse().unwrap())),
        held.account_key().transit_key_name().into(),
        1,
        held.account_key().public_sec1().try_into().unwrap(),
    )
    .unwrap();
    let signed = signer.sign(b"protected.payload").await.unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, held.account_key().public_sec1())
        .verify(b"protected.payload", &signed)
        .unwrap();
    let identity = config.certificate_identity().unwrap();
    let csr_body = leaf.csr_request(&identity).unwrap();
    let csr_path = format!("transit/keys/{}/csr", leaf.transit_key_name());
    let csr = request(
        &bao,
        Method::POST,
        &csr_path,
        Some(&csr_body),
        Some(&csr_token),
    )
    .await
    .unwrap();
    validate_signed_csr(
        csr["data"]["csr"].as_str().unwrap().as_bytes(),
        &identity,
        &leaf,
    )
    .unwrap();
    leaf.require_metadata(
        &metadata(&bao, &csr_token, leaf.transit_key_name())
            .await
            .unwrap(),
    )
    .unwrap();
    let tls_message = b"marty isolated TLS signer custody proof";
    let tls_body = json!({"input":STANDARD.encode(Sha256::digest(tls_message)),"key_version":"1","prehashed":true,"hash_algorithm":"sha2-256","marshaling_algorithm":"asn1"});
    let tls_path = format!("transit/sign/{}", leaf.transit_key_name());
    let signed = request(
        &bao,
        Method::POST,
        &tls_path,
        Some(&tls_body),
        Some(&edge_token),
    )
    .await
    .unwrap();
    let signed = STANDARD
        .decode(
            signed["data"]["signature"]
                .as_str()
                .unwrap()
                .strip_prefix("vault:v1:")
                .unwrap(),
        )
        .unwrap();
    let leaf_public = SubjectPublicKeyInfoOwned::from_der(leaf.public_spki_der()).unwrap();
    UnparsedPublicKey::new(
        &ECDSA_P256_SHA256_ASN1,
        leaf_public.subject_public_key.as_bytes().unwrap(),
    )
    .verify(tls_message, &signed)
    .unwrap();
    let account_path = format!("transit/sign/{}", held.account_key().transit_key_name());
    let account_body = json!({"input":STANDARD.encode(b"protected.payload"),"key_version":"1","prehashed":false,"hash_algorithm":"sha2-256","marshaling_algorithm":"jws"});
    for token in [&csr_token, &edge_token] {
        denial(
            &bao,
            token,
            Method::POST,
            &account_path,
            Some(account_body.clone()),
        )
        .await
        .unwrap();
    }
    for token in [&account_token, &csr_token] {
        denial(&bao, token, Method::POST, &tls_path, Some(tls_body.clone()))
            .await
            .unwrap();
    }
    for token in [&account_token, &edge_token] {
        denial(&bao, token, Method::POST, &csr_path, Some(csr_body.clone()))
            .await
            .unwrap();
    }
    for token in [&account_token, &csr_token, &edge_token] {
        for path in [
            "auth/token/create".into(),
            format!(
                "transit/keys/{}/rotate",
                held.account_key().transit_key_name()
            ),
            format!("transit/keys/{}/rotate", leaf.transit_key_name()),
        ] {
            denial(&bao, token, Method::POST, &path, Some(json!({})))
                .await
                .unwrap();
        }
        for path in [
            format!(
                "transit/export/signing-key/{}",
                held.account_key().transit_key_name()
            ),
            format!("transit/export/signing-key/{}", leaf.transit_key_name()),
            format!("transit/keys/{}", held.account_key().transit_key_name()),
        ] {
            denial(&bao, token, Method::GET, &path, None).await.unwrap();
        }
    }
    for (field, value) in [
        ("version", json!("2")),
        ("version", json!(1)),
        ("csr", json!("foreign request")),
        ("extra", json!(true)),
    ] {
        let mut bad = csr_body.clone();
        bad[field] = value;
        denial(&bao, &csr_token, Method::POST, &csr_path, Some(bad))
            .await
            .unwrap();
    }
    let mut missing = csr_body.clone();
    missing.as_object_mut().unwrap().remove("csr");
    denial(&bao, &csr_token, Method::POST, &csr_path, Some(missing))
        .await
        .unwrap();
    for (field, value) in [
        ("key_version", json!("2")),
        ("key_version", json!(1)),
        ("prehashed", json!(true)),
        ("marshaling_algorithm", json!("asn1")),
        ("batch_input", json!([])),
    ] {
        let mut bad = account_body.clone();
        bad[field] = value;
        denial(&bao, &account_token, Method::POST, &account_path, Some(bad))
            .await
            .unwrap();
    }
    assert!(BoundAcmeConfiguration::bind(
        state.inspection(),
        parameters(AcmeEnvironment::Production)
    )
    .is_err());
    let (_production_files, mut production_state, production) =
        fixture_for(AcmeEnvironment::Production);
    let production_leaf = create_leaf(&bao, &root, &production).await;
    let second = provision_initial(
        &mut production_state,
        &production,
        &production_leaf,
        &bao,
        &root,
    )
    .await
    .unwrap();
    assert_ne!(
        second.account_key().transit_key_name(),
        held.account_key().transit_key_name()
    );
    assert_ne!(
        second.account_key().public_spki_der(),
        held.account_key().public_spki_der()
    );
    assert_ne!(second.csr_policy_name(), held.csr_policy_name());
    denial(
        &bao,
        &account_token,
        Method::POST,
        &format!("transit/sign/{}", second.account_key().transit_key_name()),
        Some(account_body),
    )
    .await
    .unwrap();
    let export = builder(
        &bao,
        Method::GET,
        &format!(
            "transit/export/signing-key/{}",
            held.account_key().transit_key_name()
        ),
        None,
        Some(&root),
    )
    .send()
    .await
    .unwrap();
    assert!(
        !export.status().is_success(),
        "even fixture root must not export account key"
    );
    request(
        &bao,
        Method::PUT,
        &format!("sys/policies/acl/{}", held.csr_policy_name()),
        Some(&json!({"policy":"path \"transit/*\" { capabilities = [\"read\"] }"})),
        Some(&root),
    )
    .await
    .unwrap();
    assert!(provision_initial(&mut state, &config, &leaf, &bao, &root)
        .await
        .is_err());
    assert_eq!(
        state
            .read_evidence("acme-custody-staging-result.json")
            .unwrap()
            .unwrap(),
        before
    );
    let (_collision_files, mut collision_state, collision_config) = fixture();
    let collision_leaf = create_leaf(&bao, &root, &collision_config).await;
    let collision_name = account_resource_name(
        &collision_config.installation_id().to_string(),
        AcmeEnvironment::Staging,
    )
    .unwrap();
    request(
        &bao,
        Method::POST,
        &format!("transit/keys/{collision_name}"),
        Some(&json!({"type":"ecdsa-p256"})),
        Some(&root),
    )
    .await
    .unwrap();
    assert!(provision_initial(
        &mut collision_state,
        &collision_config,
        &collision_leaf,
        &bao,
        &root
    )
    .await
    .is_err());
    assert!(collision_state
        .read_evidence("acme-custody-staging-intent.json")
        .unwrap()
        .is_none());
}
