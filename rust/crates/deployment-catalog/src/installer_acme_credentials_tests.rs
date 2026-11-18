use super::*;
use crate::{
    installer_acme_configuration::AcmeParameters, installer_acme_custody, installer_hosting,
    installer_state::Identity as InstallationIdentity, operator_http::denial,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use spki::{
    der::{asn1::BitString, pem::LineEnding, DecodePem, Encode, EncodePem},
    SubjectPublicKeyInfoOwned,
};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
};

const CLUSTER: &str = "ba4ea6d7-1a04-4575-a331-e1b0ea178426";
const PUBLIC_ROOT: &[u8] =
    include_bytes!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");

fn public() -> Vec<u8> {
    // Unit-only arbitrary public points; actual ingress/account custody in the
    // integration below is created solely inside the official OpenBao server.
    let random = SystemRandom::new();
    let bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, bytes.as_ref(), &random).unwrap();
    let mut public = x509_cert::Certificate::from_pem(PUBLIC_ROOT)
        .unwrap()
        .tbs_certificate
        .subject_public_key_info;
    public.subject_public_key = BitString::from_bytes(key.public_key().as_ref()).unwrap();
    public.to_der().unwrap()
}
fn metadata(name: &str, public: &[u8]) -> Value {
    use spki::der::Decode;
    json!({"name":name,"type":"ecdsa-p256","derived":false,"imported_key":false,"supports_signing":true,
        "exportable":false,"allow_plaintext_backup":false,"deletion_allowed":false,"soft_deleted":false,
        "auto_rotate_period":0,"latest_version":1,
        "keys":{"1":{"public_key":SubjectPublicKeyInfoOwned::from_der(public).unwrap().to_pem(LineEnding::LF).unwrap()}}})
}
fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn parameters(environment: AcmeEnvironment) -> AcmeParameters {
    AcmeParameters::parse(&serde_json::to_vec(&json!({"environment":environment,"directory_url":environment.directory_url(),
        "profile":"shortlived","terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf","terms_agreed":true})).unwrap()).unwrap()
}
struct Fixture {
    files: tempfile::TempDir,
    installation: PathBuf,
    state: LockedMaintenance,
    configuration: BoundAcmeConfiguration,
}
fn fixture() -> Fixture {
    let files = tempfile::tempdir().unwrap();
    fs::set_permissions(files.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let installation = files.path().join("installation");
    let mut state = InstallerState::create(
        &installation,
        InstallationIdentity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    let hosting = files.path().join("hosting.json");
    private_write(&hosting, &serde_json::to_vec(&json!({"schema":"elevenid.installation-hosting/v1","mode":"direct",
        "public_origin":"https://login.example.com:9443","public_entry_origin":"https://198.51.100.7:8443",
        "listener":{"bind_address":"0.0.0.0","port":8443},
        "tls":{"termination":"marty-keyless","certificate_source":"acme",
            "acme":parameters(AcmeEnvironment::Staging),"http01_host_port":18080}})).unwrap());
    installer_hosting::select(
        installer_hosting::prepare(Some(&hosting), None).unwrap(),
        &mut state,
    )
    .unwrap();
    state.advance(Phase::Provisioning).unwrap();
    drop(state);
    let state = LockedMaintenance::open(&installation).unwrap();
    let configuration = BoundAcmeConfiguration::from_selection(state.inspection()).unwrap();
    Fixture {
        files,
        installation,
        state,
        configuration,
    }
}
fn bindings(configuration: &BoundAcmeConfiguration) -> (AccountKeyBinding, RetainedIngressKey) {
    let id = configuration.installation_id().to_string();
    let account_spki = public();
    let ingress_spki = public();
    let account = AccountKeyBinding::bind(
        &id,
        configuration.parameters().environment(),
        1,
        &account_spki,
        &metadata(
            &account_resource_name(&id, configuration.parameters().environment()).unwrap(),
            &account_spki,
        ),
    )
    .unwrap();
    let ingress = RetainedIngressKey::bind(
        &id,
        1,
        &ingress_spki,
        &metadata(
            &crate::installer_ingress_provision::resource_name(&id).unwrap(),
            &ingress_spki,
        ),
    )
    .unwrap();
    (account, ingress)
}
fn plan(configuration: &BoundAcmeConfiguration) -> CredentialResourcePlan {
    let (account, ingress) = bindings(configuration);
    CredentialResourcePlan::from_bound(configuration, &account, &ingress, CLUSTER).unwrap()
}
fn secret(plan: &CredentialResourcePlan, purpose: Purpose) -> store::SecretIdentity {
    store::SecretIdentity::new(
        plan,
        purpose,
        &uuid::Uuid::new_v4().to_string(),
        &uuid::Uuid::new_v4().to_string(),
    )
    .unwrap()
}

#[test]
fn transferred_plan_is_exact_public_input_and_cannot_choose_arbitrary_resources() {
    let fixture = fixture();
    let plan = plan(&fixture.configuration);
    let encoded = plan.public_bytes().unwrap();
    assert_eq!(
        CredentialResourcePlan::parse_authenticated(&encoded, &plan.sha256().unwrap()).unwrap(),
        plan
    );
    assert!(CredentialResourcePlan::parse_authenticated(&encoded, &"0".repeat(64)).is_err());
    assert!(!String::from_utf8(encoded.clone())
        .unwrap()
        .contains("secret_id"));
    assert_eq!(plan.identity().unwrap().dns_name(), "login.example.com");
    assert_eq!(
        plan.identity().unwrap().ip_address().unwrap().to_string(),
        "198.51.100.7"
    );
    for (field, value) in [
        ("canonical_origin", json!("https://198.51.100.7")),
        ("public_entry_origin", json!("https://foreign.example.com")),
        ("server_cluster_id", json!("not-a-cluster")),
        ("owner_policy", json!("root")),
        ("configuration_sha256", json!("bad")),
    ] {
        let mut tampered: Value = serde_json::from_slice(&encoded).unwrap();
        tampered[field] = value;
        let bytes = serde_json::to_vec(&tampered).unwrap();
        assert!(
            CredentialResourcePlan::parse_authenticated(&bytes, &installer_release::sha256(&bytes))
                .is_err(),
            "{field}"
        );
    }
    let mut reused = plan.clone();
    reused.0.account_public_spki_der = reused.0.ingress_public_spki_der.clone();
    assert!(reused.validate().is_err());
    assert!(BoundAcmeConfiguration::bind(
        fixture.state.inspection(),
        parameters(AcmeEnvironment::Production),
    )
    .is_err());
}

#[test]
fn owner_roles_can_only_mint_the_exact_bounded_operation_profile() {
    let fixture = fixture();
    let plan = plan(&fixture.configuration);
    let account = plan.spec(Purpose::Account).unwrap();
    let csr = plan.spec(Purpose::Csr).unwrap();
    assert_ne!(account.owner_policy, csr.owner_policy);
    assert_ne!(account.leaf_role, csr.leaf_role);
    assert!(account
        .owner_policy()
        .contains(&format!("auth/token/create/{}", account.leaf_role)));
    for forbidden in [
        "/secret-id",
        "transit/sign/",
        "transit/keys/*",
        "capabilities = [\"sudo\"]",
        "auth/token/renew",
        "auth/token/create-orphan",
    ] {
        assert!(!account.owner_policy().contains(forbidden), "{forbidden}");
        assert!(!csr.owner_policy().contains(forbidden), "{forbidden}");
    }
    assert!(!account.owner_policy().contains(&csr.owner_policy));
    assert!(!csr.owner_policy().contains(&account.owner_policy));
    let mut leaf = account.leaf_role_body();
    leaf["name"] = json!(account.leaf_role);
    leaf["period"] = json!(0);
    leaf["explicit_max_ttl"] = json!(0);
    account.require_leaf_role(&leaf).unwrap();
    for (field, value) in [
        ("renewable", json!(true)),
        ("orphan", json!(false)),
        ("token_explicit_max_ttl", json!(301)),
        ("allowed_policies", json!(["root"])),
        ("allowed_policies_glob", json!(["*"])),
        ("token_no_default_policy", json!(false)),
        ("token_period", json!(60)),
        ("path_suffix", json!("changed")),
        ("allowed_entity_aliases", json!(["*"])),
    ] {
        let mut drift = leaf.clone();
        drift[field] = value;
        assert!(account.require_leaf_role(&drift).is_err(), "{field}");
    }
    let mut owner = account.owner_role_body();
    account.require_owner_role(&owner).unwrap();
    owner["token_max_ttl"] = json!(61);
    assert!(account.require_owner_role(&owner).is_err());
    assert_eq!(account.mint_body()["ttl"], "5m");
    assert_eq!(account.mint_body()["policies"], account.leaf_policy);
    assert_eq!(account.mint_body()["renewable"], false);
}

#[test]
fn interrupted_authentication_records_uncertainty_then_retries_after_server_time_backoff() {
    let fixture = fixture();
    let plan = plan(&fixture.configuration);
    let account = secret(&plan, Purpose::Account);
    let csr = secret(&plan, Purpose::Csr);
    let installed = store::install(fixture.state.inspection(), &plan, &account, &csr).unwrap();
    let storage = store::IdentityStorage::open(
        fixture.state.inspection(),
        &fixture.installation,
        &plan,
        &installed,
        Purpose::Account,
    )
    .unwrap();
    {
        let mut attempt = storage.lock(&plan, Purpose::Account).unwrap();
        attempt.begin(&plan, Purpose::Account, 1000, true).unwrap();
        assert!(storage.lock(&plan, Purpose::Account).is_err());
        // A process interruption loses the result, never the durable intent.
    }
    let directory = fixture.installation.join(plan.directory()).join("account");
    let pending: Value =
        serde_json::from_slice(&fs::read(directory.join("refresh-current.json")).unwrap()).unwrap();
    assert!(pending["result"].is_null());
    {
        let mut retry = storage.lock(&plan, Purpose::Account).unwrap();
        assert_eq!(
            retry
                .begin(&plan, Purpose::Account, 1000, true)
                .unwrap_err(),
            BACKOFF
        );
    }
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("refresh-current.json")).unwrap()).unwrap();
    let receipt = &state["result"];
    assert_eq!(receipt["unknown_short_lived_token"], true);
    assert_eq!(receipt["outcome"], "unknown-bounded-authentication");
    assert_eq!(receipt["next_attempt_server_time"], 1011);
    assert!(!receipt.to_string().contains("secret_id"));
    assert!(!receipt.to_string().contains("client_token"));
    assert_eq!(state["intent"]["sequence"], 0);
    assert!(directory
        .join("refresh-unknown-00000000000000000000.json")
        .exists());
    {
        let mut retry = storage.lock(&plan, Purpose::Account).unwrap();
        assert!(retry.begin(&plan, Purpose::Account, 999, true).is_err());
        assert_eq!(
            retry
                .begin(&plan, Purpose::Account, 1010, true)
                .unwrap_err(),
            BACKOFF
        );
        retry.begin(&plan, Purpose::Account, 1011, true).unwrap();
        retry.complete(false).unwrap();
    }
    {
        let mut retry = storage.lock(&plan, Purpose::Account).unwrap();
        assert_eq!(
            retry
                .begin(&plan, Purpose::Account, 1026, true)
                .unwrap_err(),
            BACKOFF
        );
        retry.begin(&plan, Purpose::Account, 1027, false).unwrap();
        retry.complete(true).unwrap();
    }
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("refresh-current.json")).unwrap()).unwrap();
    assert_eq!(state["intent"]["sequence"], 2);
    let receipt = &state["result"];
    assert_eq!(receipt["consecutive_failures"], 0);
    assert_eq!(receipt["unknown_short_lived_token"], false);
    let before = fs::read_dir(&directory).unwrap().count();
    store::IdentityStorage::open(
        fixture.state.inspection(),
        &fixture.installation,
        &plan,
        &installed,
        Purpose::Account,
    )
    .unwrap();
    assert_eq!(
        before,
        fs::read_dir(&directory).unwrap().count(),
        "restore is read-only"
    );
}

#[test]
fn private_identity_binding_rejects_replacement_permissions_links_and_receipt_tampering() {
    let fixture = fixture();
    let plan = plan(&fixture.configuration);
    let installed = store::install(
        fixture.state.inspection(),
        &plan,
        &secret(&plan, Purpose::Account),
        &secret(&plan, Purpose::Csr),
    )
    .unwrap();
    let storage = store::IdentityStorage::open(
        fixture.state.inspection(),
        &fixture.installation,
        &plan,
        &installed,
        Purpose::Account,
    )
    .unwrap();
    let directory = fixture.installation.join(plan.directory()).join("account");
    let identity = directory.join("identity.json");
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(storage.lock(&plan, Purpose::Account).is_err());
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
    let moved = directory.join("retained-identity.json");
    fs::rename(&identity, &moved).unwrap();
    symlink(&moved, &identity).unwrap();
    assert!(storage.lock(&plan, Purpose::Account).is_err());
    fs::remove_file(&identity).unwrap();
    private_write(&identity, &fs::read(&moved).unwrap());
    assert!(
        storage.lock(&plan, Purpose::Account).is_err(),
        "same bytes in a replacement inode are refused"
    );
    fs::remove_file(&identity).unwrap();
    fs::rename(&moved, &identity).unwrap();
    {
        let mut attempt = storage.lock(&plan, Purpose::Account).unwrap();
        attempt.begin(&plan, Purpose::Account, 1000, true).unwrap();
        attempt.complete(true).unwrap();
    }
    let receipt = directory.join("refresh-current.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    value["result"]["next_attempt_server_time"] = json!(0);
    private_write(&receipt, &serde_json::to_vec(&value).unwrap());
    assert!(storage.lock(&plan, Purpose::Account).is_err());
}

#[test]
fn refresh_history_stays_bounded_after_thousands_of_successes_and_repeated_uncertainty() {
    let fixture = fixture();
    let plan = plan(&fixture.configuration);
    let installed = store::install(
        fixture.state.inspection(),
        &plan,
        &secret(&plan, Purpose::Account),
        &secret(&plan, Purpose::Csr),
    )
    .unwrap();
    let storage = store::IdentityStorage::open(
        fixture.state.inspection(),
        &fixture.installation,
        &plan,
        &installed,
        Purpose::Account,
    )
    .unwrap();
    assert!(storage
        .require_initialized(&plan, Purpose::Account)
        .is_err());
    let directory = fixture.installation.join(plan.directory()).join("account");
    for sequence in 0..2100 {
        let mut attempt = storage.lock(&plan, Purpose::Account).unwrap();
        attempt
            .begin(&plan, Purpose::Account, 10_000 + sequence, true)
            .unwrap();
        attempt.complete(true).unwrap();
    }
    assert_eq!(
        fs::read_dir(&directory).unwrap().count(),
        2,
        "success does not accumulate lifetime receipts"
    );
    storage
        .require_initialized(&plan, Purpose::Account)
        .unwrap();
    for sequence in 0..64 {
        let mut attempt = storage.lock(&plan, Purpose::Account).unwrap();
        attempt
            .begin(&plan, Purpose::Account, 20_000 + 400 * sequence, true)
            .unwrap();
        attempt.complete(false).unwrap();
    }
    assert_eq!(
        fs::read_dir(&directory).unwrap().count(),
        34,
        "current state, identity, and the last 32 uncertainty receipts"
    );
    // A private unpublished preparation left by a crash is removed only under
    // the active purpose lock; local read-only restore leaves it untouched.
    let preparation = directory.join(format!("acme-write-{}.tmp", uuid::Uuid::new_v4()));
    private_write(&preparation, b"partial preparation");
    store::IdentityStorage::open(
        fixture.state.inspection(),
        &fixture.installation,
        &plan,
        &installed,
        Purpose::Account,
    )
    .unwrap();
    assert!(preparation.exists());
    let mut recovered = storage.lock(&plan, Purpose::Account).unwrap();
    recovered
        .begin(&plan, Purpose::Account, 100_000, false)
        .unwrap();
    recovered.complete(true).unwrap();
    assert!(!preparation.exists());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 34);
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("refresh-current.json")).unwrap()).unwrap();
    assert_eq!(state["intent"]["sequence"], 2164);
    assert_eq!(state["result"]["consecutive_failures"], 0);
}

#[test]
fn token_admission_rejects_default_identity_policies_ttl_expansion_and_renewable_leaves() {
    let auth = json!({"client_token":"test-only-bounded-operation-token","lease_duration":300,"policies":["leaf"],
        "token_policies":["leaf"],"identity_policies":[],"token_type":"service","orphan":true,"renewable":false});
    validate_auth(&auth, "leaf", 300, true).unwrap();
    for (field, bad) in [
        ("policies", json!(["default", "leaf"])),
        ("identity_policies", json!(["extra"])),
        ("lease_duration", json!(301)),
        ("token_policies", json!(["owner"])),
        ("renewable", json!(true)),
        ("orphan", json!(false)),
        ("token_type", json!("batch")),
    ] {
        let mut changed = auth.clone();
        changed[field] = bad;
        assert!(
            validate_auth(&changed, "leaf", 300, true).is_err(),
            "{field}"
        );
    }
    let error = validate_auth(
        &json!({"errors":["secret-backend-marker"]}),
        "leaf",
        300,
        true,
    )
    .unwrap_err();
    assert_eq!(error, REFUSED);
    assert!(!error.contains("secret-backend-marker"));
}

#[tokio::test]
async fn pending_initial_setup_never_replays_or_contacts_openbao() {
    let mut fixture = fixture();
    let (account, ingress) = bindings(&fixture.configuration);
    fixture
        .state
        .write_evidence_exclusive(
            "acme-credentials-staging-intent.json",
            b"{\"uncertain\":true}",
        )
        .unwrap();
    let bao = OpenBaoHttp::connect("https://127.0.0.1:1", None, Duration::from_millis(1)).unwrap();
    let failure = prepare_initial(
        &mut fixture.state,
        &fixture.installation,
        &fixture.configuration,
        &account,
        &ingress,
        &bao,
    )
    .await
    .unwrap_err();
    assert_eq!(failure, SETUP_HOLD);
    assert!(!fixture
        .installation
        .join("acme-credentials-staging")
        .exists());
}

struct Server {
    process: std::process::Child,
    files: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let files = tempfile::tempdir().unwrap();
    fs::set_permissions(files.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = format!("test-only-{}", uuid::Uuid::new_v4());
    let process = Command::new(executable)
        .args(["server", "-dev", "-dev-tls", "-dev-no-store-token"])
        .arg(format!("-dev-listen-address={address}"))
        .arg(format!("-dev-tls-cert-dir={}", files.path().display()))
        .env("BAO_DEV_ROOT_TOKEN_ID", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server { process, files };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            server.process.try_wait().unwrap().is_none(),
            "official OpenBao exited"
        );
        assert!(
            Instant::now() < deadline,
            "official OpenBao startup timeout"
        );
        if let Ok(bao) = OpenBaoHttp::connect(
            &format!("https://{address}"),
            Some(&server.files.path().join("vault-ca.pem")),
            Duration::from_secs(5),
        ) {
            if server_time(&bao).await.is_ok() {
                return (server, bao, root);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
async fn real_ingress(
    bao: &OpenBaoHttp,
    root: &str,
    configuration: &BoundAcmeConfiguration,
) -> RetainedIngressKey {
    let id = configuration.installation_id().to_string();
    let name = crate::installer_ingress_provision::resource_name(&id).unwrap();
    request(
        bao,
        Method::POST,
        &format!("transit/keys/{name}"),
        Some(&json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false})),
        Some(root),
    )
    .await
    .unwrap();
    let data = data(bao, root, &format!("transit/keys/{name}"))
        .await
        .unwrap();
    let spki = crate::operator::public_spki(
        data["keys"]["1"]["public_key"].as_str().unwrap().as_bytes(),
        false,
    )
    .unwrap();
    RetainedIngressKey::bind(&id, 1, &spki, &data).unwrap()
}

#[tokio::test]
#[ignore = "requires verified official OpenBao 2.5.5 and loopback TLS; no live CA or exported key"]
async fn official_openbao_proves_separate_owner_leaf_credentials_readonly_restore_and_denied_escalation(
) {
    use marty_acme_client::{protocol::ExternalAccountSigner, OpenBaoAccountSigner};
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
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
    let mut fixture = fixture();
    let ingress = real_ingress(&bao, &root, &fixture.configuration).await;
    let custody_plan = installer_acme_custody::prepare_locked(
        &mut fixture.state,
        &fixture.configuration,
        &ingress,
        &bao,
    )
    .await
    .unwrap();
    let custody_plan = installer_acme_custody::CustodyResourcePlan::parse_authenticated(
        &custody_plan.public_bytes().unwrap(),
        &custody_plan.sha256().unwrap(),
    )
    .unwrap();
    let custody_output = installer_acme_custody::provision_resources(&custody_plan, &bao, &root)
        .await
        .unwrap();
    let public_transfer = fixture.files.path().join("public-custody-transfer");
    fs::create_dir(&public_transfer).unwrap();
    fs::set_permissions(&public_transfer, fs::Permissions::from_mode(0o700)).unwrap();
    custody_output
        .write_public_transfer(&public_transfer)
        .unwrap();
    let custody = installer_acme_custody::admit_locked(
        &mut fixture.state,
        &fixture.configuration,
        &ingress,
        &custody_plan,
        &public_transfer,
    )
    .unwrap();
    assert!(
        installer_acme_custody::provision_resources(&custody_plan, &bao, &root)
            .await
            .is_err()
    );
    let account_key = custody.account_key();
    let plan = prepare_initial(
        &mut fixture.state,
        &fixture.installation,
        &fixture.configuration,
        account_key,
        &ingress,
        &bao,
    )
    .await
    .unwrap();
    let exported = plan.public_bytes().unwrap();
    let helper_plan =
        CredentialResourcePlan::parse_authenticated(&exported, &plan.sha256().unwrap()).unwrap();
    let identities = provision_resources(&helper_plan, &bao, &root)
        .await
        .unwrap();
    // The fixed helper API needs neither the host path nor its live flock.
    let transfer = fixture.files.path().join("private-transfer");
    fs::create_dir(&transfer).unwrap();
    fs::set_permissions(&transfer, fs::Permissions::from_mode(0o700)).unwrap();
    identities.write_private_transfer(&transfer).unwrap();
    // Inspect only public capability/lease metadata, never credential fields.
    let probe_spec = plan.spec(Purpose::Account).unwrap();
    let probe = request(
        &bao,
        Method::POST,
        &format!("auth/{}/login", probe_spec.mount),
        Some(&identities.account.login_body()),
        None,
    )
    .await
    .unwrap();
    let public_auth = json!({"policies":probe["auth"]["policies"],"token_policies":probe["auth"]["token_policies"],"identity_policies":probe["auth"]["identity_policies"],"lease_duration":probe["auth"]["lease_duration"],"token_type":probe["auth"]["token_type"],"orphan":probe["auth"]["orphan"],"renewable":probe["auth"]["renewable"]});
    let probe_token = validate_auth(&probe["auth"], &probe_spec.owner_policy, 60, false)
        .unwrap_or_else(|_| panic!("owner metadata refused: {public_auth}"));
    for path in [
        probe_spec.role_path(),
        format!("auth/token/roles/{}", probe_spec.leaf_role),
        format!("sys/policies/acl/{}", probe_spec.owner_policy),
        format!("sys/policies/acl/{}", probe_spec.leaf_policy),
        format!("transit/keys/{}", probe_spec.key_name),
        format!("{}/role-id", probe_spec.role_path()),
    ] {
        assert!(
            data(&bao, header_text(&probe_token).unwrap(), &path)
                .await
                .is_ok(),
            "owner read refused: {path}"
        );
    }
    let probe_lookup = data(
        &bao,
        header_text(&probe_token).unwrap(),
        "auth/token/lookup-self",
    )
    .await
    .unwrap();
    let public_lookup = json!({"policies":probe_lookup["policies"],"identity_policies":probe_lookup["identity_policies"],"ttl":probe_lookup["ttl"],"creation_ttl":probe_lookup["creation_ttl"],"explicit_max_ttl":probe_lookup["explicit_max_ttl"],"type":probe_lookup["type"],"orphan":probe_lookup["orphan"],"num_uses":probe_lookup["num_uses"],"path":probe_lookup["path"],"renewable":probe_lookup["renewable"]});
    validate_lookup(
        &probe_lookup,
        &probe_spec.owner_policy,
        60,
        &format!("auth/{}/login", probe_spec.mount),
        None,
        false,
    )
    .unwrap_or_else(|_| panic!("owner lookup refused: {public_lookup}"));
    let minted = builder(
        &bao,
        Method::POST,
        &format!("auth/token/create/{}", probe_spec.leaf_role),
        Some(&probe_spec.mint_body()),
        Some(header_text(&probe_token).unwrap()),
    )
    .send()
    .await
    .unwrap();
    assert!(
        minted.status().is_success(),
        "exact scoped mint status: {}",
        minted.status()
    );
    let minted = bounded_json(minted).await.unwrap();
    let public_auth = json!({"policies":minted["auth"]["policies"],"token_policies":minted["auth"]["token_policies"],"identity_policies":minted["auth"]["identity_policies"],"lease_duration":minted["auth"]["lease_duration"],"token_type":minted["auth"]["token_type"],"orphan":minted["auth"]["orphan"],"renewable":minted["auth"]["renewable"]});
    let leaf = validate_auth(&minted["auth"], &probe_spec.leaf_policy, 300, true)
        .unwrap_or_else(|_| panic!("leaf metadata refused: {public_auth}"));
    let lookup = request(
        &bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":header_text(&leaf).unwrap()})),
        Some(header_text(&probe_token).unwrap()),
    )
    .await
    .unwrap();
    let lookup = &lookup["data"];
    let public_lookup = json!({"policies":lookup["policies"],"identity_policies":lookup["identity_policies"],"ttl":lookup["ttl"],"creation_ttl":lookup["creation_ttl"],"explicit_max_ttl":lookup["explicit_max_ttl"],"type":lookup["type"],"orphan":lookup["orphan"],"num_uses":lookup["num_uses"],"path":lookup["path"],"role":lookup["role"],"renewable":lookup["renewable"]});
    validate_lookup(
        lookup,
        &probe_spec.leaf_policy,
        300,
        &format!("auth/token/create/{}", probe_spec.leaf_role),
        Some(&probe_spec.leaf_role),
        true,
    )
    .unwrap_or_else(|_| panic!("leaf lookup refused: {public_lookup}"));
    request(
        &bao,
        Method::POST,
        "auth/token/revoke-self",
        Some(&json!({})),
        Some(header_text(&probe_token).unwrap()),
    )
    .await
    .unwrap();
    let providers = admit_initial(
        &mut fixture.state,
        &fixture.installation,
        &fixture.configuration,
        bao.clone(),
        identities,
    )
    .await
    .unwrap();
    let receipt_before = fixture
        .state
        .read_evidence("acme-credentials-staging-result.json")
        .unwrap()
        .unwrap();
    assert!(!String::from_utf8(receipt_before.clone())
        .unwrap()
        .contains("secret_id\":"));
    assert_eq!(
        providers
            .account_credentials()
            .verified_key()
            .await
            .unwrap(),
        *account_key
    );
    assert_eq!(providers.csr().retained_key().await.unwrap(), ingress);
    let signer = OpenBaoAccountSigner::new(
        bao.clone(),
        providers.account(),
        account_key.transit_key_name().into(),
        1,
        account_key.public_sec1().try_into().unwrap(),
    )
    .unwrap();
    let signature = signer.sign(b"protected.payload").await.unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, account_key.public_sec1())
        .verify(b"protected.payload", &signature)
        .unwrap();
    let csr = providers.csr().signed_csr().await.unwrap();
    validate_signed_csr(
        csr.pem().as_bytes(),
        &fixture.configuration.certificate_identity().unwrap(),
        &ingress,
    )
    .unwrap();
    let restored = restore(
        fixture.state.inspection(),
        &fixture.installation,
        &fixture.configuration,
        bao.clone(),
    )
    .unwrap();
    assert_eq!(
        fixture
            .state
            .read_evidence("acme-credentials-staging-result.json")
            .unwrap()
            .unwrap(),
        receipt_before
    );
    let account_token = restored.account().token().await.unwrap();
    let csr_token = restored.csr.0.refresh(true).await.unwrap().token.unwrap();
    let account_spec = plan.spec(Purpose::Account).unwrap();
    let csr_spec = plan.spec(Purpose::Csr).unwrap();
    for (token, policy, role) in [
        (
            &account_token,
            &account_spec.leaf_policy,
            &account_spec.leaf_role,
        ),
        (&csr_token, &csr_spec.leaf_policy, &csr_spec.leaf_role),
    ] {
        let lookup = request(
            &bao,
            Method::POST,
            "auth/token/lookup",
            Some(&json!({"token":header_text(token).unwrap()})),
            Some(&root),
        )
        .await
        .unwrap();
        validate_lookup(
            &lookup["data"],
            policy,
            300,
            &format!("auth/token/create/{role}"),
            Some(role),
            true,
        )
        .unwrap();
        for path in [
            "auth/token/create".into(),
            format!("auth/token/create/{}", account_spec.leaf_role),
            format!("{}/secret-id", account_spec.role_path()),
            format!("transit/keys/{}/rotate", ingress.transit_key_name()),
        ] {
            denial(
                &bao,
                header_text(token).unwrap(),
                Method::POST,
                &path,
                Some(json!({})),
            )
            .await
            .unwrap();
        }
        for path in [
            format!("sys/policies/acl/{}", account_spec.owner_policy),
            format!(
                "transit/export/signing-key/{}",
                account_key.transit_key_name()
            ),
            format!("transit/keys/{}", account_key.transit_key_name()),
        ] {
            denial(&bao, header_text(token).unwrap(), Method::GET, &path, None)
                .await
                .unwrap();
        }
        denial(
            &bao,
            header_text(token).unwrap(),
            Method::POST,
            "auth/token/renew-self",
            Some(json!({})),
        )
        .await
        .unwrap();
    }
    denial(
        &bao,
        header_text(&account_token).unwrap(),
        Method::POST,
        &format!("transit/keys/{}/csr", ingress.transit_key_name()),
        Some(ingress.csr_request(&plan.identity().unwrap()).unwrap()),
    )
    .await
    .unwrap();
    denial(&bao, header_text(&csr_token).unwrap(), Method::POST, &format!("transit/sign/{}", account_key.transit_key_name()), Some(json!({"input":STANDARD.encode(b"protected.payload"),"key_version":"1","prehashed":false,"hash_algorithm":"sha2-256","marshaling_algorithm":"jws"}))).await.unwrap();
    // Inspect an owner via the exact private identity without widening leaf ACLs.
    let owner_identity = store::SecretIdentity::read(
        &installer_host_fs::directory(&transfer, REFUSED).unwrap(),
        "account-identity.json",
        &plan,
        Purpose::Account,
    )
    .unwrap();
    let logged = request(
        &bao,
        Method::POST,
        &format!("auth/{}/login", plan.mount()),
        Some(&owner_identity.login_body()),
        None,
    )
    .await
    .unwrap();
    let owner = validate_auth(&logged["auth"], &account_spec.owner_policy, 60, false).unwrap();
    denial(
        &bao,
        header_text(&owner).unwrap(),
        Method::GET,
        &format!("sys/auth/{}/tune", plan.mount()),
        None,
    )
    .await
    .unwrap();
    for path in [
        "auth/token/create".into(),
        "auth/token/create-orphan".into(),
        format!("auth/token/create/{}", csr_spec.leaf_role),
        format!("{}/secret-id", account_spec.role_path()),
        format!("{}/role-id", account_spec.role_path()),
        format!("sys/policies/acl/{}", account_spec.owner_policy),
        format!("sys/auth/{}/tune", plan.mount()),
        format!("transit/sign/{}", account_key.transit_key_name()),
    ] {
        denial(
            &bao,
            header_text(&owner).unwrap(),
            Method::POST,
            &path,
            Some(json!({})),
        )
        .await
        .unwrap();
    }
    for (field, bad) in [
        ("ttl", json!("10m")),
        ("explicit_max_ttl", json!("10m")),
        ("renewable", json!(true)),
        ("no_default_policy", json!(false)),
        ("policies", json!([csr_spec.leaf_policy])),
        ("policies", json!([account_spec.leaf_policy])),
        ("period", json!("5m")),
        ("extra", json!(true)),
    ] {
        let mut altered = account_spec.mint_body();
        altered[field] = bad;
        denial(
            &bao,
            header_text(&owner).unwrap(),
            Method::POST,
            &format!("auth/token/create/{}", account_spec.leaf_role),
            Some(altered),
        )
        .await
        .unwrap();
    }
    let mut missing = account_spec.mint_body();
    missing.as_object_mut().unwrap().remove("renewable");
    denial(
        &bao,
        header_text(&owner).unwrap(),
        Method::POST,
        &format!("auth/token/create/{}", account_spec.leaf_role),
        Some(missing),
    )
    .await
    .unwrap();
    request(
        &bao,
        Method::POST,
        "auth/token/revoke-self",
        Some(&json!({})),
        Some(header_text(&owner).unwrap()),
    )
    .await
    .unwrap();
    // Existing resources cannot be adopted by replaying the independent helper.
    assert!(provision_resources(&plan, &bao, &root).await.is_err());
    // Drift is observed and refused; no repair mutation is authorized.
    request(
        &bao,
        Method::POST,
        &format!("auth/token/roles/{}", account_spec.leaf_role),
        Some(&json!({"renewable":true})),
        Some(&root),
    )
    .await
    .unwrap();
    assert!(restored.account().token().await.is_err());
    assert_eq!(
        data(
            &bao,
            &root,
            &format!("auth/token/roles/{}", account_spec.leaf_role)
        )
        .await
        .unwrap()["renewable"],
        true
    );
    assert_eq!(
        fixture
            .state
            .read_evidence("acme-credentials-staging-result.json")
            .unwrap()
            .unwrap(),
        receipt_before
    );
    let journal_before = fixture.state.journal().clone();
    assert!(prepare_initial(
        &mut fixture.state,
        &fixture.installation,
        &fixture.configuration,
        account_key,
        &ingress,
        &bao
    )
    .await
    .is_err());
    assert_eq!(fixture.state.journal(), &journal_before);
}
