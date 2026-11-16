use super::*;
use std::{
    cell::RefCell,
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::PathBuf,
};

struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("organization-installer-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn output(&self) -> files::Output {
        files::test_support::open(&self.0)
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (Context, DateTime<Utc>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let now = DateTime::from_timestamp(1_793_448_000, 0).unwrap();
    let installation = Uuid::new_v4();
    let organization = Uuid::new_v4();
    let project = format!("marty-install-{}", installation.simple());
    let journal = serde_json::json!({
        "schema":"elevenid.installer-state/v1", "installation_id":installation,
        "phase":"provisioning", "runtime":{"engine_id":"rootless-owned-engine"},
        "identity":{"source_sha":"public-source-only", "private_ignored_value":"never-copy-me"},
    });
    let session = serde_json::json!({
        "schema":"elevenid.installer-compose-session/v1", "installation_id":installation,
        "inputs":{"project":project},
        "receipt":{"project":project,"engine_id":"rootless-owned-engine",
            "command_succeeded":true,"observation_validated":true},
        "model":{"services":{
            "organization":{"environment":{"MARTY_ORG_ID":organization,"UNRELATED_SECRET":"never-copy-me"}},
            "db-migrate":{"environment":{"MARTY_ORG_ID":organization}}
        }}
    });
    let journal = json(&journal).unwrap();
    let session = json(&session).unwrap();
    let request = json(&serde_json::json!({
        "schema":REQUEST_SCHEMA,"request_id":Uuid::new_v4(),"created_at":now,
        "installation_sha256":hash(&journal),"compose_session_sha256":hash(&session)
    }))
    .unwrap();
    (
        Context::read(&request, &journal, &session).unwrap(),
        now,
        request,
        journal,
        session,
    )
}

fn altered_request(request: &[u8], journal: &[u8], session: &[u8]) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(request).unwrap();
    value["installation_sha256"] = hash(journal).into();
    value["compose_session_sha256"] = hash(session).into();
    json(&value).unwrap()
}

#[test]
fn scope_comes_from_exact_completed_startup_without_copying_other_values() {
    let (context, now, request, journal, session) = fixture();
    assert_eq!(
        Context::read(&request, &journal, &session).unwrap(),
        context
    );
    let intent = Intent::new(&context, now).unwrap();
    let command = intent.command();
    assert_eq!(
        command.created_by,
        format!("installer:{}", context.installation_id)
    );
    assert_eq!(command.scopes, Some(vec!["keys:write".into()]));
    assert_eq!(
        command.expires_at,
        Some(now + chrono::Duration::minutes(15))
    );
    assert_eq!(command.scope_type, ApiKeyScopeType::Organization);
    assert_eq!(command.deployment_profile_id, None);
    assert!(!command.is_test);
    let public = json(&receipt(&intent, "issued", Some(Uuid::new_v4()), false).unwrap()).unwrap();
    assert!(!String::from_utf8(public).unwrap().contains("never-copy-me"));
}

#[test]
fn mismatched_org_engine_project_incomplete_startup_and_changed_snapshots_are_refused() {
    let (_, _, request, journal, session) = fixture();
    let original: Value = serde_json::from_slice(&session).unwrap();
    for pointer in [
        "/installation_id",
        "/inputs/project",
        "/receipt/project",
        "/receipt/engine_id",
        "/model/services/db-migrate/environment/MARTY_ORG_ID",
    ] {
        let mut bad = original.clone();
        *bad.pointer_mut(pointer).unwrap() = "foreign".into();
        let bytes = json(&bad).unwrap();
        let bound = altered_request(&request, &journal, &bytes);
        assert!(
            Context::read(&bound, &journal, &bytes).is_err(),
            "{pointer}"
        );
    }
    for field in ["command_succeeded", "observation_validated"] {
        let mut bad = original.clone();
        bad["receipt"][field] = false.into();
        let bytes = json(&bad).unwrap();
        let bound = altered_request(&request, &journal, &bytes);
        assert!(Context::read(&bound, &journal, &bytes).is_err());
    }
    let mut changed = session.clone();
    changed.push(b' ');
    assert!(Context::read(&request, &journal, &changed).is_err());
    let mut bad: Value = serde_json::from_slice(&journal).unwrap();
    bad["phase"] = "initialized".into();
    let bytes = json(&bad).unwrap();
    assert!(Context::read(
        &altered_request(&request, &bytes, &session),
        &bytes,
        &session
    )
    .is_err());
}

#[test]
fn request_cannot_choose_creator_scope_lifetime_or_database() {
    let (_, _, request, journal, session) = fixture();
    for field in [
        "actor_type",
        "created_by",
        "scopes",
        "expires_at",
        "database_url",
        "organization_id",
    ] {
        let mut bad: Value = serde_json::from_slice(&request).unwrap();
        bad[field] = "untrusted".into();
        assert!(
            Context::read(&json(&bad).unwrap(), &journal, &session).is_err(),
            "{field}"
        );
    }
}

#[test]
fn issue_request_expires_but_recorded_revoke_identity_does_not_gain_a_new_lease() {
    let (context, now, _, _, _) = fixture();
    assert!(Intent::new(&context, now - chrono::Duration::microseconds(1)).is_err());
    assert!(Intent::new(&context, now + chrono::Duration::seconds(301)).is_err());
    let intent = Intent::new(&context, now).unwrap();
    intent.validate(&context).unwrap();
    let mut changed = intent.clone();
    changed.expires_at += chrono::Duration::microseconds(1);
    assert!(changed.validate(&context).is_err());
    let mut changed_context = context.clone();
    changed_context.request_id = Uuid::new_v4();
    assert!(intent.validate(&changed_context).is_err());
}

#[test]
fn credential_intent_uses_postgres_microsecond_precision_for_recovery() {
    let (context, now, _, _, _) = fixture();
    let intent = Intent::new(&context, now + chrono::Duration::nanoseconds(123_456_789)).unwrap();
    assert_eq!(intent.created_at.timestamp_subsec_nanos(), 123_456_000);
    intent.validate(&context).unwrap();
}

#[derive(Default)]
struct FakeKeys {
    keys: RefCell<Vec<ApiKey>>,
    creates: RefCell<usize>,
    revokes: RefCell<Vec<Uuid>>,
    raw: RefCell<Option<String>>,
    absent_organization: bool,
    lost_create_response: bool,
    fail_revoke: bool,
}

impl Keys for FakeKeys {
    async fn active_organization(&self, _: Uuid) -> Result<bool> {
        Ok(!self.absent_organization)
    }
    async fn list(&self, _: Uuid) -> Result<Vec<ApiKey>> {
        Ok(self.keys.borrow().clone())
    }
    async fn create(&self, intent: &Intent) -> Result<ApiKeyCreation> {
        *self.creates.borrow_mut() += 1;
        let command = intent.command();
        let (key, raw) = ApiKey::create(
            crate::ApiKeySpec {
                organization_id: command.organization_id,
                name: command.name,
                created_by: command.created_by,
                scopes: command.scopes,
                description: command.description,
                expires_at: command.expires_at,
                now: command.now,
            },
            false,
        );
        self.keys.borrow_mut().push(key.clone());
        *self.raw.borrow_mut() = Some(raw.clone());
        if self.lost_create_response {
            return Err(BootstrapError("key creation uncertain"));
        }
        Ok(ApiKeyCreation {
            api_key: key,
            raw_key: raw,
        })
    }
    async fn revoke(&self, _: &Intent, id: Uuid, now: DateTime<Utc>) -> Result<ApiKey> {
        self.revokes.borrow_mut().push(id);
        if self.fail_revoke {
            return Err(BootstrapError("key revocation uncertain"));
        }
        let mut keys = self.keys.borrow_mut();
        let key = keys.iter_mut().find(|key| key.id == id).unwrap();
        key.revoke(now);
        Ok(key.clone())
    }
}

fn operation(directory: &PrivateDirectory) -> (files::Output, Intent) {
    let (context, now, _, _, _) = fixture();
    let output = directory.output();
    output.require_empty().unwrap();
    let intent = Intent::new(&context, now).unwrap();
    output.write(INTENT_FILE, &json(&intent).unwrap()).unwrap();
    (output, intent)
}

#[tokio::test]
async fn issue_and_revoke_use_bound_key_and_never_put_secret_in_receipt() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let keys = FakeKeys::default();
    let issued = issue(&keys, &output, &intent).await.unwrap();
    assert_eq!(*keys.creates.borrow(), 1);
    let raw = keys.raw.borrow().clone().unwrap();
    assert_eq!(output.read(KEY_FILE).unwrap(), raw.as_bytes());
    for record in [INTENT_FILE, "issued.json"] {
        assert!(!String::from_utf8(output.read(record).unwrap())
            .unwrap()
            .contains(&raw));
    }
    assert!(output.require_empty().is_err());
    assert!(issue(&keys, &output, &intent).await.is_err());
    assert_eq!(*keys.creates.borrow(), 1);
    let revoked = revoke(&keys, &output, &intent).await.unwrap();
    assert_eq!(revoked.api_key_id, issued.api_key_id);
    assert!(revoked.revoked);
    assert!(output.optional(KEY_FILE).unwrap().is_none());
    assert_eq!(keys.revokes.borrow().len(), 1);
}

#[tokio::test]
async fn missing_organization_never_creates_or_reconciles_a_tenant() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let keys = FakeKeys {
        absent_organization: true,
        ..FakeKeys::default()
    };
    assert!(issue(&keys, &output, &intent).await.is_err());
    assert_eq!(*keys.creates.borrow(), 0);
    assert!(keys.revokes.borrow().is_empty());
    assert!(output.require_empty().is_err());
}

#[tokio::test]
async fn lost_create_response_is_reconciled_and_revoked_without_second_mint() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let keys = FakeKeys {
        lost_create_response: true,
        ..FakeKeys::default()
    };
    assert!(issue(&keys, &output, &intent).await.is_err());
    assert_eq!(*keys.creates.borrow(), 1);
    assert_eq!(keys.revokes.borrow().len(), 1);
    let failed: Receipt = serde_json::from_slice(&output.read("failed.json").unwrap()).unwrap();
    assert!(failed.revoked && failed.api_key_id.is_some());
    assert!(!failed.automatic_replay_allowed);
    assert!(output.optional(KEY_FILE).unwrap().is_none());
    assert!(issue(&keys, &output, &intent).await.is_err());
    assert_eq!(*keys.creates.borrow(), 1);
}

#[tokio::test]
async fn output_collision_revokes_created_key_and_preserves_foreign_file() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    output.write(KEY_FILE, b"foreign-output").unwrap();
    let keys = FakeKeys::default();
    assert!(issue(&keys, &output, &intent).await.is_err());
    assert_eq!(keys.revokes.borrow().len(), 1);
    assert_eq!(output.read(KEY_FILE).unwrap(), b"foreign-output");
    let failed: Receipt = serde_json::from_slice(&output.read("failed.json").unwrap()).unwrap();
    assert!(failed.revoked);
}

#[tokio::test]
async fn cleanup_failure_keeps_known_key_identity_and_preserves_foreign_receipt() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    // Refuse the success receipt after the credential was durably delivered.
    output.write("issued.json", b"occupied").unwrap();
    let mut keys = FakeKeys {
        fail_revoke: true,
        ..FakeKeys::default()
    };
    assert!(issue(&keys, &output, &intent).await.is_err());
    let failed: Receipt = serde_json::from_slice(&output.read("failed.json").unwrap()).unwrap();
    assert!(!failed.revoked);
    assert_eq!(failed.api_key_id, Some(keys.keys.borrow()[0].id));
    // A malformed receipt is preserved and refuses explicit mutation.
    keys.fail_revoke = false;
    assert!(revoke(&keys, &output, &intent).await.is_err());
    assert_eq!(keys.revokes.borrow().len(), 1);
    assert_eq!(*keys.creates.borrow(), 1);
}

#[tokio::test]
async fn lost_issue_and_cleanup_responses_support_explicit_revocation_from_original_intent() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let mut keys = FakeKeys {
        lost_create_response: true,
        fail_revoke: true,
        ..FakeKeys::default()
    };
    assert!(issue(&keys, &output, &intent).await.is_err());
    let failed: Receipt = serde_json::from_slice(&output.read("failed.json").unwrap()).unwrap();
    assert!(!failed.revoked);
    assert!(output.optional("issued.json").unwrap().is_none());
    keys.fail_revoke = false;
    let requested = receipt(&intent, "revoke_requested", None, false).unwrap();
    record_revoke(&output, "revoke-intent.json", &requested).unwrap();
    let completed = revoke(&keys, &output, &intent).await.unwrap();
    let saved = output.read("revoked.json").unwrap();
    let revocations = keys.revokes.borrow().len();
    // The caller explicitly repeats revoke after a lost response. This only
    // observes the exact already-revoked row and keeps immutable evidence.
    record_revoke(&output, "revoke-intent.json", &requested).unwrap();
    assert_eq!(revoke(&keys, &output, &intent).await.unwrap(), completed);
    assert_eq!(output.read("revoked.json").unwrap(), saved);
    assert_eq!(keys.revokes.borrow().len(), revocations);
    assert_eq!(*keys.creates.borrow(), 1);
    assert!(completed.revoked);
    assert!(issue(&keys, &output, &intent).await.is_err());
}

#[tokio::test]
async fn explicit_revoke_reports_absent_key_without_claiming_revocation() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let keys = FakeKeys::default();
    let result = revoke(&keys, &output, &intent).await.unwrap();
    assert_eq!(result.operation, "revoke_absent");
    assert!(!result.revoked);
    assert_eq!(result.api_key_id, None);
    assert!(keys.revokes.borrow().is_empty());
    assert_eq!(*keys.creates.borrow(), 0);
}

#[test]
fn explicit_revoke_never_adopts_or_overwrites_a_different_record() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let original = receipt(&intent, "revoke_requested", None, false).unwrap();
    record_revoke(&output, "revoke-intent.json", &original).unwrap();
    let mut different = original.clone();
    different.request_id = Uuid::new_v4();
    assert!(record_revoke(&output, "revoke-intent.json", &different).is_err());
    assert_eq!(
        output.read("revoke-intent.json").unwrap(),
        json(&original).unwrap()
    );
}

#[tokio::test]
async fn surviving_intent_recovers_key_when_issue_receipt_was_never_written() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let keys = FakeKeys::default();
    let creation = keys.create(&intent).await.unwrap();
    assert!(output.optional("issued.json").unwrap().is_none());
    let revoked = revoke(&keys, &output, &intent).await.unwrap();
    assert_eq!(revoked.api_key_id, Some(creation.api_key.id));
    assert!(revoked.revoked);
    assert_eq!(*keys.creates.borrow(), 1);
}

#[tokio::test]
async fn unrelated_or_rebound_keys_are_never_revoked() {
    for change in ["actor", "request", "scope", "expiry", "organization"] {
        let directory = PrivateDirectory::new();
        let (output, intent) = operation(&directory);
        let keys = FakeKeys::default();
        let _ = keys.create(&intent).await.unwrap();
        {
            let mut stored = keys.keys.borrow_mut();
            let key = &mut stored[0];
            match change {
                "actor" => key.created_by = "human".into(),
                "request" => key.description = Some("other request".into()),
                "scope" => key.scopes.push("admin:full".into()),
                "expiry" => key.expires_at = None,
                "organization" => key.organization_id = Uuid::new_v4(),
                _ => unreachable!(),
            }
        }
        assert!(revoke(&keys, &output, &intent).await.is_err(), "{change}");
        assert!(keys.revokes.borrow().is_empty());
    }
}

#[tokio::test]
async fn duplicate_installation_candidates_refuse_cleanup_before_any_revocation() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    let keys = FakeKeys::default();
    let _ = keys.create(&intent).await.unwrap();
    let _ = keys.create(&intent).await.unwrap();
    assert!(revoke(&keys, &output, &intent).await.is_err());
    assert!(keys.revokes.borrow().is_empty());
}

#[test]
fn setup_envelope_requires_actual_readonly_inputs_and_writable_output() {
    let status = "Uid:\t0\t0\t0\t0\nNoNewPrivs:\t1\n";
    let mut mounts = String::new();
    for (index, path) in [
        "/",
        "/input/organization-bootstrap-request.json",
        "/input/installation.json",
        "/input/compose-session.json",
        "/input/marty-db-password",
        "/output",
    ]
    .into_iter()
    .enumerate()
    {
        let mode = if path == "/output" { "rw" } else { "ro" };
        mounts.push_str(&format!(
            "{} 1 0:1 / {path} {mode},relatime - ext4 source rw\n",
            index + 2
        ));
    }
    assert_eq!(files::test_support::envelope(status, &mounts).unwrap(), 0);
    assert!(files::test_support::envelope(
        &status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        &mounts
    )
    .is_err());
    assert!(files::test_support::envelope(
        status,
        &mounts.replace(
            "/input/installation.json ro,",
            "/input/installation.json rw,"
        )
    )
    .is_err());
    assert!(
        files::test_support::envelope(status, &mounts.replace("/output rw,", "/output ro,"))
            .is_err()
    );
    assert!(files::test_support::envelope(
        status,
        &mounts.replace("/input/compose-session.json", "/elsewhere")
    )
    .is_err());
}

#[test]
fn private_inputs_reject_links_writable_permissions_and_nonregular_files() {
    let directory = PrivateDirectory::new();
    let file = directory.0.join("record");
    fs::write(&file, b"owned").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let uid = fs::metadata(&file).unwrap().uid();
    assert_eq!(files::test_support::read(&file, uid).unwrap(), b"owned");
    let link = directory.0.join("link");
    symlink(&file, &link).unwrap();
    assert!(files::test_support::read(&link, uid).is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&file, &link).unwrap();
    assert!(files::test_support::read(&file, uid).is_err());
    fs::remove_file(link).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(files::test_support::read(&file, uid).is_err());
    assert!(files::test_support::read(&directory.0, uid).is_err());
}

#[test]
fn exclusive_intents_and_changed_output_directory_block_replay() {
    let directory = PrivateDirectory::new();
    let (output, intent) = operation(&directory);
    assert!(output.write(INTENT_FILE, &json(&intent).unwrap()).is_err());
    output.write("revoke-intent.json", b"first").unwrap();
    assert!(output.write("revoke-intent.json", b"second").is_err());
    let retained = directory.0.with_extension("retained");
    fs::rename(&directory.0, &retained).unwrap();
    fs::create_dir(&directory.0).unwrap();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(output.write(KEY_FILE, b"must-not-appear").is_err());
    assert!(!directory.0.join(KEY_FILE).exists());
    assert!(!retained.join(KEY_FILE).exists());
    fs::remove_dir_all(retained).unwrap();
}
