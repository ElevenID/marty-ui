#[expect(
    dead_code,
    reason = "shared command fixture has other acceptance owners"
)]
#[path = "../../../services/issuance/tests/support/bounded_fixture_command.rs"]
mod bounded_fixture_command;
#[expect(
    dead_code,
    reason = "shared database fixture has other acceptance owners"
)]
#[path = "../../../services/issuance/tests/support/canvas_published_database.rs"]
mod canvas_published_database;
#[path = "../../canvas-acceptance/tests/support/owned_cleanup.rs"]
mod owned_cleanup;
#[path = "../../../services/issuance/tests/support/remote_integration_secret.rs"]
mod remote_integration_secret;
#[path = "../../../services/issuance/tests/support/renewal_reference_fixture.rs"]
mod renewal_reference_fixture;
#[path = "../../selfhost-bundle/tests/support/extracted_bundle.rs"]
mod selfhost_extracted;
#[path = "support/selfhost_packaged_runtime.rs"]
mod selfhost_packaged_runtime;
#[path = "../../selfhost-bundle/tests/support/resolved_selfhost_runtime.rs"]
mod selfhost_prepared;
#[path = "support/selfhost_runtime_sidecar.rs"]
mod selfhost_runtime_sidecar;

#[tokio::test]
async fn packaged_remote_secret_fixture_requires_verified_https() {
    let fixture = remote_integration_secret::container_server(
        std::net::Ipv4Addr::LOCALHOST,
        selfhost_runtime_sidecar::MANAGEMENT_KEY,
    )
    .await
    .unwrap();
    assert!(fixture.base_url.starts_with("https://127.0.0.1:"));
    assert!(fixture.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(fixture.ca_pem.contains("-----END CERTIFICATE-----"));
}

#[test]
fn selfhost_public_image_loader_isolated() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Selfhost public image acceptance requires the configured Linux gate");
        return;
    }
    selfhost_packaged_runtime::run_isolated_child().unwrap();
}

#[tokio::test]
async fn selfhost_public_image_loader_child() {
    if std::env::var("MARTY_SELFHOST_LOADER_CHILD").as_deref() != Ok("1") {
        eprintln!("Selfhost loader child requires the closed host coordinator");
        return;
    }
    selfhost_runtime_sidecar::require_closed_child().unwrap();
    let sentinel = std::env::var("MARTY_SELFHOST_CHILD_SENTINEL").unwrap();
    uuid::Uuid::parse_str(&sentinel).unwrap();
    let fixture = selfhost_packaged_runtime::preflight().unwrap();
    // The surviving host owns this UUID and always verifies recovery. Do not
    // remove its namespace before an interrupted native mount is recovered.
    let database_pending = selfhost_runtime_sidecar::PendingOperation::begin(
        selfhost_runtime_sidecar::PendingKind::Database,
    )
    .unwrap();
    let owned = std::mem::ManuallyDrop::new(
        canvas_published_database::PublishedDatabase::start_with_scope(
            selfhost_runtime_sidecar::parent_scope().unwrap(),
        )
        .await
        .unwrap(),
    );
    database_pending.complete().unwrap();
    selfhost_packaged_runtime::after_database_checkpoint().unwrap();
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(selfhost_packaged_runtime::run(&owned, fixture))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err("Selfhost child operation panicked".into()));
    result.unwrap();
    println!("\nSELFHOST_PUBLIC_LOADER_COMPLETE:{sentinel}");
}
