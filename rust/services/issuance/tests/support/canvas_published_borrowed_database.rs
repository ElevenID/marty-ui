//! Outer database ownership must survive a forcibly terminated borrowing child.
use super::{
    canvas_published_database::PublishedDatabase, canvas_worker_process_signals::OwnedWorker,
};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

struct Handshake(PathBuf);

impl Handshake {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("canvas-borrower-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn ready(&self) -> PathBuf {
        self.0.join("borrower-ready")
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        // Only the exact file and empty directory created by this test owner.
        if let Err(error) = fs::remove_file(self.ready()) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("Owned borrower handshake file needs cleanup");
            }
        }
        if fs::remove_dir(&self.0).is_err() {
            eprintln!("Owned borrower handshake directory needs cleanup");
        }
    }
}

#[tokio::test]
async fn borrower_child() {
    let Ok(descriptor) = std::env::var("MARTY_CANVAS_BORROWER_TEST_DATABASE") else {
        return;
    };
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let directory = PathBuf::from(std::env::var("MARTY_CANVAS_BORROWER_TEST_DIRECTORY").unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(
        directory.parent().unwrap(),
        std::env::temp_dir().canonicalize().unwrap()
    );
    assert!(directory
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("canvas-borrower-"));
    let url = PublishedDatabase::borrowed_url(&descriptor).unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let value: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(value, 1);
    fs::File::create_new(directory.join("borrower-ready")).unwrap();
    // Deliberately no cleanup/Drop ownership for Docker resources in this child.
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn outer_database_owner_survives_forced_borrower_exit() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = PublishedDatabase::start().await.unwrap();
    let descriptor = owned.borrow_descriptor().unwrap();
    let handshake = Handshake::new();
    let mut child = OwnedWorker(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "canvas_published_borrowed_database::borrower_child",
                "--exact",
            ])
            .env("MARTY_CANVAS_BORROWER_TEST_DATABASE", &descriptor)
            .env("MARTY_CANVAS_BORROWER_TEST_DIRECTORY", &handshake.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        while !handshake.ready().is_file() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "Borrower exited before readiness"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Borrower must prove database access before forced termination");
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap();
    assert!(!child.wait().await.success());
    drop(child);
    assert_eq!(
        PublishedDatabase::borrowed_url(&descriptor).unwrap(),
        owned.url
    );
    let pool = sqlx::PgPool::connect(&owned.url).await.unwrap();
    let value: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(value, 1);
    pool.close().await;
    owned.close_verified().unwrap();
    drop(handshake);
}
