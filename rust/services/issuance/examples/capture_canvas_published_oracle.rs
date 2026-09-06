//! Offline reference capture, not a qualification gate or deployment command.
//! Reuses the exact-owned disposable published-image/database fixture.
#[allow(dead_code)]
#[path = "../tests/support/canvas_published_database.rs"]
mod canvas_published_database;

#[tokio::main]
async fn main() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [scenario] = arguments.as_slice() else {
        return Err("expected validation-boundary or status-provider".into());
    };
    use canvas_published_database::PublishedDatabase;
    let owned = match scenario.as_str() {
        "validation-boundary" => PublishedDatabase::start_with_validation_boundary().await?,
        "status-provider" => PublishedDatabase::start_with_status_provider().await?,
        _ => return Err("expected validation-boundary or status-provider".into()),
    };
    let observation = owned
        .oracle
        .as_ref()
        .ok_or("published fixture did not return an oracle")?;
    println!("CANVAS_PUBLISHED_ORACLE={observation}");
    owned.close()
}
