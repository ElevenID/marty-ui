//! Representative persisted Canvas reads through the rendered executables.
//! Reuses the unchanged full operations corpus/seed; lifecycle publication and
//! cancellation remain qualified by their existing dedicated configured gates.
use super::{
    base_runtime_gateway::GatewayFixture,
    canvas_operations_read_replay::{fixtures, seed, timestamps},
    issuance_named_peers::CANVAS_CLIENT_KEY,
};
use serde_json::Value;

pub(super) async fn run(pool: &sqlx::PgPool, gateway: &GatewayFixture, seed_once: bool) {
    if seed_once {
        seed(pool).await;
    }
    let [shared, scenarios, frozen] = fixtures();
    let before: Value = sqlx::query_scalar(scenarios["snapshot_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let preserved: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    for name in [
        "jobs_list",
        "candidates_list",
        "reviews_list",
        "jobs_filtered",
        "candidates_filtered",
        "reviews_filtered",
    ] {
        let case = scenarios["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["name"] == name)
            .unwrap();
        let expected = frozen["observations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["name"] == name)
            .unwrap();
        let response = gateway
            .client
            .get(format!(
                "{}{}",
                gateway.origin,
                case["path"].as_str().unwrap()
            ))
            .header("x-api-key", CANVAS_CLIENT_KEY)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            expected["status"].as_u64().unwrap() as u16
        );
        assert_eq!(
            response.headers()["content-type"].to_str().unwrap(),
            expected["content_type"].as_str().unwrap()
        );
        let mut body: Value = response.json().await.unwrap();
        timestamps(&mut body);
        assert_eq!(body, expected["body"], "frozen Canvas read {name}");
        let after: Value = sqlx::query_scalar(scenarios["snapshot_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(after, before, "read must not change operational state");
        let after: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            after, preserved,
            "read must not change protected application/evidence rows"
        );
    }
}
