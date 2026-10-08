//! Pure roster progress decision; the PostgreSQL adapter owns the atomic merge and fences.

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

pub(crate) fn roster_cursor_patch(
    snapshot: &Map<String, Value>,
    next_cursor: usize,
    roster_size: usize,
    completed_at: Option<DateTime<Utc>>,
) -> Value {
    let mut patch = json!({
        "roster_cursor": next_cursor,
        "roster_size": roster_size,
        "roster_cycle_completed_at": completed_at,
    });
    // The worker snapshots before writing its heartbeat. Preserve only these
    // snapshot keys (including explicit null); SQL removes the current values
    // before applying this patch so absent keys stay absent.
    for key in ["worker_id", "worker_heartbeat_at"] {
        if let Some(value) = snapshot.get(key) {
            patch[key] = value.clone();
        }
    }
    patch
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const OBLIGATIONS: &str =
        include_str!("../../../../contracts/canvas-roster-metadata-obligations.json");
    const SHAPES: &[&str] = &[
        "absent",
        "preexisting",
        "explicit_null",
        "worker_only",
        "heartbeat_only",
    ];

    #[test]
    fn snapshot_shapes_have_independent_expected_patches() {
        let obligations: Value = serde_json::from_str(OBLIGATIONS).unwrap();
        let expected_cases: BTreeSet<&str> = obligations["fast_shape_cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            SHAPES.iter().copied().collect::<BTreeSet<_>>(),
            expected_cases
        );
        assert_eq!(SHAPES.len(), expected_cases.len());
        let now = DateTime::parse_from_rfc3339("2026-09-01T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        for name in SHAPES {
            let mut snapshot = match *name {
                "absent" => json!({}),
                "preexisting" => json!({
                    "worker_id": "prior-worker",
                    "worker_heartbeat_at": "2026-09-01T00:00:01Z",
                }),
                "explicit_null" => json!({
                    "worker_id": null, "worker_heartbeat_at": null,
                }),
                "worker_only" => json!({"worker_id": "prior-worker"}),
                "heartbeat_only" => json!({
                    "worker_heartbeat_at": "2026-09-01T00:00:01Z",
                }),
                _ => unreachable!(),
            };
            snapshot["unrelated"] = json!({"version": "current"});
            // Literal expectations deliberately do not reuse the production
            // key-copy algorithm; they detect loss of absence/null semantics.
            let expected = match *name {
                "absent" => {
                    json!({"roster_cursor":1,"roster_size":7,"roster_cycle_completed_at":null})
                }
                "preexisting" => {
                    json!({"roster_cursor":1,"roster_size":7,"roster_cycle_completed_at":null,"worker_id":"prior-worker","worker_heartbeat_at":"2026-09-01T00:00:01Z"})
                }
                "explicit_null" => {
                    json!({"roster_cursor":1,"roster_size":7,"roster_cycle_completed_at":null,"worker_id":null,"worker_heartbeat_at":null})
                }
                "worker_only" => {
                    json!({"roster_cursor":1,"roster_size":7,"roster_cycle_completed_at":null,"worker_id":"prior-worker"})
                }
                "heartbeat_only" => {
                    json!({"roster_cursor":1,"roster_size":7,"roster_cycle_completed_at":null,"worker_heartbeat_at":"2026-09-01T00:00:01Z"})
                }
                _ => unreachable!(),
            };
            let actual = roster_cursor_patch(snapshot.as_object().unwrap(), 1, 7, None);
            assert_eq!(actual, expected, "{name}");
            assert!(actual.get("unrelated").is_none(), "{name}");
        }
        let completed = roster_cursor_patch(&Map::new(), 0, 7, Some(now));
        assert_eq!(
            completed["roster_cycle_completed_at"],
            json!("2026-09-01T12:34:56Z")
        );
        assert_eq!(completed["roster_cursor"], 0);
    }
}
