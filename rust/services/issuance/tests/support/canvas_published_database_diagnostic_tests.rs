#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    #[test]
    fn docker_create_errors_report_only_fixed_categories() {
        for (stderr, expected) in [
            (
                "Error: No such image: private.example/image",
                "image_unavailable",
            ),
            (
                "Cannot connect to the Docker daemon at /var/run/docker.sock",
                "daemon_unavailable",
            ),
            (
                "failed to create: no space left on device",
                "storage_exhausted",
            ),
            (
                "failed to create: cannot allocate memory",
                "runtime_capacity",
            ),
            (
                "Bind for 127.0.0.1 failed: port is already allocated",
                "port_conflict",
            ),
            ("daemon says permission denied", "permission_denied"),
            ("unexpected detail with password=must-not-leak", "unknown"),
        ] {
            let category = docker_create_failure_category(stderr.as_bytes());
            assert_eq!(category, expected);
            assert!(!category.contains("password"));
            assert!(!category.contains("private.example"));
        }
        assert_eq!(docker_create_failure_category(&[0xff, 0xfe]), "unknown");
    }

    fn installed_revisions(postgres: &str) -> String {
        docker(&[
            "exec",
            postgres,
            "psql",
            "-X",
            "-A",
            "-t",
            "-U",
            "oracle",
            "-d",
            DATABASE,
            "-c",
            "SELECT string_agg(version_num, ',' ORDER BY version_num) FROM issuance_service.alembic_version",
        ])
        .unwrap()
    }

    fn marker_absence(postgres: &str) -> String {
        docker(&[
            "exec",
            postgres,
            "psql",
            "-X",
            "-A",
            "-t",
            "-U",
            "oracle",
            "-d",
            DATABASE,
            "-c",
            "SELECT to_regclass('public.marty_pilot_marker') IS NULL",
        ])
        .unwrap()
    }

    // Compare only the two psql guard keys after validating their pair. Never
    // normalize SQL, table rows, or a COPY payload, and never print the dump.
    fn comparable_dump(dump: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(dump.len());
        let mut restrict_key: Option<&[u8]> = None;
        let mut unrestrict_key: Option<&[u8]> = None;
        let mut in_copy = false;
        for line in dump.split_inclusive(|byte| *byte == b'\n') {
            let body = line.strip_suffix(b"\n").unwrap_or(line);
            if !in_copy {
                if let Some(key) = body.strip_prefix(b"\\restrict ") {
                    assert!(
                        restrict_key.replace(key).is_none() && unrestrict_key.is_none(),
                        "misordered or duplicate dump guard"
                    );
                    result.extend_from_slice(b"\\restrict [key]");
                } else if let Some(key) = body.strip_prefix(b"\\unrestrict ") {
                    assert!(
                        restrict_key.is_some() && unrestrict_key.replace(key).is_none(),
                        "misordered or duplicate dump guard"
                    );
                    result.extend_from_slice(b"\\unrestrict [key]");
                } else {
                    result.extend_from_slice(body);
                }
            } else {
                result.extend_from_slice(body);
            }
            if line.ends_with(b"\n") {
                result.push(b'\n');
            }
            if body.starts_with(b"COPY ") && body.ends_with(b"FROM stdin;") {
                in_copy = true;
            } else if in_copy && body == b"\\." {
                in_copy = false;
            }
        }
        let key = restrict_key.expect("missing opening dump guard");
        assert!(!key.is_empty() && key.len() <= 128 && key.iter().all(u8::is_ascii_alphanumeric));
        assert_eq!(unrestrict_key, Some(key), "dump guard pair differs");
        result
    }

    // PostgreSQL deparses twelve pinned CHECK/index expressions differently
    // after restore (varchar-array literals become explicit text casts). All
    // other lines, including COPY rows, must match byte-for-byte. Pin both
    // sides of the twelve exceptional lines so a shared restore loss cannot
    // masquerade as parity. Never log dump contents or differing SQL.
    fn known_roundtrip_dump_parity(fresh: &[u8], restored: &[u8]) -> bool {
        const REPARSED_EXPRESSIONS: [&str; 12] = [
            "    CONSTRAINT ck_canvas_award_candidates_state CHECK ",
            "    CONSTRAINT ck_canvas_sync_jobs_status CHECK ",
            "    CONSTRAINT ck_canvas_sync_targets_type CHECK ",
            "    CONSTRAINT ck_canvas_learner_identities_status CHECK ",
            "    CONSTRAINT ck_canvas_oauth_connections_status CHECK ",
            "    CONSTRAINT ck_canvas_platforms_lti_trust_profile CHECK ",
            "    CONSTRAINT ck_canvas_platforms_registration_status CHECK ",
            "    CONSTRAINT ck_evidence_policy_reviews_resolution_claim CHECK ",
            "    CONSTRAINT ck_evidence_policy_reviews_status CHECK ",
            "    CONSTRAINT ck_issuance_transactions_issuer_algorithm CHECK ",
            "    CONSTRAINT ck_oid4vci_ephemeral_capabilities_purpose CHECK ",
            "CREATE UNIQUE INDEX ux_canvas_sync_jobs_one_active_target ON ",
        ];
        let fresh = comparable_dump(fresh);
        let restored = comparable_dump(restored);
        let fresh_lines = fresh.split(|byte| *byte == b'\n').collect::<Vec<_>>();
        let restored_lines = restored.split(|byte| *byte == b'\n').collect::<Vec<_>>();
        if fresh_lines.len() != restored_lines.len() {
            return false;
        }
        let mut fresh_hash = Sha256::new();
        let mut restored_hash = Sha256::new();
        let mut changed = 0;
        for (left, right) in fresh_lines.iter().zip(restored_lines.iter()) {
            if left != right {
                let Some(label) = REPARSED_EXPRESSIONS.get(changed) else {
                    return false;
                };
                if !left.starts_with(label.as_bytes()) || !right.starts_with(label.as_bytes()) {
                    return false;
                }
                changed += 1;
                fresh_hash.update(left);
                fresh_hash.update([0]);
                restored_hash.update(right);
                restored_hash.update([0]);
            }
        }
        changed == REPARSED_EXPRESSIONS.len()
            && format!("{:x}", fresh_hash.finalize())
                == "332d498157de505749e9e9d219d5856d64bd533ba014d5236f69100903f3425f"
            && format!("{:x}", restored_hash.finalize())
                == "c2d3800dbab229009231418818835431c67d554c80921b4d68c31d12d364c204"
    }

    #[test]
    fn comparable_dump_normalizes_only_matched_outer_guards() {
        let first = b"\\restrict RandomKey123\nCOPY demo FROM stdin;\n\\restrict row\n\\.\n\\unrestrict RandomKey123\n";
        let second = b"\\restrict OtherKey456\nCOPY demo FROM stdin;\n\\restrict row\n\\.\n\\unrestrict OtherKey456\n";
        assert_eq!(comparable_dump(first), comparable_dump(second));
        let changed_row = b"\\restrict OtherKey456\nCOPY demo FROM stdin;\n\\restrict different\n\\.\n\\unrestrict OtherKey456\n";
        assert_ne!(comparable_dump(first), comparable_dump(changed_row));
        assert!(
            std::panic::catch_unwind(|| comparable_dump(b"\\restrict A\n\\unrestrict B\n"))
                .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| comparable_dump(b"\\unrestrict A\n\\restrict A\n"))
                .is_err()
        );
        assert!(std::panic::catch_unwind(|| comparable_dump(
            b"COPY demo FROM stdin;\n\\restrict row\n\\.\n"
        ))
        .is_err());
    }

    #[tokio::test]
    #[ignore = "pinned Docker images required; run exact test in separate baseline and opt-in processes"]
    async fn eight_fixed_published_databases_keep_migration_heads() {
        assert_ne!(std::env::var(BASE_REUSE_SWITCH).as_deref(), Ok("1"));
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let expected = fixture["migration_revisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|revision| revision.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        for _ in 0..8 {
            let owned = PublishedDatabase::start().await.unwrap();
            assert_eq!(
                installed_revisions(owned.postgres.as_deref().unwrap()),
                expected
            );
            owned.close_verified().unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "opt-in pinned Docker image pilot; compare independent fresh and round-tripped schema/data dumps"]
    async fn fresh_probe_and_cached_restore_keep_roundtrip_schema_and_data() {
        assert_eq!(std::env::var(BASE_REUSE_SWITCH).as_deref(), Ok("1"));
        let restored = PublishedDatabase::start().await.unwrap();
        let captured_base = PUBLISHED_BASE
            .get()
            .expect("missing verified published base");
        let restored_dump =
            dump_published_base_with_restrict_key(restored.postgres.as_deref().unwrap(), true)
                .unwrap();
        restored.close_verified().unwrap();

        // A second pinned producer must have the same pre-restore SQL as the
        // captured base. Compare the complete bytes except the validated
        // per-invocation psql guard key; never print schema or table contents.
        let fresh = PublishedDatabase::start_probe(None).await.unwrap();
        let fresh_dump =
            dump_published_base_with_restrict_key(fresh.postgres.as_deref().unwrap(), true)
                .unwrap();
        fresh.close_verified().unwrap();
        assert!(
            comparable_dump(captured_base) == comparable_dump(&fresh_dump),
            "independent published migrations produced different schema/data"
        );

        // The only permitted fresh/restore differences are the pinned
        // PostgreSQL deparse forms. Every other byte must be unchanged.
        assert!(
            known_roundtrip_dump_parity(&fresh_dump, &restored_dump),
            "restored published base differs from pinned fresh schema/data"
        );
    }

    #[tokio::test]
    #[ignore = "opt-in pinned Docker image pilot; run alone with MARTY_CANVAS_REUSE_PUBLISHED_BASE_PILOT=1"]
    async fn immutable_published_base_keeps_revision_parity_and_case_isolation() {
        assert_eq!(std::env::var(BASE_REUSE_SWITCH).as_deref(), Ok("1"));
        let first = PublishedDatabase::start().await.unwrap();
        assert!(PUBLISHED_BASE.get().is_some());
        let second = PublishedDatabase::start().await.unwrap();
        let first_id = first.postgres.as_ref().unwrap().clone();
        let second_id = second.postgres.as_ref().unwrap().clone();
        assert_ne!(first_id, second_id);
        assert_ne!(first.scope, second.scope);

        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let expected = fixture["migration_revisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|revision| revision.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(installed_revisions(&first_id), expected);
        assert_eq!(installed_revisions(&second_id), expected);
        docker(&[
            "exec",
            &first_id,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "oracle",
            "-d",
            DATABASE,
            "-c",
            "CREATE TABLE public.marty_pilot_marker (id integer)",
        ])
        .unwrap();
        assert_eq!(marker_absence(&second_id), "t");
        first.close_verified().unwrap();
        second.close_verified().unwrap();
        let third = PublishedDatabase::start().await.unwrap();
        assert_eq!(marker_absence(third.postgres.as_deref().unwrap()), "t");
        third.close_verified().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "opt-in pinned Docker pilot; run this exact test alone with MARTY_CANVAS_REUSE_PUBLISHED_BASE_PILOT=1"]
    async fn concurrent_published_base_keeps_eight_cases_isolated() {
        assert_eq!(std::env::var(BASE_REUSE_SWITCH).as_deref(), Ok("1"));
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let expected = fixture["migration_revisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|revision| revision.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let mut all_ids = BTreeSet::new();
        let mut all_scopes = BTreeSet::new();

        for batch in 0..2 {
            let mut starts = tokio::task::JoinSet::new();
            for _ in 0..4 {
                starts.spawn(PublishedDatabase::start());
            }
            let deadline = Instant::now() + Duration::from_secs(180);
            let mut owned = Vec::with_capacity(4);
            while owned.len() < 4 {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let next = tokio::time::timeout(remaining, starts.join_next())
                    .await
                    .expect("four concurrent published databases exceeded 180 seconds")
                    .expect("missing published database task")
                    .expect("published database task panicked")
                    .expect("published database creation failed");
                owned.push(next);
            }
            assert!(PUBLISHED_BASE.get().is_some());
            assert!(starts.is_empty());
            for case in &owned {
                let id = case.postgres.as_deref().unwrap();
                assert!(all_ids.insert(id.to_owned()), "database container reused");
                assert!(
                    all_scopes.insert(case.scope.clone()),
                    "ownership scope reused"
                );
                assert_eq!(installed_revisions(id), expected);
                assert_eq!(
                    marker_absence(id),
                    "t",
                    "previous case leaked into fresh database"
                );
            }

            let marked = owned[batch].postgres.as_deref().unwrap();
            docker(&[
                "exec",
                marked,
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "oracle",
                "-d",
                DATABASE,
                "-c",
                "CREATE TABLE public.marty_pilot_marker (id integer)",
            ])
            .unwrap();
            for (index, case) in owned.iter().enumerate() {
                assert_eq!(
                    marker_absence(case.postgres.as_deref().unwrap()),
                    if index == batch { "f" } else { "t" },
                    "write crossed a live case boundary"
                );
            }

            for case in owned {
                let scope = Uuid::parse_str(&case.scope).unwrap();
                case.close_verified().unwrap();
                assert!(scope_ids(scope, &docker).unwrap().is_empty());
            }
        }
        assert_eq!(all_ids.len(), 8);
        assert_eq!(all_scopes.len(), 8);
    }

    #[tokio::test]
    #[ignore = "opt-in pinned Docker image pilot; run alone with MARTY_CANVAS_REUSE_PUBLISHED_BASE_PILOT=1"]
    async fn failed_published_base_restore_removes_only_its_owned_container() {
        assert_eq!(std::env::var(BASE_REUSE_SWITCH).as_deref(), Ok("1"));
        let scope = Uuid::new_v4();
        assert!(PublishedDatabase::start_from_published_base_with_scope(
            scope,
            b"THIS IS NOT SQL;\n",
        )
        .await
        .is_err());
        assert!(scope_ids(scope, &docker).unwrap().is_empty());
    }

    #[test]
    fn published_postgres_registry_fallback_keeps_the_frozen_digest() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let canonical = fixture["observed_postgres_image"].as_str().unwrap();
        let mirrored = format!("mirror.gcr.io/library/{canonical}");
        assert_eq!(selected_postgres_image(&fixture, None).unwrap(), canonical);
        assert_eq!(
            selected_postgres_image(&fixture, Some(canonical)).unwrap(),
            canonical
        );
        assert_eq!(
            selected_postgres_image(&fixture, Some(&mirrored)).unwrap(),
            mirrored
        );
        for untrusted in [
            "postgres:latest",
            "mirror.gcr.io/library/postgres:latest",
            "mirror.gcr.io/library/postgres@sha256:deadbeef",
        ] {
            assert!(selected_postgres_image(&fixture, Some(untrusted)).is_err());
        }
    }

    #[test]
    fn worker_matrix_timing_ids_are_bounded_and_contain_only_case_identity() {
        assert_eq!(
            worker_matrix_timing_name("worker-retry-after", "http_date_future").unwrap(),
            "retry-after.http_date_future"
        );
        for case in ["", "secret\nvalue", "quoted\"value", "path/value"] {
            assert!(worker_matrix_timing_name("worker-retry-after", case).is_err());
        }
        assert!(worker_matrix_timing_name("worker-retry-after", &"a".repeat(96)).is_err());
        assert!(worker_matrix_timing_name("retry-after", "http_date_future").is_err());
    }

    #[test]
    fn published_probe_timing_names_reveal_only_fixed_constructor_origins() {
        assert_eq!(
            published_probe_timing_name(Some("operations")),
            "operations"
        );
        assert_eq!(
            published_probe_timing_name(Some("worker_provider_signals")),
            "worker_provider_signals"
        );
        assert_eq!(published_probe_timing_name(None), "published_probe");
        assert_eq!(
            published_probe_timing_name(Some("credential://secret")),
            "published_probe"
        );
    }

    #[test]
    fn json_consumer_case_timing_accepts_exact_inventory_only() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-json-consumer-scenarios.json"
        ))
        .unwrap();
        let mut rows = Vec::new();
        for phase in ["validation", "provider"] {
            for case in fixture[phase].as_array().unwrap() {
                rows.push(json!({
                    "name": format!("json_consumer.{phase}.{}", case["name"].as_str().unwrap()),
                    "duration_ms": 1,
                }));
            }
        }
        assert_eq!(rows.len(), 132);
        let report = json!({"ci_case_timing": rows});
        assert_eq!(json_consumer_case_timings(&report).unwrap().len(), 132);
        for changed in [
            {
                let mut changed = report.clone();
                changed["ci_case_timing"][0]["name"] = json!("private-url");
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_case_timing"][0]["duration_ms"] = json!(-1);
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_case_timing"][0]["duration_ms"] = json!(120_001);
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_case_timing"][0]["payload"] = json!("secret");
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_case_timing"].as_array_mut().unwrap().pop();
                changed
            },
        ] {
            assert!(json_consumer_case_timings(&changed).is_err());
        }
    }

    #[test]
    fn json_depth_phase_timing_accepts_only_fixed_payload_free_rows() {
        let report = json!({"ci_phase_timing": [
            {"name": "json_depth.setup", "duration_ms": 1},
            {"name": "json_depth.validation", "duration_ms": 2},
            {"name": "json_depth.provider", "duration_ms": 3},
            {"name": "json_depth.encoding", "duration_ms": 4},
        ]});
        assert_eq!(
            json_depth_phase_timings(&report).unwrap(),
            [
                ("json_depth.setup", 1),
                ("json_depth.validation", 2),
                ("json_depth.provider", 3),
                ("json_depth.encoding", 4),
            ]
        );
        for changed in [
            {
                let mut changed = report.clone();
                changed["ci_phase_timing"][0]["name"] = json!("secret-url");
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_phase_timing"][0]["duration_ms"] = json!(-1);
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_phase_timing"][0]["duration_ms"] = json!(180_001);
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_phase_timing"][0]["payload"] = json!("secret");
                changed
            },
            {
                let mut changed = report.clone();
                changed["ci_phase_timing"].as_array_mut().unwrap().pop();
                changed
            },
        ] {
            assert!(json_depth_phase_timings(&changed).is_err());
        }
    }

    fn recovery_rows() -> (Uuid, Vec<(String, Value)>) {
        let (mut database, id, scope) = borrow_fixture();
        database["HostConfig"]["Privileged"] = json!(false);
        database["HostConfig"]["PortBindings"] =
            json!({"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":""}]});
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let root = super::repository_root();
        let probe_id = "b".repeat(64);
        let probe = json!({
            "Id":probe_id,
            "Config":{"Image":fixture["observed_image"],"Labels":{LABEL:scope},
                "Entrypoint":["python"],"Cmd":["/verification/scripts/prepare_canvas_published_schema.py"],
                "Env":["PYTHONDONTWRITEBYTECODE=1","TOKEN_HMAC_KEY=synthetic-schema-only-hmac-key"]},
            "HostConfig":{"NetworkMode":format!("container:{id}"),"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"]},
            "Mounts":[
                {"Type":"bind","RW":false,"Source":root.join("scripts/prepare_canvas_published_schema.py"),"Destination":"/verification/scripts/prepare_canvas_published_schema.py"},
                {"Type":"bind","RW":false,"Source":root.join("contracts/canvas-worker-consumer-range-oracle.json"),"Destination":"/verification/contracts/canvas-worker-consumer-range-oracle.json"}
            ]
        });
        (
            Uuid::parse_str(&scope).unwrap(),
            vec![(id, database), (probe_id, probe)],
        )
    }

    #[test]
    fn caller_scope_recovery_rejects_foreign_or_incomplete_ownership_before_removal() {
        let (scope, rows) = recovery_rows();
        assert_eq!(
            checked_recovery_rows(scope, &rows).unwrap(),
            [rows[1].0.clone(), rows[0].0.clone()]
        );
        let mut mutations = Vec::new();
        for (index, pointer, replacement) in [
            (
                0,
                "/Config/Labels/com.elevenid.test.canvas-published-schema",
                json!(Uuid::new_v4().to_string()),
            ),
            (0, "/Config/Image", json!("unowned:latest")),
            (0, "/Mounts", json!([{"Type":"bind","Source":"/operator"}])),
            (
                0,
                "/HostConfig/PortBindings/5432~1tcp/0/HostIp",
                json!("0.0.0.0"),
            ),
            (1, "/HostConfig/NetworkMode", json!("host")),
            (1, "/HostConfig/SecurityOpt", json!([])),
            (1, "/Config/Env", json!(["TOKEN_HMAC_KEY=changed"])),
            (1, "/Mounts/0/RW", json!(true)),
            (1, "/Mounts/0/Source", json!("/operator")),
            (1, "/Config/Entrypoint", json!(["sh"])),
        ] {
            let mut changed = rows.clone();
            *changed[index].1.pointer_mut(pointer).unwrap() = replacement;
            mutations.push(changed);
        }
        mutations.push(vec![rows[0].clone(), rows[0].clone()]);
        mutations.push(vec![rows[1].clone()]);
        mutations.push(vec![rows[0].clone(), rows[1].clone(), rows[0].clone()]);
        for changed in mutations {
            let writes = std::cell::RefCell::new(Vec::new());
            let invoke = |args: &[&str]| -> Result<String, String> {
                match args[0] {
                    "ps" => Ok(changed
                        .iter()
                        .map(|v| v.0.clone())
                        .collect::<Vec<_>>()
                        .join("\n")),
                    "inspect" => Ok(changed
                        .iter()
                        .find(|v| v.0 == args[3])
                        .unwrap()
                        .1
                        .to_string()),
                    _ => {
                        writes.borrow_mut().push(args[0].to_owned());
                        Err("Unexpected write".into())
                    }
                }
            };
            assert!(PublishedDatabase::recover_scope(scope, &invoke).is_err());
            assert!(writes.borrow().is_empty());
        }
        assert!(scope_ids(Uuid::nil(), &|_| panic!(
            "invalid UUID must not invoke Docker"
        ))
        .is_err());
    }

    #[tokio::test]
    async fn caller_scope_constructor_rejects_invalid_uuid_before_docker() {
        assert!(PublishedDatabase::start_with_scope(Uuid::nil())
            .await
            .is_err());
    }

    fn borrow_fixture() -> (Value, String, String) {
        let id = "a".repeat(64);
        let scope = "12345678-1234-4234-8234-123456789abc".to_owned();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let postgres_image = ci_postgres_image(&fixture).unwrap();
        let info = json!({
            "Id": id,
            "Config": { "Labels": { LABEL: scope }, "Image": postgres_image,
                "Env": ["POSTGRES_USER=oracle", "POSTGRES_PASSWORD=synthetic-local-only", "POSTGRES_DB=canvas_published_schema_test"] },
            "Mounts": [],
            "HostConfig": {"Tmpfs": {"/var/lib/postgresql/data": "rw", "/var/run/postgresql": "rw"}},
            "State": {"Running": true},
            "NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25432"}]}}
        });
        (info, id, scope)
    }

    #[test]
    fn borrowed_database_descriptor_is_closed_and_never_accepts_connection_strings() {
        let (_, id, scope) = borrow_fixture();
        let valid = json!({"postgres_id": id, "scope": scope});
        assert_eq!(
            checked_borrow_descriptor(&valid.to_string()).unwrap(),
            (id, scope)
        );
        for rejected in [
            json!("postgresql://private-sentinel@deployment.invalid/live"),
            json!({"postgres_id": "--all", "scope": valid["scope"]}),
            json!({"postgres_id": valid["postgres_id"], "scope": "private-sentinel"}),
            json!({"postgres_id": valid["postgres_id"], "scope": "00000000-0000-0000-0000-000000000000"}),
            json!({"postgres_id": valid["postgres_id"], "scope": valid["scope"], "url": "private-sentinel"}),
            json!({"scope": valid["scope"]}),
            json!([]),
            json!(null),
        ] {
            let error = checked_borrow_descriptor(&rejected.to_string()).unwrap_err();
            assert!(!error.contains("private-sentinel"));
        }
        assert!(checked_borrow_descriptor(&"x".repeat(257)).is_err());
        let duplicate = format!(
            "{{\"postgres_id\":{},\"scope\":{},\"scope\":{}}}",
            valid["postgres_id"], valid["scope"], valid["scope"]
        );
        assert!(checked_borrow_descriptor(&duplicate).is_err());
        let non_rfc = json!({"postgres_id": valid["postgres_id"], "scope": "12345678-1234-4234-1234-123456789abc"});
        assert!(checked_borrow_descriptor(&non_rfc.to_string()).is_err());
    }

    #[test]
    fn borrowed_database_requires_exact_identity_storage_image_and_loopback_configuration() {
        let (valid, id, scope) = borrow_fixture();
        assert_eq!(
            checked_borrowed_url(&valid, &id, &scope).unwrap(),
            "postgresql://oracle:synthetic-local-only@127.0.0.1:25432/canvas_published_schema_test"
        );
        for (pointer, value) in [
            ("/Id", json!("b".repeat(64))),
            ("/Config/Image", json!("wrong-image")),
            ("/Config/Env", json!(["POSTGRES_USER=private-sentinel"])),
            ("/State/Running", json!(false)),
            ("/Mounts", json!([{"Source": "private-sentinel"}])),
            ("/HostConfig/Tmpfs", json!({})),
            (
                "/NetworkSettings/Ports/5432~1tcp/0/HostIp",
                json!("0.0.0.0"),
            ),
            ("/NetworkSettings/Ports/5432~1tcp/0/HostPort", json!("0")),
            (
                "/NetworkSettings/Ports/5432~1tcp/0/HostPort",
                json!("65536"),
            ),
            (
                "/NetworkSettings/Ports/5432~1tcp/0/HostPort",
                json!("private-sentinel"),
            ),
            ("/NetworkSettings/Ports/5432~1tcp", json!([])),
        ] {
            let mut info = valid.clone();
            *info.pointer_mut(pointer).unwrap() = value;
            let error = checked_borrowed_url(&info, &id, &scope).unwrap_err();
            assert!(!error.contains("private-sentinel"));
        }
        let mut wrong_scope = valid.clone();
        wrong_scope["Config"]["Labels"][LABEL] = json!("wrong-scope");
        assert!(checked_borrowed_url(&wrong_scope, &id, &scope).is_err());
        let mut extra_tmpfs = valid.clone();
        extra_tmpfs["HostConfig"]["Tmpfs"]["/unexpected"] = json!("rw");
        assert!(checked_borrowed_url(&extra_tmpfs, &id, &scope).is_err());
        let mut duplicate = valid.clone();
        duplicate["Config"]["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("POSTGRES_USER=oracle"));
        assert!(checked_borrowed_url(&duplicate, &id, &scope).is_err());
        let mut extra = valid.clone();
        extra["NetworkSettings"]["Ports"]["1234/tcp"] = json!([]);
        assert!(checked_borrowed_url(&extra, &id, &scope).is_err());
        let mut doubled = valid.clone();
        let binding = doubled["NetworkSettings"]["Ports"]["5432/tcp"][0].clone();
        doubled["NetworkSettings"]["Ports"]["5432/tcp"]
            .as_array_mut()
            .unwrap()
            .push(binding);
        assert!(checked_borrowed_url(&doubled, &id, &scope).is_err());
    }

    #[test]
    fn timing_diagnostic_forwarding_accepts_only_closed_bounded_numeric_fields() {
        let valid = json!({
            "error_class": "DeadlineClockDisagreement",
            "timing_diagnostics": {
                "database_elapsed_seconds": 30.1,
                "monotonic_lower_seconds": 29.4,
                "monotonic_upper_seconds": 30.5,
            },
        });
        assert_eq!(
            safe_timing_diagnostics(&valid),
            valid.get("timing_diagnostics")
        );
        for rejected in [
            json!(true),
            json!("synthetic-secret"),
            Value::Null,
            json!([]),
            json!({"payload": "synthetic-secret"}),
            json!(300.001),
            json!(-300.001),
        ] {
            let mut report = valid.clone();
            report["timing_diagnostics"]["database_elapsed_seconds"] = rejected;
            assert!(safe_timing_diagnostics(&report).is_none());
        }
        for boundary in [-300.0, 300.0] {
            let mut report = valid.clone();
            report["timing_diagnostics"]["database_elapsed_seconds"] = json!(boundary);
            assert!(safe_timing_diagnostics(&report).is_some());
        }
        let mut extra = valid.clone();
        extra["timing_diagnostics"]["unexpected"] = json!("synthetic-secret");
        assert!(safe_timing_diagnostics(&extra).is_none());
        let mut missing = valid.clone();
        missing["timing_diagnostics"]
            .as_object_mut()
            .unwrap()
            .remove("monotonic_lower_seconds");
        assert!(safe_timing_diagnostics(&missing).is_none());
        let mut wrong_class = valid;
        wrong_class["error_class"] = json!("UnrelatedError");
        assert!(safe_timing_diagnostics(&wrong_class).is_none());
    }

    #[test]
    fn lease_observation_forwarding_accepts_only_closed_boolean_flags() {
        let valid = json!({
            "error_class": "LeaseObservationChanged",
            "lease_observation_diagnostics": {
                "jobs": true, "facts": false, "oauth": false,
                "snapshot": false, "heartbeat": false, "target": false,
                "shape": false,
            },
        });
        assert_eq!(
            safe_lease_observation_diagnostics(&valid),
            valid.get("lease_observation_diagnostics")
        );
        for rejected in [json!("synthetic-secret"), json!(1), Value::Null, json!({})] {
            let mut report = valid.clone();
            report["lease_observation_diagnostics"]["jobs"] = rejected;
            assert!(safe_lease_observation_diagnostics(&report).is_none());
        }
        let mut extra = valid.clone();
        extra["lease_observation_diagnostics"]["unexpected"] = json!("synthetic-secret");
        assert!(safe_lease_observation_diagnostics(&extra).is_none());
        let mut missing = valid.clone();
        missing["lease_observation_diagnostics"]
            .as_object_mut()
            .unwrap()
            .remove("heartbeat");
        assert!(safe_lease_observation_diagnostics(&missing).is_none());
        let mut wrong_class = valid;
        wrong_class["error_class"] = json!("UnrelatedError");
        assert!(safe_lease_observation_diagnostics(&wrong_class).is_none());
    }
}
