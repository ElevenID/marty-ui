#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use serde_json::json;

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
        let info = json!({
            "Id": id,
            "Config": { "Labels": { LABEL: scope }, "Image": fixture["observed_postgres_image"],
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
}
