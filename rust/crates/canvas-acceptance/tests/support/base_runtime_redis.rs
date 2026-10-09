include!("../../../../services/issuance/tests/support/base_runtime_redis.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ping_cleanup_failure_is_terminal_not_readiness_retry() {
        assert_eq!(super::ping_ready(Ok("PONG".into())), Ok(true));
        assert_eq!(super::ping_ready(Ok("LOADING".into())), Ok(false));
        assert_eq!(
            super::ping_ready(Err("Docker exec failed".into())),
            Ok(false)
        );
        assert_eq!(
            super::ping_ready(Err("Docker command cleanup failed".into())),
            Err("Docker command cleanup failed".into())
        );
    }

    fn fixture() -> (Value, String, String, String) {
        let id = "a".repeat(64);
        let scope = "12345678-1234-4234-8234-123456789abc".to_owned();
        let image = format!("sha256:{}", "b".repeat(64));
        let info = json!({
            "Id":id,"Image":image,"Config":{"Image":image,"Labels":{LABEL:scope},
              "User":"redis","Entrypoint":["redis-server"],"Cmd":COMMAND},
            "Mounts":[],"HostConfig":{"Tmpfs":{"/data":TMPFS},"ReadonlyRootfs":true,
              "CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"NetworkMode":"bridge"},
            "State":{"Running":true},
            "NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"127.0.0.1","HostPort":"26379"}]}}
        });
        (info, id, scope, image)
    }

    #[test]
    fn redis_fixture_requires_exact_owner_storage_and_loopback_without_database_override() {
        let (info, id, scope, image) = fixture();
        assert_eq!(
            checked_url(&info, &id, &scope, &image, &Network::Loopback).unwrap(),
            "redis://127.0.0.1:26379"
        );
        for (pointer, value) in [
            ("/Id", json!("c".repeat(64))),
            (
                "/Config/Labels/com.elevenid.test.base-native-redis",
                json!("foreign"),
            ),
            ("/Image", json!("sha256:invalid")),
            ("/Config/Image", json!(IMAGE)),
            ("/Config/User", json!("root")),
            ("/Config/Entrypoint", json!(["sh"])),
            ("/Config/Cmd", json!(["--appendonly", "yes"])),
            ("/Mounts", json!([{"Type":"bind","Source":"synthetic"}])),
            ("/HostConfig/Tmpfs", json!({})),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/CapDrop", json!([])),
            ("/HostConfig/SecurityOpt", json!([])),
            ("/State/Running", json!(false)),
            (
                "/NetworkSettings/Ports/6379~1tcp/0/HostIp",
                json!("0.0.0.0"),
            ),
            ("/NetworkSettings/Ports/6379~1tcp/0/HostPort", json!("0")),
            ("/NetworkSettings/Ports/6379~1tcp", json!([])),
            (
                "/NetworkSettings/Ports",
                json!({"6379/tcp":[],"6380/tcp":[]}),
            ),
        ] {
            let mut changed = info.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                checked_url(&changed, &id, &scope, &image, &Network::Loopback).is_err(),
                "{pointer}"
            );
        }
        for invalid in ["", "abc", &"g".repeat(64)] {
            assert!(exact_id(invalid).is_err());
            assert!(image_identity(invalid).is_err());
        }
    }

    #[test]
    fn namespace_redis_rejects_other_networks_and_every_host_publication() {
        let (mut info, id, scope, image) = fixture();
        let postgres = "c".repeat(64);
        let network = Network::PublishedNamespace {
            descriptor: String::new(),
            id: postgres.clone(),
        };
        info["HostConfig"]["NetworkMode"] = json!(format!("container:{postgres}"));
        info["HostConfig"]["PortBindings"] = json!({});
        info["NetworkSettings"]["Ports"] = json!({});
        assert_eq!(
            checked_url(&info, &id, &scope, &image, &network).unwrap(),
            "redis://127.0.0.1:6379"
        );
        for (pointer, value) in [
            ("/HostConfig/NetworkMode", json!("bridge")),
            (
                "/HostConfig/NetworkMode",
                json!(format!("container:{}", "d".repeat(64))),
            ),
            (
                "/HostConfig/PortBindings",
                json!({"6379/tcp":[{"HostIp":"127.0.0.1","HostPort":"26379"}]}),
            ),
            ("/NetworkSettings/Ports", json!({"6379/tcp":[]})),
        ] {
            let mut changed = info.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                checked_url(&changed, &id, &scope, &image, &network).is_err(),
                "{pointer}"
            );
        }
    }
}
