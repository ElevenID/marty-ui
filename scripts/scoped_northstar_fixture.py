"""D11 single-role adapter over the reviewed metadata replacement/recovery core.

No CLI, transport, lock acquisition, authority mint or Docker call on import.
The reviewed caller supplies fresh hash-bound core/transport, full22 identities,
created-container verifier and existing external-component/public verifier.
"""
from copy import deepcopy
from pathlib import Path

ROLE = "northstar-admissions"
SOURCE = "27a273d8a9f82778a2b19f9981f56d073b2793f6"
IMAGE = "sha256:366911734ad16cac52553148dd10c1f59bc2e90613ef7fc5c97485a701f0ff2e"
TARGET = "/run/secrets/northstar_run"


def require(value, code):
    if not value:
        raise ValueError(code)


def model_delta(before, after, fixture):
    require(before.get("name") == after.get("name") == "elevenid-beta", "PROJECT_CHANGED")
    require(set(before.get("services", {})) == {ROLE}, "ONE_ROLE_REQUIRED")
    service = before["services"][ROLE]
    require(service.get("image") == IMAGE and service.get("read_only") is True
            and service.get("pull_policy") == "never", "IMAGE_OR_RO_POLICY_CHANGED")
    require(set(before.get("secrets", {})) == {"northstar_run"}
            and set(before["secrets"]["northstar_run"]) == {"file"}, "ONE_FILE_SECRET_REQUIRED")
    require(not any(key in service for key in ("build", "volumes", "ports", "privileged")),
            "UNREVIEWED_SERVICE_AUTHORITY")
    secret = service.get("secrets")
    require(isinstance(secret, list) and len(secret) == 1
            and secret[0]["source"] == secret[0]["target"] == "northstar_run",
            "SECRET_TARGET_CHANGED")
    expected = deepcopy(before)
    expected["secrets"]["northstar_run"]["file"] = str(fixture)
    require(after == expected, "DELTA_OUTSIDE_ONE_FIXTURE_SOURCE")


def execution_type(core):
    require(core.Operation.execute.__globals__ is vars(core), "FRESH_CORE_GLOBALS_REQUIRED")
    require(core.ROLES == ("ui-prod", "gateway"), "UNREVIEWED_CORE_SCOPE")
    require(all(hasattr(core.Operation, name) for name in
                ("cached_image_matches", "stop_arguments", "stop_exit_codes")), "SHARED_HOOKS_REQUIRED")
    core.ROLES = (ROLE,)

    class NorthstarFixture(core.Operation):
        def __init__(self, config, output, *, transport, identities,
                     representations, observe_external):
            require(config["scope"] == "FUNCTIONAL_ONLY" and config["sourceRevision"] == SOURCE,
                    "SOURCE_OR_FUNCTIONAL_SCOPE_CHANGED")
            require(set(config["oldCids"]) == {ROLE}, "ONE_KNOWN_ROLE_REQUIRED")
            require(len(identities) == 22 and ROLE not in identities, "PRODUCT22_REQUIRED")
            require(callable(representations.host_mounts) and callable(representations.daemon_source)
                    and callable(observe_external), "REVIEWED_VERIFIERS_REQUIRED")
            self.c, self.output, self.g = config, Path(output), transport
            self.models = {ROLE: core.load(config["oldModels"][ROLE])}
            self.changed = {ROLE: core.load(config["newModels"][ROLE])}
            model_delta(self.models[ROLE], self.changed[ROLE], core.read_ref(config["newFixture"]))
            self.identities = identities
            self.marker = None
            self.observe_external = observe_external
            self.recovery_started_cids = set()
            def verify(row, model, *, running):
                mode = "rollback" if model == self.models[ROLE] else "apply"
                require(model in (self.models[ROLE], self.changed[ROLE]), "MODEL_NOT_BOUND")
                candidate_guard(core.load(config["originalContainer"]), row,
                    fixture=model["secrets"]["northstar_run"]["file"],
                    provenance=config["provenance"][mode], running=running,
                    allow_known_exited=row["Id"] in self.recovery_started_cids,
                    allow_original_restart=(config.get("rollbackAuthorized") is True
                        and "rollback-start-original-" + ROLE in self.state["operations"]),
                    host_mounts=representations.host_mounts, daemon_source=representations.daemon_source)
            self.verify_container = verify
            self.g.candidate_guard = lambda role, row, model, *, running: (require(role == ROLE, "ONE_ROLE_REQUIRED"), self.verify_container(row, model, running=running))
            require(config["publicManifest"] == config["newFixture"]
                    and config["oldPublicManifest"] == config["oldFixture"], "EXTERNAL_FIXTURE_AUTHORITY_CHANGED")
            self.state = dict(schema="marty.d11-known-role-rebind/v1",runId=config["runId"],
                              sourceSha256=config["sourceSha256"],oldCids=config["oldCids"],
                              newCids={},operations=[],terminals={},pending=None,
                              releaseQualified=False,recordingQualified=False)

        def stop_arguments(self, role, cid, signal):
            require(role == ROLE and signal == "SIGTERM", "STOP_ROLE_CHANGED")
            return ["stop", "--signal", "SIGTERM", "--timeout", "-1", cid]

        def stop_exit_codes(self, role):
            require(role == ROLE, "STOP_ROLE_CHANGED")
            return (143,)  # Source27a Node entrypoint has no TERM handler; preserve actual receipt.

        def cached_image_matches(self, reference, row):
            return reference == IMAGE and row.get("Id") == IMAGE and row.get("Config", {}).get(
                "Labels", {}).get("org.opencontainers.image.revision") == SOURCE

        def guarded(self, role, cid, model, running):
            require(role == ROLE, "ONE_ROLE_REQUIRED")
            row = self.g.inspect(cid)
            self.verify_container(row, model, running=running)
            return row

        def healthy(self, role, cid, model):
            # Existing shared health loop invokes g.candidate_guard; caller binds
            # that same reviewed verifier, never the Rust-only phase2 default.
            return super().healthy(role, cid, model)

        def baseline(self):
            self.g.engine()
            self.retained_twenty()  # Existing shared method validates all22; none is this external role.
            ids = set(self.g.observe_lines(["ps", "-aq", "--no-trunc"], "all-before"))
            image = self.g.observe(["image", "inspect", IMAGE], "northstar-image")[0]
            require(self.cached_image_matches(IMAGE, image), "NORTHSTAR_IMAGE_SOURCE_CHANGED")
            self.g.IMAGE_IDS[IMAGE], self.g.IMAGE_CONFIG[IMAGE] = IMAGE, image["Config"]
            for network in self.models[ROLE]["networks"].values():
                row = self.g.observe(["network", "inspect", network["name"]], "northstar-network")[0]
                self.g.NETWORK_IDS[network["name"]] = row["Id"]
            original = core.load(self.c["originalContainer"])
            row = self.g.old_guard(original, running=True)
            self.guarded(ROLE, row["Id"], self.models[ROLE], True)
            require(row["State"]["Pid"] == original["State"]["Pid"]
                    and row["State"].get("Health", {}).get("Status") == "healthy", "OLD_GENERATION_OR_HEALTH_CHANGED")
            return ids, {ROLE: row}

        def public(self, marker, fixture_ref):
            # Retains actual external image/source/file/fixture checks; no imported outcome is sufficient.
            return self.observe_external(core.read_ref(fixture_ref))

        def preflight(self):
            require(self.c.get("preflightAuthorized") is True, "PREFLIGHT_NOT_ARMED")
            ids, before = self.baseline()
            proof = self.public(None, self.c["oldFixture"])
            return dict(state="D11_REBIND_PREFLIGHT_PASSED",allIds=sorted(ids),
                        before={ROLE:self.save("northstar-before.json", before[ROLE])},oldExternal=proof)

        def execute(self, preflight):
            require(self.c.get("executeAuthorized") is True, "EXECUTION_NOT_ARMED")
            result = super().execute(preflight)
            result["state"] = "D11_NORTHSTAR_FIXTURE_REBOUND_NOT_FEATURE_QUALIFIED"
            return result

        def original_public(self):
            return self.public(None, self.c["oldFixture"])

        def recover(self, failed):
            require(self.c.get("rollbackAuthorized") is True, "ROLLBACK_NOT_ARMED")
            require(core.load(self.c["recoveryState"]) == failed
                    and failed["sourceSha256"] == self.c["sourceSha256"]
                    and failed["runId"] == self.c["runId"]
                    and failed["oldCids"] == self.c["oldCids"], "RECOVERY_AUTHORITY_CHANGED")
            require(set(failed["newCids"]) <= {ROLE}, "RECOVERY_ROLE_CHANGED")
            start = "apply-start-" + ROLE
            self.recovery_started_cids = ({failed["newCids"][ROLE]}
                if ROLE in failed["newCids"] and (start in failed["operations"] or failed.get("pending") == start)
                else set())
            result = super().recover(failed)
            result["state"] = "D11_NORTHSTAR_ORIGINAL_CONFIGURATION_RESTORED"
            return result

    return NorthstarFixture


def candidate_guard(original, actual, *, fixture, provenance, running, host_mounts, daemon_source, allow_original_restart=False, allow_known_exited=False):
    """Exact one-RO-secret successor using shared host-mount representation readers."""
    require(actual["Image"] == original["Image"] == IMAGE and actual["Name"] == original["Name"], "ROLE_OR_IMAGE_CHANGED")
    require(actual["State"]["Running"] is running and not actual["State"]["OOMKilled"], "RUNNING_OR_OOM_CHANGED")
    require(actual["Path"] == original["Path"] and actual["Args"] == original["Args"], "PROCESS_CHANGED")
    require(set(provenance) >= {"com.docker.compose.config-hash", "com.docker.compose.project.config_files",
                               "com.docker.compose.project.working_dir", "com.docker.compose.version"}, "COMPLETE_COMPOSE_PROVENANCE_REQUIRED")
    a, b = deepcopy(original["Config"]), deepcopy(actual["Config"])
    same = actual["Id"] == original["Id"]
    if not same and a.get("Hostname") == original["Id"][:12]:
        require(b.get("Hostname") == actual["Id"][:12], "DERIVED_HOSTNAME_CHANGED")
        b["Hostname"] = a["Hostname"]
    if not same:
        for key, value in provenance.items():
            require(key in ("com.docker.compose.config-hash", "com.docker.compose.project.config_files",
                            "com.docker.compose.project.working_dir", "com.docker.compose.version",
                            "com.docker.compose.project.environment_file", "com.docker.compose.depends_on"), "PROVENANCE_FIELD_UNKNOWN")
            require(b["Labels"].get(key) == value, "COMPOSE_PROVENANCE_CHANGED")
            if key in a["Labels"]:
                b["Labels"][key] = a["Labels"][key]
            else:
                b["Labels"].pop(key, None)
    require(a == b, "CONFIG_CHANGED")
    ah, bh = deepcopy(original["HostConfig"]), deepcopy(actual["HostConfig"])
    for field in ("Binds", "Mounts"):
        ah.pop(field, None);bh.pop(field, None)
    require(ah == bh, "HOST_CONFIG_CHANGED")
    for row in (original, actual):
        require(len(row["Mounts"]) == 1 and row["Mounts"][0]["Destination"] == TARGET
                and row["Mounts"][0]["Type"] == "bind" and row["Mounts"][0]["RW"] is False, "ONE_RO_FIXTURE_REQUIRED")
    old_mount, new_mount = deepcopy(original["Mounts"][0]), deepcopy(actual["Mounts"][0])
    require(daemon_source(new_mount["Source"]) == daemon_source(str(fixture)), "FIXTURE_SOURCE_CHANGED")
    old_mount.pop("Source");new_mount.pop("Source")
    require(old_mount == new_mount, "MOUNT_OPTIONS_CHANGED")
    old_binds, old_api = host_mounts(original)
    new_binds, new_api = host_mounts(actual)
    if TARGET in old_binds:
        old_binds[TARGET] = (old_binds[TARGET][0], daemon_source(str(fixture)), old_binds[TARGET][2])
    if TARGET in old_api:
        old_api[TARGET]["Source"] = daemon_source(str(fixture))
    require(old_binds == new_binds and old_api == new_api, "HOST_MOUNT_REPRESENTATION_CHANGED")
    old_networks, networks = original["NetworkSettings"]["Networks"], actual["NetworkSettings"]["Networks"]
    require(set(old_networks) == set(networks), "NETWORK_SET_CHANGED")
    assigned = {"NetworkID", "EndpointID", "Gateway", "IPAddress", "IPPrefixLen", "IPv6Gateway",
                "GlobalIPv6Address", "GlobalIPv6PrefixLen", "MacAddress", "DNSNames"}
    for name, previous in old_networks.items():
        current = networks[name]
        require(current["NetworkID"] in ((previous["NetworkID"],) if running else ("", previous["NetworkID"])), "NETWORK_ID_CHANGED")
        require({k:v for k,v in previous.items() if k not in assigned} ==
                {k:v for k,v in current.items() if k not in assigned}, "NETWORK_STATIC_OPTIONS_CHANGED")
    if same:
        require(actual["State"]["StartedAt"] == original["State"]["StartedAt"]
                or (allow_original_restart and running
                    and actual["State"]["StartedAt"] > original["State"]["StartedAt"]), "ORIGINAL_GENERATION_CHANGED")
    elif not running:
        state = actual["State"]
        prestart = state["Status"] == "created" and state["Pid"] == 0 and state["StartedAt"].startswith("0001-")
        known_exited = (allow_known_exited and state["Status"] == "exited" and state["Pid"] == 0
            and state.get("Restarting") is False and not state["StartedAt"].startswith("0001-")
            and state["FinishedAt"] >= state["StartedAt"])
        require(prestart or known_exited, "CANDIDATE_NOT_PRESTART_OR_AUTHORIZED_EXITED")
