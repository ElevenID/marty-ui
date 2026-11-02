"""D11 single-role adapter over the reviewed metadata replacement/recovery core.

No CLI, transport, lock acquisition, authority mint or Docker call on import.
The reviewed stopped137 baseline remains OFF; only a separate literal startup
flag permits starting the repaired asset. Recovery never starts the legacy model.
The reviewed caller supplies fresh hash-bound core/transport, full22 identities,
created-container verifier and existing external-component/public verifier.
"""
from copy import deepcopy
from pathlib import Path
import re

ROLE = "northstar-admissions"
SOURCE = "27a273d8a9f82778a2b19f9981f56d073b2793f6"
IMAGE = "sha256:366911734ad16cac52553148dd10c1f59bc2e90613ef7fc5c97485a701f0ff2e"
TARGET = "/run/secrets/northstar_run"
SERVER_TARGET = "/app/src/server.mjs"
CODE_SOURCE = "ad286f6122abdc88e79b1d0f02669206dcafea14"
SERVER_SHA256 = "50bf1bc507bd772f8711e95a21100c993722c33dab7d05bc29fd6363274ec754"


def asset_contract(config, core):
    """Authorized immutable refs carry evidence; code fixes the reviewed asset policy."""
    asset = config["codeOverlay"]
    require(set(asset) == {"sourceRevision", "server", "signalProof"}
            and asset["sourceRevision"] == CODE_SOURCE
            and asset["server"]["sha256"] == SERVER_SHA256, "REPAIRED_SOURCE_CHANGED")
    server = core.read_ref(asset["server"])
    require(server.name == "server.mjs" and not server.is_symlink(), "SERVER_FILE_CHANGED")
    proof = asset["signalProof"]
    require(set(proof) == {"input", "intent", "result", "terminals"}, "SIGNAL_PROOF_REFS_CHANGED")
    supplied, intent, result = (core.load(proof[k]) for k in ("input", "intent", "result"))
    cases = [{"signal": "SIGTERM", "init": False}, {"signal": "SIGINT", "init": True}]
    require(supplied["scope"] == "LOCAL_SOURCE_CONTROLS_ONLY" and supplied["image"] == IMAGE
            and supplied["server"]["sha256"] == SERVER_SHA256 and supplied["cases"] == cases
            and supplied["executeAuthorized"] is True
            and intent["inputSha256"] == proof["input"]["sha256"]
            and intent["sourceSha256"] == supplied["sourceSha256"], "SIGNAL_PROOF_SOURCE_CHANGED")
    require(result["state"] == "ISOLATED_SHUTDOWN_SOURCE_CONTROLS_PASS"
            and result["allIdsUnchanged"] is True and result["betaOrProdStarted"] is False
            and result["imageBuilt"] is False and result["demoQualified"] is False
            and len(result["results"]) == 2
            and len({r["cid"] for r in result["results"]}) == 2, "SIGNAL_PROOF_NOT_COMPLETE")
    require(isinstance(proof["terminals"], list) and len(proof["terminals"]) == 2,
            "SIGNAL_TERMINALS_REQUIRED")
    for expected, observed, terminal_ref in zip(cases, result["results"], proof["terminals"]):
        require(observed["signal"] == expected["signal"] and observed["init"] is expected["init"]
                and observed["exit"] == 0 and observed["serverCloseCompletion"] is True
                and observed["removed"] is True and re.fullmatch(r"[a-f0-9]{64}", observed["cid"]),
                "SIGNAL_PROOF_CASE_CHANGED")
        terminal = core.load(terminal_ref)
        state = terminal["State"]
        require(terminal["Id"] == observed["cid"] and terminal["Image"] == IMAGE
                and state["Running"] is False and state["Pid"] == 0
                and state["OOMKilled"] is False and state["ExitCode"] == 0
                and state["Restarting"] is False, "SIGNAL_TERMINAL_NOT_CLEAN")
    return server


def recovered_off_authority(config, core, representations, depth):
    proof = config["recoveredOffAuthority"]
    require(set(proof) == {"input", "invocation", "result", "dispatcher"}
            and representations is not None and depth < 8, "RECOVERED_OFF_REFS_CHANGED")
    previous, invocation, result = (core.load(proof[k]) for k in ("input", "invocation", "result"))
    require(invocation["mode"] == "rollback"
            and core.load(invocation["input"]) == previous
            and invocation["input"]["sha256"] == proof["input"]["sha256"]
            and invocation["sourceSha256"] == previous["sourceSha256"] == proof["dispatcher"]["sha256"]
            and previous["rollbackAuthorized"] is True and previous["executeAuthorized"] is False,
            "RECOVERED_OFF_INVOCATION_CHANGED")
    core.read_ref(proof["dispatcher"])
    original = stopped_authority(previous, core, representations, depth + 1)
    failed = core.load(previous["recoveryState"])
    require(result["state"] == "D11_NORTHSTAR_ORIGINAL_CONFIGURATION_RESTORED_OFF"
            and core.load(result["originalFailure"]) == failed
            and failed["sourceSha256"] == previous["sourceSha256"]
            and failed["runId"] == previous["runId"] and failed["oldCids"] == previous["oldCids"]
            and set(failed["newCids"]) == {ROLE}, "RECOVERED_OFF_RESULT_CHANGED")
    recovered = core.load(result["recovered"])
    require(set(recovered) == {ROLE}, "RECOVERED_OFF_ROLE_CHANGED")
    row = core.load(config["originalContainer"])
    require(row == recovered[ROLE] and config["oldCids"] == {ROLE: row["Id"]}
            and row["Id"] not in (original["Id"], failed["newCids"][ROLE])
            and config["shutdown"] == previous["shutdown"]
            and core.load(config["oldModels"][ROLE]) == core.load(previous["oldModels"][ROLE])
            and config["oldFixture"] == previous["oldFixture"], "RECOVERED_OFF_PREIMAGE_CHANGED")
    fixture = Path(core.load(previous["oldModels"][ROLE])["secrets"]["northstar_run"]["file"])
    require(fixture.read_bytes() == core.read_ref(previous["oldFixture"]).read_bytes(),
            "RECOVERED_OFF_FIXTURE_BYTES_CHANGED")
    candidate_guard(original, row, fixture=fixture,
        provenance=previous["provenance"]["rollback"], running=False,
        host_mounts=representations.host_mounts, daemon_source=representations.daemon_source,
        replaced_cid=failed["newCids"][ROLE])
    state = row["State"]
    require(state["Status"] == "created" and state["Running"] is False and state["Pid"] == 0
            and state["Restarting"] is False and state["OOMKilled"] is False
            and state["ExitCode"] == 0 and state["StartedAt"].startswith("0001-")
            and result["served"] == {"state": "ORIGINAL_CONFIGURATION_OFF", "cid": row["Id"],
                "pid": 0, "actualExitCode": 0}, "RECOVERED_OFF_NOT_NEVER_STARTED")
    require(core.load(config["globalCohortPreimage"]) == result["allIds"]
            and len(result["allIds"]) == len(set(result["allIds"]))
            and row["Id"] in result["allIds"], "RECOVERED_OFF_COHORT_CHANGED")
    return row


def stopped_authority(config, core, representations=None, depth=0):
    if "recoveredOffAuthority" in config:
        return recovered_off_authority(config, core, representations, depth)
    proof = config["shutdown"]
    require(set(proof) == {"result", "after"}, "SHUTDOWN_REFS_CHANGED")
    result, after = core.load(proof["result"]), core.load(proof["after"])
    original = core.load(config["originalContainer"])
    cid = config["oldCids"][ROLE]
    require(result["state"] == "BETA_AND_SELFHOST_PRODUCTION_STOPPED"
            and result["restartAutomatically"] is False
            and result["forcedStatelessNodeContainer"] == cid
            and original == after[cid] and original["Id"] == cid
            and original["Image"] == IMAGE
            and original["Config"]["Labels"]["org.opencontainers.image.revision"] == SOURCE,
            "STOPPED_ORIGINAL_AUTHORITY_CHANGED")
    state = original["State"]
    require(state["Status"] == "exited" and state["Running"] is False and state["Pid"] == 0
            and state["Restarting"] is False and state["OOMKilled"] is False
            and state["ExitCode"] == 137, "ORIGINAL_OFF137_REQUIRED")
    return original


def require(value, code):
    if not value:
        raise ValueError(code)


def model_delta(before, after, fixture, server):
    require(before.get("name") == after.get("name") == "elevenid-beta", "PROJECT_CHANGED")
    require(set(before.get("services", {})) == {ROLE}, "ONE_ROLE_REQUIRED")
    service = before["services"][ROLE]
    require(service.get("image") == IMAGE and service.get("read_only") is True
            and service.get("pull_policy") == "never", "IMAGE_OR_RO_POLICY_CHANGED")
    require(set(before.get("secrets", {})) == {"northstar_run"}
            and set(before["secrets"]["northstar_run"]) == {"file"}, "ONE_FILE_SECRET_REQUIRED")
    require(service.get("init") in (None, False)
            and not any(key in service for key in ("build", "volumes", "ports", "privileged")),
            "UNREVIEWED_SERVICE_AUTHORITY")
    secret = service.get("secrets")
    require(isinstance(secret, list) and len(secret) == 1
            and secret[0]["source"] == secret[0]["target"] == "northstar_run",
            "SECRET_TARGET_CHANGED")
    expected = deepcopy(before)
    expected["secrets"]["northstar_run"]["file"] = str(fixture)
    expected["services"][ROLE]["init"] = True
    expected["services"][ROLE]["volumes"] = [{"type": "bind", "source": str(server),
        "target": SERVER_TARGET, "read_only": True, "bind": {"create_host_path": False}}]
    require(after == expected, "DELTA_OUTSIDE_REPAIRED_ASSET_AND_FIXTURE")


def execution_type(core):
    require(core.Operation.execute.__globals__ is vars(core), "FRESH_CORE_GLOBALS_REQUIRED")
    require(core.ROLES == ("ui-prod", "gateway"), "UNREVIEWED_CORE_SCOPE")
    require(all(hasattr(core.Operation, name) for name in
                ("cached_image_matches", "stop_arguments", "stop_exit_codes", "preimage_running", "should_start_created")), "SHARED_HOOKS_REQUIRED")
    core.ROLES = (ROLE,)

    class NorthstarFixture(core.Operation):
        def __init__(self, config, output, *, transport, identities,
                     representations, observe_external):
            require(config["scope"] == "FUNCTIONAL_ONLY" and config["sourceRevision"] == SOURCE
                    and config["imageSource"] == SOURCE,
                    "SOURCE_OR_FUNCTIONAL_SCOPE_CHANGED")
            require(set(config["oldCids"]) == {ROLE}, "ONE_KNOWN_ROLE_REQUIRED")
            require(len(identities) == 22 and ROLE not in identities, "PRODUCT22_REQUIRED")
            require(callable(representations.host_mounts) and callable(representations.daemon_source)
                    and callable(observe_external), "REVIEWED_VERIFIERS_REQUIRED")
            self.c, self.output, self.g = config, Path(output), transport
            self.models = {ROLE: core.load(config["oldModels"][ROLE])}
            self.changed = {ROLE: core.load(config["newModels"][ROLE])}
            self.server = asset_contract(config, core)
            self.original = stopped_authority(config, core, representations)
            require(type(config.get("functionalStartupAuthorized", False)) is bool,
                    "EXPLICIT_STARTUP_FLAG_REQUIRED")
            require(set(config["retainedContainers"]) == set(identities), "EXACT_RETAINED22_SNAPSHOTS_REQUIRED")
            model_delta(self.models[ROLE], self.changed[ROLE], core.read_ref(config["newFixture"]), self.server)
            self.identities = identities
            self.marker = None
            self.observe_external = observe_external
            self.recovery_started_cids = set()
            self.recovery_replaced_cid = None
            def verify(row, model, *, running):
                mode = "rollback" if model == self.models[ROLE] else "apply"
                require(model in (self.models[ROLE], self.changed[ROLE]), "MODEL_NOT_BOUND")
                candidate_guard(core.load(config["originalContainer"]), row,
                    fixture=model["secrets"]["northstar_run"]["file"],
                    provenance=config["provenance"][mode], running=running,
                    server=self.server if mode == "apply" else None,
                    replaced_cid=(config["oldCids"][ROLE] if mode == "apply"
                                  else self.recovery_replaced_cid),
                    allow_known_exited=(config.get("functionalStartupAuthorized") is True
                        and row["Id"] in self.recovery_started_cids),
                    allow_known_running=(config.get("functionalStartupAuthorized") is True and (
                        row["Id"] in self.recovery_started_cids or (
                            row["Id"] == self.state["newCids"].get(ROLE)
                            and ("apply-start-" + ROLE in self.state["operations"]
                                 or self.state.get("pending") == "apply-start-" + ROLE)))),
                    host_mounts=representations.host_mounts, daemon_source=representations.daemon_source)
            self.verify_container = verify
            self.g.candidate_guard = lambda role, row, model, *, running: (require(role == ROLE, "ONE_ROLE_REQUIRED"), self.verify_container(row, model, running=running))
            require(config["publicManifest"] == config["newFixture"]
                    and config["oldPublicManifest"] == config["oldFixture"], "EXTERNAL_FIXTURE_AUTHORITY_CHANGED")
            self.state = dict(schema="marty.d11-known-role-rebind/v1",runId=config["runId"],
                              sourceSha256=config["sourceSha256"],oldCids=config["oldCids"],
                              newCids={},operations=[],terminals={},pending=None,
                              releaseQualified=False,recordingQualified=False)

        def preimage_running(self, role, prefix):
            require(role == ROLE, "ONE_ROLE_REQUIRED")
            return prefix != "apply"

        def should_start_created(self, role, prefix):
            require(role == ROLE, "ONE_ROLE_REQUIRED")
            return prefix == "apply" and self.c.get("functionalStartupAuthorized") is True

        def retained_twenty(self):
            require(len(self.identities) == 22, "EXACT_RUNTIME22_REQUIRED")
            for role, identity in self.identities.items():
                expected = core.load(self.c["retainedContainers"][role])
                require(expected["Id"] == identity["containerId"]
                        and expected["Image"] == identity["imageId"]
                        and expected["Config"]["Image"] == identity["reference"]
                        and expected["Config"]["Labels"]["com.docker.compose.service"] == role
                        and expected["Config"]["Labels"]["com.docker.compose.project"] == identity["project"],
                        "RETAINED_SNAPSHOT_IDENTITY_CHANGED")
                row = self.g.old_guard(expected, running=expected["State"]["Running"])
                require(all(row["State"][key] == expected["State"][key]
                            for key in ("Running", "Pid", "StartedAt", "FinishedAt"))
                        and not row["State"]["OOMKilled"] and not row["State"]["Restarting"],
                        "RETAINED_GENERATION_CHANGED")
                if row["State"]["Running"]:
                    require(row["State"].get("Health", {}).get("Status") == "healthy"
                            or role == "canvas-sync-worker" and row["State"].get("Health") is None,
                            "RETAINED_ROLE_UNHEALTHY")

        def stop_arguments(self, role, cid, signal):
            require(role == ROLE and signal == "SIGTERM", "STOP_ROLE_CHANGED")
            return ["stop", "--signal", "SIGTERM", "--timeout", "-1", cid]

        def stop_exit_codes(self, role):
            require(role == ROLE, "STOP_ROLE_CHANGED")
            return (0,)  # Only the repaired asset is ever started or stopped.

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
            row = self.g.old_guard(original, running=False)
            self.guarded(ROLE, row["Id"], self.models[ROLE], False)
            require(row["State"] == original["State"], "STOPPED_GENERATION_CHANGED")
            return ids, {ROLE: row}

        def public(self, marker, fixture_ref):
            # Retains actual external image/source/file/fixture checks; no imported outcome is sufficient.
            if self.c.get("functionalStartupAuthorized") is True:
                return self.observe_external(core.read_ref(fixture_ref), image_source=SOURCE,
                    code_overlay={"sourceRevision": CODE_SOURCE, "server": self.c["codeOverlay"]["server"]})
            cid = self.state["newCids"].get(ROLE, self.c["oldCids"][ROLE])
            row = self.guarded(ROLE, cid, self.changed[ROLE], False)
            return {"state": "REPAIRED_CONFIGURATION_OFF_NOT_FUNCTIONAL", "cid": cid,
                    "imageSource": SOURCE, "codeOverlay": CODE_SOURCE, "pid": row["State"]["Pid"]}

        def preflight(self):
            require(self.c.get("preflightAuthorized") is True, "PREFLIGHT_NOT_ARMED")
            ids, before = self.baseline()
            exit_code = before[ROLE]["State"]["ExitCode"]
            proof = {"state": "ORIGINAL_CONFIGURATION_OFF137" if exit_code == 137 else "ORIGINAL_CONFIGURATION_OFF",
                     "cid": before[ROLE]["Id"], "actualExitCode": exit_code}
            return dict(state="D11_REBIND_PREFLIGHT_PASSED",allIds=sorted(ids),
                        before={ROLE:self.save("northstar-before.json", before[ROLE])},oldExternal=proof)

        def execute(self, preflight):
            require(self.c.get("executeAuthorized") is True, "EXECUTION_NOT_ARMED")
            result = super().execute(preflight)
            result["state"] = ("D11_REPAIRED_ASSET_RUNNING_NOT_FEATURE_QUALIFIED"
                if self.c.get("functionalStartupAuthorized") is True else "D11_REPAIRED_ASSET_CREATED_OFF")
            return result

        def original_public(self):
            cid = self.state["newCids"].get(ROLE, self.c["oldCids"][ROLE])
            row = self.guarded(ROLE, cid, self.models[ROLE], False)
            return {"state": "ORIGINAL_CONFIGURATION_OFF", "cid": cid,
                    "pid": row["State"]["Pid"], "actualExitCode": row["State"]["ExitCode"]}

        def recover(self, failed):
            require(self.c.get("rollbackAuthorized") is True, "ROLLBACK_NOT_ARMED")
            require(core.load(self.c["recoveryState"]) == failed
                    and failed["sourceSha256"] == self.c["sourceSha256"]
                    and failed["runId"] == self.c["runId"]
                    and failed["oldCids"] == self.c["oldCids"], "RECOVERY_AUTHORITY_CHANGED")
            require(set(failed["newCids"]) <= {ROLE}, "RECOVERY_ROLE_CHANGED")
            start = "apply-start-" + ROLE
            if start in failed["operations"] or failed.get("pending") == start:
                require(self.c.get("functionalStartupAuthorized") is True, "UNAUTHORIZED_START_INTENT")
            self.recovery_replaced_cid = failed["newCids"].get(ROLE)
            self.recovery_started_cids = ({failed["newCids"][ROLE]}
                if ROLE in failed["newCids"] and (start in failed["operations"] or failed.get("pending") == start)
                else set())
            self.retained_twenty()
            result = super().recover(failed)
            self.retained_twenty()
            result["state"] = "D11_NORTHSTAR_ORIGINAL_CONFIGURATION_RESTORED_OFF"
            return result

    return NorthstarFixture


def candidate_guard(original, actual, *, fixture, provenance, running, host_mounts, daemon_source, server=None, replaced_cid=None, allow_known_exited=False, allow_known_running=False):
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
    if not same and ("com.docker.compose.replace" in a["Labels"]
                     or "com.docker.compose.replace" in b["Labels"]):
        number = a["Labels"].get("com.docker.compose.container-number", "")
        retained_name = (isinstance(number, str) and re.fullmatch(r"[1-9][0-9]*", number)
            and a["Labels"].get("com.docker.compose.replace") == ROLE + "-" + number
            and b["Labels"].get("com.docker.compose.replace") == ROLE + "-" + number
            and original["Name"] == "/elevenid-beta-" + ROLE + "-" + number)
        require(replaced_cid is not None and (
            b["Labels"].get("com.docker.compose.replace") == replaced_cid or retained_name),
            "COMPOSE_REPLACED_CID_CHANGED")
        if "com.docker.compose.replace" in a["Labels"]:
            b["Labels"]["com.docker.compose.replace"] = a["Labels"]["com.docker.compose.replace"]
        else:b["Labels"].pop("com.docker.compose.replace", None)
    if not same:
        def environment(values):
            require(isinstance(values, list) and all(isinstance(v, str) and "=" in v for v in values),
                    "ENVIRONMENT_SHAPE_CHANGED")
            pairs = [v.split("=", 1) for v in values]
            result = dict(pairs)
            require(len(result) == len(pairs), "DUPLICATE_ENVIRONMENT_KEY")
            return result
        require(environment(a["Env"]) == environment(b["Env"]), "ENVIRONMENT_VALUES_CHANGED")
        b["Env"] = a["Env"]
    require(a == b, "CONFIG_CHANGED")
    ah, bh = deepcopy(original["HostConfig"]), deepcopy(actual["HostConfig"])
    for field in ("Binds", "Mounts"):
        ah.pop(field, None);bh.pop(field, None)
    if server is not None:
        require(bh.get("Init") is True, "REPAIRED_INIT_REQUIRED")
        if "Init" in ah:bh["Init"] = ah["Init"]
        else:bh.pop("Init", None)
    if not same:
        for key in ("Dns", "DnsOptions", "DnsSearch"):
            if key in ah and key in bh:
                empty = lambda v: v is None or isinstance(v, list) and not v
                if empty(ah[key]) and empty(bh[key]):
                    bh[key] = ah[key]
        if "OomKillDisable" in ah and "OomKillDisable" in bh:
            enabled = lambda v: v is None or v is False
            if enabled(ah["OomKillDisable"]) and enabled(bh["OomKillDisable"]):
                bh["OomKillDisable"] = ah["OomKillDisable"]
    require(ah == bh, "HOST_CONFIG_CHANGED")
    require(len(original["Mounts"]) == 1 and original["Mounts"][0]["Destination"] == TARGET
            and original["Mounts"][0]["Type"] == "bind" and original["Mounts"][0]["RW"] is False,
            "ONE_ORIGINAL_RO_FIXTURE_REQUIRED")
    mounts = {m["Destination"]: m for m in actual["Mounts"]}
    require(len(mounts) == len(actual["Mounts"])
            and set(mounts) == ({TARGET, SERVER_TARGET} if server is not None else {TARGET}),
            "EXACT_REPAIRED_MOUNTS_REQUIRED")
    old_mount, new_mount = deepcopy(original["Mounts"][0]), deepcopy(mounts[TARGET])
    require(daemon_source(new_mount["Source"]) == daemon_source(str(fixture)), "FIXTURE_SOURCE_CHANGED")
    old_mount.pop("Source");new_mount.pop("Source")
    require(old_mount == new_mount, "MOUNT_OPTIONS_CHANGED")
    old_binds, old_api = host_mounts(original)
    new_binds, new_api = host_mounts(actual)
    if server is not None:
        server_mount = deepcopy(mounts[SERVER_TARGET])
        server_mount["Source"] = daemon_source(server_mount["Source"])
        require(server_mount == {"Type": "bind", "Source": daemon_source(str(server)),
            "Destination": SERVER_TARGET, "Mode": "", "RW": False, "Propagation": "rprivate"},
            "SERVER_TOP_MOUNT_CHANGED")
        require(SERVER_TARGET not in new_binds and new_api.pop(SERVER_TARGET, None) == {
            "Type": "bind", "Source": daemon_source(str(server)), "Target": SERVER_TARGET,
            "ReadOnly": True, "BindOptions": {}}, "SERVER_HOST_API_MOUNT_CHANGED")
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
    if server is None:
        require(running is False, "LEGACY_CONFIGURATION_MUST_REMAIN_OFF")
    elif running:
        require(allow_known_running, "REPAIRED_START_INTENT_REQUIRED")
    if same:
        require(actual["State"] == original["State"], "ORIGINAL_STOPPED_GENERATION_CHANGED")
    elif not running:
        state = actual["State"]
        prestart = state["Status"] == "created" and state["Pid"] == 0 and state["StartedAt"].startswith("0001-")
        known_exited = (allow_known_exited and state["Status"] == "exited" and state["Pid"] == 0
            and state.get("Restarting") is False and not state["StartedAt"].startswith("0001-")
            and state["FinishedAt"] >= state["StartedAt"])
        require(prestart or known_exited, "CANDIDATE_NOT_PRESTART_OR_AUTHORIZED_EXITED")
