"""Signer-only successor adapter over the reviewed D02 execution library.

No dispatcher is run on import. The private caller binds the actual library,
helper modules, journal and inputs before selecting check/preflight/apply/rollback.
The original two-role library and its failed authority remain immutable.
"""
from __future__ import annotations
from copy import deepcopy
import json
import inspect
from pathlib import Path
import subprocess
import textwrap
import time
from scoped_native_runtime import read_ref, require, sha

PROFILE = "d02-signing-cas-no-transform"
ROLES = ("signing-keys",)
SOURCE = "9b1efd21163dadeff7cf1ced5fe47c5e046d2121"
CORE_SOURCE = "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"


def verify_candidate_output(reference):
    candidate = read_ref(reference, 512 * 1024 * 1024)
    require(type(reference.get("bytes")) is int and reference["bytes"] > 0
            and candidate.stat().st_size == reference["bytes"], "EXACT_ELF_SIZE_REQUIRED")
    return candidate


def environment(values):
    require(isinstance(values, list) and all(isinstance(v, str) and "=" in v for v in values), "ENV_SCHEMA")
    pairs = [value.split("=", 1) for value in values]
    parsed = dict(pairs)
    require(len(parsed) == len(pairs), "DUPLICATE_ENVIRONMENT_KEY")
    return parsed


def effective_environment(image_values, compose_values):
    require(isinstance(compose_values, dict), "COMPOSE_ENV_SCHEMA")
    effective = environment(image_values)
    for key, value in compose_values.items():
        require(isinstance(key, str) and key and "=" not in key and (value is None or isinstance(value, str)), "COMPOSE_ENV_SCHEMA")
        if value is None:
            effective.pop(key, None)
        else:
            effective[key] = value
    return effective


def live_compose_arguments(arguments, working_directory):
    require(arguments[:4] == ["docker", "compose", "--project-name", "elevenid-beta"]
            and "--project-directory" not in arguments and isinstance(working_directory, str)
            and working_directory, "LIVE_COMPOSE_GRAMMAR")
    return arguments[:4] + ["--project-directory", working_directory] + arguments[4:]


def normalized_created(old, actual, role, candidate, compose_hash, files, version, *, core, adapter, network_read, command, reviewed_role="signing-keys"):
    """Only previously proven Docker/Compose representation equivalences."""
    require(reviewed_role in ("signing-keys", "issuance-native") and role == reviewed_role
            and "--no-deps" in command, "REVIEWED_SINGLE_ROLE_NO_DEPS_REQUIRED")
    a, b = deepcopy(old), deepcopy(actual)
    environment(a["Config"]["Env"]); environment(b["Config"]["Env"])
    env_files = [command[i + 1] for i, arg in enumerate(command) if arg == "--env-file"]
    label = "com.docker.compose.project.environment_file"
    require(b["Config"]["Labels"].get(label) == ",".join(env_files), "ENV_FILE_PROVENANCE_CHANGED")
    require(b["Config"]["Labels"].get("com.docker.compose.depends_on") == "", "NO_DEPS_PROVENANCE_CHANGED")
    for row in (a, b):
        mounts = row["Mounts"]
        require(len({m["Destination"] for m in mounts}) == len(mounts), "DUPLICATE_MOUNT")
        for mount in mounts:
            if mount["Type"] == "bind":
                mount["Source"] = adapter.daemon_source(mount["Source"])
    for field in ("Dns", "DnsOptions", "DnsSearch"):
        if a["HostConfig"].get(field) in (None, []) and b["HostConfig"].get(field) in (None, []):
            a["HostConfig"][field] = b["HostConfig"][field] = []
    if a["HostConfig"].get("OomKillDisable") in (None, False) and b["HostConfig"].get("OomKillDisable") in (None, False):
        a["HostConfig"]["OomKillDisable"] = b["HostConfig"]["OomKillDisable"] = False
    networks, previous = b["NetworkSettings"]["Networks"], a["NetworkSettings"]["Networks"]
    require(set(networks) == set(previous), "NETWORK_SET_CHANGED")
    for name, old_network in previous.items():
        observed = network_read(name)
        require(len(observed) == 1 and observed[0]["Id"] == old_network["NetworkID"], "TARGET_NETWORK_CHANGED")
        require(networks[name]["NetworkID"] in ("", old_network["NetworkID"]), "NETWORK_TARGET_CHANGED")
        assigned = {"NetworkID", "EndpointID", "Gateway", "IPAddress", "IPPrefixLen", "IPv6Gateway",
                    "GlobalIPv6Address", "GlobalIPv6PrefixLen", "MacAddress", "DNSNames"}
        require({k: v for k, v in networks[name].items() if k not in assigned}
                == {k: v for k, v in old_network.items() if k not in assigned}, "NETWORK_STATIC_OPTIONS_CHANGED")
        for field in assigned - {"NetworkID", "DNSNames"}:
            require(networks[name].get(field) == old_network.get(field)
                    or networks[name].get(field) in (None, "", 0), "CREATED_ENDPOINT_NOT_UNATTACHED")
        names = networks[name].get("DNSNames") or []
        expected_names = set(old_network.get("DNSNames") or []) - {old["Id"][:12]}
        require(not names or set(names) - {actual["Id"][:12]} == expected_names, "CREATED_DNS_NAMES_CHANGED")
        networks[name]["NetworkID"] = old_network["NetworkID"]
    prior = core.AUTO_LABELS
    try:
        core.AUTO_LABELS = prior | {label, "com.docker.compose.depends_on"}
        core._successor_original_created(a, b, role, adapter.daemon_source(candidate), compose_hash, files, version)
    finally:
        core.AUTO_LABELS = prior


def execution_type(core):
    """The caller supplies a fresh, hash-verified module, never a runpy copy."""
    require(core.Execution.apply.__globals__ is vars(core), "EXECUTION_MODULE_GLOBALS_REQUIRED")
    require(not hasattr(core, "_successor_original_created"), "FRESH_CORE_MODULE_REQUIRED")
    core._successor_original_created = core.created_matches
    core.ROLES = ROLES
    rollback_source = textwrap.dedent(inspect.getsource(core.Execution.rollback))
    require(rollback_source.count('"D02_TWO_ROLE_BETA_OVERLAY"') == 1, "ROLLBACK_OPERATION_SOURCE_CHANGED")
    rollback_source = rollback_source.replace('"D02_TWO_ROLE_BETA_OVERLAY"', '"D02_SIGNER_HEADER_SUCCESSOR"')
    old_etag = "etag = '\"' + bytes.fromhex(sidecar[\"valueHex\"]).decode().split(\":\", 1)[0] + '\"' if sidecar else None"
    require(rollback_source.count(old_etag) == 1, "ROLLBACK_REVISION_SOURCE_CHANGED")
    rollback_source = rollback_source.replace(old_etag, old_etag.replace("etag = '\"'", "etag = '\"r-'"))
    # Reuse the exact reviewed rollback body with two explicit scope/prefix
    # corrections. Its functions retain this fresh core module's real globals.
    exec(compile(rollback_source, __file__ + ":reviewed-rollback", "exec"), vars(core))
    reviewed_rollback = core.rollback

    class SignerSuccessor(core.Execution):
        def __init__(self, context, inputs, input_ref):
            self.g, self.i, self.input_ref = context, inputs, input_ref
            self.root, self.base = Path(inputs["privateRoot"]), context["base"]
            self.preview = core.document(inputs["preview"]) if inputs.get("preview") else None
            self.store = context["journal_factory"](inputs)
            self.state = {"schema": 1, "operation": "D02_SIGNER_HEADER_SUCCESSOR", "runId": inputs["runId"],
                "inputSha256": input_ref["sha256"], "operatorSha256": sha(context["__file__"]),
                "phase": "PRECHECK", "new": {}, "releaseQualified": False, "recordingQualified": False}
            self.evidence = core.document(inputs["successorEvidence"])
            self.template = self.evidence["profileTemplate"]
            self.old_profile = self.template["nativeOverlay"]["predecessor"]
            self.snapshot_config_ref = self.preview["roles"]["signing-keys"]["beforeConfig"] if self.preview else None
            def compare(before, after, *, etag=None):
                self.node("domain", {"before": before, "after": after, **({"etag": etag} if etag is not None else {})})
            core.registry_equal = compare
            def created(old, actual, role, candidate, compose_hash, files, version):
                command = self.scoped_command(role, rollback=getattr(self, "rolling_back", False))
                normalized_created(old, actual, role, candidate, compose_hash, files, version,
                                   core=core, adapter=self.g["adapter"], command=command,
                                   network_read=lambda name: json.loads(self.command(["docker", "network", "inspect", name])))
            core.created_matches = created

        def save(self, name, value):
            if name == "signing-keys-before-config.private.json":
                previous = core.document(self.preview["roles"]["signing-keys"]["beforeConfig"])
                require(all(value[k] == previous[k] for k in ("Id", "Image", "Name", "HostConfig")), "PREVIEW_SIGNER_CONFIG_CHANGED")
                a, b = deepcopy(value["Config"]), deepcopy(previous["Config"])
                require(environment(a.pop("Env")) == environment(b.pop("Env")) and a == b, "PREVIEW_SIGNER_CONFIG_CHANGED")
                for row in (value, previous):
                    require(len({m["Destination"] for m in row["Mounts"]}) == len(row["Mounts"]), "DUPLICATE_MOUNT")
                require({m["Destination"]: {**m, "Source": self.g["adapter"].daemon_source(m["Source"])} for m in value["Mounts"]}
                        == {m["Destination"]: {**m, "Source": self.g["adapter"].daemon_source(m["Source"])} for m in previous["Mounts"]}, "PREVIEW_SIGNER_MOUNTS_CHANGED")
            reference = super().save(name, value)
            if name == "signing-keys-before-config.private.json":
                self.snapshot_config_ref = reference
            return reference

        def preflight(self):
            """Cheap Compose checks first, then real22 and scoped DB2 backup."""
            self.g["assert_inputs"]()
            require(self.preview is None, "PRESERVE_PREVIOUS_PREFLIGHT")
            self.before_rows = self.node("preimage", {"profile": self.template})
            expected = next(row for row in self.before_rows if row["role"] == "signing-keys")
            current = self.base.docker_inspect(expected["requiredContainerId"])
            require(current["Id"] == expected["requiredContainerId"] and current["Image"] == expected["imageId"]
                    and current["State"]["Running"] and not current["State"]["Paused"]
                    and current["State"]["StartedAt"] == expected["requiredStartedAt"]
                    and current["State"]["Pid"] == expected["requiredHostPid"], "CURRENT_SIGNER_GENERATION_CHANGED")
            labels = current["Config"]["Labels"]
            require(labels["com.docker.compose.project"] == "elevenid-beta"
                    and labels["com.docker.compose.service"] == "signing-keys", "CURRENT_SIGNER_SCOPE_CHANGED")
            runtime_env = [read_ref(ref) for ref in self.i["runtimeEnv"]]
            argv, env_hashes = self.base.compose_base({"compose_files": labels["com.docker.compose.project.config_files"].split(",")}, runtime_env)
            live_argv = live_compose_arguments(argv, labels["com.docker.compose.project.working_dir"])
            before_model = self.base.validate_compose(live_argv)
            images = json.loads(self.command(["docker", "image", "inspect", current["Image"]]))
            require(len(images) == 1 and images[0]["Id"] == current["Image"], "RUNTIME_IMAGE_CHANGED")
            image_ref = self.save("runtime-image.private.json", images[0])
            require(environment(current["Config"]["Env"]) == effective_environment(
                images[0]["Config"]["Env"], before_model["services"]["signing-keys"]["environment"]), "COMPOSE_ENVIRONMENT_CHANGED")
            require(self.base.run(*(live_argv + ["config", "--hash", "signing-keys"])).decode().split()[-1]
                    == labels["com.docker.compose.config-hash"], "LIVE_COMPOSE_HASH_DRIFT")
            frozen, hashes = self.g["freeze"](argv, before_model, "signing-keys", labels["com.docker.compose.project.working_dir"])
            overlay = self.root / "signing-keys-binary-only.compose.json"
            self.save(overlay.name, self.g["adapter"].binary_overlay(self.g["binaries"], PROFILE, ROLES, before_model))
            after_model = self.base.validate_compose(frozen, overlay=overlay)
            self.g["adapter"].validate_delta(before_model, after_model, self.g["binaries"], PROFILE, ROLES)
            config_ref = self.save("preview-signing-keys-before-config.private.json", current)
            self.snapshot_config_ref = config_ref
            self.save("signing-keys-before-compose.private.json", before_model)
            self.save("signing-keys-after-compose.private.json", after_model)
            first = self.fresh_observed()
            first_domain = self.snapshot()
            authority = json.loads(read_ref(self.old_profile["failedAuthority"]).read_bytes())["value"]
            prior_domain = json.loads(read_ref(authority["headerGateFailure"]["signingDomainReadback"]).read_bytes())
            core.registry_equal(prior_domain, first_domain)
            second = self.fresh_observed()
            require(first == second, "READ_ONLY_RUNTIME_CHANGED")
            core.registry_equal(first_domain, self.snapshot())
            snapshot = self.save("preview-before-observed-runtime.json", {
                "baseProfileSha256": self.i["baseProfile"]["sha256"], "binding": second})
            backup = self.save("preview-signing-domain.private.json", first_domain)
            preview = {"state": "READ_ONLY_PREVIEW_READY_NOT_APPLIED", "actual22Unchanged": True,
                "applyAuthorized": False, "redisWrites": False, "roles": {"signing-keys": {
                    "beforeContainerId": current["Id"], "beforeConfig": config_ref, "frozenArguments": frozen, "frozenInputHashes": hashes,
                    "runtimeEnvHashes": env_hashes, "runtimeImage": image_ref, "overlay": self.g["ref"](overlay),
                    "allowedDelta": "ONLY_EXISTING_READ_ONLY_SIGNER_BINARY_SOURCE"}},
                "beforeRuntimeBinding": snapshot, "signingDomainBackup": backup}
            result = self.save("preview.private.json", preview)
            return {"state": "READ_ONLY_SIGNER_SUCCESSOR_READY", "preview": result,
                    "runtimeMutated": False, "redisWrites": False}

        def node(self, operation, payload=None):
            if operation == "expected":
                operation, payload = "preimage", {"profile": self.template}
            if operation == "before":
                return self.fresh_observed()
            # Owned subprocess receives private JSON on stdin; only safe projected
            # results are returned. No arbitrary program/command is accepted.
            program = """const fs=require('node:fs');const h=require(process.argv[1]);const x=JSON.parse(fs.readFileSync(0,'utf8'));
let r;if(x.op==='preimage')r=h.expectedHeaderSuccessorPreimage(x.profile);
else if(x.op==='observe')r=h.observeDocker(x.row);
else if(x.op==='validate')r=h.validateRuntimeObservation(x.row,x.actual);
else if(x.op==='domain'){h.validateSigningDomainTransition(x.before,x.after,x.etag);r={valid:true};}
else if(x.op==='verify')r=h.verifyFunctionalRuntime(x.profile,{qualification:'FUNCTIONAL_ONLY'});
else if(x.op==='successorRows')r=h.applyNativeOverlayObservedRows(x.expected,x.before,x.deployed,x.selection);
else throw Error('operation refused');console.log(JSON.stringify(r));"""
            self.g["assert_inputs"]()
            result = subprocess.run([str(self.g["node"]), "-e", program, self.i["runtimeHelper"]["path"]],
                                    input=json.dumps({"op": operation, **(payload or {})}).encode(),
                                    capture_output=True, timeout=300, env=self.g["env"])
            if result.returncode != 0:
                self.save("reader-failure-" + str(time.time_ns()) + ".private.json", {
                    "operation": operation, "exitCode": result.returncode,
                    "stderr": result.stderr[:65536].decode("utf8", errors="replace")})
                raise RuntimeError("SOURCE_BOUND_READER_FAILED")
            require(len(result.stdout) <= 1024 * 1024, "READER_OUTPUT_BOUND")
            self.g["assert_inputs"]()
            return json.loads(result.stdout)

        def snapshot(self, expected=None):
            # Set the real function globals. A runpy returned mapping is not
            # authority over the function's global namespace.
            reader = self.g["redis_snapshot"]
            require(reader.__globals__ is self.g["reader_globals"], "SNAPSHOT_GLOBALS_CHANGED")
            require(self.snapshot_config_ref is not None, "STAGE_BOUND_CONFIG_REQUIRED")
            reader.__globals__["FROZEN_CONFIG_REFERENCE"] = self.snapshot_config_ref
            reader.__globals__["SIGNING_EXPECTED"] = expected
            return reader()

        def checks(self):
            self.g["assert_inputs"]()
            require(self.i["buildProfile"] == PROFILE, "SIGNER_PROFILE_REQUIRED")
            build = core.document(self.i["buildReceipt"])
            require(build["state"] == "BUILD_SUCCEEDED" and build["uiRevision"] == SOURCE
                    and build["coreRevision"] == CORE_SOURCE and build["roleBinaries"] == {"signing-keys": "marty-signing-keys"}, "EXACT_SIGNER_BUILD_REQUIRED")
            self.before_rows = self.node("preimage", {"profile": self.template})
            require(self.preview["state"] == "READ_ONLY_PREVIEW_READY_NOT_APPLIED"
                    and self.preview["actual22Unchanged"] is True and self.preview["applyAuthorized"] is False
                    and self.preview["redisWrites"] is False, "PREVIEW_NOT_READY")
            require(set(self.preview["roles"]) == set(ROLES), "SIGNER_ONLY_PREVIEW_REQUIRED")
            require(json.loads(self.command(["docker", "compose", "version", "--format", "json"]))["version"] == "v5.4.0", "COMPOSE_VERSION_CHANGED")
            for item in self.preview["roles"].values():
                frozen_image = core.document(item["runtimeImage"])
                live_image = json.loads(self.command(["docker", "image", "inspect", frozen_image["Id"]]))[0]
                require(live_image["Id"] == frozen_image["Id"] and environment(live_image["Config"]["Env"])
                        == environment(frozen_image["Config"]["Env"]), "RUNTIME_IMAGE_ENV_CHANGED")
                for path, value in item["frozenInputHashes"].items():
                    require(sha(path) == value, "COMPOSE_INPUT_CHANGED")
                before = self.base.validate_compose(item["frozenArguments"])
                after = self.base.validate_compose(item["frozenArguments"], overlay=core.bound(item["overlay"]))
                self.g["adapter"].validate_delta(before, after, self.g["binaries"], PROFILE, ROLES)
            return {"state": "SUCCESSOR_CHECK_PASSED", "runtimeMutated": False}

        def fresh_observed(self):
            rows = []
            for row in self.before_rows:
                actual = self.node("observe", {"row": row})
                verified = self.node("validate", {"row": row, "actual": actual})
                rows.append({**verified, **actual})
            return {"schema": "marty.observed-unqualified-native-preimage/v1", "scope": "OBSERVED_PREIMAGE_ONLY",
                    "releaseQualified": False, "recordingQualified": False, "roles": rows}

        def apply(self):
            # Reuse the original reviewed stop/create/inspect/start mechanism.
            # Its node('before') seam carries only an explicitly observed preimage.
            return super().apply()

        def rollback(self):
            state = self.store.read("build-state.json")
            phase = state.get("lastPhase") if state.get("phase") == "FAILED_RECONCILIATION_REQUIRED" else state.get("phase")
            require(phase in {"STOPPED", "CREATED", "STARTED", "CANDIDATES_HEALTHY",
                              "EXPLICIT_CONFIG_GET_OBSERVED", "APPLIED_FUNCTIONAL_ONLY"}, "UNKNOWN_OPERATION_REQUIRES_RECONCILIATION")
            require("UNKNOWN" not in state.get("failure", {}).get("errorCode", ""), "UNKNOWN_OPERATION_REQUIRES_RECONCILIATION")
            self.save("primary-state-before-rollback.private.json", state)
            self.rolling_back = True
            try:
                return reviewed_rollback(self)
            finally:
                self.rolling_back = False

        def finish_applied(self, before, registry, roles):
            build = core.document(self.i["buildReceipt"])
            expected = self.node("successorRows", {"expected": self.before_rows, "before": before["roles"],
                "deployed": {"roles": roles}, "selection": {"roles": list(ROLES), "source": SOURCE,
                "coreSource": CORE_SOURCE, "kind": "SCOPED_NATIVE_FUNCTIONAL_OVERLAY",
                "hashes": {name: row["sha256"] for name, row in build["binaries"].items()}}})
            actual = []
            for row in expected:
                observation = self.node("observe", {"row": row})
                self.node("validate", {"row": row, "actual": observation})
                actual.append(observation)
            self.save("candidate-22-readback.json", {"rows": actual, "releaseQualified": False})
            new = {"containerId": roles["signing-keys"]["containerId"], "startedAt": roles["signing-keys"]["startedAt"]}
            pre_get = self.snapshot(new)
            core.registry_equal(registry, pre_get)
            self.save("preget-signing-domain.private.json", pre_get)
            auth_input = core.document(self.i["authInputs"])
            require(auth_input["organizationId"] == core.ORG and Path(auth_input["privateRun"]) == self.root, "AUTH_CUSTODY_CHANGED")
            environment = dict(self.g["env"])
            environment["NODE_PATH"] = auth_input["nodeModulesRoot"]
            self.phase("EXPLICIT_CONFIG_GET_PENDING")
            result = subprocess.run([str(self.g["node"]), str(core.bound(self.i["authHelper"])),
                                    str(core.bound(self.i["authInputs"])), self.i["authInputs"]["sha256"]],
                                   env=environment, capture_output=True, timeout=240)
            # Preserve actual body/header evidence and the post-GET namespace
            # before interpreting the HTTP/ETag assertion outcome.
            self.save("auth-process-result.private.json", {"exitCode": result.returncode,
                "stdout": result.stdout[:65536].decode("utf8", errors="replace"),
                "stderr": result.stderr[:65536].decode("utf8", errors="replace")})
            auth_path = self.root / "config-read-result.private.json"
            require(auth_path.is_file(), "AUTH_OUTCOME_UNKNOWN")
            auth = json.loads(auth_path.read_bytes())
            auth_ref = self.g["ref"](auth_path)
            after_ref = self.save("postget-signing-domain.private.json", self.snapshot(new))
            self.phase("EXPLICIT_CONFIG_GET_OBSERVED", authResult=auth_ref, signingDomainAfter=after_ref)
            require(all(auth.get(k) is True for k in ("sessionRetired", "privateCookieRetired", "browserClosed")), "AUTH_CLEANUP_INCOMPLETE")
            require(result.returncode == 0 and auth.get("state") == "PASSED", "SIGNING_CONFIG_GET_NOT_QUALIFIED")
            before_ref = self.g["ref"](self.root / "preapply-signing-domain.private.json")
            observed_ref = self.save("before-observed-runtime.json", {"rows": before["roles"], "releaseQualified": False})
            deployed = {"schema": "marty.scoped-native-overlay-deployment/v1", "profile": PROFILE,
                "state": "APPLIED_FUNCTIONAL_ONLY", "actualReadbackVerified": True,
                "baseProfileSha256": self.i["baseProfile"]["sha256"], "buildReceiptSha256": self.i["buildReceipt"]["sha256"],
                "compatibilityResultSha256": self.i["compatibilityResult"]["sha256"], "sourceRevision": SOURCE,
                "coreRevision": CORE_SOURCE, "engineId": "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341",
                "predecessorAuthoritySha256": self.old_profile["failedAuthority"]["sha256"],
                "beforeObservedRuntime": observed_ref, "roles": roles, "productionTouched": False,
                "imagesBuilt": False, "releaseQualified": False, "recordingQualified": False,
                "configGate": {"authResult": auth_ref, "signingDomainBefore": before_ref,
                    "signingDomainAfter": after_ref, "registryUnchanged": True, "revisionBindingVerified": True}}
            # Independent validator derives namespace/digest checks from the
            # immutable snapshots; summary flags are not sufficient evidence.
            profile = deepcopy(self.template)
            receipt_ref = self.save("deployment-receipt.json", deployed)
            profile["nativeOverlay"]["deploymentReceipt"] = receipt_ref
            profile_ref = self.save("functional-runtime-profile.json", profile)
            first = self.node("verify", {"profile": profile})
            second = self.node("verify", {"profile": profile})
            require(first == second, "POSTAPPLY_RUNTIME_CHANGED")
            proof = self.save("actual-postapply-runtime-binding.json", second)
            self.phase("APPLIED_FUNCTIONAL_ONLY", deploymentReceipt=receipt_ref,
                       runtimeProfile=profile_ref, actualRuntimeBinding=proof)

    return SignerSuccessor
