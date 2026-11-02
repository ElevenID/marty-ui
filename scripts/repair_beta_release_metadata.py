"""Closed, source-bound beta Gateway/UI release-metadata repair.

The hash-bound historical adapter supplies bounded Docker/Compose transport only.
No database, KMS, image build/pull, generic role selection or automatic recovery.
"""

from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import time
import urllib.request
from scoped_native_runtime import (
    read_ref,
    read_executable_ref,
    ref,
    require,
    save_exclusive,
    save_state,
)
from beta_release_metadata import TARGET, marker_maps, gateway_metadata_model, ui_metadata_model
from bind_deployed_demo_manifest import bind_manifest
from prepare_beta_release_metadata import git_blob

ROLES = ("ui-prod", "gateway")
GUARD_SHA = "9b1ac1ad73588d12c1115e9fc15c3424836b6c6a519b9debdfddf913a8e28224"
KEYS = ("ELEVENID_COMPONENT_REVISIONS_JSON", "ELEVENID_IMAGE_DIGESTS_JSON")
SERVING_DIRECTORY = "/usr/share/nginx/html"
READ_HELPER_COMMAND = (
    "set -eu; sh /docker-entrypoint.d/40-ui-selfhost.sh >/dev/null; "
    "id -u; id -g; id -G; "
    "cat /usr/share/nginx/html/demos/manifests/2026.08.0.json"
)


def read_helper_tmpfs(uid, gid):
    return "rw,noexec,nosuid,nodev,size=64m,mode=0755,uid=" + str(uid) + ",gid=" + str(gid)


SOURCE_FILES = frozenset(
    {
        "repair_beta_release_metadata.py",
        "beta_release_metadata.py",
        "bind_deployed_demo_manifest.py",
        "prepare_beta_release_metadata.py",
        "scoped_native_runtime.py",
        "validate_demo_manifests.py",
        "demo_asset_hashes.py",
        "../deploy-config/catalog/demo-portfolio-v3.json",
        "../deploy-config/schemas/stack-demo-manifest.schema.json",
    }
)


def load(bound):
    return json.loads(read_ref(bound).read_bytes())


def static_contract(c):
    require(
        c["schema"] == "marty.beta-release-metadata-repair-input/v1", "INPUT_SCHEMA"
    )
    require(
        c["roles"] == list(ROLES) and c["betaOnly"] is True,
        "CLOSED_BETA_ROLES_REQUIRED",
    )
    require(
        re.fullmatch(
            "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}",
            c["runId"],
        )
        is not None,
        "RUN_UUID_REQUIRED",
    )
    require(
        c["releaseQualified"] is False and c["recordingQualified"] is False,
        "FUNCTIONAL_ONLY",
    )
    require(
        c["sourceSha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "OPERATOR_SOURCE_CHANGED",
    )
    require(
        c["guardSource"]["sha256"] == GUARD_SHA, "EXACT_REVIEWED_TRANSPORT_REQUIRED"
    )
    read_ref(c["guardSource"])
    read_executable_ref(c["dockerExecutable"])
    required_sources = SOURCE_FILES
    require(
        set(c["sourceFiles"]) == required_sources, "OPERATOR_SOURCE_CLOSURE_CHANGED"
    )
    for filename, source_ref in c["sourceFiles"].items():
        require(
            read_ref(source_ref).resolve()
            == (Path(__file__).parent / filename).resolve(),
            "OPERATOR_SOURCE_PATH_CHANGED",
        )
    require(
        c["sourceFiles"]["repair_beta_release_metadata.py"]["sha256"]
        == c["sourceSha256"],
        "OPERATOR_SOURCE_CHANGED",
    )
    models = {role: load(c["oldModels"][role]) for role in ROLES}
    changed = {role: load(c["newModels"][role]) for role in ROLES}
    marker, manifest = load(c["expectedMarker"]), load(c["publicManifest"])
    source = load(c["sourceManifest"])
    require(
        marker["marty_ui_sha"] == c["productRevision"] == source["marty_ui_sha"],
        "SOURCE_CHANGED",
    )
    require(
        marker["release_version"]
        == marker["deployment_release_marker"]
        == source["release_version"],
        "RELEASE_CHANGED",
    )
    require(
        marker["component_revisions"]
        == {v["component"]: v["revision"] for v in source["component_revisions"]},
        "COMPONENT_MAP_CHANGED",
    )
    require(
        "marty-demo-recorder" not in marker["component_revisions"],
        "UNDEPLOYED_RECORDER_CLAIM",
    )
    require(
        manifest["recorder_revision"]["value"] == c["captureRecorderRevision"],
        "CAPTURE_RECORDER_CHANGED",
    )
    require(
        manifest["deployment_release_marker"] == marker["release_version"],
        "PUBLIC_MANIFEST_MARKER_CHANGED",
    )
    require(
        manifest["release_ready"] is False and manifest["public_demo_ready"] is False,
        "NO_PUBLIC_QUALIFICATION",
    )
    require(
        changed["gateway"] == gateway_metadata_model(models["gateway"], marker),
        "GATEWAY_DELTA_NOT_TWO_METADATA_FIELDS",
    )
    require(
        changed["ui-prod"]
        == ui_metadata_model(models["ui-prod"], c["publicManifest"]["path"]),
        "UI_DELTA_NOT_ONE_READONLY_PUBLIC_FILE",
    )
    observation = load(c["runtimeObservation"])
    require(
        observation["binding"]["runtimeKind"] == "SIGNED_NIGHTLY_IMAGES",
        "SIGNED_RUNTIME_REQUIRED",
    )
    rows = observation["binding"]["roles"]
    require(
        len(rows) == 22 and len({r["role"] for r in rows}) == 22,
        "EXACT_RUNTIME22_REQUIRED",
    )
    descriptor = load(c["productDescriptor"])
    signed = load(c["releaseLock"])
    require(
        descriptor["source"]["commit"] == c["productRevision"],
        "SIGNED_PRODUCT_SOURCE_CHANGED",
    )
    require(
        signed["release"] == "marty-ui@" + marker["release_version"],
        "SIGNED_RELEASE_CHANGED",
    )
    components, images = marker_maps(
        c["productRevision"], read_ref(c["cargoLock"]).read_bytes(), signed, rows
    )
    require(
        marker["component_revisions"] == components
        and marker["image_digests"] == images,
        "STALE_OR_UNVERIFIED_MARKER_MAPS",
    )
    require(
        {v["component"]: v["revision"] for v in manifest["component_revisions"]}
        == components,
        "PUBLIC_COMPONENT_MAP_CHANGED",
    )
    require(
        {v["component"]: v["digest"] for v in manifest["image_digests"]} == images,
        "PUBLIC_IMAGE_MAP_CHANGED",
    )

    template_bytes = git_blob(
        c["productRepository"],
        c["productRevision"],
        "ui/public/demos/manifests/2026.08.0.json",
    )
    require(
        template_bytes == read_ref(c["template"]).read_bytes(),
        "TEMPLATE_NOT_COMMITTED_PRODUCT",
    )
    require(
        git_blob(c["productRepository"], c["productRevision"], "rust/Cargo.lock")
        == read_ref(c["cargoLock"]).read_bytes(),
        "CARGO_LOCK_NOT_COMMITTED_PRODUCT",
    )
    require(
        manifest == bind_manifest(json.loads(template_bytes), source, images),
        "PUBLIC_MANIFEST_NOT_CANONICAL_BINDER_OUTPUT",
    )
    identities = {r["role"]: r for r in rows}
    for role in ROLES:
        row = identities[role]
        require(
            row["source"] == c["productRevision"]
            and row["containerId"] == c["oldCids"][role],
            "OLD_ROLE_BINDING_CHANGED",
        )
        require(
            models[role]["services"][role]["image"]
            == changed[role]["services"][role]["image"]
            == row["reference"],
            "IMAGE_CHANGE_FORBIDDEN",
        )
    return models, changed, marker, identities


NGINX_CENSUS = r"""set -eu
awk '{print "MASTER\t" $22}' /proc/1/stat
for d in /proc/[0-9]*; do
 [ -r "$d/comm" ] || continue
 [ "$(cat "$d/comm")" = nginx ] || continue
 cmd=$(tr '\000' ' ' < "$d/cmdline")
 case "$cmd" in 'nginx: worker process'*)
 p=${d##*/}; parent=$(awk '$1=="PPid:"{print $2}' "$d/status"); ticks=$(awk '{print $22}' "$d/stat")
 uids=$(awk '$1=="Uid:"{printf "%s,%s,%s,%s",$2,$3,$4,$5}' "$d/status")
 gids=$(awk '$1=="Gid:"{printf "%s,%s,%s,%s",$2,$3,$4,$5}' "$d/status")
 groups=$(awk '$1=="Groups:"{for(i=2;i<=NF;i++){printf "%s%s",i==2?"":",",$i}}' "$d/status")
 printf 'WORKER\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$parent" "$ticks" "$uids" "$gids" "${groups:--}"
 ;; esac
done
"""


def validate_nginx_principal(ui, witness, first, second):
    require(first == second, "NGINX_WORKER_CENSUS_CHANGED")
    require(
        witness["state"] == "ACTUAL_NGINX_SERVING_PRINCIPAL_AND_EXE_VERIFIED_READONLY",
        "NGINX_EXE_WITNESS_REQUIRED",
    )
    require(
        ui["Id"] == witness["containerId"]
        and ui["Image"] == witness["imageId"]
        and ui["State"]["Pid"] == witness["masterHostPid"]
        and ui["State"]["StartedAt"] == witness["containerStartedAt"],
        "NGINX_MASTER_GENERATION_CHANGED",
    )
    lines = first.decode("utf8").splitlines()
    require(
        lines[0] == "MASTER\t" + str(witness["master"]["startTicks"]),
        "NGINX_MASTER_START_CHANGED",
    )
    workers = {row["namespacePids"][-1]: row for row in witness["workers"]}
    require(
        0 < len(workers) <= 64 and len(workers) == len(witness["workers"]),
        "NGINX_WORKER_SET_INVALID",
    )
    actual = {}
    for line in lines[1:]:
        kind, pid, parent, ticks, uids, gids, groups = line.split("\t")
        pid = int(pid)
        require(
            kind == "WORKER" and pid not in actual and pid in workers,
            "NGINX_WORKER_GENERATION_CHANGED",
        )
        row = workers[pid]
        uid_values, gid_values = (
            list(map(int, uids.split(","))),
            list(map(int, gids.split(","))),
        )
        supplementary = [] if groups == "-" else list(map(int, groups.split(",")))
        require(
            int(parent) == 1
            and int(ticks) == row["startTicks"]
            and uid_values == row["uids"]
            and gid_values == row["gids"]
            and supplementary == row["supplementaryGroups"],
            "NGINX_WORKER_IDENTITY_CHANGED",
        )
        require(
            row["parentHostPid"] == witness["masterHostPid"]
            and row["executablePath"] == witness["master"]["executablePath"]
            and row["executableSha256"] == witness["master"]["executableSha256"],
            "NGINX_EXE_WITNESS_CHANGED",
        )
        require(
            len(uid_values) == 4
            and len(set(uid_values)) == 1
            and uid_values[1] > 0
            and len(gid_values) == 4
            and len(set(gid_values)) == 1,
            "NGINX_NONROOT_SERVING_PRINCIPAL_REQUIRED",
        )
        actual[pid] = (
            uid_values[1],
            gid_values[1],
            tuple(sorted(set(supplementary + [gid_values[1]]))),
        )
    require(
        set(actual) == set(workers) and len(set(actual.values())) == 1,
        "NGINX_WORKER_SET_CHANGED",
    )
    uid, gid, groups = next(iter(actual.values()))
    require(list(groups) == [gid], "UNREVIEWED_NGINX_ADDITIONAL_GROUPS")
    return dict(
        uid=uid, gid=gid, permissionGroups=list(groups), workerCount=len(actual)
    )


def rendered_delta(role, original, changed, marker, public_path):
    expected = (
        gateway_metadata_model(original, marker)
        if role == "gateway"
        else ui_metadata_model(original, public_path)
    )
    require(
        role in ROLES and changed == expected, "RENDER_CHANGED_OUTSIDE_METADATA_DELTA"
    )


class Operation:
    def __init__(self, c, output):
        self.c, self.output = c, output
        self.models, self.changed, self.marker, self.identities = static_contract(c)
        self.state = dict(
            schema="marty.beta-release-metadata-operation/v1",
            runId=c["runId"],
            sourceSha256=c["sourceSha256"],
            oldCids=c["oldCids"],
            newCids={},
            operations=[],
            terminals={},
            pending=None,
            releaseQualified=False,
            recordingQualified=False,
        )
        spec = importlib.util.spec_from_file_location(
            "metadata_reviewed_transport", read_ref(c["guardSource"])
        )
        self.g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.g)
        self.g.PLAN = load(c["transportInput"])
        self.g.OUT = output
        self.g.SEQUENCE = 0
        require(self.g.PLAN["engineId"] == c["engineId"], "ENGINE_INPUT_CHANGED")
        self.g.DAEMON_SOURCE = self.g.load_daemon_source()
        self.g.IMAGE_IDS = {}
        self.g.IMAGE_CONFIG = {}
        self.g.NETWORK_IDS = {}

    def save(self, name, value):
        save_exclusive(self.output / name, value)
        return ref(self.output / name)

    def persist(self):
        save_state(self.output / "operation.json", self.state)

    def guarded(self, role, cid, model, running):
        row = self.g.inspect(cid)
        self.g.candidate_guard(role, copy.deepcopy(row), model, running=running)
        return row

    def effect(self, step, function):
        require(self.state["pending"] is None, "PRIOR_EFFECT_UNRESOLVED")
        self.g.engine()
        self.state["pending"] = step
        self.persist()
        value = function()
        if isinstance(value, Path):
            terminal = value.with_name(value.stem + "-terminal.json")
            terminal_value = json.loads(terminal.read_bytes())
            require(terminal_value["exit"] == 0, "EFFECT_TERMINAL_NONZERO")
            self.state["terminals"][step] = ref(terminal)
        self.state["operations"].append(step)
        self.state["pending"] = None
        self.persist()
        return value

    def retained_twenty(self):
        require(len(self.identities) == 22, "EXACT_RUNTIME22_REQUIRED")
        for role, expected in self.identities.items():
            if role in ROLES:
                continue
            row = self.g.inspect(expected["containerId"])
            require(
                row["Id"] == expected["containerId"]
                and row["Image"] == expected["imageId"]
                and row["Config"]["Image"] == expected["reference"],
                "RETAINED_ROLE_IMAGE_OR_ID_CHANGED",
            )
            require(
                row["Config"]["Labels"]["com.docker.compose.service"] == role
                and row["Config"]["Labels"]["com.docker.compose.project"]
                == expected["project"],
                "RETAINED_ROLE_SCOPE_CHANGED",
            )
            require(
                row["State"]["Running"]
                and not row["State"]["OOMKilled"]
                and row["State"]["Pid"] == expected["hostPid"]
                and row["State"]["StartedAt"] == expected["startedAt"],
                "RETAINED_ROLE_GENERATION_CHANGED",
            )
            require(
                row["State"].get("Health", {}).get("Status") == "healthy"
                or (
                    role == "canvas-sync-worker" and row["State"].get("Health") is None
                ),
                "RETAINED_ROLE_UNHEALTHY",
            )

    def baseline(self):
        self.g.engine()
        self.retained_twenty()
        all_ids = set(self.g.observe_lines(["ps", "-aq", "--no-trunc"], "all-before"))
        none = self.g.observe(
            ["network", "inspect", "none"], "read-helper-none-network"
        )[0]
        require(
            none["Name"] == "none" and none["Driver"] == "null",
            "READ_HELPER_NONE_NETWORK_CHANGED",
        )
        self.g.NETWORK_IDS["none"] = none["Id"]
        before = {}
        for role in ROLES:
            image_ref = self.models[role]["services"][role]["image"]
            image = self.g.observe(["image", "inspect", image_ref], role + "-image")[0]
            require(
                self.cached_image_matches(image_ref, image), "SIGNED_IMAGE_NOT_CACHED"
            )
            require(
                image["Config"]["Labels"].get("org.opencontainers.image.revision")
                == self.c["productRevision"],
                "IMAGE_SOURCE_CHANGED",
            )
            self.g.IMAGE_IDS[image_ref] = image["Id"]
            self.g.IMAGE_CONFIG[image_ref] = image["Config"]
            for network in self.models[role]["networks"].values():
                actual = self.g.observe(
                    ["network", "inspect", network["name"]],
                    "network-" + network["name"],
                )[0]
                self.g.NETWORK_IDS[network["name"]] = actual["Id"]
            row = self.guarded(role, self.c["oldCids"][role], self.models[role], True)
            require(
                row["State"].get("Health", {}).get("Status") == "healthy",
                "OLD_ROLE_UNHEALTHY",
            )
            expected = self.identities[role]
            require(
                row["State"]["Pid"] == expected["hostPid"]
                and row["State"]["StartedAt"] == expected["startedAt"],
                "OLD_PROCESS_GENERATION_CHANGED",
            )
            before[role] = row
        return all_ids, before

    def healthy(self, role, cid, model):
        deadline = time.monotonic() + 75
        while True:
            row = self.g.inspect(cid)
            if row["State"].get("Health", {}).get("Status") == "healthy":
                self.g.candidate_guard(role, copy.deepcopy(row), model, running=True)
                return row
            require(
                time.monotonic() < deadline and not row["State"].get("OOMKilled"),
                "NEW_HEALTH_TIMEOUT_OR_OOM",
            )
            time.sleep(2)

    def compose(self, role, model, stem):
        return self.g.compose(
            [
                "up",
                "--no-start",
                "--no-deps",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                role,
            ],
            stem,
            ui=role == "ui-prod",
            model_path=read_ref(model),
            timeout=180,
        )

    def public(self, expected_marker, expected_manifest_ref):
        values = {}
        for label, route in [
            ("marker", "/.well-known/marty-release"),
            ("manifest", "/demos/manifests/2026.08.0.json"),
        ]:
            request = urllib.request.Request(
                "https://beta.elevenidllc.com" + route,
                headers={"Accept-Encoding": "identity", "User-Agent": "marty-demo-audit/1.0"},
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                require(
                    response.status == 200 and response.url == request.full_url,
                    "PUBLIC_METADATA_REDIRECT_OR_STATUS",
                )
                data = response.read(4 * 1024 * 1024 + 1)
                require(len(data) <= 4 * 1024 * 1024, "PUBLIC_METADATA_OVERSIZE")
            file = self.output / ("served-" + label + ".json")
            with file.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            values[label] = ref(file)
            if label == "marker":
                require(json.loads(data) == expected_marker, "SERVED_MARKER_MISMATCH")
            else:
                require(
                    hashlib.sha256(data).hexdigest() == expected_manifest_ref["sha256"],
                    "SERVED_MANIFEST_BYTES_MISMATCH",
                )
        return values

    def stop_arguments(self, role, cid, signal):
        return ["kill", "--signal", signal, cid]

    def stop_exit_codes(self, role):
        return (0,)

    def cached_image_matches(self, reference, row):
        return reference in row.get("RepoDigests", [])

    def preimage_running(self, role, prefix):
        return True

    def should_start_created(self, role, prefix):
        return True

    def stop_generation(self, role, cid, model, prefix):
        running = self.preimage_running(role, prefix)
        row = self.guarded(role, cid, model, running)
        if not running:
            require(not row["State"]["Running"] and row["State"]["Pid"] == 0
                    and not row["State"].get("Restarting")
                    and not row["State"]["OOMKilled"], "PREIMAGE_NOT_STOPPED")
            self.save(prefix + "-already-stopped-" + role + ".json", row)
            return
        signal = "SIGQUIT" if role == "ui-prod" else "SIGTERM"
        self.save(prefix + "-stop-preimage-" + role + ".json", row)
        self.effect(
            prefix + "-stop-" + role,
            lambda: self.g.command(
                self.stop_arguments(role, cid, signal), prefix + "-stop-" + role
            ),
        )
        deadline = time.monotonic() + 45
        while True:
            current = self.g.inspect(cid)
            self.g.candidate_guard(
                role, copy.deepcopy(current), model, running=current["State"]["Running"]
            )
            require(
                current["State"]["StartedAt"] == row["State"]["StartedAt"],
                "STOP_GENERATION_CHANGED",
            )
            if not current["State"]["Running"]:
                require(
                    current["State"]["Pid"] == 0
                    and current["State"]["ExitCode"] in self.stop_exit_codes(role)
                    and current["State"]["OOMKilled"] is False,
                    "METADATA_ROLE_NOT_GRACEFULLY_STOPPED",
                )
                self.save(prefix + "-stopped-" + role + ".json", current)
                return
            require(time.monotonic() < deadline, "METADATA_ROLE_STOP_NOT_TERMINAL")
            time.sleep(0.5)

    def create_start(self, role, model, prefix):
        self.effect(
            prefix + "-create-" + role,
            lambda: self.compose(role, model, prefix + "-create-" + role),
        )
        project = "elevenid-beta-ui" if role == "ui-prod" else "elevenid-beta"
        ids = self.g.observe_lines(
            [
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                "label=com.docker.compose.project=" + project,
                "--filter",
                "label=com.docker.compose.service=" + role,
            ],
            prefix + "-discover-" + role,
        )
        require(
            len(ids) == 1 and ids[0] != self.c["oldCids"][role],
            "CREATE_GENERATION_UNKNOWN",
        )
        cid = ids[0]
        row = self.guarded(role, cid, load(model), False)
        require(
            row["State"]["Status"] == "created" and row["State"]["Pid"] == 0,
            "CREATED_ROLE_ALREADY_STARTED",
        )
        self.state["newCids"][role] = cid
        self.save(prefix + "-created-" + role + ".json", row)
        self.persist()
        if not self.should_start_created(role, prefix):
            return row
        self.effect(
            prefix + "-start-" + role,
            lambda: self.g.command(
                ["start", cid], prefix + "-start-" + role, timeout=45
            ),
        )
        return self.healthy(role, cid, load(model))

    def execute(self, preflight):
        all_ids, before = self.baseline()
        require(
            sorted(all_ids) == preflight["allIds"], "BASELINE_REGISTRATIONS_CHANGED"
        )
        for role in ROLES:
            previous = load(preflight["before"][role])
            current = self.g.old_guard(previous, running=self.preimage_running(role, "apply"))
            require(
                current["NetworkSettings"] == previous["NetworkSettings"],
                "PREVIEW_ROLE_NETWORK_CHANGED",
            )
            before[role] = current
        self.save("before.json", before)
        self.state["before"] = ref(self.output / "before.json")
        self.persist()
        after = {}
        for role in ROLES:
            self.stop_generation(
                role, self.c["oldCids"][role], self.models[role], "apply"
            )
            after[role] = self.create_start(role, self.c["newModels"][role], "apply")
        self.retained_twenty()
        served = self.public(self.marker, self.c["publicManifest"])
        ids = set(self.g.observe_lines(["ps", "-aq", "--no-trunc"], "all-after"))
        require(
            ids
            == (all_ids - set(self.c["oldCids"].values()))
            | set(self.state["newCids"].values()),
            "UNRELATED_CONTAINER_REGISTRATION_CHANGED",
        )
        return dict(
            state="BETA_RELEASE_METADATA_REPAIRED",
            operation=ref(self.output / "operation.json"),
            before=self.state["before"],
            after=self.save("after.json", after),
            served=served,
            oldCids=self.c["oldCids"],
            newCids=self.state["newCids"],
            allIds=sorted(ids),
            runId=self.c["runId"],
            sourceSha256=self.c["sourceSha256"],
            releaseQualified=False,
            recordingQualified=False,
        )

    def guard_read_helper(self, value, cid):
        image = self.models["ui-prod"]["services"]["ui-prod"]["image"]
        witness = load(self.c["uiServingPrincipal"])
        uid, gid = witness["uid"], witness["gid"]
        owner = "beta-release-metadata-" + self.c["runId"]
        source = str(read_ref(self.c["publicManifest"])).replace("\\", "/")

        require(
            value["Id"] == cid
            and value["Image"] == self.g.IMAGE_IDS[image]
            and value["Config"]["Labels"].get("io.elevenid.owner") == owner,
            "PUBLIC_READ_HELPER_IDENTITY_CHANGED",
        )
        require(
            value["Config"].get("Image") == image
            and value["Config"].get("User") == str(uid) + ":" + str(gid)
            and value["Config"].get("Entrypoint") == ["/bin/sh"]
            and value["Config"].get("Cmd")
            == ["-c", READ_HELPER_COMMAND],
            "PUBLIC_READ_HELPER_COMMAND_OR_USER_CHANGED",
        )
        host = value["HostConfig"]
        require(
            host["NetworkMode"] == "none"
            and host["ReadonlyRootfs"] is True
            and host["Memory"] == 64 * 1024**2
            and host["MemorySwap"] == 64 * 1024**2
            and host["NanoCpus"] == 250000000
            and host["PidsLimit"] == 16
            and host.get("Privileged") is False
            and host.get("CapAdd") in (None, [])
            and host.get("CapDrop") == ["ALL"]
            and host.get("SecurityOpt") == ["no-new-privileges:true"]
            and host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0}
            and host.get("Tmpfs") == {SERVING_DIRECTORY: read_helper_tmpfs(uid, gid)},
            "PUBLIC_READ_HELPER_CAPS_CHANGED",
        )
        require(len(value["Mounts"]) == 1, "PUBLIC_READ_HELPER_MOUNTS_CHANGED")
        mount = value["Mounts"][0]
        require(
            mount["Type"] == "bind"
            and mount["Destination"] == TARGET
            and mount["RW"] is False
            and self.g.DAEMON_SOURCE(mount["Source"]) == self.g.DAEMON_SOURCE(source),
            "PUBLIC_READ_HELPER_SOURCE_CHANGED",
        )
        networks = value["NetworkSettings"]["Networks"]
        require(set(networks) == {"none"}, "PUBLIC_READ_HELPER_NETWORK_CHANGED")
        network_id = networks["none"]["NetworkID"]
        require(
            network_id == self.g.NETWORK_IDS["none"]
            or (
                network_id == ""
                and value["State"]["Status"] == "created"
                and value["State"]["Pid"] == 0
            ),
            "PUBLIC_READ_HELPER_NETWORK_ID_CHANGED",
        )

    def readability(self, before):
        public_file = read_ref(self.c["publicManifest"])
        acl_before = {
            "file": acl_digest(public_file),
            "parent": acl_digest(public_file.parent),
        }
        role = "ui-prod"
        image = self.models[role]["services"][role]["image"]
        witness = load(self.c["uiServingPrincipal"])
        require(
            self.c["uiServingPrincipalSource"]["sha256"] == witness["sourceSha256"],
            "NGINX_PRINCIPAL_SOURCE_CHANGED",
        )
        read_ref(self.c["uiServingPrincipalSource"])
        require(
            witness["engineId"] == self.c["engineId"], "NGINX_PRINCIPAL_ENGINE_CHANGED"
        )
        ui = self.guarded(role, self.c["oldCids"][role], self.models[role], True)
        first = self.g.command(
            ["exec", "--user", "0", ui["Id"], "sh", "-c", NGINX_CENSUS],
            "nginx-serving-first",
            timeout=20,
            limit=65536,
        )
        second = self.g.command(
            ["exec", "--user", "0", ui["Id"], "sh", "-c", NGINX_CENSUS],
            "nginx-serving-second",
            timeout=20,
            limit=65536,
        )
        principal = validate_nginx_principal(
            ui, witness, first.read_bytes(), second.read_bytes()
        )
        self.state["uiServingPrincipal"] = self.save(
            "ui-serving-principal.json",
            dict(
                **principal,
                witness=self.c["uiServingPrincipal"],
                first=ref(first),
                second=ref(second),
            ),
        )
        self.persist()
        uid, gid = principal["uid"], principal["gid"]
        require(
            not self.g.IMAGE_CONFIG[image].get("Volumes"),
            "IMAGE_ANONYMOUS_VOLUMES_NOT_ALLOWED",
        )
        name = "marty-public-metadata-read-" + self.c["runId"]
        owner = "beta-release-metadata-" + self.c["runId"]
        source = str(read_ref(self.c["publicManifest"])).replace("\\", "/")
        require("," not in source, "UNSUPPORTED_BIND_SOURCE")
        self.effect(
            "public-file-read-create",
            lambda: self.g.command(
                [
                    "create",
                    "--name",
                    name,
                    "--label",
                    "io.elevenid.owner=" + owner,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--memory",
                    "64m",
                    "--memory-swap",
                    "64m",
                    "--cpus",
                    "0.25",
                    "--pids-limit",
                    "16",
                    "--user",
                    str(uid) + ":" + str(gid),
                    "--entrypoint",
                    "/bin/sh",
                    "--mount",
                    "type=bind,source=" + source + ",target=" + TARGET + ",readonly",
                    "--tmpfs",
                    SERVING_DIRECTORY + ":" + read_helper_tmpfs(uid, gid),
                    image,
                    "-c",
                    READ_HELPER_COMMAND,
                ],
                "public-file-read-create",
            ),
        )
        row = self.g.observe(
            ["container", "inspect", name], "public-file-read-created"
        )[0]
        cid = row["Id"]
        self.state["readHelperCid"] = cid
        self.persist()

        self.guard_read_helper(row, cid)
        require(
            row["State"]["Status"] == "created" and row["State"]["Pid"] == 0,
            "PUBLIC_READ_HELPER_ALREADY_STARTED",
        )
        self.effect(
            "public-file-read-start",
            lambda: self.g.command(["start", cid], "public-file-read-start"),
        )
        deadline = time.monotonic() + 15
        while True:
            row = self.g.inspect(cid)
            self.guard_read_helper(row, cid)
            if not row["State"]["Running"]:
                break
            require(time.monotonic() < deadline, "PUBLIC_READ_HELPER_NOT_TERMINAL")
            time.sleep(0.2)
        require(
            row["State"]["ExitCode"] == 0 and row["State"]["OOMKilled"] is False,
            "PUBLIC_FILE_NOT_READABLE_AS_UI_UID",
        )
        transcript = self.g.command(["logs", cid], "public-file-read-logs").read_bytes()
        actual_uid, sep, remainder = transcript.partition(b"\n")
        actual_gid, sep2, remainder = remainder.partition(b"\n")
        actual_groups, sep3, body = remainder.partition(b"\n")
        require(
            sep
            and sep2
            and sep3
            and sorted(set(map(int, actual_groups.split())))
            == principal["permissionGroups"]
            and actual_uid.strip() == str(uid).encode()
            and actual_gid.strip() == str(gid).encode()
            and hashlib.sha256(body).hexdigest() == self.c["publicManifest"]["sha256"],
            "PUBLIC_READBACK_BYTES_OR_UID_CHANGED",
        )
        self.effect(
            "public-file-read-remove",
            lambda: self.g.command(["rm", cid], "public-file-read-remove"),
        )
        ids = set(
            self.g.observe_lines(["ps", "-aq", "--no-trunc"], "public-file-read-absent")
        )
        require(
            cid not in ids and ids == before,
            "PUBLIC_READ_HELPER_OR_UNRELATED_ID_REMAINS",
        )
        self.state["readHelperRemoved"] = True
        self.persist()
        require(
            acl_before
            == {
                "file": acl_digest(public_file),
                "parent": acl_digest(public_file.parent),
            },
            "PUBLIC_FILE_OR_PRIVATE_PARENT_ACL_CHANGED",
        )
        return dict(
            aclBeforeAndAfter=acl_before,
            servingPrincipal=self.state["uiServingPrincipal"],
            permissionGroups=principal["permissionGroups"],
            uid=uid,
            gid=gid,
            sourceSha256=self.c["publicManifest"]["sha256"],
            mountReadOnly=True,
            helperCid=cid,
            helperRemoved=True,
            knownExit=0,
        )

    def preflight(self):
        all_ids, before = self.baseline()
        self.state["preflightAllIds"] = sorted(all_ids)
        self.persist()
        for role in ROLES:
            original = json.loads(
                self.g.compose(
                    ["config", "--format", "json"],
                    "render-old-" + role,
                    ui=role == "ui-prod",
                    model_path=read_ref(self.c["oldModels"][role]),
                ).read_bytes()
            )
            changed = json.loads(
                self.g.compose(
                    ["config", "--format", "json"],
                    "render-new-" + role,
                    ui=role == "ui-prod",
                    model_path=read_ref(self.c["newModels"][role]),
                ).read_bytes()
            )
            rendered_delta(
                role, original, changed, self.marker, self.c["publicManifest"]["path"]
            )
        proof = self.readability(all_ids)
        old_served = self.original_public()
        snapshots = {
            role: self.save("preflight-before-" + role + ".json", before[role])
            for role in ROLES
        }
        return dict(
            state="BETA_METADATA_PREFLIGHT_PASSED",
            sourceSha256=self.c["sourceSha256"],
            runId=self.c["runId"],
            allIds=sorted(all_ids),
            before=snapshots,
            publicManifestSha256=self.c["publicManifest"]["sha256"],
            readability=proof,
            oldServed=old_served,
            models=self.c["newModels"],
            betaRoleWrites=False,
        )

    def cleanup_read_helper(self, failed):
        require(
            not failed["newCids"] and failed.get("before") is None,
            "NOT_PREFLIGHT_ONLY_HELPER",
        )
        require(
            failed["sourceSha256"] == self.c["sourceSha256"]
            and failed["runId"] == self.c["runId"],
            "HELPER_RECOVERY_SCOPE_CHANGED",
        )
        cid = failed.get("readHelperCid")
        require(
            isinstance(cid, str) and re.fullmatch("[a-f0-9]{64}", cid),
            "UNKNOWN_HELPER_CREATE_REQUIRES_RECONCILIATION",
        )
        # This reuses preflight's exact image and network custody, never role creation/start.
        all_ids, _ = self.baseline()
        expected = set(failed["preflightAllIds"])
        require(all_ids == expected | {cid}, "READ_HELPER_UNRELATED_ID_CHANGED")
        row = self.g.inspect(cid)
        self.guard_read_helper(row, cid)
        if row["State"]["Running"]:
            self.effect(
                "read-helper-cleanup-stop",
                lambda: self.g.command(
                    ["kill", "--signal", "SIGTERM", cid], "read-helper-cleanup-stop"
                ),
            )
            deadline = time.monotonic() + 15
            while True:
                row = self.g.inspect(cid)
                self.guard_read_helper(row, cid)
                if not row["State"]["Running"]:
                    break
                require(time.monotonic() < deadline, "READ_HELPER_STOP_NOT_TERMINAL")
                time.sleep(0.2)
        require(row["State"]["Pid"] == 0, "READ_HELPER_PID_LIVE")
        self.effect(
            "read-helper-cleanup-remove",
            lambda: self.g.command(["rm", cid], "read-helper-cleanup-remove"),
        )
        require(
            set(
                self.g.observe_lines(
                    ["ps", "-aq", "--no-trunc"], "read-helper-cleanup-after"
                )
            )
            == expected,
            "READ_HELPER_CLEANUP_ID_PARITY",
        )
        return dict(
            state="OWNED_READ_HELPER_REMOVED",
            cid=cid,
            originalFailure=self.c["recoveryState"],
            betaRoleWrites=False,
        )

    def original_public(self):
        return self.public(load(self.c["oldMarker"]), self.c["oldPublicManifest"])

    def recover(self, failed):
        require(
            failed["sourceSha256"] == self.c["sourceSha256"]
            and failed["oldCids"] == self.c["oldCids"],
            "RECOVERY_SOURCE_OR_SCOPE_CHANGED",
        )
        require(failed.get("before"), "ORIGINAL_BEFORE_JOURNAL_REQUIRED")
        originals = load(failed["before"])
        require(
            set(originals) == set(ROLES)
            and all(originals[r]["Id"] == self.c["oldCids"][r] for r in ROLES),
            "RECOVERY_ORIGINAL_PREIMAGE_CHANGED",
        )
        changed = failed["newCids"]
        require(set(changed) <= set(ROLES), "RECOVERY_ROLE_SCOPE_CHANGED")
        for role in ROLES:
            created = (
                "apply-create-" + role in failed["operations"]
                or failed.get("pending") == "apply-create-" + role
            )
            require(
                not created or role in changed,
                "UNKNOWN_CREATE_REQUIRES_READONLY_RECONCILIATION",
            )
        # Populate immutable cached-image/network identities without assuming old CIDs survive.
        self.g.engine()
        for role in ROLES:
            image = self.models[role]["services"][role]["image"]
            row = self.g.observe(["image", "inspect", image], "recovery-image-" + role)[
                0
            ]
            require(self.cached_image_matches(image, row), "RECOVERY_IMAGE_CHANGED")
            self.g.IMAGE_IDS[image] = row["Id"]
            self.g.IMAGE_CONFIG[image] = row["Config"]
            for network in self.models[role]["networks"].values():
                n = self.g.observe(
                    ["network", "inspect", network["name"]],
                    "recovery-network-" + network["name"],
                )[0]
                self.g.NETWORK_IDS[network["name"]] = n["Id"]
        baseline = load(self.c["preflightResult"])
        current = set(
            self.g.observe_lines(["ps", "-aq", "--no-trunc"], "recovery-all-before")
        )
        require(
            current
            == (set(baseline["allIds"]) - {self.c["oldCids"][r] for r in changed})
            | set(changed.values()),
            "RECOVERY_UNRELATED_ID_CHANGED",
        )
        for role in ROLES:
            if role in changed:
                row = self.g.inspect(changed[role])
                self.g.candidate_guard(
                    role,
                    copy.deepcopy(row),
                    self.changed[role],
                    running=row["State"]["Running"],
                )
            else:
                row = self.g.inspect(self.c["oldCids"][role])
                self.g.candidate_guard(
                    role,
                    copy.deepcopy(row),
                    self.models[role],
                    running=row["State"]["Running"],
                )
                require(
                    row["State"]["StartedAt"] == originals[role]["State"]["StartedAt"],
                    "RECOVERY_OLD_GENERATION_CHANGED",
                )
        self.state["recoveryOriginal"] = self.c["recoveryState"]
        self.persist()
        recovered = {}
        for role in ROLES:
            if role in changed:
                current = self.g.inspect(changed[role])
                if current["State"]["Running"]:
                    self.stop_generation(
                        role, changed[role], self.changed[role], "rollback"
                    )
                recovered[role] = self.create_start(
                    role, self.c["oldModels"][role], "rollback"
                )
            else:
                row = self.g.inspect(self.c["oldCids"][role])
                if not row["State"]["Running"] and self.should_start_created(role, "rollback"):
                    self.effect(
                        "rollback-start-original-" + role,
                        lambda: self.g.command(
                            ["start", row["Id"]], "rollback-start-original-" + role
                        ),
                    )
                    self.healthy(role, row["Id"], self.models[role])
        served = self.original_public()
        ids = set(
            self.g.observe_lines(["ps", "-aq", "--no-trunc"], "recovery-all-after")
        )
        require(
            ids
            == (set(baseline["allIds"]) - {self.c["oldCids"][r] for r in changed})
            | {r["Id"] for r in recovered.values()},
            "RECOVERY_UNRELATED_ID_CHANGED",
        )
        return dict(
            state="BETA_METADATA_ORIGINAL_CONFIG_RESTORED",
            originalFailure=self.c["recoveryState"],
            recovered=self.save("recovered.json", recovered),
            served=served,
            allIds=sorted(ids),
            releaseQualified=False,
            recordingQualified=False,
        )


def recovery_context(
    original, failed, state_ref, error_ref, invocation_ref, lock_ref, recovery_root
):
    """Pure disabled context builder. Unknown creates require a separate read-only reconciliation."""
    require(
        failed["sourceSha256"] == original["sourceSha256"]
        and failed["runId"] == original["runId"]
        and failed["oldCids"] == original["oldCids"],
        "RECOVERY_SOURCE_OR_SCOPE_CHANGED",
    )
    new = failed["newCids"]
    require(set(new) <= set(ROLES), "RECOVERY_ROLE_SCOPE_CHANGED")
    for role in ROLES:
        if failed.get("pending") == "apply-create-" + role:
            require(role in new, "UNKNOWN_CREATE_REQUIRES_READONLY_RECONCILIATION")
    helper_only = not new and not failed.get("before")
    if helper_only and not failed.get("readHelperRemoved"):
        require(
            re.fullmatch("[a-f0-9]{64}", failed.get("readHelperCid", "")),
            "UNKNOWN_HELPER_CREATE_REQUIRES_RECONCILIATION",
        )
    result = copy.deepcopy(original)
    for key in (
        "executeAuthorized",
        "preflightAuthorized",
        "rollbackAuthorized",
        "helperCleanupAuthorized",
        "lockRetirementAuthorized",
    ):
        result[key] = False
    result.update(
        recoveryState=state_ref,
        recoveryOutputRoot=str(recovery_root),
        recoveryMode="cleanup-read-helper" if helper_only else "rollback",
        failedLock=dict(lock=lock_ref, invocation=invocation_ref, failure=error_ref),
    )
    return result


def acl_digest(path):
    """Read the actual owner/group/DACL descriptor; no ACL or mode mutation."""
    import ctypes
    from ctypes import wintypes

    require(os.name == "nt", "WINDOWS_PUBLIC_FILE_ACL_REQUIRED")
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.GetFileSecurityW.restype = wintypes.BOOL
    needed = wintypes.DWORD()
    require(
        not api.GetFileSecurityW(str(path), 7, None, 0, ctypes.byref(needed))
        and ctypes.get_last_error() == 122
        and 0 < needed.value <= 65536,
        "PUBLIC_ACL_DESCRIPTOR_UNAVAILABLE",
    )
    buffer = ctypes.create_string_buffer(needed.value)
    require(
        api.GetFileSecurityW(str(path), 7, buffer, needed.value, ctypes.byref(needed)),
        "PUBLIC_ACL_READ_FAILED",
    )
    return hashlib.sha256(buffer.raw[: needed.value]).hexdigest()


def process_identity(pid):
    """Read actual Windows creation identity without signaling or terminating a process."""
    import ctypes
    from ctypes import wintypes

    require(
        os.name == "nt" and isinstance(pid, int) and pid > 4,
        "WINDOWS_USER_PROCESS_REQUIRED",
    )
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        *([ctypes.POINTER(wintypes.FILETIME)] * 4),
    ]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        require(ctypes.get_last_error() == 87, "PROCESS_IDENTITY_UNAVAILABLE")
        return None
    try:
        created, exited, kernel_time, user_time = (
            wintypes.FILETIME() for _ in range(4)
        )
        require(
            kernel.GetProcessTimes(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ),
            "PROCESS_CREATION_UNAVAILABLE",
        )
        status = wintypes.DWORD()
        require(
            kernel.GetExitCodeProcess(handle, ctypes.byref(status)),
            "PROCESS_EXIT_UNAVAILABLE",
        )
        return dict(
            pid=pid,
            creation=(created.dwHighDateTime << 32) | created.dwLowDateTime,
            live=status.value == 259,
        )
    finally:
        kernel.CloseHandle(handle)


def retire_failed_lock(c, probe=process_identity):
    recovery = c["failedLock"]
    lock_path = read_ref(recovery["lock"])
    value = json.loads(lock_path.read_bytes())
    invocation = load(recovery["invocation"])
    original_input = load(invocation["input"])
    failure = load(recovery["failure"])
    require(
        value["purpose"] == "BETA_GATEWAY_UI_METADATA"
        and value["runId"] == c["runId"]
        and value["sourceSha256"] == c["sourceSha256"],
        "FAILED_LOCK_SCOPE_CHANGED",
    )
    require(
        invocation["sourceSha256"]
        == c["sourceSha256"]
        == original_input["sourceSha256"]
        == failure["sourceSha256"],
        "FAILED_LOCK_SOURCE_CHANGED",
    )
    current = probe(value["pid"])
    require(
        current is None
        or not current["live"]
        or current["creation"] != value["creation"],
        "FAILED_OPERATOR_STILL_LIVE",
    )
    # Re-read the same hash-bound lock immediately before the sole unlink; no other lock is adopted.
    require(read_ref(recovery["lock"]) == lock_path, "FAILED_LOCK_CHANGED")
    lock_path.unlink()
    return dict(
        state="OWNED_FAILED_METADATA_LOCK_RETIRED",
        originalLock=recovery["lock"],
        observedProcess=current,
        originalFailure=recovery["failure"],
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in (
        "check",
        "preflight",
        "execute",
        "rollback",
        "retire-lock",
        "cleanup-read-helper",
    ):
        mode.add_argument("--" + name, action="store_true")
    args = parser.parse_args()
    c = json.loads(args.input.read_bytes())
    static_contract(c)
    if args.retire_lock:
        require(
            c.get("lockRetirementAuthorized") is True, "LOCK_RETIREMENT_NOT_AUTHORIZED"
        )
        receipt = retire_failed_lock(c)
        target = Path(c["lockRetirementReceipt"])
        require(
            target.is_relative_to(Path.home() / ".codex/private"),
            "PRIVATE_RECEIPT_REQUIRED",
        )
        save_exclusive(target, receipt)
        print(json.dumps(dict(state=receipt["state"], receipt=ref(target))))
        return
    if args.check:
        print(
            json.dumps(
                dict(
                    state="METADATA_STATIC_CHECK_PASSED",
                    dockerCommands=0,
                    betaWrites=False,
                )
            )
        )
        return
    require(c.get("preflightAuthorized") is True, "PREFLIGHT_NOT_AUTHORIZED")
    if args.execute:
        require(c.get("executeAuthorized") is True, "EXECUTION_NOT_AUTHORIZED")
    if args.cleanup_read_helper:
        require(
            c.get("helperCleanupAuthorized") is True, "HELPER_CLEANUP_NOT_AUTHORIZED"
        )
    if args.rollback:
        require(c.get("rollbackAuthorized") is True, "ROLLBACK_NOT_AUTHORIZED")
    output = Path(
        c["recoveryOutputRoot"]
        if args.rollback or args.cleanup_read_helper
        else c["executeOutputRoot"]
        if args.execute
        else c["preflightOutputRoot"]
    )
    private = Path.home() / ".codex/private"
    require(
        output.is_absolute() and output.is_relative_to(private) and not output.exists(),
        "FRESH_PRIVATE_OUTPUT_REQUIRED",
    )
    output.mkdir(mode=0o700)
    op = Operation(c, output)
    lock = Path(op.g.PLAN["canonicalLock"])
    lock_value = dict(
        pid=os.getpid(),
        creation=process_identity(os.getpid())["creation"],
        pidScope="host",
        purpose="BETA_GATEWAY_UI_METADATA",
        runId=c["runId"],
        sourceSha256=c["sourceSha256"],
    )
    save_exclusive(lock, lock_value)
    result = None
    try:
        op.save(
            "invocation.json",
            dict(
                input=ref(args.input),
                sourceSha256=c["sourceSha256"],
                mode="rollback"
                if args.rollback
                else "execute"
                if args.execute
                else "preflight",
            ),
        )
        if args.cleanup_read_helper:
            result = op.cleanup_read_helper(load(c["recoveryState"]))
        elif args.rollback:
            result = op.recover(load(c["recoveryState"]))
        elif args.execute:
            prior = load(c["preflightResult"])
            require(
                prior["state"] == "BETA_METADATA_PREFLIGHT_PASSED"
                and prior["sourceSha256"] == c["sourceSha256"]
                and prior["models"] == c["newModels"]
                and prior["publicManifestSha256"] == c["publicManifest"]["sha256"],
                "PREFLIGHT_BINDING_CHANGED",
            )
            result = op.execute(prior)
        else:
            result = op.preflight()
        op.save("result.json", result)
        print(
            json.dumps(dict(state=result["state"], result=ref(output / "result.json")))
        )
    except BaseException as error:
        op.save("failure-state.json", op.state)
        code = (
            str(error)
            if re.fullmatch("[A-Z][A-Z0-9_]{2,100}", str(error))
            else "METADATA_OPERATION_FAILED"
        )
        op.save(
            "failure.json",
            dict(
                state="FAILED",
                errorClass=type(error).__name__,
                code=code,
                sourceSha256=c["sourceSha256"],
            ),
        )
        raise
    finally:
        clean_no_effect = (
            op.state["pending"] is None
            and not op.state["operations"]
            and not op.state["newCids"]
        )
        if result is not None or clean_no_effect:
            require(
                json.loads(lock.read_bytes()) == lock_value, "CANONICAL_LOCK_CHANGED"
            )
            lock.unlink()


if __name__ == "__main__":
    main()
