"""Bounded cached native build with closed reviewed output profiles.

The caller supplies the existing hash-bound build helper (resources/run), not a
new daemon transport. Import and verify are read-only. Start is an explicit
mutation entry point requiring a separately reviewed prepared-input digest.
The default passport source, recipe bytes and durability gate remain unchanged.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
from scoped_native_runtime import (CORE_REVISION, UI_REVISION, ROLE_BINARIES,
    daemon_source, durable_barrier, read_ref, ref, require, save_exclusive, save_state, selected_sources, sha)

PACKAGES = ("marty-flow", "marty-gateway", "marty-issuance-service")
CARGO_ARGV = ["cargo", "build", "--locked", "--offline", "--message-format=json"] + [item for package in PACKAGES for item in ("-p", package, "--bin", package)]
REVIEWED_BUILD_HELPER_SHA256 = "60f061cc55f6c254ce4b883caa71cf02bdefdded6b581cc004da87fadbce8356"
VOLUMES = ("ui-canvas-cargo", "d05-rust-target-20261026")

def build_scope(profile=None):
    if profile is None:
        return {"uiRevision": UI_REVISION, "roles": ROLE_BINARIES, "packages": PACKAGES,
                "prefix": "marty-d12-", "owner": "d12-scoped-native"}
    from scoped_native_profiles import reviewed_profile
    selected = reviewed_profile(profile)
    return {"uiRevision": selected.ui_revision, "roles": dict(selected.roles),
            "packages": selected.packages, "prefix": selected.container_prefix, "owner": selected.owner}


def cargo_arguments(profile=None):
    return ["cargo", "build", "--locked", "--offline", "--message-format=json"] + [
        item for package in build_scope(profile)["packages"] for item in ("-p", package, "--bin", package)]


def verify_export(repository, revision, directory, inventory_ref, git):
    """Compare every exported byte to actual selected Git blobs, not its own list."""
    inventory = json.loads(read_ref(inventory_ref).read_bytes())
    tree = git(["-C", str(repository), "ls-tree", "-rz", "-r", revision])
    tracked = {}
    for record in tree.split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        mode, kind, oid = header.split()
        require(mode in (b"100644", b"100755") and kind == b"blob", "SOURCE_LINK_OR_GITLINK_UNSUPPORTED")
        tracked[name.decode()] = oid.decode()
    directory = Path(directory)
    paths = list(directory.rglob("*"))
    require(not directory.is_symlink() and not getattr(directory, "is_junction", lambda: False)(), "SOURCE_EXPORT_LINK")
    require(all(not p.is_symlink() and not getattr(p, "is_junction", lambda: False)() for p in paths), "SOURCE_EXPORT_LINK")
    files = {p.relative_to(directory).as_posix(): p for p in paths if p.is_file()}
    require(set(files) == set(tracked) == {row["path"] for row in inventory}, "SOURCE_EXPORT_FILE_SET_CHANGED")
    for row in inventory:
        raw = files[row["path"]].read_bytes()
        import hashlib
        oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(oid == tracked[row["path"]] and len(raw) == row["bytes"] and sha(files[row["path"]]) == row["sha256"], "SOURCE_EXPORT_BYTES_CHANGED")

def verify(plan, git, profile=None):
    selected_sources(plan, profile)
    scope = build_scope(profile)
    private = Path(plan["privateDirectory"]).resolve()
    require(private.is_relative_to(Path.home() / ".codex/private"), "OWNED_PRIVATE_BUILD_ROOT_REQUIRED")
    for name, revision in (("ui", scope["uiRevision"]), ("core", CORE_REVISION)):
        source = plan["sources"][name]
        require(source["revision"] == revision, "SOURCE_REVISION_CHANGED")
        directory = Path(source["directory"]).resolve()
        require(directory.is_relative_to(private), "EXPORT_OUTSIDE_CUSTODY")
        verify_export(source["repository"], revision, directory, source["inventory"], git)
    recipe = read_ref(plan["recipe"])
    require(recipe.read_text() == render_recipe(profile), "THREE_ROLE_RECIPE_CHANGED")
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", plan.get("builderImage", "")), "PINNED_BUILDER_REQUIRED")
    require(re.fullmatch(r"[a-f0-9-]{36}", plan.get("runId", "")), "OWNED_BUILD_RUN_REQUIRED")
    output = Path(plan["outputDirectory"]).resolve()
    require(output.is_relative_to(private) and output.is_dir() and not output.is_symlink(), "OWNED_OUTPUT_REQUIRED")
    return private, output

def render_recipe(profile=None):
    scope = build_scope(profile)
    binaries = tuple(scope["roles"].values())
    return """#!/bin/sh
set -eu
export CARGO_HOME=/cargo CARGO_TARGET_DIR=/target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_BUILD_JOBS=1
finish() { status=$?; printf '%s\\n' "$status" > /out/exit-code; }
trap finish EXIT
rustc -vV > /out/rustc-version.txt
cargo -vV > /out/cargo-version.txt
grep -Fx 'release: 1.95.0' /out/rustc-version.txt
grep -Fx 'host: x86_64-unknown-linux-gnu' /out/rustc-version.txt
mkdir -p /build/ui
cp -a /src/ui/. /build/ui/
cd /build/ui
python3 scripts/localize_marty_core_dependencies.py rust/Cargo.toml .github/feature-regression/rust-probe/Cargo.toml --core-root /build/core > /out/localizer.log
cargo metadata --offline --format-version 1 --manifest-path rust/Cargo.toml > /out/localized-metadata.json
cargo tree --offline --locked --manifest-path rust/Cargo.toml """ + " ".join("-p " + package for package in scope["packages"]) + """ -e features,no-dev > /out/production-feature-tree.txt
python3 - <<'BOUNDARY'
import json,pathlib,sys
sys.path.insert(0,'scripts/ci')
import check_marty_core_kms_boundary as guard
m=json.loads(pathlib.Path('/out/localized-metadata.json').read_text())
nodes={n['id']:n for n in m['resolve']['nodes']}
core=[p for p in m['packages'] if p['name'] in guard.CORE_CRATES]
assert {p['name'] for p in core}==guard.CORE_CRATES
assert not any('github.com/ElevenID/marty-core' in (p.get('source') or '') for p in m['packages'])
for p in core:
 assert p['source'] is None and pathlib.Path(p['manifest_path']).resolve().is_relative_to(pathlib.Path('/build/core'))
 features=set(nodes[p['id']]['features']);assert not features&guard.FORBIDDEN_FEATURES
 if p['name'] in guard.KMS_ONLY_CRATES:assert 'kms-only' in features
guard.check_production_crypto_tree(pathlib.Path('/out/production-feature-tree.txt').read_text())
BOUNDARY
cd rust
""" + " ".join(cargo_arguments(profile)) + """ > /out/compiler-artifacts.jsonl 2> /out/compiler.log
python3 - <<'ARTIFACTS'
import json,pathlib,sys
sys.path.insert(0,'/build/ui/scripts/ci')
import check_marty_core_kms_boundary as guard
m=json.loads(pathlib.Path('/out/localized-metadata.json').read_text())
core={p['id']:p for p in m['packages'] if p['name'] in guard.CORE_CRATES}
rows=[];services=[]
for line in pathlib.Path('/out/compiler-artifacts.jsonl').read_text().splitlines():
 x=json.loads(line)
 if x.get('reason')!='compiler-artifact':continue
 if x['package_id'] in core:
  p=core[x['package_id']];features=set(x['features']);assert not features&guard.FORBIDDEN_FEATURES
  if p['name'] in guard.KMS_ONLY_CRATES:assert 'kms-only' in features
  rows.append({'name':p['name'],'manifest':p['manifest_path'],'features':sorted(features),'fresh':x['fresh'],'filenames':x['filenames']})
 if x.get('executable') in """ + "{" + ",".join(repr("/target/debug/" + binary) for binary in binaries) + "}" + """:services.append(x)
assert 'marty-oid4vci' in {p['name'] for p in rows}
assert len(services)==""" + str(len(binaries)) + """ and len({p['executable'] for p in services})==""" + str(len(binaries)) + """
pathlib.Path('/out/core-compiler-artifacts.json').write_text(json.dumps(rows,indent=2)+'\\n')
pathlib.Path('/out/service-compiler-artifacts.json').write_text(json.dumps(services,indent=2)+'\\n')
ARTIFACTS
for binary in """ + " ".join(binaries) + """; do
 install -m 0755 /target/debug/$binary /out/$binary
 sha256sum /out/$binary > /out/$binary.sha256
 readelf -h -d /out/$binary > /out/$binary.elf.txt
 ldd /out/$binary > /out/$binary.libraries.txt
done
"""

def build_arguments(plan, profile=None):
    selected_sources(plan, profile)
    scope = build_scope(profile)
    require(re.fullmatch(re.escape(scope["prefix"]) + r"[a-f0-9-]{36}", plan.get("containerName", "")) and plan["containerName"] == scope["prefix"] + plan["runId"], "RUN_BOUND_CONTAINER_NAME_REQUIRED")
    args = ["docker", "--context", "desktop-linux", "run", "--detach", "--pull", "never", "--network", "none", "--name", plan["containerName"],
        "--cpus", "1", "--memory", "2g", "--memory-swap", "4g", "--label", "elevenid.owner=" + scope["owner"],
        "--label", "elevenid.run=" + plan["runId"]]
    for source, target, readonly in ((plan["sources"]["ui"]["directory"], "/src/ui", True), (plan["sources"]["core"]["directory"], "/build/core", True),
            (plan["outputDirectory"], "/out", False), (plan["recipe"]["path"], "/build.sh", True)):
        args += ["--mount", "type=bind,src=" + daemon_source(source) + ",dst=" + target + (",readonly" if readonly else "")]
    for volume, target in zip(VOLUMES, ("/cargo", "/target")):
        args += ["--mount", "type=volume,src=" + volume + ",dst=" + target]
    return args + ["--entrypoint", "/bin/sh", plan["builderImage"], "/build.sh"]

def start(prepared_ref, helper, git, profile=None):
    plan = json.loads(read_ref(prepared_ref).read_bytes())
    preparation_sha = prepared_ref["sha256"]
    require(plan.get("executionOperatorSha256") == sha(Path(__file__)), "BUILD_OPERATOR_CHANGED")
    private, output = verify(plan, git, profile)
    require(sha(helper.__file__) == REVIEWED_BUILD_HELPER_SHA256, "REVIEWED_SHARED_BUILD_HELPER_CHANGED")
    require(os.environ.get("DOCKER_CONTEXT") == "desktop-linux", "EXPLICIT_DESKTOP_CONTEXT_REQUIRED")
    require(not list(output.iterdir()), "PRESERVE_PREVIOUS_BUILD_OUTPUTS")
    require(helper.VOLUMES == VOLUMES, "SHARED_RESOURCE_SCOPE_CHANGED")
    require(helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}").stdout.strip() == plan["engineId"], "ENGINE_CHANGED")
    resource_state = None
    if profile is not None:
        # The existing resource helper itself creates one 64 MiB read-only probe.
        # Consume this D02 attempt before that effect, not only before compilation.
        image = json.loads(helper.run("docker", "image", "inspect", plan["builderImage"]).stdout)[0]
        require(image["Id"] == plan["builderImage"] and image["Os"] == "linux" and image["Architecture"] == "amd64", "BUILDER_IDENTITY_CHANGED")
        resource_state = {"state": "RESOURCE_CHECK_INTENT", "runId": plan["runId"],
                          "preparationSha256": preparation_sha, "buildProfile": profile,
                          "resourceProbe": {"effect": "EXISTING_64M_READONLY_NETWORK_NONE_DOCKER_PROBE",
                                            "image": plan["builderImage"], "volumes": list(VOLUMES),
                                            "containerId": None, "outcome": "INTENT_DISPATCH_MAY_FOLLOW"},
                          "releaseQualified": False, "recordingQualified": False}
        resource_state["intentDurability"] = save_exclusive(private / "build-apply-intent.json", resource_state)
        barrier = save_state(private / "build-state.json", resource_state)
        if not (durable_barrier(resource_state["intentDurability"]) and durable_barrier(barrier)):
            resource_state["state"] = "BUILD_DURABILITY_BLOCKED_NO_DOCKER_DISPATCH"
            resource_state["resourceProbe"]["outcome"] = "NOT_DISPATCHED"
            save_state(private / "build-state.json", resource_state)
            raise ValueError("DURABLE_INTENT_AND_JOURNAL_REQUIRED")
        try:
            resource = helper.resources(private, plan["builderImage"])
            resource_state.update(state="RESOURCE_CHECK_READY", resourcesBefore=resource)
            resource_state["resourceProbe"]["outcome"] = "HELPER_RETURNED_READY_CID_NOT_EXPOSED"
            require(durable_barrier(save_state(private / "build-state.json", resource_state)),
                    "DURABLE_RESOURCE_RESULT_REQUIRED")
        except BaseException:
            resource_state["state"] = "RESOURCE_CHECK_FAILED_OR_UNKNOWN_NO_AUTOMATIC_RETRY"
            save_state(private / "build-state.json", resource_state)
            raise
    else:
        resource = helper.resources(private, plan["builderImage"])
    image = json.loads(helper.run("docker", "image", "inspect", plan["builderImage"]).stdout)[0]
    require(image["Id"] == plan["builderImage"] and image["Os"] == "linux" and image["Architecture"] == "amd64", "BUILDER_IDENTITY_CHANGED")
    require(helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}").stdout.strip() == plan["engineId"], "ENGINE_CHANGED_AFTER_RESOURCE_CHECK")
    state = {"state": "BUILD_CREATE_INTENT", "runId": plan["runId"], "preparationSha256": preparation_sha, "resourcesBefore": resource, "releaseQualified": False, "recordingQualified": False}
    intent = private / "build-apply-intent.json"
    if resource_state is None:
        state["intentDurability"] = save_exclusive(intent, state)
    else:
        state.update(intentDurability=resource_state["intentDurability"],
                     buildProfile=profile, resourceProbe=resource_state["resourceProbe"])
    journal = private / "build-state.json"
    journal_barrier = save_state(journal, state)
    if not (durable_barrier(state["intentDurability"]) and durable_barrier(journal_barrier)):
        state["state"] = "BUILD_DURABILITY_BLOCKED_NO_DOCKER_DISPATCH" if resource_state is None else "BUILD_DURABILITY_BLOCKED_NO_COMPILER_DISPATCH"
        save_state(journal, state)
        raise ValueError("DURABLE_INTENT_AND_JOURNAL_REQUIRED")
    try:
        result = helper.run(*build_arguments(plan, profile))
        cid = result.stdout.strip()
        require(re.fullmatch(r"[a-f0-9]{64}", cid), "BUILD_DISPATCH_UNRESOLVED")
        state.update(state="BUILD_RUNNING", containerId=cid)
    except BaseException:
        state["state"] = "BUILD_DISPATCH_UNKNOWN_RECONCILE_EXACT_LABELS"
        save_state(journal, state)
        raise
    save_state(journal, state)
    return state

def finish(prepared_ref, helper, git, profile=None):
    plan = json.loads(read_ref(prepared_ref).read_bytes())
    preparation_sha = prepared_ref["sha256"]
    require(plan.get("executionOperatorSha256") == sha(Path(__file__)), "BUILD_OPERATOR_CHANGED")
    private, _ = verify(plan, git, profile)
    scope = build_scope(profile)
    require(sha(helper.__file__) == REVIEWED_BUILD_HELPER_SHA256, "REVIEWED_SHARED_BUILD_HELPER_CHANGED")
    require(os.environ.get("DOCKER_CONTEXT") == "desktop-linux", "EXPLICIT_DESKTOP_CONTEXT_REQUIRED")
    require(helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}").stdout.strip() == plan["engineId"], "ENGINE_CHANGED")
    state = json.loads((private / "build-state.json").read_bytes())
    require(state["state"] == "BUILD_RUNNING" and state["preparationSha256"] == preparation_sha, "BUILD_OWNERSHIP_UNRESOLVED")
    row = json.loads(helper.run("docker", "inspect", state["containerId"]).stdout)[0]
    require(row["Id"] == state["containerId"] and row["Image"] == plan["builderImage"] and row["Config"]["Labels"]["elevenid.run"] == plan["runId"]
        and row["Config"]["Labels"]["elevenid.owner"] == scope["owner"], "BUILD_OWNER_CHANGED")
    require(row["State"]["Status"] == "exited", "BUILD_STILL_ACTIVE")
    result = {**state, "state": "BUILD_FAILED_RETAINED", "exitCode": row["State"]["ExitCode"], "oomKilled": row["State"].get("OOMKilled", False), "uiRevision": scope["uiRevision"], "coreRevision": CORE_REVISION, "roleBinaries": scope["roles"]}
    if result["exitCode"] == 0 and not result["oomKilled"]:
        output = Path(plan["outputDirectory"])
        require((output / "exit-code").read_text().strip() == "0", "BUILD_RECIPE_OUTCOME_MISSING")
        artifacts = {}
        require((output / "compiler-artifacts.jsonl").stat().st_size <= 64 * 1024 * 1024, "COMPILER_METADATA_TOO_LARGE")
        require((output / "core-compiler-artifacts.json").is_file(), "ACTUAL_CORE_FEATURE_EVIDENCE_MISSING")
        messages = [json.loads(line) for line in (output / "compiler-artifacts.jsonl").read_text().splitlines()]
        for binary in scope["roles"].values():
            file = output / binary
            header = file.open("rb").read(20)
            require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00", "AMD64_ELF_REQUIRED")
            require((output / (binary + ".sha256")).read_text().split()[0] == sha(file), "ELF_COPY_HASH_CHANGED")
            matches = [m for m in messages if m.get("reason") == "compiler-artifact" and m.get("executable") == "/target/debug/" + binary]
            require(len(matches) == 1, "EXACT_COMPILER_OUTPUT_REQUIRED")
            artifacts[binary] = ref(file)
        result.update(state="BUILD_SUCCEEDED", binaries=artifacts, runtimeUidLibrariesValidated=False, coreCompilerArtifacts=ref(output / "core-compiler-artifacts.json"))
    save_exclusive(private / "build-receipt.json", result)
    return result
