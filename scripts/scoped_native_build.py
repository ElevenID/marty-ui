"""Bounded cached native build with closed reviewed output profiles.

The caller supplies the existing hash-bound build helper (resources/run), not a
new daemon transport. Import and verify are read-only. Start is an explicit
mutation entry point requiring a separately reviewed prepared-input digest.
The default passport source, recipe bytes and durability gate remain unchanged.
"""
from __future__ import annotations
import json
import math
import os
from pathlib import Path
import re
import shutil
from contextlib import contextmanager
from scoped_native_runtime import (CORE_REVISION, UI_REVISION, ROLE_BINARIES,
    daemon_source, durable_barrier, read_ref, ref, require, save_exclusive, save_state, selected_sources, sha)

PACKAGES = ("marty-flow", "marty-gateway", "marty-issuance-service")
CARGO_ARGV = ["cargo", "build", "--locked", "--offline", "--message-format=json"] + [item for package in PACKAGES for item in ("-p", package, "--bin", package)]
REVIEWED_BUILD_HELPER_SHA256 = "60f061cc55f6c254ce4b883caa71cf02bdefdded6b581cc004da87fadbce8356"
VOLUMES = ("ui-canvas-cargo", "d05-rust-target-20261026")
OFFICIAL_PROFILE = "oid4vc-all-services"
LATEST_OFFICIAL_PROFILE = "oid4vc-latest-maintenance-all-services"
CURRENT_ISSUER_READY_PROFILE = "current-issuer-ready-two-role"
CURRENT_ISSUER_POLICY_PROFILE = "current-issuer-policy-signing-only"
CURRENT_ISSUER_POLICY_COMPACT_PROFILE = "current-issuer-policy-signing-compact"
CURRENT_ISSUER_POLICY_PROFILES = (CURRENT_ISSUER_POLICY_PROFILE, CURRENT_ISSUER_POLICY_COMPACT_PROFILE)
ISSUANCE_OFFER_PROFILE = "d05-issuance-offer-format-only"
CURRENT_ISSUER_READY_PROFILES = (CURRENT_ISSUER_READY_PROFILE, *CURRENT_ISSUER_POLICY_PROFILES, ISSUANCE_OFFER_PROFILE)
OFFICIAL_PROFILES = (OFFICIAL_PROFILE, LATEST_OFFICIAL_PROFILE)
LATEST_FREEZE_SHA256 = "075a9bafaf27bd31acfe8372c3172e04cf584120882018ff327e71044b69a5c1"
OFFICIAL_FREEZE_SHA256 = "b77d6883f51bc1d3cf19d6cfa76fe567477c7d27e32134e05007c9104e49c941"

def build_scope(profile=None):
    if profile is None:
        return {"uiRevision": UI_REVISION, "coreRevision": CORE_REVISION, "roles": ROLE_BINARIES, "packages": PACKAGES,
                "prefix": "marty-d12-", "owner": "d12-scoped-native", "volumes": VOLUMES,
                "cargoProfile": "dev"}
    from scoped_native_profiles import reviewed_profile
    selected = reviewed_profile(profile)
    return {"uiRevision": selected.ui_revision, "coreRevision": selected.core_revision, "roles": dict(selected.roles),
            "packages": selected.packages, "prefix": selected.container_prefix, "owner": selected.owner,
            "volumes": selected.volumes, "cargoProfile": selected.cargo_profile}


def cargo_arguments(profile=None):
    return ["cargo", "build", "--locked", "--offline", "--message-format=json"] + [
        item for package in build_scope(profile)["packages"] for item in ("-p", package, "--bin", package)]


def artifact_directory(profile=None):
    cargo_profile = build_scope(profile)["cargoProfile"]
    return "debug" if cargo_profile == "dev" else cargo_profile


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
    # Ordinary Windows enumeration can silently omit tracked paths above MAX_PATH.
    # The extended spelling preserves the same path and all link/file-set guards.
    if os.name == "nt" and not str(directory).startswith("\\\\?\\"):
        directory = Path("\\\\?\\" + os.path.abspath(directory))
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


def verify_official_inputs(freeze, seed, source_script, scope, build_tool=None):
    require(freeze["productRevision"] == scope["uiRevision"]
            and freeze["coreRevision"] == CORE_REVISION
            and freeze["imagesBuilt"] is False and freeze["releaseQualified"] is False,
            "EXACT_OFFICIAL_SOURCE_FREEZE_REQUIRED")
    names = set(re.findall(r"--bin (marty-[a-z0-9-]+)", source_script))
    require(len(names) == 29 and names == set(scope["roles"].values()),
            "CANONICAL_ALL_SERVICES_SET_CHANGED")
    if build_tool is not None:
        tool_names = set(re.findall(r"--bin (marty-[a-z0-9-]+)", build_tool))
        require(tool_names == names and len(tool_names) == 29,
                "BUILD_TOOL_BINARY_SET_CHANGED")
    from scoped_native_profiles import LATEST_ALL_SERVICES
    if scope["uiRevision"] == LATEST_ALL_SERVICES.ui_revision:
        from seed_local_official_native_target import validate_cache_reuse
        validate_cache_reuse(seed)
        require(seed["targetVolume"] == scope["volumes"][1], "LATEST_RELEASE_CACHE_CHANGED")
    else:
        require(seed.get("state") == "COPIED_AND_READBACK_MATCHED"
                and seed.get("targetVolume") == scope["volumes"][1]
                and seed.get("sourceTarget") == "marty-demo-native-cache-20261021/target"
                and seed.get("copyKind") == "ordinary-byte-copy-no-hardlinks"
                and re.fullmatch(r"[a-f0-9]{64}", seed.get("sourceManifestSha256", ""))
                and seed["sourceManifestSha256"] == seed.get("targetManifestSha256")
                and seed.get("sourceBeforeAfterMatched") is True
                and seed.get("sourceMountedReadOnly") is True
                and seed.get("targetHardlinksToSource") is False,
                "ISOLATED_TARGET_SEED_REQUIRED")

def verify(plan, git, profile=None):
    selected_sources(plan, profile)
    scope = build_scope(profile)
    private = Path(plan["privateDirectory"]).resolve()
    require(private.is_relative_to(Path.home() / ".codex/private"), "OWNED_PRIVATE_BUILD_ROOT_REQUIRED")
    for name, revision in (("ui", scope["uiRevision"]), ("core", scope["coreRevision"])):
        source = plan["sources"][name]
        require(source["revision"] == revision, "SOURCE_REVISION_CHANGED")
        directory = Path(source["directory"]).resolve()
        require(directory.is_relative_to(private), "EXPORT_OUTSIDE_CUSTODY")
        verify_export(source["repository"], revision, directory, source["inventory"], git)
    if profile in OFFICIAL_PROFILES:
        require(plan["sourceFreezeReceipt"]["sha256"] == (OFFICIAL_FREEZE_SHA256 if profile == OFFICIAL_PROFILE else LATEST_FREEZE_SHA256),
                "EXACT_OFFICIAL_SOURCE_FREEZE_REQUIRED")
        freeze = json.loads(read_ref(plan["sourceFreezeReceipt"]).read_bytes())
        source_script = Path(plan["sources"]["ui"]["directory"]) / "scripts/build-rust-service-binaries.sh"
        cache_key = "targetReuseReceipt" if profile == LATEST_OFFICIAL_PROFILE else "targetSeedReceipt"
        seed = json.loads(read_ref(plan[cache_key]).read_bytes())
        tool = read_ref(plan["buildTool"])
        lock_guard = read_ref(plan["lockGuard"])
        require(sha(tool) == sha(Path(__file__).with_name("build-rust-service-binaries.sh")),
                "EXACT_REVIEWED_BUILD_TOOL_REQUIRED")
        require(sha(lock_guard) == sha(Path(__file__).with_name("ci") / "check_core_localized_lock.py"),
                "EXACT_REVIEWED_LOCK_GUARD_REQUIRED")
        verify_official_inputs(freeze, seed, source_script.read_text(), scope, tool.read_text())
    recipe = read_ref(plan["recipe"])
    exact_recipe_bytes(recipe, profile)
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", plan.get("builderImage", "")), "PINNED_BUILDER_REQUIRED")
    require(re.fullmatch(r"[a-f0-9-]{36}", plan.get("runId", "")), "OWNED_BUILD_RUN_REQUIRED")
    output = Path(plan["outputDirectory"]).resolve()
    require(output.is_relative_to(private) and output.is_dir() and not output.is_symlink(), "OWNED_OUTPUT_REQUIRED")
    return private, output

def exact_recipe_bytes(recipe, profile=None):
    require(recipe.read_bytes() == render_recipe(profile).encode(), "THREE_ROLE_RECIPE_CHANGED")


def render_recipe(profile=None):
    if profile in OFFICIAL_PROFILES:
        return render_official_recipe(profile)
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
""" + ("""set +e
cargo test -p marty-signing-keys --lib current_issuer_validation_tests:: --locked --offline -j1 > /out/focused-rust-test.stdout.txt 2> /out/focused-rust-test.stderr.txt
focused_status=$?
set -e
printf '%s\n' "$focused_status" > /out/focused-rust-test.exit-code
test "$focused_status" -eq 0
""" if profile in CURRENT_ISSUER_POLICY_PROFILES else "") + ("""set +e
cargo test -p marty-issuance-service --lib public_offer_uses_the_same_format_specific_configuration_id_as_application_offers --locked --offline -j1 > /out/issuance-lib-test.stdout.txt 2> /out/issuance-lib-test.stderr.txt
issuance_lib_status=$?
set -e
printf '%s\n' "$issuance_lib_status" > /out/issuance-lib-test.exit-code
test "$issuance_lib_status" -eq 0
set +e
cargo test -p marty-issuance-service --test http_behavior native_offer_transaction_reads_match_the_python_oracle_contract --locked --offline -j1 > /out/issuance-http-test.stdout.txt 2> /out/issuance-http-test.stderr.txt
issuance_http_status=$?
set -e
printf '%s\n' "$issuance_http_status" > /out/issuance-http-test.exit-code
test "$issuance_http_status" -eq 0
""" if profile == ISSUANCE_OFFER_PROFILE else "")


def focused_rust_test_receipt(output, prefix, name, expected_passes):
    stdout = output / (prefix + ".stdout.txt")
    stderr = output / (prefix + ".stderr.txt")
    exit_file = output / (prefix + ".exit-code")
    require(exit_file.is_file() and stdout.is_file() and stderr.is_file()
            and exit_file.read_text().strip() == "0"
            and stdout.stat().st_size <= 1024 * 1024
            and stderr.stat().st_size <= 1024 * 1024
            and f"test result: ok. {expected_passes} passed; 0 failed;" in stdout.read_text(),
            "FOCUSED_SIGNING_POLICY_TEST_REQUIRED")
    return {"name": name, "exitCode": 0, "stdout": ref(stdout), "stderr": ref(stderr)}


def render_official_recipe(profile=OFFICIAL_PROFILE):
    """Compile the frozen canonical 29-bin release set with KMS-only Core proof."""
    require(profile in OFFICIAL_PROFILES, "CLOSED_ALL29_RECIPE_REQUIRED")
    names = tuple(build_scope(profile)["roles"].values())
    return """#!/bin/sh
set -eu
export CARGO_HOME=/cargo CARGO_TARGET_DIR=/target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_NET_OFFLINE=true
finish() { status=$?; printf '%s\\n' "$status" > /out/exit-code; }
trap finish EXIT
rustc -vV > /out/rustc-version.txt
cargo -vV > /out/cargo-version.txt
grep -Fx 'release: 1.95.0' /out/rustc-version.txt
grep -Fx 'host: x86_64-unknown-linux-gnu' /out/rustc-version.txt
mkdir -p /build/ui
cp -a /src/ui/. /build/ui/
cd /build/ui
cp rust/Cargo.lock /out/original-cargo-lock.toml
python3 scripts/localize_marty_core_dependencies.py rust/Cargo.toml .github/feature-regression/rust-probe/Cargo.toml --core-root /build/core > /out/localizer.log
cargo metadata --offline --format-version 1 --manifest-path rust/Cargo.toml > /out/localized-metadata.json
cp rust/Cargo.lock /out/localized-cargo-lock.toml
python3 /build/lock_guard.py /out/original-cargo-lock.toml /out/localized-cargo-lock.toml > /out/localized-lock-proof.json
cargo metadata --offline --locked --format-version 1 --manifest-path rust/Cargo.toml > /out/locked-localized-metadata.json
python3 - <<'BOUNDARY'
import json,pathlib,subprocess,sys
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
services=pathlib.Path('/build/ui/rust/services')
packages=sorted(p['name'] for p in m['packages'] if pathlib.Path(p['manifest_path']).resolve().is_relative_to(services))
assert packages
command=['cargo','tree','--offline','--locked','--manifest-path','rust/Cargo.toml','-e','features,no-dev']
for name in packages:command.extend(['-p',name])
tree=subprocess.run(command,check=True,capture_output=True,text=True).stdout
pathlib.Path('/out/production-feature-tree.txt').write_text(tree)
guard.check_production_crypto_tree(tree)
rows=[{'name':p['name'],'manifest':p['manifest_path'],'features':sorted(nodes[p['id']]['features'])} for p in core]
pathlib.Path('/out/core-feature-resolution.json').write_text(json.dumps(rows,indent=2)+'\\n')
BOUNDARY
cd rust
sh /build/tool.sh default --offline -j1 --message-format=json > /out/compiler-artifacts.jsonl 2> /out/compiler.log
python3 - <<'ARTIFACTS'
import json,pathlib,sys
sys.path.insert(0,'/build/ui/scripts/ci')
import check_marty_core_kms_boundary as guard
m=json.loads(pathlib.Path('/out/localized-metadata.json').read_text())
core={p['id']:p for p in m['packages'] if p['name'] in guard.CORE_CRATES}
expected=set(""" + repr(names) + """)
core_rows=[];services=[]
for line in pathlib.Path('/out/compiler-artifacts.jsonl').read_text().splitlines():
 x=json.loads(line)
 if x.get('reason')!='compiler-artifact':continue
 if x['package_id'] in core:
  p=core[x['package_id']];features=set(x['features']);assert not features&guard.FORBIDDEN_FEATURES
  if p['name'] in guard.KMS_ONLY_CRATES:assert 'kms-only' in features
  core_rows.append({'name':p['name'],'manifest':p['manifest_path'],'features':sorted(features),'fresh':x['fresh'],'filenames':x['filenames']})
 if x.get('executable') in {'/target/release/'+name for name in expected}:services.append(x)
assert 'marty-oid4vci' in {p['name'] for p in core_rows}
assert len(services)==len(expected)==29 and {pathlib.Path(s['executable']).name for s in services}==expected
pathlib.Path('/out/core-compiler-artifacts.json').write_text(json.dumps(core_rows,indent=2)+'\\n')
pathlib.Path('/out/service-compiler-artifacts.json').write_text(json.dumps(services,indent=2)+'\\n')
ARTIFACTS
for binary in """ + " ".join(names) + """; do
 install -m 0755 /target/release/$binary /out/$binary
 sha256sum /out/$binary > /out/$binary.sha256
 readelf -h -d /out/$binary > /out/$binary.elf.txt
 ldd /out/$binary > /out/$binary.libraries.txt
done
"""

def current_issuer_limits(profile):
    require(profile in CURRENT_ISSUER_READY_PROFILES, "CURRENT_ISSUER_PROFILE_REQUIRED")
    if profile == CURRENT_ISSUER_POLICY_COMPACT_PROFILE:
        return "1536m", 1536 * 1024 ** 2, 1536 * 1024 + math.ceil(1.1 * 1024 * 1024)
    if profile == ISSUANCE_OFFER_PROFILE:
        return "3g", 3 * 1024 ** 3, int(4.1 * 1024 * 1024)
    return "2g", 2 * 1024 ** 3, int(3.1 * 1024 * 1024)


def build_arguments(plan, profile=None):
    selected_sources(plan, profile)
    scope = build_scope(profile)
    require(re.fullmatch(re.escape(scope["prefix"]) + r"[a-f0-9-]{36}", plan.get("containerName", "")) and plan["containerName"] == scope["prefix"] + plan["runId"], "RUN_BOUND_CONTAINER_NAME_REQUIRED")
    memory = current_issuer_limits(profile)[0] if profile in CURRENT_ISSUER_READY_PROFILES else "2g"
    args = ["docker", "--context", "desktop-linux", "run", "--detach", "--pull", "never", "--network", "none", "--name", plan["containerName"],
        "--cpus", "1", "--memory", memory, "--memory-swap", memory if profile in CURRENT_ISSUER_READY_PROFILES else "4g",
        "--label", "elevenid.owner=" + scope["owner"],
        "--label", "elevenid.run=" + plan["runId"]]
    if profile in CURRENT_ISSUER_READY_PROFILES:
        args += ["--pids-limit", "64", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    for source, target, readonly in ((plan["sources"]["ui"]["directory"], "/src/ui", True), (plan["sources"]["core"]["directory"], "/build/core", True),
            (plan["outputDirectory"], "/out", False), (plan["recipe"]["path"], "/build.sh", True)):
        args += ["--mount", "type=bind,src=" + daemon_source(source) + ",dst=" + target + (",readonly" if readonly else "")]
    if profile in OFFICIAL_PROFILES:
        args += ["--mount", "type=bind,src=" + daemon_source(plan["buildTool"]["path"])
                 + ",dst=/build/tool.sh,readonly"]
        args += ["--mount", "type=bind,src=" + daemon_source(plan["lockGuard"]["path"])
                 + ",dst=/build/lock_guard.py,readonly"]
    for volume, target in zip(scope["volumes"], ("/cargo", "/target")):
        args += ["--mount", "type=volume,src=" + volume + ",dst=" + target]
    return args + ["--entrypoint", "/bin/sh", plan["builderImage"], "/build.sh"]

def current_issuer_capacity(helper, private, profile=CURRENT_ISSUER_READY_PROFILE):
    host_kib = int(helper.run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                              "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory").stdout.strip())
    require(host_kib >= current_issuer_limits(profile)[2], "CURRENT_ISSUER_HOST_HEADROOM_REQUIRED")
    require(shutil.disk_usage(private).free >= 8 * 1024 ** 3, "CURRENT_ISSUER_DISK_HEADROOM_REQUIRED")
    return host_kib

def current_issuer_created_identity(helper, plan, cid, expected_status="created", profile=CURRENT_ISSUER_READY_PROFILE):
    row = json.loads(helper.run("docker", "inspect", cid).stdout)[0]
    host = row["HostConfig"]
    require(row["Id"] == cid and row["Image"] == plan["builderImage"]
            and row["Name"] == "/" + plan["containerName"]
            and row["State"]["Status"] == expected_status
            and row["Config"]["Entrypoint"] == ["/bin/sh"]
            and row["Config"]["Cmd"] == ["/build.sh"]
            and row["Config"]["Labels"]["elevenid.owner"] == "current-issuer-ready-native"
            and row["Config"]["Labels"]["elevenid.run"] == plan["runId"],
            "CURRENT_ISSUER_CREATED_IDENTITY_CHANGED")
    require(host["Memory"] == host["MemorySwap"] == current_issuer_limits(profile)[1]
            and host["PidsLimit"] == 64 and host["NetworkMode"] == "none"
            and host["Privileged"] is False and "ALL" in host["CapDrop"]
            and "no-new-privileges" in host["SecurityOpt"],
            "CURRENT_ISSUER_CREATED_LIMITS_CHANGED")
    require(host["NanoCpus"] == 10 ** 9 or host["CpuQuota"] == host["CpuPeriod"] > 0,
            "CURRENT_ISSUER_CREATED_CPU_CHANGED")
    mounts = {m["Destination"]: m for m in row["Mounts"]}
    require(len(row["Mounts"]) == len(mounts) == 6
            and set(mounts) == {"/src/ui", "/build/core", "/out", "/build.sh", "/cargo", "/target"},
            "CURRENT_ISSUER_CREATED_MOUNTS_CHANGED")
    require(all(mounts[name]["Type"] == "bind" and mounts[name]["RW"] is False
                for name in ("/src/ui", "/build/core", "/build.sh"))
            and mounts["/out"]["Type"] == "bind" and mounts["/out"]["RW"] is True
            and all(daemon_source(mounts[d]["Source"]) == daemon_source(p)
                    for d, p in (("/src/ui", plan["sources"]["ui"]["directory"]),
                                 ("/build/core", plan["sources"]["core"]["directory"]),
                                 ("/out", plan["outputDirectory"]),
                                 ("/build.sh", plan["recipe"]["path"])))
            and mounts["/cargo"]["Type"] == mounts["/target"]["Type"] == "volume"
            and mounts["/cargo"]["Name"] == "ui-canvas-cargo"
            and mounts["/target"]["Name"] == "d05-rust-target-20261026",
            "CURRENT_ISSUER_CREATED_MOUNTS_CHANGED")
    return row

class LocalBuildJournal:
    def __init__(self, private):
        self.private = private

    def exclusive(self, name, value):
        return save_exclusive(self.private / name, value)

    def state(self, value):
        return save_state(self.private / "build-state.json", value)

    def read(self, name):
        return json.loads((self.private / name).read_bytes())


def build_journal(plan, private, profile=None):
    if "journalBackend" not in plan:
        return LocalBuildJournal(private)
    require(profile in ("d02-signing-cas", "d02-signing-cas-no-transform", *CURRENT_ISSUER_READY_PROFILES,
                        "canvas-issuer-scoped-jobs", "d12-passport-current-three-role", *OFFICIAL_PROFILES),
            "LINUX_JOURNAL_REVIEWED_PROFILE_REQUIRED")
    from scoped_linux_journal import LinuxBuildJournal
    return LinuxBuildJournal(private, plan["runId"], plan["journalBackend"])


def require_d12_fresh_target(plan, helper):
    """Refuse Docker's implicit volume creation or reuse for the new D12 build."""
    from scoped_native_profiles import D12_PASSPORT_CURRENT
    volume = D12_PASSPORT_CURRENT.volumes[1]
    proof = json.loads(read_ref(plan["targetVolumeReceipt"]).read_bytes())
    require(proof.get("state") == "CREATED_EMPTY_OWNED_TARGET"
            and proof.get("volume") == volume
            and proof.get("runId") == plan["runId"]
            and proof.get("engineId") == plan["engineId"]
            and proof.get("owner") == D12_PASSPORT_CURRENT.owner
            and proof.get("emptyReadback") is True
            and proof.get("sourceIndependent") is True
            and proof.get("consumers") == [], "D12_FRESH_OWNED_TARGET_REQUIRED")
    rows = json.loads(helper.run("docker", "--context", "desktop-linux", "volume", "inspect", volume).stdout)
    require(len(rows) == 1 and rows[0]["Name"] == volume
            and rows[0]["Driver"] == rows[0]["Scope"] == "local"
            and rows[0]["CreatedAt"] == proof["createdAt"]
            and rows[0]["Labels"].get("elevenid.owner") == D12_PASSPORT_CURRENT.owner
            and rows[0]["Labels"].get("elevenid.run") == plan["runId"],
            "D12_OWNED_TARGET_CHANGED")
    consumers = helper.run("docker", "--context", "desktop-linux", "ps", "--all", "--quiet",
                           "--filter", "volume=" + volume).stdout.strip()
    require(not consumers, "D12_TARGET_ALREADY_CONSUMED")


@contextmanager
def selected_resource_volumes(helper, volumes):
    """Use the reviewed resource probe on one closed volume pair, then restore it."""
    require(helper.VOLUMES == VOLUMES, "SHARED_RESOURCE_SCOPE_CHANGED")
    try:
        helper.VOLUMES = volumes
        yield
    finally:
        helper.VOLUMES = VOLUMES


def start(prepared_ref, helper, git, profile=None):
    plan = json.loads(read_ref(prepared_ref).read_bytes())
    preparation_sha = prepared_ref["sha256"]
    require(plan.get("executionOperatorSha256") == sha(Path(__file__)), "BUILD_OPERATOR_CHANGED")
    private, output = verify(plan, git, profile)
    store = build_journal(plan, private, profile)
    require(sha(helper.__file__) == REVIEWED_BUILD_HELPER_SHA256, "REVIEWED_SHARED_BUILD_HELPER_CHANGED")
    require(os.environ.get("DOCKER_CONTEXT") == "desktop-linux", "EXPLICIT_DESKTOP_CONTEXT_REQUIRED")
    require(not list(output.iterdir()), "PRESERVE_PREVIOUS_BUILD_OUTPUTS")
    require(helper.VOLUMES == VOLUMES, "SHARED_RESOURCE_SCOPE_CHANGED")
    if profile == "d12-passport-current-three-role":
        require_d12_fresh_target(plan, helper)
    if profile in CURRENT_ISSUER_READY_PROFILES:
        current_issuer_capacity(helper, private, profile)
    require(helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}").stdout.strip() == plan["engineId"], "ENGINE_CHANGED")
    if profile in OFFICIAL_PROFILES:
        volume = build_scope(profile)["volumes"][1]
        rows = json.loads(helper.run("docker", "volume", "inspect", volume).stdout)
        require(len(rows) == 1 and rows[0]["Name"] == volume
                and rows[0]["Labels"].get("io.elevenid.demo-audit.owner")
                == "root-local-oid4vc-current-source-20261028",
                "OWNED_SEEDED_TARGET_VOLUME_MISSING")
    resource_state = None
    if profile is not None:
        # The existing resource helper itself creates one 64 MiB read-only probe.
        # Consume this D02 attempt before that effect, not only before compilation.
        image = json.loads(helper.run("docker", "image", "inspect", plan["builderImage"]).stdout)[0]
        require(image["Id"] == plan["builderImage"] and image["Os"] == "linux" and image["Architecture"] == "amd64", "BUILDER_IDENTITY_CHANGED")
        resource_state = {"state": "RESOURCE_CHECK_INTENT", "runId": plan["runId"],
                          "preparationSha256": preparation_sha, "buildProfile": profile,
                          "resourceProbe": {"effect": "EXISTING_64M_READONLY_NETWORK_NONE_DOCKER_PROBE",
                                            "image": plan["builderImage"], "volumes": list(build_scope(profile)["volumes"]),
                                            "containerId": None, "outcome": "INTENT_DISPATCH_MAY_FOLLOW"},
                          "releaseQualified": False, "recordingQualified": False}
        if profile in OFFICIAL_PROFILES:
            cache_prefix = "targetReuse" if profile == LATEST_OFFICIAL_PROFILE else "targetSeed"
            resource_state[cache_prefix + "Probe"] = {
                "effect": "EXISTING_READONLY_NETWORK_NONE_TARGET_MANIFEST_PROBE",
                "volume": build_scope(profile)["volumes"][1], "outcome": "INTENT_DISPATCH_MAY_FOLLOW"}
        resource_state["intentDurability"] = store.exclusive("build-apply-intent.json", resource_state)
        barrier = store.state(resource_state)
        if not (durable_barrier(resource_state["intentDurability"]) and durable_barrier(barrier)):
            resource_state["state"] = "BUILD_DURABILITY_BLOCKED_NO_DOCKER_DISPATCH"
            resource_state["resourceProbe"]["outcome"] = "NOT_DISPATCHED"
            store.state(resource_state)
            raise ValueError("DURABLE_INTENT_AND_JOURNAL_REQUIRED")
        try:
            if profile in OFFICIAL_PROFILES:
                from seed_local_official_native_target import inspect_target, inspect_reuse_target
                cache_prefix = "targetReuse" if profile == LATEST_OFFICIAL_PROFILE else "targetSeed"
                reader = inspect_reuse_target if profile == LATEST_OFFICIAL_PROFILE else inspect_target
                resource_state[cache_prefix + "Readback"] = reader(Path(plan[cache_prefix + "Receipt"]["path"]))
                resource_state[cache_prefix + "Probe"]["outcome"] = "READBACK_MATCHED"
                require(durable_barrier(store.state(resource_state)),
                        "DURABLE_TARGET_SEED_RESULT_REQUIRED")
            with selected_resource_volumes(helper, build_scope(profile)["volumes"]):
                resource = helper.resources(private, plan["builderImage"])
            if profile == "d12-passport-current-three-role":
                require_d12_fresh_target(plan, helper)
            resource_state.update(state="RESOURCE_CHECK_READY", resourcesBefore=resource)
            resource_state["resourceProbe"]["outcome"] = "HELPER_RETURNED_READY_CID_NOT_EXPOSED"
            require(durable_barrier(store.state(resource_state)),
                    "DURABLE_RESOURCE_RESULT_REQUIRED")
        except BaseException:
            resource_state["state"] = "RESOURCE_CHECK_FAILED_OR_UNKNOWN_NO_AUTOMATIC_RETRY"
            store.state(resource_state)
            raise
    else:
        with selected_resource_volumes(helper, build_scope(profile)["volumes"]):
            resource = helper.resources(private, plan["builderImage"])
    image = json.loads(helper.run("docker", "image", "inspect", plan["builderImage"]).stdout)[0]
    require(image["Id"] == plan["builderImage"] and image["Os"] == "linux" and image["Architecture"] == "amd64", "BUILDER_IDENTITY_CHANGED")
    require(helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}").stdout.strip() == plan["engineId"], "ENGINE_CHANGED_AFTER_RESOURCE_CHECK")
    if profile in CURRENT_ISSUER_READY_PROFILES:
        current_issuer_capacity(helper, private, profile)
    state = {"state": "BUILD_CREATE_INTENT", "runId": plan["runId"], "preparationSha256": preparation_sha, "resourcesBefore": resource, "releaseQualified": False, "recordingQualified": False}
    if resource_state is None:
        state["intentDurability"] = store.exclusive("build-apply-intent.json", state)
    else:
        state.update(intentDurability=resource_state["intentDurability"],
                     buildProfile=profile, resourceProbe=resource_state["resourceProbe"])
        if profile in OFFICIAL_PROFILES:
            cache_prefix = "targetReuse" if profile == LATEST_OFFICIAL_PROFILE else "targetSeed"
            state.update({key: resource_state[key] for key in (cache_prefix + "Probe", cache_prefix + "Readback")})
    journal_barrier = store.state(state)
    if not (durable_barrier(state["intentDurability"]) and durable_barrier(journal_barrier)):
        state["state"] = "BUILD_DURABILITY_BLOCKED_NO_DOCKER_DISPATCH" if resource_state is None else "BUILD_DURABILITY_BLOCKED_NO_COMPILER_DISPATCH"
        store.state(state)
        raise ValueError("DURABLE_INTENT_AND_JOURNAL_REQUIRED")
    try:
        args = build_arguments(plan, profile)
        if profile in CURRENT_ISSUER_READY_PROFILES:
            require(args[3:5] == ["run", "--detach"], "BUILD_ARGUMENTS_CHANGED")
            args = args[:3] + ["create"] + args[5:]
        result = helper.run(*args)
        cid = result.stdout.strip()
        require(re.fullmatch(r"[a-f0-9]{64}", cid), "BUILD_DISPATCH_UNRESOLVED")
        state.update(state="BUILD_CREATED" if profile in CURRENT_ISSUER_READY_PROFILES else "BUILD_RUNNING", containerId=cid)
        if profile in CURRENT_ISSUER_READY_PROFILES:
            require(durable_barrier(store.state(state)), "BUILD_CREATED_JOURNAL_REQUIRED")
            current_issuer_created_identity(helper, plan, cid, profile=profile)
            current_issuer_capacity(helper, private, profile)
            state["state"] = "BUILD_START_INTENT"
            require(durable_barrier(store.state(state)), "BUILD_START_INTENT_JOURNAL_REQUIRED")
            require(helper.run("docker", "start", cid).stdout.strip() == cid, "BUILD_START_ACK_CHANGED")
            state["state"] = "BUILD_RUNNING"
    except BaseException:
        state["state"] = "BUILD_DISPATCH_UNKNOWN_RECONCILE_EXACT_LABELS"
        store.state(state)
        raise
    store.state(state)
    return state

def finish(prepared_ref, helper, git, profile=None):
    plan = json.loads(read_ref(prepared_ref).read_bytes())
    preparation_sha = prepared_ref["sha256"]
    require(plan.get("executionOperatorSha256") == sha(Path(__file__)), "BUILD_OPERATOR_CHANGED")
    private, _ = verify(plan, git, profile)
    store = build_journal(plan, private, profile)
    scope = build_scope(profile)
    require(sha(helper.__file__) == REVIEWED_BUILD_HELPER_SHA256, "REVIEWED_SHARED_BUILD_HELPER_CHANGED")
    require(os.environ.get("DOCKER_CONTEXT") == "desktop-linux", "EXPLICIT_DESKTOP_CONTEXT_REQUIRED")
    require(helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}").stdout.strip() == plan["engineId"], "ENGINE_CHANGED")
    state = store.read("build-state.json")
    require(state["state"] == "BUILD_RUNNING" and state["preparationSha256"] == preparation_sha, "BUILD_OWNERSHIP_UNRESOLVED")
    row = json.loads(helper.run("docker", "inspect", state["containerId"]).stdout)[0]
    require(row["Id"] == state["containerId"] and row["Image"] == plan["builderImage"] and row["Config"]["Labels"]["elevenid.run"] == plan["runId"]
        and row["Config"]["Labels"]["elevenid.owner"] == scope["owner"], "BUILD_OWNER_CHANGED")
    require(row["State"]["Status"] == "exited", "BUILD_STILL_ACTIVE")
    if profile in CURRENT_ISSUER_READY_PROFILES:
        current_issuer_created_identity(helper, plan, state["containerId"], "exited", profile=profile)
    if profile in OFFICIAL_PROFILES:
        mounts = {mount["Destination"]: mount for mount in row["Mounts"]}
        for destination, volume in zip(("/cargo", "/target"), scope["volumes"]):
            require(mounts[destination]["Type"] == "volume" and mounts[destination]["Name"] == volume,
                    "OFFICIAL_COMPILER_VOLUME_CHANGED")
        require(all(mounts[d]["RW"] is False for d in ("/src/ui", "/build/core", "/build.sh", "/build/tool.sh", "/build/lock_guard.py")),
                "OFFICIAL_SOURCE_MOUNT_CHANGED")
    if profile == "d12-passport-current-three-role":
        mounts = {mount["Destination"]: mount for mount in row["Mounts"]}
        require(len(mounts) == len(row["Mounts"]) == 6
                and set(mounts) == {"/src/ui", "/build/core", "/out", "/build.sh", "/cargo", "/target"}
                and mounts["/cargo"]["Type"] == mounts["/target"]["Type"] == "volume"
                and mounts["/cargo"]["Name"] == scope["volumes"][0]
                and mounts["/target"]["Name"] == scope["volumes"][1]
                and all(mounts[d]["Type"] == "bind" and mounts[d]["RW"] is False
                        for d in ("/src/ui", "/build/core", "/build.sh"))
                and mounts["/out"]["Type"] == "bind" and mounts["/out"]["RW"] is True
                and all(daemon_source(mounts[d]["Source"]) == daemon_source(p)
                        for d, p in (("/src/ui", plan["sources"]["ui"]["directory"]),
                                     ("/build/core", plan["sources"]["core"]["directory"]),
                                     ("/out", plan["outputDirectory"]),
                                     ("/build.sh", plan["recipe"]["path"])))
                and row["Name"] == "/" + plan["containerName"]
                and row["Config"]["Entrypoint"] == ["/bin/sh"]
                and row["Config"]["Cmd"] == ["/build.sh"]
                and row["HostConfig"]["NetworkMode"] == "none"
                and row["HostConfig"]["Memory"] == 2 * 1024 ** 3
                and row["HostConfig"]["MemorySwap"] == 4 * 1024 ** 3,
                "D12_COMPILER_MOUNTS_CHANGED")
    result = {**state, "state": "BUILD_FAILED_RETAINED", "exitCode": row["State"]["ExitCode"], "oomKilled": row["State"].get("OOMKilled", False), "uiRevision": scope["uiRevision"], "coreRevision": scope["coreRevision"], "roleBinaries": scope["roles"]}
    if result["exitCode"] == 0 and not result["oomKilled"]:
        output = Path(plan["outputDirectory"])
        require((output / "exit-code").read_text().strip() == "0", "BUILD_RECIPE_OUTCOME_MISSING")
        artifacts = {}
        if profile in OFFICIAL_PROFILES:
            require((output / "core-feature-resolution.json").is_file()
                    and (output / "production-feature-tree.txt").is_file()
                    and (output / "original-cargo-lock.toml").is_file()
                    and (output / "localized-cargo-lock.toml").is_file()
                    and (output / "locked-localized-metadata.json").is_file()
                    and (output / "compiler.log").is_file()
                    and (output / "localized-lock-proof.json").is_file(),
                    "ACTUAL_CORE_FEATURE_EVIDENCE_MISSING")
        require((output / "compiler-artifacts.jsonl").stat().st_size <= 64 * 1024 * 1024,
                "COMPILER_METADATA_TOO_LARGE")
        require((output / "core-compiler-artifacts.json").is_file(), "ACTUAL_CORE_FEATURE_EVIDENCE_MISSING")
        messages = [json.loads(line) for line in (output / "compiler-artifacts.jsonl").read_text().splitlines()]
        for binary in scope["roles"].values():
            file = output / binary
            header = file.open("rb").read(20)
            require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00", "AMD64_ELF_REQUIRED")
            require((output / (binary + ".sha256")).read_text().split()[0] == sha(file), "ELF_COPY_HASH_CHANGED")
            target_profile = artifact_directory(profile)
            matches = [m for m in messages if m.get("reason") == "compiler-artifact"
                       and m.get("executable") == "/target/" + target_profile + "/" + binary]
            require(len(matches) == 1, "EXACT_COMPILER_OUTPUT_REQUIRED")
            artifacts[binary] = ref(file)
        result.update(state="BUILD_SUCCEEDED", binaries=artifacts, runtimeUidLibrariesValidated=False)
        if profile in CURRENT_ISSUER_POLICY_PROFILES:
            result["focusedRustTest"] = focused_rust_test_receipt(
                output, "focused-rust-test", "current_issuer_validation_tests::", 4)
        if profile == ISSUANCE_OFFER_PROFILE:
            result["focusedRustTests"] = [
                focused_rust_test_receipt(output, "issuance-lib-test",
                    "public_offer_uses_the_same_format_specific_configuration_id_as_application_offers", 1),
                focused_rust_test_receipt(output, "issuance-http-test",
                    "native_offer_transaction_reads_match_the_python_oracle_contract", 1),
            ]
        if profile in OFFICIAL_PROFILES:
            require(len(artifacts) == 29, "OFFICIAL_NATIVE_BINARY_COVERAGE_CHANGED")
            result.update(state="PASSED", source=scope["uiRevision"], canonicalAllServices=True,
                          imagesBuilt=False, releaseQualified=False,
                          originalCargoLock=ref(output / "original-cargo-lock.toml"),
                          localizedCargoLock=ref(output / "localized-cargo-lock.toml"),
                          localizedLockProof=ref(output / "localized-lock-proof.json"),
                          lockedLocalizedMetadata=ref(output / "locked-localized-metadata.json"),
                          coreFeatureResolution=ref(output / "core-feature-resolution.json"),
                          productionFeatureTree=ref(output / "production-feature-tree.txt"),
                          canonicalCompilerLog=ref(output / "compiler.log"))
        result["coreCompilerArtifacts"] = ref(output / "core-compiler-artifacts.json")
    store.exclusive("build-receipt.json", result)
    return result
