#!/usr/bin/env python3
"""Bind a local official lane to reviewed source-built binaries and shared KMS setup.

This adapter reuses the audited local lane driver. It does not build or publish
images, change official tests, or qualify a release. The supplied native binary
and plugin receipts must be produced separately from the selected source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
LANES = {"oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi"}
BASELINE_IMAGE_SOURCE = "4edd631c8c908d74f82330cc3232bcc08b6b453f"
AUDITED_DRIVER_SHA256 = "b62c65918cf3cd37df8c7dd44664822cbc5f70494986ade5870b0d47bde67a84"
NATIVE_HELPER_SHA256 = "28f472694efec4e5fa994e96877c76b73bc51ac4f77d44ef372bd5af7ddaaa34"
UI_HELPER_SHA256 = "b641ec7a03100f9e4d5cf66009d2e07fb876239f7bd6d6fb75445a83b3d8a3c6"
EUDI_HELPER_SHA256 = "3182b7bb10bb6a77bb924f0122a84dfe0f4137a77a54a2d813dd56e309008c0f"
CORE_CRATES = ("marty-crypto", "marty-didcomm", "marty-oid4vci", "marty-verification")


def fail(message: str) -> None:
    raise ValueError(message)


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"expected JSON object: {path}")
    return value


def exact_file(path: Path, expected: str) -> None:
    if not SHA256.fullmatch(expected) or not path.is_file() or path.is_symlink():
        fail(f"missing or invalid pinned file: {path}")
    if sha256(path) != expected:
        fail(f"pinned file changed: {path}")


def check(plan: dict) -> dict:
    """Validate source and ownership before even checking the runtime handle."""
    lane, run_id, tag = (plan[name] for name in ("lane", "runId", "tag"))
    if lane not in LANES or not re.fullmatch(r"local-[a-z0-9][a-z0-9-]{1,40}[a-z0-9]", run_id):
        fail("invalid official lane or run ID")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,60}[a-z0-9]", tag):
        fail("invalid unique evidence tag")
    if plan.get("imagesBuilt") is not False or plan.get("releaseQualified") is not False:
        fail("this runner accepts local-only, no-image-build inputs")
    product = Path(plan["productCheckout"]).resolve(strict=True)
    harness = Path(plan["harnessRepository"]).resolve(strict=True)
    product_sha, harness_sha = plan["productRevision"], plan["harnessRevision"]
    if not SHA.fullmatch(product_sha) or not SHA.fullmatch(harness_sha):
        fail("source revisions must be full Git commits")
    if (git(product, "rev-parse", "HEAD") != product_sha
            or git(product, "status", "--porcelain", "--untracked-files=all")):
        fail("product checkout must be clean at the exact selected revision")
    if git(product, "rev-parse", "HEAD^{tree}") != plan["productTree"]:
        fail("product tree changed from the selected source packet")
    if (git(product, "rev-parse", "origin/main") != product_sha
            or git(product, "ls-remote", "origin", "refs/heads/main").split()[0] != product_sha):
        fail("selected product source is not the fetched protected main")
    if git(harness, "cat-file", "-t", harness_sha) != "commit":
        fail("selected harness commit is unavailable")
    if (git(harness, "rev-parse", "origin/main") != harness_sha
            or git(harness, "ls-remote", "origin", "refs/heads/main").split()[0] != harness_sha):
        fail("selected harness source is not the fetched protected main")

    cargo = tomllib.loads((product / "rust/Cargo.toml").read_text(encoding="utf-8"))
    deps = cargo["workspace"]["dependencies"]
    core = plan["coreRevision"]
    if not SHA.fullmatch(core):
        fail("Core revision must be a full commit")
    for crate in CORE_CRATES:
        row = deps[crate]
        if row.get("git") != "https://github.com/ElevenID/marty-core" or row.get("rev") != core:
            fail(f"{crate} does not match selected Core source")
        if "kms-only" not in row.get("features", ()) or row.get("default-features") is not False:
            fail(f"{crate} is not configured KMS-only")
    lock = (product / "rust/Cargo.lock").read_text(encoding="utf-8")
    if f"?rev={core}#{core}" not in lock:
        fail("Core lockfile does not contain the selected exact source")

    pinned_runner = json.loads(git(harness, "show", f"{harness_sha}:conformance/oidf-runner.json"))
    official = pinned_runner["official_runner"]
    if (official.get("source_policy") != "unmodified"
            or official.get("commit") != plan["officialRunnerRevision"]):
        fail("official runner is not the harness's unmodified pinned source")
    w3c = json.loads(git(harness, "show", f"{harness_sha}:conformance/w3c-vc-data-model-v2.json"))
    w3c_source = w3c["official_suite"]
    if (w3c_source.get("source_policy") != "unmodified"
            or w3c_source.get("commit") != plan["w3cSuiteRevision"]):
        fail("W3C suite is not the harness's unmodified pinned source")
    eudi = json.loads(git(harness, "show", f"{harness_sha}:conformance/eudi-reference-interop.json"))
    if (eudi.get("components", {}).get("verifier_endpoint", {}).get("commit")
            != plan["eudiVerifierRevision"]):
        fail("EUDI verifier source is not the harness's pinned source")

    plugin_path = Path(plan["kmsPluginReceipt"]).resolve(strict=True)
    native_path = Path(plan["nativeServicesReceipt"]).resolve(strict=True)
    build_path = Path(plan["nativeBuildReceipt"]).resolve(strict=True)
    ui_path = Path(plan["nativeUiReceipt"]).resolve(strict=True)
    eudi_path = Path(plan["nativeEudiReceipt"]).resolve(strict=True) if lane == "eudi" else None
    for path, field in ((plugin_path, "kmsPluginReceiptSha256"),
                        (native_path, "nativeServicesReceiptSha256"),
                        (build_path, "nativeBuildReceiptSha256"),
                        (ui_path, "nativeUiReceiptSha256")):
        exact_file(path, plan[field])
    if eudi_path:
        exact_file(eudi_path, plan["nativeEudiReceiptSha256"])
    plugin, native, build, ui = load(plugin_path), load(native_path), load(build_path), load(ui_path)
    if (plugin.get("source") != product_sha
            or plan["kmsPluginRevision"] != product_sha
            or plugin.get("state") != "PASSED" or plugin.get("imagesBuilt") is not False):
        fail("KMS plugin is not built from the selected product source without an image")
    if (native.get("source") != product_sha or native.get("state") != "PASSED"
            or native.get("imagesBuilt") is not False or native.get("linuxReadbackMatched") is not True):
        fail("native service binary receipt is not bound to current product source")
    if (native.get("buildReceipt") != build_path.name or build.get("source") != product_sha
            or build.get("state") != "PASSED" or build.get("exitCode") != 0
            or build.get("canonicalAllServices") is not True or build.get("imagesBuilt") is not False):
        fail("all-role native source build is not proved by the selected receipt")
    expected_bins = set(re.findall(r"--bin (marty-[a-z0-9-]+)",
                                   (product / "scripts/build-rust-service-binaries.sh").read_text()))
    actual_bins = {item["binary_name"] for item in native["files"]}
    if not expected_bins or expected_bins != actual_bins or len(native["files"]) != len(actual_bins):
        fail("native source-built binary coverage is incomplete")
    for item in native["files"]:
        if not SHA256.fullmatch(item["sha256"]) or not item["linuxPath"].endswith("/" + item["binary_name"]):
            fail("invalid native service binary receipt")
    if not SHA256.fullmatch(plugin.get("sha256", "")):
        fail("invalid native plugin digest")
    if (ui.get("source") != product_sha or ui.get("state") != "PASSED"
            or ui.get("imagesBuilt") is not False or ui.get("releaseQualified") is not False
            or ui.get("linuxReadbackMatched") is not True):
        fail("static UI receipt is not built from selected product source")
    if eudi_path:
        eudi_build = load(eudi_path)
        if (eudi_build.get("source") != harness_sha or eudi_build.get("state") != "PASSED"
                or eudi_build.get("exitCode") != 0
                or eudi_build.get("sourceReadbackMatched") is not True
                or not isinstance(eudi_build.get("distFiles"), dict)
                or "bin/eudi-wallet-harness" not in eudi_build["distFiles"]):
            fail("EUDI facade is not source-built from the selected unmodified harness")

    driver = Path(plan["auditedLaneDriver"]).resolve(strict=True)
    helper = Path(plan["nativeServicesHelper"]).resolve(strict=True)
    ui_helper = Path(plan["nativeUiHelper"]).resolve(strict=True)
    eudi_helper = Path(plan["nativeEudiHelper"]).resolve(strict=True) if eudi_path else None
    if (plan["auditedLaneDriverSha256"] != AUDITED_DRIVER_SHA256
            or plan["nativeServicesHelperSha256"] != NATIVE_HELPER_SHA256
            or plan["nativeUiHelperSha256"] != UI_HELPER_SHA256):
        fail("reviewed local driver or helper pin changed")
    exact_file(driver, plan["auditedLaneDriverSha256"])
    exact_file(helper, plan["nativeServicesHelperSha256"])
    exact_file(ui_helper, plan["nativeUiHelperSha256"])
    if eudi_helper:
        if plan["nativeEudiHelperSha256"] != EUDI_HELPER_SHA256:
            fail("reviewed EUDI helper pin changed")
        exact_file(eudi_helper, EUDI_HELPER_SHA256)
    if BASELINE_IMAGE_SOURCE not in driver.read_text(encoding="utf-8"):
        fail("audited local driver no longer identifies its immutable image baseline")
    return {"productRevision": product_sha, "harnessRevision": harness_sha,
            "coreRevision": core, "kmsPluginRevision": plugin["source"],
            "officialRunnerRevision": official["commit"], "officialRunnerRelease": official["release"],
            "w3cSuiteRevision": w3c_source["commit"],
            "eudiVerifierRevision": plan["eudiVerifierRevision"],
            "baselineImageSource": BASELINE_IMAGE_SOURCE, "nativeBinaryCount": len(actual_bins),
            "imagesBuilt": False, "releaseQualified": False}


def dispatch(plan: dict) -> int:
    """Run only with a freshly reviewed, existing owned local-tooling container."""
    container = plan["ownedToolContainer"]
    if not re.fullmatch(r"marty-oid4vc-local-[a-z0-9-]+-runner", container):
        fail("invalid owned tooling container name")
    row = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
    if not row["State"]["Running"] or row["Config"]["Labels"].get(
            "io.elevenid.demo-audit.owner") != plan["ownedToolOwner"]:
        fail("owned local tooling container is absent or changed")
    base = plan["linuxBase"]
    if not base.startswith("/var/lib/docker/volumes/marty-oid4vc-local-") or not base.endswith("/_data"):
        fail("invalid owned local tooling base")
    mounts = row["Mounts"]
    if not any(m["Destination"] == base and m["Type"] == "volume" for m in mounts):
        fail("tooling container does not mount the selected owned volume")
    for name, digest in (("stack/stack-manifest.json", plan["baselineManifestSha256"]),
                         ("stack/.env.stack", plan["baselineStackEnvSha256"])):
        if not SHA256.fullmatch(digest):
            fail("invalid pinned immutable image baseline digest")
        observed = subprocess.check_output(["docker", "exec", container, "sha256sum",
                                            f"{base}/{name}"], text=True).split()[0]
        if observed != digest:
            fail("immutable image baseline changed")
    for receipt in (load(Path(plan["kmsPluginReceipt"])),
                    *load(Path(plan["nativeServicesReceipt"]))["files"]):
        path = receipt["linuxPath"]
        if not path.startswith(base + "/"):
            fail("native executable is outside owned local tooling volume")
        observed = subprocess.check_output(["docker", "exec", container, "sha256sum", path],
                                           text=True).split()[0]
        if observed != receipt["sha256"]:
            fail("source-built native executable changed in owned tooling volume")
        if subprocess.run(["docker", "exec", container, "test", "-x", path],
                          check=False).returncode:
            fail("source-built native executable is not executable in owned tooling volume")
    ui = load(Path(plan["nativeUiReceipt"]))
    if not ui["linuxPath"].startswith(base + "/"):
        fail("current static UI is outside owned local tooling volume")
    if plan["lane"] == "eudi":
        eudi = load(Path(plan["nativeEudiReceipt"]))
        dist = eudi["linuxPath"]
        if not dist.startswith(base + "/") or ".." in PurePosixPath(dist).parts:
            fail("compiled EUDI facade is outside owned local tooling volume")
        files = eudi["distFiles"]
        if any(not isinstance(name, str) or not isinstance(digest, str)
               or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
               or not SHA256.fullmatch(digest) for name, digest in files.items()):
            fail("compiled EUDI facade receipt has invalid file bindings")
        observed = subprocess.check_output(
            ["docker", "exec", container, "sha256sum", *(f"{dist}/{name}" for name in files)],
            text=True,
        )
        actual = {name.removeprefix(dist + "/"): digest
                  for digest, name in (line.split(maxsplit=1) for line in observed.splitlines())}
        if actual != files:
            fail("compiled EUDI facade files changed in owned tooling volume")
    if plan["lane"] != "eudi":
        official_directory = ("w3c-suite" if plan["lane"] == "w3c-v2" else "oidf-runner")
        official_revision = (plan["w3cSuiteRevision"] if plan["lane"] == "w3c-v2"
                             else plan["officialRunnerRevision"])
        official_root = f"{base}/{official_directory}"
        if subprocess.check_output(["docker", "exec", container, "git", "-C", official_root,
                                    "rev-parse", "HEAD"], text=True).strip() != official_revision:
            fail("local official suite is not the exact unmodified harness pin")
        if subprocess.check_output(["docker", "exec", container, "git", "-C", official_root,
                                    "status", "--porcelain", "--untracked-files=all"], text=True).strip():
            fail("local official suite checkout has source changes")
    if plan["lane"] == "w3c-v2":
        node = json.loads(subprocess.check_output(
            ["docker", "exec", container, "cat", f"{base}/node-runtime.json"], text=True))
        if not node.get("binPath", "").startswith(base + "/") or not node.get("npmCli", "").startswith(base + "/"):
            fail("W3C Node/npm runtime is not bound to owned local tooling")
    port = plan["martyPort"]
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        fail("invalid local public TLS port")
    active = subprocess.check_output(["docker", "ps", "-q"], text=True).split()
    rows = json.loads(subprocess.check_output(["docker", "inspect", *active])) if active else []
    if any(int(binding["HostPort"]) == port for item in rows
           for bindings in item["NetworkSettings"]["Ports"].values() if bindings
           for binding in bindings):
        fail("local public TLS port is already published")
    existing_project = subprocess.check_output(
        ["docker", "ps", "-aq", "--filter",
         f"label=com.docker.compose.project=marty-conformance-{plan['runId']}"],
        text=True,
    ).strip()
    if existing_project:
        fail("local official project already has containers")
    for path in (f"{base}/work/{plan['tag']}-material",
                 f"{base}/work/{plan['tag']}-kms",
                 f"{base}/work/{plan['tag']}-evidence",
                 f"{base}/work/{plan['tag']}-source-migration.json"):
        if subprocess.run(["docker", "exec", container, "test", "!", "-e", path],
                          check=False).returncode:
            fail("local run ID or evidence tag already owns disposable data")
    driver = Path(plan["auditedLaneDriver"]).resolve(strict=True)
    helper = Path(plan["nativeServicesHelper"]).resolve(strict=True)
    ui_helper = Path(plan["nativeUiHelper"]).resolve(strict=True)
    eudi_helper = Path(plan["nativeEudiHelper"]).resolve(strict=True) if plan["lane"] == "eudi" else None
    subprocess.run(["docker", "cp", str(driver), f"{container}:{base}/run-local-lane.py"], check=True)
    subprocess.run(["docker", "cp", str(helper), f"{container}:{base}/local_native_services.py"], check=True)
    subprocess.run(["docker", "cp", str(ui_helper), f"{container}:{base}/local_ui_overlay.py"], check=True)
    if eudi_helper:
        subprocess.run(["docker", "cp", str(eudi_helper), f"{container}:{base}/local_eudi_overlay.py"], check=True)
    config = {"base": base, "tag": plan["tag"], "lane": plan["lane"],
              "run_id": plan["runId"], "product_revision": plan["productRevision"],
              "harness_revision": plan["harnessRevision"], "native_roles": [],
              "native_services": load(Path(plan["nativeServicesReceipt"])),
              "native_ui": ui,
              "native_eudi": load(Path(plan["nativeEudiReceipt"])) if eudi_helper else None,
              "native_kms_plugin": {key: load(Path(plan["kmsPluginReceipt"]))[key]
                                    for key in ("source", "linuxPath", "sha256")},
              "marty_port": plan["martyPort"], "gh_token": subprocess.check_output(
                  ["gh", "auth", "token"], text=True).strip()}
    migrator = next(item for item in config["native_services"]["files"]
                    if item["binary_name"] == "marty-issuance-service")
    command = ["docker", "exec", "--user", "0", "-i",
               "--env", f"MARTY_CONFORMANCE_SOURCE_MIGRATION_BINARY={migrator['linuxPath']}",
               "--env", f"MARTY_CONFORMANCE_SOURCE_MIGRATION_SHA256={migrator['sha256']}",
               "--env", f"MARTY_CONFORMANCE_SOURCE_VOLUME_ROOT={base}",
               "--env", f"MARTY_CONFORMANCE_SOURCE_REVISION={plan['productRevision']}",
               "--env", f"MARTY_CONFORMANCE_SOURCE_MIGRATION_RECEIPT={base}/work/{plan['tag']}-source-migration.json",
               container,
               f"{base}/venv/bin/python", f"{base}/run-local-lane.py"]
    try:
        return subprocess.run(command, input=json.dumps(config), text=True, check=False).returncode
    finally:
        config.clear()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--run", action="store_true", help="dispatch one local-only lane after source review")
    args = parser.parse_args(argv)
    plan = load(args.plan.resolve(strict=True))
    result = check(plan)
    print(json.dumps({"state": "SOURCE_BOUND", **result}, sort_keys=True))
    return dispatch(plan) if args.run else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Local official source run rejected: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(2) from error
