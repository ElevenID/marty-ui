#!/usr/bin/env python3
"""Exercise the pinned Linux public-stack happy path on exact nightly images."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.request import urlopen

from nightly_release import file_digest, product_manifest, read, require, validate_candidate

CASES = (
    "tests/oss_stack/test_public_stack.py::test_gateway_is_healthy",
    "tests/oss_stack/test_public_stack.py::test_required_public_services_are_healthy",
    "tests/oss_stack/test_public_stack.py::test_oid4vci_metadata_is_available",
    "tests/oss_stack/test_public_stack.py::test_ui_is_served",
    "tests/oss_stack/test_positive_credential_issuance.py::test_application_offer_redeems_to_issued_credential",
)
SCHEMA = "elevenid.nightly-runtime-happy-path/v1"


def require_cases(path: Path) -> None:
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    require(len(cases) == len(CASES), "nightly happy-path test inventory differs")
    require({item.get("name") for item in cases} == {item.rsplit("::", 1)[1] for item in CASES},
            "nightly happy-path test identities differ")
    require(all(not list(item) or all(child.tag == "properties" for child in item)
                for item in cases), "nightly happy-path test failed, errored or skipped")


def execute(harness: Path, assets: Path, source: Path, report: Path) -> None:
    require(sys.platform == "linux", "nightly runtime admission requires Linux")
    candidate = validate_candidate(read(assets / "selfhost-preparation-transaction.json"))
    manifest = read(assets / "stack-manifest.json")
    require(manifest == product_manifest(candidate, source / "release/stack-lock.json",
                                          manifest["generated_at"]),
            "runtime manifest differs from nightly candidate")
    require(not report.exists(), "nightly runtime report already exists")
    project = "marty-nightly-" + candidate["build_run_id"]
    env = {**os.environ, "COMPOSE_PROJECT_NAME": project}
    compose = ["docker", "compose", "--project-name", project, "--env-file", ".env.stack",
               "--file", "docker-compose.yml", "--file", "docker-compose.rust-revocation.yml"]

    def run(args: list[str], timeout: int = 600) -> str:
        result = subprocess.run(args, cwd=harness, env=env, text=True,
                                capture_output=True, timeout=timeout, check=False)
        require(result.returncode == 0, "nightly runtime command failed: " + args[0])
        return result.stdout.strip()

    require(not run(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"]),
            "nightly runtime project already exists")
    require(not run(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"]),
            "nightly runtime project has pre-existing volumes")
    (harness / "stack-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    run([sys.executable, "scripts/render_stack_env.py", "--manifest", "stack-manifest.json",
         "--output", ".env.stack", "--pull"], timeout=1200)
    run([*compose, "config", "--quiet"])
    started = time.monotonic()
    try:
        run([*compose, "up", "-d"], timeout=900)
        for _ in range(90):
            try:
                with urlopen("http://127.0.0.1:28000/health", timeout=3) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            time.sleep(2)
        else:
            raise ValueError("nightly gateway did not become healthy")
        run([sys.executable, str(source / "scripts/wait_for_public_services.py"),
             "--url", "http://127.0.0.1:28000/health/services", "--timeout", "120"])
        run([sys.executable, "-m", "pytest", *CASES, "-q", "--junitxml=nightly-tests.xml"],
            timeout=900)
        require_cases(harness / "nightly-tests.xml")
    finally:
        run([*compose, "down", "--volumes", "--remove-orphans"], timeout=180)
        require(not run(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"]),
                "nightly runtime cleanup left owned containers")
        require(not run(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"]),
                "nightly runtime cleanup left owned volumes")
    record = {"schema": SCHEMA, "tier": "nightly", "status": "passed",
        "scope": "runtime-happy-path; self-host ZIP remains unqualified",
        "source_sha": candidate["source_sha"], "tag": candidate["tag"],
        "run_id": candidate["build_run_id"], "cases": list(CASES),
        "owned_cleanup": "observed", "elapsed_seconds": round(time.monotonic() - started, 3),
        "candidate_sha256": file_digest(assets / "selfhost-preparation-transaction.json"),
        "manifest_sha256": file_digest(assets / "stack-manifest.json"),
        "archive_sha256": file_digest(assets / "prepared-selfhost-bundle.zip"),
        "junit_sha256": file_digest(harness / "nightly-tests.xml")}
    with report.open("x", encoding="utf-8") as output:
        output.write(json.dumps(record, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("harness", "assets", "source", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    execute(args.harness.resolve(), args.assets.resolve(), args.source.resolve(), args.report.resolve())


if __name__ == "__main__":
    main()
