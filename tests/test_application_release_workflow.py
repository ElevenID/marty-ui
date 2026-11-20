"""The package producer must qualify the exact image before issuing evidence."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/production-web-release.yml"


def application_job():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["application"]


@pytest.mark.parametrize("changes,allowed", [
    ({}, True),
    ({"EXPECTED_SOURCE_SHA": ""}, False),
    ({"EXPECTED_SOURCE_SHA": "main"}, False),
    ({"EXPECTED_SOURCE_SHA": "b" * 40}, False),
    ({"EXPECTED_SOURCE_SHA": "a" * 40 + "\n"}, False),
    ({"GITHUB_REF": "refs/heads/topic"}, False),
    ({"DIRTY_SOURCE": " M ui/package.json"}, False),
    ({"BACKEND_TAG": "v1.1.273"}, False),
    ({"WEBSITE_RUN": "44449706828"}, False),
    ({"WEBSITE_ATTEMPT": "2"}, False),
    ({"APPLICATION_RUN": "42385654811"}, False),
    ({"APPLICATION_ATTEMPT": "1"}, False),
])
def test_application_guard_requires_its_exact_clean_source_and_exclusive_inputs(tmp_path, changes, allowed):
    steps = application_job()["steps"]
    assert steps[0]["with"] == {"ref": "${{ github.sha }}", "fetch-depth": 0, "persist-credentials": False}
    guard = steps[1]
    assert guard["name"] == "Require the exact protected-main application source"
    git = tmp_path / "git"
    git.write_text('#!/bin/sh\ncase "$1" in\n'
                   'rev-parse) printf "%s\\n" "$GITHUB_SHA" ;;\n'
                   'status) printf "%s" "$DIRTY_SOURCE" ;;\n'
                   'merge-base) exit 0 ;;\n*) exit 90 ;;\nesac\n')
    git.chmod(0o700)
    environment = {**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40,
                   "EXPECTED_SOURCE_SHA": "a" * 40, "DIRTY_SOURCE": "", "BACKEND_TAG": "",
                   "RUNNER_TEMP": str(tmp_path), "GITHUB_ENV": str(tmp_path / "environment"),
                   "WEBSITE_RUN": "", "WEBSITE_ATTEMPT": "", "APPLICATION_RUN": "", "APPLICATION_ATTEMPT": "",
                   **changes}
    result = subprocess.run(["bash", "--noprofile", "--norc"], input=guard["run"],
                            env=environment, text=True, capture_output=True, check=False)
    assert (result.returncode == 0) is allowed, result.stderr


def test_application_publisher_uses_one_package_build_and_qualifies_the_pushed_digest_before_signing():
    job = application_job()
    assert job["permissions"] == {"contents": "read", "packages": "write", "id-token": "write",
                                  "attestations": "write", "artifact-metadata": "write"}
    assert job["env"]["APP_IMAGE"] == "ghcr.io/elevenid/marty-ui-oss/application"
    steps = job["steps"]
    by_name = {step.get("name", ""): index for index, step in enumerate(steps)}
    plan = next(index for index, step in enumerate(steps) if step.get("id") == "plan")
    login = next(index for index, step in enumerate(steps) if step.get("uses", "").startswith("docker/login-action@"))
    builds = [(index, step) for index, step in enumerate(steps) if step.get("uses", "").startswith("docker/build-push-action@")]
    assert len(builds) == 1
    build_index, build = builds[0]
    qualify = by_name["Qualify the exact published digest and sandboxed browser before signing"]
    attestations = [index for index, step in enumerate(steps) if step.get("uses", "").startswith("actions/attest-build-provenance@")]
    sign = by_name["Sign the qualified application image and release receipt"]
    assert 1 < plan < login < build_index < qualify < min(attestations)
    assert qualify < sign
    assert build["with"]["context"] == "${{ env.APPLICATION_CONTEXT }}"
    assert build["with"]["file"] == "docker/application.Dockerfile"
    assert build["with"]["platforms"] == "linux/amd64"
    assert build["with"]["provenance"] == "mode=max" and build["with"]["sbom"] is True
    assert "push-by-digest=true" in build["with"]["outputs"] and "tags" not in build["with"]
    assert steps[qualify]["env"]["DIGEST"] == steps[sign]["env"]["DIGEST"] == "${{ steps.build.outputs.digest }}"
    assert '--image-reference "$APP_IMAGE@$DIGEST" --browser-startup' in steps[qualify]["run"]
    assert '--browser-channel chrome' in steps[qualify]["run"]
    assert 'application_release.py record' in steps[qualify]["run"]
    assert steps[qualify]["run"].index('application-runtime-context.mjs') < steps[qualify]["run"].index('application_release.py record')
    assert 'sign --yes "$APP_IMAGE@$DIGEST"' in steps[sign]["run"]
    upload = next(step for step in steps if step.get("with", {}).get("name") == "application-release-${{ github.run_id }}-${{ github.run_attempt }}")
    assert upload["with"]["name"] == "application-release-${{ github.run_id }}-${{ github.run_attempt }}"
    assert "if" not in upload and upload["with"]["if-no-files-found"] == "error"
    diagnostics = steps[-1]
    assert diagnostics["if"] == "failure()"
    assert diagnostics["with"]["name"] == "application-release-diagnostics-${{ github.run_id }}-${{ github.run_attempt }}"
    assert "application-release.json" not in diagnostics["with"]["path"]
    for step in steps:
        assert "continue-on-error" not in step
        if "uses" in step:
            assert re.fullmatch(r"[^\s]+@[0-9a-f]{40}", step["uses"])
        if "run" in step:
            subprocess.run(["bash", "-n"], input=step["run"], text=True, capture_output=True, check=True)
    commands = "\n".join(step.get("run", "") for step in steps)
    for required in ("--fresh-install --dependency-profile application", "export-application-source.mjs",
                     "application-package-consumer.mjs", "application_release.py plan",
                     "application_provenance.py", "--subject application-release.json"):
        assert required in commands
    for unrelated in ("package_production_deployment.py", "web_release_intake.py backend", "package_web_composition.py",
                      "bun pm pkg set", "helm upgrade", "kubectl", "--no-sandbox"):
        assert unrelated not in commands


def test_ci_qualifies_the_production_recipe_without_publication_authority():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["test-website"]
    steps = job["steps"]
    consumer = next(index for index, step in enumerate(steps) if "application-package-consumer.mjs" in step.get("run", ""))
    plan = next(index for index, step in enumerate(steps) if "application_release.py plan" in step.get("run", ""))
    bootstrap = next(index for index, step in enumerate(steps) if "download-verified-ui-release-assets.sh" in step.get("run", ""))
    candidate = next(index for index, step in enumerate(steps) if "--build-release-image" in step.get("run", ""))
    assert consumer < plan < bootstrap < candidate
    for index in (plan, candidate):
        assert "if" not in steps[index] and "continue-on-error" not in steps[index]
    assert '--browser-startup' in steps[candidate]["run"] and '--browser-channel chrome' in steps[candidate]["run"]
    assert "--image-reference" not in steps[candidate]["run"]
    assert "packages" not in job.get("permissions", {}) and "id-token" not in job.get("permissions", {})
    upload = next(step for step in steps if step.get("with", {}).get("name") == "application-image-candidate-${{ github.run_id }}-${{ github.run_attempt }}")
    assert upload["if"] == "always()"
    assert upload["with"]["path"].splitlines() == [
        "${{ runner.temp }}/application-build-plan.json", "${{ runner.temp }}/application-runtime-context.json",
        "${{ runner.temp }}/application-image-check.json", "${{ runner.temp }}/application-image-browser.json",
    ]
