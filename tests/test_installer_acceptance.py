import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_acceptance as gate


@pytest.fixture
def evidence():
    inventory = b'{"exact":"signed inventory bytes"}\n'
    report = {
        "schema": gate.SCHEMA, "repository": gate.REPOSITORY,
        "source_sha": "a" * 40, "source_ref": "refs/heads/main",
        "release_tag": "v1.1.260-nightly.20261025.42", "phase": "published",
        "platform": "linux/amd64", "inventory_sha256": "sha256:" + hashlib.sha256(inventory).hexdigest(),
        "workflow": gate.WORKFLOW, "run_id": 42, "run_attempt": 1,
        "cases": dict.fromkeys(gate.CASES, "passed"),
        "host": {"docker_version": "28.0.0", "compose_version": "2.39.0",
                 "memory_bytes": 32 * 1024**3, "disk_free_bytes": 20 * 1024**3,
                 "image_cache_empty": True, "source_available": False,
                 "development_tools_available": False, "credentials_available": False,
                 "tls_errors_ignored": False},
        "cleanup": {"owned_containers_remaining": 0, "owned_networks_remaining": 0,
                    "owned_volumes_remaining": 0, "recovery_retention_verified": True},
    }
    run = {"id": 42, "run_attempt": 1, "path": gate.WORKFLOW,
           "head_sha": "a" * 40, "head_branch": "main", "event": "workflow_dispatch",
           "status": "completed", "conclusion": "success",
           "repository": {"full_name": gate.REPOSITORY}}
    return report, dict(inventory_bytes=inventory, source_sha="a" * 40,
                        release_tag=report["release_tag"], phase="published", run=run)


def test_accepts_exact_candidate_in_both_release_tiers_and_all_phases(evidence):
    report, args = evidence
    for tag in (report["release_tag"], "v1.1.260"):
        for phase in ("staged", "published", "channel"):
            report.update(release_tag=tag, phase=phase)
            gate.validate(report, **{**args, "release_tag": tag, "phase": phase})


@pytest.mark.parametrize("name,value", [
    ("head_sha", "b" * 40), ("head_branch", "feature"), ("path", ".github/workflows/nightly-release.yml"),
    ("event", "pull_request"), ("run_attempt", 2), ("conclusion", "failure"),
    ("status", "in_progress"), ("repository", {"full_name": "attacker/marty-ui"}),
])
def test_wrong_or_unfinished_authoritative_run_rejected(evidence, name, value):
    report, args = evidence
    args["run"][name] = value
    with pytest.raises(ValueError):
        gate.validate(report, **args)


@pytest.mark.parametrize("case", gate.CASES)
@pytest.mark.parametrize("outcome", ["skipped", "failed", "review", None])
def test_every_installed_journey_step_is_mandatory(evidence, case, outcome):
    report, args = evidence
    report["cases"][case] = outcome
    with pytest.raises(ValueError):
        gate.validate(report, **args)


def test_same_inventory_semantics_different_bytes_rejected(evidence):
    report, args = evidence
    args["inventory_bytes"] = args["inventory_bytes"].rstrip()
    with pytest.raises(ValueError, match="inventory"):
        gate.validate(report, **args)


@pytest.mark.parametrize("run", [None, [], {"repository": None}, {"repository": "ElevenID/marty-ui"}])
def test_malformed_authoritative_run_rejected(evidence, run):
    report, args = evidence
    args["run"] = run
    with pytest.raises(ValueError, match="run shape"):
        gate.validate(report, **args)


@pytest.mark.parametrize("case", gate.CASES)
def test_no_required_case_can_be_omitted(evidence, case):
    report, args = evidence
    del report["cases"][case]
    with pytest.raises(ValueError, match="fields differ"):
        gate.validate(report, **args)


@pytest.mark.parametrize("section,name,value", [
    ("host", "tls_errors_ignored", True), ("host", "credentials_available", True),
    ("host", "source_available", True), ("host", "development_tools_available", True),
    ("host", "image_cache_empty", False), ("host", "memory_bytes", True),
    ("cleanup", "owned_volumes_remaining", 1), ("cleanup", "owned_containers_remaining", False),
    ("cleanup", "recovery_retention_verified", False),
])
def test_unclean_host_or_incomplete_cleanup_rejected(evidence, section, name, value):
    report, args = evidence
    report[section][name] = value
    with pytest.raises(ValueError):
        gate.validate(report, **args)


def test_no_runtime_smoke_or_extra_case_substitution(evidence):
    report, args = evidence
    changed = copy.deepcopy(report)
    changed["schema"] = "elevenid.nightly-runtime-happy-path/v1"
    with pytest.raises(ValueError):
        gate.validate(changed, **args)
    report["cases"]["runtime-happy-path"] = "passed"
    with pytest.raises(ValueError):
        gate.validate(report, **args)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"nested":{"a":1,"a":2}}', b'[]', b' ' * 65537],
                         ids=["duplicate", "nested-duplicate", "array", "oversized"])
def test_ambiguous_or_oversized_json_rejected(tmp_path, raw):
    path = tmp_path / "report.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        gate.read_report(path)
