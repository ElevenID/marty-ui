from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
PROBE = runpy.run_path(str(ROOT / "scripts/probe_selfhost_openbao_raft_bootstrap.py"))


def test_failed_bootstrap_preserves_stage_status_and_class_without_raw_custody() -> None:
    secret = "bootstrap-private-custody-sentinel"
    result = subprocess.CompletedProcess(["unit-fixture-only"], 1,
        stdout="Initializing OpenBao...\nUnsealing OpenBao...\n" + secret,
        stderr=f"URL: https://{secret}/v1/secret/{secret}\nCode: 500. Errors:\nfailed to contact leader\n{secret}")
    diagnostic = PROBE["bootstrap_failure_diagnostic"](result)
    assert diagnostic["last_observed_stage"] == "unseal"
    assert diagnostic["http_statuses"] == [500]
    assert diagnostic["error_classes"] == ["leader-unavailable"]
    assert diagnostic["exit_code"] == 1
    assert secret not in json.dumps(diagnostic)
    assert "https" not in json.dumps(diagnostic)


def test_unknown_output_stays_a_failure_and_never_echoes_arbitrary_payloads() -> None:
    result = subprocess.CompletedProcess(["unit-fixture-only"], 137,
                                         stdout="arbitrary-private-value", stderr="another-private-value")
    diagnostic = PROBE["bootstrap_failure_diagnostic"](result)
    assert diagnostic["exit_code"] == 137
    assert diagnostic["last_observed_stage"] == "unknown"
    assert diagnostic["error_classes"] == ["unclassified"]
    assert "private-value" not in json.dumps(diagnostic)


def test_request_category_does_not_expose_policy_names_or_urls() -> None:
    secret = "private-policy-name-sentinel"
    result = subprocess.CompletedProcess(["unit-fixture-only"], 2, stdout="",
        stderr=f"URL: PUT https://127.0.0.1:8200/v1/sys/policies/acl/{secret}\nCode: 403. permission denied")
    diagnostic = PROBE["bootstrap_failure_diagnostic"](result)
    assert diagnostic["request_categories"] == ["acl-policy"]
    assert diagnostic["http_statuses"] == [403]
    assert secret not in json.dumps(diagnostic)
    assert "https" not in json.dumps(diagnostic)
