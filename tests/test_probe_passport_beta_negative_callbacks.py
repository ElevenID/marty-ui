"""The beta negative callbacks must bind to one completed native job."""

from __future__ import annotations

import json
import sys
from io import BytesIO
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from scripts import probe_passport_beta_negative_callbacks as negative
from scripts import collect_passport_beta_acceptance as collector
from scripts.probe_passport_beta_negative_callbacks import (
    NegativeCallbackError, exercise,
)
from scripts.collect_passport_beta_acceptance import (
    production_attachment_commitment, production_snapshot_commitment,
)


KEY = "synthetic-beta-api-key-32-characters"
SIGNATURE = "vault:v1:" + "A" * 43 + "="
BUREAU_JOB = "76a7baef-368a-4722-95a4-df70ea1dfefa"


def handoff() -> dict[str, str]:
    return {"schema": "marty.passport-beta-demo-private/v1",
            "source_commit": "a" * 40, "stack_manifest_sha256": "b" * 64,
            "organization_id": "selected-org", "flow_definition_id": "selected-flow",
            "flow_instance_id": "selected-instance", "application_id": "selected-app",
            "source_job_id": "selected-job", "bureau_job_id": BUREAU_JOB}


def test_proves_both_denials_without_publishing_private_values() -> None:
    calls = []
    job = {"id": "selected-job", "application_id": "selected-app",
           "organization_id": "selected-org", "bureau_job_id": BUREAU_JOB,
           "status": "ACTIVE", "tracking_number": "BETA-SIM-" + BUREAU_JOB.replace("-", "")}

    def request(method, path, body, key):
        assert (method, path, body, key) == (
            "GET", "/v1/passport/applications/selected-app/production-status", None, KEY)
        calls.append("status")
        return 200, dict(job)

    def post(body, signature):
        event = json.loads(body)
        assert event["bureau_job_id"] == BUREAU_JOB
        assert event["provider_profile_id"] == "passport-beta-bureau"
        if signature is None:
            assert event["organization_id"] == "selected-org"
            calls.append("unsigned")
            return 422, {"missing_signature_header": True}
        assert signature == SIGNATURE
        assert event["organization_id"] == "foreign-org"
        calls.append("foreign")
        return 404, {"webhook_job_not_found": True}

    def sign(container, organization, body):
        assert container == "c" * 64
        assert organization == "foreign-org"
        assert json.loads(body)["organization_id"] == organization
        calls.append("sign")
        return SIGNATURE

    result = exercise(handoff(), KEY, "c" * 64, request=request, post=post,
                      sign=sign, foreign_organization="foreign-org")
    assert calls == ["status", "unsigned", "status", "sign", "foreign", "status"]
    assert result["verified"] is True
    assert result["unsigned"]["http_status"] == 422
    assert result["foreign"]["http_status"] == 404
    assert result["unsigned"]["job_state_before_commitment"] == (
        result["foreign"]["job_state_after_commitment"])
    wire = json.dumps(result)
    for private_value in ("selected-org", "foreign-org", "selected-job", BUREAU_JOB,
                          "selected-app", KEY, SIGNATURE):
        assert private_value not in wire
    assert "video_sha256" not in wire


def test_separate_uncut_cases_keep_one_selected_job_commitment() -> None:
    calls = []

    def request(*_args):
        calls.append("state")
        return 200, {"id": "selected-job", "application_id": "selected-app",
                     "organization_id": "selected-org", "bureau_job_id": BUREAU_JOB,
                     "status": "ACTIVE"}

    def post(body, signature):
        event = json.loads(body)
        assert event["bureau_job_id"] == BUREAU_JOB
        if signature is None:
            assert event["organization_id"] == "selected-org"
            calls.append("unsigned")
            return 422, {"missing_signature_header": True}
        assert event["organization_id"] == "foreign-org"
        calls.append("foreign")
        return 404, {"webhook_job_not_found": True}

    def sign(*_args):
        calls.append("sign")
        return SIGNATURE

    unsigned = exercise(handoff(), KEY, "c" * 64, request=request, post=post,
                        sign=sign, case="unsigned")
    foreign = exercise(handoff(), KEY, "c" * 64, request=request, post=post,
                       sign=sign, foreign_organization="foreign-org", case="foreign")
    assert calls == ["state", "unsigned", "state", "state", "sign", "foreign", "state"]
    assert unsigned["schema"] == foreign["schema"] == (
        "marty.passport-beta-negative-callback-case/v1")
    assert unsigned["case"] == "unsigned" and foreign["case"] == "foreign"
    assert unsigned["verified"] is True and foreign["verified"] is True
    for field in ("source_job_commitment", "bureau_job_commitment",
                  "job_state_before_commitment", "job_state_after_commitment"):
        assert unsigned["evidence"][field] == foreign["evidence"][field]
    assert unsigned["evidence"]["organization_commitment"] != (
        foreign["evidence"]["organization_commitment"])
    assert "selected-job" not in json.dumps((unsigned, foreign))
    assert "video_sha256" not in json.dumps((unsigned, foreign))


def test_separate_case_rejects_wrong_denial_or_state_change() -> None:
    def request(*_args):
        return 200, {"id": "selected-job", "application_id": "selected-app",
                     "organization_id": "selected-org", "bureau_job_id": BUREAU_JOB,
                     "status": "ACTIVE"}

    with pytest.raises(NegativeCallbackError):
        exercise(handoff(), KEY, "c" * 64, request=request,
                 post=lambda *_: (200, {}), case="unsigned")
    with pytest.raises(NegativeCallbackError):
        exercise(handoff(), KEY, "c" * 64, request=request,
                 post=lambda *_: (200, {}), sign=lambda *_: SIGNATURE,
                 foreign_organization="foreign-org", case="foreign")
    with pytest.raises(NegativeCallbackError, match="case is invalid"):
        exercise(handoff(), KEY, "c" * 64, case="untrusted")


@pytest.mark.parametrize("failure", ["unsigned", "foreign", "changed"])
def test_rejects_denial_or_selected_job_drift(failure: str) -> None:
    count = 0

    def request(*_):
        nonlocal count
        count += 1
        return 200, {"id": "selected-job", "application_id": "selected-app",
                     "organization_id": "selected-org", "bureau_job_id": BUREAU_JOB,
                     "status": "FAILED" if failure == "changed" and count == 3 else "ACTIVE"}

    def post(_body, signature):
        if signature is None:
            return (200, {}) if failure == "unsigned" else (422, {"missing_signature_header": True})
        return (200, {}) if failure == "foreign" else (404, {"webhook_job_not_found": True})

    with pytest.raises(NegativeCallbackError):
        exercise(handoff(), KEY, "c" * 64, request=request, post=post,
                 sign=lambda *_: SIGNATURE, foreign_organization="foreign-org")


def test_signer_adapter_keeps_internal_key_out_of_host_process_args(monkeypatch) -> None:
    seen = {}

    def run(command, **kwargs):
        seen["command"] = command
        seen["request"] = json.loads(kwargs["input"])
        return SimpleNamespace(stdout=json.dumps({"signature": SIGNATURE}).encode())

    monkeypatch.setattr(negative.subprocess, "run", run)
    assert negative._sign_foreign("c" * 64, "foreign-org",
                                  b'{"organization_id":"foreign-org"}') == SIGNATURE
    assert seen["command"][:4] == ["docker", "exec", "-i", "c" * 64]
    assert "SIGNING_KEYS_INTERNAL_API_KEY" in seen["command"][7]
    assert "SIGNING_KEYS_INTERNAL_API_KEY_FILE" in seen["command"][7]
    assert KEY not in str(seen["command"])
    assert seen["request"].keys() == {"body_b64"}


def test_cli_blocks_private_handoff_from_another_aggregate_release(
    tmp_path, monkeypatch,
) -> None:
    private_path = tmp_path / "private.json"
    private_path.write_text(json.dumps(handoff()), encoding="utf-8")
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "aggregate-deployment.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "blocked.json"
    monkeypatch.setenv("PASSPORT_ACCEPTANCE_API_KEY", KEY)
    monkeypatch.setattr(negative, "collect", lambda *_args, **_kwargs: {
        "release": {"signed_manifest_verified": True, "source_commit": "b" * 40,
                    "stack_manifest_sha256": "b" * 64},
        "deployment": {"provider_mode": "simulator"},
        "runtime_images": {"passport-beta-bureau": {"container_id": "c" * 64}},
    })
    monkeypatch.setattr(negative, "exercise", lambda *_args: pytest.fail("No callback"))
    monkeypatch.setattr(sys, "argv", ["probe", "--private-handoff", str(private_path),
                                      "--artifact-dir", str(artifact_dir),
                                      "--output", str(output)])
    with pytest.raises(SystemExit) as exc:
        negative.main()
    assert exc.value.code == 1
    assert json.loads(output.read_text())["verified"] is False
    assert "selected-job" not in output.read_text()


@pytest.mark.parametrize("status,detail,projection", [
    (422, [{"type": "missing", "loc": ["header", "x-personalization-signature"]}],
     "missing_signature_header"),
    (404, "Physical document job not found", "webhook_job_not_found"),
])
def test_http_adapter_projects_only_frozen_denial(
    monkeypatch, status, detail, projection,
) -> None:
    def open_request(request, timeout):
        assert timeout == 20
        assert request.full_url == "https://beta.elevenidllc.com/v1/passport/webhooks/personalization"
        raise HTTPError(request.full_url, status, "denied", {},
                        BytesIO(json.dumps({"detail": detail,
                                             "private": "must-not-publish"}).encode()))

    monkeypatch.setattr(negative, "build_opener",
                        lambda *_: SimpleNamespace(open=open_request))
    observed_status, evidence = negative._post_callback(
        b'{"organization_id":"synthetic"}', SIGNATURE if status == 404 else None)
    assert observed_status == status
    assert evidence[projection] is True
    assert "must-not-publish" not in str(evidence)


def test_negative_probe_requires_original_production_baselines(monkeypatch) -> None:
    deployment = {
        "production_snapshot_commitment": production_snapshot_commitment(KEY, "a" * 64),
        "production_attachment_commitment": production_attachment_commitment(KEY, "b" * 64),
    }
    monkeypatch.setattr(negative, "production_snapshot",
                        lambda: {"sha256": "a" * 64})
    monkeypatch.setattr(negative, "production_attachment_sha256",
                        lambda: "b" * 64)
    negative._check_production(KEY, deployment)
    monkeypatch.setattr(negative, "production_attachment_sha256",
                        lambda: "c" * 64)
    with pytest.raises(NegativeCallbackError, match="Production differs"):
        negative._check_production(KEY, deployment)


def test_cli_rechecks_production_and_beta_after_failed_callback(
    tmp_path, monkeypatch,
) -> None:
    private_path = tmp_path / "private.json"
    private_path.write_text(json.dumps(handoff()), encoding="utf-8")
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "aggregate-deployment.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "blocked.json"
    observed = []
    deployed = {
        "release": {"signed_manifest_verified": True, "source_commit": "a" * 40,
                    "stack_manifest_sha256": "b" * 64},
        "deployment": {"provider_mode": "simulator"},
        "runtime_images": {"passport-beta-bureau": {"container_id": "c" * 64}},
    }

    def collect(*_args, **_kwargs):
        observed.append("collect")
        return deployed

    def exercise(*_args):
        observed.append("callback")
        raise NegativeCallbackError("Denied callback did not verify")

    monkeypatch.setenv("PASSPORT_ACCEPTANCE_API_KEY", KEY)
    monkeypatch.setattr(negative, "collect", collect)
    monkeypatch.setattr(negative, "exercise", exercise)
    monkeypatch.setattr(negative, "_check_production",
                        lambda *_args: observed.append("production"))
    monkeypatch.setattr(negative, "beta_native_route_ownership",
                        lambda *_args: {"verified": True, "evidence": {
                            "webhook_owner": "issuance-native"}})
    monkeypatch.setattr(sys, "argv", ["probe", "--private-handoff", str(private_path),
                                      "--artifact-dir", str(artifact_dir),
                                      "--output", str(output)])
    with pytest.raises(SystemExit):
        negative.main()
    assert observed == ["collect", "production", "callback", "production", "collect"]
    assert json.loads(output.read_text())["verified"] is False


def test_cli_single_case_keeps_release_binding_and_checks_runtime(
    tmp_path, monkeypatch,
) -> None:
    private_path = tmp_path / "private.json"
    private_path.write_text(json.dumps(handoff()), encoding="utf-8")
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "aggregate-deployment.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "unsigned.json"
    observed = []
    deployed = {
        "release": {"signed_manifest_verified": True, "source_commit": "a" * 40,
                    "stack_manifest_sha256": "b" * 64},
        "deployment": {"provider_mode": "simulator",
                       "aggregate_deployment_receipt_sha256": "d" * 64,
                       "aggregate_plan_sha256": "e" * 64},
        "runtime_images": {"passport-beta-bureau": {"container_id": "c" * 64}},
    }

    def exercise_case(*_args, **kwargs):
        observed.append(("callback", kwargs["case"]))
        return {"schema": "marty.passport-beta-negative-callback-case/v1",
                "verified": True, "physical_claim": "not_claimed",
                "case": "unsigned", "evidence": {"http_status": 422}}

    monkeypatch.setenv("PASSPORT_ACCEPTANCE_API_KEY", KEY)
    monkeypatch.setattr(negative, "collect",
                        lambda *_args, **_kwargs: (observed.append("collect") or deployed))
    monkeypatch.setattr(negative, "exercise", exercise_case)
    monkeypatch.setattr(negative, "_check_production",
                        lambda *_args: observed.append("production"))
    monkeypatch.setattr(negative, "beta_native_route_ownership",
                        lambda *_args: {"verified": True, "evidence": {
                            "webhook_owner": "issuance-native"}})
    monkeypatch.setattr(sys, "argv", ["probe", "--private-handoff", str(private_path),
                                      "--artifact-dir", str(artifact_dir),
                                      "--output", str(output), "--case", "unsigned"])
    assert negative.main() == 0
    assert observed == ["collect", "production", ("callback", "unsigned"),
                        "production", "collect"]
    result = json.loads(output.read_text())
    assert result["schema"] == "marty.passport-beta-negative-callback-case/v1"
    assert result["release"] == {"source_commit": "a" * 40,
                                 "stack_manifest_sha256": "b" * 64}
    assert result["deployment"] == {"aggregate_deployment_receipt_sha256": "d" * 64,
                                    "aggregate_plan_sha256": "e" * 64}


@pytest.mark.parametrize("unsafe", ["private_in_artifacts", "overwrite_private",
                                     "overwrite_aggregate"])
def test_cli_preserves_private_and_aggregate_inputs_on_unsafe_paths(
    tmp_path, monkeypatch, unsafe,
) -> None:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    aggregate = artifact_dir / "aggregate-deployment.json"
    aggregate.write_text("aggregate-original", encoding="utf-8")
    private_path = (artifact_dir if unsafe == "private_in_artifacts" else tmp_path) / "private.json"
    private_path.write_text(json.dumps(handoff()), encoding="utf-8")
    original_private = private_path.read_bytes()
    output = (private_path if unsafe == "overwrite_private" else
              aggregate if unsafe == "overwrite_aggregate" else tmp_path / "blocked.json")
    monkeypatch.setattr(negative, "collect",
                        lambda *_args, **_kwargs: pytest.fail("No beta request"))
    monkeypatch.setattr(sys, "argv", ["probe", "--private-handoff", str(private_path),
                                      "--artifact-dir", str(artifact_dir),
                                      "--output", str(output)])
    with pytest.raises(SystemExit):
        negative.main()
    assert private_path.read_bytes() == original_private
    assert aggregate.read_text(encoding="utf-8") == "aggregate-original"


def test_direct_beta_opener_disables_environment_proxy(monkeypatch) -> None:
    handlers = []
    monkeypatch.setattr(negative, "build_opener",
                        lambda *args: handlers.extend(args))
    negative._direct_opener()
    assert isinstance(handlers[0], negative.ProxyHandler)
    assert handlers[0].proxies == {}
    assert handlers[1] is negative.NoRedirect


def test_capability_probe_also_disables_environment_proxy(monkeypatch) -> None:
    handlers = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def geturl(self):
            return collector.BETA_ORIGIN + "/v1/passport/capabilities"

        def read(self, _limit):
            return b"{}"

    def opener(*args):
        handlers.extend(args)
        return SimpleNamespace(open=lambda *_args, **_kwargs: Response())

    monkeypatch.setattr(collector, "build_opener", opener)
    assert collector.get_capabilities(None) == (200, {})
    assert isinstance(handlers[0], collector.ProxyHandler)
    assert handlers[0].proxies == {}


def test_cli_rejects_local_beta_proxy_flag_before_collection(tmp_path, monkeypatch) -> None:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    private_path = tmp_path / "private.json"
    private_path.write_text(json.dumps(handoff()), encoding="utf-8")
    output = tmp_path / "blocked.json"
    monkeypatch.setenv("BETA_LOCAL_PROXY", "1")
    monkeypatch.setattr(negative, "collect",
                        lambda *_args, **_kwargs: pytest.fail("No proxy-backed collection"))
    monkeypatch.setattr(sys, "argv", ["probe", "--private-handoff", str(private_path),
                                      "--artifact-dir", str(artifact_dir),
                                      "--output", str(output)])
    with pytest.raises(SystemExit):
        negative.main()
    assert json.loads(output.read_text())["verified"] is False
