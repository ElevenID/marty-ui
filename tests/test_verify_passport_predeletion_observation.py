"""A protected drain can enter predeletion only through its signed run."""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts import verify_passport_predeletion_observation as verifier
from scripts.probe_passport_beta_host import HostProbeError


COMMIT = "a" * 40
RUN_ID = 123


def run_data() -> dict:
    return {
        "id": RUN_ID, "repository": {"full_name": verifier.REPOSITORY},
        "status": "completed", "conclusion": "success", "event": "workflow_dispatch",
        "head_branch": "main", "head_sha": COMMIT, "run_attempt": 1,
        "workflow_id": 456, "updated_at": "2026-09-29T00:00:05Z",
    }


def test_run_requires_exact_protected_workflow_and_source() -> None:
    calls = []

    def runner(args):
        calls.append(args)
        if args[-1].endswith("/456"):
            return json.dumps({"path": verifier.WORKFLOW, "state": "active"})
        return json.dumps(run_data())

    result = verifier.verify_run(RUN_ID, COMMIT, runner)
    assert result == {"run_id": RUN_ID, "source_commit": COMMIT,
                      "completed_at_utc": "2026-09-29T00:00:05Z"}
    assert calls == [
        ["gh", "api", f"repos/{verifier.REPOSITORY}/actions/runs/{RUN_ID}"],
        ["gh", "api", f"repos/{verifier.REPOSITORY}/actions/workflows/456"],
    ]

    with pytest.raises(HostProbeError, match="exact-main"):
        verifier.verify_run(RUN_ID, "b" * 40, runner)

    def wrong_workflow(args):
        return json.dumps({"path": "other.yml", "state": "active"}) if (
            args[-1].endswith("/456")) else json.dumps(run_data())

    with pytest.raises(HostProbeError, match="different workflow"):
        verifier.verify_run(RUN_ID, COMMIT, wrong_workflow)


def test_attestation_checks_signer_ref_and_source(tmp_path) -> None:
    artifact = tmp_path / "snapshot.json"
    artifact.write_text("{}")
    calls = []

    def runner(args):
        calls.append(args)
        return json.dumps([{"attestation": {"bundle": "signed"},
                            "verificationResult": {"statement": {}}}])

    result = verifier.verify_attestation(artifact, COMMIT, runner)
    assert result == hashlib.sha256(b'{"bundle":"signed"}').hexdigest()
    assert calls == [[
        "gh", "attestation", "verify", str(artifact), "--repo", verifier.REPOSITORY,
        "--signer-workflow", verifier.SIGNER, "--source-ref", "refs/heads/main",
        "--source-digest", COMMIT, "--format", "json",
    ]]
    with pytest.raises(HostProbeError, match="one verified"):
        verifier.verify_attestation(artifact, COMMIT, lambda _: "[]")


def artifact(tmp_path, monkeypatch):
    installation = {"schema": "installation", "source_commit": COMMIT}
    snapshot = {"schema": "snapshot", "observed_at_utc": "2026-09-29T00:00:03Z"}
    names = {
        "installation": f"passport-beta-fence-installation-{RUN_ID}.json",
        "snapshot": f"passport-beta-cutover-snapshot-{RUN_ID}.json",
        "drain": f"passport-beta-predeletion-drain-{RUN_ID}.json",
    }
    paths = {key: tmp_path / name for key, name in names.items()}
    paths["installation"].write_text(json.dumps(installation))
    paths["snapshot"].write_text(json.dumps(snapshot))
    report = {"schema": "marty.passport-rust-predeletion-drain/v1",
              "status": "observed_unattested",
              "probe": {"verified": True, "evidence": {"legacy_source": {},
                                                  "nonterminal_job_count": 0}}}
    def recompute(install, observed, *, installation_file_sha256,
                  snapshot_file_sha256, source_commit):
        assert install == installation and observed == snapshot
        assert source_commit == COMMIT
        assert installation_file_sha256 == hashlib.sha256(
            paths["installation"].read_bytes()).hexdigest()
        assert snapshot_file_sha256 == hashlib.sha256(
            paths["snapshot"].read_bytes()).hexdigest()
        return report

    monkeypatch.setattr(verifier, "collect", recompute)
    paths["drain"].write_text(json.dumps(report))
    return paths


def test_verified_observation_binds_signed_snapshot_and_projection(tmp_path,
                                                                  monkeypatch) -> None:
    paths = artifact(tmp_path, monkeypatch)
    seen = []

    def attest(path, commit):
        seen.append((path, commit))
        return "f" * 64 if path == paths["snapshot"] else "e" * 64

    result = verifier.verify_observation(
        tmp_path, RUN_ID, COMMIT, "2026-09-29T00:00:05Z", attest)
    assert result["status"] == "verified_observation"
    assert result["probe"]["evidence"]["legacy_source"][
        "drain_snapshot_attestation_sha256"] == "f" * 64
    assert {path for path, commit in seen if commit == COMMIT} == set(paths.values())
    assert result["observation_run_id"] == RUN_ID
    assert result["installation"]["source_commit"] == COMMIT
    assert result["snapshot"]["observed_at_utc"] == "2026-09-29T00:00:03Z"

    projection = json.loads(paths["drain"].read_text())
    projection["probe"]["evidence"]["nonterminal_job_count"] = 1
    paths["drain"].write_text(json.dumps(projection))
    with pytest.raises(HostProbeError, match="projection differs"):
        verifier.verify_observation(tmp_path, RUN_ID, COMMIT,
                                    "2026-09-29T00:00:05Z", attest)


def test_observation_rejects_extra_files_and_early_completion(tmp_path,
                                                               monkeypatch) -> None:
    artifact(tmp_path, monkeypatch)
    with pytest.raises(HostProbeError, match="completed before"):
        verifier.verify_observation(tmp_path, RUN_ID, COMMIT,
                                    "2026-09-29T00:00:02Z",
                                    lambda *_: "f" * 64)
    (tmp_path / "extra.json").write_text("{}")
    with pytest.raises(HostProbeError, match="missing or extra"):
        verifier.verify_observation(tmp_path, RUN_ID, COMMIT,
                                    "2026-09-29T00:00:05Z",
                                    lambda *_: "f" * 64)
