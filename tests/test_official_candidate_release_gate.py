from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/build_product_stack_manifest.py"))
TRANSACTION = BUILDER["TRANSACTION"]
STAMP = "2026-10-22T00:00:00+00:00"


def candidate(tmp_path: Path) -> tuple[Path, Path, dict]:
    lock = tmp_path / "stack-lock.json"
    lock.write_bytes((ROOT / "release/stack-lock.json").read_bytes())
    version = json.loads(lock.read_text())["release"].split("@", 1)[1]
    claim = TRANSACTION["create_claim"](
        repository="ElevenID/marty-ui", tag="v" + version, source_sha="a" * 40,
        stack_lock=lock, claim_run_id="99", image_uris=TRANSACTION["IMAGE_URIS"],
        tag_absent=True, release_absent=True,
        version_tags_absent={role: True for role in TRANSACTION["REQUIRED_IMAGE_ROLES"]},
    )
    claim = TRANSACTION["record_digests"](claim, {
        role: "sha256:" + str(index + 1) * 64
        for index, role in enumerate(TRANSACTION["REQUIRED_IMAGE_ROLES"])
    }, build_run_id="100")
    transaction = tmp_path / "transaction.json"
    transaction.write_text(json.dumps(claim), encoding="utf-8")
    return lock, transaction, claim


def test_candidate_is_byte_stable_through_qualification_and_lock_is_unchanged(tmp_path: Path) -> None:
    lock, transaction, claim = candidate(tmp_path)
    original = lock.read_bytes()
    before = BUILDER["build_product_manifest"](lock, transaction, STAMP)
    qualified = TRANSACTION["qualify"](claim, {
        role: {"run_id": "100", "evidence_sha256": "sha256:" + "e" * 64}
        for role in TRANSACTION["REQUIRED_GATE_ROLES"]
    })
    transaction.write_text(json.dumps(qualified), encoding="utf-8")
    after = BUILDER["build_product_manifest"](lock, transaction, STAMP)
    assert json.dumps(before) == json.dumps(after)
    assert lock.read_bytes() == original
    product = after["components"][-1]
    assert product["commit"] == "a" * 40
    assert len(product["artifacts"]) == 5
    assert {item["uri"] for item in product["artifacts"]} == set(TRANSACTION["IMAGE_URIS"].values())
    assert after["generated_at"] == STAMP


def test_candidate_rejects_changed_lock_before_using_its_components(tmp_path: Path) -> None:
    lock, transaction, _ = candidate(tmp_path)
    lock.write_bytes(lock.read_bytes() + b" ")
    with pytest.raises(ValueError, match="frozen release claim"):
        BUILDER["build_product_manifest"](lock, transaction, STAMP)


def test_publication_depends_on_complete_official_gate_and_reuses_tested_manifest() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/cd.yml").read_text())["jobs"]
    producer = jobs["prepare-official-candidate"]
    suite = jobs["official-interoperability"]
    receipt = jobs["official-gate-evidence"]
    qualifier = jobs["qualify-release"]
    assert "record-digests" in producer["needs"]
    assert suite["with"]["lane"] == "all"
    assert suite["with"]["collect_only"] is True
    assert suite["with"]["review_recipient"] == "${{ vars.OFFICIAL_REVIEW_RECIPIENT }}"
    assert suite["uses"].endswith("@" + suite["with"]["harness_revision"])
    assert "official-interoperability" in receipt["needs"]
    freezes = [step for step in receipt["steps"] if step.get("name") == "Preserve immutable review inputs before requiring approval"]
    assert len(freezes) == 1
    assert freezes[0]["with"]["name"] == "official-review-input-${{ github.run_id }}"
    assert freezes[0]["with"]["path"] == "official-review-input/"
    assert "official-gate-evidence" in qualifier["needs"]
    assert "qualify-release" in jobs["publish-manifest"]["needs"]
    for job in (suite, receipt, qualifier):
        assert "if" not in job
        assert "continue-on-error" not in job
    qualifier_text = json.dumps(qualifier)
    assert "official_interoperability=$GITHUB_RUN_ID:$official_digest" in qualifier_text
    publisher = next(step for step in jobs["publish-manifest"]["steps"]
                     if step.get("name") == "Add immutable UI evidence")
    assert 'test "$actual" = "$EXPECTED_MANIFEST_SHA256"' in publisher["run"]
    assert "cp official-candidate/stack-manifest.json stack-manifest.json" in publisher["run"]
