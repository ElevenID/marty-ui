"""An external verifier verdict must cover the exact candidate it names."""

import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INTAKE = runpy.run_path(str(ROOT / "scripts/product_evidence_intake.py"))
ROLES = {
    "marty-server": ("services", "migrations", "openbao-didcomm", "keycloak"),
    "marty-console": ("ui",),
}


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fixture(tmp_path: Path, product: str) -> tuple[Path, Path, Path, dict]:
    prefix = "server-v" if product == "marty-server" else "console-v"
    package = {
        "schema": "marty.product-package/v1",
        "product": product,
        "version": "0.1.0",
        "tag": prefix + "0.1.0",
        "source": {"repository": "ElevenID/marty-ui", "commit": "a" * 40},
        "api": {"http": "v1", "mip": "0.5.0"},
        "images": [
            {
                "role": role,
                "uri": f"ghcr.io/elevenid/{product}/{role}",
                "digest": "sha256:" + str(index) * 64,
                "platform": "linux/amd64",
            }
            for index, role in enumerate(ROLES[product], start=1)
        ],
        "producer": {
            "workflow": ".github/workflows/product-packages.yml",
            "run_id": "123",
            "run_attempt": "2",
        },
        "build_plan_sha256": "sha256:" + "f" * 64,
        "platforms": ["linux/amd64"],
        "support_state": "experimental",
        "qualification": "unqualified",
    }
    package_path = tmp_path / "product-package.json"
    package_path.write_text(json.dumps(package), encoding="utf-8")
    archive = tmp_path / "product-package.tar.gz"
    archive.write_bytes(b"independently verified candidate bytes")
    candidate = {
        "archive_sha256": sha(archive.read_bytes()),
        "package_sha256": sha(package_path.read_bytes()),
        "product": product,
        "version": "0.1.0",
        "tag": prefix + "0.1.0",
        "source": package["source"],
        "producer": package["producer"],
        "images": sorted(package["images"], key=lambda image: image["role"]),
    }
    report = {
        "schema": "marty.product-artifact-verification/v1",
        "candidate": candidate,
        "verification": {
            "repository": "ElevenID/marty-ui",
            "workflow": ".github/workflows/product-verification.yml",
            "run_id": "456",
            "run_attempt": "1",
            "conclusion": "success",
        },
        "checks": {name: "pass" for name in ("payload", "provenance", "sbom", "cross_host")},
        "result": "pass",
    }
    report_path = tmp_path / "verification.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return package_path, archive, report_path, report


@pytest.mark.parametrize("product", list(ROLES))
def test_report_binds_exact_candidate_but_makes_no_release_claim(tmp_path, product):
    package, archive, report, _ = fixture(tmp_path, product)
    record = INTAKE["bind_report"](package, archive, report, sha(report.read_bytes()))
    assert record["state"] == "pending_authenticated_promotion"
    assert record["candidate"]["product"] == product
    assert record["verification_report_sha256"] == sha(report.read_bytes())
    assert "qualification" not in record and "support_state" not in record


def test_cli_writes_pending_record_without_overwriting_it(tmp_path):
    package, archive, report, _ = fixture(tmp_path, "marty-console")
    output = tmp_path / "intake.json"
    command = [
        sys.executable, str(ROOT / "scripts/product_evidence_intake.py"),
        "--package", str(package), "--archive", str(archive),
        "--verification-report", str(report),
        "--trusted-report-sha256", sha(report.read_bytes()),
        "--output", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)
    assert json.loads(output.read_text(encoding="utf-8"))["state"] == "pending_authenticated_promotion"
    repeated = subprocess.run(command, capture_output=True, text=True)
    assert repeated.returncode != 0


@pytest.mark.parametrize("malformed", ["duplicate", "nan"])
def test_ambiguous_or_nonstandard_json_never_reaches_verdict_checks(tmp_path, malformed):
    package, archive, report_path, _ = fixture(tmp_path, "marty-server")
    source = report_path.read_text(encoding="utf-8")
    if malformed == "duplicate":
        source = source.replace('"result": "pass"', '"result": "fail", "result": "pass"')
    else:
        source = source.replace('"run_attempt": "1"', '"run_attempt": NaN')
    report_path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key|nonstandard JSON constant"):
        INTAKE["bind_report"](package, archive, report_path, sha(report_path.read_bytes()))


@pytest.mark.parametrize("mutation", [
    "archive", "package", "report_digest", "image", "source", "producer_attempt",
    "verifier_run", "verifier_repository", "failed_check", "missing_check",
    "failed_result", "unsupported_schema",
])
def test_mismatch_or_failed_external_verdict_blocks_intake(tmp_path, mutation):
    package, archive, report_path, report = fixture(tmp_path, "marty-server")
    trusted_digest = sha(report_path.read_bytes())
    if mutation == "archive":
        archive.write_bytes(b"different archive")
    elif mutation == "package":
        value = json.loads(package.read_text(encoding="utf-8"))
        value["version"] = "0.1.1"
        package.write_text(json.dumps(value), encoding="utf-8")
    elif mutation == "report_digest":
        trusted_digest = "sha256:" + "0" * 64
    else:
        if mutation == "image":
            report["candidate"]["images"][0]["digest"] = "sha256:" + "0" * 64
        elif mutation == "source":
            report["candidate"]["source"]["commit"] = "b" * 40
        elif mutation == "producer_attempt":
            report["candidate"]["producer"]["run_attempt"] = "3"
        elif mutation == "verifier_run":
            report["verification"]["run_id"] = "0"
        elif mutation == "verifier_repository":
            report["verification"]["repository"] = "Other/repo"
        elif mutation == "failed_check":
            report["checks"]["sbom"] = "fail"
        elif mutation == "missing_check":
            del report["checks"]["cross_host"]
        elif mutation == "failed_result":
            report["result"] = "fail"
        else:
            report["schema"] = "unknown/v1"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        trusted_digest = sha(report_path.read_bytes())
    with pytest.raises(ValueError):
        INTAKE["bind_report"](package, archive, report_path, trusted_digest)
