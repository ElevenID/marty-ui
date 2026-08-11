import json
from pathlib import Path

from scripts.check_rust_ownership import scan_repository


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_current_repository_matches_rust_ownership_manifest() -> None:
    assert scan_repository(REPO_ROOT) == []


def test_guard_rejects_new_python_crypto_import(tmp_path: Path) -> None:
    manifest = json.loads(
        (REPO_ROOT / "docs" / "rust-migration-ownership.json").read_text(encoding="utf-8")
    )
    manifest["guardrails"]["approved_imports"] = []
    manifest["guardrails"]["text_rules"] = []
    manifest_path = tmp_path / "ownership.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    source = tmp_path / "services" / "new_protocol" / "verify.py"
    source.parent.mkdir(parents=True)
    source.write_text("from cryptography import x509\n", encoding="utf-8")

    findings = scan_repository(tmp_path, manifest_path)

    assert findings == [
        "unapproved non-Rust crypto import (1x): "
        "services/new_protocol/verify.py: from cryptography import x509"
    ]


def test_guard_rejects_unrecorded_unsigned_token_decoder(tmp_path: Path) -> None:
    manifest = json.loads(
        (REPO_ROOT / "docs" / "rust-migration-ownership.json").read_text(encoding="utf-8")
    )
    manifest["guardrails"]["approved_imports"] = []
    manifest["guardrails"]["text_rules"] = [
        {
            "id": "unsigned-token",
            "glob": "services/auth/**/*.py",
            "pattern": "decode_jwt_claims",
            "expected_matches": {},
        }
    ]
    manifest_path = tmp_path / "ownership.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    source = tmp_path / "services" / "auth" / "adapter.py"
    source.parent.mkdir(parents=True)
    source.write_text("def decode_jwt_claims(token): return {}\n", encoding="utf-8")

    findings = scan_repository(tmp_path, manifest_path)

    assert findings == [
        "text guard unsigned-token changed: expected {}, found "
        "{'services/auth/adapter.py': 1}"
    ]
