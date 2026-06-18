from __future__ import annotations

import importlib.util
import sys
from argparse import Namespace
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check-canvas-credentials-contract.py"


def load_checker_module():
    spec = importlib.util.spec_from_file_location("check_canvas_credentials_contract", SCRIPT_PATH)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_badgeclass_check_builds_validation_and_assertions_urls(tmp_path, monkeypatch):
    checker = load_checker_module()
    env_file = tmp_path / "canvas.env"
    env_file.write_text(
        "\n".join(
            [
                "CANVAS_CREDENTIALS_PROVIDER=badgr_api",
                "CANVAS_CREDENTIALS_API_BASE_URL=https://credentials.example.test",
                "CANVAS_CREDENTIALS_API_TOKEN=secret-token",
                "CANVAS_CREDENTIALS_ASSERTION_SCOPE=badgeclasses",
                "CANVAS_CREDENTIALS_BADGECLASS_ID=badge-123",
            ]
        ),
        encoding="utf-8",
    )
    captured_urls = []

    def fake_api_get(url, token, timeout):
        captured_urls.append((url, token, timeout))
        return checker.ApiResponse(url=url, status=200, headers={"x-request-id": "req-1"}, body={"id": "ok"})

    monkeypatch.setattr(checker, "api_get", fake_api_get)

    result = checker.run_check(Namespace(env_file=env_file, list_assertions=True, timeout=7, json=True))

    assert result["ok"] is True
    assert result["scope"] == "badgeclasses"
    assert result["badgeclass_id"] == "badge-123"
    assert captured_urls == [
        ("https://credentials.example.test/v2/badgeclasses/badge-123", "secret-token", 7),
        ("https://credentials.example.test/v2/badgeclasses/badge-123/assertions?limit=1", "secret-token", 7),
    ]


def test_contract_check_requires_real_provider(tmp_path):
    checker = load_checker_module()
    env_file = tmp_path / "canvas.env"
    env_file.write_text(
        "\n".join(
            [
                "CANVAS_CREDENTIALS_PROVIDER=bridge",
                "CANVAS_CREDENTIALS_API_TOKEN=secret-token",
                "CANVAS_CREDENTIALS_BADGECLASS_ID=badge-123",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(checker.ContractCheckError, match="must be badgr_api"):
        checker.run_check(Namespace(env_file=env_file, list_assertions=False, timeout=7, json=True))
