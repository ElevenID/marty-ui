"""Run the shared credential-metadata contract against the Python baseline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from gateway.routes.credential_metadata import credential_metadata_router


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "credential-metadata-behavior.json"
    ).read_text(encoding="utf-8")
)


def test_python_credential_metadata_matches_shared_contract(monkeypatch) -> None:
    assert CONTRACT["schema_version"] == 1
    monkeypatch.setenv("PUBLIC_API_URL", CONTRACT["base_url"])
    app = FastAPI()
    app.include_router(credential_metadata_router)
    client = TestClient(app)

    for case in CONTRACT["json_cases"]:
        for path in case["paths"]:
            response = client.get(path)
            assert response.status_code == 200, path
            assert response.headers["cache-control"] == case["cache_control"], path
            assert response.json() == case["expected"], path

    for case in CONTRACT["svg_cases"]:
        response = client.get(case["path"])
        assert response.status_code == 200, case["path"]
        assert response.headers["content-type"].startswith("image/svg+xml")
        assert response.headers["cache-control"] == case["cache_control"]
        assert len(response.content) == case["length"]
        assert hashlib.sha256(response.content).hexdigest() == case["sha256"]
