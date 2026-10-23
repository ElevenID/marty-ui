"""Frozen URL helper identity and formatter/error observations."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "contracts/canvas-url-template-python-reference.json"
SCENARIOS = ROOT / "contracts/canvas-url-template-scenarios.json"
ADAPTER = "issuance.infrastructure.adapters.canvas_credentials_adapter"
SOURCE_COMMIT = "578e86ef43166be79add2d812e92ef650535edaa"


def reference():
    return json.loads(REFERENCE.read_text(encoding="utf-8"))


def test_frozen_artifacts_pin_complete_cases_and_original_source_closure():
    for path, digest in [
        (
            REFERENCE,
            "1824310cfaaa929cb0c902ac4d54d18c912926e37eb28aa17c5d4f1c095b092d",
        ),
        (
            SCENARIOS,
            "ed71d0bcc3c86c90523079814510871b401ae683199df54c413c01aab925b606",
        ),
    ]:
        assert (
            hashlib.sha256(
                path.read_bytes().decode("utf-8").replace("\r\n", "\n").encode("utf-8")
            ).hexdigest()
            == digest
        )
    value = reference()
    assert value["source_commit"] == SOURCE_COMMIT
    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    assert [row["id"] for row in value["observations"]] == [
        row["id"] for row in scenarios["cases"]
    ]
    assert len(value["observations"]) == 123
    assert sum("error" in row for row in value["observations"]) == 54
    assert value["selected_definitions"][ADAPTER] == [
        "CredentialDeliveryRecord",
        "_badgr_assertion_url",
        "_badgr_revoke_url",
        "_badgr_validation_url",
        "os",
        "quote",
    ]
    assert value["source_blobs"] == {
        "issuance.domain.entities": "1b5e2eba90c1ec13c1a38135f4da92813f1d1073",
        ADAPTER: "c86671e2b2ab5bb8a72de78a9bdadb0f340a5ec8",
    }


def test_known_formatter_quote_and_error_observations_are_independent():
    rows = {v["id"]: v for v in reference()["observations"]}
    assert (
        rows["assertion-default"]["url"]
        == "https://api.example/v2/badgeclasses/badge%20%2F%E9%9B%AA%25/assertions"
    )
    assert (
        rows["validation-default"]["url"]
        == "https://api.example/v2/badgeclasses/badge%20%2F%E9%9B%AA%25"
    )
    assert (
        rows["revoke-default"]["url"]
        == "https://api.example/v2/assertions/award%20%2F%E9%9B%AA%25"
    )
    for operation in ("assertion", "validation", "revoke"):
        assert rows[f"{operation}-literal-escaped"]["url"] == "/{literal}/{}"
        assert rows[f"{operation}-deterministic-attribute"]["url"] == "/str"
        assert rows[f"{operation}-position"]["error"]["type"] == "IndexError"
        assert rows[f"{operation}-missing-name"]["error"] == {
            "type": "KeyError",
            "message": "'missing'",
        }
        assert (
            rows[f"{operation}-quote-before-unused-format"]["error"]["type"]
            == "UnicodeEncodeError"
        )
        field = "external_credential_id" if operation == "revoke" else "badgeclass_id"
        assert rows[f"{operation}-no-recursive-replace"]["url"].startswith(
            "/{" + field + "}/"
        )
    assert (
        rows["validation-badge-missing"]["error"]["message"]
        == "CANVAS_CREDENTIALS_BADGECLASS_ID is required for Canvas Credentials validation"
    )
    assert (
        rows["assertion-badge-missing"]["error"]["message"]
        == "CANVAS_CREDENTIALS_ISSUER_ID is required when assertion scope is 'issuers'"
    )
