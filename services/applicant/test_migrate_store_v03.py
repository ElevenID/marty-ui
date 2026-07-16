from __future__ import annotations

import json

import pytest

from services.applicant.migrate_store_v03 import migrate


def test_migration_renames_template_and_separates_data(tmp_path, monkeypatch):
    path = tmp_path / "applicants.json"
    path.write_text(json.dumps({
        "applications": [{
            "id": "application-1",
            "applicant_id": "applicant-1",
            "organization_id": "org-1",
            "credential_configuration_id": "credential-1",
            "status": "approved",
            "metadata": {
                "given_name": "Ada",
                "canvas_lti": {"state": "state-1"},
                "credential_offer_uri": "openid-credential-offer://offer-1",
                "auto_approve": True,
            },
            "created_at": "2026-07-11T00:00:00Z",
            "updated_at": "2026-07-11T00:00:00Z",
        }],
    }), encoding="utf-8")
    monkeypatch.setenv("APPLICATION_TEMPLATE_MIGRATION_MAP", '{"credential-1":"application-template-1"}')

    assert migrate(path) is True

    payload = json.loads(path.read_text(encoding="utf-8"))
    application = payload["applications"][0]
    assert payload["schema_version"] == "MIP/0.3.0"
    assert application["credential_template_id"] == "credential-1"
    assert application["application_template_id"] == "application-template-1"
    assert application["form_data"] == {"given_name": "Ada"}
    assert application["integration_context"] == {"canvas_lti": {"state": "state-1"}}
    assert application["system_data"]["credential_offer_uri"].endswith("offer-1")
    assert application["system_data"]["approval_strategy"] == "AUTO"
    assert application["claim_state"] == "OFFER_READY"
    assert "metadata" not in application
    assert path.with_suffix(".json.mip-0.2.bak").exists()


def test_migration_aborts_without_resolvable_application_template(tmp_path, monkeypatch):
    path = tmp_path / "applicants.json"
    original = {"applications": [{
        "id": "application-unresolved",
        "credential_configuration_id": "credential-missing",
        "metadata": {},
    }]}
    path.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setenv("APPLICATION_TEMPLATE_MIGRATION_MAP", "{}")

    with pytest.raises(RuntimeError, match="application-unresolved"):
        migrate(path)

    assert json.loads(path.read_text(encoding="utf-8")) == original
    assert not path.with_suffix(".json.mip-0.2.bak").exists()
