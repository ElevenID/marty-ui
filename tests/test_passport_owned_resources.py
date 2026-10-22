"""Source-only ownership/race controls; these ports never qualify a live demo."""
import copy
import json
from urllib.parse import urlsplit

import pytest

from scripts.passport_owned_resources import OwnedPassportResources, PassportOwnershipError
from tests.test_passport_fresh_operations import plan


@pytest.fixture
def owned(tmp_path, monkeypatch):
    (tmp_path / "work").mkdir()
    (tmp_path / "private").mkdir()
    monkeypatch.chdir(tmp_path / "work")
    records, calls, identities = {}, [], {}
    key = {"kty": "EC", "crv": "P-256", "x": "source-control-x", "y": "source-control-y"}
    status = {"certificate": "VALID", "key_denied": True, "sessions_denied": True}

    def request(role, method, path, body):
        calls.append((role, method, path))
        route = urlsplit(path).path
        if route.endswith("/api-keys"):
            return 200, {**body, "id": "new-key", "organization_id": "org-a",
                         "scope_type": "organization", "enabled": True, "key": "k" * 40}
        if route.endswith("/api-keys/new-key"):
            return 200, {"success": True}
        if "issuer-identities" in route:
            if route.endswith("/resolve"):
                return (200, {"public_jwk": key}) if role in identities else (404, {})
            if method == "DELETE":
                return 200, {"deleted": identities.pop(role)}
            identities[role] = copy.deepcopy(body)
            return 200, {"created": True, "identity": body}
        if route == "/v1/flows/instances/new-instance":
            return 200, {"id": "new-instance", "organization_id": "org-a", "status": "COMPLETED",
                         "flow_id": journal.value["resources"]["flow_definition_id"]["id"]}
        if route.startswith("/v1/passport/applications/"):
            app = route.split("/")[-2]
            job = next(row for row in jobs if row["application_id"] == app)
            return 200, {**job, "status": "ACTIVE", "completed_at": "2026-10-21T00:00:00Z"}
        if method == "POST" and route.count("/") in (2, 3) and route.split("/")[-1] in (
                "application-templates", "credential-templates", "delivery-destinations", "definitions"):
            identifier = "new-" + str(len(records))
            record = {**body, "id": identifier, "status": "DRAFT"}
            records[route + "/" + identifier] = record
            return 201, copy.deepcopy(record)
        if route.endswith("/activate"):
            records[route.removesuffix("/activate")]["status"] = "ACTIVE"
            return 200, copy.deepcopy(records[route.removesuffix("/activate")])
        if route.endswith("/deprecate"):
            records[route.removesuffix("/deprecate")]["status"] = "DEPRECATED"
            return 200, copy.deepcopy(records[route.removesuffix("/deprecate")])
        if method == "PATCH":
            records[route].update(body, status="DRAFT")
        if method == "DELETE":
            del records[route]
            return 200, {"success": True}
        return (200, copy.deepcopy(records[route])) if route in records else (404, {})

    def private(path, body):
        calls.append(("private", "POST" if body else "GET", path))
        if path.endswith("/revoke"):
            status["certificate"] = "REVOKED"
        return {"certificate_id": journal.value["plan"]["certificate_plan"]["csca"]["certificate_id"],
                "metadata": {"issuer_did": journal.value["plan"]["application"]["issuer_did"]},
                "public_jwk": key, "status": status["certificate"],
                "revoked_at": "2026-10-21T00:00:00Z" if status["certificate"] == "REVOKED" else None}

    journal = OwnedPassportResources(tmp_path / "private/owned.json", "org-a", request=request, private_signing=private)
    original = plan()
    original["application"]["issuer_did"] = "did:web:beta.elevenidllc.com:orgs:org-a"
    fresh = journal.fresh_plan(original)
    journal.create_issuers(fresh)
    blueprints = {field: {"name": "Source control"} for field in (
        "application_template_id", "credential_template_id", "delivery_destination_profile_id", "flow_definition_id")}
    blueprints["flow_definition_id"]["flow_type"] = "physical_document_issuance"
    fresh = journal.create_inputs(fresh, blueprints)
    journal.create_key()
    jobs = [{"organization_id": "org-a", "id": "job-" + str(i), "application_id": "app-" + str(i),
             "flow_execution_id": "new-instance" if i == 0 else "passport-native-batch-companion",
             "bureau_job_id": "bureau-" + str(i)} for i in range(2)]
    journal.owned_job("batch_bound", {"organization_id": "org-a", "jobs": jobs,
                      "owned_flow_instance_ids": ["new-instance"],
                      "standalone_companion_execution_id": "passport-native-batch-companion"})
    selected = {"application_id": "app-0", "source_job_id": "job-0", "bureau_job_id": "bureau-0",
                "flow_instance_id": "new-instance"}
    kwargs = {"selected": selected, "certificate_id": fresh["certificate_plan"]["csca"]["certificate_id"],
              "check_key_denied": lambda: status["key_denied"], "retire_sessions": lambda: status["sessions_denied"]}
    return journal, calls, records, kwargs, status


def test_exact_fresh_setup_and_retirement_preserve_terminal_history(owned):
    journal, calls, records, kwargs, _ = owned
    assert journal.retire(**kwargs)["complete"] is True
    assert all(row["status"] == "DEPRECATED" for row in records.values())
    assert [row[:2] for row in calls if row[0] == "private"] == [
        ("private", "GET"), ("private", "POST"), ("private", "GET")]
    persisted = json.loads(journal.path.read_text())
    assert persisted["cleanup_complete"] is True and len(persisted["jobs"][0]["jobs"]) == 2
    assert "k" * 40 not in journal.path.read_text()
    assert not journal.key_path.exists()


@pytest.mark.parametrize("failure", ["foreign-job", "duplicate-job", "pending-mutation", "changed-resource", "key-revived", "session-revived"])
def test_cleanup_never_qualifies_incomplete_or_changed_authority(owned, failure):
    journal, calls, records, kwargs, status = owned
    before = len(calls)
    if failure == "foreign-job":
        journal.value["jobs"][0]["jobs"][1]["organization_id"] = "foreign"
    elif failure == "duplicate-job":
        journal.value["jobs"][0]["jobs"][1] = journal.value["jobs"][0]["jobs"][0]
    elif failure == "pending-mutation":
        journal.value["operations"].append({"response_received": False})
    elif failure == "changed-resource":
        next(iter(records.values()))["name"] = "unowned replacement"
    elif failure == "key-revived":
        status["key_denied"] = False
    else:
        status["sessions_denied"] = False
    with pytest.raises(PassportOwnershipError):
        journal.retire(**kwargs)
    assert journal.value["cleanup_complete"] is False
    if failure == "key-revived":
        assert journal.key_path.exists()
    if failure in ("foreign-job", "duplicate-job", "pending-mutation"):
        assert len(calls) == before


def test_setup_refuses_resource_id_adoption_and_reused_journal(owned):
    journal, calls, _, _, _ = owned
    with pytest.raises(ValueError, match="Pending native batch"):
        OwnedPassportResources(journal.path, "org-a", request=None, private_signing=None)
    blueprints = {field: {"id": "existing", "name": "Existing"} for field in journal.value["resources"]}
    before = len(calls)
    with pytest.raises(PassportOwnershipError, match="Cannot adopt"):
        journal.create_inputs(journal.value["plan"], blueprints)
    assert len(calls) == before
