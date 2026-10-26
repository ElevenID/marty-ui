"""Source-only ownership/race controls; these ports never qualify a live demo."""
import copy
import hashlib
import json
from uuid import uuid4
from pathlib import Path
from scripts.passport_supported_flow_start import STEPS
from urllib.parse import urlsplit

import pytest

from scripts.passport_owned_resources import (
    OwnedPassportResources, PassportOwnershipError, retire_failed_owned_resources,
)
from scripts import probe_passport_beta_native_batch as batch
from tests.test_passport_fresh_operations import plan


@pytest.fixture
def owned(tmp_path, monkeypatch):
    (tmp_path / "work").mkdir()
    (tmp_path / "private").mkdir(mode=0o700)
    monkeypatch.chdir(tmp_path / "work")
    records, calls, identities = {}, [], {}
    key = {"kty": "EC", "crv": "P-256", "x": "source-control-x", "y": "source-control-y"}
    status = {"certificate": "VALID", "key_denied": True, "sessions_denied": True}

    def request(role, method, path, body, headers=None):
        calls.append((role, method, path))
        route = urlsplit(path).path
        if route.endswith("/api-keys"):
            return 200, {**body, "id": "new-key", "organization_id": "00000000-0000-0000-0000-000000000001",
                         "scope_type": "ORGANIZATION", "enabled": True, "key": "k" * 40}
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
            return 200, {"id": "new-instance", "organization_id": "00000000-0000-0000-0000-000000000001", "status": "COMPLETED",
                         "flow_id": journal.value["resources"]["flow_definition_id"]["id"]}
        if route.startswith("/v1/passport/applications/"):
            app = route.split("/")[-2]
            job = next(row for row in jobs if row["application_id"] == app)
            return 200, {**job, "status": "ACTIVE", "completed_at": "2026-10-21T00:00:00Z"}
        if method == "POST" and route.count("/") in (2, 3) and route.split("/")[-1] in (
                "application-templates", "credential-templates", "delivery-destinations", "definitions"):
            if route == "/v1/application-templates":
                credential = records.get("/v1/credential-templates/" + body.get("credential_template_id", ""))
                assert credential and credential["status"] == "ACTIVE"
                assert headers == {"idempotency-key": "passport-demo-" + journal.value["run_id"]}
            identifier = str(uuid4())
            record = {**body, "id": identifier, "status": "DRAFT", "is_system": False, "resolved_steps": list(STEPS)}
            records[route + "/" + identifier] = record
            return (201 if route == "/v1/delivery-destinations" else 200), copy.deepcopy(record)
        if route.endswith("/validate"):
            return 200, {"valid": True, "errors": []}
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

    journal = OwnedPassportResources(tmp_path / "private/owned.json", "00000000-0000-0000-0000-000000000001", request=request, private_signing=private)
    original = plan()
    original["application"]["organization_id"] = journal.organization
    original["certificate_plan"]["organization_id"] = journal.organization
    original["application"]["issuer_did"] = "did:web:beta.elevenidllc.com:orgs:00000000-0000-0000-0000-000000000001"
    fresh = journal.fresh_plan(original)
    assert len(fresh["application"]["issuer_did"].split(":")) == 5
    assert fresh["application"]["issuer_did"].endswith("-demo-" + journal.value["run_id"])
    journal.create_issuers(fresh)
    fresh = journal.create_inputs(fresh, {"name_prefix": "Source control",
        "compliance_profile_id": "10000000-0000-0000-0000-000000000005"})
    journal.create_key()
    jobs = [{"organization_id": "00000000-0000-0000-0000-000000000001", "id": "job-" + str(i), "application_id": "app-" + str(i),
             "flow_execution_id": "new-instance" if i == 0 else "passport-native-batch-companion",
             "bureau_job_id": "bureau-" + str(i)} for i in range(2)]
    journal.owned_job("batch_bound", {"organization_id": "00000000-0000-0000-0000-000000000001", "jobs": jobs,
                      "owned_flow_instance_ids": ["new-instance"],
                      "standalone_companion_execution_id": "passport-native-batch-companion"})
    selected = {"application_id": "app-0", "source_job_id": "job-0", "bureau_job_id": "bureau-0",
                "flow_instance_id": "new-instance"}
    journal.value["flow_start"] = {"state": "OBSERVED", "instance_id": "new-instance",
                                    "application_id": "app-0", "source_job_id": "job-0"}
    journal.save()
    kwargs = {"selected": selected, "certificate_id": fresh["certificate_plan"]["csca"]["certificate_id"],
              "check_key_denied": lambda: status["key_denied"], "retire_sessions": lambda: status["sessions_denied"]}
    return journal, calls, records, kwargs, status


def test_fresh_issuer_rejects_an_extra_did_path(owned):
    journal, _, _, _, _ = owned
    plan_value = copy.deepcopy(journal.value["plan"])
    plan_value["application"]["issuer_did"] += ":another"
    with pytest.raises(PassportOwnershipError, match="did:web organization slug"):
        journal.fresh_plan(plan_value)


def test_exact_fresh_setup_and_retirement_preserve_terminal_history(owned):
    journal, calls, records, kwargs, _ = owned
    assert journal.retire(**kwargs)["complete"] is True
    assert ("flow", "POST", "/v1/api-keys?organization_id=" + journal.organization) in calls
    assert ("flow", "DELETE", "/v1/api-keys/new-key?organization_id=" + journal.organization) in calls
    assert all(row["status"] == "DEPRECATED" for row in records.values())
    assert [row[:2] for row in calls if row[0] == "private"] == [
        ("private", "GET"), ("private", "POST"), ("private", "GET")]
    persisted = json.loads(journal.path.read_text())
    assert persisted["cleanup_complete"] is True and len(persisted["jobs"][0]["jobs"]) == 2
    assert "k" * 40 not in journal.path.read_text()
    assert not journal.key_path.exists()


@pytest.fixture
def failed_owned(owned):
    """Protocol/control fixture only; never a production cleanup result."""
    original, calls, records, _, authority = owned
    canonical_journal = original.path.with_name("native-handoff.owned-resources.json")
    original.path.rename(canonical_journal)
    original.path = canonical_journal
    batch.clear_private_state(original.key_path)  # Simulate already-retired original authority.
    bound = original.value["jobs"][0]
    bound["batch_id"] = str(uuid4())
    for row in bound["jobs"]:
        row.update(id=str(uuid4()), application_id=str(uuid4()))
    selected, companion = bound["jobs"]
    original.value.pop("flow_start")  # Actual older journals predate PR1579.
    original.value["jobs"].append({"event": "companion_terminal", **companion,
        "status": "ACTIVE", "completed_at": "2026-10-21T00:00:00Z"})
    original.value["jobs"].append({"event": "companion_created", **companion,
        "flow_instance_created": False, "issuer_did": original.value["plan"]["application"]["issuer_did"]})
    original.value["authority_retirement"] = {"complete": True, "keyDenied": True,
        "sessionsRetired": 3, "qualificationEligible": False}
    original.save()
    wire = {"schema": "marty.passport-beta-native-pending/v1", "state": "dispatching",
        "organization_id": original.organization, "batch_id": bound["batch_id"],
        "selected_source_job_id": selected["id"], "selected_application_id": selected["application_id"],
        "selected_flow_instance_id": selected["flow_execution_id"],
        "companion_source_job_id": companion["id"], "companion_application_id": companion["application_id"],
        "companion_flow_execution_id": companion["flow_execution_id"], "wire_key_b64": "NEVER_COPY_WIRE_KEY"}
    def source(name, value):
        path = original.path.with_name(name)
        batch._write_private_state(path, value, initial=True)
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    refs = {"journal_ref": {"path": str(original.path), "sha256": hashlib.sha256(original.path.read_bytes()).hexdigest()},
        "wire_ref": source("failed-wire.json", wire),
        "failure_ref": source("passport-failure-" + uuid4().hex + ".json", {"schema": "marty.passport-private-failure/v1",
            "stage": "material-continuity", "errorType": "MissingFlowSod", "qualificationEligible": False})}
    refs["fixture_ref"] = source("fixture.json", {"schema": "marty.passport-fresh-private/v3",
        "privateStatePath": refs["wire_ref"]["path"],
        "privateHandoffPath": str(original.path.with_name("native-handoff.json")),
        "plan": {"application": {"organization_id": original.organization}},
        "custody": {"serviceToken": "NEVER_COPY_FIXTURE_TOKEN"}})
    snapshots = {ref["path"]: Path(ref["path"]).read_bytes() for ref in refs.values()}
    base = {"credential_template_id": original.value["resources"]["credential_template_id"]["id"],
            "delivery_destination_profile_id": original.value["resources"]["delivery_destination_profile_id"]["id"],
            "issuer_did": original.value["plan"]["application"]["issuer_did"]}
    jobs = {row["id"]: {**row, **base, "status": "READY_FOR_ACTIVATION" if row is selected else "ACTIVE",
        "completed_at": None if row is selected else "2026-10-21T00:00:00Z"} for row in bound["jobs"]}
    model = {"jobs": jobs, "flow_status": "IN_PROGRESS", "lost_cancel": False,
             "wrong_audit": False, "extra_flow": False, "native_posts": [], "flow_posts": 0}
    real = original.request
    def flow():
        return {"id": selected["flow_execution_id"], "organization_id": original.organization,
            "flow_id": original.value["resources"]["flow_definition_id"]["id"],
            "status": model["flow_status"], "context_data": {"physical_document_job": copy.deepcopy(selected)}}
    def request(role, method, path, body=None, headers=None):
        if role == "api":
            row = next(job for job in jobs.values() if job["application_id"] in path)
            if method == "GET":
                assert not path.endswith("production-status")
                return 200, copy.deepcopy(row)
            assert row["id"] == selected["id"] and path.endswith("/cancel")
            model["native_posts"].append((copy.deepcopy(body), copy.deepcopy(headers)))
            row["status"] = "CANCELLED"
            model.setdefault("audit", {"event_id": str(uuid4()), "job_id": selected["id"],
                "organization_id": original.organization, "actor_kind": "AUTHENTICATED_PASSPORT_TENANT",
                "actor_organization_id": original.organization, "prior_status": "READY_FOR_ACTIVATION",
                "reason_code": body["reason_code"], "reason": body["reason"],
                "recorded_at": "2026-10-26T00:00:00Z", "bureau_cancellation_requested": False})
            audit = copy.deepcopy(model["audit"])
            if model["wrong_audit"]:
                audit["actor_organization_id"] = "foreign"
            if model["lost_cancel"]:
                model["lost_cancel"] = False
                raise OSError("response lost after actual model mutation")
            return 200, {"job": copy.deepcopy(row), "administrative_cancellation": audit,
                "bureau_cancellation_requested": False, "flow_cancellation_requested": False,
                "replayed": len(model["native_posts"]) > 1}
        if path.startswith("/v1/flows/instances?"):
            return 200, model.get("list_override", [flow()] + ([{**flow(), "id": "unowned-extra"}] if model["extra_flow"] else []))
        if path.startswith("/v1/flows/instances/"):
            if method == "POST":
                assert path.endswith("/cancel")
                model["flow_posts"] += 1
                model["flow_status"] = "CANCELLED"
            return 200, flow()
        return real(role, method, path, body, headers)
    args = {**refs, "request": request, "private_signing": original.private_signing,
            "verify_runtime": lambda: "a" * 64}
    path = original.path.with_name("failed-continuation.json")
    return original, calls, records, authority, model, args, path, snapshots


def test_failed_cleanup_uses_original_ownership_without_qualifying_or_copying_secrets(failed_owned):
    original, calls, _, _, model, args, path, snapshots = failed_owned
    start = len(calls)
    continuation = OwnedPassportResources.failed_continuation(path, **args)
    result = continuation.retire_failed(retire_cleanup_authority=lambda: True)
    assert result["complete"] and result["qualificationEligible"] is False
    assert result["bureauCancellationRequested"] is False
    assert len(model["native_posts"]) == model["flow_posts"] == 1
    assert "NEVER_COPY_WIRE_KEY" not in path.read_text()
    assert "NEVER_COPY_FIXTURE_TOKEN" not in path.read_text()
    assert "k" * 40 not in path.read_text()
    assert "flow_start" not in continuation.value
    assert not any("api-keys/new-key" in row[2] for row in calls[start:])
    assert original.value["cleanup_complete"] is False
    assert all(Path(name).read_bytes() == raw for name, raw in snapshots.items())
    with pytest.raises(PassportOwnershipError, match="cannot qualify"):
        continuation.retire(selected={}, certificate_id="", check_key_denied=lambda: True, retire_sessions=lambda: True)


def test_failed_cleanup_lost_native_response_requires_explicit_same_key_recovery(failed_owned):
    _, _, _, _, model, args, path, snapshots = failed_owned
    continuation = OwnedPassportResources.failed_continuation(path, **args)
    model["lost_cancel"] = True
    with pytest.raises(OSError, match="response lost"):
        continuation.retire_failed(retire_cleanup_authority=lambda: True)
    assert len(model["native_posts"]) == 1 and model["flow_posts"] == 0
    assert json.loads(path.read_text())["cleanup_complete"] is False
    with pytest.raises(PassportOwnershipError, match="already exists"):
        OwnedPassportResources.failed_continuation(path, **args)
    resumed = OwnedPassportResources.failed_continuation(path, resume=True, **args)
    assert resumed.retire_failed(retire_cleanup_authority=lambda: True)["qualificationEligible"] is False
    assert model["native_posts"][0] == model["native_posts"][1]
    assert all(Path(name).read_bytes() == raw for name, raw in snapshots.items())


def test_failed_cleanup_authority_only_resume_verifies_retired_state_without_repeat_mutation(failed_owned):
    _, calls, _, _, model, args, path, snapshots = failed_owned
    continuation = OwnedPassportResources.failed_continuation(path, **args)
    with pytest.raises(PassportOwnershipError, match="authority is not retired"):
        continuation.retire_failed(retire_cleanup_authority=lambda: False)
    assert json.loads(path.read_text())["failed_cleanup"]["stage"] == "RESOURCES_RETIRED_AUTHORITY_PENDING"
    start, native_posts, flow_posts = len(calls), len(model["native_posts"]), model["flow_posts"]
    result = retire_failed_owned_resources(path, resume=True, **args, retire_cleanup_authority=lambda: True)
    assert result["complete"] and result["authorityOnlyResume"] and result["qualificationEligible"] is False
    assert len(model["native_posts"]) == native_posts and model["flow_posts"] == flow_posts
    assert all(method == "GET" or (method == "POST" and "/issuer-identities/resolve" in route)
               for _, method, route in calls[start:])
    assert all(Path(name).read_bytes() == raw for name, raw in snapshots.items())


@pytest.mark.parametrize("gap", ["active-template", "missing-certificate", "changed-companion",
                                  "foreign-singleton", "nonterminal-singleton"])
def test_failed_cleanup_authority_only_resume_denies_missing_or_changed_terminal_readback(failed_owned, gap):
    original, calls, records, _, model, args, path, _ = failed_owned
    continuation = OwnedPassportResources.failed_continuation(path, **args)
    with pytest.raises(PassportOwnershipError):
        continuation.retire_failed(retire_cleanup_authority=lambda: False)
    if gap == "active-template":
        identifier = original.value["resources"]["credential_template_id"]["id"]
        records["/v1/credential-templates/" + identifier]["status"] = "ACTIVE"
    elif gap == "missing-certificate":
        args["private_signing"] = lambda *a: {}
    elif gap == "changed-companion":
        next(row for row in model["jobs"].values() if row["status"] == "ACTIVE")["tracking_number"] = "changed"
    else:
        _, rows = args["request"]("flow", "GET", "/v1/flows/instances?source-control", None)
        if gap == "foreign-singleton":
            rows[0]["id"] = "foreign-instance"
        else:
            rows[0]["status"] = "IN_PROGRESS"
        model["list_override"] = rows
        # A mutable local digest must not override explicit terminal ownership.
        continuation.value["failed_cleanup"]["owned_flow_instances_readback_sha256"] = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
        continuation.save()
    start, native_posts, flow_posts = len(calls), len(model["native_posts"]), model["flow_posts"]
    with pytest.raises(PassportOwnershipError):
        retire_failed_owned_resources(path, resume=True, **args, retire_cleanup_authority=lambda: True)
    assert json.loads(path.read_text())["cleanup_complete"] is False
    assert len(model["native_posts"]) == native_posts and model["flow_posts"] == flow_posts
    assert all(method == "GET" or (method == "POST" and "/issuer-identities/resolve" in route)
               for _, method, route in calls[start:])


def test_failed_cleanup_controller_closes_dedicated_authority_on_constructor_failure(failed_owned):
    _, _, _, _, model, args, path, _ = failed_owned
    closed = []
    def unavailable():
        raise OSError("runtime verifier unavailable")
    args["verify_runtime"] = unavailable
    with pytest.raises(OSError, match="runtime verifier"):
        retire_failed_owned_resources(path, **args, retire_cleanup_authority=lambda: closed.append(True) or True)
    assert closed == [True] and not path.exists()
    assert model["native_posts"] == [] and model["flow_posts"] == 0


@pytest.mark.parametrize("gap", ["extra-job", "wrong-companion", "unknown-start"])
def test_failed_cleanup_rejects_ambiguous_creation_before_requests(failed_owned, gap):
    original, _, _, _, model, args, path, _ = failed_owned
    if gap == "extra-job":
        original.value["jobs"].append(copy.deepcopy(original.value["jobs"][-1]))
    elif gap == "wrong-companion":
        original.value["jobs"][-1]["id"] = str(uuid4())
    else:
        original.value["flow_start"] = {"state": "UNKNOWN"}
    original.save()
    args["journal_ref"]["sha256"] = hashlib.sha256(original.path.read_bytes()).hexdigest()
    with pytest.raises(PassportOwnershipError):
        OwnedPassportResources.failed_continuation(path, **args)
    assert not path.exists() and model["native_posts"] == []


@pytest.mark.parametrize("gap", ["other-directory", "ambiguous-failure", "wrong-fixture-path"])
def test_failed_cleanup_requires_original_producer_failure_provenance(failed_owned, gap):
    original, _, _, _, model, args, path, _ = failed_owned
    if gap == "other-directory":
        directory = original.path.parent / "other-run"
        directory.mkdir(mode=0o700)
        changed = directory / Path(args["failure_ref"]["path"]).name
        batch._write_private_state(changed, json.loads(Path(args["failure_ref"]["path"]).read_bytes()), initial=True)
        args["failure_ref"] = {"path": str(changed), "sha256": hashlib.sha256(changed.read_bytes()).hexdigest()}
    elif gap == "ambiguous-failure":
        changed = original.path.with_name("passport-failure-" + uuid4().hex + ".json")
        batch._write_private_state(changed, json.loads(Path(args["failure_ref"]["path"]).read_bytes()), initial=True)
    else:
        changed = Path(args["fixture_ref"]["path"])
        value = json.loads(changed.read_bytes())
        value["privateStatePath"] = str(changed.with_name("unrelated-wire.json"))
        batch._write_private_state(changed, value, initial=False)
        args["fixture_ref"]["sha256"] = hashlib.sha256(changed.read_bytes()).hexdigest()
    with pytest.raises(PassportOwnershipError):
        OwnedPassportResources.failed_continuation(path, **args)
    assert not path.exists() and model["native_posts"] == []


@pytest.mark.parametrize("gap", ["duplicate-json-key", "changed-intent", "invented-stage"])
def test_failed_cleanup_resume_rejects_changed_or_ambiguous_state(failed_owned, gap):
    _, _, _, _, model, args, path, _ = failed_owned
    continuation = OwnedPassportResources.failed_continuation(path, **args)
    model["lost_cancel"] = True
    with pytest.raises(OSError):
        continuation.retire_failed(retire_cleanup_authority=lambda: True)
    value = json.loads(path.read_text())
    if gap == "changed-intent":
        value["failed_cleanup"]["cancel_intent"]["body"]["expected_job_id"] = str(uuid4())
    elif gap == "invented-stage":
        value["failed_cleanup"]["stage"] = "READY_TO_ACTIVATE"
    encoded = json.dumps(value)
    if gap == "duplicate-json-key":
        encoded = '{"cleanup_complete":true,' + encoded[1:]
    path.write_text(encoded)
    with pytest.raises(PassportOwnershipError):
        OwnedPassportResources.failed_continuation(path, resume=True, **args)
    assert len(model["native_posts"]) == 1 and model["flow_posts"] == 0


@pytest.mark.parametrize("gap", ["selected-active", "wrong-audit", "extra-flow", "authority-not-retired", "runtime-changed"])
def test_failed_cleanup_stops_without_success_claim_on_gaps(failed_owned, gap):
    _, _, _, _, model, args, path, _ = failed_owned
    continuation = OwnedPassportResources.failed_continuation(path, **args)
    if gap == "selected-active":
        next(row for row in model["jobs"].values() if row["status"] != "ACTIVE")["status"] = "ACTIVE"
    elif gap == "wrong-audit":
        model["wrong_audit"] = True
    elif gap == "extra-flow":
        model["extra_flow"] = True
    elif gap == "runtime-changed":
        # The verifier is a bound operation port, never an imported report flag.
        args["verify_runtime"] = lambda: "b" * 64
        with pytest.raises(PassportOwnershipError, match="runtime changed"):
            OwnedPassportResources.failed_continuation(path, resume=True, **args)
        return
    with pytest.raises(PassportOwnershipError):
        continuation.retire_failed(retire_cleanup_authority=lambda: gap != "authority-not-retired")
    assert json.loads(path.read_text())["cleanup_complete"] is False
    assert json.loads(path.read_text())["failed_cleanup"]["qualificationEligible"] is False
    if gap == "selected-active":
        assert model["native_posts"] == [] and model["flow_posts"] == 0


def test_rejected_key_response_retains_exact_authority_for_teardown(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    org = "00000000-0000-0000-0000-000000000001"
    journal = OwnedPassportResources(private / "owned.json", org,
        request=lambda role, method, path, body, headers=None: (200, {
            **body, "id": "new-key", "organization_id": org,
            "scope_type": "WRONG", "enabled": True, "key": "k" * 40}),
        private_signing=lambda *args: None)
    with pytest.raises(PassportOwnershipError, match="Scoped passport API key"):
        journal.create_key()
    assert json.loads(journal.path.read_text())["api_key_id"] == "new-key"
    assert "k" * 40 not in journal.path.read_text()
    assert journal.key_path.exists()


@pytest.mark.parametrize("failure", ["foreign-job", "duplicate-job", "pending-mutation", "unknown-start", "changed-resource", "key-revived", "session-revived"])
def test_cleanup_never_qualifies_incomplete_or_changed_authority(owned, failure):
    journal, calls, records, kwargs, status = owned
    before = len(calls)
    if failure == "foreign-job":
        journal.value["jobs"][0]["jobs"][1]["organization_id"] = "foreign"
    elif failure == "duplicate-job":
        journal.value["jobs"][0]["jobs"][1] = journal.value["jobs"][0]["jobs"][0]
    elif failure == "pending-mutation":
        journal.value["operations"].append({"response_received": False})
    elif failure == "unknown-start":
        journal.value["flow_start"]["state"] = "UNKNOWN"
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
    if failure in ("foreign-job", "duplicate-job", "pending-mutation", "unknown-start"):
        assert len(calls) == before


def test_setup_refuses_resource_id_adoption_and_reused_journal(owned):
    journal, calls, _, _, _ = owned
    with pytest.raises(ValueError, match="Pending native batch"):
        OwnedPassportResources(journal.path, "00000000-0000-0000-0000-000000000001", request=None, private_signing=None)
    reference_plan = {"name_prefix": "Existing", "compliance_profile_id": "existing", "id": "adopted"}
    before = len(calls)
    with pytest.raises(PassportOwnershipError, match="cannot adopt"):
        journal.create_inputs(journal.value["plan"], reference_plan)
    assert len(calls) == before


def test_flow_start_intent_precedes_one_input_and_binds_exact_job(owned):
    journal, _, _, _, _ = owned
    journal.value["flow_start"] = None
    journal.save()
    definition = journal.value["resources"]["flow_definition_id"]["id"]
    body = {"organization_id": journal.organization, "flow_definition_id": definition,
            "initial_context": {"physical_document": {"synthetic": True}}}
    row = {"id": "fresh-instance", "organization_id": journal.organization,
           "flow_id": definition, "flow_type": "physical_document_issuance",
           "status": "IN_PROGRESS", "context_data": {"physical_document_job": {
               "id": "fresh-job", "application_id": "fresh-application",
               "organization_id": journal.organization, "flow_execution_id": "fresh-instance",
               "status": "DRAFT",
               "issuer_did": journal.value["plan"]["application"]["issuer_did"]}}}
    calls = []
    def request(method, path, payload):
        calls.append((method, path))
        assert json.loads(journal.path.read_text())["flow_start"]["state"] == "INTENT"
        assert payload == body
        return 200, row
    assert journal.start_selected_flow(body, request) == (200, row)
    assert calls == [("POST", "/v1/flows/instances")]
    assert journal.value["flow_start"]["state"] == "OBSERVED"
    assert journal.value["flow_start"]["source_job_id"] == "fresh-job"
    with pytest.raises(PassportOwnershipError):
        journal.start_selected_flow(body, request)
    assert len(calls) == 1


@pytest.mark.parametrize("listing,expected", [("one", "RECONCILED_AFTER_UNKNOWN_RESPONSE"),
    ("none", "UNKNOWN"), ("two", "UNKNOWN"), ("foreign", "UNKNOWN"),
    ("read-failed", "UNKNOWN")])
def test_lost_flow_start_never_retries_and_reconciles_only_unique_owned_projection(owned, listing, expected):
    journal, _, _, _, _ = owned
    journal.value["flow_start"] = None
    journal.save()
    definition = journal.value["resources"]["flow_definition_id"]["id"]
    body = {"organization_id": journal.organization, "flow_definition_id": definition,
            "initial_context": {"physical_document": {"synthetic": True}}}
    row = {"id": "fresh-instance", "organization_id": journal.organization,
           "flow_id": definition, "flow_type": "physical_document_issuance",
           "status": "IN_PROGRESS", "context_data": {"physical_document_job": {
               "id": "fresh-job", "application_id": "fresh-application",
               "organization_id": journal.organization, "flow_execution_id": "fresh-instance",
               "status": "DRAFT",
               "issuer_did": journal.value["plan"]["application"]["issuer_did"]}}}
    calls = []
    def request(method, path, payload):
        calls.append((method, path))
        if method == "POST":
            assert json.loads(journal.path.read_text())["flow_start"]["state"] == "INTENT"
            raise ConnectionError("response lost")
        assert method == "GET" and payload is None
        assert "organization_id=" + journal.organization in path
        assert "flow_definition_id=" + definition in path
        if listing == "read-failed":
            raise ConnectionError("read failed")
        if listing == "foreign":
            return 200, [{**row, "organization_id": "foreign"}]
        return 200, [row] if listing == "one" else [] if listing == "none" else [row, row]
    with pytest.raises(ConnectionError, match="response lost"):
        journal.start_selected_flow(body, request)
    assert [method for method, _ in calls] == ["POST", "GET"]
    assert journal.value["flow_start"]["state"] == expected
    assert json.loads(journal.path.read_text())["flow_start"]["state"] == expected
    assert "synthetic" not in journal.path.read_text()
