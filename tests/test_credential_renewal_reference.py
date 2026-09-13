"""Repo-local frozen guards; live legacy replay is a separate explicit command."""

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture_credential_renewal_reference.py"
CAPTURE = runpy.run_path(str(SCRIPT))
FROZEN = json.loads((ROOT / "contracts/credential-renewal-python-reference.json").read_text(encoding="utf-8"))
CASES = {case["case"]: case for case in FROZEN["cases"]}
SOURCE = "synthetic-source-credential"


def state(case, phase="after"):
    return FROZEN["states"][case[phase]["$ref"].removeprefix("#/states/")]


def owners(case):
    return [row for row in case["observations"] if "owner_enter" in row]


def ports(case):
    return [row for row in case["observations"] if "port" in row]


def test_closed_cases_and_source_binding_provenance():
    assert FROZEN["schema"] == "marty.credential-renewal-python-reference/v1"
    assert len(CASES) == 31
    assert [row["input"] for row in FROZEN["cases"]] == list(CAPTURE["CASES"])
    reference = FROZEN["reference"]
    assert reference["source_commit"] == "87eae30788924921a42848425d315e2f33f7ae41"
    assert reference["source_blobs"] == CAPTURE["SOURCES"]
    assert len(reference["source_blobs"]) == 10
    assert reference["binding_version"] == "0.1.60"
    assert reference["binding_binary_sha256"] == [
        "94b41c5125e580edb1809a101561c3bfa5c1fb0839e24a8596ffdf7bdc5fa44b"
    ]
    assert "NOT PostgreSQL" in reference["scope"]
    assert "signer and transport controlled" in reference["crypto_scope"]


def test_every_full_snapshot_is_losslessly_addressed_and_used():
    referenced = set()

    def visit(value):
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            if "$ref" in value:
                assert set(value) == {"$ref"}
                assert value["$ref"].startswith("#/states/")
                referenced.add(value["$ref"].removeprefix("#/states/"))
            else:
                for child in value.values():
                    visit(child)

    visit(FROZEN["cases"])
    assert referenced == set(FROZEN["states"])
    assert len(referenced) == 22
    for digest, snapshot in FROZEN["states"].items():
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(encoded).hexdigest() == digest
        assert set(snapshot) == {"transactions", "credentials", "delivery_records", "events"}
        for rows in snapshot.values():
            for row in rows:
                if "created_at" in row:
                    assert row["created_at"] == "2023-11-14T22:13:20+00:00"


@pytest.mark.parametrize("name,status,detail", [
    ("missing-key", 401, "X-API-Key header is missing"),
    ("wrong-key", 401, "Invalid API Key"),
    ("missing-tenant", 403, "Trusted organization context is required"),
    ("foreign-tenant", 404, "Resource not found"),
    ("missing-source", 404, "Issued credential not found"),
    ("inactive-source", 409, "Only active credentials can be renewed."),
    ("already-renewed", 409, "Credential has already been renewed."),
    ("missing-source-transaction", 409, "Source issuance transaction is unavailable."),
    ("not-renewable", 409, "Credential Template does not allow renewal."),
    ("missing-source-issuer", 409, "Source issuance lacks an issuer_did and cannot be renewed safely."),
    ("missing-expiry", 409, "Credential has no renewal eligibility date."),
    ("before-window", 409, {"code": "RENEWAL_NOT_YET_AVAILABLE", "eligible_at": "2023-11-14T22:13:20.000001+00:00", "message": "Credential is outside its renewal window."}),
    ("invalid-idempotency-key", 422, "idempotency key must contain 1-128 ASCII letters, digits, '.', '_', ':', or '-'"),
    ("direct-signing-header", 422, "Direct signing or issuer-profile selection is not allowed; supply issuer_did in the request body."),
])
def test_exact_guard_responses_have_no_mutations_or_external_ports(name, status, detail):
    case = CASES[name]
    assert case["responses"] == [{"status": status, "content_type": "application/json", "body": {"detail": detail}}]
    assert case["before"] == case["after_first"] == case["after"]
    assert ports(case) == []
    assert all(row.get("repository", "").startswith("get_") for row in case["observations"] if "repository" in row)
    if name in {"missing-key", "wrong-key"}:
        assert case["observations"] == []


def test_ordinary_offer_window_and_idempotency_preserve_full_response_and_link():
    for name in ("ordinary-offer", "at-window", "after-expiry", "ordinary-keyed-retry"):
        case = CASES[name]
        response = case["responses"][0]
        assert response["status"] == 200
        assert set(response["body"]) == {"transaction_id", "source_credential_id", "credential_offer_uri", "credential_offer_uris", "credential_offer_labels", "expires_at"}
        assert response["body"]["expires_at"] == "2023-11-21T22:13:20+00:00"
        tx = state(case)["transactions"][0]
        assert tx["id"] == response["body"]["transaction_id"]
        assert tx["renewal_of_credential_id"] == SOURCE
        assert tx["application_id"] == "synthetic-application"
        assert tx["status"] == "pending"
    retry = CASES["ordinary-keyed-retry"]
    assert retry["responses"][0] == retry["responses"][1]
    assert retry["after_first"] == retry["after"]
    marker = retry["observations"].index({"request": "renewal-retry"})
    assert [row["port"] for row in retry["observations"][marker:] if "port" in row] == ["organization"]
    conflict = CASES["ordinary-keyed-conflict"]
    assert conflict["responses"][1] == {"status": 409, "content_type": "application/json", "body": {"detail": "idempotency key was already used for a different issuance request"}}
    expected = deepcopy(state(conflict, "after_first"))
    next(row for row in expected["transactions"] if row["id"] == "synthetic-source-transaction")["claims"]["name"] = "Changed Synthetic Holder"
    assert state(conflict) == expected  # Explicit scenario mutation, not a retry effect.


@pytest.mark.parametrize("mode,algorithm", [("anoncrypt", "ECDH-ES+A256KW"), ("authcrypt", "ECDH-1PU+A256KW")])
def test_actual_encryption_and_link_after_finalization_defect_remain_visible(mode, algorithm):
    automatic = CASES[f"{mode}-automatic-success"]
    direct = CASES[f"{mode}-ordinary-then-direct-delivery"]
    for case in (automatic, direct):
        wallet = next(row for row in ports(case) if row["port"] == "wallet-http")
        assert wallet["encryption_alg"] == algorithm
        assert wallet["encryption_enc"] == "A256CBC-HS512"
        assert wallet["response_status"] == 202
        assert wallet["headers"] == {"Content-Type": "application/didcomm-encrypted+json"}
        assert wallet["endpoint"] == "https://wallet.example/renewal-inbox"
    auto_final = owners(automatic)[-1]
    assert auto_final["owner_enter"] == "_finalize_credential_renewal"
    assert auto_final["renewal_of_credential_id"] is None
    assert auto_final["application_id"] is None
    assert auto_final["status"] == "issued"
    assert [row["owner_enter"] for row in owners(automatic)] == ["renew_issued_credential", "initiate_issuance", "_issuance_response_from_transaction", "_didcomm_sign_and_deliver", "_finalize_credential_renewal"]
    auto_state = state(automatic)
    assert auto_state["credentials"][0]["status"] == "active"
    assert auto_state["credentials"][0]["renewed_to_credential_id"] is None
    assert auto_state["credentials"][1]["renewed_from_credential_id"] is None
    assert auto_state["events"][0]["application_id"] is None
    assert auto_state["transactions"][0]["renewal_of_credential_id"] == SOURCE
    final = owners(direct)[-2]
    assert final["owner_enter"] == "_finalize_credential_renewal"
    assert final["renewal_of_credential_id"] == SOURCE
    assert final["application_id"] == "synthetic-application"
    assert owners(direct)[-1]["owner_enter"] == "revoke_credential"
    direct_state = state(direct)
    assert direct_state["credentials"][0]["status"] == "revoked"
    assert direct_state["credentials"][0]["renewed_to_credential_id"] == direct_state["credentials"][1]["id"]
    assert direct_state["credentials"][1]["renewed_from_credential_id"] == SOURCE
    assert direct_state["events"][0]["application_id"] == "synthetic-application"
    assert ports(direct)[-1]["port"] == "status-publication"


@pytest.mark.parametrize("mode", ["anoncrypt", "authcrypt"])
def test_refusal_missing_subject_and_keyed_mixed_guards_are_not_normalized(mode):
    refused = CASES[f"{mode}-automatic-refused"]
    missing = CASES[f"{mode}-automatic-no-subject"]
    assert refused["responses"][0]["status"] == 200
    assert refused["responses"][0]["body"]["credential_offer_uris"] == {"didcomm": "didcomm://https://wallet.example/renewal-inbox"}
    assert ports(refused)[-1]["response_status"] == 503
    assert missing["responses"][0]["body"]["credential_offer_uris"] == {"didcomm": "didcomm://pending?transaction_id=00000000-0000-0000-0000-000000000001"}
    assert all(row["port"] != "wallet-http" for row in ports(missing))
    for case in (refused, missing):
        snapshot = state(case)
        assert snapshot["transactions"][0]["status"] == "pending"
        assert len(snapshot["credentials"]) == 1
        assert snapshot["events"] == snapshot["delivery_records"] == []
    for suffix in ("keyed-rejection", "mixed-keyed-rejection"):
        case = CASES[f"{mode}-{suffix}"]
        assert case["responses"] == [{"status": 422, "content_type": "application/json", "body": {"detail": "idempotent initiation does not support DIDComm push delivery"}}]
        assert case["before"] == case["after"]
        assert [row["port"] for row in ports(case)] == ["organization", "template", "revocation-binding"]
        assert all(not row.get("repository", "").startswith(("save_", "reserve_", "finalize_")) for row in case["observations"])


@pytest.mark.parametrize("section", ["responses", "observations", "after", "reference", "states"])
def test_exact_comparator_rejects_any_changed_observable(section):
    changed = deepcopy(FROZEN)
    if section in {"reference", "states"}:
        changed[section] = {}
    else:
        changed["cases"][19][section] = None
    with pytest.raises(ValueError, match="Exact renewal reference observations differ"):
        CAPTURE["verify_observations"](changed, FROZEN)


def test_capture_patches_only_explicit_ports_and_checks_origins_and_network():
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    replacements = next(node.iter for node in ast.walk(tree) if isinstance(node, ast.For) and ast.unparse(node.target) == "(obj, name, replacement)")
    names = {row.elts[1].value for row in replacements.elts}
    assert not names.intersection({"renew_issued_credential", "initiate_issuance", "_issuance_response_from_transaction", "_didcomm_sign_and_deliver", "_finalize_credential_renewal", "revoke_credential", "prepare_didcomm_delivery_encryption", "didcomm_encrypt_prepared_delivery", "didcomm_pack_credential", "didcomm_extract_endpoint", "record_post_issuance_deliveries"})
    clocks = {ast.unparse(row.elts[0]) for row in replacements.elts if row.elts[1].value == "datetime"}
    assert clocks == {"routes", "entities", "memory_repository", "canvas_sync_service", "delivery_records"}
    assert 'Path(module.__file__).resolve() != reference / path' in source
    assert 'if not native_binaries:' in source
    assert 'sys.setprofile(previous_profile)' in source
    assert 'return await method(*args, **kwargs)' in source
    for name in ("connect", "connect_ex", "create_connection", "getaddrinfo"):
        assert f'"{name}"' in source
    assert 'assert not socket_attempts' in source
    assert 'patch.dict(os.environ, {}, clear=True)' in source


def test_source_verifier_rejects_changed_blob_without_reference_checkout(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("original\n", encoding="utf-8")
    owner = CAPTURE["OWNER"]
    sources = {"source.py": owner["git_blob"](path.read_bytes())}
    owner["verify_sources"](tmp_path, sources)
    path.write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError):
        owner["verify_sources"](tmp_path, sources)
