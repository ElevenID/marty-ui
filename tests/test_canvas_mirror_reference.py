"""Frozen Canvas artifact identity, response, and side-effect regression guards."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/issuance-canvas-mirror.json"

# Historical source identities for the frozen corpora, independent of capture tooling.
REVISION = "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26"
ROUTES = "issuance.infrastructure.api.routes"
ADAPTER = "issuance.infrastructure.adapters.canvas_credentials_adapter"
SOURCES = {
    "issuance.infrastructure.api.routes": (
        "services/issuance/infrastructure/api/routes.py",
        "f71dd82163fcb2296209f880fe78d55a130d356b",
    ),
    "issuance.infrastructure.adapters.canvas_credentials_adapter": (
        "services/issuance/infrastructure/adapters/canvas_credentials_adapter.py",
        "c86671e2b2ab5bb8a72de78a9bdadb0f340a5ec8",
    ),
    "issuance.domain.entities": (
        "services/issuance/domain/entities.py",
        "1b5e2eba90c1ec13c1a38135f4da92813f1d1073",
    ),
    "issuance.domain.ports": (
        "services/issuance/domain/ports.py",
        "3454e78deb21af39a1d842ebfed3d8899aa69325",
    ),
    "issuance.infrastructure.adapters.memory_repository": (
        "services/issuance/infrastructure/adapters/memory_repository.py",
        "b9c65f5b35eebe1de9392491b8e3595396ff6565",
    ),
    "issuance.infrastructure.adapters.delivery_records": (
        "services/issuance/infrastructure/adapters/delivery_records.py",
        "eda21f907f3abd1e4652e06400f5a6dcf424952f",
    ),
    "issuance.application.canvas_feature_flags": (
        "services/issuance/application/canvas_feature_flags.py",
        "0fd22c63f09641f886d6c7c4bad5d16393fabe92",
    ),
    "issuance.application.canvas_runtime": (
        "services/issuance/application/canvas_runtime.py",
        "ae2874fb057e19db7cfd6b28dc39a77eba02c3fb",
    ),
    "issuance.application.canvas_lti_services": (
        "services/issuance/application/canvas_lti_services.py",
        "6bde953e9be8c01b51e622668a2cf9fc016f581d",
    ),
    "issuance.application.credential_vct": (
        "services/issuance/application/credential_vct.py",
        "bff0c6bf046e7df15447350d0e4bcc645b8e28d2",
    ),
    "mirror_seed": (
        "tests/test_issuance_changes.py",
        "7ab0a410bd6a4b4507ddd535365fadf7f3dbac03",
    ),
    "startup_evidence": (
        "services/issuance/main.py",
        "d2c7135bffc8d3ea8184233626b7e573f1fb837d",
    ),
    "release_profile": (
        "services/Dockerfile",
        "13bcb60f46601303b0f524427d9d5aa6bce927d9",
    ),
}
RELEASE_IMAGE = "ghcr.io/elevenid/marty-credentials-issuance"
RELEASE_IMAGE_DIGEST = (
    "sha256:815cbba6efc7c91e770a8dd15fe5fa102d252a485073bf60f0e0d5e0a73b28e5"
)
RELEASE_DEPENDENCIES = {"fastapi": "0.109.0", "pydantic": "2.11.7", "httpx": "0.26.0"}
OPERATIONS = (
    "publish_issued_credential_canvas_mirror",
    "process_pending_canvas_mirror_deliveries",
    "process_failed_canvas_mirror_status_syncs",
    "run_canvas_mirror_automation_cycle_endpoint",
    "get_canvas_mirror_health",
    "get_canvas_mirror_provenance",
)


def canonical_json_bytes(raw):
    return raw.decode("utf-8").replace("\r\n", "\n").encode("utf-8")


@pytest.fixture
def artifact():
    return json.loads(
        (ROOT / "contracts/canvas-mirror-python-reference.json").read_text(
            encoding="utf-8"
        )
    )


def assert_artifact_files(contract, read_bytes):
    for owner in ("reference", "scenarios"):
        assert (
            hashlib.sha256(
                canonical_json_bytes(read_bytes(contract[owner]["path"]))
            ).hexdigest()
            == contract[owner]["sha256"]
        )


def assert_connected(contract, reference, scenarios):
    assert contract["phase"] == "frozen-controlled-reference-only"
    assert contract["source_commit"] == reference["source_commit"] == REVISION
    assert reference["sources"] == {
        name: list(value) for name, value in SOURCES.items()
    }
    assert {route["operation"] for route in contract["routes"]} == set(OPERATIONS)
    selected = set(reference["selected_definitions"][ROUTES])
    assert set(OPERATIONS) <= selected
    assert {
        "_verify_management_api_key",
        "_require_trusted_organization",
        "run_canvas_mirror_automation_loop",
        "CanvasMirrorAutomationConfig",
    } <= selected
    expected_http = (
        [case["id"] for case in scenarios["http"]]
        + [
            f"auth_{operation}_{'missing' if key is None else 'wrong'}"
            for operation in scenarios["authentication"]["operations"]
            for key in scenarios["authentication"]["keys"]
        ]
        + [case["id"] for case in scenarios["authentication"]["order_cases"]]
    )
    assert [case["id"] for case in reference["http"]] == expected_http
    assert (
        len(expected_http)
        == len(set(expected_http))
        == contract["observations"]["http"]
    )
    for key, count in (
        ("loop", "controlled_loop"),
        ("provider_cancellation", "provider_cancellation"),
        ("configuration", "configuration"),
    ):
        assert [case["id"] for case in reference[key]] == [
            case["id"] for case in scenarios[key]
        ]
        assert len(reference[key]) == contract["observations"][count]
    assert contract["automation"]["not_the_same_owner_as"] == "CanvasSyncWorker"
    assert contract["native_selection"] == "unchanged"


def require_publication_boundary(contract, read_bytes):
    decoded = {}
    for kind in ("reference", "scenarios"):
        owner = contract[f"publication_boundary_{kind}"]
        raw = canonical_json_bytes(read_bytes(owner["path"]))
        assert hashlib.sha256(raw).hexdigest() == owner["sha256"]
        decoded[kind] = json.loads(raw)
    reference, scenarios = decoded["reference"], decoded["scenarios"]
    assert reference["schema"] == "marty.canvas-publication-boundary-reference/v1"
    assert reference["source_commit"] == scenarios["source_commit"] == REVISION
    assert reference["sources"] == {
        name: list(value) for name, value in SOURCES.items()
    }
    assert (
        reference["scenarios_sha256"]
        == contract["publication_boundary_scenarios"]["sha256"]
    )
    assert contract["publication_boundary_observations"] == {
        "datetime": 10,
        "adapter_cancellation": 2,
        "response_shapes": 3,
    }
    expected_ids = [
        "bridge_milliseconds",
        "badgr_milliseconds",
        "bridge_microseconds",
        "badgr_microseconds",
        "bridge_offset",
        "badgr_offset",
        "bridge_expiry_absent",
        "badgr_expiry_absent",
        "bridge_provider_cancel",
        "badgr_provider_cancel",
        "badgr_empty_result_data_fallback",
        "badgr_first_nonobject_no_fallback",
        "badgr_empty_result_object_no_fallback",
        "bridge_naive_datetime",
        "badgr_naive_datetime",
    ]
    assert [case["id"] for case in reference["adapter"]] == expected_ids
    assert [case["id"] for case in scenarios["adapter"]] == expected_ids
    assert {
        "publish_canvas_credential_mirror",
        "_build_badgr_assertion_payload",
        "_build_canvas_publish_payload",
    } <= set(reference["selected_definitions"][ADAPTER])
    assert reference["infrastructure_controls"] == [
        "missing-global-fatal",
        "caught-unowned-origin-fatal",
    ]
    for index, case in enumerate(reference["adapter"]):
        assert case["entrypoint"] == "direct_adapter"
        assert case["before"] == case["after"]
        assert case["before"]["snapshot_sha256"] in reference["snapshots"]
        requests = [call for call in case["trace"] if call["kind"] == "http"]
        assert len(requests) == 1 and requests[0]["method"] == "POST"
        response = case["responses"][0]
        if index in (8, 9):
            assert response == {"outcome": "CancelledError"}
        elif index in (11, 12):
            assert response == {
                "exception": "RuntimeError",
                "detail": "Canvas Credentials assertion publish response did not include an assertion id",
            }
        else:
            assert response["result_encoding"] == "python-json-text"
        body = json.loads(requests[0]["body"])
        if index < 6:
            issued = body["issuedOn"] if index % 2 else body["credential"]["issued_at"]
            expected = [
                "2026-08-31T23:59:58.123000+00:00",
                "2026-08-31T23:59:58.123456+00:00",
                "2026-08-31T23:59:58.123000-06:00",
            ][index // 2]
            assert issued == expected
        if index == 6:
            assert body["credential"]["expires_at"] is None
        if index in (13, 14):
            issued = (
                body["credential"]["issued_at"] if index == 13 else body["issuedOn"]
            )
            expiry = (
                body["credential"]["expires_at"] if index == 13 else body["expires"]
            )
            assert issued == "2026-08-31T23:59:58.123000"
            assert expiry == "2027-08-31T23:59:58.123456"
        if index == 7:
            assert "expires" not in body
        if index == 10:
            assert (
                json.loads(response["result_json"])["external_credential_id"]
                == "data-id"
            )


def test_additive_publication_boundary_hashes_sources_and_complete_observations():
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def read(path):
        return (ROOT / path).read_bytes()

    require_publication_boundary(contract, read)
    require_publication_boundary(
        contract,
        lambda path: canonical_json_bytes(read(path)).replace(b"\n", b"\r\n"),
    )
    for key in ("publication_boundary_reference", "publication_boundary_scenarios"):
        target = contract[key]["path"]
        with pytest.raises(AssertionError):
            require_publication_boundary(
                contract,
                lambda path: read(path) + b" " if path == target else read(path),
            )
    changed = copy.deepcopy(contract)
    changed["publication_boundary_observations"]["adapter_cancellation"] = 0
    with pytest.raises(AssertionError):
        require_publication_boundary(changed, read)


def test_contract_artifact_hashes_and_source_coverage(artifact):
    contract = json.loads(CONTRACT.read_text())
    scenarios = json.loads(
        (ROOT / contract["scenarios"]["path"]).read_text(encoding="utf-8")
    )
    assert_artifact_files(contract, lambda path: (ROOT / path).read_bytes())
    assert contract["artifact_identity"] == "UTF-8; CRLF normalized to LF only"
    assert_connected(contract, artifact, scenarios)
    coverage = json.loads(
        (ROOT / "contracts/issuance-native-coverage.json").read_text()
    )
    assert coverage["upstream"]["sha256"] == contract["upstream_surface_sha256"]
    assert artifact["scenarios_sha256"] == contract["scenarios"]["sha256"]
    assert artifact["release_image"] == {
        "uri": RELEASE_IMAGE,
        "digest": RELEASE_IMAGE_DIGEST,
    }
    assert artifact["dependencies"] == RELEASE_DEPENDENCIES


@pytest.mark.parametrize("owner", ["reference", "scenarios"])
def test_changed_artifact_is_rejected(owner):
    contract = json.loads(CONTRACT.read_text())
    target = contract[owner]["path"]
    original = (ROOT / target).read_bytes()
    mutated = original.replace(b'"id":', b'"changed_id":', 1)
    assert mutated != original

    def changed(path):
        return mutated if path == target else (ROOT / path).read_bytes()

    with pytest.raises(AssertionError):
        assert_artifact_files(contract, changed)


def test_crlf_artifacts_preserve_exact_identity():
    contract = json.loads(CONTRACT.read_text())

    def crlf(path):
        raw = canonical_json_bytes((ROOT / path).read_bytes())
        assert b"\n" in raw
        return raw.replace(b"\n", b"\r\n")

    assert_artifact_files(contract, crlf)


def test_canonical_json_identity_has_no_other_normalization():
    raw = '{"value":"é", "space": 1}\r\n'.encode("utf-8")
    assert canonical_json_bytes(raw) == raw.replace(b"\r\n", b"\n")
    assert canonical_json_bytes(b"{\r}") == b"{\r}"
    with pytest.raises(UnicodeDecodeError):
        canonical_json_bytes(b"\xff")


@pytest.fixture
def adapter_artifact():
    def reject_nonfinite(value):
        raise ValueError(f"Nonstandard outer JSON constant: {value}")

    return json.loads(
        (ROOT / "contracts/canvas-mirror-adapter-reference.json").read_text(
            encoding="utf-8"
        ),
        parse_constant=reject_nonfinite,
    )


def test_adapter_artifact_hashes_and_closed_source(adapter_artifact):
    contract = json.loads(CONTRACT.read_text())
    owners = {key: contract[f"adapter_{key}"] for key in ("reference", "scenarios")}
    assert_artifact_files(owners, lambda path: (ROOT / path).read_bytes())
    assert_artifact_files(
        owners,
        lambda path: canonical_json_bytes((ROOT / path).read_bytes()).replace(
            b"\n", b"\r\n"
        ),
    )
    scenarios = json.loads(
        (ROOT / owners["scenarios"]["path"]).read_text(encoding="utf-8")
    )
    assert adapter_artifact["schema"] == "marty.canvas-mirror-adapter-reference/v1"
    assert adapter_artifact["source_commit"] == scenarios["source_commit"] == REVISION
    assert adapter_artifact["sources"] == {
        key: list(value) for key, value in SOURCES.items()
    }
    assert adapter_artifact["scenarios_sha256"] == owners["scenarios"]["sha256"]
    assert [case["id"] for case in adapter_artifact["adapter"]] == [
        case["id"] for case in scenarios["adapter"]
    ]
    assert len(adapter_artifact["adapter"]) == contract["adapter_observations"] == 51
    assert (
        "publish_canvas_credential_mirror"
        in adapter_artifact["selected_definitions"][
            "issuance.infrastructure.adapters.canvas_credentials_adapter"
        ]
    )
    assert contract["adapter_result_encoding"] == "python-json-text"


@pytest.mark.parametrize("owner", ["reference", "scenarios"])
def test_adapter_content_mutation_is_rejected(owner):
    contract = json.loads(CONTRACT.read_text())
    owners = {key: contract[f"adapter_{key}"] for key in ("reference", "scenarios")}
    path = owners[owner]["path"]
    original = (ROOT / path).read_bytes()
    changed = original.replace(b"bridge_base", b"changed_base", 1)
    assert original != changed
    with pytest.raises(AssertionError):
        assert_artifact_files(
            owners,
            lambda current: (
                changed if current == path else (ROOT / current).read_bytes()
            ),
        )


def test_adapter_observations_preserve_input_state_and_owned_effects(adapter_artifact):
    snapshots = adapter_artifact["snapshots"]
    referenced = set()
    for case in adapter_artifact["adapter"]:
        assert case["entrypoint"] == "direct_adapter"
        assert case["request"] is None
        assert case["before"] == case["after"]
        referenced.add(case["before"]["snapshot_sha256"])
        assert all(call["kind"] != "repository" for call in case["trace"])
        if case["id"].startswith("ownership_"):
            assert case["trace"] == []
            assert case["responses"] == [
                {
                    "exception": "RuntimeError",
                    "detail": "Canvas delivery resources are unavailable",
                }
            ]
    assert referenced == set(snapshots)
    for digest, value in snapshots.items():
        assert (
            hashlib.sha256(
                json.dumps(
                    value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
            == digest
        )


def test_adapter_portable_gate_precedes_aggregate_ownership(adapter_artifact):
    case = next(
        case
        for case in adapter_artifact["adapter"]
        if case["id"] == "portable_foreign_organization"
    )
    assert case["trace"] == []
    assert case["responses"] == [
        {
            "exception": "RuntimeError",
            "detail": "Portable Canvas delivery is not enabled for this organization",
        }
    ]


def test_adapter_result_text_preserves_numeric_nan_string_and_surrogate(
    adapter_artifact,
):
    cases = {case["id"]: case for case in adapter_artifact["adapter"]}

    def result(name):
        response = cases[name]["responses"][0]
        assert response["result_encoding"] == "python-json-text"
        return json.loads(response["result_json"])

    finite = result("bridge_response_scalar_id")
    assert finite["external_credential_id"] == "17"
    assert finite["metadata"]["publish_response"]["id"] == 17
    numeric = result("bridge_response_nonfinite_id")
    assert numeric["external_credential_id"] == "nan"
    assert math.isnan(numeric["metadata"]["publish_response"]["id"])
    text = result("bridge_response_string_nan_id")
    assert (
        text["external_credential_id"]
        == text["metadata"]["publish_response"]["id"]
        == "NaN"
    )
    surrogate = result("bridge_response_surrogate_id")
    assert (
        surrogate["external_credential_id"]
        == surrogate["metadata"]["publish_response"]["id"]
        == "\ud800"
    )
    assert (
        "\\ud800"
        in cases["bridge_response_surrogate_id"]["responses"][0]["result_json"]
    )
    assert result("bridge_utf16_json")["external_credential_id"] == "encoded-id"


def test_adapter_delivery_secret_policy_is_not_validation_policy(adapter_artifact):
    cases = {case["id"]: case for case in adapter_artifact["adapter"]}
    ordered = cases["secret_ordered_sources"]["trace"]
    assert [call for call in ordered if call["kind"] == "secret"] == [
        {"kind": "secret", "organization": "org-1", "identifier": "empty"},
        {"kind": "secret", "organization": "org-1", "identifier": "selected"},
    ]
    for name, case in cases.items():
        if name.startswith("secret_alias_"):
            assert case["trace"][0] == {
                "kind": "secret",
                "organization": "org-1",
                "identifier": "selected-secret",
            }
            assert (
                next(call for call in case["trace"] if call["kind"] == "http")[
                    "headers"
                ]["authorization"]
                == "Bearer synthetic-selected-token"
            )
    fallback = next(
        call
        for call in cases["secret_operator_fallback"]["trace"]
        if call["kind"] == "http"
    )
    assert fallback["headers"]["authorization"] == "Bearer synthetic-provider-token"
    sanitized = json.loads(
        next(
            call
            for call in cases["bridge_metadata_sanitization"]["trace"]
            if call["kind"] == "http"
        )["body"]
    )["metadata"]
    assert sanitized == {
        "canvas_credentials": {"issuer_id": "metadata-issuer"},
        "public_custom": {"value": "kept"},
    }


@pytest.mark.parametrize("mutation", ["route", "auth", "loop", "case", "source"])
def test_disconnected_reference_is_rejected(artifact, mutation):
    contract = json.loads(CONTRACT.read_text())
    scenarios = json.loads(
        (ROOT / contract["scenarios"]["path"]).read_text(encoding="utf-8")
    )
    changed = copy.deepcopy(artifact)
    if mutation == "route":
        changed["selected_definitions"][ROUTES].remove(OPERATIONS[0])
    elif mutation == "auth":
        changed["selected_definitions"][ROUTES].remove("_verify_management_api_key")
    elif mutation == "loop":
        changed["loop"].pop()
    elif mutation == "case":
        changed["http"].pop()
    else:
        changed["sources"][ROUTES][1] = "0" * 40
    with pytest.raises(AssertionError):
        assert_connected(contract, changed, scenarios)


def test_lossless_snapshot_references_are_complete(artifact):
    snapshots = artifact["snapshots"]
    referenced = set()

    def visit(value):
        if isinstance(value, dict):
            if set(value) == {"snapshot_sha256"}:
                referenced.add(value["snapshot_sha256"])
            else:
                for nested in value.values():
                    visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(artifact["http"])
    visit(artifact["provider_cancellation"])
    assert referenced == set(snapshots)
    for digest, value in snapshots.items():
        encoded = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode()
        assert hashlib.sha256(encoded).hexdigest() == digest


def test_positive_replay_and_denial_side_effects(artifact):
    cases = {case["id"]: case for case in artifact["http"]}
    for name in ("bridge_publish", "badgr_publish"):
        case = cases[name]
        assert [response["status"] for response in case["responses"]] == [200, 200]
        assert case["responses"][0] == case["responses"][1]
        assert sum(call["kind"] == "http" for call in case["trace"]) == 1
    for case in artifact["http"]:
        if case["id"].startswith("auth_"):
            assert case["responses"][0]["status"] == 401
            assert case["before"] == case["after"]
            assert case["trace"] == []
    assert cases["publish_foreign_context"]["responses"][0]["status"] == 404
    assert cases["provenance_context_mismatch"]["responses"][0]["status"] == 403
    # Frozen management health/batch handlers do not impose the provenance
    # header restriction. Do not silently turn this into gateway proof.
    assert cases["health_foreign_context"]["responses"][0]["status"] == 200


def test_current_release_route_inventory_is_exact():
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["source_release"] == "v0.1.76"
    assert contract["source_commit"] == REVISION
    assert contract["source_tree"] == "819b7458a31c75d28043a4660643b029c5ec4567"
    assert contract["source_path"] == SOURCES[ROUTES][0]
    assert contract["source_blob_sha1"] == SOURCES[ROUTES][1]
    assert contract["release_runtime"] == {
        "image": RELEASE_IMAGE,
        "digest": RELEASE_IMAGE_DIGEST,
        "dependencies": RELEASE_DEPENDENCIES,
        "profile_source_path": SOURCES["release_profile"][0],
        "profile_source_blob_sha1": SOURCES["release_profile"][1],
    }
    assert [route["operation"] for route in contract["routes"]] == list(OPERATIONS)
    assert [route["source_line"] for route in contract["routes"]] == [
        6151,
        6201,
        6220,
        6237,
        6256,
        6393,
    ]
    assert sum(route["definition_lines"] for route in contract["routes"]) == 237
    assert contract["route_definition_lines"] == 237
    assert contract["registered_route_envelope_lines"] == 277


def test_all_six_routes_have_success_and_owned_side_effect_contracts(artifact):
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    cases = {case["id"]: case for case in artifact["http"]}
    success = contract["behavior"]["success_cases"]
    assert set(success) == {
        "publish",
        "pending",
        "resync",
        "cycle",
        "health",
        "provenance",
    }
    outbound = {
        "publish": 1,
        "pending": 1,
        "resync": 1,
        "cycle": 2,
        "health": 0,
        "provenance": 0,
    }
    mutations = {"publish", "pending", "resync", "cycle"}
    for operation, case_id in success.items():
        case = cases[case_id]
        assert all(response["status"] == 200 for response in case["responses"])
        assert (
            sum(call["kind"] == "http" for call in case["trace"]) == outbound[operation]
        )
        assert (case["before"] != case["after"]) == (operation in mutations)


def test_authentication_precedes_validation_tenant_repository_and_effects(artifact):
    cases = {case["id"]: case for case in artifact["http"]}
    auth = [case for case in artifact["http"] if case["id"].startswith("auth_")]
    assert len(auth) == 15
    for case in auth:
        missing = case["id"].endswith("_missing") or case["id"] == (
            "auth_pending_before_validation"
        )
        detail = "X-API-Key header is missing" if missing else "Invalid API Key"
        assert case["responses"] == [{"status": 401, "body": {"detail": detail}}]
        assert case["before"] == case["after"]
        assert case["trace"] == []
    assert (
        cases["auth_publish_before_tenant"]["request"]["headers"]["X-Organization-ID"]
        == "org-other"
    )
    assert cases["auth_pending_before_validation"]["request"]["query"]["limit"] == "0"
    assert (
        cases["auth_provenance_before_tenant"]["request"]["headers"][
            "X-Organization-ID"
        ]
        == "org-other"
    )


def test_tenant_order_and_management_scope_do_not_regress(artifact):
    cases = {case["id"]: case for case in artifact["http"]}

    for case_id, status_code in (
        ("publish_foreign_context", 404),
        ("publish_missing_context", 403),
    ):
        case = cases[case_id]
        assert case["responses"][0]["status"] == status_code
        assert [call["method"] for call in case["trace"]] == ["get_credential"]
        assert case["before"] == case["after"]

    for case_id in ("provenance_missing_context", "provenance_context_mismatch"):
        case = cases[case_id]
        assert case["responses"][0]["status"] == 403
        assert case["trace"] == []
        assert case["before"] == case["after"]

    health = cases["health_foreign_context"]
    assert health["responses"][0]["status"] == 200
    assert [call["method"] for call in health["trace"]] == ["list_delivery_records"]
    assert health["before"] == health["after"]
    assert (
        "organization_id" not in cases["pending_all_organizations"]["request"]["query"]
    )


def test_repository_failures_are_generic_ordered_and_effect_free(artifact):
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    cases = {case["id"]: case for case in artifact["http"]}
    failure_methods = contract["behavior"]["repository_failure"]["cases"]
    ids = {
        "publish": "publish_repository_failure",
        "pending": "pending_repository_failure",
        "resync": "status_repository_failure",
        "cycle": "automation_repository_failure",
        "health": "health_repository_failure",
        "provenance": "provenance_repository_failure",
    }
    assert set(ids) == set(failure_methods)
    for operation, case_id in ids.items():
        case = cases[case_id]
        assert case["responses"] == [{"status": 500, "body": "Internal Server Error"}]
        assert case["before"] == case["after"]
        assert len(case["trace"]) == 1
        failure = case["trace"][0]
        assert failure["kind"] == "repository"
        assert failure["method"] == failure_methods[operation]
        assert failure["failure"] == "RuntimeError"
        assert not any(call["kind"] in {"http", "secret"} for call in case["trace"])
        response_text = json.dumps(case["responses"], sort_keys=True)
        assert "RuntimeError" not in response_text
        assert "synthetic repository failure" not in response_text
        assert "private_fixture_marker" not in response_text


def test_feature_gate_and_management_regression_cases_are_connected(artifact):
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    cases = {case["id"]: case for case in artifact["http"]}
    assert set(contract["behavior"]["feature_regression_cases"]) <= set(cases)

    expected = {
        "publish_gate_disabled": (409, "enable_canvas_mirror_publish"),
        "publish_operations_disabled": (409, "enable_canvas_mirror_ops"),
        "status_gate_disabled": (200, "enable_canvas_mirror_ops"),
    }
    for case_id, (status_code, feature) in expected.items():
        case = cases[case_id]
        assert case["responses"][0]["status"] == status_code
        assert not any(call["kind"] in {"http", "secret"} for call in case["trace"])
        assert case["before"] != case["after"]
        snapshot = artifact["snapshots"][case["after"]["snapshot_sha256"]]
        metadata = snapshot["delivery_records"]["delivery-001"]["metadata"]
        assert metadata["canvas_feature_gate_blocked"] is True
        assert metadata["canvas_feature_gate"] == feature


def test_provider_cancellation_is_not_only_a_stubbed_loop(artifact):
    for case in artifact["provider_cancellation"]:
        assert case["responses"] == [{"outcome": "CancelledError"}]
        assert sum(call["kind"] == "http" for call in case["trace"]) == 1
        assert not any(
            call["kind"] == "repository" and call["method"] == "save_delivery_record"
            for call in case["trace"]
        )
    assert {case["entrypoint"] for case in artifact["provider_cancellation"]} == {
        "ASGI",
        "automation_loop",
    }


def test_loop_timing_and_exception_continuation(artifact):
    loops = {case["id"]: case for case in artifact["loop"]}
    assert loops["disabled"]["outcome"] == "returned"
    assert loops["disabled"]["trace"] == []
    delayed = [call for call in loops["delayed_start"]["trace"] if "phase" in call]
    assert [(call["phase"], call["at"]) for call in delayed] == [
        ("sleep", 0.0),
        ("publish", 5.0),
        ("sleep", 5.0),
        ("sync", 7.0),
        ("sleep", 7.0),
    ]
    relative = [
        call for call in loops["completion_relative"]["trace"] if "phase" in call
    ]
    assert [(call["phase"], call["at"]) for call in relative] == [
        ("publish", 0.0),
        ("sync", 4.0),
        ("sleep", 11.0),
        ("publish", 12.0),
        ("sleep", 16.0),
        ("sync", 18.0),
        ("sleep", 25.0),
    ]
    failed = loops["publish_exception_continues"]["trace"]
    assert any(call.get("exception") == "RuntimeError" for call in failed)
    assert any(call.get("phase") == "sync" for call in failed)
    assert all(
        case["outcome"] == "CancelledError"
        for name, case in loops.items()
        if name != "disabled"
    )
