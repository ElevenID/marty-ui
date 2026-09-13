"""Repo-local corpus guards; real reference replay is an explicit script --check."""

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture_didcomm_projector_reference.py"
CORPUS = ROOT / "contracts/didcomm-projector-python-reference.json"
SPEC = importlib.util.spec_from_file_location("didcomm_projector_capture", SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def corpus():
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def test_corpus_names_and_source_provenance_are_closed():
    frozen = corpus()
    assert frozen["schema"] == "marty.didcomm-projector-python-reference/v1"
    assert frozen["reference"]["source_commit"] == capture.SOURCE_COMMIT
    assert frozen["reference"]["source_blobs"] == capture.SOURCES
    assert len(capture.SOURCES) == 5
    assert [case["case"] for case in frozen["projector_cases"]] == [
        row[0] for row in capture.CASES
    ]
    assert len(frozen["projector_cases"]) == 8
    assert len(frozen["idempotency_guard_cases"]) == 4
    governed = frozen["reference"]["governed_didcomm_target"]
    assert governed["legacy_grpc"] == "openid-offer-only"
    assert governed["native_rust_target"] == "same-delivery-semantics-as-http"


def test_full_service_responses_preserve_differences_and_sensitive_field_boundary():
    expected_fields = {
        "id",
        "organization_id",
        "credential_template_id",
        "status",
        "credential_offer_uri",
        "credential_offer_uris",
        "credential_offer_labels",
        "pre_auth_code",
        "expires_at",
    }
    for case in corpus()["projector_cases"]:
        http, grpc = case["http"]["response"], case["grpc"]["response"]
        assert set(http) == set(grpc) == expected_fields
        assert grpc["status"] == case["input"]["transaction_status"]
        assert case["grpc"]["delivery_call_count"] == 0
        assert http["credential_offer_uris"]["didcomm"].startswith("didcomm://")
        assert grpc["credential_offer_uris"]["didcomm"].startswith(
            "openid-credential-offer://"
        )
        assert (
            http["pre_auth_code"] == grpc["pre_auth_code"] == "synthetic-pre-auth-code"
        )
    assert "public gateway redaction is separate" in corpus()["reference"]["scope"]


@pytest.mark.parametrize(
    "name,holder,calls,status",
    [
        ("explicit-holder", "did:example:holder", 1, "issued"),
        ("subject-fallback", "did:example:subject", 1, "issued"),
        ("missing-holder", None, 0, "pending"),
        ("delivery-failure", "did:example:holder", 1, "pending"),
        ("recovered-pending-snapshot", "did:example:holder", 1, "issued"),
        ("recovered-issued-snapshot", "did:example:holder", 1, "issued"),
        ("recovered-failed-snapshot", "did:example:holder", 1, "failed"),
    ],
)
def test_holder_failure_and_snapshot_observations(name, holder, calls, status):
    case = next(row for row in corpus()["projector_cases"] if row["case"] == name)
    assert len(case["http"]["delivery_calls"]) == calls
    if calls:
        assert case["http"]["delivery_calls"][0]["holder_did"] == holder
    assert case["http"]["response"]["status"] == status
    assert case["input"]["snapshot_only"] == name.startswith("recovered-")


def test_mixed_wallets_preserve_non_didcomm_fields_and_existing_query():
    case = next(
        row for row in corpus()["projector_cases"] if row["case"] == "mixed-wallets"
    )
    http, grpc = case["http"]["response"], case["grpc"]["response"]
    assert set(http["credential_offer_uris"]) == {
        "didcomm",
        "default",
        "manager",
        "apple",
    }
    assert http["credential_offer_labels"] == grpc["credential_offer_labels"]
    for wallet in ("default", "manager", "apple"):
        assert (
            http["credential_offer_uris"][wallet]
            == grpc["credential_offer_uris"][wallet]
        )
    assert http["credential_offer_uris"]["manager"].startswith(
        "custom://open?existing=yes&credential_offer="
    )


def test_idempotency_guards_preserve_status_and_fallthrough_scope():
    for case in corpus()["idempotency_guard_cases"]:
        rejected = case["case"] in {"didcomm-with-key", "mixed-with-key"}
        assert case["http"]["rejected"] == case["grpc"]["rejected"] == rejected
        if rejected:
            assert case["http"]["status"] == 422
            assert case["grpc"]["status"] == "INVALID_ARGUMENT"
            assert (
                case["http"]["body"]["detail"]
                == case["grpc"]["detail"]
                == capture.GUARD_DETAIL
            )
            assert case["grpc"]["response"] == {}
        else:
            assert (
                case["http"]["scope"]
                == case["grpc"]["scope"]
                == "guard-fallthrough-only"
            )


def test_source_hash_accepts_checkout_line_endings_but_rejects_changed_bytes(tmp_path):
    source = tmp_path / "source.py"
    source.write_bytes(b"original\r\n")
    hashes = {"source.py": capture.git_blob(b"original\n")}
    capture.verify_sources(tmp_path, hashes)
    source.write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="source.py"):
        capture.verify_sources(tmp_path, hashes)


def test_guard_extraction_requires_exact_unique_statement():
    source = (
        "async def initiate():\n"
        "    if True:\n"
        f"        raise ValueError({capture.GUARD_DETAIL!r})\n"
    )
    namespace = {}
    exec(capture.isolated_guard(source, "initiate"), namespace)
    with pytest.raises(ValueError, match="idempotent initiation"):
        namespace["observed_guard"]()
    with pytest.raises(ValueError, match="guard is not unique"):
        capture.isolated_guard("async def initiate():\n    pass\n", "initiate")
    with pytest.raises(ValueError, match="function is not unique"):
        capture.isolated_guard(source + source, "initiate")


def test_exact_observation_comparison_accepts_equal_corpus():
    capture.verify_observations(corpus(), corpus())


def test_exact_observation_comparison_rejects_normalized_transport_difference():
    observed = corpus()
    observed["projector_cases"][0]["grpc"]["response"] = observed["projector_cases"][0][
        "http"
    ]["response"]
    with pytest.raises(ValueError, match="observations differ"):
        capture.verify_observations(observed, corpus())
