from __future__ import annotations

import json
import re
from pathlib import Path

from services.presentation_policy import main as pp


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = json.loads(
    (ROOT / "contracts" / "presentation-policy-service-behavior.json").read_text(
        encoding="utf-8"
    )
)


def test_complete_http_and_grpc_surfaces_are_frozen() -> None:
    actual_http = {
        (method, route.path)
        for route in pp.router.routes
        for method in route.methods
    }
    expected_http = {
        (operation["method"], operation["path"])
        for operation in CONTRACT["http_operations"]
    }
    assert actual_http == expected_http

    proto = (ROOT / "proto" / "v1" / "presentation_policy_service.proto").read_text(
        encoding="utf-8"
    )
    actual_grpc = re.findall(r"^\s*rpc\s+(\w+)\(", proto, flags=re.MULTILINE)
    assert actual_grpc == CONTRACT["grpc_methods"]


def test_domain_enums_and_holder_binding_match_the_shared_contract() -> None:
    assert [status.value for status in pp.PolicyStatus] == CONTRACT["statuses"]
    assert [constraint.value for constraint in pp.ConstraintType] == CONTRACT[
        "constraint_types"
    ]
    assert [purpose.value for purpose in pp.RequestPurpose] == CONTRACT[
        "request_purposes"
    ]
    for vector in CONTRACT["holder_binding_vectors"]:
        normalized = pp.normalize_holder_binding(vector["input"])
        assert {
            "required": normalized.required,
            "binding_methods": normalized.binding_methods,
            "proof_profiles": normalized.proof_profiles,
            "proof_freshness": normalized.proof_freshness,
        } == vector["expected"]


def test_every_python_migration_has_one_frozen_revision() -> None:
    revisions = []
    for migration in sorted(
        (ROOT / "services" / "presentation_policy" / "infrastructure" / "migrations" / "versions").glob("*.py")
    ):
        match = re.search(r"^revision\s*=\s*[\"']([^\"']+)", migration.read_text(encoding="utf-8"), re.MULTILINE)
        assert match, migration
        revisions.append(match.group(1))
    assert revisions == CONTRACT["migration_revisions"]
