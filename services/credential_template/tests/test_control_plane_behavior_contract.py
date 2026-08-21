from __future__ import annotations

import json
from pathlib import Path

from credential_template import main as service


FIXTURE = json.loads(
    (Path(__file__).parents[3] / "contracts" / "credential-template-control-plane-behavior.json").read_text(
        encoding="utf-8"
    )
)


def test_control_plane_behavior_fixture_matches_legacy_python_kernel() -> None:
    assert FIXTURE["schema_version"] == 1
    for case in FIXTURE["key_purpose_cases"]:
        assert service._key_purpose_for_credential_format(case["credential_format"]) == case["expected"]

    identifiers = service._trust_profile_issuer_identifiers(FIXTURE["trust_profile"])
    assert set(FIXTURE["expected_trusted_identifiers"]) <= identifiers
    assert set(FIXTURE["forbidden_trusted_identifiers"]).isdisjoint(identifiers)
