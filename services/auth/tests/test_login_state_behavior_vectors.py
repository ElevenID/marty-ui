import json
from pathlib import Path

from auth.infrastructure.adapters.http_adapter import (
    _build_canvas_lti_user,
    _credential_callback_session_id,
    _credential_login_failure_payload,
)


FIXTURE = json.loads(
    (Path(__file__).parents[3] / "contracts" / "auth-login-state-behavior.json").read_text()
)


def test_python_oracle_matches_language_neutral_login_state_vectors():
    for case in FIXTURE["session_id_vectors"]:
        assert str(
            _credential_callback_session_id(
                case["secret"],
                flow_instance_id=case["flow_instance_id"],
                nonce=case["nonce"],
            )
        ) == case["expected"]

    for case in FIXTURE["canvas_cases"]:
        user = _build_canvas_lti_user(case["session"])
        for field, expected in case["expected"].items():
            assert getattr(user, field) == expected

    for case in FIXTURE["failure_cases"]:
        failure = _credential_login_failure_payload(case["reason"])
        assert failure["reason_code"] == case["reason_code"]
        assert case["message_contains"] in failure["message"]
        assert ("detail" in failure) is case["detail"]
