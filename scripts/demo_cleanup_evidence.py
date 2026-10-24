"""Pure run-owned cleanup checks shared by D10 capture and evidence review."""
from typing import Any


def owned_api_key_cleanup_proven(report: dict[str, Any]) -> bool:
    """Require a successful exact-tenant revocation for every run-created key."""
    created = report.get("created_api_keys")
    actions = report.get("cleanup_actions")
    if not isinstance(created, list) or not isinstance(actions, list):
        return False
    # A completed setup must retain the response-owned key identity. Labels
    # alone cannot establish either key ownership or successful cleanup.
    if not created:
        return not any(step.get("label") == "api-key-created" for step in report.get("steps", []))
    owned = set()
    for key in created:
        if not isinstance(key, dict):
            return False
        identity = (key.get("id"), key.get("organization_id"))
        if not all(isinstance(value, str) and value.strip() for value in identity) or identity in owned:
            return False
        owned.add(identity)
        matches = [action for action in actions if isinstance(action, dict)
                   and action.get("type") == "revoke_api_key"
                   and (action.get("id"), action.get("organization_id")) == identity]
        if len(matches) != 1:
            return False
        action = matches[0]
        # The adapter stores strings in its existing durable report format.
        if action.get("ok") != "true" or action.get("status") not in {"200", "204"}:
            return False
    return True


