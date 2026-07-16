from __future__ import annotations

import importlib.util
import pathlib
import sys
from types import SimpleNamespace


def _load_migration():
    sys.modules.setdefault("alembic", SimpleNamespace(op=SimpleNamespace(get_bind=lambda: None)))
    path = (
        pathlib.Path(__file__).parents[1]
        / "infrastructure"
        / "migrations"
        / "versions"
        / "20260710_0001_seed_marty_login_badge_issuance_flows.py"
    )
    spec = importlib.util.spec_from_file_location("marty_login_badge_issuance_flows", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_marty_login_badge_issuance_migration_seeds_active_oid4vci_flows():
    migration = _load_migration()

    template_ids = {flow["credential_template_id"] for flow in migration.ISSUANCE_FLOWS}
    assert template_ids == {
        migration.LEGACY_MEMBER_TEMPLATE_ID,
        migration.OPEN_BADGE_TEMPLATE_ID,
    }
    assert migration.FLOW_STATUS == "ACTIVE"
    assert migration.FLOW_TYPE == "oid4vci_pre_authorized"

    preconditions = migration._build_preconditions()
    assert preconditions["items"] == ["application_approved"]
    assert preconditions["protocol"]["enabled"] is True
    assert preconditions["protocol"]["trigger"] == "application_approved"

    steps = migration._build_steps()
    transitions = migration._build_transitions()
    assert steps[0]["id"] == "step-check-preconditions"
    assert steps[0]["config"]["required_preconditions"] == ["application_approved"]
    assert any(step["id"] == "step-create-offer" and step["step_type"] == "issuance" for step in steps)
    assert transitions[0]["from_step_id"] == "step-check-preconditions"
    assert transitions[0]["to_step_id"] == "step-create-offer"
