"""Helpers for migration profile-aware data seeding."""

from __future__ import annotations

import os


_PRODUCTION_PROFILES = {
    "prod",
    "production",
    "selfhost-prod",
    "selfhost-production",
    "selfhost_prod",
    "selfhost_production",
}


def migration_profile() -> str:
    """Return the normalized migration profile name."""
    return os.environ.get("MARTY_MIGRATION_PROFILE", "").strip().lower()


def skip_demo_migrations() -> bool:
    """Return True when demo-only data migrations should no-op."""
    return migration_profile() in _PRODUCTION_PROFILES