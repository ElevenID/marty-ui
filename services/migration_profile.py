"""Profile names needed by the native-service bootstrap and demo seed tools."""

from __future__ import annotations

import os


_ALIASES = {
    "": "dev",
    "local": "dev",
    "development": "dev",
    "experiment": "experiments",
    "experimental": "experiments",
    "beta-experiment": "experiments",
    "beta_experiment": "experiments",
    "beta-experiments": "experiments",
    "beta_experiments": "experiments",
    "prod": "production",
    "selfhost-prod": "selfhost-production",
    "selfhost_prod": "selfhost-production",
    "selfhostproduction": "selfhost-production",
    "selfhost_production": "selfhost-production",
    "qa": "test",
    "ci": "test",
}


def normalize_migration_profile(profile: str | None) -> str:
    name = (profile or "").strip().lower()
    return _ALIASES.get(name, name) or "dev"


def is_persistent_profile(profile: str | None = None) -> bool:
    if profile is None:
        profile = os.environ.get("MARTY_MIGRATION_PROFILE")
    return normalize_migration_profile(profile) in {"production", "selfhost-production"}
