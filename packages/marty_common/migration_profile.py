"""Helpers for profile-aware migrations and seed orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import os


_ENABLED_VALUES = {"1", "true", "yes", "on", "enabled"}


_PROFILE_ALIASES = {
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


@dataclass(frozen=True)
class MigrationProfileSettings:
    """Normalized behavior flags for a migration profile."""

    name: str
    include_demo_seed_data: bool
    include_beta_seed_data: bool
    include_experimental_seed_data: bool
    include_test_seed_data: bool
    allow_experimental_data_fixes: bool
    persistent: bool


_PROFILE_SETTINGS = {
    "dev": MigrationProfileSettings(
        name="dev",
        include_demo_seed_data=True,
        include_beta_seed_data=True,
        include_experimental_seed_data=True,
        include_test_seed_data=True,
        allow_experimental_data_fixes=True,
        persistent=False,
    ),
    "beta": MigrationProfileSettings(
        name="beta",
        include_demo_seed_data=True,
        include_beta_seed_data=True,
        include_experimental_seed_data=False,
        include_test_seed_data=False,
        allow_experimental_data_fixes=True,
        persistent=False,
    ),
    "experiments": MigrationProfileSettings(
        name="experiments",
        include_demo_seed_data=True,
        include_beta_seed_data=True,
        include_experimental_seed_data=True,
        include_test_seed_data=False,
        allow_experimental_data_fixes=True,
        persistent=False,
    ),
    "test": MigrationProfileSettings(
        name="test",
        include_demo_seed_data=False,
        include_beta_seed_data=False,
        include_experimental_seed_data=False,
        include_test_seed_data=True,
        allow_experimental_data_fixes=False,
        persistent=False,
    ),
    "production": MigrationProfileSettings(
        name="production",
        include_demo_seed_data=False,
        include_beta_seed_data=False,
        include_experimental_seed_data=False,
        include_test_seed_data=False,
        allow_experimental_data_fixes=False,
        persistent=True,
    ),
    "selfhost-production": MigrationProfileSettings(
        name="selfhost-production",
        include_demo_seed_data=False,
        include_beta_seed_data=False,
        include_experimental_seed_data=False,
        include_test_seed_data=False,
        allow_experimental_data_fixes=False,
        persistent=True,
    ),
}


def normalize_migration_profile(profile: str | None) -> str:
    """Return the canonical profile name used by migration helpers."""
    normalized = (profile or "").strip().lower()
    normalized = _PROFILE_ALIASES.get(normalized, normalized)
    return normalized or "dev"


def migration_profile() -> str:
    """Return the normalized migration profile name."""
    return normalize_migration_profile(os.environ.get("MARTY_MIGRATION_PROFILE"))


def migration_profile_settings() -> MigrationProfileSettings:
    """Return the resolved profile settings, defaulting unknown values to dev."""
    return _PROFILE_SETTINGS.get(migration_profile(), _PROFILE_SETTINGS["dev"])


def include_demo_seed_data() -> bool:
    """Return True when demo fixtures should be applied."""
    return migration_profile_settings().include_demo_seed_data


def include_beta_seed_data() -> bool:
    """Return True when beta-only fixtures should be applied."""
    return migration_profile_settings().include_beta_seed_data


def include_experimental_seed_data() -> bool:
    """Return True when experiment-only fixtures should be applied."""
    return migration_profile_settings().include_experimental_seed_data


def include_test_seed_data() -> bool:
    """Return True when test-only fixtures should be applied."""
    return migration_profile_settings().include_test_seed_data


def allow_experimental_data_fixes() -> bool:
    """Return True when profile-specific experimental data rewrites are allowed."""
    return migration_profile_settings().allow_experimental_data_fixes


def is_persistent_profile() -> bool:
    """Return True when the target database is expected to survive upgrades."""
    return migration_profile_settings().persistent


def use_explicit_demo_seed_pack() -> bool:
    """Return True when reset workflows should bypass historical demo migrations."""
    return os.environ.get("MARTY_USE_EXPLICIT_DEMO_SEED_PACK", "").strip().lower() in _ENABLED_VALUES


def skip_demo_migrations() -> bool:
    """Backward-compatible helper used by existing demo migrations."""
    return not include_demo_seed_data() or use_explicit_demo_seed_pack()
