from marty_common.migration_profile import (
    allow_experimental_data_fixes,
    include_beta_seed_data,
    include_demo_seed_data,
    include_experimental_seed_data,
    include_test_seed_data,
    is_persistent_profile,
    migration_profile,
    migration_profile_settings,
    normalize_migration_profile,
    skip_demo_migrations,
    use_explicit_demo_seed_pack,
)


def test_normalize_migration_profile_maps_aliases():
    assert normalize_migration_profile("Prod") == "production"
    assert normalize_migration_profile("selfhost-prod") == "selfhost-production"
    assert normalize_migration_profile("selfhost_prod") == "selfhost-production"
    assert normalize_migration_profile("qa") == "test"
    assert normalize_migration_profile("experiment") == "experiments"
    assert normalize_migration_profile("experimental") == "experiments"
    assert normalize_migration_profile("beta-experiments") == "experiments"
    assert normalize_migration_profile("") == "dev"
    assert normalize_migration_profile(None) == "dev"


def test_migration_profile_defaults_to_dev(monkeypatch):
    monkeypatch.delenv("MARTY_MIGRATION_PROFILE", raising=False)
    assert migration_profile() == "dev"
    assert migration_profile_settings().name == "dev"


def test_dev_profile_includes_demo_beta_and_test(monkeypatch):
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "dev")
    assert include_demo_seed_data() is True
    assert include_beta_seed_data() is True
    assert include_experimental_seed_data() is True
    assert include_test_seed_data() is True
    assert allow_experimental_data_fixes() is True
    assert skip_demo_migrations() is False
    assert is_persistent_profile() is False


def test_beta_profile_includes_demo_and_beta_but_not_test(monkeypatch):
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "beta")
    assert include_demo_seed_data() is True
    assert include_beta_seed_data() is True
    assert include_experimental_seed_data() is False
    assert include_test_seed_data() is False
    assert allow_experimental_data_fixes() is True
    assert is_persistent_profile() is False


def test_experiments_profile_includes_demo_and_experiment_fixtures(monkeypatch):
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "experiments")
    assert migration_profile() == "experiments"
    assert include_demo_seed_data() is True
    assert include_beta_seed_data() is True
    assert include_experimental_seed_data() is True
    assert include_test_seed_data() is False
    assert allow_experimental_data_fixes() is True
    assert is_persistent_profile() is False


def test_test_profile_excludes_demo_and_beta_but_keeps_test(monkeypatch):
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "test")
    assert include_demo_seed_data() is False
    assert include_beta_seed_data() is False
    assert include_experimental_seed_data() is False
    assert include_test_seed_data() is True
    assert allow_experimental_data_fixes() is False


def test_production_profiles_skip_demo_and_are_persistent(monkeypatch):
    for raw in ("production", "prod", "selfhost-prod", "selfhost_production"):
        monkeypatch.setenv("MARTY_MIGRATION_PROFILE", raw)
        assert include_demo_seed_data() is False
        assert include_beta_seed_data() is False
        assert include_experimental_seed_data() is False
        assert include_test_seed_data() is False
        assert allow_experimental_data_fixes() is False
        assert skip_demo_migrations() is True
        assert is_persistent_profile() is True


def test_explicit_demo_seed_pack_forces_demo_migrations_to_skip(monkeypatch):
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "beta")
    monkeypatch.setenv("MARTY_USE_EXPLICIT_DEMO_SEED_PACK", "true")

    assert include_demo_seed_data() is True
    assert use_explicit_demo_seed_pack() is True
    assert skip_demo_migrations() is True
