"""Regression contracts for operator-owned catalog/schema provisioning."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_organization_schema_and_catalog_writes_are_operator_only() -> None:
    source = read("rust/services/organization/src/main.rs")
    operator = source[source.index("let arguments"):source.index("let config")]
    runtime = source[source.index("let config"):]
    assert 'command == "migrate"' in operator
    assert 'command == "verify-owned-schema"' in operator
    assert 'command == "bootstrap"' in operator
    assert "migrate_organization_schema(&pool)" in operator
    assert "reconcile_organization_startup(" in operator
    assert "PostgresOutboxStore::new(pool.clone(), \"organization\", 16)" in operator
    assert "outbox.migrate().await?" in operator
    assert "outbox.health().await?" in operator
    assert "migrate_organization_schema(" not in runtime
    assert "reconcile_organization_startup(" not in runtime
    assert "outbox.migrate()" not in runtime

    application = read("rust/services/organization/src/application.rs")
    initialize = application[application.index("pub async fn initialize"):application.index("pub async fn create_organization")]
    assert "validate_organization_schema(self.store.pool())" in initialize
    assert "migrate_organization_schema(" not in initialize
    assert "self.outbox.migrate()" not in initialize


def test_credential_template_schema_and_catalog_writes_are_operator_only() -> None:
    source = read("rust/services/credential-template/src/main.rs")
    operator = source[source.index("let arguments"):source.index("let config")]
    runtime = source[source.index("let config"):]
    assert 'command == "migrate"' in operator
    assert 'command == "verify-owned-schema"' in operator
    assert 'command == "bootstrap"' in operator
    assert "migrate_credential_template_schema(&pool)" in operator
    assert "reconcile_credential_template_data(" in operator
    assert "seed_system_catalog(" in operator
    assert "migrate_credential_template_schema(" not in runtime
    assert "reconcile_credential_template_data(" not in runtime
    assert "seed_system_catalog(" not in runtime
    assert "validate_credential_template_schema(&pool)" in runtime


def test_presentation_policy_schema_and_builtin_writes_are_operator_only() -> None:
    source = read("rust/services/presentation-policy/src/main.rs")
    operator = source[source.index("let arguments"):source.index("tracing_subscriber::fmt()")]
    runtime = source[source.index("let config"):]
    assert '"migrate" => migrate_presentation_policy_schema(&pool)' in operator
    assert '"verify-owned-schema" => validate_presentation_policy_schema(&pool)' in operator
    assert '"bootstrap-builtins"' in operator
    assert "reconcile_builtin_policies(&store, organization_id)" in operator
    assert "migrate_presentation_policy_schema(" not in runtime
    assert "reconcile_builtin_policies(" not in runtime
    assert "validate_presentation_policy_schema(&pool)" in runtime


def test_compose_and_helm_operator_order_matches_rust_commands() -> None:
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        source = read(path)
        owner_match = re.search(
            r"(?ms)^  owner-migrations:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
            source,
        )
        assert owner_match is not None
        block = owner_match.group(1)
        commands = [
            "marty-organization migrate",
            "marty-organization bootstrap",
            "marty-credential-template bootstrap",
            "marty-presentation-policy migrate",
            "marty-presentation-policy bootstrap-builtins",
        ]
        positions = [block.index(command) for command in commands]
        assert positions == sorted(positions)
        for service in ("organization", "credential-template", "presentation-policy"):
            match = re.search(
                rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
                source,
            )
            assert match is not None
            assert "owner-migrations:" in match.group(1)

    helm = read("deploy/helm/marty/templates/migrations.yaml")
    ordered = [
        '"name" "organization"',
        '"name" "bootstrap-organization"',
        '"name" "credential-template"',
        '"name" "presentation-policy"',
        '"name" "bootstrap-presentation-policy"',
    ]
    positions = [helm.index(value) for value in ordered]
    assert positions == sorted(positions)


def test_kubernetes_activation_and_disposable_qualification_include_bootstrap_steps() -> None:
    activation = read("scripts/activate_kubernetes_application_credentials.py")
    assert '"bootstrap-organization": ["/usr/local/bin/marty-organization", "bootstrap"]' in activation
    assert '"credential-template": ["/usr/local/bin/marty-credential-template", "bootstrap"]' in activation
    assert '"bootstrap-presentation-policy": ["/usr/local/bin/marty-presentation-policy", "bootstrap-builtins"]' in activation

    migration_probe = read("scripts/qualify_selfhost_migrations.py")
    assert '("marty-organization", "bootstrap")' in migration_probe
    assert '("marty-credential-template", "bootstrap")' in migration_probe
    assert '("marty-presentation-policy", "bootstrap-builtins")' in migration_probe
