"""External database layer coverage against the current production service graph.

These are source-model checks; the installer native Compose qualification remains
the authority for a resolved application model and never starts a database here.
"""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
LAYER = ROOT / "deploy-config/compose/selfhost-installer/compose.external-postgres.yml"


class Reset:
    pass


class ComposeLoader(yaml.SafeLoader):
    pass


ComposeLoader.add_constructor("!reset", lambda _loader, _node: Reset())


def read(path):
    return yaml.load(path.read_text(), Loader=ComposeLoader)


class ExternalPostgresComposeTests(unittest.TestCase):
    def setUp(self):
        self.base = read(ROOT / "docker-compose.selfhost.prod.yml")
        self.external = read(LAYER)

    def test_every_inherited_database_template_uses_the_selected_endpoint(self):
        consumers = {
            name
            for name, service in self.base["services"].items()
            if "DATABASE_URL_TEMPLATE" in service.get("environment", {})
        }
        selected = {
            name
            for name, service in self.external["services"].items()
            if isinstance(service, dict)
            and "DATABASE_URL_TEMPLATE" in service.get("environment", {})
        }
        self.assertEqual(selected, consumers)
        self.assertEqual(len(consumers), 18)
        for name in consumers:
            self.assertEqual(
                self.external["services"][name]["environment"]["DATABASE_URL_TEMPLATE"],
                "${MARTY_EXTERNAL_POSTGRES_URL_TEMPLATE:?external PostgreSQL selection required}",
                name,
            )
            self.assertEqual(
                self.base["services"][name]["environment"]["MARTY_DB_PASSWORD_FILE"],
                "/run/secrets/marty_db_password",
                name,
            )

    def test_local_database_and_all_remaining_health_dependencies_are_removed(self):
        self.assertIsInstance(self.external["services"]["postgres"], Reset)
        runtime = read(ROOT / "deploy-config/compose/selfhost-installer/compose.runtime.yml")
        inherited = [
            read(ROOT / service["extends"]["file"])
            for service in self.base["services"].values()
            if "extends" in service
        ]
        for layer in [self.base, runtime, *inherited]:
            for name, service in layer["services"].items():
                # The external OIDC layer removes Keycloak completely.
                if name == "keycloak":
                    continue
                if "postgres" in service.get("depends_on", {}):
                    self.assertIsInstance(
                        self.external["services"][name]["depends_on"]["postgres"],
                        Reset,
                        name,
                    )

    def test_imported_password_preserves_the_established_container_secret_target(self):
        self.assertEqual(
            self.external["secrets"]["marty_db_password"]["file"],
            "${SELFHOST_SECRET_DIR:?SELFHOST_SECRET_DIR must be set}/external_postgres_password",
        )
        self.assertIsInstance(self.external["secrets"]["postgres_password"], Reset)
        # No replacement secret lists may discard another service credential.
        for service in self.external["services"].values():
            if isinstance(service, dict):
                self.assertNotIn("secrets", service)

    def test_hosted_runtime_health_checks_allow_cold_schema_initialization(self):
        runtime = {
            name for name, service in self.external["services"].items()
            if isinstance(service, dict) and any(
                key.endswith("DATABASE_MAX_CONNECTIONS") and value == "2"
                for key, value in service.get("environment", {}).items()
            )
        }
        self.assertEqual(len(runtime), 13)
        for name in runtime:
            # A partial healthcheck mapping merges into the inherited check;
            # it must never replace the probe, disable health or change retries.
            self.assertEqual(self.external["services"][name]["healthcheck"],
                             {"start_period": "120s"}, name)
        for name, service in self.external["services"].items():
            if isinstance(service, dict) and name not in runtime:
                self.assertNotIn("healthcheck", service, name)

    def test_primary_runtime_pool_budget_and_setup_pools_are_separate(self):
        setup = {
            "revocation-profile-migrate", "db-migrate", "kms-initialize", "issuance-migrations"
        }
        runtime_limits = []
        for name, service in self.external["services"].items():
            if not isinstance(service, dict):
                continue
            limits = [
                int(value)
                for key, value in service.get("environment", {}).items()
                if key.endswith("DATABASE_MAX_CONNECTIONS")
            ]
            if name in setup:
                self.assertEqual(limits, [1], name)
            elif name != "applicant":
                self.assertEqual(limits, [2], name)
                runtime_limits.extend(limits)
        self.assertEqual(len(runtime_limits), 13)
        self.assertEqual(sum(runtime_limits), 26)


if __name__ == "__main__":
    unittest.main()
