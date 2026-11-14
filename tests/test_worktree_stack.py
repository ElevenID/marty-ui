"""Worktree-local development must never inherit another stack's identity."""

from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.dev import worktree_stack


class WorktreeStackTests(unittest.TestCase):
    def test_project_and_ports_are_stable_and_path_scoped(self):
        first = worktree_stack.identity(Path("/tmp/marty-worktree-one"))
        self.assertEqual(first, worktree_stack.identity(Path("/tmp/marty-worktree-one")))
        second = worktree_stack.identity(Path("/tmp/marty-worktree-two"))
        self.assertNotEqual(first[0], second[0])
        self.assertTrue(first[0].startswith("marty-wt-"))
        self.assertLessEqual(first[1] + max(worktree_stack.PORT_OFFSETS.values()), 65535)

    def test_environment_discards_ambient_service_credentials(self):
        with patch.dict(os.environ, {
            "POSTGRES_PASSWORD": "not-for-this-worktree",
            "MARTY_RS_URI": "https://outside.invalid/wheel",
            "GOOGLE_CLIENT_SECRET": "not-for-this-worktree",
            "KEYCLOAK_KMS_ADDR": "https://other-stack.invalid",
            "SIGNING_KEYS_TLS_KMS_TOKEN_FILE": "/other-stack/managed-token",
        }, clear=True):
            env = worktree_stack.environment(Path("/tmp/worktree"), "marty-wt-test", 28000)
        self.assertNotIn("POSTGRES_PASSWORD", env)
        self.assertNotIn("GOOGLE_CLIENT_SECRET", env)
        self.assertEqual(env["MARTY_RS_URI"], "file:///worktree-dev-infra-only")
        self.assertEqual(env["MARTY_NETWORK_NAME"], "marty-wt-test-network")
        self.assertEqual(env["COMPOSE_DISABLE_ENV_FILE"], "1")
        self.assertEqual(env["PUBLIC_API_URL"], "http://127.0.0.1:28000")
        self.assertEqual(env["WT_UI_PORT"], "28001")
        self.assertEqual(env["KEYCLOAK_KMS_ADDR"], "https://worktree-dev-infra-only.invalid")
        self.assertEqual(env["KEYCLOAK_KMS_KEY_VERSION"], "0")
        self.assertEqual(env["SIGNING_KEYS_TLS_KMS_TOKEN_FILE"],
                         str(Path("/tmp/worktree") / ".worktree-dev-infra-only"
                             / "signing_keys_tls_kms_token_file"))

    def test_full_base_required_inputs_are_explicit_and_create_no_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = worktree_stack.environment(root, "marty-wt-test", 28000)
            source = (worktree_stack.ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
            required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", source))
            self.assertTrue(required)
            self.assertEqual(required - env.keys(), set())
            self.assertEqual(list(root.iterdir()), [])

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI is unavailable")
    def test_real_worktree_model_renders_with_isolated_infrastructure(self):
        root = worktree_stack.ROOT
        project = "marty-wt-real-render"
        env = worktree_stack.environment(root, project, 28000)
        command = worktree_stack.compose_command(root, project)
        rendered = subprocess.run(
            [*command, "config", "--format", "json"],
            env=env, text=True, capture_output=True, check=False,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        model = json.loads(rendered.stdout)
        worktree_stack.validate_config(command, env)
        for service in ("postgres", "redis"):
            config = model["services"][service]
            self.assertFalse(config.get("secrets"))
            self.assertNotIn("worktree-dev-infra-only", json.dumps(config))
            self.assertEqual(config["networks"], {"marty-network": None})
        self.assertEqual(model["volumes"]["postgres_data"]["name"],
                         f"{project}_postgres_data")
        self.assertEqual(model["volumes"]["redis_data"]["name"],
                         f"{project}_redis_data")

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI is unavailable")
    def test_compose_does_not_load_worktree_dotenv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text("SHOULD_NOT_LOAD=contaminated\n", encoding="utf-8")
            compose = root / "compose.yml"
            compose.write_text(
                "services:\n  probe:\n    image: busybox\n"
                "    environment:\n      VALUE: ${SHOULD_NOT_LOAD:-clean}\n",
                encoding="utf-8",
            )
            env = worktree_stack.environment(root, "marty-wt-test", 28000)
            probe = subprocess.run(
                ["docker", "compose", "--project-directory", str(root),
                 "-f", str(compose), "config", "--format", "json"],
                env=env, text=True, capture_output=True, check=False,
            )
            if probe.returncode and "unknown flag" in probe.stderr:
                self.skipTest("Docker Compose plugin is unavailable")
            self.assertEqual(probe.returncode, 0, probe.stderr)
            rendered = json.loads(probe.stdout)
            self.assertEqual(rendered["services"]["probe"]["environment"]["VALUE"], "clean")


if __name__ == "__main__":
    unittest.main()
