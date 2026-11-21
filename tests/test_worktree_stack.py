"""Worktree-local development must never inherit another stack's identity."""

from pathlib import Path
import json
import os
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
        }, clear=True):
            env = worktree_stack.environment(Path("/tmp/worktree"), "marty-wt-test", 28000)
        self.assertNotIn("POSTGRES_PASSWORD", env)
        self.assertNotIn("GOOGLE_CLIENT_SECRET", env)
        self.assertEqual(env["MARTY_RS_URI"], "file:///worktree-dev-infra-only")
        self.assertEqual(env["MARTY_NETWORK_NAME"], "marty-wt-test-network")
        self.assertEqual(env["COMPOSE_DISABLE_ENV_FILE"], "1")
        self.assertEqual(env["PUBLIC_API_URL"], "http://127.0.0.1:28000")
        self.assertEqual(env["WT_UI_PORT"], "28001")

    @unittest.skipUnless(shutil.which("bun") and shutil.which("node"),
                         "Bun and Node are required for the UI process boundary")
    def test_ui_runner_does_not_reload_service_credentials_from_dotenv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ui = root / "ui"
            (ui / "node_modules" / "vite").mkdir(parents=True)
            (ui / ".env").write_text("POSTGRES_PASSWORD=dotenv-service-sentinel\n", encoding="utf-8")
            (ui / ".env.local").write_text("GOOGLE_CLIENT_SECRET=local-service-sentinel\n", encoding="utf-8")
            (ui / "package.json").write_text(json.dumps({"scripts": {"dev": "node probe.cjs"}}), encoding="utf-8")
            (ui / "probe.cjs").write_text(
                "console.log(JSON.stringify(Object.fromEntries(['POSTGRES_PASSWORD', "
                "'GOOGLE_CLIENT_SECRET', 'VITE_PORT', 'VITE_API_URL', 'VITE_DEV_PROXY_TARGET']"
                ".map(name => [name, process.env[name] ?? null]))));\n",
                encoding="utf-8",
            )
            observations = []

            def run_ui(command, **kwargs):
                result = subprocess.run(command, **kwargs, text=True, capture_output=True,
                                        timeout=10, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                observations.append(json.loads(result.stdout))
                return result.returncode

            with patch.object(worktree_stack, "ROOT", root), \
                    patch.object(worktree_stack, "validate_config"), \
                    patch.object(worktree_stack.subprocess, "call", side_effect=run_ui), \
                    patch.object(worktree_stack.sys, "argv", ["worktree-stack", "ui", "--port-base", "28000"]):
                self.assertEqual(worktree_stack.main(), 0)
            self.assertEqual(observations, [{
                "POSTGRES_PASSWORD": None, "GOOGLE_CLIENT_SECRET": None,
                "VITE_PORT": "28001", "VITE_API_URL": "http://127.0.0.1:28000",
                "VITE_DEV_PROXY_TARGET": "http://127.0.0.1:28000",
            }])

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
