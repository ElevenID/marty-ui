"""Verify resolved deployment credentials reach the scoped issuer resolver."""

import os
from pathlib import Path
import shutil
import unittest

import yaml

from scripts.test_canvas_worker_compose_render import render

ROOT = Path(__file__).resolve().parents[1]


class PresentationRegistryDeployment(unittest.TestCase):
    def test_compose_registry_credentials_match_signing_owner_and_mounts(self):
        if shutil.which("docker") is None:
            self.skipTest("Docker Compose is required for resolved deployment checks")
        for filename in (
            "docker-compose.base.yml",
            "docker-compose.selfhost.prod.yml",
            "docker-compose.passport-supported-disposable.yml",
        ):
            with self.subTest(stack=filename):
                # Use the established source-only renderer: no .env, env-file
                # reads, path expansion, daemon, or interpolation of credentials.
                # Unexpanded required image expressions are not runtime config.
                renderer = os.environ.get("MARTY_COMPOSE_RENDERER")
                services = render(
                    filename, compose_command=[renderer] if renderer else None
                )["services"]
                verifier = services["presentation-policy"]
                env = verifier["environment"]
                owner = services["signing-keys"]["environment"]
                self.assertEqual(
                    env["SIGNING_KEYS_SERVICE_URL"], "http://signing-keys:8017"
                )
                if "SIGNING_KEYS_INTERNAL_API_KEY_FILE" in env:
                    path = env["SIGNING_KEYS_INTERNAL_API_KEY_FILE"]
                    self.assertEqual(path, owner["SIGNING_KEYS_INTERNAL_API_KEY_FILE"])
                    mounts = {
                        s.get("target", s["source"]): s["source"]
                        for s in verifier["secrets"]
                    }
                    self.assertIn(path, mounts)
                else:
                    self.assertEqual(
                        env["SIGNING_KEYS_INTERNAL_API_KEY"],
                        owner["SIGNING_KEYS_INTERNAL_API_KEY"],
                    )

    def test_kubernetes_verifier_uses_the_registry_owner_secret(self):
        documents = list(
            yaml.safe_load_all((ROOT / "k8s/oracle/07-microservices.yaml").read_text())
        )
        documents.extend(
            yaml.safe_load_all((ROOT / "k8s/oracle/07b-signing-keys.yaml").read_text())
        )
        deployments = {
            d["metadata"]["name"]: d
            for d in documents
            if d and d.get("kind") == "Deployment"
        }

        def environment(name):
            container = deployments[name]["spec"]["template"]["spec"]["containers"][0]
            return {e["name"]: e for e in container["env"]}

        verifier = environment("presentation-policy")
        owner = environment("signing-keys")
        self.assertEqual(
            verifier["SIGNING_KEYS_SERVICE_URL"]["value"], "http://signing-keys:8017"
        )
        self.assertEqual(
            verifier["SIGNING_KEYS_INTERNAL_API_KEY"]["valueFrom"],
            owner["SIGNING_KEYS_INTERNAL_API_KEY"]["valueFrom"],
        )


if __name__ == "__main__":
    unittest.main()
