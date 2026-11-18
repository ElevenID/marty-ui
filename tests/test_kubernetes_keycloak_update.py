"""Image-only updates require the deployed Keycloak KMS manifest shape."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from scripts.check_kubernetes_keycloak_update import validate


ROOT = Path(__file__).resolve().parents[1]


def deployment() -> dict:
    documents = list(yaml.safe_load_all((ROOT / "k8s/oracle/05-keycloak.yaml").read_text(encoding="utf-8")))
    manifest = next(item for item in documents if item.get("kind") == "Deployment")
    manifest["spec"]["template"]["spec"]["containers"][0]["image"] = (
        "ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:" + "a" * 64
    )
    return manifest


def test_current_manifest_allows_exact_image_update() -> None:
    validate(deployment(), "marty-prod")


def redirect_signing_token(manifest: dict) -> None:
    env = manifest["spec"]["template"]["spec"]["containers"][0]["env"]
    next(item for item in env if item["name"] == "BAO_TOKEN_FILE")["value"] = "/tmp/token"


@pytest.mark.parametrize("change", [
    lambda d: d["spec"]["template"]["spec"]["containers"][0].update(
        {"image": "quay.io/keycloak/keycloak:25.0"}),
    redirect_signing_token,
    lambda d: d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].pop(),
    lambda d: d["spec"]["template"]["spec"]["volumes"].pop(),
])
def test_rejects_legacy_or_incomplete_keycloak_deployment(change) -> None:
    changed = copy.deepcopy(deployment())
    change(changed)
    with pytest.raises(ValueError):
        validate(changed, "marty-prod")
