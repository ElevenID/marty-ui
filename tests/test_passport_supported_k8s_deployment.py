"""The opt-in K8s callback pair exposes only the intended secret and peers."""

from pathlib import Path
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "k8s/oracle/07c-passport-provider-supported.yaml"


def resources() -> dict[tuple[str, str], dict]:
    documents = yaml.safe_load_all((ROOT / MANIFEST).read_text(encoding="utf-8"))
    return {(item["kind"], item["metadata"]["name"]): item for item in documents}


def container(deployment: dict) -> dict:
    return deployment["spec"]["template"]["spec"]["containers"][0]


def environment(deployment: dict) -> dict:
    return {entry["name"]: entry for entry in container(deployment)["env"]}


def test_supported_k8s_pair_is_explicit_and_private() -> None:
    objects = resources()
    assert set(objects) == {
        ("Deployment", "passport-callback-signer-supported"),
        ("Deployment", "passport-provider-ingress"),
        ("Service", "passport-callback-signer-supported"),
        ("Service", "passport-provider-ingress"),
        ("NetworkPolicy", "passport-callback-signer-supported-ingress"),
        ("NetworkPolicy", "passport-provider-ingress-gateway"),
    }
    deploy_script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    assert MANIFEST.split("/")[-1] not in deploy_script
    config = yaml.safe_load((ROOT / "k8s/oracle/01-configmap.yaml").read_text(encoding="utf-8"))
    assert config["data"]["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] == "false"
    assert config["data"]["PASSPORT_PROVIDER_INGRESS_SERVICE_URL"] == ""

    signer = objects[("Deployment", "passport-callback-signer-supported")]
    ingress = objects[("Deployment", "passport-provider-ingress")]
    signer_env = environment(signer)
    ingress_env = environment(ingress)
    assert signer_env["ENVIRONMENT"]["value"] == "production"
    assert signer_env["PASSPORT_SUPPORTED_CALLBACK_SIGNER_ENABLED"]["value"] == "true"
    assert ingress_env["PASSPORT_PROVIDER_INGRESS_ENABLED"]["value"] == "true"
    assert ingress_env["PASSPORT_PROVIDER_SIGNER_URL"]["value"] == (
        "http://passport-callback-signer-supported:8018/internal/documents"
    )
    assert ingress_env["DATABASE_URL"]["valueFrom"]["secretKeyRef"]["key"] == (
        "DATABASE_SYNC_URL"
    )
    assert set(signer_env).isdisjoint(
        {"BAO_TOKEN", "BAO_TOKEN_FILE", "OPENBAO_SERVICE_TOKEN", "OPENBAO_SERVICE_TOKEN_FILE"}
    )
    assert "PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE" not in signer_env
    assert "PASSPORT_CALLBACK_SIGNER_BAO_TOKEN_FILE" not in ingress_env

    signer_spec = signer["spec"]["template"]["spec"]
    ingress_spec = ingress["spec"]["template"]["spec"]
    assert {item["secret"]["secretName"] for item in signer_spec["volumes"]} == {
        "passport-callback-signer-api",
        "passport-callback-signer-bao-token",
    }
    assert {item["secret"]["secretName"] for item in ingress_spec["volumes"]} == {
        "passport-callback-signer-api",
        "passport-provider-webhook",
    }
    assert all(volume["secret"]["defaultMode"] == 0o440 for volume in signer_spec["volumes"])
    assert all(volume["secret"]["defaultMode"] == 0o440 for volume in ingress_spec["volumes"])
    assert all(spec["automountServiceAccountToken"] is False for spec in (signer_spec, ingress_spec))
    assert all(
        objects[("Service", name)]["spec"]["type"] == "ClusterIP"
        for name in ("passport-callback-signer-supported", "passport-provider-ingress")
    )


def test_supported_k8s_network_policies_admit_only_intended_peers() -> None:
    objects = resources()
    expected = {
        "passport-callback-signer-supported-ingress": ("passport-provider-ingress", 8018),
        "passport-provider-ingress-gateway": ("gateway", 8021),
    }
    for name, (peer, port) in expected.items():
        policy = objects[("NetworkPolicy", name)]["spec"]
        assert policy["policyTypes"] == ["Ingress"]
        assert policy["ingress"] == [
            {
                "from": [{"podSelector": {"matchLabels": {"app": peer}}}],
                "ports": [{"protocol": "TCP", "port": port}],
            }
        ]


def test_supported_k8s_renderer_requires_digest_and_binds_both_pods() -> None:
    script = ROOT / "scripts/render_passport_provider_k8s.py"
    image = "example.invalid/marty@sha256:" + "a" * 64
    rendered = subprocess.run(
        [sys.executable, str(script), "--image", image],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    documents = list(yaml.safe_load_all(rendered))
    deployments = [item for item in documents if item["kind"] == "Deployment"]
    assert len(deployments) == 2
    assert {container(item)["image"] for item in deployments} == {image}
    assert "${" not in rendered

    mutable = subprocess.run(
        [sys.executable, str(script), "--image", "example.invalid/marty:latest"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert mutable.returncode != 0
    assert mutable.stdout == ""
