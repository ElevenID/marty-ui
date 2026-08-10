"""Marty-owned deployment gates for the verification workload trust boundary."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE_SECRETS = {
    "workload_identity_ca_cert",
    "pp_workload_server_cert",
    "pp_workload_server_key",
    "flow_workload_client_cert",
    "flow_workload_client_key",
    "verification_workload_client_cert",
    "verification_workload_client_key",
}


def test_production_stacks_require_all_workload_certificate_inputs() -> None:
    for stack_name in ("selfhost-production", "kubernetes-production"):
        stack = json.loads(
            (ROOT / "deploy-config/stacks" / f"{stack_name}.json").read_text(
                encoding="utf-8"
            )
        )
        assert CERTIFICATE_SECRETS <= set(stack["required_secrets"])


def test_selfhost_mounts_only_each_workloads_private_key() -> None:
    compose = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )
    services = compose["services"]

    presentation_secrets = set(services["presentation-policy"]["secrets"])
    flow_secrets = set(services["flow"]["secrets"])
    verification_secrets = set(services["verification"]["secrets"])

    assert {"pp_workload_server_cert", "pp_workload_server_key"} <= (
        presentation_secrets
    )
    assert {"flow_workload_client_cert", "flow_workload_client_key"} <= flow_secrets
    assert {
        "verification_workload_client_cert",
        "verification_workload_client_key",
    } <= verification_secrets
    assert "flow_workload_client_key" not in presentation_secrets
    assert "verification_workload_client_key" not in flow_secrets
    assert "pp_workload_server_key" not in verification_secrets

    presentation_env = services["presentation-policy"]["environment"]
    flow_env = services["flow"]["environment"]
    verification_env = services["verification"]["environment"]
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in presentation_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" not in presentation_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in flow_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in flow_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in verification_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in verification_env


def test_kubernetes_mounts_separate_workload_tls_secrets() -> None:
    documents = yaml.safe_load_all(
        (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
    )
    deployments = {
        document["metadata"]["name"]: document
        for document in documents
        if document and document.get("kind") == "Deployment"
    }

    expected = {
        "presentation-policy": "presentation-policy-workload-tls",
        "flow": "flow-workload-tls",
        "verification": "verification-workload-tls",
    }
    for service, secret_name in expected.items():
        pod_spec = deployments[service]["spec"]["template"]["spec"]
        [container] = pod_spec["containers"]
        env_names = [entry["name"] for entry in container["env"]]
        assert len(env_names) == len(set(env_names))
        assert any(
            mount["name"] == secret_name
            and mount["mountPath"] == "/var/run/secrets/marty/workload"
            and mount["readOnly"] is True
            for mount in container["volumeMounts"]
        )
        assert any(
            volume["name"] == secret_name
            and volume["secret"]["secretName"] == secret_name
            for volume in pod_spec["volumes"]
        )

        if service == "presentation-policy":
            assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_SERVER_KEY" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" not in env_names
        else:
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" in env_names
            assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in env_names
        assert env_names.count("GRPC_WORKLOAD_TLS_CA_CERT") == 1


def test_kubernetes_helper_creates_service_scoped_tls_secrets() -> None:
    deploy_script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(
        encoding="utf-8"
    )
    for secret_name in (
        "presentation-policy-workload-tls",
        "flow-workload-tls",
        "verification-workload-tls",
    ):
        assert f"kubectl create secret generic {secret_name}" in deploy_script
