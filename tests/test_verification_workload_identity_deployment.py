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
    "flow_workload_server_cert",
    "flow_workload_server_key",
    "auth_workload_client_cert",
    "auth_workload_client_key",
    "applicant_workload_client_cert",
    "applicant_workload_client_key",
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
    auth_secrets = set(services["auth"]["secrets"])
    applicant_secrets = set(services["applicant"]["secrets"])

    assert {"pp_workload_server_cert", "pp_workload_server_key"} <= (
        presentation_secrets
    )
    assert {"flow_workload_client_cert", "flow_workload_client_key"} <= flow_secrets
    assert {"flow_workload_server_cert", "flow_workload_server_key"} <= flow_secrets
    assert {"auth_workload_client_cert", "auth_workload_client_key"} <= auth_secrets
    assert {
        "applicant_workload_client_cert",
        "applicant_workload_client_key",
    } <= applicant_secrets
    assert {
        "verification_workload_client_cert",
        "verification_workload_client_key",
    } <= verification_secrets
    assert "flow_workload_client_key" not in presentation_secrets
    assert "verification_workload_client_key" not in flow_secrets
    assert "pp_workload_server_key" not in verification_secrets
    assert "auth_workload_client_key" not in flow_secrets
    assert "applicant_workload_client_key" not in auth_secrets
    assert "flow_workload_server_key" not in applicant_secrets

    presentation_env = services["presentation-policy"]["environment"]
    flow_env = services["flow"]["environment"]
    verification_env = services["verification"]["environment"]
    auth_env = services["auth"]["environment"]
    applicant_env = services["applicant"]["environment"]
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in presentation_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" not in presentation_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in flow_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in flow_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in verification_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in verification_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in auth_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in auth_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in applicant_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in applicant_env


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
        "presentation-policy": {
            "presentation-policy-workload-tls": "/var/run/secrets/marty/workload"
        },
        "flow": {
            "flow-workload-tls": "/var/run/secrets/marty/workload",
            "flow-server-workload-tls": "/var/run/secrets/marty/flow-server-workload",
        },
        "verification": {
            "verification-workload-tls": "/var/run/secrets/marty/workload"
        },
        "auth": {"auth-workload-tls": "/var/run/secrets/marty/workload"},
        "applicant": {"applicant-workload-tls": "/var/run/secrets/marty/workload"},
    }
    for service, expected_mounts in expected.items():
        pod_spec = deployments[service]["spec"]["template"]["spec"]
        [container] = pod_spec["containers"]
        env_names = [entry["name"] for entry in container["env"]]
        assert len(env_names) == len(set(env_names))
        for secret_name, mount_path in expected_mounts.items():
            assert any(
                mount["name"] == secret_name
                and mount["mountPath"] == mount_path
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
        elif service == "flow":
            assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_SERVER_KEY" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" in env_names
        else:
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" in env_names
            assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in env_names
        assert env_names.count("GRPC_WORKLOAD_TLS_CA_CERT") == 1


def test_kubernetes_helper_creates_service_scoped_tls_secrets() -> None:
    deploy_script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    for secret_name in (
        "presentation-policy-workload-tls",
        "flow-workload-tls",
        "flow-server-workload-tls",
        "auth-workload-tls",
        "applicant-workload-tls",
        "verification-workload-tls",
    ):
        assert f"kubectl create secret generic {secret_name}" in deploy_script
