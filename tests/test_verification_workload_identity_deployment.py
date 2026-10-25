"""Marty-owned deployment gates for the verification workload trust boundary."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE_SECRETS = {
    "workload_identity_ca_cert",
    "openbao_tls_ca_cert",
    "pp_workload_server_cert",
    "pp_tls_kms_token",
    "flow_workload_client_cert",
    "flow_client_tls_kms_token",
    "flow_workload_server_cert",
    "flow_server_tls_kms_token",
    "auth_workload_client_cert",
    "auth_tls_kms_token",
    "verification_workload_client_cert",
    "verification_tls_kms_token",
    "deployment_profile_workload_client_cert",
    "deployment_profile_tls_kms_token",
    "compliance_profile_workload_client_cert",
    "compliance_profile_tls_kms_token",
}


def test_production_stacks_require_all_workload_certificate_inputs() -> None:
    for stack_name in ("selfhost-production", "kubernetes-production"):
        stack = json.loads(
            (ROOT / "deploy-config/stacks" / f"{stack_name}.json").read_text(
                encoding="utf-8"
            )
        )
        assert CERTIFICATE_SECRETS <= set(stack["required_secrets"])


def test_selfhost_signing_keys_tls_uses_remote_signer_without_a_private_key_mount() -> None:
    compose = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )
    service = compose["services"]["signing-keys"]
    environment = service["environment"]
    assert "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KEY_FILE" not in environment
    assert "signing_keys_workload_server_key" not in service["secrets"]
    assert {
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_ADDR",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_CA_CERT_FILE",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_TOKEN_FILE",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_NAME",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_VERSION",
    } <= environment.keys()
    assert {"openbao_tls_ca_cert", "signing_keys_tls_kms_token"} <= set(
        service["secrets"]
    )
    example = ROOT / "docker/secrets/selfhost.example"
    assert not (example / "signing_keys_workload_server_key").exists()
    assert all(
        (example / name).is_file()
        for name in ("openbao_tls_ca_cert", "signing_keys_tls_kms_token")
    )


def test_selfhost_workload_secret_mounts_match_current_tls_contract() -> None:
    compose = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )
    services = compose["services"]

    presentation_secrets = set(services["presentation-policy"]["secrets"])
    flow_secrets = set(services["flow"]["secrets"])
    verification_secrets = set(services["verification"]["secrets"])
    auth_secrets = set(services["auth"]["secrets"])
    applicant_secrets = set(services["applicant"]["secrets"])
    deployment_profile_secrets = set(services["deployment-profile"]["secrets"])
    compliance_profile_secrets = set(services["compliance-profile"]["secrets"])
    device_registration = services["device-registration"]

    assert {"pp_workload_server_cert", "openbao_tls_ca_cert", "pp_tls_kms_token"} <= (
        presentation_secrets
    )
    assert "pp_workload_server_key" not in presentation_secrets
    assert {
        "flow_workload_client_cert",
        "flow_workload_server_cert",
        "openbao_tls_ca_cert",
        "flow_client_tls_kms_token",
        "flow_server_tls_kms_token",
    } <= flow_secrets
    assert "flow_workload_client_key" not in flow_secrets
    assert "flow_workload_server_key" not in flow_secrets
    assert {
        "auth_workload_client_cert", "auth_workload_server_cert",
        "openbao_tls_ca_cert", "auth_tls_kms_token", "auth_server_tls_kms_token",
    } <= auth_secrets
    assert "auth_workload_client_key" not in auth_secrets
    assert not any(secret.startswith("applicant_workload_") for secret in applicant_secrets)
    assert {
        "verification_workload_client_cert",
        "openbao_tls_ca_cert",
        "verification_tls_kms_token",
    } <= verification_secrets
    assert "verification_workload_client_key" not in verification_secrets
    assert {
        "deployment_profile_workload_client_cert",
        "openbao_tls_ca_cert",
        "deployment_profile_tls_kms_token",
    } <= deployment_profile_secrets
    assert "deployment_profile_workload_client_key" not in deployment_profile_secrets
    assert {
        "compliance_profile_workload_client_cert",
        "openbao_tls_ca_cert",
        "compliance_profile_tls_kms_token",
    } <= compliance_profile_secrets
    assert "compliance_profile_workload_client_key" not in compliance_profile_secrets
    assert "flow_workload_client_key" not in presentation_secrets
    assert "verification_workload_client_key" not in flow_secrets
    assert "pp_workload_server_key" not in verification_secrets
    assert "auth_workload_client_key" not in flow_secrets
    assert "applicant_workload_client_key" not in auth_secrets
    assert "flow_workload_server_key" not in applicant_secrets
    assert "workload_identity_ca_cert" in device_registration["secrets"]
    assert device_registration["environment"]["ORG_GRPC_TARGET"] == "https://organization:9002"
    assert device_registration["environment"]["ORG_GRPC_CA_CERT"] == "/run/secrets/workload_identity_ca_cert"

    presentation_env = services["presentation-policy"]["environment"]
    assert presentation_env["ORG_GRPC_TARGET"] == "https://organization:9002"
    assert presentation_env["ORG_GRPC_CA_CERT"] == "/run/secrets/workload_identity_ca_cert"
    flow_env = services["flow"]["environment"]
    verification_env = services["verification"]["environment"]
    auth_env = services["auth"]["environment"]
    applicant_env = services["applicant"]["environment"]
    deployment_profile_env = services["deployment-profile"]["environment"]
    compliance_profile_env = services["compliance-profile"]["environment"]
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in presentation_env
    assert "GRPC_WORKLOAD_TLS_SERVER_KEY" not in presentation_env
    assert {
        "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION",
    } <= presentation_env.keys()
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" not in presentation_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in flow_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in flow_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in flow_env
    assert "GRPC_WORKLOAD_TLS_SERVER_KEY" not in flow_env
    assert {
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION",
    } <= flow_env.keys()
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in verification_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in verification_env
    assert {
        "GRPC_WORKLOAD_TLS_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_KMS_KEY_VERSION",
    } <= verification_env.keys()
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in verification_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in auth_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in auth_env
    assert {
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION",
    } <= auth_env.keys()
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in auth_env
    assert "GRPC_WORKLOAD_TLS_SERVER_KEY" not in auth_env
    assert {
        "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION",
    } <= auth_env.keys()
    assert not any(name.startswith("GRPC_WORKLOAD_TLS_") for name in applicant_env)
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in applicant_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in deployment_profile_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in deployment_profile_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in deployment_profile_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in compliance_profile_env
    assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in compliance_profile_env
    assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in compliance_profile_env
    profile_kms_names = {
        "GRPC_WORKLOAD_TLS_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_KMS_KEY_VERSION",
    }
    assert profile_kms_names <= deployment_profile_env.keys()
    assert profile_kms_names <= compliance_profile_env.keys()


def test_profile_organization_channels_require_remote_tls_in_deployments() -> None:
    production = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )["services"]
    beta = yaml.safe_load(
        (ROOT / "docker-compose.beta.yml").read_text(encoding="utf-8")
    )["services"]
    for profile in ("compliance-profile", "deployment-profile"):
        secret_prefix = profile.replace("-", "_")
        for stack in (production, beta):
            service = stack[profile]
            environment = service["environment"]
            assert environment["GRPC_INSECURE_ALLOWED"] == "false"
            assert environment["ORG_GRPC_TARGET"] == "https://organization:9002"
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in environment
            assert {
                f"{secret_prefix}_workload_client_cert",
                f"{secret_prefix}_tls_kms_token",
                "openbao_tls_ca_cert",
                "workload_identity_ca_cert",
            } <= set(service["secrets"])


def test_verification_targets_are_explicit_https_in_production_and_beta() -> None:
    for manifest in ("docker-compose.selfhost.prod.yml", "docker-compose.beta.yml"):
        service = yaml.safe_load((ROOT / manifest).read_text(encoding="utf-8"))["services"]["verification"]
        assert {
            name: service["environment"][name]
            for name in ("ORG_GRPC_TARGET", "CT_GRPC_TARGET", "PP_GRPC_TARGET")
        } == {
            "ORG_GRPC_TARGET": "https://organization:9002",
            "CT_GRPC_TARGET": "https://credential-template:9003",
            "PP_GRPC_TARGET": "https://presentation-policy:9009",
        }


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
            "presentation-policy-workload-tls": "/var/run/secrets/marty/workload",
            "pp-tls-kms": "/var/run/secrets/marty/pp-tls-kms",
        },
        "flow": {
            "flow-workload-tls": "/var/run/secrets/marty/workload",
            "flow-client-tls-kms": "/var/run/secrets/marty/flow-client-tls-kms",
            "flow-server-workload-tls": "/var/run/secrets/marty/flow-server-workload",
            "flow-server-tls-kms": "/var/run/secrets/marty/flow-server-tls-kms",
        },
        "verification": {
            "verification-workload-tls": "/var/run/secrets/marty/workload",
            "verification-tls-kms": "/var/run/secrets/marty/verification-tls-kms",
        },
        "auth": {
            "auth-workload-tls": "/var/run/secrets/marty/workload",
            "auth-tls-kms": "/var/run/secrets/marty/auth-tls-kms",
        },
        "deployment-profile": {
            "deployment-profile-workload-tls": "/var/run/secrets/marty/workload",
            "deployment-profile-tls-kms": "/var/run/secrets/marty/deployment-profile-tls-kms",
        },
        "compliance-profile": {
            "compliance-profile-workload-tls": "/var/run/secrets/marty/workload",
            "compliance-profile-tls-kms": "/var/run/secrets/marty/compliance-profile-tls-kms",
        },
        "device-registration": {
            "org-workload-tls": "/var/run/secrets/marty/org-workload",
        },
    }
    for service, expected_mounts in expected.items():
        pod_spec = deployments[service]["spec"]["template"]["spec"]
        [container] = pod_spec["containers"]
        env_names = [entry["name"] for entry in container["env"]]
        assert len(env_names) == len(set(env_names))
        if service in {"compliance-profile", "deployment-profile"}:
            environment = {
                entry["name"]: entry["value"]
                for entry in container["env"]
                if "value" in entry
            }
            assert environment["GRPC_INSECURE_ALLOWED"] == "false"
            assert environment["ORG_GRPC_TARGET"] == "https://organization:9002"
        if service == "presentation-policy":
            environment = {
                entry["name"]: entry["value"]
                for entry in container["env"]
                if "value" in entry
            }
            assert environment["ORG_GRPC_TARGET"] == "https://organization:9002"
            assert environment["ORG_GRPC_CA_CERT"] == "/var/run/secrets/marty/workload/ca.crt"
        if service == "device-registration":
            environment = {
                entry["name"]: entry["value"]
                for entry in container["env"]
                if "value" in entry
            }
            assert environment["ORG_GRPC_TARGET"] == "https://organization:9002"
            assert environment["ORG_GRPC_CA_CERT"] == "/var/run/secrets/marty/org-workload/ca.crt"
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
            assert "GRPC_WORKLOAD_TLS_SERVER_KEY" not in env_names
            assert {
                "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION",
            } <= set(env_names)
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" not in env_names
        elif service == "flow":
            assert "GRPC_WORKLOAD_TLS_SERVER_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_SERVER_KEY" not in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in env_names
            assert {
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
                "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION",
            } <= set(env_names)
        elif service == "auth":
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in env_names
            assert {
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME",
                "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION",
            } <= set(env_names)
        elif service == "verification":
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in env_names
            assert {
                "GRPC_WORKLOAD_TLS_KMS_ADDR",
                "GRPC_WORKLOAD_TLS_KMS_CA_CERT",
                "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE",
                "GRPC_WORKLOAD_TLS_KMS_KEY_NAME",
                "GRPC_WORKLOAD_TLS_KMS_KEY_VERSION",
            } <= set(env_names)
        elif service == "device-registration":
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in env_names
        else:
            assert "GRPC_WORKLOAD_TLS_CLIENT_CERT" in env_names
            assert "GRPC_WORKLOAD_TLS_CLIENT_KEY" not in env_names
            assert {
                "GRPC_WORKLOAD_TLS_KMS_ADDR",
                "GRPC_WORKLOAD_TLS_KMS_CA_CERT",
                "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE",
                "GRPC_WORKLOAD_TLS_KMS_KEY_NAME",
                "GRPC_WORKLOAD_TLS_KMS_KEY_VERSION",
            } <= set(env_names)
            assert "GRPC_WORKLOAD_TLS_SERVER_CERT" not in env_names
        if service != "device-registration":
            assert env_names.count("GRPC_WORKLOAD_TLS_CA_CERT") == 1

    applicant_pod = deployments["applicant"]["spec"]["template"]["spec"]
    assert not any(
        entry["name"].startswith("GRPC_WORKLOAD_TLS_")
        for entry in applicant_pod["containers"][0]["env"]
    )
    assert not any(
        mount["name"] == "applicant-workload-tls"
        for mount in applicant_pod["containers"][0].get("volumeMounts", [])
    )


def test_kubernetes_helper_creates_service_scoped_tls_secrets() -> None:
    deploy_script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    spec = json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_text())
    names = {entry["name"] for entry in spec["secrets"]}
    assert 'kubernetes-secrets "$K8S_STACK_NAME" "$NAMESPACE"' in deploy_script
    for secret_name in (
        "presentation-policy-workload-tls",
        "flow-workload-tls",
        "flow-server-workload-tls",
        "auth-workload-tls",
        "verification-workload-tls",
        "deployment-profile-workload-tls",
        "compliance-profile-workload-tls",
    ):
        assert secret_name in names
