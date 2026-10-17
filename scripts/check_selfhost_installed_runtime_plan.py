#!/usr/bin/env python3
"""Fail-closed, unqualified plan for the exact extracted self-host Compose DAG.

This does not start services or qualify an installation. The existing prepared
consumer verifies ZIP, receipt, descriptor, image and mount identity first.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from check_prepared_selfhost_consumer import check, verify_descriptor


EXPECTED_SERVICES = frozenset({
    "applicant", "auth", "canvas-sync-worker", "cloudflared", "cloudflared-beta",
    "compliance-profile", "credential-template", "db-migrate",
    "deployment-profile", "device-registration", "edge", "event-stream", "flow",
    "gateway", "issuance", "issuance-migrations", "issuance-native", "keycloak",
    "keycloak-configurator", "notification", "organization", "postgres",
    "presentation-policy", "redis", "revocation-profile",
    "revocation-profile-migrate", "signing-keys", "trust-profile",
    "tunnel-nginx-proxy", "ui", "verification",
})
BETA_SERVICES = frozenset({"cloudflared-beta", "tunnel-nginx-proxy"})
CONDITIONS = frozenset({"service_healthy", "service_completed_successfully"})
H, C = "service_healthy", "service_completed_successfully"
# Reviewed all-profile Compose edge set. An intentional source dependency change
# must update this contract and its source-render test in the same review.
EXPECTED_DEPENDENCIES = {
    "applicant": {"db-migrate": C},
    "auth": {"db-migrate": C, "flow": H, "keycloak-configurator": C, "redis": H},
    "canvas-sync-worker": {"db-migrate": C, "issuance-migrations": C},
    "cloudflared": {"edge": H},
    "cloudflared-beta": {"tunnel-nginx-proxy": H},
    "compliance-profile": {"db-migrate": C},
    "credential-template": {"db-migrate": C},
    "db-migrate": {"postgres": H, "redis": H, "revocation-profile-migrate": C},
    "deployment-profile": {"db-migrate": C},
    "device-registration": {"db-migrate": C, "redis": H},
    "edge": {"flow": H, "gateway": H, "keycloak": H, "ui": H},
    "flow": {"credential-template": H, "db-migrate": C, "issuance": H, "organization": H,
             "presentation-policy": H, "redis": H},
    "gateway": {"applicant": H, "auth": H, "compliance-profile": H,
                "credential-template": H, "deployment-profile": H,
                "event-stream": H, "flow": H, "issuance": H, "issuance-native": H,
                "notification": H, "organization": H, "presentation-policy": H,
                "revocation-profile": H, "trust-profile": H, "verification": H},
    "issuance": {"db-migrate": C, "issuance-migrations": C, "issuance-native": H},
    "issuance-migrations": {"credential-template": H, "db-migrate": C,
                            "organization": H},
    "issuance-native": {"db-migrate": C, "issuance-migrations": C,
                        "postgres": H, "revocation-profile": H, "signing-keys": H},
    "keycloak": {"postgres": H},
    "keycloak-configurator": {"keycloak": H},
    "notification": {"db-migrate": C},
    "organization": {"db-migrate": C, "redis": H},
    "presentation-policy": {"db-migrate": C},
    "revocation-profile": {"db-migrate": C, "redis": H},
    "revocation-profile-migrate": {"postgres": H},
    "signing-keys": {"db-migrate": C, "redis": H},
    "trust-profile": {"db-migrate": C},
    "tunnel-nginx-proxy": {"edge": H},
    "verification": {"credential-template": H, "presentation-policy": H, "redis": H},
}
EXPECTED_ROLE_SECRETS = {
    "applicant": {"marty_db_password", "grpc_service_token",
                  "notification_applicant_event_token", "flow_application_event_hmac_key",
                  "workload_identity_ca_cert"},
    "auth": {"marty_api_client_secret", "marty_db_password", "grpc_service_token",
             "auth_workload_client_cert", "openbao_tls_ca_cert", "auth_tls_kms_token",
             "auth_workload_server_cert", "auth_server_tls_kms_token",
             "workload_identity_ca_cert", "flow_webhook_secret"},
    "canvas-sync-worker": {"marty_db_password", "issuance_api_key", "token_hmac_key",
                           "signing_keys_integration_secret_key", "signing_keys_issuer_sign_key",
                           "sign_grant_mint_issuance_canvas_token", "openbao_tls_ca_cert",
                           "workload_identity_ca_cert"},
    "cloudflared": {"cloudflare_tunnel_token"},
    "cloudflared-beta": {"cloudflare_beta_tunnel_token"},
    "compliance-profile": {"marty_db_password", "grpc_service_token",
                           "compliance_profile_workload_client_cert",
                           "openbao_tls_ca_cert", "compliance_profile_tls_kms_token",
                           "workload_identity_ca_cert"},
    "credential-template": {"marty_db_password", "issuance_api_key", "grpc_service_token",
                            "workload_identity_ca_cert", "ct_workload_server_cert",
                            "openbao_tls_ca_cert", "ct_tls_kms_token"},
    "db-migrate": {"marty_db_password", "openbao_bootstrap_token", "notification_openbao_token",
                   "openbao_tls_ca_cert"},
    "deployment-profile": {"marty_db_password", "grpc_service_token",
                           "deployment_profile_workload_client_cert",
                           "openbao_tls_ca_cert", "deployment_profile_tls_kms_token",
                           "workload_identity_ca_cert"},
    "device-registration": {"marty_db_password", "grpc_service_token",
                            "device_registration_gateway_key", "device_registration_signing_keys_key",
                            "workload_identity_ca_cert"},
    "event-stream": {"grpc_service_token", "es_workload_server_cert",
                     "openbao_tls_ca_cert", "es_tls_kms_token"},
    "flow": {"marty_db_password", "grpc_service_token", "flow_workload_client_cert",
             "flow_client_tls_kms_token", "flow_workload_server_cert",
             "flow_server_tls_kms_token", "openbao_tls_ca_cert", "workload_identity_ca_cert", "flow_webhook_secret",
             "flow_application_event_hmac_key", "issuance_api_key",
             "sign_grant_mint_flow_wallet_token", "signing_keys_issuer_sign_key"},
    "gateway": {"issuance_api_key", "grpc_service_token", "device_registration_gateway_key",
                "sign_grant_mint_gateway_issuer_did_token", "sign_grant_mint_gateway_service_token",
                "signing_keys_issuer_sign_key", "signing_keys_service_sign_gateway_key",
                "workload_identity_ca_cert", "gateway_workload_client_cert",
                "gateway_tls_kms_token", "openbao_tls_ca_cert"},
    "issuance": {"marty_db_password", "openbao_service_token", "openbao_tls_ca_cert",
                 "issuance_api_key",
                 "token_hmac_key", "canvas_credentials_shared_secret", "grpc_service_token",
                 "didcomm_issuance_openbao_token", "sign_grant_mint_issuance_canvas_token",
                 "sign_grant_mint_issuance_credential_token", "sign_grant_mint_issuance_passport_token",
                 "sign_grant_mint_issuance_readiness_token", "signing_keys_issuer_sign_key",
                 "signing_keys_integration_secret_key",
                 "workload_identity_ca_cert"},
    "issuance-migrations": {"marty_db_password"},
    "issuance-native": {"marty_db_password", "issuance_api_key",
                        "token_hmac_key", "canvas_credentials_shared_secret", "grpc_service_token",
                        "didcomm_issuance_openbao_token", "sign_grant_mint_issuance_canvas_token",
                        "sign_grant_mint_issuance_credential_token", "sign_grant_mint_issuance_passport_token",
                        "sign_grant_mint_issuance_readiness_token", "signing_keys_integration_secret_key",
                        "signing_keys_issuer_sign_key", "workload_identity_ca_cert",
                        "issuance_workload_server_cert", "openbao_tls_ca_cert",
                        "issuance_tls_kms_token"},
    "keycloak": {"keycloak_admin_password", "keycloak_db_password", "google_client_id",
                 "google_client_secret", "marty_api_client_secret", "openbao_tls_ca_cert",
                 "keycloak_signing_kms_token", "keycloak_master_rs256_cert",
                 "keycloak_11id_rs256_cert", "keycloak_master_cookie_token",
                 "keycloak_master_ciba_token", "keycloak_11id_cookie_token",
                 "keycloak_11id_ciba_token"},
    "keycloak-configurator": {"keycloak_admin_password", "google_client_id",
                              "google_client_secret", "marty_api_client_secret", "smtp_password"},
    "notification": {"marty_db_password", "grpc_service_token", "smtp_password",
                     "notification_webhook_secret", "notification_applicant_event_token",
                     "notification_openbao_token", "openbao_tls_ca_cert",
                     "notification_workload_server_cert", "notification_tls_kms_token"},
    "organization": {"marty_db_password", "grpc_service_token",
                     "org_workload_server_cert", "openbao_tls_ca_cert", "org_tls_kms_token",
                     "workload_identity_ca_cert"},
    "postgres": {"postgres_password", "keycloak_db_password", "marty_db_password"},
    "presentation-policy": {"marty_db_password", "grpc_service_token",
                            "pp_workload_server_cert", "pp_tls_kms_token",
                            "openbao_tls_ca_cert", "workload_identity_ca_cert"},
    "revocation-profile": {"marty_db_password", "grpc_service_token",
                           "workload_identity_ca_cert", "rp_workload_server_cert",
                           "openbao_tls_ca_cert", "rp_tls_kms_token"},
    "revocation-profile-migrate": {"marty_db_password"},
    "signing-keys": {"issuance_api_key", "device_registration_signing_keys_key",
                     "haip_kms_token", "sign_grant_verify_token",
                     "signing_keys_integration_secret_key", "signing_keys_issuer_sign_key",
                     "signing_keys_openbao_token", "signing_keys_service_sign_gateway_key",
                     "signing_keys_workload_server_cert", "openbao_tls_ca_cert",
                     "signing_keys_tls_kms_token", "workload_identity_ca_cert"},
    "trust-profile": {"marty_db_password", "grpc_service_token", "issuance_api_key",
                      "workload_identity_ca_cert"},
    "ui": {"google_analytics_measurement_id", "google_site_verification"},
    "verification": {"grpc_service_token", "verification_workload_client_cert",
                     "openbao_tls_ca_cert", "verification_tls_kms_token",
                     "workload_identity_ca_cert"},
}
EXPECTED_SECRET_NAMES = frozenset().union(*EXPECTED_ROLE_SECRETS.values())
KEYCLOAK_IMAGE = re.compile(r"^ghcr\.io/elevenid/marty-ui-oss/keycloak@sha256:[0-9a-f]{64}$")
KEYCLOAK_SECRET_TARGETS = {
    "keycloak_master_rs256_cert": "keycloak-master-rs256.crt",
    "keycloak_11id_rs256_cert": "keycloak-11id-rs256.crt",
    "keycloak_master_cookie_token": "master-cookie.token",
    "keycloak_master_ciba_token": "master-ciba.token",
    "keycloak_11id_cookie_token": "11id-cookie.token",
    "keycloak_11id_ciba_token": "11id-ciba.token",
}


def secret_target(service: str, source: str) -> str:
    """Return the reviewed in-container secret path for a service binding."""
    filename = KEYCLOAK_SECRET_TARGETS.get(source, source) if service == "keycloak" else source
    return f"/run/secrets/{filename}"


def plan(model: dict, preflight: dict, secret_root: Path) -> dict:
    """Validate every rendered role and edge, then emit non-secret identity/counts."""
    services = model.get("services")
    if not isinstance(services, dict) or set(services) != EXPECTED_SERVICES:
        raise ValueError("installed runtime service set differs from reviewed DAG")
    if (preflight.get("schema") != "marty.selfhost-consumer-preflight/v1"
            or preflight.get("qualification") != "unqualified"
            or preflight.get("service_count") != len(services)):
        raise ValueError("runtime DAG is not bound to full prepared preflight")
    keycloak = services["keycloak"]
    configurator = services["keycloak-configurator"]
    if (not isinstance(keycloak, dict) or not isinstance(configurator, dict)
            or not isinstance(keycloak.get("image"), str)
            or KEYCLOAK_IMAGE.fullmatch(keycloak["image"]) is None
            or configurator.get("image") != keycloak["image"]):
        raise ValueError("installed Keycloak services require the same pinned remote-key image")
    keycloak_env = keycloak.get("environment")
    if (not isinstance(keycloak_env, dict)
            or not isinstance(keycloak_env.get("BAO_ADDR"), str)
            or not keycloak_env["BAO_ADDR"].startswith("https://")
            or keycloak_env.get("BAO_CACERT") != "/run/secrets/openbao_tls_ca_cert"
            or keycloak_env.get("BAO_TOKEN_FILE") != "/run/secrets/keycloak_signing_kms_token"
            or keycloak_env.get("MARTY_KEYCLOAK_RS256_CERT_DIR") != "/run/secrets"
            or keycloak_env.get("MARTY_KEYCLOAK_JWE_TOKEN_DIR") != "/run/secrets"
            or keycloak_env.get("MARTY_KEYCLOAK_JWE_MOUNT") != "didcomm"
            or keycloak_env.get("MARTY_KEYCLOAK_KMS_KEY_PREFIX") != "keycloak"
            or re.fullmatch(r"[1-9][0-9]*", str(keycloak_env.get("MARTY_KEYCLOAK_KMS_KEY_VERSION", ""))) is None):
        raise ValueError("installed Keycloak remote-key environment is invalid")
    for digest_name in ("archive_sha256", "image_lock_sha256", "transaction_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(preflight.get(digest_name, ""))) is None:
            raise ValueError("runtime DAG lacks exact artifact identity")

    secrets = model.get("secrets", {})
    configs = model.get("configs", {})
    if not isinstance(secrets, dict) or set(secrets) != EXPECTED_SECRET_NAMES or configs != {}:
        raise ValueError("installed runtime secret/config declarations are invalid")
    for name, declaration in secrets.items():
        if (not isinstance(declaration, dict)
                or set(declaration) != {"name", "file"}
                or declaration["name"] != f"marty-selfhost-prod_{name}"
                or not isinstance(declaration["file"], str)
                or Path(declaration["file"]).resolve() != (secret_root / name).resolve()):
            raise ValueError(f"installed runtime secret {name} changed declaration")
    edges: dict[str, set[str]] = {}
    profile_members: dict[str, set[str]] = {"default": set(), "beta-tunnel": set()}
    for name, service in services.items():
        if not isinstance(service, dict):
            raise ValueError(f"installed runtime service {name} is invalid")
        profiles = service.get("profiles", [])
        if not isinstance(profiles, list) or any(not isinstance(p, str) for p in profiles):
            raise ValueError(f"installed runtime service {name} has invalid profiles")
        expected_profiles = ["beta-tunnel"] if name in BETA_SERVICES else []
        if profiles != expected_profiles:
            raise ValueError(f"installed runtime service {name} changed profile")
        if profiles:
            profile_members["beta-tunnel"].add(name)
        else:
            profile_members["default"].add(name)
        references = service.get("secrets", [])
        if not isinstance(references, list) or service.get("configs", []) != []:
            raise ValueError(f"installed runtime service {name} changed secret/config bindings")
        seen_secrets = set()
        for reference in references:
            if (not isinstance(reference, dict) or set(reference) != {"source", "target"}
                    or not isinstance(reference["source"], str)
                    or reference["source"] not in secrets
                    or reference["target"] != secret_target(name, reference["source"])
                    or reference["source"] in seen_secrets):
                raise ValueError(f"installed runtime service {name} has invalid secret binding")
            seen_secrets.add(reference["source"])
        if seen_secrets != EXPECTED_ROLE_SECRETS.get(name, set()):
            raise ValueError(f"installed runtime service {name} changed required secrets")
        dependencies = service.get("depends_on", {})
        if not isinstance(dependencies, dict):
            raise ValueError(f"installed runtime service {name} has invalid dependencies")
        if {peer: item.get("condition") if isinstance(item, dict) else None
            for peer, item in dependencies.items()} != EXPECTED_DEPENDENCIES.get(name, {}):
            raise ValueError(f"installed runtime service {name} changed dependency edges")
        edges[name] = set()
        for peer, dependency in dependencies.items():
            if (peer not in services or peer == name or not isinstance(dependency, dict)
                    or dependency.get("condition") not in CONDITIONS
                    or dependency.get("required") is not True):
                raise ValueError(f"installed runtime service {name} has invalid dependency")
            if peer in BETA_SERVICES and name not in BETA_SERVICES:
                raise ValueError("default runtime depends on beta-tunnel service")
            healthcheck = services[peer].get("healthcheck")
            health_test = healthcheck.get("test") if isinstance(healthcheck, dict) else None
            if dependency["condition"] == "service_healthy" and (
                    not isinstance(health_test, list) or len(health_test) < 2
                    or health_test[0] not in ("CMD", "CMD-SHELL")
                    or not all(isinstance(part, str) and part.strip() for part in health_test)
                    or healthcheck.get("disable") is True):
                raise ValueError(f"installed runtime dependency {peer} has no healthcheck")
            if dependency["condition"] == "service_completed_successfully" and str(
                    services[peer].get("restart")) != "no":
                raise ValueError(f"installed runtime dependency {peer} is not one-shot")
            edges[name].add(peer)

    # Kahn traversal is deterministic and rejects cycles, including optional roles.
    pending = {name: set(peers) for name, peers in edges.items()}
    layers: list[list[str]] = []
    while pending:
        ready = sorted(name for name, peers in pending.items() if not peers)
        if not ready:
            raise ValueError("installed runtime dependency DAG has a cycle")
        layers.append(ready)
        for name in ready:
            del pending[name]
        for peers in pending.values():
            peers.difference_update(ready)
    return {
        "schema": "marty.selfhost-installed-runtime-plan/v1",
        "qualification": "unqualified",
        "archive_sha256": preflight["archive_sha256"],
        "image_lock_sha256": preflight["image_lock_sha256"],
        "transaction_sha256": preflight["transaction_sha256"],
        "release": preflight["release"],
        "source_sha": preflight["source_sha"],
        "run_id": preflight["run_id"],
        "service_count": len(services),
        "default_service_count": len(profile_members["default"]),
        "beta_tunnel_service_count": len(profile_members["beta-tunnel"]),
        "dependency_count": sum(map(len, edges.values())),
        "startup_layers": layers,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt", "descriptor",
                 "compose-model", "source-checkout", "install-root", "state-root",
                 "secret-root", "expected-source-sha", "expected-run-id", "output"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    archive, lock, transaction, receipt = (Path(args.archive), Path(args.image_lock),
                                            Path(args.transaction), Path(args.receipt))
    verify_descriptor(archive, lock, transaction, receipt, Path(args.descriptor))
    preflight = check(archive, lock, transaction, receipt, Path(args.compose_model),
                      Path(args.source_checkout), args.expected_source_sha,
                      args.expected_run_id, Path(args.install_root), Path(args.state_root),
                      Path(args.secret_root))
    # check() has just recomputed and compared this complete receipt.
    verified_receipt = json.loads(receipt.read_text(encoding="utf-8"))
    preflight.update({name: verified_receipt[name] for name in
                      ("image_lock_sha256", "transaction_sha256", "release")})
    result = plan(json.loads(Path(args.compose_model).read_text(encoding="utf-8")),
                  preflight, Path(args.secret_root))
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")


if __name__ == "__main__":
    main()
