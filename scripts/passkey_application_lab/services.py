"""Derive cached-image development service definitions for the owned application lab.
The source model is never executed: global mounts, names, ports and secrets are discarded.
"""

import copy
import json

from config import IMAGE, OUT

TOKEN_ROLES = {
    "BAO_TOKEN_FILE": "runtime",
    "DIDCOMM_KMS_TOKEN_FILE": "holder",
    "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE": "grant-verify",
    "FLOW_SIGN_GRANT_MINT_TOKEN_FILE": "grant-flow",
    "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE": "grant-issuance-credential",
    "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE": "grant-issuance-canvas",
    "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN_FILE": "grant-issuance-readiness",
    "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN_FILE": "grant-issuance-passport",
    "GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE": "grant-gateway-service",
    "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN_FILE": "grant-gateway-issuer",
    "NOTIFICATION_OPENBAO_TOKEN_FILE": "notification",
}


def definition(name, origin, keycloak_host, ca_file, tokens):
    model = json.loads((OUT / "canonical-service-model.json").read_text())
    settings = json.loads((OUT / "generated-lab-settings.json").read_text())
    source = model[name]
    env = copy.deepcopy(source.get("environment", {}))
    # Resolve local development defaults first. WorkloadMixin installs native TLS
    # certificates and HTTPS targets on the supported links before startup.
    env = {k: ("" if v is None else str(v)) for k, v in env.items() if "TLS" not in k}
    env.update(
        ENVIRONMENT="development",
        ALLOW_PLAINTEXT_GRPC="true",
        GRPC_SERVICE_TOKEN=settings["GRPC_SERVICE_TOKEN"],
    )
    for key, value in tuple(env.items()):
        if key.endswith("_GRPC_TARGET") and value.startswith("https://"):
            env[key] = "http://" + value[len("https://") :]
    for key in tuple(env):
        if key in settings:
            env[key] = settings[key]
    if "DATABASE_URL" in env:
        env["DATABASE_URL"] = (
            "postgresql://marty:"
            + settings["MARTY_DB_PASSWORD"]
            + "@postgres:5432/marty"
        )
    for key in ("UI_BASE_URL", "ISSUER_BASE_URL", "PUBLIC_BASE_URL", "PUBLIC_API_URL"):
        if key in env:
            env[key] = origin
    if "PUBLIC_DOMAIN" in env:
        env["PUBLIC_DOMAIN"] = "localhost"
    if name == "auth":
        env.update(
            KEYCLOAK_REALM="11id",
            OIDC_ISSUER_URL=f"http://{keycloak_host}:8080/realms/11id",
            OIDC_EXTERNAL_ISSUER_URL=origin + "/realms/11id",
            OIDC_REDIRECT_URI=origin + "/v1/auth/callback",
            OIDC_POST_LOGOUT_REDIRECT_URI=origin + "/",
            OIDC_CLIENT_ID="marty-ui",
            COOKIE_SECURE="false",
            KEYCLOAK_ADMIN_URL=f"http://{keycloak_host}:8080",
            KEYCLOAK_PASSKEYS_ENABLED="true",
            MARTY_API_CLIENT_ID="marty-api",
            MARTY_API_CLIENT_SECRET=settings["MARTY_API_CLIENT_SECRET"],
        )
    if name == "flow":
        env["FLOW_CALLBACK_DESTINATIONS"] = (
            settings["MARTY_ORG_ID"]
            + "|http://auth:8001/internal/v1/auth/credential-verified?nonce=__MARTY_TOKEN__"
        )
    if name == "signing-keys":
        env["ISSUER_BASE_URL"] = origin
    if "ISSUANCE_SERVICE_URL" in env:
        env["ISSUANCE_SERVICE_URL"] = "http://issuance-native:8005"
    mounts = []
    if "BAO_ADDR" in env:
        env["BAO_ADDR"] = "https://openbao:8200"
        env["BAO_CACERT"] = "/run/lab/ca.crt"
        mounts.append(
            {
                "type": "bind",
                "source": str(ca_file),
                "target": "/run/lab/ca.crt",
                "read_only": True,
            }
        )
    for key, role in TOKEN_ROLES.items():
        if key in env:
            assert role in tokens, f"Missing scoped lab token: {role}"
            target = "/run/lab/" + role + ".token"
            env[key] = target
            mounts.append(
                {
                    "type": "bind",
                    "source": str(tokens[role]),
                    "target": target,
                    "read_only": True,
                }
            )
    if "NOTIFICATION_OPENBAO_CA_CERT_FILE" in env:
        env["NOTIFICATION_OPENBAO_CA_CERT_FILE"] = "/run/lab/ca.crt"
    assert not any(str(v).startswith("/bao/") for v in env.values()), (
        "Unmapped global secret path"
    )
    result = {
        "image": IMAGE,
        "pull_policy": "never",
        "environment": env,
        "read_only": True,
        "mem_limit": "512m",
        "cpus": 1,
        "entrypoint": ["/app/services/entrypoint.sh"],
        "tmpfs": [
            "/tmp:rw,nosuid,nodev,size=32m",
            "/app/data:rw,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700",
        ],
        "logging": {
            "driver": "json-file",
            "options": {"max-size": "1m", "max-file": "1"},
        },
        "volumes": mounts,
        "labels": {"marty.test": "passkey-application", "marty.writer": "root"},
        "restart": "no",
    }
    result["environment"]["SERVICE_NAME"] = name.replace("-", "_")
    if name == "issuance-native":
        result["environment"]["SERVICE_NAME"] = "issuance_native"
    return result
