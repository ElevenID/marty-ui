"""Read the canonical Compose environment into an isolated test-only model.
Never start the base Compose file. No production files or process env are read.
"""

import json
import os
import re
import secrets
import subprocess

from config import KEYCLOAK_IMAGE, OUT, ROOT

FILES = [
    "docker-compose.base.yml",
    "docker-compose.profile.issuance-native.yml",
    "docker-compose.service.issuance-native-runtime.yml",
]


def prepare():
    OUT.mkdir(parents=True, exist_ok=True)
    unused = OUT / "unused-model-input"
    unused.write_text("", encoding="utf-8")
    values = {}
    for filename in FILES:
        text = (ROOT / filename).read_text(encoding="utf-8")
        for name in re.findall(r"\$\{([A-Z0-9_]+):\?", text):
            values[name] = (
                str(unused)
                if name.endswith("_FILE")
                else ("1" if name.endswith("_VERSION") else "isolated-model-only")
            )
            if name.endswith("_ADDR"):
                values[name] = "https://openbao:8200"
    values.update(
        KEYCLOAK_KMS_IMAGE_DIGEST=KEYCLOAK_IMAGE,
        ENVIRONMENT="development",
        MARTY_ORG_ID="00000000-0000-0000-0000-000000000001",
        MARTY_ORG_SLUG="marty",
        MARTY_ISSUER_DID="did:web:localhost:orgs:marty",
        OID4VP_ISSUER_DID="did:web:localhost:orgs:marty",
        CREDENTIAL_LOGIN_ISSUER_DID="did:web:localhost:orgs:marty",
        CREDENTIAL_LOGIN_ORGANIZATION_ID="00000000-0000-0000-0000-000000000001",
        CREDENTIAL_LOGIN_POLICY_ID="50000000-0000-0000-0000-000000000004",
        MARTY_ORG_ADMIN_EMAIL="administrator.passkey@example.invalid",
        MARTY_ORG_REVIEWER_EMAIL="reviewer.passkey@example.invalid",
        KEYCLOAK_PASSKEYS_ENABLED="true",
        KEYCLOAK_PASSKEY_RP_ID="localhost",
        KEYCLOAK_SOCIAL_LOGIN_ENABLED="false",
        MARTY_KMS_BOOTSTRAP_ENABLED="true",
    )
    for key in (
        "MARTY_DB_PASSWORD",
        "GRPC_SERVICE_TOKEN",
        "ISSUANCE_API_KEY",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "SIGNING_KEYS_ISSUER_SIGN_KEY",
        "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY",
        "SIGNING_KEYS_INTEGRATION_SECRET_KEY",
        "FLOW_WEBHOOK_SECRET",
        "FLOW_APPLICATION_EVENT_HMAC_KEY",
        "MARTY_API_CLIENT_SECRET",
        "KEYCLOAK_ADMIN_PASSWORD",
        "TOKEN_HMAC_KEY",
    ):
        values[key] = secrets.token_urlsafe(36)
    environment_file = OUT / "model.env"
    environment_file.write_text(
        "".join(f"{key}={value}\n" for key, value in sorted(values.items())),
        encoding="utf-8",
    )
    process_env = {
        key: os.environ[key]
        for key in (
            "PATH",
            "SystemRoot",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "ProgramData",
            "ALLUSERSPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
        )
        if key in os.environ
    }
    raw = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(environment_file),
            "-f",
            "docker-compose.base.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=process_env,
        capture_output=True,
        text=True,
    )
    if raw.returncode:
        diagnostic = raw.stderr
        for value in values.values():
            if len(value) > 16:
                diagnostic = diagnostic.replace(value, "<generated>")
        raise RuntimeError(diagnostic[:1200])
    model = json.loads(raw.stdout)
    chosen = [
        "auth",
        "organization",
        "applicant",
        "event-stream",
        "flow",
        "signing-keys",
        "issuance-native",
        "credential-template",
        "device-registration",
        "compliance-profile",
        "presentation-policy",
        "trust-profile",
        "deployment-profile",
        "verification",
        "revocation-profile",
        "notification",
        "gateway",
    ]
    selected = {name: model["services"][name] for name in chosen}
    # Store the source model only; it has global mounts/ports and must not run.
    (OUT / "canonical-service-model.json").write_text(
        json.dumps(selected, indent=2), encoding="utf-8"
    )
    (OUT / "generated-lab-settings.json").write_text(
        json.dumps(values, indent=2), encoding="utf-8"
    )
    print(
        "Canonical model resolved for",
        len(selected),
        "real services; generated isolated credentials only. Not a runnable stack.",
    )
    for name, service in selected.items():
        env = service.get("environment", {})
        print(
            name,
            "environment_fields=" + str(len(env)),
            "native="
            + str(
                "rust" in str(service.get("build", {}))
                or "services/Dockerfile" in str(service.get("build", {}))
            ),
        )
