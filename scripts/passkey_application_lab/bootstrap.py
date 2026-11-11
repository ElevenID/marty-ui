"""First real-service application fixture phase: native schema and KMS bootstrap.
Uses only capabilities supplied by the disposable KMS probe; no production access.
"""

import base64
import json
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

from config import IMAGE, OUT, ROOT

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from tests import test_keycloak_passkey_live as native


class ApplicationLab:
    def __init__(self, context):
        self.context = context
        self.created = []
        self.suffix = secrets.token_hex(5)
        self.prefix = "marty-passkey-application-" + self.suffix
        self.settings = json.loads((OUT / "generated-lab-settings.json").read_text())
        self.sensitive = []
        self.scratch = None

    def bao(self, *args):
        command = 'export BAO_ADDR=https://127.0.0.1:8200 BAO_CACERT=/tmp/bao-tls/vault-ca.pem BAO_TOKEN="$(cat /run/secrets/bao_root_token)"; exec bao "$@"'
        value = native.docker(
            "exec",
            self.context["openbao_container"],
            "sh",
            "-c",
            command,
            "application-lab",
            *args,
        )
        return json.loads(value) if value else {}

    def note(self, message):
        print(message, flush=True)

    def child_token(self, policy_name, policy):
        # The policy contains no credentials; root credential remains inside the owned Bao container.
        encoded = base64.b64encode(policy.encode()).decode()
        self.bao(
            "write",
            "-format=json",
            "sys/policies/acl/" + policy_name,
            "policy=" + encoded,
        )
        value = self.bao(
            "write",
            "-format=json",
            "auth/token/create",
            "policies=" + policy_name,
            "no_default_policy=true",
            "ttl=45m",
            "renewable=false",
        )["auth"]["client_token"]
        self.sensitive.append(value)
        return value

    def run_binary(self, binary, env, files=None, arguments=()):
        name = self.prefix + "-" + binary.removeprefix("marty-")
        command = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--name",
            name,
            "--label",
            "marty.test=passkey-application",
            "--network",
            self.context["network"],
            "--memory",
            "768m",
            "--cpus",
            "2",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=32m",
            "--log-opt",
            "max-size=1m",
            "--log-opt",
            "max-file=1",
        ]
        for source, target in files or []:
            command.extend(
                ["--mount", f"type=bind,source={source},target={target},readonly"]
            )
        for key, value in env.items():
            command.extend(["-e", key + "=" + str(value)])
        command += ["--entrypoint", "/usr/local/bin/" + binary, IMAGE, *arguments]
        self.created.append(name)
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        if result.returncode:
            diagnostic = (result.stdout + "\n" + result.stderr)[-6000:]
            for value in [*self.sensitive, *self.settings.values()]:
                if len(value) > 12:
                    diagnostic = diagnostic.replace(value, "<generated>")
            (OUT / (binary + "-bootstrap-diagnostic.txt")).write_text(
                diagnostic, encoding="utf-8"
            )
            raise RuntimeError(
                binary + " failed; sanitized private diagnostic retained"
            )
        self.note(binary + " completed successfully")

    def cleanup_container(self, name):
        assert name.startswith(self.prefix + "-")
        result = subprocess.run(
            ["docker", "container", "inspect", name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode:
            # Successful --rm migration commands have already removed themselves.
            if (
                "No such container" in result.stderr
                or "No such object" in result.stderr
            ):
                return
            raise RuntimeError("Could not inspect owned fixture container " + name)
        state = json.loads(result.stdout)[0]
        assert state["Config"]["Labels"]["marty.test"] == "passkey-application"
        assert self.context["network"] in state["NetworkSettings"]["Networks"]
        native.docker("rm", "-f", "-v", name)

    def bootstrap(self):
        assert self.context["network"].startswith("marty-keycloak-kms-net-")
        assert self.context["container"].startswith("marty-keycloak-kms-oidc-")
        self.scratch = tempfile.TemporaryDirectory(
            prefix="marty-passkey-application-", delete=False
        )
        scratch = pathlib.Path(self.scratch.name)
        try:
            pg = self.context["container"].replace("-oidc-", "-pg-")
            state = json.loads(native.docker("inspect", pg))[0]
            assert state["Config"]["Labels"]["marty.test"] == "keycloak-passkeys"
            assert "/var/lib/postgresql/data" in state["HostConfig"]["Tmpfs"]
            password = self.settings["MARTY_DB_PASSWORD"]
            assert re.fullmatch(r"[A-Za-z0-9_-]+", password)
            sql = f"CREATE ROLE marty LOGIN PASSWORD '{password}';\nCREATE DATABASE marty OWNER marty;\n"
            native.docker(
                "exec",
                "-i",
                pg,
                "psql",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "keycloak",
                "-d",
                "keycloak",
                input=sql,
            )
            redis = self.prefix + "-redis"
            self.created.append(redis)
            native.docker(
                "run",
                "-d",
                "--pull=never",
                "--name",
                redis,
                "--label",
                "marty.test=passkey-application",
                "--network",
                self.context["network"],
                "--network-alias",
                "redis",
                "--memory",
                "128m",
                "--cpus",
                "1",
                "--read-only",
                "--tmpfs",
                "/data:rw,size=32m",
                "redis:7-alpine",
                "redis-server",
                "--save",
                "",
                "--appendonly",
                "no",
            )
            ca = scratch / "ca.crt"
            ca.write_text(
                native.docker(
                    "exec",
                    self.context["openbao_container"],
                    "cat",
                    "/tmp/bao-tls/vault-ca.pem",
                ),
                encoding="ascii",
            )
            assert "PRIVATE KEY" not in ca.read_text()
            prefixes = [
                "cred-issuer-",
                "cred-dsc-",
                "lti-tool-",
                "oid4vp-verifier-",
                "marty-sign-grant-",
                "flow-response-envelope-",
                "notification-webhook-envelope-",
            ]
            policy = 'path "sys/mounts" { capabilities = ["read"] }\n'
            for prefix in prefixes:
                policy += f'path "transit/keys/{prefix}*" {{ capabilities = ["create", "read", "update"] }}\n'
            token = self.child_token(
                "passkey-application-bootstrap-" + self.suffix, policy
            )
            token_file = scratch / "bootstrap-token"
            token_file.write_text(token, encoding="ascii")
            files = [(ca, "/run/lab/ca.crt"), (token_file, "/run/lab/bootstrap-token")]
            env = {
                "DATABASE_URL": "postgresql://marty:"
                + password
                + "@postgres:5432/marty",
                "REDIS_URL": "redis://redis:6379",
                "REDIS_DB_GATEWAY": "2",
                "MARTY_ORG_ID": self.settings["MARTY_ORG_ID"],
                "MARTY_ORG_SLUG": self.settings["MARTY_ORG_SLUG"],
                "MARTY_ORG_ADMIN_EMAIL": self.settings["MARTY_ORG_ADMIN_EMAIL"],
                "MARTY_ORG_REVIEWER_EMAIL": self.settings["MARTY_ORG_REVIEWER_EMAIL"],
                "MARTY_ISSUER_DID": self.settings.get("MARTY_ISSUER_DID", ""),
                "MARTY_KMS_BOOTSTRAP_ENABLED": "true",
                "BAO_ADDR": "https://openbao:8200",
                "BAO_CACERT": "/run/lab/ca.crt",
                "BAO_TOKEN_FILE": "/run/lab/bootstrap-token",
                "NOTIFICATION_SECRET_KMS_PROVIDER": "openbao-transit",
                "NOTIFICATION_OPENBAO_TOKEN_FILE": "/run/lab/bootstrap-token",
                "NOTIFICATION_OPENBAO_CA_CERT_FILE": "/run/lab/ca.crt",
                "PUBLIC_DOMAIN": "localhost",
                "ISSUER_BASE_URL": "http://localhost",
                "PUBLIC_API_URL": "http://localhost",
            }
            self.run_binary("marty-migration-bootstrap", env, files)
            self.run_binary("marty-notification", env, files, ["--migrate"])
            self.run_binary("marty-organization", env, files, ["migrate"])
            self.run_binary("marty-credential-template", env, files, ["migrate"])
            self.run_binary("marty-device-registration", env, files, ["migrate"])
            self.run_binary("marty-issuance-service", env, files, ["migrate"])
            self.run_binary("marty-verification-service", env, files, ["migrate"])
            self.note(
                "Real native application database/KMS bootstrap and requested application qualification completed"
            )
        finally:
            failures = []
            for name in reversed(self.created):
                try:
                    self.cleanup_container(name)
                except Exception as error:
                    failures.append(type(error).__name__ + ": " + name)
            if failures:
                # Preserve mounts/diagnostics when a real cleanup gate fails.
                self.note("Fixture cleanup requires recovery: " + ", ".join(failures))
                raise RuntimeError("Owned application fixture cleanup incomplete")
            if self.scratch:
                self.scratch.cleanup()


def qualify(context):
    ApplicationLab(context).bootstrap()
