"""Opt-in native passkeys on the packaged remote-KMS/PostgreSQL/cluster fixture."""
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse

import pytest

from tests import test_keycloak_passkey_live as native

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_keycloak_remote_rs256 as kms  # noqa: E402

KEYCLOAK_IMAGE = os.environ.get("MARTY_PASSKEY_PACKAGED_IMAGE")
OPENBAO_IMAGE = os.environ.get("MARTY_PASSKEY_PACKAGED_OPENBAO_IMAGE")
pytestmark = pytest.mark.skipif(
    not KEYCLOAK_IMAGE or not OPENBAO_IMAGE,
    reason="Select owned packaged Keycloak and OpenBao test images explicitly",
)


def qualify_passkeys(context):
    """Only receives capabilities for a live, owned disposable KMS fixture."""
    primary = context["container"]
    replica_name = primary + "-passkey-replica"
    smtp_name = primary + "-passkey-smtp"
    replica = smtp = None
    # Chrome WebAuthn uses the loopback hostname as RP ID. Each token below is
    # minted on that same origin; the parent probe retains its own loopback URL.
    port = urllib.parse.urlparse(context["base"]).port
    base = f"http://localhost:{port}"
    admin = base + "/admin/realms/11id"

    def admin_token():
        return native.request(base + "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli", "username": "probe",
            "password": "synthetic-probe-only"})["access_token"]

    try:
        smtp = native.docker("run", "-d", "--name", smtp_name, "--memory", "64m",
            "--network", context["network"], "--network-alias", "passkey-smtp", "--read-only",
            "--label", "marty.test=keycloak-passkeys", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
            "python:3.12.10-slim-bookworm", "python", "-u", "-c", native.SMTP_CAPTURE)
        native.request(admin, token=admin_token, method="PUT", body={
            "loginTheme": "11id", "emailTheme": "11id", "registrationAllowed": True,
            "resetPasswordAllowed": True, "registrationEmailAsUsername": True,
            "smtpServer": {"host": "passkey-smtp", "port": "1025", "from": "noreply@example.invalid",
                           "auth": "false", "ssl": "false", "starttls": "false"}})
        native.request(admin + "/clients", token=admin_token, body={
            "clientId": "passkey-test-ui", "enabled": True, "publicClient": True,
            "standardFlowEnabled": True, "redirectUris": [base + "/callback"],
            "attributes": {"pkce.code.challenge.method": "S256"}})
        native.request(admin + "/identity-provider/instances", token=admin_token, body={
            "alias": "google", "providerId": "google", "enabled": True,
            "config": {"clientId": "synthetic", "clientSecret": "synthetic"}})
        fixture = {"name": primary, "container": primary, "smtp": smtp,
                   "base": base, "admin": admin, "realm": "11id", "admin_username": "probe",
                   "token": admin_token, "env": {"KEYCLOAK_ADMIN_PASSWORD": "synthetic-probe-only"}}
        result = native.configure(fixture, "true")
        assert result.returncode == 0, result.stderr

        original = json.loads(native.docker("inspect", primary))[0]
        required_mounts = {"/run/kms/ca.crt", "/run/kms/token", "/run/kms/certs",
                           "/run/kms/jwe-tokens", "/opt/keycloak/themes/11id"}
        mounts = original["Mounts"]
        assert {mount["Destination"] for mount in mounts} == required_mounts
        arguments = []
        for mount in mounts:
            assert mount["Type"] == "bind" and not mount["RW"]
            arguments += ["--mount", f"type=bind,src={mount['Source']},dst={mount['Destination']},readonly"]
        for setting in original["Config"]["Env"]:
            arguments += ["-e", setting]
        replica = native.docker("run", "-d", "--name", replica_name, "--memory", "768m", "--cpus", "2",
            "--network", context["network"], "-p", "127.0.0.1::8080",
            "--label", "marty.test=keycloak-passkeys", *arguments,
            "-e", "JAVA_OPTS_KC_HEAP=-Xms64m -Xmx384m", original["Image"],
            "start-dev", "--cache=ispn", "--cache-stack=jdbc-ping", "--hostname=" + base)
        replica_port = native.docker("port", replica, "8080/tcp").rsplit(":", 1)[-1]
        replica_base = "http://localhost:" + replica_port
        kms.wait_for_keycloak(replica_base, replica)
        deadline = time.monotonic() + 30
        while True:
            views = [native.docker("logs", name) for name in (primary, replica)]
            if all(re.search(r"ISPN000094:.*\(2\)", view) for view in views):
                break
            assert time.monotonic() < deadline, "Both disposable Keycloak nodes must observe the two-member cluster"
            time.sleep(1)
        fixture["replica_account"] = replica_base + "/realms/11id/account/credentials"

        # These exercise the installed canonical configurator/theme/provider,
        # native browser WebAuthn, signed email and shared database removal lock.
        print("Both disposable Keycloak nodes observed the two-member cluster; starting native lifecycle checks", flush=True)
        native.test_native_google_redirect_uses_supported_prompt_without_weakening_keycloak_login(fixture)
        print("Native supported Google redirect/default and explicit prompt preservation passed with passkeys on/off", flush=True)
        native.test_native_email_action_enrolls_a_verified_existing_account_without_password(fixture)
        print("Native email, console, cross-node removal and surviving login passed", flush=True)
        native.test_native_enrollment_and_delete_actions_cancel_without_mutating_credentials(fixture)
        print("Native registration/deletion confirmation and cancellation passed", flush=True)
        native.test_real_realm_reconciliation_preserves_providers_and_policy_on_rollback(fixture)
        for mode in ("conditional", "modal"):
            native.test_virtual_authenticator_enrollment_and_login_keep_the_same_subject(fixture, mode)
        for enabled in ("true", "false"):
            native.test_expired_login_action_restarts_with_usable_existing_login_options(fixture, enabled)
        print("Expired-tab recovery retained client/state/PKCE and existing login options with passkeys on/off", flush=True)
        native.test_native_assertion_rejects_tampering_replay_and_deleted_credentials(fixture)
        native.test_explicit_required_otp_remains_required_after_passkey_and_password_login(fixture)
        print("Explicit required OTP and wrong-code denial passed for passkey/password with feature on/off", flush=True)
        assert native.request(admin, token=admin_token)["webAuthnPolicyPasswordlessPasskeysEnabled"] is True
        # Model a human window outliving the parent probe's original sessions
        # without waiting thirty minutes or increasing any token lifetime.
        for realm_name, username in (("11id", "probe11"), ("master", "probe")):
            realm_admin = base + "/admin/realms/" + realm_name
            users = native.request(realm_admin + "/users?" + urllib.parse.urlencode({
                "username": username, "exact": "true"}), token=admin_token)
            assert len(users) == 1
            native.request(realm_admin + "/users/" + users[0]["id"] + "/logout",
                           token=admin_token, method="POST")
        print("Packaged PostgreSQL/KMS passkey enrollment, native console and cross-node removal/login checks passed", flush=True)
    finally:
        for name in (replica_name, smtp_name):
            container = native.docker("ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}")
            if container:
                owned = json.loads(native.docker("inspect", container))[0]
                assert owned["Name"] == "/" + name
                assert owned["Config"]["Labels"]["marty.test"] == "keycloak-passkeys"
                native.docker("rm", "-f", container)
                assert not native.docker("ps", "-a", "--filter", "id=" + container, "--format", "{{.ID}}")


def test_packaged_passkeys_keep_remote_custody_and_surviving_authentication_methods():
    kms.probe(KEYCLOAK_IMAGE, OPENBAO_IMAGE, Path("unused-bundled-provider"),
              require_browser=True, qualify_ready=qualify_passkeys)
