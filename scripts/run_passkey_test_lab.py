#!/usr/bin/env python3
"""User-invoked, loopback-only passkey workbench on the disposable KMS fixture."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from email.parser import BytesParser
import email.policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
import re
import secrets
import shutil
import sys
import threading
import time
import urllib.parse
import urllib.error
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from tests import test_keycloak_passkey_live as native  # noqa: E402
import probe_keycloak_remote_rs256 as kms  # noqa: E402


def encoded(value):
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode() if isinstance(value, dict) else value
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def badge_fixture(context):
    """Dedicated non-exportable lab issuer/holder keys, never OAuth signing keys."""
    def bao(*arguments):
        command = ('export BAO_ADDR=https://127.0.0.1:8200 '
                   'BAO_CACERT=/tmp/bao-tls/vault-ca.pem '
                   'BAO_TOKEN="$(cat /run/secrets/bao_root_token)"; exec bao "$@"')
        value = native.docker("exec", context["openbao_container"], "/bin/sh", "-c", command, "lab", *arguments)
        return json.loads(value)

    suffix = secrets.token_hex(6)
    identities = []
    for purpose in ("issuer", "holder"):
        key = f"passkey-lab-badge-{purpose}-{suffix}"
        bao("write", "-format=json", "transit/keys/" + key, "type=ed25519",
            "exportable=false", "allow_plaintext_backup=false")
        metadata = bao("read", "-format=json", "transit/keys/" + key)["data"]
        assert metadata["exportable"] is False and metadata["allow_plaintext_backup"] is False
        public = {"kty": "OKP", "crv": "Ed25519", "x": encoded(base64.b64decode(metadata["keys"]["1"]["public_key"]))}
        identities.append((key, "did:jwk:" + encoded(public), public))
    issuer_key, issuer, jwk = identities[0]
    holder = identities[1][1]
    now = int(time.time())
    identifier = "urn:uuid:" + str(uuid.uuid4())
    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
        "id": identifier, "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "issuer": {"id": issuer, "type": ["Profile"], "name": "Marty isolated passkey lab"},
        "validFrom": datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z"),
        "validUntil": datetime.fromtimestamp(now + 3600, timezone.utc).isoformat().replace("+00:00", "Z"),
        "name": "Passkey testing â€” synthetic Open Badge",
        "credentialSubject": {"id": holder, "type": ["AchievementSubject"],
            "identifier": [{"type": "IdentityObject", "hashed": False,
                "identityHash": "badge.lab@example.invalid", "identityType": "emailAddress"}],
            "achievement": {"id": "urn:uuid:" + str(uuid.uuid4()), "type": ["Achievement"],
                "name": "Isolated sign-in testing", "description": "Synthetic fixture with no production authority.",
                "criteria": {"narrative": "Created only for the disposable passkey test lab."}}},
        "credentialSchema": [{"id": "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json",
                              "type": "1EdTechJsonSchemaValidator2019"}],
    }
    payload = {**credential, "iss": issuer, "sub": holder, "nbf": now, "exp": now + 3600,
               "jti": identifier, "vc": credential}
    signing_input = encoded({"alg": "EdDSA", "typ": "JWT", "kid": issuer + "#0"}) + "." + encoded(payload)
    input_value = "input=" + base64.b64encode(signing_input.encode()).decode()
    signed = bao("write", "-format=json", "transit/sign/" + issuer_key, input_value, "key_version=1")["data"]["signature"]
    assert bao("write", "-format=json", "transit/verify/" + issuer_key,
               input_value, "signature=" + signed)["data"]["valid"] is True
    compact = signing_input + "." + encoded(base64.b64decode(signed.split(":", 2)[2]))
    public = {"issuer_did": issuer, "holder_did": holder, "verification_method": {
        "id": issuer + "#0", "controller": issuer, "type": "JsonWebKey2020", "publicKeyJwk": jwk},
        "test_only": True, "signature_verified_by_openbao": True,
        "note": "Install this issuer through the governed test trust-profile path; presented documents do not confer trust."}
    return credential, compact, public


class Lab:
    def __init__(self, output: Path, minutes: int):
        self.output, self.minutes = output, minutes
        self.stop = threading.Event()
        self.csrf = secrets.token_urlsafe(32)
        self.ready = False
        self.accounts = []
        self.urls = {}

    def page(self):
        if not self.ready:
            if self.stop.is_set():
                return "<h1>The passkey lab is closed</h1><p>Run the launcher again to prepare a fresh environment.</p>"
            return "<h1>Preparing the isolated passkey lab</h1><p>Reload when the terminal reports READY.</p>"
        rows = "".join(f"<tr><td>{html.escape(a['purpose'])}</td><td>{html.escape(a['email'])}</td><td><code>{html.escape(a.get('password', 'Use the local enrollment email'))}</code></td></tr>" for a in self.accounts)
        messages = []
        captured = native.docker("exec", self.smtp, "sh", "-c", "cat /tmp/messages.jsonl 2>/dev/null || true")
        for line in reversed(captured.splitlines()):
            mail = BytesParser(policy=email.policy.default).parsebytes(base64.b64decode(json.loads(line)))
            body = mail.get_body(preferencelist=("html", "plain")).get_content()
            for link in re.findall(r'https?://[^\s"<>]+', body):
                link = html.unescape(link)
                if link.startswith(self.keycloak + "/realms/11id/login-actions/"):
                    messages.append(f'<li>{html.escape(str(mail["To"]))}: <a href="{html.escape(link, quote=True)}">Open captured Keycloak email</a></li>')
        return f"""<!doctype html><meta charset=utf-8><title>Marty passkey test lab</title>
<style>body{{font:17px system-ui;max-width:1000px;margin:40px auto;padding:20px;line-height:1.55}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:10px;text-align:left}}button,a{{margin:8px}}code{{overflow-wrap:anywhere}}section{{margin:30px 0}}label{{display:block;margin:10px}}</style>
<h1>Marty passkey test lab</h1><p>Isolated synthetic accounts. This lab closes automatically after {self.minutes} minutes.</p>
<p><a href="{html.escape(self.urls['console'], quote=True)}">Open native account console</a> Â· <a href="/">Refresh inbox</a></p>
<table><tr><th>Case</th><th>Username / email</th><th>Test password</th></tr>{rows}</table>
<section><h2>Try a real passkey</h2><ol><li>Open the account console and use the password account.</li><li>Under Signing in, choose Set up Passkey, then REGISTER on the ElevenID registration page. Complete the browser prompt using Windows Hello or a USB security key.</li><li>Sign out, open a private browser window, then sign in with the passkey.</li><li>Rename it, add a second key, and test removal. Keep another passkey or a working password.</li></ol>
<p>For a password-free account, send a local enrollment email below, open the captured link, then use its passkey in a private window.</p>
<form method=post action=/email><input type=hidden name=csrf value="{self.csrf}"><button>Send password-free enrollment email</button></form>
<ul>{''.join(messages) or '<li>No captured mail yet.</li>'}</ul></section>
<section><h2>Broker and Google</h2><p>The Test broker option uses a separate native OIDC identity and the broker account above. It is a simulator; actual Google qualification remains open.</p>
<p>For real Google, create a nonproduction web OAuth client with this exact redirect URI: <code>{html.escape(self.keycloak)}/realms/11id/broker/google/endpoint</code>. Enter its client values only into this local form.</p>
<form method=post action=/google><input type=hidden name=csrf value="{self.csrf}"><label>Client ID <input name=client_id required autocomplete=off></label><label>Client secret <input type=password name=client_secret required autocomplete=off></label><button>Connect Google to this disposable realm</button></form></section>
<section><h2>Open Badge fixture</h2><p><a href=/openbadge.jwt>Signed VC-JWT</a> Â· <a href=/openbadge.json>Credential JSON</a> Â· <a href=/issuer-public.json>Public issuer and holder details</a></p>
<p>The issuer and holder have separate non-exportable lab keys. This prepares credential material; the actual Marty presentation-policy, wallet and credential-login journey still needs its governed connection. The password-free account above exercises its native Keycloak enrollment portion.</p></section>
<section><h2>Record the result</h2><p>Use RESULT-TEMPLATE.md in the lab output folder. Desktop localhost is a secure browser context. Phone-native and cross-device checks still need a suitable trusted HTTPS test origin and physical prompts.</p>
<form method=post action=/stop><input type=hidden name=csrf value="{self.csrf}"><button>Close and clean up this lab</button></form></section>"""

    def attach(self, context):
        self.keycloak = "http://localhost:" + str(urllib.parse.urlparse(context["base"]).port)
        admin = self.keycloak + "/admin/realms/11id"
        smtp_name = context["container"] + "-manual-smtp"
        original_master = None

        def token():
            return native.request(self.keycloak + "/realms/master/protocol/openid-connect/token", form={
                "grant_type": "password", "client_id": "admin-cli", "username": "probe",
                "password": "synthetic-probe-only"})["access_token"]

        try:
            self.smtp = native.docker("run", "-d", "--name", smtp_name, "--memory", "64m", "--read-only",
                "--network", context["network"], "--network-alias", "lab-smtp", "--label", "marty.test=passkey-manual-lab",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "python:3.12.10-slim-bookworm", "python", "-u", "-c", native.SMTP_CAPTURE)
            native.request(admin, token=token, method="PUT", body={"loginTheme": "11id", "emailTheme": "11id", "accountTheme": "11id",
                "registrationEmailAsUsername": True, "resetPasswordAllowed": True,
                "smtpServer": {"host": "lab-smtp", "port": "1025", "from": "lab@example.invalid",
                               "auth": "false", "ssl": "false", "starttls": "false"}})
            fixture = {"container": context["container"], "realm": "11id", "admin_username": "probe",
                       "env": {"KEYCLOAK_ADMIN_PASSWORD": "synthetic-probe-only"}}
            configured = native.configure(fixture, "true")
            if configured.returncode:
                raise RuntimeError("The canonical passkey configurator refused this lab image")
            for purpose, address, realm in (("Password + passkeys", "password.lab@example.invalid", "11id"),
                    ("Broker simulator", "broker.lab@example.invalid", "master"),
                    ("Password-free enrollment", "badge.lab@example.invalid", "11id")):
                account = {"purpose": purpose, "email": address}
                user = {"username": address, "email": address, "emailVerified": True, "enabled": True,
                        "firstName": "Lab", "lastName": "Tester"}
                if purpose != "Password-free enrollment":
                    account["password"] = "Lab-" + secrets.token_urlsafe(18)
                    user["credentials"] = [{"type": "password", "value": account["password"], "temporary": False}]
                native.request(self.keycloak + f"/admin/realms/{realm}/users", token=token, body=user)
                self.accounts.append(account)
            master_admin = self.keycloak + "/admin/realms/master"
            original_master = native.request(master_admin, token=token).get("attributes", {})
            native.request(master_admin, token=token, method="PUT", body={"attributes": {**original_master, "frontendUrl": self.keycloak}})
            native.request(master_admin + "/clients", token=token, body={"clientId": "passkey-lab-broker",
                "enabled": True, "publicClient": True, "standardFlowEnabled": True,
                "redirectUris": [self.keycloak + "/realms/11id/broker/lab-broker/endpoint"]})
            native.request(admin + "/clients", token=token, body={"clientId": "passkey-lab-ui", "enabled": True,
                "publicClient": True, "standardFlowEnabled": True, "redirectUris": [self.origin + "/return"]})
            native.request(admin + "/identity-provider/instances", token=token, body={"alias": "lab-broker",
                "displayName": "Test broker (simulated)", "providerId": "oidc", "enabled": True, "trustEmail": True,
                "config": {"clientId": "passkey-lab-broker", "clientAuthMethod": "none", "defaultScope": "openid email profile",
                    "authorizationUrl": self.keycloak + "/realms/master/protocol/openid-connect/auth",
                    "tokenUrl": "http://localhost:8080/realms/master/protocol/openid-connect/token",
                    "userInfoUrl": "http://localhost:8080/realms/master/protocol/openid-connect/userinfo",
                    "jwksUrl": "http://localhost:8080/realms/master/protocol/openid-connect/certs", "useJwksUrl": "true",
                    "validateSignature": "true", "issuer": self.keycloak + "/realms/master", "pkceEnabled": "true", "pkceMethod": "S256"}})
            subject_query = urllib.parse.urlencode({"email": "badge.lab@example.invalid", "exact": "true"})
            subject = native.request(admin + "/users?" + subject_query, token=token)[0]["id"]
            self.email_action = lambda: native.request(admin + "/users/" + subject + "/execute-actions-email?" +
                urllib.parse.urlencode({"client_id": "passkey-lab-ui", "redirect_uri": self.origin + "/return", "lifespan": 300}),
                token=token, method="PUT", body=["webauthn-register-passwordless"])
            def connect_google(values):
                provider = {"alias": "google", "providerId": "google", "enabled": True,
                    "config": {"clientId": values["client_id"][0], "clientSecret": values["client_secret"][0]}}
                resource = admin + "/identity-provider/instances"
                try:
                    native.request(resource + "/google", token=token)
                except urllib.error.HTTPError as error:
                    if error.code != 404:
                        raise
                    native.request(resource, token=token, body=provider)
                else:
                    native.request(resource + "/google", token=token, method="PUT", body=provider)
            self.google_action = connect_google
            self.urls["console"] = self.keycloak + "/realms/11id/account/account-security/signing-in"
            credential, compact, public = badge_fixture(context)
            for name, value in (("openbadge.json", credential), ("issuer-public.json", public), ("lab-accounts.json", self.accounts)):
                (self.output / name).write_text(json.dumps(value, indent=2), encoding="utf-8")
            (self.output / "openbadge.jwt").write_text(compact, encoding="ascii")
            (self.output / "READY.json").write_text(json.dumps({"url": self.origin, "keycloak": self.keycloak,
                "expires_at": int(time.time()) + self.minutes * 60, "test_only": True}, indent=2), encoding="utf-8")
            (self.output / "RESULT-TEMPLATE.md").write_text(
                "# Passkey lab results\n\nRecord date, OS/browser/device and each observed result.\n\n"
                "- Password login / recovery:\n- Windows Hello:\n- Hardware key:\n- Phone / cross-device:\n"
                "- Broker simulation / stable account:\n- Actual Google:\n- Password-free email enrollment:\n"
                "- Rename / second key / native removal confirmation:\n- Actual Marty Open Badge presentation:\n"
                "- Cancellation / errors:\n- Missing or blocked checks:\n", encoding="utf-8")
            self.ready = True
            print(f"PASSKEY LAB READY {self.origin}\nPrivate test files: {self.output}\nCloses after {self.minutes} minutes, or use Close lab.", flush=True)
            self.stop.wait(self.minutes * 60)
        finally:
            self.ready = False
            self.stop.set()
            if original_master is not None:
                native.request(self.keycloak + "/admin/realms/master", token=token, method="PUT", body={"attributes": original_master})
            existing = native.docker("ps", "-a", "--filter", "name=^/" + smtp_name + "$", "--format", "{{.ID}}")
            if existing:
                owned = json.loads(native.docker("inspect", existing))[0]
                assert owned["Config"]["Labels"]["marty.test"] == "passkey-manual-lab"
                native.docker("rm", "-f", existing)


def handler(lab):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, status, content, kind="text/html; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(content.encode())

        def do_GET(self):
            if self.headers.get_all("Host") != [urllib.parse.urlparse(lab.origin).netloc]:
                return self.send(400, "Use the lab's localhost address")
            name = self.path.split("?", 1)[0]
            if name == "/health":
                self.send(200, json.dumps({"ready": lab.ready, "closed": lab.stop.is_set()}), "application/json")
            elif name in ("/", "/return", "/badge"):
                self.send(200, lab.page())
            elif name in ("/openbadge.jwt", "/openbadge.json", "/issuer-public.json") and lab.ready:
                self.send(200, (lab.output / name[1:]).read_text(), "text/plain; charset=utf-8")
            else:
                self.send(404, "Not found")

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.send(400, "Invalid request length")
            if not 0 < length <= 16384:
                return self.send(403, "This action requires the current local lab page")
            # Consume the bounded body before closing a rejected connection;
            # unread POST bytes can turn a denial into a TCP reset on Windows.
            self.connection.settimeout(5)
            body = self.rfile.read(length)
            if (not lab.ready or self.headers.get_all("Origin") != [lab.origin]
                    or self.headers.get_all("Host") != [urllib.parse.urlparse(lab.origin).netloc]):
                return self.send(403, "This action requires the current local lab page")
            try:
                values = urllib.parse.parse_qs(body.decode())
            except UnicodeDecodeError:
                return self.send(400, "Invalid local form encoding")
            if not secrets.compare_digest(values.get("csrf", [""])[0], lab.csrf):
                return self.send(403, "Reload the local lab page")
            try:
                if self.path == "/email":
                    lab.email_action()
                elif self.path == "/google" and all(values.get(key, [""])[0] for key in ("client_id", "client_secret")):
                    lab.google_action(values)
                elif self.path == "/stop":
                    lab.stop.set()
                else:
                    return self.send(400, "Unknown lab action")
                self.send(200, '<p>Action completed. <a href="/">Return to the lab</a></p>')
            except Exception:
                self.send(503, "Lab action failed; no credential values are included in this response")
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-image", required=True)
    parser.add_argument("--openbao-image", required=True)
    parser.add_argument("--minutes", type=int, default=20, choices=range(1, 31))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    output = args.output_dir or Path.home() / ".codex/private" / ("passkey-final-lab-" + secrets.token_hex(4))
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    lab = Lab(output, args.minutes)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(lab))
    lab.origin = "http://localhost:" + str(server.server_port)
    theme = output / "theme"
    shutil.copytree(ROOT / "config/keycloak/themes/11id", theme)
    properties = theme / "login/theme.properties"
    properties.write_text(properties.read_text().replace("credentialLoginUrl=/v1/auth/credential-login",
        "credentialLoginUrl=" + lab.origin + "/badge"), encoding="utf-8")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        kms.probe(args.keycloak_image, args.openbao_image, Path("unused-bundled-provider"),
                  require_browser=True, qualify_ready=lab.attach, qualification_theme=theme)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
