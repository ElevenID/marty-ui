"""Opt-in disposable Keycloak check; never reads existing deployment credentials."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import email.policy
from email.parser import BytesParser
import html
import json
import os
from pathlib import Path
import secrets
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("MARTY_PASSKEY_TEST_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="Set MARTY_PASSKEY_TEST_IMAGE to a qualified local Keycloak image")

# No relay and no external recipient: only records synthetic messages inside the
# owned fixture network. Nothing is published on the host or persisted in a volume.
SMTP_CAPTURE = r'''
import base64, json, socketserver
class SMTP(socketserver.StreamRequestHandler):
    def reply(self, value):
        self.wfile.write(value.encode("ascii") + b"\r\n")
        self.wfile.flush()
    def handle(self):
        self.reply("220 synthetic fixture")
        while True:
            line = self.rfile.readline(65537)
            if not line: return
            command = line.split(b" ", 1)[0].strip().upper()
            if command in (b"EHLO", b"HELO"):
                self.reply("250-synthetic fixture\r\n250 8BITMIME")
            elif command == b"DATA":
                self.reply("354 Send message")
                data = bytearray()
                while True:
                    line = self.rfile.readline(65537)
                    if line in (b".\r\n", b".\n", b""): break
                    data.extend(line[1:] if line.startswith(b"..") else line)
                    if len(data) > 1048576: return
                with open("/tmp/messages.jsonl", "a") as output:
                    output.write(json.dumps(base64.b64encode(data).decode("ascii")) + "\n")
                self.reply("250 Recorded locally")
            elif command == b"QUIT":
                self.reply("221 Bye")
                return
            else:
                self.reply("250 OK")
socketserver.TCPServer(("0.0.0.0", 1025), SMTP).serve_forever()
'''


def docker(*args, **kwargs):
    if "env" in kwargs:
        kwargs["env"] = {**os.environ, **kwargs["env"]}
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True,
                          timeout=60, **kwargs).stdout.strip()


def request(url, *, token=None, body=None, form=None, method=None):
    headers = {"Accept": "application/json"}
    if token:
        if callable(token):
            token = token()
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body).encode()
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(form).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method=method), timeout=10) as response:
        data = response.read()
        return json.loads(data) if data else None


@pytest.fixture(scope="module")
def keycloak():
    name = "marty-passkey-test-" + secrets.token_hex(5)
    password = secrets.token_urlsafe(32)
    # Keep the pytest fixture representation free of inherited host/CI secrets.
    env = {"KC_BOOTSTRAP_ADMIN_PASSWORD": password, "KEYCLOAK_ADMIN_PASSWORD": password}
    container = None
    smtp = None
    network = None
    provider_mount = []
    if os.environ.get("MARTY_PASSKEY_PROVIDER_JAR"):
        provider = Path(os.environ["MARTY_PASSKEY_PROVIDER_JAR"]).resolve(strict=True)
        assert provider.is_file() and provider.suffix == ".jar"
        provider_mount = ["--mount", f"type=bind,source={provider},target=/opt/keycloak/providers/marty-passkey-provider.jar,readonly"]
    try:
        network = docker("network", "create", "--label", "marty.test=keycloak-passkeys", name)
        smtp = docker("run", "-d", "--name", name + "-smtp", "--memory", "64m",
            "--network", network, "--network-alias", "smtp", "--read-only",
            "--label", "marty.test=keycloak-passkeys", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
            "python:3.12.10-slim-bookworm", "python", "-u", "-c", SMTP_CAPTURE)
        container = docker("run", "-d", "--name", name, "--memory", "768m", "--cpus", "2",
            "--network", network,
            "--label", "marty.test=keycloak-passkeys", "-p", "127.0.0.1::8080",
            *provider_mount,
            "--mount", f"type=bind,source={ROOT / 'config/keycloak/themes/11id'},target=/opt/keycloak/themes/11id,readonly",
            "--tmpfs", "/opt/keycloak/data:rw,nosuid,nodev,size=128m",
            "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=passkey-test-admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD",
            "-e", "JAVA_OPTS_KC_HEAP=-Xms64m -Xmx384m", IMAGE,
            "start-dev", "--http-port=8080", "--hostname-strict=false", env=env)
        port = docker("port", container, "8080/tcp").rsplit(":", 1)[1]
        base = "http://localhost:" + port
        deadline = time.monotonic() + 150
        while True:
            try:
                request(base + "/realms/master/.well-known/openid-configuration")
                break
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise AssertionError("Disposable Keycloak did not become ready") from None
                time.sleep(1)
        token = request(base + "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli", "username": "passkey-test-admin", "password": password})["access_token"]
        admin = base + "/admin/realms/passkey-test"
        request(base + "/admin/realms", token=token, body={"realm": "passkey-test", "enabled": True,
            "loginTheme": "11id", "emailTheme": "11id", "sslRequired": "none", "registrationAllowed": True,
            "resetPasswordAllowed": True, "registrationEmailAsUsername": True,
            "smtpServer": {"host": "smtp", "port": "1025", "from": "noreply@example.invalid",
                           "auth": "false", "ssl": "false", "starttls": "false"}})
        request(admin + "/clients", token=token, body={"clientId": "passkey-test-ui", "enabled": True,
            "publicClient": True, "standardFlowEnabled": True, "redirectUris": [base + "/callback"],
            "attributes": {"pkce.code.challenge.method": "S256"}})
        request(admin + "/identity-provider/instances", token=token, body={"alias": "google", "providerId": "google",
            "enabled": True, "config": {"clientId": "synthetic", "clientSecret": "synthetic"}})
        def admin_token():
            return request(base + "/realms/master/protocol/openid-connect/token", form={
                "grant_type": "password", "client_id": "admin-cli", "username": "passkey-test-admin", "password": password})["access_token"]

        yield {"name": name, "container": container, "smtp": smtp, "base": base, "realm": "passkey-test",
               "admin": admin, "token": admin_token, "env": env}
    finally:
        if container:
            docker("rm", "-f", container)
            assert not docker("ps", "-a", "--filter", "id=" + container, "--format", "{{.ID}}")
        if smtp:
            docker("rm", "-f", smtp)
            assert not docker("ps", "-a", "--filter", "id=" + smtp, "--format", "{{.ID}}")
        if network:
            docker("network", "rm", network)


def configure(fixture, enabled, rp="localhost"):
    script = (ROOT / "scripts/setup-keycloak.sh").read_text(encoding="utf-8").rsplit('main "$@"', 1)[0]
    result = subprocess.run(["docker", "exec", "-i", "-e", "KEYCLOAK_ADMIN_PASSWORD",
        "-e", "KEYCLOAK_ADMIN=" + fixture.get("admin_username", "passkey-test-admin"), "-e", "KC_URL=http://localhost:8080",
        "-e", "KEYCLOAK_REALM=" + fixture["realm"], "-e", "KEYCLOAK_PASSKEYS_ENABLED=" + enabled,
        "-e", "KEYCLOAK_PASSKEY_RP_ID=" + rp, fixture["container"], "bash"],
        input=(script + "authenticate_keycloak\nconfigure_passkey_login\n").encode("utf-8"),
        env={**os.environ, **fixture["env"]},
        capture_output=True, timeout=60)
    result.stdout = result.stdout.decode("utf-8")
    result.stderr = result.stderr.decode("utf-8")
    return result


def test_native_email_action_enrolls_a_verified_existing_account_without_password(keycloak):
    from playwright.sync_api import sync_playwright

    result = configure(keycloak, "true")
    assert result.returncode == 0, result.stderr
    email_address = "badge-only-user@example.invalid"
    request(keycloak["admin"] + "/users", token=keycloak["token"], body={
        "username": email_address, "email": email_address, "emailVerified": True,
        "enabled": True, "firstName": "Synthetic", "lastName": "Badge User"})
    query = "/users?" + urllib.parse.urlencode({"email": email_address, "exact": "true"})
    subject = request(keycloak["admin"] + query, token=keycloak["token"])[0]["id"]
    credentials_url = keycloak["admin"] + "/users/" + subject + "/credentials"
    assert request(credentials_url, token=keycloak["token"]) == []
    action_query = urllib.parse.urlencode({"client_id": "passkey-test-ui", "lifespan": 300,
                                          "redirect_uri": keycloak["base"] + "/callback"})
    request(keycloak["admin"] + "/users/" + subject + "/execute-actions-email?" + action_query,
            token=keycloak["token"], method="PUT", body=["webauthn-register-passwordless"])
    messages = docker("exec", keycloak["smtp"], "cat", "/tmp/messages.jsonl").splitlines()
    mail = BytesParser(policy=email.policy.default).parsebytes(base64.b64decode(json.loads(messages[-1])))
    assert email_address in mail["To"]
    body = mail.get_body(preferencelist=("html", "plain")).get_content()
    links = [html.unescape(value) for value in re.findall(r'https?://[^\s"<>]+', body)]
    action_link = next(value for value in links if "/login-actions/action-token?" in value)
    parsed = urllib.parse.urlparse(action_link)
    parameters = urllib.parse.parse_qs(parsed.query)
    prefix, signature = parameters["key"][0].rsplit(".", 1)
    parameters["key"] = [prefix + "." + ("A" if signature[0] != "A" else "B") + signature[1:]]
    invalid_link = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(parameters, doseq=True)))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            invalid = browser.new_context()
            page = invalid.new_page()
            page.goto(invalid_link)
            assert page.locator("#registerWebAuthn").count() == 0
            assert request(credentials_url, token=keycloak["token"]) == []
            invalid.close()
            context = browser.new_context()
            page = context.new_page()
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            device = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
            page.goto(action_link)
            assert page.locator("#password").count() == 0
            confirm = page.locator("a[href*='/login-actions/action-token']")
            if confirm.count():
                confirm.click()
            page.once("dialog", lambda dialog: dialog.accept("Synthetic badge account passkey"))
            page.locator("#registerWebAuthn").click(timeout=30000)
            page.wait_for_function("""base => location.pathname === '/callback' ||
                [...document.querySelectorAll('a')].some(link => link.href.startsWith(base + '/callback'))""",
                arg=keycloak["base"], timeout=30000)
            if urllib.parse.urlparse(page.url).path != "/callback":
                page.locator('a[href^="' + keycloak["base"] + '/callback"]').click()
            assert urllib.parse.urlparse(page.url).path == "/callback"
            stored = request(credentials_url, token=keycloak["token"])
            assert len(stored) == 1 and stored[0]["type"] == "webauthn-passwordless"
            assert request(keycloak["admin"] + query, token=keycloak["token"])[0]["id"] == subject
            qualify_native_lifecycle(keycloak, page, cdp, device, subject, credentials_url, action_query)
        finally:
            browser.close()


def qualify_native_lifecycle(keycloak, page, cdp, device, subject, credentials_url, action_query):
    """Exercise native account APIs, including the concurrent deletion race."""
    issuer = keycloak["base"] + f"/realms/{keycloak['realm']}/protocol/openid-connect"
    account = keycloak["base"] + f"/realms/{keycloak['realm']}/account/credentials"

    def account_token():
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        parameters = {"client_id": "passkey-test-ui", "response_type": "code", "scope": "openid",
                      "redirect_uri": keycloak["base"] + "/callback", "state": secrets.token_urlsafe(24),
                      "nonce": secrets.token_urlsafe(24), "code_challenge": challenge, "code_challenge_method": "S256"}
        page.goto(issuer + "/auth?" + urllib.parse.urlencode(parameters))
        page.wait_for_url(keycloak["base"] + "/callback?**", timeout=30000)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query)["code"][0]
        token = request(issuer + "/token", form={"grant_type": "authorization_code", "client_id": "passkey-test-ui",
            "code": code, "code_verifier": verifier, "redirect_uri": keycloak["base"] + "/callback"})["access_token"]
        assert request(issuer + "/userinfo", token=token)["sub"] == subject
        return token

    token = account_token()
    stored = request(credentials_url, token=keycloak["token"])
    credential_id = stored[0]["id"]
    metadata = request(account, token=token)
    assert next(item for item in metadata if item["type"] == "webauthn-passwordless")["removeable"] is False
    with pytest.raises(urllib.error.HTTPError) as refused:
        request(account + "/" + credential_id, token=token, method="DELETE")
    assert refused.value.code == 400
    assert len(request(credentials_url, token=keycloak["token"])) == 1
    request(account + "/" + credential_id + "/label", token=token, method="PUT", body="Travel key")
    assert request(credentials_url, token=keycloak["token"])[0]["userLabel"] == "Travel key"
    page.goto(keycloak["base"] + f"/realms/{keycloak['realm']}/account/account-security/signing-in")
    try:
        page.get_by_text("Travel key", exact=True).wait_for(timeout=30000)
    except Exception as error:
        raise AssertionError(page.locator("body").inner_text()) from error

    # Native registration on a second device, without adding a password.
    device_keys = cdp.send("WebAuthn.getCredentials", {"authenticatorId": device})["credentials"]
    request(keycloak["admin"] + "/users/" + subject + "/execute-actions-email?" + action_query,
            token=keycloak["token"], method="PUT", body=["webauthn-register-passwordless"])
    message = docker("exec", keycloak["smtp"], "cat", "/tmp/messages.jsonl").splitlines()[-1]
    mail = BytesParser(policy=email.policy.default).parsebytes(base64.b64decode(json.loads(message)))
    links = re.findall(r'https?://[^\s"<>]+', mail.get_body(preferencelist=("html", "plain")).get_content())
    link = next(html.unescape(value) for value in links if "/login-actions/action-token?" in value)
    cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": device})
    second_device = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
    page.goto(link)
    confirm = page.locator("a[href*='/login-actions/action-token']")
    if confirm.count():
        confirm.click()
    page.once("dialog", lambda dialog: dialog.accept("Second device"))
    page.locator("#registerWebAuthn").click(timeout=30000)
    page.wait_for_function("""base => location.pathname === '/callback' ||
        [...document.querySelectorAll('a')].some(link => link.href.startsWith(base + '/callback'))""",
        arg=keycloak["base"], timeout=30000)
    stored = request(credentials_url, token=keycloak["token"])
    assert len(stored) == 2 and all(item["type"] == "webauthn-passwordless" for item in stored)
    token = account_token()
    device_keys.extend(cdp.send("WebAuthn.getCredentials", {"authenticatorId": second_device})["credentials"])
    assert next(item for item in request(account, token=token) if item["type"] == "webauthn-passwordless")["removeable"] is True
    barrier = threading.Barrier(2)

    def remove(indexed):
        index, credential = indexed
        endpoint = keycloak.get("replica_account", account) if index else account
        barrier.wait(timeout=10)
        try:
            request(endpoint + "/" + credential["id"], token=token, method="DELETE")
            return 204
        except urllib.error.HTTPError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(remove, enumerate(stored)))
    assert sorted(results) == [204, 400], results
    remaining = request(credentials_url, token=keycloak["token"])
    assert len(remaining) == 1 and remaining[0]["type"] == "webauthn-passwordless"
    assert next(item for item in request(account, token=token) if item["type"] == "webauthn-passwordless")["removeable"] is False
    # Restore only the surviving key in a cookie-free browser context. A retained
    # database row alone does not establish that native login still works.
    surviving_id = json.loads(remaining[0]["credentialData"])["credentialId"]
    survivor = next(key for key in device_keys if key["credentialId"] == surviving_id)
    fresh = page.context.browser.new_context()
    try:
        page = fresh.new_page()
        fresh_cdp = fresh.new_cdp_session(page)
        fresh_cdp.send("WebAuthn.enable")
        fresh_device = fresh_cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        fresh_cdp.send("WebAuthn.addCredential", {"authenticatorId": fresh_device, "credential": survivor})
        account_token()
        after = fresh_cdp.send("WebAuthn.getCredentials", {"authenticatorId": fresh_device})["credentials"][0]
        assert after["signCount"] > survivor["signCount"]
        # The native AIA must enforce the same policy after confirmation, even
        # when its challenge was shown for a credential that cannot be removed.
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        parameters = {"client_id": "passkey-test-ui", "response_type": "code", "scope": "openid",
                      "redirect_uri": keycloak["base"] + "/callback", "state": secrets.token_urlsafe(24),
                      "nonce": secrets.token_urlsafe(24), "code_challenge": challenge, "code_challenge_method": "S256",
                      "kc_action": "delete_credential:" + remaining[0]["id"]}
        page.goto(issuer + "/auth?" + urllib.parse.urlencode(parameters))
        page.locator("#kc-accept").click(timeout=30000)
        page.get_by_text("Credential type cannot be removed", exact=False).wait_for(timeout=10000)
        assert [item["id"] for item in request(credentials_url, token=keycloak["token"])] == [remaining[0]["id"]]
    finally:
        fresh.close()


def test_native_enrollment_and_delete_actions_cancel_without_mutating_credentials(keycloak):
    from playwright.sync_api import sync_playwright

    assert configure(keycloak, "true").returncode == 0
    address = "native-actions@example.invalid"
    password = secrets.token_urlsafe(24)
    request(keycloak["admin"] + "/users", token=keycloak["token"], body={
        "username": address, "email": address, "emailVerified": True, "enabled": True,
        "firstName": "Synthetic", "lastName": "Actions",
        "credentials": [{"type": "password", "value": password, "temporary": False}]})
    query = urllib.parse.urlencode({"email": address, "exact": "true"})
    subject = request(keycloak["admin"] + "/users?" + query, token=keycloak["token"])[0]["id"]
    credentials_url = keycloak["admin"] + "/users/" + subject + "/credentials"
    issuer = keycloak["base"] + f"/realms/{keycloak['realm']}/protocol/openid-connect"

    def begin(page, action):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {"client_id": "passkey-test-ui", "response_type": "code", "scope": "openid",
                  "redirect_uri": keycloak["base"] + "/callback", "state": secrets.token_urlsafe(24),
                  "nonce": secrets.token_urlsafe(24), "code_challenge": challenge, "code_challenge_method": "S256",
                  "kc_action": action}
        page.goto(issuer + "/auth?" + urllib.parse.urlencode(params))
        return verifier

    def complete(page, verifier, status):
        page.wait_for_url(keycloak["base"] + "/callback?**", timeout=30000)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query)
        assert params["kc_action_status"] == [status]
        token = request(issuer + "/token", form={"grant_type": "authorization_code", "client_id": "passkey-test-ui",
            "code": params["code"][0], "code_verifier": verifier, "redirect_uri": keycloak["base"] + "/callback"})["access_token"]
        assert request(issuer + "/userinfo", token=token)["sub"] == subject

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            context = browser.new_context()
            page = context.new_page()
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
            verifier = begin(page, "webauthn-register-passwordless")
            page.locator("#username").fill(address)
            page.locator("#password").fill(password)
            page.locator("#kc-login").click()
            original = request(credentials_url, token=keycloak["token"])
            page.locator("#cancelWebAuthnAIA").click(timeout=30000)
            complete(page, verifier, "cancelled")
            assert request(credentials_url, token=keycloak["token"]) == original

            verifier = begin(page, "webauthn-register-passwordless")
            page.once("dialog", lambda dialog: dialog.accept("Actions key"))
            page.locator("#registerWebAuthn").click(timeout=30000)
            complete(page, verifier, "success")
            stored = request(credentials_url, token=keycloak["token"])
            credential_id = next(item["id"] for item in stored if item["type"] == "webauthn-passwordless")
            verifier = begin(page, "delete_credential:" + credential_id)
            page.locator("#kc-decline").click(timeout=30000)
            complete(page, verifier, "cancelled")
            assert request(credentials_url, token=keycloak["token"]) == stored

            verifier = begin(page, "delete_credential:" + credential_id)
            page.locator("#kc-accept").click(timeout=30000)
            complete(page, verifier, "success")
            assert request(credentials_url, token=keycloak["token"]) == original
        finally:
            browser.close()


def test_explicit_required_otp_remains_required_after_passkey_and_password_login(keycloak):
    from playwright.sync_api import sync_playwright

    assert configure(keycloak, "true").returncode == 0
    address = "strict-mfa@example.invalid"
    password = secrets.token_urlsafe(24)
    request(keycloak["admin"] + "/users", token=keycloak["token"], body={
        "username": address, "email": address, "emailVerified": True, "enabled": True,
        "firstName": "Synthetic", "lastName": "MFA", "requiredActions": ["CONFIGURE_TOTP"],
        "credentials": [{"type": "password", "value": password, "temporary": False}]})
    query = urllib.parse.urlencode({"email": address, "exact": "true"})
    subject = request(keycloak["admin"] + "/users?" + query, token=keycloak["token"])[0]["id"]
    credentials_url = keycloak["admin"] + "/users/" + subject + "/credentials"
    issuer = keycloak["base"] + f"/realms/{keycloak['realm']}/protocol/openid-connect"
    realm = request(keycloak["admin"], token=keycloak["token"])
    assert realm["otpPolicyAlgorithm"] == "HmacSHA1"
    period, digits = realm["otpPolicyPeriod"], realm["otpPolicyDigits"]
    last_counter = -1

    def code(secret, counter):
        digest = hmac.new(secret.encode(), counter.to_bytes(8, "big"), hashlib.sha1).digest()
        offset = digest[-1] & 15
        number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
        return str(number % 10 ** digits).zfill(digits)

    def fresh_code(secret):
        nonlocal last_counter
        while int(time.time()) // period <= last_counter:
            time.sleep(0.2)
        last_counter = int(time.time()) // period
        return code(secret, last_counter)

    def begin(page, action=None):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {"client_id": "passkey-test-ui", "response_type": "code", "scope": "openid",
            "redirect_uri": keycloak["base"] + "/callback", "state": secrets.token_urlsafe(24),
            "nonce": secrets.token_urlsafe(24), "code_challenge": challenge, "code_challenge_method": "S256"}
        if action:
            params["kc_action"] = action
        page.goto(issuer + "/auth?" + urllib.parse.urlencode(params))
        return verifier

    def complete(page, verifier):
        try:
            page.wait_for_url(keycloak["base"] + "/callback?**", timeout=30000)
        except Exception as error:
            raise AssertionError({"path": urllib.parse.urlparse(page.url).path,
                "fields": page.locator("input").evaluate_all("items => items.map(item => item.id)"),
                "alerts": page.locator("[role=alert], #kc-error-message .instruction").all_text_contents()}) from error
        params = urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query)
        token = request(issuer + "/token", form={"grant_type": "authorization_code", "client_id": "passkey-test-ui",
            "code": params["code"][0], "code_verifier": verifier, "redirect_uri": keycloak["base"] + "/callback"})["access_token"]
        assert request(issuer + "/userinfo", token=token)["sub"] == subject

    clients = request(keycloak["admin"] + "/clients?clientId=passkey-test-ui", token=keycloak["token"])
    assert len(clients) == 1
    client_url = keycloak["admin"] + "/clients/" + clients[0]["id"]
    original_bindings = clients[0].get("authenticationFlowBindingOverrides", {})
    flow_name = "strict-passkey-mfa"
    request(keycloak["admin"] + "/authentication/flows/browser/copy", token=keycloak["token"], body={"newName": flow_name})
    flows = request(keycloak["admin"] + "/authentication/flows", token=keycloak["token"])
    flow = next(item for item in flows if item["alias"] == flow_name)
    executions_url = keycloak["admin"] + "/authentication/flows/" + flow_name + "/executions"
    executions = request(executions_url, token=keycloak["token"])
    otp_entries = [item for item in executions if item.get("providerId") == "auth-otp-form"]
    assert len(otp_entries) == 1
    for entry in executions:
        requirement = None
        if entry.get("providerId") == "auth-otp-form":
            requirement = "REQUIRED"
        # Keycloak 26.8's documented always-2FA policy disables only the
        # passkey credential exception. Keep unrelated organization conditions
        # and the enrolled-user condition intact.
        elif entry.get("providerId") == "conditional-credential":
            requirement = "DISABLED"
        if requirement:
            request(executions_url, token=keycloak["token"], method="PUT", body={"id": entry["id"], "requirement": requirement})
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            context = browser.new_context()
            page = context.new_page()
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            device = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
            verifier = begin(page, "webauthn-register-passwordless")
            page.locator("#username").fill(address)
            page.locator("#password").fill(password)
            page.locator("#kc-login").click()
            secret = page.locator("#totpSecret").input_value(timeout=30000)
            page.locator("#totp").fill(fresh_code(secret))
            page.locator("#userLabel").fill("Synthetic required OTP")
            page.locator("#saveTOTPBtn").click()
            page.locator("#registerWebAuthn").wait_for(timeout=30000)
            page.wait_for_load_state("load")
            page.once("dialog", lambda dialog: dialog.accept("MFA passkey"))
            page.locator("#registerWebAuthn").click(timeout=30000)
            complete(page, verifier)
            stored_key = cdp.send("WebAuthn.getCredentials", {"authenticatorId": device})["credentials"][0]
            request(client_url, token=keycloak["token"], method="PUT", body={
                "authenticationFlowBindingOverrides": {**original_bindings, "browser": flow["id"]}})
            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": device})
            context.close()
            for primary in ("passkey", "password-enabled", "password-disabled"):
                if primary == "password-disabled":
                    assert configure(keycloak, "false").returncode == 0
                context = browser.new_context()
                page = context.new_page()
                if primary == "passkey":
                    cdp = context.new_cdp_session(page)
                    cdp.send("WebAuthn.enable")
                    device = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
                    cdp.send("WebAuthn.addCredential", {"authenticatorId": device, "credential": stored_key})
                verifier = begin(page)
                if primary != "passkey":
                    page.locator("#username").fill(address)
                    page.locator("#password").fill(password)
                    page.locator("#kc-login").click()
                page.locator("#otp").wait_for(timeout=30000)
                assert urllib.parse.urlparse(page.url).path != "/callback"
                if primary == "passkey":
                    after = cdp.send("WebAuthn.getCredentials", {"authenticatorId": device})["credentials"][0]
                    assert after["signCount"] > stored_key["signCount"]
                counter = int(time.time()) // period
                valid = {code(secret, value) for value in range(max(0, counter - 2), counter + 3)}
                invalid = next(str(value).zfill(digits) for value in range(10) if str(value).zfill(digits) not in valid)
                page.locator("#otp").fill(invalid)
                page.locator("#kc-login").click()
                page.locator("#input-error-otp-code").wait_for(timeout=10000)
                assert urllib.parse.urlparse(page.url).path != "/callback"
                page.locator("#otp").fill(fresh_code(secret))
                page.locator("#kc-login").click()
                complete(page, verifier)
                context.close()
            assert {item["type"] for item in request(credentials_url, token=keycloak["token"])} == {
                "password", "otp", "webauthn-passwordless"}
        finally:
            browser.close()
            request(client_url, token=keycloak["token"], method="PUT", body={
                "authenticationFlowBindingOverrides": {**original_bindings, "browser": original_bindings.get("browser", "")}})
            assert request(client_url, token=keycloak["token"]).get("authenticationFlowBindingOverrides", {}) == original_bindings
            assert configure(keycloak, "true").returncode == 0


def test_real_realm_reconciliation_preserves_providers_and_policy_on_rollback(keycloak):
    before = request(keycloak["admin"], token=keycloak["token"])
    version = request(keycloak["base"] + "/admin/serverinfo", token=keycloak["token"])["systemInfo"]["version"]
    assert version.startswith("26.8."), version
    for _ in range(2):
        result = configure(keycloak, "true")
        assert result.returncode == 0, result.stderr
    enabled = request(keycloak["admin"], token=keycloak["token"])
    assert enabled["webAuthnPolicyPasswordlessPasskeysEnabled"] is True
    assert enabled["webAuthnPolicyPasswordlessRpId"] == "localhost"
    assert enabled["webAuthnPolicyPasswordlessResidentKey"] == "required"
    assert enabled["webAuthnPolicyPasswordlessUserVerificationRequirement"] == "required"
    for key in ["browserFlow", "registrationFlow", "resetCredentialsFlow", "registrationAllowed", "resetPasswordAllowed", "loginTheme"]:
        assert enabled[key] == before[key]
    provider = request(keycloak["admin"] + "/identity-provider/instances/google", token=keycloak["token"])
    assert provider["enabled"] is True
    result = configure(keycloak, "true", "different.example.test")
    assert result.returncode != 0
    assert "RP ID differs" in result.stderr
    result = configure(keycloak, "false")
    assert result.returncode == 0, result.stderr
    disabled = request(keycloak["admin"], token=keycloak["token"])
    assert disabled["webAuthnPolicyPasswordlessPasskeysEnabled"] is False
    for key, value in enabled.items():
        if key.startswith("webAuthnPolicyPasswordless") and key != "webAuthnPolicyPasswordlessPasskeysEnabled":
            assert disabled[key] == value


@pytest.mark.parametrize("mode", ["conditional", "modal"])
def test_virtual_authenticator_enrollment_and_login_keep_the_same_subject(keycloak, mode):
    from playwright.sync_api import sync_playwright

    result = configure(keycloak, "true")
    assert result.returncode == 0, result.stderr
    password = secrets.token_urlsafe(24)
    username = "passkey-user-" + mode
    email = username + "@example.invalid"
    request(keycloak["admin"] + "/users", token=keycloak["token"], body={
        "username": username, "email": email, "emailVerified": True,
        "enabled": True, "firstName": "Synthetic", "lastName": "User",
        "credentials": [{"type": "password", "value": password, "temporary": False}]})
    user_query = "/users?" + urllib.parse.urlencode({"email": email, "exact": "true"})
    users = request(keycloak["admin"] + user_query, token=keycloak["token"])
    subject = users[0]["id"]
    issuer = keycloak["base"] + f"/realms/{keycloak['realm']}/protocol/openid-connect"

    def authorization(enroll=False):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {"client_id": "passkey-test-ui", "response_type": "code", "scope": "openid",
                  "redirect_uri": keycloak["base"] + "/callback", "state": secrets.token_urlsafe(24),
                  "nonce": secrets.token_urlsafe(24), "code_challenge": challenge, "code_challenge_method": "S256"}
        if enroll:
            params["kc_action"] = "webauthn-register-passwordless"
        return issuer + "/auth?" + urllib.parse.urlencode(params), verifier

    def assert_identity(page, verifier):
        page.wait_for_url(keycloak["base"] + "/callback?**", timeout=30000)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query)["code"][0]
        tokens = request(issuer + "/token", form={"grant_type": "authorization_code", "client_id": "passkey-test-ui",
            "code": code, "code_verifier": verifier, "redirect_uri": keycloak["base"] + "/callback"})
        assert request(issuer + "/userinfo", token=tokens["access_token"])["sub"] == subject
        return tokens["access_token"]

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            context = browser.new_context()
            page = context.new_page()
            page_errors = []
            page.on("pageerror", lambda error: page_errors.append(str(error)))
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
            url, verifier = authorization(enroll=True)
            page.goto(url)
            assert page.locator("#social-google").count() == 1
            assert page.locator("#credential-login").count() == 1
            page.locator("#username").fill(email)
            page.locator("#password").fill(password)
            page.locator("#kc-login").click()
            page.once("dialog", lambda dialog: dialog.accept("Synthetic passkey"))
            page.locator("#registerWebAuthn").click(timeout=30000)
            try:
                assert_identity(page, verifier)
            except Exception as error:
                raise AssertionError((page.locator("body").inner_text(), page_errors)) from error
            stored = request(keycloak["admin"] + "/users/" + subject + "/credentials", token=keycloak["token"])
            assert sum(item["type"] == "webauthn-passwordless" for item in stored) == 1
            assert any(item["type"] == "password" for item in stored)
            credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator})["credentials"]
            assert len(credentials) == 1 and credentials[0]["isResidentCredential"] is True
            # Virtual devices automatically fulfill conditional requests. For the
            # modal case, model an autofill request on which no user has selected
            # a credential. The explicit request still uses the real browser API
            # and virtual device; the separate conditional case is unmodified.
            # A completely new browser context rules out SSO/cookie state from
            # the enrollment callback. Transfer only the virtual device key.
            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
            context.close()
            context = browser.new_context()
            page = context.new_page()
            page.on("pageerror", lambda error: page_errors.append(str(error)))
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True,
                "automaticPresenceSimulation": True}})["authenticatorId"]
            cdp.send("WebAuthn.addCredential", {"authenticatorId": authenticator, "credential": credentials[0]})
            if mode == "modal":
                page.add_init_script("""(() => {
                  const originalGet = navigator.credentials.get.bind(navigator.credentials);
                  window.passkeyTestRequests = [];
                  navigator.credentials.get = (options) => {
                    window.passkeyTestRequests.push(options.mediation || 'modal');
                    if (options.mediation === 'conditional') {
                      return new Promise((resolve, reject) => {
                        options.signal.addEventListener('abort', () =>
                          reject(new DOMException('Autofill cancelled', 'AbortError')), {once: true});
                      });
                    }
                    return originalGet(options);
                  };
                })();""")
            url, verifier = authorization()
            page.goto(url)
            if mode == "modal":
                page.wait_for_function("window.passkeyTestRequests?.includes('conditional')")
                assert page.locator("#authenticateWebAuthnButton").count() == 1, (
                    page.locator("body").inner_text(), page_errors)
                page.locator("#authenticateWebAuthnButton").click(timeout=30000, no_wait_after=True)
            try:
                login_token = assert_identity(page, verifier)
            except Exception as error:
                raise AssertionError((page.locator("body").inner_text(), page_errors)) from error
            after = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator})["credentials"]
            assert after[0]["signCount"] > credentials[0]["signCount"]
            assert len(request(keycloak["admin"] + user_query, token=keycloak["token"])) == 1
            assert page_errors == []
            if mode == "modal":
                account = keycloak["base"] + f"/realms/{keycloak['realm']}/account/credentials"
                metadata = request(account, token=login_token)
                assert next(item for item in metadata if item["type"] == "webauthn-passwordless")["removeable"] is True
                credential_id = next(item["id"] for item in stored if item["type"] == "webauthn-passwordless")
                request(account + "/" + credential_id, token=login_token, method="DELETE")
                remaining = request(keycloak["admin"] + "/users/" + subject + "/credentials", token=keycloak["token"])
                assert [item["type"] for item in remaining] == ["password"]
                context.close()
                context = browser.new_context()
                page = context.new_page()
                url, verifier = authorization()
                page.goto(url)
                page.locator("#username").fill(email)
                page.locator("#password").fill(password)
                page.locator("#kc-login").click()
                assert_identity(page, verifier)
        finally:
            browser.close()
