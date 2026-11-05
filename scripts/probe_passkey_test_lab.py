#!/usr/bin/env python3
"""Exercise a live disposable lab's seeded broker and password-free enrollment."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
import urllib.parse

from playwright.sync_api import sync_playwright

from run_passkey_test_lab import native


def probe(output):
    ready = json.loads((output / "READY.json").read_text())
    assert ready["test_only"] is True and ready["expires_at"] > time.time()
    for field in ("url", "keycloak"):
        parsed = urllib.parse.urlparse(ready[field])
        assert parsed.scheme == "http" and parsed.hostname == "localhost" and parsed.port
    assert native.request(ready["url"] + "/health")["ready"] is True
    accounts = json.loads((output / "lab-accounts.json").read_text())
    broker = next(account for account in accounts if account["purpose"] == "Broker simulator")
    assert broker["email"].endswith("@example.invalid")
    base = ready["keycloak"]
    issuer = base + "/realms/11id/protocol/openid-connect"
    admin = base + "/admin/realms/11id"

    def token():
        return native.request(base + "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli", "username": "probe",
            "password": "synthetic-probe-only"})["access_token"]

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            context = browser.new_context()
            page = context.new_page()
            page.goto(ready["url"])
            assert page.get_by_text("Marty passkey test lab", exact=True).count() == 1
            page.get_by_role("link", name="Open native account console").click()
            page.locator("#social-lab-broker").click(timeout=30000)
            page.locator("#username").fill(broker["email"])
            page.locator("#password").fill(broker["password"])
            page.locator("#kc-login").click()
            page.wait_for_url(base + "/realms/11id/account/account-security/signing-in**", timeout=30000)
            users = native.request(admin + "/users?" + urllib.parse.urlencode({"email": broker["email"], "exact": "true"}), token=token)
            assert len(users) == 1
            subject = users[0]["id"]
            credentials_url = admin + "/users/" + subject + "/credentials"
            assert native.request(credentials_url, token=token) == []
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            params = {"client_id": "passkey-lab-ui", "response_type": "code", "scope": "openid",
                "redirect_uri": ready["url"] + "/return", "state": secrets.token_urlsafe(24),
                "nonce": secrets.token_urlsafe(24), "code_challenge": challenge, "code_challenge_method": "S256",
                "kc_action": "webauthn-register-passwordless"}
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
            page.goto(issuer + "/auth?" + urllib.parse.urlencode(params))
            page.once("dialog", lambda dialog: dialog.accept("Lab broker smoke key"))
            page.locator("#registerWebAuthn").click(timeout=30000)
            page.wait_for_url(ready["url"] + "/return?**", timeout=30000)
            code = urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query)["code"][0]
            access = native.request(issuer + "/token", form={"grant_type": "authorization_code", "client_id": "passkey-lab-ui",
                "code": code, "code_verifier": verifier, "redirect_uri": ready["url"] + "/return"})["access_token"]
            assert native.request(issuer + "/userinfo", token=access)["sub"] == subject
            stored = native.request(credentials_url, token=token)
            assert len(stored) == 1 and stored[0]["type"] == "webauthn-passwordless"
            assert stored[0]["userLabel"] == "Lab broker smoke key"
            # This is our temporary virtual key, not a user's real device. Leave
            # the prepared broker account ready for the operator's own passkey.
            native.request(credentials_url + "/" + stored[0]["id"], token=token, method="DELETE")
            assert native.request(credentials_url, token=token) == []
            page.goto(ready["url"])
            page.get_by_role("button", name="Send password-free enrollment email").click()
            page.get_by_role("link", name="Return to the lab").click()
            assert page.get_by_role("link", name="Open captured Keycloak email").count() >= 1
            print("Lab page, seeded native broker, password-free passkey enrollment, account continuity and captured-mail UI passed")
        except Exception as error:
            raise RuntimeError("Lab browser check failed; current page text: " + page.locator("body").inner_text()[:1800]) from error
        finally:
            browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    probe(parser.parse_args().output.resolve())
