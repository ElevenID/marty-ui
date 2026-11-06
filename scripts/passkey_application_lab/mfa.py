"""Native OTP assurance for an owned privileged application test account."""

import hashlib
import hmac
import json
import time

from config import OUT


class MfaMixin:
    def prepare_mfa(self, admin, token, subject):
        from tests import test_keycloak_passkey_live as native

        self.mfa_admin, self.mfa_token, self.mfa_subject = admin, token, subject
        realm = native.request(admin, token=token)
        assert realm["otpPolicyAlgorithm"] == "HmacSHA1"
        self.otp_period, self.otp_digits = (
            realm["otpPolicyPeriod"],
            realm["otpPolicyDigits"],
        )
        self.otp_counter, self.otp_secret = -1, None
        self.otp_denials, self.otp_challenges, self.passkey_then_otp = 0, 0, False
        client = native.request(admin + "/clients?clientId=marty-ui", token=token)[0]
        self.mfa_client = admin + "/clients/" + client["id"]
        self.mfa_bindings = client.get("authenticationFlowBindingOverrides", {})
        alias = "passkey-app-required-otp-" + self.suffix
        native.request(
            admin + "/authentication/flows/" + realm["browserFlow"] + "/copy",
            token=token,
            body={"newName": alias},
        )
        flow = next(
            item
            for item in native.request(admin + "/authentication/flows", token=token)
            if item["alias"] == alias
        )
        self.mfa_flow = flow["id"]
        executions_url = admin + "/authentication/flows/" + alias + "/executions"
        executions = native.request(executions_url, token=token)
        assert (
            sum(item.get("providerId") == "auth-otp-form" for item in executions) == 1
        )
        assert any(
            item.get("providerId") == "conditional-credential" for item in executions
        )
        for entry in executions:
            requirement = {
                "auth-otp-form": "REQUIRED",
                "conditional-credential": "DISABLED",
            }.get(entry.get("providerId"))
            if requirement:
                native.request(
                    executions_url,
                    token=token,
                    method="PUT",
                    body={"id": entry["id"], "requirement": requirement},
                )
        native.request(
            self.mfa_client,
            token=token,
            method="PUT",
            body={
                "authenticationFlowBindingOverrides": {
                    **self.mfa_bindings,
                    "browser": self.mfa_flow,
                }
            },
        )
        native.request(
            admin + "/users/" + subject,
            token=token,
            method="PUT",
            body={"requiredActions": ["CONFIGURE_TOTP"]},
        )
        self.note(
            "Owned application client requires OTP after passkey/password; unrelated native conditions retained"
        )

    def qualify_login(self, files):
        try:
            return super().qualify_login(files)
        finally:
            if getattr(self, "mfa_flow", None):
                from tests import test_keycloak_passkey_live as native

                native.request(
                    self.mfa_client,
                    token=self.mfa_token,
                    method="PUT",
                    body={
                        "authenticationFlowBindingOverrides": {
                            **self.mfa_bindings,
                            "browser": self.mfa_bindings.get("browser", ""),
                        }
                    },
                )
                assert (
                    native.request(self.mfa_client, token=self.mfa_token).get(
                        "authenticationFlowBindingOverrides", {}
                    )
                    == self.mfa_bindings
                )
                native.request(
                    self.mfa_admin + "/authentication/flows/" + self.mfa_flow,
                    token=self.mfa_token,
                    method="DELETE",
                )

    def otp_code(self, secret, counter):
        digest = hmac.new(
            secret.encode(), counter.to_bytes(8, "big"), hashlib.sha1
        ).digest()
        offset = digest[-1] & 15
        number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
        return str(number % 10**self.otp_digits).zfill(self.otp_digits)

    def fresh_otp(self):
        while int(time.time()) // self.otp_period <= self.otp_counter:
            time.sleep(0.2)
        self.otp_counter = int(time.time()) // self.otp_period
        return self.otp_code(self.otp_secret, self.otp_counter)

    def authentication_step(self, page, origin, phase):
        if not self.require_otp:
            return False
        if page.locator("#totpSecret").count():
            assert phase == "signin" and self.otp_secret is None
            assert (
                page.request.get(origin + "/v1/auth/me").json()["authenticated"]
                is False
            )
            self.otp_secret = page.locator("#totpSecret").input_value()
            self.sensitive.append(self.otp_secret)
            page.locator("#totp").fill(self.fresh_otp())
            page.locator("#userLabel").fill("Disposable administrator OTP")
            page.locator("#saveTOTPBtn").click()
            return True
        if not page.locator("#otp").is_visible():
            return False
        assert self.otp_secret is not None
        counter = int(time.time()) // self.otp_period
        valid = {
            self.otp_code(self.otp_secret, value)
            for value in range(max(0, counter - 2), counter + 3)
        }
        invalid = next(
            str(value).zfill(self.otp_digits)
            for value in range(10)
            if str(value).zfill(self.otp_digits) not in valid
        )
        page.locator("#otp").fill(invalid)
        page.locator("#kc-login").click()
        page.locator("#input-error-otp-code").wait_for(timeout=10000)
        me = page.request.get(origin + "/v1/auth/me").json()
        if phase == "signin":
            assert me["authenticated"] is False, (
                "Wrong OTP must not create a Marty session"
            )
            credentials = self.virtual_cdp.send(
                "WebAuthn.getCredentials", {"authenticatorId": self.virtual_device}
            )["credentials"]
            assert any(item["signCount"] > 0 for item in credentials)
            self.passkey_then_otp = True
        else:
            assert me["authenticated"] is True
            fields = [
                "user_id",
                "roles",
                "user_type",
                "organization_id",
                "organizations",
                "default_organization_id",
            ]
            assert {key: me["user"].get(key) for key in fields} == {
                key: self.application_baseline_user.get(key) for key in fields
            }
            from tests import test_keycloak_passkey_live as native

            stored = native.request(
                self.mfa_admin + "/users/" + self.mfa_subject + "/credentials",
                token=self.mfa_token,
            )
            assert not any(
                item["type"] == "webauthn-passwordless" for item in stored
            ), "Failed reauthentication must precede enrollment"
        self.otp_denials += 1
        page.locator("#otp").fill(self.fresh_otp())
        page.locator("#kc-login").click()
        self.otp_challenges += 1
        return True

    def verify_mfa(self, origin):
        from playwright.sync_api import sync_playwright

        assert (
            self.otp_secret
            and self.otp_challenges >= 2
            and self.otp_denials >= 2
            and self.passkey_then_otp
        )
        assert self.application_baseline_user["user_type"] == "administrator"
        with sync_playwright() as playwright:
            request = playwright.request.new_context(
                storage_state={
                    "cookies": self.application_session_cookies,
                    "origins": [],
                }
            )
            try:
                assert (
                    request.get(
                        origin
                        + "/v1/trust-profiles/60000000-0000-0000-0000-000000000001"
                    ).status
                    == 200
                )
            finally:
                request.dispose()
        (OUT / "application-mfa-result.json").write_text(
            json.dumps(
                {
                    "scope": "owned native policy, administrator, Chrome virtual passkey",
                    "native_otp_enrollment_before_application_login": True,
                    "wrong_otp_cannot_create_fresh_application_session": True,
                    "wrong_otp_precedes_passkey_enrollment": True,
                    "fresh_passkey_assertion_still_requires_otp": True,
                    "same_administrator_identity_and_authorization": True,
                    "governed_administrator_access_after_otp": True,
                    "physical_device_or_google": False,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.note(
            "Real administrator password/passkey plus required OTP and wrong-code/session denials PASSED"
        )
