"""Disposable native Badge issuance, presentation/login and same-account email/passkey journey."""

import base64
import importlib.util
import json
import pathlib
import urllib.parse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("passed_application", HERE / "login.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
spec2 = importlib.util.spec_from_file_location("workload_tls", HERE / "workloads.py")
workload = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(workload)


class BadgeLab(workload.WorkloadMixin, app.LoginLab):
    profile_path = "/console/applicant/profile"

    def setup_client(self, admin, token, origin):
        self.applicant_account = super().setup_client(admin, token, origin)
        import secrets

        email = self.settings["MARTY_ORG_ADMIN_EMAIL"]
        password = secrets.token_urlsafe(32)
        self.sensitive.append(password)
        app.native.request(
            admin + "/users",
            token=token,
            body={
                "username": email,
                "email": email,
                "emailVerified": True,
                "enabled": True,
                "firstName": "Passkey",
                "lastName": "Administrator",
                "attributes": {"user_type": ["admin"]},
                "credentials": [
                    {"type": "password", "value": password, "temporary": False}
                ],
            },
        )
        subject = app.native.request(
            admin
            + "/users?"
            + urllib.parse.urlencode({"username": email, "exact": "true"}),
            token=token,
        )[0]["id"]
        self.smtp = self.start(
            "mail",
            "python:3.12.10-slim-bookworm",
            aliases=["smtp"],
            entrypoint="python",
            args=["-u", "-c", app.native.SMTP_CAPTURE],
            tmpfs=["/tmp:rw,nosuid,nodev,size=16m"],
            memory="64m",
        )
        self.smtp_original = app.native.request(admin, token=token).get(
            "smtpServer", {}
        )
        app.native.request(
            admin,
            token=token,
            method="PUT",
            body={
                "emailTheme": "11id",
                "smtpServer": {
                    "host": "smtp",
                    "port": "1025",
                    "from": "noreply@example.invalid",
                    "auth": "false",
                    "ssl": "false",
                    "starttls": "false",
                },
            },
        )
        client = app.native.request(admin + "/clients?clientId=marty-ui", token=token)[
            0
        ]["id"]
        app.native.request(
            admin + "/clients/" + client,
            token=token,
            method="PUT",
            body={
                "redirectUris": [
                    origin + "/v1/auth/callback",
                    origin + "/console/applicant/profile",
                ]
            },
        )
        return email, password, subject

    def browser_journey(self, origin, email, password, subject, admin, token):
        super().browser_journey(origin, email, password, subject, admin, token)
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome", headless=True)
            try:
                context = browser.new_context()
                page = context.new_page()
                browser_errors = []
                page.on(
                    "pageerror", lambda error: browser_errors.append(str(error)[:1000])
                )
                page.on(
                    "console",
                    lambda message: (
                        browser_errors.append(message.text[:1000])
                        if message.type == "error"
                        else None
                    ),
                )
                context.add_cookies(self.application_session_cookies)
                assert self.application_baseline_user["user_type"] == "administrator"
                (app.base.OUT / "application-admin-authorization.json").write_text(
                    json.dumps(
                        {
                            k: self.application_baseline_user.get(k)
                            for k in [
                                "user_type",
                                "roles",
                                "organization_id",
                                "default_organization_id",
                            ]
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                profile = page.request.get(
                    origin + "/v1/trust-profiles/60000000-0000-0000-0000-000000000001"
                )
                (app.base.OUT / "badge-trust-owner-response.json").write_text(
                    json.dumps(
                        {"status": profile.status, "body": profile.json()}, indent=2
                    ),
                    encoding="utf-8",
                )
                assert profile.status == 200, (
                    "Native administrator could not read the governed trust profile"
                )
                relationships = page.request.get(
                    origin
                    + "/v1/trust-profiles/60000000-0000-0000-0000-000000000001/issuers"
                )
                (app.base.OUT / "badge-trust-relationships.json").write_text(
                    json.dumps(
                        {"status": relationships.status, "body": relationships.json()},
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                import time

                # Establish the existing applicant application identity with its real OIDC login.
                applicant_context = browser.new_context()
                applicant_page = applicant_context.new_page()
                target = origin + "/console/applicant/profile"
                applicant_page.goto(
                    origin
                    + "/v1/auth/login?"
                    + urllib.parse.urlencode({"redirect_uri": target})
                )
                applicant_page.locator("#username").fill(self.applicant_account[0])
                applicant_page.locator("#password").fill(self.applicant_account[1])
                applicant_page.locator("#kc-login").click()
                deadline = time.monotonic() + 35
                while not applicant_page.url.startswith(target):
                    if time.monotonic() > deadline:
                        raise RuntimeError(
                            "Applicant baseline callback did not complete"
                        )
                    if applicant_page.locator("#kc-oauth-grant").is_visible():
                        applicant_page.locator("#kc-oauth-grant").locator(
                            "[name=accept]"
                        ).click()
                    time.sleep(0.2)
                applicant_baseline = applicant_page.request.get(
                    origin + "/v1/auth/me"
                ).json()["user"]
                assert (
                    applicant_baseline["email"] == self.applicant_account[0]
                    and applicant_baseline["user_type"] == "applicant"
                )
                applicant_context.close()
                from datetime import datetime, timezone

                claims = {
                    "member_id": applicant_baseline["applicant_id"],
                    "email": self.applicant_account[0],
                    "organization_id": self.settings["MARTY_ORG_ID"],
                    "organization_name": "Disposable Marty Test",
                    "achievement_description": "Synthetic membership issued only in the disposable test stack",
                    "role": "applicant",
                    "achievement_name": "Isolated verified membership",
                    "issued_at": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
                offer = page.request.post(
                    origin + "/v1/issuance",
                    data={
                        "organization_id": self.settings["MARTY_ORG_ID"],
                        "issuer_did": self.settings["MARTY_ISSUER_DID"],
                        "credential_template_id": "50000000-0000-0000-0000-000000000040",
                        "claims": claims,
                    },
                )
                (app.base.OUT / "badge-native-offer.json").write_text(
                    json.dumps(
                        {"status": offer.status, "body": offer.json()}, indent=2
                    ),
                    encoding="utf-8",
                )
                self.note(
                    "Native governed trust/profile reads and issuance initiation statuses: "
                    + str([profile.status, relationships.status, offer.status])
                )
                assert offer.status == 200, (
                    "Native issuance did not produce a credential offer"
                )
                # A disposable wallet owns only its ephemeral proof key; issuer keys stay remote.
                import time

                wallet = p.request.new_context()
                offer_data = json.loads(
                    urllib.parse.parse_qs(
                        urllib.parse.urlparse(
                            offer.json()["credential_offer_uri"]
                        ).query
                    )["credential_offer"][0]
                )
                grant = offer_data["grants"][
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ]
                token_response = wallet.post(
                    origin + "/v1/issuance/token",
                    form={
                        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "pre-authorized_code": grant["pre-authorized_code"],
                    },
                )
                (app.base.OUT / "badge-wallet-token-status.json").write_text(
                    json.dumps(
                        {
                            "status": token_response.status,
                            "body": token_response.json()
                            if token_response.status >= 400
                            else {"keys": sorted(token_response.json())},
                        }
                    ),
                    encoding="utf-8",
                )
                assert token_response.status == 200, (
                    "Native wallet token exchange failed"
                )
                access = token_response.json()["access_token"]
                self.sensitive.append(access)
                nonce_response = wallet.post(origin + "/v1/issuance/nonce")
                assert nonce_response.status == 200
                nonce = nonce_response.json()["c_nonce"]
                key = ec.generate_private_key(ec.SECP256R1())
                numbers = key.public_key().public_numbers()
                b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
                encode = lambda value: b64(
                    json.dumps(value, separators=(",", ":")).encode()
                )
                jwk = {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": b64(numbers.x.to_bytes(32, "big")),
                    "y": b64(numbers.y.to_bytes(32, "big")),
                }
                proof_parts = [
                    encode({"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": jwk}),
                    encode(
                        {
                            "aud": offer_data["credential_issuer"],
                            "nonce": nonce,
                            "iat": int(time.time()),
                        }
                    ),
                ]
                r, sig_s = utils.decode_dss_signature(
                    key.sign(".".join(proof_parts).encode(), ec.ECDSA(hashes.SHA256()))
                )
                proof = ".".join(
                    [
                        *proof_parts,
                        b64(r.to_bytes(32, "big") + sig_s.to_bytes(32, "big")),
                    ]
                )
                credential_response = wallet.post(
                    origin + "/v1/issuance/credential",
                    headers={"Authorization": "Bearer " + access},
                    data={
                        "credential_configuration_id": offer_data[
                            "credential_configuration_ids"
                        ][0],
                        "proofs": {"jwt": [proof]},
                    },
                )
                (app.base.OUT / "badge-wallet-credential.json").write_text(
                    json.dumps(
                        {
                            "status": credential_response.status,
                            "body": credential_response.json(),
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                assert credential_response.status == 200, (
                    "Native wallet credential exchange failed"
                )
                self.note(
                    "Native wallet token, single-use nonce, real proof signature and credential issuance passed"
                )
                # Configure only this owned realm's governed trust through the real admin session.
                trust_url = (
                    origin + "/v1/trust-profiles/60000000-0000-0000-0000-000000000001"
                )
                current = profile.json()
                assert len(current["trust_sources"]) == 1
                source = current["trust_sources"][0]
                assert source["issuer_did"] == self.settings["MARTY_ISSUER_DID"]
                profile_patch = {
                    "supported_formats": list(
                        dict.fromkeys([*current["supported_formats"], "VC_JWT"])
                    ),
                    "trust_sources": [
                        {
                            "source_type": source["source_type"],
                            "issuer_did": source["issuer_did"],
                            "description": source["description"],
                            "organization_id": self.settings["MARTY_ORG_ID"],
                        }
                    ],
                }
                patch = page.request.patch(trust_url, data=profile_patch)
                (app.base.OUT / "badge-governed-trust-patch.json").write_text(
                    json.dumps(
                        {"status": patch.status, "body": patch.json()}, indent=2
                    ),
                    encoding="utf-8",
                )
                assert patch.status == 200, "Governed trust profile update failed"
                relation = relationships.json()[0]
                metadata = relation["metadata"]
                metadata["credential_template_ids"] = list(
                    dict.fromkeys(
                        [
                            *metadata["credential_template_ids"],
                            "50000000-0000-0000-0000-000000000040",
                        ]
                    )
                )
                patch = page.request.patch(
                    trust_url + "/issuers/" + relation["id"],
                    data={"metadata": metadata},
                )
                (app.base.OUT / "badge-governed-relationship-patch.json").write_text(
                    json.dumps(
                        {"status": patch.status, "body": patch.json()}, indent=2
                    ),
                    encoding="utf-8",
                )
                assert patch.status == 200, "Governed issuer relationship update failed"
                self.note(
                    "Administrator admitted the exact managed issuer, native Badge format and catalog template through governed APIs"
                )
                context.clear_cookies()
                response = page.goto(origin + "/v1/auth/credential-login")
                if response.status != 200:
                    (app.base.OUT / "badge-start-diagnostic.txt").write_text(
                        page.locator("body").inner_text()[:8000], encoding="utf-8"
                    )
                    raise RuntimeError(
                        "Real Badge login did not start; private rendered diagnostic retained"
                    )
                link = page.locator("#wallet-link").get_attribute("href")
                auth_nonce = page.locator("body").get_attribute("data-nonce")
                assert auth_nonce
                query = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
                uri = query.get("request_uri", [""])[0]
                assert uri.startswith(origin + "/v1/flows/instances/")
                request = page.request.get(uri)
                if request.status != 200:
                    (app.base.OUT / "badge-request-diagnostic.txt").write_text(
                        request.text()[:8000], encoding="utf-8"
                    )
                    raise RuntimeError(
                        "Real signed wallet request could not be fetched"
                    )
                compact = request.text().strip()
                parts = compact.split(".")
                assert len(parts) == 3
                header = json.loads(
                    base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
                )
                payload = json.loads(
                    base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
                )
                document = page.request.get(origin + "/orgs/marty/did.json")
                (app.base.OUT / "badge-public-did.json").write_text(
                    json.dumps(
                        {"status": document.status, "body": document.json()}, indent=2
                    ),
                    encoding="utf-8",
                )
                assert document.status == 200
                methods = document.json()["verificationMethod"]
                jwk = next(
                    m["publicKeyJwk"] for m in methods if m["id"] == header["kid"]
                )

                decode = lambda value: base64.urlsafe_b64decode(
                    value + "=" * (-len(value) % 4)
                )
                key = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(decode(jwk["x"]), "big"),
                    int.from_bytes(decode(jwk["y"]), "big"),
                    ec.SECP256R1(),
                ).public_key()
                signature = decode(parts[2])
                assert len(signature) == 64
                key.verify(
                    utils.encode_dss_signature(
                        int.from_bytes(signature[:32], "big"),
                        int.from_bytes(signature[32:], "big"),
                    ),
                    (".".join(parts[:2])).encode(),
                    ec.ECDSA(hashes.SHA256()),
                )
                self.note(
                    "Native signed Badge wallet request verified against its published DID method"
                )
                (app.base.OUT / "badge-wallet-request.json").write_text(
                    json.dumps({"header": header, "payload": payload}, indent=2),
                    encoding="utf-8",
                )
                self.note(
                    "Real Badge flow started and emitted signed wallet request: "
                    + json.dumps(
                        {
                            "alg": header.get("alg"),
                            "response_mode": payload.get("response_mode"),
                            "claims": sorted(payload),
                        }
                    )
                )
                issued = credential_response.json()["credentials"]
                assert len(issued) == 1 and isinstance(issued[0]["credential"], str)
                query_id = payload["dcql_query"]["credentials"][0]["id"]
                submit_uri = payload["response_uri"]
                assert submit_uri.startswith(origin + "/v1/flows/instances/")
                result = wallet.post(
                    submit_uri,
                    form={
                        "vp_token": json.dumps({query_id: [issued[0]["credential"]]}),
                        "state": payload["state"],
                    },
                )
                (app.base.OUT / "badge-native-presentation-result.json").write_text(
                    json.dumps(
                        {"status": result.status, "body": result.json()}, indent=2
                    ),
                    encoding="utf-8",
                )
                assert result.status == 200, "Native verified Badge presentation failed"
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    me = page.request.get(origin + "/v1/auth/me").json()
                    if me.get("authenticated"):
                        break
                    time.sleep(0.5)
                else:
                    raise RuntimeError(
                        "Native Badge callback did not establish a real application session"
                    )
                fields = [
                    "user_id",
                    "email",
                    "applicant_id",
                    "user_type",
                    "roles",
                    "organization_id",
                    "organizations",
                    "default_organization_id",
                ]
                (app.base.OUT / "badge-identity-comparison.json").write_text(
                    json.dumps(
                        {
                            "baseline": {k: applicant_baseline.get(k) for k in fields},
                            "badge": {k: me["user"].get(k) for k in fields},
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )

                # Existing Badge account lookup includes this native umbrella role, while
                # OIDC maps the application's business roles. No other difference is allowed.
                def same_authority(user):
                    assert {k: user.get(k) for k in fields if k != "roles"} == {
                        k: applicant_baseline.get(k) for k in fields if k != "roles"
                    }
                    assert set(user.get("roles", [])) - {"default-roles-11id"} == set(
                        applicant_baseline.get("roles", [])
                    )

                same_authority(me["user"])
                badge_user = me["user"]
                denied = page.request.patch(
                    trust_url,
                    data={"description": "Applicant authorization denial probe"},
                )
                assert denied.status == 403, (
                    "Badge applicant unexpectedly acquired trust administration"
                )
                assert (
                    len(
                        app.native.request(
                            admin
                            + "/users?"
                            + urllib.parse.urlencode(
                                {"username": self.applicant_account[0], "exact": "true"}
                            ),
                            token=token,
                        )
                    )
                    == 1
                )
                (app.base.OUT / "badge-application-login-result.json").write_text(
                    json.dumps(
                        {
                            "native_issuance": True,
                            "request_signature_verified": True,
                            "real_presentation_verification": True,
                            "native_callback_session": True,
                            "same_application_identity_and_effective_authorization": True,
                            "known_native_default_realm_role_marker_only": True,
                            "trust_administration_denied": True,
                            "physical_wallet_or_google": False,
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                self.note(
                    "Genuine native-issued Badge presentation, callback and same-account application login PASSED"
                )
                # A Badge session has no browser SSO. Native signed mail owns enrollment.
                assert not any(
                    cookie["name"].startswith("KEYCLOAK_SESSION")
                    for cookie in context.cookies()
                )
                before_credentials = app.native.request(
                    admin + "/users/" + self.applicant_account[2] + "/credentials",
                    token=token,
                )
                assert not any(
                    value["type"] == "webauthn-passwordless"
                    for value in before_credentials
                )
                cdp = context.new_cdp_session(page)
                cdp.send("WebAuthn.enable")
                cdp.send(
                    "WebAuthn.addVirtualAuthenticator",
                    {
                        "options": {
                            "protocol": "ctap2",
                            "transport": "internal",
                            "hasResidentKey": True,
                            "hasUserVerification": True,
                            "isUserVerified": True,
                            "automaticPresenceSimulation": True,
                        }
                    },
                )
                for headers in ({}, {"Origin": "https://untrusted.example.invalid"}):
                    assert (
                        page.request.post(
                            origin + "/v1/auth/passkeys/enroll",
                            data={},
                            headers=headers,
                        ).status
                        == 403
                    )
                page.goto(target)
                with page.expect_response(
                    lambda value: (
                        value.url == origin + "/v1/auth/passkeys/enroll"
                        and value.request.method == "POST"
                    )
                ) as sent:
                    page.get_by_role(
                        "button", name="Create a passkey", exact=True
                    ).click(timeout=30000)
                response = sent.value
                assert response.status == 200 and response.json() == {
                    "email_sent": True
                }
                page.get_by_role(
                    "button", name="Enrollment email sent", exact=True
                ).wait_for(state="visible")
                assert page.get_by_role(
                    "button", name="Enrollment email sent", exact=True
                ).is_disabled()

                import email.policy
                import html
                import re
                from email.parser import BytesParser

                messages = app.native.docker(
                    "exec", self.smtp, "cat", "/tmp/messages.jsonl"
                ).splitlines()
                assert len(messages) == 1
                mail = BytesParser(policy=email.policy.default).parsebytes(
                    base64.b64decode(json.loads(messages[0]))
                )
                assert self.applicant_account[0] in mail["To"]
                body = mail.get_body(preferencelist=("html", "plain")).get_content()
                links = [
                    html.unescape(value)
                    for value in re.findall(r'https?://[^\s"<>]+', body)
                ]
                action = next(
                    value for value in links if "/login-actions/action-token?" in value
                )
                assert (
                    urllib.parse.urlparse(action).netloc
                    == urllib.parse.urlparse(origin).netloc
                )
                page.goto(action)
                confirm = page.locator("a[href*='/login-actions/action-token']")
                if confirm.is_visible():
                    confirm.click()
                page.locator("#registerWebAuthn").wait_for(timeout=30000)
                page.once(
                    "dialog",
                    lambda dialog: dialog.accept("Badge account virtual passkey"),
                )
                page.locator("#registerWebAuthn").click()
                page.wait_for_function(
                    "target=>location.href.startsWith(target)||[...document.querySelectorAll('a')].some(link=>link.href.startsWith(target))",
                    arg=target,
                    timeout=30000,
                )
                if not page.url.startswith(target):
                    page.locator('a[href^="' + target + '"]').click()
                same = page.request.get(origin + "/v1/auth/me").json()
                assert same["authenticated"] and {
                    k: same["user"].get(k) for k in fields
                } == {k: badge_user.get(k) for k in fields}
                stored = app.native.request(
                    admin + "/users/" + self.applicant_account[2] + "/credentials",
                    token=token,
                )
                assert (
                    sum(value["type"] == "webauthn-passwordless" for value in stored)
                    == 1
                )
                assert any(value["type"] == "password" for value in stored)
                assert page.request.post(
                    origin + "/v1/auth/logout",
                    headers={"Origin": origin},
                    max_redirects=0,
                ).status in (302, 303)
                context.clear_cookies()
                page.goto(
                    origin
                    + "/v1/auth/login?"
                    + urllib.parse.urlencode({"redirect_uri": target})
                )
                deadline = time.monotonic() + 35
                while not page.url.startswith(target):
                    if time.monotonic() > deadline:
                        raise RuntimeError(
                            "Badge-enrolled fresh passkey callback did not finish"
                        )
                    if page.locator("#kc-oauth-grant").is_visible():
                        page.locator("#kc-oauth-grant").locator("[name=accept]").click()
                    time.sleep(0.2)
                fresh = page.request.get(origin + "/v1/auth/me").json()
                assert fresh["authenticated"]
                same_authority(fresh["user"])
                assert (
                    page.request.patch(
                        trust_url,
                        data={"description": "Applicant authorization denial probe"},
                    ).status
                    == 403
                )
                (app.base.OUT / "badge-passkey-enrollment-result.json").write_text(
                    json.dumps(
                        {
                            "genuine_badge_login": True,
                            "no_preexisting_keycloak_sso": True,
                            "same_origin_enrollment_email_only": True,
                            "native_action_for_original_subject": True,
                            "badge_session_unchanged": True,
                            "fresh_passkey_same_application_identity_and_effective_authorization": True,
                            "trust_administration_denied_for_badge_and_passkey": True,
                            "password_retained": True,
                            "physical_device_or_google": False,
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                self.note(
                    "Real Badge session native email enrollment and fresh same-account passkey application login PASSED"
                )
                assert page.request.post(
                    origin + "/v1/auth/logout",
                    headers={"Origin": origin},
                    max_redirects=0,
                ).status in (302, 303)
                context.clear_cookies()
                self.verify_badge_rejections(
                    browser, origin, issued[0]["credential"], payload, auth_nonce
                )
            except Exception as error:
                self.save_browser_failure(page, "badge", error, browser_errors)
                raise
            finally:
                app.native.request(
                    admin,
                    token=token,
                    method="PUT",
                    body={"smtpServer": self.smtp_original},
                )
                browser.close()

    def verify_badge_rejections(
        self, browser, origin, credential, completed_request, completed_nonce
    ):
        """Exercise real admission/callback/session boundaries with owned data."""
        import uuid

        results = {}
        fresh = browser.new_context()
        try:
            assert (
                fresh.request.get(origin + "/v1/auth/me").json()["authenticated"]
                is False
            )
            query_id = completed_request["dcql_query"]["credentials"][0]["id"]
            replay = fresh.request.post(
                completed_request["response_uri"],
                form={
                    "vp_token": json.dumps({query_id: [credential]}),
                    "state": completed_request["state"],
                },
            )
            (app.base.OUT / "badge-replay-response.json").write_text(
                json.dumps({"status": replay.status, "body": replay.text()}),
                encoding="utf-8",
            )
            assert replay.status == 400, (
                "Consumed direct-post transaction must reject replay"
            )
            final = fresh.request.get(
                origin
                + "/v1/auth/credential-login/finalize?"
                + urllib.parse.urlencode({"nonce": completed_nonce}),
                max_redirects=0,
            )
            assert final.status in (302, 303) and "auth_error=" in final.headers.get(
                "location", ""
            )
            assert (
                fresh.request.get(origin + "/v1/auth/me").json()["authenticated"]
                is False
            )
            results["consumed_replay"] = {
                "submission_status": replay.status,
                "finalize_cannot_restore_session": True,
            }
        finally:
            fresh.close()

        for case in ("invalid_signature", "wrong_state", "expired_transaction"):
            context = browser.new_context()
            page = context.new_page()
            try:
                assert page.goto(origin + "/v1/auth/credential-login").status == 200
                nonce = page.locator("body").get_attribute("data-nonce")
                link = page.locator("#wallet-link").get_attribute("href")
                uri = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)[
                    "request_uri"
                ][0]
                assert uri.startswith(origin + "/v1/flows/instances/")
                request = page.request.get(uri)
                assert request.status == 200
                pieces = request.text().strip().split(".")
                assert len(pieces) == 3
                payload = json.loads(
                    base64.urlsafe_b64decode(pieces[1] + "=" * (-len(pieces[1]) % 4))
                )
                query_id = payload["dcql_query"]["credentials"][0]["id"]
                submit_uri = payload["response_uri"]
                assert submit_uri.startswith(origin + "/v1/flows/instances/")
                selected, state = credential, payload["state"]
                if case == "invalid_signature":
                    parts = credential.split(".")
                    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
                    selected = ".".join(parts)
                elif case == "wrong_state":
                    state = "untrusted-disposable-state"
                else:
                    # Arrange an expired persisted instance, not a fake verifier
                    # result or a claim of waiting for the signed JWT to expire.
                    instance = str(
                        uuid.UUID(urllib.parse.urlparse(submit_uri).path.split("/")[-2])
                    )
                    organization = str(uuid.UUID(self.settings["MARTY_ORG_ID"]))
                    pg = self.context["container"].replace("-oidc-", "-pg-")
                    inspected = json.loads(app.native.docker("inspect", pg))[0]
                    assert (
                        inspected["Config"]["Labels"]["marty.test"]
                        == "keycloak-passkeys"
                    )
                    assert (
                        self.context["network"]
                        in inspected["NetworkSettings"]["Networks"]
                    )
                    sql = f"WITH changed AS (UPDATE flow_service.flow_instances SET expires_at=NOW()-INTERVAL '1 second' WHERE id='{instance}' AND organization_id='{organization}' RETURNING id) SELECT count(*) FROM changed;"
                    assert (
                        app.native.docker(
                            "exec",
                            pg,
                            "psql",
                            "-At",
                            "-v",
                            "ON_ERROR_STOP=1",
                            "-U",
                            "keycloak",
                            "-d",
                            "marty",
                            "-c",
                            sql,
                        ).strip()
                        == "1"
                    )
                response = context.request.post(
                    submit_uri,
                    form={
                        "vp_token": json.dumps({query_id: [selected]}),
                        "state": state,
                    },
                )
                expected = 410 if case == "expired_transaction" else 400
                (app.base.OUT / ("badge-negative-" + case + ".json")).write_text(
                    json.dumps(
                        {"status": response.status, "body": response.json()}, indent=2
                    ),
                    encoding="utf-8",
                )
                assert response.status == expected, (
                    "Native Badge rejection failed: " + case
                )
                assert (
                    context.request.get(origin + "/v1/auth/me").json()["authenticated"]
                    is False
                )
                final = context.request.get(
                    origin
                    + "/v1/auth/credential-login/finalize?"
                    + urllib.parse.urlencode({"nonce": nonce}),
                    max_redirects=0,
                )
                assert final.status in (
                    302,
                    303,
                ) and "auth_error=" in final.headers.get("location", "")
                assert (
                    context.request.get(origin + "/v1/auth/me").json()["authenticated"]
                    is False
                )
                results[case] = {
                    "submission_status": response.status,
                    "finalize_cannot_create_session": True,
                }
            finally:
                context.close()
        (app.base.OUT / "badge-rejection-result.json").write_text(
            json.dumps(
                {
                    "scope": "real native submission, callback and Marty session admission",
                    "expiry_fixture": "owned persisted transaction deadline; signed credential/request lifetime is not altered",
                    "cases": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.note(
            "Native Badge signature/state/expired-transaction/replay denials and no-session finalization PASSED"
        )
