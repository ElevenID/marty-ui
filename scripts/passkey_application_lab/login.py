"""Owned real-service password -> native passkey -> fresh application login probe.
Development localhost/virtual device only; no Google or physical-device claim.
"""

import importlib.util
import json
import pathlib
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request

from config import NGINX_IMAGE, UI_DIST

HERE = pathlib.Path(__file__).parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


base = load("application_bootstrap", "bootstrap.py")
services = load("application_services", "services.py")
native = base.native


class LoginLab(base.ApplicationLab):
    def run_binary(self, binary, env, files=None, arguments=()):
        super().run_binary(binary, env, files, arguments)
        if binary == "marty-verification-service" and list(arguments) == ["migrate"]:
            self.qualify_login(files)

    def start(
        self,
        name,
        image,
        env=None,
        mounts=(),
        aliases=(),
        entrypoint=None,
        args=(),
        tmpfs=(),
        memory="512m",
        publish=False,
    ):
        container = self.prefix + "-" + name
        cmd = [
            "run",
            "-d",
            "--pull=never",
            "--name",
            container,
            "--label",
            "marty.test=passkey-application",
            "--network",
            self.context["network"],
            "--memory",
            memory,
            "--cpus",
            "1",
            "--read-only",
            "--log-opt",
            "max-size=1m",
            "--log-opt",
            "max-file=1",
        ]
        for alias in aliases:
            cmd += ["--network-alias", alias]
        for source, target in mounts:
            cmd += ["--mount", f"type=bind,source={source},target={target},readonly"]
        for target in tmpfs:
            cmd += ["--tmpfs", target]
        for key, value in (env or {}).items():
            cmd += ["-e", key + "=" + str(value)]
        if publish:
            cmd += ["-p", "127.0.0.1::8080"]
        if entrypoint:
            cmd += ["--entrypoint", entrypoint]
        cmd += [image, *args]
        self.created.append(container)
        native.docker(*cmd)
        return container

    def wait_service(self, name):
        model = json.loads((base.OUT / "canonical-service-model.json").read_text())
        health = " ".join(model[name].get("healthcheck", {}).get("test", []))
        match = re.search(r"http://localhost:[0-9]+/[A-Za-z0-9/_-]+", health)
        if not match:
            raise RuntimeError("No canonical HTTP health probe for " + name)
        target = match.group()
        container = self.prefix + "-" + name
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            state = json.loads(native.docker("inspect", container))[0]["State"]
            if not state["Running"]:
                raise RuntimeError("Owned application " + name + " exited at startup")
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "curl",
                    "--max-time",
                    "3",
                    "-fsS",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=6,
            )
            if result.returncode == 0:
                return
            time.sleep(0.5)
        raise RuntimeError(
            "Owned application " + name + " did not pass its canonical health probe"
        )

    def runtime_tokens(self):
        folder = pathlib.Path(self.scratch.name)
        grant_names = {
            "grant-flow": "marty-sign-grant-flow-wallet-v1",
            "grant-issuance-credential": "marty-sign-grant-issuance-credential-v1",
            "grant-issuance-canvas": "marty-sign-grant-issuance-canvas-v1",
            "grant-issuance-readiness": "marty-sign-grant-issuance-readiness-v1",
            "grant-issuance-passport": "marty-sign-grant-issuance-passport-v1",
            "grant-gateway-service": "marty-sign-grant-gateway-service-v1",
            "grant-gateway-issuer": "marty-sign-grant-gateway-issuer-did-v1",
        }
        for key in grant_names.values():
            self.bao(
                "write",
                "-format=json",
                "transit/keys/" + key,
                "type=hmac",
                "key_size=256",
                "exportable=false",
                "allow_plaintext_backup=false",
            )
        policies = {}
        runtime = ""
        for prefix in ["cred-issuer-", "cred-dsc-", "lti-tool-", "oid4vp-verifier-"]:
            runtime += f'path "transit/keys/{prefix}*" {{ capabilities=["read","create","update"] }}\n'
            runtime += f'path "transit/sign/{prefix}*" {{ capabilities=["update"] }}\n'
        for operation in ["encrypt", "decrypt", "rewrap"]:
            runtime += f'path "transit/{operation}/flow-response-envelope-*" {{ capabilities=["update"] }}\n'
            runtime += f'path "transit/{operation}/notification-webhook-envelope-*" {{ capabilities=["update"] }}\n'
        runtime += (
            'path "transit/keys/flow-response-envelope-*" { capabilities=["read"] }\n'
        )
        self.bao(
            "write",
            "-format=json",
            "transit/keys/integration-secret-envelope-marty-aes256",
            "type=aes256-gcm96",
            "exportable=false",
            "allow_plaintext_backup=false",
        )
        runtime += 'path "transit/keys/integration-secret-envelope-marty-aes256" { capabilities=["read"] }\n'
        for operation in ["encrypt", "decrypt"]:
            runtime += f'path "transit/{operation}/integration-secret-envelope-marty-aes256" {{ capabilities=["update"] }}\n'
        policies["runtime"] = runtime
        policies["notification"] = (
            'path "transit/keys/notification-webhook-envelope-*" { capabilities=["read"] }\n'
            + "".join(
                f'path "transit/{op}/notification-webhook-envelope-*" {{ capabilities=["update"] }}\n'
                for op in ["encrypt", "decrypt"]
            )
        )
        policies["holder"] = (
            'path "transit/keys" { capabilities=["list"] }\npath "transit/keys/cred-holder-*" { capabilities=["read","create","update","delete"] }\npath "transit/sign/cred-holder-*" { capabilities=["update"] }\npath "didcomm/keys" { capabilities=["list"] }\n'
        )
        policies["grant-verify"] = ""
        for role, key in grant_names.items():
            policies[role] = (
                f'path "transit/keys/{key}" {{ capabilities=["read"] }}\npath "transit/hmac/{key}*" {{ capabilities=["update"] }}\n'
            )
            policies["grant-verify"] += (
                f'path "transit/keys/{key}" {{ capabilities=["read"] }}\npath "transit/verify/{key}*" {{ capabilities=["update"] }}\n'
            )
        tokens = {}
        for role, policy in policies.items():
            token = self.child_token("passkey-app-" + self.suffix + "-" + role, policy)
            path = folder / (role + ".token")
            path.write_text(token, encoding="ascii")
            tokens[role] = path
        return tokens

    def integration_tls(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        folder = pathlib.Path(self.scratch.name)
        mount = "passkey-app-pki-" + self.suffix
        key = "passkey-app-integration-tls-" + self.suffix
        self.bao("write", "-format=json", "sys/mounts/" + mount, "type=pki")
        root = self.bao(
            "write",
            "-format=json",
            mount + "/root/generate/internal",
            "common_name=Disposable Passkey Application CA",
            "ttl=1h",
            "key_type=ec",
            "key_bits=256",
        )["data"]["certificate"]
        self.bao(
            "write",
            "-format=json",
            mount + "/roles/signing-keys",
            "allowed_domains=signing-keys",
            "allow_bare_domains=true",
            "allow_subdomains=false",
            "max_ttl=30m",
            "key_type=ec",
            "key_bits=256",
            "use_csr_common_name=false",
            "use_csr_sans=false",
        )
        self.bao(
            "write",
            "-format=json",
            "transit/keys/" + key,
            "type=ecdsa-p256",
            "exportable=false",
            "allow_plaintext_backup=false",
        )
        metadata = self.bao("read", "-format=json", "transit/keys/" + key)["data"]
        assert (
            metadata["exportable"] is False
            and metadata["allow_plaintext_backup"] is False
        )
        csr = self.bao(
            "write", "-format=json", "transit/keys/" + key + "/csr", "version=1"
        )["data"]["csr"]
        request = x509.load_pem_x509_csr(csr.encode())
        assert request.is_signature_valid
        leaf = self.bao(
            "write",
            "-format=json",
            mount + "/sign/signing-keys",
            "csr=" + csr,
            "common_name=signing-keys",
            "alt_names=signing-keys",
            "ttl=20m",
        )["data"]["certificate"]
        certificate = x509.load_pem_x509_certificate(leaf.encode())
        certificate.verify_directly_issued_by(
            x509.load_pem_x509_certificate(root.encode())
        )
        assert certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) == request.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName) == ["signing-keys"]
        assert "PRIVATE KEY" not in leaf + root + csr
        ca = folder / "integration-ca.crt"
        ca.write_text(root, encoding="ascii")
        chain = folder / "integration-server.crt"
        chain.write_text(leaf + "\n" + root, encoding="ascii")
        policy = f'path "transit/keys/{key}" {{ capabilities=["read"] }}\npath "transit/sign/{key}" {{ capabilities=["update"] }}\npath "transit/sign/{key}/*" {{ capabilities=["update"] }}\n'
        token = self.child_token("passkey-app-integration-tls-" + self.suffix, policy)
        token_file = folder / "integration-tls.token"
        token_file.write_text(token, encoding="ascii")
        self.note(
            "Dedicated non-exportable remote TLS key, signed CSR and private test-CA certificate verified"
        )
        return {"ca": ca, "chain": chain, "token": token_file, "key": key}

    def setup_client(self, admin, token, origin):
        native.request(
            admin + "/clients",
            token=token,
            body={
                "clientId": "marty-ui",
                "enabled": True,
                "publicClient": True,
                "standardFlowEnabled": True,
                "redirectUris": [origin + "/v1/auth/callback"],
                "webOrigins": [origin],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "post.logout.redirect.uris": origin + "/*",
                },
                "defaultClientScopes": ["profile", "email", "roles"],
                "protocolMappers": [
                    {
                        "name": "application-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.client.audience": "marty-ui",
                            "access.token.claim": "true",
                            "id.token.claim": "true",
                        },
                    },
                    {
                        "name": "application-user-type",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-attribute-mapper",
                        "config": {
                            "user.attribute": "user_type",
                            "claim.name": "user_type",
                            "jsonType.label": "String",
                            "id.token.claim": "true",
                            "access.token.claim": "true",
                            "userinfo.token.claim": "true",
                        },
                    },
                ],
            },
        )
        native.request(
            admin + "/clients",
            token=token,
            body={
                "clientId": "marty-api",
                "enabled": True,
                "publicClient": False,
                "serviceAccountsEnabled": True,
                "secret": self.settings["MARTY_API_CLIENT_SECRET"],
            },
        )
        api = native.request(admin + "/clients?clientId=marty-api", token=token)[0][
            "id"
        ]
        svc = native.request(
            admin + "/clients/" + api + "/service-account-user", token=token
        )["id"]
        management = native.request(
            admin + "/clients?clientId=realm-management", token=token
        )[0]["id"]
        roles = [
            native.request(
                admin + "/clients/" + management + "/roles/" + role, token=token
            )
            for role in ["query-users", "view-users", "manage-users"]
        ]
        native.request(
            admin + "/users/" + svc + "/role-mappings/clients/" + management,
            token=token,
            body=roles,
        )
        email = "applicant.passkey@example.invalid"
        password = secrets.token_urlsafe(32)
        self.sensitive.append(password)
        native.request(
            admin + "/users",
            token=token,
            body={
                "username": email,
                "email": email,
                "emailVerified": True,
                "enabled": True,
                "firstName": "Passkey",
                "lastName": "Applicant",
                "attributes": {"user_type": ["applicant"]},
                "credentials": [
                    {"type": "password", "value": password, "temporary": False}
                ],
            },
        )
        subject = native.request(
            admin
            + "/users?"
            + urllib.parse.urlencode({"username": email, "exact": "true"}),
            token=token,
        )[0]["id"]
        return email, password, subject

    def qualify_login(self, files):
        ca = next(source for source, target in files if target == "/run/lab/ca.crt")
        tokens = self.runtime_tokens()
        scratch = pathlib.Path(self.scratch.name)
        tls = self.integration_tls()
        # Reuse cached public Nginx image by immutable ID, never another container's configuration.
        nginx_image = NGINX_IMAGE
        config = scratch / "nginx.conf"
        config.write_text(
            """events {}\nhttp { include /etc/nginx/mime.types; proxy_buffer_size 128k; proxy_buffers 4 256k; resolver 127.0.0.11 valid=5s; server { listen 8080; server_name localhost; root /usr/share/nginx/html;
 location /v1/ { set $target http://gateway:8000; proxy_pass $target$request_uri; proxy_set_header Host $http_host; }
 location /orgs/ { set $target http://gateway:8000; proxy_pass $target$request_uri; proxy_set_header Host $http_host; }
 location /oid4vp/ { set $target http://gateway:8000; proxy_pass $target$request_uri; proxy_set_header Host $http_host; }
 location /realms/ { set $target http://KEYCLOAK:8080; proxy_pass $target$request_uri; proxy_set_header Host $http_host; }
 location /resources/ { set $target http://KEYCLOAK:8080; proxy_pass $target$request_uri; proxy_set_header Host $http_host; }
 location = /console { try_files /console/index.html =404; }
 location ^~ /console/ { try_files $uri $uri/ /console/index.html; }
 location / { try_files $uri $uri/ /index.html; } } }\n""".replace(
                "KEYCLOAK", self.context["container"]
            ),
            encoding="utf-8",
        )
        front = self.start(
            "front",
            nginx_image,
            mounts=[
                (config, "/etc/nginx/nginx.conf"),
                (UI_DIST, "/usr/share/nginx/html"),
            ],
            entrypoint="nginx",
            args=["-g", "daemon off;"],
            tmpfs=[
                "/tmp:rw,size=16m",
                "/var/cache/nginx:rw,size=16m",
                "/var/run:rw,size=1m",
            ],
            memory="64m",
            publish=True,
        )
        port = native.docker("port", front, "8080/tcp").rsplit(":", 1)[1]
        origin = "http://localhost:" + port
        for route, filename in (
            ("/", "index.html"),
            ("/console/applicant/profile", "console/index.html"),
        ):
            expected = re.search(
                r'<script[^>]+type="module"[^>]+src="([^"]+)"',
                (UI_DIST / filename).read_text(encoding="utf-8"),
            )
            assert expected and expected[1].startswith("/assets/")
            with urllib.request.urlopen(origin + route, timeout=10) as response:
                actual = re.search(
                    r'<script[^>]+type="module"[^>]+src="([^"]+)"',
                    response.read().decode("utf-8"),
                )
                assert actual and actual[1] == expected[1], (
                    "Test front door selected the wrong UI entry"
                )
            with urllib.request.urlopen(origin + expected[1], timeout=10) as response:
                assert response.headers.get_content_type() in (
                    "application/javascript",
                    "text/javascript",
                ), (
                    "Test front door must serve JavaScript modules with their native MIME type"
                )
        admin = self.context["base"] + "/admin/realms/11id"

        def token():
            return native.request(
                self.context["base"] + "/realms/master/protocol/openid-connect/token",
                form={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "probe",
                    "password": "synthetic-probe-only",
                },
            )["access_token"]

        realm = native.request(admin, token=token)
        native.request(
            admin,
            token=token,
            method="PUT",
            body={
                "attributes": {**realm.get("attributes", {}), "frontendUrl": origin},
                "loginTheme": "11id",
            },
        )
        try:
            fixture = {
                "container": self.context["container"],
                "realm": "11id",
                "admin_username": "probe",
                "env": {"KEYCLOAK_ADMIN_PASSWORD": "synthetic-probe-only"},
            }
            assert native.configure(fixture, "true").returncode == 0
            email, password, subject = self.setup_client(admin, token, origin)
            names = [
                "event-stream",
                "signing-keys",
                "organization",
                "revocation-profile",
                "credential-template",
                "trust-profile",
                "deployment-profile",
                "presentation-policy",
                "device-registration",
                "compliance-profile",
                "verification",
                "notification",
                "issuance-native",
                "applicant",
                "flow",
                "auth",
                "gateway",
            ]
            for name in names:
                definition = services.definition(
                    name, origin, self.context["container"], ca, tokens
                )
                mounts = [(m["source"], m["target"]) for m in definition["volumes"]]
                if name == "signing-keys":
                    definition["environment"].update(
                        SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE="/run/lab/integration-server.crt",
                        SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_ADDR="https://openbao:8200",
                        SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_CA_CERT_FILE="/run/lab/ca.crt",
                        SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_TOKEN_FILE="/run/lab/integration-tls.token",
                        SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_NAME=tls["key"],
                        SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_VERSION="1",
                    )
                    mounts.extend(
                        [
                            (tls["chain"], "/run/lab/integration-server.crt"),
                            (tls["token"], "/run/lab/integration-tls.token"),
                        ]
                    )
                if name == "issuance-native":
                    definition["environment"].update(
                        INTEGRATION_SECRET_KMS_URL="https://signing-keys:8018/internal",
                        INTEGRATION_SECRET_KMS_CA_FILE="/run/lab/integration-ca.crt",
                    )
                    mounts.append((tls["ca"], "/run/lab/integration-ca.crt"))
                self.start(
                    name,
                    base.IMAGE,
                    env=definition["environment"],
                    mounts=mounts,
                    aliases=[name]
                    + (["issuance"] if name == "issuance-native" else []),
                    entrypoint="/app/services/entrypoint.sh",
                    tmpfs=definition["tmpfs"],
                )
                self.wait_service(name)
                self.note("Real application service healthy: " + name)
            self.note(
                "Started17 owned canonical application services; waiting for real readiness"
            )
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                try:
                    result = native.request(origin + "/v1/auth/me")
                    if result.get("authenticated") is False:
                        break
                except Exception:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError("Real application gateway/Auth did not become ready")
            self.browser_journey(origin, email, password, subject, admin, token)
        except Exception:
            for name in self.created:
                if not name.startswith(self.prefix):
                    continue
                result = subprocess.run(
                    ["docker", "logs", "--tail", "40", name],
                    capture_output=True,
                    text=True,
                )
                diagnostic = result.stdout + "\n" + result.stderr
                for value in [*self.sensitive, *self.settings.values()]:
                    if len(value) > 12:
                        diagnostic = diagnostic.replace(value, "<generated>")
                (base.OUT / (name + "-diagnostic.log")).write_text(
                    diagnostic, encoding="utf-8"
                )
            raise
        finally:
            native.request(
                admin,
                token=token,
                method="PUT",
                body={
                    "attributes": realm.get("attributes", {}),
                    "loginTheme": realm.get("loginTheme", "keycloak"),
                },
            )

    def browser_journey(self, origin, email, password, subject, admin, token):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome", headless=True)
            try:
                context = browser.new_context()
                page = context.new_page()
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
                )["authenticatorId"]
                target = origin + getattr(
                    self, "profile_path", "/console/applicant/profile"
                )
                page.goto(
                    origin
                    + "/v1/auth/login?"
                    + urllib.parse.urlencode({"redirect_uri": target})
                )
                page.locator("#username").fill(email)
                page.locator("#password").fill(password)
                page.locator("#kc-login").click()

                def finish():
                    deadline = time.monotonic() + 35
                    while time.monotonic() < deadline:
                        if page.url.startswith(target):
                            page.get_by_test_id("profile-passkey-enrollment").wait_for(
                                state="visible", timeout=30000
                            )
                            return
                        if page.locator("#kc-oauth-grant").is_visible():
                            page.locator("#kc-oauth-grant").locator(
                                "[name=accept]"
                            ).click()
                        time.sleep(0.2)
                    raise RuntimeError(
                        "Application callback did not reach the requested profile"
                    )

                finish()
                before = page.request.get(origin + "/v1/auth/me").json()
                assert before["authenticated"] is True
                assert before["user"]["email"] == email
                self.application_baseline_user = before["user"]
                for headers in ({}, {"Origin": "https://untrusted.example.invalid"}):
                    assert (
                        page.request.post(
                            origin + "/v1/auth/passkeys/enroll",
                            data={},
                            headers=headers,
                        ).status
                        == 403
                    )
                response = page.request.post(
                    origin + "/v1/auth/passkeys/enroll",
                    data={"redirect_uri": target},
                    headers={"Origin": origin},
                )
                assert response.status == 200
                self.note(
                    "Real application password login, authenticated enrollment start and Origin denials passed"
                )
                url = response.json()["authorization_url"]
                page.goto(url)
                deadline = time.monotonic() + 35
                while not page.locator("#registerWebAuthn").is_visible():
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "Native enrollment did not reach its registration action"
                        )
                    if page.locator("#kc-oauth-grant").is_visible():
                        page.locator("#kc-oauth-grant").locator("[name=accept]").click()
                    elif page.locator("#password").is_visible():
                        if page.locator("#username").is_visible():
                            page.locator("#username").fill(email)
                        page.locator("#password").fill(password)
                        page.locator("#kc-login").click()
                    elif page.locator("#username").is_visible():
                        page.locator("#username").fill(email)
                        page.locator("#kc-login").click()
                    else:
                        time.sleep(0.2)
                page.once(
                    "dialog",
                    lambda dialog: dialog.accept("Application virtual passkey"),
                )
                page.locator("#registerWebAuthn").click(timeout=30000)
                finish()
                after = page.request.get(origin + "/v1/auth/me").json()
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
                assert {k: after["user"].get(k) for k in fields} == {
                    k: before["user"].get(k) for k in fields
                }
                credentials = native.request(
                    admin + "/users/" + subject + "/credentials", token=token
                )
                assert (
                    sum(c["type"] == "webauthn-passwordless" for c in credentials) == 1
                )
                assert any(c["type"] == "password" for c in credentials)
                logout = page.request.post(
                    origin + "/v1/auth/logout",
                    headers={"Origin": origin},
                    max_redirects=0,
                )
                assert logout.status in (302, 303)
                context.clear_cookies()
                assert (
                    page.request.get(origin + "/v1/auth/me").json()["authenticated"]
                    is False
                )
                page.goto(
                    origin
                    + "/v1/auth/login?"
                    + urllib.parse.urlencode({"redirect_uri": target})
                )
                finish()
                fresh = page.request.get(origin + "/v1/auth/me").json()
                assert fresh["authenticated"] is True
                self.application_session_cookies = context.cookies()
                assert {k: fresh["user"].get(k) for k in fields} == {
                    k: before["user"].get(k) for k in fields
                }
                result = {
                    "scope": "real local development services, virtual device",
                    "credential_registered_for_original_native_subject": True,
                    "app_user_and_authorization_preserved": True,
                    "native_password_retained": True,
                    "cross_origin_enrollment_denied": True,
                    "fresh_passkey_application_login": True,
                    "google_or_badge_or_physical_device_proof": False,
                }
                (base.OUT / "application-passkey-result.json").write_text(
                    json.dumps(result, indent=2), encoding="utf-8"
                )
                self.note(
                    "Real Marty application password/enrollment/fresh-passkey login and authorization continuity PASSED"
                )
            except Exception as error:
                self.save_browser_failure(page, "application", error)
                raise
            finally:
                browser.close()

    def save_browser_failure(self, page, name, error, browser_errors=()):
        """Keep the original failure even if a navigation races the snapshot."""
        diagnostic = {
            "path": urllib.parse.urlparse(page.url).path,
            "failure": type(error).__name__ + ": " + str(error)[:1000],
            "browser_errors": list(browser_errors)[-30:],
        }
        try:
            page.screenshot(
                path=str(base.OUT / (name + "-browser-failure.png")), full_page=True
            )
            diagnostic.update(
                title=page.title(),
                headings=page.locator("h1,h2").all_text_contents(),
                buttons=page.locator("button,input[type=submit]").all_text_contents(),
            )
        except Exception as snapshot_error:
            diagnostic["snapshot_error"] = type(snapshot_error).__name__
        (base.OUT / (name + "-browser-failure.json")).write_text(
            json.dumps(diagnostic, indent=2), encoding="utf-8"
        )
