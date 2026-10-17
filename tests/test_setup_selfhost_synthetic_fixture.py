"""Synthetic fixture refuses unrelated identities and unbound transit keys."""

import asyncio
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ssl
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from setup_selfhost_synthetic_fixture import (  # noqa: E402
    audit_client,
    custody_signer_public,
    keycloak_user,
    managed_key_binding,
    managed_reference,
    profile_proof,
    required_environment,
    validate_audit_token,
    validate_custody_signer_token,
    validate_installed_model,
    validate_profile_projection,
    validate_transit_binding,
    write_signed_evidence,
    trusted_audit_context,
)


@pytest.mark.parametrize("existing_without_name", [False, True])
def test_synthetic_keycloak_operator_satisfies_required_profile(
    existing_without_name: bool,
) -> None:
    seen: list[str] = []
    user = {"id": "synthetic-id", "firstName": "Self-host", "lastName": "Operator"}

    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append(f"{request.method} {path}")
        if path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "synthetic-admin-token"})
        if path.endswith("/users") and request.method == "GET":
            if existing_without_name:
                return httpx.Response(200, json=[{"id": "synthetic-id"}])
            return httpx.Response(200, json=[user] if "POST /admin/realms/11id/users" in seen else [])
        if path.endswith("/users") and request.method == "POST":
            body = json.loads(request.content)
            assert (body["firstName"], body["lastName"]) == ("Self-host", "Operator")
            return httpx.Response(201)
        if path.endswith("/users/synthetic-id") and request.method == "PUT":
            assert json.loads(request.content) == {"firstName": "Self-host", "lastName": "Operator"}
            return httpx.Response(204)
        if path.endswith("/reset-password"):
            return httpx.Response(204)
        if path.endswith("/roles/administrator"):
            return httpx.Response(200, json={"name": "administrator"})
        if path.endswith("/role-mappings/realm"):
            return httpx.Response(204)
        pytest.fail(f"unexpected Keycloak request: {request.method} {path}")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond),
                                     base_url="http://127.0.0.1:38180") as client:
            await keycloak_user(client, {"SELFHOST_TEST_USERNAME": "operator@selfhost.marty.invalid",
                                         "SELFHOST_TEST_PASSWORD": "synthetic-password"},
                                "synthetic-admin-password")

    asyncio.run(run())
    update = "PUT /admin/realms/11id/users/synthetic-id"
    assert (update in seen) == existing_without_name


def fixture_env() -> dict[str, str]:
    names = (
        "SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL", "SELFHOST_PUBLIC_DOMAIN",
        "SELFHOST_TEST_USERNAME", "SELFHOST_TEST_PASSWORD", "SELFHOST_ORG_ID",
        "SELFHOST_ISSUER_DID", "SELFHOST_VERIFIER_DID",
        "SELFHOST_SECRET_ROOT", "SELFHOST_COMPOSE_MODEL_PATH",
        "SELFHOST_BAO_AUDIT_URL", "SELFHOST_BAO_AUDIT_TOKEN_FILE",
        "SELFHOST_KMS_JWK_TOOL",
        "SELFHOST_CUSTODY_SIGNING_TOKEN_FILE", "SELFHOST_SOURCE_SHA",
        "SELFHOST_ARCHIVE_SHA256", "SELFHOST_IMAGE_LOCK_SHA256",
        "SELFHOST_RUN_ID", "SELFHOST_FIXTURE_SHA256", "SELFHOST_CUSTODY_CHALLENGE",
        "SELFHOST_KMS_CUSTODY_EVIDENCE_PATH", "SELFHOST_KMS_CUSTODY_SIGNATURE_PATH",
        "SELFHOST_KMS_CUSTODY_PUBLIC_KEY_PATH",
    )
    values = {name: "fixture" for name in names}
    values.update(SELFHOST_PUBLIC_DOMAIN="selfhost.marty.test",
                  SELFHOST_TEST_USERNAME="operator@selfhost.marty.invalid",
                  SELFHOST_ORG_ID="00000000-0000-0000-0000-000000000001",
                  SELFHOST_GATEWAY_URL="http://127.0.0.1:19080",
                  SELFHOST_KEYCLOAK_URL="http://127.0.0.1:18180",
                  SELFHOST_BAO_AUDIT_URL="https://127.0.0.1:18200",
                  SELFHOST_FIXTURE_SHA256="f" * 64,
                  SELFHOST_CUSTODY_CHALLENGE="c" * 64)
    did = "did:web:selfhost.marty.test:orgs:marty"
    values.update(SELFHOST_ISSUER_DID=did, SELFHOST_VERIFIER_DID=did)
    return values


def fixture_model(values: dict[str, str]) -> dict:
    return {"services": {
        "db-migrate": {"environment": {"MARTY_ORG_ID": values["SELFHOST_ORG_ID"],
                                       "MARTY_ORG_SLUG": "marty",
                                       "MARTY_ORG_ADMIN_EMAIL": values["SELFHOST_TEST_USERNAME"],
                                       "PUBLIC_DOMAIN": values["SELFHOST_PUBLIC_DOMAIN"]}},
        "keycloak-configurator": {"environment": {
            "MARTY_ORG_ADMIN_EMAIL": values["SELFHOST_TEST_USERNAME"],
            "KEYCLOAK_REALM": "11id", "PUBLIC_DOMAIN": values["SELFHOST_PUBLIC_DOMAIN"]}},
        "signing-keys": {"environment": {"BAO_ADDR": "https://host.docker.internal:18200"}},
        "edge": {"ports": [{"host_ip": "127.0.0.1", "published": "19080",
                            "target": 80, "protocol": "tcp"}]},
        "keycloak": {"ports": [{"host_ip": "127.0.0.1", "published": "18180",
                                "target": 8080, "protocol": "tcp"}]},
    }}


def test_synthetic_identity_is_bound_to_public_domain_and_seeded_org() -> None:
    values = fixture_env()
    assert required_environment(values)["SELFHOST_ISSUER_DID"] == values["SELFHOST_VERIFIER_DID"]
    values["SELFHOST_VERIFIER_DID"] = "did:web:elsewhere"
    with pytest.raises(ValueError, match="share the local organization DID"):
        required_environment(values)
    values = fixture_env()
    values["SELFHOST_TEST_USERNAME"] = "real@company.example"
    with pytest.raises(ValueError, match="reserved test domain"):
        required_environment(values)


def test_audit_uses_https_on_disposable_loopback() -> None:
    values = fixture_env()
    required_environment(values)
    for url in ("http://127.0.0.1:18200", "https://example.com:18200",
                "https://127.0.0.1:18200/other"):
        values["SELFHOST_BAO_AUDIT_URL"] = url
        with pytest.raises(ValueError, match="loopback HTTPS"):
            required_environment(values)


def test_custody_signer_is_non_exportable_and_scoped() -> None:
    raw = "V4R5DrcNEOahL046jfk/QYO+hD44DCZ/LMzSHqcMIrM="
    metadata = {"type": "ed25519", "exportable": False,
                "allow_plaintext_backup": False, "latest_version": 1,
                "keys": {"1": {"public_key": raw}}}
    version, pem = custody_signer_public(metadata)
    assert version == 1
    assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
    for changed in ({**metadata, "exportable": True},
                    {**metadata, "allow_plaintext_backup": True},
                    {**metadata, "type": "ecdsa-p256"}):
        with pytest.raises(ValueError, match="non-exportable Ed25519"):
            custody_signer_public(changed)
    with pytest.raises(ValueError, match="public key is invalid"):
        custody_signer_public({**metadata, "keys": {"1": {"public_key": "bad"}}})
    validate_custody_signer_token({"policies": ["selfhost-qualification-custody-signer"],
                                   "ttl": 3600, "orphan": True})
    for policy in (["root"], ["default", "selfhost-qualification-custody-signer"]):
        with pytest.raises(ValueError, match="not scoped"):
            validate_custody_signer_token({"policies": policy, "ttl": 3600,
                                           "orphan": True})
    with pytest.raises(ValueError, match="not scoped"):
        validate_custody_signer_token({"policies": ["selfhost-qualification-custody-signer"],
                                       "ttl": 3600, "orphan": False})


@pytest.mark.parametrize("export_status", [403, 200])
def test_custody_evidence_uses_scoped_transit_signing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, export_status: int,
) -> None:
    values = fixture_env()
    token = tmp_path / "signer.token"
    token.write_text("scoped-token", encoding="ascii")
    values.update(SELFHOST_SECRET_ROOT=str(tmp_path),
                  SELFHOST_CUSTODY_SIGNING_TOKEN_FILE=str(token),
                  SELFHOST_KMS_CUSTODY_EVIDENCE_PATH=str(tmp_path / "custody.json"),
                  SELFHOST_KMS_CUSTODY_SIGNATURE_PATH=str(tmp_path / "custody.sig"),
                  SELFHOST_KMS_CUSTODY_PUBLIC_KEY_PATH=str(tmp_path / "custody.pub"))
    raw_public = "V4R5DrcNEOahL046jfk/QYO+hD44DCZ/LMzSHqcMIrM="
    observed = []

    def respond(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert request.headers["x-vault-token"] == "scoped-token"
        path = request.url.path
        if path.endswith("/auth/token/lookup-self"):
            return httpx.Response(200, json={"data": {
                "policies": ["selfhost-qualification-custody-signer"], "ttl": 300,
                "orphan": True}})
        if path.endswith("/transit/keys/selfhost-qualification-custody-v1"):
            return httpx.Response(200, json={"data": {
                "type": "ed25519", "exportable": False,
                "allow_plaintext_backup": False, "latest_version": 1,
                "keys": {"1": {"public_key": raw_public}}}})
        if path.endswith("/transit/export/signing-key/selfhost-qualification-custody-v1"):
            return httpx.Response(export_status)
        if path.endswith("/transit/sign/cred-issuer-qualification-denied"):
            return httpx.Response(403)
        if path.endswith("/transit/sign/selfhost-qualification-custody-v1"):
            return httpx.Response(200, json={"data": {
                "signature": "vault:v1:" + base64.b64encode(b"s" * 64).decode("ascii")}})
        pytest.fail("unexpected OpenBao custody request")

    transport = httpx.MockTransport(respond)
    monkeypatch.setattr("setup_selfhost_synthetic_fixture.audit_client",
                        lambda url, _root: httpx.AsyncClient(base_url=url, transport=transport))
    if export_status == 200:
        with pytest.raises(ValueError, match="excess capabilities"):
            asyncio.run(write_signed_evidence(values, {"test": "custody"}))
        assert not (tmp_path / "custody.json").exists()
        return
    asyncio.run(write_signed_evidence(values, {"test": "custody"}))
    document = json.loads((tmp_path / "custody.json").read_text(encoding="utf-8"))
    assert document == {"test": "custody", "attestation_key_non_exportable": True,
                        "attestation_key_reference": "selfhost-qualification-custody-v1",
                        "attestation_key_version": 1}
    assert (tmp_path / "custody.sig").read_bytes() == b"s" * 64
    sent = observed[-1]
    assert base64.b64decode(json.loads(sent.content)["input"]) == (
        tmp_path / "custody.json").read_bytes()


def test_audit_ca_is_private_to_secret_root_and_contains_no_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="OpenBao TLS CA file is absent"):
        trusted_audit_context(tmp_path)
    ca = tmp_path / "openbao_tls_ca_cert"
    ca.write_text("-----BEGIN PRIVATE KEY-----\nsecret\n", encoding="ascii")
    with pytest.raises(ValueError, match="contains private key"):
        trusted_audit_context(tmp_path)
    ca.write_text("-----BEGIN CERTIFICATE-----\npublic\n", encoding="ascii")
    observed = []
    monkeypatch.setattr("setup_selfhost_synthetic_fixture.ssl.create_default_context",
                        lambda *, cafile: observed.append(cafile) or "trusted-context")
    assert trusted_audit_context(tmp_path) == "trusted-context"
    assert observed == [str(ca)]


def test_audit_client_verifies_real_tls_ca_and_hostname(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args: object) -> None:
            pass

    def certificate(name: str) -> tuple[Path, Path]:
        cert, key = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
        config = tmp_path / "openssl.cnf"
        config.write_text("[ req ]\ndistinguished_name = req_dn\n[ req_dn ]\n",
                          encoding="ascii")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-config", str(config), "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ], check=True, capture_output=True, timeout=15)
        return cert, key

    cert, key = certificate("server")
    wrong_ca, _ = certificate("unrelated")
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    staged_ca = secret_root / "openbao_tls_ca_cert"
    staged_ca.write_bytes(cert.read_bytes())
    server = HTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(cert), str(key))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        async def probe(url: str) -> bytes:
            async with audit_client(url, secret_root) as client:
                return (await client.get("/")).content

        port = server.server_port
        assert asyncio.run(probe(f"https://127.0.0.1:{port}")) == b"ok"
        with pytest.raises(httpx.ConnectError, match="certificate verify failed"):
            asyncio.run(probe(f"https://localhost:{port}"))
        staged_ca.write_bytes(wrong_ca.read_bytes())
        with pytest.raises(httpx.ConnectError, match="certificate verify failed"):
            asyncio.run(probe(f"https://127.0.0.1:{port}"))
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_migration_admin_must_match_synthetic_public_operator() -> None:
    values = fixture_env()
    model = fixture_model(values)
    validate_installed_model(model, values)
    model["services"]["db-migrate"]["environment"]["MARTY_ORG_ADMIN_EMAIL"] = "other@example.test"
    with pytest.raises(ValueError, match="migration-seeded organization"):
        validate_installed_model(model, values)


def test_synthetic_did_must_match_installed_slug() -> None:
    values = fixture_env()
    model = fixture_model(values)
    validate_installed_model(model, values)
    model["services"]["db-migrate"]["environment"]["MARTY_ORG_SLUG"] = "other"
    with pytest.raises(ValueError, match="organization slug"):
        validate_installed_model(model, values)


def test_installed_signing_keys_must_use_same_https_openbao_port() -> None:
    values = fixture_env()
    model = fixture_model(values)
    validate_installed_model(model, values)
    for address in ("http://host.docker.internal:18200",
                    "https://host.docker.internal:18201"):
        model["services"]["signing-keys"]["environment"]["BAO_ADDR"] = address
        with pytest.raises(ValueError, match="migration-seeded organization"):
            validate_installed_model(model, values)


@pytest.mark.parametrize("service,url_name,other_port", [
    ("edge", "SELFHOST_GATEWAY_URL", 19081),
    ("keycloak", "SELFHOST_KEYCLOAK_URL", 18181),
])
def test_journey_urls_must_use_installed_published_ports(
        service: str, url_name: str, other_port: int) -> None:
    values = fixture_env()
    model = fixture_model(values)
    validate_installed_model(model, values)
    values[url_name] = f"http://127.0.0.1:{other_port}"
    with pytest.raises(ValueError, match="differs from installed"):
        validate_installed_model(model, values)
    values = fixture_env()
    model["services"][service]["ports"].append(
        {"host_ip": "127.0.0.1", "published": str(other_port), "target": 80})
    with pytest.raises(ValueError, match="differs from installed"):
        validate_installed_model(model, values)


def test_signed_profile_selector_has_no_null_private_id() -> None:
    values = fixture_env()
    selector = validate_profile_projection({
        "issuer_did": values["SELFHOST_ISSUER_DID"],
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "ES256", "status": "active",
    }, did=values["SELFHOST_ISSUER_DID"], purpose="vc_jwt_issuer")
    assert selector == {"issuer_did": values["SELFHOST_ISSUER_DID"],
                        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
                        "algorithm": "ES256"}
    assert "profile_id" not in selector
    assert profile_proof(selector, "cred-issuer-test-es256", 1) == {
        "profile_selector": selector,
        "key_reference": "cred-issuer-test-es256", "key_version": 1}
    with pytest.raises(ValueError, match="incomplete"):
        profile_proof(selector, "cred-issuer-test-es256", 0)
    with pytest.raises(ValueError, match="differs from expected selector"):
        validate_profile_projection({**selector, "status": "active",
                                     "key_purpose": "oid4vp_request_signing"},
                                    did=values["SELFHOST_ISSUER_DID"], purpose="vc_jwt_issuer")


def test_purpose_specific_managed_key_references_are_distinct() -> None:
    values = fixture_env()
    org = values["SELFHOST_ORG_ID"]
    issuer = managed_reference(org, "vc_jwt_issuer")
    verifier = managed_reference(org, "oid4vp_request_signing")
    tenant = uuid.uuid5(uuid.NAMESPACE_URL, org).hex
    assert issuer == f"cred-issuer-{tenant}-marty-es256"
    assert verifier == f"oid4vp-verifier-{tenant}-marty-es256"
    assert issuer != verifier
    with pytest.raises(ValueError, match="unsupported"):
        managed_reference(org, "mdoc_dsc")
    assert managed_reference("another-org", "vc_jwt_issuer") != issuer


def test_managed_key_binding_is_scoped_to_org_service_and_reference() -> None:
    binding = managed_key_binding("org-a", "cred-issuer-key-a")
    assert binding == "795e3bc59e96474ffd1791289dd82098a7dfb2655799b7075b45d4359cf45b5c"
    assert binding != managed_key_binding("org-b", "cred-issuer-key-a")
    assert binding != managed_key_binding("org-a", "cred-issuer-key-b")


def test_public_profile_and_nonexportable_transit_metadata_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
    }
    pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n"
        "6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n"
        "-----END PUBLIC KEY-----\n"
    )
    metadata = {"type": "ecdsa-p256", "exportable": False, "latest_version": 2,
                "keys": {"2": {"public_key": pem}}}
    other_pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfPJ7GI0DT36KUjgDBLUaw8CJaeJ3\n"
        "8hs1pgtI/EdmmXgHd1UQ247QQCk9msafdDDbun2t5jzpgimeBLedInhz0Q==\n"
        "-----END PUBLIC KEY-----\n"
    )
    other_jwk = {**jwk, "x": "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg",
                 "y": "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"}
    tool = Path("/fixture/public-kms-jwk")

    def convert(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert args == [str(tool)]
        candidate = kwargs["input"]
        if candidate == pem:
            return subprocess.CompletedProcess(args, 0, json.dumps(jwk), "")
        if candidate == other_pem:
            return subprocess.CompletedProcess(args, 0, json.dumps(other_jwk), "")
        return subprocess.CompletedProcess(args, 1, "", "invalid public key")

    monkeypatch.setattr("setup_selfhost_synthetic_fixture.subprocess.run", convert)
    assert validate_transit_binding(metadata, jwk, tool) == 2
    with pytest.raises(ValueError, match="not canonical P-256"):
        validate_transit_binding(metadata, {**jwk, "x": "wrong"}, tool)
    with pytest.raises(ValueError, match="differs from resolved profile"):
        validate_transit_binding(metadata, {**jwk, "x": "A" * 43, "y": "A" * 43}, tool)
    with pytest.raises(ValueError, match="non-exportable"):
        validate_transit_binding({**metadata, "exportable": True}, jwk, tool)
    with pytest.raises(ValueError, match="differs from resolved profile"):
        validate_transit_binding({**metadata, "keys": {"2": {"public_key": other_pem}}}, jwk,
                                 tool)
    with pytest.raises(ValueError, match="invalid"):
        validate_transit_binding({**metadata, "keys": {"2": {
            "public_key": "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n"
        }}}, jwk, tool)


def test_openbao_audit_token_rejects_root_or_long_lived_authority() -> None:
    scoped = {"policies": ["default", "selfhost-qualification-audit"], "ttl": 900}
    validate_audit_token(scoped)
    for candidate in ({**scoped, "policies": ["root"]},
                      {**scoped, "ttl": 7200},
                      {**scoped, "policies": ["selfhost-qualification-audit", "admin"]}):
        with pytest.raises(ValueError, match="expected policy name or short TTL"):
            validate_audit_token(candidate)
