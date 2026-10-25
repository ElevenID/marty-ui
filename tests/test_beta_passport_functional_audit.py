"""Local prerequisite contract controls; these do not qualify a demo run."""
from copy import deepcopy
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import beta_passport_functional_audit as audit


def test_native_binding_requires_actual_parent_context_and_unchanged_receipt(tmp_path, monkeypatch):
    receipt = tmp_path / "native.json"
    receipt.write_text('{"source":"control-only"}', encoding="utf8")
    context = {"nativeSourceRevision": "a" * 40, "receiptSha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
               "imageSourceId": "b" * 40, "betaImageMarkersRemainBaseline": True, "releaseQualified": False}
    for name, value in {"RECORD_VIDEO": "0", "DEMO_LOCAL_NATIVE_LIVE_BINDING": "1",
                        "DEMO_LOCAL_NATIVE_OVERLAY_RECEIPT": str(receipt),
                        "DEMO_LOCAL_NATIVE_OVERLAY_SHA256": context["receiptSha256"]}.items():
        monkeypatch.setenv(name, value)
    assert audit.local_native_overlay_binding(SimpleNamespace(native_runtime_binding=context), "b" * 40) == context
    for changed in [None, {**context, "releaseQualified": True}, {**context, "imageSourceId": "c" * 40},
                    {**context, "receiptSha256": "0" * 64}]:
        with pytest.raises(audit.PassportPrerequisiteError):
            audit.local_native_overlay_binding(SimpleNamespace(native_runtime_binding=changed), "b" * 40)
    receipt.write_text('{}', encoding="utf8")
    with pytest.raises(audit.PassportPrerequisiteError):
        audit.local_native_overlay_binding(SimpleNamespace(native_runtime_binding=context), "b" * 40)


def test_native_binding_cannot_claim_recording_or_substitute_an_unrequested_overlay(monkeypatch):
    monkeypatch.delenv("DEMO_LOCAL_NATIVE_OVERLAY_RECEIPT", raising=False)
    assert audit.local_native_overlay_binding(SimpleNamespace(native_runtime_binding=None), "b" * 40) is None
    with pytest.raises(audit.PassportPrerequisiteError):
        audit.local_native_overlay_binding(SimpleNamespace(native_runtime_binding={}), "b" * 40)
    monkeypatch.setenv("DEMO_LOCAL_NATIVE_OVERLAY_RECEIPT", "/unavailable/native.json")
    monkeypatch.setenv("RECORD_VIDEO", "1")
    with pytest.raises(audit.PassportPrerequisiteError):
        audit.local_native_overlay_binding(SimpleNamespace(native_runtime_binding={}), "b" * 40)


def test_negative_callback_transport_in_recorder_top_level_loader():
    source = Path(audit.__file__)
    specification = importlib.util.spec_from_file_location('passport_recorder_client', source)
    loaded = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(loaded)
    assert loaded.__package__ == ''
    observed = []
    port = SimpleNamespace(callback_container_id='a' * 64,
        callback_post=lambda *args: (observed.append(args) or (422, {'missing_signature_header': True})))
    status, projection = loaded.ObservedPassportRequests.negative_post(port, b'{}', None)
    assert status == 422 and projection['missing_signature_header'] is True
    assert observed == [('a' * 64, b'{}', None)]


@pytest.fixture
def bound():
    image = "sha256:" + "a" * 64
    receipt = {"scope": "LOCAL_DEVELOPER_STACK", "betaDeployed": True,
               "exactRuntimeImagesAndMarkersVerified": True, "publicUiMarkerVerified": True,
               "sourceRevision": "b" * 40, "sourceId": "c" * 40, "release": "dev-reviewed",
               "images": {"services": {"imageId": image}}}
    deployment = {"source_kind": "local-worktree-snapshot", "promotion_eligible": False,
                  "release_ready": False, "beta_origin": audit.ORIGIN,
                  "compose_project": "elevenid-beta", "marty_ui_sha": "c" * 40,
                  "release_version": "dev-reviewed", "passport_provider_mode": "simulator",
                  "images": []}
    containers = {}
    for index, role in enumerate(audit.ROLES, 1):
        container = str(index) * 64
        deployment["images"].append({"service": role, "container_id": container, "image_id": image})
        env = dict(audit.FEATURES[role])
        if role == "passport-callback-signer":
            env.update(BAO_ADDR="https://openbao:8200", BAO_CACERT="/bao/public-ca/ca.crt",
                       BAO_TOKEN_FILE="/bao/passport-callback/token")
        containers[container] = {"Id": container, "Image": image,
                                 "State": {"Running": True, "Health": {"Status": "healthy"}},
                                 "Config": {"Labels": {"com.docker.compose.project": "elevenid-beta",
                                                       "com.docker.compose.service": role},
                                            "Env": [key + "=" + value for key, value in env.items()]}}
    kms = "f" * 64
    containers[kms] = {"Id": kms, "State": {"Running": True}, "Config": {"Labels": {
        "com.docker.compose.project": "elevenid-beta", "com.docker.compose.service": "openbao"}}}
    network = {"Name": audit.CALLBACK_NETWORK, "Id": "9" * 64, "Internal": True,
               "Labels": {"com.docker.compose.project": "elevenid-beta",
                          "com.docker.compose.network": "passport-callback-signing"}, "Containers": {
        "5" * 64: {}, "6" * 64: {}, kms: {}}}
    calls = []

    def observe(*args):
        calls.append(args)
        return [deepcopy(network if args[:2] == ("network", "inspect") else containers[args[1]])]

    return receipt, deployment, containers, network, calls, observe


def test_exact_runtime_feature_and_isolated_kms_network_binding(bound):
    receipt, deployment, _, _, calls, observe = bound
    result = audit.verify_runtime(receipt, deployment, observe=observe)
    assert set(result["containers"]) == set(audit.ROLES)
    assert result["physicalClaim"] == "not_claimed"
    assert len(calls) == 8


def test_off_profile_blocks_before_any_docker_or_feature_operation(bound):
    receipt, deployment, _, _, calls, observe = bound
    deployment["passport_provider_mode"] = "off"
    with pytest.raises(audit.PassportPrerequisiteError, match="explicit beta native simulator"):
        audit.verify_runtime(receipt, deployment, observe=observe)
    assert calls == []


@pytest.mark.parametrize("mutation", ["source", "origin", "project", "promotable"])
def test_receipt_and_deployment_identity_mismatch_blocks_observation(bound, mutation):
    receipt, deployment, _, _, calls, observe = bound
    key, value = {"source": ("marty_ui_sha", "e" * 40), "origin": ("beta_origin", "http://localhost"),
                  "project": ("compose_project", "production"), "promotable": ("promotion_eligible", True)}[mutation]
    deployment[key] = value
    with pytest.raises(audit.PassportPrerequisiteError, match="differs"):
        audit.verify_runtime(receipt, deployment, observe=observe)
    assert calls == []


@pytest.mark.parametrize("mutation", ["foreign-project", "image", "unhealthy", "disabled", "keyring"])
def test_actual_role_drift_is_not_accepted_from_receipt(bound, mutation):
    receipt, deployment, containers, _, _, observe = bound
    gateway = containers["1" * 64]
    if mutation == "foreign-project":
        gateway["Config"]["Labels"]["com.docker.compose.project"] = "production"
    elif mutation == "image":
        gateway["Image"] = "sha256:" + "d" * 64
    elif mutation == "unhealthy":
        gateway["State"]["Health"]["Status"] = "unhealthy"
    elif mutation == "disabled":
        gateway["Config"]["Env"] = ["PASSPORT_NATIVE_GATEWAY_ENABLED=false"]
    else:
        gateway["Config"]["Env"].append("PASSPORT_TENANT_API_KEYS_FILE=/unapproved/keyring")
    with pytest.raises(audit.PassportPrerequisiteError):
        audit.verify_runtime(receipt, deployment, observe=observe)


def test_missing_bureau_cannot_be_replaced_by_unrelated_running_service(bound):
    receipt, deployment, _, _, _, observe = bound
    deployment["images"] = [row for row in deployment["images"] if row["service"] != "passport-beta-bureau"]
    with pytest.raises(audit.PassportPrerequisiteError, match="missing or duplicated: passport-beta-bureau"):
        audit.verify_runtime(receipt, deployment, observe=observe)


@pytest.mark.parametrize("mutation", ["public", "foreign-member", "fake-kms", "wrong-name",
                                     "foreign-network-project", "wrong-kms-id"])
def test_callback_network_boundaries(bound, mutation):
    receipt, deployment, containers, network, _, observe = bound
    if mutation == "public":
        network["Internal"] = False
    elif mutation == "foreign-member":
        network["Containers"]["e" * 64] = {}
    elif mutation == "fake-kms":
        containers["f" * 64]["Config"]["Labels"]["com.docker.compose.service"] = "not-openbao"
    elif mutation == "wrong-name":
        network["Name"] = "foreign-network"
    elif mutation == "foreign-network-project":
        network["Labels"]["com.docker.compose.project"] = "production"
    else:
        containers["f" * 64]["Id"] = "e" * 64
    with pytest.raises(audit.PassportPrerequisiteError, match="network|KMS"):
        audit.verify_runtime(receipt, deployment, observe=observe)


def test_duplicate_environment_name_is_not_last_value_wins(bound):
    receipt, deployment, containers, _, _, observe = bound
    containers["1" * 64]["Config"]["Env"].insert(0, "PASSPORT_NATIVE_GATEWAY_ENABLED=false")
    with pytest.raises(audit.PassportPrerequisiteError, match="repeats a name"):
        audit.verify_runtime(receipt, deployment, observe=observe)


def test_actual_browser_transport_isolates_authorities_and_preserves_signed_body():
    from playwright.sync_api import sync_playwright

    class Capture:
        failed = None
        completed = False

        def __init__(self):
            self.pages = []

        def bind_page(self, page):
            self.pages.append(page)

    # This is a browser transport control, not a product/UI or live-trace proof.
    capture = Capture()
    observed = []
    revoked_cookies = set()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, args=["--host-resolver-rules=MAP * ~NOTFOUND",
                                 "--proxy-server=http://127.0.0.1:9",
                                 "--proxy-bypass-list=<-loopback>"])
        try:
            def route(handler):
                request = handler.request
                assert request.url.startswith(audit.ORIGIN + "/")
                observed.append({"url": request.url, "method": request.method,
                                 "headers": request.all_headers(), "body": request.post_data})
                assert request.frame.page in capture.pages
                if request.url.endswith("/v1/auth/logout"):
                    revoked_cookies.add(request.all_headers()["cookie"])
                    handler.fulfill(status=302, headers={"Location": "https://sso.invalid/logout",
                        "Set-Cookie": "sessionId=; Max-Age=0; Path=/; Secure; HttpOnly"})
                    return
                if request.url.endswith("/v1/auth/me"):
                    assert request.all_headers()["cookie"] in revoked_cookies
                    handler.fulfill(status=200, content_type="application/json", body='{"authenticated":false}')
                    return
                if request.url.endswith("/webhooks/personalization"):
                    payload = {"detail": [{"type": "missing", "loc": ["header", "x-personalization-signature"]}]}
                    status = 422
                else:
                    payload, status = {"ok": True}, 200
                handler.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

            class RoutedBrowser:
                def new_context(self, **options):
                    context = browser.new_context(**options)
                    # Install before the first Page exists; Browser context
                    # events do not announce explicit new_context calls.
                    context.route("**/*", route)
                    return context

            ports = audit.ObservedPassportRequests(
                capture, RoutedBrowser(), csca_session="sessionId=csca-test", dsc_session="sessionId=dsc-test",
                flow_session="sessionId=flow-test", api_key="test-api-key-" * 4,
                callback_container_id='a' * 64,
                callback_post=lambda container, body, signature: (422, {'missing_signature_header': True}))
            assert len(capture.pages) == 4
            ports.chain_request("/v1/signing-keys/issuer-identities/csca-self-signed-certificate",
                                {"organization_id": "org-a", "country": "US"}, "sessionId=csca-test")
            assert observed[-1]["headers"]["cookie"] == "sessionId=csca-test"
            assert observed[-1]["url"].endswith("?organization_id=org-a")
            assert json.loads(observed[-1]["body"]) == {"country": "US"}
            ports.chain_request("/v1/signing-keys/issuer-identities/dsc-certificate",
                                {"organization_id": "org-a"}, "sessionId=dsc-test")
            assert observed[-1]["headers"]["cookie"] == "sessionId=dsc-test"
            ports.flow_request("GET", "/v1/flows/definitions/selected", None, "sessionId=flow-test")
            assert observed[-1]["headers"]["cookie"] == "sessionId=flow-test"
            ports.passport_request("GET", "/v1/passport/applications/selected/production-status",
                                   None, "test-api-key-" * 4)
            assert observed[-1]["headers"]["x-api-key"] == "test-api-key-" * 4
            assert "cookie" not in observed[-1]["headers"]
            body = b'{ "organization_id" : "org-a", "status": "SHIPPED" }'
            status, projection = ports.negative_post(body, None)
            assert status == 422 and projection["missing_signature_header"] is True
            ports.resource_request("flow", "POST", "/v1/application-templates", {"name": "Fresh"},
                                   {"idempotency-key": "passport-demo-" + "a" * 32})
            assert observed[-1]["headers"]["idempotency-key"] == "passport-demo-" + "a" * 32
            scoped_key = "/v1/api-keys?organization_id=00000000-0000-0000-0000-000000000001"
            ports.resource_request("flow", "POST", scoped_key, {"name": "Owned"})
            assert observed[-1]["url"].endswith(scoped_key)
            with pytest.raises(audit.PassportPrerequisiteError, match="resource route"):
                ports.resource_request("flow", "POST", "/v1/api-keys", {"name": "Unscoped"})
            before_headers = len(observed)
            with pytest.raises(audit.PassportPrerequisiteError, match="header"):
                ports.resource_request("flow", "POST", "/v1/credential-templates", {},
                                       {"idempotency-key": "passport-demo-" + "a" * 32})
            assert len(observed) == before_headers
            ports.resource_request("flow", "PATCH", "/v1/flows/definitions/owned",
                                   {"organization_id": "org-a", "name": "Owned"})
            assert observed[-1]["method"] == "PATCH" and observed[-1]["headers"]["cookie"] == "sessionId=flow-test"
            ports.resource_request("csca", "DELETE", "/v1/signing-keys/issuer-identities?organization_id=org-a", {})
            assert observed[-1]["method"] == "DELETE" and observed[-1]["headers"]["cookie"] == "sessionId=csca-test"
            assert ports.retire_sessions() is True
            assert len(revoked_cookies) == 3
            assert not any("sso.invalid" in row["url"] for row in observed)
            before = len(observed)
            for path in ("//foreign.example/v1/passport/a", "/v1/passport/../admin", "https://foreign.example"):
                with pytest.raises(audit.PassportPrerequisiteError):
                    ports.passport_request("POST", path, {}, "test-api-key-" * 4)
            assert len(observed) == before
            capture.failed = ValueError("owned live capture failed")
            with pytest.raises(audit.PassportPrerequisiteError, match="stopped"):
                ports.passport_request("POST", "/v1/passport/applications", {}, "test-api-key-" * 4)
            assert len(observed) == before
            ports.close()
        finally:
            browser.close()


def test_bound_input_tampering_fails_before_any_operation(tmp_path):
    file = tmp_path / "bound.json"
    file.write_text('{"scope":"reviewed"}', encoding="utf8")
    binding = {"path": str(file), "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
    assert audit.bound_json(binding) == {"scope": "reviewed"}
    file.write_text('{"scope":"changed"}', encoding="utf8")
    with pytest.raises(audit.PassportPrerequisiteError, match="acknowledged input bytes"):
        audit.bound_json(binding)


def test_custody_file_cannot_be_imported_from_public_artifacts(tmp_path):
    file = tmp_path / "public-fixture.json"
    file.write_text('{"schema":"not-private"}', encoding="utf8")
    binding = {"path": str(file), "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
    with pytest.raises(audit.PassportPrerequisiteError, match="protected private directory"):
        audit.bound_json(binding, private=True)


def test_actual_isolated_child_refuses_to_act_without_owned_ipc_client():
    environment = dict(os.environ)
    environment.pop("DEMO_PYTHON_CAPTURE_CLIENT", None)
    environment.pop("DEMO_PYTHON_CAPTURE_CLIENT_SHA256", None)
    result = subprocess.run([sys.executable, "-I", str(Path(audit.__file__).resolve())],
                            capture_output=True, env=environment, timeout=15)
    assert result.returncode == 1 and result.stdout == b""
    assert result.stderr.decode().strip() == "Fresh passport operation failed: PassportPrerequisiteError"


def test_recording_mode_fails_explicitly_before_fixture_or_runtime_reads():
    result = subprocess.run(["node", "tests/scripts/audit-beta-passport-functional.js"],
        capture_output=True, env=dict(os.environ, RECORD_VIDEO="1"), timeout=15)
    assert result.returncode == 1 and result.stdout == b""
    assert result.stderr.decode().strip() == (
        "D12 fresh operations require --functional-rerun; recording support remains pending")


def test_caller_rejects_imported_report_instead_of_loading_or_mutating(monkeypatch):
    class Capture:
        inputs = {"origin": audit.ORIGIN, "scenario": {"importedReport": "prior-result.json"}}

    calls = []
    monkeypatch.setattr(audit, "bound_json", lambda *args, **kwargs: calls.append("read"))
    with pytest.raises(audit.PassportPrerequisiteError, match="acknowledged operation inputs"):
        audit.run_bound_capture(Capture())
    assert calls == []


def test_duplicate_cookie_values_fail_before_any_browser_context():
    class NoBrowser:
        def new_context(self, **_):
            pytest.fail("Duplicate authority must be rejected before browser creation")
    with pytest.raises(audit.PassportPrerequisiteError, match="Separate governed"):
        audit.ObservedPassportRequests(None, NoBrowser(), csca_session="sessionId=same",
            dsc_session="sessionId=same ", flow_session="sessionId=other", api_key="k" * 40,
            callback_container_id='a' * 64)


@pytest.mark.parametrize("key_revived", [False, True])
def test_bounded_failure_teardown_closes_sessions_even_after_trace_failure(key_revived):
    """Command-port control only; these responses are not live demo evidence."""
    from types import SimpleNamespace
    observed = []
    class Api:
        def fetch(self, url, **options):
            observed.append((url, options))
            assert url.startswith(audit.ORIGIN + "/") and options["max_redirects"] == 0
            if url.endswith("/logout"):
                code, body = 302, b""
            elif url.endswith("/auth/me"):
                code, body = 200, b'{"authenticated":false}'
            elif url.endswith("/production-status"):
                code, body = (200 if key_revived else 401), b'{}'
            else:
                assert options["method"] == "DELETE" and url.endswith(
                    "/v1/api-keys/owned-key?organization_id=org-a")
                code, body = 200, b'{"success":true}'
            return SimpleNamespace(status=code, body=lambda: body)
    ports = object.__new__(audit.ObservedPassportRequests)
    ports.capture = SimpleNamespace(failed=ValueError("Actual trace failed"))
    ports.api_key = "private-owned-key"
    ports.sessions = {role: "sessionId=" + role for role in ("csca", "dsc", "flow")}
    ports.pages = {role: SimpleNamespace(context=SimpleNamespace(request=Api(), add_cookies=lambda _: None))
                   for role in ("api", "csca", "dsc", "flow")}
    result = ports.failure_teardown(organization="org-a", key_id="owned-key", old_key=ports.api_key,
        probe_path="/v1/passport/applications/demo-owned-run/production-status")
    assert result["qualificationEligible"] is False
    assert result["sessionsRetired"] == 3 and result["complete"] is (not key_revived)
    assert result["keyDenied"] is (not key_revived)
    assert len(observed) == 8


@pytest.mark.parametrize("owned_marker", [True, False])
def test_setup_failure_retires_only_exact_owned_issuer_before_sessions(owned_marker):
    from types import SimpleNamespace
    observed = []
    run_id = "a" * 32
    identity = {"issuer_did": "did:web:beta.elevenidllc.com:orgs:owned-demo-" +
                (run_id if owned_marker else "b" * 32), "key_purpose": "csca",
                "credential_format": "ICAO_EMRTD", "algorithm": "ES256"}
    class Api:
        def fetch(self, url, **options):
            observed.append((url, options["method"]))
            if "/issuer-identities/resolve?" in url:
                return SimpleNamespace(status=404, body=lambda: b'{}')
            if "/issuer-identities?" in url:
                assert options["method"] == "DELETE" and json.loads(options["data"]) == identity
                return SimpleNamespace(status=200, body=lambda: json.dumps({"deleted": identity}).encode())
            if url.endswith("/auth/me"):
                return SimpleNamespace(status=200, body=lambda: b'{"authenticated":false}')
            assert url.endswith("/auth/logout")
            return SimpleNamespace(status=302, body=lambda: b'')
    ports = object.__new__(audit.ObservedPassportRequests)
    ports.api_key = ""
    ports.sessions = {role: "sessionId=" + role for role in ("csca", "dsc", "flow")}
    ports.pages = {role: SimpleNamespace(context=SimpleNamespace(request=Api(), add_cookies=lambda _: None))
                   for role in ("api", "csca", "dsc", "flow")}
    result = ports.failure_teardown(organization="00000000-0000-0000-0000-000000000001",
        key_id=None, old_key="", probe_path="/v1/passport/applications/uncreated/production-status",
        owned_issuers=[{"role": "csca", "tuple": identity, "creation_returned": True}],
        owned_run_id=run_id)
    assert result["qualificationEligible"] is False and result["sessionsRetired"] == 3
    assert result["issuerIdentitiesRetired"] == int(owned_marker)
    assert result["complete"] is owned_marker
    assert sum("/issuer-identities?" in url for url, _ in observed) == int(owned_marker)


@pytest.mark.parametrize("proxy", [None, "", "0", "1", "true", "false", "http://localhost:8443"])
def test_direct_beta_transport_uses_explicit_disabled_proxy_flag(monkeypatch, proxy):
    monkeypatch.setenv("BETA_ORIGIN", audit.ORIGIN)
    monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "1")
    if proxy is None:
        monkeypatch.delenv("BETA_LOCAL_PROXY", raising=False)
    else:
        monkeypatch.setenv("BETA_LOCAL_PROXY", proxy)
    if proxy in (None, "", "0"):
        audit.require_direct_beta_transport()
    else:
        with pytest.raises(audit.PassportPrerequisiteError, match="exact beta origin and normal TLS"):
            audit.require_direct_beta_transport()


@pytest.mark.parametrize("changed", ["origin", "tls"])
def test_disabled_proxy_does_not_bypass_exact_origin_or_tls(monkeypatch, changed):
    monkeypatch.setenv("BETA_LOCAL_PROXY", "0")
    monkeypatch.setenv("BETA_ORIGIN", "https://other.invalid" if changed == "origin" else audit.ORIGIN)
    monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "0" if changed == "tls" else "1")
    with pytest.raises(audit.PassportPrerequisiteError, match="exact beta origin and normal TLS"):
        audit.require_direct_beta_transport()


def test_bound_capture_accepts_runner_proxy_zero_before_any_input_read(monkeypatch):
    class Capture:
        inputs = {"origin": audit.ORIGIN, "scenario": {"importedReport": "prior-result.json"}}
    monkeypatch.setenv("BETA_LOCAL_PROXY", "0")
    monkeypatch.setenv("BETA_ORIGIN", audit.ORIGIN)
    monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "1")
    monkeypatch.setattr(audit, "bound_json", lambda *_args, **_kw: pytest.fail("No input may be read"))
    monkeypatch.setattr(audit, "docker_json", lambda *_args: pytest.fail("No runtime call may occur"))
    with pytest.raises(audit.PassportPrerequisiteError, match="acknowledged operation inputs"):
        audit.run_bound_capture(Capture())


@pytest.mark.parametrize("changed", [None, "repository", "manifest"])
def test_product_repository_binds_parent_coordinated_workspace(tmp_path, changed):
    repository = tmp_path / "workspace" / "marty-ui"
    artifacts = repository / "tests/artifacts/current"
    artifacts.mkdir(parents=True)
    (repository / ".git").write_text("gitdir: retained-fixed-source")
    manifest = artifacts / "source-manifest.json"
    manifest.write_text("{}")
    if changed == "repository":
        repository = repository.parent
    elif changed == "manifest":
        manifest = tmp_path / "foreign.json"
    if changed:
        with pytest.raises(audit.PassportPrerequisiteError, match="fixed product repository"):
            audit.coordinated_product_workspace(repository, manifest)
    else:
        assert audit.coordinated_product_workspace(repository, manifest) == repository.parent


def test_private_stage_diagnostic_never_retains_exception_or_custody(tmp_path, monkeypatch):
    private = tmp_path / ".codex/private/owned-run"
    private.mkdir(parents=True, mode=0o700)
    fixture = private / "fixture.json"
    fixture.write_text('{"token":"DO-NOT-RETAIN-CUSTODY"}')
    monkeypatch.setattr(audit.Path, "home", lambda: tmp_path)
    class Capture:
        inputs = {"scenario": {"privateFixture": {"path": str(fixture)}}}
        _passport_failure_stage = "COORDINATED_SOURCE"
    try:
        raise RuntimeError("DO-NOT-RETAIN-EXCEPTION")
    except RuntimeError as error:
        audit.retain_private_failure(Capture(), error)
    outputs = list(private.glob("passport-failure-*.json"))
    assert len(outputs) == 1
    raw = outputs[0].read_text()
    result = json.loads(raw)
    assert {key: value for key, value in result.items() if key != "sourceTrace"} == {
        "schema": "marty.passport-private-failure/v1",
        "stage": "COORDINATED_SOURCE", "errorType": "RuntimeError", "qualificationEligible": False}
    assert len(result["sourceTrace"]) == 1
    assert result["sourceTrace"][0]["module"] == "tests/test_beta_passport_functional_audit.py"
    assert result["sourceTrace"][0]["function"] == "test_private_stage_diagnostic_never_retains_exception_or_custody"
    assert isinstance(result["sourceTrace"][0]["line"], int)
    assert "DO-NOT-RETAIN" not in raw


def test_private_stage_diagnostic_refuses_foreign_fixture(tmp_path, monkeypatch):
    fixture = tmp_path / "fixture.json"
    fixture.write_text("{}")
    monkeypatch.setattr(audit.Path, "home", lambda: tmp_path)
    class Capture:
        inputs = {"scenario": {"privateFixture": {"path": str(fixture)}}}
        _passport_failure_stage = "COORDINATED_SOURCE"
    audit.retain_private_failure(Capture(), RuntimeError("unlogged"))
    assert list(tmp_path.glob("passport-failure-*.json")) == []
