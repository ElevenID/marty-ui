"""Local prerequisite contract controls; these do not qualify a demo run."""
from copy import deepcopy
import json

import pytest

from scripts import beta_passport_functional_audit as audit


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
                flow_session="sessionId=flow-test", api_key="test-api-key-" * 4)
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
            assert observed[-1]["body"].encode() == body
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
