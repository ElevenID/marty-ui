"""An owned localhost HTTPS edge carries the complete synthetic route probe."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import uuid
from urllib.error import HTTPError

import pytest

from scripts import passport_supported_disposable_route_probe as probe
from services.passport_disposable_identity import ORGANIZATION_ID, issuer_did


NOW = datetime(2026, 9, 28, 17, tzinfo=timezone.utc)
BUREAU_ID = "be6bccf4-51eb-4985-a079-6424bf5c5685"
KEY = "mk_test_" + "a" * 43
OTHER_KEY = "mk_test_" + "b" * 43
OTHER_ORG = "00000000-0000-0000-0000-000000000002"


class Response:
    def __init__(self, url: str, status: int, body: dict):
        self.url = url
        self.status = status
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self.url

    def read(self, size: int):
        return self.body[:size]


class Opener:
    def __init__(self):
        self.requests = []
        self.states = iter(("DRAFT", "DATA_GENERATED", "SOD_SIGNED", "SUBMITTED",
                            "QUALITY_CHECK", "READY_FOR_ACTIVATION", "ACTIVE"))

    def open(self, request, timeout: int):
        self.requests.append(request)
        assert request.full_url.startswith("https://localhost:29877/v1/passport/")
        path = request.full_url.removeprefix("https://localhost:29877")
        if path == "/v1/passport/capabilities":
            if "X-api-key" not in request.headers:
                raise HTTPError(request.full_url, 403, "Unauthenticated", None, None)
            return Response(request.full_url, 200, {
                "supported": True, "blockers": [], "bureau_configured": True,
                "encrypted_artifact_store": True,
                "signer": {"mode": "MANAGED_ISSUER_PROFILE"},
            })
        if path == "/v1/passport/webhooks/personalization":
            assert "X-api-key" not in request.headers
            raise HTTPError(request.full_url, 422, "Unsigned", None, None)
        if path.endswith("/production-status") and "X-api-key" not in request.headers:
            raise HTTPError(request.full_url, 403, "Unauthenticated", None, None)
        if (path.endswith("/production-status")
            and request.headers.get("X-api-key") == OTHER_KEY):
            raise HTTPError(request.full_url, 404, "Cross-tenant", None, None)
        assert request.headers["X-api-key"] == KEY
        state = next(self.states)
        body = {"id": "job-1", "application_id": "application-1",
                "organization_id": ORGANIZATION_ID, "status": state,
                "bureau_job_id": (BUREAU_ID if state in (
                    "SUBMITTED", "QUALITY_CHECK", "READY_FOR_ACTIVATION", "ACTIVE")
                    else None)}
        if state == "SOD_SIGNED":
            body.update(sod_sha256="f" * 64, sod_signature_verified=True)
        if state == "SUBMITTED":
            body["sod_sha256"] = "f" * 64
        if state == "READY_FOR_ACTIVATION":
            body["quality_result"] = {"passed": True}
        if state == "ACTIVE":
            body["completed_at"] = "2026-09-28T00:00:00Z"
        return Response(request.full_url, 201 if state == "DRAFT" else 200, body)


def staged():
    project = "marty-passport-acceptance-selfhost-" + uuid.uuid4().hex[:12]
    root = Path(tempfile.gettempdir()) / project
    root.mkdir(mode=0o700)
    secrets = root / "secrets"
    secrets.mkdir(mode=0o700)
    (secrets / "passport_acceptance_api_key").write_text(KEY + "\n")
    (secrets / "passport_acceptance_tenant_probe_api_key").write_text(
        OTHER_ORG + "\n" + OTHER_KEY + "\n")
    (secrets / "workload_identity_ca_cert").write_text("synthetic-ca")
    return root, {"project": project, "disposable_root": str(root),
                  "expires_at": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                  "containers": {"edge": "e" * 64,
                                 "passport-beta-bureau": "b" * 64,
                                 "gateway": "g" * 64,
                                 "issuance-native": "i" * 64}}


def callback_containers(project: str) -> dict[str, dict]:
    private = project + "_private"
    return {
        "b" * 64: {"HostConfig": {},
                   "NetworkSettings": {"Networks": {private: {"Aliases": [
                       project + "-passport-beta-bureau-1", "passport-beta-bureau"]}}},
                   "Config": {"Env": [
            "PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED=true",
            "PASSPORT_BUREAU_CALLBACK_URL=" + probe.GATEWAY_CALLBACK]}},
        "g" * 64: {"NetworkSettings": {"Networks": {private: {"Aliases": [
                       project + "-gateway-1", "gateway"]}}},
                   "Config": {"Env": [
            "PASSPORT_NATIVE_GATEWAY_ENABLED=true",
            "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=false",
            "ISSUANCE_SERVICE_URL=http://issuance-native:8005",
            "ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005"]}},
        "i" * 64: {"NetworkSettings": {"Networks": {private: {"Aliases": [
                       project + "-issuance-native-1", "issuance-native"]}}},
                   "Config": {"Env": [
            "PASSPORT_NATIVE_HTTP_ENABLED=true",
            "PASSPORT_KMS_CALLBACKS_ENABLED=true"]}},
    }


def cleanup(root: Path) -> None:
    assert root.parent == Path(tempfile.gettempdir())
    assert root.name.startswith("marty-passport-acceptance-selfhost-")
    for name in ("passport_acceptance_api_key",
                 "passport_acceptance_tenant_probe_api_key",
                 "workload_identity_ca_cert"):
        (root / "secrets" / name).unlink()
    (root / "secrets").rmdir()
    root.rmdir()


def application() -> dict:
    return {"organization_id": ORGANIZATION_ID, "issuer_did": issuer_did(29877),
            "flow_execution_id": "synthetic-flow", "application_template_id": "template",
            "credential_template_id": "credential",
            "delivery_destination_profile_id": "destination", "country_code": "USA",
            "applicant": {}, "mrz": {}, "data_groups": {"DG1": "YQ=="}}


def test_owned_https_probe_uses_same_job_private_receipt(monkeypatch) -> None:
    root, record = staged()
    opener = Opener()
    monkeypatch.setattr(probe.ssl, "create_default_context", lambda **kwargs: object())
    monkeypatch.setattr(probe, "build_opener", lambda *handlers: opener)
    edge = {"HostConfig": {"PortBindings": {"8443/tcp": [
        {"HostIp": "127.0.0.1", "HostPort": "29877"}]}},
        "NetworkSettings": {"Ports": {"8443/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "29877"}]},
            "Networks": {record["project"] + "_private": {"Aliases": ["edge"]}}}}
    containers = callback_containers(record["project"])
    try:
        report = probe.exercise_owned_disposable(
            record, "selfhost", application(), now=NOW,
            inspector=lambda args: json.dumps([
                edge if args[-1] == "e" * 64 else containers[args[-1]]]),
            ownership=lambda *args: {"live_ownership_verified": True},
            private_poll=lambda rec, surface, job, **kwargs: (
                200, {"status": "QUALITY_CHECK", "tracking_number": None,
                      "callback_receipt_sha256": "b" * 64}
            ) if job == BUREAU_ID else (404, {}),
            poll_interval_seconds=0,
        )
        assert report["verified"] is True
        assert report["flow_execution_verified"] is False
        assert report["evidence"]["signed_gateway_callback_verified"] is True
        assert report["evidence"]["unauthenticated_status"] == 403
        assert report["evidence"]["cross_tenant_status"] == 404
        assert report["evidence"]["tenant_capability_status"] == 200
        assert len(opener.requests) == 13
    finally:
        cleanup(root)


def test_wrong_disposable_issuer_fails_before_http(monkeypatch) -> None:
    root, record = staged()
    requests = []
    edge = {"HostConfig": {"PortBindings": {"8443/tcp": [
        {"HostIp": "127.0.0.1", "HostPort": "29877"}]}},
        "NetworkSettings": {"Ports": {"8443/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "29877"}]}}}
    monkeypatch.setattr(probe, "build_opener", lambda *args: requests.append(args))
    try:
        candidate = application()
        candidate["issuer_did"] = issuer_did(29878)
        with pytest.raises(probe.DisposableRouteProbeError, match="issuer scope"):
            probe.exercise_owned_disposable(
                record, "selfhost", candidate, now=NOW,
                inspector=lambda args: json.dumps([edge]),
                ownership=lambda *args: {"live_ownership_verified": True},
            )
        assert requests == []
    finally:
        cleanup(root)


@pytest.mark.parametrize("identifier,name,value", [
    ("b" * 64, "PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED", "false"),
    ("b" * 64, "PASSPORT_BUREAU_CALLBACK_URL",
     "http://issuance-native:8005/v1/passport/webhooks/personalization"),
    ("g" * 64, "PASSPORT_NATIVE_GATEWAY_ENABLED", "false"),
    ("g" * 64, "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED", "true"),
    ("g" * 64, "ISSUANCE_NATIVE_SERVICE_URL", "http://issuance:8005"),
    ("i" * 64, "PASSPORT_NATIVE_HTTP_ENABLED", "false"),
    ("i" * 64, "PASSPORT_KMS_CALLBACKS_ENABLED", "false"),
])
def test_running_gateway_callback_selectors_must_match_model(
    identifier: str, name: str, value: str,
) -> None:
    record = {"project": "marty-passport-acceptance-selfhost-test",
              "containers": {"passport-beta-bureau": "b" * 64,
                             "gateway": "g" * 64, "issuance-native": "i" * 64}}
    containers = callback_containers(record["project"])
    entries = containers[identifier]["Config"]["Env"]
    entries[:] = [f"{name}={value}" if entry.startswith(name + "=") else entry
                  for entry in entries]

    def inspector(args: list[str]) -> str:
        return json.dumps([containers[args[-1]]])

    with pytest.raises(probe.DisposableRouteProbeError,
                       match="callback routing drifted"):
        probe._gateway_callback_selected(record, inspector)


@pytest.mark.parametrize("defect", ["proxy", "extra_host", "gateway_alias_missing",
                                    "gateway_alias_duplicate"])
def test_running_gateway_callback_cannot_bypass_private_docker_dns(defect: str) -> None:
    project = "marty-passport-acceptance-selfhost-test"
    private = project + "_private"
    record = {"project": project, "containers": {
        "passport-beta-bureau": "b" * 64,
        "gateway": "g" * 64,
        "issuance-native": "i" * 64}}
    containers = callback_containers(project)
    if defect == "proxy":
        containers["b" * 64]["Config"]["Env"].append("HTTP_PROXY=http://issuance-native:8005")
    elif defect == "extra_host":
        containers["b" * 64]["HostConfig"]["ExtraHosts"] = ["gateway:10.0.0.9"]
    elif defect == "gateway_alias_missing":
        containers["g" * 64]["NetworkSettings"]["Networks"][private]["Aliases"] = []
    else:
        containers["b" * 64]["NetworkSettings"]["Networks"][private]["Aliases"].append(
            "gateway")

    def inspector(args: list[str]) -> str:
        return json.dumps([containers[args[-1]]])

    with pytest.raises(probe.DisposableRouteProbeError):
        probe._gateway_callback_selected(record, inspector)
