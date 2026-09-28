"""Supported passport evidence remains blocked without disposable live acceptance."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import ssl
from threading import Thread

import pytest
import yaml

from scripts import collect_passport_supported_acceptance as gate
from scripts.passport_supported_infra_images import qualified_images
from scripts.stage_passport_disposable_tls import stage_tls


COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
REFERENCE = "ghcr.io/elevenid/marty-ui-oss/services@" + DIGEST
BASE = "marty-passport-acceptance-base-abcdef"
SELFHOST = "marty-passport-acceptance-selfhost-abcdef"
NAMESPACE = "marty-passport-acceptance-abcdef"
CONTEXT = "marty-passport-acceptance-testxyz"


def manifest(tmp_path: Path) -> Path:
    path = tmp_path / "stack-manifest.json"
    path.write_text(json.dumps({
        "schema": "marty.stack/v1", "release": "marty-ui@1.2.3",
        "components": [{"name": "marty-ui", "repository": "ElevenID/marty-ui",
                        "commit": COMMIT, "artifacts": [
                            {"type": "oci", "uri": f"ghcr.io/elevenid/marty-ui-oss/{role}",
                             "digest": "sha256:" + letter * 64}
                            for role, letter in (("ui", "c"), ("services", "b"),
                                                 ("migrations", "d"))
                        ]}],
    }), encoding="utf-8")
    return path


@pytest.mark.parametrize("surface,target", [
    ("base", "marty-selfhost-prod"),
    ("base", "elevenid-beta"),
    ("selfhost", "marty-passport-acceptance-base-abcdef"),
    ("kubernetes", "marty-prod"),
    ("kubernetes", "default"),
])
def test_production_and_wrong_disposable_targets_are_rejected(
    tmp_path: Path, surface: str, target: str
) -> None:
    kwargs = {"base": "base_project", "selfhost": "selfhost_project",
              "kubernetes": "namespace"}
    with pytest.raises(gate.SupportedEvidenceError, match="disposable"):
        gate.collect(manifest(tmp_path), COMMIT, **{kwargs[surface]: target},
                     kubernetes_context=CONTEXT if surface == "kubernetes" else None,
                     attest=lambda *args: True)


def test_production_origin_is_rejected_before_runtime_probe(tmp_path: Path) -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="loopback"):
        gate.collect(manifest(tmp_path), COMMIT,
                     base_origin="https://elevenidllc.com", attest=lambda *args: True)


def docker_runner(project: str, *, wrong_image: bool = False):
    def run(args: list[str]) -> str:
        if args[:2] == ["docker", "ps"]:
            service = args[-1].split("=")[-1]
            return service + "-container\n"
        service = args[-1].removesuffix("-container")
        flags = [f"{name}=true" for name in gate.COMPOSE_FLAGS.get(service, ())]
        image = (qualified_images(verify_registry=False)["edge"]
                 if service == "edge" else REFERENCE)
        edge_binding = [{"HostIp": "127.0.0.1", "HostPort": "28000"}]
        record = {
            "Image": "sha256:" + "e" * 64,
            "Config": {
                "Image": ("ghcr.io/other/unreleased@" + DIGEST)
                if wrong_image else image,
                "Labels": {"com.docker.compose.project": project,
                           "com.docker.compose.service": service},
                "Env": flags,
            },
            "State": {"Running": True, "Status": "running",
                      "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Ports": {"8443/tcp": edge_binding}}
            if service == "edge" else {"Ports": {}},
            "HostConfig": {"PortBindings": {"8443/tcp": edge_binding}}
            if service == "edge" else {"PortBindings": {}},
        }
        return json.dumps([record])
    return run


def test_compose_runtime_reads_five_exact_running_service_images() -> None:
    observed = gate.observe_compose("base", BASE, REFERENCE, docker_runner(BASE))
    assert set(observed) == set(gate.COMPOSE_SERVICES) | {"edge"}
    assert all(item["oci_reference"] == REFERENCE
               for service, item in observed.items() if service != "edge")
    assert observed["edge"]["oci_reference"] == qualified_images(
        verify_registry=False)["edge"]
    with pytest.raises(gate.SupportedEvidenceError, match="released services image"):
        gate.observe_compose("base", BASE, REFERENCE, docker_runner(BASE, wrong_image=True))


def test_disposable_https_capability_probe_uses_scoped_ca(tmp_path: Path) -> None:
    stage_tls(tmp_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == "/v1/passport/capabilities"
            body = b'{"supported":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(tmp_path / "passport_edge_tls_cert"),
                            str(tmp_path / "passport_edge_tls_key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"https://localhost:{server.server_port}"
        with pytest.raises(gate.SupportedEvidenceError, match="no CA"):
            gate.capability_status(origin, None)
        assert gate.capability_status(
            origin, None, tmp_path / "workload_identity_ca_cert"
        ) == (200, {"supported": True})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_missing_targets_and_runtime_proof_remain_blocked(tmp_path: Path) -> None:
    report = gate.collect(manifest(tmp_path), COMMIT, attest=lambda *args: True)
    assert report["status"] == "blocked"
    assert set(report["surfaces"]) == {"base", "selfhost", "kubernetes"}
    assert all(surface["runtime_accepted"] is False
               and surface["rollback_accepted"] is False
               for surface in report["surfaces"].values())


def test_live_compose_prerequisite_still_does_not_claim_routes_or_rollback(
    tmp_path: Path
) -> None:
    report = gate.collect(
        manifest(tmp_path), COMMIT, base_project=BASE,
        compose_probe=lambda name, project, image: {
            "gateway": {"oci_reference": image, "container_id": "gateway-container"}
        },
        attest=lambda *args: True,
    )
    base = report["surfaces"]["base"]
    assert base["probes"]["released_image"]["verified"] is True
    assert base["probes"]["released_image"]["evidence"] == {
        "oci_reference": REFERENCE,
        "source_commit": COMMIT,
        "container_id": "gateway-container",
    }
    assert base["probes"]["nine_route_gateway_flow"]["verified"] is False
    assert base["probes"]["signed_bureau_callback"]["verified"] is False
    assert base["rollback_accepted"] is False
    assert report["status"] == "blocked"
    assert report["physical_claim"] == "not_claimed"


def test_kubernetes_inspection_is_bounded_to_disposable_namespace() -> None:
    def run(args: list[str]) -> str:
        assert args[1:5] == ["--context", CONTEXT, "-n", NAMESPACE]
        if args[6] == "configmap":
            return json.dumps({"data": {flag: "true" for names in gate.KUBERNETES_FLAGS.values()
                                        for flag in names}})
        if args[6] == "pods":
            service = args[8].removeprefix("app=")
            return json.dumps({"items": [{
                "metadata": {"namespace": NAMESPACE, "uid": service + "-pod"},
                "status": {"phase": "Running", "containerStatuses": [{
                    "ready": True, "imageID": "docker-pullable://" + REFERENCE,
                    "containerID": "containerd://" + service + "-container",
                }]},
            }]})
        service = args[7]
        return json.dumps({
            "metadata": {"namespace": NAMESPACE, "uid": service + "-uid"},
            "status": {"readyReplicas": 1},
            "spec": {"template": {"spec": {"containers": [{
                "image": REFERENCE,
                "env": [{"name": flag, "value": "true"} for flag in gate.KUBERNETES_FLAGS[service]],
            }]}}},
        })
    observed = gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, run)
    assert set(observed) == set(gate.KUBERNETES_SERVICES)


def test_capability_origin_must_match_inspected_gateway_port(tmp_path: Path) -> None:
    called = []
    report = gate.collect(
        manifest(tmp_path), COMMIT, base_project=BASE,
        base_origin="https://localhost:28001", api_key="private",
        compose_probe=lambda *args: {"gateway": {
            "oci_reference": REFERENCE,
            "container_id": "gateway-container",
        }, "edge": {"loopback_port": 28000}},
        capability_probe=lambda *args: called.append(args),
        attest=lambda *args: True,
    )
    assert called == []
    assert "capabilities_http" not in report["surfaces"]["base"]
    assert report["surfaces"]["base"]["blocker"] == (
        "probe origin is not bound to the inspected HTTPS edge"
    )


def test_duplicate_released_oci_role_is_rejected(tmp_path: Path) -> None:
    path = manifest(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["components"][0]["artifacts"].append(data["components"][0]["artifacts"][0])
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(gate.SupportedEvidenceError, match="image roles"):
        gate.collect(path, COMMIT, attest=lambda *args: True)


def test_protected_workflow_is_read_only_and_artifact_matches_verifier() -> None:
    path = gate.ROOT / ".github/workflows/passport-supported-consumer-acceptance.yml"
    source = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(source)
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch"}
    job = workflow["jobs"]["collect"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    steps = job["steps"]
    upload = steps[-1]
    assert steps[-2]["id"] == "collect"
    assert 'rm -f "$report"' in steps[-2]["run"]
    assert '.status == "accepted"' in steps[-2]["run"]
    assert upload["if"] == (
        "always() && (steps.collect.outcome == 'success' || "
        "steps.collect.outcome == 'failure')"
    )
    assert upload["with"]["name"] == (
        "passport-supported-consumer-acceptance-${{ github.run_id }}"
    )
    assert upload["with"]["path"] == (
        "passport-supported-consumer-acceptance-${{ github.run_id }}.json"
    )
    assert "--exercise-kubernetes-rollback" not in source
    assert "docker compose up" not in source
    assert "kubectl set env" not in source
