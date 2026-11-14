"""Protect resume diagnostics against stale readiness, false HTTP success and leaks."""
from __future__ import annotations

import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_kubernetes_dev_resume as check


def arguments():
    result = check.parser().parse_args([
        "--context", "explicit-dev", "--namespace", "active-app", "--origin", "https://192.0.2.20",
        "--instance-id", "i-0123456789abcdef0", "--region", "us-east-2",
        "--certificate-namespace", "certificate-owner",
    ])
    result.tls_store_namespace = result.certificate_namespace
    return result


def certificate():
    return {
        "metadata": {"generation": 11, "resourceVersion": "1234"},
        "spec": {"ipAddresses": ["192.0.2.20"], "secretName": "public-tls", "issuerRef": {"name": "existing-issuer"}},
        "status": {"conditions": [{"type": "Ready", "status": "True", "observedGeneration": 11}]},
    }


def workloads():
    result = []
    for name in sorted(check.CORE_DEPLOYMENTS | {"postgres", "redis"}):
        stateful = name in {"postgres", "redis"}
        container = {"name": name, "env": [{"name": "synthetic-private-value", "value": "never-include-this-in-report"}]}
        pod = {"containers": [container], "volumes": []}
        if name not in {"ui", "postgres"}:
            secret = "custom-" + name
            container["volumeMounts"] = [{"name": "identity", "mountPath": "/run/identity"}]
            pod["volumes"] = [{"name": "identity", "secret": {"secretName": secret}}]
            if name == "keycloak":
                container["env"].append({"name": "MARTY_KEYCLOAK_RS256_CERT_DIR", "value": "/run/identity"})
            elif name == "redis":
                container["args"] = ["--tls-cert-file", "/run/identity/tls.crt"]
            else:
                container["env"].append({"name": "GRPC_WORKLOAD_TLS_SERVER_CERT", "value": "/run/identity/tls.crt"})
                container["env"].append({"name": "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE", "value": "/run/identity/token"})
        result.append({"kind": "StatefulSet" if stateful else "Deployment", "metadata": {"name": name, "generation": 3},
                       "spec": {"replicas": 1, "template": {"spec": pod}},
                       "status": {"observedGeneration": 3, "readyReplicas": 1, "availableReplicas": 1,
                                  "replicas": 1, "updatedReplicas": 1, "currentRevision": "same", "updateRevision": "same"}})
    return result


def readiness():
    return {"service": "api-gateway", "status": "ready", "services": {
        name: {"status": "healthy"} for name in (
            "auth", "organizations", "credential-templates", "trust-profiles", "presentation-policies",
            "deployment-profiles", "signing-keys", "flows", "issuance-native",
        )
    }}


class ObservedPreflight(check.Preflight):
    """Public fake Kubernetes observations; no network or credentials required."""
    def __init__(self):
        super().__init__(arguments())
        self.objects = {
            "certificate.cert-manager.io": certificate(),
            "tlsstore.traefik.io": {"spec": {"defaultCertificate": {"secretName": "public-tls"}}},
            "issuer.cert-manager.io": {"metadata": {"generation": 2}, "status": {
                "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 2}]}},
            "configmap": b"https://192.0.2.20\nhttps://192.0.2.20",
            "ingress": {"metadata": {"annotations": {"traefik.ingress.kubernetes.io/router.tls": "true"}},
                        "spec": {"ingressClassName": "traefik", "tls": [{"secretName": "old-copy"}]}},
            "deployments,statefulsets": {"items": workloads()},
        }
        self.expired = set()
        self.peer = "a" * 64

    def get(self, namespace, resource, name="", **_kwargs):
        return copy.deepcopy(self.objects[resource])

    def ec2(self):
        return {"publicIp": self.host}

    def leaf(self, namespace, name, field="tls.crt"):
        # The copied ingress certificate is stale, while the actual default is current.
        fingerprint = "b" * 64 if name == "old-copy" else "a" * 64
        end = time.time() - 10 if name == "old-copy" or name in self.expired else time.time() + 7200
        return check.Leaf(fingerprint, time.time() - 100, end)

    def https(self):
        return {"sha256": self.peer, "httpStatus": 200, "contentType": "application/json", "body": json.dumps(readiness()).encode()}


def test_current_tls_with_stale_copy_is_warning_and_never_qualifies_demo():
    report = ObservedPreflight().run()
    assert report["status"] == "ready-for-authenticated-check"
    assert report["demoQualified"] is False
    assert any(item["check"] == "ingress_certificate_copy" and item["status"] == "warn" for item in report["checks"])
    assert report["checks"][-1]["status"] == "not_checked"
    encoded = json.dumps(report)
    assert "never-include-this-in-report" not in encoded
    assert "TOKEN_FILE" not in encoded
    assert "BEGIN CERTIFICATE" not in encoded


@pytest.mark.parametrize("change", ["old_generation", "old_issuer_generation", "old_ip", "wrong_store", "different_served_leaf", "expired_internal_leaf"])
def test_observed_resume_failures_block_with_specific_stage(change):
    preflight = ObservedPreflight()
    if change == "old_generation":
        preflight.objects["certificate.cert-manager.io"]["status"]["conditions"][0]["observedGeneration"] = 10
    elif change == "old_issuer_generation":
        preflight.objects["issuer.cert-manager.io"]["status"]["conditions"][0]["observedGeneration"] = 1
    elif change == "old_ip":
        preflight.objects["certificate.cert-manager.io"]["spec"]["ipAddresses"] = ["192.0.2.19"]
    elif change == "wrong_store":
        preflight.objects["tlsstore.traefik.io"]["spec"]["defaultCertificate"]["secretName"] = "wrong-owner"
    elif change == "different_served_leaf":
        preflight.peer = "c" * 64
    else:
        preflight.expired.add("custom-auth")
    report = preflight.run()
    assert report["status"] == "blocked"
    failed = [item for item in report["checks"] if item["status"] == "fail"]
    expected = ("served_certificate_owner" if change == "different_served_leaf" else
                "public_leaf_lifetime:custom-auth/tls.crt" if change == "expired_internal_leaf" else "public_certificate_owner")
    assert any(item["check"] == expected and item["action"] for item in failed)


@pytest.mark.parametrize("status,content_type,body", [
    (200, "text/html", b"<html>UI shell</html>"),
    (302, "application/json", b"{}"),
    (503, "application/json", b"{}"),
    (200, "application/json", b'{"status":"healthy"}'),
    (200, "application/json", b'{"status":"ready","service":"api-gateway","services":{}}'),
])
def test_http_success_cannot_substitute_for_gateway_readiness(status, content_type, body):
    with pytest.raises(check.CheckError):
        check.readiness_contract(status, content_type, body)


def test_gateway_contract_requires_healthy_core_dependencies():
    body = readiness()
    assert check.readiness_contract(200, "application/json; charset=utf-8", json.dumps(body).encode())["healthyServices"] == 9
    body["services"]["auth"]["status"] = "unhealthy"
    with pytest.raises(check.CheckError, match="unhealthy"):
        check.readiness_contract(200, "application/json", json.dumps(body).encode())


def test_legacy_issuance_alias_cannot_replace_required_native_owner():
    body = readiness()
    body["services"]["issuance"] = body["services"].pop("issuance-native")
    with pytest.raises(check.CheckError, match="omits core"):
        check.readiness_contract(200, "application/json", json.dumps(body).encode())


@pytest.mark.parametrize("mutate", [
    lambda items: items.pop(next(index for index, item in enumerate(items) if item["metadata"]["name"] == "auth")),
    lambda items: items[0]["status"].update(observedGeneration=2),
    lambda items: items[0]["status"].update(updatedReplicas=0),
    lambda items: items[0]["status"].update(readyReplicas=0),
    lambda items: items[0]["spec"].update(replicas=0),
])
def test_workload_readiness_requires_present_current_ready_revisions(mutate):
    items = workloads()
    mutate(items)
    with pytest.raises(check.CheckError):
        check.workload_readiness(items)


def test_public_leaf_projection_follows_actual_secret_names_and_omits_tokens():
    targets = check.public_cert_targets(workloads())
    assert ("custom-auth", "tls.crt") in targets
    assert ("custom-keycloak", "keycloak-11id-rs256.crt") in targets
    assert ("custom-redis", "tls.crt") in targets
    assert all(field in check.PUBLIC_LEAF_KEYS for _, field in targets)
    items = workloads()
    auth = next(item for item in items if item["metadata"]["name"] == "auth")
    auth["spec"]["template"]["spec"]["volumes"][0]["secret"]["items"] = [{"key": "token", "path": "tls.crt"}]
    with pytest.raises(check.CheckError, match="public certificate fields"):
        check.public_cert_targets(items)


def test_public_leaf_projection_rejects_subpath_and_missing_core_identity():
    items = workloads()
    pod = next(item for item in items if item["metadata"]["name"] == "auth")["spec"]["template"]["spec"]
    pod["containers"][0]["volumeMounts"][0]["subPath"] = "tls.crt"
    with pytest.raises(check.CheckError, match="subPath"):
        check.public_cert_targets(items)
    pod["containers"][0]["env"] = []
    with pytest.raises(check.CheckError, match="core workload"):
        check.public_cert_targets(items)


def test_command_output_and_runtime_are_bounded_without_echoing_failure():
    runner = check.BoundedRunner(2, 1)
    with pytest.raises(check.CheckError, match="output limit"):
        runner.run([sys.executable, "-c", "print('x'*100000)"], limit=1024)
    with pytest.raises(check.CheckError) as failure:
        runner.run([sys.executable, "-c", "import sys; sys.stderr.write('private-error-sentinel'); sys.exit(1)"])
    assert "private-error-sentinel" not in str(failure.value)
    with pytest.raises(check.CheckError, match="deadline"):
        check.BoundedRunner(0.1, 0.1).run([sys.executable, "-c", "import time; time.sleep(5)"])
    with pytest.raises(check.CheckError, match="deadline"):
        with check.network_deadline(0.05):
            time.sleep(5)


@pytest.fixture(scope="module")
def public_certificate(tmp_path_factory):
    root = tmp_path_factory.mktemp("public-preflight-certificate")
    cert, key = root / "public.crt", root / "synthetic-test.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=preflight-test",
                    "-addext", "subjectAltName=IP:127.0.0.1"], capture_output=True, check=True, timeout=10)
    return cert, key


def test_public_secret_field_selection_and_real_x509_parsing(monkeypatch, public_certificate):
    pem = public_certificate[0].read_bytes()
    runner = check.BoundedRunner(5, 3)
    parsed = check.parse_leaf(pem, runner, "openssl")
    check.check_lifetime(parsed, time.time(), 3600)
    preflight = check.Preflight(arguments())
    captured = []
    original = preflight.runner.run
    def run(argv, **kwargs):
        if "get" in argv:
            captured.append(argv)
            return base64.b64encode(pem)
        return original(argv, **kwargs)
    monkeypatch.setattr(preflight.runner, "run", run)
    assert preflight.leaf("active-app", "custom-auth").fingerprint == parsed.fingerprint
    assert captured[0][-2:] == ["-o", 'go-template={{index .data "tls.crt"}}']
    with pytest.raises(check.CheckError, match="public certificate fields"):
        preflight.leaf("active-app", "custom-auth", "token")
    assert len(captured) == 1
    with pytest.raises(check.CheckError, match="private material"):
        check.parse_leaf(pem + b"-----BEGIN PRIVATE KEY-----", runner, "openssl")


def test_real_https_requires_trust_and_verifies_ip_before_readiness(monkeypatch, public_certificate):
    cert, key = public_certificate
    body = json.dumps(readiness()).encode()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.path == "/health/ready"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        args = arguments()
        args.origin = "https://127.0.0.1:" + str(server.server_port)
        preflight = check.Preflight(args)
        with pytest.raises(check.CheckError, match="normal trust"):
            preflight.https()
        original_context = ssl.create_default_context
        monkeypatch.setattr(ssl, "create_default_context", lambda: original_context(cafile=str(cert)))
        response = preflight.https()
        assert response["sha256"] == check.parse_leaf(cert.read_bytes(), preflight.runner, "openssl").fingerprint
        assert check.readiness_contract(response["httpStatus"], response["contentType"], response["body"])["healthyServices"] == 9

        # Route another requested IP to the same local fixture, as if an ingress
        # served a trusted certificate for its previous address. Trust alone
        # must not allow that connection: the requested IP SAN still differs.
        original_connect = socket.create_connection
        def connect_fixture(address, *positional, **keywords):
            return original_connect(("127.0.0.1", address[1]), *positional, **keywords)
        monkeypatch.setattr(socket, "create_connection", connect_fixture)
        args.origin = "https://192.0.2.20:" + str(server.server_port)
        with pytest.raises(check.CheckError, match="IP SAN verification"):
            check.Preflight(args).https()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ec2_origin_mismatch_blocks_even_with_previous_ready_certificate(monkeypatch):
    preflight = check.Preflight(arguments())
    observed = [{"InstanceId": preflight.args.instance_id, "State": "running", "PublicIp": "192.0.2.21"}]
    monkeypatch.setattr(preflight.runner, "run", lambda *_args, **_kwargs: json.dumps(observed).encode())
    with pytest.raises(check.CheckError, match="current public IPv4"):
        preflight.ec2()


@pytest.mark.parametrize("context", ["", " \t "])
def test_empty_context_is_rejected_before_any_observation(monkeypatch, capsys, context):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Invalid context must be rejected before constructing the observation or doing I/O")
    monkeypatch.setattr(check, "Preflight", forbidden)
    with pytest.raises(SystemExit) as failure:
        check.main([
            "--context", context, "--namespace", "active-app", "--origin", "https://192.0.2.20",
            "--instance-id", "i-0123456789abcdef0", "--region", "us-east-2",
            "--certificate-namespace", "certificate-owner",
        ])
    assert failure.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert "Invalid preflight input" in output.err


@pytest.mark.parametrize("origin", ["http://192.0.2.20", "https://name.example.test", "https://user:password@192.0.2.20", "https://192.0.2.20/path"])
def test_origin_is_explicit_https_ip_without_private_components(origin):
    with pytest.raises(check.CheckError):
        check.parse_origin(origin)
