#!/usr/bin/env python3
"""Read-only preflight for an existing AWS/K3s IP-based development installation.

This is an observation, not a credential renewal or authenticated demo test.
Only public certificate fields are emitted by kubectl; tokens, private keys,
Secret manifests, subprocess stderr and HTTP response bodies are never reported.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import PurePosixPath
import re
import selectors
import signal
import ssl
import subprocess
import time
from urllib.parse import urlsplit


SCHEMA = "marty.kubernetes-dev-resume-preflight/v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CERT_BYTES = 64 * 1024
PUBLIC_LEAF_KEYS = {"tls.crt", "keycloak-master-rs256.crt", "keycloak-11id-rs256.crt"}
CORE_DEPLOYMENTS = {"ui", "gateway", "auth", "keycloak", "issuance-native", "verification", "signing-keys"}
CORE_READY_SERVICES = {"auth", "organizations", "credential-templates", "trust-profiles",
                       "presentation-policies", "deployment-profiles", "signing-keys", "flows", "issuance"}
RESUME_GUIDE = "docs/kubernetes-ui-live-reload.md#resume-an-existing-development-installation"
CREDENTIAL_GUIDE = "docs/kubernetes-installation-configuration.md#resume-a-stopped-development-node"


class CheckError(Exception):
    """A diagnostic safe to print; never wrap raw command output in this class."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckError(message)


def valid_name(value: str) -> str:
    require(isinstance(value, str) and bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value)),
            "Expected a Kubernetes resource name.")
    return value


def parse_origin(value: str) -> tuple[str, int]:
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and not parsed.username and not parsed.password
            and not parsed.path and not parsed.query and not parsed.fragment,
            "Origin must be an HTTPS origin without credentials, path, query or fragment.")
    try:
        host = str(ipaddress.IPv4Address(parsed.hostname or ""))
        port = parsed.port or 443
    except ValueError as error:
        raise CheckError("This AWS development preflight requires a literal IPv4 origin and valid port.") from error
    require(value in {f"https://{host}", f"https://{host}:{port}"} and 0 < port < 65536,
            "Origin must use its canonical IPv4 address and a valid port.")
    return host, port


class BoundedRunner:
    """Bound subprocess time, stdout and descendants; discard untrusted stderr."""

    def __init__(self, total_seconds: float, request_seconds: float):
        self.deadline = time.monotonic() + total_seconds
        self.request_seconds = request_seconds

    def remaining(self) -> float:
        remaining = min(self.request_seconds, self.deadline - time.monotonic())
        require(remaining > 0, "The preflight deadline was reached; no readiness claim was made.")
        return remaining

    def run(self, argv: list[str], *, data: bytes = b"", limit: int = MAX_JSON_BYTES) -> bytes:
        deadline = time.monotonic() + self.remaining()
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError as error:
            raise CheckError("A required executable could not start; check the documented prerequisites.") from error
        output = bytearray()
        pending = memoryview(data)
        try:
            with selectors.DefaultSelector() as selector:
                assert process.stdout is not None
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                if process.stdin is not None:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "A command exceeded the bounded request deadline.")
                    for key, _ in selector.select(remaining):
                        if key.fileobj is process.stdin:
                            try:
                                pending = pending[os.write(key.fd, pending[:4096]):]
                            except BrokenPipeError:
                                pending = memoryview(b"")
                            if not pending:
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                        else:
                            chunk = os.read(key.fd, 8192)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            else:
                                output.extend(chunk)
                                require(len(output) <= limit, "A command exceeded the bounded output limit.")
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            require(process.returncode == 0,
                    "A read-only command failed; check context, connectivity, permissions and resource names. Raw output is withheld.")
            return bytes(output)
        except subprocess.TimeoutExpired as error:
            raise CheckError("A command exceeded the bounded request deadline.") from error
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stdin is not None:
                process.stdin.close()


@contextmanager
def network_deadline(seconds: float):
    """A wall-clock bound also stops a peer that drips headers or response bytes."""
    def expired(_signum, _frame):
        raise CheckError("The verified HTTPS probe exceeded its bounded request deadline.")
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


@dataclass(frozen=True)
class Leaf:
    fingerprint: str
    not_before: float
    not_after: float

    def evidence(self) -> dict:
        return {"sha256": self.fingerprint,
                "notAfter": datetime.fromtimestamp(self.not_after, timezone.utc).isoformat()}


def parse_leaf(pem: bytes, runner: BoundedRunner, openssl: str) -> Leaf:
    require(0 < len(pem) <= MAX_CERT_BYTES and b"PRIVATE KEY" not in pem,
            "The selected public certificate is empty, oversized or contains private material.")
    match = re.search(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----", pem)
    require(match is not None, "The selected public certificate is not PEM encoded.")
    assert match is not None
    leaf = match.group(0)
    dates = runner.run([openssl, "x509", "-noout", "-startdate", "-enddate"], data=leaf, limit=1024)
    fields = dict(line.split("=", 1) for line in dates.decode("ascii").splitlines())
    return Leaf(hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.decode("ascii"))).hexdigest(),
                ssl.cert_time_to_seconds(fields["notBefore"]), ssl.cert_time_to_seconds(fields["notAfter"]))


def check_lifetime(leaf: Leaf, now: float, minimum: int) -> None:
    require(leaf.not_before <= now, "The public certificate is not valid yet; check the clock and its issuer.")
    require(leaf.not_after > now, "The public certificate has expired.")
    require(leaf.not_after - now >= minimum, "The public certificate expires before the requested testing window ends.")


def certificate_is_current(certificate: dict, host: str) -> dict:
    generation = certificate["metadata"]["generation"]
    ready = [item for item in certificate.get("status", {}).get("conditions", []) if item.get("type") == "Ready"]
    require(type(generation) is int and len(ready) == 1 and ready[0].get("status") == "True"
            and ready[0].get("observedGeneration") == generation,
            "The Certificate does not have Ready=True for its current generation; an older Ready condition is insufficient.")
    require(host in certificate["spec"].get("ipAddresses", []),
            "The current EC2 IP is absent from the public Certificate's requested IP SANs.")
    return {"generation": generation, "resourceVersion": certificate["metadata"]["resourceVersion"]}


def workload_readiness(workloads: list[dict]) -> dict:
    names = {item["metadata"]["name"] for item in workloads if item["kind"] == "Deployment"}
    missing = sorted(CORE_DEPLOYMENTS - names)
    require(not missing, "Core Deployments are missing from the selected release: " + ", ".join(missing))
    statefulsets = {item["metadata"]["name"] for item in workloads if item["kind"] == "StatefulSet"}
    require({"postgres", "redis"} <= statefulsets, "The selected release is missing its postgres or redis StatefulSet.")
    unready = []
    for item in workloads:
        name = valid_name(item["metadata"]["name"])
        status, spec = item.get("status", {}), item["spec"]
        desired = spec.get("replicas", 1)
        current = (type(desired) is int and desired > 0
                   and status.get("observedGeneration", 0) >= item["metadata"]["generation"]
                   and status.get("readyReplicas", 0) == desired
                   and status.get("updatedReplicas", 0) == desired
                   and status.get("replicas", 0) == desired)
        if item["kind"] == "Deployment":
            current = current and status.get("availableReplicas", 0) == desired
        elif item["kind"] == "StatefulSet":
            current = current and bool(status.get("currentRevision")) and status.get("currentRevision") == status.get("updateRevision")
        if not current:
            unready.append(name)
    require(not unready, "Workloads are not fully ready at their current revision: " + ", ".join(sorted(unready)))
    return {"deployments": len(names), "statefulsets": len(statefulsets)}


def public_cert_projection(pod: dict, container: dict, filename: str) -> tuple[str, str]:
    """Resolve only a supported public leaf path through the actual mounted Secret."""
    file_path = PurePosixPath(filename)
    require(file_path.is_absolute() and ".." not in file_path.parts,
            "A public certificate path is outside the supported Secret projection.")
    volumes = {volume["name"]: volume for volume in pod.get("volumes", [])}
    candidates = []
    for mount in container.get("volumeMounts", []):
        mount_path = PurePosixPath(mount["mountPath"])
        if file_path == mount_path or mount_path in file_path.parents:
            candidates.append((len(mount_path.parts), mount, file_path.relative_to(mount_path)))
    require(bool(candidates), "A configured public leaf has no matching Secret mount.")
    _, mount, relative = max(candidates, key=lambda entry: entry[0])
    require(not mount.get("subPath") and not mount.get("subPathExpr"),
            "A public certificate uses a subPath mount; this preflight cannot establish its current projected bytes.")
    secret = volumes[mount["name"]].get("secret", {})
    name = valid_name(secret.get("secretName", ""))
    path = str(relative)
    keys = [item["key"] for item in secret.get("items", []) if item["path"] == path]
    if "items" not in secret:
        keys = [path]
    require(len(keys) == 1 and keys[0] in PUBLIC_LEAF_KEYS,
            "A configured leaf is not one of the supported public certificate fields; inspect its projection manually.")
    return name, keys[0]


def public_cert_targets(workloads: list[dict]) -> dict[tuple[str, str], list[str]]:
    targets: dict[tuple[str, str], list[str]] = {}
    keycloak_seen = False
    for item in workloads:
        pod = item["spec"]["template"]["spec"]
        for container in pod.get("containers", []):
            paths = []
            for entry in container.get("env", []):
                name = entry["name"]
                if "TLS" in name and re.search(r"(?:^|_)CERT(?:_FILE)?$", name) and "CA_CERT" not in name:
                    require(isinstance(entry.get("value"), str), "A workload leaf path is indirect; inspect its public projection manually.")
                    paths.append(entry["value"])
                if name == "MARTY_KEYCLOAK_RS256_CERT_DIR":
                    directory = entry.get("value", "")
                    require(bool(directory), "The Keycloak public certificate directory is not explicit.")
                    paths += [str(PurePosixPath(directory) / key) for key in sorted(PUBLIC_LEAF_KEYS) if key.startswith("keycloak-")]
                    keycloak_seen = True
            args = container.get("args", [])
            if "--tls-cert-file" in args:
                paths.append(args[args.index("--tls-cert-file") + 1])
            for path in paths:
                target = public_cert_projection(pod, container, path)
                targets.setdefault(target, []).append(valid_name(item["metadata"]["name"]))
    require(keycloak_seen and any(key == "tls.crt" for _, key in targets),
            "Workload or Keycloak public leaf projections were not found; no internal lifetime claim can be made.")
    consumers = {name for names in targets.values() for name in names}
    require(CORE_DEPLOYMENTS - {"ui"} <= consumers,
            "A core workload has no supported public leaf projection; inspect its configured identity before testing.")
    require(len(targets) <= 64, "Too many public certificate projections for this bounded development preflight.")
    return {key: sorted(set(value)) for key, value in targets.items()}


def readiness_contract(status: int, content_type: str, body: bytes) -> dict:
    require(status == 200, f"The gateway readiness route returned HTTP {status}; redirects are not followed.")
    require(content_type.split(";", 1)[0].strip().lower() == "application/json",
            "The readiness route did not return JSON; an HTML UI response is not gateway readiness.")
    value = json.loads(body)
    require(isinstance(value, dict) and value.get("service") == "api-gateway" and value.get("status") == "ready",
            "The response does not identify a ready API gateway.")
    services = value.get("services", {})
    require(isinstance(services, dict) and CORE_READY_SERVICES <= set(services),
            "The gateway readiness response omits core development services.")
    require(all(isinstance(entry, dict) and entry.get("status") == "healthy" for entry in services.values()),
            "The gateway reports an unhealthy required service.")
    return {"healthyServices": len(services)}


class Preflight:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.host, self.port = parse_origin(args.origin)
        self.runner = BoundedRunner(args.timeout_seconds, args.request_timeout_seconds)
        self.checks: list[dict] = []
        self.leaves: dict[tuple[str, str, str], Leaf] = {}

    def check(self, name: str, action: str, function):
        try:
            evidence = function()
            self.checks.append({"check": name, "status": "pass", "evidence": evidence or {}})
            return evidence
        except CheckError as error:
            self.checks.append({"check": name, "status": "fail", "message": str(error), "action": action})
        except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, http.client.HTTPException):
            self.checks.append({"check": name, "status": "fail",
                                "message": "The observation failed or its response had an unsupported shape; raw output is withheld.",
                                "action": action})
        return None

    def get(self, namespace: str, resource: str, name: str = "", *, output: str = "json", selector: str = ""):
        command = [self.args.kubectl, "--context", self.args.context,
                   "--request-timeout", f"{max(1, math.ceil(self.runner.remaining()))}s", "-n", namespace, "get", resource]
        if name:
            command.append(valid_name(name))
        if selector:
            command += ["-l", selector]
        raw = self.runner.run(command + ["-o", output], limit=MAX_CERT_BYTES * 2 if output != "json" else MAX_JSON_BYTES)
        if output != "json":
            return raw
        value = json.loads(raw)
        require(isinstance(value, dict), "Kubernetes returned an unsupported object shape.")
        return value

    def leaf(self, namespace: str, name: str, field: str = "tls.crt") -> Leaf:
        require(field in PUBLIC_LEAF_KEYS, "Only supported public certificate fields may be selected.")
        key = namespace, name, field
        if key not in self.leaves:
            # Never capture Secret JSON: kubectl emits this one public field only.
            value = self.get(namespace, "secret", name, output='go-template={{index .data "' + field + '"}}')
            pem = base64.b64decode(value.strip(), validate=True)
            self.leaves[key] = parse_leaf(pem, self.runner, self.args.openssl)
        return self.leaves[key]

    def ec2(self) -> dict:
        raw = self.runner.run([self.args.aws, "--region", self.args.region, "--cli-connect-timeout", "5",
                               "--cli-read-timeout", "5", "ec2", "describe-instances", "--instance-ids", self.args.instance_id,
                               "--query", "Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name,PublicIp:PublicIpAddress}",
                               "--output", "json", "--no-cli-pager"], limit=8192)
        instances = json.loads(raw)
        require(isinstance(instances, list) and len(instances) == 1
                and instances[0].get("InstanceId") == self.args.instance_id,
                "The EC2 read did not identify exactly the requested instance.")
        instance = instances[0]
        require(instance.get("State") == "running", "The existing EC2 instance is not running.")
        require(instance.get("PublicIp") == self.host,
                "The requested HTTPS origin does not match the instance's current public IPv4 address.")
        return {"instanceId": self.args.instance_id, "publicIp": self.host, "region": self.args.region}

    def public_owner(self) -> dict:
        args = self.args
        certificate = self.get(args.certificate_namespace, "certificate.cert-manager.io", args.certificate)
        evidence = certificate_is_current(certificate, self.host)
        secret = valid_name(certificate["spec"]["secretName"])
        store = self.get(args.tls_store_namespace, "tlsstore.traefik.io", "default")
        require(args.tls_store_namespace == args.certificate_namespace
                and store["spec"].get("defaultCertificate", {}).get("secretName") == secret
                and not store["spec"].get("defaultGeneratedCert"),
                "The expected default TLSStore does not have this Certificate's Secret as its sole default certificate owner.")
        issuer_ref = certificate["spec"]["issuerRef"]
        require(issuer_ref.get("group", "cert-manager.io") == "cert-manager.io"
                and issuer_ref.get("kind", "Issuer") in {"Issuer", "ClusterIssuer"},
                "The public Certificate has an unsupported issuer reference.")
        issuer = self.get(args.certificate_namespace, issuer_ref.get("kind", "Issuer").lower() + ".cert-manager.io", issuer_ref["name"])
        require(type(issuer.get("metadata", {}).get("generation")) is int
                and any(item.get("type") == "Ready" and item.get("status") == "True"
                        and item.get("observedGeneration") == issuer["metadata"]["generation"]
                    for item in issuer.get("status", {}).get("conditions", [])),
                "The existing public certificate Issuer is not Ready at its current generation.")
        leaf = self.leaf(args.certificate_namespace, secret)
        check_lifetime(leaf, time.time(), args.minimum_validity_seconds)
        return {**evidence, "namespace": args.certificate_namespace, "certificate": args.certificate,
                "secret": secret, "tlsStore": args.tls_store_namespace + "/default", **leaf.evidence()}

    def origin_config(self) -> dict:
        # These values are public routing configuration; do not dump the ConfigMap.
        values = self.get(self.args.namespace, "configmap", "marty-config",
                          output='go-template={{index .data "PUBLIC_API_URL"}}{{"\\n"}}{{index .data "KC_HOSTNAME"}}')
        require(values.decode("utf-8").splitlines() == [self.args.origin, self.args.origin],
                "PUBLIC_API_URL or KC_HOSTNAME differs from the browser origin.")
        return {"origin": self.args.origin}

    def https(self) -> dict:
        with network_deadline(self.runner.remaining()):
            return self._https()

    def _https(self) -> dict:
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.runner.remaining(),
                                                 context=ssl.create_default_context())
        try:
            connection.connect()  # Trust chain, dates and IP SAN must all verify; no insecure fallback.
            assert connection.sock is not None
            peer = connection.sock.getpeercert(binary_form=True)
            require(bool(peer), "The HTTPS peer did not supply a certificate.")
            connection.sock.settimeout(self.runner.remaining())
            connection.request("GET", "/health/ready", headers={"Accept": "application/json", "Connection": "close"})
            response = connection.getresponse()
            body = bytearray()
            # read1 avoids waiting for an entire declared body while retaining a shared deadline.
            while True:
                if connection.sock is not None:
                    connection.sock.settimeout(self.runner.remaining())
                else:
                    self.runner.remaining()
                chunk = response.read1(8192)
                if not chunk:
                    break
                body.extend(chunk)
                require(len(body) <= MAX_CERT_BYTES, "The readiness response exceeded its bounded size limit.")
            return {"sha256": hashlib.sha256(peer).hexdigest(), "httpStatus": response.status,
                    "contentType": response.getheader("Content-Type", ""), "body": bytes(body)}
        except ssl.SSLCertVerificationError as error:
            raise CheckError("The served HTTPS certificate failed normal trust, validity or IP SAN verification.") from error
        finally:
            connection.close()

    def ingress(self, owner: dict | None, served: dict | None) -> dict:
        ingress = self.get(self.args.namespace, "ingress", "marty")
        require(ingress["spec"].get("ingressClassName") == "traefik", "The application Ingress does not explicitly select Traefik.")
        annotations = ingress["metadata"].get("annotations", {})
        require(annotations.get("traefik.ingress.kubernetes.io/router.tls") == "true",
                "The application Ingress does not explicitly enable Traefik TLS.")
        copies = []
        for tls in ingress["spec"].get("tls", []):
            secret = tls.get("secretName")
            if not secret:
                continue
            try:
                leaf = self.leaf(self.args.namespace, valid_name(secret))
            except (CheckError, ValueError, KeyError, OSError):
                self.checks.append({"check": "ingress_certificate_copy", "status": "warn",
                                    "message": "A per-ingress certificate reference could not be inspected; the separately verified HTTPS result establishes observed delivery.",
                                    "evidence": {"namespace": self.args.namespace, "secret": valid_name(secret)},
                                    "action": "Inspect this reference and remove obsolete copies through the supported default-store chart option. See " + RESUME_GUIDE})
                continue
            if owner and leaf.fingerprint != owner["sha256"]:
                copies.append(secret)
        if copies:
            message = "The Ingress also loads a certificate that differs from the default TLSStore owner."
            if owner and served and owner["sha256"] == served["sha256"]:
                message += " The verified IP connection served the expected default certificate; this copy is not evidence of a broken browser TLS connection."
            self.checks.append({"check": "ingress_certificate_copy", "status": "warn", "message": message,
                                "evidence": {"namespace": self.args.namespace, "secrets": copies},
                                "action": "Review ingress.useDefaultCertificate in " + RESUME_GUIDE + "; retain one certificate owner and remove the per-ingress reference through the supported chart option."})
        return {"namespace": self.args.namespace, "name": "marty", "certificateMode": "namespace-secret" if ingress["spec"].get("tls") else "default-store"}

    def run(self) -> dict:
        args = self.args
        self.check("ec2_current_origin", "Re-read the retained EC2 instance in the intended AWS account/region, then follow " + RESUME_GUIDE, self.ec2)
        owner = self.check("public_certificate_owner", "Inspect the existing cert-manager Certificate, Issuer and default TLSStore. Reconcile its IP SAN in place; require the new generation and served certificate to agree. See " + RESUME_GUIDE, self.public_owner)
        self.check("application_origin", "Use the documented origin-only Helm/Keycloak update while preserving issuer DID, credentials and disabled setup Jobs. See " + RESUME_GUIDE, self.origin_config)
        served = None
        try:
            served = self.https()
            self.checks.append({"check": "served_https", "status": "pass", "evidence": {"sha256": served["sha256"], "origin": args.origin}})
        except (CheckError, OSError, http.client.HTTPException) as error:
            self.checks.append({"check": "served_https", "status": "fail",
                                "message": str(error) if isinstance(error, CheckError) else "The bounded verified HTTPS probe failed; raw output is withheld.",
                                "action": "Inspect the current IP, existing certificate owner and ingress delivery. Do not bypass TLS verification. See " + RESUME_GUIDE})
        if owner and served:
            def same_leaf():
                require(owner["sha256"] == served["sha256"], "The verified HTTPS peer is not the leaf in the expected default TLSStore Secret.")
                return {"sha256": served["sha256"]}
            self.check("served_certificate_owner", "Inspect which default TLSStore Traefik discovers; compare the existing owner and delivery before changing any Secrets.", same_leaf)
        if served:
            self.check("gateway_readiness", "Inspect current gateway/dependency readiness and private service logs. A UI shell or HTTP 200 alone does not establish backend readiness.",
                       lambda: readiness_contract(served["httpStatus"], served["contentType"], served["body"]))
        self.check("ingress_delivery", "Inspect the selected application's Ingress and its certificate references; use " + RESUME_GUIDE, lambda: self.ingress(owner, served))
        workloads = self.check("workload_inventory", "Check the explicit context, namespace and Helm release selector.",
                               lambda: self.get(args.namespace, "deployments,statefulsets", selector="app.kubernetes.io/instance=" + args.release))
        if workloads is not None:
            # Never emit Deployment env or volumes. Keep only summary evidence in the report.
            self.checks[-1]["evidence"] = {"namespace": args.namespace, "release": args.release}
            items = workloads.get("items", [])
            self.check("workload_readiness", "Inspect current rollout status and failed pods; preserve healthy services. Credential errors require their own current evidence. See " + CREDENTIAL_GUIDE,
                       lambda: workload_readiness(items))
            targets = self.check("public_leaf_projections", "Inspect the actual configured public certificate mounts; tokens and private keys are outside this check.", lambda: public_cert_targets(items))
            if targets is not None:
                self.checks[-1]["evidence"] = {"certificates": len(targets)}
                for (secret, field), consumers in sorted(targets.items()):
                    def lifetime(secret=secret, field=field, consumers=consumers):
                        leaf = self.leaf(args.namespace, secret, field)
                        check_lifetime(leaf, time.time(), args.minimum_validity_seconds)
                        return {"namespace": args.namespace, "secret": secret, "field": field, "consumers": consumers, **leaf.evidence()}
                    self.check("public_leaf_lifetime:" + secret + "/" + field,
                               "Inspect the applicable retained credential lifecycle; stage/activate before expiry or use its supported recovery after expiry. Public certificate dates do not establish token validity. See " + CREDENTIAL_GUIDE, lifetime)
        self.checks.append({"check": "authenticated_demo", "status": "not_checked",
                            "message": "OpenBao token validity, in-process credential reload, Keycloak client redirects and authenticated OB3 issuance/presentation are not established by this preflight.",
                            "action": "After blocking checks pass, log in through the exact HTTPS origin and complete the intended OB3 demo journey."})
        blocked = any(check["status"] == "fail" for check in self.checks)
        return {"schema": SCHEMA, "observedAt": datetime.now(timezone.utc).isoformat(),
                "readOnly": True, "status": "blocked" if blocked else "ready-for-authenticated-check",
                "demoQualified": False, "checks": self.checks}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    for name, help_text in (
        ("context", "Explicit kubectl context for the retained installation."),
        ("namespace", "Existing application namespace."),
        ("origin", "Exact current HTTPS IPv4 origin, with an optional port."),
        ("instance-id", "Existing EC2 instance; this command only describes it."),
        ("region", "AWS region for that instance."),
        ("certificate-namespace", "Namespace of the actual cert-manager public Certificate owner."),
    ):
        result.add_argument("--" + name, required=True, help=help_text)
    result.add_argument("--release", default="marty", help="Existing Helm release label (default: marty).")
    result.add_argument("--certificate", default="marty-public")
    result.add_argument("--tls-store-namespace", help="Namespace of Traefik's existing default TLSStore (defaults to Certificate namespace).")
    result.add_argument("--minimum-validity-seconds", type=int, default=3600, help="Required public leaf lifetime remaining (default: one hour).")
    result.add_argument("--timeout-seconds", type=int, default=120, help="Total observation budget, at most 600 seconds (default: 120).")
    result.add_argument("--request-timeout-seconds", type=int, default=10, help="Per subprocess/network request budget (default: 10).")
    result.add_argument("--format", choices=("text", "json"), default="text")
    for command in ("kubectl", "aws", "openssl"):
        result.add_argument("--" + command, default=command, help="Executable path for " + command + ".")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        require(bool(args.context.strip()),
                "An explicit nonempty kubectl context is required; current-context fallback is not allowed.")
        require(0 < args.request_timeout_seconds <= args.timeout_seconds <= 600
                and 0 <= args.minimum_validity_seconds <= 86400,
                "Timeouts must be positive and bounded by 600 seconds; the validity window must be 0–86400 seconds.")
        args.tls_store_namespace = args.tls_store_namespace or args.certificate_namespace
        for value in (args.namespace, args.certificate_namespace, args.tls_store_namespace, args.certificate, args.release):
            valid_name(value)
        require(bool(re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", args.instance_id)), "Expected an EC2 instance ID.")
        require(bool(re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", args.region)), "Expected an AWS region.")
        report = Preflight(args).run()
    except (CheckError, ValueError):
        # Input validation must not echo a malformed origin containing credentials.
        parser().error("Invalid preflight input; use the documented explicit names, HTTPS IPv4 origin and bounded timeouts.")
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("Development resume preflight: " + report["status"])
        for check in report["checks"]:
            print(check["status"].upper() + " " + check["check"] + (": " + check["message"] if "message" in check else ""))
            if "action" in check:
                print("  Next: " + check["action"])
        print("Authenticated demo qualification: NOT CHECKED")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
