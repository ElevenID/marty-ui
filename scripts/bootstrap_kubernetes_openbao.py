#!/usr/bin/env python3
"""Bootstrap a fresh, disposable Kubernetes development namespace with OpenBao.

This transports existing tools: the official Helm chart, bao CLI, the signed
workload TLS producer, and the signed marty-deploy operator. It has no server,
controller, custom crypto, template renderer, or implicit retry of initialization.
Root/recovery material stays in a new private operator directory. Only public
certificates and scoped credentials are published as application Secrets.

The selected runtime artifacts are authenticated again before any cluster write.
The development identity profile expires after eight hours. This command neither
renews credentials nor upgrades/adopts an existing installation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid
import zipfile

sys.dont_write_bytecode = True
import installer_release as release
from installer_candidate_authorize import read_record
from passport_remote_tls import SELFHOST_TLS_FILES, SELFHOST_CERT_FILES, accept_remote_tls
from prepare_kubernetes_helm_values import prepare
from provision_selfhost_disposable_tls import verified_key_metadata


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy/helm/openbao/values-k3s-dev.yaml"
UPSTREAM = ROOT / "deploy/helm/openbao/upstream.json"
NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,255}\Z")
PUBLICATION_SCHEMA = "marty.kubernetes-secret-publication/v1"
PUBLICATION_CONTRACT_LIMIT = 128 * 1024
KEYCLOAK_FILES = {
    "keycloak_signing_kms_token", "keycloak_master_rs256_cert", "keycloak_11id_rs256_cert",
    "keycloak_master_cookie_token", "keycloak_master_ciba_token",
    "keycloak_11id_cookie_token", "keycloak_11id_ciba_token",
}
SCALAR_CREDENTIALS = (
    "POSTGRES_PASSWORD", "KEYCLOAK_DB_PASSWORD", "MARTY_DB_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD", "MARTY_API_CLIENT_SECRET", "RABBITMQ_PASSWORD",
    "RABBITMQ_ERLANG_COOKIE", "SESSION_SECRET_KEY", "ISSUANCE_API_KEY",
    "TOKEN_HMAC_KEY", "SIGNING_KEYS_ISSUER_SIGN_KEY",
    "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY", "SIGNING_KEYS_INTEGRATION_SECRET_KEY",
    "GRPC_SERVICE_TOKEN", "DEVICE_REGISTRATION_GATEWAY_KEY",
    "DEVICE_REGISTRATION_SIGNING_KEYS_KEY", "NOTIFICATION_WEBHOOK_SECRET",
    "NOTIFICATION_APPLICANT_EVENT_TOKEN", "FLOW_WEBHOOK_SECRET",
    "FLOW_APPLICATION_EVENT_HMAC_KEY", "CANVAS_CREDENTIALS_SHARED_SECRET",
)
# Policy contents remain owned by docker/openbao-init.sh in the signed bundle.
TOKEN_POLICIES = {
    "OPENBAO_SERVICE_TOKEN": ("credential-service",),
    "OPENBAO_BOOTSTRAP_TOKEN": ("kms-bootstrap",),
    "SIGNING_KEYS_OPENBAO_TOKEN": ("credential-service", "signing-keys-managed"),
    "DIDCOMM_ISSUANCE_OPENBAO_TOKEN": ("didcomm-issuance",),
    "NOTIFICATION_OPENBAO_TOKEN": ("notification-webhook-service",),
    "GATEWAY_SIGN_GRANT_MINT_TOKEN": ("sign-grant-mint-gateway-service",),
    "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN": ("sign-grant-mint-gateway-issuer-did",),
    "FLOW_SIGN_GRANT_MINT_TOKEN": ("sign-grant-mint-flow-wallet",),
    "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN": ("sign-grant-mint-issuance-credential",),
    "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN": ("sign-grant-mint-issuance-canvas",),
    "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN": ("sign-grant-mint-issuance-readiness",),
    "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN": ("sign-grant-mint-issuance-passport",),
    "SIGNING_KEYS_GRANT_VERIFY_TOKEN": ("sign-grant-verify",),
}


class BootstrapError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapError(message)


def write_new(path: Path, contents: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def private_directory(path: Path) -> None:
    require(path.is_absolute() and path.resolve() == path, "state path must be absolute and canonical")
    require(not path.exists() and not path.is_symlink(), "state directory already exists; reconcile the previous attempt")
    require(path.parent.is_dir(), "state parent directory must already exist")
    path.mkdir(mode=0o700)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700, "state directory must be private")


class Transport:
    def __init__(self, state: Path, kubeconfig: Path, namespace: str, kubectl: str):
        self.state = state
        self.base = [kubectl, "--kubeconfig", str(kubeconfig), "--namespace", namespace]
        self.namespace = namespace
        self.step = 0

    def run(self, operation: str, command: list[str], *, data: bytes | None = None,
            timeout: int = 300, env: dict[str, str] | None = None) -> bytes:
        self.step += 1
        try:
            result = subprocess.run(command, input=data, capture_output=True,
                                    timeout=timeout, env=env, check=False)
        except subprocess.TimeoutExpired as error:
            raise BootstrapError(f"{operation} timed out; preserve the namespace and private state") from error
        if result.returncode:
            # Diagnostics can include remote response bodies. Keep them private.
            write_new(self.state / f"failure-{self.step}.stderr", result.stderr[:1024 * 1024])
            raise BootstrapError(f"{operation} failed; private diagnostics retained")
        return result.stdout

    def kubectl(self, operation: str, *args: str, data: bytes | None = None,
                timeout: int = 300) -> bytes:
        return self.run(operation, [*self.base, *args], data=data, timeout=timeout)

    def create(self, document: dict) -> None:
        self.kubectl("Kubernetes resource creation", "create", "-f", "-", data=encoded(document))

    def execute(self, pod: str, command: list[str], *, data: bytes | None = None,
                timeout: int = 300) -> bytes:
        args = ["exec"]
        if data is not None:
            args.append("-i")
        args += [pod, "--", *command]
        return self.kubectl("Kubernetes command", *args, data=data, timeout=timeout)

    def upload(self, pod: str, destination: str, contents: bytes, *, executable: bool = False) -> None:
        # Contents travel on private stdin, never in argv, logs or Helm values.
        command = 'umask 077; set -C; cat > "$1"; chmod "$2" "$1"'
        self.execute(pod, ["/bin/sh", "-ec", command, "--", destination,
                           "700" if executable else "600"], data=contents)


def root_command(transport: Transport, token: str, command: list[str], *, timeout: int = 300) -> bytes:
    return transport.execute(
        "openbao-0",
        ["/bin/sh", "-ec", 'IFS= read -r BAO_TOKEN; export BAO_TOKEN; exec "$@"', "--", *command],
        data=(token + "\n").encode(), timeout=timeout,
    )


def bundle_file(contents: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(contents)) as archive:
        info = archive.getinfo("selfhost-prepared/" + name)
        require(not info.is_dir() and info.file_size < 1024 * 1024,
                "signed bootstrap script is missing or oversized")
        return archive.read(info)


def authenticated_bootstrap_inputs(assets: Path, identity: dict) -> tuple[bytes, bytes]:
    """Consume exact bytes bound by the in-process prepare() result.

    The caller must supply prepare()'s returned identity, never a values file.
    Keep the small init script in memory so later cluster operations do not
    reopen a potentially changed staged bundle.
    """
    inventory_bytes = read_record(assets / "installer-inventory.json")
    require(hashlib.sha256(inventory_bytes).hexdigest() == identity["inventorySha256"],
            "authenticated installer inventory changed")
    inventory = release.decode(inventory_bytes)

    def payload(name: str, expected_sha: str) -> bytes:
        maximum = release.ARTIFACT_MAX_BYTES[name]
        with (assets / name).open("rb") as stream:
            contents = stream.read(maximum + 1)
        require(len(contents) <= maximum and hashlib.sha256(contents).hexdigest() == expected_sha,
                "authenticated installer artifact changed")
        return contents

    operator = payload("marty-deploy-linux-amd64", identity["operatorSha256"])
    bundle_sha = next(entry["sha256"] for entry in inventory["artifacts"]
                      if entry["name"] == "prepared-selfhost-bundle.zip")
    init_script = bundle_file(payload("prepared-selfhost-bundle.zip", bundle_sha),
                              "docker/openbao-init.sh")
    return operator, init_script


def publication_contract(operator: Path) -> dict:
    """Check the authenticated binary's compiled publisher before cluster access.

    The dynamic catalog read by --repo-root cannot establish what destinations
    an older binary actually publishes. This command needs no repository,
    credentials, or Kubernetes access and exposes only compiled public metadata.
    """
    try:
        result = subprocess.run([str(operator), "kubernetes-secrets-contract"],
            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=10, env={})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BootstrapError("signed operator Kubernetes publication contract is unavailable; "
                             "select a compatible signed runtime") from error
    require(result.returncode == 0,
            "signed operator does not provide the required Kubernetes publication contract; "
            "select a compatible signed runtime")
    require(0 < len(result.stdout) <= PUBLICATION_CONTRACT_LIMIT,
            "signed operator Kubernetes publication contract is empty or oversized")

    def unique_members(pairs: list[tuple[str, object]]) -> dict:
        members: dict = {}
        for key, value in pairs:
            if key in members:
                raise ValueError("duplicate publication contract member")
            members[key] = value
        return members

    try:
        observed = json.loads(result.stdout, object_pairs_hook=unique_members)
        expected = {"schema": PUBLICATION_SCHEMA, "catalog": json.loads(
            (ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())}
        # Canonical bytes preserve JSON types (in particular true versus 1).
        # Exact mappings, required inputs, optional destinations and templates
        # must agree; Secret counts or input names alone are not capabilities.
        matches = encoded(observed) == encoded(expected)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise BootstrapError("signed operator Kubernetes publication contract is malformed") from error
    require(matches, "signed operator Kubernetes publication contract differs from this installer; "
            "select a compatible signed runtime")
    return observed


def take_tls_outputs(payload: bytes, output: Path) -> None:
    expected = set(SELFHOST_TLS_FILES) | {"selfhost-tls-kms-roles.json"}
    require(len(payload) <= 2 * 1024 * 1024, "TLS output archive is oversized")
    observed: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for entry in archive:
            if entry.isdir() and entry.name in (".", "./"):
                continue
            name = entry.name.removeprefix("./")
            require(entry.isfile() and name in expected and name not in observed
                    and 0 < entry.size < 65536, "TLS producer output inventory differs")
            observed.add(name)
            stream = archive.extractfile(entry)
            require(stream is not None, "TLS producer output could not be read")
            write_new(output / name, stream.read())
    require(observed == expected, "TLS producer output is incomplete")


def namespace_identity(transport: Transport) -> dict[str, str]:
    observed = json.loads(transport.kubectl("namespace identity", "get", "namespace",
                                            transport.namespace, "-o", "json"))
    metadata = observed.get("metadata") if isinstance(observed, dict) else None
    require(isinstance(metadata, dict) and metadata.get("name") == transport.namespace,
            "Kubernetes namespace identity differs")
    uid = metadata.get("uid")
    require(isinstance(uid, str) and IDENTIFIER.fullmatch(uid) is not None,
            "Kubernetes namespace UID is missing or invalid")
    return {"name": transport.namespace, "uid": uid}


def openbao_cluster_identity(transport: Transport) -> str:
    observed = json.loads(transport.execute("openbao-0", ["bao", "status", "-format=json"]))
    require(isinstance(observed, dict) and observed.get("initialized") is True
            and observed.get("sealed") is False and observed.get("type") == "static"
            and observed.get("storage_type") == "raft", "OpenBao identity status differs")
    cluster_id = observed.get("cluster_id")
    require(isinstance(cluster_id, str) and IDENTIFIER.fullmatch(cluster_id) is not None,
            "OpenBao cluster ID is missing or invalid")
    return cluster_id


def ordinary_token_requests() -> list[dict]:
    """The closed ordinary-token request inventory, excluding native TLS/Keycloak outputs.

    These are requested settings, not observed expiry or live lookup results.
    The same entries drive issuance and the successful bootstrap receipt.
    """
    return [{"input": name, "requestedPolicies": list(policies),
             "requestedTtl": "2h" if name == "OPENBAO_BOOTSTRAP_TOKEN" else "8h",
             "requestedRenewable": False, "requestedOrphan": True,
             "requestedNoDefaultPolicy": True}
            for name, policies in TOKEN_POLICIES.items()]


def provision_application_tokens(transport: Transport, root_token: str,
                                 credential_dir: Path, files: dict[str, Path]) -> list[dict]:
    requests = ordinary_token_requests()
    for request in requests:
        name = request["input"]
        command = ["bao", "token", "create"]
        for field, flag in (("requestedNoDefaultPolicy", "-no-default-policy"),
                            ("requestedOrphan", "-orphan")):
            if request[field]:
                command.append(flag)
        command += ["-ttl=" + request["requestedTtl"],
                    "-renewable=" + str(request["requestedRenewable"]).lower(), "-field=token",
                    *["-policy=" + policy for policy in request["requestedPolicies"]]]
        token = root_command(transport, root_token, command).strip()
        require(20 <= len(token) <= 1024 and b"\n" not in token and b"\r" not in token
                and token != root_token.encode(), "OpenBao scoped token output differs")
        path = credential_dir / name.lower()
        write_new(path, token)
        files[name] = path
    return requests


def prepare_namespace(transport: Transport, bootstrap_id: str, publication: dict) -> dict[str, str]:
    found = transport.kubectl("namespace inspection", "get", "namespace",
                              transport.namespace, "--ignore-not-found", "-o", "json")
    if found.strip():
        workloads = json.loads(transport.kubectl(
            "namespace workload inspection", "get",
            "deployments,statefulsets,jobs,pods,persistentvolumeclaims", "-o", "json"))
        require(not workloads["items"], "namespace must have no existing workloads or PVCs")
        destinations = {entry["name"] for entry in publication["catalog"]["secrets"]} | {
            "marty-openbao-seal", "marty-operator",
        }
        existing = transport.kubectl("namespace Secret inspection", "get", "secret",
                                    *sorted(destinations), "--ignore-not-found", "-o", "name")
        require(not existing.strip(), "namespace already contains Marty credentials")
    else:
        transport.create({"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": transport.namespace,
                "labels": {"app.kubernetes.io/part-of": "marty-development",
                           "marty.elevenid.com/bootstrap-id": bootstrap_id}}})
    namespace = namespace_identity(transport)
    write_new(transport.state / "namespace.json", encoded({**namespace, "bootstrapId": bootstrap_id}))
    return namespace


def provision_workload_identity(transport: Transport, *, image: str, operator: Path,
                               root_token: str, ca: bytes, nonce: str, workload_project: str,
                               files: dict[str, Path], pull_secrets: list[str]) -> None:
    require(re.fullmatch(r"[0-9a-f]{12}", nonce) is not None
            and workload_project == "marty-selfhost-disposable-k8s-" + nonce,
            "native producer identity differs from the retained bootstrap project")
    pod = "marty-kms-bootstrap-" + nonce
    # A bounded disposable transport pod runs the existing native producers.
    # No authority is present in its spec; private inputs arrive over exec stdin.
    transport.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod},
        "spec": {
            "restartPolicy": "Never", "activeDeadlineSeconds": 1200,
            "automountServiceAccountToken": False,
            "securityContext": {"runAsUser": 10001, "runAsGroup": 10001,
                "fsGroup": 10001, "runAsNonRoot": True,
                "seccompProfile": {"type": "RuntimeDefault"}},
            "imagePullSecrets": [{"name": name} for name in pull_secrets],
            "containers": [{"name": "native-producers", "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-ec",
                    "umask 077; mkdir /tmp/workload-tls; chmod 700 /tmp/workload-tls; exec sleep 1200"],
                "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                              "limits": {"cpu": "750m", "memory": "512Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "private", "mountPath": "/tmp"}]}],
            "volumes": [{"name": "private", "emptyDir": {"medium": "Memory", "sizeLimit": "128Mi"}}],
        }})
    try:
        transport.kubectl("native producer readiness", "wait", "--for=condition=Ready",
                          "pod/" + pod, "--timeout=300s", timeout=330)
        transport.upload(pod, "/tmp/root.token", root_token.encode())
        transport.upload(pod, "/tmp/ca.crt", ca)
        transport.upload(pod, "/tmp/marty-deploy", operator.read_bytes(), executable=True)
        copied = transport.execute(pod, ["sha256sum", "/tmp/marty-deploy"]).split()[0].decode()
        require(copied == hashlib.sha256(operator.read_bytes()).hexdigest(),
                "copied native operator digest differs")
        transport.execute(pod, ["env",
            "MARTY_TLS_BOOTSTRAP_PROFILE=selfhost-disposable",
            "MARTY_SELFHOST_DISPOSABLE_OPENBAO=1",
            "MARTY_SELFHOST_PROJECT=" + workload_project,
            "BAO_ADDR=https://openbao:8200", "BAO_CACERT=/tmp/ca.crt",
            "BAO_ROOT_TOKEN_FILE=/tmp/root.token", "SELFHOST_TLS_OUTPUT_DIR=/tmp/workload-tls",
            "/usr/local/bin/marty-passport-tls-bootstrap"], timeout=600)
        output = transport.state / "tls-output"
        output.mkdir(mode=0o700)
        take_tls_outputs(transport.execute(pod, ["tar", "-cf", "-", "-C", "/tmp/workload-tls", "."]), output)
        verified_key_metadata(output)
        (output / "selfhost-tls-kms-roles.json").rename(transport.state / "tls-key-metadata.json")
        destination = transport.state / "credentials"
        accept_remote_tls(output, destination, root_token,
                          expected_files=SELFHOST_TLS_FILES, certificate_files=SELFHOST_CERT_FILES)
        for name in SELFHOST_TLS_FILES:
            key = "MARTY_WORKLOAD_IDENTITY_CA_CERT" if name == "workload_identity_ca_cert" else name.upper()
            files[key] = destination / name
        context = {"token": root_token, "renew": False, "pki_mount": "keycloak-pki", "nonce": nonce}
        outputs = json.loads(transport.execute(pod, ["/tmp/marty-deploy", "operator", "keycloak-provision",
            "https://openbao:8200", "/tmp/ca.crt"], data=encoded(context), timeout=600))
        require(isinstance(outputs, dict) and set(outputs) == KEYCLOAK_FILES,
                "Keycloak producer output inventory differs")
        tokens = []
        for name, value in outputs.items():
            require(isinstance(value, str) and value and "PRIVATE KEY" not in value
                    and root_token not in value and len(value) < 65536,
                    "Keycloak producer output is invalid")
            if name.endswith("_token"):
                require(20 <= len(value) <= 1024 and "\n" not in value and "\r" not in value,
                        "Keycloak scoped token is invalid")
                tokens.append(value)
            else:
                require("BEGIN CERTIFICATE" in value, "Keycloak public certificate is invalid")
            path = destination / name
            write_new(path, value.encode())
            files[name.upper()] = path
        require(len(tokens) == len(set(tokens)) == 5, "Keycloak scoped tokens are shared")
    finally:
        # All authority in this pod lives in its memory-backed temporary volume.
        # Failure to remove it is a visible error, never a successful bootstrap.
        transport.kubectl("native producer cleanup", "delete", "pod", pod,
                          "--wait=true", "--timeout=120s", timeout=150)


def publish_credentials(transport: Transport, operator: Path, files: dict[str, Path]) -> None:
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "SSL_CERT_FILE") if key in os.environ}
    environment["KUBECONFIG"] = str(transport.state / "kubeconfig")
    environment.update({name + "_FILE": str(path) for name, path in files.items()})
    transport.run("native Kubernetes credential publication",
        [str(operator), "--repo-root", str(ROOT), "kubernetes-secrets",
         "kubernetes-production", transport.namespace], env=environment)
    # The initial organization login remains bootstrap-owned. Workload and
    # OpenBao credentials, including Notification TLS, have one native owner.
    transport.kubectl("application credential publication", "create", "secret", "generic",
                      "marty-operator", f"--from-file=password={files['MARTY_ORG_ADMIN_PASSWORD']}")


def bootstrap(args: argparse.Namespace) -> None:
    require(os.name == "posix", "this development bootstrap requires Linux")
    require(NAMESPACE.fullmatch(args.namespace) is not None
            and args.namespace not in {"default", "kube-system", "kube-public", "kube-node-lease"},
            "select a dedicated development namespace")
    require(args.context and len(args.context) <= 256, "an explicit kubeconfig context is required")
    require(args.kubeconfig.is_file(), "explicit kubeconfig is unavailable")
    kubectl = shutil.which("kubectl")
    require(kubectl is not None, "kubectl must be installed")
    private_directory(args.state_dir)
    state = args.state_dir
    values, _ = prepare(assets=args.assets, runtime_source_sha=args.runtime_source_sha,
        release_tag=args.release_tag, build_run_id=args.build_run_id,
        build_run_attempt=args.build_run_attempt, chart_source_sha=args.chart_source_sha,
        gh=args.gh, cosign=args.cosign, output=state / "marty-images.json",
        openbao_output=state / "openbao-images.json")
    operator_bytes, init_script_bytes = authenticated_bootstrap_inputs(args.assets, values["release"])
    operator = state / "marty-deploy"
    write_new(operator, operator_bytes, 0o700)
    # The signed runtime identity is intentionally separate from chart HEAD.
    identity = subprocess.run([str(operator), "--build-identity"], capture_output=True, check=False, timeout=10)
    require(identity.returncode == 0
            and identity.stdout.strip().decode() == args.runtime_source_sha + ":" + args.release_tag,
            "signed operator build identity differs")
    publication = publication_contract(operator)
    write_new(state / "kubernetes-secret-publication.json", encoded(publication))
    upstream = json.loads(UPSTREAM.read_bytes())
    require(args.chart_package.is_file()
            and hashlib.sha256(args.chart_package.read_bytes()).hexdigest() == upstream["sha256"],
            "official OpenBao chart archive differs from pinned upstream")
    scoped = subprocess.run([kubectl, "--kubeconfig", str(args.kubeconfig), "--context", args.context,
        "config", "view", "--minify", "--flatten", "--raw", "-o", "json"],
        capture_output=True, check=False, timeout=30)
    require(scoped.returncode == 0, "explicit Kubernetes context could not be selected")
    selected = json.loads(scoped.stdout)
    require(selected.get("current-context") == args.context and len(selected.get("contexts", [])) == 1,
            "Kubernetes context selection is ambiguous")
    write_new(state / "kubeconfig", scoped.stdout)
    transport = Transport(state, state / "kubeconfig", args.namespace, kubectl)
    bootstrap_id = str(uuid.uuid4())
    nonce = secrets.token_hex(6)
    workload_project = "marty-selfhost-disposable-k8s-" + nonce
    namespace = prepare_namespace(transport, bootstrap_id, publication)
    seal = secrets.token_bytes(32)
    write_new(state / "static.key", seal, 0o400)
    transport.create({"apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": "marty-openbao-seal", "namespace": args.namespace},
        "type": "Opaque", "immutable": True,
        "data": {"static.key": base64.b64encode(seal).decode()}})
    del seal
    pull_values = {"global": {"imagePullSecrets": [{"name": name} for name in args.image_pull_secret]}}
    write_new(state / "openbao-pull-secrets.json", encoded(pull_values))
    transport.run("official OpenBao Helm installation",
        [str(args.helm), "--kubeconfig", str(state / "kubeconfig"), "install", "openbao",
         str(args.chart_package), "--namespace", args.namespace,
         "--values", str(PROFILE), "--values", str(state / "openbao-images.json"),
         "--values", str(state / "openbao-pull-secrets.json"), "--timeout", "5m"], timeout=330)
    transport.kubectl("OpenBao container startup", "wait",
        "--for=jsonpath={.status.phase}=Running", "pod/openbao-0", "--timeout=300s", timeout=330)
    # A fresh server returns status exit code 2 while sealed. Bound the one
    # initial connection race; native initialization below is never retried.
    status = json.loads(transport.execute("openbao-0", ["/bin/sh", "-ec",
        'for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do '
        'code=0; status=$(bao status -format=json 2>/dev/null) || code=$?; '
        'if [ "$code" = 0 ] || [ "$code" = 2 ]; then printf "%s" "$status"; exit 0; fi; '
        'sleep 2; done; exit 1'], timeout=45))
    require(status.get("initialized") is False and status.get("type") == "static",
            "OpenBao must be fresh and use the selected static seal")
    write_new(state / "initialize-requested.json", encoded({
        "bootstrapId": bootstrap_id, "namespace": args.namespace,
        "namespaceUid": namespace["uid"], "producerNonce": nonce,
        "workloadProject": workload_project,
        "operation": "bao operator init", "recoveryShares": 1, "recoveryThreshold": 1,
    }))
    initialized = transport.execute("openbao-0", [
        "bao", "operator", "init", "-recovery-shares=1", "-recovery-threshold=1", "-format=json"],
        timeout=180)
    # Persist before interpretation. An uncertain response must not be replayed.
    write_new(state / "openbao-initialization.json", initialized, 0o400)
    material = json.loads(initialized)
    root_token = material.get("root_token")
    require(isinstance(root_token, str) and 20 <= len(root_token) <= 256
            and "\n" not in root_token and "\r" not in root_token
            and len(material.get("recovery_keys_b64", [])) == 1,
            "native OpenBao initialization output differs")
    transport.kubectl("unsealed OpenBao readiness", "wait", "--for=condition=Ready",
                      "pod/openbao-0", "--timeout=180s", timeout=210)
    openbao_cluster_id = openbao_cluster_identity(transport)
    ca = transport.execute("openbao-0", ["cat", "/bao/data/tls/ca.crt"])
    require(b"BEGIN CERTIFICATE" in ca and b"PRIVATE KEY" not in ca, "OpenBao public CA is invalid")
    credential_dir = state / "credentials"
    credential_dir.mkdir(mode=0o700)
    ca_path = credential_dir / "openbao_tls_ca_cert"
    write_new(ca_path, ca)
    files: dict[str, Path] = {"OPENBAO_TLS_CA_CERT": ca_path}
    init_script = "/tmp/marty-openbao-init-" + nonce + ".sh"
    transport.upload("openbao-0", init_script, init_script_bytes)
    root_command(transport, root_token, ["env", "DIDCOMM_KMS_PLUGIN_REQUIRED=true",
                                       "/bin/sh", init_script], timeout=600)
    token_requests = provision_application_tokens(transport, root_token, credential_dir, files)
    for name in SCALAR_CREDENTIALS:
        path = credential_dir / name.lower()
        write_new(path, ("Aa1!" + secrets.token_hex(24) if name == "KEYCLOAK_ADMIN_PASSWORD"
                         else secrets.token_hex(32)).encode())
        files[name] = path
    operator_password = credential_dir / "marty_org_admin_password"
    write_new(operator_password, ("Aa1!" + secrets.token_hex(24)).encode())
    files["MARTY_ORG_ADMIN_PASSWORD"] = operator_password
    provision_workload_identity(transport, image=values["images"]["services"],
        operator=operator, root_token=root_token, ca=ca, nonce=nonce,
        workload_project=workload_project, files=files, pull_secrets=args.image_pull_secret)
    publish_credentials(transport, operator, files)
    require(namespace_identity(transport) == namespace,
            "Kubernetes namespace changed during bootstrap; completion withheld")
    require(openbao_cluster_identity(transport) == openbao_cluster_id,
            "OpenBao cluster changed during bootstrap; completion withheld")
    write_new(state / "bootstrap-complete.json", encoded({
        "bootstrapId": bootstrap_id, "namespace": args.namespace,
        "openbaoClusterId": openbao_cluster_id, "openbaoChart": upstream["version"],
        "runtimeSourceSha": args.runtime_source_sha, "chartSourceSha": args.chart_source_sha,
        "openbaoImage": values["images"]["openbao_didcomm"],
        "status": "openbao-and-application-credentials-ready",
        "credentialLifetimeHours": 8, "migrationBootstrapLifetimeHours": 2,
        "credentialPublication": publication,
        "credentialLifecycle": {
            "schema": "marty.kubernetes-credential-lifecycle/v1",
            "namespaceUid": namespace["uid"], "producerNonce": nonce,
            "workloadProject": workload_project, "ordinaryTokens": token_requests,
        },
    }))
    print("OpenBao is initialized and unsealed; application credentials are installed.")
    print("Keep the private state directory. Finish first-install migrations within two hours.")
    print("This development credential set expires after eight hours; renewal is not installed.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "state-dir", "assets", "gh", "cosign", "helm", "chart-package"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("context", "namespace", "runtime-source-sha", "chart-source-sha", "release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    parser.add_argument("--image-pull-secret", action="append", default=[],
                        help="existing same-namespace registry Secret; may be repeated")
    args = parser.parse_args(argv)
    try:
        bootstrap(args)
    except (BootstrapError, ValueError, OSError, subprocess.TimeoutExpired,
            KeyError, zipfile.BadZipFile, tarfile.TarError) as error:
        # Never echo native stdout, credentials, shell commands or API bodies.
        detail = str(error) if isinstance(error, BootstrapError) else type(error).__name__
        parser.exit(1, f"Kubernetes OpenBao bootstrap stopped: {detail}. "
                    "Retain the namespace and private state; initialization is never replayed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
