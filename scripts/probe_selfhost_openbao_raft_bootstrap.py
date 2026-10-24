"""Qualify self-host OpenBao HTTPS bootstrap and Raft recovery in Docker volumes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import uuid
import zipfile
from functools import partial
from pathlib import Path

from check_selfhost_root_retirement import STATIC_KMS_TOKENS, checked_static_tokens
from provision_selfhost_audit_identity import bootstrap as bootstrap_audit_identity
from provision_selfhost_audit_identity import checked_login as audit_login
from provision_selfhost_audit_identity import mint as mint_audit_token
from provision_selfhost_audit_identity import rotate as rotate_audit_identity
from provision_selfhost_audit_identity import require_revoked as audit_revoked
from provision_selfhost_audit_identity import ROLE_ID_FILE as AUDIT_ROLE_ID_FILE
from provision_selfhost_audit_identity import SECRET_ID_FILE as AUDIT_SECRET_ID_FILE
from provision_selfhost_audit_identity import LEAF_ROLE as AUDIT_LEAF_ROLE
from provision_selfhost_audit_token import POLICY as AUDIT_POLICY
from provision_selfhost_audit_token import policy_for as audit_policy_for
from provision_selfhost_custody_signer import refresh_scoped_token
from provision_selfhost_evidence_identity import bootstrap as bootstrap_evidence_identity
from provision_selfhost_evidence_identity import checked_login as evidence_login
from provision_selfhost_evidence_identity import mint as mint_evidence_token
from provision_selfhost_evidence_identity import rotate as rotate_evidence_identity
from provision_selfhost_evidence_identity import require_revoked as evidence_revoked
from provision_selfhost_evidence_identity import ROLE_ID_FILE as EVIDENCE_ROLE_ID_FILE
from provision_selfhost_evidence_identity import SECRET_ID_FILE as EVIDENCE_SECRET_ID_FILE
from provision_selfhost_evidence_identity import LEAF_ROLE as EVIDENCE_LEAF_ROLE
from provision_selfhost_snapshot_rotator import bootstrap as bootstrap_snapshot_rotator
from provision_selfhost_snapshot_rotator import rotate_reader as rotate_snapshot_reader
from provision_selfhost_snapshot_rotator import rotate_rotator as rotate_snapshot_rotator
from provision_selfhost_snapshot_rotator import READER_ROTATION, ROTATOR_ROTATION
from selfhost_approle_rotation import require_revoked as rotation_revoked
from provision_selfhost_snapshot_identity import ROLE_ID_FILE as SNAPSHOT_ROLE_ID_FILE
from provision_selfhost_snapshot_identity import SECRET_ID_FILE as SNAPSHOT_SECRET_ID_FILE
from probe_didcomm_openbao_ha import (
    IMAGE,
    ROOT,
    docker,
    docker_process,
    prepare_image,
    request as http_request,
    require_status as http_require_status,
    wait_for,
    wait_for_active_node,
)
from selfhost_openbao_client import (Bao, CUSTODY_SIGNER, CUSTODY_SIGNER_LEAF_ACL,
                                   CUSTODY_SIGNER_POLICY)

DOCKER_ROOT = Path(os.environ.get("MARTY_OPENBAO_PROBE_HOST_ROOT", str(ROOT)))


def bootstrap_failure_diagnostic(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    """Keep actionable failure facts after cleanup without echoing custody data."""
    stages = {
        "Waiting for OpenBao": "listener",
        "Initializing OpenBao": "initialization",
        "Unsealing OpenBao": "unseal",
        "Registering DIDComm": "plugin-registration",
        "Minting Notification webhook OpenBao token": "notification-authority",
        "Minting HAIP workload token": "haip-authority",
        "OpenBao self-host bootstrap complete": "complete",
    }
    stdout, stderr = result.stdout or "", result.stderr or ""
    observed = [(stdout.rfind(message), stage) for message, stage in stages.items() if message in stdout]
    stage = max(observed, default=(-1, "unknown"))[1]
    statuses = sorted({int(value) for value in re.findall(r"\bCode:\s*([1-5][0-9]{2})\b", stderr)})
    patterns = {
        "leader-unavailable": ("not the leader", "no active leader", "failed to contact leader"),
        "sealed": ("vault is sealed", "openbao is sealed"),
        "tls": ("x509:", "tls handshake", "certificate verify failed"),
        "connectivity": ("connection refused", "connection reset", "no such host"),
        "timeout": ("context deadline exceeded", "i/o timeout", "timed out"),
        "authorization": ("permission denied", "invalid token", "missing client token"),
        "plugin-startup": ("error starting plugin", "failed to start plugin", "fork/exec"),
        "resource-exhaustion": ("out of memory", "no space left on device", "resource temporarily unavailable"),
        "file-custody": ("read-only file system", "no such file or directory"),
    }
    lower = stderr.lower()
    classes = sorted(name for name, phrases in patterns.items() if any(phrase in lower for phrase in phrases))
    routes = {"plugin-catalog": "/v1/sys/plugins/catalog", "secret-mount": "/v1/sys/mounts/",
              "acl-policy": "/v1/sys/policies/acl/", "token-create": "/v1/auth/token/create",
              "transit": "/v1/transit/", "didcomm": "/v1/didcomm/"}
    operations = sorted(name for name, prefix in routes.items() if prefix in lower)
    return {"schema": "marty.selfhost-bootstrap-failure/v1", "exit_code": result.returncode,
            "last_observed_stage": stage, "http_statuses": statuses, "error_classes": classes or ["unclassified"],
            "request_categories": operations or ["unclassified"]}


def volume_file(volume: str, path: str) -> str:
    return docker(
        "run", "--rm", "-v", f"{volume}:/bao/data:ro",
        "--entrypoint", "/bin/cat", IMAGE, f"/bao/data/{path}",
    )


def initialize_tls(volume: str, ca_file: Path) -> None:
    docker(
        "run", "--rm", "-v", f"{volume}:/bao/data",
        "--entrypoint", "/usr/local/bin/selfhost-tls-init", IMAGE,
    )
    ca_file.write_text(volume_file(volume, "tls/ca.crt") + "\n", encoding="utf-8")


def server_digest(volume: str) -> str:
    return docker(
        "run", "--rm", "-v", f"{volume}:/bao/data:ro",
        "--entrypoint", "/bin/sh", IMAGE, "-c",
        "sha256sum /bao/data/tls/server.pem",
    ).split()[0]


def start_node(name: str, volume: str, ca_file: Path) -> str:
    config = DOCKER_ROOT / "docker/openbao-selfhost.hcl"
    docker(
        "run", "-d", "--name", name,
        "--label", "marty.disposable=kms-selfhost-probe",
        "-p", "127.0.0.1::8200", "-v", f"{volume}:/bao/data",
        "-v", f"{config}:/bao/config/openbao.hcl:ro",
        IMAGE, "server", "-config=/bao/config/openbao.hcl",
    )
    try:
        port = int(docker("port", name, "8200/tcp").splitlines()[0].rsplit(":", 1)[1])
        base = f"https://127.0.0.1:{port}"
        wait_for(
            "self-host Raft listener",
            lambda: http_request(base, "GET", "sys/health", ca_file=ca_file)[0]
            in (200, 501, 503),
        )
        return base
    except (RuntimeError, IndexError, ValueError) as error:
        logs = docker_process(
            ["docker", "logs", "--tail", "20", name], timeout=10,
        )
        raise RuntimeError(
            f"Disposable Raft server did not start: {(logs.stdout + logs.stderr)[-2500:]}"
        ) from error


def replace_node(name: str, replacement: str, volume: str, ca_file: Path,
                 started: list[str]) -> str:
    """Reload restored custody state and resolve the replacement's fresh port."""
    docker("stop", name)
    docker("rm", name)
    started.remove(name)
    started.append(replacement)
    return start_node(replacement, volume, ca_file)


def run() -> None:
    prepare_image()
    suffix = uuid.uuid4().hex[:12]
    server = f"kms-selfhost-{suffix}"
    state = f"kms-selfhost-state-{suffix}"
    runtime = f"kms-selfhost-runtime-{suffix}"
    cold_state = f"kms-selfhost-cold-{suffix}"
    snapshot_state = f"kms-selfhost-snapshot-{suffix}"
    volumes: list[str] = []
    started: list[str] = []
    public_ca_dir = tempfile.TemporaryDirectory(prefix="marty-selfhost-raft-ca-")
    try:
        for volume in (state, runtime, cold_state, snapshot_state):
            docker(
                "volume",
                "create",
                "--label",
                "marty.disposable=kms-selfhost-probe",
                volume,
            )
            volumes.append(volume)
        ca_file = Path(public_ca_dir.name) / "ca.crt"
        initialize_tls(state, ca_file)
        before_rotation = server_digest(state)
        docker(
            "run", "--rm", "-v", f"{state}:/bao/data",
            "--entrypoint", "/usr/local/bin/selfhost-tls-init",
            IMAGE, "-rotate",
        )
        if server_digest(state) == before_rotation:
            raise RuntimeError("OpenBao listener rotation did not replace its key")
        if volume_file(state, "tls/ca.crt") != ca_file.read_text(encoding="utf-8").strip():
            raise RuntimeError("OpenBao listener rotation changed the trusted public CA")
        permissions = docker(
            "run", "--rm", "-v", f"{state}:/bao/data:ro",
            "--entrypoint", "/bin/sh", IMAGE, "-c",
            "stat -c '%a:%U' /bao/data/tls/server.pem",
        )
        if permissions != "600:openbao":
            raise RuntimeError("Rotated TLS identity escaped OpenBao file custody")
        request = partial(http_request, ca_file=ca_file)
        require_status = partial(http_require_status, ca_file=ca_file)
        started.append(server)
        base = start_node(server, state, ca_file)
        if request(base, "GET", "sys/health")[0] != 501:
            raise RuntimeError("Fresh self-host Raft state was initialized unexpectedly")
        bootstrap_command = [
                "docker",
                "run",
                "--rm",
                "--network",
                f"container:{server}",
                "-e",
                "BAO_ADDR=https://127.0.0.1:8200",
                "-e",
                "BAO_CACERT=/bao/data/tls/ca.crt",
                "-e",
                "DIDCOMM_KMS_PLUGIN_REQUIRED=true",
                "-v",
                f"{state}:/bao/data",
                "-v",
                f"{runtime}:/bao/runtime",
                "-v",
                f"{DOCKER_ROOT / 'docker/openbao-init.sh'}:/scripts/openbao-init.sh:ro",
                "-v",
                f"{DOCKER_ROOT / 'docker/openbao-selfhost-init.sh'}:/scripts/openbao-selfhost-init.sh:ro",
                "-v",
                f"{DOCKER_ROOT / 'docker/openbao-haip-workload-policy.hcl'}:/scripts/openbao-haip-workload-policy.hcl:ro",
                "--entrypoint",
                "/bin/sh",
                IMAGE,
                "/scripts/openbao-selfhost-init.sh",
            ]
        result = docker_process(bootstrap_command, timeout=300)
        if result.returncode:
            diagnostic = json.dumps(bootstrap_failure_diagnostic(result), sort_keys=True)
            raise RuntimeError(f"Disposable self-host Raft bootstrap failed: {diagnostic}")
        docker(
            "run", "--rm", "-v", f"{state}:/bao/data:ro",
            "--entrypoint", "/bin/sh", IMAGE, "-c",
            "test ! -e /bao/data/selfhost-init.json",
        )
        repeated = docker_process(bootstrap_command, timeout=60)
        if repeated.returncode == 0 or "requires fresh, uninitialized Raft state" not in repeated.stderr:
            raise RuntimeError(
                "Initialized OpenBao bootstrap refusal differed: "
                f"exit={repeated.returncode}, stderr={repeated.stderr[-300:]}"
            )
        published_ca = docker(
            "run", "--rm", "-v", f"{runtime}:/bao/runtime:ro",
            "--entrypoint", "/bin/cat", IMAGE,
            "/bao/runtime/openbao_tls_ca_cert",
        )
        if published_ca.strip() != ca_file.read_text(encoding="utf-8").strip():
            raise RuntimeError("Disposable bootstrap published the wrong public CA")
        if "PRIVATE KEY" in published_ca:
            raise RuntimeError("Disposable runtime CA contains private key material")
        root = volume_file(state, "root.token")
        if len(root) < 16:
            raise RuntimeError("Disposable bootstrap did not retain its root token")
        static_root = Path(public_ca_dir.name) / "static-token-audit"
        static_root.mkdir(mode=0o700)
        default_runtime_names = {
            "openbao_service_token": "credential-service.token",
            "notification_openbao_token": "notification-webhook-service.token",
            "haip_kms_token": "haip-kms.token",
        }
        for name in STATIC_KMS_TOKENS:
            (static_root / name).write_text(
                volume_file(runtime, default_runtime_names.get(name, name)),
                encoding="ascii",
            )
        checked_static_tokens(Bao(base, ca_file, root), static_root, 3600)
        leader = require_status(base, "GET", "sys/leader", root)
        if leader.get("is_self") is not True:
            raise RuntimeError("Disposable self-host Raft node is not active")
        did = "did:example:selfhost-probe"
        sender = require_status(
            base,
            "POST",
            "didcomm/keys/tenant_a/sender",
            root,
            {"sender_did": did, "sender_key_id": did + "#agreement-1"},
        )
        haip = require_status(
            base, "POST", "didcomm/haip/keys/tenant_a/flow_a", root, {}
        )
        sender_version = sender["data"]["version"]
        haip_version = haip["data"]["version"]
        key_name = "integration-secret-envelope-marty-aes256"
        metadata = require_status(base, "GET", f"transit/keys/{key_name}", root)["data"]
        if (
            metadata.get("type") != "aes256-gcm96"
            or metadata.get("exportable") is not False
            or metadata.get("allow_plaintext_backup") is not False
        ):
            raise RuntimeError("Disposable integration-secret key has unsafe metadata")
        token = docker(
            "run", "--rm", "-v", f"{runtime}:/bao/runtime:ro",
            "--entrypoint", "/bin/cat", IMAGE,
            "/bao/runtime/signing_keys_openbao_token",
        )
        encrypted = require_status(
            base,
            "POST",
            f"transit/encrypt/{key_name}",
            token,
            {"plaintext": "cHJvYmU="},
        )["data"]["ciphertext"]
        decrypted = require_status(
            base,
            "POST",
            f"transit/decrypt/{key_name}",
            token,
            {"ciphertext": encrypted},
        )["data"]["plaintext"]
        if decrypted != "cHJvYmU=":
            raise RuntimeError(
                "Scoped token could not decrypt integration-secret proof"
            )
        if (
            request(
                base, "GET", f"transit/export/encryption-key/{key_name}", token=token
            )[0]
            != 403
        ):
            raise RuntimeError(
                "Scoped token unexpectedly exported integration-secret key"
            )
        host_state = Path(public_ca_dir.name) / "state"
        host_state.mkdir()
        (host_state / "tls").mkdir()
        (host_state / "tls" / "ca.crt").write_bytes(ca_file.read_bytes())
        root_file = host_state / "root.token"
        root_file.write_text(volume_file(state, "root.token"), encoding="utf-8")
        root_file.chmod(0o600)
        evidence_bao = Bao(base, ca_file, root)
        evidence_bao.request("POST", f"transit/keys/{CUSTODY_SIGNER}", {
            "type": "ed25519", "exportable": False,
            "allow_plaintext_backup": False,
        })
        evidence_bao.request("PUT", f"sys/policies/acl/{CUSTODY_SIGNER_POLICY}", {
            "policy": CUSTODY_SIGNER_LEAF_ACL,
        })
        evidence_identity = Path(public_ca_dir.name) / "evidence-identity"
        evidence_identity.mkdir(mode=0o700)
        bootstrap_evidence_identity(evidence_bao, evidence_identity)
        retired_evidence_identity = evidence_identity
        evidence_identity = Path(public_ca_dir.name) / "evidence-identity-rotated"
        evidence_identity.mkdir(mode=0o700)
        rotate_evidence_identity(Bao(base, ca_file, ""), retired_evidence_identity,
                                 evidence_identity)
        minted_initial = evidence_bao.request("POST", "auth/token/create", {
            "policies": [CUSTODY_SIGNER_POLICY], "no_default_policy": True,
            "no_parent": True, "renewable": False, "ttl": "1h",
            "explicit_max_ttl": "1h",
        })
        first_evidence_leaf = minted_initial.get("auth", {}).get("client_token")
        if not isinstance(first_evidence_leaf, str) or len(first_evidence_leaf) < 20:
            raise RuntimeError("Initial orphan evidence token is absent")
        mint_evidence_token(Bao(base, ca_file, ""), evidence_identity)
        audit_org = "00000000-0000-0000-0000-000000000001"
        audit_policy, audit_paths = audit_policy_for(
            audit_org, "marty", "did:web:localhost:orgs:marty",
        )
        for path in audit_paths[:2]:
            evidence_bao.request("POST", path, {
                "type": "ed25519", "exportable": False,
                "allow_plaintext_backup": False,
            })
        evidence_bao.request("PUT", f"sys/policies/acl/{AUDIT_POLICY}", {
            "policy": audit_policy,
        })
        audit_identity = Path(public_ca_dir.name) / "audit-identity"
        audit_identity.mkdir(mode=0o700)
        bootstrap_audit_identity(evidence_bao, audit_identity, audit_policy)
        retired_audit_identity = audit_identity
        audit_identity = Path(public_ca_dir.name) / "audit-identity-rotated"
        audit_identity.mkdir(mode=0o700)
        rotate_audit_identity(Bao(base, ca_file, ""), retired_audit_identity,
                              audit_identity, audit_policy)
        initial_audit = evidence_bao.request("POST", "auth/token/create", {
            "policies": [AUDIT_POLICY], "no_default_policy": True,
            "no_parent": True, "renewable": False, "ttl": "1h",
            "explicit_max_ttl": "1h",
        }).get("auth", {}).get("client_token")
        if not isinstance(initial_audit, str) or len(initial_audit) < 20:
            raise RuntimeError("Initial orphan audit token is absent")
        identity = Path(public_ca_dir.name) / "snapshot-identity"
        identity.mkdir(mode=0o700)
        provision = subprocess.run(
            [sys.executable, str(ROOT / "scripts/provision_selfhost_snapshot_identity.py"),
             "--bao-addr", base, "--bao-ca", str(host_state / "tls" / "ca.crt"),
             "--root-token-file", str(root_file), "--output", str(identity)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if provision.returncode:
            raise RuntimeError(f"Disposable snapshot identity failed: {provision.stderr[-800:]}")
        snapshot_rotator = Path(public_ca_dir.name) / "snapshot-rotator-identity"
        snapshot_rotator.mkdir(mode=0o700)
        bootstrap_snapshot_rotator(evidence_bao, snapshot_rotator)
        root_file.unlink()
        exported = Path(public_ca_dir.name) / "exports"
        exported.mkdir(mode=0o700)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/export-selfhost-openbao.py"),
             "--state-dir", str(host_state), "--export-dir", str(exported),
             "--bao-url", base, "--snapshot-identity-dir", str(identity)],
            capture_output=True, text=True, timeout=300, check=False,
        )
        if result.returncode:
            raise RuntimeError(f"Disposable HTTPS Raft export failed: {result.stderr[-800:]}")
        with zipfile.ZipFile(next(exported.glob("*.zip"))) as bundle:
            if any(name.startswith("recovery/") for name in bundle.namelist()):
                raise RuntimeError("Raft archive leaked root or unseal recovery material")
            snapshot = bundle.read("raft.snap")
            manifest = json.loads(bundle.read("manifest.json"))
        if hashlib.sha256(snapshot).hexdigest() != manifest["snapshot_sha256"]:
            raise RuntimeError("Disposable Raft snapshot checksum differs")

        # A stopped full-state copy retains the KMS-owned TLS identity.
        docker("stop", server)
        docker("rm", server)
        started.remove(server)
        docker(
            "run", "--rm", "-v", f"{state}:/source:ro",
            "-v", f"{cold_state}:/target", "--entrypoint", "/bin/sh",
            IMAGE, "-c", "cp -a /source/. /target/",
        )
        cold_name = f"{server}-cold"
        started.append(cold_name)
        cold_base = start_node(cold_name, cold_state, ca_file)
        require_status(cold_base, "POST", "sys/unseal", "",
                       {"key": volume_file(state, "unseal.key")})
        wait_for_active_node(cold_base, ca_file=ca_file,
                             operation="cold-copy Raft leader after unseal")
        cold = partial(http_require_status, ca_file=ca_file)
        if cold(cold_base, "POST", f"transit/decrypt/{key_name}", root,
                {"ciphertext": encrypted})["data"]["plaintext"] != "cHJvYmU=":
            raise RuntimeError("Cold Raft state copy lost Transit ciphertext")
        if cold(cold_base, "GET", "didcomm/keys/tenant_a/sender/versions/"
                f"{sender_version}", root)["data"]["version"] != sender_version:
            raise RuntimeError("Cold Raft state copy lost DIDComm key version")
        if cold(cold_base, "GET", "didcomm/haip/keys/tenant_a/flow_a/versions/"
                f"{haip_version}", root)["data"]["version"] != haip_version:
            raise RuntimeError("Cold Raft state copy lost HAIP key version")

        # The dedicated snapshot identity must survive revocation of the
        # original bootstrap root on the copied Raft state.
        revoked_status, revoked_response = http_request(
            cold_base, "POST", "auth/token/revoke-self", token=root,
            ca_file=ca_file, revocation_error_diagnostics=True,
        )
        if revoked_status not in (200, 204):
            root_lookup_status = http_request(
                cold_base, "GET", "auth/token/lookup-self", token=root,
                ca_file=ca_file,
            )[0]
            health_status = http_request(
                cold_base, "GET", "sys/health", ca_file=ca_file,
            )[0]
            raise RuntimeError(
                f"Bootstrap root revocation failed: status {revoked_status}; "
                f"classes {revoked_response.get('error_classes', [])}; "
                f"root lookup status {root_lookup_status}; health status {health_status}"
            )
        if http_request(cold_base, "GET", f"transit/keys/{key_name}",
                        token=root, ca_file=ca_file)[0] != 403:
            raise RuntimeError("Revoked bootstrap root still has KMS access")
        old_snapshot_rotator = snapshot_rotator
        snapshot_rotator = Path(public_ca_dir.name) / "snapshot-rotator-identity-next"
        snapshot_rotator.mkdir(mode=0o700)
        rotate_snapshot_rotator(Bao(cold_base, ca_file, ""),
                                old_snapshot_rotator, snapshot_rotator)
        rotation_revoked(
            Bao(cold_base, ca_file, ""),
            (old_snapshot_rotator / ROTATOR_ROTATION.role_id_file).read_text().strip(),
            (old_snapshot_rotator / ROTATOR_ROTATION.secret_id_file).read_text().strip(),
            ROTATOR_ROTATION,
        )
        old_snapshot_reader = identity
        identity = Path(public_ca_dir.name) / "snapshot-identity-next"
        identity.mkdir(mode=0o700)
        rotate_snapshot_reader(Bao(cold_base, ca_file, ""), old_snapshot_reader,
                               identity, snapshot_rotator)
        rotation_revoked(
            Bao(cold_base, ca_file, ""),
            (old_snapshot_reader / SNAPSHOT_ROLE_ID_FILE).read_text().strip(),
            (old_snapshot_reader / SNAPSHOT_SECRET_ID_FILE).read_text().strip(),
            READER_ROTATION,
        )
        evidence_revoked(
            Bao(cold_base, ca_file, ""),
            (retired_evidence_identity / EVIDENCE_ROLE_ID_FILE).read_text().strip(),
            (retired_evidence_identity / EVIDENCE_SECRET_ID_FILE).read_text().strip(),
        )
        renewed_evidence_leaf = mint_evidence_token(Bao(cold_base, ca_file, ""),
                                                    evidence_identity)
        evidence_file = Path(public_ca_dir.name) / "evidence-leaf.token"
        evidence_file.write_text(first_evidence_leaf, encoding="ascii")
        operator = evidence_login(Bao(cold_base, ca_file, ""), evidence_identity)
        refresh_scoped_token(
            Bao(cold_base, ca_file, operator), evidence_file, renewed_evidence_leaf,
            lambda path, value, _mode: path.write_text(value, encoding="ascii"),
        )
        if (evidence_file.read_text(encoding="ascii") != renewed_evidence_leaf
                or http_request(cold_base, "GET", f"transit/keys/{CUSTODY_SIGNER}",
                                token=first_evidence_leaf, ca_file=ca_file)[0] != 403):
            raise RuntimeError("Rootless evidence refresh retained its old token")
        renewed_audit = mint_audit_token(Bao(cold_base, ca_file, ""), audit_identity,
                                        audit_policy, audit_paths)
        audit_revoked(
            Bao(cold_base, ca_file, ""),
            (retired_audit_identity / AUDIT_ROLE_ID_FILE).read_text().strip(),
            (retired_audit_identity / AUDIT_SECRET_ID_FILE).read_text().strip(),
        )
        audit_file = Path(public_ca_dir.name) / "audit-leaf.token"
        audit_file.write_text(initial_audit, encoding="ascii")
        audit_operator = audit_login(Bao(cold_base, ca_file, ""), audit_identity,
                                     audit_policy)
        refresh_scoped_token(
            Bao(cold_base, ca_file, audit_operator), audit_file, renewed_audit,
            lambda path, value, _mode: path.write_text(value, encoding="ascii"),
        )
        if (audit_file.read_text(encoding="ascii") != renewed_audit
                or http_request(cold_base, "GET", audit_paths[0],
                                token=initial_audit, ca_file=ca_file)[0] != 403
                or http_request(cold_base, "GET", audit_paths[0],
                                token=renewed_audit, ca_file=ca_file)[0] != 200):
            raise RuntimeError("Rootless audit refresh lost scoped read authority")
        # Mint short-lived orphan leaves only after root revocation, prove they
        # work before expiry, then exercise the expired-token refresh branch.
        short_evidence = Bao(cold_base, ca_file, operator).request(
            "POST", f"auth/token/create/{EVIDENCE_LEAF_ROLE}", {
                "policies": [CUSTODY_SIGNER_POLICY], "no_default_policy": True,
                "renewable": False, "ttl": "3s", "explicit_max_ttl": "3s",
            },
        ).get("auth", {}).get("client_token")
        short_audit = Bao(cold_base, ca_file, audit_operator).request(
            "POST", f"auth/token/create/{AUDIT_LEAF_ROLE}", {
                "policies": [AUDIT_POLICY], "no_default_policy": True,
                "renewable": False, "ttl": "3s", "explicit_max_ttl": "3s",
            },
        ).get("auth", {}).get("client_token")
        if (not isinstance(short_evidence, str) or len(short_evidence) < 20
                or not isinstance(short_audit, str) or len(short_audit) < 20
                or http_request(cold_base, "GET", f"transit/keys/{CUSTODY_SIGNER}",
                                token=short_evidence, ca_file=ca_file)[0] != 200
                or http_request(cold_base, "GET", audit_paths[0],
                                token=short_audit, ca_file=ca_file)[0] != 200):
            raise RuntimeError("Short-lived rootless custody leaves are invalid")
        wait_for(
            "short-lived evidence and audit leaves to expire",
            lambda: (
                http_request(cold_base, "GET", f"transit/keys/{CUSTODY_SIGNER}",
                             token=short_evidence, ca_file=ca_file)[0] == 403
                and http_request(cold_base, "GET", audit_paths[0],
                                 token=short_audit, ca_file=ca_file)[0] == 403
            ),
            seconds=20,
        )
        expired_evidence_file = Path(public_ca_dir.name) / "expired-evidence.token"
        expired_evidence_file.write_text(short_evidence, encoding="ascii")
        after_expiry_evidence = mint_evidence_token(Bao(cold_base, ca_file, ""),
                                                    evidence_identity)
        refresh_scoped_token(
            Bao(cold_base, ca_file, operator), expired_evidence_file,
            after_expiry_evidence,
            lambda path, value, _mode: path.write_text(value, encoding="ascii"),
        )
        expired_audit_file = Path(public_ca_dir.name) / "expired-audit.token"
        expired_audit_file.write_text(short_audit, encoding="ascii")
        after_expiry_audit = mint_audit_token(Bao(cold_base, ca_file, ""),
                                              audit_identity, audit_policy,
                                              audit_paths)
        refresh_scoped_token(
            Bao(cold_base, ca_file, audit_operator), expired_audit_file,
            after_expiry_audit,
            lambda path, value, _mode: path.write_text(value, encoding="ascii"),
        )
        if (expired_evidence_file.read_text(encoding="ascii") != after_expiry_evidence
                or expired_audit_file.read_text(encoding="ascii") != after_expiry_audit
                or http_request(cold_base, "GET", f"transit/keys/{CUSTODY_SIGNER}",
                                token=after_expiry_evidence, ca_file=ca_file)[0] != 200
                or http_request(cold_base, "GET", audit_paths[0],
                                token=after_expiry_audit, ca_file=ca_file)[0] != 200):
            raise RuntimeError("Rootless custody token recovery failed after expiry")
        rootless_exports = Path(public_ca_dir.name) / "rootless-exports"
        rootless_exports.mkdir(mode=0o700)
        rootless = subprocess.run(
            [sys.executable, str(ROOT / "scripts/export-selfhost-openbao.py"),
             "--state-dir", str(host_state), "--export-dir", str(rootless_exports),
             "--bao-url", cold_base, "--snapshot-identity-dir", str(identity)],
            capture_output=True, text=True, timeout=300, check=False,
        )
        if rootless.returncode:
            raise RuntimeError(f"Rootless Raft export failed: {rootless.stderr[-800:]}")
        with zipfile.ZipFile(next(rootless_exports.glob("*.zip"))) as bundle:
            if (bundle.read("raft.snap") == b"" or
                    any(name.startswith("recovery/") for name in bundle.namelist())):
                raise RuntimeError("Rootless Raft archive is invalid")

        # A fresh node has its own TLS CA; a Raft snapshot never exports that
        # node-local private identity into the application or archive.
        snapshot_ca = Path(public_ca_dir.name) / "snapshot-ca.crt"
        initialize_tls(snapshot_state, snapshot_ca)
        snapshot_name = f"{server}-snapshot"
        started.append(snapshot_name)
        snapshot_base = start_node(snapshot_name, snapshot_state, snapshot_ca)
        fresh = partial(http_require_status, ca_file=snapshot_ca)
        initialized = fresh(snapshot_base, "POST", "sys/init", "",
                            {"secret_shares": 1, "secret_threshold": 1},
                            timeout=30)
        fresh(snapshot_base, "POST", "sys/unseal", "",
              {"key": initialized["keys_base64"][0]})
        wait_for_active_node(snapshot_base, ca_file=snapshot_ca,
                             operation="replacement Raft leader before restore")
        restore_request = urllib.request.Request(
            snapshot_base + "/v1/sys/storage/raft/snapshot-force",
            data=snapshot, method="POST",
            headers={"X-Vault-Token": initialized["root_token"],
                     "Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(
            restore_request, timeout=60,
            context=ssl.create_default_context(cafile=str(snapshot_ca)),
        ) as response:  # noqa: S310 - verified disposable loopback TLS
            if response.status not in (200, 204):
                raise RuntimeError("Fresh Raft snapshot force-restore failed")
        wait_for(
            "force-restored Raft node to seal",
            lambda: http_request(snapshot_base, "GET", "sys/seal-status",
                                 ca_file=snapshot_ca)[1].get("sealed") is True,
        )
        # A force restore replaces the persisted barrier/seal configuration.
        # Reload it before submitting the original recovery key, just as the
        # coordinated restore path does; the fresh process must use a newly
        # resolved published port rather than the stopped node's endpoint.
        restored_name = f"{server}-snapshot-reloaded"
        snapshot_base = replace_node(snapshot_name, restored_name, snapshot_state,
                                     snapshot_ca, started)
        snapshot_name = restored_name
        original_unseal_key = volume_file(state, "unseal.key")
        unseal_statuses: set[int] = set()
        unseal_error_classes: set[str] = set()

        def restored_unseal_ready() -> bool:
            status, response = http_request(snapshot_base, "POST", "sys/unseal",
                                            {"key": original_unseal_key},
                                            ca_file=snapshot_ca,
                                            unseal_error_diagnostics=True)
            unseal_statuses.add(status)
            unseal_error_classes.update(response.get("error_classes", []))
            return status == 200 and response.get("sealed") is False

        try:
            wait_for("force-restored Raft node to accept original unseal key",
                     restored_unseal_ready, seconds=90)
        except RuntimeError as error:
            raise RuntimeError(
                f"Force-restored Raft unseal failed with statuses "
                f"{sorted(unseal_statuses)}; classified errors "
                f"{sorted(unseal_error_classes)}"
            ) from error
        wait_for_active_node(snapshot_base, ca_file=snapshot_ca,
                             operation="restored Raft leader after original-key unseal")
        if fresh(snapshot_base, "POST", f"transit/decrypt/{key_name}", root,
                 {"ciphertext": encrypted})["data"]["plaintext"] != "cHJvYmU=":
            raise RuntimeError("Force-restored Raft node lost Transit ciphertext")
        restored_name = f"{server}-restored"
        snapshot_base = replace_node(snapshot_name, restored_name, snapshot_state,
                                     snapshot_ca, started)
        snapshot_name = restored_name
        if fresh(snapshot_base, "GET", "sys/seal-status", "").get("sealed"):
            fresh(snapshot_base, "POST", "sys/unseal", "",
                  {"key": original_unseal_key})
        wait_for_active_node(snapshot_base, ca_file=snapshot_ca,
                             operation="restarted restored Raft leader")
        if fresh(snapshot_base, "POST", f"transit/decrypt/{key_name}", root,
                 {"ciphertext": encrypted})["data"]["plaintext"] != "cHJvYmU=":
            raise RuntimeError("Snapshot restore lost Transit ciphertext")
        if fresh(snapshot_base, "GET", "didcomm/haip/keys/tenant_a/flow_a/versions/"
                 f"{haip_version}", root)["data"]["version"] != haip_version:
            raise RuntimeError("Snapshot restore lost HAIP key version")
        if fresh(snapshot_base, "GET", "didcomm/keys/tenant_a/sender/versions/"
                 f"{sender_version}", root)["data"]["version"] != sender_version:
            raise RuntimeError("Snapshot restore lost DIDComm key version")
        print("Self-host HTTPS Raft bootstrap, cold copy and snapshot recovery passed")
    finally:
        for name in reversed(started):
            docker_process(["docker", "rm", "-f", name], timeout=30)
        for volume in reversed(volumes):
            docker_process(["docker", "volume", "rm", volume], timeout=30)
        public_ca_dir.cleanup()


if __name__ == "__main__":
    run()
