"""Exercise Rust integration-secret reads after disposable PostgreSQL/Raft restore.

This opt-in probe builds candidate Rust binaries and the OpenBao plugin locally.
It uses random, labeled Docker containers and synthetic data only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path

from probe_didcomm_openbao_ha import (
    IMAGE,
    ROOT,
    docker,
    prepare_image,
    request,
    require_status,
    wait_for,
)
from with_disposable_event_stream_kms import execute as with_disposable_tls_kms

INTEGRATION_SECRET_KEY = "disposable-dedicated-integration-secret-key-32-chars"

CATALOG = json.loads(
    (ROOT / "deploy-config/passport-supported-disposable-infra-images.json").read_text(
        encoding="utf-8"
    )
)["images"]
DATABASE = "marty_kms_restore_test"
PASSWORD = "disposable-test-only"
GO_IMAGE = next(
    line.split()[1]
    for line in (ROOT / "openbao/didcomm-authcrypt/Dockerfile")
    .read_text(encoding="utf-8")
    .splitlines()
    if line.startswith("FROM golang:")
)
RUST_PREPARATION_PHASES = (
    "signing_keys_binary",
    "signing_keys_holder_proof",
    "issuance_library",
    "issuance_oauth_postgres",
    "issuance_remote_kms",
    "flow_haip_live_signing",
    "flow_haip_remote_http",
    "flow_haip_expired_http",
)
CACHE_SNAPSHOT_PHASES = ("preparation_baseline",) + RUST_PREPARATION_PHASES
PUBLIC_CACHE_COUNTERS = frozenset(
    {
        "compile_requests",
        "compile_requests_executed",
        "cache_hits",
        "cache_hits_rust",
        "cache_misses",
        "cache_misses_rust",
        "cache_timeouts",
        "cache_read_errors",
        "cache_write_errors",
        "non_cacheable_compilations",
        "non_cacheable_calls",
        "unsupported_compiler_calls",
    }
)


def record_preparation_timing(phase: str, status: str, started: float) -> None:
    # Fixed labels only: do not retain commands, paths, exceptions or environment.
    if phase not in RUST_PREPARATION_PHASES or status not in {"ok", "failed", "timeout", "error"}:
        raise ValueError("Unknown recovery preparation timing label")
    record = {
        "schema_version": 1,
        "phase": phase,
        "status": status,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
    }
    line = json.dumps(record, sort_keys=True)
    print(f"MARTY_RECOVERY_PREPARATION_V1 {line}", flush=True)
    output = os.environ.get("MARTY_RECOVERY_PREPARATION_TIMING_FILE")
    if output:
        try:
            with Path(output).open("a", encoding="utf-8", newline="\n") as evidence:
                evidence.write(line + "\n")
        except OSError:
            print("[kms-recovery-prepare] optional timing artifact unavailable", flush=True)


def record_preparation_cache(phase: str) -> bool:
    """Retain allowlisted counters; stop sampling after an unavailable snapshot."""
    if phase not in CACHE_SNAPSHOT_PHASES:
        raise ValueError("Unknown recovery preparation cache label")
    output = os.environ.get("MARTY_RECOVERY_PREPARATION_CACHE_FILE")
    if not output:
        return False
    try:
        stats = subprocess.run(
            ["sccache", "--show-stats"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if stats.returncode:
            return False
        sanitized = subprocess.run(
            [
                "awk",
                "-v",
                "phase=recovery_probe",
                "-f",
                str(ROOT / "scripts/ci/public-sccache-stats.awk"),
            ],
            input=stats.stdout,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if sanitized.returncode:
            return False
        prefix = "MARTY_PUBLIC_SCCACHE_V1 "
        if not isinstance(sanitized.stdout, str) or not sanitized.stdout.startswith(prefix):
            return False
        parsed = json.loads(sanitized.stdout[len(prefix) :])
        if not isinstance(parsed, dict):
            return False
        counters = parsed.get("counters")
        if parsed.get("phase") != "recovery_probe" or not isinstance(counters, dict):
            return False
        if not counters or not set(counters) <= PUBLIC_CACHE_COUNTERS:
            return False
        if any(type(value) is not int or value < 0 for value in counters.values()):
            return False
        record = {"schema_version": 1, "phase": phase, "counters": counters}
        with Path(output).open("a", encoding="utf-8", newline="\n") as evidence:
            evidence.write(json.dumps(record, sort_keys=True) + "\n")
        return True
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        # This optional diagnostic must not replace the live restore result.
        print("[kms-recovery-prepare] optional cache artifact unavailable", flush=True)
        return False


def port_of(name: str, internal: str) -> int:
    return int(docker("port", name, internal).splitlines()[0].rsplit(":", 1)[1])


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def build_rust() -> Path:
    rust = ROOT / "rust"
    commands = (
        [
            "cargo",
            "+1.95.0",
            "build",
            "--locked",
            "-p",
            "marty-signing-keys",
            "--bin",
            "marty-signing-keys",
            "-j",
            "1",
        ],
        [
            "cargo",
            "+1.95.0",
            "test",
            "--locked",
            "-p",
            "marty-signing-keys",
            "--test",
            "vc_api_holder_proof_live_kms",
            "--no-run",
            "-j",
            "1",
        ],
        [
            "cargo",
            "+1.95.0",
            "test",
            "--locked",
            "-p",
            "marty-issuance-service",
            "--lib",
            "--no-run",
            "-j",
            "1",
        ],
        [
            "cargo",
            "+1.95.0",
            "test",
            "--locked",
            "-p",
            "marty-issuance-service",
            "--test",
            "canvas_oauth_postgres_contract",
            "--no-run",
            "-j",
            "1",
        ],
        [
            "cargo",
            "+1.95.0",
            "test",
            "--locked",
            "-p",
            "marty-issuance-service",
            "--test",
            "didcomm_remote_kms_live",
            "--no-run",
            "-j",
            "1",
        ],
        *(
            [
                "cargo",
                "+1.95.0",
                "test",
                "--locked",
                "-p",
                "marty-flow",
                "--test",
                target,
                "--no-run",
                "-j",
                "1",
            ]
            for target in ("haip_live_signing", "haip_remote_http", "haip_expired_http")
        ),
    )
    cache_available = record_preparation_cache("preparation_baseline")
    for phase, command in zip(RUST_PREPARATION_PHASES, commands, strict=True):
        print(f"[kms-recovery-prepare] starting {phase}", flush=True)
        started = time.monotonic()
        status = "error"
        try:
            result = subprocess.run(command, cwd=rust, timeout=1800, check=False)
            if result.returncode:
                status = "failed"
                raise RuntimeError("Candidate Rust recovery target did not build")
            status = "ok"
        except subprocess.TimeoutExpired:
            status = "timeout"
            raise RuntimeError("Candidate Rust recovery preparation timed out") from None
        except OSError:
            raise RuntimeError("Candidate Rust recovery preparation could not start") from None
        finally:
            record_preparation_timing(phase, status, started)
            if cache_available:
                cache_available = record_preparation_cache(phase)
    binary = (
        rust
        / "target/debug"
        / ("marty-signing-keys.exe" if os.name == "nt" else "marty-signing-keys")
    )
    if not binary.is_file():
        raise RuntimeError("Candidate Signing Keys binary is missing")
    return binary


def start_postgres(name: str, volume: str) -> tuple[str, int]:
    docker(
        "run",
        "--rm",
        "-d",
        "--name",
        name,
        "--label",
        "marty.disposable=kms-coordinated-restore",
        "-p",
        "127.0.0.1::5432",
        "-e",
        f"POSTGRES_PASSWORD={PASSWORD}",
        "-e",
        f"POSTGRES_DB={DATABASE}",
        "-v",
        f"{volume}:/var/lib/postgresql/data",
        CATALOG["postgres"]["reference"],
    )
    wait_for(
        "PostgreSQL readiness",
        lambda: (
            subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "pg_isready",
                    "-U",
                    "postgres",
                    "-d",
                    DATABASE,
                ],
                capture_output=True,
                timeout=5,
                check=False,
            ).returncode
            == 0
        ),
        seconds=60,
    )
    # The image briefly starts a bootstrap server before its final postmaster.
    time.sleep(2)
    wait_for(
        "PostgreSQL final postmaster",
        lambda: (
            subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "pg_isready",
                    "-U",
                    "postgres",
                    "-d",
                    DATABASE,
                ],
                capture_output=True,
                timeout=5,
                check=False,
            ).returncode
            == 0
        ),
        seconds=60,
    )
    port = port_of(name, "5432/tcp")
    return f"postgresql://postgres:{PASSWORD}@127.0.0.1:{port}/{DATABASE}", port


def start_bao(name: str, volume: str, ca_file: Path) -> str:
    config = ROOT / "docker/openbao-selfhost.hcl"
    docker(
        "run",
        "--rm",
        "-d",
        "--name",
        name,
        "--label",
        "marty.disposable=kms-coordinated-restore",
        "-p",
        "127.0.0.1::8200",
        "-v",
        f"{volume}:/bao/data",
        "-v",
        f"{config}:/bao/config/openbao.hcl:ro",
        IMAGE,
        "server",
        "-config=/bao/config/openbao.hcl",
    )
    base = f"https://127.0.0.1:{port_of(name, '8200/tcp')}"
    wait_for(
        "OpenBao listener",
        lambda: request(base, "GET", "sys/health", ca_file=ca_file)[0]
        in (200, 501, 503),
        seconds=60,
    )
    return base


def bootstrap_bao(name: str, state: str, runtime: str) -> None:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            f"container:{name}",
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
            f"{ROOT / 'docker/openbao-init.sh'}:/scripts/openbao-init.sh:ro",
            "-v",
            f"{ROOT / 'docker/openbao-selfhost-init.sh'}:/scripts/openbao-selfhost-init.sh:ro",
            "-v",
            f"{ROOT / 'docker/openbao-haip-workload-policy.hcl'}:/scripts/openbao-haip-workload-policy.hcl:ro",
            "--entrypoint",
            "/bin/sh",
            IMAGE,
            "/scripts/openbao-selfhost-init.sh",
        ],
        capture_output=True,
        timeout=300,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Disposable OpenBao bootstrap failed")


def read_volume_file(volume: str, path: str) -> str:
    return docker(
        "run",
        "--rm",
        "-v",
        f"{volume}:/volume:ro",
        "--entrypoint",
        "/bin/cat",
        IMAGE,
        f"/volume/{path}",
    )


def start_signing(
    binary: Path,
    bao_url: str,
    bao_ca_file: Path,
    token: str,
    haip_token_file: Path,
    grant_verify_token_file: Path,
    redis_port: int,
    key: str,
    log_path: Path,
):
    port = free_port()
    tls_port = free_port()
    while tls_port == port:
        tls_port = free_port()
    tls_cert = os.environ["MARTY_TEST_SIGNING_KEYS_TLS_CERT"]
    tls_ca = os.environ["MARTY_TEST_SIGNING_KEYS_TLS_CA"]
    tls_kms_ca = os.environ["MARTY_TEST_SIGNING_KEYS_TLS_KMS_CA"]
    tls_kms_token = os.environ["MARTY_TEST_SIGNING_KEYS_TLS_KMS_TOKEN_FILE"]
    tls_kms_key = os.environ["MARTY_TEST_SIGNING_KEYS_TLS_KMS_KEY_NAME"]
    tls_kms_url = os.environ["MARTY_TEST_SIGNING_KEYS_TLS_KMS_URL"]
    if not tls_kms_url.startswith("https://"):
        raise RuntimeError("Coordinated restore requires HTTPS remote TLS KMS")
    environment = os.environ.copy()
    environment.update(
        {
            "MARTY_RELEASE_VERSION": "development",
            "SIGNING_KEYS_SERVICE_PORT": str(port),
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_PORT": str(tls_port),
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE": tls_cert,
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_ADDR": tls_kms_url,
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_CA_CERT_FILE": tls_kms_ca,
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_TOKEN_FILE": tls_kms_token,
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_NAME": tls_kms_key,
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_VERSION": "1",
            "SIGNING_KEYS_INTERNAL_API_KEY": key,
            "SIGNING_KEYS_INTEGRATION_SECRET_KEY": INTEGRATION_SECRET_KEY,
            "SIGNING_KEYS_REDIS_URL": f"redis://127.0.0.1:{redis_port}/2",
            "ISSUER_BASE_URL": "https://issuer.example",
            "BAO_ADDR": bao_url,
            "BAO_CACERT": str(bao_ca_file),
            "BAO_TOKEN": token,
            "HAIP_KMS_TOKEN_FILE": str(haip_token_file),
            "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE": str(grant_verify_token_file),
        }
    )
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [str(binary)],
            cwd=ROOT / "rust",
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    deadline = time.monotonic() + 40
    last_health_error = "not ready"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            details = log_path.read_text(encoding="utf-8", errors="replace")[-1800:]
            details = details.replace(token, "[redacted]").replace(key, "[redacted]")
            raise RuntimeError(f"Disposable Signing Keys exited: {details}")
        try:
            with urllib.request.urlopen(  # noqa: S310 - disposable loopback only
                f"http://127.0.0.1:{port}/health", timeout=2
            ) as response:
                if response.status == 200:
                    context = ssl.create_default_context(
                        cafile=tls_ca
                    )
                    with urllib.request.urlopen(  # noqa: S310 - loopback TLS
                        f"https://localhost:{tls_port}/health",
                        timeout=2, context=context,
                    ) as tls_response:
                        if tls_response.status == 200:
                            return (
                                process,
                                f"http://127.0.0.1:{port}/internal",
                                f"https://localhost:{tls_port}/internal",
                            )
        except (OSError, ValueError) as error:
            last_health_error = f"{type(error).__name__}: {error}"
        time.sleep(0.25)
    stop_process(process)
    raise RuntimeError(
        "Disposable Signing Keys did not become healthy: " + last_health_error
    )


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def rust_phase(
    phase: str, database_url: str, signing_url: str, ca_file: Path, key: str
) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "MARTY_KMS_RESTORE_PHASE": phase,
            "MARTY_ISSUANCE_POSTGRES_CONTRACT_URL": database_url,
            "MARTY_TEST_SIGNING_KEYS_INTERNAL_URL": signing_url,
            "MARTY_TEST_SIGNING_KEYS_INTERNAL_CA_FILE": str(ca_file),
            "MARTY_TEST_SIGNING_KEYS_INTEGRATION_SECRET_KEY": INTEGRATION_SECRET_KEY,
        }
    )
    result = subprocess.run(
        [
            "cargo",
            "+1.95.0",
            "test",
            "--locked",
            "-p",
            "marty-issuance-service",
            "--test",
            "canvas_oauth_postgres_contract",
            "-j",
            "1",
            "integration_secret_coordinated_restore_phase",
            "--",
            "--ignored",
            "--exact",
        ],
        cwd=ROOT / "rust",
        env=environment,
        timeout=300,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Rust integration-secret {phase} phase failed")


def live_issuance_signing_phase(bao_url: str, token: str, ca_file: Path) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "MARTY_KMS_DISPOSABLE_PROBE": "1",
            "MARTY_TEST_OPENBAO_URL": bao_url,
            "MARTY_TEST_OPENBAO_TOKEN": token,
            "BAO_CACERT": str(ca_file),
        }
    )
    for target in ("credential_builder::tests", "canvas_readiness_runtime::tests"):
        result = subprocess.run(
            [
                "cargo",
                "+1.95.0",
                "test",
                "--locked",
                "-p",
                "marty-issuance-service",
                "--lib",
                "-j",
                "1",
                target,
                "--",
                "--ignored",
            ],
            cwd=ROOT / "rust",
            env=environment,
            timeout=300,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"Rust {target} live-KMS proof failed")
    result = subprocess.run(
        [
            "cargo",
            "+1.95.0",
            "test",
            "--locked",
            "-p",
            "marty-signing-keys",
            "--test",
            "vc_api_holder_proof_live_kms",
            "-j",
            "1",
            "--",
            "--ignored",
        ],
        cwd=ROOT / "rust",
        env=environment,
        timeout=300,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Rust holder-proof live-KMS proof failed")


def live_didcomm_phase() -> None:
    # The Raft phase below checks the restored plugin/token state. Native
    # authcrypt runs against a separate disposable HTTPS listener so the
    # production client never needs an HTTP test bypass.
    environment = os.environ.copy()
    environment["MARTY_OPENBAO_PROBE_IMAGE"] = IMAGE
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/probe_didcomm_remote_tls.py"),
        ],
        cwd=ROOT,
        env=environment,
        timeout=360,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Rust DIDComm authcrypt live-KMS proof failed")


def flow_haip_phase(
    pg_name: str, database_url: str, signing_url: str, key: str, input_path: Path
) -> None:
    for name in ("marty_haip_http_test", "marty_haip_expiry_test"):
        docker("exec", pg_name, "createdb", "-U", "postgres", name)
    environment = os.environ.copy()
    environment.update(
        {
            "MARTY_TEST_SIGNING_KEYS_URL": signing_url.removesuffix("/internal"),
            "MARTY_TEST_SIGNING_KEYS_API_KEY": key,
            "MARTY_TEST_HAIP_FLOW_INPUT": str(input_path),
        }
    )
    go_test = [
        "go",
        "test",
        "./integration",
        "-run",
        "^TestHaipRustSigningRouteLiveOpenBao$",
        "-count=1",
    ]
    if shutil.which("go"):
        result = subprocess.run(
            go_test,
            cwd=ROOT / "openbao/didcomm-authcrypt",
            env=environment,
            timeout=300,
            check=False,
        )
    else:
        container_environment = environment.copy()
        container_environment["MARTY_TEST_SIGNING_KEYS_URL"] = environment[
            "MARTY_TEST_SIGNING_KEYS_URL"
        ].replace("127.0.0.1", "host.docker.internal")
        container_environment["MARTY_TEST_HAIP_FLOW_INPUT"] = f"/out/{input_path.name}"
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--add-host",
                "host.docker.internal:host-gateway",
                "--label",
                "marty.disposable=kms-coordinated-restore",
                "-v",
                f"{ROOT / 'openbao/didcomm-authcrypt'}:/src:ro",
                "-v",
                f"{input_path.parent}:/out",
                "-w",
                "/src",
                "-e",
                "MARTY_TEST_SIGNING_KEYS_URL",
                "-e",
                "MARTY_TEST_SIGNING_KEYS_API_KEY",
                "-e",
                "MARTY_TEST_HAIP_FLOW_INPUT",
                GO_IMAGE,
                *go_test,
            ],
            env=container_environment,
            timeout=300,
            check=False,
        )
    if result.returncode or not input_path.is_file():
        raise RuntimeError("Disposable Go holder HAIP response generation failed")
    for target, database in (
        ("haip_live_signing", "marty_haip_http_test"),
        ("haip_remote_http", "marty_haip_http_test"),
        ("haip_expired_http", "marty_haip_expiry_test"),
    ):
        environment["HAIP_FLOW_POSTGRES_TEST_URL"] = (
            database_url.rsplit("/", 1)[0] + "/" + database
        )
        result = subprocess.run(
            [
                "cargo",
                "+1.95.0",
                "test",
                "--locked",
                "-p",
                "marty-flow",
                "--test",
                target,
                "-j",
                "1",
            ],
            cwd=ROOT / "rust",
            env=environment,
            timeout=300,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"Disposable Flow {target} HAIP proof failed")


def run() -> None:
    if "MARTY_TEST_SIGNING_KEYS_TLS_KMS_URL" not in os.environ:
        status = with_disposable_tls_kms(
            CATALOG["openbao"]["reference"],
            [sys.executable, str(Path(__file__).resolve())],
            profile="signing-keys",
        )
        if status:
            raise RuntimeError("Keyless coordinated restore child failed")
        return
    prepare_image()
    binary = build_rust()
    suffix = uuid.uuid4().hex[:12]
    bao_name = f"kms-restore-bao-{suffix}"
    pg_name = f"kms-restore-pg-{suffix}"
    redis_name = f"kms-restore-redis-{suffix}"
    state = f"kms-restore-bao-state-{suffix}"
    runtime = f"kms-restore-bao-runtime-{suffix}"
    pg_data = f"kms-restore-pg-data-{suffix}"
    restored_state = f"kms-restore-bao-new-{suffix}"
    restored_pg = f"kms-restore-pg-new-{suffix}"
    containers: list[str] = []
    volumes: list[str] = []
    signing_process = None
    with tempfile.TemporaryDirectory(prefix="kms-coordinated-restore-") as temporary:
        temp = Path(temporary)
        try:
            for volume in (state, runtime, pg_data, restored_state, restored_pg):
                docker(
                    "volume",
                    "create",
                    "--label",
                    "marty.disposable=kms-coordinated-restore",
                    volume,
                )
                volumes.append(volume)
            for volume in (state, restored_state):
                docker(
                    "run",
                    "--rm",
                    "-v",
                    f"{volume}:/bao/data",
                    "--entrypoint",
                    "/usr/local/bin/selfhost-tls-init",
                    IMAGE,
                )
            source_ca = temp / "source-openbao-ca.crt"
            source_ca.write_text(
                read_volume_file(state, "tls/ca.crt") + "\n", encoding="utf-8"
            )
            restored_ca = temp / "restored-openbao-ca.crt"
            restored_ca.write_text(
                read_volume_file(restored_state, "tls/ca.crt") + "\n",
                encoding="utf-8",
            )
            containers.append(bao_name)
            bao_url = start_bao(bao_name, state, source_ca)
            bootstrap_bao(bao_name, state, runtime)
            root = read_volume_file(state, "root.token")
            unseal = read_volume_file(state, "unseal.key")
            token = read_volume_file(runtime, "signing_keys_openbao_token")
            didcomm_token = read_volume_file(runtime, "didcomm_issuance_openbao_token")
            bootstrap_bao(bao_name, state, runtime)
            if read_volume_file(runtime, "didcomm_issuance_openbao_token") != didcomm_token:
                raise RuntimeError("Idempotent OpenBao bootstrap replaced the DIDComm Issuance token")
            version = "0" * 32
            expected_capabilities = {
                f"didcomm/keys/synthetic/issuer/versions/{version}": ["read"],
                f"didcomm/pack/synthetic/issuer/{version}": ["update"],
                "didcomm/keys/synthetic/issuer": ["deny"],
                "didcomm/keys/synthetic/issuer/rotate": ["deny"],
                "didcomm/haip/keys/synthetic": ["deny"],
            }
            status, capabilities = request(
                bao_url,
                "POST",
                "sys/capabilities",
                {"token": didcomm_token, "paths": list(expected_capabilities)},
                root,
                ca_file=source_ca,
            )
            if status != 200 or any(
                capabilities.get("data", {}).get(path) != allowed
                for path, allowed in expected_capabilities.items()
            ):
                raise RuntimeError(
                    f"DIDComm Issuance token capabilities differ: status={status}, "
                    f"actual={capabilities.get('data', {})!r}"
                )
            haip_token_file = temp / "haip-kms.token"
            haip_token_file.write_text(
                read_volume_file(runtime, "haip-kms.token"), encoding="utf-8"
            )
            grant_verify_token_file = temp / "sign_grant_verify_token"
            grant_verify_token_file.write_text(
                read_volume_file(runtime, "sign_grant_verify_token"), encoding="utf-8"
            )
            live_issuance_signing_phase(bao_url, token, source_ca)
            live_didcomm_phase()
            init_material = json.loads(read_volume_file(state, "selfhost-init.json"))
            if unseal != init_material["unseal_keys_b64"][0]:
                raise RuntimeError(
                    "Disposable OpenBao unseal file differs from init material"
                )
            host_state = temp / "state"
            host_state.mkdir()
            (host_state / "tls").mkdir()
            shutil.copyfile(source_ca, host_state / "tls" / "ca.crt")
            for name, value in (
                ("selfhost-init.json", read_volume_file(state, "selfhost-init.json")),
                ("root.token", root),
                ("unseal.key", unseal),
            ):
                (host_state / name).write_text(value, encoding="utf-8")
            containers.append(pg_name)
            database_url, _ = start_postgres(pg_name, pg_data)
            docker(
                "run",
                "--rm",
                "-d",
                "--name",
                redis_name,
                "--label",
                "marty.disposable=kms-coordinated-restore",
                "-p",
                "127.0.0.1::6379",
                CATALOG["redis"]["reference"],
            )
            containers.append(redis_name)
            redis_port = port_of(redis_name, "6379/tcp")
            wait_for(
                "Redis readiness",
                lambda: (
                    subprocess.run(
                        ["docker", "exec", redis_name, "redis-cli", "ping"],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    ).returncode
                    == 0
                ),
            )
            api_key = f"disposable-{uuid.uuid4().hex}"
            signing_process, signing_url, secret_url = start_signing(
                binary,
                bao_url,
                source_ca,
                token,
                haip_token_file,
                grant_verify_token_file,
                redis_port,
                api_key,
                temp / "signing-source.log",
            )
            flow_haip_phase(
                pg_name, database_url, signing_url, api_key, temp / "haip-holder.json"
            )
            rust_phase("write", database_url, secret_url,
                       Path(os.environ["MARTY_TEST_SIGNING_KEYS_TLS_CA"]), api_key)
            stop_process(signing_process)
            signing_process = None
            require_status(bao_url, "POST", "sys/seal", root, ca_file=source_ca)
            source_unseal = require_status(
                bao_url, "POST", "sys/unseal", "", {"key": unseal},
                ca_file=source_ca,
            )
            if source_unseal.get("sealed") is not False:
                raise RuntimeError(
                    "Disposable source OpenBao did not unseal with saved key"
                )
            wait_for(
                "source Raft leader after unseal",
                lambda: (
                    request(bao_url, "GET", "sys/leader", token=root,
                            ca_file=source_ca)[1].get("is_self")
                    is True
                ),
            )

            export_dir = temp / "exports"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/export-selfhost-openbao.py"),
                    "--state-dir",
                    str(host_state),
                    "--export-dir",
                    str(export_dir),
                    "--bao-url",
                    bao_url,
                ],
                capture_output=True,
                timeout=300,
                check=False,
            )
            if result.returncode:
                raise RuntimeError("Coordinated OpenBao snapshot export failed")
            archive = next(export_dir.glob("*.zip"))
            with zipfile.ZipFile(archive) as bundle:
                snapshot = bundle.read("raft.snap")
                manifest = json.loads(bundle.read("manifest.json"))
            if hashlib.sha256(snapshot).hexdigest() != manifest["snapshot_sha256"]:
                raise RuntimeError("Coordinated OpenBao snapshot hash mismatch")
            docker(
                "exec",
                pg_name,
                "pg_dump",
                "-Fc",
                "-U",
                "postgres",
                "-d",
                DATABASE,
                "-f",
                "/tmp/kms.dump",
            )
            dump = temp / "kms.dump"
            docker("cp", f"{pg_name}:/tmp/kms.dump", str(dump))
            docker("rm", "-f", pg_name)
            containers.remove(pg_name)
            docker("stop", bao_name)
            containers.remove(bao_name)

            containers.append(pg_name)
            restored_database_url, _ = start_postgres(pg_name, restored_pg)
            docker("cp", str(dump), f"{pg_name}:/tmp/kms.dump")
            restored = subprocess.run(
                [
                    "docker",
                    "exec",
                    pg_name,
                    "pg_restore",
                    "-U",
                    "postgres",
                    "-d",
                    DATABASE,
                    "/tmp/kms.dump",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if restored.returncode:
                raise RuntimeError(
                    f"Disposable pg_restore failed: {restored.stderr[-1200:]}"
                )
            containers.append(bao_name)
            restored_bao_url = start_bao(bao_name, restored_state, restored_ca)
            initialized = require_status(
                restored_bao_url,
                "POST",
                "sys/init",
                "",
                {"secret_shares": 1, "secret_threshold": 1},
                timeout=60,
                ca_file=restored_ca,
            )
            require_status(
                restored_bao_url,
                "POST",
                "sys/unseal",
                "",
                {"key": initialized["keys_base64"][0]},
                ca_file=restored_ca,
            )
            new_root = initialized["root_token"]
            wait_for(
                "replacement Raft leader",
                lambda: (
                    request(restored_bao_url, "GET", "sys/leader", token=new_root,
                            ca_file=restored_ca)[
                        1
                    ].get("is_self")
                    is True
                ),
            )
            snapshot_request = urllib.request.Request(
                restored_bao_url + "/v1/sys/storage/raft/snapshot-force",
                data=snapshot,
                method="POST",
                headers={
                    "X-Vault-Token": new_root,
                    "Content-Type": "application/octet-stream",
                },
            )
            with urllib.request.urlopen(
                snapshot_request, timeout=60,
                context=ssl.create_default_context(cafile=str(restored_ca)),
            ) as response:  # noqa: S310 - verified disposable loopback TLS
                if response.status not in (200, 204):
                    raise RuntimeError("OpenBao snapshot restore failed")
            docker("stop", bao_name)
            containers.remove(bao_name)
            # A disposable --rm container can linger briefly after stop; the
            # restored Raft process gets a distinct name to avoid that race.
            bao_name = f"kms-restore-bao-final-{suffix}"
            containers.append(bao_name)
            restored_bao_url = start_bao(bao_name, restored_state, restored_ca)
            wait_for(
                "restored OpenBao initialization",
                lambda: (
                    request(restored_bao_url, "GET", "sys/init",
                            ca_file=restored_ca)[1].get("initialized")
                    is True
                ),
            )
            health, _ = request(restored_bao_url, "GET", "sys/health",
                                ca_file=restored_ca)
            if health != 200:
                unseal_request = urllib.request.Request(
                    restored_bao_url + "/v1/sys/unseal",
                    data=json.dumps({"key": unseal}).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                try:
                    with urllib.request.urlopen(
                        unseal_request, timeout=10,
                        context=ssl.create_default_context(cafile=str(restored_ca)),
                    ) as response:  # noqa: S310 - verified disposable loopback TLS
                        unseal_status = response.status
                except urllib.error.HTTPError as error:
                    detail = (
                        error.read()
                        .decode(errors="replace")
                        .replace(unseal, "[redacted]")
                    )
                    raise RuntimeError(
                        f"Restored OpenBao unseal failed: health {health}, status {error.code}: {detail[:500]}"
                    ) from None
                if unseal_status not in (200, 204):
                    raise RuntimeError(
                        f"Restored OpenBao unseal failed: health {health}, status {unseal_status}"
                    )
            wait_for(
                "restored Raft leader",
                lambda: (
                    request(restored_bao_url, "GET", "sys/leader", token=root,
                            ca_file=restored_ca)[1].get(
                        "is_self"
                    )
                    is True
                ),
            )
            signing_process, signing_url, secret_url = start_signing(
                binary,
                restored_bao_url,
                restored_ca,
                token,
                haip_token_file,
                grant_verify_token_file,
                redis_port,
                api_key,
                temp / "signing-restored.log",
            )
            rust_phase(
                "read", restored_database_url, secret_url,
                Path(os.environ["MARTY_TEST_SIGNING_KEYS_TLS_CA"]), api_key,
            )
            print("Disposable Rust/PostgreSQL/OpenBao coordinated restore passed")
        finally:
            if signing_process is not None:
                stop_process(signing_process)
            for name in reversed(containers):
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            for volume in reversed(volumes):
                subprocess.run(
                    ["docker", "volume", "rm", volume],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare-rust-only",
        action="store_true",
        help="Prepare the same Rust targets without starting disposable services",
    )
    args = parser.parse_args(argv)
    if args.prepare_rust_only:
        build_rust()
    else:
        run()


if __name__ == "__main__":
    main()
