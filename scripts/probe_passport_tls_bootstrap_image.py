#!/usr/bin/env python3
"""Run the staged Linux passport TLS binaries beside disposable HTTPS OpenBao."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from passport_remote_tls import TLS_PREFIXES

OPENBAO = ("quay.io/openbao/openbao@sha256:"
           "6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452")
def run(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True,
                          timeout=timeout)


def require_ok(args: list[str], what: str, timeout: int = 60) -> str:
    result = run(args, timeout)
    if result.returncode:
        if what == "containerized remote-signed HTTPS callback":
            raise RuntimeError(f"{what} failed: {result.stderr.strip()[:500]}")
        raise RuntimeError(f"{what} failed")
    return result.stdout.strip()


def probe(image: str) -> None:
    if re.fullmatch(r"marty-services-kms-tls-local-[0-9]+", image) is None:
        raise RuntimeError("expected the staged local services image")
    image_id = require_ok(["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                          "local services image inspection")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise RuntimeError("staged services image ID is invalid")
    suffix = secrets.token_hex(5)
    network = "marty-passport-keyless-net-" + suffix
    volume = "marty-passport-keyless-output-" + suffix
    wrong_ca_volume = "marty-passport-keyless-wrong-ca-" + suffix
    bao_name = "marty-passport-keyless-bao-" + suffix
    edge_name = "marty-passport-keyless-edge-" + suffix
    project = "marty-passport-acceptance-base-" + suffix
    script = Path(__file__).with_name("passport_supported_openbao_start.sh").resolve()
    with tempfile.TemporaryDirectory(prefix="marty-passport-keyless-image-") as temporary:
        root = Path(temporary)
        public = root / "public"
        public.mkdir()
        token = root / "token"
        token.write_text(secrets.token_hex(32), encoding="ascii")
        try:
            require_ok(["docker", "network", "create", "--internal", network],
                       "private network creation")
            require_ok(["docker", "volume", "create", volume], "output volume creation")
            require_ok(["docker", "volume", "create", wrong_ca_volume],
                       "wrong-CA output volume creation")
            require_ok([
                "docker", "run", "-d", "--name", bao_name,
                "--network", network, "--network-alias", "openbao",
                "--hostname", "openbao", "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "--mount", f"type=bind,src={script},dst=/usr/local/bin/passport-supported-openbao-start,readonly",
                "--mount", f"type=bind,src={token},dst=/run/secrets/bao_root_token,readonly",
                "--mount", f"type=bind,src={public},dst=/bao/public-ca",
                "-e", "PASSPORT_BAO_TLS_MODE=required",
                "--entrypoint", "/bin/sh", OPENBAO,
                "/usr/local/bin/passport-supported-openbao-start",
            ], "HTTPS OpenBao startup")
            ca = public / "ca.crt"
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if ca.is_file() and ca.stat().st_size:
                    peer = run([
                        "docker", "run", "--rm", "--network", network,
                        "--mount", f"type=bind,src={ca},dst=/ca.crt,readonly",
                        "--entrypoint", "bao", OPENBAO, "status",
                        "-address=https://openbao:8200", "-ca-cert=/ca.crt",
                    ])
                    if peer.returncode == 0:
                        break
                time.sleep(0.25)
            else:
                raise RuntimeError("HTTPS OpenBao peer trust did not become ready")
            if b"PRIVATE KEY" in ca.read_bytes():
                raise RuntimeError("OpenBao public CA mount contains private material")
            require_ok([
                "docker", "run", "--rm", "--user", "0",
                "--mount", f"type=volume,src={volume},dst=/work/output",
                "--entrypoint", "/bin/sh", image, "-ec",
                "chown 10001:10001 /work/output && chmod 0700 /work/output",
            ], "private output preparation")
            require_ok([
                "docker", "run", "--rm", "--network", network,
                "--mount", f"type=bind,src={ca},dst=/run/openbao/ca.crt,readonly",
                "--mount", f"type=bind,src={token},dst=/run/secrets/bao_root_token,readonly",
                "--mount", f"type=volume,src={volume},dst=/work/output",
                "-e", "BAO_ADDR=https://openbao:8200",
                "-e", "BAO_CACERT=/run/openbao/ca.crt",
                "-e", "BAO_ROOT_TOKEN_FILE=/run/secrets/bao_root_token",
                "-e", f"PASSPORT_ACCEPTANCE_PROJECT={project}",
                "-e", "PASSPORT_TLS_OUTPUT_DIR=/work/output",
                "--entrypoint", "/usr/local/bin/marty-passport-tls-bootstrap", image,
            ], "containerized remote TLS bootstrap", timeout=120)
            names = require_ok([
                "docker", "run", "--rm",
                "--mount", f"type=volume,src={volume},dst=/work/output,readonly",
                "--entrypoint", "/bin/sh", image, "-c", "ls -1 /work/output",
            ], "bootstrap output inventory").splitlines()
            expected = {"workload_identity_ca_cert"} | {
                f"{prefix}_{suffix}" for prefix in TLS_PREFIXES
                for suffix in ("cert", "kms_token")
            }
            if set(names) != expected:
                raise RuntimeError("containerized bootstrap output differs")
            require_ok([
                "docker", "run", "--rm", "--user", "0",
                "--mount", f"type=volume,src={wrong_ca_volume},dst=/work/output",
                "--entrypoint", "/bin/sh", image, "-ec",
                "chown 10001:10001 /work/output && chmod 0700 /work/output",
            ], "wrong-CA output preparation")
            wrong_ca = run([
                "docker", "run", "--rm", "--network", network,
                "--mount", f"type=volume,src={volume},dst=/wrong-ca,readonly",
                "--mount", f"type=bind,src={token},dst=/run/secrets/bao_root_token,readonly",
                "--mount", f"type=volume,src={wrong_ca_volume},dst=/work/output",
                "-e", "BAO_ADDR=https://openbao:8200",
                "-e", "BAO_CACERT=/wrong-ca/workload_identity_ca_cert",
                "-e", "BAO_ROOT_TOKEN_FILE=/run/secrets/bao_root_token",
                "-e", f"PASSPORT_ACCEPTANCE_PROJECT={project}",
                "-e", "PASSPORT_TLS_OUTPUT_DIR=/work/output",
                "--entrypoint", "/usr/local/bin/marty-passport-tls-bootstrap", image,
            ], timeout=30)
            if wrong_ca.returncode == 0 or require_ok([
                "docker", "run", "--rm",
                "--mount", f"type=volume,src={wrong_ca_volume},dst=/work/output,readonly",
                "--entrypoint", "/bin/sh", image, "-c", "ls -1 /work/output",
            ], "wrong-CA output inventory"):
                raise RuntimeError("containerized bootstrap accepted the wrong CA")
            require_ok([
                "docker", "run", "-d", "--name", edge_name,
                "--network", network, "--network-alias", "edge",
                "--mount", f"type=bind,src={ca},dst=/run/openbao/ca.crt,readonly",
                "--mount", f"type=volume,src={volume},dst=/work/output,readonly",
                "-e", "PASSPORT_EDGE_BIND=0.0.0.0:8443",
                "-e", "PASSPORT_EDGE_TLS_CERT_FILE=/work/output/passport_edge_tls_cert",
                "-e", "PASSPORT_EDGE_TLS_KMS_CA_CERT_FILE=/run/openbao/ca.crt",
                "-e", "PASSPORT_EDGE_TLS_KMS_TOKEN_FILE=/work/output/passport_edge_tls_kms_token",
                "-e", f"PASSPORT_EDGE_TLS_KMS_KEY_NAME={project}-passport-edge",
                "-e", "PASSPORT_EDGE_TLS_KMS_KEY_VERSION=1",
                "-e", "PASSPORT_EDGE_TLS_KMS_ADDR=https://openbao:8200",
                "--entrypoint", "/usr/local/bin/marty-passport-keyless-edge", image,
            ], "containerized keyless edge startup")
            require_ok([
                "docker", "run", "--rm", "--network", network,
                "--mount", f"type=volume,src={volume},dst=/work/output,readonly",
                "--entrypoint", "curl", image, "--silent", "--show-error", "--fail",
                "--retry", "10", "--retry-connrefused", "--retry-delay", "1",
                "--max-time", "20", "--cacert",
                "/work/output/workload_identity_ca_cert", "-X", "POST",
                "https://edge:8443/__disposable/flow-callback",
            ], "containerized remote-signed HTTPS callback", timeout=45)
            print(f"Containerized passport TLS bootstrap and edge passed: {image_id}")
        finally:
            # All names have a fresh random suffix, including on partial startup.
            for name in (edge_name, bao_name):
                run(["docker", "rm", "-f", name])
            run(["docker", "network", "rm", network])
            run(["docker", "volume", "rm", volume])
            run(["docker", "volume", "rm", wrong_ca_volume])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="marty-services-kms-tls-local-3")
    args = parser.parse_args()
    probe(args.image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
