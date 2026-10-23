#!/usr/bin/env python3
"""Verify disposable OpenBao HTTPS startup exports only its public CA."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time


def checked(args: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("disposable OpenBao Docker command failed")
    return result.stdout.strip()


def probe(image: str, *, bootstrap: bool = False) -> None:
    if re.fullmatch(r"quay\.io/openbao/openbao@sha256:[0-9a-f]{64}", image) is None:
        raise RuntimeError("disposable OpenBao image must be pinned by digest")
    suffix = secrets.token_hex(5)
    name = "marty-passport-bao-tls-" + suffix
    network = "marty-passport-bao-tls-net-" + suffix
    script = Path(__file__).with_name("passport_supported_openbao_start.sh").resolve()
    bootstrap_script = Path(__file__).with_name(
        "passport_supported_openbao_bootstrap.sh").resolve()
    initializer = script.parents[1] / "docker" / "openbao-init.sh"
    with tempfile.TemporaryDirectory(prefix="marty-passport-bao-tls-") as temporary:
        root = Path(temporary)
        (root / "public").mkdir()
        (root / "output").mkdir()
        (root / "token").write_text(secrets.token_hex(32), encoding="ascii")
        started = False
        network_created = False
        try:
            checked(["docker", "network", "create", "--internal", network])
            network_created = True
            checked([
                "docker", "run", "-d", "--name", name,
                "--network", network, "--network-alias", "openbao",
                "--hostname", "openbao",
                "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "--mount", f"type=bind,src={script},dst=/usr/local/bin/passport-supported-openbao-start,readonly",
                "--mount", f"type=bind,src={root / 'token'},dst=/run/secrets/bao_root_token,readonly",
                "--mount", f"type=bind,src={root / 'public'},dst=/bao/public-ca",
                "-e", "PASSPORT_BAO_TLS_MODE=required",
                "--entrypoint", "/bin/sh", image,
                "/usr/local/bin/passport-supported-openbao-start",
            ])
            started = True
            ca = root / "public" / "ca.crt"
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                if ca.is_file() and ca.stat().st_size:
                    try:
                        checked([
                            "docker", "run", "--rm", "--network", network,
                            "--mount", f"type=bind,src={ca},dst=/ca.pem,readonly",
                            "--entrypoint", "bao", image, "status",
                            "-address=https://openbao:8200", "-ca-cert=/ca.pem",
                        ])
                        break
                    except RuntimeError:
                        pass
                time.sleep(0.3)
            else:
                raise RuntimeError("disposable OpenBao HTTPS did not become healthy")
            public = ca.read_bytes()
            if b"BEGIN CERTIFICATE" not in public or b"PRIVATE KEY" in public:
                raise RuntimeError("disposable OpenBao exported private material")
            if bootstrap:
                checked([
                    "docker", "run", "--rm", "--network", network,
                    "--mount", f"type=bind,src={root / 'token'},dst=/run/secrets/bao_root_token,readonly",
                    "--mount", f"type=bind,src={root / 'public'},dst=/bao/public-ca,readonly",
                    "--mount", f"type=bind,src={root / 'output'},dst=/work/secrets",
                    "--mount", f"type=bind,src={bootstrap_script},dst=/scripts/passport_supported_openbao_bootstrap.sh,readonly",
                    "--mount", f"type=bind,src={initializer},dst=/scripts/openbao-init.sh,readonly",
                    "-e", "BAO_ADDR=https://openbao:8200",
                    "-e", "BAO_CACERT=/bao/public-ca/ca.crt",
                    "-e", "PASSPORT_ACCEPTANCE_CSCA_KEY_REFERENCE=cred-dsc-aaaaaaaaaaaaaaaaaaaa-es256",
                    "-e", "PASSPORT_ACCEPTANCE_DSC_KEY_REFERENCE=cred-dsc-bbbbbbbbbbbbbbbbbbbb-es256",
                    "--entrypoint", "/bin/sh", image,
                    "/scripts/passport_supported_openbao_bootstrap.sh",
                ], timeout=120)
                expected = {"bao_token", "callback_signer_bao_token",
                            "notification_openbao_token"}
                if {path.name for path in (root / "output").iterdir()} != expected:
                    raise RuntimeError("disposable HTTPS bootstrap token set differs")
                tokens = [(root / "output" / name).read_text(encoding="ascii")
                          for name in sorted(expected)]
                root_token = (root / "token").read_text(encoding="ascii")
                if (len(set(tokens)) != len(tokens)
                    or any(len(token) < 20 or token == root_token for token in tokens)):
                    raise RuntimeError("disposable HTTPS bootstrap tokens are invalid")
            print("Disposable OpenBao HTTPS startup passed; public CA only exported")
            if bootstrap:
                print("Disposable OpenBao HTTPS policy bootstrap and three scoped tokens passed")
        finally:
            if started:
                subprocess.run(["docker", "rm", "-f", name], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=30)
            if network_created:
                subprocess.run(["docker", "network", "rm", network], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=30)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    probe(args.image, bootstrap=args.bootstrap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
