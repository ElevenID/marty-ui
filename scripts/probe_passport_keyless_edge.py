#!/usr/bin/env python3
"""Exercise the disposable Rust HTTPS edge with a real remote TLS signer."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def attempt(binary: Path, environment: dict[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen([str(binary)], env=environment,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(binary: Path) -> None:
    if not binary.is_file():
        raise RuntimeError("disposable Rust edge binary is missing")
    ca = Path(os.environ["MARTY_TEST_PASSPORT_EDGE_CA"])
    if b"PRIVATE KEY" in ca.read_bytes():
        raise RuntimeError("disposable edge CA exposed private key material")
    port = free_port()
    environment = {**os.environ, "PASSPORT_EDGE_BIND": f"127.0.0.1:{port}"}
    broken = attempt(binary, {
        **environment, "PASSPORT_EDGE_TLS_KMS_KEY_NAME": "missing-edge-key",
    })
    try:
        if broken.wait(timeout=12) == 0:
            raise RuntimeError("disposable Rust edge started without its remote key")
    finally:
        if broken.poll() is None:
            broken.kill()
            broken.wait(timeout=5)
    edge = attempt(binary, environment)
    try:
        opener = build_opener(ProxyHandler({}), HTTPSHandler(
            context=ssl.create_default_context(cafile=str(ca))))
        url = f"https://localhost:{port}/__disposable/flow-callback"
        deadline = time.monotonic() + 20
        while True:
            if edge.poll() is not None:
                raise RuntimeError("disposable Rust edge exited before TLS readiness")
            try:
                request = Request(url, data=b"synthetic-callback", method="POST")
                with opener.open(request, timeout=2) as response:
                    if (response.status != 204
                            or response.headers.get("X-Marty-Synthetic-Only") != "true"):
                        raise RuntimeError("synthetic callback response changed")
                break
            except (URLError, TimeoutError) as error:
                if time.monotonic() >= deadline:
                    raise RuntimeError("remote-signed edge TLS did not become ready") from error
                time.sleep(0.2)
        try:
            opener.open(Request(url, method="GET"), timeout=3)
        except HTTPError as error:
            if error.code != 405 or error.headers.get("X-Marty-Synthetic-Only") != "true":
                raise RuntimeError("synthetic callback method guard changed") from error
        else:
            raise RuntimeError("synthetic callback accepted GET")
        print("Remote-signed passport edge TLS and callback guard passed")
    finally:
        edge.terminate()
        try:
            edge.wait(timeout=5)
        except subprocess.TimeoutExpired:
            edge.kill()
            edge.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
