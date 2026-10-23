#!/usr/bin/env python3
"""Generate the Envoy descriptor from canonical proto/v1 sources.

Use make proto-gen for the pinned dependencies in requirements-proto.txt.
No Python stubs are generated.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO_DIR = ROOT / "proto" / "v1"


def googleapis_proto_dir() -> Path:
    """Return the installed include root that contains google/api/*.proto."""
    try:
        import google.api  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "googleapis-common-protos is required to compile service protobufs"
        ) from exc

    api_dir = Path(next(iter(google.api.__path__)))
    include_root = api_dir.parent.parent
    if not (include_root / "google" / "api" / "annotations.proto").is_file():
        raise RuntimeError(
            "googleapis-common-protos does not provide google/api/annotations.proto"
        )
    return include_root


def compile_descriptor_set(output: Path) -> None:
    """Compile all service schemas, failing the command on generation errors."""
    proto_files = sorted(PROTO_DIR.glob("*.proto"))
    if not proto_files:
        raise RuntimeError(f"No proto files found in {PROTO_DIR}")
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            f"--proto_path={PROTO_DIR}",
            f"--proto_path={googleapis_proto_dir()}",
            f"--descriptor_set_out={output}",
            "--include_imports",
            *[str(path) for path in proto_files],
        ],
        check=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "config/envoy/proto_descriptor.pb"
    )
    compile_descriptor_set(parser.parse_args().output)
