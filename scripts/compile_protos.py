#!/usr/bin/env python3
"""Compile proto files for marty-ui services.

Generates Python protobuf and gRPC stubs from proto/v1/*.proto into
packages/marty_proto/v1/. Fixes imports to use relative paths and
generates an __init__.py for convenience.

Usage:
    python scripts/compile_protos.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = ROOT / "proto" / "v1"
OUT_DIR = ROOT / "packages" / "marty_proto" / "v1"


def compile_protos() -> None:
    """Compile all .proto files into Python stubs."""
    proto_files = sorted(PROTO_DIR.glob("*.proto"))
    if not proto_files:
        print(f"No .proto files found in {PROTO_DIR}")
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Compiling {len(proto_files)} proto files...")
    for proto_file in proto_files:
        print(f"  {proto_file.name}")

    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"--proto_path={PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        *[str(f) for f in proto_files],
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"protoc failed:\n{result.stderr}")
        sys.exit(1)

    print(f"Generated stubs in {OUT_DIR}")

    # Fix imports to use relative paths
    fix_grpc_imports(OUT_DIR)

    # Generate __init__.py
    create_init_file(OUT_DIR)

    print("Done.")


def fix_grpc_imports(out_dir: Path) -> None:
    """Fix protoc's absolute imports to relative imports."""
    pattern = re.compile(r"^(import (\w+_pb2))", re.MULTILINE)

    for py_file in out_dir.glob("*_pb2_grpc.py"):
        content = py_file.read_text()
        fixed = pattern.sub(r"from . \1", content)
        if fixed != content:
            py_file.write_text(fixed)
            print(f"  Fixed imports in {py_file.name}")


def create_init_file(out_dir: Path) -> None:
    """Generate a lazy __init__.py that re-exports all generated modules."""
    modules = sorted(
        f.stem
        for f in out_dir.glob("*_pb2*.py")
    )
    module_items = "\n".join(f'    "{mod}",' for mod in modules)
    lines = [
        '"""Auto-generated protobuf and gRPC stubs for marty-ui services.',
        "",
        "The generated modules are imported lazily to avoid circular-import traps during",
        "service startup when a service requests one stub but the package would otherwise",
        "eagerly import every other stub.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from importlib import import_module",
        "",
        "_SUBMODULES = {",
        module_items,
        "}",
        "",
        "__all__ = sorted(_SUBMODULES)",
        "",
        "",
        "def __getattr__(name: str):",
        "    if name in _SUBMODULES:",
        "        module = import_module(f\"{__name__}.{name}\")",
        "        globals()[name] = module",
        "        return module",
        "    raise AttributeError(f\"module {__name__!r} has no attribute {name!r}\")",
        "",
        "",
        "def __dir__() -> list[str]:",
        "    return sorted(list(globals().keys()) + list(_SUBMODULES))",
        "",
    ]

    init_file = out_dir / "__init__.py"
    init_file.write_text("\n".join(lines))
    print(f"  Generated {init_file.name}")

    # Also ensure parent package has __init__.py
    parent_init = out_dir.parent / "__init__.py"
    if not parent_init.exists():
        parent_init.write_text('"""Marty UI proto package."""\n')


def compile_descriptor_set() -> None:
    """Compile a binary proto descriptor set for Envoy gRPC-JSON transcoding.

    Produces ``config/envoy/proto_descriptor.pb`` combining all protos.
    """
    proto_files = sorted(PROTO_DIR.glob("*.proto"))
    if not proto_files:
        return

    desc_dir = ROOT / "config" / "envoy"
    desc_dir.mkdir(parents=True, exist_ok=True)
    desc_file = desc_dir / "proto_descriptor.pb"

    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"--proto_path={PROTO_DIR}",
        f"--descriptor_set_out={desc_file}",
        "--include_imports",
        *[str(f) for f in proto_files],
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Descriptor set generation failed:\n{result.stderr}")
        return

    print(f"  Generated descriptor set: {desc_file}")


if __name__ == "__main__":
    compile_protos()
    compile_descriptor_set()
