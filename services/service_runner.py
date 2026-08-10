"""Launch a Marty service without duplicating its ``main`` module."""

from __future__ import annotations

import importlib
import os
import re
from types import ModuleType

import uvicorn

_SERVICE_MODULE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


def load_service_module(service_name: str) -> ModuleType:
    """Import one service under the canonical ``<service>.main`` name."""
    module_name = service_name.strip().replace("-", "_")
    if not _SERVICE_MODULE_PATTERN.fullmatch(module_name):
        raise ValueError(f"Invalid SERVICE_NAME: {service_name!r}")
    return importlib.import_module(f"{module_name}.main")


def main() -> None:
    """Import and serve the configured service application."""
    service_name = os.environ.get("SERVICE_NAME", "")
    if not service_name.strip():
        raise RuntimeError("SERVICE_NAME is required")

    service_module = load_service_module(service_name)
    uvicorn.run(
        service_module.app,
        host="0.0.0.0",
        port=service_module.SERVICE_PORT,
        reload=False,
    )


if __name__ == "__main__":
    main()
