"""Optional, provider-neutral gateway extension loading.

The public distribution does not set an extension module. Private or downstream
images may add a module to the image and opt in with
``MARTY_GATEWAY_EXTENSION_MODULE``. The module must expose ``install(app)``.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable

from fastapi import FastAPI


def install_gateway_extension(app: FastAPI, module_path: str | None = None) -> bool:
    """Install an optional downstream extension and fail fast if it is invalid."""
    configured_path = module_path or os.getenv("MARTY_GATEWAY_EXTENSION_MODULE", "")
    configured_path = configured_path.strip()
    if not configured_path:
        return False

    module = importlib.import_module(configured_path)
    installer: Callable[[FastAPI], object] | None = getattr(module, "install", None)
    if not callable(installer):
        raise RuntimeError(f"Gateway extension {configured_path!r} must expose install(app)")

    installer(app)
    return True
