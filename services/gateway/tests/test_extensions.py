import sys
from types import ModuleType

import pytest
from fastapi import FastAPI

from gateway.extensions import install_gateway_extension


def test_gateway_extension_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MARTY_GATEWAY_EXTENSION_MODULE", raising=False)
    assert install_gateway_extension(FastAPI()) is False


def test_gateway_extension_installs_downstream_module(monkeypatch):
    module = ModuleType("test_downstream_extension")
    module.install = lambda app: setattr(app.state, "extension_installed", True)
    monkeypatch.setitem(sys.modules, module.__name__, module)

    app = FastAPI()
    assert install_gateway_extension(app, module.__name__) is True
    assert app.state.extension_installed is True


def test_gateway_extension_rejects_module_without_installer(monkeypatch):
    module = ModuleType("test_invalid_extension")
    monkeypatch.setitem(sys.modules, module.__name__, module)

    with pytest.raises(RuntimeError, match=r"must expose install\(app\)"):
        install_gateway_extension(FastAPI(), module.__name__)
