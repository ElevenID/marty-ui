"""Service containers must import each application module exactly once."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from services import service_runner

ROOT = Path(__file__).resolve().parents[1]


def test_runner_imports_the_canonical_service_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = object()
    imported: list[str] = []
    uvicorn_calls: list[tuple[object, dict[str, object]]] = []

    def import_module(module_name: str) -> SimpleNamespace:
        imported.append(module_name)
        return SimpleNamespace(app=application, SERVICE_PORT=8011)

    def run(app: object, **kwargs: object) -> None:
        uvicorn_calls.append((app, kwargs))

    monkeypatch.setenv("SERVICE_NAME", "flow")
    monkeypatch.setattr(service_runner.importlib, "import_module", import_module)
    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(run=run))

    service_runner.main()

    assert imported == ["flow.main"]
    assert uvicorn_calls == [
        (
            application,
            {"host": "0.0.0.0", "port": 8011, "reload": False},
        )
    ]


def test_runner_normalizes_hyphenated_service_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []

    def import_module(module_name: str) -> SimpleNamespace:
        imported.append(module_name)
        return SimpleNamespace()

    monkeypatch.setattr(service_runner.importlib, "import_module", import_module)

    service_runner.load_service_module("presentation-policy")

    assert imported == ["presentation_policy.main"]


@pytest.mark.parametrize("service_name", ["", "../flow", "flow.main", "Flow"])
def test_runner_rejects_invalid_service_names(service_name: str) -> None:
    with pytest.raises(ValueError, match="Invalid SERVICE_NAME"):
        service_runner.load_service_module(service_name)


def test_container_entrypoint_uses_the_canonical_import_runner() -> None:
    entrypoint = (service_runner.__file__.replace("service_runner.py", "entrypoint.sh"))
    with open(entrypoint, encoding="utf-8") as entrypoint_file:
        script = entrypoint_file.read()

    assert "exec python -m service_runner" in script
    assert "exec python -m ${MODULE_NAME}.main" not in script
    assert 'if [ "$MODULE_NAME" = "event_stream" ]' in script
    assert "exec /usr/local/bin/marty-event-stream" in script


def test_event_stream_has_only_the_canonical_rust_server() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert not list((ROOT / "services" / "event_stream").glob("*.py"))
    assert "cargo build --locked --release -p marty-event-stream" in dockerfile
    assert (
        "COPY --from=event-stream-builder "
        "/build/rust/target/release/marty-event-stream "
        "/usr/local/bin/marty-event-stream"
    ) in dockerfile
