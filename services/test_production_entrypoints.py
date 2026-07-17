"""Release-safety tests for service process entrypoints."""

from pathlib import Path


SERVICES_DIR = Path(__file__).resolve().parent


def test_service_entrypoints_do_not_enable_development_reload() -> None:
    offenders = [
        str(path.relative_to(SERVICES_DIR))
        for path in SERVICES_DIR.glob("*/main.py")
        if "reload=True" in path.read_text(encoding="utf-8")
    ]

    assert not offenders, f"development reload enabled in release services: {offenders}"
