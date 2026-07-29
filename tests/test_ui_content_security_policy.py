"""Keep the production UI compatible with its own strict script policy."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ui_bootstrap_uses_an_external_script_allowed_by_production_csp() -> None:
    startup = ROOT / "ui" / "public" / "startup.js"
    production_nginx = (ROOT / "ui" / "nginx.prod.conf").read_text(encoding="utf-8")

    assert startup.read_text(encoding="utf-8").strip()
    assert "script-src 'self'" in production_nginx
    script_policy = next(
        segment.strip()
        for segment in next(
            line for line in production_nginx.splitlines() if "script-src" in line
        ).split(";")
        if "script-src" in segment
    )
    assert "'unsafe-inline'" not in script_policy

    for index_path in ("ui/index.html", "ui/console/index.html"):
        index = (ROOT / index_path).read_text(encoding="utf-8")
        assert '<script src="/startup.js"></script>' in index
        assert "<script>" not in index
