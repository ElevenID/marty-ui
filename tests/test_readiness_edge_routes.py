"""Regression checks for edge readiness routing.

These config files are easy to break accidentally: if /ready falls through to
the SPA server, external health checks can report a healthy UI while gateway
dependencies such as the organization service are unavailable.
"""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _assert_ready_proxied_before_spa_fallback(relative_path: str) -> None:
    contents = _text(relative_path)

    assert "location = /ready" in contents
    assert "proxy_pass http://$backend_api/ready;" in contents
    assert "location = /health/ready" in contents
    assert "proxy_pass http://$backend_api/health/ready;" in contents
    assert contents.index("location = /ready") < contents.index("location / {")


def test_selfhost_nginx_proxies_readiness_before_spa_fallback() -> None:
    _assert_ready_proxied_before_spa_fallback("docker/nginx-selfhost.prod.conf.template")


def test_tunnel_nginx_proxies_readiness_before_spa_fallback() -> None:
    _assert_ready_proxied_before_spa_fallback("nginx-tunnel.conf.template")


def test_static_ui_nginx_does_not_serve_spa_for_readiness() -> None:
    contents = _text("ui/nginx.spa.conf")

    assert "location = /ready" in contents
    assert "location = /health/ready" in contents
    assert "readiness_not_proxied" in contents
    assert contents.index("location = /ready") < contents.index("location / {")


def test_beta_tunnel_edge_healthcheck_uses_readiness() -> None:
    contents = _text("docker-compose.profile.tunnel.yml")

    assert "http://127.0.0.1/ready" in contents
    assert "http://127.0.0.1/health" not in contents


def test_selfhost_edge_healthchecks_use_readiness() -> None:
    contents = _text("docker-compose.selfhost.prod.yml")

    assert contents.count("http://127.0.0.1/ready") >= 2
    assert "http://127.0.0.1/health" not in contents


def test_gateway_container_healthchecks_use_dependency_readiness() -> None:
    assert "http://localhost:8000/health/ready" in _text("docker-compose.base.yml")
    assert "http://localhost:8000/health/ready" in _text("docker-compose.selfhost.prod.yml")
