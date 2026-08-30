from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_northstar_is_a_hardened_secret_mounted_partner_service() -> None:
    compose = _text("docker-compose.profile.northstar-admissions.yml")

    assert "NORTHSTAR_RUN_SECRET_FILE: /run/secrets/northstar_run" in compose
    assert "file: ${NORTHSTAR_RUN_SECRET_FILE:?" in compose
    assert (
        "MARTY_PUBLIC_GATEWAY_ORIGIN: ${MARTY_PUBLIC_GATEWAY_ORIGIN:-https://beta.elevenidllc.com}"
        in compose
    )
    assert "HOST: 0.0.0.0" in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "http://127.0.0.1:4175/health" in compose


def test_tunnel_routes_only_the_northstar_hostname_to_the_partner_service() -> None:
    nginx = _text("nginx-tunnel.conf.template")
    entrypoint = _text("scripts/nginx-entrypoint.sh")
    server = nginx.split("# D-11 external partner application", 1)[1]

    assert "server_name ${NORTHSTAR_ADMISSIONS_PUBLIC_HOST};" in server
    assert "northstar-admissions:4175" in server
    assert "proxy_set_header X-Forwarded-Proto https;" in server
    assert "gateway:8000" not in server
    assert "NORTHSTAR_ADMISSIONS_PUBLIC_HOST" in entrypoint
    assert "${NORTHSTAR_ADMISSIONS_PUBLIC_HOST}" in entrypoint


def test_d11_stack_declares_the_public_partner_origin_and_service() -> None:
    stack = json.loads(_text("deploy-config/stacks/tunnel-beta-d11.json"))
    services = json.loads(_text("deploy-config/catalog/services.json"))
    secrets = json.loads(_text("deploy-config/catalog/secrets.json"))

    assert stack["parent_stack"] == "tunnel-beta-experiments"
    assert "docker-compose.profile.northstar-admissions.yml" in stack["compose_files"]
    assert "admissions-test.elevenidllc.com" in stack["domains"]
    assert "external_demo" in stack["required_service_groups"]
    assert services["groups"]["external_demo"] == ["northstar-admissions"]
    assert (
        secrets["secrets"]["northstar_run"]["file_env"] == "NORTHSTAR_RUN_SECRET_FILE"
    )
    assert secrets["secrets"]["northstar_run"]["no_log"] is True
    assert stack["experiments"]["d11"]["marty_boundary"] == "public-v1-only"
