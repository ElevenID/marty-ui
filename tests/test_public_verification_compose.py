"""Actual Compose merge/interpolation only; never starts a service or reads operator inputs."""

from copy import deepcopy
import json
from pathlib import Path
import runpy
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "deploy-config/compose/public-verification/compose.openbao.yml"
BASE = ROOT / "docker-compose.selfhost.prod.yml"
GATE = runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))
BIND = runpy.run_path(str(ROOT / "scripts/test_beta_application_image_compose.py"))
TOKEN = "sign_grant_mint_flow_demo_holder_token"
CONFIG_INPUT = "MARTY_PUBLIC_VERIFICATION_CONFIG_PATH"
TOKEN_INPUT = "MARTY_PUBLIC_VERIFICATION_HOLDER_MINT_TOKEN_FILE"


def test_opt_in_overlay_preserves_every_unrelated_service_and_authority():
    before = GATE["render"](str(BASE))
    after = GATE["render"](str(BASE), str(OVERLAY))
    for model in (before, after):
        model["services"]["flow"]["environment"] = GATE["environment_mapping"](
            model["services"]["flow"]["environment"]
        )
    flow = after["services"]["flow"]
    assert flow["environment"]["MARTY_SIGNING_GRANT_PROVIDER"] == "openbao-transit"
    assert (
        flow["environment"]["FLOW_PUBLIC_VERIFICATION_CONFIG_FILE"]
        == "/run/marty/public-verification.json"
    )
    assert (
        flow["environment"]["FLOW_DEMO_HOLDER_SIGN_GRANT_MINT_TOKEN_FILE"]
        == f"/run/secrets/{TOKEN}"
    )
    config = [
        mount
        for mount in flow["volumes"]
        if mount["target"] == "/run/marty/public-verification.json"
    ]
    assert len(config) == 1
    assert config[0]["type"] == "bind" and config[0]["read_only"] is True
    assert config[0].get("bind", {}).get("create_host_path") is False
    recipients = {
        name
        for name, service in after["services"].items()
        if any(secret["source"] == TOKEN for secret in service.get("secrets", []))
    }
    assert recipients == {"flow"}

    # Strip exactly the reviewed additions; all commands, image pins, auth,
    # ports, TLS, existing mint credentials and other service models must match.
    restored = deepcopy(after)
    restored_flow = restored["services"]["flow"]
    for key in (
        "MARTY_SIGNING_GRANT_PROVIDER",
        "FLOW_PUBLIC_VERIFICATION_CONFIG_FILE",
        "FLOW_DEMO_HOLDER_SIGN_GRANT_MINT_TOKEN_FILE",
    ):
        if key in before["services"]["flow"]["environment"]:
            restored_flow["environment"][key] = before["services"]["flow"][
                "environment"
            ][key]
        else:
            restored_flow["environment"].pop(key)
    restored_flow["volumes"] = [
        mount for mount in restored_flow["volumes"] if mount not in config
    ]
    if "volumes" not in before["services"]["flow"]:
        restored_flow.pop("volumes")
    restored_flow["secrets"] = [
        secret for secret in restored_flow["secrets"] if secret["source"] != TOKEN
    ]
    restored["secrets"].pop(TOKEN)
    assert restored == before


def synthetic_base(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(
        json.dumps({"services": {"flow": {"image": "synthetic-unused:fixture"}}}),
        encoding="utf-8",
    )
    return base


@pytest.mark.parametrize("missing", [CONFIG_INPUT, TOKEN_INPUT])
@pytest.mark.parametrize("value", [None, ""])
def test_missing_or_empty_operator_paths_fail_compose_render(tmp_path, missing, value):
    values = {
        CONFIG_INPUT: "/synthetic/config.json",
        TOKEN_INPUT: "/synthetic/dedicated-token",
    }
    if value is None:
        values.pop(missing)
    else:
        values[missing] = value
    (tmp_path / "images.env").write_text(
        "".join(f"{key}={item}\n" for key, item in values.items()), encoding="utf-8"
    )
    with pytest.raises(subprocess.CalledProcessError) as failure:
        BIND["render_binding"](
            tmp_path, ["docker", "compose"], synthetic_base(tmp_path), OVERLAY
        )
    assert missing in failure.value.stderr


def test_interpolated_files_are_read_only_and_render_does_not_change_them(tmp_path):
    config = tmp_path / "fictional-config.json"
    token = tmp_path / "synthetic-mint-token"
    config.write_text('{"fixture":"not-an-enabled-catalog"}', encoding="utf-8")
    token.write_text("synthetic-only-not-a-live-capability", encoding="utf-8")
    contents = {path: path.read_bytes() for path in (config, token)}
    (tmp_path / "images.env").write_text(
        f"{CONFIG_INPUT}={config.as_posix()}\n{TOKEN_INPUT}={token.as_posix()}\n",
        encoding="utf-8",
    )
    model = BIND["render_binding"](
        tmp_path, ["docker", "compose"], synthetic_base(tmp_path), OVERLAY
    )
    mount = model["services"]["flow"]["volumes"][0]
    assert Path(mount["source"]).resolve() == config.resolve()
    assert mount["read_only"] is True
    assert mount.get("bind", {}).get("create_host_path") is False
    assert Path(model["secrets"][TOKEN]["file"]).resolve() == token.resolve()
    assert all(path.read_bytes() == content for path, content in contents.items())


def test_no_default_stack_or_bundle_selects_public_admission():
    for directory in (ROOT / "deploy-config/stacks", ROOT / "deploy-config/bundles"):
        for path in directory.glob("*.json"):
            assert "public-verification/compose.openbao.yml" not in path.read_text(
                encoding="utf-8"
            ), path
