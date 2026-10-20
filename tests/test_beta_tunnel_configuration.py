"""Controlled credential/configuration rejection cases; no service starts or demo proof."""

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts/beta_tunnel_configuration.py"
TOKEN = "CONTROLLED_TEST_ONLY_BASE64_TOKEN_" + "a" * 48


@pytest.fixture
def gate():
    return runpy.run_path(str(MODULE))


def active():
    return {
        "Id": "a" * 64,
        "State": {"Running": True},
        "Config": {
            "Labels": {
                "com.docker.compose.project": "elevenid-beta",
                "com.docker.compose.service": "cloudflared",
            },
            "Env": ["TUNNEL_TOKEN=" + TOKEN],
            "Cmd": ["tunnel", "--no-autoupdate", "run"],
        },
    }


def test_actual_input_text_accepts_bom_crlf_without_disclosing_value(gate):
    assert (
        gate["token_from_input"](("\ufeffTUNNEL_TOKEN=" + TOKEN + "\r\n").encode())
        == TOKEN
    )
    assert gate["bind_active"](TOKEN, active()) == "a" * 64


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"TUNNEL_TOKEN=placeholder",
        b"TUNNEL_TOKEN=bad\nSECRET=x\n",
        ("TUNNEL_TOKEN=" + TOKEN + "\nTUNNEL_TOKEN=" + TOKEN).encode(),
        b"\xff",
    ],
)
def test_malformed_or_ambiguous_input_has_generic_failure(gate, content):
    with pytest.raises(
        gate["TunnelInputError"],
        match="^Beta tunnel credential/configuration binding failed$",
    ):
        gate["token_from_input"](content)


@pytest.mark.parametrize(
    "change",
    [
        "stale",
        "project",
        "service",
        "stopped",
        "duplicate",
        "argv",
        "joined-argv",
        "embedded",
        "entrypoint",
    ],
)
def test_active_peer_and_exact_secret_binding_fail_closed(gate, change):
    c = active()
    if change == "stale":
        c["Config"]["Env"] = ["TUNNEL_TOKEN=" + TOKEN + "other"]
    if change == "project":
        c["Config"]["Labels"]["com.docker.compose.project"] = "marty-selfhost-prod"
    if change == "service":
        c["Config"]["Labels"]["com.docker.compose.service"] = "other"
    if change == "stopped":
        c["State"]["Running"] = False
    if change == "duplicate":
        c["Config"]["Env"] *= 2
    if change == "argv":
        c["Config"]["Cmd"] += ["--token", TOKEN]
    if change == "joined-argv":
        c["Config"]["Cmd"] += ["--token=" + TOKEN]
    if change == "embedded":
        c["Config"]["Cmd"] += ["unexpected=" + TOKEN]
    if change == "entrypoint":
        c["Config"]["Entrypoint"] = ["cloudflared", "--token=" + TOKEN]
    with pytest.raises(
        gate["TunnelInputError"],
        match="^Beta tunnel credential/configuration binding failed$",
    ):
        gate["bind_active"](TOKEN, c)


def secure_file(path):
    if os.name != "nt":
        path.chmod(0o600)
        return
    sid = subprocess.check_output(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ],
        text=True,
    ).strip()
    subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
        ],
        check=True,
        capture_output=True,
    )


def test_real_private_file_check_allows_normal_read_access_timestamp_changes(
    gate, tmp_path
):
    p = tmp_path / "controlled.env"
    p.write_text("TUNNEL_TOKEN=" + TOKEN + "\n")
    secure_file(p)
    actual, content = gate["private_input"](p)
    assert actual == p and content == p.read_bytes()


def test_real_file_rejects_excessive_readers_and_cloud_synced_path(gate, tmp_path):
    p = tmp_path / "controlled.env"
    p.write_text("TUNNEL_TOKEN=" + TOKEN + "\n")
    secure_file(p)
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(p), "/grant", "*S-1-5-32-545:(R)"],
            check=True,
            capture_output=True,
        )
    else:
        p.chmod(0o644)
    with pytest.raises(gate["TunnelInputError"]):
        gate["private_input"](p)
    cloud = tmp_path / "OneDrive - controlled"
    cloud.mkdir()
    q = cloud / "credential.env"
    q.write_text("TUNNEL_TOKEN=" + TOKEN)
    secure_file(q)
    with pytest.raises(gate["TunnelInputError"]):
        gate["private_input"](q)


def test_changed_source_or_connector_is_rejected_on_revalidation(
    gate, tmp_path, monkeypatch
):
    namespace = gate["validate"].__globals__
    monkeypatch.setitem(
        namespace,
        "private_input",
        lambda path: (path, ("TUNNEL_TOKEN=" + TOKEN).encode()),
    )
    monkeypatch.setitem(namespace, "inspect_active", active)
    first = gate["validate"](tmp_path / "credential.env")
    assert TOKEN not in json.dumps(first)
    assert (
        gate["validate"](
            tmp_path / "credential.env",
            first["credential_sha256"],
            first["connector_id"],
        )
        == first
    )
    for fingerprint, identity in [
        ("b" * 64, first["connector_id"]),
        (first["credential_sha256"], "b" * 64),
    ]:
        with pytest.raises(gate["TunnelInputError"]):
            gate["validate"](tmp_path, fingerprint, identity)


@pytest.mark.skipif(
    not shutil.which("docker"), reason="requires Compose configuration renderer only"
)
def test_actual_compose_reset_uses_private_input_and_preserves_other_settings(
    gate, tmp_path
):
    credential = tmp_path / "controlled.env"
    credential.write_text("TUNNEL_TOKEN=" + TOKEN + "\n")
    base = {
        "services": {
            "cloudflared": {
                "image": "cloudflare/cloudflared:2024.12.2",
                "command": ["tunnel", "run", "--token", "CONTROLLED_OLD_VALUE"],
                "environment": {
                    "TUNNEL_TOKEN": "CONTROLLED_OLD_VALUE",
                    "KEEP": "unchanged",
                },
            }
        }
    }
    base_path = tmp_path / "base.json"
    base_path.write_text(json.dumps(base))
    override = tmp_path / "override.yml"
    override.write_text(gate["override_text"](credential))
    assert TOKEN not in override.read_text()
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            "controlled-beta-tunnel-config",
            "-f",
            str(base_path),
            "-f",
            str(override),
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
    )
    assert result.returncode == 0
    service = json.loads(result.stdout)["services"]["cloudflared"]
    assert service["command"] == ["tunnel", "--no-autoupdate", "run"]
    assert service["environment"] == {"TUNNEL_TOKEN": TOKEN, "KEEP": "unchanged"}


def test_cli_failure_does_not_echo_input_or_native_errors(tmp_path):
    p = tmp_path / "controlled.env"
    p.write_text("TUNNEL_TOKEN=" + TOKEN + "\nPRIVATE=" + TOKEN)
    secure_file(p)
    result = subprocess.run(
        [__import__("sys").executable, str(MODULE), "--credential-env-file", str(p)],
        capture_output=True,
    )
    assert result.returncode == 1 and result.stdout == b""
    assert (
        result.stderr.replace(b"\r\n", b"\n")
        == b"Beta tunnel private input validation failed\n"
    )
