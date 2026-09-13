"""Render a closed, synthetic process fixture from the actual base opt-in model.

The fixture overlay changes only owned addresses/listeners and filesystem paths.
It is not a deployment overlay and does not claim container DNS/mount acceptance.
No application is launched, operator env file read, or policy content loaded here.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import runpy
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_base_native_issuance_compose.py"))
INPUT_KEYS = frozenset(
    {
        "ISSUANCE_API_KEY",
        "GRPC_SERVICE_TOKEN",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "TOKEN_HMAC_KEY",
        "INTEGRATION_SECRET_MASTER_KEY",
        "PUBLIC_API_URL",
        "UI_BASE_URL",
        "ISSUANCE_OFFER_TTL_MINUTES",
        "TOKEN_RATE_LIMIT",
        "CANVAS_PORTABLE_INTEGRATION_ENABLED",
        "CANVAS_PILOT_ORGANIZATION_IDS",
    }
)
SPEC_KEYS = frozenset(
    {
        "inputs",
        "http_port",
        "grpc_port",
        "gateway_port",
        "database_url",
        "redis_url",
        "peer_origin",
        "legacy_origin",
        "ca_file",
        "policy_directory",
        "authcrypt",
        "allow_private_ips",
    }
)
GATEWAY_PEER_URLS = frozenset(
    """
AUTH_SERVICE_URL ORGANIZATION_SERVICE_URL CREDENTIAL_TEMPLATE_SERVICE_URL
TRUST_PROFILE_SERVICE_URL APPLICANT_SERVICE_URL NOTIFICATION_SERVICE_URL
COMPLIANCE_PROFILE_SERVICE_URL PRESENTATION_POLICY_SERVICE_URL
DEPLOYMENT_PROFILE_SERVICE_URL SIGNING_KEYS_SERVICE_URL FLOW_SERVICE_URL
DEVICE_REGISTRATION_SERVICE_URL REVOCATION_PROFILE_SERVICE_URL
""".split()
)


def owned_url(value, scheme):
    assert isinstance(value, str)
    parsed = urlsplit(value)
    assert parsed.scheme in scheme and parsed.hostname in {"127.0.0.1", "localhost"}
    assert parsed.port and not parsed.query and not parsed.fragment
    return value


def validate_spec(spec):
    assert isinstance(spec, dict) and set(spec) == SPEC_KEYS
    assert isinstance(spec["inputs"], dict) and set(spec["inputs"]) == INPUT_KEYS
    assert all(
        isinstance(value, str) and "\n" not in value and "\r" not in value
        for value in spec["inputs"].values()
    )
    assert type(spec["authcrypt"]) is type(spec["allow_private_ips"]) is bool
    ports = [spec[name] for name in ("http_port", "grpc_port", "gateway_port")]
    assert len(set(ports)) == 3
    assert all(type(port) is int and 0 < port < 65536 for port in ports)
    owned_url(spec["database_url"], {"postgres", "postgresql"})
    owned_url(spec["redis_url"], {"redis"})
    for name in ("peer_origin", "legacy_origin"):
        owned_url(spec[name], {"http"})
        assert not urlsplit(spec[name]).username and not urlsplit(spec[name]).password
    assert spec["peer_origin"] != spec["legacy_origin"]
    directory = Path(spec["policy_directory"])
    ca = Path(spec["ca_file"])
    assert (
        directory.is_absolute() and directory.is_dir() and directory.parent != directory
    )
    assert ca.is_file() and ca.parent.resolve() == directory.resolve()
    if spec["authcrypt"]:
        assert (directory / "didcomm-encryption-policy.json").is_file()


def fixture_overlay(spec, selected):
    native = {
        "MARTY_ISSUANCE__SERVER__HOST": "127.0.0.1",
        "DATABASE_URL": spec["database_url"],
        "ISSUANCE_SERVICE_PORT": str(spec["http_port"]),
        "ISSUANCE_GRPC_PORT": str(spec["grpc_port"]),
        "ORG_GRPC_TARGET": spec["peer_origin"],
        "CT_GRPC_TARGET": spec["peer_origin"],
        "RP_GRPC_TARGET": spec["peer_origin"],
        "CREDENTIAL_TEMPLATE_SERVICE_URL": spec["peer_origin"],
        "REVOCATION_PROFILE_SERVICE_URL": spec["peer_origin"],
        "SIGNING_KEYS_INTERNAL_URL": spec["peer_origin"],
        "DIDCOMM_DID_WEB_INTERNAL_BASE_URL": spec["peer_origin"],
        "DIDCOMM_TLS_CA_FILE": spec["ca_file"],
    }
    if spec["authcrypt"]:
        native["DIDCOMM_ENCRYPTION_POLICY_FILE"] = str(
            Path(spec["policy_directory"]) / "didcomm-encryption-policy.json"
        )
    addresses = {
        name
        for name in selected["services"]["gateway"]["environment"]
        if name.endswith("_SERVICE_URL")
    }
    assert addresses == GATEWAY_PEER_URLS | {
        "ISSUANCE_SERVICE_URL",
        "ISSUANCE_NATIVE_SERVICE_URL",
    }
    gateway = dict.fromkeys(GATEWAY_PEER_URLS, spec["peer_origin"])
    gateway.update(
        {
            "GATEWAY_PORT": str(spec["gateway_port"]),
            "ISSUANCE_SERVICE_URL": spec["legacy_origin"],
            "ISSUANCE_NATIVE_SERVICE_URL": f"http://127.0.0.1:{spec['http_port']}",
            "AUTH_GRPC_TARGET": spec["peer_origin"],
            "ORG_GRPC_TARGET": spec["peer_origin"],
            "ES_GRPC_TARGET": spec["peer_origin"],
            "REDIS_URL": spec["redis_url"],
        }
    )
    return {
        "services": {
            "issuance-native": {"environment": native},
            "gateway": {"environment": gateway},
        }
    }


def assert_fixture_delta(selected, actual, overlay, spec):
    assert overlay == fixture_overlay(spec, selected), (
        "Unapproved fixture input override"
    )
    assert set(overlay) == {"services"}
    assert set(overlay["services"]) == {"issuance-native", "gateway"}
    expected = deepcopy(selected)
    for name, service in overlay["services"].items():
        assert set(service) == {"environment"}
        expected["services"][name]["environment"].update(service["environment"])
    assert actual == expected, (
        "Runtime fixture changed outside the closed address/path overlay"
    )


def render(spec, command):
    validate_spec(spec)
    GATE["assert_sources"](
        GATE["source"]("docker-compose.base.yml"),
        GATE["source"](GATE["PROFILE"]),
        GATE["source"](GATE["RUNTIME"]),
    )
    with tempfile.TemporaryDirectory(prefix="base-runtime-render-") as temporary:
        directory = Path(temporary)
        # Reuse the base gate's existing required-artifact binding. No image or
        # build is executed; all inputs remain synthetic and process-local.
        import re

        required = {
            key: "synthetic-required-artifact"
            for key in re.findall(
                r"\$\{([A-Z0-9_]+):\?", (ROOT / "docker-compose.base.yml").read_text()
            )
        }
        inputs = {
            **required,
            **spec["inputs"],
            "DIDCOMM_ENCRYPTION_POLICY_DIR": Path(spec["policy_directory"]).as_posix(),
            "DIDCOMM_ALLOW_PRIVATE_IPS": "true"
            if spec["allow_private_ips"]
            else "false",
        }
        (directory / "images.env").write_text(
            "".join(f"{key}={value}\n" for key, value in sorted(inputs.items())),
            encoding="utf-8",
        )
        baseline = GATE["BIND"]["render_binding"](
            directory,
            command,
            *GATE["files"](native=False, local=True, authcrypt=False),
            project=GATE["PROJECT"],
        )
        files = GATE["files"](native=True, local=True, authcrypt=spec["authcrypt"])
        selected = GATE["BIND"]["render_binding"](
            directory, command, *files, project=GATE["PROJECT"]
        )
        GATE["assert_model"](
            baseline,
            selected,
            local=True,
            authcrypt=spec["authcrypt"],
            inputs=inputs,
            policy_directory=Path(spec["policy_directory"]),
        )
        overlay = fixture_overlay(spec, selected)
        overlay_file = directory / "owned-process-addresses.json"
        overlay_file.write_text(json.dumps(overlay), encoding="utf-8")
        actual = GATE["BIND"]["render_binding"](
            directory, command, *files, overlay_file, project=GATE["PROJECT"]
        )
        assert_fixture_delta(selected, actual, overlay, spec)
        native = actual["services"]["issuance-native"]["environment"]
        gateway = actual["services"]["gateway"]["environment"]
        assert native["ISSUANCE_GRPC_ENABLED"] == "true"
        assert (
            gateway["REDIS_DB_GATEWAY"]
            == baseline["services"]["gateway"]["environment"]["REDIS_DB_GATEWAY"]
            == "2"
        )
        return {
            "schema": "marty.base-native-process-fixture/v1",
            "native_environment": native,
            "gateway_environment": gateway,
            "overlay": overlay,
            "base_files": [path.name for path in files],
            "native_entrypoint": actual["services"]["issuance-native"]["entrypoint"],
            "native_command": actual["services"]["issuance-native"]["command"],
            "scope": "actual rendered settings with closed owned-process address/path substitutions; not container networking or release-image proof",
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    args = parser.parse_args()
    spec = json.loads(sys.stdin.buffer.read(65537))
    result = render(spec, args.compose_command)
    print(json.dumps(result, separators=(",", ":")))
