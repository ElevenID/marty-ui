"""Test-only actual Compose -> closed Flow loader fixture; never deployment.

Target substitution follows the rendered owner, including a real legacy control.
No service starts here, operator environment is loaded, or TLS policy is changed.
Only synthetic secret files are created in the caller's empty owned directory.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import runpy
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
BASE = runpy.run_path(str(ROOT / "scripts/test_base_native_issuance_compose.py"))
SELFHOST = runpy.run_path(str(ROOT / "scripts/test_selfhost_native_owner_compose.py"))
TOKEN = "synthetic-flow-composed-service-token"
KEY = "synthetic-legacy-physical-api-key"
SPEC_KEYS = {"native_rpc", "legacy_rpc", "legacy_http", "directory"}
SECRET_VALUES = {
    "grpc_service_token": TOKEN,
    "issuance_api_key": KEY,
    "marty_db_password": "synthetic-flow-database-password",
    "flow_webhook_secret": "synthetic-flow-rendered-webhook-secret",
    "flow_application_event_hmac_key": "synthetic-flow-rendered-event-hmac-key",
}
TLS_FILES = {
    "GRPC_WORKLOAD_TLS_CLIENT_CERT": "flow_workload_client_cert",
    "GRPC_WORKLOAD_TLS_CLIENT_KEY": "flow_workload_client_key",
    "GRPC_WORKLOAD_TLS_SERVER_CERT": "flow_workload_server_cert",
    "GRPC_WORKLOAD_TLS_SERVER_KEY": "flow_workload_server_key",
    "GRPC_WORKLOAD_TLS_CA_CERT": "workload_identity_ca_cert",
}


def validate_spec(spec):
    assert isinstance(spec, dict) and set(spec) == SPEC_KEYS
    for name in ("native_rpc", "legacy_rpc", "legacy_http"):
        value = urlsplit(spec[name])
        assert value.scheme == "http" and value.hostname == "127.0.0.1"
        assert value.port and not value.username and not value.password
        assert not value.path and not value.query and not value.fragment
    assert (
        len({spec[name] for name in ("native_rpc", "legacy_rpc", "legacy_http")}) == 3
    )
    directory = Path(spec["directory"])
    assert directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
    assert not list(directory.iterdir()), "Fixture directory must be empty and owned"
    return directory


def mapped_environment(service, spec):
    """Only owned listener and declared-file paths may differ from Compose."""
    original = service["environment"]
    environment = deepcopy(original)
    environment["ISSUANCE_GRPC_TARGET"] = {
        "issuance:9005": spec["legacy_rpc"],
        "issuance-native:9005": spec["native_rpc"],
    }[original["ISSUANCE_GRPC_TARGET"]]
    assert original["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
    environment["ISSUANCE_SERVICE_URL"] = spec["legacy_http"]
    declared = {item["source"] for item in service.get("secrets", [])}
    for key, value in original.items():
        if key.endswith("_FILE") or key in TLS_FILES:
            name = Path(value).name
            assert value == f"/run/secrets/{name}" and name in declared
            assert name in SECRET_VALUES or name in TLS_FILES.values()
            environment[key] = (Path(spec["directory"]) / name).as_posix()
    assert all(isinstance(value, str) for value in environment.values())
    return environment


def render(spec, command):
    directory = validate_spec(spec)
    BASE["assert_sources"](
        BASE["source"]("docker-compose.base.yml"),
        BASE["source"](BASE["PROFILE"]),
        BASE["source"](BASE["RUNTIME"]),
    )
    with tempfile.TemporaryDirectory(prefix="flow-render-model-") as temporary:
        root = Path(temporary)
        required = set()
        for name in ("docker-compose.base.yml", SELFHOST["GATE"]["BASE"]):
            required.update(
                re.findall(r"\$\{([A-Z0-9_]+):\?", (ROOT / name).read_text())
            )
        inputs = dict.fromkeys(required, "synthetic-required-artifact")
        inputs.update(
            ISSUANCE_API_KEY=KEY,
            SIGNING_KEYS_INTERNAL_API_KEY=KEY,
            GRPC_SERVICE_TOKEN=TOKEN,
            PUBLIC_API_URL="https://issuer.example",
            FLOW_CALLBACK_DESTINATIONS="org-1|https://callback.example/result?nonce=__MARTY_TOKEN__",
            SELFHOST_STATE_DIR=(directory / "unused-state").as_posix(),
            SELFHOST_SECRET_DIR=directory.as_posix(),
            KEYCLOAK_SOCIAL_LOGIN_ENABLED="false",
        )
        (root / "images.env").write_text(
            "".join(f"{key}={value}\n" for key, value in sorted(inputs.items())),
            encoding="utf-8",
        )

        def compose(*files):
            return BASE["BIND"]["render_binding"](
                root, command, *files, project="flow-rendered-selection"
            )

        base = compose(*BASE["files"](native=False, local=True, authcrypt=False))
        native = compose(*BASE["files"](native=True, local=True, authcrypt=False))
        BASE["assert_model"](
            base,
            native,
            local=True,
            authcrypt=False,
            inputs=inputs,
            policy_directory=directory,
        )
        previous = compose(ROOT / SELFHOST["FROZEN"])
        selfhost = compose(ROOT / SELFHOST["GATE"]["BASE"])
        SELFHOST["assert_models"](previous, selfhost)
        models = {"base": base, "base_native": native, "selfhost": selfhost}
        result = {
            name: {
                "environment": mapped_environment(model["services"]["flow"], spec),
                "original_environment": model["services"]["flow"]["environment"],
            }
            for name, model in models.items()
        }
        for name, value in SECRET_VALUES.items():
            (directory / name).write_text(value, encoding="utf-8")
        # Existing ephemeral certificate helper, not operator credential creation.
        fixture = runpy.run_path(str(ROOT / "scripts/test_canvas_lti_https.py"))
        certificate, key = fixture["create_loopback_certificate"](directory)
        for name in TLS_FILES.values():
            source = key if name.endswith("_key") else certificate
            (directory / name).write_bytes(source.read_bytes())
        return {"schema": "marty.flow-rendered-selection/v1", "profiles": result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    args = parser.parse_args()
    result = render(json.loads(sys.stdin.buffer.read(65537)), args.compose_command)
    print(json.dumps(result, separators=(",", ":")))
