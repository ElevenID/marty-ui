"""Actual Compose model gate for the explicit Envoy override; never deploys."""

from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
import runpy
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BIND = runpy.run_path(str(ROOT / "scripts/test_beta_application_image_compose.py"))
BASE = ROOT / "docker-compose.base.yml"
NATIVE = ROOT / "docker-compose.profile.issuance-native.yml"
PROFILE = ROOT / "docker-compose.profile.envoy-native-issuance.yml"


def assert_model(baseline, selected, path):
    """Derive only the two intended Envoy service changes from the baseline."""
    expected = deepcopy(baseline)
    envoy = expected["services"]["envoy"]
    slots = [
        index
        for index, volume in enumerate(envoy["volumes"])
        if volume["target"] == "/etc/envoy/envoy.yaml"
    ]
    assert len(slots) == 1
    envoy["volumes"][slots[0]] = {
        "type": "bind",
        "source": path.as_posix(),
        "target": "/etc/envoy/envoy.yaml",
        "read_only": True,
        "bind": {"create_host_path": False},
    }
    envoy["depends_on"]["issuance-native"] = {
        "condition": "service_healthy",
        "required": True,
    }
    assert selected == expected, "Envoy selection changed unrelated Compose settings"
    # No test claim that Compose config verifies file presence or Envoy semantics.
    assert path.is_file() and not path.is_symlink(), (
        "Candidate must be an existing regular file"
    )


def run(command):
    with tempfile.TemporaryDirectory(prefix="envoy-native-model-") as temporary:
        directory = Path(temporary)
        candidate = directory / "synthetic-candidate.yaml"
        candidate.write_text("static_resources: {}\n", encoding="utf-8")
        required = dict.fromkeys(
            re.findall(r"\$\{([A-Z0-9_]+):\?", BASE.read_text(encoding="utf-8")),
            "synthetic-required-artifact",
        )
        for token in (None, "", "synthetic-envoy-custom-service-token"):
            values = {**required, "MARTY_ENVOY_NATIVE_CONFIG": candidate.as_posix()}
            if token is not None:
                values["GRPC_SERVICE_TOKEN"] = token
            (directory / "images.env").write_text(
                "".join(f"{key}={value}\n" for key, value in values.items()),
                encoding="utf-8",
            )
            baseline = BIND["render_binding"](directory, command, BASE, NATIVE)
            selected = BIND["render_binding"](directory, command, BASE, NATIVE, PROFILE)
            assert_model(baseline, selected, candidate)
        for value in (None, ""):
            (directory / "images.env").write_text(
                "".join(f"{key}={value}\n" for key, value in required.items())
                + ("" if value is None else "MARTY_ENVOY_NATIVE_CONFIG=\n"),
                encoding="utf-8",
            )
            try:
                BIND["render_binding"](directory, command, BASE, NATIVE, PROFILE)
            except subprocess.CalledProcessError as error:
                assert "required variable MARTY_ENVOY_NATIVE_CONFIG" in error.stderr
            else:
                raise AssertionError("Missing required generated config was accepted")
        # The shared renderer disables consistency checks; this is model evidence
        # only, never a claim that a native owner has started or is reachable.
        assert "issuance-native" in selected["services"]
    print(
        "PASS: three complete Envoy Compose models and missing/empty selectors; configuration only"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", default="docker")
    args = parser.parse_args()
    command = [args.compose_command]
    if Path(args.compose_command).stem.lower() == "docker":
        command.append("compose")
    run(command)
