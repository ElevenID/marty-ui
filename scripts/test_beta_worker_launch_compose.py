"""Render synthetic rollback overlays; never pull, build, start, or restore containers.

Requires installed PowerShell and Compose. Only owned temporary files and real
pure-helper definitions are used; no actual deployment configuration is loaded.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORKER = "canvas-sync-worker"
PROCESSOR = (
    "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target"
)
SELECTIONS = ("SERVICE_NAME", "CANVAS_SYNC_PROCESSOR")
OLD_IMAGE = "sha256:" + "a" * 64
CURRENT_IMAGE = "sha256:" + "b" * 64

CAPTURE_SCRIPT = r"""
param([string]$Source, [string]$InputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Pure rollback helper syntax errors' }
$definitions=$ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
},$false)
if ($definitions.Count -eq 0) { throw 'Pure rollback helper definitions missing' }
foreach ($definition in $definitions) { Invoke-Expression $definition.Extent.Text }
function docker { throw 'Docker is forbidden in pure helper capture' }
function Invoke-Checked { throw 'Runner invocation is forbidden in pure helper capture' }
$cases=ConvertFrom-Json -InputObject (Get-Content -LiteralPath $InputPath -Raw)
$results=@()
foreach ($case in $cases) {
    $launch=New-BetaWorkerRollbackLaunch -ContainerConfig $case.config
    $record=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject @{rollback_launch=$launch} -Depth 20 -Compress)
    $resolved=Resolve-BetaWorkerRollbackLaunch -Record $record -CurrentWorker $null -ImageConfig $case.config
    $results+=@{name=$case.name; launch=$resolved; lines=@(ConvertTo-BetaWorkerRollbackLines -Launch $resolved)}
}
ConvertTo-Json -InputObject @($results) -Depth 20 -Compress
"""


def synthetic_captures():
    """Representative configurations, not a second implementation/allowlist."""
    python = ["python", "-m", "issuance.canvas_worker"]
    native = ["/usr/local/bin/marty-canvas-sync-worker"]
    dispatcher = ["/app/services/entrypoint.sh"]
    samples = [
        ("python-processing", None, python, {"CANVAS_SYNC_PROCESSOR": PROCESSOR}),
        (
            "python-empty-vectors",
            [],
            python,
            {"SERVICE_NAME": "issuance", "CANVAS_SYNC_PROCESSOR": PROCESSOR},
        ),
        ("native-entrypoint", native, None, {}),
        (
            "native-command-empty-selectors",
            [],
            native,
            {name: "" for name in SELECTIONS},
        ),
        (
            "rust-dispatcher-entrypoint",
            dispatcher,
            [],
            {"SERVICE_NAME": "canvas_sync_worker"},
        ),
        (
            "rust-dispatcher-command",
            None,
            dispatcher,
            {"SERVICE_NAME": "canvas-sync-worker"},
        ),
        (
            "python-secret-loader",
            ["/bin/sh", "-c"],
            [". /app/load-secrets-env.sh\nexec python -m issuance.canvas_worker\n"],
            {"CANVAS_SYNC_PROCESSOR": PROCESSOR},
        ),
        (
            "native-secret-loader",
            ["/bin/sh", "-c"],
            [
                ". /app/load-secrets-env.sh\nexec /usr/local/bin/marty-canvas-sync-worker\n"
            ],
            {},
        ),
    ]
    return [
        {
            "name": name,
            "config": {
                "Entrypoint": entrypoint,
                "Cmd": command,
                "Env": [f"{key}={value}" for key, value in selections.items()]
                + [
                    "API_KEY=synthetic-do-not-capture",
                    "DATABASE_URL=synthetic-do-not-capture",
                ],
            },
        }
        for name, entrypoint, command, selections in samples
    ]


def synthetic_model(current):
    service = {
        "image": CURRENT_IMAGE,
        "entrypoint": None,
        "command": ["python", "-m", "issuance.canvas_worker"],
        "environment": {
            "SERVICE_NAME": "issuance",
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
            "DATABASE_URL_TEMPLATE": "synthetic-file-secret-template",
            "MARTY_DB_PASSWORD_FILE": "/run/secrets/database_password",
            "CANVAS_SYNC_POLL_SECONDS": "60",
        },
        "secrets": [{"source": "database_password", "target": "database_password"}],
        "volumes": [{"type": "volume", "source": "worker_state", "target": "/state"}],
        "depends_on": {
            name: {"condition": "service_completed_successfully"}
            for name in ("db-migrate", "issuance-migrations")
        },
        "networks": ["application"],
        "restart": "unless-stopped",
        "healthcheck": {"disable": True},
        "init": True,
        "read_only": True,
        "stop_grace_period": "35s",
        "labels": {"synthetic.future-field": "preserve-complete-runtime-model"},
    }
    if current.startswith("rust"):
        service["entrypoint"] = ["/app/services/entrypoint.sh"]
        service["command"] = []
        service["environment"]["SERVICE_NAME"] = "canvas_sync_worker"
        del service["environment"]["CANVAS_SYNC_PROCESSOR"]
        if current == "rust-command":
            service["entrypoint"], service["command"] = [], service["entrypoint"]
    return {
        "services": {
            WORKER: service,
            **{
                name: {"image": CURRENT_IMAGE, "command": ["true"]}
                for name in ("db-migrate", "issuance-migrations")
            },
        },
        "secrets": {"database_password": {"file": "synthetic-secret.txt"}},
        "volumes": {"worker_state": {}},
        "networks": {"application": {}},
    }


def render(directory, compose_command, *files):
    environment = dict(os.environ)
    environment.update(
        {name: "synthetic-ambient-must-not-be-inherited" for name in SELECTIONS}
    )
    result = subprocess.run(
        [
            *compose_command,
            "--project-name",
            "rollback-launch-contract",
            "--env-file",
            "empty.env",
            *(argument for file in files for argument in ("-f", file)),
            "config",
            "--no-env-resolution",
            "--no-path-resolution",
            "--no-consistency",
            "--format",
            "json",
        ],
        cwd=directory,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return json.loads(result.stdout)


def assert_exact_model(actual, expected, name):
    assert actual == expected, (
        f"Synthetic rollback changed the complete runtime model: {name}"
    )


def run(compose_command=None, powershell_executable=None):
    compose_command = list(compose_command or ["docker", "compose"])
    powershell_executable = (
        powershell_executable
        or os.environ.get("POWERSHELL_TEST_EXE")
        or shutil.which("pwsh")
        or shutil.which("powershell")
    )
    if not powershell_executable:
        raise RuntimeError(
            "Executable PowerShell is mandatory for rollback Compose gate"
        )
    cases = synthetic_captures()
    checked = 0
    with tempfile.TemporaryDirectory(prefix="beta-worker-launch-compose-") as temporary:
        directory = Path(temporary)
        (directory / "empty.env").write_text("", encoding="utf-8")
        (directory / "synthetic-secret.txt").write_text(
            "synthetic-only", encoding="utf-8"
        )
        (directory / "capture.ps1").write_text(CAPTURE_SCRIPT, encoding="utf-8")
        (directory / "input.json").write_text(json.dumps(cases), encoding="utf-8")
        captured = subprocess.run(
            [
                str(powershell_executable),
                "-NoProfile",
                "-File",
                str(directory / "capture.ps1"),
                "-Source",
                str(ROOT / "scripts/beta-worker-launch-contract.ps1"),
                "-InputPath",
                str(directory / "input.json"),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        results = json.loads(captured.stdout)
        assert [result["name"] for result in results] == [
            case["name"] for case in cases
        ]
        assert "synthetic-do-not-capture" not in captured.stdout
        # Positive control: ordinary YAML null really can pick up ambient values.
        # No external .env is loaded and these are the only interpolated fields.
        ambient_model = synthetic_model("python")
        ambient_model["services"][WORKER]["environment"].update(
            {name: None for name in SELECTIONS}
        )
        (directory / "ambient.json").write_text(
            json.dumps(ambient_model), encoding="utf-8"
        )
        ambient = render(directory, compose_command, "ambient.json")
        assert all(
            ambient["services"][WORKER]["environment"][name]
            == "synthetic-ambient-must-not-be-inherited"
            for name in SELECTIONS
        )
        for current in ("python", "rust-entrypoint", "rust-command"):
            (directory / "base.json").write_text(
                json.dumps(synthetic_model(current)), encoding="utf-8"
            )
            base = render(directory, compose_command, "base.json")
            for case, result in zip(cases, results, strict=True):
                config = case["config"]
                assert result["launch"]["entrypoint"] == config["Entrypoint"]
                assert result["launch"]["command"] == config["Cmd"]
                overlay = (
                    "services:\n  canvas-sync-worker:\n    image: "
                    + OLD_IMAGE
                    + "\n"
                    + "\n".join(result["lines"])
                    + "\n"
                )
                (directory / "rollback.yml").write_text(overlay, encoding="utf-8")
                actual = render(directory, compose_command, "base.json", "rollback.yml")
                expected = deepcopy(base)
                worker = expected["services"][WORKER]
                worker.update(
                    image=OLD_IMAGE,
                    entrypoint=config["Entrypoint"] or [],
                    command=config["Cmd"] or [],
                )
                selections = dict(
                    entry.split("=", 1)
                    for entry in config["Env"]
                    if entry.split("=", 1)[0] in SELECTIONS
                )
                for name in SELECTIONS:
                    worker["environment"].pop(name, None)
                worker["environment"].update(selections)
                assert_exact_model(actual, expected, f"{current} <- {case['name']}")
                checked += 1
    assert checked == len(cases) * 3
    print(
        f"Rollback launch Compose gate: {checked} synthetic merges preserve launch, both selectors and complete runtime wiring; config only"
    )
    return checked


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    parser.add_argument("--powershell-executable")
    args = parser.parse_args()
    run(args.compose_command, args.powershell_executable)
