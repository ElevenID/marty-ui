"""Execute only pure launch-contract functions, never deploy/restore runners."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "scripts/beta-worker-launch-contract.ps1"
POWERSHELL = (
    os.environ.get("POWERSHELL_TEST_EXE")
    or shutil.which("pwsh")
    or shutil.which("powershell")
)
PYTHON_IMAGE_COMMAND = [
    "python",
    "-m",
    "uvicorn",
    "main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8005",
]

PROCESSOR = (
    "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target"
)

HARNESS = r"""
param([string]$Source, [string]$InputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Launch helper has syntax errors' }
# Load definitions only. No runner top-level code or external command is executed.
$definitions = $ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
}, $false)
if ($definitions.Count -eq 0) { throw 'Launch helpers missing' }
foreach ($definition in $definitions) { Invoke-Expression $definition.Extent.Text }
$script:ForbiddenCalls = 0
function docker {
    $script:ForbiddenCalls += 1
    throw 'Unexpected Docker invocation in pure helper'
}
function Invoke-Checked {
    $script:ForbiddenCalls += 1
    throw 'Unexpected mutation in pure helper'
}
$env:SERVICE_NAME = 'ambient-must-not-be-used'
$reports = @()
$cases = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $InputPath -Raw)
foreach ($case in $cases) {
    $launch = $null
    $lines = @()
    $mutations = 0
    $caught = $false
    $message = $null
    try {
        switch ($case.operation) {
            'capture' { $launch = New-BetaWorkerRollbackLaunch -ContainerConfig $case.config }
            'validate' { $launch = $case.launch }
            'resolve' {
                $launch = Resolve-BetaWorkerRollbackLaunch -Record $case.record -CurrentWorker $case.current_worker -ImageConfig $case.image_config
            }
            default { throw 'Unknown synthetic operation' }
        }
        # Exercise persisted JSON, including PowerShell singleton/empty-array behavior.
        $launch = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $launch -Depth 20 -Compress)
        Assert-BetaWorkerRollbackLaunch -Launch $launch
        $lines = @(ConvertTo-BetaWorkerRollbackLines -Launch $launch)
        # Synthetic marker represents mutation only after all validation/rendering.
        $mutations += 1
    } catch {
        $caught = $true
        $message = $_.Exception.Message
    }
    $reports += @{
        caught=$caught; message=$message; launch=$launch; lines=@($lines)
        mutations=$mutations; ambient=$env:SERVICE_NAME
        forbidden_calls=$script:ForbiddenCalls
    }
}
ConvertTo-Json -InputObject @($reports) -Depth 30 -Compress
"""


def test_ci_requires_executable_launch_contracts() -> None:
    assert not os.environ.get("CI") or POWERSHELL, (
        "CI must provide PowerShell; do not silently skip launch rollback contracts"
    )


@pytest.fixture
def exercise(tmp_path: Path):
    if not POWERSHELL:
        pytest.skip("PowerShell is required for executable launch rollback contracts")
    harness = tmp_path / "exercise.ps1"
    harness.write_text(HARNESS, encoding="utf-8")

    def run(cases: list[dict]) -> list[dict]:
        inputs = tmp_path / "cases.json"
        inputs.write_text(json.dumps(cases), encoding="utf-8")
        result = subprocess.run(
            [
                str(POWERSHELL),
                "-NoProfile",
                "-File",
                str(harness),
                "-Source",
                str(CONTRACT),
                "-InputPath",
                str(inputs),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
            timeout=30,
        )
        reports = json.loads(result.stdout)
        assert len(reports) == len(cases)
        assert all(report["forbidden_calls"] == 0 for report in reports)
        return reports

    return run


def launch(entrypoint, command, selector=None, processor=None) -> dict:
    return {
        "schema_version": 1,
        "entrypoint": entrypoint,
        "command": command,
        "service_name_present": selector is not None,
        "service_name": selector,
        "canvas_sync_processor_present": processor is not None,
        "canvas_sync_processor": processor,
    }


def rendered_fields(report: dict) -> dict:
    node = yaml.compose(
        "services:\n  canvas-sync-worker:\n" + "\n".join(report["lines"])
    )
    services = dict((key.value, value) for key, value in node.value)["services"]
    worker = dict((key.value, value) for key, value in services.value)[
        "canvas-sync-worker"
    ]
    return {key.value: value for key, value in worker.value}


@pytest.mark.parametrize(
    ("entrypoint", "command", "selector"),
    [
        (None, ["python", "-m", "issuance.canvas_worker"], None),
        ([], ["python", "-m", "issuance.canvas_worker"], None),
        (None, ["python3", "-m", "issuance.canvas_worker"], None),
        (["python", "-m", "issuance.canvas_worker"], None, None),
        (["python", "-m", "issuance.canvas_worker"], [], None),
        (["/usr/local/bin/marty-canvas-sync-worker"], None, None),
        (["/usr/local/bin/marty-canvas-sync-worker"], [], None),
        (["/usr/local/bin/marty-canvas-sync-worker"], [], ""),
        (None, ["/usr/local/bin/marty-canvas-sync-worker"], None),
        (["/app/services/entrypoint.sh"], None, "canvas_sync_worker"),
        (None, ["/app/services/entrypoint.sh"], "canvas-sync-worker"),
        (
            ["/bin/sh", "-c"],
            [". /app/load-secrets-env.sh\nexec python -m issuance.canvas_worker\n"],
            None,
        ),
    ],
)
def test_capture_persist_and_render_exact_headless_launch(
    exercise, entrypoint, command, selector
) -> None:
    environment = [
        "DATABASE_URL=synthetic-secret-never-capture",
        "TOKEN=synthetic-token",
    ]
    if selector is not None:
        environment.append(f"SERVICE_NAME={selector}")
    [report] = exercise(
        [
            {
                "operation": "capture",
                "config": {
                    "Entrypoint": entrypoint,
                    "Cmd": command,
                    "Env": environment,
                },
            }
        ]
    )
    assert report["caught"] is False, report["message"]
    assert report["mutations"] == 1
    assert report["ambient"] == "ambient-must-not-be-used"
    assert report["launch"] == launch(entrypoint, command, selector)
    assert "synthetic-secret" not in json.dumps(report)
    assert "synthetic-token" not in json.dumps(report)
    fields = rendered_fields(report)
    for name, expected in (("entrypoint", entrypoint), ("command", command)):
        assert fields[name].tag == "tag:yaml.org,2002:seq"
        assert [item.value for item in fields[name].value] == (expected or [])
    environment_node = fields["environment"]
    environment_fields = {key.value: value for key, value in environment_node.value}
    assert set(environment_fields) == {"SERVICE_NAME", "CANVAS_SYNC_PROCESSOR"}
    assert environment_fields["CANVAS_SYNC_PROCESSOR"].tag == "!reset"
    if selector is None:
        assert environment_fields["SERVICE_NAME"].tag == "!reset"
        assert environment_fields["SERVICE_NAME"].value == "null"
    else:
        assert environment_fields["SERVICE_NAME"].tag == "tag:yaml.org,2002:str"
        assert environment_fields["SERVICE_NAME"].value == selector


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("schema_version", 2),
        ("schema_version", "1"),
        ("schema_version", True),
        ("schema_version", 1.0),
        ("entrypoint", "/usr/local/bin/marty-canvas-sync-worker"),
        ("command", "python -m issuance.canvas_worker"),
        ("command", [1]),
        ("command", [None]),
        ("command", [["nested"]]),
        ("service_name_present", "false"),
        ("service_name", "issuance_native"),
        ("service_name", "${SERVICE_NAME}"),
        ("service_name", "canvas_sync_worker\nOTHER: synthetic-secret"),
    ],
)
def test_malformed_persisted_contract_is_rejected_before_mutation(exercise, field, bad):
    invalid = launch(["/usr/local/bin/marty-canvas-sync-worker"], None)
    invalid[field] = bad
    [report] = exercise([{"operation": "validate", "launch": invalid}])
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert report["lines"] == []
    assert "synthetic-secret" not in (report["message"] or "")


@pytest.mark.parametrize("missing", list(launch(None, None)))
def test_missing_contract_field_does_not_gain_ambient_defaults(exercise, missing):
    invalid = launch(["/usr/local/bin/marty-canvas-sync-worker"], None)
    del invalid[missing]
    [report] = exercise([{"operation": "validate", "launch": invalid}])
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert report["ambient"] == "ambient-must-not-be-used"


@pytest.mark.parametrize(
    "command",
    [
        [
            ". /app/load-secrets-env.sh\nexec python -m issuance.canvas_worker ${UNTRUSTED}"
        ],
        ["python -m issuance.canvas_worker; echo synthetic-secret"],
        ["exec python -m issuance.canvas_worker\nsynthetic-not-a-command"],
        ["exec python -m issuance.canvas_worker --token=synthetic-secret"],
    ],
)
def test_unrecognized_shell_or_secret_bearing_launch_is_not_replayed(exercise, command):
    [report] = exercise(
        [
            {
                "operation": "capture",
                "config": {"Entrypoint": ["/bin/sh", "-c"], "Cmd": command, "Env": []},
            }
        ]
    )
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert report["lines"] == []
    assert "synthetic-secret" not in (report["message"] or "")


def resolution_case(snapshot=None, *, current=None, image=None) -> dict:
    record = {
        "service": "canvas-sync-worker",
        "running": True,
        "image_id": "sha256:" + "a" * 64,
    }
    if snapshot is not None:
        record["rollback_launch"] = snapshot
    return {
        "operation": "resolve",
        "record": record,
        "current_worker": current
        if current is not None
        else {
            "command": ["python", "-m", "issuance.canvas_worker"],
            "environment": {"CANVAS_SYNC_PROCESSOR": PROCESSOR},
        },
        "image_config": image
        if image is not None
        else {
            "Entrypoint": None,
            "Cmd": PYTHON_IMAGE_COMMAND,
            "Env": [],
        },
    }


def test_saved_python_launch_overrides_new_rust_consumer_without_ambient_selector(
    exercise,
):
    saved = launch(None, ["python", "-m", "issuance.canvas_worker"])
    [report] = exercise(
        [
            resolution_case(
                saved,
                current={
                    "entrypoint": ["/app/services/entrypoint.sh"],
                    "command": [],
                    "environment": {"SERVICE_NAME": "canvas_sync_worker"},
                },
            )
        ]
    )
    assert report["caught"] is False, report["message"]
    assert report["launch"] == saved
    assert report["mutations"] == 1
    selector = dict(
        (key.value, value)
        for key, value in rendered_fields(report)["environment"].value
    )["SERVICE_NAME"]
    assert selector.tag == "!reset"


def test_saved_rust_launch_overrides_python_consumer(exercise):
    saved = launch(["/app/services/entrypoint.sh"], [], "canvas_sync_worker")
    [report] = exercise(
        [
            resolution_case(
                saved,
                image={
                    "Entrypoint": ["/app/services/entrypoint.sh"],
                    "Cmd": None,
                    "Env": ["SERVICE_NAME=issuance_native", "API_KEY=synthetic-secret"],
                },
            )
        ]
    )
    assert report["caught"] is False, report["message"]
    assert report["launch"] == saved
    assert report["mutations"] == 1
    assert "synthetic-secret" not in json.dumps(report)


@pytest.mark.parametrize("image_selector", ["", "canvas_sync_worker", "issuance"])
def test_absent_captured_selector_cannot_silently_inherit_image_selector(
    exercise, image_selector
):
    saved = launch(None, ["python", "-m", "issuance.canvas_worker"])
    [report] = exercise(
        [
            resolution_case(
                saved,
                image={
                    "Entrypoint": None,
                    "Cmd": None,
                    "Env": [f"SERVICE_NAME={image_selector}"],
                },
            )
        ]
    )
    assert report["caught"] is True
    assert report["mutations"] == 0


@pytest.mark.parametrize("selector", [None, "issuance", ""])
def test_legacy_manifest_allows_proven_python_image_and_consumer(exercise, selector):
    current = {
        "command": ["python", "-m", "issuance.canvas_worker"],
        "environment": {"CANVAS_SYNC_PROCESSOR": PROCESSOR},
    }
    if selector is not None:
        current["environment"]["SERVICE_NAME"] = selector
    [report] = exercise([resolution_case(current=current)])
    assert report["caught"] is False, report["message"]
    assert report["launch"] == launch(None, current["command"], selector, PROCESSOR)
    assert report["mutations"] == 1
    assert report["ambient"] == "ambient-must-not-be-used"


@pytest.mark.parametrize(
    ("current", "image"),
    [
        (
            {"command": ["/usr/local/bin/marty-canvas-sync-worker"], "environment": {}},
            None,
        ),
        (
            {
                "entrypoint": ["/app/services/entrypoint.sh"],
                "command": [],
                "environment": {"SERVICE_NAME": "canvas_sync_worker"},
            },
            None,
        ),
        (
            None,
            {
                "Entrypoint": ["/usr/local/bin/marty-canvas-sync-worker"],
                "Cmd": None,
                "Env": [],
            },
        ),
        (
            {
                "command": ["python", "-m", "issuance.canvas_worker"],
                "environment": {"SERVICE_NAME": None},
            },
            None,
        ),
    ],
)
def test_legacy_manifest_rejects_unproven_or_ambient_launch_before_mutation(
    exercise, current, image
):
    [report] = exercise([resolution_case(current=current, image=image)])
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert report["lines"] == []


@pytest.mark.parametrize(
    "environment",
    [
        ["SERVICE_NAME=canvas_sync_worker", "SERVICE_NAME=issuance"],
        ["SERVICE_NAME"],
        ["SERVICE_NAME=synthetic-secret-unsupported-selector"],
    ],
)
def test_ambiguous_or_unsupported_selector_is_not_captured(exercise, environment):
    [report] = exercise(
        [
            {
                "operation": "capture",
                "config": {
                    "Entrypoint": ["/usr/local/bin/marty-canvas-sync-worker"],
                    "Cmd": [],
                    "Env": environment,
                },
            }
        ]
    )
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert "synthetic-secret" not in (report["message"] or "")


def test_legacy_selector_uses_explicit_consumer_then_image_not_host(exercise):
    image = {
        "Entrypoint": None,
        "Cmd": PYTHON_IMAGE_COMMAND,
        "Env": ["SERVICE_NAME=issuance"],
    }
    reports = exercise(
        [
            resolution_case(image=image),
            resolution_case(
                image=image,
                current={
                    "command": ["python", "-m", "issuance.canvas_worker"],
                    "environment": {
                        "SERVICE_NAME": "issuance_native",
                        "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                    },
                },
            ),
        ]
    )
    for report, selector in zip(reports, ["issuance", "issuance_native"], strict=True):
        assert report["caught"] is False, report["message"]
        assert report["launch"]["service_name_present"] is True
        assert report["launch"]["service_name"] == selector
        assert report["ambient"] == "ambient-must-not-be-used"


def test_persisted_contract_cannot_expand_to_secret_environment_capture(exercise):
    invalid = launch(["/usr/local/bin/marty-canvas-sync-worker"], None)
    invalid["environment"] = {"DATABASE_URL": "synthetic-secret"}
    [report] = exercise([{"operation": "validate", "launch": invalid}])
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert report["lines"] == []
    assert "synthetic-secret" not in report["message"]


@pytest.mark.parametrize(
    "command",
    [
        None,
        ["/app/services/entrypoint.sh"],
        ["/usr/local/bin/marty-canvas-sync-worker"],
    ],
)
def test_legacy_python_consumer_requires_proven_python_image_command(exercise, command):
    [report] = exercise(
        [resolution_case(image={"Entrypoint": None, "Cmd": command, "Env": []})]
    )
    assert report["caught"] is True
    assert report["mutations"] == 0


def test_lowercase_environment_name_is_not_uppercase_selector(exercise):
    reports = exercise(
        [
            {
                "operation": "capture",
                "config": {
                    "Entrypoint": None,
                    "Cmd": ["python", "-m", "issuance.canvas_worker"],
                    "Env": ["service_name=issuance"],
                },
            },
            resolution_case(
                current={
                    "command": ["python", "-m", "issuance.canvas_worker"],
                    "environment": {
                        "service_name": "issuance",
                        "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                    },
                }
            ),
        ]
    )
    for report in reports:
        assert report["caught"] is False, report["message"]
        assert report["launch"]["service_name_present"] is False
        assert report["launch"]["service_name"] is None


@pytest.mark.parametrize(
    "processor",
    [
        None,
        "",
        "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target",
    ],
)
def test_old_python_processor_configuration_survives_current_rust_consumer(
    exercise, processor
):
    saved = launch(
        None, ["python", "-m", "issuance.canvas_worker"], processor=processor
    )
    [report] = exercise(
        [
            resolution_case(
                saved,
                current={
                    "entrypoint": ["/app/services/entrypoint.sh"],
                    "command": [],
                    "environment": {"SERVICE_NAME": "canvas_sync_worker"},
                },
            )
        ]
    )
    assert report["caught"] is False, report["message"]
    assert report["launch"] == saved
    fields = {
        key.value: value for key, value in rendered_fields(report)["environment"].value
    }
    node = fields["CANVAS_SYNC_PROCESSOR"]
    assert node.tag == ("!reset" if processor is None else "tag:yaml.org,2002:str")
    assert node.value == ("null" if processor is None else processor)


@pytest.mark.parametrize("processor", [None, "", "unsupported.synthetic:callback"])
def test_legacy_manifest_requires_proven_nonempty_builtin_processor(
    exercise, processor
):
    environment = {} if processor is None else {"CANVAS_SYNC_PROCESSOR": processor}
    [report] = exercise(
        [
            resolution_case(
                current={
                    "command": ["python", "-m", "issuance.canvas_worker"],
                    "environment": environment,
                }
            )
        ]
    )
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert "unsupported.synthetic" not in report["message"]


def test_legacy_processor_can_come_from_inspected_image_but_explicit_empty_blocks_it(
    exercise,
):
    image = {
        "Entrypoint": None,
        "Cmd": PYTHON_IMAGE_COMMAND,
        "Env": [f"CANVAS_SYNC_PROCESSOR={PROCESSOR}"],
    }
    reports = exercise(
        [
            resolution_case(
                image=image,
                current={
                    "command": ["python", "-m", "issuance.canvas_worker"],
                    "environment": {},
                },
            ),
            resolution_case(
                image=image,
                current={
                    "command": ["python", "-m", "issuance.canvas_worker"],
                    "environment": {"CANVAS_SYNC_PROCESSOR": ""},
                },
            ),
        ]
    )
    assert reports[0]["caught"] is False, reports[0]["message"]
    assert reports[0]["launch"]["canvas_sync_processor"] == PROCESSOR
    assert reports[1]["caught"] is True
    assert reports[1]["mutations"] == 0


def test_captured_absent_processor_cannot_inherit_immutable_image_default(exercise):
    [report] = exercise(
        [
            resolution_case(
                launch(None, ["python", "-m", "issuance.canvas_worker"]),
                image={
                    "Entrypoint": None,
                    "Cmd": PYTHON_IMAGE_COMMAND,
                    "Env": [f"CANVAS_SYNC_PROCESSOR={PROCESSOR}"],
                },
            )
        ]
    )
    assert report["caught"] is True
    assert report["mutations"] == 0


@pytest.mark.parametrize(
    "environment",
    [
        [f"CANVAS_SYNC_PROCESSOR={PROCESSOR}", "CANVAS_SYNC_PROCESSOR="],
        ["CANVAS_SYNC_PROCESSOR"],
        ["CANVAS_SYNC_PROCESSOR=unsupported.synthetic:callback"],
    ],
)
def test_ambiguous_or_unsupported_processor_is_not_captured(exercise, environment):
    [report] = exercise(
        [
            {
                "operation": "capture",
                "config": {
                    "Entrypoint": None,
                    "Cmd": ["python", "-m", "issuance.canvas_worker"],
                    "Env": environment,
                },
            }
        ]
    )
    assert report["caught"] is True
    assert report["mutations"] == 0
    assert "unsupported.synthetic" not in report["message"]


@pytest.mark.skipif(not POWERSHELL, reason="PowerShell is required for AST contracts")
def test_real_runner_ast_keeps_capture_scoped_and_restore_preflight_before_mutation(
    tmp_path,
):
    """Parse the runners, without evaluating even their parameter/default blocks."""
    harness = tmp_path / "inspect-integration.ps1"
    harness.write_text(
        r"""
param([string]$Root)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Read-Ast([string]$Path) {
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0) { throw 'Runner syntax errors' }
    return $ast
}
function Inside-Function($Node) {
    for ($parent=$Node.Parent; $null -ne $parent; $parent=$parent.Parent) {
        if ($parent -is [Management.Automation.Language.FunctionDefinitionAst]) { return $true }
    }
    return $false
}
$restore=Read-Ast (Join-Path $Root 'scripts/restore-local-beta-release.ps1')
$commands=@($restore.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst]
},$true) | Where-Object { -not (Inside-Function $_) })
$resolve=@($commands | Where-Object { $_.GetCommandName() -eq 'Resolve-BetaWorkerRollbackLaunch' })
$render=@($commands | Where-Object { $_.GetCommandName() -eq 'ConvertTo-BetaWorkerRollbackLines' })
$mutations=@($commands | Where-Object { $_.GetCommandName() -eq 'Invoke-Checked' } | Sort-Object { $_.Extent.StartOffset })
$write=@($commands | Where-Object {
    $_.GetCommandName() -eq 'Set-Content' -and @($_.CommandElements | Where-Object {
        $_ -is [Management.Automation.Language.VariableExpressionAst] -and $_.VariablePath.UserPath -eq 'restoreImages'
    }).Count -eq 1
})
$attach=@($restore.FindAll({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
    $node.Left.VariablePath.UserPath -eq 'composeFiles' -and
    $node.Operator -eq 'PlusEquals' -and
    @($node.Right.FindAll({ param($child)
        $child -is [Management.Automation.Language.VariableExpressionAst] -and
        $child.VariablePath.UserPath -eq 'restoreImages'
    },$true)).Count -eq 1
},$true))
if ($resolve.Count -ne 1 -or $render.Count -ne 1 -or $write.Count -ne 1 -or $attach.Count -ne 1 -or $mutations.Count -eq 0) { throw 'Missing unique restore integration owner' }
$dataTargets=@($restore.FindAll({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
    $node.Left.VariablePath.UserPath -cin @('postgres', 'redisVolumeName', 'applicantVolumeName')
},$true) | Where-Object { -not (Inside-Function $_) })
$dataValidations=@($commands | Where-Object {
    $_.GetCommandName() -cin @('Get-ServiceContainer', 'Assert-BetaVolume')
})
if ($dataTargets.Count -ne 3 -or $dataValidations.Count -ne 3) { throw 'Data targets must have unique preflight resolutions' }
$targetReport=@($dataTargets | ForEach-Object {
    $validation=@($_.Right.FindAll({ param($node)
        $node -is [Management.Automation.Language.CommandAst]
    },$true))
    if ($validation.Count -ne 1) { throw 'Data target must use one existing identity validator' }
    @{
        variable=$_.Left.VariablePath.UserPath; end=$_.Extent.EndOffset
        validator=$validation[0].GetCommandName()
        arguments=@($validation[0].CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Value })
    }
})
$deploy=Read-Ast (Join-Path $Root 'scripts/deploy-local-beta-release.ps1')
$captures=@($deploy.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'New-BetaWorkerRollbackLaunch'
},$true))
if ($captures.Count -ne 1) { throw 'Missing unique capture integration owner' }
$capture=$captures[0]
$guard=$null; $function=$null; $assignment=$null
for ($parent=$capture.Parent; $null -ne $parent; $parent=$parent.Parent) {
    if ($null -eq $guard -and $parent -is [Management.Automation.Language.IfStatementAst]) { $guard=$parent }
    if ($null -eq $assignment -and $parent -is [Management.Automation.Language.AssignmentStatementAst]) { $assignment=$parent }
    if ($parent -is [Management.Automation.Language.FunctionDefinitionAst]) { $function=$parent; break }
}
if ($null -eq $guard -or $guard.Clauses.Count -ne 1 -or $null -ne $guard.ElseClause) { throw 'Capture must have an explicit worker-only guard' }
$conditions=@($guard.Clauses[0].Item1.FindAll({ param($node)
    $node -is [Management.Automation.Language.BinaryExpressionAst]
},$true))
if ($conditions.Count -ne 1) { throw 'Capture guard must be one service comparison' }
$condition=$conditions[0]
@{
    resolve=$resolve[0].Extent.EndOffset; render=$render[0].Extent.EndOffset
    write=$write[0].Extent.EndOffset; attach=$attach[0].Extent.EndOffset
    first_mutation=$mutations[0].Extent.StartOffset
    data_targets=$targetReport
    first_mutation_arguments=@($mutations[0].FindAll({ param($node)
        $node -is [Management.Automation.Language.StringConstantExpressionAst]
    },$true) | ForEach-Object { $_.Value })
    capture_function=$function.Name
    capture_guard=@{
        operator=[string]$condition.Operator
        variable=$condition.Left.Expression.VariablePath.UserPath
        member=$condition.Left.Member.Value; value=$condition.Right.Value
    }
    capture_assignment=@{
        variable=$assignment.Left.Target.VariablePath.UserPath
        key=$assignment.Left.Index.Value
    }
} | ConvertTo-Json -Depth 10 -Compress
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-File", str(harness), "-Root", str(ROOT)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert (
        report["resolve"]
        < report["render"]
        < report["write"]
        < report["attach"]
        < report["first_mutation"]
    )
    assert "stop" in report["first_mutation_arguments"]
    targets = {target["variable"]: target for target in report["data_targets"]}
    assert len(targets) == 3
    for name, validator, argument in (
        ("postgres", "Get-ServiceContainer", "postgres"),
        ("redisVolumeName", "Assert-BetaVolume", "elevenid-beta_redis_data"),
        ("applicantVolumeName", "Assert-BetaVolume", "elevenid-beta_applicant_data"),
    ):
        assert targets[name]["validator"] == validator
        assert targets[name]["arguments"] == [argument]
        assert targets[name]["end"] < report["first_mutation"]
    assert report["capture_function"] == "Get-ServiceRecords"
    assert report["capture_guard"] == {
        "operator": "Ieq",
        "variable": "target",
        "member": "service",
        "value": "canvas-sync-worker",
    }
    assert report["capture_assignment"] == {
        "variable": "record",
        "key": "rollback_launch",
    }
