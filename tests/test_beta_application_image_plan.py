"""Pure image-plan and full-model guards; no deployment or image operations."""

from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/test_beta_application_image_compose.py"


@pytest.fixture
def gate():
    return runpy.run_path(str(GATE))


def synthetic_base():
    common = {
        "image": "synthetic.invalid/before@sha256:" + "e" * 64,
        "entrypoint": None,
        "command": [],
        "environment": {
            "OTHER": "synthetic-private-value",
            "DATABASE_URL_TEMPLATE": "synthetic-db-template",
            "TOKEN_HMAC_KEY_FILE": "/run/secrets/synthetic-key",
        },
        "secrets": ["synthetic-key"],
        "depends_on": {
            "issuance-migrations": {"condition": "service_completed_successfully"}
        },
        "healthcheck": {"disable": True},
        "restart": "unless-stopped",
        "future_field": {"preserved": True},
        "build": {"context": ".", "args": {"SERVICE_NAME": "unchanged"}},
    }
    services = {
        name: deepcopy(common)
        for name in (
            "issuance",
            "canvas-sync-worker",
            "verification",
            "signing-keys",
            "issuance-migrations",
        )
    }
    services["canvas-sync-worker"]["command"] = [
        "/usr/local/bin/marty-canvas-sync-worker",
    ]
    return {
        "services": services,
        "secrets": {"synthetic-key": {"file": "synthetic-file"}},
    }


@pytest.mark.parametrize("mode", ["local", "official"])
def test_expected_projection_preserves_all_nonselection_fields(gate, mode):
    base = synthetic_base()
    names = [name for name in base["services"] if name != "issuance-migrations"]
    actual = gate["expected_model"](base, names, mode)
    assert base == synthetic_base()
    assert (
        actual["services"]["issuance-migrations"]
        == base["services"]["issuance-migrations"]
    )
    for name in names:
        original = deepcopy(base["services"][name])
        projected = deepcopy(actual["services"][name])
        del original["image"], projected["image"]
        if mode == "official" and name not in gate["EXTERNAL"]:
            assert projected["environment"].pop("SERVICE_NAME") == name.replace(
                "-", "_"
            )
        assert projected == original


@pytest.mark.parametrize(
    "field",
    [
        "command",
        "entrypoint",
        "environment",
        "secrets",
        "depends_on",
        "healthcheck",
        "restart",
        "future_field",
        "build",
        "image",
    ],
)
def test_complete_model_comparison_rejects_worker_field_loss_without_private_output(
    gate, field
):
    expected = synthetic_base()
    actual = deepcopy(expected)
    del actual["services"]["canvas-sync-worker"][field]
    with pytest.raises(AssertionError) as error:
        gate["assert_model"](actual, expected)
    assert (
        str(error.value) == "Generated beta overlay changed the complete runtime model"
    )
    assert "synthetic-private-value" not in str(error.value)


def test_comparison_rejects_swapped_selector_and_pinned_overlay_order(gate):
    base = synthetic_base()
    names = [name for name in base["services"] if name != "issuance-migrations"]
    official = gate["expected_model"](base, names, "official")
    wrong = deepcopy(official)
    wrong["services"]["signing-keys"]["environment"]["SERVICE_NAME"] = "verification"
    with pytest.raises(AssertionError):
        gate["assert_model"](wrong, official)
    pinned = gate["expected_model"](base, names, "local", pinned=True)
    unpinned = gate["expected_model"](base, names, "local")
    with pytest.raises(AssertionError):
        gate["assert_model"](unpinned, pinned)


def test_environment_list_mapping_equivalence_preserves_absent_null_and_duplicates(
    gate,
):
    expected = synthetic_base()
    expected["services"]["canvas-sync-worker"]["environment"] = {
        "SELECTOR": None,
        "OTHER": "",
    }
    actual = deepcopy(expected)
    actual["services"]["canvas-sync-worker"]["environment"] = ["SELECTOR", "OTHER="]
    gate["assert_model"](actual, expected)
    actual["services"]["canvas-sync-worker"]["environment"] = ["OTHER="]
    with pytest.raises(AssertionError):
        gate["assert_model"](actual, expected)
    actual["services"]["canvas-sync-worker"]["environment"] = [
        "SELECTOR",
        "SELECTOR=",
        "OTHER=",
    ]
    with pytest.raises(AssertionError):
        gate["assert_model"](actual, expected)


def test_ci_requires_executable_powershell():
    assert not os.environ.get("CI") or (
        os.environ.get("POWERSHELL_TEST_EXE")
        or shutil.which("pwsh")
        or shutil.which("powershell")
    ), "CI must run executable PowerShell image-plan controls"


@pytest.fixture
def exercise(gate, tmp_path):
    if not (
        os.environ.get("POWERSHELL_TEST_EXE")
        or shutil.which("pwsh")
        or shutil.which("powershell")
    ):
        pytest.skip("PowerShell is required for executable image-plan contracts")
    return lambda cases: gate["exercise"](tmp_path, cases)


@pytest.mark.parametrize("mode", ["local", "official"])
def test_actual_plan_covers_inventory_builds_selectors_and_evidence(
    gate, exercise, mode
):
    [report] = exercise([gate["inputs"](mode)])
    assert report["caught"] is False, report
    gate["assert_report"](report, mode)
    names = report["services"]
    assert len(names) == len(set(names)) == 19
    assert {item["service"] for item in report["plan"]} == set(names)
    native = set(names) - gate["EXTERNAL"]
    assert len(native) == 18
    assert gate["EXTERNAL"] == {"issuance"}
    assert "canvas-sync-worker" in native
    assert set(report["build_services"]) == (native if mode == "local" else set())
    for item in report["plan"]:
        external = item["service"] in gate["EXTERNAL"]
        if external:
            assert item["image_expression"] == "${MARTY_ISSUANCE_IMAGE}"
            assert item["effective_reference"] == gate["ISSUANCE_IMAGE"]
            assert item["artifact_role"] == "issuance"
        elif mode == "official":
            assert item["image_expression"] == "${MARTY_SERVICES_IMAGE}"
            assert item["effective_reference"] == gate["SERVICES_IMAGE"]
            assert item["artifact_role"] == "services"
        else:
            assert (
                item["effective_reference"]
                == f"elevenid-local/{item['service']}:{gate['RELEASE']}"
            )
            assert item["image_expression"] == item["effective_reference"]
            assert item["artifact_role"] == "local"
        has_selector = mode == "official" and not external
        assert item["selector_present"] is has_selector
        assert item["selector"] == (
            item["service"].replace("-", "_") if has_selector else None
        )
        assert item["build_eligible"] is (mode == "local" and not external)
        assert item["known_digest"] == (
            gate["ISSUANCE_DIGEST"]
            if external and mode == "official"
            else gate["SERVICES_DIGEST"]
            if mode == "official"
            else None
        )
    assert set(report["digests"]) == set(names)
    if mode == "official":
        assert report["inspected"] == []
        assert report["pin_lines"] == []
    else:
        assert report["digests"]["verification"] == gate["VERIFICATION_DIGEST"]
        assert gate["RETAGGED_VERIFICATION_DIGEST"] not in report["digests"].values()
        assert (
            f"elevenid-local/verification:{gate['RELEASE']}" not in report["inspected"]
        )
        assert len(report["inspected"]) == 18
        originals = {item["service"]: item for item in report["plan"]}
        finals = {item["service"]: item for item in report["final_plan"]}
        for name in names:
            if name != "verification":
                assert originals[name] == finals[name]
        assert originals["verification"]["known_digest"] is None
        assert finals["verification"]["known_digest"] == gate["VERIFICATION_DIGEST"]
        assert (
            finals["verification"]["effective_reference"] == gate["VERIFICATION_DIGEST"]
        )


def test_independent_projection_rejects_retagged_evidence_and_missing_build(
    gate, exercise
):
    [report] = exercise([gate["inputs"]("local")])
    gate["assert_report"](report, "local")
    retagged = deepcopy(report)
    retagged["digests"]["verification"] = gate["RETAGGED_VERIFICATION_DIGEST"]
    with pytest.raises(AssertionError):
        gate["assert_report"](retagged, "local")
    missing = deepcopy(report)
    missing["build_services"].remove("signing-keys")
    with pytest.raises(AssertionError):
        gate["assert_report"](missing, "local")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("release", "release\nsynthetic-private-value"),
        ("release", "release:synthetic-private-value"),
        ("issuance_reference", "synthetic.invalid/issuance:latest"),
        ("issuance_reference", "synthetic.invalid/issuance@sha256:" + "f" * 64),
        ("issuance_digest", "sha256:" + "f" * 64),
        ("services_reference", "synthetic.invalid/services:latest"),
        ("services_digest", "sha256:" + "f" * 64),
        (
            "services",
            ["issuance", "canvas-sync-worker", "verification", "verification"],
        ),
        (
            "services",
            ["issuance", "canvas-sync-worker", "synthetic-private-value\nservice"],
        ),
        ("services", []),
    ],
)
def test_independent_gate_rejects_incorrect_selection_projection(
    gate, exercise, field, value
):
    mode = "local" if field == "release" else "official"
    case = gate["inputs"](mode)
    case[field] = value
    [report] = exercise([case])
    # The extracted helper deliberately projects already-validated runner
    # inputs. This gate, not a new production input-domain restriction, rejects
    # a projection that disagrees with our independent declared test inputs.
    with pytest.raises(AssertionError) as error:
        gate["assert_report"](report, mode)
    assert "synthetic-private-value" not in str(error.value)


def test_verification_pin_rejects_mutable_or_malformed_image(gate, exercise):
    cases = []
    for value in (
        "synthetic.invalid/verification:latest",
        "sha256:bad",
        "sha256:" + "c" * 64 + "\nsynthetic-private-value",
    ):
        case = gate["inputs"]("local")
        case["verification_digest"] = value
        cases.append(case)
    for report in exercise(cases):
        assert report["caught"] is True
        assert "synthetic-private-value" not in report["message"]


def test_runner_ast_consumes_real_plan_for_overlay_build_pin_and_evidence(tmp_path):
    powershell = (
        os.environ.get("POWERSHELL_TEST_EXE")
        or shutil.which("pwsh")
        or shutil.which("powershell")
    )
    if not powershell:
        pytest.skip("PowerShell is required for actual runner AST checks")
    harness = tmp_path / "inspect-image-plan.ps1"
    harness.write_text(
        r"""
param([string]$Runner)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Runner,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Runner syntax error' }
function Outside-Function($Node) {
    for ($parent=$Node.Parent; $null -ne $parent; $parent=$parent.Parent) {
        if ($parent -is [Management.Automation.Language.FunctionDefinitionAst]) { return $false }
    }
    return $true
}
$commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true) | Where-Object { Outside-Function $_ } | ForEach-Object {
    $assignment=$null
    for ($parent=$_.Parent; $null -ne $parent; $parent=$parent.Parent) {
        if ($parent -is [Management.Automation.Language.AssignmentStatementAst]) {
            $assignment=$parent.Left.Extent.Text; break
        }
    }
    @{name=$_.GetCommandName(); text=$_.Extent.Text; offset=$_.Extent.StartOffset; assignment=$assignment}
})
$assignments=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst]},$true) | Where-Object { Outside-Function $_ } | ForEach-Object {
    @{left=$_.Left.Extent.Text; right=$_.Right.Extent.Text; operator=[string]$_.Operator; offset=$_.Extent.StartOffset}
})
$pipelines=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.PipelineAst]},$true) | Where-Object { Outside-Function $_ } | ForEach-Object {$_.Extent.Text})
$loops=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.ForEachStatementAst]},$true) | Where-Object { Outside-Function $_ } | ForEach-Object {
    @{condition=$_.Condition.Extent.Text; body=$_.Body.Extent.Text; offset=$_.Extent.StartOffset}
})
@{commands=$commands; assignments=$assignments; pipelines=$pipelines; loops=$loops} | ConvertTo-Json -Depth 12 -Compress
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-File",
            str(harness),
            "-Runner",
            str(ROOT / "scripts/deploy-local-beta-release.ps1"),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    commands = report["commands"]

    def one(name):
        matches = [item for item in commands if item["name"] == name]
        assert len(matches) == 1, name
        return matches[0]

    new = one("New-BetaApplicationImagePlan")
    pin = one("Set-BetaApplicationVerificationImage")
    evidence = one("Get-BetaApplicationImageEvidence")
    assert new["assignment"] == pin["assignment"] == "$applicationImagePlan"
    assert new["text"] == "New-BetaApplicationImagePlan @applicationImageArguments"
    assert (
        pin["text"]
        == "Set-BetaApplicationVerificationImage -Plan $applicationImagePlan -ImageId $verificationMigrationImage"
    )
    assert (
        evidence["text"]
        == "Get-BetaApplicationImageEvidence -Plan $applicationImagePlan"
    )
    renders = [
        item
        for item in commands
        if item["name"] == "ConvertTo-BetaApplicationImageLines"
    ]
    assert len(renders) == 2
    render = next(item for item in renders if item["assignment"] == "$releaseCompose")
    pin_render = next(
        item for item in renders if item["assignment"] == "$verificationImageLines"
    )
    assert (
        render["text"]
        == "ConvertTo-BetaApplicationImageLines -Plan $applicationImagePlan"
    )
    assert (
        '$applicationImagePlan | Where-Object { $_.service -eq "verification" }'
        in pin_render["text"]
    )
    assert (
        '$releaseCompose -join "`n" | Set-Content -LiteralPath $releaseComposeFile -Encoding utf8'
        in report["pipelines"]
    )
    pin_write = next(
        item
        for item in commands
        if item["name"] == "Write-Utf8Text"
        and "-Path $verificationImageOverride " in item["text"]
    )
    assert '-Content (($verificationImageLines -join "`n") + "`n")' in pin_write["text"]
    attached = {
        item["right"]: item
        for item in report["assignments"]
        if item["left"] == "$script:ComposeFiles" and item["operator"] == "PlusEquals"
    }
    profile_append = "(Join-Path $script:RepoRoot $profile)"
    assert set(attached) == {
        "$releaseComposeFile",
        "$verificationImageOverride",
        profile_append,
    }
    profile_loops = [
        item for item in report["loops"] if item["condition"] == "$didcommProfiles"
    ]
    assert len(profile_loops) == 1
    assert "$script:ComposeFiles += " + profile_append in profile_loops[0]["body"]
    assert attached[profile_append]["offset"] < new["offset"]
    rehearsal = next(
        item
        for item in commands
        if item["name"] == "Write-Step"
        and item["text"]
        == 'Write-Step "Rehearse one-way migration on isolated beta copy"'
    )
    maintenance = next(
        item
        for item in commands
        if item["name"] == "Write-Step"
        and item["text"]
        == 'Write-Step "Enter maintenance window and apply live migration"'
    )
    assert (
        new["offset"]
        < render["offset"]
        < attached["$releaseComposeFile"]["offset"]
        < pin["offset"]
        < pin_render["offset"]
        < pin_write["offset"]
        < attached["$verificationImageOverride"]["offset"]
        < rehearsal["offset"]
        < evidence["offset"]
        < maintenance["offset"]
    )
    builds = [
        loop for loop in report["loops"] if "$_.build_eligible" in loop["condition"]
    ]
    assert len(builds) == 1
    assert (
        builds[0]["condition"]
        == "@($applicationImagePlan | Where-Object { $_.build_eligible })"
    )
    assert "$service = [string]$entry.service" in builds[0]["body"]
    assert (
        "Invoke-Compose -Arguments ($applicationBuildArguments + @($service))"
        in builds[0]["body"]
    )
    assert builds[0]["offset"] < pin["offset"]
    evidence_loops = [
        loop
        for loop in report["loops"]
        if "Get-BetaApplicationImageEvidence" in loop["condition"]
    ]
    assert len(evidence_loops) == 1
    assert (
        "$runtimeImageDigests[$service] = [string]$imageEvidence.digest"
        in evidence_loops[0]["body"]
    )
    assert (
        "$imageRef = [string]$imageEvidence.inspect_reference"
        in evidence_loops[0]["body"]
    )
    assert "if ($null -ne $imageEvidence.digest)" in evidence_loops[0]["body"]
