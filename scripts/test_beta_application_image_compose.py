"""Exercise generated beta image plans and read-only effective Compose models.

Only pure PowerShell definitions and owned synthetic inputs are executed. The
deployment runner is parsed, never invoked. No images are pulled or started.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/deploy-local-beta-release.ps1"
HELPER = ROOT / "scripts/beta-application-image-plan.ps1"
RELEASE = "2026.09.99"
ISSUANCE_DIGEST = "sha256:" + "a" * 64
SERVICES_DIGEST = "sha256:" + "b" * 64
VERIFICATION_DIGEST = "sha256:" + "c" * 64
RETAGGED_VERIFICATION_DIGEST = "sha256:" + "d" * 64
ISSUANCE_IMAGE = "synthetic.invalid/issuance@" + ISSUANCE_DIGEST
SERVICES_IMAGE = "synthetic.invalid/services@" + SERVICES_DIGEST
EXTERNAL = frozenset({"issuance", "canvas-sync-worker"})

HARNESS = r"""
param([string]$Source, [string]$Runner, [string]$InputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Read-Ast([string]$Path) {
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0) { throw 'Image plan source has syntax errors' }
    return $ast
}
$ast=Read-Ast $Source
$definitions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false))
if ($definitions.Count -eq 0) { throw 'Missing image plan definitions' }
foreach ($definition in $definitions) { Invoke-Expression $definition.Extent.Text }
$runnerAst=Read-Ast $Runner
$assignments=@($runnerAst.FindAll({param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left -is [Management.Automation.Language.VariableExpressionAst] -and
    $n.Left.VariablePath.UserPath -ceq 'script:ApplicationServices'
},$true))
if ($assignments.Count -ne 1) { throw 'Ambiguous application service inventory' }
$literal=$assignments[0].Right.Extent.Text
if ($literal -cnotmatch '^@\(\s*"[a-z][a-z0-9-]*"(?:\s*,\s*"[a-z][a-z0-9-]*")*\s*\)$') {
    throw 'Application service inventory must remain a closed literal array'
}
$services=@([regex]::Matches($literal,'"([a-z][a-z0-9-]*)"') | ForEach-Object {$_.Groups[1].Value})
if (@($services | Sort-Object -Unique).Count -ne $services.Count) { throw 'Duplicate application service' }
function docker { throw 'Docker is forbidden in pure image-plan harness' }
function Invoke-Checked { throw 'Runner invocation is forbidden in pure image-plan harness' }
$cases=ConvertFrom-Json -InputObject (Get-Content -LiteralPath $InputPath -Raw)
$reports=@()
foreach ($case in $cases) {
    try {
        $selectedServices=if ($case.PSObject.Properties.Name -contains 'services') {@($case.services)} else {$services}
        $plan=@(New-BetaApplicationImagePlan -Services $selectedServices -ReleaseVersion $case.release `
            -OfficialStackRelease $case.official -IssuanceReference $case.issuance_reference `
            -IssuanceDigest $case.issuance_digest -ServicesReference $case.services_reference `
            -ServicesDigest $case.services_digest)
        # The serializer and evidence owner consume a persisted plan, not an
        # accidental live PowerShell array/dictionary implementation detail.
        $plan=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject @($plan) -Depth 20 -Compress)
        $lines=@(ConvertTo-BetaApplicationImageLines -Plan $plan)
        $final=$plan
        $pinLines=@()
        if (-not $case.official) {
            $final=@(Set-BetaApplicationVerificationImage -Plan $plan -ImageId $case.verification_digest)
            $pinLines=@(ConvertTo-BetaApplicationImageLines -Plan @($final | Where-Object service -CEQ 'verification'))
        }
        $evidence=@(Get-BetaApplicationImageEvidence -Plan $final)
        $inspected=@()
        $digests=[ordered]@{}
        foreach ($entry in $evidence) {
            if ($null -ne $entry.inspect_reference) {
                $inspected+=@($entry.inspect_reference)
                # Simulate a tag move after rehearsal: querying the verification
                # tag now yields B. Correct pinned evidence never queries it.
                $digests[$entry.service]=if ($entry.service -ceq 'verification') {$case.retagged_verification_digest} else {$case.synthetic_inspect_digest}
            } else { $digests[$entry.service]=$entry.digest }
        }
        $reports+=@{caught=$false; services=@($services); plan=@($plan); final_plan=@($final);
            lines=@($lines); pin_lines=@($pinLines); evidence=@($evidence); inspected=@($inspected);
            digests=$digests; build_services=@($plan | Where-Object build_eligible | ForEach-Object service)}
    } catch {
        $reports+=@{caught=$true; message=$_.Exception.Message}
    }
}
ConvertTo-Json -InputObject @($reports) -Depth 30 -Compress
"""


def inputs(mode):
    if mode not in {"local", "official"}:
        raise AssertionError("Unsupported synthetic image-plan mode")
    return {
        "release": RELEASE,
        "official": mode == "official",
        "issuance_reference": ISSUANCE_IMAGE,
        "issuance_digest": ISSUANCE_DIGEST,
        "services_reference": SERVICES_IMAGE if mode == "official" else "",
        "services_digest": SERVICES_DIGEST if mode == "official" else "",
        "verification_digest": VERIFICATION_DIGEST,
        "retagged_verification_digest": RETAGGED_VERIFICATION_DIGEST,
        "synthetic_inspect_digest": "sha256:" + "e" * 64,
    }


def exercise(directory, cases, powershell=None):
    powershell = (
        powershell
        or os.environ.get("POWERSHELL_TEST_EXE")
        or shutil.which("pwsh")
        or shutil.which("powershell")
    )
    if not powershell:
        raise RuntimeError("PowerShell is required for generated image-plan tests")
    harness = directory / "image-plan.ps1"
    data = directory / "cases.json"
    harness.write_text(HARNESS, encoding="utf-8")
    data.write_text(json.dumps(cases), encoding="utf-8")
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-File",
            str(harness),
            "-Source",
            str(HELPER),
            "-Runner",
            str(RUNNER),
            "-InputPath",
            str(data),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=30,
    )
    reports = json.loads(result.stdout)
    if not isinstance(reports, list) or len(reports) != len(cases):
        raise AssertionError("Image-plan harness returned incomplete observations")
    return reports


def expected_model(base, names, mode, *, pinned=False, bound=False):
    """Independent contract projection; never use generated plan as expectation."""
    if mode not in {"local", "official"}:
        raise AssertionError("Unsupported synthetic image-plan mode")
    if not names or len(set(names)) != len(names) or not EXTERNAL.issubset(names):
        raise AssertionError("Incomplete synthetic application inventory")
    expected = deepcopy(base)
    for name in names:
        service = expected["services"][name]
        if name in EXTERNAL:
            service["image"] = ISSUANCE_IMAGE if bound else "${MARTY_ISSUANCE_IMAGE}"
        elif mode == "official":
            service["image"] = SERVICES_IMAGE if bound else "${MARTY_SERVICES_IMAGE}"
            owner = runpy.run_path(
                str(ROOT / "scripts/test_canvas_worker_compose_render.py")
            )
            environment = owner["environment_mapping"](service.get("environment", {}))
            environment["SERVICE_NAME"] = name.replace("-", "_")
            service["environment"] = environment
        else:
            service["image"] = f"elevenid-local/{name}:{RELEASE}"
    if pinned:
        if mode != "local":
            raise AssertionError("Unexpected official verification override")
        expected["services"]["verification"]["image"] = VERIFICATION_DIGEST
    return expected


def assert_model(actual, expected):
    owner = runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))
    normalized = []
    for model in (actual, expected):
        model = deepcopy(model)
        for service in model.get("services", {}).values():
            if "environment" in service:
                service["environment"] = owner["environment_mapping"](
                    service["environment"]
                )
        normalized.append(model)
    if normalized[0] != normalized[1]:
        # Never print interpolated models or their environment values.
        raise AssertionError(
            "Generated beta overlay changed the complete runtime model"
        )


def assert_report(report, mode):
    """Validate observed projections independently of the pure trusted-input helper."""
    if mode not in {"local", "official"}:
        raise AssertionError("Unsupported synthetic image-plan mode")
    if report.get("caught"):
        raise AssertionError("Pure beta image-plan generation failed")
    names = report["services"]
    if len(names) != 19 or len(set(names)) != 19 or not EXTERNAL.issubset(names):
        raise AssertionError("Review changed application image inventory")
    expected = []
    for name in names:
        external = name in EXTERNAL
        selector_present = mode == "official" and not external
        image = (
            "${MARTY_ISSUANCE_IMAGE}"
            if external
            else (
                "${MARTY_SERVICES_IMAGE}"
                if mode == "official"
                else f"elevenid-local/{name}:{RELEASE}"
            )
        )
        expected.append(
            {
                "service": name,
                "image_expression": image,
                "effective_reference": ISSUANCE_IMAGE
                if external
                else SERVICES_IMAGE
                if mode == "official"
                else image,
                "artifact_role": "issuance"
                if external
                else "services"
                if mode == "official"
                else "local",
                "selector_present": selector_present,
                "selector": name.replace("-", "_") if selector_present else None,
                "build_eligible": mode == "local" and not external,
                "known_digest": (ISSUANCE_DIGEST if external else SERVICES_DIGEST)
                if mode == "official"
                else None,
            }
        )
    if report["plan"] != expected:
        raise AssertionError(
            "Generated image plan differs from declared artifact selection"
        )
    final = deepcopy(expected)
    if mode == "local":
        for item in final:
            if item["service"] == "verification":
                item.update(
                    image_expression=VERIFICATION_DIGEST,
                    effective_reference=VERIFICATION_DIGEST,
                    known_digest=VERIFICATION_DIGEST,
                )
    if report["final_plan"] != final:
        raise AssertionError(
            "Generated verification pin changed unrelated artifact selection"
        )
    evidence = [
        {
            "service": item["service"],
            "digest": item["known_digest"],
            "inspect_reference": item["effective_reference"]
            if item["known_digest"] is None
            else None,
        }
        for item in final
    ]
    if report["evidence"] != evidence:
        raise AssertionError("Image evidence differs from effective artifact selection")
    builds = [item["service"] for item in expected if item["build_eligible"]]
    inspected = [
        item["inspect_reference"]
        for item in evidence
        if item["inspect_reference"] is not None
    ]
    digests = {
        item["service"]: item["digest"] or "sha256:" + "e" * 64 for item in evidence
    }
    if (
        report["build_services"] != builds
        or report["inspected"] != inspected
        or report["digests"] != digests
    ):
        raise AssertionError(
            "Build or provenance projection differs from effective artifact selection"
        )


def render_binding(directory, compose_command, *files):
    # This model contains only synthetic images and selectors. Unlike the actual
    # tracked-source renderer it intentionally tests two-variable interpolation.
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "PATHEXT",
            "COMSPEC",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMFILES",
            "PROGRAMDATA",
            "HOME",
            "HOMEDRIVE",
            "HOMEPATH",
        }
    }
    result = subprocess.run(
        [
            *compose_command,
            "--project-name",
            "synthetic-beta-image-binding",
            "--env-file",
            "images.env",
            *(argument for file in files for argument in ("-f", str(file))),
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


def run(compose_command=None, powershell=None):
    compose_command = compose_command or ["docker", "compose"]
    owner = runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))
    files = owner["beta_release_source_files"]()
    base = owner["render"](*files, compose_command=compose_command)
    checked = 0
    with tempfile.TemporaryDirectory(
        prefix="beta-application-image-plan-"
    ) as temporary:
        directory = Path(temporary)
        reports = exercise(directory, [inputs("local"), inputs("official")], powershell)
        for mode, report in zip(("local", "official"), reports, strict=True):
            assert_report(report, mode)
            names = report["services"]
            if (
                len(names) != 19
                or len(set(names)) != 19
                or len(set(names) - EXTERNAL) != 17
            ):
                raise AssertionError("Review changed application image inventory")
            overlay = directory / f"{mode}-images.yml"
            overlay.write_text("\n".join(report["lines"]) + "\n", encoding="utf-8")
            layers = [*files, str(overlay)]
            model = owner["render"](*layers, compose_command=compose_command)
            assert_model(model, expected_model(base, names, mode))
            checked += 1
            if mode == "local":
                pin = directory / "verification-pin.yml"
                pin.write_text("\n".join(report["pin_lines"]) + "\n", encoding="utf-8")
                layers.append(str(pin))
                model = owner["render"](*layers, compose_command=compose_command)
                assert_model(model, expected_model(base, names, mode, pinned=True))
                checked += 1

            # Bind only two synthetic image variables. Actual tracked secret
            # expressions above are never interpolated or environment-resolved.
            (directory / "images.env").write_text(
                f"MARTY_ISSUANCE_IMAGE={ISSUANCE_IMAGE}\nMARTY_SERVICES_IMAGE={SERVICES_IMAGE}\n",
                encoding="utf-8",
            )
            synthetic = {
                "services": {
                    name: {
                        "image": ISSUANCE_IMAGE,
                        "command": ["synthetic-never-run"],
                        "environment": {"UNCHANGED": "preserve"},
                    }
                    for name in names
                }
            }
            synthetic_path = directory / "synthetic.json"
            synthetic_path.write_text(json.dumps(synthetic), encoding="utf-8")
            synthetic_base = render_binding(directory, compose_command, synthetic_path)
            bound_layers = [synthetic_path, overlay]
            if mode == "local":
                bound_layers.append(pin)
            bound = render_binding(directory, compose_command, *bound_layers)
            assert_model(
                bound,
                expected_model(
                    synthetic_base, names, mode, pinned=mode == "local", bound=True
                ),
            )
            checked += 1
    if checked != 5:
        raise AssertionError("Incomplete generated beta image merge matrix")
    print(
        "Generated beta image gate: 3 tracked-source full-model merges and 2 synthetic image-binding merges; 19 application services per model; config only"
    )
    return checked


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    parser.add_argument("--powershell-executable")
    args = parser.parse_args()
    run(args.compose_command, args.powershell_executable)
