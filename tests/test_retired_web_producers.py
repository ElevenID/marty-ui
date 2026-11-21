"""Current CLI producers fail before creating a misleading legacy release plan."""

from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script", ["ui_release.py", "website_release.py"])
@pytest.mark.parametrize("command", ["plan", "record"])
def test_current_source_refuses_retired_production_commands(tmp_path, script, command):
    output = tmp_path / "release.json"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), command,
         "--source-sha", "a" * 40, "--output", str(output)],
        text=True, capture_output=True, check=False,
    )
    assert result.returncode != 0
    assert "producer is retired in this source" in result.stderr
    assert "ElevenID/website" in result.stderr
    assert not output.exists()


def test_historical_target_is_explicit_and_cannot_be_replaced_by_a_comment(tmp_path):
    sys.path.insert(0, str(ROOT / "scripts"))
    import ui_release

    dockerfile = tmp_path / "docker/ui.Dockerfile"
    dockerfile.parent.mkdir()
    dockerfile.write_text("FROM nginx AS application\n# FROM nginx AS public\n")
    with pytest.raises(ValueError, match="producer is retired"):
        ui_release.require_legacy_build_target(tmp_path, "public")
    dockerfile.write_text("FROM nginx AS public\nFROM nginx AS website\n")
    ui_release.require_legacy_build_target(tmp_path, "public")
    ui_release.require_legacy_build_target(tmp_path, "website")


def test_manual_builders_select_application_without_using_a_retired_target():
    shell = (ROOT / "scripts/build-push-registry.sh").read_text()
    powershell = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text()
    assert "--target application --build-arg UI_SURFACE=application" in shell
    assert '"--target", "application"' in powershell
    assert '"UI_SURFACE=application"' in powershell


def test_beta_catalog_preserves_exact_product_source_before_mutation():
    script = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text()
    check = '(Join-Path $PSScriptRoot "operator_demo_catalog.py")'
    assert script.count(check) == 2
    assert script.index(check) < script.index('Write-Step "Stage durable source-pinned beta runtime configuration"')
    assert script.index(check) < script.index('Write-Step "Enter maintenance window and apply live migration"')
    assert '"--template", $operatorDemoSelection.template_path' in script
    assert "[string]$sourceManifest.repositories.'marty-ui'.head_sha" in script
    assert "[string]$sourceManifest.repositories.'marty-ui'.revision" in script
    assert '"--product-revision", $operatorDemoProductRevision' in script
    assert '"--product-root", $script:RepoRoot' in script
    assert "$currentOperatorDemoSelection.template_sha256 -cne $operatorDemoSelection.template_sha256" in script
    assert '"ui\\public\\demos\\manifests\\${stackVersion}.json"' not in script
