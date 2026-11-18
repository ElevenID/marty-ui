"""The real generated-image config gate stays mandatory before image builds."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_generated_application_image_gate_is_mandatory_and_additive():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["test-rust-service-images"]
    assert job["needs"] == ["changes", "release-preflight"]
    assert job["if"] == "needs.changes.outputs.rust_runtime == 'true'"
    assert job["runs-on"] == "ubuntu-latest"
    assert not job.get("continue-on-error", False)
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    name = "Verify generated beta application image configuration"
    assert names.count(name) == 1
    index = names.index(name)
    gate = steps[index]
    assert gate == {
        "name": name,
        "run": (
            "python3 scripts/test_beta_application_image_compose.py "
            '--compose-command "$RUNNER_TEMP/compose-render-v5.4.0"'
        ),
    }
    existing = {
        "Verify self-host native owner preservation": (
            "python3 scripts/test_selfhost_native_owner_compose.py"
        ),
    }
    for retained, command in existing.items():
        assert names.count(retained) == 1
        retained_index = names.index(retained)
        assert retained_index < index
        assert steps[retained_index] == {"name": retained, "run": command}
    consumer = names.index("Install pinned Compose renderer for configuration checks")
    assert consumer < index
    assert steps[consumer]["run"] == "bash scripts/ci/install-compose-renderer.sh"
    assert (
        "sha256sum --check --strict"
        in (ROOT / "scripts/ci/install-compose-renderer.sh").read_text()
    )
    assert "if" not in steps[consumer]
    assert not steps[consumer].get("continue-on-error", False)
    builds = [
        number
        for number, step in enumerate(steps)
        if step.get("uses", "").startswith("docker/build-push-action@")
    ]
    assert builds and index < min(builds)
