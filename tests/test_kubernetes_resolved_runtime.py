"""Required test wiring only; these guards do not qualify Kubernetes execution."""

from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
NAMES = (
    "kubernetes_resolved_native_profile_delivers_both_encryption_modes",
    "kubernetes_profile_gateway_composition_isolated",
    "kubernetes_profile_gateway_composition_child",
)


def inputs():
    return (
        (
            ROOT / "rust/services/issuance/tests/canvas_published_schema_contract.rs"
        ).read_text(),
        (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(),
        yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")),
    )


def required(source, runner, workflow):
    for name in NAMES:
        assert re.findall(
            r"((?:#\[[^\n]+\]\s*)+)async fn " + name + r"\(\)\s*\{", source
        ) == ["#[tokio::test]\n"]
        assert runner.count(f"'{name}: test'") == 1
    assert '"${executables[0]}" --nocapture --test-threads=2' in runner
    for module in ("resolved_runtime", "resolved_kubernetes_runtime"):
        assert source.count(f'#[path = "support/{module}.rs"]\nmod {module};') == 1
    assert "base_runtime_container::run_kubernetes(&owned, &redis)" in source
    assert "renewal_fresh_main::run_kubernetes(" in source
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    prerequisites = [
        step
        for step in steps
        if step.get("name") == "Require Kubernetes deployment contract executables"
    ]
    assert len(prerequisites) == 1
    step = prerequisites[0]
    assert "if" not in step and not step.get("continue-on-error")
    assert step["run"].strip().splitlines() == [
        "set -euo pipefail",
        "command -v bash",
        "command -v envsubst",
    ]
    builds = [
        step
        for step in steps
        if step.get("name") == "Prepare required rendered base executable acceptance"
    ]
    assert (
        len(builds) == 1
        and "if" not in builds[0]
        and not builds[0].get("continue-on-error")
    )
    assert "test -x rust/target/debug/marty-gateway" in builds[0]["run"]
    assert "test -x rust/target/debug/marty-issuance-service" in builds[0]["run"]


def test_kubernetes_executable_gates_reuse_required_artifact_and_renderer_prerequisites():
    required(*inputs())


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize(
    "fault",
    ["missing", "ignored", "conditional", "duplicate", "unlisted", "disconnected"],
)
def test_missing_or_disconnected_kubernetes_gates_fail(name, fault):
    source, runner, workflow = inputs()
    if fault == "missing":
        source = source.replace(f"async fn {name}", "async fn removed")
    elif fault in {"ignored", "conditional"}:
        annotation = "#[ignore]" if fault == "ignored" else "#[cfg(any())]"
        source = source.replace(f"async fn {name}", f"{annotation}\nasync fn {name}")
    elif fault == "duplicate":
        source += f"\n#[tokio::test]\nasync fn {name}() {{}}"
    elif fault == "unlisted":
        runner = runner.replace(f"'{name}: test'", "'removed: test'")
    else:
        runner = runner.replace(
            '"${executables[0]}" --nocapture --test-threads=2', "echo disconnected"
        )
    with pytest.raises(AssertionError):
        required(source, runner, workflow)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-envsubst",
        "optional-envsubst",
        "missing-gateway",
        "disconnected-resolver",
    ],
)
def test_missing_runtime_dependencies_fail(fault):
    source, runner, workflow = inputs()
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    if fault in {"missing-envsubst", "optional-envsubst"}:
        step = next(
            v
            for v in steps
            if v.get("name") == "Require Kubernetes deployment contract executables"
        )
        if fault == "missing-envsubst":
            step["run"] = step["run"].replace("command -v envsubst", "true")
        else:
            step["continue-on-error"] = True
    elif fault == "missing-gateway":
        step = next(
            v
            for v in steps
            if v.get("name") == "Prepare required rendered base executable acceptance"
        )
        step["run"] = step["run"].replace(
            "test -x rust/target/debug/marty-gateway", "true"
        )
    else:
        source = source.replace("mod resolved_kubernetes_runtime;", "mod disconnected;")
    with pytest.raises(AssertionError):
        required(source, runner, workflow)


@pytest.mark.parametrize("fault", [None, "missing", "ignored", "unlisted"])
def test_prepared_model_cleanup_control_is_required(fault):
    name = (
        "prepared_cleanup_retains_modified_bytes_until_exact_owned_content_is_restored"
    )
    source = (
        ROOT / "rust/services/issuance/tests/support/resolved_kubernetes_runtime.rs"
    ).read_text()
    runner = inputs()[1]

    def check(source, runner):
        assert re.findall(
            r"((?:#\[[^\n]+\]\s*)+)fn " + name + r"\(\)\s*\{", source
        ) == ["#[test]\n"]
        assert runner.count(f"'resolved_kubernetes_runtime::{name}: test'") == 1

    check(source, runner)
    if fault == "missing":
        source = source.replace(f"fn {name}", "fn removed")
    elif fault == "ignored":
        source = source.replace(f"fn {name}", f"#[ignore]\nfn {name}")
    elif fault == "unlisted":
        runner = runner.replace(
            f"'resolved_kubernetes_runtime::{name}: test'", "'removed: test'"
        )
    if fault:
        with pytest.raises(AssertionError):
            check(source, runner)
