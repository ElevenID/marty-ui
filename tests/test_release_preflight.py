from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_preflight", ROOT / "scripts/ci/check_release_preflight.py")
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)
from product_package_plan import SERVER_RUNTIME_FILES

SOURCE = "a" * 40


@pytest.fixture
def source(tmp_path: Path) -> Path:
    files = {
        "release/stack-lock.json", "release/product-packages.json", "release/server-version.txt",
        "release/console-version.txt", "ui/package.json", "ui/package-lock.json",
        "docker/ui.Dockerfile", "services/Dockerfile", "services/Dockerfile.migrations",
        "openbao/didcomm-authcrypt/Dockerfile", "keycloak/openbao-provider/Dockerfile",
        *SERVER_RUNTIME_FILES,
    }
    for name in files:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    cargo = tmp_path / "rust/Cargo.toml"
    cargo.parent.mkdir(exist_ok=True)
    cargo.write_text('[workspace]\nmembers=[]\n', encoding="utf-8")
    return tmp_path


def edit_json(root: Path, name: str, transform) -> None:
    path = root / name
    document = json.loads(path.read_bytes())
    transform(document)
    path.write_text(json.dumps(document))


def test_current_source_preflight_resolves_independent_product_versions() -> None:
    result = preflight.check(ROOT, SOURCE)
    lock = json.loads((ROOT / "release/stack-lock.json").read_bytes())
    assert result["stack_version"] == lock["release"].removeprefix("marty-ui@")
    assert result["claim_eligible"] is True
    assert result["product_tags"] == {
        "marty-server": "server-v" + (ROOT / "release/server-version.txt").read_text().strip(),
        "marty-console": "console-v" + (ROOT / "release/console-version.txt").read_text().strip(),
    }


def test_development_hold_is_valid_ci_input_but_never_claim_eligible(source: Path) -> None:
    edit_json(source, "release/stack-lock.json", lambda d: d.update(release_state="hold"))
    result = preflight.check(source, SOURCE)
    assert result["claim_eligible"] is False
    with pytest.raises(ValueError, match="eligible"):
        preflight.check(source, SOURCE, require_eligible=True)


@pytest.mark.parametrize("state", [None, False, "Eligible", "", "held"])
def test_invalid_eligibility_metadata_fails_early(source: Path, state) -> None:
    edit_json(source, "release/stack-lock.json", lambda d: d.update(release_state=state))
    with pytest.raises(ValueError, match="release_state"):
        preflight.check(source, SOURCE)


def test_ui_version_mismatch_fails_without_installing_dependencies(source: Path) -> None:
    edit_json(source, "ui/package-lock.json", lambda d: d["packages"][""].update(version="9.0.0"))
    with pytest.raises(ValueError, match="versions differ"):
        preflight.check(source, SOURCE)


def test_dependency_coordinate_mismatch_fails_without_building(source: Path) -> None:
    edit_json(source, "ui/package.json", lambda d: d["dependencies"].update({"@elevenid/marty-blog": "latest"}))
    with pytest.raises(ValueError, match="dependency differs"):
        preflight.check(source, SOURCE)


def test_product_catalog_is_validated_before_expensive_jobs(source: Path) -> None:
    edit_json(source, "release/product-packages.json", lambda d: d["products"]["marty-console"].update(tag_prefix="server-v"))
    with pytest.raises(ValueError, match="namespace"):
        preflight.check(source, SOURCE)


def test_stack_version_must_remain_a_stable_coordinate(source: Path) -> None:
    edit_json(source, "release/stack-lock.json", lambda d: d.update(release="marty-ui@01.2.3"))
    with pytest.raises(ValueError, match="stable tag"):
        preflight.check(source, SOURCE)


def test_source_sha_cannot_be_missing_or_a_branch_name() -> None:
    for source in ("", "main", "A" * 40, "a" * 39):
        with pytest.raises(ValueError, match="source SHA"):
            preflight.check(ROOT, source)


def test_selected_ci_jobs_wait_for_source_preflight_and_gate_requires_it() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    jobs = workflow["jobs"]
    for name, job in jobs.items():
        if "needs.changes.outputs" in job.get("if", ""):
            assert "release-preflight" in job["needs"], name
    assert "release-preflight" in jobs["ci-gate"]["needs"]
    preflight_job = jobs["release-preflight"]
    assert not preflight_job.get("continue-on-error", False)
    assert not preflight_job.get("if")
    script = preflight_job["steps"][-1]["run"]
    assert "scripts/ci/check_release_preflight.py" in script
    assert "--require-eligible" not in script


@pytest.mark.parametrize("workflow_name", ["prepare-nightly-claim.yml", "prepare-stack-tag.yml"])
def test_claim_entry_points_require_eligibility_before_external_work(workflow_name: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text())
    steps = next(job["steps"] for job in workflow["jobs"].values() if "steps" in job)
    index = next(i for i, step in enumerate(steps) if "check_release_preflight.py" in step.get("run", ""))
    assert "--require-eligible" in steps[index]["run"]
    assert not steps[index].get("continue-on-error", False)
    assert all("gh api" not in step.get("run", "") for step in steps[:index])


def test_inherited_dependency_refuses_before_release_inputs_or_build_setup(tmp_path):
    cargo = tmp_path / "rust/Cargo.toml"
    cargo.parent.mkdir()
    cargo.write_text('[workspace]\n[package]\nname="fixture"\nversion="0.1.0"\n[dependencies]\nmarty-oid4vp-contract.workspace=true\n', encoding="utf-8")
    # No lock, release inputs, dependency cache or Cargo executable is needed to
    # diagnose this exact candidate's dangling workspace inheritance.
    with pytest.raises(ValueError, match="Missing workspace dependency marty-oid4vp-contract"):
        preflight.check(tmp_path, SOURCE)


def test_valid_inherited_dependency_retains_next_release_input_gate(tmp_path):
    cargo = tmp_path / "rust/Cargo.toml"
    cargo.parent.mkdir()
    cargo.write_text('[workspace]\n[workspace.dependencies]\nalias="1"\n[package]\nname="fixture"\nversion="0.1.0"\n[dependencies]\nalias.workspace=true\n', encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="stack-lock.json"):
        preflight.check(tmp_path, SOURCE)
