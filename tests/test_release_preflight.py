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


CORE_REVISION = "1" * 40
OTHER_CORE_REVISION = "2" * 40
PRIVATE_REVISION = "3" * 40
CORE_REPOSITORY = "https://github.com/ElevenID/marty-core"
CORE_PROBE = ".github/feature-regression/rust-probe"
CORE_POLICY = "scripts/ci/check_marty_core_kms_boundary.py"


def _write_core_source(root: Path, name: str, content: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def core_source(tmp_path: Path) -> Path:
    core = f'git="{CORE_REPOSITORY}",rev="{CORE_REVISION}"'
    patch = (
        '[patch.crates-io]\n'
        f'curve={{package="elliptic-curve",git="{CORE_REPOSITORY}.git",rev="{CORE_REVISION}"}}\n'
        f'ssi={{git="https://github.com/ElevenID/ssi-elevenid",rev="{PRIVATE_REVISION}",default-features=false}}\n'
    )
    _write_core_source(tmp_path, "rust/Cargo.toml",
                      '[workspace]\nmembers=["services/*"]\n[workspace.dependencies]\n'
                      f'crypto_alias={{package="marty-crypto",{core},features=["kms-only"],default-features=false}}\n'
                      + patch)
    _write_core_source(tmp_path, "rust/services/issuance/Cargo.toml",
                      '[package]\nname="issuer"\nversion="0.1.0"\n[dependencies]\n'
                      'crypto_alias.workspace=true\n'
                      f'emrtd_alias={{package="marty-emrtd-issuance",{core}}}\n'
                      '[build-dependencies]\nhidden={path="../../support/.hidden"}\n')
    _write_core_source(tmp_path, "rust/support/.hidden/Cargo.toml",
                      '[package]\nname="hidden"\nversion="0.1.0"\n'
                      "[target.'cfg(windows)'.build-dependencies]\n"
                      f'digest_alias={{package="marty-canonical-digest",{core}}}\n'
                      '[package.metadata.dependencies]\n'
                      f'ignored={{git="{CORE_REPOSITORY}",rev="{OTHER_CORE_REVISION}"}}\n')
    _write_core_source(tmp_path, f"{CORE_PROBE}/Cargo.toml",
                      '[package]\nname="probe"\nversion="0.0.0"\n[dependencies]\n'
                      'issuer={path="../../../rust/services/issuance"}\n' + patch)
    lock = 'version = 4\n'
    for package in ("marty-crypto", "marty-emrtd-issuance", "marty-canonical-digest"):
        lock += (
            f'[[package]]\nname="{package}"\nversion="0.2.2"\n'
            f'source="git+{CORE_REPOSITORY}?rev={CORE_REVISION}#{CORE_REVISION}"\n'
        )
    lock += (
        '[[package]]\nname="private-fixture"\nversion="0.1.0"\n'
        f'source="git+https://github.com/ElevenID/ssi-elevenid?rev={PRIVATE_REVISION}#{PRIVATE_REVISION}"\n'
        '[[patch.unused]]\nname="elliptic-curve"\nversion="0.13.8"\n'
        f'source="git+{CORE_REPOSITORY}.git?rev={CORE_REVISION}#{CORE_REVISION}"\n'
    )
    for name in ("rust/Cargo.lock", f"{CORE_PROBE}/Cargo.lock"):
        _write_core_source(tmp_path, name, lock)
    _write_core_source(tmp_path, CORE_POLICY,
                      f'CORE_REVISION = "{CORE_REVISION}"\n'
                      'raise AssertionError("policy must never be executed")\n')
    # This separate workspace is outside both governed roots. Its source
    # choices are not adopted into the production or probe graph.
    _write_core_source(tmp_path, "docker/canvas-localhost-bridge/Cargo.toml",
                      '[workspace]\n[package]\nname="bridge"\nversion="0.1.0"\n'
                      '[dependencies]\n'
                      f'isolated={{git="{CORE_REPOSITORY}",rev="{OTHER_CORE_REVISION}"}}\n')
    return tmp_path


def _replace_core_source(root: Path, name: str, before: str, after: str) -> None:
    path = root / name
    original = path.read_text(encoding="utf-8")
    assert before in original
    path.write_text(original.replace(before, after, 1), encoding="utf-8")


@pytest.mark.parametrize("revision", [CORE_REVISION, "d" * 40])
def test_release_core_sources_accept_consistent_graph_without_changing_inputs(core_source: Path, revision: str) -> None:
    paths = [path for path in core_source.rglob("Cargo*") if path.is_file()]
    paths.append(core_source / CORE_POLICY)
    for path in paths:
        path.write_text(path.read_text().replace(CORE_REVISION, revision), encoding="utf-8")
    before = {path: (path.read_bytes(), path.stat().st_mode)
              for path in core_source.rglob("*") if path.is_file()}
    # The fixture's top-level raise proves policy is parsed, never executed.
    preflight.validate_release_core_sources(core_source)
    assert {path: (path.read_bytes(), path.stat().st_mode)
            for path in core_source.rglob("*") if path.is_file()} == before


@pytest.mark.parametrize("manifest", [
    "rust/services/issuance/Cargo.toml",
    "rust/support/.hidden/Cargo.toml",
    f"{CORE_PROBE}/Cargo.toml",
])
def test_stale_child_hidden_or_probe_core_revision_fails_before_release_metadata(core_source: Path, manifest: str) -> None:
    _replace_core_source(core_source, manifest, CORE_REVISION, OTHER_CORE_REVISION)
    # The fixture deliberately has no release metadata, cache or build output.
    # The observed mismatch must be the first failure through the actual entry.
    with pytest.raises(ValueError, match="Core release revision differs"):
        preflight.check(core_source, SOURCE)


@pytest.mark.parametrize("coordinate", [
    'rev="short"',
    f'rev="{"A" * 40}"',
    'branch="main"',
    'tag="v0.2.2"',
    f'rev="{CORE_REVISION}",branch="main"',
    f'rev="{CORE_REVISION}",path="../../../core"',
])
def test_release_core_dependencies_require_one_immutable_source(core_source: Path, coordinate: str) -> None:
    _replace_core_source(core_source, "rust/services/issuance/Cargo.toml",
                         f'rev="{CORE_REVISION}"', coordinate)
    with pytest.raises(ValueError, match="full immutable rev"):
        preflight.validate_release_core_sources(core_source)


@pytest.mark.parametrize("lock_name", ["rust/Cargo.lock", f"{CORE_PROBE}/Cargo.lock"])
@pytest.mark.parametrize("unused", [False, True])
@pytest.mark.parametrize("part", ["query", "fragment"])
def test_stale_active_or_unused_core_lock_identity_is_rejected(core_source: Path, lock_name: str, unused: bool, part: str) -> None:
    repository = CORE_REPOSITORY + (".git" if unused else "")
    original = f"git+{repository}?rev={CORE_REVISION}#{CORE_REVISION}"
    query = OTHER_CORE_REVISION if part == "query" else CORE_REVISION
    fragment = OTHER_CORE_REVISION if part == "fragment" else CORE_REVISION
    _replace_core_source(core_source, lock_name, original,
                         f"git+{repository}?rev={query}#{fragment}")
    with pytest.raises(ValueError, match="Core lock source differs"):
        preflight.validate_release_core_sources(core_source)


@pytest.mark.parametrize("lock_name", ["rust/Cargo.lock", f"{CORE_PROBE}/Cargo.lock"])
def test_lock_without_any_core_identity_is_rejected(core_source: Path, lock_name: str) -> None:
    path = core_source / lock_name
    path.write_text(path.read_text().replace(CORE_REPOSITORY, "https://example.test/unrelated"), encoding="utf-8")
    with pytest.raises(ValueError, match="contains no Marty Core source"):
        preflight.validate_release_core_sources(core_source)


def test_governed_probe_preserves_complete_production_patch_policy(core_source: Path) -> None:
    _replace_core_source(core_source, f"{CORE_PROBE}/Cargo.toml",
                         'default-features=false', 'default-features=true')
    with pytest.raises(ValueError, match="probe patches differ"):
        preflight.validate_release_core_sources(core_source)


def test_governed_probe_direct_target_dependency_cannot_hide_old_core(core_source: Path) -> None:
    path = core_source / CORE_PROBE / "Cargo.toml"
    path.write_text(path.read_text() + (
        "[target.'cfg(unix)'.dev-dependencies]\n"
        f'alias={{package="marty-crypto",git="{CORE_REPOSITORY}",rev="{OTHER_CORE_REVISION}"}}\n'
    ), encoding="utf-8")
    with pytest.raises(ValueError, match="Core release revision differs"):
        preflight.validate_release_core_sources(core_source)


@pytest.mark.parametrize("missing", ["Cargo.toml", "Cargo.lock"])
def test_core_release_requires_governed_probe_source_inputs(core_source: Path, missing: str) -> None:
    (core_source / CORE_PROBE / missing).unlink()
    with pytest.raises((ValueError, FileNotFoundError), match="Cargo"):
        preflight.validate_release_core_sources(core_source)


def test_coherent_cargo_graph_cannot_bless_an_unreviewed_kms_revision(core_source: Path) -> None:
    for path in core_source.rglob("Cargo*"):
        if path.is_file():
            path.write_text(path.read_text().replace(CORE_REVISION, OTHER_CORE_REVISION), encoding="utf-8")
    before = {path: (path.read_bytes(), path.stat().st_mode)
              for path in core_source.rglob("*") if path.is_file()}
    with pytest.raises(ValueError, match="differs from reviewed KMS boundary"):
        preflight.check(core_source, SOURCE)
    assert {path: (path.read_bytes(), path.stat().st_mode)
            for path in core_source.rglob("*") if path.is_file()} == before


@pytest.mark.parametrize("policy_source", [
    "",
    "CORE_REVISION = 7\n",
    'CORE_REVISION = "short"\n',
    'CORE_REVISION = "' + "A" * 40 + '"\n',
    'CORE_REVISION = "1" * 40\n',
    "CORE_REVISION = load_manifest_revision()\n",
    f'CORE_REVISION = "{CORE_REVISION}"\nCORE_REVISION = "{CORE_REVISION}"\n',
    f'other = CORE_REVISION = "{CORE_REVISION}"\n',
    f'if True:\n    CORE_REVISION = "{CORE_REVISION}"\n',
    f'CORE_REVISION = "{CORE_REVISION}"\nif True:\n    CORE_REVISION = "{OTHER_CORE_REVISION}"\n',
    "CORE_REVISION = (\n",
    f'CORE_REVISION = "{CORE_REVISION}"\nCORE_REVISION += ""\n',
])
def test_reviewed_kms_revision_requires_one_module_level_literal(core_source: Path, policy_source: str) -> None:
    (core_source / CORE_POLICY).write_text(policy_source, encoding="utf-8")
    with pytest.raises(ValueError, match="Reviewed KMS boundary"):
        preflight.validate_release_core_sources(core_source)


def test_core_release_requires_existing_reviewed_kms_policy_source(core_source: Path) -> None:
    (core_source / CORE_POLICY).unlink()
    with pytest.raises(FileNotFoundError, match="check_marty_core_kms_boundary"):
        preflight.check(core_source, SOURCE)
