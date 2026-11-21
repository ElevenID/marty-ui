from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from scripts import create_demo_manifest_draft as generator
from scripts.bind_deployed_demo_manifest import bind_manifest
from scripts.operator_demo_catalog import (
    CATALOG_DIRECTORY, ROOT, DEMO_TEMPLATE_PATHS, load_operator_demo_catalog,
    load_operator_demo_template, load_product_demo_template,
)
from scripts.validate_demo_manifests import ManifestValidationError, load_manifests, validate_manifest


@pytest.fixture
def operator_root(tmp_path):
    target = tmp_path / "source"
    shutil.copytree(ROOT / CATALOG_DIRECTORY, target / CATALOG_DIRECTORY)
    (target / "VERSION").write_text("2026.08.0\n")
    return target


def test_operator_catalog_is_independent_of_website_files(operator_root):
    catalog = load_operator_demo_catalog(operator_root)
    assert not (operator_root / "ui").exists()
    assert catalog.manifest["stack_version"] == "2026.08.0"
    assert catalog.manifest["binding_state"] == "PENDING_DEPLOYMENT"
    assert catalog.manifest["release_ready"] is False
    assert catalog.manifest["public_demo_ready"] is False
    assert catalog.metadata["source"] == {
        "repository": "ElevenID/marty-ui",
        "commit": "b1095e8c86389929cf1a93c4ed04d9eb784f3a6d",
    }
    assert sum(path.is_file() for path in (operator_root / CATALOG_DIRECTORY).rglob("*")) == 3
    assert load_operator_demo_template("2026.08.0", operator_root) == catalog.manifest
    with pytest.raises(ValueError, match="No reviewed operator demo template"):
        load_operator_demo_template("2026.08.1", operator_root)


@pytest.mark.parametrize("name", ["catalog.json", "2026.08.0.json", "2026.08.1/portfolio-draft.svg"])
def test_catalog_and_retained_inputs_are_hash_bound(operator_root, name):
    target = operator_root / CATALOG_DIRECTORY / name
    target.write_bytes(target.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="digest changed"):
        load_operator_demo_catalog(operator_root)


@pytest.mark.parametrize("name", ["catalog.json", "2026.08.0.json", "2026.08.1/portfolio-draft.svg"])
def test_missing_inputs_cannot_be_replaced_by_old_public_files(operator_root, name):
    (operator_root / CATALOG_DIRECTORY / name).unlink()
    (operator_root / "ui/public/demos/manifests").mkdir(parents=True)
    (operator_root / "ui/public/demos/manifests/2026.08.0.json").write_text("unreviewed fallback")
    with pytest.raises(ValueError, match="input is missing"):
        load_operator_demo_catalog(operator_root)


def test_retained_inputs_reject_symbolic_links_even_with_matching_bytes(operator_root, tmp_path):
    target = operator_root / CATALOG_DIRECTORY / "2026.08.0.json"
    outside = tmp_path / "same.json"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(ValueError, match="symbolic links"):
        load_operator_demo_catalog(operator_root)


def test_windows_checkouts_preserve_frozen_text_hashes(operator_root):
    for path in (operator_root / CATALOG_DIRECTORY).rglob("*"):
        if path.is_file():
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert load_operator_demo_template("2026.08.0", operator_root)["stack_version"] == "2026.08.0"


def test_operator_template_binds_exact_deployment_without_claiming_recording():
    revision = "a" * 40
    source = {
        "source_kind": "signed-nightly-deployment", "scope": "FUNCTIONAL_ONLY",
        "promotion_eligible": False, "release_ready": False,
        "release_version": "operator-fixture", "mip_version": "0.5.0", "marty_ui_sha": revision,
        "capture_recorder_revision": "b" * 40,
        "repositories": {"marty-ui": {"head_sha": revision}},
        "component_revisions": [{"component": "marty-ui", "repository": "https://github.com/ElevenID/marty-ui", "revision": revision}],
    }
    bound = bind_manifest(load_operator_demo_template("2026.08.0"), source, {"ui-prod": "sha256:" + "c" * 64})
    validate_manifest(bound)
    assert bound["binding_state"] == "DEPLOYED_PENDING_EVIDENCE"
    assert bound["release_evidence"]["source_marker"] == revision
    assert bound["release_evidence"]["recorded_at"] is None
    assert bound["release_ready"] is False
    assert bound["public_demo_ready"] is False
    assert any(item["slug"] == "canvas-learning-achievement" for item in bound["scenarios"])


def test_public_manifest_loader_still_checks_actual_poster_bytes(tmp_path):
    manifest = generator.build_manifest()
    root = tmp_path / "public/demos/manifests"
    root.mkdir(parents=True)
    version = manifest["stack_version"]
    (root / f"{version}.json").write_text(json.dumps(manifest))
    row = {key: manifest[key] for key in ("stack_version", "release_name", "mip_version", "publication_state", "coverage_state")}
    row["manifest_url"] = f"/demos/manifests/{version}.json"
    (root / "index.json").write_text(json.dumps({
        "schema_version": 2, "latest_approved_stack_version": None,
        "latest_available_stack_version": version, "releases": [row],
    }))
    with pytest.raises(ManifestValidationError, match="poster is missing"):
        load_manifests(root)
    poster = root.parent.parent / generator.POSTER_URL.lstrip("/")
    poster.parent.mkdir(parents=True)
    shutil.copyfile(generator.POSTER_PATH, poster)
    assert load_manifests(root)[1][version] == manifest
    poster.write_text("changed public image")
    with pytest.raises(ManifestValidationError, match="poster SHA-256 mismatch"):
        load_manifests(root)


def test_generator_writes_only_an_unbound_draft_output(tmp_path, monkeypatch):
    target = tmp_path / "drafts/2026.08.1.json"
    monkeypatch.setattr(generator, "OUTPUT_PATH", target)
    assert generator.main() == 0
    assert json.loads(target.read_text()) == generator.build_manifest()
    assert not (ROOT / "ui/public/demos/manifests/2026.08.1.json").exists()


@pytest.mark.parametrize("changed", [False, True])
def test_catalog_cli_is_a_read_only_preflight(operator_root, changed):
    if changed:
        (operator_root / CATALOG_DIRECTORY / "2026.08.0.json").write_text("changed")
    before = {path.relative_to(operator_root): path.read_bytes() for path in operator_root.rglob("*") if path.is_file()}
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/operator_demo_catalog.py"),
        "--repository-root", str(operator_root), "--stack-version", "2026.08.0",
    ], capture_output=True, text=True)
    assert result.returncode == (1 if changed else 0), result.stderr
    if not changed:
        report = json.loads(result.stdout)
        assert report["scope"] == "operator-inputs"
        assert report["website_assets_verified"] is False
    after = {path.relative_to(operator_root): path.read_bytes() for path in operator_root.rglob("*") if path.is_file()}
    assert before == after


def product_checkout(tmp_path, historical):
    from tests.test_create_local_release_manifest import make_repo, commit_changes
    root = tmp_path / "marty-ui"
    make_repo(root)
    (root / ".gitignore").write_text("tests/artifacts/\n")
    (root / "VERSION").write_text("2026.08.0\n")
    if historical:
        relative = DEMO_TEMPLATE_PATHS[1]
        source = ROOT / "tests/fixtures/demo-manifests/2026.08.0-nightly273.json"
        target = root / relative
        target.parent.mkdir(parents=True)
        target.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
    else:
        relative = DEMO_TEMPLATE_PATHS[0]
        shutil.copytree(ROOT / CATALOG_DIRECTORY, root / CATALOG_DIRECTORY)
    (root / "scripts").mkdir()
    shutil.copyfile(ROOT / "scripts/create_local_release_manifest.py", root / "scripts/create_local_release_manifest.py")
    commit_changes(root)
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    return root, revision, relative


@pytest.mark.parametrize("historical", [False, True])
def test_product_cli_preserves_exact_source_owned_template_and_is_read_only(tmp_path, historical):
    root, revision, relative = product_checkout(tmp_path, historical)
    before = (root / relative).read_bytes()
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/operator_demo_catalog.py"),
        "--product-root", str(root), "--product-revision", revision, "--stack-version", "2026.08.0",
    ], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["scope"] == "product-template"
    assert report["source"]["commit"] == revision
    assert report["source_path"] == relative
    assert report["template_path"] == str(root / relative)
    assert report["template_sha256"] == (
        "3e643f3b471daac620c670aa506c654fb7894b940744c83169775fb643a655f1" if historical
        else "3859324f5f2fb13dae158b8ff95c1e2261ae69c5ce2ce8806a2e4048e16ca494"
    )
    assert (root / relative).read_bytes() == before
    if historical:
        assert not (root / CATALOG_DIRECTORY).exists()
    assert subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"]) == b""


@pytest.mark.parametrize("changed", ["bytes", "missing", "head", "stack", "current-catalog"])
def test_product_selection_never_substitutes_operator_snapshot_on_failure(tmp_path, changed):
    root, revision, relative = product_checkout(tmp_path, changed != "current-catalog")
    stack = "2026.08.0"
    if changed == "bytes":
        (root / relative).write_bytes((root / relative).read_bytes() + b"\n")
    elif changed == "missing":
        (root / relative).unlink()
    elif changed == "head":
        revision = "0" * 40
    elif changed == "stack":
        stack = "2026.08.1"
    else:
        (root / CATALOG_DIRECTORY / "catalog.json").write_text("changed")
    with pytest.raises(ValueError):
        load_product_demo_template(stack, root, revision)


def local_product_snapshot(tmp_path, historical):
    from tests.test_create_local_release_manifest import make_repo
    from scripts.create_local_release_manifest import REPOSITORIES, create_manifest
    root, revision, relative = product_checkout(tmp_path, historical)
    for name in REPOSITORIES:
        if name != "marty-ui":
            make_repo(tmp_path / name)
    artifacts = root / "tests/artifacts/run"
    artifacts.mkdir(parents=True)
    source = create_manifest(tmp_path, "local-template-test", artifacts / "source-manifest.json", artifacts / "snapshots")
    (artifacts / "backup-manifest.json").write_text(json.dumps({"phase": "not-quiesced"}))
    assert source["marty_ui_sha"] != revision
    assert source["repositories"]["marty-ui"]["head_sha"] == revision
    return root, revision, relative, artifacts, source


@pytest.mark.parametrize("historical", [False, True])
def test_startup_verifies_snapshot_then_selects_its_git_template_before_mutation(tmp_path, monkeypatch, historical):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import complete_local_beta_startup as startup
    root, revision, relative, artifacts, source = local_product_snapshot(tmp_path, historical)
    before = (root / relative).read_bytes()
    observed = []
    select = startup.load_product_demo_template

    def observe_selection(stack, product, pinned):
        selected = select(stack, product, pinned)
        observed.append(selected)
        return selected

    monkeypatch.setattr(startup, "load_product_demo_template", observe_selection)
    monkeypatch.setattr(startup, "docker", lambda *args: pytest.fail("Startup cannot mutate before source/template and backup admission"))
    with pytest.raises(RuntimeError, match="Quiesced backup is required"):
        startup.complete(root, artifacts, root / "runtime", True)
    assert len(observed) == 1
    assert observed[0].source_revision == revision != source["marty_ui_sha"]
    assert observed[0].manifest == json.loads(before)
    assert observed[0].template_path == root / relative
    assert (root / relative).read_bytes() == before
    if historical:
        assert not (root / CATALOG_DIRECTORY).exists()


def test_startup_snapshot_failure_precedes_selection_and_mutation(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import complete_local_beta_startup as startup
    root, _, relative, artifacts, _ = local_product_snapshot(tmp_path, True)
    (root / relative).write_bytes((root / relative).read_bytes() + b"\n")
    monkeypatch.setattr(startup, "load_product_demo_template", lambda *args: pytest.fail("Source verification must precede template selection"))
    monkeypatch.setattr(startup, "docker", lambda *args: pytest.fail("Changed frozen source cannot reach Docker"))
    with pytest.raises(subprocess.CalledProcessError):
        startup.complete(root, artifacts, root / "runtime", True)
