"""Actual helper closure and consistency with already-authenticated bundle bytes."""
from __future__ import annotations

import ast
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_legacy_recovery_sources as sources


@pytest.fixture
def source_case(tmp_path, monkeypatch):
    root, assets = tmp_path / "source", tmp_path / "assets"
    root.mkdir(mode=0o700)
    assets.mkdir(mode=0o700)
    files = ("scripts/synthetic_recovery_helper.py", "deploy-config/catalog/synthetic_catalog.json")
    monkeypatch.setattr(sources, "SOURCE_FILES", files)
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((name + "\n").encode())
        path.chmod(0o600)
    item = SimpleNamespace(root=root, assets=assets, files=files, identity=None)

    def bundle(*, missing=None, duplicate=None, tamper=None, symlink=None):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name in files:
                if name == missing:
                    continue
                entry = zipfile.ZipInfo("selfhost-prepared/" + name)
                entry.create_system = 3
                entry.external_attr = ((stat.S_IFLNK if name == symlink else stat.S_IFREG) | 0o600) << 16
                raw = b"different packaged bytes" if name == tamper else (root / name).read_bytes()
                archive.writestr(entry, raw)
                if name == duplicate:
                    with pytest.warns(UserWarning, match="Duplicate name"):
                        archive.writestr(entry, raw)
        raw = stream.getvalue()
        inventory = bootstrap.encoded({"artifacts": [{"name": "prepared-selfhost-bundle.zip", "sha256": sources.digest(raw)}]})
        for name, value in (("prepared-selfhost-bundle.zip", raw), ("installer-inventory.json", inventory)):
            path = assets / name
            path.write_bytes(value)
            path.chmod(0o600)
        item.identity = {"inventorySha256": sources.digest(inventory)}

    item.bundle = bundle
    bundle()
    return item


def test_source_match_uses_the_verified_inventory_bytes_and_rechecks_local_files(source_case):
    item = source_case
    actual = sources.authenticate(item.assets, item.identity, root=item.root)
    assert actual == {name: sources.digest((item.root / name).read_bytes()) for name in item.files}


@pytest.mark.parametrize("field", ["missing", "duplicate", "tamper", "symlink"])
def test_missing_or_changed_signed_source_cannot_pass_the_existing_inventory(source_case, field):
    item = source_case
    item.bundle(**{field: item.files[0]})
    with pytest.raises(bootstrap.BootstrapError):
        sources.authenticate(item.assets, item.identity, root=item.root)


@pytest.mark.parametrize("name", ["installer-inventory.json", "prepared-selfhost-bundle.zip"])
def test_changed_authenticated_payload_is_refused_before_matching_sources(source_case, name):
    item = source_case
    with (item.assets / name).open("ab") as stream:
        stream.write(b"\n" if name == "installer-inventory.json" else b"changed after verification")
    with pytest.raises(bootstrap.BootstrapError, match="authenticated recovery"):
        sources.authenticate(item.assets, item.identity, root=item.root)


def test_malformed_authenticated_archive_has_a_sanitized_refusal(source_case):
    item = source_case
    raw = b"not a ZIP archive"
    (item.assets / "prepared-selfhost-bundle.zip").write_bytes(raw)
    inventory = bootstrap.encoded({"artifacts": [{"name": "prepared-selfhost-bundle.zip", "sha256": sources.digest(raw)}]})
    (item.assets / "installer-inventory.json").write_bytes(inventory)
    with pytest.raises(bootstrap.BootstrapError, match="signed recovery source archive is invalid"):
        sources.authenticate(item.assets, {"inventorySha256": sources.digest(inventory)}, root=item.root)


def test_local_source_edit_and_aliased_loaded_dependency_are_refused(source_case, monkeypatch):
    item = source_case
    path = item.root / item.files[0]
    path.write_bytes(b"local change\n")
    with pytest.raises(bootstrap.BootstrapError, match="differs from the authenticated bundle"):
        sources.authenticate(item.assets, item.identity, root=item.root)
    item.bundle()
    monkeypatch.setitem(sys.modules, "synthetic_recovery_helper", SimpleNamespace(__file__="/foreign/helper.py"))
    with pytest.raises(bootstrap.BootstrapError, match="different source directory"):
        sources.authenticate(item.assets, item.identity, root=item.root)


@pytest.mark.parametrize("change", ["symlink", "hardlink", "writable"])
def test_source_custody_rejects_aliases_and_shared_writers(source_case, change):
    item = source_case
    path = item.root / item.files[0]
    if change == "symlink":
        other = path.with_suffix(".retained")
        path.rename(other)
        path.symlink_to(other)
    elif change == "hardlink":
        os.link(path, path.with_suffix(".second"))
    else:
        path.chmod(0o666)
    with pytest.raises(bootstrap.BootstrapError):
        sources.authenticate(item.assets, item.identity, root=item.root)


def imported_local_modules(root: Path) -> set[str]:
    scripts = root / "scripts"
    pending = ["inspect_kubernetes_legacy_credentials", "recover_kubernetes_legacy_credentials",
               "reload_kubernetes_legacy_workloads", "adopt_kubernetes_renewal",
               "stage_kubernetes_application_credentials", "stage_kubernetes_renewal_credentials",
               "activate_kubernetes_application_credentials", "activate_kubernetes_renewal_credentials"]
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        for node in ast.walk(ast.parse((scripts / (name + ".py")).read_text())):
            modules = [item.name.split(".")[0] for item in node.names] if isinstance(node, ast.Import) else (
                [node.module.split(".")[0]] if isinstance(node, ast.ImportFrom) and node.module else [])
            pending.extend(module for module in modules if (scripts / (module + ".py")).is_file() and module not in seen)
    return {"scripts/" + name + ".py" for name in seen}


def test_real_bundle_descriptor_covers_the_actual_imported_source_closure():
    required = imported_local_modules(sources.ROOT) | {
        "deploy-config/catalog/kubernetes-application-tokens.json", "deploy-config/catalog/kubernetes-secrets.json"}
    assert set(sources.SOURCE_FILES) == required and len(sources.SOURCE_FILES) == len(required)
    descriptor = json.loads((sources.ROOT / "deploy-config/bundles/selfhost.json").read_bytes())
    for name in required | {"docs/kubernetes-legacy-credential-recovery.md"}:
        assert descriptor["assets"].count(name) == 1, name


def test_packaged_source_imports_without_checkout_fallback_or_private_inputs(tmp_path):
    root = tmp_path / "selfhost-prepared"
    for name in sources.SOURCE_FILES:
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sources.ROOT / name, destination)
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    for entrypoint in ("inspect_kubernetes_legacy_credentials.py", "recover_kubernetes_legacy_credentials.py"):
        result = subprocess.run([sys.executable, "-B", str(root / "scripts" / entrypoint), "--help"],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert "--recovery-source-sha" in result.stdout
    command = "import sys; sys.path.insert(0, sys.argv[1]); import kubernetes_legacy_recovery_sources as s; print(len(s.snapshot()))"
    result = subprocess.run([sys.executable, "-B", "-c", command, str(root / "scripts")],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(len(sources.SOURCE_FILES))
