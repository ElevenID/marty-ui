"""Exact committed-source handoff, with no host/deployment admission."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import package_windows_owner_source as source


def git(root, *args, input_bytes=None):
    result = subprocess.run(["git", "-C", str(root), *args], input=input_bytes,
                            capture_output=True, check=True)
    return result.stdout.decode().strip()


def commit(root):
    git(root, "add", ".")
    git(root, "-c", "user.name=Source Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "Synthetic owner source fixture")
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "source checkout"
    root.mkdir()
    git(root, "init", "-q")
    paths = set(source.EXTRA_ASSETS) | set(source.REQUIRED_MODULES)
    for name in paths:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# synthetic fixture\n")
    (root / source.CATALOG).write_text(json.dumps({
        "schema_version": 1, "name": "selfhost",
        "assets": [*source.REQUIRED_MODULES, "config/keycloak"],
    }))
    (root / "scripts/selfhost_windows_recovery.py").write_text(
        "import selfhost_windows_selection\nraise AssertionError('Never execute package input')\n")
    realm = root / "config/keycloak/realm.json"
    realm.parent.mkdir(parents=True)
    realm.write_text('{"synthetic":true}\n')
    return root, commit(root)


def build(repository):
    root, revision = repository
    raw = source.archive_bytes(root, revision)
    return raw, revision


def unpack(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return [(item, archive.read(item)) for item in archive.infolist()]


def repack(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for item, raw in entries:
            archive.writestr(item, raw)
    return output.getvalue()


def rewrite_manifest(raw, change):
    entries = unpack(raw)
    for i, (item, body) in enumerate(entries):
        if item.filename.endswith("/" + source.MANIFEST):
            value = json.loads(body)
            change(value)
            entries[i] = (item, source.packed(value))
    return repack(entries)


def inspect(raw, revision):
    return source.inspect_archive(raw, source.digest(raw), revision)


def test_exact_commit_export_is_deterministic_and_ignores_working_tree(repository, tmp_path):
    root, revision = repository
    before = source.archive_bytes(root, revision)
    (root / "scripts/selfhost_windows_recovery.py").write_text("raise RuntimeError('dirty')\n")
    (root / "scripts/private-untracked.py").write_text("SECRET = 'never-package-this'\n")
    (root / source.CATALOG).write_text("broken working tree catalog")
    after = source.archive_bytes(root, revision)
    assert before == after
    assert b"never-package-this" not in after and b"RuntimeError('dirty')" not in after
    receipt = source.create(root, revision, tmp_path / "handoff.zip")
    assert receipt == inspect(before, revision)
    assert receipt["files"] == len(set(source.EXTRA_ASSETS) | set(source.REQUIRED_MODULES)) + 1
    assert all(value is False for value in receipt["boundaries"].values())
    assert (tmp_path / "handoff.zip").read_bytes() == before
    with pytest.raises(FileExistsError):
        source.create(root, revision, tmp_path / "handoff.zip")
    assert (tmp_path / "handoff.zip").read_bytes() == before


@pytest.mark.parametrize("revision", ["HEAD", "a" * 7, "A" * 40, "--help", "a" * 39, "a" * 41])
def test_named_short_or_malformed_revisions_refuse(repository, revision):
    with pytest.raises(ValueError):
        source.archive_bytes(repository[0], revision)


def test_tree_object_is_not_a_source_commit(repository):
    root, revision = repository
    with pytest.raises(ValueError, match="commit"):
        source.archive_bytes(root, git(root, "rev-parse", revision + "^{tree}"))


def test_git_replace_objects_cannot_substitute_reviewed_commit(repository):
    root, original = repository
    before = source.archive_bytes(root, original)
    (root / "scripts/selfhost_windows_recovery.py").write_text("# replacement\n")
    replacement = commit(root)
    git(root, "replace", original, replacement)
    assert source.archive_bytes(root, original) == before


def test_inherited_git_directory_cannot_redirect_source(repository, monkeypatch):
    root, revision = repository
    before = source.archive_bytes(root, revision)
    monkeypatch.setenv("GIT_DIR", str(root / "missing"))
    monkeypatch.setenv("GIT_WORK_TREE", str(root / "missing"))
    assert source.archive_bytes(root, revision) == before


def test_local_import_omitted_by_catalog_refuses(repository):
    root, _ = repository
    (root / "scripts/required_helper.py").write_text("# committed helper\n")
    (root / "scripts/selfhost_windows_recovery.py").write_text("import required_helper\n")
    with pytest.raises(ValueError, match="local Python import"):
        source.archive_bytes(root, commit(root))


@pytest.mark.parametrize("asset", ["../outside", "/absolute", "scripts/CON.py", "scripts/a:secret",
                                  "scripts/trailing.", "scripts//file.py", "scripts\\file.py"])
def test_unsafe_catalog_names_refuse(repository, asset):
    root, _ = repository
    catalog = json.loads((root / source.CATALOG).read_bytes())
    catalog["assets"].append(asset)
    (root / source.CATALOG).write_text(json.dumps(catalog))
    with pytest.raises(ValueError, match="path"):
        source.archive_bytes(root, commit(root))


def test_catalog_duplicate_and_overlap_refuse(repository):
    root, _ = repository
    catalog = json.loads((root / source.CATALOG).read_bytes())
    catalog["assets"].append("config/keycloak/realm.json")
    (root / source.CATALOG).write_text(json.dumps(catalog))
    with pytest.raises(ValueError, match="overlaps"):
        source.archive_bytes(root, commit(root))


@pytest.mark.parametrize("name", [source.MANIFEST, source.MANIFEST.upper(), source.MANIFEST + "/nested"])
def test_catalog_cannot_place_files_under_reserved_manifest_namespace(repository, name):
    root, _ = repository
    payload = root / name / "payload.py"
    payload.parent.mkdir(parents=True)
    payload.write_text("# synthetic reserved-namespace collision\n")
    catalog = json.loads((root / source.CATALOG).read_bytes())
    catalog["assets"].append(name)
    (root / source.CATALOG).write_text(json.dumps(catalog))
    with pytest.raises(ValueError, match="reserved manifest namespace"):
        source.archive_bytes(root, commit(root))


@pytest.mark.parametrize("name", [source.MANIFEST, source.MANIFEST.upper(), source.MANIFEST + "/nested"])
def test_verifier_rejects_internally_consistent_reserved_namespace_collision(repository, name):
    raw, revision = build(repository)
    prefix = "windows-owner-source-" + revision + "/"
    bodies = {item.filename.removeprefix(prefix): body for item, body in unpack(raw)}
    manifest = json.loads(bodies.pop(source.MANIFEST))
    catalog = json.loads(bodies[source.CATALOG])
    catalog["assets"].append(name)
    bodies[source.CATALOG] = source.packed(catalog)
    payload_name = name + "/payload.py"
    bodies[payload_name] = b"# synthetic reserved-namespace collision\n"
    # Bind every changed byte coherently. The original verifier accepted this
    # file/directory collision even with an otherwise exact manifest/catalog.
    manifest["catalog"]["sha256"] = source.digest(bodies[source.CATALOG])
    manifest["files"] = {
        path: {"git_blob": source.blob_digest(body), "mode": "100644", "bytes": len(body),
               "sha256": source.digest(body)} for path, body in bodies.items()
    }
    malformed = source.zip_bytes(revision, {**bodies, source.MANIFEST: source.packed(manifest)},
                                 {path: "100644" for path in [*bodies, source.MANIFEST]})
    with pytest.raises(ValueError, match="reserved manifest namespace"):
        inspect(malformed, revision)


def test_git_symlink_asset_refuses_without_following_target(repository):
    root, _ = repository
    blob = git(root, "hash-object", "-w", "--stdin", input_bytes=b"../../../private.env")
    git(root, "update-index", "--cacheinfo", "120000", blob, "scripts/selfhost_windows_recovery.py")
    git(root, "-c", "user.name=Source Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "Synthetic symlink fixture")
    with pytest.raises(ValueError, match="special"):
        source.archive_bytes(root, git(root, "rev-parse", "HEAD"))


def test_wrong_external_digest_or_commit_refuses(repository):
    raw, revision = build(repository)
    with pytest.raises(ValueError, match="digest"):
        source.inspect_archive(raw, "0" * 64, revision)
    with pytest.raises(ValueError, match="commit root"):
        source.inspect_archive(raw, source.digest(raw), "0" * 40)


@pytest.mark.parametrize("prefix,suffix", [(b"unexpected executable prefix", b""), (b"", b"trailing bytes")])
def test_zip_preamble_or_trailing_bytes_refuse(repository, prefix, suffix):
    raw, revision = build(repository)
    with pytest.raises(ValueError, match="canonical"):
        inspect(prefix + raw + suffix, revision)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(source_commit="0" * 40),
    lambda value: value.update(source_tree="main"),
    lambda value: value["catalog"].update(sha256="0" * 64),
    lambda value: value["files"].pop("scripts/selfhost_windows_inputs.py"),
    lambda value: value["files"]["scripts/selfhost_windows_inputs.py"].update(sha256="0" * 64),
    lambda value: value["files"]["scripts/selfhost_windows_inputs.py"].update(bytes=True),
    lambda value: value["local_imports"].pop("scripts/selfhost_windows_recovery.py"),
    lambda value: value["boundaries"].update(runtime_admission=True),
    lambda value: value["boundaries"].update(runtime_admission=0),
    lambda value: value["extra_assets"].remove("scripts/install-marty-boot-recovery.ps1"),
])
def test_stale_incomplete_or_admitting_manifest_refuses(repository, mutation):
    raw, revision = build(repository)
    with pytest.raises(ValueError):
        inspect(rewrite_manifest(raw, mutation), revision)


def test_duplicate_manifest_json_keys_refuse(repository):
    raw, revision = build(repository)
    entries = unpack(raw)
    for i, (item, body) in enumerate(entries):
        if item.filename.endswith("/" + source.MANIFEST):
            entries[i] = (item, b'{"schema":"wrong",' + body[1:])
    with pytest.raises(ValueError, match="Duplicate JSON"):
        inspect(repack(entries), revision)


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate", "traversal", "case",
                                     "symlink", "directory", "compressed", "comment", "modified"])
def test_unsafe_or_changed_zip_members_refuse(repository, mutation):
    raw, revision = build(repository)
    entries = unpack(raw)
    index = next(i for i, (item, _) in enumerate(entries) if item.filename.endswith("/scripts/selfhost_windows_inputs.py"))
    item, body = entries[index]
    if mutation == "missing":
        entries.pop(index)
    elif mutation == "extra":
        extra = copy.copy(item)
        extra.filename = extra.filename.rsplit("/", 1)[0] + "/unexpected.py"
        entries.append((extra, b"# extra"))
    elif mutation == "duplicate":
        entries.append((copy.copy(item), body))
    elif mutation == "traversal":
        item.filename = item.filename.rsplit("/", 1)[0] + "/../escape"
    elif mutation == "case":
        extra = copy.copy(item)
        extra.filename = item.filename.replace("selfhost_windows_inputs.py", "SELFHOST_WINDOWS_INPUTS.py")
        entries.append((extra, body))
    elif mutation == "symlink":
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
    elif mutation == "directory":
        item.filename += "/"
        item.external_attr = (stat.S_IFDIR | 0o755) << 16
    elif mutation == "compressed":
        item.compress_type = zipfile.ZIP_DEFLATED
    elif mutation == "comment":
        item.comment = b"unexpected"
    elif mutation == "modified":
        entries[index] = (item, body + b"# changed\n")
    with pytest.raises(ValueError):
        inspect(repack(entries), revision)


@pytest.mark.parametrize("limit", ["files", "file_bytes", "total_bytes"])
def test_create_enforces_source_size_bounds(repository, monkeypatch, limit):
    monkeypatch.setitem(source.LIMITS, limit, 1)
    with pytest.raises(ValueError):
        source.archive_bytes(*repository)


def test_verify_enforces_archive_bound_before_zip_parsing(monkeypatch):
    monkeypatch.setattr(source, "MAX_ARCHIVE_BYTES", 1)
    with pytest.raises(ValueError, match="digest"):
        source.inspect_archive(b"xx", source.digest(b"xx"), "a" * 40)


def test_complete_repository_catalog_and_managed_imports_from_isolated_export(tmp_path):
    revision = git(ROOT, "rev-parse", "HEAD")
    raw = source.archive_bytes(ROOT, revision)
    result = inspect(raw, revision)
    assert result["files"] > 200
    exported = tmp_path / "exported"
    exported.mkdir()
    prefix = "windows-owner-source-" + revision + "/"
    for item, body in unpack(raw):
        relative = item.filename.removeprefix(prefix)
        target = exported / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    child = subprocess.run([sys.executable, "-I", "-B", "-c", """
import importlib,pathlib,sys
scripts=pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0,str(scripts))
for name in ['selfhost_windows_selection','selfhost_windows_recovery','selfhost_windows_expired_origin',
             'deploy_website','recover_product_services']:
 module=importlib.import_module(name)
 assert pathlib.Path(module.__file__).resolve().parent==scripts
print('isolated owner and wrapper imports passed')
""", str(exported / "scripts")], cwd=exported, capture_output=True, text=True, timeout=60)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "isolated owner and wrapper imports passed"


def test_cli_create_then_verify_requires_separately_supplied_identity(repository, tmp_path):
    root, revision = repository
    output = tmp_path / "source.zip"
    executable = [sys.executable, str(ROOT / "scripts/package_windows_owner_source.py")]
    created = subprocess.run([*executable, "create", "--repository", str(root), "--commit", revision,
                              "--output", str(output)], capture_output=True, text=True, check=True)
    receipt = json.loads(created.stdout)
    verified = subprocess.run([*executable, "verify", "--archive", str(output),
                               "--expected-commit", revision,
                               "--expected-sha256", receipt["archive_sha256"]],
                              capture_output=True, text=True, check=True)
    assert json.loads(verified.stdout) == receipt
    assert set(root.iterdir()) == {root / name for name in [".git", "scripts", "docs", "config", "deploy-config"]}
