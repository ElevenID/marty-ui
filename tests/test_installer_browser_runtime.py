"""Pinned runtime admission and local extraction; no executable is launched."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

if sys.platform != "linux":
    pytest.skip("browser runtime admission requires Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_browser_runtime as runtime
import installer_browser_runtime_policy as production_policy


def digest(value):
    return hashlib.sha256(value).hexdigest()


FILES = {
    "node/bin/node": (b"fixture-node-never-executed\n", 0o555),
    "node/LICENSE": (b"fixture-node-license\n", 0o444),
    "playwright-core/package.json": (b'{"name":"playwright-core","version":"1.62.1"}\n', 0o444),
    "playwright-core/index.js": (b"throw new Error('fixture must not execute');\n", 0o444),
    "chrome-linux64/chrome": (b"fixture-chromium-never-executed\n", 0o555),
    "chrome-linux64/resources/data.bin": (b"fixture-browser-resource\n", 0o444),
}
DIRECTORIES = sorted({str(parent) for name in FILES
                      for parent in Path(name).parents if str(parent) != "."})


def manifest():
    return json.dumps(dict(schema=runtime.MANIFEST_SCHEMA, directories=DIRECTORIES,
        files={name: dict(sha256=digest(data), size=len(data), mode=mode)
               for name, (data, mode) in FILES.items()}), sort_keys=True).encode()


def policy(archives=None):
    value = copy.deepcopy(production_policy.POLICY)
    if archives:
        for name, path in archives.items():
            raw = path.read_bytes()
            value["archives"][name]["size"] = len(raw)
            value["archives"][name]["sha256"] = digest(raw)
    raw = manifest()
    return runtime._policy_from(value, raw, digest(raw))


def tree(parent):
    root = parent / "runtime"
    root.mkdir(mode=0o700)
    for name in DIRECTORIES:
        (root / name).mkdir(mode=0o700)
    for name, (data, mode) in FILES.items():
        (root / name).write_bytes(data)
        (root / name).chmod(mode)
    return root


def tar_bytes(kind, entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode=f"w:{kind}") as bundle:
        for name, data, link in entries:
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755
            if link:
                entry.type = tarfile.SYMTYPE if link == "symlink" else tarfile.LNKTYPE
                entry.linkname = "/must-not-follow"
                bundle.addfile(entry)
            else:
                entry.size = len(data)
                bundle.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def archives(parent, fault=None):
    result = {}
    for name, spec in production_policy.POLICY["archives"].items():
        entries = [(spec["prefix"] + path[len(spec["destination"]) + 1:], data, None)
                   for path, (data, _mode) in FILES.items()
                   if path.startswith(spec["destination"] + "/")]
        if name == "node":
            # Official Node carries unused npm symlinks. Only its two explicit
            # selected members may enter the runtime, so those are never used.
            entries.append((spec["prefix"] + "bin/npm", b"", "symlink"))
            if fault == "selected-symlink": entries[0] = (entries[0][0], b"", "symlink")
            if fault == "selected-hardlink": entries[0] = (entries[0][0], b"", "hardlink")
            if fault == "duplicate": entries.append(entries[0])
        if name == "playwright":
            if fault == "traversal": entries.append(("package/../outside", b"escape", None))
            if fault == "unmanifested": entries.append(("package/unexpected.js", b"extra", None))
            if fault == "content": entries[0] = (entries[0][0], b"x" * len(entries[0][1]), None)
            if fault == "size": entries[0] = (entries[0][0], entries[0][1] + b"x", None)
        path = parent / spec["name"]
        if name == "chromium":
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for entry, data, _link in entries:
                    bundle.writestr(entry, data)
                if fault == "absolute": bundle.writestr("/outside", b"escape")
                if fault == "zip-symlink":
                    entry = zipfile.ZipInfo(spec["prefix"] + "resources/link")
                    entry.create_system = 3
                    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                    bundle.writestr(entry, "/must-not-follow")
            path.write_bytes(output.getvalue())
        else:
            path.write_bytes(tar_bytes("xz" if name == "node" else "gz", entries))
        path.chmod(0o600)
        result[name] = path
    return result


def test_real_policy_binds_every_file_and_exact_public_identity():
    admitted = runtime._load_policy()
    assert len(admitted.files) == 416 and len(admitted.directories) == 40
    assert sum(value["size"] for value in admitted.files.values()) == 547326437
    identity = runtime.validate_identity(dict(admitted.identity))
    assert identity == dict(schema=runtime.IDENTITY_SCHEMA, platform="linux/amd64",
        node_version="24.22.1", playwright_version="1.62.1", chromium_version="151.0.7922.34",
        chromium_revision="1234", manifest_sha256=production_policy.MANIFEST_SHA256,
        node_sha256=admitted.files["node/bin/node"]["sha256"],
        chromium_sha256=admitted.files["chrome-linux64/chrome"]["sha256"])
    for field in identity:
        changed = dict(identity, **{field: "untrusted"})
        with pytest.raises(ValueError): runtime.validate_identity(changed)
    with pytest.raises(ValueError): runtime.validate_identity(dict(identity, extra="unknown"))
    with pytest.raises(ValueError): runtime.validate_identity(dict(identity, chromium_revision=1234))


def test_private_exact_tree_keeps_immutable_identity_paths_and_closes_all_fds(tmp_path):
    root = tree(tmp_path)
    before = len(os.listdir("/proc/self/fd"))
    with runtime._admit(root, policy(), os.geteuid()) as admitted:
        assert admitted.node == root / "node/bin/node"
        assert admitted.chromium == root / "chrome-linux64/chrome"
        assert admitted.playwright == root / "playwright-core"
        with pytest.raises(TypeError): admitted.identity["node_version"] = "other"
        with pytest.raises(AttributeError): admitted.node = Path("/another/node")
        admitted.check()
        assert len(os.listdir("/proc/self/fd")) >= before + len(FILES) + len(DIRECTORIES)
    assert len(os.listdir("/proc/self/fd")) == before
    with pytest.raises(ValueError): admitted.check()


@pytest.mark.parametrize("fault", ["missing", "extra", "extra-directory", "content", "size",
    "owner-write", "group-write", "directory-mode", "symlink", "hardlink", "fifo", "directory"])
def test_tree_admission_refuses_changed_unsafe_or_extra_members(tmp_path, fault):
    root = tree(tmp_path)
    target = root / "node/bin/node"
    if fault == "missing": target.unlink()
    elif fault == "extra": (root / "unexpected").write_bytes(b"extra")
    elif fault == "extra-directory": (root / "unexpected").mkdir(mode=0o700)
    elif fault == "content":
        target.chmod(0o600); target.write_bytes(b"x" * len(FILES["node/bin/node"][0])); target.chmod(0o555)
    elif fault == "size":
        target.chmod(0o600); target.write_bytes(FILES["node/bin/node"][0] + b"x"); target.chmod(0o555)
    elif fault == "owner-write": target.chmod(0o755)
    elif fault == "group-write": target.chmod(0o575)
    elif fault == "directory-mode": (root / "node").chmod(0o755)
    elif fault == "symlink": target.unlink(); target.symlink_to(tmp_path / "outside")
    elif fault == "hardlink": os.link(target, tmp_path / "outside")
    elif fault == "fifo": target.unlink(); os.mkfifo(target, 0o555)
    elif fault == "directory": target.unlink(); target.mkdir(mode=0o555)
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises((ValueError, OSError)):
        with runtime._admit(root, policy(), os.geteuid()): pass
    assert len(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("fault", ["file", "directory", "root", "ancestor", "restored-content"])
def test_check_refuses_same_bytes_after_inode_or_held_path_replacement(tmp_path, fault):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    root = tree(private)
    with pytest.raises((ValueError, OSError)):
        with runtime._admit(root, policy(), os.geteuid()) as admitted:
            if fault == "file":
                target = root / "node/bin/node"
                target.unlink(); target.write_bytes(FILES["node/bin/node"][0]); target.chmod(0o555)
            elif fault == "directory":
                os.rename(root / "node", private / "retained-node")
                shutil.copytree(private / "retained-node", root / "node")
            elif fault == "root":
                os.rename(root, private / "retained-root")
                shutil.copytree(private / "retained-root", root)
            elif fault == "ancestor":
                os.rename(private, tmp_path / "retained-private")
                shutil.copytree(tmp_path / "retained-private", private)
            else:
                target = root / "node/bin/node"
                target.chmod(0o600); target.write_bytes(FILES["node/bin/node"][0]); target.chmod(0o555)
            admitted.check()


def test_root_symlink_ancestor_symlink_and_foreign_owner_are_refused(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    root = tree(private)
    link = tmp_path / "alias"
    link.symlink_to(private, target_is_directory=True)
    for path, uid in [(link / "runtime", os.geteuid()), (root, os.geteuid() + 1)]:
        with pytest.raises((ValueError, OSError)):
            with runtime._admit(path, policy(), uid): pass
    root_link = private / "runtime-link"
    root_link.symlink_to(root, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        with runtime._admit(root_link, policy(), os.geteuid()): pass


def test_public_entry_refuses_root_or_setid_before_loading_any_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError):
        with runtime.admit(tmp_path / "absent"): pass
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(runtime.os, "getuid", lambda: 1002)
    with pytest.raises(ValueError):
        with runtime.admit(tmp_path / "absent"): pass


def test_local_archive_install_creates_only_manifest_files_without_executing(tmp_path):
    sources = archives(tmp_path)
    selected = policy(sources)
    root = tmp_path / "installed"
    result = runtime._install(root, sources, selected, os.geteuid())
    assert result == dict(selected.identity)
    assert sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()) == sorted(FILES)
    for name, (data, mode) in FILES.items():
        assert (root / name).read_bytes() == data
        assert stat.S_IMODE((root / name).stat().st_mode) == mode
    assert all(stat.S_IMODE((root / name).stat().st_mode) == 0o700 for name in DIRECTORIES)
    with runtime._admit(root, selected, os.geteuid()) as admitted: admitted.check()
    with pytest.raises(FileExistsError): runtime._install(root, sources, selected, os.geteuid())


@pytest.mark.parametrize("fault", ["selected-symlink", "selected-hardlink", "duplicate", "traversal",
    "unmanifested", "content", "size", "absolute", "zip-symlink"])
def test_authenticated_archive_still_refuses_unsafe_or_unmanifested_extraction(tmp_path, fault):
    sources = archives(tmp_path, fault)
    root = tmp_path / "incomplete"
    with pytest.raises((ValueError, OSError)):
        runtime._install(root, sources, policy(sources), os.geteuid())
    assert not (tmp_path / "outside").exists()
    if root.exists():
        with pytest.raises((ValueError, OSError)):
            with runtime._admit(root, policy(sources), os.geteuid()): pass


@pytest.mark.parametrize("fault", ["digest", "size", "symlink", "writable"])
def test_archive_preflight_refuses_before_destination_creation(tmp_path, fault):
    sources = archives(tmp_path)
    selected = policy(sources)
    target = sources["node"]
    if fault == "digest":
        raw = bytearray(target.read_bytes()); raw[0] ^= 1; target.write_bytes(raw)
    elif fault == "size": target.write_bytes(target.read_bytes() + b"x")
    elif fault == "symlink":
        alternate = tmp_path / "retained-node"; target.rename(alternate); target.symlink_to(alternate)
    else: target.chmod(0o666)
    root = tmp_path / "not-created"
    with pytest.raises((ValueError, OSError)): runtime._install(root, sources, selected, os.geteuid())
    assert not root.exists()


def test_policy_parser_refuses_manifest_hash_inventory_and_duplicate_fields():
    value = copy.deepcopy(production_policy.POLICY)
    raw = manifest()
    with pytest.raises(ValueError): runtime._policy_from(value, raw, "f" * 64)
    decoded = json.loads(raw)
    decoded["files"]["node/bin/node"]["mode"] = 0o755
    changed = json.dumps(decoded).encode()
    with pytest.raises(ValueError): runtime._policy_from(value, changed, digest(changed))
    decoded = json.loads(raw)
    decoded["files"]["node/npm"] = decoded["files"]["node/LICENSE"]
    changed = json.dumps(decoded).encode()
    with pytest.raises(ValueError): runtime._policy_from(value, changed, digest(changed))
    changed = raw[:-1] + b',"schema":"duplicate"}'
    with pytest.raises(ValueError): runtime._policy_from(value, changed, digest(changed))


def test_policy_loading_ignores_import_and_bytecode_cache_authority(monkeypatch):
    # Even a preloaded module (including one loaded from a stale/tampered .pyc)
    # cannot replace the two literals in the fixed authenticated source file.
    monkeypatch.setitem(sys.modules, "installer_browser_runtime_policy", SimpleNamespace(
        __file__=str(runtime.POLICY_PATH), POLICY={"untrusted": True}, MANIFEST_SHA256="f" * 64))
    selected = runtime._load_policy()
    assert selected.identity["manifest_sha256"] == production_policy.MANIFEST_SHA256
    assert len(selected.files) == 416


@pytest.mark.parametrize("fault", ["statement", "import", "duplicate", "dynamic-value"])
def test_policy_file_accepts_literals_only_without_executing_source(tmp_path, monkeypatch, fault):
    marker = tmp_path / "not-executed"
    source = tmp_path / "policy.py"
    text = f'"""literal test policy"""\nMANIFEST_SHA256 = {production_policy.MANIFEST_SHA256!r}\nPOLICY = {production_policy.POLICY!r}\n'
    if fault == "statement": text += f"open({str(marker)!r}, 'w').write('executed')\n"
    elif fault == "import": text += "import os\n"
    elif fault == "duplicate": text += "POLICY = {}\n"
    else: text = "MANIFEST_SHA256 = 'f' * 64\nPOLICY = {}\n"
    source.write_text(text)
    source.chmod(0o600)
    monkeypatch.setattr(runtime, "POLICY_PATH", source)
    with pytest.raises(ValueError): runtime._load_policy()
    assert not marker.exists()
