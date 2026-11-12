"""Direct Windows physical-memory ABI and unchanged admission boundaries; no subprocesses."""
import ctypes
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_runtime as runtime
import scoped_native_build as build
import scoped_native_cargo_cache as cache
import seed_local_official_native_target as seed
import rehearse_native_schema_commands as rehearsal

GIB = 1024 ** 3


def memory_api(monkeypatch, callback):
    read = Mock(side_effect=callback)
    library = Mock(return_value=SimpleNamespace(GlobalMemoryStatusEx=read))
    monkeypatch.setattr(runtime, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ctypes, "WinDLL", library, raising=False)
    return library, read


def test_direct_reader_abi_large_value_and_fresh_zero_sample(monkeypatch):
    values = iter([5 * GIB + 17, 0])
    def read(pointer):
        status = pointer._obj
        assert ctypes.sizeof(status) == status.dwLength == 64
        assert [ctypes.sizeof(kind) for _, kind in status._fields_] == [4, 4] + [8] * 7
        assert type(status).ullAvailPhys.offset == 16
        assert type(status).ullAvailExtendedVirtual.offset == 56
        status.ullTotalPhys, status.ullAvailPhys = 16 * GIB, next(values)
        # Commit/virtual values cannot contribute to physical headroom.
        status.ullAvailPageFile = status.ullAvailVirtual = 100 * GIB
        return 1
    library, reader = memory_api(monkeypatch, read)
    assert runtime.available_physical_memory_bytes() == 5 * GIB + 17
    assert runtime.available_physical_memory_bytes() == 0
    assert reader.call_count == 2
    assert reader.restype is ctypes.c_int32 and len(reader.argtypes) == 1
    assert library.call_args.kwargs == {"use_last_error": True}


def test_direct_reader_api_failure_preserves_error_and_no_fallback(monkeypatch):
    memory_api(monkeypatch, lambda pointer: 0)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(ctypes, "WinError", lambda code: OSError(code, "synthetic"), raising=False)
    with pytest.raises(OSError) as failure:
        runtime.available_physical_memory_bytes()
    assert failure.value.errno == 5


@pytest.mark.parametrize("total,available", [(0, 0), (1, 2)])
def test_direct_reader_rejects_impossible_physical_values(monkeypatch, total, available):
    def read(pointer):
        pointer._obj.ullTotalPhys, pointer._obj.ullAvailPhys = total, available
        return 1
    memory_api(monkeypatch, read)
    with pytest.raises(OSError, match="observation is invalid"):
        runtime.available_physical_memory_bytes()


def test_direct_reader_rejects_unsupported_os_before_loading_api(monkeypatch):
    monkeypatch.setattr(runtime, "os", SimpleNamespace(name="posix"))
    loader = Mock(side_effect=AssertionError("No API fallback"))
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    with pytest.raises(OSError, match="requires Windows"):
        runtime.available_physical_memory_bytes()
    loader.assert_not_called()


def test_issuer_copy_and_schema_use_direct_samples_with_unchanged_units(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("Memory admission must not start PowerShell")
    monkeypatch.setattr(build.shutil, "disk_usage", lambda path: SimpleNamespace(free=16 * GIB))
    helper = SimpleNamespace(run=forbidden)
    profile = build.CURRENT_ISSUER_READY_PROFILE
    kib = build.current_issuer_limits(profile)[2]
    monkeypatch.setattr(build, "available_physical_memory_bytes", lambda: kib * 1024)
    assert build.current_issuer_capacity(helper, tmp_path, profile) == kib
    monkeypatch.setattr(build, "available_physical_memory_bytes", lambda: (kib - 1) * 1024)
    with pytest.raises(ValueError, match="CURRENT_ISSUER_HOST_HEADROOM_REQUIRED"):
        build.current_issuer_capacity(helper, tmp_path, profile)
    monkeypatch.setattr(seed.subprocess, "check_output", forbidden)
    monkeypatch.setattr(seed, "available_physical_memory_bytes", lambda: 2 * GIB)
    assert seed.copy_capacity(1, tmp_path) == (16 * GIB, 2 * 1024 ** 2)
    monkeypatch.setattr(seed, "available_physical_memory_bytes", lambda: 2 * GIB - 1024)
    with pytest.raises(ValueError, match="TARGET_COPY_HOST_MEMORY"):
        seed.copy_capacity(1, tmp_path)
    monkeypatch.setattr(rehearsal, "bounded_run", forbidden)
    monkeypatch.setattr(rehearsal, "available_physical_memory_bytes", lambda: 4 * GIB)
    saved = []
    assert rehearsal.capacity({"save": lambda name, value: saved.append(value)}, {}) == 4 * GIB
    assert saved[0]["api"] == "GlobalMemoryStatusEx" and saved[0]["errorClass"] is None


def test_cache_capacity_boundary_reaches_only_existing_docker_boundary(monkeypatch, tmp_path):
    source = tmp_path / "source"
    (source / "rust").mkdir(parents=True)
    revision = "a" * 40
    lock = source / "rust/Cargo.lock"
    lock.write_bytes(chr(10).join(['[[package]]', 'name="marty-core"', 'version="0.0.0"',
                                  'source="git+https://github.com/ElevenID/marty-core?rev=' + revision + '#' + revision + '"', '']).encode())
    # Source admission control only, never a real cache receipt.
    output = tmp_path / "output"
    output.mkdir()
    expected = cache.git_sources(lock.read_bytes())
    script = tmp_path / "fetch.sh"
    script.write_bytes(cache.render_fetch_script(hashlib.sha256(lock.read_bytes()).hexdigest(), expected, None))
    guard = Path(cache.__file__).resolve()
    def ref(path):
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    run = "11111111-1111-4111-8111-111111111111"
    plan = {"sources": {"ui": {"directory": str(source)}, "core": {"revision": revision}},
            "cacheOutputDirectory": str(output), "cacheScript": ref(script),
            "cacheGuard": ref(guard), "cacheRunId": run}
    journal = SimpleNamespace(run_id=run, specification={"backend": "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1"})
    calls = []
    def stop_at_docker(*args):
        assert args[0] == "docker"
        calls.append(args)
        raise RuntimeError("EXISTING_DOCKER_BOUNDARY")
    helper = SimpleNamespace(run=stop_at_docker)
    floor_kib = cache.cache_budget(False)["hostFloorKiB"]
    monkeypatch.setattr(cache.shutil, "disk_usage", lambda path: SimpleNamespace(free=GIB))
    monkeypatch.setattr(cache, "available_physical_memory_bytes", lambda: (floor_kib - 1) * 1024)
    with pytest.raises(ValueError, match="NATIVE_CACHE_CAPACITY_NOT_ADMITTED"):
        cache.hydrate(plan, helper, journal)
    assert not calls
    monkeypatch.setattr(cache, "available_physical_memory_bytes", lambda: floor_kib * 1024)
    with pytest.raises(RuntimeError, match="EXISTING_DOCKER_BOUNDARY"):
        cache.hydrate(plan, helper, journal)
    assert len(calls) == 1
