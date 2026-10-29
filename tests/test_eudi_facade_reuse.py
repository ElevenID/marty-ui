"""Real Git/file controls for facade reuse; no Docker, build or official lane."""
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import subprocess

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


overlay = load("canonical_eudi_overlay", SCRIPTS / "local_eudi_overlay.py")
runner = load("maintained_source_preflight", SCRIPTS / "run_local_official_source.py")


@pytest.fixture
def facade(tmp_path):
    repository = tmp_path / "harness"
    repository.mkdir()

    def git(*args, raw=None):
        return subprocess.check_output(["git", "-C", str(repository), *args], input=raw)

    git("init", "-q")
    git("config", "user.name", "Source control fixture")
    git("config", "user.email", "control@example.invalid")
    git("config", "core.autocrlf", "false")
    files = ["Dockerfile", "build.gradle.kts", "settings.gradle.kts", "gradle.lockfile",
             "gradle/verification-metadata.xml", "gradle/wrapper/gradle-wrapper.properties",
             *[f"src/main/kotlin/Part{i}.kt" for i in range(7)]]
    for name in files:
        file = repository / overlay.MODULE_PREFIX / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(("\ntracked bytes " + name + "\n\n").encode())
    git("add", ".")
    git("commit", "-qm", "compiled facade inputs")
    compiled = git("rev-parse", "HEAD").decode().strip()
    inputs = overlay.compilation_inputs(repository, compiled)
    assert len(inputs) == 13
    assert inputs["gradle.lockfile"] == hashlib.sha256(
        (repository / overlay.MODULE_PREFIX / "gradle.lockfile").read_bytes()).hexdigest()
    # A normal Python setup-only commit. It is data, never imported by host.
    (repository / "setup.py").write_text("raise RuntimeError('never execute host harness')\n")
    git("add", ".")
    git("commit", "-qm", "correct shared Python setup")
    selected = git("rev-parse", "HEAD").decode().strip()
    dist = tmp_path / "compiled-dist"
    (dist / "bin").mkdir(parents=True)
    (dist / "bin/eudi-wallet-harness").write_bytes(b"synthetic distribution control")
    artifact = {"state": "PASSED", "exitCode": 0, "sourceReadbackMatched": True,
                "source": compiled, "sourceFiles": inputs, "linuxPath": str(dist),
                "distFiles": {"bin/eudi-wallet-harness": hashlib.sha256(
                    (dist / "bin/eudi-wallet-harness").read_bytes()).hexdigest()}}
    plan = {"harnessRepository": str(repository), "nativeEudiHelper": str(SCRIPTS / "local_eudi_overlay.py"),
            "nativeEudiHelperSha256": runner.EUDI_HELPER_SHA256}
    return tmp_path, repository, git, compiled, selected, artifact, plan


def test_host_and_linux_share_module_proof_without_relabeling_compiled_source(facade):
    base, repository, _, compiled, selected, artifact, plan = facade
    original = deepcopy(artifact)
    assert compiled != selected
    assert runner.eudi_compiled_source(plan, artifact, selected) == compiled
    assert overlay.validate(artifact, base, selected) == Path(artifact["linuxPath"])
    assert artifact == original
    # Host proof reads exact Git blobs even with dirty host files; Linux must
    # independently refuse such a runtime checkout before installing an overlay.
    (repository / overlay.MODULE_PREFIX / "build.gradle.kts").write_bytes(b"host dirty user bytes")
    assert runner.eudi_compiled_source(plan, artifact, selected) == compiled
    with pytest.raises(AssertionError):
        overlay.validate(artifact, base, selected)


@pytest.mark.parametrize("change", ["code", "lock", "verification", "add", "remove"])
def test_module_changes_require_a_new_real_build(facade, change):
    _, repository, git, _, _, artifact, plan = facade
    module = repository / overlay.MODULE_PREFIX
    if change == "remove":
        (module / "src/main/kotlin/Part0.kt").unlink()
    elif change == "add":
        (module / "new-input.txt").write_text("new input\n")
    else:
        name = {"code": "src/main/kotlin/Part0.kt", "lock": "gradle.lockfile",
                "verification": "gradle/verification-metadata.xml"}[change]
        (module / name).write_text("changed input\n")
    git("add", "-A")
    git("commit", "-qm", "changed JVM input")
    selected = git("rev-parse", "HEAD").decode().strip()
    with pytest.raises(AssertionError, match="inputs differ"):
        runner.eudi_compiled_source(plan, artifact, selected)


def test_non_regular_git_input_and_forged_helper_are_refused(facade, tmp_path):
    _, _, git, _, selected, artifact, plan = facade
    oid = git("hash-object", "-w", "--stdin", raw=b"outside-target").decode().strip()
    git("update-index", "--add", "--cacheinfo", "120000," + oid + "," + overlay.MODULE_PREFIX + "link")
    git("commit", "-qm", "nonregular module input")
    with pytest.raises(AssertionError, match="regular Git blobs"):
        overlay.compilation_inputs(Path(plan["harnessRepository"]), git("rev-parse", "HEAD").decode().strip())
    foreign = tmp_path / "foreign-helper.py"
    foreign.write_text("raise RuntimeError('must never execute')\n")
    with pytest.raises(ValueError, match="pinned file changed"):
        runner.eudi_compiled_source({**plan, "nativeEudiHelper": str(foreign)}, artifact, selected)


@pytest.mark.parametrize("change", ["missing-input", "missing-map", "failed", "unknown-source", "not-read-back"])
def test_incomplete_compilation_receipts_are_not_reuse_proof(facade, change):
    _, _, _, _, selected, artifact, plan = facade
    if change == "missing-input":
        artifact["sourceFiles"].pop("gradle.lockfile")
    elif change == "missing-map":
        del artifact["sourceFiles"]
    elif change == "failed":
        artifact["exitCode"] = 1
    elif change == "unknown-source":
        artifact["source"] = "not-a-compiled-commit"
    else:
        artifact["sourceReadbackMatched"] = False
    with pytest.raises(AssertionError):
        runner.eudi_compiled_source(plan, artifact, selected)


@pytest.mark.parametrize("change", ["bytes", "extra", "outside"])
def test_real_linux_distribution_closure_is_retained(facade, tmp_path, change):
    base, _, _, _, selected, artifact, _ = facade
    if change == "bytes":
        (Path(artifact["linuxPath"]) / "bin/eudi-wallet-harness").write_text("changed")
    elif change == "extra":
        (Path(artifact["linuxPath"]) / "extra.jar").write_text("unexpected")
    else:
        artifact["linuxPath"] = str(tmp_path.parent / "outside-facade")
    with pytest.raises(AssertionError):
        overlay.validate(artifact, base, selected)
