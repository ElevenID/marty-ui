"""Exercise retained platform execution guards against missing or forged evidence."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import check_platform_unit_execution as lifecycle

spec = importlib.util.spec_from_file_location(
    "platform_artifacts", ROOT / "scripts/ci/verify-platform-test-artifacts.py"
)
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


def test_lifecycle_requires_exact_success_for_every_retained_case():
    lifecycle.validate("\n".join(
        f"test {name} ... ok" for name in lifecycle.LIBRARY_UNIT_REQUIRED_CASES
    ))


@pytest.mark.parametrize("fault", ["missing", "ignored", "failed", "duplicate", "prefix", "suffix"])
def test_lifecycle_rejects_incomplete_or_forged_execution(fault):
    names = sorted(lifecycle.LIBRARY_UNIT_REQUIRED_CASES)
    line = f"test {names[0]} ... ok"
    replacement = {
        "missing": "", "ignored": line.replace("... ok", "... ignored, fixture"),
        "failed": line.replace("... ok", "... FAILED"),
        "duplicate": line + "\n" + line,
        "prefix": "echo " + line, "suffix": line + " unexpected",
    }[fault]
    log = "\n".join([replacement] + [f"test {name} ... ok" for name in names[1:]])
    with pytest.raises(ValueError):
        lifecycle.validate(log)


def fixture(tmp_path, scope):
    target = tmp_path / "target"
    required = {
        "flow_only": (*artifacts.FLOW_TEST_TARGETS, *artifacts.FLOW_BIN_TARGETS),
        "selfhost_only": artifacts.SELFHOST_TEST_TARGETS,
        "renewal_unit_only": artifacts.RENEWAL_UNIT_TEST_TARGETS,
    }[scope]
    records = []
    for package, name, kind in required:
        executable = target / "debug" / (name if kind == "bin" else f"deps/{name}-0123456789abcdef")
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        records.append({
            "reason": "compiler-artifact", "package_id": f"path+file:///fixture#{package}@0.1.0",
            "target": {"name": name, "kind": [kind]},
            "profile": {"test": kind != "bin"}, "executable": str(executable),
        })
    return target, records


@pytest.mark.parametrize("scope", ["flow_only", "selfhost_only", "renewal_unit_only"])
@pytest.mark.parametrize("fault", [None, "missing", "package", "kind", "profile", "outside", "absent", "substitute"])
def test_acceptance_artifacts_bind_scope_package_kind_and_executable(tmp_path, scope, fault):
    target, records = fixture(tmp_path, scope)
    if fault == "missing": records.pop(0)
    elif fault == "package": records[0]["package_id"] = "path+file:///fixture#unrelated@0.1.0"
    elif fault == "kind": records[0]["target"]["kind"] = ["bin"]
    elif fault == "profile": records[0]["profile"]["test"] = "true"
    elif fault == "absent": Path(records[0]["executable"]).unlink()
    elif fault in {"outside", "substitute"}:
        other = (tmp_path / "outside") if fault == "outside" else target / "debug/deps/other-harness"
        other.write_text("#!/bin/sh\nexit 0\n")
        other.chmod(0o755)
        if fault == "outside": records[0]["executable"] = str(other)
        else: records.append({**records[0], "executable": str(other)})
    path = tmp_path / "artifacts.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    if fault:
        with pytest.raises(ValueError): artifacts.verify(path, target, **{scope: True})
    else:
        artifacts.verify(path, target, **{scope: True})


def test_acceptance_rejects_multiple_scope_owners(tmp_path):
    with pytest.raises(ValueError, match="one owner"):
        artifacts.verify(tmp_path / "unused", tmp_path, flow_only=True, selfhost_only=True)
