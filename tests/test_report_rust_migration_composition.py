from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "report_rust_migration_composition.py"
SPEC = importlib.util.spec_from_file_location("report_rust_migration_composition", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _repository(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
    root = tmp_path / name
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.name", "Composition Test")
    _git(root, "config", "user.email", "composition@example.invalid")
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "fixture")
    return root


def _ownership(tmp_path: Path, *, second_repository: bool = False) -> Path:
    legacy_repository = "ElevenID/legacy" if second_repository else "ElevenID/example"
    manifest = {
        "schema": "marty.rust-ownership/v1",
        "capabilities": [
            {
                "id": "example-capability",
                "phase": 1,
                "status": "native-active",
                "canonical": {
                    "repository": "ElevenID/example",
                    "paths": ["rust/src"],
                    "binding_paths": ["rust/bindings.rs"],
                },
                "bindings": [
                    {
                        "repository": "ElevenID/example",
                        "paths": ["bridge/src"],
                        "disposition": "ffi-adapter-only",
                    }
                ],
                "legacy": [
                    {
                        "repository": legacy_repository,
                        "paths": ["python/kernel.py"],
                        "language": "python",
                        "disposition": "replace-service-delete",
                    }
                ],
            }
        ],
    }
    path = tmp_path / "ownership.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_reports_tracked_maintained_source_and_ignores_untracked_and_generated(tmp_path):
    repository = _repository(
        tmp_path,
        "repository",
        {
            "rust/src/lib.rs": "fn answer() -> u8 {\n    42\n}\n",
            "rust/bindings.rs": "pub fn binding() {}\n",
            "bridge/src/lib.rs": "pub fn ffi_binding() {}\n",
            "python/kernel.py": "def answer():\n    return 42\n",
            "generated/client.py": "generated = True\n",
        },
    )
    (repository / "untracked.py").write_text("ignored = True\n", encoding="utf-8")

    report = MODULE.build_report(
        _ownership(tmp_path),
        {"ElevenID/example": repository},
        generated_at="2026-08-14T00:00:00+00:00",
    )

    source = report["repositories"]["ElevenID/example"]["source"]
    assert source["languages"]["Rust"]["files"] == 3
    assert source["languages"]["Python"]["files"] == 1
    assert source["excluded_from_maintained_source"]["files"] == 1
    capability = report["capabilities"][0]
    assert capability["canonical"]["source"]["languages"]["Rust"]["files"] == 2
    assert capability["bindings"][0]["source"]["languages"]["Rust"]["files"] == 1
    assert capability["legacy"][0]["source"]["languages"]["Python"]["files"] == 1
    assert report["missing_paths"] == []
    assert report["generated_at"] == "2026-08-14T00:00:00+00:00"


def test_rejects_tracked_changes_by_default(tmp_path):
    repository = _repository(tmp_path, "repository", {"rust/src/lib.rs": "fn one() {}\n"})
    (repository / "rust/src/lib.rs").write_text("fn two() {}\n", encoding="utf-8")

    with pytest.raises(MODULE.ReportError, match="tracked changes"):
        MODULE.inspect_repository(repository)

    inspected, _ = MODULE.inspect_repository(repository, allow_dirty=True)
    assert inspected["dirty"] is True


def test_inventories_runtime_dependency_manifests(tmp_path):
    repository = _repository(
        tmp_path,
        "repository",
        {
            "rust/src/lib.rs": "fn main() {}\n",
            "Cargo.toml": """
[dependencies]
serde = "1"
[dev-dependencies]
criterion = "0.7"
""",
            "requirements-services.txt": "FastAPI==1.0\ncryptography>=2\n-r common.txt\n",
            "pyproject.toml": """
[project]
dependencies = ["PyJWT>=2", "httpx"]
[project.optional-dependencies]
test = ["pytest"]
""",
            "package.json": json.dumps(
                {"dependencies": {"react": "1"}, "devDependencies": {"vitest": "1"}}
            ),
            "pubspec.yaml": """
name: example
dependencies:
  flutter:
    sdk: flutter
  dio: ^5.0.0
dev_dependencies:
  test: any
""",
        },
    )

    inspected, _ = MODULE.inspect_repository(repository)
    dependencies = inspected["dependencies"]

    assert dependencies["cargo"]["unique"] == ["criterion", "serde"]
    assert dependencies["python_requirements"]["unique"] == ["cryptography", "fastapi"]
    assert dependencies["python_pyproject"]["unique"] == ["httpx", "pyjwt", "pytest"]
    assert dependencies["node"]["unique"] == ["react", "vitest"]
    assert dependencies["dart"]["unique"] == ["dio", "flutter", "test"]


def test_requires_every_ownership_repository_when_requested(tmp_path):
    repository = _repository(
        tmp_path,
        "repository",
        {"rust/src/lib.rs": "fn main() {}\n", "rust/bindings.rs": "fn binding() {}\n"},
    )

    with pytest.raises(MODULE.ReportError, match="ElevenID/legacy"):
        MODULE.build_report(
            _ownership(tmp_path, second_repository=True),
            {"ElevenID/example": repository},
            require_all_repositories=True,
        )


def test_reports_missing_owned_paths_without_treating_them_as_success(tmp_path):
    repository = _repository(tmp_path, "repository", {"README.md": "empty\n"})

    report = MODULE.build_report(
        _ownership(tmp_path), {"ElevenID/example": repository}
    )

    assert report["capabilities"][0]["canonical"]["source"]["totals"]["files"] == 0
    assert {item["path"] for item in report["missing_paths"]} == {
        "bridge/src",
        "python/kernel.py",
        "rust/bindings.rs",
        "rust/src",
    }


def test_baseline_delta_reports_language_and_dependency_removals(tmp_path):
    repository = _repository(
        tmp_path,
        "repository",
        {
            "rust/src/lib.rs": "fn main() {}\n",
            "rust/bindings.rs": "fn binding() {}\n",
            "python/kernel.py": "legacy = True\n",
            "requirements.txt": "cryptography\n",
        },
    )
    ownership = _ownership(tmp_path)
    baseline = MODULE.build_report(
        ownership,
        {"ElevenID/example": repository},
        generated_at="2026-08-14T00:00:00+00:00",
    )
    (repository / "python/kernel.py").unlink()
    (repository / "requirements.txt").write_text("", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "remove Python kernel")

    current = MODULE.build_report(
        ownership,
        {"ElevenID/example": repository},
        baseline=baseline,
    )
    delta = current["baseline_delta"]["ElevenID/example"]

    assert delta["languages"]["Python"]["files"] == -1
    assert delta["dependencies"]["python_requirements"]["removed"] == ["cryptography"]
    assert delta["dependencies"]["python_requirements"]["added"] == []
