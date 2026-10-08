"""Exercise the CI guard against feature and dependency pin regressions."""

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts/ci/check_marty_core_kms_boundary.py"
SPEC = importlib.util.spec_from_file_location("kms_boundary", SCRIPT)
assert SPEC and SPEC.loader
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def reviewed_graph() -> dict:
    packages = [
        {
            "id": name,
            "name": name,
            "version": "0.2.0",
            "source": guard.CORE_SOURCE,
        }
        for name in sorted(guard.CORE_CRATES)
    ]
    packages.append(
        {
            "id": "isomdl",
            "name": "isomdl",
            "version": "0.3.0",
            "source": guard.ISOMDL_SOURCE,
        }
    )
    nodes = [
        {
            "id": package["id"],
            "features": ["kms-only"] if package["name"] in guard.KMS_ONLY_CRATES else [],
        }
        for package in packages
    ]
    return {"packages": packages, "resolve": {"nodes": nodes}}


def test_reviewed_graph_passes() -> None:
    guard.check(reviewed_graph())


@pytest.mark.parametrize("feature", sorted(guard.FORBIDDEN_FEATURES))
def test_core_private_key_features_fail(feature: str) -> None:
    graph = reviewed_graph()
    node = next(node for node in graph["resolve"]["nodes"] if node["id"] == "marty-crypto")
    node["features"].append(feature)
    with pytest.raises(ValueError, match="forbidden features"):
        guard.check(graph)


def test_missing_kms_only_fails() -> None:
    graph = reviewed_graph()
    node = next(node for node in graph["resolve"]["nodes"] if node["id"] == "marty-crypto")
    node["features"].remove("kms-only")
    with pytest.raises(ValueError, match="missing the kms-only feature"):
        guard.check(graph)


@pytest.mark.parametrize("package_name", ["marty-crypto", "isomdl"])
def test_unreviewed_dependency_source_fails(package_name: str) -> None:
    graph = reviewed_graph()
    package = next(package for package in graph["packages"] if package["name"] == package_name)
    package["source"] = package["source"].replace("?rev=", "?rev=unreviewed-")
    with pytest.raises(ValueError, match="reviewed"):
        guard.check(graph)


@pytest.mark.parametrize("feature", ["default", "issuer-local-signing"])
def test_isomdl_local_signing_fails(feature: str) -> None:
    graph = reviewed_graph()
    node = next(node for node in graph["resolve"]["nodes"] if node["id"] == "isomdl")
    node["features"].append(feature)
    with pytest.raises(ValueError, match="local issuer signing"):
        guard.check(graph)
