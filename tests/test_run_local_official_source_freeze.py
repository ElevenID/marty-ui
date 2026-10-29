"""Focused controls for freezing protected source before local build receipts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_local_official_source", ROOT / "scripts/run_local_official_source.py"
)
assert SPEC and SPEC.loader
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)


def test_freeze_precedes_builds_and_accepts_frozen_main_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    product, harness = tmp_path / "product", tmp_path / "harness"
    (product / "rust").mkdir(parents=True)
    harness.mkdir()
    product_sha, harness_sha, core = "a" * 40, "b" * 40, "c" * 40
    product_tree, harness_tree = "d" * 40, "e" * 40
    official, w3c, eudi = "f" * 40, "1" * 40, "2" * 40
    dependencies = "\n".join(
        f'{name} = {{ git = "https://github.com/ElevenID/marty-core", '
        f'rev = "{core}", default-features = false, features = ["kms-only"] }}'
        for name in source.CORE_CRATES
    )
    (product / "rust/Cargo.toml").write_text("[workspace.dependencies]\n" + dependencies)
    (product / "rust/Cargo.lock").write_text(f"?rev={core}#{core}")
    plan = {
        "imagesBuilt": False, "releaseQualified": False,
        "productCheckout": str(product), "harnessRepository": str(harness),
        "productRevision": product_sha, "productTree": product_tree,
        "harnessRevision": harness_sha, "coreRevision": core,
        "officialRunnerRevision": official, "w3cSuiteRevision": w3c,
        "eudiVerifierRevision": eudi,
        "sourceFreezeReceipt": str(tmp_path / "source-freeze.json"),
    }
    tips = {product: product_sha, harness: harness_sha}

    def git(repo: Path, *args: str) -> str:
        if args == ("remote", "get-url", "origin"):
            name = "marty-ui" if repo == product else "marty-integration-tests"
            return f"https://github.com/ElevenID/{name}.git"
        if args == ("rev-parse", "HEAD") and repo == product:
            return product_sha
        if args == ("rev-parse", "HEAD^{tree}"):
            return product_tree
        if args == ("rev-parse", f"{harness_sha}^{{tree}}") and repo == harness:
            return harness_tree
        if args == ("cat-file", "-t", harness_sha) and repo == harness:
            return "commit"
        if args == ("rev-parse", "origin/main"):
            return tips[repo]
        if args == ("status", "--porcelain", "--untracked-files=all") and repo == product:
            return ""
        if args == ("ls-remote", "origin", "refs/heads/main"):
            return tips[repo] + "\trefs/heads/main"
        if args[0] == "show":
            name = args[1].split(":", 1)[1]
            if name.endswith("oidf-runner.json"):
                return json.dumps({"official_runner": {
                    "source_policy": "unmodified", "commit": official, "release": "v5.3.3"}})
            if name.endswith("w3c-vc-data-model-v2.json"):
                return json.dumps({"official_suite": {"source_policy": "unmodified", "commit": w3c}})
            if name.endswith("eudi-reference-interop.json"):
                return json.dumps({"components": {"verifier_endpoint": {"commit": eudi}}})
        raise AssertionError((repo, args))

    monkeypatch.setattr(source, "git", git)
    monkeypatch.setattr(source.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    proof = source.freeze(plan)
    receipt = Path(plan["sourceFreezeReceipt"])
    assert json.loads(receipt.read_text()) == proof
    assert proof["productRevision"] == product_sha and proof["harnessRevision"] == harness_sha
    # No native, plugin, UI, EUDI, or tooling receipt exists at freeze time.
    tips[product], tips[harness] = "3" * 40, "4" * 40
    assert source.source_proof(plan, require_tip=False) == proof
    with pytest.raises(ValueError, match="live protected tip"):
        source.source_proof(plan, require_tip=True)
    monkeypatch.setattr(source.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=1))
    with pytest.raises(ValueError, match="no longer accepted"):
        source.source_proof(plan, require_tip=False)
