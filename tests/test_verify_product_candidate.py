"""Installed candidate payloads must fail closed on tampering and unsafe paths."""

import hashlib
import io
import json
import runpy
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/product_package_plan.py"))
VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_product_candidate.py"))


def candidate(tmp_path: Path, product: str) -> tuple[Path, Path]:
    plan = BUILDER["build_plan"](ROOT, product, "a" * 40)
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    for image in plan["images"]:
        (receipts / (image["role"] + ".json")).write_text(
            json.dumps({
                "product": product, "version": plan["version"],
                "source_sha": plan["source_sha"], "role": image["role"],
                "image": image["image"], "digest": "sha256:" + "e" * 64,
                "run_id": "123", "run_attempt": "2",
            }), encoding="utf-8")
    package = BUILDER["assemble_package"](ROOT, plan, receipts, "123", "2")
    bundle = tmp_path / "bundle"
    BUILDER["write_bundle"](ROOT, plan, package, bundle)
    archive = tmp_path / "product-package.tar.gz"
    BUILDER["write_archive"](bundle, archive)
    return archive, tmp_path / "product-package.tar.gz.sha256"


@pytest.mark.parametrize("product", ["marty-server", "marty-console"])
def test_real_builder_archive_is_portable_and_exact(tmp_path, product):
    archive, checksum = candidate(tmp_path, product)
    result = VERIFIER["verify"](archive, checksum, product, "123", "2", "a" * 40)
    assert result["result"] == "pass"
    assert result["producer_run_attempt"] == "2"
    assert len(result["images"]) == (4 if product == "marty-server" else 1)


def test_changed_checksum_or_source_blocks_verification(tmp_path):
    archive, checksum = candidate(tmp_path, "marty-console")
    with pytest.raises(ValueError, match="source or producer"):
        VERIFIER["verify"](archive, checksum, "marty-console", "124", "2", "a" * 40)
    checksum.write_text("0" * 64 + "  product-package.tar.gz\n", encoding="utf-8")
    with pytest.raises(ValueError, match="adjacent archive checksum"):
        VERIFIER["verify"](archive, checksum, "marty-console", "123", "2", "a" * 40)


def test_path_traversal_is_rejected_before_extraction(tmp_path):
    archive = tmp_path / "product-package.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        payload = b"outside"
        item = tarfile.TarInfo("../outside.txt")
        item.size = len(payload)
        item.mode = 0o644
        bundle.addfile(item, io.BytesIO(payload))
    checksum = tmp_path / "product-package.tar.gz.sha256"
    checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()
                        + "  product-package.tar.gz\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe archive path"):
        VERIFIER["verify"](archive, checksum, "marty-console", "123", "2", "a" * 40)
