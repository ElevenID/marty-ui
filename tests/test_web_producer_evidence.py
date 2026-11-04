"""Producer exports keep original evidence and verify before artifact publication."""
from __future__ import annotations

import pytest

from tests.test_package_web_composition import candidate
import package_web_composition as composition
import web_producer_evidence as evidence
import website_provenance as proof
import website_release as web


def test_retained_subject_and_image_proofs_are_exact_and_reverified(candidate, tmp_path):
    kwargs, calls, _, _ = candidate
    output = tmp_path / "producer-output"
    output.mkdir(mode=0o700)
    source = kwargs["website_assets"]
    for name in ("website-release.json", "website-release.json.sigstore.json"):
        (output / name).write_bytes((source / name).read_bytes())
    release = web.read(source / "website-release.json")
    evidence.retain(output, names=["website-release.json"], producer=release["producer"],
                    release_provenance=source / "website-release.json.provenance.jsonl",
                    image=release["image"], image_provenance=source / "image.provenance.jsonl",
                    gh=kwargs["gh"], cosign=kwargs["cosign"])
    assert (output / "website-release.json.provenance.jsonl").read_bytes() == (source / "website-release.json.provenance.jsonl").read_bytes()
    assert (output / "image.provenance.jsonl").read_bytes() == (source / "image.provenance.jsonl").read_bytes()
    assert [call[0] for call in calls] == ["subject", "image"]


def test_producer_export_refuses_arbitrary_subject_paths(candidate, tmp_path):
    kwargs, calls, _, _ = candidate
    producer = web.read(kwargs["website_assets"] / "website-release.json")["producer"]
    with pytest.raises(ValueError, match="unexpected producer subjects"):
        evidence.retain(tmp_path, names=["../private/src/extension.jsx"], producer=producer,
                        release_provenance=kwargs["website_assets"] / "website-release.json.provenance.jsonl",
                        gh=kwargs["gh"], cosign=kwargs["cosign"])
    assert calls == []
