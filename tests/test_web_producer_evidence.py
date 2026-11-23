"""Producer exports keep original evidence and verify before artifact publication."""
from __future__ import annotations

import pytest

from tests.test_package_web_composition import candidate
import package_web_composition as composition
import web_producer_evidence as evidence
import website_provenance as proof
import website_release as web
from tests.test_website_provenance import verified
import json


@pytest.mark.parametrize("candidate", ["legacy", "standalone"], indirect=True)
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


def test_full_standalone_receipt_and_auxiliary_subjects_keep_website_authority(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    names = ['website-release.json', 'ui.sbom.cdx.json', 'ui-build-evidence.json']
    producer = web.producer('a'*40, None, '21', '1')
    for name in ('gh', 'cosign', 'original.provenance.jsonl', *names,
                 *(name+'.sigstore.json' for name in names)):
        (tmp_path/name).write_bytes(b'inert original producer fixture')
    calls = []
    def run(args):
        calls.append(args)
        return json.dumps(verified(producer)) if args[1] == 'attestation' else 'verified Cosign proof'
    original = proof.verify_subject
    monkeypatch.setattr(proof, 'verify_subject', lambda *args, **kwargs: original(*args, **kwargs, runner=run))
    evidence.retain(tmp_path, names=names, producer=producer,
                    release_provenance=tmp_path/'original.provenance.jsonl',
                    gh=tmp_path/'gh', cosign=tmp_path/'cosign')
    assert [args[1] for args in calls] == ['attestation', 'verify-blob']*3
    for name in names:
        assert (tmp_path/(name+'.provenance.jsonl')).read_bytes() == b'inert original producer fixture'
    assert evidence.subject_role(names) == 'website'
    assert evidence.subject_role(['production-web-release.json', *names[1:]]) == 'application'


@pytest.mark.parametrize('names', [
    ['website-release.json', 'production-web-release.json', 'ui.sbom.cdx.json'],
    ['web-composition.json', 'ui-build-evidence.json'],
    ['ui.sbom.cdx.json', 'ui-build-evidence.json'],
])
def test_auxiliary_names_do_not_authorize_mixed_or_unbound_release_roles(names):
    with pytest.raises(ValueError): evidence.subject_role(names)


@pytest.mark.parametrize("names", [["production-web-release.json"], ["application-web-compatibility.json"],
                                    ["web-composition.json", "web-composition.zip"],
                                    ["website-release.json", "production-web-release.json"]])
def test_standalone_export_rejects_other_roles_before_copying_provenance(candidate, tmp_path, names):
    kwargs, calls, _, _ = candidate
    output = tmp_path / "must-stay-empty"
    output.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        evidence.retain(output, names=names, producer=web.standalone_producer("a" * 40, "124", "2"),
                        release_provenance=kwargs["website_assets"] / "website-release.json.provenance.jsonl",
                        gh=kwargs["gh"], cosign=kwargs["cosign"])
    assert list(output.iterdir()) == [] and calls == []
