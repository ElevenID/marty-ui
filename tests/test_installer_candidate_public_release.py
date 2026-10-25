import hashlib
import os
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_public_release as subject


TAG = "v0.0.0-nightly.20261025.1"
SOURCE = "a" * 40
TAG_SHA = "b" * 40


def fixture():
    assets = [{"name": name, "id": index + 1, "size": 1,
               "digest": "sha256:" + hashlib.sha256(b"x").hexdigest(), "state": "uploaded"}
              for index, name in enumerate(subject.expected_assets())]
    return {
        "releases/tags/" + TAG: {"id": 123, "tag_name": TAG, "draft": False,
                                    "prerelease": True, "immutable": True, "assets": assets},
        "git/ref/tags/" + TAG: {"ref": "refs/tags/" + TAG,
                                  "object": {"type": "tag", "sha": TAG_SHA}},
        "git/tags/" + TAG_SHA: {"sha": TAG_SHA, "tag": TAG,
                                 "object": {"type": "commit", "sha": SOURCE}},
    }


def observe(responses):
    return subject.observe(lambda path: deepcopy(responses[path]), TAG, SOURCE)


def test_observe_immutable_annotated_tag_and_exact_assets(tmp_path):
    snapshot = observe(fixture())
    assert snapshot["immutable"] is True
    assert snapshot["tag_chain"][-1]["sha"] == SOURCE
    assert len(snapshot["assets"]) == 15
    tmp_path.chmod(0o700)
    for item in snapshot["assets"]:
        path = tmp_path / item["name"]
        path.write_bytes(b"x")
        path.chmod(0o600)
    subject.verify_downloads(snapshot, tmp_path)
    (tmp_path / snapshot["assets"][0]["name"]).write_bytes(b"y")
    with pytest.raises(ValueError):
        subject.verify_downloads(snapshot, tmp_path)


@pytest.mark.parametrize("replacement", ["symlink", "fifo", "oversize"])
def test_download_validation_rejects_replaced_file(tmp_path, replacement):
    tmp_path.chmod(0o700)
    snapshot = observe(fixture())
    for item in snapshot["assets"]:
        path = tmp_path / item["name"]
        path.write_bytes(b"x")
        path.chmod(0o600)
    victim = tmp_path / snapshot["assets"][0]["name"]
    victim.unlink()
    if replacement == "symlink":
        victim.symlink_to(tmp_path / snapshot["assets"][1]["name"])
    elif replacement == "fifo":
        os.mkfifo(victim, 0o600)
    else:
        victim.write_bytes(b"xx")
        victim.chmod(0o600)
    with pytest.raises((ValueError, OSError)):
        subject.verify_downloads(snapshot, tmp_path)


@pytest.mark.parametrize("mutate", [
    lambda r: r["releases/tags/" + TAG].update(immutable=False),
    lambda r: r["releases/tags/" + TAG].pop("immutable"),
    lambda r: r["git/tags/" + TAG_SHA]["object"].update(sha="c" * 40),
    lambda r: r["git/ref/tags/" + TAG]["object"].update(sha="c" * 40),
    lambda r: r["releases/tags/" + TAG]["assets"][0].update(digest="sha256:" + "0" * 64),
    lambda r: r["releases/tags/" + TAG]["assets"][0].update(state="starter"),
])
def test_rejects_changed_release_identity(mutate):
    responses = fixture()
    before = observe(responses)
    mutate(responses)
    if responses["releases/tags/" + TAG]["assets"][0]["digest"] == "sha256:" + "0" * 64:
        assert observe(responses) != before
    else:
        with pytest.raises((ValueError, KeyError)):
            observe(responses)
