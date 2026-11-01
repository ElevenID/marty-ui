import copy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from beta_release_metadata import gateway_metadata_model, ui_metadata_model, TARGET


def test_new_gateway_release_cannot_inherit_previous_revision_or_image_claims():
    old = {
        "services": {
            "gateway": {
                "image": "immutable-signed-image",
                "environment": {
                    "ELEVENID_COMPONENT_REVISIONS_JSON": '{"old":"a"}',
                    "ELEVENID_IMAGE_DIGESTS_JSON": '{"old":"b"}',
                    "NON_METADATA": "SOURCE_ONLY",
                },
            }
        },
        "unrelated": {"keep": True},
    }
    before = copy.deepcopy(old)
    marker = {
        "component_revisions": {"marty-ui": "f" * 40},
        "image_digests": {"gateway": "sha256:" + "1" * 64},
    }
    new = gateway_metadata_model(old, marker)
    assert old == before
    assert (
        json.loads(
            new["services"]["gateway"]["environment"][
                "ELEVENID_COMPONENT_REVISIONS_JSON"
            ]
        )
        == marker["component_revisions"]
    )
    assert (
        json.loads(
            new["services"]["gateway"]["environment"]["ELEVENID_IMAGE_DIGESTS_JSON"]
        )
        == marker["image_digests"]
    )
    restored = copy.deepcopy(new)
    for key in ("ELEVENID_COMPONENT_REVISIONS_JSON", "ELEVENID_IMAGE_DIGESTS_JSON"):
        restored["services"]["gateway"]["environment"][key] = old["services"][
            "gateway"
        ]["environment"][key]
    assert restored == old


def test_ui_adds_only_the_one_public_readonly_file():
    old = {"services": {"ui-prod": {"image": "signed-ui", "volumes": []}}}
    new = ui_metadata_model(old, "C:/public/bound-manifest.json")
    assert old["services"]["ui-prod"]["volumes"] == []
    assert new["services"]["ui-prod"]["volumes"] == [
        dict(
            type="bind",
            source="C:/public/bound-manifest.json",
            target=TARGET,
            read_only=True,
            bind={},
        )
    ]
    try:
        ui_metadata_model(new, "C:/public/another.json")
    except ValueError:
        pass
    else:
        raise AssertionError("Existing public override cannot be silently replaced")
