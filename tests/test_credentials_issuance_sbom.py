from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from scripts.check_credentials_issuance_sbom import (
    IMAGE,
    CredentialsSbomError,
    validate_sbom,
)


DIGEST = "sha256:" + "a" * 64
ROOT_ID = "SPDXRef-DocumentRoot-Image-marty-credentials-issuance"
ROOT = Path(__file__).resolve().parents[1]


def _document() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": IMAGE,
        "packages": [
            {
                "name": IMAGE,
                "SPDXID": ROOT_ID,
                "versionInfo": DIGEST,
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": ROOT_ID,
                "relationshipType": "DESCRIBES",
            }
        ],
    }


def test_exact_spdx_root_binds_the_selected_credentials_digest() -> None:
    validate_sbom(_document(), image=IMAGE, digest=DIGEST)


@pytest.mark.parametrize(
    "mutation",
    [
        "version",
        "document_id",
        "document_name",
        "relationship",
        "extra_root",
        "missing_root",
        "root_name",
        "root_digest",
    ],
)
def test_wrong_or_ambiguous_spdx_identity_fails_closed(mutation: str) -> None:
    document = deepcopy(_document())
    if mutation == "version":
        document["spdxVersion"] = "SPDX-2.2"
    elif mutation == "document_id":
        document["SPDXID"] = "SPDXRef-other"
    elif mutation == "document_name":
        document["name"] = "ghcr.io/elevenid/other"
    elif mutation == "relationship":
        document["relationships"][0]["relationshipType"] = "CONTAINS"
    elif mutation == "extra_root":
        document["relationships"].append(deepcopy(document["relationships"][0]))
    elif mutation == "missing_root":
        document["packages"] = []
    elif mutation == "root_name":
        document["packages"][0]["name"] = "ghcr.io/elevenid/other"
    else:
        document["packages"][0]["versionInfo"] = "sha256:" + "b" * 64
    with pytest.raises(CredentialsSbomError):
        validate_sbom(document, image=IMAGE, digest=DIGEST)


def test_noncanonical_image_or_digest_fails_closed() -> None:
    with pytest.raises(CredentialsSbomError, match="not canonical"):
        validate_sbom(_document(), image="ghcr.io/elevenid/other", digest=DIGEST)
    with pytest.raises(CredentialsSbomError, match="digest is invalid"):
        validate_sbom(_document(), image=IMAGE, digest="sha256:short")


def test_cd_verifies_exact_credentials_image_and_sbom_provenance() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/cd.yml").read_text())
    steps = workflow["jobs"]["validate-stack"]["steps"]
    matches = [
        step
        for step in steps
        if step.get("name") == "Verify immutable Credentials OCI provenance and SBOM"
    ]
    assert len(matches) == 1
    command = matches[0]["run"]

    assert 'source_ref="refs/tags/v${version}"' in command
    assert (
        'signer_workflow="$repository/.github/workflows/release-images.yml"' in command
    )
    assert 'gh attestation verify "oci://$uri@$digest"' in command
    assert 'gh attestation verify "$sbom_file"' in command
    assert command.count('--source-digest "$commit"') == 2
    assert command.count('--source-ref "$source_ref"') == 2
    assert command.count('--signer-workflow "$signer_workflow"') == 2
    assert command.count("--deny-self-hosted-runners") == 2
    assert 'test "$sbom" = "$expected_sbom"' in command
    assert "python scripts/check_credentials_issuance_sbom.py" in command
    assert '--sbom "$sbom_file" --image "$uri" --digest "$digest"' in command
