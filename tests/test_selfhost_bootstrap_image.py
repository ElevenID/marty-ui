"""Keep the packaged OpenBao bootstrap executable on a reviewed image digest."""

import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
HELPER = "scripts/bootstrap-selfhost-vault.sh"
OPENBAO_IMAGE = (
    "quay.io/openbao/openbao@sha256:"
    "6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
)


def test_packaged_bootstrap_uses_exact_immutable_openbao_image() -> None:
    descriptor = json.loads(
        (ROOT / "deploy-config/bundles/selfhost.json").read_text(encoding="utf-8")
    )
    assert HELPER in descriptor["assets"]
    source = (ROOT / HELPER).read_text(encoding="utf-8")
    assert re.findall(r"quay\.io/openbao/openbao\S*", source) == [OPENBAO_IMAGE]
    assert "quay.io/openbao/openbao:" not in source
    assert "-policy=credential-service" in source
    assert "-policy=notification-webhook-service" in source
    assert "-policy=passport-callback-hmac-service" in source
