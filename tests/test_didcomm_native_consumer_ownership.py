from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/didcomm-native-consumer-ownership.json").read_text(encoding="utf-8")
)


def _model(path: str) -> dict:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def _assert_selected(model: dict) -> None:
    issuance = model["services"]["issuance"]["environment"]
    assert issuance[CONTRACT["owner_selector"]["name"]] == "native"
    assert issuance[CONTRACT["native_origin"]["name"]] == CONTRACT["native_origin"]["value"]
    assert "issuance-native" in model["services"]


def test_every_declared_compose_consumer_selects_native_without_mode_downgrade() -> None:
    assert CONTRACT["required_modes"] == ["anoncrypt", "authcrypt"]
    assert CONTRACT["downgrade_or_fallback"] == "forbidden"
    for path in CONTRACT["selected_compose_models"]:
        _assert_selected(_model(path))


@pytest.mark.parametrize("path", CONTRACT["selected_compose_models"])
@pytest.mark.parametrize("mutation", ["missing-owner", "legacy", "missing-origin", "legacy-origin"])
def test_consumer_contract_rejects_partial_or_legacy_selection(path: str, mutation: str) -> None:
    model = deepcopy(_model(path))
    environment = model["services"]["issuance"]["environment"]
    if mutation == "missing-owner":
        environment.pop(CONTRACT["owner_selector"]["name"])
    elif mutation == "legacy":
        environment[CONTRACT["owner_selector"]["name"]] = "legacy"
    elif mutation == "missing-origin":
        environment.pop(CONTRACT["native_origin"]["name"])
    else:
        environment[CONTRACT["native_origin"]["name"]] = "http://issuance:8005"
    with pytest.raises((AssertionError, KeyError)):
        _assert_selected(model)


def test_default_base_and_kubernetes_sources_do_not_silently_change_production() -> None:
    base = _model("docker-compose.base.yml")
    assert CONTRACT["owner_selector"]["name"] not in base["services"]["issuance"][
        "environment"
    ]
    kubernetes = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            ROOT / "k8s/oracle/01-configmap.yaml",
            ROOT / "k8s/oracle/07-microservices.yaml",
        ]
    )
    assert CONTRACT["owner_selector"]["name"] not in kubernetes
    assert CONTRACT["production_deployment"] == "unchanged"
