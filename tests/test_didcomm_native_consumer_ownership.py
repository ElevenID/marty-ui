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
    service = model["services"]["issuance"]
    issuance = service["environment"]
    assert issuance[CONTRACT["owner_selector"]["name"]] == "native"
    assert issuance[CONTRACT["native_origin"]["name"]] == CONTRACT["native_origin"]["value"]
    readiness = CONTRACT["retained_consumer_readiness"]
    assert service["depends_on"][readiness["dependency"]] == {
        "condition": readiness["condition"],
        "required": readiness["required"],
    }
    assert service["healthcheck"]["test"][-1] == (
        f"http://localhost:8005{readiness['path']}"
    )
    assert "issuance-native" in model["services"]


def test_every_declared_compose_consumer_selects_native_without_mode_downgrade() -> None:
    assert CONTRACT["required_modes"] == ["anoncrypt", "authcrypt"]
    assert CONTRACT["downgrade_or_fallback"] == "forbidden"
    for path in CONTRACT["selected_compose_models"]:
        _assert_selected(_model(path))


@pytest.mark.parametrize("path", CONTRACT["selected_compose_models"])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing-owner",
        "legacy",
        "missing-origin",
        "legacy-origin",
        "missing-dependency",
        "weak-dependency",
        "legacy-readiness",
    ],
)
def test_consumer_contract_rejects_partial_or_legacy_selection(path: str, mutation: str) -> None:
    model = deepcopy(_model(path))
    environment = model["services"]["issuance"]["environment"]
    if mutation == "missing-owner":
        environment.pop(CONTRACT["owner_selector"]["name"])
    elif mutation == "legacy":
        environment[CONTRACT["owner_selector"]["name"]] = "legacy"
    elif mutation == "missing-origin":
        environment.pop(CONTRACT["native_origin"]["name"])
    elif mutation == "legacy-origin":
        environment[CONTRACT["native_origin"]["name"]] = "http://issuance:8005"
    elif mutation == "missing-dependency":
        model["services"]["issuance"]["depends_on"].clear()
    elif mutation == "weak-dependency":
        model["services"]["issuance"]["depends_on"]["issuance-native"][
            "condition"
        ] = "service_started"
    else:
        model["services"]["issuance"]["healthcheck"]["test"][-1] = (
            "http://localhost:8005/health"
        )
    with pytest.raises((AssertionError, KeyError)):
        _assert_selected(model)


def test_default_and_selfhost_production_models_remain_legacy() -> None:
    assert CONTRACT["legacy_compose_models"] == [
        "docker-compose.base.yml",
        "docker-compose.selfhost.prod.yml",
    ]
    for path in CONTRACT["legacy_compose_models"]:
        environment = _model(path)["services"]["issuance"]["environment"]
        assert CONTRACT["owner_selector"]["name"] not in environment
        assert CONTRACT["native_origin"]["name"] not in environment


def test_kubernetes_source_does_not_silently_change_production() -> None:
    kubernetes = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            ROOT / "k8s/oracle/01-configmap.yaml",
            ROOT / "k8s/oracle/07-microservices.yaml",
        ]
    )
    assert CONTRACT["owner_selector"]["name"] not in kubernetes
    assert CONTRACT["production_deployment"] == "unchanged"
