"""Source-layer boundary checks; native resolved model/ingress tests stay required."""
import json
import runpy
from copy import deepcopy
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
LAYER = "deploy-config/compose/selfhost-installer/compose.external-application.yml"
OIDC_LAYER = "deploy-config/compose/selfhost-installer/compose.external-application-oidc.yml"
PROVIDER = "deploy-config/compose/selfhost-installer/compose.external-oidc.yml"
POSTGRES = "deploy-config/compose/selfhost-installer/compose.external-postgres.yml"


class Reset:
    pass


class Loader(yaml.SafeLoader):
    pass


Loader.add_constructor("!reset", lambda _loader, _node: Reset())


def test_external_application_layer_removes_only_the_local_ui_and_its_edge_upstream():
    layer = yaml.load((ROOT / LAYER).read_text(), Loader=Loader)
    assert set(layer) == {"services"}
    assert set(layer["services"]) == {"ui", "edge"}
    assert isinstance(layer["services"]["ui"], Reset)
    assert set(layer["services"]["edge"]) == {"environment"}
    assert set(layer["services"]["edge"]["environment"]) == {"UI_UPSTREAM"}
    assert isinstance(layer["services"]["edge"]["environment"]["UI_UPSTREAM"], Reset)


def test_external_application_layer_is_an_authenticated_bundle_asset():
    descriptor = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text())
    assert descriptor["assets"].count(LAYER) == 1
    assert descriptor["assets"].count(OIDC_LAYER) == 1


def test_actual_compose_merge_keeps_every_backend_and_removes_no_other_input():
    helpers = runpy.run_path(str(ROOT / "scripts/compose_config_model.py"))
    render = helpers["render"]
    baseline = render("docker-compose.selfhost.prod.yml")
    selected = render("docker-compose.selfhost.prod.yml", LAYER)
    # Compose's no-interpolation model renders a reset environment as a list;
    # normalize only that standard representation before comparing every field.
    selected["services"]["edge"]["environment"] = helpers["environment_mapping"](
        selected["services"]["edge"]["environment"])
    expected = deepcopy(baseline)
    assert expected["services"].pop("ui")
    assert expected["services"]["edge"]["environment"].pop("UI_UPSTREAM") == "ui:80"
    assert selected == expected


def test_external_provider_and_database_keep_both_upstream_resets_and_backend_graph():
    helpers = runpy.run_path(str(ROOT / "scripts/compose_config_model.py"))
    for provider_layers in [(PROVIDER,), (PROVIDER, POSTGRES)]:
        baseline = helpers["render"]("docker-compose.selfhost.prod.yml", *provider_layers)
        selected = helpers["render"]("docker-compose.selfhost.prod.yml", OIDC_LAYER, *provider_layers)
        # Compare environment values, not Compose's map/list serialization.
        for model in [baseline, selected]:
            model["services"]["edge"]["environment"] = helpers["environment_mapping"](
                model["services"]["edge"]["environment"])
        expected = deepcopy(baseline)
        assert expected["services"].pop("ui")
        assert expected["services"]["edge"]["environment"].pop("UI_UPSTREAM") == "ui:80"
        assert "KEYCLOAK_UPSTREAM" not in selected["services"]["edge"]["environment"]
        assert not {"ui", "keycloak", "keycloak-configurator"} & set(selected["services"])
        if POSTGRES in provider_layers:
            assert "postgres" not in selected["services"]
        assert selected == expected
