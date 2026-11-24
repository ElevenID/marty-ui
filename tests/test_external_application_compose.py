"""Source-layer boundary checks; native resolved model/ingress tests stay required."""
import json
import runpy
from copy import deepcopy
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
LAYER = "deploy-config/compose/selfhost-installer/compose.external-application.yml"


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
