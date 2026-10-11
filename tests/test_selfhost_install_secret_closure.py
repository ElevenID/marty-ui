"""No-start ownership checks for a downloaded self-host installation."""

import json
import runpy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
validate = runpy.run_path(str(ROOT / "scripts/check_selfhost_install_secret_closure.py"))["validate"]


def fixture(tmp_path, *, secrets=("required", "optional")):
    compose = tmp_path / "docker-compose.yml"
    catalog = tmp_path / "catalog.json"
    stack = tmp_path / "stack.json"
    examples = tmp_path / "examples"
    examples.mkdir()
    model = {
        "services": {"app": {"secrets": list(secrets)}},
        "secrets": {name: {"file":
                    "${SELFHOST_SECRET_DIR:?SELFHOST_SECRET_DIR must be set}/" + name}
                    for name in secrets},
    }
    specs = {"required": {"compose_secret": "required",
                          "required_for": ["selfhost-production"]},
             "optional": {"compose_secret": "optional", "required_for": [],
                          "allow_empty": True}}
    for name in secrets:
        (examples / name).write_text("placeholder", encoding="utf-8")

    def write():
        compose.write_text(yaml.safe_dump(model), encoding="utf-8")
        catalog.write_text(json.dumps({"secrets": specs}), encoding="utf-8")
        stack.write_text(json.dumps({"required_secrets": ["required"]}), encoding="utf-8")

    write()
    return (compose, catalog, stack, examples), model, specs, write


def test_complete_closure_reports_names_only(tmp_path):
    paths, _, _, _ = fixture(tmp_path)
    result = validate(*paths)
    assert result == {
        "schema": "marty.selfhost-install-secret-closure/v1",
        "qualification": "unqualified",
        "declared_secret_names": ["optional", "required"],
        "required_secret_names": ["required"],
    }
    assert "placeholder" not in json.dumps(result)


def test_unknown_compose_secret_and_missing_stack_owner_fail(tmp_path):
    paths, _, specs, write = fixture(tmp_path)
    del specs["optional"]
    specs["notification"] = {"compose_secret": "notification",
                              "required_for": ["selfhost-production"]}
    write()
    with pytest.raises(ValueError) as error:
        validate(*paths)
    assert "Compose secrets absent from catalog: ['optional']" in str(error.value)
    assert "catalog_not_stack=['notification']" in str(error.value)
    assert "required catalog secrets absent from Compose: ['notification']" in str(error.value)


def test_secret_reference_and_path_must_be_closed(tmp_path):
    paths, model, _, write = fixture(tmp_path)
    model["services"]["app"]["secrets"] = ["required", "unknown"]
    model["secrets"]["required"]["file"] = "/shared/operator-secret"
    write()
    with pytest.raises(ValueError) as error:
        validate(*paths)
    assert "unreferenced=['optional'] undeclared=['unknown']" in str(error.value)
    assert "does not use its isolated file path" in str(error.value)


def test_missing_example_file_fails(tmp_path):
    paths, _, _, _ = fixture(tmp_path)
    (paths[3] / "optional").unlink()
    with pytest.raises(ValueError, match="lacks a regular example file"):
        validate(*paths)


def test_current_source_names_have_closed_ownership():
    result = validate(ROOT / "docker-compose.selfhost.prod.yml",
                      ROOT / "deploy-config/catalog/secrets.json",
                      ROOT / "deploy-config/stacks/selfhost-production.json",
                      ROOT / "docker/secrets/selfhost.example")
    assert result["qualification"] == "unqualified"
    assert set(result["required_secret_names"]) >= {
        "flow_webhook_secret",
        "notification_webhook_secret",
        "notification_applicant_event_token",
        "notification_openbao_token",
    }
