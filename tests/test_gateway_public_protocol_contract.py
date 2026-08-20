import json

from scripts.check_gateway_public_protocol_contract import (
    DTO_SHAPES,
    _assert_rust_behavior_vectors,
)


def test_gateway_public_dto_shape_manifest_is_unique_and_versioned() -> None:
    contract = json.loads(DTO_SHAPES.read_text(encoding="utf-8"))
    assert contract["schema_version"] == 1
    models = contract["models"]
    assert len(models) >= 40
    assert len({model["model"] for model in models}) == len(models)
    assert all(model["schema"].endswith(".json") for model in models)
    assert all(len(model["fields"]) == len(set(model["fields"])) for model in models)


def test_every_gateway_behavior_vector_executes_in_rust() -> None:
    _assert_rust_behavior_vectors()
