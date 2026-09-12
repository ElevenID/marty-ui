"""Structural witnesses must not add recursion failures to app observations."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

SPEC = importlib.util.spec_from_file_location(
    "canvas_json_tree_observation",
    Path(__file__).resolve().parents[1] / "scripts" / "canvas_json_tree_observation.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_tree_witness_has_explicit_stable_tokens():
    expected = b'marty.json-tree/v1\n["object",[[97],[98]]]\n["array",2]\n["integer","0"]\n["bool",false]\n["text",[55296]]\n'
    assert MODULE.observe_tree({"b": "\ud800", "a": [0, False]}) == {
        "representation": "marty.json-tree/v1",
        "sha256": hashlib.sha256(expected).hexdigest(),
        "nodes": 5,
        "container_depth": 2,
    }


@pytest.mark.parametrize(
    "left,right",
    [
        (0, 0.0),
        (0.0, -0.0),
        (False, 0),
        (None, "null"),
        ([], {}),
        ([0, 1], [1, 0]),
        ("\ud800\udc00", "\U00010000"),
        (float("inf"), float("-inf")),
        ({"a": 0}, {"b": 0}),
        ({"representation": "marty.json-tree/v1"}, {}),
    ],
)
def test_structurally_distinct_values_never_share_observation(left, right):
    assert MODULE.observe_tree(left)["sha256"] != MODULE.observe_tree(right)["sha256"]


def test_object_insertion_order_is_not_a_json_semantic_difference():
    assert MODULE.observe_tree({"a": 0, "b": [1]}) == MODULE.observe_tree(
        {"b": [1], "a": 0}
    )


def test_witness_does_not_recurse_or_change_interpreter_limits_or_input():
    limit = sys.getrecursionlimit()
    value = 0
    for _ in range(1600):
        value = [value]
    actual = MODULE.observe_tree(value)
    assert actual["nodes"] == 1601
    assert actual["container_depth"] == 1600
    assert sys.getrecursionlimit() == limit
    cursor = value
    for _ in range(1600):
        assert len(cursor) == 1
        cursor = cursor[0]
    assert cursor == 0
    json.dumps(actual, allow_nan=False)


def test_observer_rejects_unsupported_non_json_objects():
    with pytest.raises(TypeError, match="unsupported observation value"):
        MODULE.observe_tree({0, 1})
