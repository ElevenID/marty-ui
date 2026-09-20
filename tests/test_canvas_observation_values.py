"""The diagnostic serializer must not change or ambiguously encode app values."""

import importlib.util
import json
import math
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "canvas_observation_values",
    Path(__file__).resolve().parents[1] / "scripts" / "canvas_observation_values.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("\ud800", {"python_codepoints": [55296]}),
        ("\ud800\udc00", {"python_codepoints": [55296, 56320]}),
        ("\U00010000", "\U00010000"),
        (float("nan"), {"python_float": "nan"}),
        (float("inf"), {"python_float": "positive_infinity"}),
        (float("-inf"), {"python_float": "negative_infinity"}),
        (2**53 - 1, 2**53 - 1),
        (2**53, {"python_integer": "9007199254740992"}),
        (-(2**53), {"python_integer": "-9007199254740992"}),
        (True, True),
        (None, None),
        (-0.0, {"python_float": "negative_zero"}),
        (0.0, 0.0),
    ],
)
def test_exceptional_values_have_json_safe_lossless_observations(value, expected):
    actual = MODULE.encode_observation(value)
    assert actual == expected
    json.dumps(actual, allow_nan=False)
    if isinstance(value, float) and value == 0:
        assert (actual == {"python_float": "negative_zero"}) == (
            math.copysign(1, value) < 0
        )


@pytest.mark.parametrize("marker", sorted(MODULE.MARKERS))
def test_literal_marker_objects_cannot_masquerade_as_encoded_values(marker):
    value = {marker: [55296]}
    assert MODULE.encode_observation(value) == {"python_object": [[marker, [55296]]]}
    assert value == {marker: [55296]}


def test_non_scalar_keys_and_nested_values_are_encoded_after_observation_only():
    value = {"before": 1, "\ud800": ["\udc00"], "after": {"ordinary": True}}
    assert MODULE.encode_observation(value) == {
        "python_object": [
            ["before", 1],
            [{"python_codepoints": [55296]}, [{"python_codepoints": [56320]}]],
            ["after", {"ordinary": True}],
        ]
    }
    assert list(value) == ["before", "\ud800", "after"]
    assert value["\ud800"] == ["\udc00"]
