"""JSON-safe observation encoding, applied only AFTER real consumer execution.

Reserved-marker objects are represented as entries too, so literal application
objects cannot masquerade as encoded Python text, floats or object keys.
"""

import math


MARKERS = frozenset(
    {"python_codepoints", "python_float", "python_integer", "python_object"}
)


def encode_observation(value):
    if isinstance(value, float) and value == 0 and math.copysign(1, value) < 0:
        return {"python_float": "negative_zero"}
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and abs(value) > 2**53 - 1
    ):
        return {"python_integer": str(value)}
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            return {"python_codepoints": [ord(character) for character in value]}
        return value
    if isinstance(value, float) and not math.isfinite(value):
        return {
            "python_float": "nan"
            if math.isnan(value)
            else ("positive_infinity" if value > 0 else "negative_infinity")
        }
    if isinstance(value, dict):
        assert all(isinstance(key, str) for key in value)
        if MARKERS.intersection(value) or any(
            any(0xD800 <= ord(character) <= 0xDFFF for character in key)
            for key in value
        ):
            return {
                "python_object": [
                    [encode_observation(key), encode_observation(item)]
                    for key, item in value.items()
                ]
            }
        return {key: encode_observation(item) for key, item in value.items()}
    if isinstance(value, list):
        return [encode_observation(item) for item in value]
    return value
