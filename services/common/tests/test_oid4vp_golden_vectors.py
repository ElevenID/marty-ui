from __future__ import annotations

import json
from pathlib import Path

import pytest

from common.native_backend import NativeOperationError
from common.oid4vp_native import (
    build_oid4vp_presentation_request,
    initialize_native_oid4vp_backend,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "vectors"
    / "oid4vp_request_builder.json"
)


def test_python_binding_matches_shared_oid4vp_golden_vectors() -> None:
    vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    initialize_native_oid4vp_backend()

    for case in vectors["valid"]:
        assert build_oid4vp_presentation_request(case["request"]) == case["expected"]

    for case in vectors["invalid"]:
        with pytest.raises(NativeOperationError, match=case["error_contains"]):
            build_oid4vp_presentation_request(case["request"])
