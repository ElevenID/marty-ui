"""Fail-closed adapter for the canonical Rust presentation-policy kernel."""

from __future__ import annotations

import json
from types import ModuleType
from typing import Any, Mapping

from common.native_backend import (
    NativeBackendUnavailable,
    NativeOperationError,
    get_marty_rs_diagnostics,
    load_marty_rs,
)


NATIVE_POLICY_CAPABILITY = "presentation_policy_service_evaluation"


class NativePolicyEvaluationError(NativeOperationError):
    """The native policy kernel rejected an operation or returned bad output."""


class NativePresentationPolicyEvaluator:
    """Serialize verified facts into the sole supported native binding surface."""

    def __init__(self, backend: ModuleType | Any | None = None) -> None:
        if backend is None:
            backend = load_marty_rs(required_capability=NATIVE_POLICY_CAPABILITY)
            diagnostics = get_marty_rs_diagnostics(
                backend,
                required_capability=NATIVE_POLICY_CAPABILITY,
            )
        else:
            diagnostics = {
                "available": True,
                "backend": "injected-test-backend",
                "version": "test",
                "capabilities": [NATIVE_POLICY_CAPABILITY],
            }

        evaluate = getattr(backend, "evaluate_service_presentation_policy", None)
        if not callable(evaluate):
            raise NativeBackendUnavailable(
                "The Marty Rust backend does not expose "
                "evaluate_service_presentation_policy"
            )
        normalize_format = getattr(
            backend,
            "normalize_presentation_credential_format",
            None,
        )
        if not callable(normalize_format):
            raise NativeBackendUnavailable(
                "The Marty Rust backend does not expose "
                "normalize_presentation_credential_format"
            )
        self._evaluate = evaluate
        self._normalize_format = normalize_format
        self.native_backend_diagnostics = diagnostics

    def normalize_credential_format(self, value: str) -> str:
        try:
            normalized = self._normalize_format(value)
        except Exception as error:
            raise NativePolicyEvaluationError(
                "Native credential-format normalization failed"
            ) from error
        if not isinstance(normalized, str) or not normalized:
            raise NativePolicyEvaluationError(
                "Native credential-format normalization returned an invalid value"
            )
        return normalized

    def evaluate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Evaluate one bounded fact document and validate the native envelope."""
        try:
            request_json = json.dumps(
                request,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError) as error:
            raise NativePolicyEvaluationError(
                "Presentation-policy facts are not valid JSON"
            ) from error

        try:
            raw_result = self._evaluate(request_json)
        except Exception as error:
            raise NativePolicyEvaluationError(
                "Native presentation-policy evaluation failed"
            ) from error

        try:
            result = json.loads(raw_result)
        except (TypeError, ValueError) as error:
            raise NativePolicyEvaluationError(
                "Native presentation-policy evaluation returned malformed JSON"
            ) from error
        if not isinstance(result, dict):
            raise NativePolicyEvaluationError(
                "Native presentation-policy evaluation returned a non-object result"
            )

        required_fields = {
            "result": str,
            "decision": str,
            "decision_reason": str,
            "policy_id": str,
            "policy_name": str,
            "credential_results": list,
            "alternative_results": list,
            "total_requirements": int,
            "satisfied_requirements": int,
            "required_satisfied": int,
            "required_total": int,
            "verified_claims": dict,
            "errors": list,
            "warnings": list,
            "evaluation_time_epoch_seconds": int,
        }
        for field, expected_type in required_fields.items():
            value = result.get(field)
            if isinstance(value, bool) or not isinstance(value, expected_type):
                raise NativePolicyEvaluationError(
                    f"Native presentation-policy result has invalid {field}"
                )
        if result["result"] not in {"passed", "failed", "partial"}:
            raise NativePolicyEvaluationError(
                "Native presentation-policy result has an unknown outcome"
            )
        if result["decision"] not in {"allow", "deny", "manual_review"}:
            raise NativePolicyEvaluationError(
                "Native presentation-policy result has an unknown decision"
            )
        return result
