"""Cedar policy evaluation engine for Marty microservices.

Wraps the cedarpy library (PyO3 binding to the Rust cedar-policy crate)
to provide in-process Cedar authorization evaluation.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import cedarpy

logger = logging.getLogger(__name__)

_CEDAR_DIR = Path(__file__).parent / "cedar"


@dataclass(frozen=True)
class AuthzDecision:
    """Result of a Cedar authorization evaluation."""

    allowed: bool
    reasons: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class CedarEngine:
    """Cedar policy evaluation engine.

    Evaluates authorization requests against MIP Cedar policies and entities
    using the Rust-backed cedarpy engine (~100μs per evaluation).
    """

    def __init__(self, schema: str, policies: str):
        self._schema = schema
        self._policies = policies

    @classmethod
    def from_files(
        cls,
        schema_path: str | Path,
        policy_paths: list[str | Path],
    ) -> "CedarEngine":
        """Load schema and policies from filesystem paths.

        Args:
            schema_path: Path to .cedarschema file.
            policy_paths: Paths to .cedar files or directories containing them.
        """
        schema = Path(schema_path).read_text()
        policy_parts: list[str] = []
        for p in policy_paths:
            path = Path(p)
            if path.is_dir():
                for f in sorted(path.glob("*.cedar")):
                    policy_parts.append(f.read_text())
            elif path.exists():
                policy_parts.append(path.read_text())
        return cls(schema=schema, policies="\n\n".join(policy_parts))

    @classmethod
    def with_defaults(cls) -> "CedarEngine":
        """Create engine with bundled MIP schema and default gateway RBAC policies.

        Loads only protocol-standard MIP authorization. Billing/plan-tier
        feature gating is handled by a separate BillingCedarEngine.
        """
        schema = (_CEDAR_DIR / "mip.cedarschema").read_text()
        policies = (_CEDAR_DIR / "gateway_policies.cedar").read_text()
        return cls(schema=schema, policies=policies)

    @classmethod
    def with_credential_verification(cls) -> "CedarEngine":
        """Create engine with gateway RBAC policies + credential verification trust rules.

        Used by the presentation-policy service for credential-level
        authorization during VP token evaluation.
        """
        engine = cls.with_defaults()
        verification_policies = (
            _CEDAR_DIR / "credential_verification.cedar"
        ).read_text()
        engine.append_policies(verification_policies)
        return engine

    @classmethod
    def with_approval_rules(cls) -> "CedarEngine":
        """Create engine with only MIP approval-rule policies.

        Approval flows evaluate provider-neutral facts and should not inherit
        broad gateway RBAC permits such as organization API-key full access.
        """
        schema = (_CEDAR_DIR / "mip.cedarschema").read_text()
        policies = (_CEDAR_DIR / "approval_rules.cedar").read_text()
        return cls(schema=schema, policies=policies)

    @classmethod
    def with_approval_policy_text(cls, policies: str) -> "CedarEngine":
        """Create engine with caller-provided approval-rule policies only."""
        schema = (_CEDAR_DIR / "mip.cedarschema").read_text()
        return cls(schema=schema, policies=policies)

    @property
    def policies(self) -> str:
        return self._policies

    @policies.setter
    def policies(self, value: str):
        self._policies = value

    def append_policies(self, additional: str):
        """Append additional Cedar policies to the current policy set."""
        self._policies = self._policies + "\n\n" + additional

    def is_authorized(
        self,
        principal: str,
        action: str,
        resource: str,
        context: dict[str, Any],
        entities: list[dict[str, Any]],
    ) -> AuthzDecision:
        """Evaluate a Cedar authorization request.

        Args:
            principal: Cedar entity UID, e.g. 'MIP::User::"user-123"'
            action: Cedar action, e.g. 'MIP::Action::"credentials:read"'
            resource: Cedar entity UID, e.g. 'MIP::Organization::"org-456"'
            context: Context record matching the action's context type.
            entities: List of Cedar entity dicts with uid, attrs, parents.

        Returns:
            AuthzDecision with allowed flag, matching policy reasons, and errors.
        """
        request = {
            "principal": principal,
            "action": action,
            "resource": resource,
            "context": context,
        }

        try:
            result = cedarpy.is_authorized(
                request, self._policies, json.dumps(entities), self._schema
            )
            return AuthzDecision(
                allowed=result.allowed,
                reasons=list(result.diagnostics.reasons)
                if result.diagnostics.reasons
                else [],
                errors=list(result.diagnostics.errors)
                if result.diagnostics.errors
                else [],
            )
        except Exception as e:
            logger.error(f"Cedar evaluation error: {e}", exc_info=True)
            # Fail closed — deny on evaluation error
            return AuthzDecision(allowed=False, errors=[str(e)])
