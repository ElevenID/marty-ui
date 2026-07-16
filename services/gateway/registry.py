"""
Service Registry and Route Configuration.

Maps service names to URLs and defines per-route auth requirements.
"""
from __future__ import annotations

import os
import re
from typing import Any


class ServiceRegistry:
    """Service registry for routing."""

    def __init__(self):
        self._services: dict[str, str] = {}
        self._load_services()

    def _load_services(self) -> None:
        """Load service URLs from environment or defaults."""
        self._services = {
            "auth": os.environ.get("AUTH_SERVICE_URL", "http://localhost:8001"),
            "organizations": os.environ.get("ORGANIZATION_SERVICE_URL", "http://localhost:8002"),
            "credential-templates": os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_URL", "http://localhost:8003"),
            "trust-profiles": os.environ.get("TRUST_PROFILE_SERVICE_URL", "http://localhost:8004"),
            "issuance": os.environ.get("ISSUANCE_SERVICE_URL", "http://localhost:8005"),
            "applicant": os.environ.get("APPLICANT_SERVICE_URL", "http://localhost:8006"),
            "notifications": os.environ.get("NOTIFICATION_SERVICE_URL", "http://localhost:8007"),
            "compliance-profiles": os.environ.get("COMPLIANCE_PROFILE_SERVICE_URL", "http://localhost:8008"),
            "presentation-policies": os.environ.get("PRESENTATION_POLICY_SERVICE_URL", "http://localhost:8009"),
            "deployment-profiles": os.environ.get("DEPLOYMENT_PROFILE_SERVICE_URL", "http://localhost:8010"),
            "signing-keys": os.environ.get("SIGNING_KEYS_SERVICE_URL", "http://localhost:8017"),
            "flows": os.environ.get("FLOW_SERVICE_URL", "http://localhost:8011"),
            "verification": os.environ.get("VERIFICATION_SERVICE_URL", "http://localhost:8012"),
            "revocation-profiles": os.environ.get("REVOCATION_PROFILE_SERVICE_URL", "http://localhost:8013"),
            "device-registration": os.environ.get("DEVICE_REGISTRATION_SERVICE_URL", "http://localhost:8014"),
        }

    def get_service_url(self, service_name: str) -> str | None:
        return self._services.get(service_name)

    def get_all_services(self) -> dict[str, str]:
        return self._services.copy()


_CANVAS_PUBLIC_PATH_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"^/v1/integrations/canvas/lti/jwks/?$",
        r"^/v1/integrations/canvas/lti/config/[^/]+/?$",
        r"^/v1/integrations/canvas/lti/platforms/[^/]+/(?:login|experience-login|launch|experience)/?$",
        r"^/v1/integrations/canvas/oauth/callback/?$",
        r"^/v1/integrations/canvas/lti/experience-sessions/(?:exchange|current(?:/(?:bootstrap|evidence-sync|evidence-status|deep-linking-response))?)/?$",
    )
)


def is_public_canvas_route(path: str) -> bool:
    """Return whether ``path`` is an explicitly public Canvas protocol route."""

    return any(pattern.fullmatch(path) for pattern in _CANVAS_PUBLIC_PATH_PATTERNS)


ROUTE_CONFIG = {
    # Auth routes (no auth required)
    "/v1/auth": {"service": "auth", "requires_auth": False},
    "/v1/organizations/invitations/validate": {"service": "auth", "requires_auth": False},
    "/v1/organizations/join/code/validate": {"service": "organizations", "requires_auth": False},

    # Organization routes
    "/v1/organizations": {"service": "organizations", "requires_auth": True},
    "/v1/api-keys": {"service": "organizations", "requires_auth": True},

    # Digital Identity Model - Configuration Resources
    "/v1/credential-templates": {"service": "credential-templates", "requires_auth": True},
    "/v1/wallet-registry": {"service": "credential-templates", "requires_auth": True},
    "/v1/delivery-destinations": {"service": "credential-templates", "requires_auth": True},
    "/v1/trust-profiles": {"service": "trust-profiles", "requires_auth": True},
    "/v1/issuer-entities": {"service": "trust-profiles", "requires_auth": True},
    "/v1/trust-frameworks": {"service": "trust-profiles", "requires_auth": True},
    "/v1/trust-registry": {"service": "trust-profiles", "requires_auth": False},
    "/v1/compliance-profiles": {"service": "compliance-profiles", "requires_auth": True},
    "/v1/presentation-policies": {"service": "presentation-policies", "requires_auth": True},
    "/v1/deployment-profiles": {"service": "deployment-profiles", "requires_auth": True},
    "/v1/signing-keys": {"service": "signing-keys", "requires_auth": True},
    "/v1/passport": {"service": "issuance", "requires_auth": True},
    "/v1/revocation-profiles": {"service": "revocation-profiles", "requires_auth": True},
    "/v1/revocation-batches": {"service": "revocation-profiles", "requires_auth": True},
    "/v1/cascade-revocations": {"service": "revocation-profiles", "requires_auth": True},
    "/v1/devices": {"service": "device-registration", "requires_auth": True},

    # Digital Identity Model - Operational Resources
    "/v1/me": {"service": "applicant", "requires_auth": True},
    "/v1/issued-credentials": {"service": "issuance", "requires_auth": True},
    # OID4VCI wallet-facing endpoints must be public (no auth token available on wallet)
    "/v1/issuance/offers": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/token": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/credential": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/nonce": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/notification": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/deferred-credential": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/authorize": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/par": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/delivery-records/canvas-credentials/provenance": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/didcomm/deliver": {"service": "issuance", "requires_auth": True},
    "/v1/issuance/didcomm/receive": {"service": "issuance", "requires_auth": False},
    "/v1/issuance": {"service": "issuance", "requires_auth": True},
    # Canvas is authenticated by default. Protocol callbacks and browser handoffs
    # are selected by the exact public allowlist in ``get_route_config`` below.
    "/v1/integrations/canvas": {"service": "issuance", "requires_auth": True},
    "/v1/application-templates": {"service": "issuance", "requires_auth": True},
    "/v1/flows/instances": {"service": "flows", "requires_auth": True},  # wallet-facing /request + /submit handled by _WALLET_PUBLIC regex
    "/v1/flows/siop/submit": {"service": "flows", "requires_auth": False},  # SIOPv2 wallet-facing
    "/v1/flows/siop": {"service": "flows", "requires_auth": True},  # SIOPv2 session creation
    "/v1/flows": {"service": "flows", "requires_auth": True},

    # Utility routes
    "/v1/notifications": {"service": "notifications", "requires_auth": True},
    "/v1/subscriptions": {"service": "notifications", "requires_auth": True},
    "/v1/webhooks": {"service": "notifications", "requires_auth": True},
    # Cedar Policy Sets
    "/v1/policy-sets": {"service": "organizations", "requires_auth": True},
}


def get_route_config(path: str) -> dict[str, Any] | None:
    """Find matching route configuration for a path."""
    if is_public_canvas_route(path):
        return {"service": "issuance", "requires_auth": False}

    for prefix, config in sorted(ROUTE_CONFIG.items(), key=lambda x: -len(x[0])):
        if path.startswith(prefix):
            return config
    return None
