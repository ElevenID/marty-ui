"""Marty-owned deployment contract for governed external event fan-out."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RETIRED_SUBSCRIBER = re.compile(
    r"\b(?:APPLICATION_APPROVED|APPLICATION_REJECTED|IDENTITY_VERIFIED|"
    r"CREDENTIAL_ISSUED|CREDENTIAL_REVOKED|QR_CODE_SCANNED|FLOW_COMPLETED)"
    r"_SUBSCRIBERS\b"
)


def test_supported_deployments_do_not_configure_direct_event_subscribers() -> None:
    paths = [
        ROOT / ".env.example",
        ROOT / ".env.production.example",
        ROOT / ".env.selfhost.production.example",
        ROOT / "docker-compose.base.yml",
        ROOT / "docker-compose.selfhost.prod.yml",
        *sorted((ROOT / "k8s" / "oracle").glob("*.yaml")),
    ]

    configured = [
        str(path.relative_to(ROOT))
        for path in paths
        if path.exists() and RETIRED_SUBSCRIBER.search(path.read_text(encoding="utf-8"))
    ]

    assert configured == [], (
        "direct event subscriber variables bypass Notification's authenticated, "
        f"tenant-bound, signed, minimized, durable egress path: {configured}"
    )
