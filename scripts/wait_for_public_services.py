"""Wait for the public gateway's required downstream-service health contract."""

from __future__ import annotations

import argparse
import json
import time
from urllib.error import URLError
from urllib.request import urlopen


REQUIRED_SERVICES = frozenset({
    "auth", "organizations", "credential-templates", "trust-profiles",
    "compliance-profiles", "presentation-policies", "deployment-profiles",
    "flows", "issuance", "revocation-profiles",
})


def unhealthy_services(payload: object) -> set[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), dict):
        return set(REQUIRED_SERVICES)
    services = payload["services"]
    return {
        name for name in REQUIRED_SERVICES
        if not isinstance(services.get(name), dict) or services[name].get("status") != "healthy"
    }


def wait_for_services(url: str, timeout: float, poll_interval: float = 2.0) -> set[str]:
    deadline = time.monotonic() + timeout
    last_unhealthy = set(REQUIRED_SERVICES)
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=5) as response:  # noqa: S310 -- caller supplies local release endpoint
                last_unhealthy = unhealthy_services(json.load(response))
            if not last_unhealthy:
                return set()
        except (URLError, TimeoutError, json.JSONDecodeError):
            pass
        time.sleep(poll_interval)
    return last_unhealthy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    unhealthy = wait_for_services(args.url, args.timeout)
    if unhealthy:
        print(f"Timed out waiting for required public services: {', '.join(sorted(unhealthy))}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
