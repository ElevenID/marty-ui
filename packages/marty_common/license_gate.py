"""Command-line entrypoint for Marty runtime license preflight."""

from __future__ import annotations

import sys

from .licensing import (
    LicenseValidationError,
    license_enforcement_enabled,
    validate_runtime_license_from_env,
)


def main() -> int:
    if not license_enforcement_enabled():
        return 0

    try:
        claims = validate_runtime_license_from_env()
    except LicenseValidationError as exc:
        print(f"License validation failed: {exc}", file=sys.stderr)
        return 1

    if claims is None:
        return 0

    org_label = claims.org_name or claims.sub
    expires_at = claims.expires_at.isoformat().replace("+00:00", "Z")
    plan_tier = claims.plan_tier or "unscoped"
    print(
        f"Validated Marty license for {org_label} "
        f"(plan_tier={plan_tier}, expires_at={expires_at})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())