#!/usr/bin/env python3
"""Bootstrap and retire a disposable machine operator through public APIs.

The caller supplies an exact reviewed integration checkout and an existing
synthetic operator identity. This does not provision that identity or qualify
a console-free installation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
from selfhost_handoff_contract import PINNED_INTEGRATION_SHA

JOURNEY = "tests/oss_stack/selfhost_machine_customer_journey.py"
PUBLIC_INPUTS = ("SELFHOST_GATEWAY_URL", "SELFHOST_ORG_ID", "SELFHOST_ISSUER_DID",
                 "SELFHOST_VERIFIER_DID")


def machine_environment(environment: dict[str, str], key_file: Path) -> dict[str, str]:
    # An allowlist also excludes generic TEST_PASSWORD, session, proxy and
    # unrelated service credentials. The machine component rejects browser auth.
    result = {name: value for name, value in environment.items()
              if name in {"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
                          "LANG", "LC_ALL", *PUBLIC_INPUTS}}
    result.update({"SELFHOST_OPERATOR_API_KEY_FILE": str(key_file),
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
    return result


def component(checkout: Path, environment: dict[str, str], key: str) -> None:
    with tempfile.TemporaryDirectory(prefix="marty-machine-operator-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        key_file = root / "operator.key"
        descriptor = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(key)
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "-p", "pytest_asyncio.plugin", JOURNEY], check=False, cwd=checkout,
            env=machine_environment(environment, key_file), capture_output=True,
            text=True, timeout=900,
        )
        # Never relay response bodies, pytest locals or the one-time key.
        if result.returncode:
            raise ValueError("public machine journey component failed")


async def exercise(client: httpx.AsyncClient, checkout: Path,
                   environment: dict[str, str], receipt: Path) -> None:
    org = environment["SELFHOST_ORG_ID"]
    expires = datetime.now(UTC) + timedelta(hours=1)
    created = await client.post("/v1/api-keys", params={"organization_id": org}, json={
        "name": "Installed machine operator " + uuid4().hex,
        "scopes": ["admin:full"], "is_test": True, "expires_at": expires.isoformat(),
    })
    created.raise_for_status()
    metadata = created.json()
    if not isinstance(metadata, dict):
        raise TypeError("public operator key returned invalid metadata")
    key_id = metadata.get("id")
    if (metadata.get("organization_id") != org or not isinstance(key_id, str)
            or str(UUID(key_id)) != key_id):
        raise ValueError("public operator key returned an invalid tenant or identity")
    record = {"schema": "marty.selfhost-machine-operator/v1", "organization_id": org,
              "key_id": key_id, "requested_expires_at": expires.isoformat(),
              "component": "not_run", "retirement": "not_confirmed"}
    valid_key = False
    try:
        key = metadata.get("key")
        valid_key = (isinstance(key, str) and key.startswith("mk_test_")
                     and 8 <= len(key) <= 1024 and key.isascii()
                     and not any(character.isspace() for character in key))
        raw_expiry = metadata.get("expires_at")
        if not isinstance(raw_expiry, str):
            raise TypeError("public operator key omitted its expiry")
        actual_expiry = datetime.fromisoformat(raw_expiry)
        if (metadata.get("scopes") != ["admin:full"]
                or metadata.get("enabled") is not True or not valid_key
                or actual_expiry.tzinfo is None
                or not datetime.now(UTC) < actual_expiry <= expires + timedelta(seconds=1)):
            raise ValueError("public operator key does not match the requested test authority")
        # The runner is synchronous, but cleanup must also cover timeouts/failures.
        await asyncio.to_thread(component, checkout, environment, key)
        record["component"] = "passed"
    finally:
        try:
            retired = await client.delete("/v1/api-keys/" + key_id,
                                          params={"organization_id": org})
            retired.raise_for_status()
            if retired.json() != {"success": True}:
                raise ValueError("public operator retirement was not acknowledged")
            record["retirement"] = "revoked"
            # A fresh client proves the revoked key cannot borrow the PKCE cookie.
            if valid_key:
                async with httpx.AsyncClient(base_url=environment["SELFHOST_GATEWAY_URL"],
                                             trust_env=False, follow_redirects=False,
                                             timeout=30) as probe:
                    rejected = await probe.get("/v1/api-keys", params={"organization_id": org},
                                               headers={"X-API-Key": key})
                if rejected.status_code != 401:
                    raise ValueError("retired public operator key still authenticated")
                record["retirement"] = "revoked_and_rejected"
        finally:
            # Non-secret recovery identity survives a failed component/retirement.
            with receipt.open("x", encoding="utf-8") as output:
                output.write(json.dumps(record, sort_keys=True, indent=2) + "\n")


async def run(checkout: Path, environment: dict[str, str], receipt: Path) -> None:
    from run_selfhost_business_journey import pinned_integration_checkout

    pinned_integration_checkout(checkout, PINNED_INTEGRATION_SHA)
    if not (checkout / JOURNEY).is_file():
        raise ValueError("pinned integration release lacks the machine journey")
    if not receipt.is_absolute() or receipt.exists() or receipt.is_symlink():
        raise ValueError("machine operator receipt must be a fresh absolute path")
    sys.path.insert(0, str(checkout))
    from tests.integration.gateway.helpers.auth_helper import AuthHelper
    from tests.oss_stack.selfhost_customer_journey import required_inputs

    # Validate all explicit inputs using the accepted public journey contract.
    fixture = required_inputs()
    helper = AuthHelper(auth_service_url=fixture["SELFHOST_GATEWAY_URL"],
                        keycloak_local_url=fixture["SELFHOST_KEYCLOAK_URL"],
                        gateway_external_host=fixture["SELFHOST_PUBLIC_DOMAIN"])
    session = await helper.get_session_id(fixture["SELFHOST_TEST_USERNAME"],
                                          fixture["SELFHOST_TEST_PASSWORD"])
    if not session:
        raise ValueError("public machine bootstrap PKCE login failed")
    async with httpx.AsyncClient(base_url=fixture["SELFHOST_GATEWAY_URL"],
                                 cookies={"sessionId": session}, trust_env=False,
                                 follow_redirects=False, timeout=30) as client:
        await exercise(client, checkout, environment, receipt)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration-checkout", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        asyncio.run(run(args.integration_checkout, dict(os.environ), args.receipt))
    except (OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError,
            subprocess.SubprocessError) as error:
        print("public machine wrapper failed: " + type(error).__name__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
