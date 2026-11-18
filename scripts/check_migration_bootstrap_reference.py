#!/usr/bin/env python3
"""Compare a candidate bootstrap with the frozen Python effect/state corpus.

The candidate reads one JSON object from stdin with ``name`` and ``input``.
It writes one JSON object with ``exit_codes``, ``effects``, ``state``, and
``error_tags``. All effects are simulated; the harness supplies no live URLs.
Expected differences are tenant-bound key names, opaque IDs on new public DID
methods, and the managed service being derived from live inventory.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

OUTPUT = Path(__file__).resolve().parents[1] / "contracts/migration-bootstrap-python-reference.json"

STANDARD_KEY_IDS = (
    "cred-issuer-marty-es256", "cred-issuer-marty-es384",
    "cred-issuer-marty-rs256", "lti-tool-marty-rs256",
    "oid4vp-verifier-marty-es256", "cred-issuer-marty-eddsa",
    "cred-dsc-marty-primary",
)
MANAGED_PREFIXES = ("cred-issuer-", "cred-dsc-", "lti-tool-", "oid4vp-verifier-")


def _current_reference(organization_id: str, historical_id: str) -> str:
    prefix = next(prefix for prefix in MANAGED_PREFIXES if historical_id.startswith(prefix))
    tenant = uuid.uuid5(uuid.NAMESPACE_URL, organization_id).hex
    return f"{prefix}{tenant}-{historical_id[len(prefix):]}"


def _scoped_expected(value: object, organization_id: str) -> object:
    """Translate only the intentional Rust tenant-scope divergence."""
    replacements = {
        historical: _current_reference(organization_id, historical)
        for historical in STANDARD_KEY_IDS
    }

    def replace(text: str) -> str:
        for historical, current in replacements.items():
            text = text.replace(historical, current)
        return text

    if isinstance(value, str):
        return replace(value)
    if isinstance(value, list):
        return [_scoped_expected(item, organization_id) for item in value]
    if isinstance(value, dict):
        return {
            replace(key): _scoped_expected(item, organization_id)
            for key, item in value.items()
        }
    return value


def expected_for_case(case: dict) -> dict:
    organization_id = case["input"]["environment"].get(
        "MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001"
    )
    expected = _scoped_expected(
        {key: case[key] for key in ("exit_codes", "effects", "state", "error_tags")},
        organization_id,
    )
    registry_key = f"org:{organization_id}:signing-key-services"
    if any(effect == f"redis.set:{registry_key}" for effect in expected["effects"]):
        registry = expected["state"]["redis"].get(registry_key)
        if isinstance(registry, dict):
            registry["services"] = [
                service for service in registry.get("services", [])
                if service.get("id") != "managed-openbao-transit"
            ]
    initial = _scoped_expected(case["input"].get("initial_redis", {}), organization_id)
    published_ids = {
        method.get("id")
        for document in initial.values() if isinstance(document, dict)
        for method in document.get("verificationMethod", []) if isinstance(method, dict)
    }
    existing_profiles = {
        profile.get("id")
        for document in initial.values() if isinstance(document, dict)
        for profile in document.get("profiles", []) if isinstance(profile, dict)
    }
    method_ids = {}
    documents = expected["state"]["redis"].values()
    keys = expected["state"]["openbao_keys"]
    for document in documents:
        if not isinstance(document, dict):
            continue
        for method in document.get("verificationMethod", []):
            jwk = method.get("publicKeyJwk", {})
            reference = jwk.get("kid")
            did = method.get("controller")
            previous_id = method.get("id")
            if (previous_id in published_ids or reference not in keys
                    or not isinstance(did, str)
                    or not isinstance(previous_id, str)
                    or not previous_id.startswith(f"{did}#")):
                continue
            # Independent reference for the established managed-ID derivation.
            # This adapts newly seeded methods only; published legacy IDs and
            # all JWKS kids remain part of the frozen compatibility contract.
            binding = f"{organization_id}|{did}|managed-openbao-transit|{reference}"
            method_id = f"{did}#managed-{uuid.uuid5(uuid.NAMESPACE_URL, binding).hex[:20]}"
            method_ids[previous_id] = method_id
            method["id"] = method_id
            method["type"] = "JsonWebKey2020"
            jwk.pop("kid")
    for document in documents:
        if not isinstance(document, dict):
            continue
        for relationship in ("assertionMethod", "authentication", "capabilityInvocation", "capabilityDelegation"):
            if relationship in document:
                document[relationship] = [method_ids.get(entry, entry) if isinstance(entry, str) else entry
                                          for entry in document[relationship]]
        for profile in document.get("profiles", []):
            if profile.get("id") not in existing_profiles and "verification_method_id" in profile:
                method_id = profile["verification_method_id"]
                profile["verification_method_id"] = method_ids.get(method_id, method_id)
    return expected


def check(candidate: list[str], contract_path: Path = OUTPUT) -> list[str]:
    reference = json.loads(contract_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    # A candidate must receive only simulated case inputs. In particular,
    # never inherit ambient database, Redis, or OpenBao credentials/URLs.
    safe_env = {key: os.environ[key] for key in
                ("PATH", "SystemRoot", "WINDIR", "PATHEXT", "TMP", "TEMP")
                if key in os.environ}
    safe_env["PYTHONNOUSERSITE"] = "1"
    for case in reference["cases"]:
        organization_id = case["input"]["environment"].get(
            "MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001"
        )
        invocation = {"name": case["name"], "input": case["input"]}
        # The frozen Python corpus had one OpenBao credential. Replay its
        # behavior with the same value assigned to the new dedicated
        # notification role; production requires separately minted tokens.
        invocation = json.loads(json.dumps(invocation))
        old_token = invocation["input"]["environment"].get("OPENBAO_SERVICE_TOKEN")
        if old_token:
            invocation["input"]["environment"]["NOTIFICATION_OPENBAO_TOKEN"] = old_token
        if case["name"] == "conflicting_managed_purpose":
            # Keep the conflict probe current without changing the frozen corpus.
            invocation = _scoped_expected(invocation, organization_id)
        result = subprocess.run(
            candidate, input=json.dumps(invocation), text=True,
            capture_output=True, timeout=30, check=False, env=safe_env,
        )
        if result.returncode:
            failures.append(f"{case['name']}: candidate exited {result.returncode}")
            continue
        try:
            actual = json.loads(result.stdout)
        except ValueError:
            failures.append(f"{case['name']}: candidate output is not JSON")
            continue
        expected = expected_for_case(case)
        if actual != expected:
            differences = [key for key in expected if actual.get(key) != expected[key]]
            failures.append(f"{case['name']}: differs in {', '.join(differences)}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", nargs=argparse.REMAINDER,
                        help="candidate command after --")
    args = parser.parse_args()
    candidate = args.candidate[1:] if args.candidate[:1] == ["--"] else args.candidate
    if not candidate:
        parser.error("provide a candidate command after --")
    failures = check(candidate)
    for failure in failures:
        print(failure, file=sys.stderr)
    count = len(json.loads(OUTPUT.read_text(encoding="utf-8"))["cases"])
    print(f"{count - len(failures)} cases matched")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
