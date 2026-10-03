#!/usr/bin/env python3
"""Issue the selected beta passport chain through staged Gateway authorization."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable

try:
    from .probe_passport_beta_aggregate_kms import (CONTAINER, IDENTIFIER,
                                                    checked_selection, docker_bytes,
                                                    docker_text, require)
    from .probe_passport_beta_chain import (ChainProbeError, exercise_with_authorities,
                                            validate_plan)
    from .probe_passport_beta_host import HostProbeError, inspect
    from .probe_passport_beta_rust_owner_flow import checked_session, signed_service
    from .probe_passport_beta_rust_owner_write import checked_application
except ImportError:
    from probe_passport_beta_aggregate_kms import (CONTAINER, IDENTIFIER,
                                                   checked_selection, docker_bytes,
                                                   docker_text, require)
    from probe_passport_beta_chain import (ChainProbeError, exercise_with_authorities,
                                           validate_plan)
    from probe_passport_beta_host import HostProbeError, inspect
    from probe_passport_beta_rust_owner_flow import checked_session, signed_service
    from probe_passport_beta_rust_owner_write import checked_application


IDENTITY_ROUTE = "/v1/signing-keys/issuer-identities"
CSCA_ROUTE = IDENTITY_ROUTE + "/csca-self-signed-certificate"
DSC_ROUTE = IDENTITY_ROUTE + "/dsc-certificate"
ROUTES = frozenset((IDENTITY_ROUTE, CSCA_ROUTE, DSC_ROUTE))
EXPECTED_DOMAIN = "beta.elevenidllc.com"


def checked_ceremony(path: Path, selection: dict[str, str]) -> tuple[dict[str, Any], str]:
    require(path.is_absolute(), "Beta issuer ceremony path must be absolute")
    try:
        raw = path.read_bytes()
        require(0 < len(raw) <= 8192, "Beta issuer ceremony file is invalid")
        plan = json.loads(raw)
        validate_plan(plan)
    except (OSError, ValueError, ChainProbeError) as exc:
        raise HostProbeError("Beta issuer ceremony file is invalid") from exc
    require(plan["organization_id"] == selection["organization_id"]
            and plan["csca"]["issuer_did"] == selection["csca_issuer_did"]
            and plan["csca"]["certificate_id"] == selection["csca_certificate_id"]
            and plan["dsc"]["dsc_issuer_did"] == selection["dsc_issuer_did"],
            "Beta issuer ceremony differs from selected chain")
    return plan, hashlib.sha256(raw).hexdigest()


def seal_intent(path: Path, expected: dict[str, str]) -> None:
    require(path.is_absolute(), "Beta issuer ceremony intent path must be absolute")
    raw = (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        try:
            recorded = json.loads(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise HostProbeError("Durable beta issuer ceremony intent is unreadable") from exc
        require(recorded == expected,
                "Durable beta issuer ceremony intent differs from this request")
        return
    except OSError as exc:
        raise HostProbeError("Durable beta issuer ceremony intent could not be sealed") from exc
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        raise HostProbeError("Durable beta issuer ceremony intent could not be sealed") from exc


def staged_public_domain(plan: dict[str, Any], runner: Callable[[list[str]], str]) -> str:
    signing_keys = signed_service(plan, "signing-keys", runner)
    record = inspect(signing_keys, runner)
    config = record.get("Config")
    environment = config.get("Env") if isinstance(config, dict) else None
    domains = ([item for item in environment
                if isinstance(item, str) and item.startswith("PUBLIC_DOMAIN=")]
               if isinstance(environment, list) else [])
    require(domains == ["PUBLIC_DOMAIN=" + EXPECTED_DOMAIN]
            and plan.get("beta_origin") == "https://" + EXPECTED_DOMAIN,
            "Staged Signing Keys public domain differs from beta origin")
    return EXPECTED_DOMAIN


def gateway_post(container: str, route: str, organization: str,
                 cookie: str, body: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
    require(CONTAINER.fullmatch(container) is not None
            and IDENTIFIER.fullmatch(organization) is not None
            and route in ROUTES and body.get("organization_id") == organization
            and isinstance(cookie, str) and bool(cookie)
            and not any(character in cookie for character in "\r\n"),
            "Beta issuer Gateway request input is invalid")
    script = (
        'IFS= read -r cookie; [ -n "$cookie" ] || exit 4; '
        'exec curl --silent --show-error --max-time 100 --include '
        '-H "Accept: application/json" -H "Content-Type: application/json" '
        '-H "Cookie: $cookie" --data-binary @- --request POST --url "$1"'
    )
    url = f"http://127.0.0.1:8000{route}?organization_id={organization}"
    payload = (cookie + "\n").encode("utf-8") + json.dumps(
        body, separators=(",", ":")).encode("utf-8")
    response = docker_bytes(["docker", "exec", "-i", container, "sh", "-eu",
                             "-c", script, "sh", url], payload, timeout=120)
    head, separator, content = response.partition(b"\r\n\r\n")
    require(bool(separator) and head.startswith(b"HTTP/1.1 "),
            "Beta issuer Gateway response is invalid")
    try:
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        result = json.loads(content)
    except (IndexError, ValueError) as exc:
        raise HostProbeError("Beta issuer Gateway response is invalid") from exc
    headers = dict(line.split(":", 1) for line in lines[1:] if ":" in line)
    request_id = next((value.strip() for key, value in headers.items()
                       if key.lower() == "x-request-id"), "")
    require(isinstance(result, dict) and 0 < len(request_id) <= 128
            and not any(character in request_id for character in "\r\n"),
            "Beta issuer Gateway response lacks route trace")
    return status, result, request_id


def issue(
    plan: dict[str, Any], application: dict[str, str], selection: dict[str, str],
    ceremony: dict[str, Any], hashes: dict[str, str],
    csca_cookie: str, dsc_cookie: str, intent_path: Path,
    *, runner: Callable[[list[str]], str] = docker_text,
    post: Callable[[str, str, str, str, dict[str, Any]],
                   tuple[int, dict[str, Any], str]] = gateway_post,
) -> dict[str, Any]:
    source = plan.get("source_commit")
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and isinstance(source, str) and len(source) == 40
            and all(character in "0123456789abcdef" for character in source)
            and selection["organization_id"] == application["organization_id"]
            and selection["dsc_issuer_did"] == application["issuer_did"]
            and csca_cookie != dsc_cookie,
            "Beta issuer ceremony source, application, or authorities differ")
    domain = staged_public_domain(plan, runner)
    prefix = f"did:web:{domain}:orgs:"
    require(all(did.startswith(prefix)
                and re.fullmatch(r"[A-Za-z0-9:_-]+", did[len(prefix):]) is not None
                for did in (selection["csca_issuer_did"], selection["dsc_issuer_did"])),
            "Selected beta issuer DIDs are outside staged managed domain")
    gateway = signed_service(plan, "gateway", runner)
    expected = {
        "schema": "marty.passport-beta-aggregate-ceremony-intent/v1",
        "source_commit": source,
        "gateway_container_id": gateway,
        "application_file_sha256": hashes["application"],
        "issuer_chain_file_sha256": hashes["selection"],
        "ceremony_file_sha256": hashes["ceremony"],
    }
    seal_intent(intent_path, expected)
    organization = selection["organization_id"]
    traces: list[str] = []
    for purpose, did, authority in (
        ("csca", selection["csca_issuer_did"], csca_cookie),
        ("x509_doc_signer", selection["dsc_issuer_did"], dsc_cookie),
    ):
        body = {"organization_id": organization, "issuer_did": did,
                "key_purpose": purpose, "credential_format": "ICAO_EMRTD",
                "algorithm": "ES256"}
        status, result, request_id = post(gateway, IDENTITY_ROUTE, organization,
                                          authority, body)
        identity = result.get("identity")
        require(status == 200 and isinstance(identity, dict)
                and all(identity.get(key) == value for key, value in body.items()
                        if key != "organization_id")
                and identity.get("status") == "active",
                "Governed beta issuer profile creation failed")
        traces.append(request_id)

    def request(route: str, body: dict[str, Any], authority: str
                ) -> tuple[int, dict[str, Any]]:
        status, result, request_id = post(gateway, route, organization,
                                          authority, body)
        traces.append(request_id)
        return status, result

    try:
        chain = exercise_with_authorities(ceremony, csca_cookie, dsc_cookie,
                                          request=request)
    except ChainProbeError as exc:
        raise HostProbeError("Governed beta issuer certificate ceremony failed") from exc
    require(chain.get("verified") is True and len(traces) == 4
            and signed_service(plan, "gateway", runner) == gateway,
            "Governed beta issuer ceremony changed during request")
    evidence = chain["evidence"]
    return {
        "schema": "marty.passport-beta-aggregate-ceremony/v1",
        "verified": True, "source_commit": source,
        "gateway_container_id": gateway,
        "application_file_sha256": hashes["application"],
        "issuer_chain_file_sha256": hashes["selection"],
        "ceremony_file_sha256": hashes["ceremony"],
        "intent_file_sha256": hashlib.sha256(intent_path.read_bytes()).hexdigest(),
        "csca_certificate_sha256": evidence["csca_certificate_sha256"],
        "dsc_certificate_sha256": evidence["dsc_certificate_sha256"],
        "gateway_request_traces_verified": True,
        "profile_creation_verified": True,
        "certificate_chain_verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--application-file", required=True, type=Path)
    parser.add_argument("--issuer-chain-file", required=True, type=Path)
    parser.add_argument("--ceremony-file", required=True, type=Path)
    parser.add_argument("--csca-session-file", required=True, type=Path)
    parser.add_argument("--dsc-session-file", required=True, type=Path)
    parser.add_argument("--intent", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        application, application_hash = checked_application(args.application_file)
        selection, selection_hash = checked_selection(args.issuer_chain_file)
        ceremony, ceremony_hash = checked_ceremony(args.ceremony_file, selection)
        csca_cookie = checked_session(args.csca_session_file)
        dsc_cookie = checked_session(args.dsc_session_file)
        result = issue(plan, application, selection, ceremony,
                       {"application": application_hash, "selection": selection_hash,
                        "ceremony": ceremony_hash}, csca_cookie, dsc_cookie, args.intent)
    except (OSError, ValueError, HostProbeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
