"""Executable public Marty profile, DID inspection and VC-API examples; standard library only."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward API credentials to a redirect destination.
        return None


class CompositionError(ValueError):
    """A public profile composition is incomplete or internally inconsistent."""


def read_json(opener, base_url, path, headers):
    request = Request(base_url.rstrip("/") + path, headers=headers)
    with opener.open(request, timeout=30) as response:
        return json.load(response)


def scoped_resource(value, resource_id, organization_id, name, *, allow_system=False):
    if not isinstance(value, dict) or value.get("id") != resource_id:
        raise CompositionError(
            f"{name} response does not identify the requested resource"
        )
    owner = value.get("organization_id")
    if owner != organization_id and not (
        allow_system and owner is None and value.get("is_system") is True
    ):
        raise CompositionError(f"{name} is outside the requested organization")
    return value


def require_reference(value, field, expected, name, *, many=False):
    actual = value.get(field)
    matches = (
        expected in actual if many and isinstance(actual, list) else actual == expected
    )
    if not matches:
        raise CompositionError(f"{name} does not reference the selected {field}")


def load_profile_composition(opener, base_url, organization_id, headers, args):
    public_headers = {"Accept": "application/json"}
    support = read_json(opener, base_url, "/v1/protocol-support", public_headers)
    support_by_id = (
        {
            entry.get("id"): entry
            for entry in support.get("entities", [])
            if isinstance(entry, dict)
        }
        if isinstance(support, dict)
        else {}
    )
    required_support = {
        "trust-profile",
        "compliance-profile",
        "revocation-profile",
        "credential-template",
        "presentation-policy",
        "deployment-profile",
        "flow-definition",
    }
    if any(
        support_by_id.get(entity_id, {}).get("support_level") in {None, "unsupported"}
        for entity_id in required_support
    ):
        raise CompositionError(
            "gateway support discovery does not cover the required composition"
        )

    query = urlencode({"organization_id": organization_id})

    def resource(path, resource_id, name, *, allow_system=False):
        resource_id = str(resource_id).strip()
        if not resource_id:
            raise CompositionError(f"{name} ID is required")
        value = read_json(
            opener,
            base_url,
            f"{path}/{quote(resource_id, safe='')}?{query}",
            headers,
        )
        return scoped_resource(
            value,
            resource_id,
            organization_id,
            name,
            allow_system=allow_system,
        )

    trust = resource("/v1/trust-profiles", args.trust_profile_id, "trust profile")
    template = resource(
        "/v1/credential-templates", args.template_id, "credential template"
    )
    policy = resource(
        "/v1/presentation-policies", args.policy_id, "presentation policy"
    )
    deployment = resource(
        "/v1/deployment-profiles", args.deployment_profile_id, "deployment profile"
    )
    issuance_flow = resource(
        "/v1/flows/definitions", args.issuance_flow_id, "issuance flow"
    )
    verification_flow = resource(
        "/v1/flows/definitions", args.verification_flow_id, "verification flow"
    )

    compliance_id = template.get("compliance_profile_id")
    if not isinstance(compliance_id, str) or not compliance_id:
        raise CompositionError("credential template has no compliance profile")
    compliance = resource(
        "/v1/compliance-profiles",
        compliance_id,
        "compliance profile",
        allow_system=True,
    )
    revocation_id = template.get("revocation_profile_id")
    revocation = None
    if isinstance(revocation_id, str) and revocation_id:
        revocation = resource(
            "/v1/revocation-profiles", revocation_id, "revocation profile"
        )

    for value, name in [
        (template, "credential template"),
        (policy, "presentation policy"),
        (deployment, "deployment profile"),
        (issuance_flow, "issuance flow"),
        (verification_flow, "verification flow"),
    ]:
        require_reference(value, "trust_profile_id", trust["id"], name)
    require_reference(
        deployment,
        "credential_template_ids",
        template["id"],
        "deployment profile",
        many=True,
    )
    require_reference(
        deployment,
        "presentation_policy_ids",
        policy["id"],
        "deployment profile",
        many=True,
    )
    require_reference(
        issuance_flow,
        "credential_template_id",
        template["id"],
        "issuance flow",
    )
    require_reference(
        verification_flow,
        "presentation_policy_id",
        policy["id"],
        "verification flow",
    )
    enabled_flow_ids = deployment.get("enabled_flow_ids", [])
    if not isinstance(enabled_flow_ids, list):
        enabled_flow_ids = []
    for flow, name in [
        (issuance_flow, "issuance flow"),
        (verification_flow, "verification flow"),
    ]:
        flow_deployments = flow.get("deployment_profile_ids", [])
        if not isinstance(flow_deployments, list):
            flow_deployments = []
        linked_from_flow = deployment["id"] in flow_deployments
        linked_from_deployment = flow["id"] in enabled_flow_ids
        if not (linked_from_flow or linked_from_deployment):
            raise CompositionError(
                f"{name} is not linked to the selected deployment profile"
            )

    readiness = read_json(
        opener,
        base_url,
        f"/v1/organizations/{quote(organization_id, safe='')}/runtime/status",
        headers,
    )
    if not isinstance(readiness, dict) or not all(
        readiness.get(field) is True for field in ("can_issue", "can_verify")
    ):
        raise CompositionError("organization runtime is not ready to issue and verify")

    def summary(value):
        return {key: value[key] for key in ("id", "status") if key in value}

    resources = {
        "trust_profile": summary(trust),
        "compliance_profile": summary(compliance),
        "credential_template": summary(template),
        "presentation_policy": summary(policy),
        "deployment_profile": summary(deployment),
        "issuance_flow": summary(issuance_flow),
        "verification_flow": summary(verification_flow),
    }
    if revocation is not None:
        resources["revocation_profile"] = summary(revocation)
    return {
        "organization_id": organization_id,
        "consistent": True,
        "resources": resources,
        "runtime_status": readiness,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        required=True,
        help="Public API origin, optionally with an /api prefix",
    )
    parser.add_argument("--organization-id")
    parser.add_argument("--output", type=Path, help="Write response JSON as UTF-8")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="Fetch the canonical gateway OpenAPI document")
    wallet = commands.add_parser(
        "wallet-profile",
        help="Read a template's derived wallet requirements and overrides",
    )
    wallet.add_argument("--template-id", required=True)
    issue = commands.add_parser(
        "issue", help="Issue through an authorized template and public DID"
    )
    issue.add_argument("--template-id", required=True)
    issue.add_argument("--issuer-did", required=True)
    issue.add_argument("--credential", required=True, type=Path)
    verify = commands.add_parser(
        "verify", help="Verify a signed credential using an authorized policy"
    )
    verify.add_argument("--policy-id", required=True)
    verify.add_argument("--credential", required=True, type=Path)
    inspect = commands.add_parser(
        "inspect", help="Inspect public DID publication and current signer matching"
    )
    inspect.add_argument("--issuer-did", required=True)
    inspect.add_argument("--purpose", required=True)
    inspect.add_argument("--format", required=True)
    inspect.add_argument("--algorithm", required=True)
    composition = commands.add_parser(
        "composition",
        help="Validate one organization-scoped profile/template/deployment/flow composition",
    )
    composition.add_argument("--trust-profile-id", required=True)
    composition.add_argument("--template-id", required=True)
    composition.add_argument("--policy-id", required=True)
    composition.add_argument("--deployment-profile-id", required=True)
    composition.add_argument("--issuance-flow-id", required=True)
    composition.add_argument("--verification-flow-id", required=True)
    args = parser.parse_args()
    parsed = urlsplit(args.base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        parser.error(
            "base-url must be an HTTP(S) API address without credentials, query or fragment"
        )
    headers = {"Accept": "application/json"}
    body = None
    path = "/openapi.json"
    if args.command != "schema":
        if not args.organization_id or not args.organization_id.strip():
            parser.error("organization-id is required for authenticated operations")
        args.organization_id = args.organization_id.strip()
        key = os.environ.get("MARTY_API_KEY")
        bearer = os.environ.get("MARTY_BEARER_TOKEN")
        if bool(key) == bool(bearer):
            parser.error("set exactly one of MARTY_API_KEY or MARTY_BEARER_TOKEN")
        headers.update(
            {"X-API-Key": key} if key else {"Authorization": f"Bearer {bearer}"}
        )
        if args.command in {"issue", "verify"}:
            try:
                credential = json.loads(args.credential.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                parser.error("credential must be a readable JSON file")
        query = {"organization_id": args.organization_id}
        if args.command == "composition":
            pass
        elif args.command == "wallet-profile":
            if not args.template_id.strip():
                parser.error("a credential template ID is required")
            path = f"/v1/credential-templates/{quote(args.template_id, safe='')}/wallet-compatibility"
        elif args.command == "inspect":
            if not args.issuer_did.startswith("did:"):
                parser.error("inspection requires a public issuer DID")
            query.update(
                issuer_did=args.issuer_did,
                key_purpose=args.purpose,
                credential_format=args.format,
                algorithm=args.algorithm,
            )
            path = "/v1/signing-keys/issuer-identities/inspection"
        elif args.command == "issue":
            if not args.issuer_did.startswith("did:") or not isinstance(
                credential, dict
            ):
                parser.error(
                    "issuance requires a public issuer DID and a credential JSON object"
                )
            query.update(
                credential_template_id=args.template_id, issuer_did=args.issuer_did
            )
            body = {"credential": credential}
            path = "/v1/vc-api/credentials/issue"
        else:
            query["presentation_policy_id"] = args.policy_id
            if isinstance(credential, dict) and "verifiableCredential" in credential:
                credential = credential["verifiableCredential"]
            body = {"verifiableCredential": credential}
            path = "/v1/vc-api/credentials/verify"
        path += "?" + urlencode(query)
        headers["Content-Type"] = "application/json"
    try:
        opener = build_opener(NoRedirect)
        if args.command == "composition":
            result = load_profile_composition(
                opener, args.base_url, args.organization_id, headers, args
            )
        else:
            request = Request(
                args.base_url.rstrip("/") + path,
                headers=headers,
                data=json.dumps(body).encode() if body is not None else None,
            )
            with opener.open(request, timeout=30) as response:
                result = json.load(response)
    except CompositionError as error:
        print(f"Composition check failed: {error}.", file=sys.stderr)
        return 1
    except HTTPError as error:
        print(
            f"API returned HTTP {error.code}; inspect organization, permissions, and profile readiness.",
            file=sys.stderr,
        )
        return 1
    except (URLError, ValueError):
        print("API request failed or returned invalid JSON.", file=sys.stderr)
        return 1
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
