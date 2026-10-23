"""Executable public Marty DID inspection and VC-API examples; standard library only."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward API credentials to a redirect destination.
        return None


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
        key = os.environ.get("MARTY_API_KEY")
        bearer = os.environ.get("MARTY_BEARER_TOKEN")
        if bool(key) == bool(bearer):
            parser.error("set exactly one of MARTY_API_KEY or MARTY_BEARER_TOKEN")
        headers.update(
            {"X-API-Key": key} if key else {"Authorization": f"Bearer {bearer}"}
        )
        if args.command != "inspect":
            try:
                credential = json.loads(args.credential.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                parser.error("credential must be a readable JSON file")
        query = {"organization_id": args.organization_id}
        if args.command == "inspect":
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
    request = Request(
        args.base_url.rstrip("/") + path,
        headers=headers,
        data=json.dumps(body).encode() if body is not None else None,
    )
    try:
        with build_opener(NoRedirect).open(request, timeout=30) as response:
            result = json.load(response)
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
