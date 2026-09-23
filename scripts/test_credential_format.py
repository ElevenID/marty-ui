"""Test credential issuance format through the route-owning gateway."""

import base64
import json
import uuid

import httpx

if __package__:
    from .operator_gateway import GatewayActorConfigurationError, resolve_gateway_actor
else:
    from operator_gateway import GatewayActorConfigurationError, resolve_gateway_actor


def main(http_client=httpx) -> int:
    try:
        gateway = resolve_gateway_actor(required_scopes=("credentials:issue",))
    except GatewayActorConfigurationError as error:
        print(error)
        return 2
    api_base_url = gateway.base_url
    api_key = gateway.api_key

    # Step 1: Initiate issuance to get a pre-auth code. This is the only gateway
    # operation in this flow that requires the management API key.
    try:
        resp = http_client.post(
            f"{api_base_url}/v1/issuance/initiate",
            json={
                "organization_id": "00000000-0000-0000-0000-000000000001",
                "credential_template_id": "50000000-0000-0000-0000-000000000010",
                "applicant_id": str(uuid.uuid4()),
                "subject_did": "",
                "holder_did": "",
                "claims": {"email": "test@example.com"},
            },
            headers={"X-API-Key": api_key},
            timeout=10,
        )
    except httpx.HTTPError:
        print("Initiation request failed.")
        return 1
    print(f"Initiate status: {resp.status_code}")
    if resp.status_code != 200:
        print("Initiation endpoint rejected the request.")
        return 1
    try:
        data = resp.json()
    except ValueError:
        print("Initiation endpoint returned malformed JSON.")
        return 1
    if not isinstance(data, dict):
        print("Initiation response must be a JSON object.")
        return 1
    print(f"Keys: {list(data.keys())}")
    pre_auth = data.get("pre_auth_code", "")
    if not pre_auth:
        print("Initiation response did not contain a pre-authorization code.")
        return 1
    print("Pre-authorization code received.")

    # Step 2: Get token
    try:
        token_resp = http_client.post(
            f"{api_base_url}/v1/issuance/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": pre_auth,
            },
            timeout=10,
        )
    except httpx.HTTPError:
        print("Token request failed.")
        return 1
    print(f"Token status: {token_resp.status_code}")
    if token_resp.status_code != 200:
        print("Token endpoint rejected the request.")
        return 1
    try:
        token_data = token_resp.json()
    except ValueError:
        print("Token endpoint returned malformed JSON.")
        return 1
    if not isinstance(token_data, dict):
        print("Token response must be a JSON object.")
        return 1
    token = token_data.get("access_token", "")
    if not token:
        print("Token response did not contain an access token.")
        return 1
    print("Access token received.")

    # Step 3: Request the current OID4VCI SD-JWT credential configuration
    try:
        cred_resp = http_client.post(
            f"{api_base_url}/v1/issuance/credential",
            json={
                "credential_configuration_id": "MemberCredential#sd-jwt",
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
    except httpx.HTTPError:
        print("Credential request failed.")
        return 1
    print(f"Credential response status: {cred_resp.status_code}")
    if cred_resp.status_code != 200:
        print("Credential endpoint rejected the request.")
        return 1
    try:
        credential = cred_resp.json()
    except ValueError:
        print("Credential endpoint returned malformed JSON.")
        return 1
    if not isinstance(credential, dict):
        print("Credential response must be a JSON object.")
        return 1
    cred_jwt = credential.get("credential", "")
    parts = cred_jwt.split(".")
    if parts[0]:
        padded = (
            parts[0] + "=" * (4 - len(parts[0]) % 4) if len(parts[0]) % 4 else parts[0]
        )
        try:
            header = json.loads(base64.urlsafe_b64decode(padded))
            print(f"JWT header: {json.dumps(header)}")
            print(f"JWT typ: {header.get('typ', 'NOT SET')}")
        except Exception as error:
            print(f"Header decode failed: {error}")
            print(f"JWT header raw: {parts[0][:80]}")
    if credential.get("credentials"):
        for item in credential["credentials"]:
            print(f"Response format: {item.get('format')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
