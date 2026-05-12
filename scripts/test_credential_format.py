"""Test credential issuance format to diagnose SpruceID parsing error."""
import httpx, json, uuid, base64

# Step 1: Initiate issuance to get a pre-auth code
resp = httpx.post("http://localhost:8005/v1/issuance/initiate", json={
    "organization_id": "00000000-0000-0000-0000-000000000001",
    "credential_template_id": "50000000-0000-0000-0000-000000000010",
    "applicant_id": str(uuid.uuid4()),
    "subject_did": "",
    "holder_did": "",
    "claims": {"email": "test@example.com"},
}, timeout=10)
data = resp.json()
print(f"Initiate status: {resp.status_code}")
print(f"Keys: {list(data.keys())}")
pre_auth = data.get("pre_auth_code", "")
if not pre_auth:
    print(f"Full response: {json.dumps(data, indent=2)[:500]}")
    exit(1)
print(f"Pre-auth code: {pre_auth[:20]}...")

# Step 2: Get token
token_resp = httpx.post("http://localhost:8005/v1/issuance/token", data={
    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": pre_auth,
}, timeout=10)
print(f"Token status: {token_resp.status_code}")
if token_resp.status_code != 200:
    print(f"Token error: {token_resp.text[:300]}")
    exit(1)
token_data = token_resp.json()
token = token_data.get("access_token", "")
print(f"Got access token: {token[:20]}...")

# Step 3: Request credential with spruce-sd-jwt format
cred_resp = httpx.post("http://localhost:8005/v1/issuance/credential", 
    json={
        "format": "spruce-vc+sd-jwt",
        "credential_configuration_id": "MemberCredential#spruce-sd-jwt",
    },
    headers={"Authorization": f"Bearer {token}"},
    timeout=10,
)
print(f"Credential response status: {cred_resp.status_code}")
if cred_resp.status_code == 200:
    cd = cred_resp.json()
    cred_jwt = cd.get("credential", "")
    # Decode JWT header
    parts = cred_jwt.split(".")
    if len(parts) >= 1:
        padded = parts[0] + "=" * (4 - len(parts[0]) % 4) if len(parts[0]) % 4 else parts[0]
        try:
            header = json.loads(base64.urlsafe_b64decode(padded))
            print(f"JWT header: {json.dumps(header)}")
            print(f"JWT typ: {header.get('typ', 'NOT SET')}")
        except Exception as e:
            print(f"Header decode failed: {e}")
            print(f"JWT header raw: {parts[0][:80]}")
    # Also check response format
    if cd.get("credentials"):
        for c in cd["credentials"]:
            print(f"Response format: {c.get('format')}")
else:
    print(f"Error: {cred_resp.text[:500]}")
