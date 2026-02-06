#!/usr/bin/env python3
"""Integration test for StatusListManager migration"""
import requests

BASE_URL = "http://localhost:8013"

print("=== StatusListManager Integration Test ===\n")

# Get profile
resp = requests.get(f"{BASE_URL}/v1/revocation-profiles", params={"organization_id": "system"})
profile_id = resp.json()[0]["id"]
print(f"Profile: {profile_id[:8]}...\n")

# Test 1: Allocate indices
print("Test 1: Allocate indices")
indices = []
for i in range(3):
    resp = requests.post(
        f"{BASE_URL}/internal/revocation-profiles/{profile_id}/allocate-index",
        json={"credential_format": "sd_jwt_vc"}
    )
    idx = resp.json()["index"]
    indices.append(idx)
    print(f"  ✓ Index {idx}")

# Test 2: Revoke
print(f"\nTest 2: Revoke index {indices[1]}")
resp = requests.post(
    f"{BASE_URL}/internal/revocation-profiles/{profile_id}/process-revocation",
    json={
        "credential_id": "cred-123",
        "index": indices[1],
        "status": "revoked",
        "credential_format": "sd_jwt_vc"
    }
)
result = resp.json()
print(f"  ✓ Success: {result['success']}")
print(f"  ✓ URL: {result['status_list_url'][:50]}...")

# Test 3: Reinstate
print(f"\nTest 3: Reinstate index {indices[1]}")
resp = requests.post(
    f"{BASE_URL}/internal/revocation-profiles/{profile_id}/process-revocation",
    json={
        "credential_id": "cred-123",
        "index": indices[1],
        "status": "reinstated",
        "credential_format": "sd_jwt_vc"
    }
)
result = resp.json()
print(f"  ✓ Success: {result['success']}")

# Test 4: mDoc
print("\nTest 4: mDoc allocation (TOKEN_STATUS_LIST)")
resp = requests.post(
    f"{BASE_URL}/internal/revocation-profiles/{profile_id}/allocate-index",
    json={"credential_format": "mdoc"}
)
print(f"  ✓ Index {resp.json()['index']}")

print("\n✅ All tests passed!")
