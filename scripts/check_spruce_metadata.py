"""Check SpruceID metadata endpoint."""
import httpx, json

url = "http://localhost:8000/.well-known/openid-credential-issuer/org/00000000-0000-0000-0000-000000000001/spruce"
r = httpx.get(url, timeout=10)
print(f"Status: {r.status_code}")
if r.status_code == 200:
    md = r.json()
    print(f"Issuer: {md.get('credential_issuer', '?')}")
    configs = md.get("credential_configurations_supported", {})
    for k, v in configs.items():
        fmt = v.get("format", "?")
        print(f"  {k}: format={fmt}")
else:
    print(f"Error: {r.text[:300]}")
