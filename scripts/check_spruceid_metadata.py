"""Check issuer metadata endpoints for SpruceID compatibility."""
import httpx
import json
import urllib3
urllib3.disable_warnings()

org_id = "00000000-0000-0000-0000-000000000001"
base = "https://beta.elevenidllc.com"

urls = [
    f"{base}/org/{org_id}/.well-known/openid-credential-issuer",
    f"{base}/org/{org_id}/spruce/.well-known/openid-credential-issuer",
    f"{base}/.well-known/openid-credential-issuer/{org_id}",
]
for url in urls:
    try:
        r = httpx.get(url, timeout=10, verify=False, follow_redirects=True)
        print(f"{url}: {r.status_code} len={len(r.text)}")
        if r.status_code == 200 and len(r.text) > 50:
            md = r.json()
            configs = md.get("credential_configurations", md.get("credentials_supported", {}))
            print(f"  Top keys: {list(md.keys())[:10]}")
            if isinstance(configs, dict):
                for cid, cc in configs.items():
                    fmt = cc.get("format", "?")
                    print(f"  {cid}: format={fmt}")
            elif isinstance(configs, list):
                for cc in configs:
                    cid = cc.get("id", "?")
                    fmt = cc.get("format", "?")
                    print(f"  {cid}: format={fmt}")
            print()
    except Exception as e:
        print(f"{url}: ERROR {type(e).__name__}: {e}")
