
import asyncio
import httpx
import os
import sys

async def check_connectivity():
    print("--- Marty Auth Troubleshooter ---")
    
    # Configuration
    internal_issuer = os.environ.get("OIDC_ISSUER_URL", "http://marty-ui-keycloak-1:8080/realms/11id")
    external_issuer = os.environ.get("OIDC_EXTERNAL_ISSUER_URL", "http://localhost:8180/realms/11id")
    
    print(f"Internal Issuer URL: {internal_issuer}")
    print(f"External Issuer URL: {external_issuer}")
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        # Check 1: Connectivity to Internal Issuer
        print("\nChecking connectivity to Internal Issuer...")
        try:
            resp = await client.get(f"{internal_issuer}/.well-known/openid-configuration")
            print(f"Status: {resp.status_code}")
            if resp.status_code == 200:
                config = resp.json()
                print(f"Discovery Issuer: {config.get('issuer')}")
                print(f"Token Endpoint: {config.get('token_endpoint')}")
                print(f"UserInfo Endpoint: {config.get('userinfo_endpoint')}")
            else:
                print(f"Error: {resp.text}")
        except Exception as e:
            print(f"Connection Failed: {e}")
            
        # Check 2: Connectivity to External Issuer (should fail inside container usually)
        print("\nChecking connectivity to External Issuer (Expect Failure)...")
        try:
            resp = await client.get(f"{external_issuer}/.well-known/openid-configuration")
            print(f"Status: {resp.status_code}")
        except Exception as e:
            print(f"Connection Failed (Expected): {e}")

        # Check 3: Check DNS resolution
        import socket
        print("\nDNS Resolution:")
        try:
            host = internal_issuer.split("//")[1].split(":")[0]
            ip = socket.gethostbyname(host)
            print(f"Resolved {host} to {ip}")
        except Exception as e:
            print(f"DNS Resolution Failed for {host}: {e}")

if __name__ == "__main__":
    asyncio.run(check_connectivity())
