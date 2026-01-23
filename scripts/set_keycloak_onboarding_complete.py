#!/usr/bin/env python3
"""
Set onboarding_completed attribute for seeded Keycloak users.

This ensures seeded test users bypass onboarding and land directly
on their dashboards after login.
"""

import subprocess
import sys

SEEDED_USERS = [
    "john.doe@marty.demo",
    "jane.smith@marty.demo",
    "carlos.garcia@marty.demo",
]

def set_onboarding_completed(email: str):
    """Set onboarding_completed attribute for a user in Keycloak."""
    try:
        # Get user ID
        cmd_get_id = [
            "docker", "compose", "exec", "-T", "keycloak",
            "/opt/keycloak/bin/kcadm.sh", "get", "users",
            "-r", "marty",
            "-q", f"username={email}",
            "--fields", "id"
        ]
        
        result = subprocess.run(cmd_get_id, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        
        # Parse JSON to get ID
        import json
        users = json.loads(output)
        
        if not users:
            print(f"❌ User not found: {email}")
            return False
            
        user_id = users[0]["id"]
        print(f"Found user {email} with ID {user_id}")
        
        # Update user attributes
        cmd_update = [
            "docker", "compose", "exec", "-T", "keycloak",
            "/opt/keycloak/bin/kcadm.sh", "update", f"users/{user_id}",
            "-r", "marty",
            "-s", "attributes.onboarding_completed=true"
        ]
        
        subprocess.run(cmd_update, check=True, capture_output=True)
        print(f"✅ Set onboarding_completed=true for {email}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to update {email}: {e.stderr}")
        return False
    except Exception as e:
        print(f"❌ Error updating {email}: {e}")
        return False

def main():
    print("🔐 Configuring Keycloak admin CLI...")
    
    # Configure kcadm
    cmd_config = [
        "docker", "compose", "exec", "-T", "keycloak",
        "/opt/keycloak/bin/kcadm.sh", "config", "credentials",
        "--server", "http://localhost:8080",
        "--realm", "master",
        "--user", "admin",
        "--password", "admin"
    ]
    
    try:
        subprocess.run(cmd_config, check=True, capture_output=True)
        print("✅ Keycloak admin CLI configured\n")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to configure kcadm: {e.stderr}")
        sys.exit(1)
    
    print("Setting onboarding_completed for seeded users...\n")
    
    success_count = 0
    for email in SEEDED_USERS:
        if set_onboarding_completed(email):
            success_count += 1
        print()
    
    print(f"✅ Updated {success_count}/{len(SEEDED_USERS)} users")
    
    if success_count < len(SEEDED_USERS):
        sys.exit(1)

if __name__ == "__main__":
    main()
