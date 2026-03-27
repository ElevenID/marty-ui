#!/usr/bin/env bash
# fetch-secrets.sh - Fetch production secrets from OCI Vault
# Replaces .env.production for deploying marty-ui
# Usage: source scripts/fetch-secrets.sh && docker compose up -d
set -euo pipefail

fetch_secret() {
  local secret_id="$1"
  oci secrets secret-bundle get --secret-id "$secret_id" \
    --query 'data."secret-bundle-content".content' --raw-output 2>/dev/null | base64 -d
}

echo "Fetching production secrets from OCI Vault..."
export CLOUDFLARE_TUNNEL_TOKEN="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hianbewy33vjuxkvlawg3jkjpf7hco4okmucnmzdqrlsq7q")"
export IMAGE_TAG="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiahowwvfwwd6hl6hdm5msk5lrgxesqlowcwzqyvefwznyq")"
export KEYCLOAK_ADMIN="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiasabimhtdmyibniutge2zyuloteyu7hgax6w5uqtzjsia")"
export KEYCLOAK_ADMIN_PASSWORD="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hianqdw27dkndrhris2dyzp5xvo6ciafr5ejtqa7kazyg5a")"
export KEYCLOAK_DB_PASSWORD="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiafk5k32tbew3jimsfakcdljhdtqiri3zqxzoyfdieyypq")"
export MARTY_API_CLIENT_SECRET="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiadeje642vogmztjfd3bfccps2h657t2b5ga4qfzf3hseq")"
export OCIR_AUTH_TOKEN="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiagamwb4docxx5s32wqaupnwi4e44d5hbfgkpkfapg76pq")"
export OCIR_REGISTRY="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiajlutbjyfccuemnzx6pxylfuoerzpyuchfi5ctjtjnjka")"
export OCIR_TENANCY_NAMESPACE="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiaz7ceeswp522nqfa7dg6yair6fvnqt4i7aa7e6qvh4k5a")"
export OCI_REGION="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiankk4cvenyyefu6ucsyw6eox643jugygbiwtszmfaut2a")"
export OCI_USERNAME="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiasye4psdnwo7vmaycpcfsgywnmtlwak5usbg6nfwyy5ga")"
export POSTGRES_PASSWORD="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiaxr6kjqsecrlnx3y3iagmcofg766ymzbja62gmi535jta")"
export RABBITMQ_ERLANG_COOKIE="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiafhihzegvjk2eq5fdzwwqfd3fercm75o7u2xmkshc6afq")"
export RABBITMQ_PASSWORD="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hialcle7fapj7h5ed4loqqvsk2e67ujmgqsxeaj33umsjaa")"
export SESSION_SECRET_KEY="$(fetch_secret "ocid1.vaultsecret.oc1.phx.amaaaaaalr7a5hiagrij33crnofd7jw3cqnvg2hjwjvcgb237cyixkmsnfuq")"

echo "All secrets loaded into environment."
