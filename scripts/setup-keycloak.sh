#!/usr/bin/env bash
# =============================================================================
# setup-keycloak.sh — Keycloak post-startup configurator
# =============================================================================
# Patches Keycloak via kcadm after realm import so that runtime env vars
# (GOOGLE_CLIENT_ID, PUBLIC_DOMAIN, etc.) are applied correctly.
#
# The realm JSON cannot rely on ${env.VAR} substitution for data fields —
# Keycloak only resolves those for SPI/startup config, not for realm JSON
# identity provider or client data stored in the database.
#
# Usage:
#   Inside container (KC_URL=http://keycloak:8080): called by keycloak-configurator
#   From host (KC_URL=http://localhost:8180): called by 'make setup-keycloak'
# =============================================================================
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
KC_URL="${KC_URL:-http://localhost:8180}"
REALM="${KEYCLOAK_REALM:-11id}"
ADMIN="${KEYCLOAK_ADMIN:-admin}"
PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
GOOGLE_CID="${GOOGLE_CLIENT_ID:-}"
GOOGLE_SEC="${GOOGLE_CLIENT_SECRET:-}"
PUBLIC_DOMAIN="${PUBLIC_DOMAIN:-}"
UI_BASE_URL="${UI_BASE_URL:-}"
MARTY_API_SECRET="${MARTY_API_CLIENT_SECRET:-}"
KCADM="${KCADM_PATH:-/opt/keycloak/bin/kcadm.sh}"

# Retry configuration
MAX_RETRIES=60
RETRY_DELAY=2

# ─── Logging Utilities ───────────────────────────────────────────────────────
log_info() {
    echo "[INFO] $*"
}

log_warning() {
    echo "[WARN] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_success() {
    echo "[✓] $*"
}

# ─── Helper Functions ────────────────────────────────────────────────────────
cleanup_temp_files() {
    if [ -n "${TEMP_FILES:-}" ]; then
        for file in $TEMP_FILES; do
            [ -f "$file" ] && rm -f "$file"
        done
    fi
}

trap cleanup_temp_files EXIT

create_temp_file() {
    local temp_file
    temp_file=$(mktemp /tmp/kc-setup-XXXXXX.json)
    TEMP_FILES="${TEMP_FILES:-} $temp_file"
    echo "$temp_file"
}

kcadm_safe() {
    local output
    local exit_code
    
    if output=$("$KCADM" "$@" 2>&1); then
        echo "$output"
        return 0
    else
        exit_code=$?
        log_error "kcadm command failed (exit $exit_code): $*"
        log_error "Output: $output"
        return "$exit_code"
    fi
}

get_client_uuid() {
    local client_id="$1"
    local uuid
    
    uuid=$(kcadm_safe get clients -r "$REALM" -q "clientId=$client_id" \
        --fields id -F id 2>/dev/null \
        | grep '"id"' | sed 's/.*"id" : "//;s/".*//' | head -1)
    
    echo "$uuid"
}

array_contains() {
    local needle="$1"
    local haystack="$2"
    echo "$haystack" | grep -qF "$needle"
}

# ─── Main Setup ──────────────────────────────────────────────────────────────
main() {
    log_info "=== Keycloak Setup Starting ==="
    log_info "  URL   : $KC_URL"
    log_info "  Realm : $REALM"
    log_info "  Domain: ${PUBLIC_DOMAIN:-<not set>}"
    echo ""
    
    authenticate_keycloak
    configure_google_idp
    configure_google_picture_mapper
    configure_profile_scope_picture_mapper
    configure_marty_ui_redirect_uris
    configure_marty_api_secret
    
    log_success "=== Keycloak Setup Complete ==="
}

# ─── Authentication ──────────────────────────────────────────────────────────
authenticate_keycloak() {
    log_info "Waiting for Keycloak to be ready..."
    
    local attempts=0
    while [ $attempts -lt $MAX_RETRIES ]; do
        if "$KCADM" config credentials \
                --server "$KC_URL" --realm master \
                --user "$ADMIN" --password "$PASS" > /dev/null 2>&1; then
            log_success "Keycloak authenticated after $((attempts * RETRY_DELAY))s"
            return 0
        fi
        
        attempts=$((attempts + 1))
        sleep $RETRY_DELAY
    done
    
    log_error "Keycloak did not become ready in time (tried for $((MAX_RETRIES * RETRY_DELAY))s)"
    exit 1
}

# ─── Google Identity Provider ────────────────────────────────────────────────
configure_google_idp() {
    if [ -z "$GOOGLE_CID" ]; then
        log_warning "GOOGLE_CLIENT_ID not set — skipping Google IdP configuration"
        return 0
    fi
    
    log_info "Patching Google Identity Provider..."
    
    if kcadm_safe update identity-provider/instances/google \
        -r "$REALM" \
        -s "config.clientId=${GOOGLE_CID}" \
        -s "config.clientSecret=${GOOGLE_SEC}"; then
        log_success "Google IdP configured (clientId: ${GOOGLE_CID:0:20}...)"
    else
        log_error "Failed to configure Google IdP"
        return 1
    fi
}

# ─── Google Picture Mapper ───────────────────────────────────────────────────
configure_google_picture_mapper() {
    log_info "Configuring Google picture identity-provider mapper..."
    
    local mappers
    mappers=$(kcadm_safe get identity-provider/instances/google/mappers -r "$REALM" 2>/dev/null || echo "")
    
    if echo "$mappers" | grep -q '"name" : "google-picture-mapper"'; then
        log_success "Google picture IdP mapper already exists"
        return 0
    fi
    
    local mapper_json
    read -r -d '' mapper_json <<'MAPEOF' || true
{
  "identityProviderMapper": "oidc-user-attribute-idp-mapper",
  "identityProviderAlias": "google",
  "name": "google-picture-mapper",
  "config": {
    "syncMode": "INHERIT",
    "claim": "picture",
    "user.attribute": "picture"
  }
}
MAPEOF
    
    local temp_file
    temp_file=$(create_temp_file)
    echo "$mapper_json" > "$temp_file"
    
    if kcadm_safe create identity-provider/instances/google/mappers \
        -r "$REALM" -f "$temp_file"; then
        log_success "Created Google picture IdP mapper"
    else
        log_warning "Could not create Google picture IdP mapper (may already exist)"
    fi
}

# ─── Profile Scope Picture Mapper ────────────────────────────────────────────
configure_profile_scope_picture_mapper() {
    log_info "Configuring profile scope picture protocol mapper..."
    
    local profile_scope_id
    profile_scope_id=$(kcadm_safe get client-scopes -r "$REALM" 2>/dev/null \
        | grep -B2 '"name" : "profile"' | grep '"id"' \
        | sed 's/.*"id" : "//;s/".*//' | head -1)
    
    if [ -z "$profile_scope_id" ]; then
        log_warning "Could not find profile scope — skipping picture protocol mapper"
        return 0
    fi
    
    local protocol_mappers
    protocol_mappers=$(kcadm_safe get "client-scopes/$profile_scope_id/protocol-mappers/models" \
        -r "$REALM" 2>/dev/null || echo "")
    
    if echo "$protocol_mappers" | grep -q '"name" : "picture"'; then
        log_success "Picture protocol mapper already exists on profile scope"
        return 0
    fi
    
    local proto_json
    read -r -d '' proto_json <<'PROTOEOF' || true
{
  "name": "picture",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "consentRequired": false,
  "config": {
    "userinfo.token.claim": "true",
    "user.attribute": "picture",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "claim.name": "picture",
    "jsonType.label": "String"
  }
}
PROTOEOF
    
    local temp_file
    temp_file=$(create_temp_file)
    echo "$proto_json" > "$temp_file"
    
    if kcadm_safe create "client-scopes/$profile_scope_id/protocol-mappers/models" \
        -r "$REALM" -f "$temp_file"; then
        log_success "Created picture protocol mapper on profile scope"
    else
        log_warning "Could not create picture protocol mapper (may already exist)"
    fi
}

# ─── Marty UI Client Configuration ───────────────────────────────────────────
configure_marty_ui_redirect_uris() {
    if [ -z "$PUBLIC_DOMAIN" ]; then
        log_warning "PUBLIC_DOMAIN not set — skipping marty-ui client redirect URI configuration"
        return 0
    fi
    
    log_info "Configuring marty-ui client for public domain: $PUBLIC_DOMAIN"
    
    local client_uuid
    client_uuid=$(get_client_uuid "marty-ui")
    
    if [ -z "$client_uuid" ]; then
        log_warning "marty-ui client not found in realm $REALM — skipping"
        return 0
    fi
    
    local public_redirect="https://${PUBLIC_DOMAIN}/*"
    local public_origin="https://${PUBLIC_DOMAIN}"
    local public_post_logout="https://${PUBLIC_DOMAIN}/*"
    
    # Get current configuration
    local current_config
    current_config=$(kcadm_safe get "clients/$client_uuid" -r "$REALM" \
        --fields redirectUris,webOrigins,attributes 2>/dev/null)
    
    # Update redirect URIs
    if ! array_contains "$public_redirect" "$current_config"; then
        if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
            -s "redirectUris+=[\"${public_redirect}\"]"; then
            log_success "Added redirect URI: $public_redirect"
        else
            log_error "Failed to add redirect URI"
        fi
    else
        log_success "Redirect URI already present: $public_redirect"
    fi
    
    # Update web origins
    if ! array_contains "\"$public_origin\"" "$current_config"; then
        if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
            -s "webOrigins+=[\"${public_origin}\"]"; then
            log_success "Added web origin: $public_origin"
        else
            log_error "Failed to add web origin"
        fi
    else
        log_success "Web origin already present: $public_origin"
    fi
    
    # Update post-logout redirect URIs
    if ! array_contains "$public_post_logout" "$current_config"; then
        local current_logout
        current_logout=$(echo "$current_config" \
            | grep -o '"post\.logout\.redirect\.uris" : "[^"]*"' \
            | sed 's/"post\.logout\.redirect\.uris" : "//;s/"$//' || echo "")
        
        local new_logout
        if [ -n "$current_logout" ]; then
            new_logout="${current_logout}##${public_post_logout}"
        else
            new_logout="$public_post_logout"
        fi
        
        if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
            -s "attributes.\"post.logout.redirect.uris\"=${new_logout}"; then
            log_success "Added post-logout redirect URI: $public_post_logout"
        else
            log_error "Failed to add post-logout redirect URI"
        fi
    else
        log_success "Post-logout URI already present: $public_post_logout"
    fi
}

# ─── Marty API Client Secret ─────────────────────────────────────────────────
configure_marty_api_secret() {
    if [ -z "$MARTY_API_SECRET" ] || [ "$MARTY_API_SECRET" = "marty-api-secret-change-in-production" ]; then
        log_warning "MARTY_API_CLIENT_SECRET not set or using default — skipping"
        return 0
    fi
    
    log_info "Patching marty-api client secret..."
    
    local client_uuid
    client_uuid=$(get_client_uuid "marty-api")
    
    if [ -z "$client_uuid" ]; then
        log_warning "marty-api client not found in realm $REALM — skipping"
        return 0
    fi
    
    if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
        -s "secret=${MARTY_API_SECRET}"; then
        log_success "marty-api client secret configured"
    else
        log_error "Failed to configure marty-api client secret"
        return 1
    fi
}

# ─── Execute ─────────────────────────────────────────────────────────────────
main "$@"
