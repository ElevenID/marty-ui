#!/usr/bin/env bash
# Keep LF line endings; this script is executed directly inside Linux containers.
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
MARTY_ORG_NAME="${MARTY_ORG_NAME:-Marty}"
MARTY_ORG_DOMAIN="${MARTY_ORG_DOMAIN:-${PUBLIC_DOMAIN:-marty.local}}"
MARTY_ORG_ADMIN_EMAIL="$(printf '%s' "${MARTY_ORG_ADMIN_EMAIL:-}" | tr '[:upper:]' '[:lower:]' | tr -d '\r')"
KCADM="${KCADM_PATH:-/opt/keycloak/bin/kcadm.sh}"

KEYCLOAK_USER_REGISTRATION_ENABLED="${KEYCLOAK_USER_REGISTRATION_ENABLED:-true}"
KEYCLOAK_VERIFY_EMAIL="${KEYCLOAK_VERIFY_EMAIL:-false}"
KEYCLOAK_RESET_PASSWORD_ENABLED="${KEYCLOAK_RESET_PASSWORD_ENABLED:-true}"
KEYCLOAK_SOCIAL_LOGIN_ENABLED="${KEYCLOAK_SOCIAL_LOGIN_ENABLED:-true}"
KEYCLOAK_SMTP_HOST="${KEYCLOAK_SMTP_HOST:-${SMTP_HOST:-}}"
KEYCLOAK_SMTP_PORT="${KEYCLOAK_SMTP_PORT:-${SMTP_PORT:-1025}}"
KEYCLOAK_SMTP_FROM="${KEYCLOAK_SMTP_FROM:-${SMTP_FROM:-noreply@marty.demo}}"
KEYCLOAK_SMTP_FROM_DISPLAY_NAME="${KEYCLOAK_SMTP_FROM_DISPLAY_NAME:-${SMTP_FROM_DISPLAY_NAME:-Marty Trust Services}}"
KEYCLOAK_SMTP_USERNAME="${KEYCLOAK_SMTP_USERNAME:-${SMTP_USERNAME:-}}"
KEYCLOAK_SMTP_PASSWORD="${KEYCLOAK_SMTP_PASSWORD:-${SMTP_PASSWORD:-}}"
KEYCLOAK_SMTP_SSL="${KEYCLOAK_SMTP_SSL:-${SMTP_SSL:-false}}"
KEYCLOAK_SMTP_STARTTLS="${KEYCLOAK_SMTP_STARTTLS:-${SMTP_STARTTLS:-false}}"

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
        --fields id 2>/dev/null \
        | grep '"id"' | sed 's/.*"id" : "//;s/".*//' | head -1)
    
    echo "$uuid"
}

array_contains() {
    local needle="$1"
    local haystack="$2"
    echo "$haystack" | grep -qF "$needle"
}

normalize_bool() {
    local raw default normalized
    raw="$1"
    default="$2"
    normalized="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
    case "$normalized" in
        true|1|yes|y|on) echo "true" ;;
        false|0|no|n|off) echo "false" ;;
        *) echo "$default" ;;
    esac
}

kcadm_secret_safe() {
    local output
    local exit_code

    if output=$("$KCADM" "$@" 2>&1); then
        echo "$output"
        return 0
    else
        exit_code=$?
        log_error "kcadm command failed while applying secret-bearing configuration (exit $exit_code)"
        log_error "Output: $output"
        return "$exit_code"
    fi
}

# ─── Main Setup ──────────────────────────────────────────────────────────────
main() {
    log_info "=== Keycloak Setup Starting ==="
    log_info "  URL   : $KC_URL"
    log_info "  Realm : $REALM"
    log_info "  Domain: ${PUBLIC_DOMAIN:-<not set>}"
    echo ""
    
    authenticate_keycloak
    configure_realm_login_settings
    configure_realm_smtp_settings
    configure_google_idp
    configure_google_picture_mapper
    configure_profile_scope_picture_mapper
    configure_marty_ui_redirect_uris
    configure_marty_api_secret
    ensure_marty_org_exists
    ensure_marty_org_admin_role
    
    log_success "=== Keycloak Setup Complete ==="
}

find_user_id_by_email() {
    local email="$1"
    local payload
    payload=$(kcadm_safe get users -r "$REALM" -q "email=${email}" --fields id,email 2>/dev/null || echo "")
    echo "$payload" | tr -d '\n' | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

get_realm_role_id() {
    local role_name="$1"
    local payload
    payload=$(kcadm_safe get "roles/${role_name}" -r "$REALM" 2>/dev/null || echo "")
    echo "$payload" | tr -d '\n' | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

ensure_marty_org_exists() {
    log_info "Ensuring Keycloak organization exists: ${MARTY_ORG_NAME}"

    local orgs
    orgs=$(kcadm_safe get organizations -r "$REALM" 2>/dev/null || echo "[]")
    if echo "$orgs" | tr -d '\n' | grep -q "\"name\"[[:space:]]*:[[:space:]]*\"${MARTY_ORG_NAME}\""; then
        log_success "Keycloak organization already present: ${MARTY_ORG_NAME}"
        return 0
    fi

        local payload
        payload=$(create_temp_file)
        cat > "$payload" <<EOF
{
    "name": "${MARTY_ORG_NAME}",
    "enabled": true,
    "domains": [
        {
            "name": "${MARTY_ORG_DOMAIN}",
            "verified": true
        }
    ]
}
EOF

        if kcadm_safe create organizations -r "$REALM" -f "$payload" > /dev/null; then
        log_success "Created Keycloak organization: ${MARTY_ORG_NAME}"
    else
        log_warning "Could not create Keycloak organization '${MARTY_ORG_NAME}' (may already exist or org API unavailable)"
    fi
}

ensure_marty_org_admin_role() {
    if [ -z "$MARTY_ORG_ADMIN_EMAIL" ]; then
        log_info "MARTY_ORG_ADMIN_EMAIL not set — skipping Keycloak admin role bootstrap"
        return 0
    fi

    log_info "Ensuring Keycloak administrator role for ${MARTY_ORG_ADMIN_EMAIL}"

    local user_id
    user_id=$(find_user_id_by_email "$MARTY_ORG_ADMIN_EMAIL")
    if [ -z "$user_id" ]; then
        log_warning "User ${MARTY_ORG_ADMIN_EMAIL} not found in Keycloak yet — role will be applied after first login"
        return 0
    fi

    local role_id
    role_id=$(get_realm_role_id "administrator")
    if [ -z "$role_id" ]; then
        log_error "Realm role 'administrator' not found in realm ${REALM}"
        return 1
    fi

    local current_roles
    current_roles=$(kcadm_safe get "users/${user_id}/role-mappings/realm" -r "$REALM" 2>/dev/null || echo "[]")
    if echo "$current_roles" | tr -d '\n' | grep -q '"name"[[:space:]]*:[[:space:]]*"administrator"'; then
        log_success "Keycloak user already has administrator role: ${MARTY_ORG_ADMIN_EMAIL}"
        return 0
    fi

    local role_payload
    role_payload=$(create_temp_file)
    cat > "$role_payload" <<EOF
[
  {
    "id": "${role_id}",
    "name": "administrator"
  }
]
EOF

    if kcadm_safe create "users/${user_id}/role-mappings/realm" -r "$REALM" -f "$role_payload" > /dev/null; then
        log_success "Granted Keycloak administrator role to ${MARTY_ORG_ADMIN_EMAIL}"
    else
        log_error "Failed to grant Keycloak administrator role to ${MARTY_ORG_ADMIN_EMAIL}"
        return 1
    fi
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

# ─── Realm Login & Email Settings ────────────────────────────────────────────
configure_realm_login_settings() {
    local registration_enabled verify_email reset_password_enabled
    registration_enabled="$(normalize_bool "$KEYCLOAK_USER_REGISTRATION_ENABLED" true)"
    verify_email="$(normalize_bool "$KEYCLOAK_VERIFY_EMAIL" false)"
    reset_password_enabled="$(normalize_bool "$KEYCLOAK_RESET_PASSWORD_ENABLED" true)"

    log_info "Patching realm login settings (registration=${registration_enabled}, verifyEmail=${verify_email}, resetPassword=${reset_password_enabled})"

    if kcadm_safe update "realms/${REALM}" \
        -s "registrationAllowed=${registration_enabled}" \
        -s "verifyEmail=${verify_email}" \
        -s "resetPasswordAllowed=${reset_password_enabled}"; then
        log_success "Realm login settings configured"
    else
        log_error "Failed to configure realm login settings"
        return 1
    fi
}

configure_realm_smtp_settings() {
    if [ -z "$KEYCLOAK_SMTP_HOST" ]; then
        if [ "$(normalize_bool "$KEYCLOAK_VERIFY_EMAIL" false)" = "true" ]; then
            log_warning "KEYCLOAK_VERIFY_EMAIL=true but no KEYCLOAK_SMTP_HOST/SMTP_HOST configured"
        else
            log_info "No Keycloak SMTP host configured — preserving imported realm SMTP settings"
        fi
        return 0
    fi

    local smtp_auth smtp_ssl smtp_starttls
    smtp_auth="false"
    if [ -n "$KEYCLOAK_SMTP_USERNAME" ] || [ -n "$KEYCLOAK_SMTP_PASSWORD" ]; then
        smtp_auth="true"
    fi
    smtp_ssl="$(normalize_bool "$KEYCLOAK_SMTP_SSL" false)"
    smtp_starttls="$(normalize_bool "$KEYCLOAK_SMTP_STARTTLS" false)"

    log_info "Patching realm SMTP settings (host=${KEYCLOAK_SMTP_HOST}, port=${KEYCLOAK_SMTP_PORT}, auth=${smtp_auth}, ssl=${smtp_ssl}, starttls=${smtp_starttls})"

    local args=(
        update "realms/${REALM}"
        -s "smtpServer.host=${KEYCLOAK_SMTP_HOST}"
        -s "smtpServer.port=${KEYCLOAK_SMTP_PORT}"
        -s "smtpServer.from=${KEYCLOAK_SMTP_FROM}"
        -s "smtpServer.fromDisplayName=${KEYCLOAK_SMTP_FROM_DISPLAY_NAME}"
        -s "smtpServer.auth=${smtp_auth}"
        -s "smtpServer.ssl=${smtp_ssl}"
        -s "smtpServer.starttls=${smtp_starttls}"
    )
    if [ -n "$KEYCLOAK_SMTP_USERNAME" ]; then
        args+=(-s "smtpServer.user=${KEYCLOAK_SMTP_USERNAME}")
    fi
    if [ -n "$KEYCLOAK_SMTP_PASSWORD" ]; then
        args+=(-s "smtpServer.password=${KEYCLOAK_SMTP_PASSWORD}")
    fi

    if kcadm_secret_safe "${args[@]}"; then
        log_success "Realm SMTP settings configured"
    else
        log_error "Failed to configure realm SMTP settings"
        return 1
    fi
}

# ─── Google Identity Provider ────────────────────────────────────────────────
configure_google_idp() {
    local social_enabled
    social_enabled="$(normalize_bool "$KEYCLOAK_SOCIAL_LOGIN_ENABLED" true)"
    if [ "$social_enabled" != "true" ]; then
        log_info "KEYCLOAK_SOCIAL_LOGIN_ENABLED=false — disabling Google IdP if present"
        kcadm_safe update identity-provider/instances/google -r "$REALM" -s enabled=false > /dev/null || \
            log_warning "Google IdP not found or could not be disabled"
        return 0
    fi

    if [ -z "$GOOGLE_CID" ]; then
        log_warning "GOOGLE_CLIENT_ID not set — skipping Google IdP configuration"
        return 0
    fi
    
    log_info "Patching Google Identity Provider..."
    
    if kcadm_safe update identity-provider/instances/google \
        -r "$REALM" \
        -s enabled=true \
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
    local flattened_config
    flattened_config=$(echo "$current_config" | tr -d '\n')
    
    # Update redirect URIs
    if ! array_contains "$public_redirect" "$current_config"; then
        local current_redirects
        current_redirects=$(echo "$flattened_config" \
            | sed -n 's/.*"redirectUris"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')
        local new_redirects
        if [ -n "$current_redirects" ]; then
            new_redirects="${current_redirects}, \"${public_redirect}\""
        else
            new_redirects="\"${public_redirect}\""
        fi
        if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
            -s "redirectUris=[${new_redirects}]"; then
            log_success "Added redirect URI: $public_redirect"
        else
            log_error "Failed to add redirect URI"
        fi
    else
        log_success "Redirect URI already present: $public_redirect"
    fi
    
    # Update web origins
    if ! array_contains "\"$public_origin\"" "$current_config"; then
        local current_origins
        current_origins=$(echo "$flattened_config" \
            | sed -n 's/.*"webOrigins"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')
        local new_origins
        if [ -n "$current_origins" ]; then
            new_origins="${current_origins}, \"${public_origin}\""
        else
            new_origins="\"${public_origin}\""
        fi
        if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
            -s "webOrigins=[${new_origins}]"; then
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
