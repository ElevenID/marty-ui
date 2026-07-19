#!/usr/bin/env bash
# Keep LF line endings; this script is executed directly inside Linux containers.
# =============================================================================
# setup-keycloak.sh — Keycloak post-startup configurator
# =============================================================================
# Patches Keycloak via kcadm after realm import so that runtime secrets,
# CSV/list settings, and deployment-specific hostnames are applied correctly.
#
# Realm imports can resolve env placeholders, but the post-import patch remains
# necessary for secret-bearing values and comma-separated additional UI origins.
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
UI_ADDITIONAL_BASE_URLS="${UI_ADDITIONAL_BASE_URLS:-${AUTH_ADDITIONAL_UI_BASE_URLS:-}}"
KEYCLOAK_REPLACE_UI_ORIGINS="${KEYCLOAK_REPLACE_UI_ORIGINS:-false}"
MARTY_API_SECRET="${MARTY_API_CLIENT_SECRET:-}"
MARTY_ORG_NAME="${MARTY_ORG_NAME:-Marty}"
MARTY_ORG_DOMAIN="${MARTY_ORG_DOMAIN:-${PUBLIC_DOMAIN:-marty.local}}"
MARTY_ORG_ADMIN_EMAIL="$(printf '%s' "${MARTY_ORG_ADMIN_EMAIL:-}" | tr '[:upper:]' '[:lower:]' | tr -d '\r')"
MARTY_ORG_ADMIN_PASSWORD="${MARTY_ORG_ADMIN_PASSWORD:-}"
MARTY_ORG_ADMIN_FIRST_NAME="${MARTY_ORG_ADMIN_FIRST_NAME:-Marty}"
MARTY_ORG_ADMIN_LAST_NAME="${MARTY_ORG_ADMIN_LAST_NAME:-Administrator}"
CANVAS_DEMO_ADMIN_ENABLED="${CANVAS_DEMO_ADMIN_ENABLED:-true}"
CANVAS_DEMO_ADMIN_EMAIL="$(printf '%s' "${CANVAS_DEMO_ADMIN_EMAIL:-canvas.admin@marty.demo}" | tr '[:upper:]' '[:lower:]' | tr -d '\r')"
CANVAS_DEMO_ADMIN_PASSWORD="${CANVAS_DEMO_ADMIN_PASSWORD:-CanvasAdmin123!}"
CANVAS_DEMO_ADMIN_FIRST_NAME="${CANVAS_DEMO_ADMIN_FIRST_NAME:-Canvas}"
CANVAS_DEMO_ADMIN_LAST_NAME="${CANVAS_DEMO_ADMIN_LAST_NAME:-Demo Admin}"
DEMO_REVIEWER_EMAIL="$(printf '%s' "${DEMO_REVIEWER_EMAIL:-reviewer@marty.demo}" | tr '[:upper:]' '[:lower:]' | tr -d '\r')"
DEMO_REVIEWER_PASSWORD="${DEMO_REVIEWER_PASSWORD:-}"
DEMO_REVIEWER_FIRST_NAME="${DEMO_REVIEWER_FIRST_NAME:-Review}"
DEMO_REVIEWER_LAST_NAME="${DEMO_REVIEWER_LAST_NAME:-User}"
KCADM="${KCADM_PATH:-/opt/keycloak/bin/kcadm.sh}"

KEYCLOAK_USER_REGISTRATION_ENABLED="${KEYCLOAK_USER_REGISTRATION_ENABLED:-true}"
KEYCLOAK_VERIFY_EMAIL="${KEYCLOAK_VERIFY_EMAIL:-false}"
KEYCLOAK_RESET_PASSWORD_ENABLED="${KEYCLOAK_RESET_PASSWORD_ENABLED:-true}"
KEYCLOAK_SOCIAL_LOGIN_ENABLED="${KEYCLOAK_SOCIAL_LOGIN_ENABLED:-true}"
KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED="${KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED:-false}"
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

json_array_from_csv() {
    local csv="$1"
    local output="["
    local first="true"
    local item escaped

    IFS=',' read -r -a items <<< "$csv"
    for item in "${items[@]}"; do
        item="$(echo "$item" | xargs)"
        if [ -z "$item" ]; then
            continue
        fi
        escaped="$(printf '%s' "$item" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        if [ "$first" = "true" ]; then
            output="${output}\"${escaped}\""
            first="false"
        else
            output="${output}, \"${escaped}\""
        fi
    done

    output="${output}]"
    printf '%s' "$output"
}

post_logout_from_csv() {
    local csv="$1"
    local output=""
    local item

    IFS=',' read -r -a items <<< "$csv"
    for item in "${items[@]}"; do
        item="$(echo "$item" | xargs)"
        if [ -z "$item" ]; then
            continue
        fi
        if [ -z "$output" ]; then
            output="$item"
        else
            output="${output}##${item}"
        fi
    done

    printf '%s' "$output"
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
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
    configure_browser_flow_alignment
    configure_realm_smtp_settings
    configure_google_idp
    configure_google_picture_mapper
    configure_profile_scope_picture_mapper
    configure_marty_ui_redirect_uris
    configure_marty_api_secret
    ensure_marty_org_exists
    ensure_canvas_demo_admin_user
    ensure_demo_reviewer_user
    ensure_marty_org_admin_user
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

ensure_realm_role() {
    local role_name="$1"
    if [ -n "$(get_realm_role_id "$role_name")" ]; then
        return 0
    fi

    local payload
    payload=$(create_temp_file)
    cat > "$payload" <<EOF
{
  "name": "${role_name}",
  "description": "Marty application role managed by the Keycloak configurator"
}
EOF
    if kcadm_safe create roles -r "$REALM" -f "$payload" > /dev/null; then
        log_success "Created Keycloak ${role_name} realm role"
        return 0
    fi

    # A concurrent or previous configurator may have created it after the
    # lookup. Verify before treating the create error as fatal.
    if [ -n "$(get_realm_role_id "$role_name")" ]; then
        return 0
    fi
    log_error "Failed to create Keycloak ${role_name} realm role"
    return 1
}

grant_realm_role_to_user() {
    local user_id="$1"
    local user_label="$2"
    local role_name="$3"

    ensure_realm_role "$role_name" || return 1

    local role_id
    role_id=$(get_realm_role_id "$role_name")
    if [ -z "$role_id" ]; then
        log_error "Realm role '${role_name}' not found in realm ${REALM}"
        return 1
    fi

    local current_roles
    current_roles=$(kcadm_safe get "users/${user_id}/role-mappings/realm" -r "$REALM" 2>/dev/null || echo "[]")
    if echo "$current_roles" | tr -d '\n' | grep -q "\"name\"[[:space:]]*:[[:space:]]*\"${role_name}\""; then
        log_success "Keycloak user already has ${role_name} role: ${user_label}"
        return 0
    fi

    local role_payload
    role_payload=$(create_temp_file)
    cat > "$role_payload" <<EOF
[
  {
    "id": "${role_id}",
    "name": "${role_name}"
  }
]
EOF

    if kcadm_safe create "users/${user_id}/role-mappings/realm" -r "$REALM" -f "$role_payload" > /dev/null; then
        log_success "Granted Keycloak ${role_name} role to ${user_label}"
    else
        log_error "Failed to grant Keycloak ${role_name} role to ${user_label}"
        return 1
    fi
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

ensure_canvas_demo_admin_user() {
    local enabled
    enabled="$(normalize_bool "$CANVAS_DEMO_ADMIN_ENABLED" true)"
    if [ "$enabled" != "true" ]; then
        log_info "CANVAS_DEMO_ADMIN_ENABLED=false - skipping Canvas demo admin bootstrap"
        return 0
    fi

    if [ -z "$CANVAS_DEMO_ADMIN_EMAIL" ]; then
        log_info "CANVAS_DEMO_ADMIN_EMAIL not set - skipping Canvas demo admin bootstrap"
        return 0
    fi

    log_info "Ensuring Canvas demo admin user exists: ${CANVAS_DEMO_ADMIN_EMAIL}"

    local user_id
    user_id=$(find_user_id_by_email "$CANVAS_DEMO_ADMIN_EMAIL")
    if [ -z "$user_id" ]; then
        local payload first_name last_name email
        payload=$(create_temp_file)
        email="$(json_escape "$CANVAS_DEMO_ADMIN_EMAIL")"
        first_name="$(json_escape "$CANVAS_DEMO_ADMIN_FIRST_NAME")"
        last_name="$(json_escape "$CANVAS_DEMO_ADMIN_LAST_NAME")"
        cat > "$payload" <<EOF
{
    "username": "${email}",
    "email": "${email}",
    "emailVerified": true,
    "enabled": true,
    "firstName": "${first_name}",
    "lastName": "${last_name}",
    "attributes": {
        "user_type": ["administrator"],
        "demo_context": ["canvas"],
        "onboarding_completed": ["true"]
    }
}

EOF

        if kcadm_safe create users -r "$REALM" -f "$payload" > /dev/null; then
            log_success "Created Canvas demo admin user: ${CANVAS_DEMO_ADMIN_EMAIL}"
        else
            log_error "Failed to create Canvas demo admin user: ${CANVAS_DEMO_ADMIN_EMAIL}"
            return 1
        fi
        user_id=$(find_user_id_by_email "$CANVAS_DEMO_ADMIN_EMAIL")
    else
        log_success "Canvas demo admin user already present: ${CANVAS_DEMO_ADMIN_EMAIL}"
    fi

    if [ -z "$user_id" ]; then
        log_error "Canvas demo admin user lookup failed after create: ${CANVAS_DEMO_ADMIN_EMAIL}"
        return 1
    fi

    if [ -n "$CANVAS_DEMO_ADMIN_PASSWORD" ]; then
        local password_payload password_value
        password_payload=$(create_temp_file)
        password_value="$(json_escape "$CANVAS_DEMO_ADMIN_PASSWORD")"
        cat > "$password_payload" <<EOF
{
    "type": "password",
    "value": "${password_value}",
    "temporary": false
}
EOF
        if kcadm_secret_safe update "users/${user_id}/reset-password" -r "$REALM" -f "$password_payload" -n > /dev/null; then
            log_success "Canvas demo admin password configured"
        else
            log_error "Failed to configure Canvas demo admin password"
            return 1
        fi
    fi

    grant_realm_role_to_user "$user_id" "$CANVAS_DEMO_ADMIN_EMAIL" "administrator"
}

ensure_demo_reviewer_user() {
    if [ -z "$DEMO_REVIEWER_EMAIL" ]; then
        log_info "DEMO_REVIEWER_EMAIL not set - skipping reviewer bootstrap"
        return 0
    fi

    log_info "Ensuring demo reviewer user exists: ${DEMO_REVIEWER_EMAIL}"
    local user_id
    user_id=$(find_user_id_by_email "$DEMO_REVIEWER_EMAIL")
    if [ -z "$user_id" ]; then
        local payload email first_name last_name
        payload=$(create_temp_file)
        email="$(json_escape "$DEMO_REVIEWER_EMAIL")"
        first_name="$(json_escape "$DEMO_REVIEWER_FIRST_NAME")"
        last_name="$(json_escape "$DEMO_REVIEWER_LAST_NAME")"
        cat > "$payload" <<EOF
{
    "username": "${email}",
    "email": "${email}",
    "emailVerified": true,
    "enabled": true,
    "firstName": "${first_name}",
    "lastName": "${last_name}",
    "attributes": {
        "user_type": ["reviewer"],
        "onboarding_completed": ["true"]
    }
}
EOF
        if ! kcadm_safe create users -r "$REALM" -f "$payload" > /dev/null; then
            log_error "Failed to create demo reviewer user: ${DEMO_REVIEWER_EMAIL}"
            return 1
        fi
        user_id=$(find_user_id_by_email "$DEMO_REVIEWER_EMAIL")
    fi

    if [ -z "$user_id" ]; then
        log_error "Demo reviewer lookup failed after create: ${DEMO_REVIEWER_EMAIL}"
        return 1
    fi

    if [ -n "$DEMO_REVIEWER_PASSWORD" ]; then
        local password_payload password_value
        password_payload=$(create_temp_file)
        password_value="$(json_escape "$DEMO_REVIEWER_PASSWORD")"
        cat > "$password_payload" <<EOF
{
    "type": "password",
    "value": "${password_value}",
    "temporary": false
}
EOF
        kcadm_secret_safe update "users/${user_id}/reset-password" -r "$REALM" -f "$password_payload" -n > /dev/null
    fi

    grant_realm_role_to_user "$user_id" "$DEMO_REVIEWER_EMAIL" "reviewer"
}

ensure_marty_org_admin_user() {
    if [ -z "$MARTY_ORG_ADMIN_EMAIL" ] || [ -z "$MARTY_ORG_ADMIN_PASSWORD" ]; then
        log_info "MARTY_ORG_ADMIN_EMAIL or MARTY_ORG_ADMIN_PASSWORD not set - skipping organization admin user bootstrap"
        return 0
    fi

    log_info "Ensuring Marty organization admin user exists: ${MARTY_ORG_ADMIN_EMAIL}"
    local user_id
    user_id=$(find_user_id_by_email "$MARTY_ORG_ADMIN_EMAIL")
    if [ -z "$user_id" ]; then
        local payload email first_name last_name
        payload=$(create_temp_file)
        email="$(json_escape "$MARTY_ORG_ADMIN_EMAIL")"
        first_name="$(json_escape "$MARTY_ORG_ADMIN_FIRST_NAME")"
        last_name="$(json_escape "$MARTY_ORG_ADMIN_LAST_NAME")"
        cat > "$payload" <<EOF
{
    "username": "${email}",
    "email": "${email}",
    "emailVerified": true,
    "enabled": true,
    "firstName": "${first_name}",
    "lastName": "${last_name}",
    "attributes": {
        "user_type": ["administrator"],
        "onboarding_completed": ["true"]
    }
}
EOF
        if ! kcadm_safe create users -r "$REALM" -f "$payload" > /dev/null; then
            log_error "Failed to create Marty organization admin user: ${MARTY_ORG_ADMIN_EMAIL}"
            return 1
        fi
        user_id=$(find_user_id_by_email "$MARTY_ORG_ADMIN_EMAIL")
    fi

    if [ -z "$user_id" ]; then
        log_error "Marty organization admin user lookup failed after create: ${MARTY_ORG_ADMIN_EMAIL}"
        return 1
    fi

    local password_payload password_value
    password_payload=$(create_temp_file)
    password_value="$(json_escape "$MARTY_ORG_ADMIN_PASSWORD")"
    cat > "$password_payload" <<EOF
{
    "type": "password",
    "value": "${password_value}",
    "temporary": false
}
EOF
    if ! kcadm_secret_safe update "users/${user_id}/reset-password" -r "$REALM" -f "$password_payload" -n > /dev/null; then
        log_error "Failed to configure Marty organization admin password"
        return 1
    fi
    grant_realm_role_to_user "$user_id" "$MARTY_ORG_ADMIN_EMAIL" "administrator"
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

    grant_realm_role_to_user "$user_id" "$MARTY_ORG_ADMIN_EMAIL" "administrator"
}

get_browser_execution_id_by_display_name() {
    local display_name="$1"
    local executions current_id current_name

    executions=$(kcadm_safe get "authentication/flows/browser/executions" -r "$REALM" 2>/dev/null || echo "")
    if [ -z "$executions" ]; then
        return 0
    fi

    current_id=""
    current_name=""
    while IFS= read -r line; do
        case "$line" in
            *'"id"'*)
                current_id="$(printf '%s' "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
                ;;
            *'"displayName"'*)
                current_name="$(printf '%s' "$line" | sed -n 's/.*"displayName"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
                if [ "$current_name" = "$display_name" ] && [ -n "$current_id" ]; then
                    printf '%s\n' "$current_id"
                    return 0
                fi
                ;;
        esac
    done <<EOF
$executions
EOF
}

configure_browser_flow_alignment() {
    local identity_first_enabled desired_requirement execution_id current_execution current_requirement
    identity_first_enabled="$(normalize_bool "$KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED" false)"

    if [ "$identity_first_enabled" = "true" ]; then
        desired_requirement="ALTERNATIVE"
    else
        desired_requirement="DISABLED"
    fi

    log_info "Patching browser flow alignment (organizationIdentityFirst=${identity_first_enabled})"

    execution_id="$(get_browser_execution_id_by_display_name "Organization")"
    if [ -z "$execution_id" ]; then
        log_warning "Could not locate the browser flow Organization execution; leaving browser flow unchanged"
        return 0
    fi

    current_execution="$(kcadm_safe get "authentication/executions/${execution_id}" -r "$REALM" 2>/dev/null || echo "")"
    current_requirement="$(printf '%s' "$current_execution" | tr -d '\n[:space:]' | sed -n 's/.*"requirement":"\([^"]*\)".*/\1/p')"
    if [ "$current_requirement" = "$desired_requirement" ]; then
        log_success "Browser flow alignment already configured"
        return 0
    fi

    if kcadm_safe update "authentication/flows/browser/executions" \
        -r "$REALM" \
        -n \
        -s "id=${execution_id}" \
        -s "requirement=${desired_requirement}" \
        -s "priority=26" > /dev/null; then
        log_success "Browser flow alignment configured"
    else
        log_error "Failed to configure browser flow alignment"
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
        local realm_config flattened current_registration current_verify_email current_reset_password
        realm_config=$(kcadm_safe get "realms/${REALM}" --fields registrationAllowed,verifyEmail,resetPasswordAllowed 2>/dev/null || echo "")
        if [ -z "$realm_config" ]; then
            log_warning "Realm login settings update failed and Keycloak could not return the realm representation; continuing because Keycloak ${REALM} admin endpoint is unavailable"
            return 0
        fi

        flattened="$(printf '%s' "$realm_config" | tr -d '\n[:space:]')"
        current_registration="$(printf '%s' "$flattened" | sed -n 's/.*"registrationAllowed":\(true\|false\).*/\1/p')"
        current_verify_email="$(printf '%s' "$flattened" | sed -n 's/.*"verifyEmail":\(true\|false\).*/\1/p')"
        current_reset_password="$(printf '%s' "$flattened" | sed -n 's/.*"resetPasswordAllowed":\(true\|false\).*/\1/p')"

        if [ "$current_registration" = "$registration_enabled" ] \
            && [ "$current_verify_email" = "$verify_email" ] \
            && [ "$current_reset_password" = "$reset_password_enabled" ]; then
            log_warning "Realm login settings update failed, but current settings already match desired values; continuing"
            log_success "Realm login settings configured"
            return 0
        fi

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

    if [ -z "$GOOGLE_CID" ] || [ -z "$GOOGLE_SEC" ]; then
        log_error "KEYCLOAK_SOCIAL_LOGIN_ENABLED=true but GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET are not both set"
        return 1
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
    if [ -z "$PUBLIC_DOMAIN" ] && [ -z "$UI_BASE_URL" ]; then
        log_warning "PUBLIC_DOMAIN and UI_BASE_URL are not set — skipping marty-ui client redirect URI configuration"
        return 0
    fi
    
    log_info "Configuring marty-ui client for public domain: $PUBLIC_DOMAIN"
    
    local client_uuid
    client_uuid=$(get_client_uuid "marty-ui")
    
    if [ -z "$client_uuid" ]; then
        log_warning "marty-ui client not found in realm $REALM — skipping"
        return 0
    fi

    local origins_csv
    if [ -n "$UI_BASE_URL" ]; then
        origins_csv="${UI_BASE_URL%/}"
    else
        origins_csv="https://${PUBLIC_DOMAIN}"
    fi
    if [ -n "$UI_ADDITIONAL_BASE_URLS" ]; then
        origins_csv="${origins_csv},${UI_ADDITIONAL_BASE_URLS}"
    fi

    local replace_origins
    replace_origins="$(normalize_bool "$KEYCLOAK_REPLACE_UI_ORIGINS" false)"
    if [ "$replace_origins" = "true" ]; then
        local desired_redirects_csv desired_web_origins_csv desired_logout_csv
        desired_redirects_csv=""
        desired_web_origins_csv=""
        desired_logout_csv=""

        IFS=',' read -r -a ui_origins <<< "$origins_csv"
        for ui_origin in "${ui_origins[@]}"; do
            ui_origin="$(echo "$ui_origin" | xargs)"
            if [ -z "$ui_origin" ]; then
                continue
            fi

            ui_origin="${ui_origin%/}"
            if [ -z "$desired_redirects_csv" ]; then
                desired_redirects_csv="${ui_origin}/*"
                desired_web_origins_csv="${ui_origin}"
                desired_logout_csv="${ui_origin}/*"
            else
                desired_redirects_csv="${desired_redirects_csv},${ui_origin}/*"
                desired_web_origins_csv="${desired_web_origins_csv},${ui_origin}"
                desired_logout_csv="${desired_logout_csv},${ui_origin}/*"
            fi
        done

        if [ -z "$desired_redirects_csv" ]; then
            log_error "No UI origins available to configure marty-ui client"
            return 1
        fi

        local desired_redirects desired_web_origins desired_logout
        desired_redirects="$(json_array_from_csv "$desired_redirects_csv")"
        desired_web_origins="$(json_array_from_csv "$desired_web_origins_csv")"
        desired_logout="$(post_logout_from_csv "$desired_logout_csv")"

        if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
            -s "redirectUris=${desired_redirects}" \
            -s "webOrigins=${desired_web_origins}" \
            -s "attributes.\"post.logout.redirect.uris\"=${desired_logout}" > /dev/null; then
            log_success "Replaced marty-ui redirect/web/post-logout origins with configured UI origins: ${desired_web_origins_csv}"
        else
            log_error "Failed to replace marty-ui redirect/web/post-logout origins"
            return 1
        fi
        return 0
    fi

    IFS=',' read -r -a ui_origins <<< "$origins_csv"
    for ui_origin in "${ui_origins[@]}"; do
        ui_origin="$(echo "$ui_origin" | xargs)"
        if [ -z "$ui_origin" ]; then
            continue
        fi

        ui_origin="${ui_origin%/}"
        local origin_redirect="${ui_origin}/*"
        local origin_post_logout="${ui_origin}/*"

        # Refresh config after each update so multiple origins append cleanly.
        local current_config
        current_config=$(kcadm_safe get "clients/$client_uuid" -r "$REALM" \
            --fields redirectUris,webOrigins,attributes 2>/dev/null)
        local flattened_config
        flattened_config=$(echo "$current_config" | tr -d '\n')

        # Update redirect URIs
        if ! array_contains "$origin_redirect" "$current_config"; then
            local current_redirects
            current_redirects=$(echo "$flattened_config" \
                | sed -n 's/.*"redirectUris"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')
            local new_redirects
            if [ -n "$current_redirects" ]; then
                new_redirects="${current_redirects}, \"${origin_redirect}\""
            else
                new_redirects="\"${origin_redirect}\""
            fi
            if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
                -s "redirectUris=[${new_redirects}]"; then
                log_success "Added redirect URI: $origin_redirect"
            else
                log_error "Failed to add redirect URI: $origin_redirect"
            fi
        else
            log_success "Redirect URI already present: $origin_redirect"
        fi

        current_config=$(kcadm_safe get "clients/$client_uuid" -r "$REALM" \
            --fields redirectUris,webOrigins,attributes 2>/dev/null)
        flattened_config=$(echo "$current_config" | tr -d '\n')

        # Update web origins
        if ! array_contains "\"$ui_origin\"" "$current_config"; then
            local current_origins
            current_origins=$(echo "$flattened_config" \
                | sed -n 's/.*"webOrigins"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')
            local new_origins
            if [ -n "$current_origins" ]; then
                new_origins="${current_origins}, \"${ui_origin}\""
            else
                new_origins="\"${ui_origin}\""
            fi
            if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
                -s "webOrigins=[${new_origins}]"; then
                log_success "Added web origin: $ui_origin"
            else
                log_error "Failed to add web origin: $ui_origin"
            fi
        else
            log_success "Web origin already present: $ui_origin"
        fi

        current_config=$(kcadm_safe get "clients/$client_uuid" -r "$REALM" \
            --fields redirectUris,webOrigins,attributes 2>/dev/null)

        # Update post-logout redirect URIs
        if ! array_contains "$origin_post_logout" "$current_config"; then
            local current_logout
            current_logout=$(echo "$current_config" \
                | grep -o '"post\.logout\.redirect\.uris" : "[^"]*"' \
                | sed 's/"post\.logout\.redirect\.uris" : "//;s/"$//' || echo "")

            local new_logout
            if [ -n "$current_logout" ]; then
                new_logout="${current_logout}##${origin_post_logout}"
            else
                new_logout="$origin_post_logout"
            fi

            if kcadm_safe update "clients/$client_uuid" -r "$REALM" \
                -s "attributes.\"post.logout.redirect.uris\"=${new_logout}"; then
                log_success "Added post-logout redirect URI: $origin_post_logout"
            else
                log_error "Failed to add post-logout redirect URI: $origin_post_logout"
            fi
        else
            log_success "Post-logout URI already present: $origin_post_logout"
        fi
    done
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
