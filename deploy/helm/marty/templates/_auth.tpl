{{- define "marty.authProvider" -}}
{{- $auth := .Values.auth | default dict -}}
{{- $provider := "keycloak" -}}
{{- if hasKey $auth "provider" -}}
{{- $provider = $auth.provider -}}
{{- end -}}
{{- if not (has $provider (list "keycloak" "external")) -}}
{{- fail "auth.provider must be keycloak or external" -}}
{{- end -}}
{{- $provider -}}
{{- end -}}

{{- define "marty.externalHttpsUrl" -}}
{{- $value := .value -}}
{{- if or (gt (len $value) 2048) (not (hasPrefix "https://" $value)) (regexMatch "[[:space:]\\\\?#]" $value) -}}
{{- fail (printf "%s must be an HTTPS URL of at most 2048 UTF-8 bytes without whitespace, a query or fragment" .name) -}}
{{- end -}}
{{- $url := urlParse $value -}}
{{- if or (ne $url.scheme "https") (empty $url.host) (not (empty $url.userinfo)) (regexMatch "[%*@]" $url.host) -}}
{{- fail (printf "%s must have an explicit HTTPS host without credentials or wildcards" .name) -}}
{{- end -}}
{{- /* Bracketed IPv6 and non-DNS hosts are deliberately outside this chart. */ -}}
{{- $authority := splitList ":" $url.host -}}
{{- $canonicalOrigin := printf "https://%s" (lower (index $authority 0)) -}}
{{- if gt (len $authority) 2 -}}
{{- fail (printf "%s must use a DNS host or IPv4 address" .name) -}}
{{- end -}}
{{- $_ := include "marty.endpointHost" (dict "name" .name "host" (index $authority 0) "allowIp" true "allowWildcard" false) -}}
{{- if eq (len $authority) 2 -}}
{{- $port := index $authority 1 -}}
{{- if or (not (regexMatch "^[0-9]{1,5}$" $port)) (lt (atoi $port) 1) (gt (atoi $port) 65535) -}}
{{- fail (printf "%s port must be between 1 and 65535" .name) -}}
{{- end -}}
{{- if ne (atoi $port) 443 -}}
{{- $canonicalOrigin = printf "%s:%d" $canonicalOrigin (atoi $port) -}}
{{- end -}}
{{- end -}}
{{- if and .originOnly (ne $value $canonicalOrigin) -}}
{{- fail (printf "%s must use canonical HTTPS origins: lowercase host, no path or trailing slash, and no default or padded port" .name) -}}
{{- end -}}
{{- end -}}

{{- define "marty.authSelection" -}}
{{- $provider := include "marty.authProvider" . -}}
{{- $auth := .Values.auth | default dict -}}
{{- $selection := dict "schema" "marty.kubernetes-auth-selection/v1" "provider" $provider -}}
{{- if eq $provider "external" -}}
{{- $external := deepCopy ($auth.external | default dict) -}}
{{- $issuer := required "auth.external.issuerUrl is required" $external.issuerUrl -}}
{{- include "marty.externalHttpsUrl" (dict "name" "auth.external.issuerUrl" "value" $issuer "originOnly" false) -}}
{{- $_ := required "auth.external.clientId is required" $external.clientId -}}
{{- if gt (len $external.clientId) 256 -}}
{{- fail "auth.external.clientId must be at most 256 UTF-8 bytes" -}}
{{- end -}}
{{- if or (empty $external.allowedAlgorithms) (gt (len $external.allowedAlgorithms) 9) -}}
{{- fail "auth.external.allowedAlgorithms must explicitly select supported signing algorithms" -}}
{{- end -}}
{{- range $algorithm := $external.allowedAlgorithms -}}
{{- if not (has $algorithm (list "ES256" "ES384" "EdDSA" "RS256" "RS384" "RS512" "PS256" "PS384" "PS512")) -}}
{{- fail "auth.external.allowedAlgorithms contains an unsupported signing algorithm" -}}
{{- end -}}
{{- end -}}
{{- $origins := $external.trustedEndpointOrigins | default list -}}
{{- range $origin := $origins -}}
{{- include "marty.externalHttpsUrl" (dict "name" "auth.external.trustedEndpointOrigins" "value" $origin "originOnly" true) -}}
{{- end -}}
{{- $_ := set $external "trustedEndpointOrigins" $origins -}}
{{- $scopes := list "openid" "profile" "email" -}}
{{- if hasKey $external "scopes" -}}
{{- $scopes = $external.scopes -}}
{{- end -}}
{{- if or (empty $scopes) (gt (len $scopes) 32) (gt (len (join "," $scopes)) 2048) (not (has "openid" $scopes)) -}}
{{- fail "auth.external.scopes must contain openid and between 1 and 32 unique OAuth scopes, at most 2048 bytes when comma-separated" -}}
{{- end -}}
{{- range $scope := $scopes -}}
{{- if or (gt (len $scope) 128) (not (regexMatch "^[!#$%&()*+./0-9:;<=>?@A-Z\\[\\]^_`a-z{|}~-]+$" $scope)) -}}
{{- fail "auth.external.scopes must contain ASCII OAuth scope tokens without commas or apostrophes" -}}
{{- end -}}
{{- end -}}
{{- $_ := set $external "scopes" $scopes -}}
{{- $secret := $external.clientSecret | default dict -}}
{{- if $secret -}}
{{- range $logical, $name := .Values.existingSecrets -}}
{{- if or (eq $secret.name $logical) (eq $secret.name $name) -}}
{{- fail "auth.external.clientSecret must reference a dedicated OIDC client Secret, separate from bootstrap and workload Secrets" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $_ := set $external "clientSecret" $secret -}}
{{- $email := required "organization.adminEmail must identify the precreated external administrator" .Values.organization.adminEmail -}}
{{- $lowerEmail := lower $email -}}
{{- if or (has $lowerEmail (list "admin@example.com" "user@example.com" "example@example.com")) (hasPrefix "change-me" $lowerEmail) -}}
{{- fail "organization.adminEmail must identify a real precreated external administrator, not a bootstrap placeholder" -}}
{{- end -}}
{{- $_ := set $selection "external" $external -}}
{{- $_ := set $selection "adminEmail" $email -}}
{{- $_ := set $selection "redirectUri" (printf "%s/v1/auth/callback" (include "marty.publicOrigin" .)) -}}
{{- $_ := set $selection "postLogoutRedirectUri" (include "marty.publicOrigin" .) -}}
{{- else if not (empty $auth.external) -}}
{{- fail "auth.external requires auth.provider=external" -}}
{{- end -}}
{{- $encoded := $selection | toJson -}}
{{- if gt (len $encoded) 16384 -}}
{{- fail "authentication selection exceeds the 16384-byte retained renewal record limit" -}}
{{- end -}}
{{- $encoded -}}
{{- end -}}

{{- define "marty.externalAuthConfig" -}}
{{- $selection := include "marty.authSelection" . | fromJson -}}
{{- $external := $selection.external -}}
OIDC_PROVIDER_MODE: external
OIDC_CLIENT_ID: {{ $external.clientId | quote }}
OIDC_ISSUER_URL: {{ $external.issuerUrl | quote }}
OIDC_ISSUER_URL_INTERNAL: {{ $external.issuerUrl | quote }}
OIDC_ISSUER_URL_EXTERNAL: {{ $external.issuerUrl | quote }}
OIDC_EXTERNAL_ISSUER_URL: {{ $external.issuerUrl | quote }}
OIDC_ALLOWED_ALGORITHMS: {{ join "," $external.allowedAlgorithms | quote }}
OIDC_TRUSTED_ENDPOINT_ORIGINS: {{ join "," $external.trustedEndpointOrigins | quote }}
OIDC_SCOPES: {{ join "," $external.scopes | quote }}
OIDC_REDIRECT_URI: {{ $selection.redirectUri | quote }}
OIDC_POST_LOGOUT_REDIRECT_URI: {{ $selection.postLogoutRedirectUri | quote }}
KEYCLOAK_ADMIN_URL: ""
KEYCLOAK_TOKEN_EXCHANGE_ENABLED: "false"
KEYCLOAK_PASSKEYS_ENABLED: "false"
CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER: "false"
CREDENTIAL_LOGIN_CREATE_USERS: "false"
{{- end -}}

{{- define "marty.validateAuthOverrides" -}}
{{- $provider := include "marty.authProvider" . -}}
{{- if eq $provider "external" -}}
{{- range $key, $_ := .Values.config -}}
{{- if or (hasPrefix "OIDC_" $key) (hasPrefix "KEYCLOAK_" $key) (hasPrefix "KC_" $key) (hasPrefix "MARTY_API_CLIENT_" $key) (hasPrefix "MARTY_ORG_ADMIN_" $key) (has $key (list "CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER" "CREDENTIAL_LOGIN_CREATE_USERS" "MARTY_INITIALIZE_KEYCLOAK_DATABASE")) -}}
{{- fail (printf "config.%s conflicts with auth.provider=external; use auth.external and organization.adminEmail for login, and configure account policy at the external provider" $key) -}}
{{- end -}}
{{- end -}}
{{- else if and (hasKey .Values.config "OIDC_PROVIDER_MODE") (ne .Values.config.OIDC_PROVIDER_MODE "keycloak") -}}
{{- fail "select external login through auth.provider=external, not config.OIDC_PROVIDER_MODE" -}}
{{- end -}}
{{- end -}}
