{{- define "marty.labels" -}}
app.kubernetes.io/name: marty
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "marty.image" -}}
{{- $reference := required (printf "images.%s must be a verified release image digest" .role) (index .root.Values.images .role) -}}
{{- include "marty.immutableImage" (dict "name" (printf "images.%s" .role) "reference" $reference) -}}
{{- end -}}

{{- define "marty.immutableImage" -}}
{{- $reference := required (printf "%s must be a verified image digest" .name) .reference -}}
{{- if not (regexMatch "^[^@[:space:]]+@sha256:[a-f0-9]{64}$" $reference) -}}
{{- fail (printf "%s must be a complete immutable repository@sha256 reference" .name) -}}
{{- end -}}
{{- $reference -}}
{{- end -}}

{{- define "marty.secretName" -}}
{{- required (printf "existingSecrets[%s] must name an existing Secret" .name) (index .root.Values.existingSecrets .name) -}}
{{- end -}}

{{- define "marty.endpointHost" -}}
{{- $host := lower .host -}}
{{- $dns := $host -}}
{{- if .allowWildcard -}}
{{- $dns = trimPrefix "*." $dns -}}
{{- end -}}
{{- if regexMatch "^[0-9.]+$" $dns -}}
{{- $octet := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])" -}}
{{- if or (not .allowIp) (not (regexMatch (printf "^%s(\\.%s){3}$" $octet $octet) $dns)) -}}
{{- fail (printf "%s must be a valid DNS hostname%s" .name (ternary " or IPv4 address" " (IP literals cannot be Ingress hosts)" .allowIp)) -}}
{{- end -}}
{{- else -}}
{{- if or (gt (len $host) 253) (not (regexMatch "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$" $dns)) -}}
{{- fail (printf "%s must be a valid DNS hostname%s, without a scheme, port, or path; IPv6 endpoints are not supported by this chart" .name (ternary " or IPv4 address" "" .allowIp)) -}}
{{- end -}}
{{- end -}}
{{- $host -}}
{{- end -}}

{{- define "marty.publicHost" -}}
{{- $validated := include "marty.endpointHost" (dict "name" "publicHost" "host" (required "publicHost must identify this installation" .Values.publicHost) "allowIp" true "allowWildcard" false) -}}
{{- .Values.publicHost -}}
{{- end -}}

{{- define "marty.publicOrigin" -}}
{{- $host := include "marty.publicHost" . -}}
{{- $origin := .Values.publicOrigin | default (printf "https://%s" $host) -}}
{{- if not (regexMatch "^https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?$" $origin) -}}
{{- fail "publicOrigin must be an HTTPS origin without credentials, a path, query, or fragment" -}}
{{- end -}}
{{- $authority := splitList ":" (trimPrefix "https://" $origin) -}}
{{- if ne (lower (index $authority 0)) (lower $host) -}}
{{- fail "publicOrigin must use publicHost; put the optional HTTPS port in publicOrigin only" -}}
{{- end -}}
{{- if eq (len $authority) 2 -}}
{{- $port := atoi (index $authority 1) -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail "publicOrigin port must be between 1 and 65535" -}}
{{- end -}}
{{- end -}}
{{- $origin -}}
{{- end -}}

{{- define "marty.ingressHost" -}}
{{- if .Values.ingress.host -}}
{{- include "marty.endpointHost" (dict "name" "ingress.host" "host" .Values.ingress.host "allowIp" false "allowWildcard" true) -}}
{{- else -}}
{{- $host := include "marty.publicHost" . | lower -}}
{{- if not (regexMatch "^[0-9.]+$" $host) -}}
{{- $host -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "marty.configData" -}}
{{- $host := include "marty.publicHost" . -}}
{{- $email := required "organization.adminEmail must identify the installation operator" .Values.organization.adminEmail -}}
{{- $origin := include "marty.publicOrigin" . -}}
{{- range $key := list "SMTP_PASSWORD" "KEYCLOAK_SMTP_PASSWORD" -}}
{{- if hasKey $.Values.config $key -}}
{{- fail (printf "config.%s is a credential: put SMTP_PASSWORD in the existing marty-secrets Secret (name selected by existingSecrets.marty-secrets), not in Helm values" $key) -}}
{{- end -}}
{{- end -}}
{{- $did := .Values.organization.did | default (printf "did:web:%s:orgs:%s" (replace ":" "%3A" (trimSuffix "/" (trimPrefix "https://" $origin))) .Values.organization.slug) -}}
{{- $cfg := .Files.Get "files/config-defaults.yaml" | fromYaml -}}
{{- range $key, $value := $cfg -}}
{{- if or (hasSuffix "_TLS_KMS_ADDR" $key) (eq $key "KEYCLOAK_KMS_ADDR") -}}
{{- $_ := set $cfg $key $.Values.openbao.address -}}
{{- end -}}
{{- end -}}
{{- $_ := set $cfg "BAO_ADDR" .Values.openbao.address -}}
{{- $_ := set $cfg "PUBLIC_DOMAIN" (trimSuffix "/" (trimPrefix "https://" $origin)) -}}
{{- $_ := set $cfg "PUBLIC_API_URL" $origin -}}
{{- $_ := set $cfg "UI_BASE_URL" $origin -}}
{{- $_ := set $cfg "ISSUER_BASE_URL" $origin -}}
{{- $_ := set $cfg "CANVAS_OAUTH_COMPLETION_REDIRECT_URL" (printf "%s/console/org/deploy/canvas" $origin) -}}
{{- $_ := set $cfg "KC_HOSTNAME" $origin -}}
{{- $_ := set $cfg "CORS_ORIGINS" $origin -}}
{{- $_ := set $cfg "MARTY_ISSUER_BASE_URL" $origin -}}
{{- $_ := set $cfg "MARTY_ORG_ID" .Values.organization.id -}}
{{- $_ := set $cfg "MARTY_ORG_SLUG" .Values.organization.slug -}}
{{- $_ := set $cfg "MARTY_ORG_DOMAIN" $host -}}
{{- $_ := set $cfg "MARTY_ORG_ADMIN_EMAIL" $email -}}
{{- $_ := set $cfg "MARTY_ISSUER_DID" $did -}}
{{- $_ := set $cfg "OID4VP_ISSUER_DID" $did -}}
{{- $_ := set $cfg "CREDENTIAL_LOGIN_ISSUER_DID" $did -}}
{{- $_ := set $cfg "OIDC_ISSUER_URL" "http://keycloak:8080/realms/11id" -}}
{{- $_ := set $cfg "OIDC_ISSUER_URL_INTERNAL" "http://keycloak:8080/realms/11id" -}}
{{- $_ := set $cfg "OIDC_ISSUER_URL_EXTERNAL" (printf "%s/realms/11id" $origin) -}}
{{- $_ := set $cfg "OIDC_EXTERNAL_ISSUER_URL" (printf "%s/realms/11id" $origin) -}}
{{- $_ := set $cfg "OIDC_REDIRECT_URI" (printf "%s/v1/auth/callback" $origin) -}}
{{- $_ := set $cfg "OIDC_POST_LOGOUT_REDIRECT_URI" $origin -}}
{{- $_ := set $cfg "FLOW_CALLBACK_DESTINATIONS" (printf "%s|http://auth:8001/internal/v1/auth/credential-verified?nonce=__MARTY_TOKEN__" .Values.organization.id) -}}
{{- $cfg = mergeOverwrite $cfg .Values.config -}}
{{- range $key, $value := $cfg }}
{{ $key }}: {{ $value | toString | quote }}
{{- end -}}
{{- end -}}

{{- define "marty.podSettings" -}}
serviceAccountName: marty-app
automountServiceAccountToken: false
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "marty.podAnnotations" -}}
checksum/config: {{ include "marty.configData" . | sha256sum | quote }}
{{- range $key, $value := .Values.release }}
{{- if $value }}
marty.11id.dev/{{ $key }}: {{ $value | toString | quote }}
{{- end }}
{{- end }}
{{- with .Values.podAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "marty.env" -}}
{{- range .env -}}
{{- $env := deepCopy . -}}
{{- with $env.valueFrom -}}
{{- with .secretKeyRef -}}
{{- $_ := set . "name" (include "marty.secretName" (dict "root" $.root "name" .name)) -}}
{{- end -}}
{{- end }}
- {{ toYaml $env | nindent 2 | trim }}
{{- end -}}
{{- end -}}

{{- define "marty.volumes" -}}
{{- range .volumes -}}
{{- $volume := deepCopy . -}}
{{- with $volume.secret -}}
{{- $_ := set . "secretName" (include "marty.secretName" (dict "root" $.root "name" .secretName)) -}}
{{- $_ := set . "defaultMode" 288 -}}
{{- end }}
- {{ toYaml $volume | nindent 2 | trim }}
{{- end -}}
{{- end -}}
