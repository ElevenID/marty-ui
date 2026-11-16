{{/* Preserve public roots and add only the private peer CAs each workload needs. */}}
{{- define "marty.redisTrustInit" -}}
- name: redis-trust
  image: {{ include "marty.image" (dict "root" .root "role" "services") | quote }}
  imagePullPolicy: {{ .root.Values.imagePullPolicy }}
  command:
    - /bin/sh
    - -ec
    - cat /etc/ssl/certs/ca-certificates.crt /redis-ca/ca.crt{{ if .withSigningCa }} /signing-ca/ca.crt{{ end }} > /trust/ca-certificates.crt
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    requests:
      cpu: 5m
      memory: 16Mi
    limits:
      cpu: 100m
      memory: 32Mi
  volumeMounts:
    - name: redis-ca
      mountPath: /redis-ca
      readOnly: true
    - name: redis-trust
      mountPath: /trust
    {{- if .withSigningCa }}
    - name: signing-ca
      mountPath: /signing-ca
      readOnly: true
    {{- end }}
{{- end -}}

{{- define "marty.redisTrustVolumes" -}}
- name: redis-ca
  secret:
    secretName: {{ include "marty.secretName" (dict "root" .root "name" "marty-redis-tls") }}
    defaultMode: 0444
    items:
      - key: ca.crt
        path: ca.crt
- name: redis-trust
  emptyDir:
    medium: Memory
    sizeLimit: 2Mi
{{- if .withSigningCa }}
- name: signing-ca
  secret:
    secretName: {{ include "marty.secretName" (dict "root" .root "name" "signing-keys-integration-secret-ca") }}
    defaultMode: 0444
    items:
      - key: ca.crt
        path: ca.crt
{{- end }}
{{- end -}}
