{{/* Preserve public trust roots while adding the private Redis issuer CA. */}}
{{- define "marty.redisTrustInit" -}}
- name: redis-trust
  image: {{ include "marty.image" (dict "root" . "role" "services") | quote }}
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  command:
    - /bin/sh
    - -ec
    - cat /etc/ssl/certs/ca-certificates.crt /redis-ca/ca.crt > /trust/ca-certificates.crt
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
{{- end -}}

{{- define "marty.redisTrustVolumes" -}}
- name: redis-ca
  secret:
    secretName: {{ include "marty.secretName" (dict "root" . "name" "marty-redis-tls") }}
    defaultMode: 0444
    items:
      - key: ca.crt
        path: ca.crt
- name: redis-trust
  emptyDir:
    medium: Memory
    sizeLimit: 2Mi
{{- end -}}
