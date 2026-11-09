{{- define "marty.uiDevelopmentContainer" -}}
image: {{ include "marty.immutableImage" (dict "name" "ui.development.nodeImage" "reference" .Values.ui.development.nodeImage) | quote }}
imagePullPolicy: {{ .Values.imagePullPolicy }}
workingDir: /workspace/ui
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
env:
  - name: NPM_CONFIG_CACHE
    value: /tmp/npm-cache
  - name: NODE_ENV
    value: development
  - name: PUPPETEER_SKIP_DOWNLOAD
    value: 'true'
  - name: VITE_UI_VARIANT
    value: selfhost
  - name: VITE_API_URL
    value: ''
  - name: VITE_DEV_PROXY_TARGET
    value: http://gateway:8000
  - name: VITE_DEV_PUBLIC_ORIGIN
    value: {{ .Values.publicOrigin | default (printf "https://%s" .Values.publicHost) | quote }}
volumeMounts:
  - name: ui-dev-source
    mountPath: /workspace/ui
    readOnly: true
  - name: ui-dev-contracts
    mountPath: /workspace/contracts
    readOnly: true
  - name: ui-dev-dependencies
    mountPath: /workspace/ui/node_modules
  - name: ui-dev-tmp
    mountPath: /tmp
{{- end -}}

{{- define "marty.uiDevelopmentProxy" -}}
proxy_pass http://127.0.0.1:3000;
# Location-level headers replace the server's entire inherited header list.
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-Host $http_host;
proxy_set_header X-Forwarded-Port $marty_forwarded_port;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $marty_dev_connection;
proxy_read_timeout 3600s;
proxy_buffering off;
{{- end -}}
