{{- define "marty.nginx" -}}
# ClusterIP Service names are stable; nginx uses ordinary pod DNS at start.
# The external Ingress terminates HTTPS and retains the original Host port.
map $http_x_forwarded_port $marty_forwarded_port {
    default $http_x_forwarded_port;
    "" 443;
}
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Commercial terms and plan checkout are withheld from browser delivery.
    location = /pricing { return 404; }
    location ^~ /pricing/ { return 404; }
    client_max_body_size 50M;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Port $marty_forwarded_port;
    proxy_redirect off;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location = /edge-healthz {
        default_type text/plain;
        return 200 "ok\n";
    }
    location = /.well-known/ai-plugin.json { try_files $uri =404; }
    location ~ ^/(api|auth|v1|\.well-known|credentials)/ {
        proxy_pass http://gateway:8000;
    }
    location ~ ^/(ready|health|health/ready|openapi.json|docs|redoc)$ {
        proxy_pass http://gateway:8000;
    }
    location = /openapi.yaml {
        absolute_redirect off;
        return 308 /openapi.json;
    }
    location ~ "^/org/([0-9a-fA-F-]{36})/(credential-manager|apple-wallet|waltid)/\.well-known/(openid-credential-issuer|oauth-authorization-server)$" {
        rewrite ^/org/([^/]+)/([^/]+)/\.well-known/([^/]+)$ /.well-known/$3/org/$1/$2 break;
        proxy_pass http://gateway:8000;
        add_header Access-Control-Allow-Origin * always;
    }
    location ~ "^/org/([0-9a-fA-F-]{36})/\.well-known/(openid-credential-issuer|oauth-authorization-server)$" {
        rewrite ^/org/([^/]+)/\.well-known/([^/]+)$ /.well-known/$2/org/$1 break;
        proxy_pass http://gateway:8000;
        add_header Access-Control-Allow-Origin * always;
    }
    location /org/ {
        default_type application/json;
        return 404 '{"error":"not_found"}';
    }
    location = /oid4vp/did.json {
        proxy_pass http://flow:8011;
        add_header Access-Control-Allow-Origin * always;
    }
    location /oid4vp/ {
        default_type application/json;
        return 404 '{"error":"not_found"}';
    }
    location ~ "^/orgs/[a-zA-Z0-9._-]+/did\.json$" {
        proxy_pass http://gateway:8000;
        add_header Access-Control-Allow-Origin * always;
    }
    location /orgs/ {
        default_type application/json;
        return 404 '{"error":"not_found"}';
    }
    location ~ ^/(realms|resources)/ { proxy_pass http://keycloak:8080; }
    location ^~ /v1/integrations/canvas/lti/ {
        proxy_pass http://gateway:8000;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Content-Security-Policy;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Content-Security-Policy "frame-ancestors {{ .Values.ui.canvasFrameAncestors }}" always;
    }
    location = /canvas/lti/experience {
        try_files /index.html =404;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Content-Security-Policy "frame-ancestors {{ .Values.ui.canvasFrameAncestors }}" always;
    }
    location / { try_files $uri $uri/ /index.html; }
}
{{- end -}}
