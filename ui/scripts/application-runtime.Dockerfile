FROM nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8

ARG APPLICATION_CONTEXT_SHA
LABEL io.elevenid.application-runtime.scope="diagnostic" \
      io.elevenid.application-runtime.context-sha256="${APPLICATION_CONTEXT_SHA}"

RUN rm -rf /usr/share/nginx/html && mkdir -p /usr/share/nginx/html /scripts
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html/ /usr/share/nginx/html/
COPY scripts/load-secrets-env.sh /scripts/load-secrets-env.sh
COPY scripts/ui-production-start.sh /docker-entrypoint.d/40-ui-production.sh

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
