# syntax=docker/dockerfile:1.7
# Marty UI web application image
# Private producers may replace this empty stage with a named BuildKit context.
# The default customer/public build never receives private commerce sources.
FROM oven/bun:1.3.14-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0 AS commerce_extension
RUN mkdir /extension

FROM oven/bun:1.3.14-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0 AS builder

ARG UI_VARIANT=public
ARG SELFHOST_PUBLIC_PROFILE=full
ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown
ARG MARTY_PRODUCTION_PAGES=public
ARG MARTY_COMMERCE_SOURCE_SHA
ARG MARTY_API_CORE_VERSION
ARG MARTY_API_CORE_URI
ARG MARTY_API_CORE_DIGEST
ARG MARTY_BLOG_VERSION
ARG MARTY_BLOG_URI
ARG MARTY_BLOG_DIGEST

# Set environment variables
ENV NODE_ENV=production
ENV VITE_UI_VARIANT=${UI_VARIANT}
ENV VITE_SELFHOST_PUBLIC_PROFILE=${SELFHOST_PUBLIC_PROFILE}
ENV MARTY_PRODUCTION_PAGES=${MARTY_PRODUCTION_PAGES}
ENV MARTY_COMMERCE_SOURCE_SHA=${MARTY_COMMERCE_SOURCE_SHA}
ENV VITE_ISSUER_API=http://localhost:8080
ENV VITE_VERIFIER_API=http://localhost:8081
ENV VITE_WALLET_API=http://localhost:8082
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /workspace/marty-ui/ui

# Install Chromium for prerendering
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont

COPY ui/package.json ui/bun.lock ./
COPY ui/scripts/patch-prerenderer-ts-deepmerge.cjs ./scripts/patch-prerenderer-ts-deepmerge.cjs
RUN test -n "$MARTY_API_CORE_VERSION" \
    && test -n "$MARTY_BLOG_VERSION" \
    && test -n "$MARTY_API_CORE_URI" \
    && test -n "$MARTY_API_CORE_DIGEST" \
    && test -n "$MARTY_BLOG_URI" \
    && test -n "$MARTY_BLOG_DIGEST" \
    && wget -q -O /tmp/marty-api-core.tgz "$MARTY_API_CORE_URI" \
    && wget -q -O /tmp/marty-blog.tgz "$MARTY_BLOG_URI" \
    && echo "${MARTY_API_CORE_DIGEST#sha256:}  /tmp/marty-api-core.tgz" | sha256sum -c - \
    && echo "${MARTY_BLOG_DIGEST#sha256:}  /tmp/marty-blog.tgz" | sha256sum -c - \
    && bun pm pkg set "dependencies.@elevenid/marty-api-core=file:/tmp/marty-api-core.tgz" \
    && bun pm pkg set "dependencies.@elevenid/marty-blog=file:/tmp/marty-blog.tgz" \
    && bun install \
    && ln -sfn /workspace/marty-ui/ui/node_modules /workspace/node_modules

# Copy application code
COPY ui/ .
COPY --from=commerce_extension /extension /workspace/commerce-extension

# Build the application
RUN { [ "$SELFHOST_PUBLIC_PROFILE" = "full" ] || [ "$SELFHOST_PUBLIC_PROFILE" = "tester" ]; } \
    && { [ "$UI_VARIANT" = "public" ] || [ "$UI_VARIANT" = "selfhost" ]; } \
    && if [ "$MARTY_PRODUCTION_PAGES" = full ]; then export MARTY_COMMERCE_EXTENSION_PATH=/workspace/commerce-extension/src/extension.jsx; fi \
    && if [ "$UI_VARIANT" = "selfhost" ]; then bun run build:selfhost && mv dist-selfhost dist-final; else bun run build && mv dist dist-final; fi \
    && if [ "$UI_VARIANT" = "public" ]; then \
      test -s dist-final/index.html \
      && grep -q 'ElevenID' dist-final/index.html \
      && ! grep -q 'Welcome to nginx' dist-final/index.html; \
    fi \
    && if [ "$UI_VARIANT" = public ]; then audience=production; else audience=customer; fi \
    && printf '{"component":"ui","release_version":"%s","marty_ui_sha":"%s","audience":"%s","ui_variant":"%s"}\n' \
      "$MARTY_RELEASE_VERSION" "$MARTY_UI_SHA" "$audience" "$UI_VARIANT" > dist-final/marty-ui-release.json \
    && if [ "$MARTY_PRODUCTION_PAGES" = full ]; then \
      bun -e 'const p="dist-final/marty-ui-release.json"; const m=await Bun.file(p).json(); m.production_pages="full"; m.commerce_extension={repository:"ElevenID/marty-subscriptions",source_sha:process.env.MARTY_COMMERCE_SOURCE_SHA}; await Bun.write(p,JSON.stringify(m)+"\n");'; \
    fi

# Use nginx to serve the built application
FROM nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8 AS runtime-base

ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown

LABEL org.opencontainers.image.source="https://github.com/ElevenID/marty-ui" \
      org.opencontainers.image.revision="${MARTY_UI_SHA}" \
      org.opencontainers.image.version="${MARTY_RELEASE_VERSION}"

# Copy both nginx configs - use build arg to select which one
# Default to PROD for safety - must explicitly opt-in to dev config
ARG NGINX_CONFIG=nginx.prod.conf
COPY ui/${NGINX_CONFIG} /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Health check (use 127.0.0.1 instead of localhost for IPv6 compatibility)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:80/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

# The self-host image must keep the static source separate from the served
# directory because the existing startup hook injects deployment-specific
# runtime metadata before Nginx starts. The customer bundle removes source
# checkout bind mounts, so both scripts and the source assets belong here.
FROM runtime-base AS selfhost
ARG UI_VARIANT=public
ARG NGINX_CONFIG=nginx.prod.conf
ARG SELFHOST_PUBLIC_PROFILE=full
RUN test "$UI_VARIANT" = selfhost && test "$NGINX_CONFIG" = nginx.spa.conf
LABEL io.elevenid.selfhost.public-profile="${SELFHOST_PUBLIC_PROFILE}" \
      io.elevenid.ui.audience="customer"
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:80/healthz || exit 1
COPY --from=builder /workspace/marty-ui/ui/dist-final /opt/marty-ui-static
COPY scripts/load-secrets-env.sh /scripts/load-secrets-env.sh
COPY scripts/ui-selfhost-start.sh /docker-entrypoint.d/40-ui-selfhost.sh
RUN chmod +x /scripts/load-secrets-env.sh /docker-entrypoint.d/40-ui-selfhost.sh

# The independently versioned console reaches one configured public server
# origin. It does not require backend images or a shared Docker network.
FROM selfhost AS console
COPY docker/nginx-console.conf.template /etc/nginx/marty-console.conf.template
COPY scripts/console-api-start.sh /docker-entrypoint.d/45-console-api.sh
RUN chmod +x /docker-entrypoint.d/45-console-api.sh

# Keep the existing public image as the default final target. Building the
# self-host variant requires an explicit target and variant selection.
FROM runtime-base AS public
ARG UI_VARIANT=public
RUN test "$UI_VARIANT" = public
LABEL io.elevenid.ui.audience="production"
COPY --from=builder /workspace/marty-ui/ui/dist-final /usr/share/nginx/html
COPY scripts/ui-production-start.sh /docker-entrypoint.d/40-ui-production.sh
COPY scripts/load-secrets-env.sh /scripts/load-secrets-env.sh
RUN chmod +x /docker-entrypoint.d/40-ui-production.sh /scripts/load-secrets-env.sh
