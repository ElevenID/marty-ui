# syntax=docker/dockerfile:1.7
# Marty UI web application image
FROM oven/bun:alpine AS builder

ARG UI_VARIANT=public
ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown
ARG MARTY_API_CORE_VERSION
ARG MARTY_API_CORE_URI
ARG MARTY_API_CORE_DIGEST
ARG MARTY_BLOG_VERSION
ARG MARTY_BLOG_URI
ARG MARTY_BLOG_DIGEST

# Set environment variables
ENV NODE_ENV=production
ENV VITE_UI_VARIANT=${UI_VARIANT}
ENV VITE_ISSUER_API=http://localhost:8080
ENV VITE_VERIFIER_API=http://localhost:8081
ENV VITE_WALLET_API=http://localhost:8082
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /workspace/marty-ui/ui

# Install Chromium for prerendering
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont

COPY ui/package.json ui/bun.lock ./
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

# Build the application
RUN if [ "$UI_VARIANT" = "selfhost" ]; then bun run build:selfhost && mv dist-selfhost dist-final; else bun run build && mv dist dist-final; fi \
    && printf '{"component":"ui","release_version":"%s","marty_ui_sha":"%s"}\n' \
      "$MARTY_RELEASE_VERSION" "$MARTY_UI_SHA" > dist-final/marty-ui-release.json

# Use nginx to serve the built application
FROM nginx:alpine

ARG MARTY_RELEASE_VERSION=development
ARG MARTY_UI_SHA=unknown

LABEL org.opencontainers.image.source="https://github.com/ElevenID/marty-ui" \
      org.opencontainers.image.revision="${MARTY_UI_SHA}" \
      org.opencontainers.image.version="${MARTY_RELEASE_VERSION}"

# Copy both nginx configs - use build arg to select which one
# Default to PROD for safety - must explicitly opt-in to dev config
ARG NGINX_CONFIG=nginx.prod.conf
COPY --from=builder /workspace/marty-ui/ui/dist-final /usr/share/nginx/html
COPY ui/${NGINX_CONFIG} /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Health check (use 127.0.0.1 instead of localhost for IPv6 compatibility)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:80/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
