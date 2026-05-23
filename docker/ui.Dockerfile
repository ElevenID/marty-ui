# syntax=docker/dockerfile:1.7
# Marty UI web application image
FROM oven/bun:alpine AS builder

ARG UI_VARIANT=public

# Set environment variables
ENV NODE_ENV=production
ENV VITE_UI_VARIANT=${UI_VARIANT}
ENV VITE_ISSUER_API=http://localhost:8080
ENV VITE_VERIFIER_API=http://localhost:8081
ENV VITE_WALLET_API=http://localhost:8082
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# Set work directory to preserve package.json file:../../ dependency paths.
WORKDIR /workspace/marty-ui/ui

# Install Chromium for prerendering
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont

# Install dependencies. The UI package references sibling workspace packages via
# file:../../ paths, so the build command must provide these named contexts:
#   --build-context marty-cli=<workspace>/marty-cli
#   --build-context marty-blog=<workspace>/marty-blog
#   --build-context marty-subscriptions=<workspace>/marty-subscriptions
COPY --from=marty-cli packages/api-core /workspace/marty-cli/packages/api-core
COPY --from=marty-blog package.json /workspace/marty-blog/package.json
COPY --from=marty-blog src /workspace/marty-blog/src
COPY --from=marty-subscriptions package.json /workspace/marty-subscriptions/package.json
COPY --from=marty-subscriptions src /workspace/marty-subscriptions/src
COPY ui/package.json ui/bun.lock ./
RUN bun install \
    && ln -sfn /workspace/marty-ui/ui/node_modules /workspace/node_modules \
    && cd /workspace/marty-blog && bun install --production \
    && cd /workspace/marty-subscriptions && bun install --production

# Copy application code
COPY ui/ .

# Build the application
RUN if [ "$UI_VARIANT" = "selfhost" ]; then bun run build:selfhost && mv dist-selfhost dist-final; else bun run build && mv dist dist-final; fi

# Use nginx to serve the built application
FROM nginx:alpine

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
