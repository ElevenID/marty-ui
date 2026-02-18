# OpenWallet Foundation Demo - Enhanced UI Application
FROM oven/bun:alpine AS builder

# Set environment variables
ENV NODE_ENV=production
ENV VITE_ISSUER_API=http://localhost:8080
ENV VITE_VERIFIER_API=http://localhost:8081
ENV VITE_WALLET_API=http://localhost:8082
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# Set work directory
WORKDIR /app

# Install Chromium for prerendering
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont

# Install dependencies
COPY ui/package.json ./
RUN bun install

# Copy application code
COPY ui/ .

# Build the application
RUN bun run build

# Use nginx to serve the built application
FROM nginx:alpine

# Copy both nginx configs - use build arg to select which one
# Default to PROD for safety - must explicitly opt-in to dev config
ARG NGINX_CONFIG=nginx.prod.conf
COPY --from=builder /app/dist /usr/share/nginx/html
COPY ui/${NGINX_CONFIG} /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Health check (use 127.0.0.1 instead of localhost for IPv6 compatibility)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:80/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
