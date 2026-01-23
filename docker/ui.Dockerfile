# OpenWallet Foundation Demo - Enhanced UI Application
FROM node:18-alpine AS builder

# Set environment variables
ENV NODE_ENV=production
ENV REACT_APP_ISSUER_API=http://localhost:8080
ENV REACT_APP_VERIFIER_API=http://localhost:8081
ENV REACT_APP_WALLET_API=http://localhost:8082

# Set work directory
WORKDIR /app

# Install dependencies
COPY ui/package.json ./
RUN npm install

# Copy application code
COPY ui/ .

# Build the application
RUN npm run build

# Use nginx to serve the built application
FROM nginx:alpine

# Copy both nginx configs - use build arg to select which one
# Default to PROD for safety - must explicitly opt-in to dev config
ARG NGINX_CONFIG=nginx.prod.conf
COPY --from=builder /app/build /usr/share/nginx/html
COPY ui/${NGINX_CONFIG} /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Health check (use 127.0.0.1 instead of localhost for IPv6 compatibility)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:80/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
