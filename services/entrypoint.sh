#!/bin/sh
set -e

echo "Starting service: $SERVICE_NAME"
echo "Working directory: $(pwd)"
echo "Python version: $(python --version)"

# Change to services directory and run service module with -m flag
# This ensures the service is treated as a package with proper relative imports
cd /app/services
exec python -m ${SERVICE_NAME}.main
