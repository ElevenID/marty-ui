#!/bin/sh
set -e

# Convert hyphens to underscores for Python module names
MODULE_NAME=$(echo "$SERVICE_NAME" | tr '-' '_')

echo "Starting service: $SERVICE_NAME (module: $MODULE_NAME)"
echo "Working directory: $(pwd)"
echo "Python version: $(python --version)"

# Change to services directory and run service module with -m flag
# This ensures the service is treated as a package with proper relative imports
cd /app/services
exec python -m ${MODULE_NAME}.main
