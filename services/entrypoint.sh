#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.
set -e

if [ -r /app/load-secrets-env.sh ]; then
	. /app/load-secrets-env.sh
fi

# Convert hyphens to underscores for Python module names
MODULE_NAME=$(echo "$SERVICE_NAME" | tr '-' '_')

echo "Starting service: $SERVICE_NAME (module: $MODULE_NAME)"
echo "Working directory: $(pwd)"
echo "Python version: $(python --version)"

# Change to services directory and run service module with -m flag
# This ensures the service is treated as a package with proper relative imports
cd /app/services
if [ "$MODULE_NAME" = "applicant" ]; then
	python -m applicant.migrate_store_v03
fi
exec python -m ${MODULE_NAME}.main
