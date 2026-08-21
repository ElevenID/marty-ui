#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.
set -e

if [ -r /app/load-secrets-env.sh ]; then
	. /app/load-secrets-env.sh
fi

# Convert hyphens to underscores for Python module names
MODULE_NAME=$(echo "$SERVICE_NAME" | tr '-' '_')

if [ "$MODULE_NAME" = "event_stream" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-event-stream
fi

if [ "$MODULE_NAME" = "gateway" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-gateway
fi

if [ "$MODULE_NAME" = "revocation_profile" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-revocation-profile
fi

if [ "$MODULE_NAME" = "signing_keys" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-signing-keys
fi

if [ "$MODULE_NAME" = "notification" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-notification
fi

if [ "$MODULE_NAME" = "flow" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-flow
fi

echo "Starting service: $SERVICE_NAME (module: $MODULE_NAME)"
echo "Working directory: $(pwd)"
echo "Python version: $(python --version)"

# Change to services directory and import the service through its canonical package name.
# Running `${MODULE_NAME}.main` directly with `python -m` would execute it as
# `__main__`; later adapter imports could then load a second copy of the module.
cd /app/services
if [ "$MODULE_NAME" = "applicant" ]; then
	python -m applicant.migrate_store_v03
fi
exec python -m service_runner
