#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.
set -e

if [ -r /app/load-secrets-env.sh ]; then
	. /app/load-secrets-env.sh
elif [ -r /usr/local/bin/load-secrets-env.sh ]; then
	# Dedicated CI images retain their existing public helper location.
	. /usr/local/bin/load-secrets-env.sh
fi

# Compose historically used both hyphenated and underscored service names.
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

if [ "$MODULE_NAME" = "organization" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-organization
fi

if [ "$MODULE_NAME" = "auth" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-auth
fi

if [ "$MODULE_NAME" = "credential_template" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-credential-template
fi

if [ "$MODULE_NAME" = "presentation_policy" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-presentation-policy
fi

if [ "$MODULE_NAME" = "trust_profile" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-trust-profile
fi

if [ "$MODULE_NAME" = "applicant" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-applicant
fi

if [ "$MODULE_NAME" = "device_registration" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-device-registration
fi

if [ "$MODULE_NAME" = "verification" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-verification-service "$@"
fi

if [ "$MODULE_NAME" = "issuance_native" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-issuance-service
fi

if [ "$MODULE_NAME" = "canvas_sync_worker" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-canvas-sync-worker
fi

if [ "$MODULE_NAME" = "deployment_profile" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-deployment-profile
fi

if [ "$MODULE_NAME" = "compliance_profile" ]; then
	echo "Starting canonical Rust service: $SERVICE_NAME"
	exec /usr/local/bin/marty-compliance-profile
fi

echo "Unsupported SERVICE_NAME: ${SERVICE_NAME:-<empty>}" >&2
exit 64
