#!/bin/sh
set -e

. /app/load-secrets-env.sh

require_secret_var MARTY_DB_PASSWORD

admin_email="$(printf '%s' "${MARTY_ORG_ADMIN_EMAIL:-}" | tr '[:upper:]' '[:lower:]' | tr -d '\r')"
case "${admin_email}" in
	""|admin@example.com|user@example.com|example@example.com|change-me*)
		echo "MARTY_ORG_ADMIN_EMAIL must be set to a customer-controlled email before migrations run." >&2
		exit 1
		;;
esac

if [ "${MARTY_LICENSE_PREFLIGHT_DONE:-0}" != "1" ]; then
	case "$(printf '%s' "${MARTY_LICENSE_ENFORCEMENT:-}" | tr '[:upper:]' '[:lower:]')" in
		""|0|false|off|disabled|none)
			;;
		*)
			python -m marty_common.license_gate
			export MARTY_LICENSE_PREFLIGHT_DONE=1
			;;
	esac
fi

exec python run_all_migrations.py