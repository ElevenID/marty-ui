#!/bin/sh
# Fixed native setup entry point. No arbitrary SQL, endpoint, role or credentials
# are accepted as arguments. Only the admitted Postgres image runs this file.
set -eu

case "${1:-}" in
    roles|grants) operation=$1 ;;
    *) echo 'Select the native feature roles or grants phase.' >&2; exit 64 ;;
esac
[ "$#" -eq 1 ] || exit 64

unset PGSERVICE PGSERVICEFILE PGOPTIONS PGPASSFILE
export PGHOST=postgres PGPORT=5432 PGDATABASE=marty PGUSER=postgres
export PGSSLMODE=verify-full PGSSLROOTCERT=/run/feature-profile/feature_postgres_ca
export PGCONNECT_TIMEOUT=5
if ! PGPASSWORD=$(cat /run/secrets/postgres_password); then
    echo 'Feature database owner credential is unavailable.' >&2
    exit 1
fi
[ -n "$PGPASSWORD" ] || exit 1
export PGPASSWORD

if [ "$operation" = roles ]; then
    if ! FEATURE_DATABASE_PASSWORDS=$(cat /run/feature-profile/feature_database_passwords); then
        echo 'Feature database credential inventory is unavailable.' >&2
        exit 1
    fi
    export FEATURE_DATABASE_PASSWORDS
fi

# Ignore psqlrc and suppress credential-bearing error context from a failed
# password statement. The fixed public phase name is enough for owner recovery;
# neither the password inventory nor any DSN is printed or put in argv.
if ! psql -X --no-password --quiet --set=ON_ERROR_STOP=1 \
    --file="/run/feature-profile-code/database-$operation.sql" >/dev/null 2>/dev/null; then
    echo "Native feature database $operation phase refused; preserve installation evidence." >&2
    exit 1
fi
unset PGPASSWORD FEATURE_DATABASE_PASSWORDS
echo "Native feature database $operation phase completed."
