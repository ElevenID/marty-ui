#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.
# PostgreSQL initialization script for multi-database setup
# Creates multiple databases in a single PostgreSQL instance
# This script is executed once when the container is first created

set -e

read_secret_value() {
    var_name="$1"
    default_value="$2"
    file_var_name="${var_name}_FILE"

    eval "current_value=\${${var_name}:-}"
    eval "file_path=\${${file_var_name}:-}"

    if [ -n "${current_value}" ] && [ -n "${file_path}" ]; then
        echo "Both ${var_name} and ${file_var_name} are set; choose one." >&2
        exit 1
    fi

    if [ -n "${file_path}" ]; then
        tr -d '\r' < "${file_path}"
        return 0
    fi

    printf '%s' "${current_value:-${default_value}}"
}

case "${MARTY_INITIALIZE_KEYCLOAK_DATABASE:-true}" in
    true) KEYCLOAK_DB_PASSWORD_VALUE="$(read_secret_value KEYCLOAK_DB_PASSWORD keycloak)" ;;
    false) ;;
    *) echo "MARTY_INITIALIZE_KEYCLOAK_DATABASE must be true or false." >&2; exit 1 ;;
esac
MARTY_DB_PASSWORD_VALUE="$(read_secret_value MARTY_DB_PASSWORD marty_dev_password)"

# Function to create database and user
create_database_and_user() {
    database=$1
    user=$2
    
    echo "Creating database '$database' with user '$user'..."
    
    # PostgreSQL 15+ psql reads the password from its environment, so it never
    # enters argv or shell-generated SQL. Let psql and format() quote customer
    # passwords and identifiers, including quotes, backslashes and newlines.
    # Ignore psqlrc so local echo settings cannot print credential-bearing SQL.
    MARTY_INIT_DATABASE="$database" MARTY_INIT_USER="$user" MARTY_INIT_PASSWORD="$3" \
        psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
        \getenv database_name MARTY_INIT_DATABASE
        \getenv database_user MARTY_INIT_USER
        \getenv database_password MARTY_INIT_PASSWORD
        SELECT format('CREATE USER %I WITH PASSWORD %L', :'database_user', :'database_password')
        WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = :'database_user')\gexec

        SELECT format('CREATE DATABASE %I OWNER %I', :'database_name', :'database_user')
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'database_name')\gexec

        GRANT ALL PRIVILEGES ON DATABASE :"database_name" TO :"database_user";
EOSQL
    
    echo "Database '$database' created successfully."
}

# Create Keycloak database
if [ "${MARTY_INITIALIZE_KEYCLOAK_DATABASE:-true}" = true ]; then
    create_database_and_user "keycloak" "keycloak" "${KEYCLOAK_DB_PASSWORD_VALUE}"
fi

# Create Marty microservices database
create_database_and_user "marty" "marty" "${MARTY_DB_PASSWORD_VALUE}"

# Create Applicant database (uses same user but separate database)
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
    SELECT 'CREATE DATABASE marty_applicants OWNER marty'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'marty_applicants')\gexec
    
    GRANT ALL PRIVILEGES ON DATABASE marty_applicants TO marty;
EOSQL

echo "All databases initialized successfully."
