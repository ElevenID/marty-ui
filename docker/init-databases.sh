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

KEYCLOAK_DB_PASSWORD_VALUE="$(read_secret_value KEYCLOAK_DB_PASSWORD keycloak)"
MARTY_DB_PASSWORD_VALUE="$(read_secret_value MARTY_DB_PASSWORD marty_dev_password)"

# Function to create database and user
create_database_and_user() {
    database=$1
    user=$2
    password=$3
    
    echo "Creating database '$database' with user '$user'..."
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        -- Create user if not exists
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$user') THEN
                CREATE USER $user WITH PASSWORD '$password';
            END IF;
        END
        \$\$;
        
        -- Create database if not exists
        SELECT 'CREATE DATABASE $database OWNER $user'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$database')\gexec
        
        -- Grant privileges
        GRANT ALL PRIVILEGES ON DATABASE $database TO $user;
EOSQL
    
    echo "Database '$database' created successfully."
}

# Create Keycloak database
create_database_and_user "keycloak" "keycloak" "${KEYCLOAK_DB_PASSWORD_VALUE}"

# Create Marty microservices database
create_database_and_user "marty" "marty" "${MARTY_DB_PASSWORD_VALUE}"

# Create Applicant database (uses same user but separate database)
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE marty_applicants OWNER marty'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'marty_applicants')\gexec
    
    GRANT ALL PRIVILEGES ON DATABASE marty_applicants TO marty;
EOSQL

echo "All databases initialized successfully."
