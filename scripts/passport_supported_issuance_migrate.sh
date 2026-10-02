#!/bin/sh
set -eu

# The released Credentials image owns the issuance Alembic history. Read the
# disposable database secret inside the container so Docker inspect never
# contains the password or an environment variable with its value.
password=$(cat /run/secrets/marty_db_password)
export DATABASE_URL="postgresql+asyncpg://marty:${password}@postgres:5432/marty"
exec python manage_migrations.py upgrade
