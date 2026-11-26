#!/usr/bin/env bash
# Fixed native rootless PostgreSQL transport adapter. The signed Compose model
# supplies the postgres arguments and read-only transport directory. PostgreSQL
# permits a root-owned0640 private key when the server's group can read it:
# https://www.postgresql.org/docs/15/ssl-tcp.html
set -Eeo pipefail

if [[ "$(id -u)" != 0 || "${1:-}" != postgres || "$(id -u postgres)" == 0 ]]; then
    echo 'Native PostgreSQL transport requires its rootless image initialization owner.' >&2
    exit 64
fi

# Reuse the pinned official image's initialization functions, including PGDATA
# and socket ownership. The unprivileged re-entry retains the official initdb,
# init scripts and restart behavior without hard-coding a distribution UID.
source /usr/local/bin/docker-entrypoint.sh
docker_setup_env
docker_create_db_directories
exec gosu postgres:0 /usr/local/bin/docker-entrypoint.sh "$@"
