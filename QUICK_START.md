# Quick Reference: Marty-UI Local Development

## Start Development Environment
```bash
cd "/Volumes/Heart of Gold/Github/work/marty-ui"
docker compose --profile dev up -d
```

## Stop Development Environment
```bash
docker compose --profile dev down
```

## Restart a Service (Python changes auto-reload, but for Rust changes)
```bash
docker compose --profile dev restart oid4vc-api
```

## View Logs
```bash
# All services
docker compose --profile dev logs -f

# Specific service
docker compose --profile dev logs -f oid4vc-api

# Last 50 lines
docker compose --profile dev logs --tail=50 oid4vc-api
```

## Check Status
```bash
docker compose --profile dev ps
```

## Rebuild After Major Changes
```bash
docker compose --profile dev down oid4vc-api
docker compose --profile dev build oid4vc-api
docker compose --profile dev up -d oid4vc-api
```

## Test the API
```bash
curl http://localhost:8000/health
```

## Service URLs
- API: http://localhost:8000
- Keycloak: http://localhost:8180
- MailHog: http://localhost:9025
- Postgres: localhost:5433
- Redis: localhost:6379

## Mounted Local Packages
- `marty-credentials` → `/app/marty-credentials`
- `marty-core` → `/app/marty-core`
- `marty-microservices-framework` → `/app/marty-microservices-framework`
- `marty-common` → `/app/marty-common`

## First Startup Time
~3-5 minutes (Rust compilation)

## Subsequent Startup
~30 seconds (if container not removed)

## Configuration Files
- `docker-compose.yml` - Base configuration
- `docker-compose.override.yml` - Local development overrides
- `docker/api.Dockerfile` - API service Dockerfile

## Troubleshooting
```bash
# Check if volumes are mounted
docker exec marty-ui-oid4vc-api-1 ls -la /app/marty-credentials
docker exec marty-ui-oid4vc-api-1 ls -la /app/marty-core

# Check running processes
docker ps --filter "name=marty-ui"

# Get into container
docker exec -it marty-ui-oid4vc-api-1 sh
```
