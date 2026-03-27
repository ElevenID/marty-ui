# Quick Reference: Marty UI Local Development

## Start the full local stack

```bash
cd "/Volumes/Heart of Gold/Github/work/marty-ui"
make dev
```

This starts infrastructure plus the current microservices stack using:

- `docker-compose.base.yml`
- `docker-compose.profile.dev.yml`

## Stop everything

```bash
make down
```

## Restart services after major changes

```bash
make restart
```

## Start only infrastructure

```bash
make infra
```

## Start infra + API microservices

```bash
make run-api
```

## Run the UI natively

```bash
make run-ui
```

## View logs

```bash
# All base services
make logs

# Microservices only
make services-logs
```

## Check status

```bash
make status
```

## Rebuild microservice images

```bash
make services-build
make services-restart
```

## Test the gateway

```bash
curl http://localhost:8000/health
```

## Useful local URLs

- Gateway: http://localhost:8000
- Gateway docs: http://localhost:8000/docs
- Auth docs: http://localhost:8001/docs
- Organization docs: http://localhost:8002/docs
- Keycloak: http://localhost:8180
- MailHog: http://localhost:9025
- Postgres: localhost:5433
- Redis: localhost:6379

## Mounted sibling repositories in dev mode

- `../marty-credentials` → `/app/marty-credentials`
- `../marty-core` → `/app/marty-core`
- `../marty-microservices-framework` → `/app/marty-microservices-framework`
- `../Marty/packages/marty-common` → `/app/marty-common`

## Startup expectations

- First startup: a few minutes if images or wheels must be built
- Subsequent startups: much faster once caches are warm

## Primary configuration files

- `docker-compose.base.yml` - unified base stack
- `docker-compose.profile.dev.yml` - local development overrides
- `docker-compose.profile.tunnel.yml` - optional public tunnel routing
- `services/Dockerfile` - generic microservice image
- `services/Dockerfile.migrations` - migration runner image

## Troubleshooting

```bash
# Check running containers
docker ps --filter "name=marty-"

# Open a shell in the gateway container
make shell

# Check gRPC health for gRPC-enabled services
make grpc-health
```
