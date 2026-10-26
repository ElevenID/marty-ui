# Console-free self-host composition

The opt-in source overlay `docker-compose.selfhost.api-only.yml` removes the UI
service and the edge's UI dependency. The backend and existing Canvas worker keep
their current composition. No-Canvas and minimal verifier distributions require
their separate migration and qualification work.

Review the selected source model using the installation's explicit environment:

```sh
docker compose --env-file <selfhost-env-file> \
  -f docker-compose.selfhost.prod.yml \
  -f docker-compose.selfhost.bundle.override.yml \
  -f docker-compose.selfhost.api-only.yml config --services
```

The result must omit `ui`, including when rendering all profiles. Gateway, Flow
and Keycloak remain required edge dependencies. Omit the API-only overlay for the
existing full-stack composition; its default console routing stays enabled.

In API-only mode, `/v1/`, `/openapi.json`, `/docs`, `/redoc`, wallet discovery,
credential metadata and readiness routes continue to reach their backend.
Console pages, the Canvas UI experience, the UI-owned AI plugin document and the
SPA fallback return 404. Backend readiness failures remain failures. The renderer
accepts only `true` or `false` for `SELFHOST_CONSOLE_ENABLED` and rejects other
values before starting Nginx. The overlay selects `false`.

This source profile is not yet a qualified distribution in published self-host
bundles or installers. Adoption must update profile-aware image/dependency/secret
inventories and runtime admission together, preserve the existing full-stack
contract, and verify an installed artifact with no UI container. The operator
bootstrap, actual CLI/SDK credential journey, KMS custody, upgrade and recovery
evidence remain required before support claims change.

The required public-protocol CI lane runs
`scripts/probe_selfhost_api_only_edge.py` with a pinned Nginx image. It exercises
real edge HTTP routing on an isolated internal network with no console and no
published ports, checks disabled/default/invalid settings, and verifies teardown
of its exact owned containers and network. Its backend is a routing fixture;
this probe does not qualify Marty credential behavior or a production install.
