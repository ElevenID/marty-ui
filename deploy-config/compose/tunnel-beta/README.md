# Tunnel Beta Compose

Canonical compose overlay:

- docker-compose.profile.tunnel.yml

Typical layered command:

- docker compose --env-file <tunnel-env-file> -f docker-compose.base.yml -f docker-compose.beta.yml -f docker-compose.profile.tunnel.yml up -d

Use beta.elevenidllc.com values in the tunnel env file.

The base service image dispatches both `event-stream` and `revocation-profile`
directly to their canonical Rust binaries. No language-selection overlay remains.
Source changes do not mutate the currently pinned beta deployment. Production and
persistent self-host deployments are not updated by this configuration.

`docker-compose.beta.yml` declares the lane as `beta` and requires a
non-placeholder `GRPC_SERVICE_TOKEN` of at least 32 characters. Missing native
service authentication therefore fails startup rather than selecting a
development mode.

Before the one aggregate beta cutover, provision the beta-only workload CA and
distinct service identities without changing the running stack:

```powershell
& .\scripts\ensure-beta-grpc-service-token.ps1
& .\scripts\ensure-beta-workload-identity.ps1
```

The workload helper writes only ignored local files, records their paths in the
generated beta environment file, reuses certificates while they remain valid,
and never prints private keys. The beta release runner requires every Flow
secret and workload file, verifies each certificate against the configured CA,
and rejects certificates expiring within one hour before it mutates the beta
stack. Flow, presentation-policy, auth, applicant and verification receive only
their own private keys.
