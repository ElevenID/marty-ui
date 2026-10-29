# Self-hosted memory limits

The base stack, standalone self-hosted stack, OpenBao stack and standalone UI
have explicit per-container RAM limits. These apply to ordinary Docker Compose;
the base stack's existing `deploy.resources.limits.memory` values match
`mem_limit`. Limits are ceilings, not startup reservations or a measured sizing
guarantee. Optional overlays can override them: check the final rendered model.

| Service | Default RAM limit |
| --- | --- |
| Keycloak | 2 GiB |
| PostgreSQL | 1 GiB |
| Redis | 256 MiB base; 512 MiB standalone self-hosted |
| Migration jobs | 1 GiB |
| Self-hosted application UI | 1 GiB |
| Standalone nginx UI | 256 MiB |
| Other services, including OpenBao and the Keycloak configurator | 512 MiB |

Set `MARTY_<SERVICE>_MEMORY_LIMIT` in the deployment environment to tune a
service, replacing hyphens with underscores. For example,
`MARTY_KEYCLOAK_MEMORY_LIMIT=3g` or `MARTY_ISSUANCE_MEMORY_LIMIT=1g`.
Use a positive size; zero disables Docker's memory limit.
The native installer admits normalized limits from 6 MiB through 64 GiB and
refuses missing, zero, negative or out-of-range values. It also checks that
Docker's observed container RAM setting matches the admitted model.

Base-stack overrides must
remain above its existing memory reservations. Sum the enabled services' needs
and leave host headroom; these defaults are not evidence that the entire stack
fits a small VM or that a workload cannot be OOM-killed.

Keycloak uses `JAVA_OPTS_KC_HEAP` with an initial heap of 20% and maximum heap of
65% of the container RAM limit. The remainder is for metaspace, native buffers,
threads and providers. At the default cap its maximum heap is about 1.3 GiB.
The configurator is a separate JVM/container with a separate limit.
See [Keycloak container memory guidance](https://www.keycloak.org/server/containers#_specifying_different_memory_settings).

RAM limits do not disable swap. With Docker's default swap behavior, a limited
container can additionally use swap up to its RAM limit, if the host provides
it. Operators can set a matching `memswap_limit` in an overlay to prohibit swap.
See [Docker memory and swap semantics](https://docs.docker.com/reference/compose-file/services/#memswap_limit).

For rootless installations, memory enforcement requires cgroup v2, systemd and
the memory controller delegated to the existing user-owned daemon. A rendered
limit or `HostConfig.Memory` alone does not prove enforcement: check Docker's
warnings, cgroup driver/controllers and the container's actual cgroup limit.
The installer must not use root, sudo, install a daemon or change host cgroup
configuration to repair missing prerequisites. See
[Docker rootless resource limits](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources).

## Existing deployments

Saving Compose changes does not resize existing containers. A targeted
`docker update --memory 2g --memory-swap 4g <exact-keycloak-container-id>` can
bound an already running unlimited Keycloak without restarting it. Inspect
current usage and preserve its prior limits first: imposing a cap below use can
cause an OOM kill. Verify the exact Engine, container ID, Compose service,
health and effective limits afterward. Do not target unrelated projects.

The JVM computes heap sizing at startup. A live container-limit update does not
apply the new JVM percentages or promise the running JVM will resize. At a
planned maintenance window, recreate only Keycloak using the deployment's
original Compose files, pinned image and environment, with the new limits and
JVM setting. Preserve data, secrets and volumes; never use `down -v`, prune or
an unrelated source revision to apply this change. Authentication is briefly
unavailable during that recreation. Monitor memory, health and OOM events and
tune limits for the workload.
