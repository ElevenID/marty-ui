# Project-scoped official interoperability stack

Official OIDF, W3C, and EUDI runs can share a Docker engine with other Marty
development stacks. Isolation comes from a unique Compose project, not from a
second Docker daemon.

The conformance overlay removes every fixed container name, removes all base
host-port publications, and restores Compose's project prefixes for networks
and volumes. Only the HTTPS protocol boundaries are published. The launcher
rejects a project that already owns containers, a port used by another
container, a global network or volume, or a service that unexpectedly exposes
a host port.

Choose a unique lowercase run identifier and keep it for the complete run:

```bash
export MARTY_CONFORMANCE_PROJECT=marty-conformance-20260719-a1
export OIDF_TLS_HOST_PORT=28443
export OIDF_PUBLIC_BASE_URL=https://marty-oidf.test:28443
export MARTY_CONFORMANCE_ADMIN_EMAIL=conformance@elevenid.dev

# Supply immutable MARTY_*_IMAGE digests, disposable TLS material, and the
# ordinary stack fixture configuration before starting.
python scripts/conformance_stack.py up
python scripts/conformance_stack.py ports
```

If `up` is interrupted after Compose creates project containers, rerun it with
`--resume`. Resume accepts only resources carrying that exact project label;
it does not adopt containers from another stack.

Add `--include-w3c` after assigning `W3C_VC_TEST_POLICY_ID`. Add
`--include-eudi` after supplying the pinned EUDI verifier keystore and HTTPS
endpoint variables. These flags only add services and configuration to the
same project-scoped network.

Inspect and remove exactly that project with:

```bash
python scripts/conformance_stack.py ps
python scripts/conformance_stack.py down
```

`down` removes only resources carrying the validated project name, including
its fresh database volumes. It does not enumerate, stop, or delete containers
from any other Compose project. Do not manually attach an existing development
container or shared volume to the conformance project; doing so invalidates the
clean-run evidence.
