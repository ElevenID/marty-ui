# Project-scoped official interoperability stack

Official OIDF and W3C runs can share a Docker engine with other Marty
development stacks. Isolation comes from a unique Compose project, not from a
second Docker daemon. EUDI runs use their own Compose project in
`ElevenID/marty-integration-tests`, attached only to the TLS bridge described
below.

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
# Must equal the hostname in OIDF_PUBLIC_BASE_URL. It is a Docker-network
# alias only; it does not expose a backend service.
export OIDF_CONFORMANCE_BRIDGE_ALIAS=marty-oidf.test
export MARTY_CONFORMANCE_ADMIN_EMAIL=conformance@elevenid.dev
export MARTY_CONFORMANCE_ADMIN_PASSWORD="$(openssl rand -base64 32)"
export MARTY_CONFORMANCE_REVIEWER_EMAIL=conformance.reviewer@elevenid.dev
# Generate a new value for every disposable run; do not commit it.
export MARTY_CONFORMANCE_REVIEWER_PASSWORD="$(openssl rand -base64 32)"

# Supply immutable MARTY_*_IMAGE digests, disposable TLS material, and the
# ordinary stack fixture configuration before starting.
python scripts/conformance_stack.py up
python scripts/conformance_stack.py ports
```

The reviewer and administrator are intentionally created in the disposable
Keycloak realm and seeded into the matching disposable Marty organization.
The administrator creates the disposable verification policy through the
published API; the reviewer can exercise the ordinary user path. Official
adapters must obtain their `sessionId` by completing `/v1/auth/login` and
`/v1/auth/callback` over the published HTTPS origin; they must not call an
internal auth endpoint or write a session directly.

## Separate official-runner Compose project

The official runner does not join `marty-network`. The OIDF profile creates an
internal, project-scoped bridge named `${MARTY_CONFORMANCE_PROJECT}_oidf-runner`
and attaches only `oidf-tls-proxy` to it. Start the official runner in its own
Compose project with its normal default network plus that bridge as an external
network. Configure its target as `OIDF_PUBLIC_BASE_URL`; Docker resolves the
matching `OIDF_CONFORMANCE_BRIDGE_ALIAS` to the TLS proxy. It therefore reaches
the same HTTPS gateway boundary as a remote wallet, while PostgreSQL, Redis,
Keycloak, and Marty backend service names remain unreachable.

```yaml
# compose override used by the separately checked-out official runner
services:
  runner:
    networks: [default, marty-oidf]
networks:
  marty-oidf:
    external: true
    name: ${MARTY_CONFORMANCE_PROJECT}_oidf-runner
```

Do not add `marty-network` to the runner, and do not add any Marty service
other than `oidf-tls-proxy` to `marty-oidf`.

To rotate the disposable reviewer password while retaining the same temporary
stack, set a new `MARTY_CONFORMANCE_REVIEWER_PASSWORD` and run:

```bash
python scripts/conformance_stack.py bootstrap-reviewer
```

This recreates only that project's one-shot Keycloak configurator. It does not
restart the gateway, attach to another project, or preserve the password in an
artifact.

If `up` is interrupted after Compose creates project containers, rerun it with
`--resume`. Resume accepts only resources carrying that exact project label;
it does not adopt containers from another stack.

Add `--include-w3c` after assigning both
`W3C_VC_TEST_CREDENTIAL_POLICY_ID` and
`W3C_VC_TEST_PRESENTATION_POLICY_ID`. The credential policy verifies issued
JWT VCs without imposing presentation holder binding; the presentation policy
verifies `eddsa-rdfc-2022` presentations with challenge and domain binding.
For EUDI, start
the pinned `conformance/eudi-reference.compose.yml` from
`ElevenID/marty-integration-tests` as its own Compose project. Its wallet
tester and wallet-kit harness join only `${MARTY_CONFORMANCE_PROJECT}_oidf-runner`;
they must never join `marty-network`.

For the OID4VP HAIP verifier plan, add `--haip` to every launcher command and
issue `VERIFIER_X509_CERT_PEM` for the public key published by the active
`OID4VP_ISSUER_PROFILE_ID`. Request-object signatures are performed through
that issuer profile and its DID; the private key remains non-exportable in the
configured KMS. Do not supply a verifier private key to Compose or the flow
service. This selects the separate HAIP overlay, which enables
HAIP only for that disposable deployment and uses `x509_hash` client IDs.

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
