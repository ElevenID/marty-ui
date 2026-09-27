# Passport native internal handoff

`PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED` is default-off. When enabled on Gateway,
Flow, and native issuance together, those services reuse their existing
`GRPC_SERVICE_TOKEN` for private passport HTTP calls. They reject a simultaneous
`PASSPORT_TENANT_API_KEYS` value or `_FILE` binding. This removes the separate
plaintext passport tenant-keyring file; it does not replace public organization
API-key validation or create another public authentication method.

Gateway validates the caller through its existing organization API-key or
session middleware, checks the passport permission, and forwards only the
authorized organization ID. Flow forwards its persisted instance organization
ID, not a caller-supplied organization hint. Native issuance requires both the
service token and an organization header, compares the token in constant time,
and scopes every repository operation to that organization. The source is
redacted from `Debug` output. The legacy per-tenant keyring remains available
while the selector is off, for compatibility with existing deployments.

The shared service token is a broad workload credential, not a tenant-scoped
credential. A compromised trusted service could assert another organization;
the network and workload boundary therefore remains essential. This opt-in is
for the isolated beta cutover only. Do not expose native issuance directly or
enable this mode on a production deployment without separate authorization and
threat-model review. It carries no DSC private key, artifact key, or webhook
MAC key into a process; those operations use the managed Signing Keys/KMS
interfaces in the companion passport changes.

Before activation, render and validate the complete beta Compose model,
confirm the three selectors and mode agree, ensure no legacy passport key
files are mounted, then run cross-tenant, callback, and recorder acceptance.
Rollback must disable the three passport selectors together; do not silently
fall back to a keyring within an enabled service.
