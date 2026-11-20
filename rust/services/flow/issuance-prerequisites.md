# Configured issuance prerequisites

Flow owns the verification half of the first configured prerequisite profile,
`managed_sd_jwt_dcql_same_holder_v1`. Issuance reserves its complete immutable
issuance intent before asking Flow to start the configured verification.

## Owner transport

The existing managed HTTPS listener exposes these operations:

| Method and path | Purpose |
| --- | --- |
| `POST /internal/v1/issuance-prerequisites/{transaction_id}/start` | Admit the configured definition and publish its original wallet request. |
| `POST /internal/v1/issuance-prerequisites/{transaction_id}/evidence` | Acquire live, persisted managed evidence for that same issuance intent. |

Both require exactly one `x-service-token` header matching
`FLOW_ISSUANCE_SERVICE_TOKEN`. This optional credential also supports the
`_FILE` convention and must contain at least 32 bytes. It must be distinct from
the general service, signing, issuance API and webhook credentials. When it is
absent, the operations reject callers. Configuring it requires the existing
`MANAGED_AUTHORITY_HTTPS_ADDR` and nonexportable TLS configuration. The ordinary
public Flow router does not expose either operation.

The Issuance client uses the same `FLOW_ISSUANCE_SERVICE_TOKEN`, a fixed
`FLOW_PREREQUISITE_OWNER_URL`, and an explicit
`FLOW_PREREQUISITE_OWNER_CA_FILE`. Responses use `Cache-Control: no-store`.

## Admission and persistence

The initiating principal must pass the existing tenant Flow-start and
definition-reference authorization checks. Flow resolves the configured active
definition ID and version and compares the complete frozen policy identity.
The admitted query contains one managed SD-JWT credential using DCQL and
cryptographic holder binding. The instance expiry is capped by the immutable
issuance deadline.

Before wallet request retrieval or signing, Flow persists the intent under the
reserved `_marty_issuance_prerequisite_v1` context key. The existing V2 request
binding hashes the complete original instance, including this context. Its
digest rules remain unchanged. The key is excluded from public projections.

Concurrent starts serialize on the tenant and issuance transaction identity.
An identical retry returns the original persisted nonce and wallet URI. A
changed intent or Flow instance ID conflicts. A pre-existing verification
without this binding cannot be attached to a new issuance transaction.

Generic instance writers can preserve the binding while advancing the wallet
lifecycle. They cannot create, strip or replace it, or extend the admitted
lifetime. Only the authenticated owner-start path can create a bound instance.

Evidence acquisition starts with `PostgresFlowRepository::managed_evidence`.
Flow then locks and reloads the instance, checks the immutable intent and exact
owner evidence, and samples `clock_timestamp()` after acquiring the lock. Both
the issuance deadline and the policy validity interval must still be live.
Issuance independently authenticates this response and consumes the evidence
with the matching native holder proof under its own signing transaction lock.

## Focused checks

The ordinary authentication and listener-isolation test runs with:

```sh
cargo test --locked -p marty-flow --test issuance_prerequisite_behavior
```

The database test requires an explicitly selected local PostgreSQL database
named `w05_flow_test`. It resets only that database's `flow_service` schema and
exercises concurrent starts, immutable selection, ordinary wallet request
progress, rejected historical attachment, and expiry while waiting for a lock:

```sh
FLOW_ISSUANCE_PREREQUISITE_TEST_URL=postgresql://localhost/w05_flow_test \
  cargo test --locked -p marty-flow --test issuance_prerequisite_behavior -- --include-ignored
```

These focused tests qualify the owner boundary and database behavior. The
managed Policy/Flow fixture supplies the separate native cryptographic and
authenticated cross-owner evidence qualification.
