# Verification workload identity

Production calls across the presentation-policy and Flow verification gRPC
boundaries use mutually authenticated TLS in addition to the internal service
token. The token remains defense in depth; authorization is based only on the
URI SAN proven by the client certificate.

The presentation-policy service denies every application RPC by default. Its
production allowlist is:

| RPC | Authorized certificate URI SANs |
| --- | --- |
| `GetPolicy` | `spiffe://marty.internal/service/flow`, `spiffe://marty.internal/service/verification` |
| `EvaluatePresentation` | `spiffe://marty.internal/service/flow`, `spiffe://marty.internal/service/verification` |

This prevents another workload that obtains the shared service token from
submitting attacker-controlled verification material or invoking policy
mutation RPCs. Health and reflection remain interceptor-exempt, although the
mTLS listener still requires a certificate at the transport layer.

The Flow service also denies every application RPC by default. Its production
allowlist is:

| RPC | Authorized certificate URI SAN |
| --- | --- |
| `StartVerification` | `spiffe://marty.internal/service/auth` |
| `ApplicationApproved` | `spiffe://marty.internal/service/applicant` |

Public HTTP verification and SIOP starts remain user operations and always
require active `verification:execute` membership. A caller-controlled user ID,
including a non-UUID string such as `auth-service`, is never service identity.

## Certificate profile

Use a dedicated internal workload CA. Do not use a public web PKI CA or an
issuer that allows arbitrary workloads to request one of the authorized URI
SANs.

- `pp_workload_server_cert`: server-auth certificate with a DNS SAN matching
  `presentation-policy` (and the cluster-qualified service name where used).
- `flow_workload_client_cert`: client-auth certificate with the exact URI SAN
  `spiffe://marty.internal/service/flow`.
- `flow_workload_server_cert`: server-auth certificate with a DNS SAN matching
  `flow` (and the cluster-qualified service name where used).
- `auth_workload_client_cert`: client-auth certificate with the exact URI SAN
  `spiffe://marty.internal/service/auth`.
- `applicant_workload_client_cert`: client-auth certificate with the exact URI
  SAN `spiffe://marty.internal/service/applicant`.
- `verification_workload_client_cert`: client-auth certificate with the exact
  URI SAN `spiffe://marty.internal/service/verification`.
- Each certificate has its own private key. Never copy a client private key to
  another workload.
- Keep certificate lifetimes short, automate rotation, and retain overlap
  between old and new CA bundles during CA rotation.

The runtime relies on the TLS library for chain, expiry, hostname, key usage,
and proof-of-private-key checks. Application authorization compares the exact
authenticated URI SAN; a caller-provided header is never treated as identity.

## Secret inputs

Docker self-host installations place these files in `SELFHOST_SECRET_DIR`:

- `workload_identity_ca_cert`
- `pp_workload_server_cert` and `pp_workload_server_key`
- `flow_workload_client_cert` and `flow_workload_client_key`
- `flow_workload_server_cert` and `flow_workload_server_key`
- `auth_workload_client_cert` and `auth_workload_client_key`
- `applicant_workload_client_cert` and `applicant_workload_client_key`
- `verification_workload_client_cert` and
  `verification_workload_client_key`

Kubernetes installations provide the equivalent values through either the
value or `_FILE` form of these variables before running `setup-secrets`:

- `MARTY_WORKLOAD_IDENTITY_CA_CERT`
- `PP_WORKLOAD_SERVER_CERT` and `PP_WORKLOAD_SERVER_KEY`
- `FLOW_WORKLOAD_CLIENT_CERT` and `FLOW_WORKLOAD_CLIENT_KEY`
- `FLOW_WORKLOAD_SERVER_CERT` and `FLOW_WORKLOAD_SERVER_KEY`
- `AUTH_WORKLOAD_CLIENT_CERT` and `AUTH_WORKLOAD_CLIENT_KEY`
- `APPLICANT_WORKLOAD_CLIENT_CERT` and `APPLICANT_WORKLOAD_CLIENT_KEY`
- `VERIFICATION_WORKLOAD_CLIENT_CERT` and
  `VERIFICATION_WORKLOAD_CLIENT_KEY`

The deployment helper creates separate Kubernetes Secrets and each pod mounts
only its own private key. Certificate material is mandatory outside development;
missing or partial configuration stops the affected service before it can
process verification traffic.
