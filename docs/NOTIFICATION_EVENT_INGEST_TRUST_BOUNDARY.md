# Notification event-ingest trust boundary

Notification's `POST /internal/events` route is an internal fan-out boundary. An
accepted event can select tenant subscriptions and enqueue externally delivered
webhooks, so network location alone is not authorization.

## Current producer policy

Applicant is currently the only production caller of this route. Deployments
assign it the exact producer role `applicant` and mount the dedicated
`NOTIFICATION_APPLICANT_EVENT_TOKEN` only into Applicant and Notification.
Notification authenticates both the role header and its role-specific token
before body validation or dispatch.

The authenticated Applicant role may emit only:

- `application.approved` with status `APPROVED`;
- `application.rejected` with status `REJECTED`.

Both events must use aggregate type `application`, bind `data.application_id`
to `aggregate_id`, and include only non-empty Applicant, application, credential
template, and status identifiers. Notification then considers subscriptions
only from the event's `organization_id`; webhook lookup retains the same tenant
boundary.

Do not reuse this credential for a new producer. Add a distinct workload
credential and an explicit event/aggregate/data policy before mounting a new
secret or accepting its role header.

## Trust and residual risk

Applicant is the system of record for application-to-organization ownership,
so its authenticated workload role is authorized across dynamic tenant IDs for
these two application transitions. Notification does not maintain a second
application database and therefore cannot independently reconstruct that
ownership assertion.

A stolen Applicant token is limited to Applicant's event policy, but a fully
compromised Applicant workload remains able to assert a false organization for
an application. Eliminating that residual trust would require an independent
authoritative source, such as a canonical event log with authenticated producer
provenance or a read model populated from Applicant's committed records. A
callback to the same compromised Applicant service or a second shared bearer
token would not provide independent assurance.

## Operations

Generate a random token of at least 32 characters, store it as
`notification_applicant_event_token` for self-hosted Compose or
`NOTIFICATION_APPLICANT_EVENT_TOKEN` in the Kubernetes secret, and rotate both
mounts together. Notification fails startup if its credential is absent, weak,
ambiguous, or a known placeholder. Applicant fails closed and skips the network
request if either its exact producer role or credential is unavailable.
