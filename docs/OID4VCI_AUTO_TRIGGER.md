# OID4VCI Application Approval Trigger

## Overview

MIP 0.3.1 can generate a pre-authorized OID4VCI offer after an organization reviewer approves an application. The application service owns claim derivation and invokes only an active custom Flow extension that explicitly handles `APPLICATION_APPROVED` for the application's Credential Template.

There are no legacy applicant review routes or client-selected issuance claims in this workflow.

## Required Resources

The target organization must have:

- an active KMS-backed issuer identity;
- an active Trust Profile that trusts the issuer;
- an active Revocation Profile;
- an active Credential Template;
- an active Application Template linked to that Credential Template; and
- an active custom Flow Definition extending `OID4VCI_PRE_AUTHORIZED` and linked to the same Credential Template.

The Flow extension uses this canonical trigger:

```json
{
  "trigger_type": "WEBHOOK",
  "config": {
    "event_type": "APPLICATION_APPROVED"
  }
}
```

## Workflow

```text
1. A holder submits an application through POST /v1/me/applications/{id}/submit.
2. An authorized reviewer acquires the current application lock.
3. The reviewer approves through:
   POST /v1/organizations/{organization_id}/applicants/{application_id}/approve
4. The applicant service derives required checks and credential claims from the
   persisted Application Template, form_data, and server-owned SYSTEM mappings.
5. The applicant service posts an internal APPLICATION_APPROVED event to:
   POST /v1/flows/webhooks/application-approved
6. The Flow service selects active custom extensions that:
   - extend OID4VCI_PRE_AUTHORIZED;
   - explicitly handle APPLICATION_APPROVED;
   - belong to the persisted application organization; and
   - reference the application's Credential Template.
7. The Flow service creates an instance and generates a pre-authorized offer.
8. The application becomes OFFER_READY only when a live offer exists.
9. The holder claims the offer and the resulting credential appears in:
   GET /v1/issued-credentials/mine
```

Only `data.claims` crosses the application-to-issuance boundary as credential content. Event metadata, reviewer identity, request headers, `integration_context`, and arbitrary top-level fields are not credential claims.

## Flow Lifecycle

Flow Definitions are draft-first. Create the custom extension as `DRAFT`, validate all references, and activate it explicitly. A client cannot create an active Flow Definition directly.

The extension must declare:

```json
{
  "flow_type": "custom",
  "credential_template_id": "credential-template-uuid",
  "trigger": {
    "trigger_type": "WEBHOOK",
    "config": {
      "event_type": "APPLICATION_APPROVED"
    }
  },
  "extension": {
    "extension_uri": "https://example.org/mip/extensions/application-approved",
    "extends_flow_type": "OID4VCI_PRE_AUTHORIZED"
  }
}
```

The service resolves the standard OID4VCI sequence. Custom extensions may add constrained hooks, but they do not replace or reorder the normative protocol sequence.

## Failure Behavior

Approval and offer readiness are separate states:

- If offer generation succeeds, the application remains `APPROVED` with `claim_state: OFFER_READY`.
- If no eligible active Flow exists, the application remains `APPROVED` with `claim_state: BLOCKED` and `claim_blocker.code: NO_ACTIVE_ISSUANCE_FLOW`.
- If an existing offer is expired, used, or absent, a claim request may generate a fresh offer when issuance dependencies are available.
- A redeemed application cannot create a duplicate credential.

The holder UI shows Claim only for a non-expired `OFFER_READY` offer. Issuer-owned failures are recoverable waiting states, not false-ready actions.

## Authorization

- The application organization comes from the persisted resource.
- The applicant identity comes from the authenticated self-service profile.
- Reviewer and lock-holder identity come from authenticated request state.
- Review requires `application:review`; approval also requires the explicit approve permission and the current lock.
- Operator issuance requires `issuance:initiate`.
- Incoming identity headers are stripped at the gateway and replaced with authenticated values.

Cross-organization access, spoofed identity, stale locks, and resource-ID enumeration fail closed and emit privacy-safe audit events.

## Verification

Automated coverage must prove:

- draft validation and activation of the custom Flow extension;
- exact organization and Credential Template matching;
- canonical trigger parsing and rejection of legacy scalar triggers;
- claim derivation from mapped `form_data` plus server-owned SYSTEM claims only;
- `OFFER_READY`, `BLOCKED`, expired-offer recovery, and duplicate-redemption behavior;
- reviewer lock and permission enforcement;
- holder inventory privacy; and
- removed applicant routes returning `404`.

The deterministic beta lifecycle gate additionally receives the credential in the Marty browser wallet, logs out, signs back in with the membership badge, and verifies an organization credential through signed DCQL presentation.
