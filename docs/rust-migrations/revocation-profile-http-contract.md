# Revocation Profile Rust HTTP Contract

This document records the compatibility boundary for the Rust revocation-profile HTTP adapter. The adapter is not selected by Compose until the remaining organization-client, executable-image, observability, and differential contracts are implemented and tested.

## Profile routes in this slice

| Route | Authorization | Compatibility behavior |
|---|---|---|
| `POST /v1/revocation-profiles` | `revocation-profile:create` in the request organization | Accepts the existing protocol fields and nested configuration, validates timing dependencies and HTTPS status URLs, and returns the existing public response shape. |
| `GET /v1/revocation-profiles` | `revocation-profile:view` in the query organization | Preserves organization filtering plus `limit` and `offset`; limits above 500 fail closed. |
| `GET /v1/revocation-profiles/{profile_id}` | `revocation-profile:view` in the stored profile organization | Resolves the profile before authorization so callers cannot select another tenant through request data. |
| `POST /v1/revocation-profiles/{profile_id}/activate` | `revocation-profile:activate` in the stored profile organization | Uses the canonical Rust lifecycle transition and durable repository. |
| `DELETE /v1/revocation-profiles/{profile_id}` | `revocation-profile:delete` in the stored profile organization | Returns the existing `{ "success": true }` body. |
| `POST /internal/revocation-profiles/{profile_id}/allocate-index` | Shared internal service token when configured | Uses atomic Rust repository allocation and rejects cross-organization profile use. |
| `POST /internal/revocation-profiles/{profile_id}/process-revocation` | Shared internal service token when configured | Preserves the existing lifecycle response envelope while mutation and status rules remain canonical Rust behavior. |
| `GET /v1/organizations/{organization_id}/revocation-profiles/{profile_id}/status-lists/{mechanism}/{purpose}` | Public | Preserves tenant-hiding 404 behavior, cache headers, and existing Bitstring/Token document shapes using canonical Rust claims and credential subjects. |
| `POST/GET /v1/cascade-revocations` | `revocation-profile:activate/view` | Preserves operation validation, circuit-breaker confirmation, rollback snapshots, status filtering, and response fields. |
| `GET/DELETE /v1/cascade-revocations/{operation_id}` plus `confirm` and `rollback` | Stored-operation organization permissions | Preserves legal transitions, the 72-hour rollback window, pending-only cancellation, and tenant ownership. |
| `POST/GET /v1/revocation-batches` | Stored/request organization permissions | Preserves intervals, the 1,000-credential circuit breaker, status filtering, and response fields while persisting credential IDs privately. |
| `GET/DELETE /v1/revocation-batches/{batch_id}` plus `publish` | Stored-batch organization permissions | Preserves publish transitions and pending-only deletion. |

The `X-User-Id` gateway context remains the administrative HTTP identity input. Missing identity returns `401`. Missing membership or permission returns `403`. Internal routes compare the configured `X-Service-Token` in constant time and return `401` when it is absent or invalid. Tokenless internal composition remains possible only when startup configuration deliberately supplies no token, matching the existing development/test contract; the executable startup layer must require a strong token outside development. An unavailable authorization, storage, or canonical status backend returns `503`; it never falls back to an in-process allow decision.

## Response compatibility

The Rust adapter intentionally exposes only the established protocol response fields: profile identity, organization, name, upper-case status, mechanism list, mechanism priority, timing mode through `check_mode`, conditional cache/grace values, protocol issuer configuration, canonical status-list URL template, and timestamps. Internal description, verifier configuration, automation configuration, and supported-format storage fields remain hidden.

`STATUS_LIST_2021` is the external spelling for the legacy status-list mechanism. The Rust domain serializes this spelling directly so a second mapping implementation is not required by callers.

## Remaining cutover work

- Connect the authorization trait to the organization gRPC service and preserve permission/backend status mappings.
- Add service configuration, health/readiness, metrics/tracing, graceful shutdown, gRPC co-hosting, and a digest-pinned image.
- Run differential Python/Rust HTTP fixtures and full integration tests before selecting the image in the coordinated beta release.

This slice makes no deployment or Compose selection change.
