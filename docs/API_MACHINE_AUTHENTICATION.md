# Machine authentication through the public gateway

Custom applications and the Marty CLI can call the public gateway without running
the Marty console. The current machine credential is an organization-bound API
key. Use `X-API-Key`, or `Authorization: Bearer` with a key beginning with
`mk_live_`, `mk_test_`, `pk_live_` or `pk_test_`. A test prefix identifies the key
type; it does not establish a separate sandbox deployment.

OAuth access tokens and OIDC ID tokens are not currently accepted as gateway
machine credentials. The CLI's client-credentials login can obtain an OAuth
token, but that alone does not authenticate requests to this gateway. The
Keycloak administrative service account is not a customer API credential.

## Provisioning and authorization

An authorized operator must first provision the organization and its initial
credential through the installation's approved bootstrap process. This document
does not define an unauthenticated bootstrap endpoint. A complete supported
no-console installation and bootstrap journey remains pending qualification.

After that initial setup, an organization-bound key with `admin:full` can manage
keys for its own organization through the public API. An authenticated human
operator instead needs the corresponding `api-key:view`, `api-key:create` or
`api-key:revoke` permission. Ordinary credential scopes do not grant key
management. Organization selection never authorizes another tenant.

| Operation | Public request | Result |
| --- | --- | --- |
| List | `GET /v1/api-keys?organization_id=<uuid>&limit=100&offset=0` | Array of key metadata; no secret keys |
| Create | `POST /v1/api-keys?organization_id=<uuid>` | Key metadata plus the one-time `key` secret |
| Revoke | `DELETE /v1/api-keys/<key-id>?organization_id=<uuid>` | `{"success":true}` |

The organization query may be omitted when the authenticated identity already
provides organization context. Prefer an explicit organization in automation.
The gateway derives the native organization-service route from authorized scope.
Callers must not send internal service tokens or spoof identity headers.

For a read-only consumer, create the key with an explicit scope list:

```json
{
  "name": "credential-reader",
  "description": "Read credential records for the customer integration",
  "scopes": ["credentials:read"],
  "is_test": false
}
```

`expires_at` optionally accepts a future RFC 3339 timestamp. Omitting `scopes`, or
sending `null`, currently grants both `credentials:read` and `credentials:issue`;
send explicit scopes to avoid this default. Unknown request fields and unknown
scopes are rejected. This API creates organization keys; deployment-profile
binding and caller-selected `created_by` fields are not accepted here.

Store the returned `key` in the application's secret store. List responses do
not recover it. Rotation consists of creating a replacement, moving the
consumer, verifying it, then revoking the previous key. A revoked or expired key
cannot authenticate new requests.

## CLI consumption

With an already provisioned key supplied privately as `MARTY_API_KEY`, the native
CLI sends `X-API-Key` without requiring a saved browser session:

```sh
marty config set apiUrl https://your-marty-gateway.example
marty orgs switch <organization-uuid>
marty --global-output json health
```

Use the CLI package's actual `--help` and versioned README for operation flags.
API-key management commands are not currently part of its command set; use the
public HTTP operations above. API discovery is served at `/openapi.json`, with
interactive documentation at `/docs`. Schema presence describes an HTTP
contract; supported-product and protocol qualification require their separate
release evidence.
