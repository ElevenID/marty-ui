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

The published [CLI v0.3.4 release](https://github.com/ElevenID/marty-cli/releases/tag/v0.3.4)
includes key lifecycle commands. With an already provisioned operator key in
`MARTY_API_KEY`, use an explicit organization and explicit consumer scopes:

```sh
marty api-keys list --organization-id <organization-uuid>
marty api-keys create --organization-id <organization-uuid> \
  --name credential-reader --scope credentials:read
marty api-keys revoke <owned-key-id> --organization-id <organization-uuid>
```

Creation returns the one-time secret in the JSON `key` field. Capture that output
privately in the application's secret store; shared terminal or build logs must
not receive it. Creating a consumer key does not replace the operator's saved
login. Organization overrides do not change saved configuration. Repeat
`--scope` for multiple scopes; `--expires-at` accepts a future RFC 3339 timestamp.
Create and revoke support `--dry-run`. Use the installed command's `--help` and
[versioned CLI guide](https://github.com/ElevenID/marty-cli/blob/v0.3.4/README.md)
for the complete flags. These commands manage keys after operator bootstrap;
they do not provision the initial tenant or establish full headless qualification.

## JavaScript consumption

Custom Node and browser applications can install the independently distributed
`@elevenid/marty-api-core` tarball from the same release. The
[versioned SDK guide](https://github.com/ElevenID/marty-cli/blob/v0.3.4/packages/api-core/README.md)
describes the JavaScript factory and installation. Node consumers require Node
24 or later and can provide `X-API-Key` through the synchronous `requestOptions`
callback without a console session. Package version `0.3.4` is distinct from
its MIP protocol version `0.5.0`. The published v0.3.4 package includes public
TypeScript declarations for the transport factory. Its JSON response generics
assert a caller-provided shape without runtime schema validation. Use the
versioned SDK guide's Node and browser compiler examples; no UI aliases or
ambient declarations are required.

API discovery is served at `/openapi.json`, with interactive documentation at
`/docs`. Schema presence describes an HTTP contract; supported-product and
protocol qualification require their separate release evidence.
