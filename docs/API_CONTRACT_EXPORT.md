# Export the public gateway contract without starting services

The gateway source supports `marty-gateway --export-openapi`. It writes the same
OpenAPI 3.1 document generator used by `/openapi.json`, then exits before loading
service configuration or constructing database, identity, Redis or KMS providers.
No Marty console process, credentials or application deployment is needed.

This mode needs an image built from source containing this change. Older public
images do not gain it retroactively. Verify the image's immutable digest,
provenance and matching release/source before using its exported contract.

For a matching shared services image, replace the digest placeholder:

```sh
MARTY_SERVICES_IMAGE='ghcr.io/elevenid/marty-ui-oss/services@sha256:REPLACE_WITH_VERIFIED_DIGEST'
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --entrypoint /usr/local/bin/marty-gateway \
  "$MARTY_SERVICES_IMAGE" --export-openapi > marty-openapi.json
```

The command accepts no additional arguments and writes only JSON to stdout.
`info.version` uses the existing `MARTY_RELEASE_VERSION` label, trimmed in the
same way as the running gateway, with `development` when absent or empty.
The document also retains its pinned `x-marty-protocol-revision`. A caller can
override environment labels; the exported text is not an independent signature
or proof of release identity. Bind it to the verified image and its provenance.
The Rust crate's `0.1.0` version is not substituted as a public API version.

CI exercises the actual built gateway image with networking disabled, a read-only
root and intentionally invalid provider configuration. Two exports must be
byte-identical, references must resolve inside the document, operation IDs must
be unique, and API-key authentication and request schemas must remain present.
Extra export arguments must fail without starting the service. The generated
document is retained as a CI artifact for review; that is not a customer release
channel or supported-installation qualification.

The two notification count URLs remain supported. The nested
`/v1/notifications/unread/count` retains operation ID
`get_v1_notifications_unread_count`; the dashed compatibility alias
`/v1/notifications/unread-count` uses
`get_v1_notifications_unread_count_legacy_alias`. Earlier documents assigned
both the same ID. Runtime routing, parameters and authorization are unchanged.

Existing operation support and schema-documentation markers remain authoritative.
This is the static public contract, not an inventory of enabled routes in a
particular deployment; instance selectors still govern runtime routing.
Exporting a document does not complete missing endpoint schemas, generate typed
endpoint DTOs, validate response payloads, or qualify a headless business journey.
Independent contract packaging, publication and compatibility checks remain
part of the API-first implementation plan.

Organization list, discovery and current-user collection responses are arrays
of the organization component, without a pagination envelope or total count.
List and discovery accept unsigned 32-bit `limit` and `offset`, defaulting to
100 and 0; the owner clamps page sizes above 1000. Only discovery applies
`search`, `org_type` and `join_mechanism` filters. The current-user collection
does not paginate. These are authenticated routes, not initial operator
bootstrap APIs. Organization membership readbacks can omit `joined_at` and role
`display_name`; the exported component reconciles these optional native fields
without changing the pinned protocol source bundle.

For local schema validation after exporting a matching executable or image:

```sh
python -m pip install jsonschema==4.23.0
python scripts/check_gateway_organization_openapi.py --openapi marty-openapi.json
```

This validates the same organization readback cases exercised by the gateway
projector and rejects private fields and invented response envelopes. CI runs
it against the export from the actual gateway image.

Trust-profile issuer overrides must contain public configuration only. The
public gateway and native owner reject nested private custody selectors and
private JWK parameters, including case variants and values inside arrays,
before saving a create or patch. Public JWKs remain valid configuration.
Readback rejects a legacy profile containing such private override data instead
of returning it; a native collection containing that profile fails as a whole.
The stored record is preserved for operator remediation. An authorized patch
with `system_issuer_overrides: {}` clears that map and restores readback; it
does not replace the profile or change its other configuration. A successful export
or structurally valid profile does not qualify its trust anchors or issuers.
