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


Native trust-profile readbacks use their own components, with all 25 public
fields and typed trust-source, DID-resolution, inline policy and override
values. Optional fields are omitted, including credential formats on a
machine-only profile. Credential-purpose profiles require supported credential
formats; machine-purpose profiles require trusted assertion formats. Public
extension values remain JSON values, with the same recursive private-custody
and private-JWK exclusions as the owner and gateway. Native-only source IDs,
registry tokens and stored synchronization state are excluded from readback.
The pinned protocol component remains available as a reference; native response
bindings cover list, create, detail, patch, activate and delete.
The native service also has a suspend operation, but the public gateway does
not publish that route yet. Public suspension remains an API lifecycle gap.
Create/patch request DTO coverage remains explicitly incomplete.

The trust-profile list requires `organization_id` and returns an array without
a total count. On the current 64-bit service deployments, `limit` and `offset`
accept unsigned 64-bit values, defaulting to 100 and 0. Zero is valid; the owner
clamps page sizes above 500. Activate has no request body. Delete
returns exactly `{"success": true}`. These schemas describe public configuration;
they do not establish authorization, anchor validity or interoperability.

After exporting a matching binary or image, validate the shared readback cases
that also run through the actual native HTTP router and gateway projector:

```sh
python scripts/check_gateway_trust_openapi.py --openapi marty-openapi.json
```
