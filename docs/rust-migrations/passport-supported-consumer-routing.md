# Physical passport supported-consumer routing preparation

`contracts/passport-supported-consumer-routing.json` names the same nine public
operations as the native passport contract. Base Compose, self-host Compose, and
the Kubernetes reference composition retain the Python owner by default. The
Gateway, Flow, and native HTTP selectors all remain `false`.

An accepted cutover must select the three flags together, enable internal
service authentication, and point Gateway and Flow at the native HTTP owner.
Self-host uses the same mounted `grpc_service_token` for all three processes.
Self-host Flow keeps `ISSUANCE_NATIVE_SERVICE_URL` at the legacy issuance URL
by default because its reference catalog uses that URL even when passport is
off. The standalone Compose file passes through the explicit
`ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005` override. Select it
with the three native passport flags after acceptance; Flow rejects a selected passport owner if
that URL still equals the legacy URL.
Kubernetes uses the same `marty-secrets/GRPC_SERVICE_TOKEN` key; the closed
native renderer passes its passport flags from `marty-config` to the native
deployment. The Kubernetes native issuance image selection must be completed
before its passport flags are changed.

These source bindings do not authorize Python route deletion. The software
route retirement gate in `ElevenID/marty-credentials#305` uses Marty's
simulator profile, a managed issuer signer, a native accepted signed callback,
job and artifact drain, live behavior for all nine routes, and Rust restart
and KMS-backed job resume in protected disposable acceptance. It records
`physical_claim=not_claimed`; an external provider or physical booklet is not
required to retire the migrated software routes. The simulator does not prove
physical personalization. Do not activate these flags in production from this
source change alone.

Native bureau dispatch also requires the current delivery destination catalog
entry. Issuance needs read access to
`credential_template_service.delivery_destinations`; unavailable catalog data
blocks dispatch. The entry must be enabled and belong to the job organization,
or be a global system entry. Its provider, mode, target, credential format and
protocol must identify physical document delivery. An explicit `connector_id`
must match the configured bureau provider profile.

The same Rust guard applies to first submission, batch submission, receipt
completion and private reconciliation replay. Disabling or deleting a
destination blocks new sends with HTTP 409. Re-enable or repair its configuration
before replaying retained signed material. A policy change after reservation
preserves that reservation and its exact material; it does not authorize a new
signature or discard uncertain submission history. Reading an already accepted
receipt does not send material and remains available.
