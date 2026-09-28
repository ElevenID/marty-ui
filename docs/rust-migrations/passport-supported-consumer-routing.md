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
job and artifact drain, live behavior for all nine routes, and rollback
acceptance in each supported composition. It records
`physical_claim=not_claimed`; an external provider or physical booklet is not
required to retire the migrated software routes. The simulator does not prove
physical personalization. Do not activate these flags in production from this
source change alone.
