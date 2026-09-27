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
off. After acceptance, the explicit
`ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005` override accompanies
the three native passport selectors; Flow rejects a selected passport owner if
that URL still equals the legacy URL.
Kubernetes uses the same `marty-secrets/GRPC_SERVICE_TOKEN` key; the closed
native renderer passes its passport flags from `marty-config` to the native
deployment. The Kubernetes native issuance image selection must be completed
before its passport flags are changed.

These source bindings do not qualify a provider or authorize Python route
deletion. A released native image, managed signer, supported bureau and callback
provider, job and artifact drain, live behavior for all nine routes, and
per-composition rollback acceptance remain required by
`ElevenID/marty-credentials#305`. The beta bureau is synthetic and is not a
production personalization provider. Do not activate these flags in production
from this source change alone.
