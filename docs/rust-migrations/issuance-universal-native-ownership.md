# Universal native issuance ownership checkpoint

Future/default source compositions now select the Rust issuance service for all
120 migrated HTTP routes and all twelve gRPC operations. The language-neutral
contract is `contracts/issuance-universal-ownership.json`; it derives the exact
remainder from the complete 131-route runtime surface instead of maintaining a
second informal allow-list.

The Python issuance service is deliberately retained for exactly eleven HTTP
operations: the organization retention summary/purge pair and nine physical-
passport operations. Gateway selection remains method-and-path exact, so a near
miss does not broaden either owner. Python deletion is not part of this
checkpoint.

The default base Compose graph launches both owners, points gateway migrated
routes and Flow gRPC to Rust, and keeps legacy HTTP available for the remainder.
The conformance launcher and Kubernetes deployment script default to native
selection. Kubernetes retains its explicit legacy recovery selector. The
conformance launcher's historical `legacy` value only omits conformance-specific
native overlays; it does not reverse the base composition's universal native
ownership and must not be treated as a Python-owner recovery mode.
Canonical Envoy source routes the complete migrated issuance gRPC/transcoded
surface to `issuance-native:9005`. First-party diagnostic and Canvas demo tools
use the gateway rather than the legacy service's host port.

Production HTTP ownership is unchanged. Auth, Applicant, Presentation Policy,
and Flow continue to select the legacy `ISSUANCE_SERVICE_URL`; their upgraded
Rust configuration prefers `ISSUANCE_NATIVE_SERVICE_URL` only when that value is
explicitly present, then falls back to the configured legacy URL. Flow's gRPC
owner remains `issuance-native`. Shared Canvas publication settings and the
disabled-by-default native worker controls may be present in the production
composition without selecting native HTTP ownership. No live beta or production
deployment is performed by this source checkpoint. `DIDCOMM-KMS-001` remains
deferred, and the existing Python service/image must remain available until the
eleven-route remainder is migrated and the aggregate beta acceptance gate passes.

Required source gates:

- exact `runtime surface - native coverage == retained legacy routes` equality;
- default Compose, conformance, Kubernetes and Envoy ownership assertions;
- first-party direct-client anti-bypass checks;
- existing DIDComm consumer, base/native Compose, Kubernetes, conformance and
  Envoy regression suites.
