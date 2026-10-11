# Product artifact contract (PKG01 / CICD02 foundation)

`deploy-config/schemas/product-artifact-manifest.schema.json` defines the
descriptor for **one immutable artifact of one product on one OS/architecture**.
`python scripts/check_product_artifact_manifest.py path/to/manifest.json` checks
its shape and cross-field invariants. It does not build, publish, install,
signature-verify, or qualify the artifact. No current product is declared
supported by adding this contract.

The descriptor binds product identity and capability list to an artifact digest,
source commit, license notice digest, SBOM digest, provenance digest, explicit
runtime/build/optional-extension dependencies, schema/protocol compatibility,
installation channel, and qualification evidence references. An OCI artifact
must use a digest reference matching the declared digest; a tag is rejected.
The no-integration graph has an empty `extensions` list and no
`optional-extension` dependency. Every selected extension must have exactly one
matching optional-extension dependency. This is descriptor closure, not a
transitive SBOM or runtime dependency proof.

## Initial sequence and evidence still needed

| Candidate | Current source observation | Next artifact/qualification boundary |
| --- | --- | --- |
| Linux/amd64 self-host stack | Existing shared services image and self-host Compose include multiple roles; the Canvas worker is in the default Compose and release binary list. | PKG02 repairs and qualifies the exact-digest no-integration bundle. Do not relabel the full stack as an independent product until its installation and journey evidence passes. |
| Offline verification library | Existing verification crate/bindings are a source basis, not an independently qualified public package. | PKG03 establishes dependency closure, a clean-project install from the public channel, and valid/tampered/wrong-trust/expiry cases without platform services. |
| Headless verifier | The current server verification binary and shared services image are not an independent offline edge runtime. | PKG04 establishes a bounded-state offline runtime, trust/policy rules, restart and blocked-egress tests, then an exact artifact. |
| Kiosk and separate issuance | Source/runtime components exist, but hardware and issuance dependency contracts remain open. | Keep these as preview *targets* until PKG05/PKG07 qualification; do not issue a `supported` manifest based on code presence. |

The shared build pipeline should produce separate runtime artifacts only after
the owning product's dependency closure and test ledger are reviewed. For each
candidate, the artifact lane must generate the descriptor from **measured**
build outputs, verify its digests against the shipped bytes and public channel,
attach signature/SBOM/license/source references, and pass this validator.
CICD03 must then install and exercise those exact digests; CICD04 may promote
only the qualified digests without rebuilding. A descriptor with
`qualification.state=qualified` and evidence URLs is still only an assertion;
the release gate must verify the evidence's candidate identity, required
coverage, freshness, and outcome. No such release-gate switch is made here.

The product owner still needs to approve the supported matrix, architectures,
capabilities and offline rules; commercial/legal owners need to approve license
expressions and notices. The artifact lane must not infer either choice from
this schema or from a Cargo feature, Compose role, or image entry point.
