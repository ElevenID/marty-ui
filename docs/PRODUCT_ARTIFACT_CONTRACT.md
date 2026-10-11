# Product artifact contract (PKG01 / CICD02 foundation)

`deploy-config/schemas/product-artifact-manifest.schema.json` defines the
descriptor for **one immutable artifact of one product**. A qualified descriptor
also names its verified OS/architecture.
`python scripts/check_product_artifact_manifest.py path/to/manifest.json` checks
its shape and cross-field invariants. It does not build, publish, install,
signature-verify, or qualify the artifact. No current product is declared
supported by adding this contract.

Every descriptor requires the product, support state, exact artifact digest,
source commit and qualification state. An **unqualified** `experimental` or
`preview` candidate may omit platform, capabilities, license, SBOM, provenance,
signature, dependency, compatibility and installation claims it cannot prove.
Its artifact may use `urn:sha256:<digest>` to identify local bytes without
pretending they have a public download URL. Present fields remain strictly
validated. A **qualified** descriptor requires all those fields, a real HTTPS
file or digest-pinned OCI artifact URI, and at least one qualification evidence
reference. `supported` and `deprecated` also require qualified state. Schema
validity alone does not verify a reference's bytes or grant supported status.

For a qualified descriptor, the artifact digest is bound to source commit,
license notice digest, SBOM digest, provenance and signature digests, explicit
runtime/build/optional-extension dependencies, schema/protocol compatibility,
installation channel, and qualification evidence references. An OCI artifact
must use a digest reference matching the declared digest; a tag is rejected.
When a complete no-integration graph is declared, it has an empty `extensions`
list and no `optional-extension` dependency. Every selected extension must have exactly one
matching optional-extension dependency. This is descriptor closure, not a
transitive SBOM or runtime dependency proof.

`scripts/produce_selfhost_product_descriptor.py` consumes a prepared self-host
ZIP, image lock, stack release transaction and preparation receipt. It
recomputes the receipt by extracting and validating the ZIP's owned inventory,
embedded lock and Compose image closure; compares every recorded byte hash;
validates the transaction's exact source and stack gate state; matches the
image-lock release to the transaction version; and requires the lock to contain
the transaction's exact services and migrations image references. It emits a
deterministic `experimental`/`unqualified` organizational-platform candidate
with a content-addressed ZIP URN and preparation hashes. It never emits a
public locator, platform or install claim, or a purported ZIP signature, SBOM,
provenance, or license notice. The qualified **stack transaction** is not
qualification of this self-host ZIP. The producer does not authenticate the
GitHub Actions run, attest image architecture, verify every independent image's
provenance, or exercise an extracted clean install; those remain release-gate
responsibilities. Its output path must be new and is not automatically uploaded
or promoted.

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
