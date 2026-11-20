# Package-built application image

This producer builds an application image from the verified portable source
package. The existing combined application release and its selected backend
remain separate contracts. An application publication does not establish
authentication, host deployment or compatibility with the accepted composition.

## Producer identity

| Field | Value |
| --- | --- |
| Repository | `ElevenID/marty-ui`, numeric ID `1140864197` |
| Workflow | `.github/workflows/production-web-release.yml`, explicit `application` mode |
| Ref | Protected `refs/heads/main`, with an exact required source SHA |
| Image | `ghcr.io/elevenid/marty-ui-oss/application` |
| Platform | `linux/amd64` |
| Plan | `marty.application-build-plan/v1` |
| Release receipt | `marty.application-release/v1` |
| Artifact | `application-release-RUN-ATTEMPT` |

The current repository remains the original source and signing authority.
The image has its own coordinate; the existing customer and combined image
coordinates retain their contracts. This increment does not rename a repository
or change the accepted composition selections.

## Source and image construction

The producer first repeats the full and application-profile fresh-install
rehearsals, exports the source archive, and qualifies an ordinary independent
consumer. All source and package operations use a clean exact checkout.
Their existing validators continue to require the selected tests, locked
dependency identities, actual SDK/WASM, preserved source and completed cleanup.

The build plan binds the source commit/tree, archive and manifest, profile and
consumer reports, selected npm lock, route contract, SDK/WASM and complete
application output inventory. It also binds the original runtime-context
manifest and the production Dockerfile's actual bytes. The producer reuses the
existing Node validators through a fixed reviewed bridge; downloaded evidence
cannot select code for the verifier to execute.

`docker/application.Dockerfile` accepts the consumer's existing closed runtime
context. It copies the 88 application outputs, nginx configuration and the two
existing runtime hooks into the pinned nginx base. Dependency installation and
the application build have already completed outside the image recipe. No
second application build occurs during image publication.

The runtime context and its diagnostic recipe stay unchanged. The production
Dockerfile is selected explicitly from the reviewed source and adds labels for
the repository, exact source, production audience, application surface and
original context-manifest digest. It introduces no replacement for the legacy
version/backend-bound `/marty-ui-release.json` endpoint.

## Qualify the exact registry digest

Buildx pushes one candidate by immutable registry digest with build provenance
and an SBOM. The runtime checker then pulls that exact digest. It checks the
registry reference, platform and source/context labels before starting an owned
container on an ephemeral loopback port.

The checker reuses the existing nginx/resource and sandboxed browser checks.
It additionally verifies the complete image output roster and every output
file's bytes after the documented startup-hook transformations. Browser evidence
includes the existing public login and console routes, exact SDK WASM, bounded
unavailable-session Retry and the deliberate WASM-abort recovery control.

Only a real successful `published-digest` check, with its exact browser report
and completed owned container/browser/descendant cleanup, can produce the
release receipt. A local image/config ID cannot replace a registry digest.
The checker retains the external Docker image cache and records that fact; it
removes only containers it owns. Fixture and local-build reports cannot satisfy
the signed-release contract.

After qualification, the workflow attests and signs that same image digest and
the source-bound receipt. The receipt binds the retained package and browser
evidence by byte length and SHA-256. The producer then verifies the original
GitHub-hosted provenance and Sigstore signatures before uploading the successful
release artifact. A failed candidate cannot produce a successful release
artifact. No moving image tag is used for release selection.

## Independent verification

The explicit verifier entry is:

```sh
python3 scripts/application_provenance.py \
  --assets /absolute/private/application-release \
  --source-sha EXACT_ORIGINAL_SOURCE_SHA \
  --gh /absolute/pinned/gh --cosign /absolute/pinned/cosign
```

It validates the receipt and fixed evidence files, verifies their original
subject/image proofs, and checks the evidence again after verification. Exact
repository, numeric repository identity, workflow, ref, source, run and attempt
remain bound to the original producer. Public website and private commerce
producers cannot claim this application image.

The existing `application` verifier continues to consume the original combined
application receipt. Its `web-application-RUN-ATTEMPT` artifact, backend relation
and composition intake remain unchanged. The current composition schema
explicitly rejects the new package image even though its original producer is
recognized for independent application publication.

## CI and acceptance

CI freezes the application build plan before the existing dependency bootstrap.
It then builds the production recipe and runs the same resource/browser checks
without registry publication or signing authority. Its
`application-image-candidate-RUN-ATTEMPT` artifact preserves the plan, original
runtime manifest, local image-check report and browser report. The established
full/profile/package gates still run.

The first successful protected-main `application` publication must be checked
against its actual original artifact and immutable image before it is recorded
as accepted publication. Composition adoption needs an explicit application
compatibility contract and the remaining authentication/OIDC and isolated-host
promotion, rollback and recovery evidence. Production activation remains a
separate acceptance gate.
