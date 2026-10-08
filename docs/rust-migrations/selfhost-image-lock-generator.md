# Self-host release image-lock generator

`scripts/build_selfhost_image_lock.py` is an offline preparation check for the
existing Rust bundle packager's `--image-lock` input. It does **not** build,
publish, pull, attest, or qualify images, and its output is not release evidence.

It accepts the exact source stack transaction, its unchanged source
`release/stack-lock.json`, the claimed source SHA and run ID, and a resolved
image-only Docker Compose JSON model from the same source checkout. Pass the
source `docker-compose.selfhost.prod.yml` and
`docker-compose.selfhost.bundle.override.yml` as `--base-compose` and
`--override-compose`. The caller must check the repository checkout is the
claimed source SHA before rendering; the generator then verifies transaction
identity, source-lock bytes, version, recorded digests, and service closure.

The two additional Marty roles are supplied in `--selfhost-images` as a JSON
object with exactly `ui-selfhost` and `cloudflared-wrapper` keys, each an
`ghcr.io/elevenid/marty-ui-oss/<role>@sha256:<digest>` reference.
`--external-services` maps every independently published service—issuance and
the PostgreSQL, Redis, Keycloak, and Nginx infrastructure—to an exact OCI
digest. The two issuance services must map to the same image. Missing, extra,
mutable, or wrongly assigned roles fail. Marty service ownership is derived
from the existing source Compose and override, not from a second static list;
the released `services` and `migrations` digests come only from the transaction.

Example invocation after a release job has independently produced and
verified all referenced digests and rendered `compose-model.json`:

```sh
python scripts/build_selfhost_image_lock.py \
  --compose-model compose-model.json \
  --base-compose docker-compose.selfhost.prod.yml \
  --override-compose docker-compose.selfhost.bundle.override.yml \
  --transaction release-transaction.json \
  --stack-lock release/stack-lock.json \
  --source-sha "$SOURCE_SHA" --claim-run-id "$CLAIM_RUN_ID" \
  --selfhost-images selfhost-images.json \
  --external-services external-services.json \
  --output qualified-images.json
```

The generated `marty.selfhost-image-lock/v1` JSON has exactly the fields the
Rust `package-selfhost-bundle --image-lock` path expects. It binds every
rendered Compose service to one digest. A release producer must still verify
provenance and anonymous pull for every image, qualify an extracted installed
bundle, and sign/attest the eventual lock and archive before publication.
