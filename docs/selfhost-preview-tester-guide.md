# Experimental self-host tester preview

This is an **unsupported, unqualified preview** for technically experienced
testers on disposable machines. Do not use production data, credentials, or
domains. The exact image-locked ZIP was prepared from `marty-ui` v1.1.247
(`189f923214e52504eb3b4bb8bb5e050c7dde140a`) by release run
`38687925960`. An independent consumer verified its archive, Compose model,
and anonymous image pulls. The full stack has **not** passed a clean installed
customer journey or KMS custody qualification. The stable v1.1.247 release
does not represent a supported self-host installation.

Use Linux amd64 with Docker Engine/Compose for the first feedback round. The
current qualification target is 32 GiB RAM and 20 GiB free disk; that is not
an installer-enforced minimum. A smaller modern development machine may be
tried experimentally, but record RAM, CPU, disk, swap/OOM events, startup
results, and which features were exercised. Windows/macOS Docker Desktop and
Apple Silicon are not yet qualified; report their results separately. Do not
increase Docker's memory allocation beyond the host's available RAM.

Download **all** preview assets from the same prerelease: the ZIP, image lock,
preparation receipt, unqualified product descriptor, original preparation
transaction, and `SHA256SUMS`. Verify their checksums before extracting. The
transaction attached here is the original *preparation* transaction, not the
promoted `release-transaction.json` from the stable Stack release.
These preview attachments have checksums but no separate preview signature;
the stable Stack's signed evidence does not qualify this installer.

Keep a clean v1.1.247 source checkout, the downloaded assets, and the extracted
installation in three separate directories:

```bash
set -euo pipefail
source_root=/path/to/clean/marty-ui-v1.1.247
assets_dir=/path/to/downloaded-assets
install_parent=/path/to/disposable-install-parent
test "$(git -C "$source_root" rev-parse HEAD)" = 189f923214e52504eb3b4bb8bb5e050c7dde140a
(cd "$assets_dir" && sha256sum -c SHA256SUMS)
python3 "$source_root/scripts/check_prepared_selfhost_consumer.py" \
  --archive "$assets_dir/prepared-selfhost-bundle.zip" \
  --image-lock "$assets_dir/prepared-selfhost-images.json" \
  --transaction "$assets_dir/selfhost-preparation-transaction.json" \
  --receipt "$assets_dir/prepared-selfhost-bundle.json" \
  --descriptor "$assets_dir/prepared-selfhost-product-descriptor.json" \
  --expected-source-sha 189f923214e52504eb3b4bb8bb5e050c7dde140a \
  --expected-run-id 38687925960 --verify-archive-only
mkdir -p "$install_parent"
unzip "$assets_dir/prepared-selfhost-bundle.zip" -d "$install_parent"
```

The extracted `selfhost-prepared/README.md` describes the manual Compose,
external OpenBao, environment, and secret-file setup. Its older release-status
paragraph predates this preview; the exact digest-pinned images and the
unqualified status in this guide and attached descriptor take precedence. The
README's plain `docker compose up -d` also starts an unprofiled Cloudflare
tunnel. Do not use that command for a disposable local test; the installed
journey runner selects only local roles and still requires isolated OpenBao
and secret setup. There is no one-command local tester installer yet;
[issue #1350](https://github.com/ElevenID/marty-ui/issues/1350) tracks it.
The bundle contains placeholder secret files only; create real, disposable secrets
outside the extracted directory. Never send passwords, tokens, private keys,
or unredacted logs with feedback. Do not use `latest`, build images locally,
or replace locked digests when reporting a result for this preview.

For feedback, provide OS/architecture, physical and Docker-VM RAM, CPU, free
disk, Docker/Compose versions, the first failed step, redacted health/status
output, and any OOM/swap observation. A successful archive check or image pull
is **not** proof that the installed customer journey works. The preview is not
for production deployment or for a security/support claim.
