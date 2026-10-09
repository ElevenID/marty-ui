#!/usr/bin/env bash
# Run the exact reviewed cargo-deny release without building its Docker action.
set -euo pipefail

version=0.20.2
archive="cargo-deny-${version}-x86_64-unknown-linux-musl.tar.gz"
digest=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
tool_dir="$(mktemp -d "${RUNNER_TEMP:?}/cargo-deny.XXXXXX")"
curl --fail --location --retry 3 --silent --show-error \
    "https://github.com/EmbarkStudios/cargo-deny/releases/download/${version}/${archive}" \
    --output "$tool_dir/$archive"
printf '%s  %s\n' "$digest" "$tool_dir/$archive" | sha256sum --check --status
tar --extract --gzip --file "$tool_dir/$archive" --directory "$tool_dir" \
    "cargo-deny-${version}-x86_64-unknown-linux-musl/cargo-deny"
"$tool_dir/cargo-deny-${version}-x86_64-unknown-linux-musl/cargo-deny" \
    --manifest-path rust/Cargo.toml --all-features \
    check advisories bans licenses sources
