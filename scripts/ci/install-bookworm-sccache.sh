#!/usr/bin/env bash
# Static sccache runs in pinned Bookworm even when the host has newer glibc.
set -euo pipefail
version=0.16.0
case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-musl; checksum=aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588 ;;
  aarch64) target=aarch64-unknown-linux-musl; checksum=f73a5c39f96bb6ebb89cc7915cf182260d4cbf30765322c5e793d0fe8bd80784 ;;
  *) echo 'Unsupported static compiler-cache architecture' >&2; exit 1 ;;
esac
directory="${RUNNER_TEMP:?}/bookworm-sccache"
mkdir -p "$directory"
archive="$directory/download.tar.gz"
curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 \
  "https://github.com/mozilla/sccache/releases/download/v$version/sccache-v$version-$target.tar.gz" \
  --output "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
tar -xzOf "$archive" "sccache-v$version-$target/sccache" > "$directory/sccache.tmp"
chmod 755 "$directory/sccache.tmp"
[[ "$("$directory/sccache.tmp" --version)" == "sccache $version" ]]
mv "$directory/sccache.tmp" "$directory/sccache"
rm "$archive"
