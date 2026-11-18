#!/usr/bin/env bash
# Linux CI only. Install fixed verifier bytes; never resolve a moving latest URL.
set -euo pipefail
umask 077
test "$#" -eq 1
destination="$1"
test ! -e "$destination"
mkdir -m 700 "$destination"
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 120 --max-filesize 15031001 \
  https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_amd64.tar.gz \
  --output "$destination/gh.tar.gz"
test "$(stat -c %s "$destination/gh.tar.gz")" = 15031001
printf '%s  %s\n' 62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8 \
  "$destination/gh.tar.gz" | sha256sum --check --strict
tar -xzf "$destination/gh.tar.gz" --no-same-owner --no-same-permissions \
  -C "$destination" gh_2.103.2_linux_amd64/bin/gh
mv "$destination/gh_2.103.2_linux_amd64/bin/gh" "$destination/gh"
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 180 --max-filesize 145688404 \
  https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 \
  --output "$destination/cosign"
test "$(stat -c %s "$destination/cosign")" = 145688404
printf '%s  %s\n' 424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa \
  "$destination/cosign" | sha256sum --check --strict
chmod 700 "$destination/gh" "$destination/cosign"
"$destination/gh" version
"$destination/cosign" version
