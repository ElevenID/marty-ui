#!/usr/bin/env bash
# Separate asset and signer policy for installation-test nightly prereleases.

nightly_policy="$(dirname "${BASH_SOURCE[0]}")/../release/nightly-assets.json"
test "$(jq -er .schema "$nightly_policy")" = elevenid.nightly-installation-assets/v1 || return 1
mapfile -t NIGHTLY_SIGNED_INPUTS < <(jq -er '.signed_inputs[]' "$nightly_policy")
test "${#NIGHTLY_SIGNED_INPUTS[@]}" -eq 18 || return 1
if ! declare -F release_require_core_or_hosting_assets >/dev/null; then
  source "$(dirname "${BASH_SOURCE[0]}")/operator-release-assets.sh" || return 1
fi
NIGHTLY_CHECKSUM_INPUTS=("${NIGHTLY_SIGNED_INPUTS[@]}")
for nightly_asset in "${NIGHTLY_SIGNED_INPUTS[@]}"; do
  [[ "$nightly_asset" =~ ^[A-Za-z0-9][A-Za-z0-9._-]+$ ]] || return 1
  NIGHTLY_CHECKSUM_INPUTS+=("$nightly_asset.sigstore.json")
done
NIGHTLY_PROVENANCE_INPUTS=(
  install.sh.provenance.jsonl
  marty-deploy-linux-amd64.provenance.jsonl
  prepared-selfhost-bundle.zip.provenance.jsonl
  prepared-selfhost-images.json.provenance.jsonl
  installer-inventory.json.provenance.jsonl
)
NIGHTLY_RELEASE_ASSETS=("${NIGHTLY_CHECKSUM_INPUTS[@]}" RELEASE-SHA256SUMS "${NIGHTLY_PROVENANCE_INPUTS[@]}")

nightly_release_require_checksum_names() {
  local actual expected
  actual="$(awk '{print $2}' "$1" | sed 's/^\*//' | LC_ALL=C sort)" || return 1
  expected="$(printf '%s\n' "${NIGHTLY_CHECKSUM_INPUTS[@]}" | LC_ALL=C sort)"
  test "$actual" = "$expected"
}

nightly_release_require_remote_allowlist() {
  local expected
  expected="$(printf '%s\n' "${NIGHTLY_RELEASE_ASSETS[@]}" | LC_ALL=C sort)"
  release_require_core_or_hosting_assets "$1" "$expected" true true
}
