#!/usr/bin/env bash
# Exact public asset set for a qualified stack release with operator binaries.

OPERATOR_LEGACY_SIGNED_INPUTS=(
  stack-manifest.json
  release-transaction.json
  marty-ui-sbom.cdx.json
  marty-ui-services-sbom.cdx.json
  marty-ui-migrations-sbom.cdx.json
  marty-ui-openbao-didcomm-sbom.cdx.json
  marty-ui-keycloak-sbom.cdx.json
  marty-deploy-linux-amd64
  marty-deploy-linux-arm64
)

OPERATOR_SIGNED_INPUTS=(
  "${OPERATOR_LEGACY_SIGNED_INPUTS[@]}"
  install.sh
  installer-inventory.json
  prepared-selfhost-bundle.zip
  prepared-selfhost-images.json
)

OPERATOR_CHECKSUM_INPUTS=(
  "${OPERATOR_SIGNED_INPUTS[@]}"
  stack-manifest.json.sigstore.json
  release-transaction.json.sigstore.json
  marty-ui-sbom.cdx.json.sigstore.json
  marty-ui-services-sbom.cdx.json.sigstore.json
  marty-ui-migrations-sbom.cdx.json.sigstore.json
  marty-ui-openbao-didcomm-sbom.cdx.json.sigstore.json
  marty-ui-keycloak-sbom.cdx.json.sigstore.json
  marty-deploy-linux-amd64.sigstore.json
  marty-deploy-linux-arm64.sigstore.json
  install.sh.sigstore.json
  installer-inventory.json.sigstore.json
  prepared-selfhost-bundle.zip.sigstore.json
  prepared-selfhost-images.json.sigstore.json
)

OPERATOR_PROVENANCE_INPUTS=(
  install.sh.provenance.jsonl
  marty-deploy-linux-amd64.provenance.jsonl
  installer-inventory.json.provenance.jsonl
  prepared-selfhost-bundle.zip.provenance.jsonl
  prepared-selfhost-images.json.provenance.jsonl
)

OPERATOR_RELEASE_ASSETS=("${OPERATOR_CHECKSUM_INPUTS[@]}" SHA256SUMS "${OPERATOR_PROVENANCE_INPUTS[@]}")

# Optional assets never join the core checksums or binary verification closure.
# They have a separate authenticated installer contract. Require the entire
# selected core and ignore only known optional names, even during an interrupted
# optional upload. Selecting the connector still requires its complete proofs.
hosting_addon_release_assets() {
  local subject
  for subject in selfhost-cloudflare-addon.zip selfhost-cloudflare-images.json cloudflared_wrapper.sbom.cdx.json; do
    printf '%s\n' "$subject" "$subject.sigstore.json" "$subject.provenance.jsonl"
  done
}

release_require_core_or_hosting_assets() {
  local response="$1" core="$2" allow_optional="${3:-true}" nightly="${4:-false}" optional=""
  if [[ "$allow_optional" = true ]]; then optional="$(hosting_addon_release_assets)"; fi
  jq -e --arg core "$core" --arg optional "$optional" --arg nightly "$nightly" '
    ($core | split("\n")) as $core |
    ($optional | split("\n") | map(select(length > 0))) as $optional |
    .assets as $assets |
    ($nightly != "true" or (.prerelease == true and .draft == false)) and
    ($assets | type) == "array" and
    all($assets[]; type == "object" and (.name | type) == "string") and
    (($assets | map(.name)) as $names |
      ($names | unique | length) == ($names | length) and
      ($core - $names | length) == 0 and
      ($names - $core - $optional | length) == 0 and
      all($assets[]; .name as $name |
        if ($core | index($name)) != null then
          .state == "uploaded" and (.size | type) == "number" and .size > 0
        else true end))
  ' "$response" >/dev/null
}

# Only the existing operator-only consumer may explicitly select historical
# releases. The publisher never calls this and remains strict about all 32 assets.
# Validate the entire legacy response before changing any active policy arrays.
operator_release_select_legacy_consumer_policy() {
  local response="$1" asset actual expected
  local legacy_checksums=("${OPERATOR_LEGACY_SIGNED_INPUTS[@]}")
  for asset in "${OPERATOR_LEGACY_SIGNED_INPUTS[@]}"; do
    legacy_checksums+=("$asset.sigstore.json")
  done
  actual="$(jq -er '.assets | if type == "array" and all(.[]; (.name | type) == "string" and .state == "uploaded" and (.size | type) == "number" and .size > 0) then map(.name) | sort | .[] else error("invalid legacy asset") end' "$response")" || return 1
  expected="$(printf '%s\n' "${legacy_checksums[@]}" SHA256SUMS | LC_ALL=C sort)"
  [[ "$actual" = "$expected" ]] || return 1
  OPERATOR_SIGNED_INPUTS=("${OPERATOR_LEGACY_SIGNED_INPUTS[@]}")
  OPERATOR_CHECKSUM_INPUTS=("${legacy_checksums[@]}")
  OPERATOR_PROVENANCE_INPUTS=()
  OPERATOR_RELEASE_ASSETS=("${OPERATOR_CHECKSUM_INPUTS[@]}" SHA256SUMS)
}

operator_release_require_local_assets() {
  local asset
  for asset in "${OPERATOR_RELEASE_ASSETS[@]}"; do
    if [[ ! -f "$asset" || -L "$asset" ]]; then
      echo "Missing or linked release asset: $asset" >&2
      return 1
    fi
  done
  operator_release_require_checksum_names || return 1
  sha256sum --check --strict SHA256SUMS >/dev/null
}

# Before attestation/export, only payloads, signatures and checksums exist.
# Offline proof sidecars are deliberately neither checksummed nor attested.
operator_release_require_pre_provenance_assets() {
  local asset
  for asset in "${OPERATOR_CHECKSUM_INPUTS[@]}" SHA256SUMS; do
    [[ -f "$asset" && ! -L "$asset" ]] || return 1
  done
  operator_release_require_checksum_names || return 1
  sha256sum --check --strict SHA256SUMS >/dev/null
}

operator_release_require_checksum_names() {
  local checksum_file="${1:-SHA256SUMS}"
  local actual expected
  actual="$(awk '{print $2}' "$checksum_file" | sed 's/^\*//' | LC_ALL=C sort)"
  expected="$(printf '%s\n' "${OPERATOR_CHECKSUM_INPUTS[@]}" | LC_ALL=C sort)"
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA256SUMS does not enumerate the exact release assets" >&2
    return 1
  fi
}

operator_release_require_remote_allowlist() {
  local response="$1"
  local expected optional=false
  expected="$(printf '%s\n' "${OPERATOR_RELEASE_ASSETS[@]}" | LC_ALL=C sort)"
  if [[ "${#OPERATOR_PROVENANCE_INPUTS[@]}" = 5 ]]; then optional=true; fi
  if ! release_require_core_or_hosting_assets "$response" "$expected" "$optional"; then
    echo "Published release assets differ from the exact allowlist" >&2
    return 1
  fi
}

operator_release_verify_published_assets() (
  local directory="$1" source_sha="$2" repo="$3" verifier="$4" tag="$5" pinned_gh="$6" file
  cd "$directory" || return 1
  operator_release_require_local_assets || return 1
  for file in "${OPERATOR_SIGNED_INPUTS[@]}"; do
    cosign verify-blob "$file" --bundle "${file}.sigstore.json" \
      --certificate-identity "https://github.com/$repo/.github/workflows/cd.yml@refs/heads/main" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com || return 1
    gh attestation verify "$file" --repo "$repo" \
      --signer-workflow "$repo/.github/workflows/cd.yml" \
      --source-digest "$source_sha" --source-ref refs/heads/main \
      --deny-self-hosted-runners || return 1
  done
  # Inventory's original producer identity is trusted only after the signatures
  # above and the exact offline subject/certificate binding below both succeed.
  python "$verifier" --phase verify-published --assets "$PWD" \
    --source-sha "$source_sha" --tag "$tag" --gh "$pinned_gh" || return 1
)
