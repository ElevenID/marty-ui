#!/usr/bin/env bash
# Exact public asset set for a qualified stack release with operator binaries.

OPERATOR_SIGNED_INPUTS=(
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
)

OPERATOR_RELEASE_ASSETS=("${OPERATOR_CHECKSUM_INPUTS[@]}" SHA256SUMS)

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
  local actual expected
  actual="$(jq -er 'if all(.assets[]; .state == "uploaded" and .size > 0) then .assets | map(.name) | sort | .[] else error("unqualified release asset") end' "$response")" || return 1
  expected="$(printf '%s\n' "${OPERATOR_RELEASE_ASSETS[@]}" | LC_ALL=C sort)"
  if [[ "$actual" != "$expected" ]]; then
    echo "Published release assets differ from the exact allowlist" >&2
    return 1
  fi
}

operator_release_verify_published_assets() (
  local directory="$1" source_sha="$2" repo="$3" file
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
)
