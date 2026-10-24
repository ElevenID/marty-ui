#!/usr/bin/env bash
# Install one exact signed Linux operator binary without requiring a Rust toolchain.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <release-tag> <source-sha> <destination-directory>" >&2
  exit 2
fi

tag="$1"
source_sha="$2"
destination="$3"
nightly=false
if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-nightly\.20[0-9]{6}\.[1-9][0-9]*$ ]]; then
  nightly=true
elif [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid release tag" >&2
  exit 2
fi
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid source SHA" >&2; exit 2; }

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) asset=marty-deploy-linux-amd64 ;;
  Linux:aarch64) asset=marty-deploy-linux-arm64 ;;
  *) echo "Unsupported operator platform" >&2; exit 2 ;;
esac

for tool in gh jq cosign sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Required verification tool is missing: $tool" >&2; exit 1; }
done

repo=ElevenID/marty-ui
source "$(dirname "$0")/operator-release-assets.sh"
checksum_file=SHA256SUMS
remote_check=operator_release_require_remote_allowlist
checksum_check=operator_release_require_checksum_names
signer_workflow=cd.yml
if [[ "$nightly" = true ]]; then
  test "$asset" = marty-deploy-linux-amd64 || { echo "Nightly installation testing requires Linux amd64" >&2; exit 2; }
  source "$(dirname "$0")/nightly-release-assets.sh"
  checksum_file=RELEASE-SHA256SUMS
  remote_check=nightly_release_require_remote_allowlist
  checksum_check=nightly_release_require_checksum_names
  signer_workflow=nightly-release.yml
fi

tag_ref="$(gh api "repos/$repo/git/ref/tags/$tag")"
test "$(jq -er '.object.type' <<<"$tag_ref")" = tag
tag_object="$(jq -er '.object.sha' <<<"$tag_ref")"
[[ "$tag_object" =~ ^[0-9a-f]{40}$ ]]
tag_doc="$(gh api "repos/$repo/git/tags/$tag_object")"
test "$(jq -er '.object.type' <<<"$tag_doc")" = commit
test "$(jq -er '.object.sha' <<<"$tag_doc")" = "$source_sha"
test "$(jq -er '.tag' <<<"$tag_doc")" = "$tag"

release_doc="$(gh api "repos/$repo/releases/tags/$tag")"
test "$(jq -er '.tag_name' <<<"$release_doc")" = "$tag"
test "$(jq -er '.draft' <<<"$release_doc")" = false
test "$(jq -r '.prerelease' <<<"$release_doc")" = "$nightly"
"$remote_check" /dev/stdin <<<"$release_doc"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
gh release download "$tag" --repo "$repo" --dir "$stage" \
  --pattern "$asset" --pattern "$asset.sigstore.json" --pattern "$checksum_file"
test -f "$stage/$asset"
test -f "$stage/$asset.sigstore.json"
test -f "$stage/$checksum_file"
"$checksum_check" "$stage/$checksum_file"

expected_sha="$(awk -v name="$asset" '$2 == name {print $1}' "$stage/$checksum_file")"
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]
test "$(awk -v name="$asset" '$2 == name {count++} END {print count+0}' "$stage/$checksum_file")" = 1
test "$(sha256sum < "$stage/$asset" | cut -d ' ' -f 1)" = "$expected_sha"

cosign verify-blob "$stage/$asset" \
  --bundle "$stage/$asset.sigstore.json" \
  --certificate-identity "https://github.com/$repo/.github/workflows/$signer_workflow@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "$stage/$asset" --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/$signer_workflow" \
  --source-digest "$source_sha" --source-ref refs/heads/main \
  --deny-self-hosted-runners

chmod 755 "$stage/$asset"
test "$("$stage/$asset" --build-identity)" = "$source_sha:$tag"
mkdir -p "$destination"
destination="$(cd "$destination" && pwd)"
install -m 0755 "$stage/$asset" "$destination/$asset"

receipt="$destination/marty-deploy.lock"
{
  printf 'export MARTY_DEPLOY_BIN=%q\n' "$destination/$asset"
  printf 'export MARTY_DEPLOY_BIN_SHA256=%q\n' "$expected_sha"
  printf 'export MARTY_DEPLOY_SOURCE_SHA=%q\n' "$source_sha"
  printf 'export MARTY_DEPLOY_RELEASE_TAG=%q\n' "$tag"
} > "$receipt"
echo "Verified $asset from $tag at $source_sha"
echo "Source $receipt before running operator commands."
