#!/bin/sh
# GitHub-hosted bootstrap. Keep all execution inside main so incomplete piped
# downloads cannot start installation. Payload verification precedes execution.
main() (
    set -eu
    umask 077
    fail() { printf 'Marty installer: %s\n' "$*" >&2; exit 1; }
    usage() {
        printf '%s\n' 'Usage: install.sh [--channel nightly|stable | --version TAG] [--install-dir PATH] [--yes]'
    }
    # Host-specific behavior stays behind the selected platform adapter.
    linux_preflight() {
        [ "$(id -u)" -ne 0 ] || fail 'Run as your regular Docker-enabled user; privileged provisioning is requested separately'
        for tool in curl sha256sum mktemp tar chmod rm wc cut grep docker mkdir env; do
            command -v "$tool" >/dev/null 2>&1 || fail "Required tool is missing: $tool"
        done
        if [ -n "${DOCKER_CONTEXT:-}" ]; then
            docker_endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{.Endpoints.docker.Host}}')
        elif [ -n "${DOCKER_HOST:-}" ]; then
            docker_endpoint=$DOCKER_HOST
        else
            docker_endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
        fi
        case "$docker_endpoint" in unix:///*) ;; *) fail 'A local Unix-socket Docker Engine is required; remote contexts are refused' ;; esac
        unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
        export DOCKER_HOST="$docker_endpoint"
        docker info >/dev/null 2>&1 || fail 'Docker Engine must be running and accessible'
        security_options=$(docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}')
        if printf '%s\n' "$security_options" | grep -Eq '^name=rootless(,|$)'; then
            fail 'Rootless Docker is not supported by this installer'
        fi
        if printf '%s\n' "$security_options" | grep -Eq '^name=userns(,|$)'; then
            fail 'Docker user namespace remapping is not supported by this installer'
        fi
        docker_engine_id=$(docker info --format '{{.ID}}')
        [ -n "$docker_engine_id" ] || fail 'Docker Engine identity is unavailable'
        docker compose version >/dev/null 2>&1 || fail 'Docker Compose plugin is required'
    }
    linux_digest() { sha256sum < "$1" | cut -d ' ' -f 1; }
    select_platform() {
        host_os=$(uname -s) || fail 'Cannot detect host operating system'
        host_arch=$(uname -m) || fail 'Cannot detect host architecture'
        # Each supported adapter owns the complete, reviewed trust-anchor tuple.
        # Never construct verifier URLs or hashes from untrusted host strings.
        unset platform operator_asset preflight digest_adapter jq_url jq_sha jq_size
        unset cosign_url cosign_sha cosign_size gh_url gh_sha gh_size gh_member
        case "$host_os:$host_arch" in
            Linux:x86_64|Linux:amd64)
                platform=linux/amd64
                operator_asset=marty-deploy-linux-amd64
                preflight=linux_preflight
                digest_adapter=linux_digest
                jq_url=https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64
                jq_sha=020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d
                jq_size=2255816
                cosign_url=https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
                cosign_sha=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
                cosign_size=145688404
                gh_url=https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_amd64.tar.gz
                gh_sha=62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8
                gh_size=15031001
                gh_member=gh_2.103.2_linux_amd64/bin/gh
                ;;
            *) fail "Unsupported platform: $host_os/$host_arch. Currently supported: Linux amd64" ;;
        esac
    }
    channel=nightly
    version=
    selection=
    destination=
    yes=false
    complete=false
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --bootstrap-complete) [ "$#" -eq 1 ] || fail 'Invalid bootstrap terminator'; complete=true; shift ;;
            --help|-h) usage; exit 0 ;;
            --yes) yes=true; shift ;;
            --channel|--version|--install-dir)
                [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Missing value for $1"
                case "$2" in --*) fail "Missing value for $1" ;; esac
                case "$1" in
                    --channel) [ -z "$selection" ] || fail 'Choose one release selector'; channel=$2; selection=channel ;;
                    --version) [ -z "$selection" ] || fail 'Choose one release selector'; version=$2; selection=version ;;
                    --install-dir) [ -z "$destination" ] || fail 'Repeated installation directory'; destination=$2 ;;
                esac
                shift 2 ;;
            *) fail "Unknown option: $1" ;;
        esac
    done
    [ "$complete" = true ] || fail 'Incomplete bootstrap download; retry the original command'
    case "$channel" in nightly|stable) ;; *) fail 'Channel must be nightly or stable' ;; esac
    select_platform
    if [ -n "$version" ]; then
        printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-nightly\.20[0-9]{6}\.[1-9][0-9]*)?$' || fail 'Invalid version'
    fi
    "$preflight"
    stage=$(mktemp -d /tmp/marty-installer.XXXXXXXX) || fail 'Cannot create private download directory'
    trap 'rm -rf -- "$stage"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir "$stage/config" "$stage/cache" "$stage/home"
    # Never consume or send a caller's GitHub credentials during public bootstrap.
    unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN GH_DEBUG
    export GH_CONFIG_DIR="$stage/config" GH_HOST=github.com GH_PROMPT_DISABLED=1
    export XDG_CACHE_HOME="$stage/cache" COSIGN_YES=true
    fetch() {
        # curlrc is disabled; restrict both the initial and redirected protocols.
        curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 20 --max-time 600 --retry 2 --max-filesize "$3" \
            --output "$2" "$1" || fail 'Download failed; check connectivity and public GitHub rate limits'
        [ "$(wc -c < "$2")" -le "$3" ] || fail 'Downloaded asset exceeds its size limit'
    }
    digest() { "$digest_adapter" "$1"; }
    pinned() {
        fetch "$1" "$2" "$4"
        [ "$(digest "$2")" = "$3" ] || fail 'Verification tool digest mismatch'
    }
    pinned "$jq_url" "$stage/jq" "$jq_sha" "$jq_size"
    pinned "$cosign_url" "$stage/cosign" "$cosign_sha" "$cosign_size"
    pinned "$gh_url" "$stage/gh.tar.gz" "$gh_sha" "$gh_size"
    tar -xzf "$stage/gh.tar.gz" -C "$stage" "$gh_member"
    gh="$stage/$gh_member"
    chmod 700 "$stage/jq" "$stage/cosign" "$gh"
    jq="$stage/jq"
    repo=ElevenID/marty-ui
    base="https://github.com/$repo/releases/download"
    run_field() {
        "$jq" -er --arg key "$2" '.[$key] | select(type == "number" and . > 0 and . < 9007199254740992 and floor == .)' "$1"
    }
    verify() {
        env -i PATH=/usr/bin:/bin HOME="$stage/home" XDG_CACHE_HOME="$stage/cache" \
            "$stage/cosign" verify-blob "$1" --bundle "$1.sigstore.json" \
            --certificate-identity "https://github.com/$repo/.github/workflows/$2@refs/heads/main" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
        env -i PATH=/usr/bin:/bin HOME="$stage/home" XDG_CACHE_HOME="$stage/cache" \
            GH_CONFIG_DIR="$stage/config" GH_HOST=github.com GH_PROMPT_DISABLED=1 \
            "$gh" attestation verify "$1" --bundle "$1.provenance.jsonl" --repo "$repo" \
            --signer-workflow "$repo/.github/workflows/$2" --source-ref refs/heads/main \
            --source-digest "$3" --deny-self-hosted-runners \
            --predicate-type https://slsa.dev/provenance/v1 --format json > "$1.verified.json"
        "$jq" -e --arg source "$3" \
            --arg signer "https://github.com/$repo/.github/workflows/$2@refs/heads/main" \
            --arg invocation "https://github.com/$repo/actions/runs/$4/attempts/$5" '
            type == "array" and length == 1 and
            (.[0].verificationResult.signature.certificate |
                .issuer == "https://token.actions.githubusercontent.com"
                and .runnerEnvironment == "github-hosted"
                and .sourceRepositoryURI == "https://github.com/ElevenID/marty-ui"
                and .sourceRepositoryIdentifier == "1140864197"
                and .sourceRepositoryDigest == $source
                and .sourceRepositoryRef == "refs/heads/main"
                and .buildSignerURI == $signer
                and .runInvocationURI == $invocation)' "$1.verified.json" >/dev/null
    }
    signed_download() {
        fetch "$1" "$2" "$3"
        fetch "$1.sigstore.json" "$2.sigstore.json" 1048576
        fetch "$1.provenance.jsonl" "$2.provenance.jsonl" 1048576
    }
    # The unsigned pointer locates immutable metadata; it grants no authority.
    # Publishers compare-and-swap one branch commit, never replace release assets.
    select_channel() {
        pointer_url="https://raw.githubusercontent.com/$repo/installer-channel/$channel.json"
        fetch "$pointer_url" "$stage/channel-pointer.json" 65536
        "$jq" -e --arg channel "$channel" '
            type == "object" and keys == ["channel","generation","record_sha256","repository","schema"]
            and .schema == "elevenid.installer-channel-pointer/v1"
            and .repository == "ElevenID/marty-ui" and .channel == $channel
            and (.generation | type == "number" and . > 0 and . < 9007199254740992 and floor == .)
            and (.record_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
        ' "$stage/channel-pointer.json" >/dev/null || fail 'Invalid channel pointer'
        generation=$("$jq" -er '.generation | tostring' "$stage/channel-pointer.json")
        signed_download "$base/installer-channel-$channel-$generation/installer-channel.json" "$stage/channel.json" 65536
        [ "$(digest "$stage/channel.json")" = "$("$jq" -er '.record_sha256' "$stage/channel-pointer.json")" ] || fail 'Channel record differs from pointer'
        [ "$("$jq" -er '.generation | tostring' "$stage/channel.json")" = "$generation" ] || fail 'Channel generation differs from pointer'
    }
    recheck_channel_pointer() {
        fetch "$pointer_url" "$stage/channel-pointer-recheck.json" 65536
        [ "$(digest "$stage/channel-pointer.json")" = "$(digest "$stage/channel-pointer-recheck.json")" ] || fail 'Channel changed during download; retry the original command'
    }
    if [ -z "$version" ]; then
        select_channel
        promotion_source=$("$jq" -er '.promotion_source_sha | select(test("^[0-9a-f]{40}$"))' "$stage/channel.json")
        verify "$stage/channel.json" installer-promote.yml "$promotion_source" \
            "$(run_field "$stage/channel.json" promotion_run_id)" "$(run_field "$stage/channel.json" promotion_run_attempt)"
        "$jq" -e --arg channel "$channel" '
            .schema == "elevenid.installer-channel/v1" and .repository == "ElevenID/marty-ui"
            and .channel == $channel and (.generation | type == "number" and . > 0 and floor == .)
            and (.admission_sha256 | test("^[0-9a-f]{64}$"))
            and (.issued_at | type == "number" and floor == .)
            and (.expires_at | type == "number" and floor == .)
            and .issued_at <= now and .expires_at > now
            and .expires_at > .issued_at and .expires_at - .issued_at <= 604800' "$stage/channel.json" >/dev/null
        version=$("$jq" -er '.release_tag' "$stage/channel.json")
        printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-nightly\.20[0-9]{6}\.[1-9][0-9]*)?$' || fail 'Invalid channel version'
        case "$channel:$version" in nightly:*-nightly.*|stable:v*) ;; *) fail 'Channel tier differs' ;; esac
        case "$channel:$version" in stable:*-nightly.*) fail 'Channel tier differs' ;; esac
    fi
    signed_download "$base/installer-admission-$version/installer-admission.json" "$stage/admission.json" 65536
    source=$("$jq" -er '.source_sha | select(test("^[0-9a-f]{40}$"))' "$stage/admission.json")
    promotion_source=$("$jq" -er '.promotion_source_sha | select(test("^[0-9a-f]{40}$"))' "$stage/admission.json")
    verify "$stage/admission.json" installer-promote.yml "$promotion_source" \
        "$(run_field "$stage/admission.json" promotion_run_id)" "$(run_field "$stage/admission.json" promotion_run_attempt)"
    "$jq" -e --arg tag "$version" --arg platform "$platform" '
        .schema == "elevenid.installer-admission/v1" and .repository == "ElevenID/marty-ui"
        and .release_tag == $tag and .platform == $platform and .status == "accepted"
        and (.operator_sha256 | test("^[0-9a-f]{64}$"))
        and (.inventory_sha256 | test("^[0-9a-f]{64}$"))' "$stage/admission.json" >/dev/null
    if [ -f "$stage/channel.json" ]; then
        [ "$(digest "$stage/admission.json")" = "$("$jq" -er '.admission_sha256' "$stage/channel.json")" ] || fail 'Channel admission changed during download'
        [ "$source" = "$("$jq" -er '.source_sha' "$stage/channel.json")" ] || fail 'Channel source differs'
    fi
    case "$version" in *-nightly.*) workflow=nightly-release.yml ;; *) workflow=cd.yml ;; esac
    signed_download "$base/$version/$operator_asset" "$stage/marty-deploy" 536870912
    [ "$(digest "$stage/marty-deploy")" = "$("$jq" -er '.operator_sha256' "$stage/admission.json")" ] || fail 'Operator digest differs from admitted version'
    verify "$stage/marty-deploy" "$workflow" "$source" \
        "$(run_field "$stage/admission.json" build_run_id)" "$(run_field "$stage/admission.json" build_run_attempt)"
    if [ -f "$stage/channel.json" ]; then
        recheck_channel_pointer
    fi
    chmod 700 "$stage/marty-deploy"
    [ "$("$stage/marty-deploy" --build-identity)" = "$source:$version" ] || fail 'Operator build identity differs'
    set -- install --version "$version" --verified-admission "$stage/admission.json" \
        --verification-tools "$stage" --gh-bin "$gh" \
        --docker-host "$docker_endpoint" --docker-engine-id "$docker_engine_id" --docker-bin "$(command -v docker)"
    [ -z "$destination" ] || set -- "$@" --install-dir "$destination"
    if [ -f "$stage/channel.json" ]; then
        set -- "$@" --channel "$channel" --verified-channel "$stage/channel.json"
    fi
    [ "$yes" = false ] || set -- "$@" --yes
    # Operator re-verifies admission/inventory and owns persistent state. Keep
    # staging alive until it exits; no exec, so the cleanup trap also runs.
    "$stage/marty-deploy" "$@"
)
main "$@" --bootstrap-complete
